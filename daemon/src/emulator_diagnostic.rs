//! Bounded operator-owned emulator transport failures. No stored state is substituted.

use std::collections::HashMap;
use std::ffi::OsStr;
#[cfg(any(test, target_os = "android"))]
use std::fs;
use std::fs::File;
use std::io::{self, Read, Write};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

use crate::{agent_log::EndpointContext, config, operation_contract, secure_fs::Directory};

const MARKER: &str = "emulator-diagnostic.json";
const LIFETIME_MS: u64 = 90_000;
const MAX_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Kind {
    StartupMutationLock,
    VehicleStateReplyLoss,
    NativeStateReadUnavailable,
    NativeStateWriteUnavailable,
    UninstallTransportLoss,
}

impl Kind {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "startup-mutation-lock" => Some(Self::StartupMutationLock),
            "vehicle-state-reply-loss" => Some(Self::VehicleStateReplyLoss),
            "native-state-read-unavailable" => Some(Self::NativeStateReadUnavailable),
            "native-state-write-unavailable" => Some(Self::NativeStateWriteUnavailable),
            "uninstall-transport-loss" => Some(Self::UninstallTransportLoss),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::StartupMutationLock => "startup-mutation-lock",
            Self::VehicleStateReplyLoss => "vehicle-state-reply-loss",
            Self::NativeStateReadUnavailable => "native-state-read-unavailable",
            Self::NativeStateWriteUnavailable => "native-state-write-unavailable",
            Self::UninstallTransportLoss => "uninstall-transport-loss",
        }
    }

    fn process(self) -> &'static str {
        match self {
            Self::VehicleStateReplyLoss
            | Self::NativeStateReadUnavailable
            | Self::NativeStateWriteUnavailable => "com.qinggan.canbus.service",
            _ => "com.qinggan.app.setting",
        }
    }

    fn agents(self) -> &'static [&'static str] {
        match self {
            Self::VehicleStateReplyLoss
            | Self::NativeStateReadUnavailable
            | Self::NativeStateWriteUnavailable => &[
                "vehicle-drive-forced-ev",
                "vehicle-drive-pedestrian-warning",
            ],
            _ => &["settings"],
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Window {
    schema_version: u8,
    kind: Kind,
    token: String,
    boot_id: String,
    release_identity: String,
    manifest_sha256: String,
    generation_id: String,
    catalog_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_writer_id: Option<String>,
    owner_pid: i32,
    owner_starttime: String,
    daemon_pid: i32,
    daemon_starttime: String,
    target_pid: i32,
    target_starttime: String,
    started_monotonic_ms: String,
    expires_monotonic_ms: String,
}

#[derive(Debug)]
struct Arguments {
    kind: Kind,
    boot: String,
    manifest: String,
    generation: String,
    catalog: String,
    target_pid: i32,
    target_starttime: u64,
}

fn positive(value: &str) -> Option<u64> {
    let parsed = value.parse::<u64>().ok()?;
    (parsed > 0 && parsed.to_string() == value).then_some(parsed)
}

fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn boot_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn parse(arguments: &[String]) -> Option<Arguments> {
    let [option, kind, boot, manifest, generation, catalog, pid, starttime] = arguments else {
        return None;
    };
    let target_pid = i32::try_from(positive(pid)?).ok()?;
    if !(option == "--emulator-diagnostic"
        && boot_id(boot)
        && hash(manifest)
        && hash(generation)
        && hash(catalog))
    {
        return None;
    }
    Some(Arguments {
        kind: Kind::parse(kind)?,
        boot: boot.clone(),
        manifest: manifest.clone(),
        generation: generation.clone(),
        catalog: catalog.clone(),
        target_pid,
        target_starttime: positive(starttime)?,
    })
}

pub(crate) fn monotonic_ms() -> io::Result<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(time.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1000))
        .and_then(|value| value.checked_add(time.tv_nsec as u64 / 1_000_000))
        .ok_or_else(|| io::Error::other("monotonic time is invalid"))
}

pub(crate) fn emulator_guard() -> bool {
    #[cfg(target_os = "android")]
    {
        unsafe extern "C" {
            fn __system_property_get(name: *const libc::c_char, value: *mut libc::c_char) -> i32;
        }
        let mut value = [0 as libc::c_char; 92];
        let length =
            unsafe { __system_property_get(c"ro.kernel.qemu".as_ptr(), value.as_mut_ptr()) };
        platform_allowed(
            true,
            length == 1 && value[0] == b'1' as libc::c_char,
            matches!(
                fs::read("/sys/fs/selinux/enforce").as_deref(),
                Ok(b"1" | b"1\n")
            ),
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
        )
    }
    #[cfg(not(target_os = "android"))]
    {
        platform_allowed(false, false, false, unsafe { libc::geteuid() }, unsafe {
            libc::getegid()
        })
    }
}

fn platform_allowed(android: bool, qemu: bool, enforcing: bool, uid: u32, gid: u32) -> bool {
    android && qemu && enforcing && uid == 0 && gid == 0
}

fn run_directory() -> io::Result<Directory> {
    let root = Directory::open(Path::new(config::ROOT_ZONE))?;
    root.validate_owner_mode(0, 0, 0o755)?;
    let run = root.open_child("run")?;
    run.validate_owner_mode(0, 0, config::RUN_DIR_MODE)?;
    Ok(run)
}

// OFD record locks are independent of the generation flock and survive
// unrelated opens/closes of operation.lock. No POSIX-lock fallback is safe.
struct OperatorLease {
    _file: File,
}

fn operator_root() -> io::Result<Directory> {
    let root = Directory::open(Path::new(config::ROOT_ZONE))?;
    root.validate_owner_mode(0, 0, 0o755)?;
    Ok(root)
}

#[cfg(any(test, target_os = "linux", target_os = "android"))]
fn kernel_operator_lease(kind: i16, pid: i32, start: i64, length: i64) -> bool {
    let write_lock: i16 = libc::F_WRLCK as _;
    kind == write_lock && pid == -1 && start == 0 && length == 1
}

impl OperatorLease {
    fn acquire(root: &Directory) -> io::Result<Self> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let file = root
                .open_trusted_readwrite_file("operation.lock", 0, 0o600)
                .map_err(|error| {
                    io::Error::other(format!("open operator lease read-write: {error}"))
                })?;
            let mut lock: libc::flock = unsafe { std::mem::zeroed() };
            lock.l_type = libc::F_WRLCK as _;
            lock.l_whence = libc::SEEK_SET as _;
            lock.l_len = 1;
            if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_OFD_SETLK, &lock) } != 0 {
                return Err(io::Error::other(format!(
                    "set operator OFD lease: {}",
                    io::Error::last_os_error()
                )));
            }
            Ok(Self { _file: file })
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let _ = root;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "operator OFD lease requires Linux",
            ))
        }
    }

    fn held(root: &Directory) -> io::Result<bool> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let (_, file) = root.read_trusted_retained("operation.lock", 0, 0o600)?;
            let mut lock: libc::flock = unsafe { std::mem::zeroed() };
            lock.l_type = libc::F_RDLCK as _;
            lock.l_whence = libc::SEEK_SET as _;
            lock.l_len = 1;
            if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_OFD_GETLK, &mut lock) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(kernel_operator_lease(
                lock.l_type,
                lock.l_pid,
                lock.l_start,
                lock.l_len,
            ))
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let _ = root;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "operator OFD lease requires Linux",
            ))
        }
    }
}

fn marker_current(run: &Directory, bytes: &[u8], inode: u64) -> bool {
    run.read_trusted(MARKER, MAX_BYTES, 0o600).ok().as_deref() == Some(bytes)
        && run
            .metadata_trusted(MARKER, 0o600)
            .ok()
            .is_some_and(|metadata| metadata.0 == inode)
}

impl Window {
    fn valid(&self) -> bool {
        self.schema_version == 1
            && hash(&self.token)
            && boot_id(&self.boot_id)
            && hash(&self.manifest_sha256)
            && hash(&self.generation_id)
            && hash(&self.catalog_sha256)
            && match self.kind {
                Kind::NativeStateReadUnavailable | Kind::NativeStateWriteUnavailable => {
                    self.owner_writer_id.as_ref().is_some_and(|id| {
                        id.len() == 32
                            && id
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
                }
                _ => self.owner_writer_id.is_none(),
            }
            && self.owner_pid > 0
            && self.daemon_pid > 0
            && self.target_pid > 0
            && positive(&self.owner_starttime).is_some()
            && positive(&self.daemon_starttime).is_some()
            && positive(&self.target_starttime).is_some()
            && positive(&self.started_monotonic_ms).is_some_and(|start| {
                positive(&self.expires_monotonic_ms) == start.checked_add(LIFETIME_MS)
            })
    }

    fn matches_lifetime(&self, now: u64, boot: &str, lease_held: bool) -> bool {
        self.valid()
            && boot == self.boot_id
            && positive(&self.started_monotonic_ms).is_some_and(|start| start <= now)
            && positive(&self.expires_monotonic_ms).is_some_and(|end| now < end)
            && lease_held
    }

    fn matches_endpoint(&self, ctx: &EndpointContext) -> bool {
        ctx.process == self.kind.process()
            && ctx.pid == self.target_pid
            && ctx.target_starttime == positive(&self.target_starttime)
            && ctx.resident_generation_id == self.generation_id
            && ctx.active_generation_id == self.generation_id
            && ctx.resident_catalog_sha256 == self.catalog_sha256
            && ctx.active_catalog_sha256 == self.catalog_sha256
    }
}

fn decode(bytes: &[u8]) -> Option<Window> {
    if bytes.len() > MAX_BYTES {
        return None;
    }
    let window: Window = serde_json::from_slice(bytes).ok()?;
    let mut canonical = serde_json::to_vec(&window).ok()?;
    canonical.push(b'\n');
    (window.valid() && canonical == bytes).then_some(window)
}

fn active_window() -> Option<Window> {
    #[cfg(test)]
    if let Some(window) = TEST_WINDOW.with(|value| value.borrow().clone()) {
        return Some(window);
    }
    let run = run_directory().ok()?;
    let (marker, descriptor) = run.read_trusted_retained(MARKER, MAX_BYTES, 0o600).ok()?;
    let marker_inode = descriptor.metadata().ok()?.ino();
    let window = decode(&marker)?;
    let root = operator_root().ok()?;
    let now = monotonic_ms().ok()?;
    let boot = operation_contract::current_boot_id().ok()?;
    if !emulator_guard()
        || !window.matches_lifetime(now, &boot, OperatorLease::held(&root).ok()?)
        || window.daemon_pid != std::process::id() as i32
        || crate::target_identity::read_starttime(window.daemon_pid).ok()
            != positive(&window.daemon_starttime)
        || crate::target_identity::read_starttime(window.target_pid).ok()
            != positive(&window.target_starttime)
        || crate::generation::GenerationStore::production()
            .active_id()
            .as_deref()
            != Some(window.generation_id.as_str())
        || crate::installed_product::load_identity()
            .ok()
            .is_none_or(|identity| {
                identity.manifest_sha256 != window.manifest_sha256
                    || identity.release_identity != window.release_identity
            })
    {
        return None;
    }
    // ADB's stock su domain cannot read another process's SELinux attr/current.
    // Keep that authority check in the resident root domain, before any fault.
    let generation = crate::generation::GenerationStore::production()
        .active()
        .ok()?;
    if generation.id != window.generation_id || generation.catalog_sha256 != window.catalog_sha256 {
        return None;
    }
    crate::target_identity::attest_catalog_target_for_agents(
        &generation.catalog,
        window.target_pid,
        window.kind.process(),
        positive(&window.target_starttime)?,
        window.kind.agents(),
    )
    .ok()?;
    crate::management::authorize_stable_cli().ok()?;
    crate::management::authorize_active_product_self().ok()?;
    if !OperatorLease::held(&root).ok()? || !marker_current(&run, &marker, marker_inode) {
        return None;
    }
    Some(window)
}

fn effect(window: &Window, name: &str, source: &str, request: &str) {
    let mut fields = HashMap::from([
        ("token".into(), window.token.clone()),
        ("kind".into(), window.kind.name().into()),
        ("effect".into(), name.into()),
        ("source".into(), source.into()),
        ("requestId".into(), request.into()),
        ("bootId".into(), window.boot_id.clone()),
        ("manifestSha256".into(), window.manifest_sha256.clone()),
        ("generationId".into(), window.generation_id.clone()),
        ("catalogSha256".into(), window.catalog_sha256.clone()),
        ("targetPid".into(), window.target_pid.to_string()),
        ("targetStarttime".into(), window.target_starttime.clone()),
    ]);
    fields.insert("process".into(), window.kind.process().into());
    crate::log::info_fields("emulator-diagnostic", "fault-effect", fields);
}

fn operational_pair(source: &str, key: &str) -> bool {
    matches!(
        (source, key),
        (
            "vehicle-drive-forced-ev",
            "forced-ev-armed" | "forced-ev-disarm-pending" | "forced-ev-lifecycle-active"
        ) | (
            "vehicle-drive-pedestrian-warning",
            "pedestrian-warning-armed"
                | "pedestrian-warning-disarm-pending"
                | "pedestrian-warning-clean-stop-pending-reconcile"
        )
    )
}

pub(crate) fn drop_state_reply(
    source: &str,
    key: &str,
    ctx: &EndpointContext,
    request: u64,
) -> bool {
    let Some(window) = active_window() else {
        return false;
    };
    if window.kind != Kind::VehicleStateReplyLoss
        || !ctx.owns_agent(source)
        || !operational_pair(source, key)
        || !window.matches_endpoint(ctx)
    {
        return false;
    }
    effect(&window, "state-reply-dropped", source, &request.to_string());
    true
}

pub(crate) fn observe_startup_rejection(
    ctx: &EndpointContext,
    request: u64,
    kind: &str,
    key: &str,
) {
    let Some(window) = active_window() else {
        return;
    };
    if window.kind == Kind::StartupMutationLock
        && window.matches_endpoint(ctx)
        && ctx.settings_allowed()
        && kind == "radio"
        && key == "voboost-startup"
    {
        effect(
            &window,
            "startup-mutation-rejected",
            "settings",
            &request.to_string(),
        );
    }
}

static UNINSTALL_TOKEN: OnceLock<Mutex<Option<String>>> = OnceLock::new();

pub(crate) fn drop_uninstall_transport(uid: u32, pid: u32, request: &str) -> bool {
    let Some(window) = active_window() else {
        return false;
    };
    if window.kind != Kind::UninstallTransportLoss
        || uid != 1000
        || i32::try_from(pid).ok() != Some(window.target_pid)
    {
        return false;
    }
    let Ok(mut consumed) = UNINSTALL_TOKEN.get_or_init(|| Mutex::new(None)).lock() else {
        return false;
    };
    if consumed.as_deref() == Some(window.token.as_str()) {
        return false;
    }
    *consumed = Some(window.token.clone());
    drop(consumed);
    effect(&window, "uninstall-transport-dropped", "settings", request);
    true
}

struct OwnedWindow {
    run: Directory,
    root: PathBuf,
    marker_inode: u64,
    lease: Option<OperatorLease>,
    window: Window,
    generation_guard: Option<operation_contract::GenerationGuard>,
}

impl OwnedWindow {
    fn remove_marker(&self) -> io::Result<()> {
        // Admission and cleanup share the existing generation mutation lock.
        // A live marker excludes another owner after admission releases it.
        let _cleanup_guard = if self.generation_guard.is_none() {
            Some(
                crate::management::acquire_generation_guard_observing(&self.root)
                    .map_err(io::Error::other)?,
            )
        } else {
            None
        };
        let (inode, _) = self.run.metadata_trusted(MARKER, 0o600)?;
        if inode != self.marker_inode
            || decode(&self.run.read_trusted(MARKER, MAX_BYTES, 0o600)?)
                .is_none_or(|window| window != self.window)
        {
            return Err(io::Error::other("diagnostic marker ownership changed"));
        }
        self.run.unlink(MARKER)?;
        self.run.sync_all()
    }
}

impl Drop for OwnedWindow {
    fn drop(&mut self) {
        self.lease.take();
        let _ = self.remove_marker();
    }
}

fn begin(arguments: Arguments) -> Result<OwnedWindow, String> {
    if !emulator_guard() {
        return Err("diagnostic requires an existing root Enforcing Android QEMU".into());
    }
    crate::management::authorize_stable_cli()?;
    crate::management::authorize_active_product_self()?;
    let guard = operation_contract::GenerationGuard::acquire_in(Path::new(config::ROOT_ZONE))?;
    let manifest = crate::installed_product::load_manifest()?;
    let generation = crate::generation::GenerationStore::production()
        .active()
        .map_err(|e| e.to_string())?;
    if operation_contract::current_boot_id()? != arguments.boot
        || manifest.digest()? != arguments.manifest
        || generation.id != arguments.generation
        || generation.catalog_sha256 != arguments.catalog
    {
        return Err("diagnostic installed identity differs".into());
    }
    crate::target_identity::attest_catalog_target_lifetime_for_agents(
        &generation.catalog,
        arguments.target_pid,
        arguments.kind.process(),
        arguments.target_starttime,
        arguments.kind.agents(),
    )
    .map_err(|e| e.to_string())?;
    let run = run_directory().map_err(|e| e.to_string())?;
    let (daemon_pid, daemon_starttime, resident_boot) =
        crate::launcher_page::authenticate_relay_server()
            .map_err(|error| format!("diagnostic resident authority: {error}"))?;
    if resident_boot != arguments.boot {
        return Err("diagnostic resident boot differs".into());
    }
    let owner_pid = std::process::id() as i32;
    let started = monotonic_ms().map_err(|e| e.to_string())?;
    let root = operator_root().map_err(|error| error.to_string())?;
    if OperatorLease::held(&root)
        .map_err(|error| format!("diagnostic operator lease query: {error}"))?
    {
        return Err("diagnostic operator lease is already held".into());
    }
    if let Ok(bytes) = run.read_trusted(MARKER, MAX_BYTES, 0o600) {
        decode(&bytes).ok_or("diagnostic stale marker is invalid")?;
        run.unlink(MARKER).map_err(|e| e.to_string())?;
    } else if run.entry_exists(MARKER).map_err(|e| e.to_string())? {
        return Err("diagnostic marker metadata is unsafe".into());
    }
    let lease = OperatorLease::acquire(&root)
        .map_err(|error| format!("diagnostic operator OFD lease: {error}"))?;
    let mut token = [0u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut token))
        .map_err(|e| e.to_string())?;
    let owner_writer_id = if matches!(
        arguments.kind,
        Kind::NativeStateReadUnavailable | Kind::NativeStateWriteUnavailable
    ) {
        match crate::owner_client::call(voboost_contract::runtime_owner::Command::ReadLogSession {})
            .map_err(|error| format!("diagnostic owner session: {error}"))?
        {
            voboost_contract::runtime_owner::Outcome::LogSession {
                boot_id, writer_id, ..
            } if boot_id == arguments.boot => Some(writer_id),
            _ => return Err("diagnostic owner session unavailable".into()),
        }
    } else {
        None
    };
    let window = Window {
        schema_version: 1,
        kind: arguments.kind,
        token: hex::encode(token),
        boot_id: arguments.boot,
        release_identity: manifest.release_identity,
        manifest_sha256: arguments.manifest,
        generation_id: arguments.generation,
        catalog_sha256: arguments.catalog,
        owner_writer_id,
        owner_pid,
        owner_starttime: crate::target_identity::read_starttime(owner_pid)
            .map_err(|e| e.to_string())?
            .to_string(),
        daemon_pid,
        daemon_starttime: daemon_starttime.to_string(),
        target_pid: arguments.target_pid,
        target_starttime: arguments.target_starttime.to_string(),
        started_monotonic_ms: started.to_string(),
        expires_monotonic_ms: (started + LIFETIME_MS).to_string(),
    };
    guard.verify_owner()?;
    let mut bytes = serde_json::to_vec(&window).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    let mut marker = run
        .create_new(OsStr::new(MARKER), 0o600)
        .map_err(|e| e.to_string())?;
    let marker_inode = marker.metadata().map_err(|e| e.to_string())?.ino();
    let written = marker
        .write_all(&bytes)
        .and_then(|()| marker.sync_all())
        .and_then(|()| run.sync_all());
    if let Err(error) = written {
        if run
            .metadata_trusted(MARKER, 0o600)
            .ok()
            .map(|value| value.0)
            == Some(marker_inode)
        {
            let _ = run.unlink(MARKER);
        }
        return Err(error.to_string());
    }
    let generation_guard = (window.kind == Kind::StartupMutationLock).then_some(guard);
    Ok(OwnedWindow {
        run,
        root: PathBuf::from(config::ROOT_ZONE),
        marker_inode,
        lease: Some(lease),
        window,
        generation_guard,
    })
}

fn receipt(window: &Window, phase: &str, terminal: Option<&str>) -> Result<(), String> {
    let mut value = serde_json::to_value(window).map_err(|e| e.to_string())?;
    value["phase"] = phase.into();
    if let Some(reason) = terminal {
        value["cleanup"] = true.into();
        value["reason"] = reason.into();
    }
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{value}")
        .and_then(|()| stdout.flush())
        .map_err(|e| e.to_string())
}

fn native_kind(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::NativeStateReadUnavailable | Kind::NativeStateWriteUnavailable
    )
}

fn native_outage(
    window: &Window,
    action: &str,
) -> Result<voboost_contract::runtime_owner::NativeStateOutageReceipt, String> {
    use voboost_contract::runtime_owner::{Command, Outcome};
    let token = window.token.clone();
    let command = match action {
        "begin" => Command::BeginNativeStateOutage { token },
        "snapshot" => Command::SnapshotNativeStateOutage { token },
        "release" => Command::ReleaseNativeStateOutage { token },
        "close" => Command::CloseNativeStateOutage { token },
        _ => return Err("invalid closed outage action".into()),
    };
    let Outcome::NativeStateOutage { receipt } = crate::owner_client::call(command)
        .map_err(|error| format!("native outage owner exchange: {error}"))?
    else {
        return Err("native outage owner did not confirm".into());
    };
    if receipt.kind != window.kind.name()
        || receipt.token != window.token
        || receipt.boot_id != window.boot_id
        || receipt.generation_id != window.generation_id
        || receipt.catalog_sha256 != window.catalog_sha256
        || Some(&receipt.owner_writer_id) != window.owner_writer_id.as_ref()
        || receipt.target_pid != window.target_pid
        || Some(receipt.target_starttime) != positive(&window.target_starttime)
        || Some(receipt.deadline_monotonic_ms) != positive(&window.expires_monotonic_ms)
        || receipt.observed_monotonic_ms >= receipt.deadline_monotonic_ms
    {
        return Err("native outage receipt identity differs".into());
    }
    Ok(receipt)
}
fn native_outage_receipt(
    phase: &str,
    value: &voboost_contract::runtime_owner::NativeStateOutageReceipt,
) -> Result<(), String> {
    let body = serde_json::json!({"schemaVersion":1,"phase":phase,"receipt":value});
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{body}")
        .and_then(|()| stdout.flush())
        .map_err(|e| e.to_string())
}

fn hold(mut owned: OwnedWindow) -> Result<(), String> {
    if native_kind(owned.window.kind) {
        let begin = native_outage(&owned.window, "begin")?;
        if begin.closed
            || begin.released
            || begin.reads != 0
            || begin.writes != 0
            || begin.wait_state_steps != 0
        {
            return Err("native outage initial counters differ".into());
        }
    }
    receipt(&owned.window, "armed", None)?;
    let mut pending = None;
    let mut control_count = 0u8;
    let mut release_requested = false;
    let deadline = positive(&owned.window.expires_monotonic_ms).ok_or("invalid deadline")?;
    let reason = loop {
        if monotonic_ms().map_err(|e| e.to_string())? >= deadline {
            break "expired";
        }
        let mut descriptor = libc::pollfd {
            fd: 0,
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, 100) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err("diagnostic owner input failed".into());
        }
        if result > 0 {
            let mut byte = [0u8; 1];
            let count = unsafe { libc::read(0, byte.as_mut_ptr().cast(), 1) };
            if count == 0 {
                if pending.is_some() {
                    return Err("incomplete diagnostic control".into());
                }
                break "eof";
            }
            if !native_kind(owned.window.kind) {
                return Err("diagnostic stdin accepts EOF only".into());
            }
            match (pending.take(), byte[0]) {
                (None, b'S' | b'R') => pending = Some(byte[0]),
                (Some(action), b'\n') => {
                    control_count = control_count
                        .checked_add(1)
                        .ok_or("diagnostic control overflow")?;
                    if control_count > 13 || action == b'R' && release_requested {
                        return Err("diagnostic control limit or replay".into());
                    }
                    if action == b'R' {
                        release_requested = true;
                    }
                    let (name, phase) = if action == b'S' {
                        ("snapshot", "snapshot")
                    } else {
                        ("release", "released")
                    };
                    let receipt = native_outage(&owned.window, name)?;
                    native_outage_receipt(phase, &receipt)?;
                }
                _ => return Err("invalid diagnostic control".into()),
            }
        }
    };
    let native_terminal = if native_kind(owned.window.kind) && reason == "eof" {
        let value = native_outage(&owned.window, "close")?;
        if !value.closed || !value.released {
            return Err("native outage terminal state unavailable".into());
        }
        Some(value)
    } else {
        None
    };
    owned.lease.take();
    owned.remove_marker().map_err(|e| e.to_string())?;
    owned.generation_guard.take();
    if let Some(value) = native_terminal {
        native_outage_receipt("native-closed", &value)?;
    }
    receipt(&owned.window, "closed", Some(reason))
}

pub(crate) fn handle_cli() -> Option<i32> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("--emulator-diagnostic") {
        return None;
    }
    let result = parse(&args)
        .ok_or_else(|| "invalid closed diagnostic arguments".to_string())
        .and_then(begin)
        .and_then(hold);
    Some(match result {
        Ok(()) => 0,
        Err(error) => {
            crate::log::err(
                "emulator-diagnostic",
                &format!("emulator diagnostic rejected: {error}"),
            );
            73
        }
    })
}

#[cfg(test)]
thread_local! {
    static TEST_WINDOW: std::cell::RefCell<Option<Window>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn with_test_window<T>(kind: &str, pid: i32, operation: impl FnOnce() -> T) -> T {
    let window = tests::window(Kind::parse(kind).unwrap(), pid);
    TEST_WINDOW.with(|value| {
        let old = value.replace(Some(window));
        struct Reset(Option<Window>);
        impl Drop for Reset {
            fn drop(&mut self) {
                TEST_WINDOW.with(|value| {
                    value.replace(self.0.take());
                });
            }
        }
        let _reset = Reset(old);
        operation()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{symlink, PermissionsExt};

    pub(super) fn window(kind: Kind, pid: i32) -> Window {
        let own = std::process::id() as i32;
        let now = monotonic_ms().unwrap();
        Window {
            schema_version: 1,
            kind,
            token: format!("{:064x}", pid),
            boot_id: "12345678-1234-1234-1234-123456789abc".into(),
            release_identity: "1.0.0-beta1".into(),
            manifest_sha256: "a".repeat(64),
            generation_id: "b".repeat(64),
            catalog_sha256: "c".repeat(64),
            owner_writer_id: match kind {
                Kind::NativeStateReadUnavailable | Kind::NativeStateWriteUnavailable => {
                    Some("d".repeat(32))
                }
                _ => None,
            },
            owner_pid: own,
            owner_starttime: crate::target_identity::read_starttime(own)
                .unwrap_or(1)
                .to_string(),
            daemon_pid: own,
            daemon_starttime: crate::target_identity::read_starttime(own)
                .unwrap_or(1)
                .to_string(),
            target_pid: pid,
            target_starttime: crate::target_identity::read_starttime(pid)
                .unwrap_or(1)
                .to_string(),
            started_monotonic_ms: now.to_string(),
            expires_monotonic_ms: (now + LIFETIME_MS).to_string(),
        }
    }

    fn context(window: &Window) -> EndpointContext {
        EndpointContext {
            pid: window.target_pid,
            process: window.kind.process().into(),
            target_starttime: positive(&window.target_starttime),
            resident_generation_id: window.generation_id.clone(),
            active_generation_id: window.generation_id.clone(),
            resident_catalog_sha256: window.catalog_sha256.clone(),
            active_catalog_sha256: window.catalog_sha256.clone(),
            resident_agents: window.kind.agents().iter().map(|v| (*v).into()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn authority_is_closed_and_fenced() {
        let args: Vec<String> = [
            "--emulator-diagnostic",
            "vehicle-state-reply-loss",
            "12345678-1234-1234-1234-123456789abc",
            &"a".repeat(64),
            &"b".repeat(64),
            &"c".repeat(64),
            "42",
            "123",
        ]
        .iter()
        .map(|v| (*v).into())
        .collect();
        assert!(parse(&args).is_some());
        for (index, value) in [
            (0, "--shell"),
            (1, "arbitrary"),
            (2, "foreign"),
            (3, "A"),
            (4, "../generation"),
            (5, ""),
            (6, "-1"),
            (6, "2147483648"),
            (7, "01"),
            (7, "0"),
            (7, "+1"),
        ] {
            let mut bad = args.clone();
            bad[index] = value.into();
            assert!(parse(&bad).is_none(), "index={index} value={value}");
        }
        let mut extra = args.clone();
        extra.push("--path".into());
        assert!(parse(&extra).is_none());
        assert!(platform_allowed(true, true, true, 0, 0));
        for (android, qemu, enforcing, uid, gid) in [
            (false, true, true, 0, 0),
            (true, false, true, 0, 0),
            (true, true, false, 0, 0),
            (true, true, true, 2000, 0),
            (true, true, true, 0, 2000),
        ] {
            assert!(!platform_allowed(android, qemu, enforcing, uid, gid));
        }
        assert!(
            !emulator_guard(),
            "host fixtures must never admit production diagnostics"
        );
        let w = window(Kind::VehicleStateReplyLoss, 42);
        assert_eq!(w.kind.process(), "com.qinggan.canbus.service");
        let ctx = context(&w);
        assert!(w.matches_endpoint(&ctx));
        for index in 0..7 {
            let mut bad = ctx.clone();
            match index {
                0 => bad.pid += 1,
                1 => bad.process = "foreign".into(),
                2 => bad.target_starttime = Some(99),
                3 => bad.resident_generation_id = "d".repeat(64),
                4 => bad.active_generation_id = "d".repeat(64),
                5 => bad.resident_catalog_sha256 = "d".repeat(64),
                _ => bad.active_catalog_sha256 = "d".repeat(64),
            }
            assert!(!w.matches_endpoint(&bad));
        }
        let mut bytes = serde_json::to_vec(&w).unwrap();
        bytes.push(b'\n');
        assert_eq!(decode(&bytes), Some(w.clone()));
        assert!(decode(&bytes[..bytes.len() - 1]).is_none());
        let now = positive(&w.expires_monotonic_ms).unwrap();
        assert!(w.matches_lifetime(now - 1, &w.boot_id, true));
        assert!(!w.matches_lifetime(now - 1, &w.boot_id, false));
        assert!(!w.matches_lifetime(now, &w.boot_id, true));
        assert!(!w.matches_lifetime(now - 1, "other-boot", true));
    }

    #[test]
    fn native_window_requires_its_current_owner_writer_and_exact_fixed_kind() {
        for kind in [
            Kind::NativeStateReadUnavailable,
            Kind::NativeStateWriteUnavailable,
        ] {
            let window = window(kind, 42);
            assert_eq!(window.kind.process(), "com.qinggan.canbus.service");
            assert!(window.valid());
            let mut missing = window.clone();
            missing.owner_writer_id = None;
            assert!(!missing.valid());
            let mut malformed = window.clone();
            malformed.owner_writer_id = Some("e".repeat(31));
            assert!(!malformed.valid());
            let mut bytes = serde_json::to_vec(&window).unwrap();
            bytes.push(b'\n');
            assert_eq!(decode(&bytes), Some(window));
        }
        let mut old = window(Kind::VehicleStateReplyLoss, 42);
        old.owner_writer_id = Some("d".repeat(32));
        assert!(!old.valid());
    }

    #[test]
    fn operator_lease_requires_exact_ofd_kernel_identity() {
        assert!(kernel_operator_lease(libc::F_WRLCK as _, -1, 0, 1));
        assert!(!kernel_operator_lease(libc::F_UNLCK as _, -1, 0, 1));
        assert!(!kernel_operator_lease(libc::F_RDLCK as _, -1, 0, 1));
        assert!(!kernel_operator_lease(libc::F_WRLCK as _, 42, 0, 1));
        assert!(!kernel_operator_lease(libc::F_WRLCK as _, -1, 1, 1));
        assert!(!kernel_operator_lease(libc::F_WRLCK as _, -1, 0, 0));
        assert!(!kernel_operator_lease(libc::F_WRLCK as _, -1, 0, 2));
    }

    #[test]
    fn old_reader_rejects_republished_marker_even_with_reused_pid() {
        let directory = tempfile::tempdir().unwrap();
        let run = Directory::open(directory.path()).unwrap();
        let window = window(Kind::VehicleStateReplyLoss, 42);
        let mut bytes = serde_json::to_vec(&window).unwrap();
        bytes.push(b'\n');
        run.write_atomic(MARKER, &bytes, 0o600).unwrap();
        let (_, old_descriptor) = run.read_trusted_retained(MARKER, MAX_BYTES, 0o600).unwrap();
        let old_inode = old_descriptor.metadata().unwrap().ino();
        assert!(marker_current(&run, &bytes, old_inode));
        // Retaining the old descriptor prevents inode reuse in this fixture.
        run.write_atomic(MARKER, &bytes, 0o600).unwrap();
        assert!(!marker_current(&run, &bytes, old_inode));
        let current_inode = run.metadata_trusted(MARKER, 0o600).unwrap().0;
        let mut replacement = window;
        replacement.token = "f".repeat(64);
        replacement.owner_starttime = "99".into();
        let mut newer = serde_json::to_vec(&replacement).unwrap();
        newer.push(b'\n');
        let mut descriptor = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(directory.path().join(MARKER))
            .unwrap();
        descriptor.write_all(&newer).unwrap();
        assert!(!marker_current(&run, &bytes, current_inode));
    }

    #[test]
    fn window_cleanup_is_inode_bound_and_restores_the_guard() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let run = Directory::open(directory.path()).unwrap();
        let window = window(Kind::StartupMutationLock, 42);
        let mut bytes = serde_json::to_vec(&window).unwrap();
        bytes.push(b'\n');
        let mut marker = run.create_new(OsStr::new(MARKER), 0o600).unwrap();
        marker.write_all(&bytes).unwrap();
        let guard = operation_contract::GenerationGuard::acquire_in(directory.path()).unwrap();
        let owned = OwnedWindow {
            run,
            root: directory.path().to_path_buf(),
            lease: None,
            marker_inode: marker.metadata().unwrap().ino(),
            window: window.clone(),
            generation_guard: Some(guard),
        };
        assert!(operation_contract::GenerationGuard::acquire_in(directory.path()).is_err());
        drop(owned);
        assert!(!directory.path().join(MARKER).exists());
        assert!(operation_contract::GenerationGuard::acquire_in(directory.path()).is_ok());
        let run = Directory::open(directory.path()).unwrap();
        run.write_atomic(MARKER, &bytes, 0o600).unwrap();
        let inode = run.metadata_trusted(MARKER, 0o600).unwrap().0;
        run.unlink(MARKER).unwrap();
        let foreign = directory.path().join("foreign");
        fs::write(&foreign, b"private").unwrap();
        symlink(&foreign, directory.path().join(MARKER)).unwrap();
        let owned = OwnedWindow {
            run,
            root: directory.path().to_path_buf(),
            lease: None,
            marker_inode: inode,
            window,
            generation_guard: None,
        };
        assert!(owned.remove_marker().is_err());
        drop(owned);
        assert_eq!(fs::read(&foreign).unwrap(), b"private");
        assert!(fs::symlink_metadata(directory.path().join(MARKER))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn cleanup_waits_for_the_same_generation_lock_as_admission() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let run = Directory::open(directory.path()).unwrap();
        let window = window(Kind::VehicleStateReplyLoss, 42);
        let mut bytes = serde_json::to_vec(&window).unwrap();
        bytes.push(b'\n');
        run.write_atomic(MARKER, &bytes, 0o600).unwrap();
        let owned = OwnedWindow {
            marker_inode: run.metadata_trusted(MARKER, 0o600).unwrap().0,
            run,
            root: directory.path().to_path_buf(),
            lease: None,
            window,
            generation_guard: None,
        };
        let admission = operation_contract::GenerationGuard::acquire_in(directory.path()).unwrap();
        let (sent, received) = std::sync::mpsc::channel();
        let cleanup = std::thread::spawn(move || {
            sent.send(owned.remove_marker()).unwrap();
        });
        assert!(received
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err());
        assert!(directory.path().join(MARKER).exists());
        drop(admission);
        received
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap()
            .unwrap();
        cleanup.join().unwrap();
        assert!(!directory.path().join(MARKER).exists());
    }

    #[test]
    fn state_reply_loss_is_owned_and_does_not_mutate_storage() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let leaf = state.join("vehicle-drive-forced-ev_forced-ev-armed.json");
        fs::write(&leaf, b"true\n").unwrap();
        fs::set_permissions(&leaf, fs::Permissions::from_mode(0o600)).unwrap();
        let (mut reader, writer) = std::os::unix::net::UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        let w = window(Kind::VehicleStateReplyLoss, 42);
        let ctx = context(&w);
        TEST_WINDOW.with(|value| value.replace(Some(w.clone())));
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                TEST_WINDOW.with(|v| v.replace(None));
            }
        }
        let _reset = Reset;
        assert_eq!(
            crate::agent_state::route_read_fixture(
                &state,
                "7|vehicle-drive-forced-ev|forced-ev-armed",
                writer.as_raw_fd(),
                &ctx
            ),
            Some(1)
        );
        let mut buffer = [0u8; 64];
        assert_eq!(
            reader.read(&mut buffer).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(fs::read(&leaf).unwrap(), b"true\n");
        let mut old_target = ctx.clone();
        old_target.process = "com.qinggan.systemservice".into();
        assert!(!drop_state_reply(
            "vehicle-drive-forced-ev",
            "forced-ev-armed",
            &old_target,
            8
        ));
        assert!(!drop_state_reply("settings", "forced-ev-armed", &ctx, 8));
        assert!(!drop_state_reply(
            "vehicle-drive-forced-ev",
            "arbitrary",
            &ctx,
            8
        ));
        let mut wrong = ctx.clone();
        wrong.pid += 1;
        assert!(!drop_state_reply(
            "vehicle-drive-forced-ev",
            "forced-ev-armed",
            &wrong,
            8
        ));
        TEST_WINDOW.with(|value| value.replace(None));
        assert_eq!(
            crate::agent_state::route_read_fixture(
                &state,
                "9|vehicle-drive-forced-ev|forced-ev-armed",
                writer.as_raw_fd(),
                &ctx
            ),
            Some(1)
        );
        crate::downlink::flush(writer.as_raw_fd());
        let count = reader.read(&mut buffer).unwrap();
        assert_eq!(&buffer[..count], b"R|9|ok|true\n");
        assert_eq!(fs::read(&leaf).unwrap(), b"true\n");
    }

    #[test]
    fn uninstall_loss_is_after_peer_authority_and_one_shot() {
        crate::canonical_log::diagnostic_uninstall_test();
    }
}
