//! Root-only, correlated launcher observation over the resident common transport.
use crate::agent_log::EndpointContext;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const PROCESS: &str = "com.qinggan.app.launcher";
const MAX_RESPONSE: usize = 16 * 1024;
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Command {
    schema_version: u32,
    operation: String,
    request_id: String,
    generation_id: String,
    catalog_sha256: String,
    document_generation: i64,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Observation {
    outer_current_item: i32,
    first_position: i32,
    page_count: i32,
    offset_x: i32,
    item_count: i32,
    scroll_state: i32,
    computing_layout: bool,
    window: Window,
    grid: Grid,
    items: Vec<Item>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Window {
    activity_class: String,
    window_type: i32,
    display_id: i32,
    focused: bool,
    attached: bool,
    shown: bool,
    token: String,
    bounds: [i32; 4],
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Grid {
    resource: String,
    class_name: String,
    layout_manager_class: String,
    bounds: [i32; 4],
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Item {
    position: i32,
    label: String,
    bounds: [i32; 4],
}
fn valid_bounds(b: &[i32; 4]) -> bool {
    b[2] > b[0] && b[3] > b[1]
}
impl Observation {
    fn valid(&self) -> bool {
        let mut positions = HashSet::new();
        self.outer_current_item == 1
            && self.first_position >= 0
            && self.first_position < self.item_count
            && self.page_count > 0
            && self.page_count == (self.item_count - 1) / 12 + 1
            && self.first_position % 12 == 0
            && self.offset_x >= 0
            && self.scroll_state == 0
            && !self.computing_layout
            && self.window.display_id == 0
            && self.window.activity_class == "com.qinggan.app.launcher.activity.MainActivity"
            && self.window.window_type == 1
            && self.window.focused
            && self.window.attached
            && self.window.shown
            && !self.window.token.is_empty()
            && self.window.token.chars().count() <= 256
            && valid_bounds(&self.window.bounds)
            && valid_bounds(&self.grid.bounds)
            && self.grid.resource == "com.qinggan.app.launcher:id/all_app_view"
            && self.grid.class_name == "com.qinggan.launcher.base.allapp.AllAppBarView"
            && self.grid.layout_manager_class
                == "com.qinggan.launcher.base.custom.PagerGridLayoutManager"
            && !self.items.is_empty()
            && self.items.len() <= 48
            && self.items.iter().all(|item| {
                item.position >= 0
                    && item.position < self.item_count
                    && positions.insert(item.position)
                    && item.label.chars().count() <= 256
                    && valid_bounds(&item.bounds)
            })
    }
}
fn boot_ms() -> Option<u64> {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    let clock = libc::CLOCK_BOOTTIME;
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    let clock = libc::CLOCK_MONOTONIC;
    let mut time: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(clock, &mut time) } != 0 || time.tv_sec < 0 {
        return None;
    }
    (time.tv_sec as u64)
        .checked_mul(1000)?
        .checked_add(time.tv_nsec as u64 / 1_000_000)
}
fn same_daemon(
    a: &crate::control_plane::DaemonIdentity,
    b: &crate::control_plane::DaemonIdentity,
) -> bool {
    a.boot_id == b.boot_id
        && a.daemon_pid == b.daemon_pid
        && a.daemon_starttime == b.daemon_starttime
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Response {
    schema_version: u32,
    operation: String,
    request_id: String,
    generation_id: String,
    catalog_sha256: String,
    document_generation: i64,
    outcome: String,
    reason: String,
    capture_started_boot_ms: u64,
    capture_finished_boot_ms: u64,
    observation: Option<Observation>,
}
struct Pending {
    request_id: String,
    started: Instant,
    bound: Option<(Command, EndpointContext, u64)>,
    identity: crate::control_plane::DaemonIdentity,
    response: Option<String>,
}
fn state() -> &'static (Mutex<Option<Pending>>, Condvar) {
    static STATE: OnceLock<(Mutex<Option<Pending>>, Condvar)> = OnceLock::new();
    STATE.get_or_init(|| (Mutex::new(None), Condvar::new()))
}
pub fn valid_nonce(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn request(request_id: &str) -> Result<String, String> {
    if !valid_nonce(request_id) {
        return Err("invalid observation nonce".into());
    }
    let identity = crate::control_plane::daemon_identity().ok_or("daemon identity unavailable")?;
    static SEEN: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let mut seen = SEEN
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .map_err(|_| "observation nonce lock poisoned")?;
    if seen.len() >= 4096 || seen.contains(request_id) {
        return Err("observation nonce replay or capacity".into());
    }
    let (lock, ready) = state();
    let mut all = lock.lock().map_err(|_| "observation lock poisoned")?;
    if all.is_some() {
        return Err("observation busy".into());
    }
    seen.insert(request_id.to_owned());
    drop(seen);
    *all = Some(Pending {
        request_id: request_id.into(),
        started: Instant::now(),
        bound: None,
        identity,
        response: None,
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(response) = all.as_mut().and_then(|p| p.response.take()) {
            *all = None;
            return Ok(response);
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            *all = None;
            return Err("observation timeout".into());
        };
        all = ready
            .wait_timeout(all, remaining)
            .map_err(|_| "observation lock poisoned")?
            .0;
    }
}
pub fn dispatch(context: &EndpointContext, fd: i32) {
    let Ok(mut all) = state().0.lock() else {
        return;
    };
    let Some(p) = all.as_mut() else {
        return;
    };
    if p.bound.is_some()
        || p.started.elapsed() >= Duration::from_secs(5)
        || context.process != PROCESS
        || context.pid <= 1
        || context.endpoint_epoch == 0
        || context.target_starttime.is_none()
        || context.document_generation.unwrap_or(0) <= 0
        || context.resident_generation_id.is_empty()
        || context.resident_generation_id.len() > 128
        || !valid_nonce(&context.resident_catalog_sha256)
        || crate::target_identity::read_starttime(context.pid).ok() != context.target_starttime
    {
        return;
    }
    let command = Command {
        schema_version: 1,
        operation: "launcher-page-observe".into(),
        request_id: p.request_id.clone(),
        generation_id: context.resident_generation_id.clone(),
        catalog_sha256: context.resident_catalog_sha256.clone(),
        document_generation: context.document_generation.unwrap(),
    };
    let Ok(json) = serde_json::to_string(&command) else {
        return;
    };
    let Some(dispatched) = boot_ms() else {
        return;
    };
    if crate::downlink::enqueue_frame(fd, format!("P|{json}\n").as_bytes()) {
        p.bound = Some((command, context.clone(), dispatched));
    }
}
fn same_endpoint(a: &EndpointContext, b: &EndpointContext) -> bool {
    a.process == b.process
        && a.pid == b.pid
        && a.target_starttime == b.target_starttime
        && a.endpoint_epoch == b.endpoint_epoch
        && a.resident_generation_id == b.resident_generation_id
        && a.resident_catalog_sha256 == b.resident_catalog_sha256
        && a.document_generation == b.document_generation
}
fn validate_response(bytes: &str, command: &Command) -> Option<Response> {
    if bytes.len() > MAX_RESPONSE
        || serde_json::from_str::<crate::strict_json::StrictValue>(bytes).is_err()
    {
        return None;
    }
    let raw: Value = serde_json::from_str(bytes).ok()?;
    if raw.get("observation").is_some_and(Value::is_null) {
        return None;
    }
    let r: Response = serde_json::from_str(bytes).ok()?;
    if r.schema_version != command.schema_version
        || r.operation != command.operation
        || r.request_id != command.request_id
        || r.generation_id != command.generation_id
        || r.catalog_sha256 != command.catalog_sha256
        || r.document_generation != command.document_generation
        || r.capture_finished_boot_ms < r.capture_started_boot_ms
    {
        return None;
    }
    match r.outcome.as_str() {
        "observed"
            if r.reason == "observed" && r.observation.as_ref().is_some_and(Observation::valid) => {
        }
        "unavailable"
            if r.observation.is_none()
                && matches!(
                    r.reason.as_str(),
                    "no-activity"
                        | "wrong-process"
                        | "no-grid"
                        | "capture-failed"
                        | "timeout"
                        | "unstable"
                        | "binding-mismatch"
                ) => {}
        _ => return None,
    }
    Some(r)
}
fn capture_window_valid(dispatched: u64, started: u64, finished: u64, received: u64) -> bool {
    dispatched <= started && started <= finished && finished <= received
}
pub fn observe(bytes: &str, context: &EndpointContext) -> Option<usize> {
    let (lock, ready) = state();
    let mut all = lock.lock().ok()?;
    let p = all.as_mut()?;
    let (command, original, dispatched) = p.bound.as_ref()?;
    if p.response.is_some()
        || p.started.elapsed() >= Duration::from_secs(5)
        || !same_endpoint(original, context)
        || crate::target_identity::read_starttime(context.pid).ok() != context.target_starttime
    {
        return None;
    }
    let r = validate_response(bytes, command)?;
    let identity = crate::control_plane::daemon_identity()?;
    if !same_daemon(&p.identity, &identity)
        || !capture_window_valid(
            *dispatched,
            r.capture_started_boot_ms,
            r.capture_finished_boot_ms,
            boot_ms()?,
        )
    {
        return None;
    }
    let mut receipt = json!({"schemaVersion":1,"requestId":r.request_id,"bootId":identity.boot_id,
        "daemonPid":identity.daemon_pid,"daemonStarttime":identity.daemon_starttime,
        "targetPid":context.pid.to_string(),"targetStarttime":context.target_starttime?.to_string(),
        "endpointEpoch":context.endpoint_epoch.to_string(),"generationId":r.generation_id,
        "catalogSha256":r.catalog_sha256,"documentGeneration":r.document_generation,
        "outcome":r.outcome,"reason":r.reason,"captureStartedBootMs":r.capture_started_boot_ms,
        "captureFinishedBootMs":r.capture_finished_boot_ms,"observation":r.observation});
    if receipt["outcome"] == "unavailable" {
        receipt.as_object_mut()?.remove("observation");
    }
    p.response = Some(receipt.to_string());
    ready.notify_one();
    Some(1)
}
fn io_stage<E: std::fmt::Display>(stage: &'static str) -> impl FnOnce(E) -> std::io::Error {
    move |error| std::io::Error::other(format!("launcher-page stage={stage}: {error}"))
}

// The installed management executable may remain in su on /data nosuid.
// Use the existing root-owned management file authority, never grant su
// access to the runtime's stream socket or relabel/transition the caller.
const RELAY_CHILD: &str = "launcher-observe";
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RelayRequest {
    request_id: String,
    daemon_pid: i32,
    daemon_starttime: u64,
    boot_id: String,
    deadline_boot_ms: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RelayResponse {
    request_id: String,
    boot_id: String,
    expires_boot_ms: u64,
    receipt: Option<String>,
    error: Option<String>,
}
fn relay_root() -> std::io::Result<crate::secure_fs::Directory> {
    let root = crate::secure_fs::Directory::open(std::path::Path::new(crate::config::ROOT_ZONE))?;
    root.validate_owner_mode(0, 0, 0o755)?;
    let run = root.open_child("run")?;
    run.validate_owner_mode(0, 0, crate::config::RUN_DIR_MODE)?;
    Ok(run)
}
fn relay_directory(create: bool) -> std::io::Result<crate::secure_fs::Directory> {
    let run = relay_root()?;
    let dir = if create {
        run.open_or_create_private_child(RELAY_CHILD)?
    } else {
        run.open_child(RELAY_CHILD)?
    };
    dir.validate_owner_mode(0, 0, 0o700)?;
    Ok(dir)
}
fn relay_name(prefix: &str, nonce: &str) -> String {
    format!("{prefix}-{nonce}.json")
}
fn request_nonce(name: &str) -> Option<&str> {
    name.strip_prefix("request-")?
        .strip_suffix(".json")
        .filter(|s| valid_nonce(s))
}
fn relay_request_valid(
    r: &RelayRequest,
    nonce: &str,
    identity: &crate::control_plane::DaemonIdentity,
    now: u64,
) -> bool {
    valid_nonce(nonce)
        && r.request_id == nonce
        && identity.daemon_pid.parse::<i32>().ok() == Some(r.daemon_pid)
        && identity.daemon_starttime.parse::<u64>().ok() == Some(r.daemon_starttime)
        && r.boot_id == identity.boot_id
        && r.deadline_boot_ms > now
        && r.deadline_boot_ms.saturating_sub(now) <= 7000
}
// File authority authenticates the resident within the existing trusted-root
// management boundary. It is not SO_PEERCRED or an independent remote-exe
// attestation: only the resident verifies its own running executable.
const AUTHORITY_FILE: &str = "launcher-observe-authority.json";
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RelayAuthority {
    schema_version: u32,
    daemon_pid: i32,
    daemon_starttime: u64,
    boot_id: String,
    manifest_sha256: String,
    executable_sha256: String,
    producer_context: String,
}
fn relay_authority_from_manifest(
    identity: crate::control_plane::DaemonIdentity,
    producer_context: &[u8],
    mut load: impl FnMut() -> std::io::Result<voboost_contract::release::Manifest>,
    verify: impl FnOnce(&voboost_contract::release::Artifact) -> std::io::Result<()>,
) -> std::io::Result<RelayAuthority> {
    if !runtime_context(producer_context) {
        return Err(std::io::Error::other(
            "authority producer self-domain mismatch",
        ));
    }
    // One authenticated snapshot supplies both verification and publication.
    // Loading again after self verification can mix product A with product B.
    let manifest = load()?;
    let artifact = manifest
        .artifact("voboost-inject")
        .map_err(io_stage("authority-artifact"))?;
    verify(artifact)?;
    Ok(RelayAuthority {
        schema_version: 2,
        producer_context: "u:r:voboost:s0".into(),
        daemon_pid: identity
            .daemon_pid
            .parse()
            .map_err(io_stage("authority-self-pid"))?,
        daemon_starttime: identity
            .daemon_starttime
            .parse()
            .map_err(io_stage("authority-self-starttime"))?,
        boot_id: identity.boot_id,
        manifest_sha256: manifest
            .digest()
            .map_err(io_stage("authority-manifest-digest"))?,
        executable_sha256: artifact.sha256.clone(),
    })
}
fn publish_relay_authority() -> std::io::Result<()> {
    crate::management::authorize_stable_cli().map_err(io_stage("authority-self-role"))?;
    let identity = crate::control_plane::daemon_identity()
        .ok_or_else(|| std::io::Error::other("resident identity unavailable"))?;
    let producer_context = read_current_thread_context_with(read_bounded, current_native_thread_id)
        .map_err(io_stage("authority-self-domain"))?;
    let authority = relay_authority_from_manifest(
        identity,
        &producer_context,
        || crate::installed_product::load_manifest().map_err(io_stage("authority-manifest")),
        |artifact| {
            crate::native_binary::verify_running(
                std::path::Path::new("/proc/self/exe"),
                usize::try_from(artifact.size).map_err(io_stage("authority-self-size"))?,
                &artifact.sha256,
            )
            .map_err(io_stage("authority-self-product"))
        },
    )?;
    let run = relay_root()?;
    verify_pidfile_lock(&run, authority.daemon_pid)?;
    run.write_atomic(AUTHORITY_FILE, &serde_json::to_vec(&authority)?, 0o600)
}

fn read_bounded(path: &str, limit: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(std::io::Error::other("authority input exceeds bound"));
    }
    Ok(bytes)
}
fn current_native_thread_id() -> std::io::Result<u32> {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        u32::try_from(tid)
            .ok()
            .filter(|tid| *tid > 0)
            .ok_or_else(|| std::io::Error::other("current native thread id unavailable"))
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "current native thread id requires Android or Linux",
        ))
    }
}
fn read_current_thread_context_with(
    mut read: impl FnMut(&str, usize) -> std::io::Result<Vec<u8>>,
    own_tid: impl FnOnce() -> std::io::Result<u32>,
) -> std::io::Result<Vec<u8>> {
    // /proc/self names the thread-group leader. A worker must inspect its
    // own task, as libselinux getcon does, without cross-task GETATTR rights.
    match read("/proc/thread-self/attr/current", 256) {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let tid = own_tid()?;
            if tid == 0 {
                return Err(std::io::Error::other("invalid current native thread id"));
            }
            read(&format!("/proc/self/task/{tid}/attr/current"), 256)
        }
        Err(error) => Err(error),
    }
}
fn runtime_context(bytes: &[u8]) -> bool {
    let bytes = bytes
        .strip_suffix(b"\n")
        .or_else(|| bytes.strip_suffix(&[0]))
        .unwrap_or(bytes);
    bytes == b"u:r:voboost:s0"
}
fn root_uids(text: &str) -> bool {
    let mut fields = text.lines().filter_map(|line| line.strip_prefix("Uid:"));
    let Some(value) = fields.next() else {
        return false;
    };
    fields.next().is_none()
        && value.split_ascii_whitespace().collect::<Vec<_>>() == ["0", "0", "0", "0"]
}
fn locked_by_pid(text: &str, pid: i32, major: u64, minor: u64, inode: u64) -> bool {
    let mut matches = 0;
    for line in text.lines() {
        let parts = line.split_ascii_whitespace().collect::<Vec<_>>();
        // Blocked waiters contain an additional -> token and are not owners.
        if parts.len() != 8 || parts[1..4] != ["FLOCK", "ADVISORY", "WRITE"] {
            continue;
        }
        let node = parts[5].split(':').collect::<Vec<_>>();
        if node.len() != 3 {
            continue;
        }
        if u64::from_str_radix(node[0], 16).ok() == Some(major)
            && u64::from_str_radix(node[1], 16).ok() == Some(minor)
            && node[2].parse::<u64>().ok() == Some(inode)
        {
            if parts[4].parse::<i32>().ok() != Some(pid) || parts[6..8] != ["0", "EOF"] {
                return false;
            }
            matches += 1;
        }
    }
    matches == 1
}
fn verify_pidfile_lock(run: &crate::secure_fs::Directory, pid: i32) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let (bytes, retained) = run.read_trusted_retained(crate::config::PID_NAME, 64, 0o600)?;
    if std::str::from_utf8(&bytes)
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        != Some(pid)
    {
        return Err(std::io::Error::other("authority pidfile mismatch"));
    }
    let m = retained.metadata()?;
    let dev = m.dev();
    // Linux dev_t encoding used by /proc/locks; Android is the production host.
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & 0xfffff000);
    let minor = (dev & 0xff) | ((dev >> 12) & 0xffffff00);
    let bytes =
        read_bounded("/proc/locks", 1024 * 1024).map_err(io_stage("authority-kernel-locks"))?;
    if !locked_by_pid(
        std::str::from_utf8(&bytes).map_err(io_stage("authority-locks-utf8"))?,
        pid,
        major,
        minor,
        m.ino(),
    ) {
        return Err(std::io::Error::other(
            "authority resident does not own exact pidfile flock",
        ));
    }
    if run.metadata_trusted(crate::config::PID_NAME, 0o600)? != (m.ino(), m.len()) {
        return Err(std::io::Error::other("authority pidfile was replaced"));
    }
    Ok(())
}
fn validate_relay_authority(
    authority: &RelayAuthority,
    pid: i32,
    starttime: u64,
    boot: &str,
    manifest_sha256: &str,
    executable_sha256: &str,
) -> bool {
    authority.schema_version == 2
        && authority.producer_context == "u:r:voboost:s0"
        && pid > 1
        && starttime > 0
        && !boot.is_empty()
        && authority.daemon_pid == pid
        && authority.daemon_starttime == starttime
        && authority.boot_id == boot
        && authority.manifest_sha256 == manifest_sha256
        && authority.executable_sha256 == executable_sha256
        && valid_nonce(manifest_sha256)
        && valid_nonce(executable_sha256)
}
pub(crate) fn authenticate_relay_server() -> std::io::Result<(i32, u64, String)> {
    let run = relay_root().map_err(io_stage("authority-root"))?;
    let bytes = run
        .read_trusted(crate::config::PID_NAME, 64, 0o600)
        .map_err(io_stage("authority-pid-file"))?;
    let pid = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        .filter(|p| *p > 1)
        .ok_or_else(|| std::io::Error::other("invalid resident pid"))?;
    let before = crate::target_identity::read_starttime(pid)
        .map_err(io_stage("authority-proc-starttime"))?;
    verify_pidfile_lock(&run, pid)?;
    let status = read_bounded(&format!("/proc/{pid}/status"), 8192)
        .map_err(io_stage("authority-proc-uid"))?;
    if !root_uids(std::str::from_utf8(&status).map_err(io_stage("authority-proc-uid-utf8"))?) {
        return Err(std::io::Error::other("authority resident is not root"));
    }
    let bytes = run
        .read_trusted(AUTHORITY_FILE, 2048, 0o600)
        .map_err(io_stage("authority-root-receipt"))?;
    serde_json::from_slice::<crate::strict_json::StrictValue>(&bytes)
        .map_err(io_stage("authority-duplicate-fields"))?;
    let authority: RelayAuthority =
        serde_json::from_slice(&bytes).map_err(io_stage("authority-receipt-shape"))?;
    let manifest =
        crate::installed_product::load_manifest().map_err(io_stage("authority-signed-manifest"))?;
    let digest = manifest
        .digest()
        .map_err(io_stage("authority-manifest-digest"))?;
    let artifact = manifest
        .artifact("voboost-inject")
        .map_err(io_stage("authority-artifact"))?;
    // Independently verify the installed stable file, not /proc/<other>/exe.
    crate::native_binary::verify_running(
        std::path::Path::new("/data/voboost/voboost-inject"),
        usize::try_from(artifact.size).map_err(io_stage("authority-artifact-size"))?,
        &artifact.sha256,
    )
    .map_err(io_stage("authority-installed-executable"))?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(io_stage("authority-boot-id"))?;
    let boot = boot.trim();
    let after = crate::target_identity::read_starttime(pid)
        .map_err(io_stage("authority-proc-starttime-after"))?;
    verify_pidfile_lock(&run, pid)?;
    if before != after
        || !validate_relay_authority(&authority, pid, before, boot, &digest, &artifact.sha256)
    {
        return Err(std::io::Error::other(
            "authority resident identity mismatch",
        ));
    }
    Ok((pid, before, boot.to_owned()))
}

fn relay_query(nonce: &str) -> std::io::Result<String> {
    let authority = authenticate_relay_server().map_err(io_stage("relay-server-authority"))?;
    let dir = relay_directory(true).map_err(io_stage("relay-directory"))?;
    relay_query_authorized(&dir, nonce, authority, authenticate_relay_server)
}
fn relay_query_authorized(
    dir: &crate::secure_fs::Directory,
    nonce: &str,
    authority: (i32, u64, String),
    verify_server: impl Fn() -> std::io::Result<(i32, u64, String)>,
) -> std::io::Result<String> {
    let (pid, start, boot) = authority;
    let _lock = dir
        .lock_transaction(Duration::from_millis(100))
        .map_err(io_stage("relay-busy"))?;
    let request_name = relay_name("request", nonce);
    let response_name = relay_name("response", nonce);
    if dir.entry_exists(&request_name)? || dir.entry_exists(&response_name)? {
        return Err(std::io::Error::other("observation nonce already published"));
    }
    let deadline = boot_ms()
        .and_then(|v| v.checked_add(7000))
        .ok_or_else(|| std::io::Error::other("boot clock unavailable"))?;
    let request = RelayRequest {
        request_id: nonce.into(),
        daemon_pid: pid,
        daemon_starttime: start,
        boot_id: boot.clone(),
        deadline_boot_ms: deadline,
    };
    dir.write_atomic(&request_name, &serde_json::to_vec(&request)?, 0o600)?;
    let result = (|| {
        let timeout = Instant::now() + Duration::from_secs(7);
        loop {
            // Check the absolute request deadline before accepting an already
            // available reply after host descheduling or device suspend.
            if Instant::now() >= timeout || boot_ms().unwrap_or(u64::MAX) >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "observation relay timeout",
                ));
            }
            match dir.read_trusted(&response_name, 32 * 1024, 0o600) {
                Ok(bytes) => {
                    if serde_json::from_slice::<crate::strict_json::StrictValue>(&bytes).is_err() {
                        return Err(std::io::Error::other("duplicate relay response fields"));
                    }
                    let response: RelayResponse = serde_json::from_slice(&bytes)?;
                    if response.request_id != nonce
                        || response.boot_id != boot
                        || boot_ms().unwrap_or(u64::MAX) >= response.expires_boot_ms
                    {
                        return Err(std::io::Error::other("relay response nonce mismatch"));
                    }
                    let receipt = match (response.receipt, response.error) {
                        (Some(receipt), None) => receipt,
                        (None, Some(error)) => return Err(std::io::Error::other(error)),
                        _ => return Err(std::io::Error::other("invalid relay response outcome")),
                    };
                    let value: Value = serde_json::from_str(&receipt)?;
                    if value["requestId"] != nonce
                        || value["daemonPid"]
                            .as_str()
                            .and_then(|v| v.parse::<i32>().ok())
                            != Some(pid)
                        || value["daemonStarttime"]
                            .as_str()
                            .and_then(|v| v.parse::<u64>().ok())
                            != Some(start)
                        || value["bootId"] != boot
                        || verify_server()? != (pid, start, boot.clone())
                    {
                        return Err(std::io::Error::other(
                            "observation server receipt identity mismatch",
                        ));
                    }
                    return Ok(receipt);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            if Instant::now() >= timeout {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "observation relay timeout",
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    })();
    let _ = dir.unlink(&request_name);
    let _ = dir.unlink(&response_name);
    result
}
fn consume_relay_requests() -> std::io::Result<()> {
    let dir = relay_directory(false)?;
    let identity = crate::control_plane::daemon_identity()
        .ok_or_else(|| std::io::Error::other("resident identity unavailable"))?;
    consume_relay_requests_authorized(&dir, &identity, request)
}
fn consume_relay_requests_authorized(
    dir: &crate::secure_fs::Directory,
    identity: &crate::control_plane::DaemonIdentity,
    capture: impl Fn(&str) -> Result<String, String>,
) -> std::io::Result<()> {
    for name in dir.entry_names_bounded(128)? {
        if let Some(nonce) = name
            .strip_prefix("response-")
            .and_then(|s| s.strip_suffix(".json"))
            .filter(|s| valid_nonce(s))
        {
            let bytes = dir.read_trusted(&name, 32 * 1024, 0o600)?;
            if let Ok(response) = serde_json::from_slice::<RelayResponse>(&bytes) {
                if response.request_id == nonce
                    && (response.boot_id != identity.boot_id
                        || boot_ms().unwrap_or(u64::MAX) >= response.expires_boot_ms)
                {
                    dir.unlink(&name)?;
                }
            }
            continue;
        }
        let Some(nonce) = request_nonce(&name) else {
            continue;
        };
        let bytes = dir.read_trusted(&name, 1024, 0o600)?;
        // Consume this unique immutable nonce before blocking for the Java reply.
        dir.unlink(&name)?;
        let result = if serde_json::from_slice::<crate::strict_json::StrictValue>(&bytes).is_err() {
            Err("duplicate relay request fields".into())
        } else {
            serde_json::from_slice::<RelayRequest>(&bytes)
                .map_err(|_| "invalid relay request".to_string())
                .and_then(|r| {
                    if !relay_request_valid(&r, nonce, identity, boot_ms().unwrap_or(u64::MAX)) {
                        Err("expired or foreign resident observation request".into())
                    } else {
                        capture(nonce)
                    }
                })
        };
        let response = match result {
            Ok(receipt) => RelayResponse {
                request_id: nonce.into(),
                boot_id: identity.boot_id.clone(),
                expires_boot_ms: boot_ms().unwrap_or(0).saturating_add(7000),
                receipt: Some(receipt),
                error: None,
            },
            Err(error) => RelayResponse {
                request_id: nonce.into(),
                boot_id: identity.boot_id.clone(),
                expires_boot_ms: boot_ms().unwrap_or(0).saturating_add(7000),
                receipt: None,
                error: Some(error),
            },
        };
        let bytes = serde_json::to_vec(&response)?;
        if bytes.len() <= 32 * 1024 {
            dir.write_atomic(&relay_name("response", nonce), &bytes, 0o600)?;
        }
    }
    Ok(())
}
#[derive(Default)]
struct AuthorityDiagnostics {
    last_cause: Option<String>,
    next_log: Option<Instant>,
}
impl AuthorityDiagnostics {
    fn failure(&mut self, error: &str, now: Instant) -> Option<(bool, String)> {
        if self.next_log.is_some_and(|next| now < next) {
            return None;
        }
        let cause = error
            .chars()
            .take(256)
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect::<String>();
        let changed = self.last_cause.as_ref() != Some(&cause);
        self.last_cause = Some(cause.clone());
        self.next_log = Some(now + Duration::from_secs(30));
        Some((changed, cause))
    }
}
fn report_authority_failure(
    diagnostics: &mut AuthorityDiagnostics,
    error: &std::io::Error,
    now: Instant,
) {
    if let Some((changed, cause)) = diagnostics.failure(&error.to_string(), now) {
        if changed {
            crate::log::info(
                "launcher-observe",
                &format!("launcher observation authority unavailable: {cause}"),
            );
        } else {
            crate::log::debug(
                "launcher-observe",
                &format!("launcher observation authority still unavailable: {cause}"),
            );
        }
    }
}
fn report_authority_ready() {
    crate::log::info(
        "launcher-observe",
        "launcher observation authority ready: schema=2 producer=runtime-self-attested",
    );
}
// Process-owned, initialized once through the resident singleton/log init.
// Like the existing socket ingress, process exit ends this worker.
pub fn start_management_relay() -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("launcher-observe-relay".into())
        .spawn(|| {
            // Optional observation admission must not prevent vehicle startup.
            // Failed authority remains unavailable; there is no weak fallback.
            let mut diagnostics = AuthorityDiagnostics::default();
            while let Err(error) = publish_relay_authority() {
                report_authority_failure(&mut diagnostics, &error, Instant::now());
                std::thread::sleep(Duration::from_secs(5));
            }
            report_authority_ready();
            loop {
                let _ = consume_relay_requests();
                std::thread::sleep(Duration::from_millis(250));
            }
        })?;
    Ok(())
}
pub fn handle_cli() -> Option<i32> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().map(String::as_str) != Some("--observe-launcher-page") {
        return None;
    }
    if args.len() != 2 || !valid_nonce(&args[1]) || unsafe { libc::geteuid() } != 0 {
        return Some(2);
    }
    if crate::management::authorize_stable_cli()
        .and_then(|()| crate::management::authorize_active_product_self())
        .is_err()
    {
        return Some(126);
    }
    let result = relay_query(&args[1]);
    Some(match result {
        Ok(value) => {
            println!("{value}");
            0
        }
        Err(error) => {
            crate::log::err("launcher_page", &format!("{error}"));
            1
        }
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn producer_context_reader_targets_current_worker_not_group_leader() {
        let leader = std::thread::current().id();
        std::thread::spawn(move || {
            let worker = std::thread::current().id();
            assert_ne!(worker, leader);
            let bytes = read_current_thread_context_with(
                |path, bound| {
                    assert_eq!(bound, 256);
                    // Fault injection models the pinned kernel's current!=p
                    // check: TGID leader needs GETATTR; current worker does not.
                    if path == "/proc/self/attr/current" {
                        return Err(std::io::Error::from_raw_os_error(13));
                    }
                    assert_eq!(path, "/proc/thread-self/attr/current");
                    Ok(b"u:r:voboost:s0".to_vec())
                },
                || panic!("available thread-self must not query a numeric TID"),
            )
            .unwrap();
            assert!(runtime_context(&bytes));
        })
        .join()
        .unwrap();
    }
    #[test]
    fn producer_context_fallback_is_enoent_only_and_exact_own_tid() {
        let mut paths = Vec::new();
        let bytes = read_current_thread_context_with(
            |path, bound| {
                assert_eq!(bound, 256);
                paths.push(path.to_owned());
                if paths.len() == 1 {
                    Err(std::io::Error::from_raw_os_error(2))
                } else {
                    Ok(b"u:r:voboost:s0".to_vec())
                }
            },
            || Ok(456),
        )
        .unwrap();
        assert_eq!(
            paths,
            [
                "/proc/thread-self/attr/current",
                "/proc/self/task/456/attr/current"
            ]
        );
        assert!(runtime_context(&bytes));
        for errno in [13, 1, 5, 22] {
            let mut calls = 0;
            let error = read_current_thread_context_with(
                |_, _| {
                    calls += 1;
                    Err(std::io::Error::from_raw_os_error(errno))
                },
                || panic!("permission/other errors must never fall back"),
            )
            .unwrap_err();
            assert_eq!(calls, 1);
            assert_eq!(error.raw_os_error(), Some(errno));
        }
        assert!(read_current_thread_context_with(
            |_, _| Err(std::io::Error::from_raw_os_error(2)),
            || Ok(0)
        )
        .is_err());
    }
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[test]
    fn linux_thread_self_resolves_actual_worker_tid() {
        std::thread::spawn(|| {
            let tgid = std::process::id();
            let tid = current_native_thread_id().unwrap();
            assert_ne!(tgid, tid);
            assert_eq!(
                std::fs::read_link("/proc/self").unwrap(),
                std::path::PathBuf::from(tgid.to_string())
            );
            assert_eq!(
                std::fs::read_link("/proc/thread-self").unwrap(),
                std::path::PathBuf::from(format!("{tgid}/task/{tid}"))
            );
        })
        .join()
        .unwrap();
    }

    #[test]
    fn authority_diagnostics_reach_canonical_sink_with_bounds_and_throttle() {
        let temp = tempfile::tempdir().unwrap();
        let logs = temp.path().join("logs");
        let now = Instant::now();
        crate::canonical_log::with_test_log(&logs, || {
            let mut diagnostics = AuthorityDiagnostics::default();
            let first =
                std::io::Error::other(format!("authority-self-domain: first\n{}", "x".repeat(500)));
            report_authority_failure(&mut diagnostics, &first, now);
            let second = std::io::Error::other("authority-self-product: changed cause");
            report_authority_failure(&mut diagnostics, &second, now + Duration::from_secs(5));
            report_authority_failure(&mut diagnostics, &second, now + Duration::from_secs(30));
            report_authority_failure(&mut diagnostics, &second, now + Duration::from_secs(60));
            report_authority_ready();
        });
        let text = std::fs::read_to_string(logs.join("segment-active.jsonl")).unwrap_or_default();
        let rows = text
            .lines()
            .map(|line| {
                serde_json::from_str::<crate::canonical_log::CanonicalRecord>(line).unwrap()
            })
            .collect::<Vec<_>>();
        let info = rows
            .iter()
            .filter(|row| row.level == crate::canonical_log::Level::Info)
            .collect::<Vec<_>>();
        assert_eq!(
            info.len(),
            3,
            "first cause, changed cause after throttle, and ready must persist in canonical sink"
        );
        for row in &rows {
            assert_eq!(row.component, "launcher-observe");
            assert_eq!(row.source.kind, "daemon");
            assert!(!row.message.contains('\n'));
            assert!(row.message.chars().count() <= 320);
        }
        assert!(info[0].message.contains("authority-self-domain: first "));
        assert_eq!(
            info[0].message.chars().count(),
            "launcher observation authority unavailable: "
                .chars()
                .count()
                + 256
        );
        assert!(info[1]
            .message
            .contains("authority-self-product: changed cause"));
        assert!(info[2].message.contains("producer=runtime-self-attested"));
        assert!(
            rows.len() == 3 || rows.len() == 4,
            "suppressed changed cause creates no record; repeated cause is debug-filtered"
        );
        if let Some(repeated) = rows
            .iter()
            .find(|row| row.level == crate::canonical_log::Level::Debug)
        {
            assert!(repeated
                .message
                .contains("still unavailable: authority-self-product"));
        }
    }

    #[test]
    fn relay_authority_requires_runtime_self_context_and_closed_schema_two() {
        let manifest = voboost_contract::release::Manifest::parse(include_bytes!(
            "../../test/fixtures/product-release/voboost/valid/minimal.json"
        ))
        .unwrap();
        for context in [b"u:r:su:s0".as_slice(), b"", b"u:r:voboost:s0:c1"] {
            let verified = std::cell::Cell::new(false);
            let outcome = relay_authority_from_manifest(
                crate::control_plane::DaemonIdentity {
                    daemon_pid: "12".into(),
                    daemon_starttime: "34".into(),
                    boot_id: "boot".into(),
                },
                context,
                || Ok(manifest.clone()),
                |_| {
                    verified.set(true);
                    Ok(())
                },
            );
            assert!(outcome.is_err());
            assert!(
                !verified.get(),
                "foreign producer cannot reach authority publication"
            );
        }
        let authority = relay_authority_from_manifest(
            crate::control_plane::DaemonIdentity {
                daemon_pid: "12".into(),
                daemon_starttime: "34".into(),
                boot_id: "boot".into(),
            },
            b"u:r:voboost:s0\0",
            || Ok(manifest.clone()),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(authority.schema_version, 2);
        assert_eq!(authority.producer_context, "u:r:voboost:s0");
        let mut value = serde_json::to_value(&authority).unwrap();
        value.as_object_mut().unwrap().remove("producerContext");
        assert!(serde_json::from_value::<RelayAuthority>(value).is_err());
        let mut unknown = serde_json::to_value(&authority).unwrap();
        unknown["independentPeerSid"] = json!(true);
        assert!(serde_json::from_value::<RelayAuthority>(unknown).is_err());
        let mut old = authority.clone();
        old.schema_version = 1;
        let mut foreign = authority.clone();
        foreign.producer_context = "u:r:su:s0".into();
        for bad in [old, foreign] {
            assert!(!validate_relay_authority(
                &bad,
                12,
                34,
                "boot",
                &manifest.digest().unwrap(),
                &manifest.artifact("voboost-inject").unwrap().sha256
            ));
        }
    }
    #[test]
    fn authority_diagnostics_are_bounded_throttled_and_preserve_changed_causes() {
        let now = Instant::now();
        let mut diagnostics = AuthorityDiagnostics::default();
        let (changed, cause) = diagnostics
            .failure(&format!("first\n{}", "x".repeat(500)), now)
            .unwrap();
        assert!(changed);
        assert_eq!(cause.chars().count(), 256);
        assert!(!cause.contains('\n'));
        assert!(diagnostics
            .failure("second", now + Duration::from_secs(5))
            .is_none());
        assert_eq!(
            diagnostics.failure("second", now + Duration::from_secs(30)),
            Some((true, "second".into()))
        );
        assert_eq!(
            diagnostics.failure("second", now + Duration::from_secs(60)),
            Some((false, "second".into()))
        );
    }

    #[test]
    fn relay_publication_uses_one_manifest_when_product_changes_between_steps() {
        use voboost_contract::release::Manifest;
        let bytes =
            include_bytes!("../../test/fixtures/product-release/voboost/valid/minimal.json");
        let a = Manifest::parse(bytes).unwrap();
        let mut b = a.clone();
        b.artifacts
            .iter_mut()
            .find(|v| v.file == "voboost-inject")
            .unwrap()
            .sha256 = "e".repeat(64);
        let loads = std::cell::Cell::new(0);
        let verified = std::cell::RefCell::new(String::new());
        let authority = relay_authority_from_manifest(
            crate::control_plane::DaemonIdentity {
                daemon_pid: "12".into(),
                daemon_starttime: "34".into(),
                boot_id: "boot".into(),
            },
            b"u:r:voboost:s0",
            || {
                let count = loads.get();
                loads.set(count + 1);
                Ok(if count == 0 { a.clone() } else { b.clone() })
            },
            |artifact| {
                *verified.borrow_mut() = artifact.sha256.clone();
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            loads.get(),
            1,
            "never reload product after self executable verification"
        );
        assert_eq!(authority.manifest_sha256, a.digest().unwrap());
        assert_ne!(authority.manifest_sha256, b.digest().unwrap());
        assert_eq!(authority.executable_sha256, *verified.borrow());
        let rejected = relay_authority_from_manifest(
            crate::control_plane::DaemonIdentity {
                daemon_pid: "12".into(),
                daemon_starttime: "34".into(),
                boot_id: "boot".into(),
            },
            b"u:r:voboost:s0",
            || Ok(b.clone()),
            |_| {
                Err(std::io::Error::other(
                    "new manifest executable does not match running binary",
                ))
            },
        );
        assert!(rejected.is_err());
    }

    #[test]
    fn relay_authority_requires_exact_kernel_lock_owner_and_inode() {
        let good = "12: FLOCK  ADVISORY  WRITE 123 00:2a:987 0 EOF\n";
        assert!(locked_by_pid(good, 123, 0, 42, 987));
        for bad in [
            good.replace("123", "124"),
            good.replace("987", "988"),
            good.replace("00:2a", "00:2b"),
            good.replace("WRITE", "READ"),
            good.replace("FLOCK", "POSIX"),
            good.replace("12:", "12: ->"),
            good.replace("0 EOF", "0 999"),
            format!("{good}{good}"),
        ] {
            assert!(!locked_by_pid(&bad, 123, 0, 42, 987), "{bad}");
        }
        assert!(!locked_by_pid("", 123, 0, 42, 987));
    }
    #[test]
    fn relay_authority_rejects_replayed_identity_and_product() {
        let a = RelayAuthority {
            schema_version: 2,
            producer_context: "u:r:voboost:s0".into(),
            daemon_pid: 123,
            daemon_starttime: 55,
            boot_id: "boot".into(),
            manifest_sha256: "a".repeat(64),
            executable_sha256: "b".repeat(64),
        };
        assert!(validate_relay_authority(
            &a,
            123,
            55,
            "boot",
            &"a".repeat(64),
            &"b".repeat(64)
        ));
        for (pid, start, boot, manifest, exe) in [
            (124, 55, "boot", "a".repeat(64), "b".repeat(64)),
            (123, 56, "boot", "a".repeat(64), "b".repeat(64)),
            (123, 55, "other", "a".repeat(64), "b".repeat(64)),
            (123, 55, "boot", "c".repeat(64), "b".repeat(64)),
            (123, 55, "boot", "a".repeat(64), "c".repeat(64)),
        ] {
            assert!(!validate_relay_authority(
                &a, pid, start, boot, &manifest, &exe
            ));
        }
        assert!(runtime_context(b"u:r:voboost:s0"));
        assert!(runtime_context(b"u:r:voboost:s0\n"));
        for bad in [
            b"u:r:su:s0".as_slice(),
            b"u:r:voboost:s0:c1",
            b"u:r:voboost:s0\n\n",
            b"u:r:voboost:s0\0x",
            b"",
        ] {
            assert!(!runtime_context(bad));
        }
        assert!(root_uids("Name:\tx\nUid:\t0\t0\t0\t0\n"));
        for bad in [
            "Uid: 0 0 0 1",
            "Uid: 0 0 0",
            "Uid: 0 0 0 0\nUid: 0 0 0 0",
            "",
        ] {
            assert!(!root_uids(bad));
        }
    }

    #[test]
    fn relay_client_and_worker_exchange_real_files_and_recheck_incarnation() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let temp = tempfile::tempdir().unwrap();
        let identity = crate::control_plane::DaemonIdentity {
            daemon_pid: "12".into(),
            daemon_starttime: "34".into(),
            boot_id: "boot".into(),
        };
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker_path = temp.path().to_owned();
        let worker = std::thread::spawn(move || {
            let dir = crate::secure_fs::Directory::open(&worker_path).unwrap();
            while !worker_stop.load(Ordering::Acquire) {
                consume_relay_requests_authorized(&dir, &identity, |nonce| Ok(json!({"requestId":nonce,"daemonPid":"12","daemonStarttime":"34","bootId":"boot","outcome":"unavailable","reason":"no-grid"}).to_string())).unwrap();
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        let dir = crate::secure_fs::Directory::open(temp.path()).unwrap();
        let authority = (12, 34, "boot".to_string());
        let nonce = "a".repeat(64);
        let result =
            relay_query_authorized(&dir, &nonce, authority.clone(), || Ok(authority.clone()))
                .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&result).unwrap()["reason"],
            "no-grid"
        );
        assert!(!dir.entry_exists(&relay_name("request", &nonce)).unwrap());
        assert!(!dir.entry_exists(&relay_name("response", &nonce)).unwrap());
        let foreign = relay_query_authorized(&dir, &"b".repeat(64), authority.clone(), || {
            Ok((12, 35, "boot".into()))
        });
        assert!(foreign
            .unwrap_err()
            .to_string()
            .contains("identity mismatch"));
        stop.store(true, Ordering::Release);
        worker.join().unwrap();
    }

    #[test]
    fn relay_production_paths_reject_expiry_replay_busy_and_cleanup_timeout() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let temp = tempfile::tempdir().unwrap();
        let dir = crate::secure_fs::Directory::open(temp.path()).unwrap();
        let identity = crate::control_plane::DaemonIdentity {
            daemon_pid: "12".into(),
            daemon_starttime: "34".into(),
            boot_id: "boot".into(),
        };
        let authority = (12, 34, "boot".to_string());
        let nonce = "c".repeat(64);
        let expired = RelayRequest {
            request_id: nonce.clone(),
            daemon_pid: 12,
            daemon_starttime: 34,
            boot_id: "boot".into(),
            deadline_boot_ms: boot_ms().unwrap(),
        };
        dir.write_atomic(
            &relay_name("request", &nonce),
            &serde_json::to_vec(&expired).unwrap(),
            0o600,
        )
        .unwrap();
        let captures = AtomicUsize::new(0);
        consume_relay_requests_authorized(&dir, &identity, |_| {
            captures.fetch_add(1, Ordering::SeqCst);
            Err("must not run".into())
        })
        .unwrap();
        assert_eq!(captures.load(Ordering::SeqCst), 0);
        let reply: RelayResponse = serde_json::from_slice(
            &dir.read_trusted(&relay_name("response", &nonce), 32768, 0o600)
                .unwrap(),
        )
        .unwrap();
        assert!(reply.receipt.is_none());
        assert!(reply.error.unwrap().contains("expired"));
        assert!(!dir.entry_exists(&relay_name("request", &nonce)).unwrap());
        // A still-retained publication rejects nonce reuse before any write.
        assert!(
            relay_query_authorized(&dir, &nonce, authority.clone(), || Ok(authority.clone()))
                .unwrap_err()
                .to_string()
                .contains("already published")
        );
        let _held = dir.lock_transaction(Duration::from_millis(1)).unwrap();
        assert!(
            relay_query_authorized(&dir, &"d".repeat(64), authority.clone(), || Ok(
                authority.clone()
            ))
            .is_err()
        );
        drop(_held);
        // No worker: exercise the actual seven-second client expiry and cleanup.
        let timeout_nonce = "e".repeat(64);
        let started = Instant::now();
        assert_eq!(
            relay_query_authorized(&dir, &timeout_nonce, authority.clone(), || Ok(
                authority.clone()
            ))
            .unwrap_err()
            .kind(),
            std::io::ErrorKind::TimedOut
        );
        assert!(started.elapsed() >= Duration::from_secs(6));
        assert!(started.elapsed() < Duration::from_secs(9));
        assert!(!dir
            .entry_exists(&relay_name("request", &timeout_nonce))
            .unwrap());
        assert!(!dir
            .entry_exists(&relay_name("response", &timeout_nonce))
            .unwrap());
    }

    #[test]
    fn relay_request_rejects_foreign_expired_and_unbounded_authority() {
        let identity = crate::control_plane::DaemonIdentity {
            daemon_pid: "12".into(),
            daemon_starttime: "34".into(),
            boot_id: "boot".into(),
        };
        let nonce = "a".repeat(64);
        let mut r = RelayRequest {
            request_id: nonce.clone(),
            daemon_pid: 12,
            daemon_starttime: 34,
            boot_id: "boot".into(),
            deadline_boot_ms: 8000,
        };
        assert!(relay_request_valid(&r, &nonce, &identity, 1000));
        assert!(!relay_request_valid(&r, &nonce, &identity, 999));
        assert!(!relay_request_valid(&r, &nonce, &identity, 8000));
        assert!(!relay_request_valid(&r, &"b".repeat(64), &identity, 1000));
        for field in 0..3 {
            let old = (r.daemon_pid, r.daemon_starttime, r.boot_id.clone());
            match field {
                0 => r.daemon_pid += 1,
                1 => r.daemon_starttime += 1,
                _ => r.boot_id = "other".into(),
            };
            assert!(!relay_request_valid(&r, &nonce, &identity, 1000));
            (r.daemon_pid, r.daemon_starttime, r.boot_id) = old;
        }
        let raw = serde_json::to_string(&r).unwrap();
        assert!(
            serde_json::from_str::<RelayRequest>(&raw.replacen('{', "{\"unknown\":1,", 1)).is_err()
        );
        assert!(
            serde_json::from_str::<crate::strict_json::StrictValue>(&raw.replacen(
                '{',
                "{\"daemonPid\":12,",
                1
            ))
            .is_err()
        );
        assert_eq!(
            request_nonce(&relay_name("request", &nonce)),
            Some(nonce.as_str())
        );
        assert!(request_nonce("request-../../evil.json").is_none());
        assert!(request_nonce(&relay_name("response", &nonce)).is_none());
    }
    #[test]
    fn relay_files_are_descriptor_bound_mode_checked_and_serialized() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = crate::secure_fs::Directory::open(temp.path()).unwrap();
        let nonce = "a".repeat(64);
        let name = relay_name("request", &nonce);
        dir.write_atomic(&name, b"bounded", 0o600).unwrap();
        assert_eq!(dir.read_trusted(&name, 7, 0o600).unwrap(), b"bounded");
        assert!(dir.read_trusted(&name, 6, 0o600).is_err());
        std::fs::set_permissions(
            temp.path().join(&name),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(dir.read_trusted(&name, 7, 0o600).is_err());
        dir.unlink(&name).unwrap();
        std::os::unix::fs::symlink("outside", temp.path().join(&name)).unwrap();
        assert!(dir.read_trusted(&name, 7, 0o600).is_err());
        let _held = dir.lock_transaction(Duration::from_millis(10)).unwrap();
        assert!(dir.lock_transaction(Duration::from_millis(10)).is_err());
    }

    #[test]
    fn observer_io_errors_keep_stage_and_cause() {
        let error = io_stage("peer-executable-link")(std::io::Error::from_raw_os_error(13));
        assert_eq!(
            error.to_string(),
            "launcher-page stage=peer-executable-link: Permission denied (os error 13)"
        );
        let string_error = io_stage("connect-daemon-socket")("denied");
        assert_eq!(
            string_error.to_string(),
            "launcher-page stage=connect-daemon-socket: denied"
        );
    }
    #[test]
    fn endpoint_lifetime_daemon_boot_and_capture_fences() {
        let ctx = EndpointContext {
            process: PROCESS.into(),
            pid: 123,
            target_starttime: Some(44),
            endpoint_epoch: 9,
            document_generation: Some(7),
            resident_generation_id: "g".into(),
            resident_catalog_sha256: "b".repeat(64),
            ..Default::default()
        };
        assert!(same_endpoint(&ctx, &ctx));
        for foreign in [
            EndpointContext {
                pid: 124,
                ..ctx.clone()
            },
            EndpointContext {
                target_starttime: Some(45),
                ..ctx.clone()
            },
            EndpointContext {
                endpoint_epoch: 10,
                ..ctx.clone()
            },
            EndpointContext {
                document_generation: Some(8),
                ..ctx.clone()
            },
            EndpointContext {
                resident_generation_id: "foreign".into(),
                ..ctx.clone()
            },
            EndpointContext {
                resident_catalog_sha256: "c".repeat(64),
                ..ctx.clone()
            },
            EndpointContext {
                process: "other".into(),
                ..ctx.clone()
            },
        ] {
            assert!(!same_endpoint(&ctx, &foreign));
        }
        let identity = crate::control_plane::DaemonIdentity {
            daemon_pid: "1".into(),
            daemon_starttime: "2".into(),
            boot_id: "boot".into(),
        };
        assert!(same_daemon(&identity, &identity));
        assert!(!same_daemon(
            &identity,
            &crate::control_plane::DaemonIdentity {
                boot_id: "next".into(),
                ..identity.clone()
            }
        ));
        assert!(!same_daemon(
            &identity,
            &crate::control_plane::DaemonIdentity {
                daemon_starttime: "3".into(),
                ..identity.clone()
            }
        ));
        assert!(!same_daemon(
            &identity,
            &crate::control_plane::DaemonIdentity {
                daemon_pid: "4".into(),
                ..identity.clone()
            }
        ));
        assert!(capture_window_valid(10, 10, 12, 12));
        for (a, b, c, d) in [(10, 9, 12, 13), (10, 11, 9, 13), (10, 11, 14, 13)] {
            assert!(!capture_window_valid(a, b, c, d));
        }
    }
    #[test]
    fn nested_observation_profile_is_closed_and_settled() {
        let value = json!({"outerCurrentItem":1,"firstPosition":0,"pageCount":2,"offsetX":0,"itemCount":13,"scrollState":0,"computingLayout":false,
            "window":{"activityClass":"com.qinggan.app.launcher.activity.MainActivity","windowType":1,"displayId":0,"focused":true,"attached":true,"shown":true,"token":"window","bounds":[0,0,1920,1080]},
            "grid":{"resource":"com.qinggan.app.launcher:id/all_app_view","className":"com.qinggan.launcher.base.allapp.AllAppBarView","layoutManagerClass":"com.qinggan.launcher.base.custom.PagerGridLayoutManager","bounds":[0,100,1800,1000]},
            "items":[{"position":0,"label":"app","bounds":[10,100,110,200]}]});
        assert!(serde_json::from_value::<Observation>(value.clone())
            .unwrap()
            .valid());
        for (key, bad) in [
            ("outerCurrentItem", json!(0)),
            ("pageCount", json!(1)),
            ("firstPosition", json!(1)),
            ("scrollState", json!(1)),
            ("computingLayout", json!(true)),
        ] {
            let mut changed = value.clone();
            changed[key] = bad;
            assert!(!serde_json::from_value::<Observation>(changed)
                .unwrap()
                .valid());
        }
        let mut later = value.clone();
        later["firstPosition"] = json!(12);
        later["offsetX"] = json!(1800);
        assert!(serde_json::from_value::<Observation>(later)
            .unwrap()
            .valid());
        let mut unknown = value;
        unknown["window"]["extra"] = json!(true);
        assert!(serde_json::from_value::<Observation>(unknown).is_err());
    }
    #[test]
    fn nonce_and_response_fail_closed() {
        assert!(valid_nonce(&"a".repeat(64)));
        assert!(!valid_nonce(&"A".repeat(64)));
        assert!(!valid_nonce(&"a".repeat(63)));
        let command = Command {
            schema_version: 1,
            operation: "launcher-page-observe".into(),
            request_id: "a".repeat(64),
            generation_id: "g".into(),
            catalog_sha256: "b".repeat(64),
            document_generation: 1,
        };
        let mut response = serde_json::to_value(&command).unwrap();
        response["outcome"] = "unavailable".into();
        response["reason"] = "no-grid".into();
        response["captureStartedBootMs"] = 10.into();
        response["captureFinishedBootMs"] = 11.into();
        let good = response.to_string();
        for (key, bad) in [
            ("observation", json!(null)),
            ("observation", json!({})),
            ("reason", json!("execute")),
            ("captureFinishedBootMs", json!(9)),
            ("catalogSha256", json!("c".repeat(64))),
        ] {
            let mut malformed = response.clone();
            malformed[key] = bad;
            assert!(validate_response(&malformed.to_string(), &command).is_none());
        }
        assert!(validate_response(&"x".repeat(MAX_RESPONSE + 1), &command).is_none());

        assert!(validate_response(&good, &command).is_some());
        response["requestId"] = "c".repeat(64).into();
        assert!(validate_response(&response.to_string(), &command).is_none());
        response["requestId"] = command.request_id.clone().into();
        response["extra"] = true.into();
        assert!(validate_response(&response.to_string(), &command).is_none());
        assert!(
            validate_response(&good.replacen('{', "{\"schemaVersion\":1,", 1), &command).is_none()
        );
    }
}
