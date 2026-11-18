//! Shared install/restore recovery for protected SELinux-policy publication.
//!
//! The journal is durable authority.  The forked child owns the live writable
//! window; EOF, timeout, or an abort byte causes recovery from its inherited
//! pristine descriptor.  No path in the journal is caller controlled.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

const MAX_POLICY_BYTES: u64 = 64 * 1024 * 1024;
/// init loads the precompiled policy only while this sidecar digest matches
/// the plat+mapping CIL digest on /system; otherwise it recompiles from CIL
/// and a patched precompiled binary is silently ignored.
const POLICY_SIDECAR: &str = "/vendor/etc/selinux/precompiled_sepolicy.plat_and_mapping.sha256";
const PLAT_MAPPING_CIL_SHA256: &str = "/system/etc/selinux/plat_and_mapping_sepolicy.cil.sha256";
const A11_DIGESTS: [(&str, &str); 3] = [
    (
        "/vendor/etc/selinux/precompiled_sepolicy.plat_sepolicy_and_mapping.sha256",
        "/system/etc/selinux/plat_sepolicy_and_mapping.sha256",
    ),
    (
        "/vendor/etc/selinux/precompiled_sepolicy.system_ext_sepolicy_and_mapping.sha256",
        "/system_ext/etc/selinux/system_ext_sepolicy_and_mapping.sha256",
    ),
    (
        "/vendor/etc/selinux/precompiled_sepolicy.product_sepolicy_and_mapping.sha256",
        "/product/etc/selinux/product_sepolicy_and_mapping.sha256",
    ),
];
const MAX_SIDECAR_BYTES: usize = 512;
const MAX_MOUNTINFO_BYTES: usize = 256 * 1024;
const MAX_MOUNTINFO_LINES: usize = 1024;
const MAX_MOUNTINFO_LINE_BYTES: usize = 4096;
const WATCHDOG_TIMEOUT_SECONDS: i32 = 45;
const WATCHDOG_PARENT_TIMEOUT_SECONDS: u64 = WATCHDOG_TIMEOUT_SECONDS as u64 * 2;
const SELINUX_ENFORCE: &str = "/sys/fs/selinux/enforce";
const MS_RDONLY_ABI: u64 = 1;
const MS_NOSUID_ABI: u64 = 2;
const MS_NODEV_ABI: u64 = 4;
const MS_NOEXEC_ABI: u64 = 8;
const MS_REMOUNT_ABI: u64 = 32;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Boundary {
    mount_id: u64,
    parent_id: u64,
    major_minor: String,
    root: String,
    mount_point: String,
    source: String,
    fs_type: String,
    security_flags: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Phase {
    Prepared,
    Writable,
    PolicyPublished,
    RebootOwned,
    Recovering,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupAction {
    None,
    AcceptLoadedPolicy,
    RestoreAndReboot,
    RestoreInterrupted,
}

fn startup_action(journal: Option<&Journal>, current_boot_id: &str) -> StartupAction {
    match journal {
        None => StartupAction::None,
        Some(value) if value.phase == Phase::RebootOwned && value.boot_id != current_boot_id => {
            StartupAction::AcceptLoadedPolicy
        }
        Some(value) if value.phase == Phase::RebootOwned => StartupAction::RestoreAndReboot,
        Some(_) => StartupAction::RestoreInterrupted,
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Journal {
    schema_version: u32,
    operation: String,
    transaction_id: String,
    policy_path: String,
    pristine_path: String,
    pristine_size: u64,
    pristine_sha256: String,
    policy_uid: u32,
    policy_gid: u32,
    policy_mode: u32,
    policy_selinux_context: Vec<u8>,
    boot_id: String,
    sidecars: Vec<Sidecar>,
    boundaries: Vec<Boundary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    block_read_only: Vec<Option<bool>>,
    changed_boundaries: usize,
    enforcing_required: bool,
    recovery_writable_required: bool,
    phase: Phase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_error: Option<String>,
}

/// Pristine identity of the plat_and_mapping digest sidecar published next to
/// the policy so that init loads the precompiled binary instead of
/// recompiling the stock CIL sources at every boot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Sidecar {
    pub path: String,
    pub present: bool,
    pub pristine: Vec<u8>,
    pub sha256: String,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub selinux_context: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SidecarBackup {
    schema_version: u32,
    sidecars: Vec<Sidecar>,
}

pub fn sidecar_backup_bytes() -> Result<Vec<u8>, String> {
    let sidecars = capture_sidecars()?;
    if !valid_sidecars(&sidecars) {
        return Err("captured policy sidecar authority is invalid".into());
    }
    canonical_json(&SidecarBackup {
        schema_version: 1,
        sidecars,
    })
}

pub fn parse_sidecar_backup(bytes: &[u8]) -> Result<Vec<Sidecar>, String> {
    if bytes.len() > 16 * 1024 {
        return Err("policy sidecar backup exceeds bound".into());
    }
    let backup: SidecarBackup = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if backup.schema_version != 1
        || !valid_sidecars(&backup.sidecars)
        || canonical_json(&backup)? != bytes
    {
        return Err("policy sidecar backup contract is invalid".into());
    }
    Ok(backup.sidecars)
}

pub struct Watchdog {
    control: Option<File>,
    pid: libc::pid_t,
    journal_path: std::path::PathBuf,
}

impl Watchdog {
    /// Transfer recovery ownership to the durable reboot milestone.
    pub fn disarm_for_reboot(mut self) -> Result<(), String> {
        let mut control = self.control.take().ok_or("watchdog is not armed")?;
        control
            .write_all(b"D")
            .map_err(|error| format!("disarm policy watchdog: {error}"))?;
        drop(control);
        wait_child(self.pid, true, &self.journal_path)
    }

    /// Ask the child to recover and wait until it has finished.
    pub fn abort(mut self) -> Result<(), String> {
        if let Some(mut control) = self.control.take() {
            let _ = control.write_all(b"A");
        }
        wait_child(self.pid, false, &self.journal_path)
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        // Closing the only parent write end is an abort signal.  The child is
        // deliberately not reaped here because Drop must not block error
        // unwinding; init adopts it if the parent exits.
        self.control.take();
    }
}

fn wait_child(pid: libc::pid_t, expect_disarmed: bool, journal_path: &Path) -> Result<(), String> {
    let mut status = 0;
    let deadline = Instant::now() + Duration::from_secs(WATCHDOG_PARENT_TIMEOUT_SECONDS);
    loop {
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if result == pid {
            break;
        }
        if result == 0 && Instant::now() >= deadline {
            // The child owns recovery after the controller closes its pipe.
            // Do not kill it, and never turn the deadline into an unbounded
            // reap if a killed task remains in uninterruptible sleep.
            return Err("policy watchdog exceeded its parent deadline".to_string());
        }
        if result == 0 {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        if result < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(format!(
            "wait for policy watchdog: {}",
            std::io::Error::last_os_error()
        ));
    }
    let code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };
    let expected = if expect_disarmed { 0 } else { 20 };
    if code != expected {
        if let Ok(journal) = load_journal(journal_path) {
            if let Some(error) = journal.recovery_error {
                return Err(format!(
                    "policy watchdog exited with {code}, expected {expected}: {error}"
                ));
            }
        }
    }
    (code == expected)
        .then_some(())
        .ok_or_else(|| format!("policy watchdog exited with {code}, expected {expected}"))
}

fn canonical_tx(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_boot_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            }
        })
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn sync_parent(path: &Path) -> Result<(), String> {
    File::open(path.parent().ok_or("path has no parent")?)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("fsync parent of {}: {error}", path.display()))
}

fn atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let leaf = path.file_name().ok_or("atomic target has no leaf")?;
    let temporary = path.with_file_name(format!(".{}.mount-policy.tmp", leaf.to_string_lossy()));
    match fs::symlink_metadata(&temporary) {
        Ok(metadata) if metadata.file_type().is_file() && metadata.nlink() == 1 => {
            fs::remove_file(&temporary).map_err(|error| error.to_string())?;
        }
        Ok(_) => return Err("mount-policy temporary has unsafe identity".to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|error| format!("create {}: {error}", temporary.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("publish {}: {error}", temporary.display()))?;
    fs::rename(&temporary, path).map_err(|error| format!("rename {}: {error}", path.display()))?;
    sync_parent(path)
}

fn read_exact_file(
    file: &mut File,
    expected_size: u64,
    expected_digest: &str,
) -> Result<Vec<u8>, String> {
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() != expected_size
        || expected_size == 0
        || expected_size > MAX_POLICY_BYTES
    {
        return Err("pristine policy descriptor has unsafe identity".to_string());
    }
    let mut bytes = Vec::with_capacity(expected_size as usize);
    Read::by_ref(file)
        .take(expected_size + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 != expected_size || digest(&bytes) != expected_digest {
        return Err("pristine policy descriptor differs from journal".to_string());
    }
    Ok(bytes)
}

fn decode_field(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'\\' {
            out.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 3 >= bytes.len() {
            return Err("truncated mountinfo escape".to_string());
        }
        out.push(match &bytes[index + 1..index + 4] {
            b"040" => b' ',
            b"011" => b'\t',
            b"012" => b'\n',
            b"134" => b'\\',
            _ => return Err("unsupported mountinfo escape".to_string()),
        });
        index += 4;
    }
    String::from_utf8(out).map_err(|_| "mountinfo field is not UTF-8".to_string())
}

fn contains(path: &str, boundary: &str) -> bool {
    boundary == "/"
        || path == boundary
        || path
            .strip_prefix(boundary)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn resolve_mounts(mountinfo: &[u8], targets: &[String]) -> Result<Vec<Boundary>, String> {
    if mountinfo.len() > MAX_MOUNTINFO_BYTES {
        return Err("mountinfo exceeds byte bound".to_string());
    }
    let text = std::str::from_utf8(mountinfo).map_err(|_| "mountinfo is not UTF-8")?;
    let mut all = Vec::new();
    let mut super_options: Vec<String> = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if index >= MAX_MOUNTINFO_LINES || line.len() > MAX_MOUNTINFO_LINE_BYTES {
            return Err("mountinfo exceeds work bound".to_string());
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let separator = fields
            .iter()
            .position(|field| *field == "-")
            .ok_or("mountinfo separator missing")?;
        if separator < 6 || fields.len() != separator + 4 {
            return Err("mountinfo record shape is invalid".to_string());
        }
        let mount_point = decode_field(fields[4])?;
        let root = decode_field(fields[3])?;
        if !mount_point.starts_with('/') || mount_point.contains("/../") {
            return Err("mountinfo path is non-canonical".to_string());
        }
        // A mount whose root is not a path (for example a namespace
        // filesystem such as `nsfs` with root `net:[...]`) can never be the
        // mount that contains a path target like `/vendor/etc/selinux/...`.
        // Skip it instead of rejecting the whole mountinfo, which would
        // otherwise fail on stock emulator/device mount tables that include
        // such special filesystems.
        if !root.starts_with('/') {
            continue;
        }
        if root.contains("/../") {
            return Err("mountinfo path is non-canonical".to_string());
        }
        let mut security_flags = 0;
        for option in fields[5].split(',') {
            security_flags |= match option {
                "nosuid" => MS_NOSUID_ABI,
                "nodev" => MS_NODEV_ABI,
                "noexec" => MS_NOEXEC_ABI,
                _ => 0,
            };
        }
        super_options.push(fields.get(separator + 3).copied().unwrap_or("").to_string());
        all.push(Boundary {
            mount_id: fields[0].parse().map_err(|_| "invalid mount ID")?,
            parent_id: fields[1].parse().map_err(|_| "invalid parent mount ID")?,
            major_minor: fields[2].to_string(),
            root,
            mount_point,
            source: decode_field(fields[separator + 2])?,
            fs_type: decode_field(fields[separator + 1])?,
            security_flags,
        });
    }
    let mut selected = Vec::new();
    for target in targets {
        let longest = all
            .iter()
            .filter(|entry| contains(target, &entry.mount_point))
            .map(|entry| entry.mount_point.len())
            .max()
            .ok_or("protected target has no mount")?;
        let mut matches = all
            .iter()
            .filter(|entry| {
                entry.mount_point.len() == longest && contains(target, &entry.mount_point)
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            // Same-length duplicates are only acceptable as an overlayfs stack
            // over the SAME mount point (userdebug writable-system boot): the
            // topmost mount (highest mount ID — mounts are ID-ordered) is the
            // one path resolution actually uses, so it is the boundary.
            let same_point = matches
                .iter()
                .all(|entry| entry.mount_point == matches[0].mount_point);
            let topmost = matches
                .iter()
                .max_by_key(|entry| entry.mount_id)
                .ok_or("protected target mount is ambiguous")?;
            let overlays = matches
                .iter()
                .filter(|entry| entry.fs_type == "overlay")
                .count();
            let stack =
                same_point && overlays == 1 && topmost.fs_type == "overlay" && matches.len() == 2;
            if !stack {
                return Err("protected target mount is ambiguous".to_string());
            }
            matches = vec![topmost];
        }
        let boundary = matches[0];
        let separator_text = super_options
            .iter()
            .zip(all.iter())
            .find(|(_, entry)| entry.mount_id == boundary.mount_id)
            .map(|(text, _)| text.as_str())
            .unwrap_or("");
        if boundary.root != "/" {
            return Err("protected target mount identity is unsafe".to_string());
        }
        if boundary.fs_type == "overlay" {
            // A writable-system (userdebug overlayfs) boot stacks an overlay on
            // top of the physical partition at the SAME mount point. Path
            // resolution then only ever sees the overlay, so it is the boundary
            // the transaction must remount. Require the stack to be exactly
            // that: the shadowed entry beneath is a physical partition and the
            // overlay's first lowerdir is its own mount point (self-stack).
            let lowers = separator_text
                .split_once("lowerdir=")
                .and_then(|(_, rest)| rest.split(',').next())
                .ok_or("protected target overlay lacks a lowerdir")?;
            if boundary.source != "overlay"
                || lowers != boundary.mount_point
                || !separator_text.contains("upperdir=")
                || !separator_text.contains("workdir=")
            {
                return Err("protected target overlay stack identity is unsafe".to_string());
            }
            let physical = all.iter().any(|entry| {
                entry.mount_point == boundary.mount_point
                    && entry.mount_id != boundary.mount_id
                    && entry.root == "/"
                    && matches!(entry.fs_type.as_str(), "ext4" | "f2fs")
                    && (entry.source == "/dev/root" || entry.source.starts_with("/dev/block/"))
            });
            if !physical {
                return Err("protected target overlay lacks its physical partition".to_string());
            }
        } else if !matches!(boundary.fs_type.as_str(), "ext4" | "f2fs")
            || !(boundary.source == "/dev/root" || boundary.source.starts_with("/dev/block/"))
        {
            return Err("protected target mount identity is unsafe".to_string());
        }
        if all.iter().any(|other| {
            other.mount_id != boundary.mount_id
                && other.major_minor == boundary.major_minor
                && other.root == boundary.root
                && other.fs_type == boundary.fs_type
        }) {
            return Err("protected target has an ambiguous superblock alias".to_string());
        }
        if !selected.contains(boundary) {
            selected.push(boundary.clone());
        }
    }
    Ok(selected)
}

fn resolved_policy_target(policy_path: &Path) -> Result<String, String> {
    let parent = fs::canonicalize(policy_path.parent().ok_or("policy target has no parent")?)
        .map_err(|error| format!("canonicalize policy parent: {error}"))?;
    parent
        .join(policy_path.file_name().ok_or("policy target has no leaf")?)
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| "resolved policy target is not UTF-8".to_string())
}

fn current_mounts(policy_path: &Path) -> Result<Vec<Boundary>, String> {
    let target = resolved_policy_target(policy_path)?;
    let mut file = File::open("/proc/self/mountinfo").map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((MAX_MOUNTINFO_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    resolve_mounts(&bytes, &[target])
}

fn block_identity(boundary: &Boundary) -> crate::protected_block::BlockIdentityRef<'_> {
    crate::protected_block::BlockIdentityRef {
        source: &boundary.source,
        major_minor: &boundary.major_minor,
        fs_type: &boundary.fs_type,
    }
}

fn original_block_flag(journal: &Journal, index: usize) -> Option<bool> {
    journal.block_read_only.get(index).copied().flatten()
}

fn valid_block_flags(journal: &Journal) -> bool {
    match journal.schema_version {
        3 => journal.block_read_only.is_empty(),
        4 => {
            journal.block_read_only.len() == journal.boundaries.len()
                && journal.boundaries.iter().zip(&journal.block_read_only).all(
                    |(boundary, flag)| {
                        matches!(boundary.fs_type.as_str(), "ext4" | "f2fs") == flag.is_some()
                    },
                )
        }
        _ => false,
    }
}

fn policy_remount(
    boundary: &Boundary,
    original: Option<bool>,
    read_only: bool,
) -> Result<(), String> {
    // Legacy journals do not grant block ioctl authority.
    if original.is_none() && read_only {
        return remount(boundary, true);
    }
    crate::protected_block::remount(block_identity(boundary), read_only, original, |ro| {
        remount(boundary, ro)
    })
}

fn remount(boundary: &Boundary, read_only: bool) -> Result<(), String> {
    remount_with(boundary, read_only, |source, target, fs_type, flags| {
        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            let result = unsafe {
                libc::mount(
                    source.as_ptr(),
                    target.as_ptr(),
                    fs_type.as_ptr(),
                    flags as libc::c_ulong,
                    std::ptr::null(),
                )
            };
            if result != 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            let mut stats: libc::statfs = unsafe { std::mem::zeroed() };
            if unsafe { libc::statfs(target.as_ptr(), &mut stats) } != 0 {
                return Err(format!(
                    "verify remount flags: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(stats.f_flags & libc::ST_RDONLY != 0)
        }
        #[cfg(not(any(target_os = "android", target_os = "linux")))]
        {
            let _ = (source, target, fs_type, flags);
            Err("remount is unsupported on this host".into())
        }
    })
    .map_err(|error| format!("{error}; {}", remount_diagnostics(boundary)))
}

fn remount_with(
    boundary: &Boundary,
    read_only: bool,
    invoke: impl FnOnce(&std::ffi::CStr, &std::ffi::CStr, &std::ffi::CStr, u64) -> Result<bool, String>,
) -> Result<(), String> {
    let source = std::ffi::CString::new(boundary.source.as_str())
        .map_err(|_| "mount source contains NUL")?;
    let target = std::ffi::CString::new(boundary.mount_point.as_str())
        .map_err(|_| "mount point contains NUL")?;
    let fs_type =
        std::ffi::CString::new(boundary.fs_type.as_str()).map_err(|_| "mount type contains NUL")?;
    let flags =
        MS_REMOUNT_ABI | boundary.security_flags | if read_only { MS_RDONLY_ABI } else { 0 };
    // Preserve the verified source and type, matching the lifecycle remounter.
    // The Android vendor ext4 boundary does not admit the NULL-source form.
    let observed_read_only = invoke(&source, &target, &fs_type, flags).map_err(|error| {
        format!(
            "remount {} source={} type={} flags={flags:#x}: {error}",
            boundary.mount_point, boundary.source, boundary.fs_type
        )
    })?;
    if observed_read_only != read_only {
        return Err(format!(
            "remount {} reported success but read-only={} (expected {})",
            boundary.mount_point, observed_read_only, read_only
        ));
    }
    Ok(())
}

fn diagnostic_digest(mut reader: impl Read, maximum: u64) -> Result<String, String> {
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 8192];
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.to_string()),
        };
        if count == 0 {
            return Ok(format!("{:x}", hasher.finalize()));
        }
        total += count as u64;
        if total > maximum {
            return Err("policy exceeds diagnostic limit".into());
        }
        hasher.update(&buffer[..count]);
    }
}

fn diagnostic_policy_digest(path: &str) -> String {
    match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| error.to_string())
        .and_then(|file| diagnostic_digest(file, MAX_POLICY_BYTES))
    {
        Ok(digest) => digest,
        Err(error) => format!("unavailable({error})"),
    }
}

fn remount_diagnostics(boundary: &Boundary) -> String {
    fn read(path: &str, maximum: u64) -> String {
        let mut bytes = Vec::new();
        match File::open(path).and_then(|file| file.take(maximum).read_to_end(&mut bytes)) {
            Ok(_) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(error) => format!("unavailable({error})"),
        }
    }
    let context = read("/proc/self/attr/current", 256);
    let status = read("/proc/self/status", 8192);
    let capabilities = status
        .lines()
        .filter(|line| {
            line.starts_with("Cap") || line.starts_with("Uid:") || line.starts_with("Gid:")
        })
        .collect::<Vec<_>>()
        .join(" | ");
    let mounts = read("/proc/self/mountinfo", MAX_MOUNTINFO_BYTES as u64);
    let selected = mounts
        .lines()
        .filter(|line| line.split_whitespace().nth(4) == Some(boundary.mount_point.as_str()))
        .take(4)
        .collect::<Vec<_>>()
        .join(" | ");
    let seccomp = status
        .lines()
        .find(|line| line.starts_with("Seccomp:"))
        .unwrap_or("Seccomp:unavailable");
    format!(
        "pid={} context={} {} loadedPolicySha256={} vendorPolicySha256={} credentials=[{}] mount=[{}]",
        std::process::id(),
        context.trim(),
        seccomp.trim(),
        diagnostic_policy_digest("/sys/fs/selinux/policy"),
        diagnostic_policy_digest("/vendor/etc/selinux/precompiled_sepolicy"),
        capabilities,
        selected
    )
}

fn enforcing() -> Result<bool, String> {
    let value =
        fs::read(SELINUX_ENFORCE).map_err(|error| format!("read SELinux enforcing: {error}"))?;
    match value.as_slice() {
        b"1" | b"1\n" => Ok(true),
        b"0" | b"0\n" => Ok(false),
        _ => Err("SELinux enforcing value is invalid".to_string()),
    }
}

fn restore_enforcing(required: bool) -> Result<(), String> {
    restore_enforcing_with(required, enforcing, || {
        let mut file = OpenOptions::new()
            .write(true)
            .open(SELINUX_ENFORCE)
            .map_err(|error| format!("open SELinux enforcing: {error}"))?;
        file.write_all(b"1")
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("restore SELinux enforcing: {error}"))
    })
}

fn restore_enforcing_with(
    required: bool,
    mut read_enforcing: impl FnMut() -> Result<bool, String>,
    mut write_enforcing: impl FnMut() -> Result<(), String>,
) -> Result<(), String> {
    if !required || read_enforcing()? {
        return Ok(());
    }
    write_enforcing()?;
    read_enforcing()?
        .then_some(())
        .ok_or_else(|| "SELinux remained permissive after restore".to_string())
}

#[cfg(target_os = "android")]
fn selinux_context(file: &File) -> Result<Vec<u8>, String> {
    const NAME: &[u8] = b"security.selinux\0";
    let size = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            NAME.as_ptr().cast(),
            std::ptr::null_mut(),
            0,
        )
    };
    if size <= 0 || size > 256 {
        return Err("policy SELinux context is invalid".to_string());
    }
    let mut value = vec![0; size as usize];
    if unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            NAME.as_ptr().cast(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    } != size
    {
        return Err("read policy SELinux context failed".to_string());
    }
    Ok(value)
}

#[cfg(not(target_os = "android"))]
fn selinux_context(_file: &File) -> Result<Vec<u8>, String> {
    Ok(Vec::new())
}

fn publish_policy(path: &Path, bytes: &[u8], journal: &Journal) -> Result<(), String> {
    publish_file(
        path,
        bytes,
        journal.policy_uid,
        journal.policy_gid,
        journal.policy_mode,
        &journal.policy_selinux_context,
    )
}

fn publish_sidecar(sidecar: &Sidecar, bytes: &[u8]) -> Result<(), String> {
    publish_file(
        Path::new(&sidecar.path),
        bytes,
        sidecar.uid,
        sidecar.gid,
        sidecar.mode,
        &sidecar.selinux_context,
    )
}

fn file_matches(
    path: &Path,
    bytes: &[u8],
    uid: u32,
    gid: u32,
    mode: u32,
    context: &[u8],
) -> Result<bool, String> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("open policy identity {}: {error}", path.display())),
    };
    let before = file.metadata().map_err(|error| error.to_string())?;
    if !before.is_file() || before.nlink() != 1 {
        return Err(format!("policy identity is unsafe: {}", path.display()));
    }
    if before.len() != bytes.len() as u64
        || before.uid() != uid
        || before.gid() != gid
        || before.mode() & 0o7777 != mode
        || selinux_context(&file)? != context
    {
        return Ok(false);
    }
    let mut current = Vec::with_capacity(bytes.len());
    Read::by_ref(&mut file)
        .take(bytes.len() as u64 + 1)
        .read_to_end(&mut current)
        .map_err(|error| format!("read policy identity {}: {error}", path.display()))?;
    let after = file.metadata().map_err(|error| error.to_string())?;
    let named = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.ctime(),
        after.ctime_nsec(),
    ) || named.file_type().is_symlink()
        || (named.dev(), named.ino()) != (after.dev(), after.ino())
    {
        return Err(format!("policy identity changed: {}", path.display()));
    }
    Ok(current == bytes)
}

fn publish_file(
    path: &Path,
    bytes: &[u8],
    uid: u32,
    gid: u32,
    mode: u32,
    selinux_context: &[u8],
) -> Result<(), String> {
    // A failure before the first replacement leaves the protected files
    // pristine. Recovery must not require write/create permissions merely
    // to restore bytes and metadata that already match its authority.
    if file_matches(path, bytes, uid, gid, mode, selinux_context)? {
        return Ok(());
    }
    let parent = path.parent().ok_or("policy path has no parent")?;
    let temporary = parent.join(format!(
        ".{}.policy-transaction.tmp",
        path.file_name()
            .ok_or("policy path has no leaf")?
            .to_string_lossy()
    ));
    match fs::symlink_metadata(&temporary) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("inspect protected policy temporary: {error}")),
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != uid
                || metadata.gid() != gid
                || ![0o600, mode].contains(&(metadata.mode() & 0o7777))
                || metadata.len() > MAX_POLICY_BYTES
            {
                return Err("protected policy temporary has foreign identity".into());
            }
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&temporary)
                .map_err(|error| error.to_string())?;
            let opened = file.metadata().map_err(|error| error.to_string())?;
            if (opened.dev(), opened.ino()) != (metadata.dev(), metadata.ino())
                || crate::mount_policy_transaction::selinux_context(&file)? != selinux_context
            {
                return Err("protected policy temporary identity changed".into());
            }
            fs::remove_file(&temporary)
                .map_err(|error| format!("clear protected policy temporary: {error}"))?;
        }
    }
    let mut target = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|error| {
            format!(
                "create protected policy temporary {}: {error}",
                temporary.display()
            )
        })?;
    let mut cleanup = PolicyTemporary::new(&temporary, &target)?;
    target.write_all(bytes).map_err(|error| {
        format!(
            "write protected policy temporary {}: {error}",
            temporary.display()
        )
    })?;
    if unsafe { libc::fchown(target.as_raw_fd(), uid, gid) } != 0
        || unsafe { libc::fchmod(target.as_raw_fd(), mode as libc::mode_t) } != 0
    {
        return Err(format!(
            "restore policy metadata: {}",
            std::io::Error::last_os_error()
        ));
    }
    #[cfg(target_os = "android")]
    if unsafe {
        libc::fsetxattr(
            target.as_raw_fd(),
            c"security.selinux".as_ptr(),
            selinux_context.as_ptr().cast(),
            selinux_context.len(),
            0,
        )
    } != 0
    {
        return Err(format!(
            "restore policy SELinux context: {}",
            std::io::Error::last_os_error()
        ));
    }
    target.sync_all().map_err(|error| {
        format!(
            "sync protected policy temporary {}: {error}",
            temporary.display()
        )
    })?;
    fs::rename(&temporary, path)
        .map_err(|error| format!("rename protected policy {}: {error}", path.display()))?;
    cleanup.disarmed = true;
    sync_parent(path)
        .map_err(|error| format!("sync protected policy parent {}: {error}", parent.display()))
}

struct PolicyTemporary {
    path: std::path::PathBuf,
    dev: u64,
    ino: u64,
    disarmed: bool,
}
impl PolicyTemporary {
    fn new(path: &Path, file: &File) -> Result<Self, String> {
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        Ok(Self {
            path: path.into(),
            dev: metadata.dev(),
            ino: metadata.ino(),
            disarmed: false,
        })
    }
}
impl Drop for PolicyTemporary {
    fn drop(&mut self) {
        if !self.disarmed
            && fs::symlink_metadata(&self.path).is_ok_and(|value| {
                value.is_file()
                    && value.nlink() == 1
                    && (value.dev(), value.ino()) == (self.dev, self.ino)
            })
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn digest_pairs(api: u32) -> Result<Vec<(&'static str, &'static str)>, String> {
    match api {
        28 => Ok(vec![(POLICY_SIDECAR, PLAT_MAPPING_CIL_SHA256)]),
        30 => Ok(A11_DIGESTS.to_vec()),
        _ => Err("policy digest publication supports only Android 9 and 11".into()),
    }
}

fn android_api() -> Result<u32, String> {
    #[cfg(target_os = "android")]
    {
        let mut value = [0u8; 92];
        let size = unsafe {
            libc::__system_property_get(c"ro.build.version.sdk".as_ptr(), value.as_mut_ptr().cast())
        };
        if size <= 0 || size as usize >= value.len() {
            return Err("Android API property is unavailable".into());
        }
        std::str::from_utf8(&value[..size as usize])
            .map_err(|_| "Android API property is malformed")?
            .parse()
            .map_err(|_| "Android API property is malformed".into())
    }
    #[cfg(not(target_os = "android"))]
    Err("policy digest capture requires Android".into())
}

fn rooted(root: &Path, absolute: &str) -> std::path::PathBuf {
    root.join(
        absolute
            .strip_prefix('/')
            .expect("fixed absolute digest path"),
    )
}

/// Capture every init digest selector, including original absence, before mutation.
pub fn capture_sidecars() -> Result<Vec<Sidecar>, String> {
    match fs::symlink_metadata("/odm/etc/selinux/precompiled_sepolicy") {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("inspect preferred ODM policy: {error}")),
        Ok(_) => {
            return Err(
                "preferred ODM policy is unsupported by the vendor publication contract".into(),
            )
        }
    }
    capture_sidecars_at(Path::new("/"), android_api()?)
}

fn capture_sidecars_at(root: &Path, api: u32) -> Result<Vec<Sidecar>, String> {
    let policy = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(rooted(root, "/vendor/etc/selinux/precompiled_sepolicy"))
        .map_err(|error| format!("open policy digest context authority: {error}"))?;
    let context = selinux_context(&policy)?;
    digest_pairs(api)?
        .into_iter()
        .map(|(path, _)| {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(rooted(root, path));
            let mut file = match file {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(Sidecar {
                        path: path.into(),
                        present: false,
                        pristine: Vec::new(),
                        sha256: digest(&[]),
                        uid: 0,
                        gid: 0,
                        mode: 0o644,
                        selinux_context: context.clone(),
                    })
                }
                Err(error) => return Err(format!("open policy digest sidecar {path}: {error}")),
            };
            let before = file.metadata().map_err(|error| error.to_string())?;
            if !before.is_file()
                || before.nlink() != 1
                || before.len() > MAX_SIDECAR_BYTES as u64
                || !matches!(before.mode() & 0o7777, 0o444 | 0o644)
                || (cfg!(target_os = "android") && (before.uid() != 0 || before.gid() != 0))
            {
                return Err(format!("policy digest sidecar identity is unsafe: {path}"));
            }
            let mut pristine = Vec::new();
            Read::by_ref(&mut file)
                .take(MAX_SIDECAR_BYTES as u64 + 1)
                .read_to_end(&mut pristine)
                .map_err(|error| format!("read policy digest sidecar {path}: {error}"))?;
            let after = file.metadata().map_err(|error| error.to_string())?;
            let named =
                fs::symlink_metadata(rooted(root, path)).map_err(|error| error.to_string())?;
            if pristine.len() as u64 != before.len()
                || (
                    before.dev(),
                    before.ino(),
                    before.len(),
                    before.ctime(),
                    before.ctime_nsec(),
                ) != (
                    after.dev(),
                    after.ino(),
                    after.len(),
                    after.ctime(),
                    after.ctime_nsec(),
                )
                || named.file_type().is_symlink()
                || (named.dev(), named.ino()) != (after.dev(), after.ino())
            {
                return Err(format!("policy digest sidecar changed: {path}"));
            }
            Ok(Sidecar {
                path: path.into(),
                present: true,
                sha256: digest(&pristine),
                pristine,
                uid: before.uid(),
                gid: before.gid(),
                mode: before.mode() & 0o7777,
                selinux_context: selinux_context(&file)?,
            })
        })
        .collect()
}

/// Only the complete, ordered Android 9 or Android 11 fixed path set is authority.
pub fn valid_sidecars(sidecars: &[Sidecar]) -> bool {
    let paths = match sidecars.len() {
        1 => vec![POLICY_SIDECAR],
        3 => A11_DIGESTS.iter().map(|(path, _)| *path).collect(),
        _ => return false,
    };
    sidecars.iter().zip(paths).all(|(sidecar, path)| {
        let context = sidecar
            .selinux_context
            .strip_suffix(&[0])
            .unwrap_or(&sidecar.selinux_context);
        sidecar.path == path
            && sidecar.uid == 0
            && sidecar.gid == 0
            && matches!(sidecar.mode, 0o444 | 0o644)
            && sidecar.pristine.len() <= MAX_SIDECAR_BYTES
            && (sidecar.present || sidecar.pristine.is_empty())
            && canonical_tx(&sidecar.sha256)
            && digest(&sidecar.pristine) == sidecar.sha256
            && context.len() <= 128
            && context.starts_with(b"u:object_r:")
            && context
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_:,.-".contains(byte))
    })
}

fn parse_digest(bytes: &[u8]) -> Result<(), String> {
    let value = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if value.len() != 64
        || !value
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err("platform mapping CIL digest is malformed".into());
    }
    Ok(())
}

fn sidecar_target(sidecar: &Sidecar) -> Result<Vec<u8>, String> {
    let source = std::iter::once((POLICY_SIDECAR, PLAT_MAPPING_CIL_SHA256))
        .chain(A11_DIGESTS)
        .find(|(path, _)| *path == sidecar.path)
        .ok_or("unknown policy digest path")?
        .1;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(source)
        .map_err(|error| format!("open platform CIL digest {source}: {error}"))?;
    let before = file.metadata().map_err(|error| error.to_string())?;
    if !before.is_file()
        || before.nlink() != 1
        || !matches!(before.len(), 64 | 65)
        || !matches!(before.mode() & 0o7777, 0o444 | 0o644)
        || (cfg!(target_os = "android") && (before.uid() != 0 || before.gid() != 0))
    {
        return Err(format!("platform CIL digest identity is unsafe: {source}"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(66)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let after = file.metadata().map_err(|error| error.to_string())?;
    let named = fs::symlink_metadata(source).map_err(|error| error.to_string())?;
    if bytes.len() as u64 != before.len()
        || (
            before.dev(),
            before.ino(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (after.dev(), after.ino(), after.ctime(), after.ctime_nsec())
        || named.file_type().is_symlink()
        || (named.dev(), named.ino()) != (after.dev(), after.ino())
    {
        return Err(format!("platform CIL digest changed: {source}"));
    }
    parse_digest(&bytes)?;
    Ok(bytes)
}

/// Called only inside the caller's protected vendor writable transaction.
pub fn restore_sidecars(sidecars: &[Sidecar]) -> Result<(), String> {
    if !valid_sidecars(sidecars) {
        return Err("policy sidecar recovery authority is invalid".into());
    }
    let mut errors = Vec::new();
    for sidecar in sidecars {
        let result = if sidecar.present {
            publish_sidecar(sidecar, &sidecar.pristine)
        } else {
            match fs::symlink_metadata(&sidecar.path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error.to_string()),
                Ok(metadata)
                    if !metadata.is_file()
                        || metadata.nlink() != 1
                        || metadata.uid() != 0
                        || metadata.gid() != 0 =>
                {
                    Err(format!(
                        "absent policy sidecar has foreign identity: {}",
                        sidecar.path
                    ))
                }
                Ok(_) => remove_absent_sidecar(sidecar),
            }
        };
        if let Err(error) = result {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        verify_sidecars(sidecars)
    } else {
        Err(errors.join("; "))
    }
}

fn remove_absent_sidecar(sidecar: &Sidecar) -> Result<(), String> {
    let path = Path::new(&sidecar.path);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("open absent policy sidecar: {error}"))?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(66)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    parse_digest(&bytes)?;
    if !file_matches(
        path,
        &bytes,
        sidecar.uid,
        sidecar.gid,
        sidecar.mode,
        &sidecar.selinux_context,
    )? {
        return Err(format!(
            "absent policy sidecar has foreign metadata: {}",
            path.display()
        ));
    }
    fs::remove_file(path)
        .map_err(|error| format!("remove originally absent policy sidecar: {error}"))?;
    sync_parent(path)
}

pub fn verify_sidecars(sidecars: &[Sidecar]) -> Result<(), String> {
    if !valid_sidecars(sidecars) {
        return Err("policy sidecar verification authority is invalid".into());
    }
    for sidecar in sidecars {
        if sidecar.present {
            if !file_matches(
                Path::new(&sidecar.path),
                &sidecar.pristine,
                sidecar.uid,
                sidecar.gid,
                sidecar.mode,
                &sidecar.selinux_context,
            )? {
                return Err(format!("pristine policy sidecar differs: {}", sidecar.path));
            }
        } else {
            match fs::symlink_metadata(&sidecar.path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.to_string()),
                Ok(_) => {
                    return Err(format!(
                        "policy sidecar was originally absent: {}",
                        sidecar.path
                    ))
                }
            }
        }
    }
    Ok(())
}

fn load_journal(path: &Path) -> Result<Journal, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("open mount-policy journal: {error}"))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || (cfg!(target_os = "android") && (metadata.uid() != 0 || metadata.gid() != 0))
    {
        return Err("mount-policy journal identity is unsafe".to_string());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read mount-policy journal: {error}"))?;
    if bytes.len() > 16 * 1024 {
        return Err("mount-policy journal exceeds bound".to_string());
    }
    let value: Journal = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if !valid_block_flags(&value)
        || !valid_operation(&value.operation)
        || !canonical_tx(&value.transaction_id)
        || !canonical_boot_id(&value.boot_id)
        || value.boundaries.is_empty()
        || value.boundaries.len() > 2
        || value.changed_boundaries > value.boundaries.len()
        || (value.recovery_writable_required
            && !matches!(
                value.phase,
                Phase::Writable | Phase::PolicyPublished | Phase::RebootOwned | Phase::Recovering
            ))
        || value
            .recovery_error
            .as_ref()
            .is_some_and(|error| error.len() > 4096)
        || value.pristine_size == 0
        || value.pristine_size > MAX_POLICY_BYTES
        || !canonical_tx(&value.pristine_sha256)
        || canonical_json(&value)? != bytes
        || value.policy_path != "/vendor/etc/selinux/precompiled_sepolicy"
        || !valid_sidecars(&value.sidecars)
    {
        return Err("mount-policy journal contract is invalid".to_string());
    }
    Ok(value)
}

fn persist(path: &Path, journal: &Journal) -> Result<(), String> {
    atomic(path, &canonical_json(journal)?, 0o600)
}

impl Boundary {
    /// Same logical mount serving the policy path. Mount IDs, parent IDs and
    /// the major:minor pair are NOT stable across a reboot (overlayfs mounts
    /// live on anonymous devices with boot-assigned numbers), so the recovery
    /// paths must compare only the stable topology.
    fn same_logical_mount(&self, other: &Boundary) -> bool {
        self.root == other.root
            && self.mount_point == other.mount_point
            && self.source == other.source
            && self.fs_type == other.fs_type
            && self.security_flags == other.security_flags
    }
}

fn boundaries_match(now: &[Boundary], journal: &[Boundary]) -> bool {
    now.len() == journal.len()
        && now
            .iter()
            .zip(journal)
            .all(|(a, b)| a.same_logical_mount(b))
}

fn with_current_boundary<T>(
    now: &[Boundary],
    journal: &Journal,
    index: usize,
    operation: impl FnOnce(&Boundary, Option<bool>) -> Result<T, String>,
) -> Result<T, String> {
    if !boundaries_match(now, &journal.boundaries) || index >= journal.changed_boundaries {
        return Err("mount topology drifted before protected remount".into());
    }
    operation(&now[index], original_block_flag(journal, index))
}

fn reopen_recovery_window(
    current: &[Boundary],
    journal: &Journal,
    mut remount: impl FnMut(&Boundary, Option<bool>) -> Result<(), String>,
) -> Result<(), String> {
    if journal.recovery_writable_required {
        for index in 0..journal.changed_boundaries {
            with_current_boundary(current, journal, index, |boundary, original| {
                remount(boundary, original)
            })?;
        }
    }
    Ok(())
}

fn recover_publication(
    changed_boundaries: usize,
    verify: impl FnOnce() -> Result<(), String>,
    publish: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    if changed_boundaries == 0 {
        return verify();
    }
    publish()
}

fn bounded_recovery_error(error: &str) -> String {
    let mut retained = error.to_owned();
    while retained.len() > 4096 {
        retained.pop();
    }
    retained
}

fn recover_with_file(
    path: &Path,
    journal: &mut Journal,
    pristine: &mut File,
) -> Result<(), String> {
    if journal.phase == Phase::RebootOwned {
        journal.recovery_writable_required = true;
    }
    journal.phase = Phase::Recovering;
    persist(path, journal)?;
    let pristine_bytes =
        read_exact_file(pristine, journal.pristine_size, &journal.pristine_sha256)?;
    let mut errors = Vec::new();
    let current = current_mounts(Path::new(&journal.policy_path));
    if current
        .as_ref()
        .is_ok_and(|now| boundaries_match(now, &journal.boundaries))
    {
        if let Err(error) =
            reopen_recovery_window(current.as_ref().unwrap(), journal, |boundary, original| {
                policy_remount(boundary, original, false)
            })
        {
            errors.push(error);
        }
        if errors.is_empty() {
            if let Err(error) = recover_publication(
                journal.changed_boundaries,
                || {
                    if !file_matches(
                        Path::new(&journal.policy_path),
                        &pristine_bytes,
                        journal.policy_uid,
                        journal.policy_gid,
                        journal.policy_mode,
                        &journal.policy_selinux_context,
                    )? {
                        return Err("policy changed outside writable recovery authority".into());
                    }
                    verify_sidecars(&journal.sidecars)
                },
                || {
                    publish_policy(Path::new(&journal.policy_path), &pristine_bytes, journal)
                        .and_then(|()| restore_sidecars(&journal.sidecars))
                },
            ) {
                errors.push(error);
            }
        }
    } else if let Err(error) = current {
        errors.push(error);
    } else {
        errors.push("mount topology drifted before policy recovery".to_string());
    }
    for index in (0..journal.changed_boundaries).rev() {
        match current_mounts(Path::new(&journal.policy_path)) {
            Ok(now) if boundaries_match(&now, &journal.boundaries) => {
                if let Err(error) =
                    with_current_boundary(&now, journal, index, |boundary, original| {
                        policy_remount(boundary, original, true)
                    })
                {
                    errors.push(error);
                }
            }
            Ok(_) => errors.push("mount topology drifted before read-only recovery".to_string()),
            Err(error) => errors.push(error),
        }
    }
    if let Err(error) = restore_enforcing(journal.enforcing_required) {
        errors.push(error);
    }
    finish_recovery(path, journal, errors)
}

fn finish_recovery(path: &Path, journal: &mut Journal, errors: Vec<String>) -> Result<(), String> {
    if errors.is_empty() {
        fs::remove_file(path).map_err(|error| error.to_string())?;
        sync_parent(path)
    } else {
        let error = errors.join("; ");
        journal.recovery_error = Some(bounded_recovery_error(&error));
        match persist(path, journal) {
            Ok(()) => Err(error),
            Err(persist_error) => Err(format!(
                "{error}; retain watchdog recovery diagnostic: {persist_error}"
            )),
        }
    }
}

/// Consume startup authority. `true` means the reboot transfer did not cross
/// a boot boundary: pristine recovery completed and a recovery reboot is due.
pub fn consume_startup(path: &Path, current_boot_id: &str) -> Result<bool, String> {
    if !path.exists() {
        return Ok(false);
    }
    let mut journal = load_journal(path)?;
    if startup_action(Some(&journal), current_boot_id) == StartupAction::AcceptLoadedPolicy {
        let mut errors = Vec::new();
        for index in (0..journal.changed_boundaries).rev() {
            match current_mounts(Path::new(&journal.policy_path)) {
                Ok(now) if boundaries_match(&now, &journal.boundaries) => {
                    if let Err(error) =
                        with_current_boundary(&now, &journal, index, |boundary, original| {
                            policy_remount(boundary, original, true)
                        })
                    {
                        errors.push(error);
                    }
                }
                Ok(_) => errors.push("mount topology drifted after reboot".to_string()),
                Err(error) => errors.push(error),
            }
        }
        if let Err(error) = restore_enforcing(journal.enforcing_required) {
            errors.push(error);
        }
        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
        fs::remove_file(path).map_err(|error| error.to_string())?;
        sync_parent(path)?;
        return Ok(false);
    }
    let reboot_failed =
        startup_action(Some(&journal), current_boot_id) == StartupAction::RestoreAndReboot;
    let mut pristine = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&journal.pristine_path)
        .map_err(|error| format!("open journaled pristine policy: {error}"))?;
    recover_with_file(path, &mut journal, &mut pristine)?;
    Ok(reboot_failed)
}

/// Enter the protected policy writable window and spawn its independent owner.
pub fn begin(
    operation: &str,
    transaction_id: &str,
    journal_path: &Path,
    policy_path: &Path,
    pristine_path: &Path,
    boot_id: &str,
) -> Result<Watchdog, String> {
    if !valid_operation(operation)
        || !canonical_tx(transaction_id)
        || !canonical_boot_id(boot_id)
        || policy_path != Path::new("/vendor/etc/selinux/precompiled_sepolicy")
    {
        return Err("mount-policy operation binding is invalid".to_string());
    }
    if journal_path.exists() {
        return Err("interrupted mount-policy journal was not recovered".to_string());
    }
    let mut pristine = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(pristine_path)
        .map_err(|error| format!("open pristine policy before mutation: {error}"))?;
    let pristine_metadata = pristine.metadata().map_err(|error| error.to_string())?;
    if !pristine_metadata.is_file()
        || pristine_metadata.nlink() != 1
        || pristine_metadata.mode() & 0o7777 != 0o600
        || pristine_metadata.len() == 0
        || pristine_metadata.len() > MAX_POLICY_BYTES
        || (cfg!(target_os = "android")
            && (pristine_metadata.uid() != 0 || pristine_metadata.gid() != 0))
    {
        return Err("pristine policy authority is unsafe".to_string());
    }
    let mut pristine_bytes = Vec::with_capacity(pristine_metadata.len() as usize);
    Read::by_ref(&mut pristine)
        .take(MAX_POLICY_BYTES + 1)
        .read_to_end(&mut pristine_bytes)
        .map_err(|error| error.to_string())?;
    if pristine_bytes.len() as u64 != pristine_metadata.len()
        || pristine_bytes.len() as u64 > MAX_POLICY_BYTES
    {
        return Err("pristine policy size is invalid".to_string());
    }
    let policy = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(policy_path)
        .map_err(|error| format!("open protected policy before mutation: {error}"))?;
    let policy_metadata = policy.metadata().map_err(|error| error.to_string())?;
    if !policy_metadata.is_file()
        || policy_metadata.nlink() != 1
        || policy_metadata.mode() & 0o7777 != 0o644
        || (cfg!(target_os = "android")
            && (policy_metadata.uid() != 0 || policy_metadata.gid() != 0))
    {
        return Err("protected policy identity is unsafe".to_string());
    }
    let boundaries = current_mounts(policy_path)?;
    let block_read_only = boundaries
        .iter()
        .map(|boundary| crate::protected_block::capture(block_identity(boundary)))
        .collect::<Result<Vec<_>, _>>()?;
    let sidecars = capture_sidecars()?;
    let mut journal = Journal {
        schema_version: 4,
        operation: operation.to_string(),
        transaction_id: transaction_id.to_string(),
        policy_path: policy_path.to_string_lossy().into_owned(),
        pristine_path: pristine_path.to_string_lossy().into_owned(),
        pristine_size: pristine_metadata.len(),
        pristine_sha256: digest(&pristine_bytes),
        policy_uid: policy_metadata.uid(),
        policy_gid: policy_metadata.gid(),
        policy_mode: policy_metadata.mode() & 0o7777,
        policy_selinux_context: selinux_context(&policy)?,
        boot_id: boot_id.to_string(),
        sidecars,
        boundaries,
        block_read_only,
        changed_boundaries: 0,
        enforcing_required: enforcing()?,
        recovery_writable_required: false,
        phase: Phase::Prepared,
        recovery_error: None,
    };
    persist(journal_path, &journal)?;
    // The watchdog child must not inherit any descriptor of the live policy
    // file. publish_candidate later renames a fresh inode over the policy
    // path, and any surviving descriptor on the replaced inode keeps the
    // overlay/superblock busy, making the transaction's read-only remount
    // fail with EBUSY. The pristine recovery copy (on /data) is inherited
    // deliberately.
    drop(policy);
    let mut pipe = [0; 2];
    if unsafe { libc::pipe(pipe.as_mut_ptr()) } != 0 {
        return Err(format!(
            "create policy watchdog pipe: {}",
            std::io::Error::last_os_error()
        ));
    }
    for descriptor in pipe {
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        if flags < 0
            || unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0
        {
            unsafe {
                libc::close(pipe[0]);
                libc::close(pipe[1]);
            }
            return Err(format!(
                "protect policy watchdog pipe: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(pipe[0]);
            libc::close(pipe[1]);
        }
        return Err(format!(
            "fork policy watchdog: {}",
            std::io::Error::last_os_error()
        ));
    }
    if pid == 0 {
        unsafe {
            libc::close(pipe[1]);
        }
        let code = watchdog_child(pipe[0], journal_path, &mut pristine);
        unsafe {
            libc::_exit(code);
        }
    }
    unsafe {
        libc::close(pipe[0]);
    }
    let watchdog = Watchdog {
        control: Some(unsafe { File::from_raw_fd(pipe[1]) }),
        pid,
        journal_path: journal_path.to_path_buf(),
    };
    for index in 0..journal.boundaries.len() {
        if current_mounts(policy_path)? != journal.boundaries {
            return watchdog.abort().and(Err(
                "mount topology changed before writable remount".to_string()
            ));
        }
        // Grant recovery authority for this boundary before its RW syscall.
        // An RO attempt is harmless if the syscall itself never executes.
        journal.changed_boundaries = index + 1;
        journal.phase = Phase::Writable;
        // A cut may occur after block unlock but before the RW mount. The
        // watchdog must reopen this known boundary before restoring bytes.
        journal.recovery_writable_required = true;
        if let Err(error) = persist(journal_path, &journal) {
            return match watchdog.abort() {
                Ok(()) => Err(error),
                Err(recovery_error) => Err(format!("{error}; {recovery_error}")),
            };
        }
        if let Err(error) = policy_remount(
            &journal.boundaries[index],
            original_block_flag(&journal, index),
            false,
        ) {
            return match watchdog.abort() {
                Ok(()) => Err(error),
                Err(recovery_error) => Err(format!("{error}; {recovery_error}")),
            };
        }
    }
    Ok(watchdog)
}

pub fn valid_operation(operation: &str) -> bool {
    matches!(operation, "install" | "restore" | "update")
}

fn watchdog_child(control_fd: RawFd, journal_path: &Path, pristine: &mut File) -> i32 {
    watchdog_control_result(control_fd, WATCHDOG_TIMEOUT_SECONDS * 1000, || {
        load_journal(journal_path).and_then(|mut journal| {
            pristine.rewind().map_err(|error| error.to_string())?;
            recover_with_file(journal_path, &mut journal, pristine)
        })
    })
}

fn watchdog_control_result(
    control_fd: RawFd,
    timeout_millis: i32,
    recover: impl FnOnce() -> Result<(), String>,
) -> i32 {
    let mut descriptor = libc::pollfd {
        fd: control_fd,
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut descriptor, 1, timeout_millis) };
    let mut command = [0u8; 1];
    let disarmed = result > 0
        && unsafe { libc::read(control_fd, command.as_mut_ptr().cast(), 1) } == 1
        && command[0] == b'D';
    unsafe {
        libc::close(control_fd);
    }
    if disarmed {
        return 0;
    }
    match recover() {
        Ok(()) => 20,
        Err(error) => {
            crate::diagnostic_log::stderr(
                crate::diagnostic_log::Service::Daemon,
                crate::diagnostic_log::Level::Error,
                "policy-watchdog",
                &format!("policy watchdog recovery failed: {error}"),
                &[],
            );
            21
        }
    }
}

/// Publish candidate bytes while the watchdog owns recovery.
pub fn publish_candidate(
    policy_path: &Path,
    bytes: &[u8],
    journal_path: &Path,
) -> Result<(), String> {
    let mut journal = load_journal(journal_path)?;
    if journal.phase != Phase::Writable || journal.policy_path != policy_path.to_string_lossy() {
        return Err("mount-policy transaction is not writable".to_string());
    }
    let targets = journal
        .sidecars
        .iter()
        .map(sidecar_target)
        .collect::<Result<Vec<_>, _>>()?;
    publish_policy(policy_path, bytes, &journal)?;
    for (sidecar, target) in journal.sidecars.iter().zip(targets) {
        publish_sidecar(sidecar, &target)?;
    }
    journal.phase = Phase::PolicyPublished;
    persist(journal_path, &journal)
}

/// Durably transfer recovery to the next-boot startup path before disarming.
pub fn transfer_to_reboot(journal_path: &Path, expected_boot_id: &str) -> Result<(), String> {
    let mut journal = load_journal(journal_path)?;
    if journal.phase != Phase::PolicyPublished || journal.boot_id != expected_boot_id {
        return Err("mount-policy reboot transfer is not correlated".to_string());
    }
    // Recovery must reopen the exact writable boundary after any cut once the
    // following read-only remount begins. Publish that authority first.
    journal.recovery_writable_required = true;
    persist(journal_path, &journal)?;
    let mut errors = Vec::new();
    for index in (0..journal.changed_boundaries).rev() {
        match current_mounts(Path::new(&journal.policy_path)) {
            Ok(now) if now == journal.boundaries => {
                if let Err(error) =
                    with_current_boundary(&now, &journal, index, |boundary, original| {
                        policy_remount(boundary, original, true)
                    })
                {
                    errors.push(error);
                }
            }
            Ok(_) => errors.push("mount topology drifted before reboot transfer".to_string()),
            Err(error) => errors.push(error),
        }
    }
    if let Err(error) = restore_enforcing(journal.enforcing_required) {
        errors.push(error);
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    journal.phase = Phase::RebootOwned;
    persist(journal_path, &journal)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_boundary() -> Boundary {
        Boundary {
            mount_id: 1,
            parent_id: 0,
            major_minor: "253:65".into(),
            root: "/".into(),
            mount_point: "/vendor".into(),
            source: "/dev/block/vendor".into(),
            fs_type: "ext4".into(),
            security_flags: 2 | 4 | 8,
        }
    }

    #[test]
    fn diagnostic_policy_hash_is_bounded_and_never_hashes_read_errors() {
        assert_eq!(
            diagnostic_digest(std::io::Cursor::new(b"policy"), 6).unwrap(),
            format!("{:x}", Sha256::digest(b"policy"))
        );
        assert!(diagnostic_digest(std::io::Cursor::new(b"policy"), 5)
            .unwrap_err()
            .contains("limit"));
        struct Denied;
        impl Read for Denied {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from_raw_os_error(13))
            }
        }
        assert!(diagnostic_digest(Denied, 64)
            .unwrap_err()
            .contains("os error 13"));
    }

    #[test]
    fn remount_preserves_source_type_and_security_flags() {
        let boundary = test_boundary();
        for read_only in [false, true] {
            remount_with(&boundary, read_only, |source, target, fs_type, flags| {
                assert_eq!(source.to_bytes(), b"/dev/block/vendor");
                assert_eq!(target.to_bytes(), b"/vendor");
                assert_eq!(fs_type.to_bytes(), b"ext4");
                assert_eq!(flags, 32 | 2 | 4 | 8 | u64::from(read_only));
                Ok(read_only)
            })
            .unwrap();
        }
    }

    #[test]
    fn remount_rejects_silent_noop_and_retains_syscall_failure() {
        let boundary = test_boundary();
        assert!(remount_with(&boundary, false, |_, _, _, _| Ok(true))
            .unwrap_err()
            .contains("reported success"));
        let error = remount_with(&boundary, false, |_, _, _, _| {
            Err("Permission denied (os error 13)".into())
        })
        .unwrap_err();
        assert!(error.contains("Permission denied (os error 13)"));
        assert!(error.contains("source=/dev/block/vendor type=ext4 flags=0x2e"));
    }

    #[test]
    fn update_journal_roundtrips_and_watchdog_returns_retained_recovery_error() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy-mount.json");
        let mut sidecar = test_sidecar();
        sidecar.selinux_context = b"u:object_r:vendor_configs_file:s0".to_vec();
        let mut journal = Journal {
            schema_version: 3,
            operation: "update".into(),
            transaction_id: "a".repeat(64),
            policy_path: "/vendor/etc/selinux/precompiled_sepolicy".into(),
            pristine_path: "/data/voboost/recovery/pristine".into(),
            pristine_size: 1,
            pristine_sha256: "b".repeat(64),
            policy_uid: 0,
            policy_gid: 0,
            policy_mode: 0o644,
            policy_selinux_context: Vec::new(),
            boot_id: "00000000-0000-0000-0000-000000000001".into(),
            sidecars: vec![sidecar],
            boundaries: vec![test_boundary()],
            block_read_only: Vec::new(),
            changed_boundaries: 0,
            enforcing_required: true,
            recovery_writable_required: false,
            phase: Phase::Recovering,
            recovery_error: Some(
                "read-only recovery remount: Permission denied (os error 13)".into(),
            ),
        };
        persist(&path, &journal).unwrap();
        assert_eq!(load_journal(&path).unwrap().operation, "update");
        #[cfg(unix)]
        {
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                unsafe {
                    libc::_exit(21);
                }
            }
            let error = wait_child(pid, false, &path).unwrap_err();
            assert!(error.contains("expected 20: read-only recovery remount: Permission denied"));
        }
        journal.recovery_error = Some("x".repeat(4097));
        persist(&path, &journal).unwrap();
        assert!(load_journal(&path).is_err());
        journal.recovery_error = None;
        persist(&path, &journal).unwrap();
        let old_bytes = fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&old_bytes).contains("recoveryError"));
        assert_eq!(
            canonical_json(&load_journal(&path).unwrap()).unwrap(),
            old_bytes
        );
        // Legacy bytes remain canonical and carry no guessed block authority.
        assert!(!String::from_utf8_lossy(&old_bytes).contains("blockReadOnly"));
        assert_eq!(original_block_flag(&journal, 0), None);
        journal.schema_version = 4;
        journal.block_read_only = vec![Some(true)];
        persist(&path, &journal).unwrap();
        assert_eq!(
            load_journal(&path).unwrap().block_read_only,
            vec![Some(true)]
        );
        journal.block_read_only = vec![Some(false)];
        persist(&path, &journal).unwrap();
        assert_eq!(
            load_journal(&path).unwrap().block_read_only,
            vec![Some(false)]
        );
        journal.block_read_only.clear();
        persist(&path, &journal).unwrap();
        assert!(load_journal(&path).is_err());
        journal.block_read_only = vec![None];
        persist(&path, &journal).unwrap();
        assert!(load_journal(&path).is_err());
        journal.boundaries[0].fs_type = "overlay".into();
        persist(&path, &journal).unwrap();
        assert!(load_journal(&path).is_ok());
        journal.block_read_only = vec![Some(true)];
        persist(&path, &journal).unwrap();
        assert!(load_journal(&path).is_err());
        journal.schema_version = 3;
        journal.block_read_only.clear();
        // Reboot remapping uses the validated current device, never stale rdev.
        journal.schema_version = 4;
        journal.block_read_only = vec![Some(false)];
        journal.boundaries[0].fs_type = "ext4".into();
        journal.changed_boundaries = 1;
        let mut current = journal.boundaries.clone();
        current[0].major_minor = "254:77".into();
        let observed = with_current_boundary(&current, &journal, 0, |boundary, original| {
            Ok((block_identity(boundary).major_minor.to_string(), original))
        })
        .unwrap();
        assert_eq!(observed, ("254:77".into(), Some(false)));
        journal.phase = Phase::Writable;
        journal.recovery_writable_required = true;
        persist(&path, &journal).unwrap();
        let cut = load_journal(&path).unwrap();
        assert!(cut.recovery_writable_required);
        assert_eq!(cut.block_read_only, vec![Some(false)]);
        journal.phase = Phase::Recovering;
        current[0].source = "/dev/block/substituted".into();
        assert!(
            with_current_boundary(&current, &journal, 0, |_, _| -> Result<(), String> {
                panic!("foreign identity reached ioctl")
            })
            .is_err()
        );
        let unicode = bounded_recovery_error(&"界".repeat(2000));
        assert!(unicode.len() <= 4096);
        assert_eq!(unicode, "界".repeat(1365));
        // Failed block protection must retain durable recovery authority.
        let error = finish_recovery(
            &path,
            &mut journal,
            vec!["block protection restore failed".into()],
        )
        .unwrap_err();
        assert!(error.contains("block protection restore failed"));
        assert!(path.exists());
        assert_eq!(
            load_journal(&path).unwrap().recovery_error.as_deref(),
            Some("block protection restore failed")
        );
        finish_recovery(&path, &mut journal, Vec::new()).unwrap();
        assert!(!path.exists());
        // Parent EOF after unlock but before RW: actual watchdog control and
        // recovery seams reopen the journaled window before publication.
        journal.phase = Phase::Writable;
        journal.recovery_writable_required = true;
        journal.block_read_only = vec![Some(true)];
        persist(&path, &journal).unwrap();
        let state = std::cell::RefCell::new((false, true)); // block unlocked, mount RO
        let mut pipe = [0; 2];
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        unsafe {
            libc::close(pipe[1]);
        }
        let code = watchdog_control_result(pipe[0], 100, || {
            let mut cut = load_journal(&path)?;
            let current = cut.boundaries.clone();
            reopen_recovery_window(&current, &cut, |_, original| {
                assert_eq!(original, Some(true));
                state.borrow_mut().0 = false;
                state.borrow_mut().1 = false;
                Ok(())
            })?;
            recover_publication(
                cut.changed_boundaries,
                || Ok(()),
                || {
                    if state.borrow().1 {
                        return Err("publication attempted on RO mount".into());
                    }
                    Ok(())
                },
            )?;
            // Authority survives partial RO recovery, so another attempt can
            // reopen the window instead of being permanently stranded.
            state.borrow_mut().1 = true;
            persist(&path, &cut)?;
            cut = load_journal(&path)?;
            reopen_recovery_window(&current, &cut, |_, _| {
                state.borrow_mut().1 = false;
                Ok(())
            })?;
            with_current_boundary(&current, &cut, 0, |_, original| {
                state.borrow_mut().1 = true;
                state.borrow_mut().0 = original.unwrap();
                Ok(())
            })?;
            finish_recovery(&path, &mut cut, Vec::new())
        });
        assert_eq!(code, 20);
        assert_eq!(*state.borrow(), (true, true));
        assert!(!path.exists());
        journal.operation = "unknown".into();
        persist(&path, &journal).unwrap();
        assert!(load_journal(&path).is_err());
    }

    #[test]
    fn untouched_policy_recovery_verifies_without_write_authority() {
        let reads = std::cell::Cell::new(0);
        let writes = std::cell::Cell::new(0);
        recover_publication(
            0,
            || {
                reads.set(reads.get() + 1);
                Ok(())
            },
            || {
                writes.set(writes.get() + 1);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!((reads.get(), writes.get()), (1, 0));
        assert!(recover_publication(
            0,
            || Err("foreign policy".into()),
            || {
                writes.set(writes.get() + 1);
                Ok(())
            }
        )
        .is_err());
        assert_eq!(writes.get(), 0);
        recover_publication(
            1,
            || panic!("writable recovery must restore"),
            || {
                writes.set(writes.get() + 1);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(writes.get(), 1);
    }

    #[test]
    fn failed_policy_publication_cleans_only_the_retained_temporary_inode() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("temporary");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let cleanup = PolicyTemporary::new(&path, &file).unwrap();
        file.write_all(b"partial").unwrap();
        drop(cleanup);
        assert!(!path.exists());
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let cleanup = PolicyTemporary::new(&path, &file).unwrap();
        fs::rename(&path, directory.path().join("retained")).unwrap();
        fs::write(&path, b"foreign").unwrap();
        drop(cleanup);
        assert_eq!(fs::read(&path).unwrap(), b"foreign");
    }

    #[test]
    fn policy_publication_preserves_foreign_symlink_and_hard_link_temporaries() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy");
        fs::write(&path, b"original").unwrap();
        let meta = fs::metadata(&path).unwrap();
        let temporary = directory.path().join(".policy.policy-transaction.tmp");
        let victim = directory.path().join("victim");
        fs::write(&victim, b"foreign").unwrap();
        std::os::unix::fs::symlink(&victim, &temporary).unwrap();
        assert!(publish_file(
            &path,
            b"candidate",
            meta.uid(),
            meta.gid(),
            meta.mode() & 0o7777,
            &[]
        )
        .is_err());
        assert!(fs::symlink_metadata(&temporary)
            .unwrap()
            .file_type()
            .is_symlink());
        fs::remove_file(&temporary).unwrap();
        fs::hard_link(&victim, &temporary).unwrap();
        assert!(publish_file(
            &path,
            b"candidate",
            meta.uid(),
            meta.gid(),
            meta.mode() & 0o7777,
            &[]
        )
        .is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"foreign");
        assert_eq!(fs::read(&path).unwrap(), b"original");
    }

    #[test]
    fn sidecar_backup_binds_complete_platform_sets_bytes_and_original_absence() {
        let fixture = include_bytes!("../../test/fixtures/policy-sidecars.json");
        let mut a9 = parse_sidecar_backup(fixture).unwrap();
        assert!(valid_sidecars(&a9));
        a9[0].pristine[0] ^= 1;
        assert!(!valid_sidecars(&a9));
        a9 = parse_sidecar_backup(fixture).unwrap();
        a9[0].present = false;
        assert!(!valid_sidecars(&a9));
        a9[0].pristine.clear();
        a9[0].sha256 = digest(&[]);
        assert!(valid_sidecars(&a9));
        let a11 = A11_DIGESTS
            .iter()
            .map(|(path, _)| {
                let mut sidecar = a9[0].clone();
                sidecar.path = (*path).into();
                sidecar
            })
            .collect::<Vec<_>>();
        assert!(valid_sidecars(&a11));
        assert!(!valid_sidecars(&a11[..2]));
        let mut reordered = a11.clone();
        reordered.swap(0, 1);
        assert!(!valid_sidecars(&reordered));
        let mut duplicate = a11;
        duplicate[2] = duplicate[1].clone();
        assert!(!valid_sidecars(&duplicate));
        for invalid in [
            String::from_utf8_lossy(fixture).replace("\"schemaVersion\":1", "\"schemaVersion\":2"),
            String::from_utf8_lossy(fixture)
                .replace("\"present\":true", "\"present\":true,\"present\":false"),
            String::from_utf8_lossy(fixture).replace("\"uid\":0", "\"uid\":1"),
            String::from_utf8_lossy(fixture)
                .replace("precompiled_sepolicy.plat_and_mapping.sha256", "../outside"),
        ] {
            assert!(parse_sidecar_backup(invalid.as_bytes()).is_err());
        }
        assert!(digest_pairs(29).is_err());
        assert_eq!(digest_pairs(28).unwrap().len(), 1);
        assert_eq!(digest_pairs(30).unwrap().len(), 3);
    }

    #[test]
    fn digest_parser_rejects_trailing_data_uppercase_and_non_sha_inputs() {
        for valid in [b"a".repeat(64), [b"a".repeat(64), b"\n".to_vec()].concat()] {
            parse_digest(&valid).unwrap();
        }
        for invalid in [
            Vec::new(),
            b"A".repeat(64),
            b"a".repeat(63),
            [b"a".repeat(64), b"\nextra".to_vec()].concat(),
        ] {
            assert!(parse_digest(&invalid).is_err());
        }
    }

    #[test]
    fn recovery_preserves_an_unchanged_policy_without_republishing() {
        let directory = tempfile::tempdir().unwrap();
        let policy = directory.path().join("policy");
        fs::write(&policy, b"pristine").unwrap();
        let before = fs::metadata(&policy).unwrap();
        publish_file(
            &policy,
            b"pristine",
            before.uid(),
            before.gid(),
            before.mode() & 0o7777,
            &[],
        )
        .unwrap();
        let after = fs::metadata(&policy).unwrap();
        assert_eq!(
            before.ino(),
            after.ino(),
            "unchanged recovery must not require create/rename rights"
        );
    }

    #[test]
    fn recovery_republishes_changed_bytes_and_rejects_a_substituted_link() {
        let directory = tempfile::tempdir().unwrap();
        let policy = directory.path().join("policy");
        fs::write(&policy, b"changed!").unwrap();
        let before = fs::metadata(&policy).unwrap();
        publish_file(
            &policy,
            b"pristine",
            before.uid(),
            before.gid(),
            before.mode() & 0o7777,
            &[],
        )
        .unwrap();
        assert_eq!(fs::read(&policy).unwrap(), b"pristine");
        assert_ne!(fs::metadata(&policy).unwrap().ino(), before.ino());
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&policy, &link).unwrap();
        assert!(publish_file(
            &link,
            b"pristine",
            before.uid(),
            before.gid(),
            before.mode() & 0o7777,
            &[]
        )
        .is_err());
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn forked_watchdog_survives_parent_sigkill_and_recovers() {
        let mut pipe = [0; 2];
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        let parent = unsafe { libc::fork() };
        assert!(parent >= 0);
        if parent == 0 {
            unsafe {
                libc::close(pipe[0]);
            }
            let mut control = [0; 2];
            if unsafe { libc::pipe(control.as_mut_ptr()) } != 0 {
                unsafe { libc::_exit(2) };
            }
            let child = unsafe { libc::fork() };
            if child == 0 {
                unsafe { libc::close(control[1]) };
                let code = watchdog_control_result(control[0], 5_000, || {
                    let byte = b'R';
                    let written = unsafe { libc::write(pipe[1], (&byte as *const u8).cast(), 1) };
                    (written == 1)
                        .then_some(())
                        .ok_or_else(|| "write recovery callback".to_string())
                });
                unsafe { libc::_exit((code != 20) as i32) };
            }
            unsafe { libc::close(control[0]) };
            let byte = b'S';
            unsafe {
                libc::write(pipe[1], (&byte as *const u8).cast(), 1);
            }
            unsafe {
                libc::pause();
                libc::_exit(1);
            }
        }
        unsafe {
            libc::close(pipe[1]);
        }
        let mut byte = 0u8;
        assert_eq!(
            unsafe { libc::read(pipe[0], (&mut byte as *mut u8).cast(), 1) },
            1
        );
        assert_eq!(byte, b'S');
        unsafe {
            libc::kill(parent, libc::SIGKILL);
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(parent, &mut status, 0) }, parent);
        assert_eq!(
            unsafe { libc::read(pipe[0], (&mut byte as *mut u8).cast(), 1) },
            1
        );
        assert_eq!(byte, b'R');
        unsafe {
            libc::close(pipe[0]);
        }
    }

    #[test]
    fn resolver_supports_shared_root_and_split_topology_and_rejects_drift() {
        let a9 = b"1 0 8:1 / / rw,nosuid,nodev - ext4 /dev/root rw\n";
        let a11 = b"1 0 8:1 / /system rw,nodev - ext4 /dev/block/system rw\n2 0 8:2 / /vendor rw,nosuid - ext4 /dev/block/vendor rw\n";
        assert_eq!(
            resolve_mounts(a9, &["/vendor/etc/selinux/precompiled_sepolicy".into()])
                .unwrap()
                .len(),
            1
        );
        let split = resolve_mounts(
            a11,
            &[
                "/system/etc/init/voboost.rc".into(),
                "/vendor/etc/selinux/precompiled_sepolicy".into(),
            ],
        )
        .unwrap();
        assert_eq!(split.len(), 2);
        assert_ne!(split[0], split[1]);
        let drift = b"1 0 8:9 / /vendor rw - ext4 /dev/block/changed rw\n";
        assert_ne!(
            resolve_mounts(drift, &["/vendor/etc/selinux/precompiled_sepolicy".into()]).unwrap(),
            split[1..]
        );
    }

    #[test]
    fn resolver_accepts_writable_system_overlay_stack_and_selects_topmost() {
        let stacked = b"56 45 253:3 / /vendor ro,relatime shared:10 - ext4 /dev/block/dm-3 ro,seclabel\n57 56 0:24 / /vendor ro,noatime shared:11 - overlay overlay ro,seclabel,lowerdir=/vendor,upperdir=/mnt/scratch/overlay/vendor/upper,workdir=/mnt/scratch/overlay/vendor/work,override_creds=off\n";
        let resolved = resolve_mounts(
            stacked,
            &["/vendor/etc/selinux/precompiled_sepolicy".into()],
        )
        .unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].mount_id, 57);
        assert_eq!(resolved[0].fs_type, "overlay");
        // Overlay over a NON-matching mount point stays ambiguous.
        let foreign = b"56 45 253:3 / /vendor ro - ext4 /dev/block/dm-3 ro\n57 56 0:24 / /vendor ro - overlay overlay ro,lowerdir=/other,upperdir=/mnt/scratch/overlay/vendor/upper,workdir=/mnt/scratch/overlay/vendor/work\n";
        assert!(resolve_mounts(
            foreign,
            &["/vendor/etc/selinux/precompiled_secompiled".into()]
        )
        .is_err());
        // Two overlays stacked (no exactly-one-overlay shape) stay ambiguous.
        let triple = b"56 45 253:3 / /vendor ro - ext4 /dev/block/dm-3 ro\n57 56 0:24 / /vendor ro - overlay overlay ro,lowerdir=/vendor,upperdir=/u,workdir=/w\n58 57 0:25 / /vendor ro - overlay overlay ro,lowerdir=/vendor,upperdir=/u2,workdir=/w2\n";
        assert!(
            resolve_mounts(triple, &["/vendor/etc/selinux/precompiled_sepolicy".into()]).is_err()
        );
        // Overlay without its physical partition beneath is rejected.
        let lonely = b"57 45 0:24 / /vendor ro - overlay overlay ro,lowerdir=/vendor,upperdir=/u,workdir=/w\n";
        assert!(
            resolve_mounts(lonely, &["/vendor/etc/selinux/precompiled_sepolicy".into()]).is_err()
        );
    }

    #[test]
    fn boundaries_match_ignores_boot_unstable_overlay_identity() {
        let before = b"3430 42 253:3 / /vendor ro,relatime shared:10 - ext4 /dev/block/dm-3 ro,seclabel\n3431 42 0:86 / /vendor ro,noatime shared:11 - overlay overlay ro,seclabel,lowerdir=/vendor,upperdir=/mnt/scratch/overlay/vendor/upper,workdir=/mnt/scratch/overlay/vendor/work\n";
        let after = b"56 45 253:3 / /vendor ro,relatime shared:10 - ext4 /dev/block/dm-3 ro,seclabel\n57 56 0:24 / /vendor ro,noatime shared:11 - overlay overlay ro,seclabel,lowerdir=/vendor,upperdir=/mnt/scratch/overlay/vendor/upper,workdir=/mnt/scratch/overlay/vendor/work\n";
        let target = "/vendor/etc/selinux/precompiled_sepolicy";
        let a = resolve_mounts(before, &[target.into()]).unwrap();
        let b = resolve_mounts(after, &[target.into()]).unwrap();
        assert_ne!(a, b); // exact equality legitimately drifts across the boot
        assert!(boundaries_match(&b, &a));
        let foreign = b"57 56 0:24 / /vendor ro - ext4 /dev/block/dm-3 ro\n";
        let c = resolve_mounts(foreign, &[target.into()]).unwrap();
        assert!(!boundaries_match(&c, &a));
    }

    #[test]
    fn enforcing_restore_uses_the_production_callback_path_and_rechecks() {
        let enforcing = std::cell::Cell::new(false);
        let writes = std::cell::Cell::new(0usize);
        restore_enforcing_with(
            true,
            || Ok(enforcing.get()),
            || {
                writes.set(writes.get() + 1);
                enforcing.set(true);
                Ok(())
            },
        )
        .unwrap();
        assert!(enforcing.get());
        assert_eq!(writes.get(), 1);
    }

    fn test_sidecar() -> Sidecar {
        let pristine = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
        Sidecar {
            path: POLICY_SIDECAR.to_string(),
            present: true,
            sha256: digest(pristine),
            uid: 0,
            gid: 0,
            mode: 0o644,
            selinux_context: Vec::new(),
            pristine: pristine.to_vec(),
        }
    }

    #[test]
    fn boot_id_failure_restores_and_requests_recovery_reboot() {
        let mut journal = Journal {
            schema_version: 3,
            operation: "install".into(),
            transaction_id: "a".repeat(64),
            policy_path: "/vendor/etc/selinux/precompiled_sepolicy".into(),
            pristine_path: "/data/voboost/recovery/pristine".into(),
            pristine_size: 1,
            pristine_sha256: "b".repeat(64),
            policy_uid: 0,
            policy_gid: 0,
            policy_mode: 0o644,
            policy_selinux_context: Vec::new(),
            boot_id: "boot-a".into(),
            sidecars: vec![test_sidecar()],
            boundaries: Vec::new(),
            block_read_only: Vec::new(),
            changed_boundaries: 0,
            enforcing_required: true,
            recovery_writable_required: false,
            phase: Phase::RebootOwned,
            recovery_error: None,
        };
        assert_eq!(
            startup_action(Some(&journal), "boot-a"),
            StartupAction::RestoreAndReboot
        );
        assert_eq!(
            startup_action(Some(&journal), "boot-b"),
            StartupAction::AcceptLoadedPolicy
        );
        journal.phase = Phase::Writable;
        assert_eq!(
            startup_action(Some(&journal), "boot-a"),
            StartupAction::RestoreInterrupted
        );
    }

    #[test]
    fn reboot_owned_recovery_persists_rw_requirement_across_recovery_cut() {
        let mut journal = Journal {
            schema_version: 3,
            operation: "restore".into(),
            transaction_id: "a".repeat(64),
            policy_path: "/vendor/etc/selinux/precompiled_sepolicy".into(),
            pristine_path: "/data/voboost/recovery/pristine".into(),
            pristine_size: 1,
            pristine_sha256: "b".repeat(64),
            policy_uid: 0,
            policy_gid: 0,
            policy_mode: 0o644,
            policy_selinux_context: Vec::new(),
            boot_id: "00000000-0000-0000-0000-000000000001".into(),
            sidecars: vec![test_sidecar()],
            boundaries: Vec::new(),
            block_read_only: Vec::new(),
            changed_boundaries: 0,
            enforcing_required: true,
            recovery_writable_required: false,
            phase: Phase::RebootOwned,
            recovery_error: None,
        };
        if journal.phase == Phase::RebootOwned {
            journal.recovery_writable_required = true;
        }
        journal.phase = Phase::Recovering;
        let bytes = canonical_json(&journal).unwrap();
        let resumed: Journal = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(resumed.phase, Phase::Recovering);
        assert!(resumed.recovery_writable_required);
    }
}
