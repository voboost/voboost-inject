// Uninstall-owned transaction implementation.
//
// Normal execution starts in the dedicated `voboost_uninstall` SELinux domain.
// The primary service publishes transaction-bound recovery state, publishes
// and verifies the pristine policy bytes on disk while retaining the loaded
// patched policy, and binds terminal cleanup to the current boot. A distinct
// init-owned watchdog durably commits cleanup; a restartable init successor
// covers every last-unlink cut and exits after exact zero residue. Reboot
// decisions belong to the external fixed absence predicate. No caller-
// controlled path or command is ever accepted.

#[path = "cli.rs"]
mod cli;

pub(crate) use cli::run;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

use operation_contract::{Operation, OperationDescriptor, OperationLease};
use voboost_contract::operation as operation_contract;
use voboost_contract::release::RestoreDocument;

use voboost_shared::fixed_process;

#[allow(unused_imports)]
use voboost_shared::installed_apk;

use voboost_shared::lifecycle_file::{FileStamp, TrustedBytes};

use crate::selinux_backend::{
    AGENT_STATE_CONTEXT, DATA_CONTEXT, INSTALLED_STATE_CONTEXT, PROTECTED_CONTEXT,
    RECOVERY_HOOK_BYTES, RECOVERY_TREE_CONTEXT, RESTORE_EXEC_CONTEXT, RUNTIME_EXEC_CONTEXT,
    SELINUX_EXEC_CONTEXT, STOCK_RECOVERY_CONTEXT, UNINSTALL_EXEC_CONTEXT,
};
struct DirectoryStream(*mut libc::DIR);

/// Append one diagnostic line to the transaction-owned `diag.log` beside the
/// WAL. The uninstall service has no other durable observability: init starts
/// it only after the resident daemon (the appender of the canonical log) has
/// already been stopped, so its own first-cause trail must live inside the
/// recovery transaction directory it exclusively owns. Every failure mirror
/// and phase transition is duplicated here with its exact input/output so a
/// failed transaction can be diagnosed from the device alone — never from
/// logcat. Best-effort by design: diagnostics must never alter the outcome of
/// the transaction, so all errors are swallowed.
///
/// Ownership guard, identical to write_failure_mirror below: the very same
/// binary also runs in its watchdog / bound-boot-id / remount-recovery roles
/// while an INSTALL transaction owns the recovery directory (install writes
/// no uninstall members there, so discover_uninstall_transaction_id still
/// hands its id to UNINSTALL_PATHS). Writing then would violate the install
/// cleanup contract ("foreign install recovery member"), so the diagnostic
/// only ever lands in a directory that carries uninstall WAL members.
pub(crate) fn diag(text: &str) {
    use voboost_shared::diagnostic_log::{self, Level, Service};
    let level = if text.starts_with("fail ") || text.starts_with("phase failed ") {
        Level::Error
    } else if text == "terminal cleanup reached" {
        Level::Info
    } else {
        Level::Debug
    };
    let phase = text
        .strip_prefix("phase begin ")
        .or_else(|| text.strip_prefix("phase ok "))
        .or_else(|| text.strip_prefix("phase failed "))
        .map(|value| value.split(':').next().unwrap_or(value));
    let fields = phase
        .map(|value| vec![("phase", value)])
        .unwrap_or_default();
    let bytes = diagnostic_log::encode(Service::Uninstall, level, "uninstall", text, &fields);
    let durable = (|| -> std::io::Result<()> {
        let paths = UNINSTALL_PATHS.get().ok_or(std::io::ErrorKind::NotFound)?;
        let owns_uninstall = ["uninstall_do.json", "uninstall-journal.json"]
            .iter()
            .any(|member| {
                fs::symlink_metadata(format!("{}/{}", paths.recovery_dir, member)).is_ok()
            });
        if !owns_uninstall {
            return Err(std::io::ErrorKind::NotFound.into());
        }
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(format!("{}/diag.log", paths.recovery_dir))?;
        file.write_all(&bytes)?;
        file.sync_all()
    })();
    if durable.is_err() {
        diagnostic_log::write_best_effort(&mut std::io::stderr().lock(), &bytes);
    }
}

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        unsafe {
            libc::closedir(self.0);
        }
    }
}

fn clear_thread_errno() {
    unsafe {
        #[cfg(target_os = "android")]
        {
            *libc::__errno() = 0;
        }
        #[cfg(target_os = "linux")]
        {
            *libc::__errno_location() = 0;
        }
        #[cfg(target_vendor = "apple")]
        {
            *libc::__error() = 0;
        }
    }
}

fn thread_errno() -> i32 {
    unsafe {
        #[cfg(target_os = "android")]
        {
            *libc::__errno()
        }
        #[cfg(target_os = "linux")]
        {
            *libc::__errno_location()
        }
        #[cfg(target_vendor = "apple")]
        {
            *libc::__error()
        }
    }
}

const OWNERSHIP_MARKER_PATH: &str = uninstall_contract::ROOT_ZONE_MARKER_PATH;
const OWNERSHIP_MARKER: &[u8] = uninstall_contract::ROOT_ZONE_MARKER_BYTES;
const SYSTEM_ARTIFACTS_PATH: &str = "/data/voboost/uninstall/system-artifacts.json";
const CURRENT_BASELINE_PATH: &str = "/data/voboost/uninstall/current-baseline.json";
const SYSTEM_STATE_PATH: &str = "/data/voboost/uninstall/system-state.json";
const RC_ARCHIVE_PATH: &str = "/data/voboost/uninstall/system/voboost.rc";
const RC_PATH: &str = "/system/etc/init/voboost.rc";
const RC_INSTALL_TEMP_PATH: &str = "/system/etc/init/.voboost.rc.install.tmp";
const SELINUX_PATH: &str = "/data/voboost/voboost-selinux";
const RESTORE_PATH: &str = "/data/voboost/voboost-restore";
const RESTORE_MANIFEST_PATH: &str = "/data/voboost/restore.json";
const RESTORE_MANIFEST_SIGNATURE_PATH: &str = "/data/voboost/restore.json.sig";
const PRECOMPILED_PATH: &str = "/vendor/etc/selinux/precompiled_sepolicy";
const PRECOMPILED_META: &str = "/data/voboost/uninstall/policy.meta.json";
const RECOVERY_PATH: &str = "/data/voboost/voboost-uninstall";
const RECOVERY_ROOT: &str = "/data/voboost/recovery";
const RECOVERY_HOOK_TEMP_PATH: &str = "/system/etc/init/.voboost-uninstall-recovery.rc.tmp";
const APP_DATA_PATHS: [&str; 3] = [
    "/data/user/0/ru.voboost",
    "/data/user_de/0/ru.voboost",
    "/data/data/ru.voboost",
];
const MAX_POLICY_CONTEXT_BYTES: usize = 128;
const MAX_REMOUNT_JOURNAL_BYTES: u64 = 4096;
const POLICY_RESTORE_TEMP_PATH: &str = "/vendor/etc/selinux/.voboost-precompiled.restore.tmp";
const ZONE: &str = "/data/voboost";
const RC_MARKER: &str = "# >>> voboost-daemon (do not edit)";
const UNINSTALL_WATCHDOG_READY: u8 = b'R';
const UNINSTALL_WATCHDOG_COMMIT: u8 = b'C';
const UNINSTALL_WATCHDOG_ACK: u8 = b'A';
const UNINSTALL_SUCCESSOR_GO: u8 = b'G';
const UNINSTALL_SUCCESSOR_DONE: u8 = b'D';
// The successor is this boot's sole reboot owner after DONE. It publishes
// REBOOT_ARMED once init accepted its sys.powerctl request, so the surviving
// watchdog can tell "successor already initiated the reboot" from "the
// successor died before arming" and must not issue a competing request (the
// property service is already shutting down and rejects it — observed as the
// v84 watchdog exit on the second reboot attempt). Byte 0 must never be a
// protocol value: it is the EOF/peer-lost channel.
const UNINSTALL_SUCCESSOR_REBOOT_ARMED: u8 = b'B';

struct RetainedUninstallDirectories {
    data_parent: File,
    root: File,
    init_parent: File,
    init_hook: Option<File>,
    init_hook_stamp: FileStamp,
}

impl RetainedUninstallDirectories {
    fn open(expected: &RecoveryState) -> Result<Self, String> {
        let data_parent = open_directory_nofollow(Path::new("/data"), "data parent")?;
        let root = openat_directory_nofollow(&data_parent, b"voboost", "root zone")?;
        let root_stamp = FileStamp::from(
            &root
                .metadata()
                .map_err(|error| format!("fstat retained root zone: {error}"))?,
        );
        if root_stamp.uid != 0
            || root_stamp.gid != 0
            || root_stamp.mode & 0o7777 != 0o755
            || root_stamp.dev != expected.zone_dev
            || root_stamp.ino != expected.zone_ino
        {
            return Err("retained root-zone identity differs from recovery authority".to_string());
        }
        let init_parent = open_directory_nofollow(Path::new("/system/etc/init"), "init parent")?;
        let init_stamp = FileStamp::from(
            &init_parent
                .metadata()
                .map_err(|error| format!("fstat retained init parent: {error}"))?,
        );
        // Overlayfs (writable-system boots) reports directory nlink as 1 even
        // for populated directories, so the long-standing "at least self plus
        // one entry" rail cannot hold there. A zero link count would mean a
        // removed-while-open directory; everything else about this handle is
        // pinned by O_DIRECTORY|O_NOFOLLOW and the exact stamp checks below.
        if init_stamp.uid != 0 || init_stamp.gid != 0 || init_stamp.nlink < 1 {
            return Err("retained init-parent identity is unsafe".to_string());
        }
        let init_hook = openat_regular_nofollow(&init_parent, "voboost.rc")?;
        let trusted = read_retained_bytes(&init_hook, 4096, "retained terminal init hook")?;
        require_root_file(trusted.stamp, 0o644, "retained terminal init hook")?;
        require_trusted_context(
            &trusted,
            STOCK_RECOVERY_CONTEXT,
            "retained terminal init hook",
        )?;
        if !recovery_hook_bytes_are_exact(&trusted.bytes) {
            return Err("retained terminal init hook bytes differ".to_string());
        }
        Ok(Self {
            data_parent,
            root,
            init_parent,
            init_hook: Some(init_hook),
            init_hook_stamp: trusted.stamp,
        })
    }

    /// Close the retained terminal init-hook handle. The hook file lives in
    /// the writable /system overlay's upperdir and overlayfs refuses the
    /// closing RO remount with EBUSY while any descriptor pins an upperdir
    /// inode (including a read-only or already unlinked one), so the
    /// terminal unlink must run with this handle closed; the recorded
    /// stamp keeps protecting the identity rail.
    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    fn close_init_hook(&mut self) -> Result<(), String> {
        // The stamp comparisons below remain the safety rail; dropping the
        // handle releases the only upperdir pin this struct holds.
        if let Some(handle) = self.init_hook.take() {
            drop(handle);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct UninstallPaths {
    transaction_id: String,
    recovery_dir: String,
    state: String,
    state_temp: String,
    prepared_marker: String,
    phase: String,
    phase_temp: String,
    remount_journal: String,
    remount_journal_temp: String,
    watchdog_socket: String,
}

static UNINSTALL_PATHS: OnceLock<UninstallPaths> = OnceLock::new();

fn initialize_uninstall_paths(transaction_id: &str) -> Result<(), String> {
    if !canonical_lower_hex(transaction_id, 32) {
        return Err("uninstall transaction id is not canonical".to_string());
    }
    let recovery_dir = format!("{RECOVERY_ROOT}/{transaction_id}");
    let paths = UninstallPaths {
        transaction_id: transaction_id.to_string(),
        state: format!("{recovery_dir}/state.json"),
        state_temp: format!("{recovery_dir}/.state.tmp"),
        prepared_marker: format!("{recovery_dir}/uninstall_do.json"),
        phase: format!("{recovery_dir}/uninstall-journal.json"),
        phase_temp: format!("{recovery_dir}/.uninstall-phase.tmp"),
        remount_journal: format!("{recovery_dir}/remount-state.json"),
        remount_journal_temp: format!("{recovery_dir}/.remount-state.tmp"),
        watchdog_socket: uninstall_watchdog_socket_path_for(&recovery_dir),
        recovery_dir,
    };
    if let Some(existing) = UNINSTALL_PATHS.get() {
        if existing.transaction_id == transaction_id {
            return Ok(());
        }
        return Err("uninstall transaction id changed within one process".to_string());
    }
    UNINSTALL_PATHS
        .set(paths)
        .map_err(|_| "uninstall paths were initialized concurrently".to_string())
}

fn uninstall_watchdog_socket_path_for(recovery_dir: &str) -> String {
    format!("{recovery_dir}/watchdog.sock")
}

fn uninstall_paths() -> &'static UninstallPaths {
    UNINSTALL_PATHS
        .get()
        .expect("uninstall paths must be initialized before use")
}

fn recovery_state_path() -> &'static str {
    &uninstall_paths().state
}

fn recovery_state_temp_path() -> &'static str {
    &uninstall_paths().state_temp
}

fn uninstall_watchdog_socket_path() -> &'static str {
    &uninstall_paths().watchdog_socket
}

fn uninstall_prepared_marker_path() -> &'static str {
    &uninstall_paths().prepared_marker
}

fn uninstall_phase_path() -> &'static str {
    &uninstall_paths().phase
}

fn uninstall_phase_temp_path() -> &'static str {
    &uninstall_paths().phase_temp
}

fn remount_journal_path() -> &'static str {
    &uninstall_paths().remount_journal
}

fn remount_journal_temp_path() -> &'static str {
    &uninstall_paths().remount_journal_temp
}

fn discover_uninstall_transaction_id() -> Result<String, String> {
    let entries = fs::read_dir(RECOVERY_ROOT)
        .map_err(|error| format!("read uninstall recovery root: {error}"))?;
    let mut found: Option<String> = None;
    for entry in entries {
        let entry = entry.map_err(|error| format!("read uninstall recovery entry: {error}"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "uninstall recovery name is not UTF-8".to_string())?;
        if !canonical_lower_hex(&name, 32) {
            return Err(format!("foreign uninstall recovery entry {name}"));
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("lstat uninstall recovery {name}: {error}"))?;
        if !metadata.file_type().is_dir() || metadata.uid() != 0 || metadata.gid() != 0 {
            return Err(format!("unsafe uninstall recovery directory {name}"));
        }
        if found.replace(name).is_some() {
            return Err("multiple uninstall recovery transactions are present".to_string());
        }
    }
    found.ok_or_else(|| "uninstall recovery transaction is absent".to_string())
}

#[cfg(test)]
const TERMINAL_FIXED_PATHS: &[&str] = &[
    ZONE,
    RC_PATH,
    RC_INSTALL_TEMP_PATH,
    SELINUX_PATH,
    RESTORE_PATH,
    RESTORE_MANIFEST_PATH,
    RESTORE_MANIFEST_SIGNATURE_PATH,
    RECOVERY_HOOK_TEMP_PATH,
    POLICY_RESTORE_TEMP_PATH,
    APP_DATA_PATHS[0],
    APP_DATA_PATHS[1],
    APP_DATA_PATHS[2],
];
// Install/recovery transaction files begin with stock labels so the installer
// can bootstrap them before the custom policy is active. They are relabelled
// to protected Voboost types before becoming committed uninstall authority.
const STOCK_DATA_CONTEXT: &str = "u:object_r:system_data_file:s0";
// The restore executable is a bootstrap program that runs before the custom
// policy is active, so production keeps it on the stock `system_file` label.
// The emulator profile labels all service executables with `su_exec` (see
// install policy `EMULATOR_SERVICE_EXECUTABLES`), so the same program carries
// `su_exec` there and the committed uninstall authority must expect that.

const MAX_SELF_BYTES: u64 = 8 * 1024 * 1024;
const MAX_POLICY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_META_BYTES: u64 = 16 * 1024;
const MAX_MARKER_BYTES: u64 = 128;
const MAX_INVENTORY_BYTES: u64 = 64 * 1024;
const MAX_STATE_BYTES: u64 = 256;
const MAX_RECOVERY_STATE_BYTES: u64 = 16 * 1024;
const MAX_MOUNTINFO_BYTES: usize = 256 * 1024;
const MAX_MOUNTINFO_LINES: usize = 1024;
const MAX_MOUNTINFO_LINE_BYTES: usize = 4096;
const MARKER_BYTES: &[u8] = b"{\"schemaVersion\":1,\"prepared\":true}\n";

const SIG_MAGIC: &[u8; 8] = b"VOBOOST\0";
const SIG_TRAILER_BYTES: usize = 8 + 8 + 64;

include!(concat!(env!("OUT_DIR"), "/embedded_pubkey.rs"));

use uninstall_contract::CommittedContract as Inventory;
use voboost_shared::uninstall_contract;

fn open_regular_nofollow(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("open {} without symlink following: {error}", path.display()))
}

fn path_entry_exists(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("lstat {}: {error}", path.display())),
    }
}

fn read_regular_nofollow(path: &Path, maximum: u64) -> Result<TrustedBytes, String> {
    let mut file = open_regular_nofollow(path)?;
    let before_metadata = file
        .metadata()
        .map_err(|error| format!("stat {}: {error}", path.display()))?;
    if !before_metadata.file_type().is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    let before = FileStamp::from(&before_metadata);
    if before.nlink != 1 {
        return Err(format!(
            "{} must have exactly one hard link",
            path.display()
        ));
    }
    if before.len == 0 || before.len > maximum {
        return Err(format!(
            "{} size {} is outside 1..={maximum}",
            path.display(),
            before.len
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(before.len).unwrap_or(0));
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    if bytes.len() as u64 != before.len || bytes.len() as u64 > maximum {
        return Err(format!("{} changed size while being read", path.display()));
    }
    #[cfg(target_os = "android")]
    let selinux_context = Some(file_selinux_context(&file)?);
    #[cfg(not(target_os = "android"))]
    let selinux_context = None;
    let after = FileStamp::from(
        &file
            .metadata()
            .map_err(|error| format!("restat {}: {error}", path.display()))?,
    );
    if before != after {
        return Err(format!(
            "{} changed identity while being read",
            path.display()
        ));
    }
    Ok(TrustedBytes {
        bytes,
        stamp: before,
        selinux_context,
    })
}

fn clear_stale_temp(
    path: &Path,
    maximum: u64,
    allowed_modes: &[u32],
    allowed_contexts: &[&str],
) -> Result<(), String> {
    if !path_entry_exists(path)? {
        return Ok(());
    }
    let file = open_regular_nofollow(path)?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("stat stale temp {}: {error}", path.display()))?;
    let stamp = FileStamp::from(&metadata);
    if !metadata.file_type().is_file()
        || stamp.uid != 0
        || stamp.gid != 0
        || stamp.nlink != 1
        || stamp.len > maximum
        || !allowed_modes.contains(&stamp.mode)
    {
        return Err(format!(
            "stale temp {} has foreign identity",
            path.display()
        ));
    }
    let context = file_selinux_context(&file)?;
    if !allowed_contexts.contains(&context.as_str()) {
        return Err(format!("stale temp {} has foreign context", path.display()));
    }
    let after = FileStamp::from(
        &file
            .metadata()
            .map_err(|error| format!("restat stale temp {}: {error}", path.display()))?,
    );
    let named = FileStamp::from(
        &fs::symlink_metadata(path)
            .map_err(|error| format!("relstat stale temp {}: {error}", path.display()))?,
    );
    if stamp != after || stamp != named {
        return Err(format!(
            "stale temp {} changed during recovery",
            path.display()
        ));
    }
    fs::remove_file(path)
        .map_err(|error| format!("remove stale temp {}: {error}", path.display()))?;
    fsync_parent(path)
}

fn require_root_file(stamp: FileStamp, mode: u32, label: &str) -> Result<(), String> {
    if stamp.uid != 0 || stamp.gid != 0 || stamp.mode != mode || stamp.nlink != 1 {
        return Err(format!(
            "{label} must be root:root {:04o} with one link",
            mode
        ));
    }
    Ok(())
}

fn require_trusted_context(
    trusted: &TrustedBytes,
    expected: &str,
    label: &str,
) -> Result<(), String> {
    match trusted.selinux_context.as_deref() {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(format!(
            "{label} has SELinux context {actual:?}, expected {expected:?}"
        )),
        None => Err(format!(
            "{label} SELinux context verification requires Android"
        )),
    }
}

/// Trusted-context rail for artifacts whose label legitimately differs by
/// install surface: the emulator/stock push leaves the file at
/// system_data_file, while the managed root-zone install (loaded
/// file_contexts) labels the same committed artifact voboost_data_file.
/// Every other trust property (ownership, mode, exact bytes, signature) is
/// enforced by the caller and unchanged by this label choice.
fn require_trusted_context_any(
    trusted: &TrustedBytes,
    allowed: &[&str],
    label: &str,
) -> Result<(), String> {
    match trusted.selinux_context.as_deref() {
        Some(actual) if allowed.contains(&actual) => Ok(()),
        Some(actual) => Err(format!(
            "{label} has SELinux context {actual:?}, expected one of {allowed:?}"
        )),
        None => Err(format!(
            "{label} SELinux context verification requires Android"
        )),
    }
}

#[cfg(target_os = "android")]
fn file_selinux_context(file: &File) -> Result<String, String> {
    use std::os::fd::AsRawFd;
    let name = b"security.selinux\0";
    let size = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr().cast(),
            std::ptr::null_mut(),
            0,
        )
    };
    if size <= 0 || size > 256 {
        return Err("missing or oversized SELinux context".to_string());
    }
    let mut value = vec![0u8; size as usize];
    let read = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr().cast(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    if read != size {
        return Err("SELinux context changed while being read".to_string());
    }
    while value.last() == Some(&0) {
        value.pop();
    }
    String::from_utf8(value).map_err(|_| "SELinux context is not UTF-8".to_string())
}

#[cfg(not(target_os = "android"))]
fn file_selinux_context(_file: &File) -> Result<String, String> {
    Err("SELinux context verification requires Android".to_string())
}

#[cfg(target_os = "android")]
fn set_file_selinux_context(file: &File, context: &str) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    let name = b"security.selinux\0";
    let result = unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            name.as_ptr().cast(),
            context.as_ptr().cast(),
            context.len(),
            0,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "set SELinux context {context}: {}",
            std::io::Error::last_os_error()
        ))
    }
}

#[cfg(not(target_os = "android"))]
fn set_file_selinux_context(_file: &File, _context: &str) -> Result<(), String> {
    Err("SELinux context publication requires Android".to_string())
}

fn directory_context_matches(expected: &str, actual: &str) -> bool {
    actual == expected || (expected == AGENT_STATE_CONTEXT && actual == DATA_CONTEXT)
}

fn validate_directory(
    path: &Path,
    mode: u32,
    expected_context: Option<&str>,
    label: &str,
) -> Result<FileStamp, String> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("open directory {}: {error}", path.display()))?;
    let metadata = directory
        .metadata()
        .map_err(|error| format!("stat directory {}: {error}", path.display()))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != mode
    {
        return Err(format!("{label} identity or mode is invalid"));
    }
    let before = FileStamp::from(&metadata);
    if let Some(expected) = expected_context {
        let actual = file_selinux_context(&directory)?;
        if !directory_context_matches(expected, &actual) {
            return Err(format!(
                "{label} has SELinux context {actual:?}, expected {expected:?}"
            ));
        }
    }
    let after = FileStamp::from(
        &directory
            .metadata()
            .map_err(|error| format!("restat directory {}: {error}", path.display()))?,
    );
    if before != after {
        return Err(format!("{label} changed while being verified"));
    }
    Ok(before)
}

fn read_own_executable() -> Result<TrustedBytes, String> {
    let mut file = File::open("/proc/self/exe").map_err(|error| format!("open self: {error}"))?;
    let before = FileStamp::from(
        &file
            .metadata()
            .map_err(|error| format!("fstat self: {error}"))?,
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_SELF_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read self: {error}"))?;
    if bytes.len() < SIG_TRAILER_BYTES || bytes.len() as u64 > MAX_SELF_BYTES {
        return Err("running executable has invalid bounded size".to_string());
    }
    let after = FileStamp::from(
        &file
            .metadata()
            .map_err(|error| format!("refstat self: {error}"))?,
    );
    if before != after || before.len != bytes.len() as u64 || before.nlink != 1 {
        return Err("running executable changed while being read".to_string());
    }
    #[cfg(target_os = "android")]
    let selinux_context = Some(file_selinux_context(&file)?);
    #[cfg(not(target_os = "android"))]
    let selinux_context = None;
    Ok(TrustedBytes {
        bytes,
        stamp: before,
        selinux_context,
    })
}

use voboost_shared::native_executable_signature;

fn appended_signature_valid_with_key(
    data: &[u8],
    public_key: &[u8; 32],
    role: native_executable_signature::NativeExecutableRole,
) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    if data.len() < SIG_TRAILER_BYTES || data.len() as u64 > MAX_SELF_BYTES {
        return false;
    }
    let elf_len = data.len() - SIG_TRAILER_BYTES;
    let trailer = &data[elf_len..];
    if &trailer[..8] != SIG_MAGIC {
        return false;
    }
    let Ok(declared_bytes) = <[u8; 8]>::try_from(&trailer[8..16]) else {
        return false;
    };
    if u64::from_le_bytes(declared_bytes) != elf_len as u64 {
        return false;
    }
    let Ok(key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&trailer[16..80]) else {
        return false;
    };
    native_executable_signature::transcript(role, &data[..elf_len])
        .is_some_and(|transcript| key.verify_strict(&transcript, &signature).is_ok())
}

fn appended_signature_valid(data: &[u8]) -> bool {
    appended_signature_valid_with_key(
        data,
        &NATIVE_EXECUTABLE_PUBKEY,
        native_executable_signature::NativeExecutableRole::Uninstall,
    )
}

fn detached_signature_valid(data: &[u8], signature: &[u8], public_key: &[u8; 32]) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    let Ok(key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    key.verify_strict(data, &signature).is_ok()
}

fn parent_is_init() -> bool {
    let Ok(stat) = fs::read_to_string("/proc/self/stat") else {
        return false;
    };
    let Some((_comm, rest)) = stat.rsplit_once(')') else {
        return false;
    };
    let Some((_state, tail)) = rest.trim_start().split_once(' ') else {
        return false;
    };
    tail.split_once(' ')
        .map(|(ppid, _)| ppid == "1")
        .unwrap_or(false)
}

fn uninstall_watchdog_args_authorized(args: &[String], effective_uid: u32) -> bool {
    args.len() == 2 && args[1] == "--watch-uninstall" && effective_uid == 0
}

fn uninstall_successor_args_authorized(args: &[String], effective_uid: u32) -> bool {
    args.len() == 2 && args[1] == "--complete-uninstall" && effective_uid == 0
}

fn get_uninstall_bound_boot_id_args_authorized(args: &[String], effective_uid: u32) -> bool {
    args.len() == 2 && args[1] == "--get-uninstall-bound-boot-id" && effective_uid == 0
}

fn resource_role_args(args: &[String], effective_uid: u32) -> Option<&'static str> {
    if args.len() != 2 || effective_uid != 0 {
        return None;
    }
    match args[1].as_str() {
        "--i18n-none-finalize" => Some("none"),
        "--resume-resource-uninstall" => Some("resume"),
        _ => None,
    }
}

/// A boot helper never creates an uninstall intent in steady state.
fn resource_resume_phase(active: Option<&OperationDescriptor>) -> bool {
    active.is_some_and(|value| {
        value.operation == Operation::Uninstall
            && value.phase == Phase::UninstallAppRemove.name()
            && matches!(value.outcome.as_str(), "running" | "reboot-required")
    })
}

fn terminal_service_phase(active: Option<&OperationDescriptor>) -> bool {
    active.is_some_and(|value| {
        value.operation == Operation::Uninstall
            && value.phase == Phase::UninstallAbsenceVerify.name()
    })
}

fn marker_content_is_prepared(content: &[u8]) -> bool {
    content == MARKER_BYTES
}

fn validate_marker() -> Result<(), String> {
    let marker = read_regular_nofollow(
        Path::new(uninstall_prepared_marker_path()),
        MAX_MARKER_BYTES,
    )?;
    require_root_file(marker.stamp, 0o600, "prepared marker")?;
    if !uninstall_metadata_context(marker.selinux_context.as_deref()) {
        return Err("prepared marker has a foreign context".to_string());
    }
    if marker_content_is_prepared(&marker.bytes) {
        Ok(())
    } else {
        Err("prepared marker is malformed or false".to_string())
    }
}

fn validate_root_zone() -> Result<(), String> {
    validate_directory(Path::new(ZONE), 0o755, Some(DATA_CONTEXT), "root zone")?;
    if path_entry_exists(Path::new("/data/voboost/state"))? {
        validate_directory(
            Path::new("/data/voboost/state"),
            0o700,
            Some(AGENT_STATE_CONTEXT),
            "state directory",
        )?;
    }
    validate_directory(
        Path::new("/data/voboost/uninstall"),
        0o700,
        Some(PROTECTED_CONTEXT),
        "uninstall directory",
    )?;
    let marker = read_regular_nofollow(Path::new(OWNERSHIP_MARKER_PATH), 64)?;
    require_root_file(marker.stamp, 0o600, "root-zone ownership marker")?;
    require_trusted_context(&marker, DATA_CONTEXT, "root-zone ownership marker")?;
    if marker.bytes != OWNERSHIP_MARKER {
        return Err("root-zone ownership marker bytes are invalid".to_string());
    }
    Ok(())
}

fn load_inventory_with_transaction_id() -> Result<(Inventory, String), String> {
    let load = |path: &str, context: &str, label: &str| -> Result<TrustedBytes, String> {
        let trusted = read_regular_nofollow(Path::new(path), MAX_INVENTORY_BYTES)?;
        require_root_file(trusted.stamp, 0o600, label)?;
        require_trusted_context(&trusted, context, label)?;
        Ok(trusted)
    };
    let inventory_path = voboost_shared::installed_state::path(Path::new(ZONE))
        .map_err(|error| error.to_string())?;
    let inventory = load(
        inventory_path.to_str().ok_or("installed state path UTF8")?,
        INSTALLED_STATE_CONTEXT,
        "install inventory",
    )?;
    let artifacts = load(SYSTEM_ARTIFACTS_PATH, PROTECTED_CONTEXT, "system artifacts")?;
    let baseline = load(
        CURRENT_BASELINE_PATH,
        PROTECTED_CONTEXT,
        "current policy baseline",
    )?;
    let metadata = load(PRECOMPILED_META, PROTECTED_CONTEXT, "policy metadata")?;
    let system_state = load(SYSTEM_STATE_PATH, PROTECTED_CONTEXT, "system state")?;
    let rc_archive = load(RC_ARCHIVE_PATH, PROTECTED_CONTEXT, "archived init bytes")?;
    let contract = uninstall_contract::parse_committed_contract(
        &inventory.bytes,
        &artifacts.bytes,
        &baseline.bytes,
        &metadata.bytes,
        &system_state.bytes,
        &rc_archive.bytes,
    )?;
    let transaction_id = uninstall_contract::uninstall_transaction_id(&contract, &inventory.bytes)?;
    Ok((contract, transaction_id))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BackupMetadata {
    size: u64,
    sha256: String,
    uid: u32,
    gid: u32,
    mode: u32,
    mode_text: String,
    context: String,
    sidecars: Vec<voboost_shared::mount_policy_transaction::Sidecar>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryState {
    schema_version: u32,
    transaction_id: String,
    phase: TerminalCleanupPhase,
    terminal_boot_id: Option<String>,
    terminal_reboot_reason: Option<String>,
    terminal_reboot_predicate_sha256: Option<String>,
    terminal_reboot_boot_id: Option<String>,
    recovery_sha256: String,
    zone_dev: u64,
    zone_ino: u64,
    policy_size: u64,
    policy_sha256: String,
    policy_uid: u32,
    policy_gid: u32,
    policy_mode: String,
    policy_context: String,
    policy_sidecars: Vec<voboost_shared::mount_policy_transaction::Sidecar>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
#[allow(clippy::enum_variant_names)] // Operation-first names are the external WAL vocabulary.
enum TerminalCleanupPhase {
    UninstallActive,
    UninstallWatchdogArmed,
    UninstallWatchdogCommitted,
    UninstallSuccessorStarted,
}

impl TerminalCleanupPhase {
    fn next(self) -> Option<Self> {
        match self {
            Self::UninstallActive => Some(Self::UninstallWatchdogArmed),
            Self::UninstallWatchdogArmed => Some(Self::UninstallWatchdogCommitted),
            Self::UninstallWatchdogCommitted => Some(Self::UninstallSuccessorStarted),
            Self::UninstallSuccessorStarted => None,
        }
    }
}

fn advance_terminal_cleanup_phase(
    state: &mut RecoveryState,
    next: TerminalCleanupPhase,
) -> Result<(), String> {
    if state.phase.next() != Some(next) {
        return Err("terminal cleanup phase transition is not the exact successor".to_string());
    }
    state.phase = next;
    Ok(())
}

fn run_terminal_transition<Operation, Publish>(
    state: &mut RecoveryState,
    next: TerminalCleanupPhase,
    operation: Operation,
    publish: Publish,
) -> Result<(), String>
where
    Operation: FnOnce(&RecoveryState) -> Result<(), String>,
    Publish: FnOnce(&RecoveryState) -> Result<(), String>,
{
    operation(state)?;
    let mut successor = state.clone();
    advance_terminal_cleanup_phase(&mut successor, next)?;
    publish(&successor)?;
    *state = successor;
    Ok(())
}

fn parse_restore_document(bytes: &[u8]) -> Result<RestoreDocument, String> {
    RestoreDocument::parse(bytes)
}

fn canonical_lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes.saturating_mul(2)
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn parse_backup_metadata(bytes: &[u8]) -> Result<BackupMetadata, String> {
    let metadata = uninstall_contract::parse_policy_metadata(bytes)?;
    let mode = u32::from_str_radix(&metadata.mode, 8)
        .map_err(|_| "policy metadata mode is invalid".to_string())?;
    Ok(BackupMetadata {
        size: metadata.size,
        sha256: metadata.sha256,
        uid: metadata.uid,
        gid: metadata.gid,
        mode,
        mode_text: metadata.mode,
        context: metadata.context,
        sidecars: metadata.sidecars,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

fn verify_policy_contract(
    path: &Path,
    size: u64,
    sha256: &str,
    uid: u32,
    gid: u32,
    mode_text: &str,
    context: &str,
) -> Result<(), String> {
    let mut file = open_regular_nofollow(path)?;
    let before = FileStamp::from(
        &file
            .metadata()
            .map_err(|error| format!("stat {}: {error}", path.display()))?,
    );
    if before.nlink != 1 || before.len != size || before.len > MAX_POLICY_BYTES {
        return Err(format!("{} identity or size is invalid", path.display()));
    }
    let expected_mode = u32::from_str_radix(mode_text, 8)
        .map_err(|_| "policy contract mode is invalid".to_string())?;
    if before.uid != uid || before.gid != gid || before.mode != expected_mode {
        return Err(format!("{} metadata is invalid", path.display()));
    }
    let mut digest = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| "policy byte count overflow".to_string())?;
        if total > size || total > MAX_POLICY_BYTES {
            return Err(format!("{} grew while being read", path.display()));
        }
        digest.update(&buffer[..count]);
    }
    let after = FileStamp::from(
        &file
            .metadata()
            .map_err(|error| format!("restat {}: {error}", path.display()))?,
    );
    if before != after || total != size {
        return Err(format!("{} changed while being read", path.display()));
    }
    if format!("{:x}", digest.finalize()) != sha256 {
        return Err(format!("{} SHA-256 differs", path.display()));
    }
    let actual_context = file_selinux_context(&file)?;
    if actual_context != context {
        return Err(format!("{} SELinux context differs", path.display()));
    }
    Ok(())
}

fn load_verified_backup() -> Result<(Vec<u8>, BackupMetadata), String> {
    let meta = read_regular_nofollow(Path::new(PRECOMPILED_META), MAX_META_BYTES)?;
    require_root_file(meta.stamp, 0o600, "policy metadata")?;
    require_trusted_context(&meta, PROTECTED_CONTEXT, "policy metadata")?;
    let metadata = parse_backup_metadata(&meta.bytes)?;

    let backup_path = uninstall_contract::baseline_backup_path(&metadata.sha256)?;
    let backup = read_regular_nofollow(Path::new(&backup_path), MAX_POLICY_BYTES)?;
    require_root_file(backup.stamp, 0o600, "policy backup")?;
    require_trusted_context(&backup, PROTECTED_CONTEXT, "policy backup")?;
    if backup.stamp.len != metadata.size || sha256_hex(&backup.bytes) != metadata.sha256 {
        return Err("policy backup bytes do not match canonical metadata".to_string());
    }
    Ok((backup.bytes, metadata))
}

fn recovery_state(
    metadata: &BackupMetadata,
    self_bytes: &[u8],
    transaction_id: &str,
) -> Result<RecoveryState, String> {
    let zone = validate_directory(Path::new(ZONE), 0o755, Some(DATA_CONTEXT), "root zone")?;
    if !canonical_lower_hex(transaction_id, 32) {
        return Err("uninstall transaction binding is not canonical".to_string());
    }
    initialize_uninstall_paths(transaction_id)?;
    Ok(RecoveryState {
        schema_version: 2,
        transaction_id: transaction_id.to_string(),
        phase: TerminalCleanupPhase::UninstallActive,
        terminal_boot_id: None,
        terminal_reboot_reason: None,
        terminal_reboot_predicate_sha256: None,
        terminal_reboot_boot_id: None,
        recovery_sha256: sha256_hex(self_bytes),
        zone_dev: zone.dev,
        zone_ino: zone.ino,
        policy_size: metadata.size,
        policy_sha256: metadata.sha256.clone(),
        policy_uid: metadata.uid,
        policy_gid: metadata.gid,
        policy_mode: metadata.mode_text.clone(),
        policy_context: metadata.context.clone(),
        policy_sidecars: metadata.sidecars.clone(),
    })
}

fn parse_recovery_state(bytes: &[u8]) -> Result<RecoveryState, String> {
    let state: RecoveryState = serde_json::from_slice(bytes)
        .map_err(|error| format!("parse uninstall recovery authority: {error}"))?;
    if state.schema_version != 2
        || !canonical_lower_hex(&state.transaction_id, 32)
        || state
            .terminal_boot_id
            .as_deref()
            .is_some_and(|value| !canonical_boot_id_text(value))
        || (state.phase != TerminalCleanupPhase::UninstallActive
            && state.terminal_boot_id.is_none())
        || !valid_terminal_reboot_evidence(&state)
        || !canonical_lower_hex(&state.recovery_sha256, 32)
        || state.zone_ino == 0
        || state.policy_size == 0
        || state.policy_size > MAX_POLICY_BYTES
        || state.policy_sha256.len() != 64
        || !state
            .policy_sha256
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        || state.policy_mode.len() != 4
        || !state
            .policy_mode
            .as_bytes()
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'7'))
        || !state.policy_mode.starts_with('0')
        || state.policy_context.is_empty()
        || state.policy_context.len() > MAX_POLICY_CONTEXT_BYTES
        || !state
            .policy_context
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_:,.-".contains(byte))
        || !state.policy_context.starts_with("u:object_r:")
        || !voboost_shared::mount_policy_transaction::valid_sidecars(&state.policy_sidecars)
    {
        return Err("uninstall recovery authority fields are invalid".to_string());
    }
    Ok(state)
}

const TERMINAL_REBOOT_REASON: &str = "loaded-init-services-and-terminal-processes";
const TERMINAL_REBOOT_PREDICATE: &[u8] = b"voboost-terminal-reboot-v2\nroot-and-init-file-will-be-absent\nloaded-init-services-present\nterminal-processes-present\npristine-policy-and-sidecars-published\n";

fn terminal_reboot_predicate_sha256() -> String {
    sha256_hex(TERMINAL_REBOOT_PREDICATE)
}

fn valid_terminal_reboot_evidence(state: &RecoveryState) -> bool {
    match (
        state.terminal_reboot_reason.as_deref(),
        state.terminal_reboot_predicate_sha256.as_deref(),
        state.terminal_reboot_boot_id.as_deref(),
    ) {
        (None, None, None) => true,
        (Some(reason), Some(predicate), Some(boot_id)) => {
            reason == TERMINAL_REBOOT_REASON
                && predicate == terminal_reboot_predicate_sha256()
                && canonical_boot_id_text(boot_id)
                && state.phase == TerminalCleanupPhase::UninstallSuccessorStarted
        }
        _ => false,
    }
}

fn armed_terminal_reboot_state(
    state: &RecoveryState,
    boot_id: &str,
) -> Result<RecoveryState, String> {
    if state.phase != TerminalCleanupPhase::UninstallSuccessorStarted
        || !canonical_boot_id_text(boot_id)
    {
        return Err("terminal reboot evidence cannot be armed in this phase".to_string());
    }
    let mut armed = state.clone();
    match armed.terminal_reboot_boot_id.as_deref() {
        Some(previous) if previous != boot_id => {
            return Err(
                "terminal reboot predicate repeated after a boot without progress".to_string(),
            )
        }
        Some(_) if !valid_terminal_reboot_evidence(&armed) => {
            return Err("terminal reboot evidence changed".to_string())
        }
        Some(_) => return Ok(armed),
        None => {}
    }
    armed.terminal_reboot_reason = Some(TERMINAL_REBOOT_REASON.to_string());
    armed.terminal_reboot_predicate_sha256 = Some(terminal_reboot_predicate_sha256());
    armed.terminal_reboot_boot_id = Some(boot_id.to_string());
    Ok(armed)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
#[allow(clippy::enum_variant_names)] // Operation-first names are the external WAL vocabulary.
enum Phase {
    UninstallPrepare,
    UninstallAgentsStop,
    UninstallPolicyRestorePrepare,
    UninstallAppRemove,
    UninstallRuntimeRemove,
    UninstallTerminalCleanup,
    UninstallAbsenceVerify,
}

impl Phase {
    fn number(self) -> u64 {
        self as u64 + 1
    }

    fn name(self) -> String {
        serde_json::to_value(self)
            .ok()
            .and_then(|value| value.as_str().map(str::to_string))
            .expect("uninstall phase serializes as a string")
    }

    fn next(self) -> Option<Self> {
        match self {
            Self::UninstallPrepare => Some(Self::UninstallAgentsStop),
            Self::UninstallAgentsStop => Some(Self::UninstallPolicyRestorePrepare),
            Self::UninstallPolicyRestorePrepare => Some(Self::UninstallAppRemove),
            Self::UninstallAppRemove => Some(Self::UninstallRuntimeRemove),
            Self::UninstallRuntimeRemove => Some(Self::UninstallTerminalCleanup),
            Self::UninstallTerminalCleanup => Some(Self::UninstallAbsenceVerify),
            Self::UninstallAbsenceVerify => None,
        }
    }
}

#[derive(Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PhaseState {
    schema_version: u32,
    phase: Phase,
}

fn uninstall_metadata_context(context: Option<&str>) -> bool {
    // The boot relabeler assigns its protected recovery label to transaction
    // members that the running daemon originally published with the data label.
    matches!(context, Some(DATA_CONTEXT | RECOVERY_TREE_CONTEXT))
}

fn load_phase() -> Result<Phase, String> {
    if !path_entry_exists(Path::new(uninstall_phase_path()))? {
        return Err("uninstall operation journal is absent".to_string());
    }
    let state = read_regular_nofollow(Path::new(uninstall_phase_path()), MAX_STATE_BYTES)?;
    require_root_file(state.stamp, 0o600, "uninstall state")?;
    let context = state.selinux_context.as_deref();
    if !uninstall_metadata_context(context) && context != Some(STOCK_DATA_CONTEXT) {
        return Err("uninstall state has a foreign context".to_string());
    }
    let state: PhaseState =
        serde_json::from_slice(&state.bytes).map_err(|error| format!("parse phase: {error}"))?;
    if state.schema_version != 1 {
        return Err("unsupported uninstall-state schema".to_string());
    }
    Ok(state.phase)
}

fn uninstall_descriptor(
    phase: Phase,
    outcome: &str,
    reboot_count: u32,
    error: Option<&str>,
) -> Result<OperationDescriptor, String> {
    let journal = read_regular_nofollow(Path::new(uninstall_phase_path()), MAX_STATE_BYTES)?;
    require_root_file(journal.stamp, 0o600, "uninstall operation journal")?;
    let parsed: PhaseState = serde_json::from_slice(&journal.bytes)
        .map_err(|value| format!("parse uninstall operation journal: {value}"))?;
    if parsed.schema_version != 1 || parsed.phase != phase {
        return Err("uninstall operation journal phase differs".to_string());
    }
    let error = error.map(|message| {
        let message = message
            .chars()
            .filter(|character| !character.is_control())
            .take(512)
            .collect::<String>();
        let message = if message.is_empty() {
            "internal uninstall failure".to_string()
        } else {
            message
        };
        serde_json::json!({
            "code": "uninstall-failed",
            "message": message
        })
    });
    Ok(OperationDescriptor {
        schema_version: 1,
        operation: Operation::Uninstall,
        transaction_id: uninstall_paths().transaction_id.clone(),
        journal: format!(
            "recovery/{}/uninstall-journal.json",
            uninstall_paths().transaction_id
        ),
        phase: phase.name(),
        outcome: outcome.to_string(),
        reboot_count: retained_reboot_count(reboot_count)?,
        boot_id: canonical_boot_id()?,
        status_sequence: uninstall_status_sequence(phase, outcome)?,
        journal_sha256: sha256_hex(&journal.bytes),
        error,
        installed_apk: None,
    })
}

fn carry_reboot_count(
    requested: u32,
    current: Option<&OperationDescriptor>,
    transaction: &str,
) -> u32 {
    current
        .filter(|value| {
            value.operation == Operation::Uninstall
                && value.transaction_id == transaction
                && value.journal == format!("recovery/{transaction}/uninstall-journal.json")
        })
        .map_or(requested, |value| requested.max(value.reboot_count))
}

fn retained_reboot_count(requested: u32) -> Result<u32, String> {
    // Counter retention is not operation admission. The caller has already
    // verified the current uninstall WAL. Its projection may still bind the
    // preceding WAL phase after a crash, so read_active_in cannot be used here.
    // Only a canonical root-owned descriptor for this same authority contributes.
    let raw = match read_regular_nofollow(
        Path::new(operation_contract::OPERATION_DESCRIPTOR_PATH),
        operation_contract::MAX_OPERATION_DESCRIPTOR_BYTES as u64,
    ) {
        Ok(value) => value,
        Err(_) if !path_entry_exists(Path::new(operation_contract::OPERATION_DESCRIPTOR_PATH))? => {
            return Ok(requested)
        }
        Err(error) => return Err(error),
    };
    require_root_file(raw.stamp, 0o600, "retained uninstall operation counter")?;
    let current = OperationDescriptor::parse(&raw.bytes)?;
    Ok(carry_reboot_count(
        requested,
        Some(&current),
        &uninstall_paths().transaction_id,
    ))
}

fn uninstall_status_sequence(phase: Phase, outcome: &str) -> Result<u64, String> {
    let offset = match outcome {
        "running" => 1,
        "reboot-required" => 2,
        "failed" => 3,
        _ => return Err("uninstall operation outcome is invalid".to_string()),
    };
    Ok((phase.number() - 1) * 3 + offset)
}

fn publish_uninstall_status(
    lease: &OperationLease,
    phase: Phase,
    outcome: &str,
    reboot_count: u32,
    error: Option<&str>,
) -> Result<(), String> {
    lease.publish(&uninstall_descriptor(phase, outcome, reboot_count, error)?)
}

fn fsync_parent(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "path has no parent".to_string())?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY)
        .open(parent)
        .map_err(|error| format!("open directory {}: {error}", parent.display()))?;
    directory
        .sync_all()
        .map_err(|error| format!("fsync directory {}: {error}", parent.display()))
}

fn persist_phase(phase: Phase) -> Result<(), String> {
    let target = Path::new(uninstall_phase_path());
    let temporary = Path::new(uninstall_phase_temp_path());
    let body = serde_json::to_vec(&PhaseState {
        schema_version: 1,
        phase,
    })
    .map_err(|error| format!("serialize phase: {error}"))?;
    if body.len() as u64 > MAX_STATE_BYTES {
        return Err("serialized uninstall state is oversized".to_string());
    }
    clear_stale_temp(
        temporary,
        MAX_STATE_BYTES,
        &[0o600],
        &[DATA_CONTEXT, RECOVERY_TREE_CONTEXT],
    )?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(temporary)
        .map_err(|error| format!("create {}: {error}", temporary.display()))?;
    let result = (|| {
        file.write_all(&body)
            .map_err(|error| format!("write phase: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("fsync phase: {error}"))?;
        set_file_selinux_context(&file, DATA_CONTEXT)?;
        file.sync_all()
            .map_err(|error| format!("fsync phase metadata: {error}"))?;
        fs::rename(temporary, target).map_err(|error| format!("publish phase: {error}"))?;
        fsync_parent(target)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

#[path = "../../shared/lifecycle_mounts.rs"]
mod mounts;
use mounts::*;

mod package;
#[cfg(test)]
use package::*;
use package::{remove_owned_restore_manifest_pair, uninstall_package};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DaemonProcess {
    pid: i32,
    starttime: u64,
}

fn daemon_starttime(pid: i32) -> Result<u64, String> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|error| format!("read daemon stat: {error}"))?;
    parse_daemon_starttime(&text)
}

fn parse_daemon_starttime(text: &str) -> Result<u64, String> {
    let close = text
        .rfind(')')
        .ok_or_else(|| "daemon stat lacks comm terminator".to_string())?;
    text.get(close + 2..)
        .and_then(|fields| fields.split_whitespace().nth(19))
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| "daemon starttime is invalid".to_string())
}

fn daemon_executable(pid: i32) -> std::io::Result<bool> {
    let path = fs::read_link(format!("/proc/{pid}/exe"))?;
    let value = path
        .to_str()
        .ok_or_else(|| std::io::Error::other("daemon executable path is not UTF-8"))?;
    Ok(matches!(
        value,
        "/data/voboost/voboost-daemon"
            | "/data/voboost/voboost-daemon (deleted)"
            | "/data/voboost/voboost-inject"
            | "/data/voboost/voboost-inject (deleted)"
    ))
}

fn observe_daemon_processes() -> Result<Vec<DaemonProcess>, String> {
    let mut processes = Vec::new();
    for (index, entry) in fs::read_dir("/proc")
        .map_err(|error| format!("read procfs: {error}"))?
        .enumerate()
    {
        if index >= 32_768 {
            return Err("procfs process inventory exceeds its bound".to_string());
        }
        let entry = entry.map_err(|error| format!("read procfs entry: {error}"))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.is_empty()
            || name.starts_with('0')
            || !name.bytes().all(|byte| byte.is_ascii_digit())
        {
            continue;
        }
        let Ok(pid) = name.parse::<i32>() else {
            continue;
        };
        match daemon_executable(pid) {
            Ok(true) => processes.push(DaemonProcess {
                pid,
                starttime: daemon_starttime(pid)?,
            }),
            Ok(false) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("read daemon executable /proc/{pid}/exe: {error}")),
        }
    }
    Ok(processes)
}

fn same_daemon_process(process: DaemonProcess) -> bool {
    daemon_executable(process.pid).ok() == Some(true)
        && daemon_starttime(process.pid).ok() == Some(process.starttime)
}

fn stop_daemon() -> Result<(), String> {
    stop_daemon_with(
        |service| {
            fixed_process::set_property("ctl.stop", service)
                .map_err(|_| format!("init rejected {service} stop request"))
        },
        observe_daemon_processes,
        stop_daemon_process,
    )
}

fn stop_daemon_with<T>(
    mut stop_service: impl FnMut(&str) -> Result<(), String>,
    mut observe: impl FnMut() -> Result<Vec<T>, String>,
    mut stop_process: impl FnMut(T) -> Result<(), String>,
) -> Result<(), String> {
    let mut errors = Vec::new();
    for service in ["voboost-inject", "voboost-daemon"] {
        if let Err(error) = stop_service(service) {
            errors.push(error);
        }
    }
    match observe() {
        Ok(processes) => {
            for process in processes {
                if let Err(error) = stop_process(process) {
                    errors.push(error);
                }
            }
        }
        Err(error) => errors.push(format!("observe daemon processes: {error}")),
    }
    match observe() {
        Ok(processes) if processes.is_empty() => (),
        Ok(_) => errors.push("daemon restarted or survived stop".to_string()),
        Err(error) => errors.push(format!("verify daemon stop: {error}")),
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn stop_daemon_process(process: DaemonProcess) -> Result<(), String> {
    if !same_daemon_process(process) {
        return Ok(());
    }
    if unsafe { libc::kill(process.pid, libc::SIGTERM) } != 0
        && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    {
        return Err("signal exact daemon process failed".to_string());
    }
    for _ in 0..20 {
        if !same_daemon_process(process) {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    if same_daemon_process(process) {
        if unsafe { libc::kill(process.pid, libc::SIGKILL) } != 0
            && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
        {
            return Err("kill exact daemon process failed".to_string());
        }
        for _ in 0..10 {
            if !same_daemon_process(process) {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
    if same_daemon_process(process) {
        return Err("exact daemon process survived stop".to_string());
    }
    Ok(())
}

fn remove_owned_file(
    path: &str,
    marker: Option<&str>,
    inventory: &Inventory,
) -> Result<(), String> {
    let target = Path::new(path);
    if !path_entry_exists(target)? {
        return Ok(());
    }
    let trusted = read_regular_nofollow(target, 8 * 1024 * 1024)?;
    require_root_file(
        trusted.stamp,
        if matches!(path, SELINUX_PATH | RESTORE_PATH) {
            0o700
        } else {
            0o644
        },
        path,
    )?;
    if path == SELINUX_PATH {
        require_trusted_context(&trusted, SELINUX_EXEC_CONTEXT, path)?;
        let expected = &inventory.artifacts.native.selinux;
        if trusted.bytes.len() as u64 != expected.size
            || sha256_hex(&trusted.bytes) != expected.sha256
            || expected.signature_role != "selinux"
            || !appended_signature_valid_with_key(
                &trusted.bytes,
                &NATIVE_EXECUTABLE_PUBKEY,
                native_executable_signature::NativeExecutableRole::Selinux,
            )
        {
            return Err(
                "installed SELinux program differs from committed role binding".to_string(),
            );
        }
    } else if path == RESTORE_PATH {
        require_trusted_context(&trusted, RESTORE_EXEC_CONTEXT, path)?;
        let expected = &inventory.artifacts.native.restore;
        if trusted.bytes.len() as u64 != expected.size
            || sha256_hex(&trusted.bytes) != expected.sha256
            || expected.signature_role != "restore"
            || !appended_signature_valid_with_key(
                &trusted.bytes,
                &NATIVE_EXECUTABLE_PUBKEY,
                native_executable_signature::NativeExecutableRole::Restore,
            )
        {
            return Err(
                "installed restore program differs from committed role binding".to_string(),
            );
        }
    } else {
        require_trusted_context(&trusted, STOCK_RECOVERY_CONTEXT, path)?;
    }
    if marker.is_some_and(|needle| {
        !trusted
            .bytes
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
    }) {
        return Err(format!("{path} does not contain its ownership marker"));
    }
    if matches!(path, SELINUX_PATH | RESTORE_PATH) {
        fs::remove_file(target).map_err(|error| format!("remove {path}: {error}"))?;
        return fsync_parent(target);
    }
    if !matches!(path, RC_PATH | RC_INSTALL_TEMP_PATH) {
        return Err(format!("unsupported protected removal path {path}"));
    }
    with_protected_mounts_rw(ProtectedMutationMount::SystemInitHook, || {
        fs::remove_file(target).map_err(|error| format!("remove {path}: {error}"))?;
        fsync_parent(target)
    })
}

fn verify_recovery_hook() -> Result<(), String> {
    let trusted = read_regular_nofollow(Path::new(RC_PATH), 4096)?;
    require_root_file(trusted.stamp, 0o644, "autonomous uninstall recovery hook")?;
    require_trusted_context(
        &trusted,
        STOCK_RECOVERY_CONTEXT,
        "autonomous uninstall recovery hook",
    )?;
    if !recovery_hook_bytes_are_exact(&trusted.bytes) {
        return Err("autonomous uninstall recovery hook bytes differ".to_string());
    }
    Ok(())
}

fn recovery_hook_bytes_are_exact(bytes: &[u8]) -> bool {
    bytes == RECOVERY_HOOK_BYTES
}

fn publish_recovery_hook(inventory: &Inventory) -> Result<(), String> {
    if path_entry_exists(Path::new(RC_PATH))? {
        let current = read_regular_nofollow(Path::new(RC_PATH), 64 * 1024)?;
        require_root_file(current.stamp, 0o644, "installed init hook")?;
        require_trusted_context(&current, STOCK_RECOVERY_CONTEXT, "installed init hook")?;
        if recovery_hook_bytes_are_exact(&current.bytes) {
            return Ok(());
        }
        if !current
            .bytes
            .windows(RC_MARKER.len())
            .any(|window| window == RC_MARKER.as_bytes())
        {
            return Err("installed init hook lacks its ownership marker".to_string());
        }
        // The strict committed inventory was validated before this call and
        // binds RC_PATH as a Voboost-created object.
        let _ = inventory;
    }
    publish_recovery_hook_at_absent_path()
}

fn publish_recovery_hook_at_absent_path() -> Result<(), String> {
    with_protected_mounts_rw(ProtectedMutationMount::SystemInitHook, || {
        if path_entry_exists(Path::new(RC_PATH))? {
            // The committed init hook still occupies the protected target. The
            // outer `publish_recovery_hook` call already verified it carries the
            // uninstall ownership marker and is bound to the committed inventory,
            // so this branch replaces it atomically. Re-checking existence here
            // keeps the protected mutation self-contained: the in-memory
            // existence check above can race with a concurrent publisher, but the
            // descriptor-relative unlink below is the authoritative cut.
            let trusted = read_regular_nofollow(Path::new(RC_PATH), 64 * 1024)?;
            require_root_file(trusted.stamp, 0o644, "installed init hook")?;
            require_trusted_context(&trusted, STOCK_RECOVERY_CONTEXT, "installed init hook")?;
            if !recovery_hook_bytes_are_exact(&trusted.bytes)
                && !trusted
                    .bytes
                    .windows(RC_MARKER.len())
                    .any(|window| window == RC_MARKER.as_bytes())
            {
                return Err("installed init hook lacks its ownership marker".to_string());
            }
            fs::remove_file(Path::new(RC_PATH))
                .map_err(|error| format!("remove installed init hook: {error}"))?;
            fsync_parent(Path::new(RC_PATH))?;
        }
        clear_stale_temp(
            Path::new(RECOVERY_HOOK_TEMP_PATH),
            4096,
            &[0o644],
            &[STOCK_RECOVERY_CONTEXT],
        )?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(RECOVERY_HOOK_TEMP_PATH)
            .map_err(|error| format!("create autonomous recovery hook: {error}"))?;
        file.write_all(RECOVERY_HOOK_BYTES)
            .map_err(|error| format!("write autonomous recovery hook: {error}"))?;
        // `OpenOptions::mode` is masked by the process umask, so the published
        // mode must be set explicitly before the descriptor is renamed and the
        // selinux context is applied.
        file.set_permissions(fs::Permissions::from_mode(0o644))
            .map_err(|error| format!("chmod autonomous recovery hook: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("fsync autonomous recovery hook: {error}"))?;
        set_file_selinux_context(&file, STOCK_RECOVERY_CONTEXT)?;
        file.sync_all()
            .map_err(|error| format!("fsync autonomous recovery hook metadata: {error}"))?;
        fs::rename(RECOVERY_HOOK_TEMP_PATH, RC_PATH)
            .map_err(|error| format!("publish autonomous recovery hook: {error}"))?;
        fsync_parent(Path::new(RC_PATH))?;
        verify_recovery_hook()
    })
}

fn publish_recovery(self_bytes: &[u8]) -> Result<(), String> {
    let target = Path::new(RECOVERY_PATH);
    let trusted = read_regular_nofollow(target, MAX_SELF_BYTES)?;
    require_root_file(trusted.stamp, 0o700, "resident uninstall executable")?;
    require_trusted_context(
        &trusted,
        UNINSTALL_EXEC_CONTEXT,
        "resident uninstall executable",
    )?;
    if trusted.bytes != self_bytes || !appended_signature_valid(&trusted.bytes) {
        return Err(
            "resident uninstall executable differs from the running signed inode".to_string(),
        );
    }
    Ok(())
}

fn ensure_uninstall_recovery_directory() -> Result<(), String> {
    let root = Path::new(RECOVERY_ROOT);
    if !path_entry_exists(root)? {
        fs::create_dir(root).map_err(|error| format!("create recovery root: {error}"))?;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("chmod recovery root: {error}"))?;
        fsync_parent(root)?;
    }
    // The recovery tree root carries its dedicated label from the loaded
    // file_contexts (file_contexts: /data/voboost/recovery(/.*)? ->
    // voboost_recovery_file); the transaction members inside it are the
    // daemon-published voboost_data_file artifacts validated separately.
    validate_directory(root, 0o700, Some(RECOVERY_TREE_CONTEXT), "recovery root")?;

    let transaction = Path::new(&uninstall_paths().recovery_dir);
    if !path_entry_exists(transaction)? {
        fs::create_dir(transaction)
            .map_err(|error| format!("create uninstall recovery transaction: {error}"))?;
        fs::set_permissions(transaction, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("chmod uninstall recovery transaction: {error}"))?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(transaction)
            .map_err(|error| format!("open uninstall recovery transaction: {error}"))?;
        // The directory stays on the recovery-tree label it inherited at
        // creation; member files carry their individual publishing labels.
        directory
            .sync_all()
            .map_err(|error| format!("fsync uninstall recovery transaction: {error}"))?;
        fsync_parent(transaction)?;
    }
    // The transaction directory is a member of the recovery tree and carries
    // its file_contexts label (voboost_recovery_file); every member file is
    // validated individually against its publishing authority.
    validate_directory(
        transaction,
        0o700,
        Some(RECOVERY_TREE_CONTEXT),
        "uninstall recovery transaction",
    )?;
    Ok(())
}

fn publish_recovery_state(expected: &RecoveryState) -> Result<(), String> {
    if expected.transaction_id != uninstall_paths().transaction_id {
        return Err("uninstall recovery state transaction id differs from its path".to_string());
    }
    ensure_uninstall_recovery_directory()?;
    let target = Path::new(recovery_state_path());
    if path_entry_exists(target)? {
        let trusted = read_regular_nofollow(target, MAX_RECOVERY_STATE_BYTES)?;
        require_root_file(trusted.stamp, 0o600, "uninstall recovery authority")?;
        require_trusted_context(&trusted, PROTECTED_CONTEXT, "uninstall recovery authority")?;
        if parse_recovery_state(&trusted.bytes)? == *expected {
            return Ok(());
        }
        return Err("existing uninstall recovery authority does not match this zone".to_string());
    }
    let body = serde_json::to_vec(expected)
        .map_err(|error| format!("serialize uninstall recovery authority: {error}"))?;
    if body.is_empty() || body.len() as u64 > MAX_RECOVERY_STATE_BYTES {
        return Err("serialized uninstall recovery authority is oversized".to_string());
    }
    let temporary = Path::new(recovery_state_temp_path());
    clear_stale_temp(
        temporary,
        MAX_RECOVERY_STATE_BYTES,
        &[0o600],
        &[PROTECTED_CONTEXT],
    )?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(temporary)
        .map_err(|error| format!("create uninstall recovery authority: {error}"))?;
    let result = (|| {
        file.write_all(&body)
            .map_err(|error| format!("write uninstall recovery authority: {error}"))?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("chmod uninstall recovery authority: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("fsync uninstall recovery authority: {error}"))?;
        set_file_selinux_context(&file, PROTECTED_CONTEXT)?;
        file.sync_all()
            .map_err(|error| format!("fsync uninstall recovery authority metadata: {error}"))?;
        fs::rename(temporary, target)
            .map_err(|error| format!("publish uninstall recovery authority: {error}"))?;
        fsync_parent(target)?;
        let trusted = read_regular_nofollow(target, MAX_RECOVERY_STATE_BYTES)?;
        require_root_file(trusted.stamp, 0o600, "uninstall recovery authority")?;
        require_trusted_context(&trusted, PROTECTED_CONTEXT, "uninstall recovery authority")?;
        if parse_recovery_state(&trusted.bytes)? != *expected {
            return Err("published uninstall recovery authority verification failed".to_string());
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn publish_recovery_bundle(self_bytes: &[u8], state: &RecoveryState) -> Result<(), String> {
    publish_recovery(self_bytes)?;
    publish_recovery_state(state)
}

fn restore_precompiled(bytes: &[u8], metadata: &BackupMetadata) -> Result<(), String> {
    {
        crate::selinux_backend::restore_policy_with(|| {
            with_protected_mounts_rw(ProtectedMutationMount::VendorPolicy, || {
                restore_precompiled_mutation(bytes, metadata)
            })
        })
    }
}

fn restore_precompiled_mutation(bytes: &[u8], metadata: &BackupMetadata) -> Result<(), String> {
    let target = Path::new(PRECOMPILED_PATH);
    let temporary = Path::new(POLICY_RESTORE_TEMP_PATH);
    clear_stale_temp(
        temporary,
        MAX_POLICY_BYTES,
        &[0o600, metadata.mode],
        &[STOCK_RECOVERY_CONTEXT, metadata.context.as_str()],
    )?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(temporary)
        .map_err(|error| format!("create restore temp: {error}"))?;
    let result = (|| {
        file.write_all(bytes)
            .map_err(|error| format!("write restored policy: {error}"))?;
        file.set_permissions(fs::Permissions::from_mode(metadata.mode))
            .map_err(|error| format!("chmod restored policy: {error}"))?;
        #[cfg(target_os = "android")]
        {
            use std::os::fd::AsRawFd;
            if unsafe { libc::fchown(file.as_raw_fd(), metadata.uid, metadata.gid) } != 0 {
                return Err(format!(
                    "chown restored policy: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        set_file_selinux_context(&file, &metadata.context)?;
        file.sync_all()
            .map_err(|error| format!("fsync restored policy: {error}"))?;
        fs::rename(temporary, target)
            .map_err(|error| format!("publish restored policy: {error}"))?;
        fsync_parent(target)?;
        voboost_shared::mount_policy_transaction::restore_sidecars(&metadata.sidecars)?;
        verify_policy_contract(
            target,
            metadata.size,
            &metadata.sha256,
            metadata.uid,
            metadata.gid,
            &metadata.mode_text,
            &metadata.context,
        )
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn load_recovery_state() -> Result<RecoveryState, String> {
    let trusted =
        read_regular_nofollow(Path::new(recovery_state_path()), MAX_RECOVERY_STATE_BYTES)?;
    require_root_file(trusted.stamp, 0o600, "uninstall recovery authority")?;
    let state = parse_recovery_state(&trusted.bytes)?;
    let context = trusted.selinux_context.as_deref();
    if context != Some(PROTECTED_CONTEXT) && context != Some(STOCK_DATA_CONTEXT) {
        return Err("uninstall recovery authority has a foreign context".to_string());
    }
    if state.transaction_id != uninstall_paths().transaction_id {
        return Err(
            "uninstall recovery authority transaction id differs from its path".to_string(),
        );
    }
    Ok(state)
}

fn replace_recovery_state(expected: &RecoveryState) -> Result<(), String> {
    let body = serde_json::to_vec(expected)
        .map_err(|error| format!("serialize uninstall recovery state: {error}"))?;
    if body.is_empty() || body.len() as u64 > MAX_RECOVERY_STATE_BYTES {
        return Err("serialized uninstall recovery state is oversized".to_string());
    }
    let target = Path::new(recovery_state_path());
    let temporary = Path::new(recovery_state_temp_path());
    let current = read_regular_nofollow(target, MAX_RECOVERY_STATE_BYTES)?;
    require_root_file(current.stamp, 0o600, "current uninstall recovery state")?;
    let target_context =
        crate::selinux_backend::recovery_state_context(current.selinux_context.as_deref())?;
    clear_stale_temp(
        temporary,
        MAX_RECOVERY_STATE_BYTES,
        &[0o600],
        &[target_context],
    )?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(temporary)
        .map_err(|error| format!("create uninstall recovery state: {error}"))?;
    let result = (|| {
        file.write_all(&body)
            .map_err(|error| format!("write uninstall recovery state: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("fsync uninstall recovery state: {error}"))?;
        set_file_selinux_context(&file, target_context)?;
        file.sync_all()
            .map_err(|error| format!("fsync uninstall recovery state metadata: {error}"))?;
        fs::rename(temporary, target)
            .map_err(|error| format!("publish uninstall recovery state: {error}"))?;
        fsync_parent(target)?;
        let published = load_recovery_state()?;
        if published != *expected {
            return Err("published uninstall recovery state differs".to_string());
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn persist_active_terminal_boot(
    state: &RecoveryState,
    boot_id: &str,
) -> Result<RecoveryState, String> {
    let prepared = active_terminal_boot_state(state, boot_id)?;
    replace_recovery_state(&prepared)?;
    Ok(prepared)
}

fn active_terminal_boot_state(
    state: &RecoveryState,
    boot_id: &str,
) -> Result<RecoveryState, String> {
    if state.phase != TerminalCleanupPhase::UninstallActive || !canonical_boot_id_text(boot_id) {
        return Err("active terminal-boot authority is invalid".to_string());
    }
    let mut prepared = state.clone();
    match prepared.terminal_boot_id.as_deref() {
        Some(bound) if bound != boot_id => {
            return Err("terminal cleanup moved to another boot".to_string());
        }
        Some(_) => return Ok(prepared),
        None => prepared.terminal_boot_id = Some(boot_id.to_string()),
    }
    Ok(prepared)
}

fn terminal_cleanup_boot_allowed(
    state: &RecoveryState,
    current_boot_id: &str,
) -> Result<(), String> {
    if !canonical_boot_id_text(current_boot_id) {
        return Err("current boot id is not canonical".to_string());
    }
    let before = state
        .terminal_boot_id
        .as_deref()
        .ok_or_else(|| "terminal cleanup lacks its bound boot id".to_string())?;
    if before != current_boot_id {
        return Err("terminal cleanup rejects a changed boot".to_string());
    }
    Ok(())
}

fn verify_restored_policy(state: &RecoveryState) -> Result<(), String> {
    verify_policy_contract(
        Path::new(PRECOMPILED_PATH),
        state.policy_size,
        &state.policy_sha256,
        state.policy_uid,
        state.policy_gid,
        &state.policy_mode,
        &state.policy_context,
    )
    .and_then(|()| {
        voboost_shared::mount_policy_transaction::verify_sidecars(&state.policy_sidecars)
    })
    .map_err(|error| {
        format!("uninstall recovery refuses non-pristine SELinux boot inputs: {error}")
    })
}

#[cfg(test)]
fn verify_recovery_zone_at(
    root: &Path,
    state: &RecoveryState,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<bool, String> {
    if !path_entry_exists(root)? {
        return Ok(false);
    }
    let zone = fs::symlink_metadata(root).map_err(|error| format!("lstat {ZONE}: {error}"))?;
    if !zone.file_type().is_dir()
        || zone.file_type().is_symlink()
        || zone.uid() != expected_uid
        || zone.gid() != expected_gid
        || zone.mode() & 0o7777 != 0o755
        || zone.dev() != state.zone_dev
        || zone.ino() != state.zone_ino
    {
        return Err("uninstall recovery root-zone identity changed".to_string());
    }
    Ok(true)
}

#[path = "../../shared/lifecycle_secure_fs.rs"]
mod secure_fs;
use secure_fs::*;

fn canonical_boot_id() -> Result<String, String> {
    let value = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| format!("read boot id: {error}"))?;
    let value = value.trim_end_matches('\n');
    if !canonical_boot_id_text(value) {
        return Err("boot id is not canonical lowercase UUID text".to_string());
    }
    Ok(value.to_string())
}

fn canonical_boot_id_text(value: &str) -> bool {
    value.len() == 36
        && !value.as_bytes().iter().enumerate().any(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte != b'-'
            } else {
                !(byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            }
        })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PhaseProgress {
    ResourceBootPending,
    Terminal,
}

trait UninstallActions {
    fn before_app_remove(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn resource_continuation(
        &mut self,
    ) -> Result<crate::i18n_resource_files::OperationContinuation, String> {
        Ok(crate::i18n_resource_files::OperationContinuation::Continue)
    }
    fn resource_boot_pending(&mut self, _request: bool) -> Result<(), String> {
        Ok(())
    }
    fn verify_owner(&mut self) -> Result<(), String>;
    fn execute(&mut self, phase: Phase) -> Result<(), String>;
    fn persist(&mut self, phase: Phase) -> Result<(), String>;
}

struct DeviceUninstallActions<'a> {
    self_bytes: &'a [u8],
    inventory: &'a Inventory,
    recovery: &'a RecoveryState,
    lease: &'a OperationLease,
}

impl UninstallActions for DeviceUninstallActions<'_> {
    fn before_app_remove(&mut self) -> Result<(), String> {
        crate::cluster_recovery::preserve_if_pending(
            Path::new(ZONE),
            &uninstall_paths().transaction_id,
        )?;
        crate::i18n_resource_files::require_operation_resume_service(&RELEASE_CATALOG_PUBLIC_KEY)
            .map_err(|error| format!("resource resume preflight: {error}"))
    }
    fn resource_continuation(
        &mut self,
    ) -> Result<crate::i18n_resource_files::OperationContinuation, String> {
        crate::i18n_resource_files::prepare_operation_before_runtime_remove(
            &RELEASE_CATALOG_PUBLIC_KEY,
            self.lease,
        )
        .map_err(|error| format!("resource intermediate boot: {error}"))
    }
    fn resource_boot_pending(&mut self, request: bool) -> Result<(), String> {
        publish_uninstall_status(
            self.lease,
            Phase::UninstallAppRemove,
            "reboot-required",
            1,
            None,
        )?;
        if request {
            fixed_process::request_reboot()?;
        }
        Ok(())
    }
    fn verify_owner(&mut self) -> Result<(), String> {
        self.lease.verify_owner()
    }

    fn execute(&mut self, phase: Phase) -> Result<(), String> {
        match phase {
            Phase::UninstallPrepare => unreachable!("start has no predecessor"),
            Phase::UninstallAgentsStop => stop_daemon(),
            Phase::UninstallPolicyRestorePrepare => Ok(()),
            Phase::UninstallAppRemove => cleanup_application(
                || {
                    crate::i18n_resource_files::cleanup_for_operation(
                        &RELEASE_CATALOG_PUBLIC_KEY,
                        self.lease,
                        Operation::Uninstall,
                    )
                    .map(|_| ())
                    .map_err(|error| error.to_string())
                },
                || {
                    crate::cache_cleanup::cleanup_launcher(Some(&uninstall_paths().transaction_id))
                        .map(|_| ())
                        .map_err(|error| error.to_string())
                },
                uninstall_package,
                |warning| diag(&format!("fail nonfatal cleanup: {warning}")),
            ),
            Phase::UninstallRuntimeRemove => cleanup_runtime(
                || publish_recovery_bundle(self.self_bytes, self.recovery),
                || remove_owned_restore_manifest_pair(self.inventory),
                || remove_owned_file(RESTORE_PATH, None, self.inventory),
                || remove_owned_file(SELINUX_PATH, None, self.inventory),
            ),
            Phase::UninstallTerminalCleanup => {
                publish_recovery_bundle(self.self_bytes, self.recovery)?;
                publish_recovery_hook(self.inventory)
            }
            Phase::UninstallAbsenceVerify => {
                unreachable!("watchdog publishes pristine phase")
            }
        }
    }

    fn persist(&mut self, phase: Phase) -> Result<(), String> {
        persist_phase(phase)?;
        publish_uninstall_status(self.lease, phase, "running", 0, None)
    }
}

fn cleanup_runtime(
    preserve_recovery: impl FnOnce() -> Result<(), String>,
    restore_manifest: impl FnOnce() -> Result<(), String>,
    restore_executable: impl FnOnce() -> Result<(), String>,
    policy_executable: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    preserve_recovery()?;
    let errors: Vec<_> = [
        ("restore authorization cleanup", restore_manifest()),
        ("restore executable cleanup", restore_executable()),
        ("policy executable cleanup", policy_executable()),
    ]
    .into_iter()
    .filter_map(|(step, result)| result.err().map(|error| format!("{step}: {error}")))
    .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn cleanup_application(
    resources: impl FnOnce() -> Result<(), String>,
    cache: impl FnOnce() -> Result<(), String>,
    package: impl FnOnce() -> Result<(), String>,
    mut warning: impl FnMut(&str),
) -> Result<(), String> {
    let resources = resources();
    let cache = cache();
    let package = package();
    if let Err(error) = cache {
        warning(&format!("launcher icon cache cleanup: {error}"));
    }
    let errors: Vec<_> = [
        ("owned resource cleanup", resources),
        ("application removal", package),
    ]
    .into_iter()
    .filter_map(|(step, result)| result.err().map(|error| format!("{step}: {error}")))
    .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn drive_uninstall_phases(
    mut phase: Phase,
    actions: &mut impl UninstallActions,
) -> Result<PhaseProgress, String> {
    while let Some(next) = phase.next() {
        diag(&format!("phase begin {}", next.name()));
        actions.verify_owner()?;
        if next == Phase::UninstallAppRemove {
            actions.before_app_remove()?;
        }
        if next == Phase::UninstallRuntimeRemove {
            use crate::i18n_resource_files::OperationContinuation;
            match actions.resource_continuation()? {
                OperationContinuation::Continue => (),
                pending => {
                    actions
                        .resource_boot_pending(pending == OperationContinuation::RequestReboot)?;
                    return Ok(PhaseProgress::ResourceBootPending);
                }
            }
        }
        let executed = actions.execute(next);
        match &executed {
            Ok(()) => diag(&format!("phase ok {}", next.name())),
            Err(error) => diag(&format!("phase failed {}: {error}", next.name())),
        }
        executed?;
        actions.persist(next)?;
        phase = next;
        if phase == Phase::UninstallTerminalCleanup {
            diag("terminal cleanup reached");
            return Ok(PhaseProgress::Terminal);
        }
    }
    Err("primary uninstall reached an invalid terminal phase".to_string())
}

#[path = "../../shared/lifecycle_uninstall_terminal.rs"]
mod terminal;
use terminal::*;

fn acquire_uninstall_lease_with<T>(
    mut acquire: impl FnMut() -> Result<T, String>,
    mut wait: impl FnMut(),
) -> Result<T, String> {
    for attempt in 0..=20 {
        match acquire() {
            Err(error) if error == "operation busy" && attempt < 20 => wait(),
            result => return result,
        }
    }
    unreachable!("bounded lease acquisition always returns")
}

fn run_phase_machine(self_bytes: &[u8]) -> Result<(), String> {
    let _runtime_exec_context = RUNTIME_EXEC_CONTEXT;
    if !path_entry_exists(Path::new(ZONE))? {
        return Err(
            "root-zone-free retry requires the fixed signed uninstall recovery".to_string(),
        );
    }
    validate_root_zone()?;
    validate_marker()?;
    let (inventory, transaction_id) = load_inventory_with_transaction_id()?;
    let (backup_bytes, backup_metadata) = load_verified_backup()?;
    let recovery_authority = recovery_state(&backup_metadata, self_bytes, &transaction_id)?;
    let phase = load_phase()?;
    let descriptor = uninstall_descriptor(phase, "running", 0, None)?;
    // init may start this worker before the triggering daemon drops its lease.
    // Every retry reacquires through the same checked operation authority.
    let lease = acquire_uninstall_lease_with(
        || OperationLease::acquire_in(Path::new(ZONE), descriptor.clone()),
        || thread::sleep(Duration::from_millis(250)),
    )?;
    lease.verify_owner()?;

    if matches!(
        phase,
        Phase::UninstallTerminalCleanup | Phase::UninstallAbsenceVerify
    ) {
        lease.verify_owner()?;
        crate::i18n_resource_files::verify_operation_absence(
            &RELEASE_CATALOG_PUBLIC_KEY,
            &lease,
            Operation::Uninstall,
        )
        .map_err(|error| format!("terminal resource absence: {error}"))?;
        let current_boot_id = canonical_boot_id()?;
        let active = load_recovery_state()?;
        let mut expected = recovery_authority.clone();
        expected.terminal_boot_id = Some(current_boot_id.clone());
        if active != recovery_authority && active != expected {
            return Err("terminal primary recovery authority differs".to_string());
        }
        publish_recovery(self_bytes)?;
        verify_recovery_hook()?;
        if active.terminal_boot_id.is_none() {
            persist_active_terminal_boot(&active, &current_boot_id)?;
        }
        let active = load_recovery_state()?;
        let directories = RetainedUninstallDirectories::open(&active)?;
        prepare_terminal_cleanup(
            self_bytes,
            &active,
            &backup_bytes,
            &backup_metadata,
            &directories,
            &lease,
        )?;
        return run_terminal_cleanup(self_bytes, lease);
    }

    if phase >= Phase::UninstallRuntimeRemove {
        lease.verify_owner()?;
        publish_recovery_bundle(self_bytes, &recovery_authority)?;
    }

    let progress = drive_uninstall_phases(
        phase,
        &mut DeviceUninstallActions {
            self_bytes,
            inventory: &inventory,
            recovery: &recovery_authority,
            lease: &lease,
        },
    )?;
    if progress == PhaseProgress::ResourceBootPending {
        return Ok(());
    }
    if progress != PhaseProgress::Terminal {
        return Err("primary uninstall did not reach terminal cleanup".to_string());
    }
    crate::i18n_resource_files::verify_operation_absence(
        &RELEASE_CATALOG_PUBLIC_KEY,
        &lease,
        Operation::Uninstall,
    )
    .map_err(|error| format!("terminal resource absence: {error}"))?;
    let current_boot_id = canonical_boot_id()?;
    let active = persist_active_terminal_boot(&recovery_authority, &current_boot_id)?;
    let directories = RetainedUninstallDirectories::open(&active)?;
    prepare_terminal_cleanup(
        self_bytes,
        &active,
        &backup_bytes,
        &backup_metadata,
        &directories,
        &lease,
    )?;
    run_terminal_cleanup(self_bytes, lease)
}

fn fail(event: &str, code: i32, error: String) -> ! {
    // Terminal diagnostics belong to the recovery transaction, which may itself
    // be the reason of the failure (busy lease, unreadable journal). The
    // fixed-depth stderr mirror under the recovery root is written first so a
    // crashing init service still leaves its exact first cause on the device.
    diag(&format!("fail event={event} code={code} error={error}"));
    write_failure_mirror(&format!("{event}: {error}"));
    if UNINSTALL_PATHS.get().is_some() {
        let _ = (|| -> Result<(), String> {
            let phase = load_phase()?;
            let reboot_count = load_recovery_state()
                .ok()
                .and_then(|state| state.terminal_reboot_boot_id.map(|_| 1))
                .unwrap_or(0);
            let descriptor = uninstall_descriptor(phase, "running", reboot_count, None)?;
            let lease = OperationLease::acquire_in(Path::new(ZONE), descriptor)?;
            publish_uninstall_status(
                &lease,
                phase,
                "failed",
                reboot_count,
                Some(&format!("{event}: {error}")),
            )
        })();
    }
    std::process::exit(code)
}

/// Best-effort first-cause mirror inside the uninstall transaction directory
/// only. A foreign transaction (install/restore) must never gain members:
/// install cleanup rejects unknown files, and the fixed catalog is part of the
/// terminal cleanup contract. Every error is ignored because the process is
/// already on its terminal exit path.
fn write_failure_mirror(text: &str) {
    let Ok(dir) = fs::read_dir(RECOVERY_ROOT) else {
        return;
    };
    let mut names: Vec<String> = dir
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| canonical_lower_hex(name, 32))
        .collect();
    names.sort();
    for transaction in names {
        let transaction_root = PathBuf::from(RECOVERY_ROOT).join(&transaction);
        let owns_uninstall = ["uninstall_do.json", "uninstall-journal.json"]
            .iter()
            .any(|member| transaction_root.join(member).exists());
        if !owns_uninstall {
            continue;
        }
        // The write is a temporary: the transaction directory rejects unknown
        // permanent members, so relabel the mirror to the fixed root-zone label
        // through the same prepare/rename pattern the WALs use.
        let target = transaction_root.join("failure.txt");
        let temp = transaction_root.join(".failure.txt.tmp");
        let Ok(mut file) = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temp)
        else {
            continue;
        };
        use std::io::Write as _;
        if writeln!(file, "{text}").is_err() {
            let _ = fs::remove_file(&temp);
            continue;
        }
        let Ok(()) = file.sync_all() else {
            let _ = fs::remove_file(&temp);
            continue;
        };
        drop(file);
        if fs::rename(&temp, &target).is_err() {
            let _ = fs::remove_file(&temp);
            continue;
        }
        return;
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod resource_role_tests {
    use super::*;
    #[test]
    fn resource_roles_reject_nonroot_extra_arguments_and_unknown_commands() {
        for flag in ["--i18n-none-finalize", "--resume-resource-uninstall"] {
            let mut args = vec!["voboost-uninstall".into(), flag.into()];
            assert!(resource_role_args(&args, 0).is_some());
            assert_eq!(resource_role_args(&args, 2000), None);
            args.push("/data/untrusted.dex".into());
            assert_eq!(resource_role_args(&args, 0), None);
        }
        assert_eq!(resource_role_args(&["voboost-uninstall".into()], 0), None);
        assert_eq!(
            resource_role_args(&["voboost-uninstall".into(), "--resume".into()], 0),
            None
        );
    }
    #[test]
    fn boot_resume_requires_existing_exact_uninstall_phase() {
        assert!(!resource_resume_phase(None));
        let mut active = OperationDescriptor {
            schema_version: 1,
            operation: Operation::Uninstall,
            transaction_id: "a".repeat(64),
            journal: format!("recovery/{}/uninstall-journal.json", "a".repeat(64)),
            phase: Phase::UninstallAppRemove.name(),
            outcome: "reboot-required".into(),
            reboot_count: 1,
            boot_id: "11111111-1111-4111-8111-111111111111".into(),
            status_sequence: 1,
            journal_sha256: "b".repeat(64),
            error: None,
            installed_apk: None,
        };
        // Input has already passed read_active_in's authenticated WAL parser.
        assert!(resource_resume_phase(Some(&active)));
        assert!(uninstall_metadata_context(Some(DATA_CONTEXT)));
        assert!(uninstall_metadata_context(Some(RECOVERY_TREE_CONTEXT)));
        assert!(!uninstall_metadata_context(Some(STOCK_DATA_CONTEXT)));
        assert!(!uninstall_metadata_context(None));
        assert!(!terminal_service_phase(None));
        assert!(!terminal_service_phase(Some(&active)));
        let mut terminal = active.clone();
        terminal.phase = Phase::UninstallAbsenceVerify.name();
        assert!(!resource_resume_phase(Some(&terminal)));
        assert!(terminal_service_phase(Some(&terminal)));
        let parsed = OperationDescriptor::parse(&active.canonical_bytes().unwrap()).unwrap();
        assert_eq!(
            carry_reboot_count(0, Some(&parsed), &active.transaction_id),
            1
        );
        assert_eq!(
            carry_reboot_count(2, Some(&parsed), &active.transaction_id),
            2
        );
        assert_eq!(carry_reboot_count(0, Some(&parsed), &"c".repeat(64)), 0);

        active.operation = Operation::Install;
        assert_eq!(
            carry_reboot_count(0, Some(&active), &active.transaction_id),
            0
        );
        assert!(!resource_resume_phase(Some(&active)));
        active.operation = Operation::Uninstall;
        active.phase = Phase::UninstallPrepare.name();
        assert!(!resource_resume_phase(Some(&active)));
        active.phase = Phase::UninstallAppRemove.name();
        active.outcome = "complete".into();
        assert!(!resource_resume_phase(Some(&active)));
    }
}
