//! Shared crash-safe publication for fixed files on protected system mounts.
//!
//! The caller supplies only compile-time fixed paths and exact content
//! authorities.  This module owns mount resolution, the durable remount WAL,
//! the forked watchdog, and the atomic target/temporary state machine.

use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(any(target_os = "android", target_os = "linux"))]
use std::os::fd::AsRawFd;
use std::os::fd::{FromRawFd, RawFd};
#[cfg(any(target_os = "android", target_os = "linux"))]
use std::os::unix::ffi::OsStrExt;
#[cfg(test)]
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_MOUNTINFO_BYTES: usize = 1024 * 1024;
const MAX_MOUNTINFO_LINES: usize = 4096;
const MAX_MOUNTINFO_LINE_BYTES: usize = 4096;
const WATCHDOG_TIMEOUT_SECONDS: i32 = 45;
const WATCHDOG_PARENT_TIMEOUT_SECONDS: u64 = WATCHDOG_TIMEOUT_SECONDS as u64 * 2;
#[cfg(any(target_os = "android", target_os = "linux"))]
const SELINUX_XATTR: &[u8] = b"security.selinux\0";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MountBoundary {
    mount_id: u64,
    major_minor: String,
    root: String,
    mount_point: String,
    source: String,
    fs_type: String,
    security_flags: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RemountJournal {
    schema_version: u32,
    transaction_id: String,
    targets: Vec<String>,
    boundaries: Vec<MountBoundary>,
    block_read_only: Vec<Option<bool>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Member {
    Absent,
    Candidate,
    Previous,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Create,
    Exchange,
    NoReplace,
    RemovePrevious,
    Finish,
}

#[derive(Clone, Copy)]
pub enum PreviousIdentity<'a> {
    #[allow(dead_code)] // Used by the product helper consumer; restore uses a legacy marker.
    Exact(&'a [u8]),
    Contains(&'a [u8]),
}

#[derive(Clone, Copy)]
pub struct FileIdentity<'a> {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub selinux_context: Option<&'a str>,
}

pub struct Publication<'a> {
    pub target: &'a Path,
    pub remount_wal: &'a Path,
    pub transaction_id: &'a str,
    pub temporary_namespace: &'a str,
    pub candidate: &'a [u8],
    pub maximum_bytes: u64,
    pub identity: FileIdentity<'a>,
    pub previous: PreviousIdentity<'a>,
}

fn canonical_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn canonical_transaction_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn action(target: Member, temporary: Member) -> Result<Action, String> {
    use Member::{Absent, Candidate, Previous};
    match (target, temporary) {
        (Absent | Previous, Absent) => Ok(Action::Create),
        (Absent, Candidate) => Ok(Action::NoReplace),
        (Previous, Candidate) => Ok(Action::Exchange),
        (Candidate, Previous) => Ok(Action::RemovePrevious),
        (Candidate, Absent) => Ok(Action::Finish),
        _ => Err("protected target and temporary state is unsafe".to_string()),
    }
}

fn classify(
    bytes: Option<&[u8]>,
    candidate: &[u8],
    previous: PreviousIdentity<'_>,
) -> Result<Member, String> {
    match bytes {
        None => Ok(Member::Absent),
        Some(value) if value == candidate => Ok(Member::Candidate),
        Some(value)
            if match previous {
                PreviousIdentity::Exact(expected) => value == expected,
                PreviousIdentity::Contains(marker) => {
                    !marker.is_empty() && value.windows(marker.len()).any(|window| window == marker)
                }
            } =>
        {
            Ok(Member::Previous)
        }
        Some(_) => Err("protected member has unknown content identity".to_string()),
    }
}

fn absent_only_on_enoent<T>(result: std::io::Result<T>, path: &Path) -> Result<Option<T>, String> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        Err(error) => Err(format!(
            "observe protected member {}: {error}",
            path.display()
        )),
    }
}

fn read_member(
    path: &Path,
    maximum: u64,
    identity: FileIdentity<'_>,
) -> Result<Option<Vec<u8>>, String> {
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    let _ = identity.selinux_context;
    let file = absent_only_on_enoent(
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path),
        path,
    )?;
    let Some(mut file) = file else {
        return Ok(None);
    };
    let before = file
        .metadata()
        .map_err(|error| format!("stat protected member {}: {error}", path.display()))?;
    if !before.is_file()
        || before.uid() != identity.uid
        || before.gid() != identity.gid
        || before.nlink() != 1
        || before.mode() & 0o7777 != identity.mode
        || before.len() == 0
        || before.len() > maximum
    {
        return Err(format!(
            "protected member {} has a foreign identity",
            path.display()
        ));
    }
    #[cfg(any(target_os = "android", target_os = "linux"))]
    if let Some(expected_context) = identity.selinux_context {
        let mut context = [0u8; 256];
        let size = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                SELINUX_XATTR.as_ptr().cast(),
                context.as_mut_ptr().cast(),
                context.len(),
            )
        };
        let mut expected = expected_context.as_bytes().to_vec();
        expected.push(0);
        if size < 0 || context[..size as usize] != expected {
            return Err(format!(
                "protected member {} has a foreign SELinux context",
                path.display()
            ));
        }
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read protected member {}: {error}", path.display()))?;
    let after = file
        .metadata()
        .map_err(|error| format!("restat protected member {}: {error}", path.display()))?;
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
    ) || bytes.len() as u64 != before.len()
    {
        return Err(format!(
            "protected member {} changed while reading",
            path.display()
        ));
    }
    Ok(Some(bytes))
}

fn sync_parent(path: &Path) -> Result<(), String> {
    File::open(path.parent().ok_or("path has no parent")?)
        .and_then(|file| file.sync_all())
        .map_err(|error| error.to_string())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let temporary = path.with_file_name(format!(
        ".{}.tmp",
        path.file_name()
            .ok_or("missing WAL leaf")?
            .to_string_lossy()
    ));
    if temporary.exists() {
        fs::remove_file(&temporary).map_err(|error| error.to_string())?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())?;
    fs::rename(&temporary, path).map_err(|error| error.to_string())?;
    sync_parent(path)
}

fn parse_mounts(bytes: &[u8], targets: &[String]) -> Result<Vec<MountBoundary>, String> {
    if bytes.len() > MAX_MOUNTINFO_BYTES {
        return Err("mountinfo exceeds byte bound".to_string());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "mountinfo is not UTF-8")?;
    let mut all = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if index >= MAX_MOUNTINFO_LINES || line.len() > MAX_MOUNTINFO_LINE_BYTES {
            return Err("mountinfo exceeds work bound".to_string());
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        let separator = fields
            .iter()
            .position(|field| *field == "-")
            .ok_or("bad mountinfo")?;
        if separator < 6 || fields.len() != separator + 4 {
            return Err("bad mountinfo shape".to_string());
        }
        let mut security_flags = 0;
        for flag in fields[5].split(',') {
            security_flags |= match flag {
                "nosuid" => 2,
                "nodev" => 4,
                "noexec" => 8,
                _ => 0,
            };
        }
        all.push(MountBoundary {
            mount_id: fields[0].parse().map_err(|_| "bad mount id")?,
            major_minor: fields[2].to_string(),
            root: fields[3].to_string(),
            mount_point: fields[4].to_string(),
            source: fields[separator + 2].to_string(),
            fs_type: fields[separator + 1].to_string(),
            security_flags,
        });
    }
    let mut selected = Vec::new();
    for target in targets {
        let contains = |mount: &&MountBoundary| {
            mount.mount_point == "/"
                || target == &mount.mount_point
                || target
                    .strip_prefix(&mount.mount_point)
                    .is_some_and(|tail| tail.starts_with('/'))
        };
        let longest = all
            .iter()
            .filter(contains)
            .map(|mount| mount.mount_point.len())
            .max()
            .ok_or("fixed target has no mount")?;
        let candidates: Vec<_> = all
            .iter()
            .filter(contains)
            .filter(|mount| mount.mount_point.len() == longest)
            .collect();
        if candidates.len() != 1 {
            return Err("fixed target mount is ambiguous".to_string());
        }
        let mount = candidates[0];
        if mount.root != "/"
            || !matches!(mount.fs_type.as_str(), "ext4" | "f2fs")
            || !(mount.source == "/dev/root" || mount.source.starts_with("/dev/block/"))
            || all.iter().any(|other| {
                other.mount_id != mount.mount_id
                    && other.major_minor == mount.major_minor
                    && other.root == mount.root
                    && other.fs_type == mount.fs_type
            })
        {
            return Err("fixed target mount identity is unsafe".to_string());
        }
        if !selected.contains(mount) {
            selected.push(mount.clone());
        }
    }
    Ok(selected)
}

fn resolved_targets(targets: &[&Path]) -> Result<Vec<String>, String> {
    targets
        .iter()
        .map(|target| {
            if !target.is_absolute() {
                return Err("protected target is not absolute".to_string());
            }
            let parent = fs::canonicalize(target.parent().ok_or("target lacks parent")?)
                .map_err(|error| error.to_string())?;
            parent
                .join(target.file_name().ok_or("target lacks leaf")?)
                .to_str()
                .map(str::to_string)
                .ok_or_else(|| "resolved target is not UTF-8".to_string())
        })
        .collect()
}

fn read_mountinfo_at(path: &Path) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|error| format!("open mountinfo: {error}"))?;
    let mut bytes = Vec::new();
    file.take((MAX_MOUNTINFO_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read mountinfo: {error}"))?;
    if bytes.len() > MAX_MOUNTINFO_BYTES {
        return Err("mountinfo exceeds byte bound".to_string());
    }
    Ok(bytes)
}

fn mounted_targets(targets: &[&Path]) -> Result<Vec<MountBoundary>, String> {
    parse_mounts(
        &read_mountinfo_at(Path::new("/proc/self/mountinfo"))?,
        &resolved_targets(targets)?,
    )
}

fn block_identity(boundary: &MountBoundary) -> crate::protected_block::BlockIdentityRef<'_> {
    crate::protected_block::BlockIdentityRef {
        source: &boundary.source,
        major_minor: &boundary.major_minor,
        fs_type: &boundary.fs_type,
    }
}

fn valid_block_protection(boundaries: &[MountBoundary], flags: &[Option<bool>]) -> bool {
    boundaries.len() == flags.len()
        && boundaries.iter().zip(flags).all(|(boundary, flag)| {
            matches!(boundary.fs_type.as_str(), "ext4" | "f2fs") == flag.is_some()
        })
}

fn remount(
    boundary: &MountBoundary,
    read_only: bool,
    original: Option<bool>,
) -> Result<(), String> {
    crate::protected_block::remount(block_identity(boundary), read_only, original, |ro| {
        remount_filesystem(boundary, ro)
    })
}

fn remount_filesystem(boundary: &MountBoundary, read_only: bool) -> Result<(), String> {
    remount_with(boundary, read_only, |source, target, fs_type, flags| {
        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            if unsafe {
                libc::mount(
                    source.as_ptr(),
                    target.as_ptr(),
                    fs_type.as_ptr(),
                    flags as libc::c_ulong,
                    std::ptr::null(),
                )
            } != 0
            {
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
}

fn remount_with(
    boundary: &MountBoundary,
    read_only: bool,
    invoke: impl FnOnce(&std::ffi::CStr, &std::ffi::CStr, &std::ffi::CStr, u64) -> Result<bool, String>,
) -> Result<(), String> {
    let source = std::ffi::CString::new(boundary.source.as_str())
        .map_err(|_| "mount source contains NUL")?;
    let target = std::ffi::CString::new(boundary.mount_point.as_str())
        .map_err(|_| "mount point contains NUL")?;
    let fs_type =
        std::ffi::CString::new(boundary.fs_type.as_str()).map_err(|_| "mount type contains NUL")?;
    let flags = 32_u64 | boundary.security_flags | u64::from(read_only);
    let observed = invoke(&source, &target, &fs_type, flags).map_err(|error| {
        format!(
            "remount {} source={} type={} flags={flags:#x}: {error}",
            boundary.mount_point, boundary.source, boundary.fs_type
        )
    })?;
    if observed != read_only {
        return Err(format!(
            "remount {} reported success but read-only={} (expected {})",
            boundary.mount_point, observed, read_only
        ));
    }
    Ok(())
}

fn wait_watchdog(pid: libc::pid_t, disarmed: bool) -> Result<(), String> {
    let mut status = 0;
    let deadline = Instant::now() + Duration::from_secs(WATCHDOG_PARENT_TIMEOUT_SECONDS);
    loop {
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if result == pid {
            break;
        }
        if result == 0 && Instant::now() >= deadline {
            return Err("protected-system watchdog exceeded its parent deadline".to_string());
        }
        if result == 0 {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        if result < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(format!(
            "wait for protected-system watchdog: {}",
            std::io::Error::last_os_error()
        ));
    }
    let code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };
    let expected = if disarmed { 0 } else { 20 };
    (code == expected)
        .then_some(())
        .ok_or_else(|| format!("protected-system watchdog exited with {code}, expected {expected}"))
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
    unsafe { libc::close(control_fd) };
    if disarmed {
        0
    } else if recover().is_ok() {
        20
    } else {
        21
    }
}

fn recover_boundaries(
    wal: &Path,
    transaction_id: &str,
    targets: &[&Path],
    boundaries: &[MountBoundary],
    block_read_only: &[Option<bool>],
) -> Result<(), String> {
    if boundaries.is_empty() || boundaries.len() > 8 {
        return Err("protected-system recovery WAL has invalid boundary count".to_string());
    }
    let expected = remount_journal(transaction_id, targets, boundaries, block_read_only)?;
    if load_remount_journal(wal)? != expected {
        return Err("protected-system recovery WAL differs from inherited authority".to_string());
    }
    for (boundary, original) in boundaries.iter().zip(block_read_only).rev() {
        let current = mounted_targets(targets)?;
        if !current.iter().any(|candidate| candidate == boundary) {
            return Err("mount topology changed before protected-system recovery".to_string());
        }
        remount(boundary, true, *original)?;
    }
    fs::remove_file(wal).map_err(|error| error.to_string())?;
    sync_parent(wal)
}

fn watchdog_child(
    control_fd: RawFd,
    transaction_id: &str,
    targets: &[&Path],
    boundaries: &[MountBoundary],
    block_read_only: &[Option<bool>],
    wal: &Path,
) -> i32 {
    watchdog_control_result(control_fd, WATCHDOG_TIMEOUT_SECONDS * 1000, || {
        recover_boundaries(wal, transaction_id, targets, boundaries, block_read_only)
    })
}

fn remount_journal(
    transaction_id: &str,
    targets: &[&Path],
    boundaries: &[MountBoundary],
    block_read_only: &[Option<bool>],
) -> Result<RemountJournal, String> {
    if !canonical_transaction_id(transaction_id)
        || targets.is_empty()
        || targets.len() > 8
        || boundaries.is_empty()
        || boundaries.len() > 8
        || !valid_block_protection(boundaries, block_read_only)
    {
        return Err("protected-system remount authority is invalid".to_string());
    }
    Ok(RemountJournal {
        schema_version: 2,
        transaction_id: transaction_id.to_string(),
        targets: resolved_targets(targets)?,
        boundaries: boundaries.to_vec(),
        block_read_only: block_read_only.to_vec(),
    })
}

fn load_remount_journal(wal: &Path) -> Result<RemountJournal, String> {
    let bytes = read_member(
        wal,
        64 * 1024,
        FileIdentity {
            uid: 0,
            gid: 0,
            mode: 0o600,
            selinux_context: None,
        },
    )?
    .ok_or("protected-system recovery WAL disappeared")?;
    let journal: RemountJournal = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse protected-system recovery WAL: {error}"))?;
    if journal.schema_version != 2
        || !canonical_transaction_id(&journal.transaction_id)
        || journal.targets.is_empty()
        || journal.targets.len() > 8
        || journal
            .targets
            .iter()
            .any(|target| !target.starts_with('/'))
        || journal.boundaries.is_empty()
        || journal.boundaries.len() > 8
        || !valid_block_protection(&journal.boundaries, &journal.block_read_only)
    {
        return Err("protected-system recovery WAL authority is invalid".to_string());
    }
    Ok(journal)
}

fn with_writable_mounts<T>(
    targets: &[&Path],
    wal: &Path,
    transaction_id: &str,
    mutation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let boundaries = mounted_targets(targets)?;
    let block_read_only = boundaries
        .iter()
        .map(|boundary| crate::protected_block::capture(block_identity(boundary)))
        .collect::<Result<Vec<_>, _>>()?;
    let journal = remount_journal(transaction_id, targets, &boundaries, &block_read_only)?;

    let mut wal_bytes = serde_json::to_vec(&journal).map_err(|error| error.to_string())?;
    wal_bytes.push(b'\n');
    write_atomic(wal, &wal_bytes)?;
    let mut pipe = [0; 2];
    if unsafe { libc::pipe(pipe.as_mut_ptr()) } != 0 {
        return Err(format!(
            "create protected-system watchdog pipe: {}",
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
                "protect protected-system watchdog pipe: {}",
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
            "fork protected-system watchdog: {}",
            std::io::Error::last_os_error()
        ));
    }
    if pid == 0 {
        unsafe { libc::close(pipe[1]) };
        let code = watchdog_child(
            pipe[0],
            transaction_id,
            targets,
            &boundaries,
            &block_read_only,
            wal,
        );
        unsafe { libc::_exit(code) };
    }
    unsafe { libc::close(pipe[0]) };
    let mut watchdog = unsafe { File::from_raw_fd(pipe[1]) };
    let mut writable = Vec::new();
    for (boundary, original) in boundaries.iter().zip(&block_read_only) {
        if mounted_targets(targets)? != boundaries {
            drop(watchdog);
            let _ = wait_watchdog(pid, false);
            return Err("mount topology changed before remount".to_string());
        }
        if let Err(error) = remount(boundary, false, *original) {
            drop(watchdog);
            let recovery = wait_watchdog(pid, false);
            return recovery.and(Err(error));
        }
        writable.push((boundary, *original));
    }
    let result = mutation();
    let mut restore_error = None;
    for (boundary, original) in writable.into_iter().rev() {
        if mounted_targets(targets)?
            .iter()
            .any(|current| current == boundary)
        {
            if let Err(error) = remount(boundary, true, original) {
                restore_error = Some(error);
            }
        } else {
            restore_error = Some("mount topology changed before read-only restore".to_string());
        }
    }
    if restore_error.is_none() {
        fs::remove_file(wal).map_err(|error| error.to_string())?;
        sync_parent(wal)?;
        watchdog
            .write_all(b"D")
            .map_err(|error| format!("disarm protected-system watchdog: {error}"))?;
        drop(watchdog);
        wait_watchdog(pid, true)?;
    } else {
        drop(watchdog);
        if let Some(error) = wait_watchdog(pid, false).err() {
            restore_error = Some(match restore_error {
                Some(existing) => format!("{existing}; {error}"),
                None => error,
            });
        }
    }
    match (result, restore_error) {
        (Ok(value), None) => Ok(value),
        (Err(error), None) => Err(error),
        (Ok(_), Some(error)) => Err(format!("mutation succeeded; {error}")),
        (Err(error), Some(restore)) => Err(format!("{error}; {restore}")),
    }
}

/// Bounded owned-RRO write scope; caller must already hold signed resource authority.
/// Neither target nor WAL path is caller-controlled. Existing watchdog restores RO.
pub fn recover_owned_resource_write(transaction_id: &str) -> Result<(), String> {
    if !canonical_transaction_id(transaction_id) {
        return Err("invalid owned resource transaction identity".into());
    }
    let wal = Path::new("/data/voboost/i18n-resource-transaction/remount.json");
    if !wal.exists() {
        return Ok(());
    }
    let journal = load_remount_journal(wal)?;
    let parent = fs::canonicalize("/vendor/overlay")
        .map_err(|error| format!("resolve owned overlay root: {error}"))?;
    let target = owned_resource_wal_target(&journal, transaction_id, &parent)?;
    recover_pending(target, wal, transaction_id)
}
pub fn with_owned_resource_write<T>(
    transaction_id: &str,
    mutation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    recover_owned_resource_write(transaction_id)?;
    with_writable_mounts(
        &[Path::new("/vendor/overlay/voboost-setting-ru.apk")],
        Path::new("/data/voboost/i18n-resource-transaction/remount.json"),
        transaction_id,
        mutation,
    )
}
/// Bounded owned-RRO write scope for the install resource variant set: the
/// single /vendor/overlay boundary covers every staged owned overlay file.
pub fn with_owned_resource_variant_write<T>(
    transaction_id: &str,
    owned_file: &str,
    mutation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    // One explicit scope supplies both recovery and publication identities.
    owned_resource_variant_scope(
        transaction_id,
        owned_file,
        |_target| recover_owned_resource_write(transaction_id),
        |target| {
            if let Err(error) = fs::create_dir(Path::new("/data/voboost/i18n-resource-transaction"))
            {
                if error.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(format!("create owned resource transaction root: {error}"));
                }
            }
            with_writable_mounts(
                &[target],
                Path::new("/data/voboost/i18n-resource-transaction/remount.json"),
                transaction_id,
                mutation,
            )
        },
    )
}

fn owned_resource_wal_target<'a>(
    journal: &'a RemountJournal,
    transaction_id: &str,
    overlay_parent: &Path,
) -> Result<&'a Path, String> {
    if journal.schema_version != 2
        || !canonical_transaction_id(transaction_id)
        || journal.transaction_id != transaction_id
        || journal.targets.len() != 1
    {
        return Err("owned resource recovery WAL authority differs".into());
    }
    let target = Path::new(&journal.targets[0]);
    let known = crate::owned_overlay::Variant::ALL.iter().any(|variant| {
        target.file_name().and_then(|leaf| leaf.to_str()) == Some(variant.file())
            || target.file_name().and_then(|leaf| leaf.to_str()) == Some(variant.staged())
    });
    if target.parent() != Some(overlay_parent) || !known {
        return Err("owned resource recovery WAL target is foreign".into());
    }
    Ok(target)
}

fn owned_resource_variant_scope<T>(
    transaction_id: &str,
    owned_file: &str,
    recover: impl FnOnce(&Path) -> Result<(), String>,
    publish: impl FnOnce(&Path) -> Result<T, String>,
) -> Result<T, String> {
    let known = crate::owned_overlay::Variant::ALL.iter().any(|variant| {
        owned_file == format!("/vendor/overlay/{}", variant.file())
            || owned_file == format!("/vendor/overlay/{}", variant.staged())
    });
    if !canonical_transaction_id(transaction_id) || !known {
        return Err("invalid owned resource variant write request".into());
    }
    let target = Path::new("/vendor/overlay/voboost-setting-ru.apk");
    recover(target)?;
    publish(target)
}

pub fn recover_pending(target: &Path, wal: &Path, transaction_id: &str) -> Result<(), String> {
    if !wal.exists() {
        return Ok(());
    }
    let journal = load_remount_journal(wal)?;
    let targets = [target];
    let expected = remount_journal(
        transaction_id,
        &targets,
        &journal.boundaries,
        &journal.block_read_only,
    )?;
    if journal != expected {
        return Err("protected-system recovery WAL has wrong transaction or target".to_string());
    }
    recover_boundaries(
        wal,
        transaction_id,
        &targets,
        &journal.boundaries,
        &journal.block_read_only,
    )
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn rename_with_flags(
    parent: &File,
    from: &std::ffi::CStr,
    to: &std::ffi::CStr,
    flags: u32,
) -> Result<(), String> {
    if unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            parent.as_raw_fd(),
            from.as_ptr(),
            parent.as_raw_fd(),
            to.as_ptr(),
            flags,
        )
    } != 0
    {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn create_temporary(
    parent: &File,
    temporary_name: &std::ffi::CStr,
    bytes: &[u8],
    identity: FileIdentity<'_>,
) -> Result<(), String> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            temporary_name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(format!(
            "create protected temporary: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)
        .map_err(|error| format!("write protected temporary: {error}"))?;
    if unsafe { libc::fchown(file.as_raw_fd(), identity.uid, identity.gid) } != 0
        || unsafe { libc::fchmod(file.as_raw_fd(), identity.mode) } != 0
    {
        return Err(format!(
            "set protected temporary identity: {}",
            std::io::Error::last_os_error()
        ));
    }
    if let Some(expected_context) = identity.selinux_context {
        let context = std::ffi::CString::new(expected_context)
            .map_err(|_| "protected context contains NUL")?;
        if unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                SELINUX_XATTR.as_ptr().cast(),
                context.as_ptr().cast(),
                context.as_bytes_with_nul().len(),
                0,
            )
        } != 0
        {
            return Err("set protected temporary SELinux context failed".to_string());
        }
    }
    file.sync_all()
        .map_err(|error| format!("sync protected temporary: {error}"))
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn apply_action(
    action: Action,
    parent: &File,
    target_name: &std::ffi::CStr,
    temporary_name: &std::ffi::CStr,
    candidate: &[u8],
    identity: FileIdentity<'_>,
) -> Result<(), String> {
    match action {
        Action::Create => {
            create_temporary(parent, temporary_name, candidate, identity)?;
        }
        Action::Exchange => {
            rename_with_flags(
                parent,
                temporary_name,
                target_name,
                libc::RENAME_EXCHANGE as u32,
            )?;
        }
        Action::NoReplace => {
            rename_with_flags(
                parent,
                temporary_name,
                target_name,
                libc::RENAME_NOREPLACE as u32,
            )?;
        }
        Action::RemovePrevious => {
            if unsafe { libc::unlinkat(parent.as_raw_fd(), temporary_name.as_ptr(), 0) } != 0 {
                return Err(format!(
                    "remove previous protected temporary: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        Action::Finish => return Ok(()),
    }
    parent
        .sync_all()
        .map_err(|error| format!("sync protected parent: {error}"))
}

fn temporary_path(publication: &Publication<'_>) -> Result<PathBuf, String> {
    if !canonical_transaction_id(publication.transaction_id)
        || !canonical_component(publication.temporary_namespace)
    {
        return Err("protected publication namespace is invalid".to_string());
    }
    let leaf = publication
        .target
        .file_name()
        .ok_or("protected target lacks leaf")?
        .to_str()
        .ok_or("protected target leaf is not UTF-8")?;
    // The single product OperationLease serializes this fixed protected target.
    // Its temporary name also binds the narrow SELinux filename transition.
    if publication.target == Path::new("/system/etc/init/voboost.rc")
        && publication.temporary_namespace == "product-rollback"
    {
        return Ok(publication.target.with_file_name(".voboost.rc.product-rollback.tmp"));
    }
    Ok(publication.target.with_file_name(format!(
        ".{leaf}.{}-{}.tmp",
        publication.temporary_namespace, publication.transaction_id
    )))
}

type ObservedPair = (Option<Vec<u8>>, Option<Vec<u8>>);

fn observe_pair(publication: &Publication<'_>, temporary: &Path) -> Result<ObservedPair, String> {
    Ok((
        read_member(
            publication.target,
            publication.maximum_bytes,
            publication.identity,
        )?,
        read_member(temporary, publication.maximum_bytes, publication.identity)?,
    ))
}

pub fn publish(publication: &Publication<'_>) -> Result<(), String> {
    if publication.candidate.is_empty()
        || publication.candidate.len() as u64 > publication.maximum_bytes
        || publication.identity.mode & !0o7777 != 0
    {
        return Err("protected candidate authority is invalid".to_string());
    }
    let temporary = temporary_path(publication)?;
    let initial = observe_pair(publication, &temporary)?;
    let first_action = action(
        classify(
            initial.0.as_deref(),
            publication.candidate,
            publication.previous,
        )?,
        classify(
            initial.1.as_deref(),
            publication.candidate,
            publication.previous,
        )?,
    )?;
    if first_action == Action::Finish {
        return Ok(());
    }
    with_writable_mounts(
        &[publication.target],
        publication.remount_wal,
        publication.transaction_id,
        || {
            if observe_pair(publication, &temporary)? != initial {
                return Err("protected member identity changed before publication".to_string());
            }
            #[cfg(any(target_os = "android", target_os = "linux"))]
            {
                let parent_path = publication
                    .target
                    .parent()
                    .ok_or("protected target lacks parent")?;
                let parent = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
                    .open(parent_path)
                    .map_err(|error| format!("open protected parent: {error}"))?;
                let target_name = std::ffi::CString::new(
                    publication
                        .target
                        .file_name()
                        .ok_or("protected target lacks leaf")?
                        .as_bytes(),
                )
                .map_err(|error| error.to_string())?;
                let temporary_name = std::ffi::CString::new(
                    temporary
                        .file_name()
                        .ok_or("protected temporary lacks leaf")?
                        .as_bytes(),
                )
                .map_err(|error| error.to_string())?;
                let mut next = first_action;
                for _ in 0..4 {
                    apply_action(
                        next,
                        &parent,
                        &target_name,
                        &temporary_name,
                        publication.candidate,
                        publication.identity,
                    )?;
                    let observed = observe_pair(publication, &temporary)?;
                    next = action(
                        classify(
                            observed.0.as_deref(),
                            publication.candidate,
                            publication.previous,
                        )?,
                        classify(
                            observed.1.as_deref(),
                            publication.candidate,
                            publication.previous,
                        )?,
                    )?;
                    if next == Action::Finish {
                        return Ok(());
                    }
                }
                Err("protected publication did not converge".to_string())
            }
            #[cfg(not(any(target_os = "android", target_os = "linux")))]
            Err("protected publication requires renameat2".to_string())
        },
    )?;
    let installed = read_member(
        publication.target,
        publication.maximum_bytes,
        publication.identity,
    )?
    .ok_or("protected candidate did not publish")?;
    (installed == publication.candidate)
        .then_some(())
        .ok_or_else(|| "protected candidate did not publish".to_string())
}

/// Verify the exact terminal publication state without mutating it.
pub fn verify(publication: &Publication<'_>) -> Result<(), String> {
    if publication.remount_wal.exists() {
        return Err("protected publication still owns a remount WAL".to_string());
    }
    let temporary = temporary_path(publication)?;
    let observed = observe_pair(publication, &temporary)?;
    if classify(
        observed.0.as_deref(),
        publication.candidate,
        publication.previous,
    )? != Member::Candidate
        || classify(
            observed.1.as_deref(),
            publication.candidate,
            publication.previous,
        )? != Member::Absent
    {
        return Err("protected publication is not terminal".to_string());
    }
    Ok(())
}

/// Publish rollback bytes through the same transaction.  For a rollback
/// request, `candidate` is the exact previous release and `previous` binds the
/// currently installed release being replaced.
#[allow(dead_code)] // Exported for the product-system helper consumer.
pub fn rollback(publication: &Publication<'_>) -> Result<(), String> {
    publish(publication)?;
    verify(publication)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_state_machine_covers_every_durable_cut() {
        use Action::{Create, Exchange, Finish, NoReplace, RemovePrevious};
        use Member::{Absent, Candidate, Previous};
        assert_eq!(action(Previous, Absent).unwrap(), Create);
        assert_eq!(action(Previous, Candidate).unwrap(), Exchange);
        assert_eq!(action(Candidate, Previous).unwrap(), RemovePrevious);
        assert_eq!(action(Candidate, Absent).unwrap(), Finish);
        assert_eq!(action(Absent, Candidate).unwrap(), NoReplace);
        assert_eq!(action(Absent, Absent).unwrap(), Create);
        for hostile in [
            (Candidate, Candidate),
            (Absent, Previous),
            (Previous, Previous),
        ] {
            assert!(action(hostile.0, hostile.1).is_err());
        }
    }

    #[test]
    fn exact_and_marker_previous_authorities_do_not_overlap_candidate() {
        assert_eq!(
            classify(Some(b"old"), b"new", PreviousIdentity::Exact(b"old")).unwrap(),
            Member::Previous
        );
        assert_eq!(
            classify(
                Some(b"prefix recovery hook suffix"),
                b"new",
                PreviousIdentity::Contains(b"recovery hook")
            )
            .unwrap(),
            Member::Previous
        );
        assert_eq!(
            classify(Some(b"new"), b"new", PreviousIdentity::Exact(b"new")).unwrap(),
            Member::Candidate
        );
        assert!(classify(Some(b"foreign"), b"new", PreviousIdentity::Exact(b"old")).is_err());
        assert!(classify(Some(b"foreign"), b"new", PreviousIdentity::Contains(b"")).is_err());
    }

    #[test]
    fn member_reader_rejects_non_enoent_and_foreign_identity() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let identity = FileIdentity {
            uid,
            gid,
            mode: 0o600,
            selinux_context: None,
        };
        let missing = root.path().join("missing");
        assert_eq!(read_member(&missing, 16, identity).unwrap(), None);
        for errno in [
            libc::EACCES,
            libc::EIO,
            libc::ELOOP,
            libc::ENOTDIR,
            libc::ESTALE,
        ] {
            assert!(absent_only_on_enoent::<()>(
                Err(std::io::Error::from_raw_os_error(errno)),
                Path::new("hostile")
            )
            .is_err());
        }

        let regular = root.path().join("regular");
        fs::write(&regular, b"candidate").unwrap();
        fs::set_permissions(&regular, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_member(&regular, 16, identity).unwrap().unwrap(),
            b"candidate"
        );
        let wrong_mode = FileIdentity {
            mode: 0o644,
            ..identity
        };
        assert!(read_member(&regular, 16, wrong_mode).is_err());
        let wrong_owner = FileIdentity {
            uid: uid.wrapping_add(1),
            ..identity
        };
        assert!(read_member(&regular, 16, wrong_owner).is_err());

        let hardlink = root.path().join("hardlink");
        fs::hard_link(&regular, &hardlink).unwrap();
        assert!(read_member(&regular, 16, identity).is_err());
        assert!(read_member(&hardlink, 16, identity).is_err());
        let symlink_path = root.path().join("symlink");
        symlink(&regular, &symlink_path).unwrap();
        assert!(read_member(&symlink_path, 16, identity).is_err());

        let oversized = root.path().join("oversized");
        fs::write(&oversized, [b'x'; 17]).unwrap();
        fs::set_permissions(&oversized, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_member(&oversized, 16, identity).is_err());
    }

    #[test]
    fn remount_uses_verified_boundary_and_checks_readback() {
        let boundary = MountBoundary {
            mount_id: 26,
            major_minor: "8:1".into(),
            root: "/".into(),
            mount_point: "/vendor".into(),
            source: "/dev/block/vendor".into(),
            fs_type: "ext4".into(),
            security_flags: 2 | 4 | 8,
        };
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
        assert!(remount_with(&boundary, false, |_, _, _, _| Ok(true)).is_err());
        assert!(remount_with(&boundary, false, |_, _, _, _| Err(
            "Permission denied".into()
        ))
        .unwrap_err()
        .contains("Permission denied"));
    }

    #[test]
    fn mount_resolver_accepts_a9_and_a11_and_rejects_hostile_aliases() {
        let target = "/system/etc/init/voboost.rc".to_string();
        let a9 = b"25 1 8:1 / / ro,nosuid,nodev - ext4 /dev/root ro\n";
        let mounts = parse_mounts(a9, std::slice::from_ref(&target)).unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].mount_point, "/");
        assert_eq!(mounts[0].security_flags, 6);

        let a11 = concat!(
            "25 1 8:1 / / ro,nosuid,nodev - ext4 /dev/root ro\n",
            "26 25 8:2 / /system ro,nosuid,nodev - ext4 /dev/block/system ro\n",
        );
        let mounts = parse_mounts(a11.as_bytes(), std::slice::from_ref(&target)).unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].mount_point, "/system");

        for hostile in [
            concat!(
                "25 1 8:1 / / ro - ext4 /dev/root ro\n",
                "26 25 8:2 / /system ro - ext4 /dev/block/system ro\n",
                "27 25 8:2 / /alias ro - ext4 /dev/block/system ro\n",
            ),
            "26 25 8:2 /subtree /system ro - ext4 /dev/block/system ro\n",
            "26 25 0:44 / /system ro - overlay overlay ro\n",
        ] {
            assert!(parse_mounts(hostile.as_bytes(), std::slice::from_ref(&target)).is_err());
        }
        let drift = b"26 25 8:9 / /system ro - ext4 /dev/block/system ro\n";
        assert_ne!(
            parse_mounts(drift, std::slice::from_ref(&target)).unwrap(),
            mounts
        );
    }

    #[test]
    fn mountinfo_reader_rejects_n_plus_one_before_parsing() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("mountinfo");
        fs::write(&path, vec![b'x'; MAX_MOUNTINFO_BYTES + 1]).unwrap();
        assert!(read_mountinfo_at(&path).is_err());
    }

    #[test]
    fn owned_recovery_accepts_only_exact_current_transaction_and_known_target() {
        let parent = Path::new("/vendor/overlay");
        let tx = "a".repeat(64);
        for variant in crate::owned_overlay::Variant::ALL {
            for leaf in [variant.file(), variant.staged()] {
                let journal = RemountJournal {
                    schema_version: 2,
                    transaction_id: tx.clone(),
                    targets: vec![format!("/vendor/overlay/{leaf}")],
                    boundaries: vec![],
                    block_read_only: vec![],
                };
                assert_eq!(
                    owned_resource_wal_target(&journal, &tx, parent).unwrap(),
                    Path::new(&journal.targets[0])
                );
                assert!(owned_resource_wal_target(&journal, &"b".repeat(64), parent).is_err());
                let mut extra = journal.clone();
                extra.targets.push("/vendor/overlay/foreign.apk".into());
                assert!(owned_resource_wal_target(&extra, &tx, parent).is_err());
            }
        }
        for target in [
            "/vendor/overlay/foreign.apk",
            "/system/voboost-setting-ru.apk",
            "/vendor/overlay/../voboost-setting-ru.apk",
        ] {
            let journal = RemountJournal {
                schema_version: 2,
                transaction_id: tx.clone(),
                targets: vec![target.into()],
                boundaries: vec![],
                block_read_only: vec![],
            };
            assert!(owned_resource_wal_target(&journal, &tx, parent).is_err());
        }
    }

    #[test]
    fn owned_variant_scope_uses_one_target_for_recovery_and_publication() {
        for variant in crate::owned_overlay::Variant::ALL {
            for leaf in [variant.file(), variant.staged()] {
                let owned = format!("/vendor/overlay/{leaf}");
                let recovery = std::cell::RefCell::new(None);
                owned_resource_variant_scope(
                    &"a".repeat(64),
                    &owned,
                    |target| {
                        *recovery.borrow_mut() = Some(target.to_path_buf());
                        Ok(())
                    },
                    |target| {
                        assert_eq!(recovery.borrow().as_deref(), Some(target), "{owned}");
                        Ok(())
                    },
                )
                .unwrap();
            }
        }
        for foreign in [
            "/vendor/overlay/foreign.apk",
            "/vendor/overlay/../evil.apk",
            "/system/voboost-setting-ru.apk",
        ] {
            assert!(owned_resource_variant_scope::<()>(
                &"a".repeat(64),
                foreign,
                |_| panic!("foreign recovery"),
                |_| panic!("foreign publish")
            )
            .is_err());
        }
    }

    #[test]
    fn resource_remount_requires_durable_original_block_protection() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("resource.apk");
        let mut boundary = MountBoundary {
            mount_id: 26,
            major_minor: "253:65".into(),
            root: "/".into(),
            mount_point: "/vendor".into(),
            source: "/dev/block/vendor".into(),
            fs_type: "ext4".into(),
            security_flags: 0,
        };
        let tx = "a".repeat(64);
        for flags in [&[][..], &[None][..], &[Some(true), Some(false)][..]] {
            assert!(
                remount_journal(&tx, &[&target], std::slice::from_ref(&boundary), flags).is_err()
            );
        }
        assert_eq!(
            remount(&boundary, false, None).unwrap_err(),
            "missing journaled block protection"
        );
        for original in [true, false] {
            let journal = remount_journal(
                &tx,
                &[&target],
                std::slice::from_ref(&boundary),
                &[Some(original)],
            )
            .unwrap();
            let encoded = serde_json::to_value(&journal).unwrap();
            assert_eq!(encoded["blockReadOnly"], serde_json::json!([original]));
            assert_eq!(
                serde_json::from_value::<RemountJournal>(encoded.clone()).unwrap(),
                journal
            );
            let mut absent = encoded;
            absent.as_object_mut().unwrap().remove("blockReadOnly");
            assert!(serde_json::from_value::<RemountJournal>(absent).is_err());
        }
        boundary.fs_type = "overlay".into();
        assert!(remount_journal(
            &tx,
            &[&target],
            std::slice::from_ref(&boundary),
            &[Some(true)]
        )
        .is_err());
        assert!(remount_journal(&tx, &[&target], &[boundary], &[None]).is_ok());
    }

    #[test]
    fn remount_wal_binds_schema_transaction_target_and_mount_identity() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("voboost.rc");
        let boundary = MountBoundary {
            mount_id: 26,
            major_minor: "8:2".to_string(),
            root: "/".to_string(),
            mount_point: "/system".to_string(),
            source: "/dev/block/system".to_string(),
            fs_type: "ext4".to_string(),
            security_flags: 6,
        };
        let tx = "a".repeat(64);
        let journal = remount_journal(
            &tx,
            &[&target],
            std::slice::from_ref(&boundary),
            &[Some(true)],
        )
        .unwrap();
        assert_eq!(journal.schema_version, 2);
        assert_eq!(journal.transaction_id, tx);
        let resolved_target = fs::canonicalize(root.path())
            .unwrap()
            .join("voboost.rc")
            .display()
            .to_string();
        assert_eq!(journal.targets, vec![resolved_target]);
        assert_eq!(journal.boundaries, vec![boundary]);

        let other_tx = "b".repeat(64);
        assert_ne!(
            journal,
            remount_journal(
                &other_tx,
                &[&target],
                std::slice::from_ref(&journal.boundaries[0]),
                &journal.block_read_only
            )
            .unwrap()
        );
        let other_target = root.path().join("other.rc");
        assert_ne!(
            journal,
            remount_journal(
                &journal.transaction_id,
                &[&other_target],
                std::slice::from_ref(&journal.boundaries[0]),
                &journal.block_read_only
            )
            .unwrap()
        );

        let mut value = serde_json::to_value(&journal).unwrap();
        value["foreign"] = serde_json::json!(true);
        assert!(serde_json::from_value::<RemountJournal>(value).is_err());
    }

    #[test]
    fn forked_watchdog_recovers_after_controller_sigkill() {
        let mut signal = [0; 2];
        assert_eq!(unsafe { libc::pipe(signal.as_mut_ptr()) }, 0);
        let controller = unsafe { libc::fork() };
        assert!(controller >= 0);
        if controller == 0 {
            unsafe { libc::close(signal[0]) };
            let mut control = [0; 2];
            if unsafe { libc::pipe(control.as_mut_ptr()) } != 0 {
                unsafe { libc::_exit(2) };
            }
            let child = unsafe { libc::fork() };
            if child == 0 {
                unsafe { libc::close(control[1]) };
                let code = watchdog_control_result(control[0], 5_000, || {
                    let byte = b'R';
                    let written = unsafe { libc::write(signal[1], (&byte as *const u8).cast(), 1) };
                    (written == 1)
                        .then_some(())
                        .ok_or_else(|| "write recovery callback".to_string())
                });
                unsafe { libc::_exit((code != 20) as i32) };
            }
            unsafe { libc::close(control[0]) };
            let byte = b'S';
            unsafe { libc::write(signal[1], (&byte as *const u8).cast(), 1) };
            unsafe {
                libc::pause();
                libc::_exit(1);
            }
        }
        unsafe { libc::close(signal[1]) };
        let mut byte = 0u8;
        assert_eq!(
            unsafe { libc::read(signal[0], (&mut byte as *mut u8).cast(), 1) },
            1
        );
        assert_eq!(byte, b'S');
        unsafe { libc::kill(controller, libc::SIGKILL) };
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(controller, &mut status, 0) },
            controller
        );
        assert_eq!(
            unsafe { libc::read(signal[0], (&mut byte as *mut u8).cast(), 1) },
            1
        );
        assert_eq!(byte, b'R');
        unsafe { libc::close(signal[0]) };
    }

    #[test]
    fn watchdog_timeout_and_abort_recover_but_exact_disarm_does_not() {
        for (command, expected, recoveries) in
            [(None, 20, 1), (Some(b'A'), 20, 1), (Some(b'D'), 0, 0)]
        {
            let mut pipe = [0; 2];
            assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
            if let Some(command) = command {
                assert_eq!(
                    unsafe { libc::write(pipe[1], (&command as *const u8).cast(), 1) },
                    1
                );
            }
            unsafe { libc::close(pipe[1]) };
            let count = std::cell::Cell::new(0);
            let code = watchdog_control_result(pipe[0], 1, || {
                count.set(count.get() + 1);
                Ok(())
            });
            assert_eq!(code, expected);
            assert_eq!(count.get(), recoveries);
        }
    }
}
