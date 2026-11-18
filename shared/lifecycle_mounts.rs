use super::*;

#[path = "lifecycle_block.rs"]
mod block;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, serde::Serialize)]
pub(super) struct RequiredMount {
    pub(super) mount_id: u64,
    pub(super) parent_id: u64,
    pub(super) major_minor: String,
    pub(super) root: String,
    pub(super) mount_point: String,
    pub(super) source: String,
    pub(super) fs_type: String,
    pub(super) security_flags: u64,
    pub(super) super_options: String,
}

pub(super) const REMOUNT_NOSUID: u64 = 2;
pub(super) const REMOUNT_NODEV: u64 = 4;
pub(super) const REMOUNT_NOEXEC: u64 = 8;

#[derive(Debug)]
#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
pub(super) struct NativeRemountError {
    message: String,
}

impl std::fmt::Display for NativeRemountError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

pub(super) fn decode_mountinfo_field(field: &str) -> Result<String, String> {
    let bytes = field.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'\\' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 3 >= bytes.len() {
            return Err("truncated mountinfo escape".to_string());
        }
        let value = match &bytes[index + 1..index + 4] {
            b"040" => b' ',
            b"011" => b'\t',
            b"012" => b'\n',
            b"134" => b'\\',
            _ => return Err("unsupported mountinfo escape".to_string()),
        };
        decoded.push(value);
        index += 4;
    }
    String::from_utf8(decoded).map_err(|_| "non-UTF8 mountinfo field".to_string())
}

pub(super) fn path_is_within(path: &str, boundary: &str) -> bool {
    boundary == "/"
        || path == boundary
        || path
            .strip_prefix(boundary)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

pub(super) fn resolve_required_mounts(
    mountinfo: &[u8],
    resolved_targets: &[&str],
) -> Result<Vec<RequiredMount>, String> {
    if mountinfo.len() > MAX_MOUNTINFO_BYTES {
        return Err("mountinfo exceeds byte bound".to_string());
    }
    let text = std::str::from_utf8(mountinfo).map_err(|_| "mountinfo is not UTF-8".to_string())?;
    let mut mounts = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if index >= MAX_MOUNTINFO_LINES || line.len() > MAX_MOUNTINFO_LINE_BYTES {
            return Err("mountinfo exceeds work bound".to_string());
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let separator = fields
            .iter()
            .position(|field| *field == "-")
            .ok_or_else(|| "mountinfo record has no separator".to_string())?;
        if separator < 6 || fields.len() != separator + 4 {
            return Err("mountinfo record has invalid shape".to_string());
        }
        let mount_id = fields[0]
            .parse::<u64>()
            .map_err(|_| "invalid mount ID".to_string())?;
        if mounts
            .iter()
            .any(|mount: &RequiredMount| mount.mount_id == mount_id)
        {
            return Err("duplicate mount ID".to_string());
        }
        let parent_id = fields[1]
            .parse::<u64>()
            .map_err(|_| "invalid parent mount ID".to_string())?;
        let major_minor = fields[2];
        let Some((major, minor)) = major_minor.split_once(':') else {
            return Err("invalid mount major:minor".to_string());
        };
        if major.parse::<u64>().is_err() || minor.parse::<u64>().is_err() {
            return Err("invalid mount major:minor".to_string());
        }
        let root = decode_mountinfo_field(fields[3])?;
        let mount_point = decode_mountinfo_field(fields[4])?;
        let fs_type = decode_mountinfo_field(fields[separator + 1])?;
        let source = decode_mountinfo_field(fields[separator + 2])?;
        if !root.starts_with('/')
            || !mount_point.starts_with('/')
            || root.contains("/../")
            || root.contains("/./")
            || root.contains("//")
            || root.ends_with("/.")
            || root.ends_with("/..")
            || mount_point.contains("/../")
            || mount_point.contains("/./")
            || mount_point.ends_with("/.")
            || mount_point.ends_with("/..")
            || mount_point.contains("//")
        {
            // The uninstall mount resolver only needs the canonical block
            // mounts that carry `/system` and `/vendor`. Android mountinfo also
            // contains non-canonical namespace and sdcardfs entries (for example
            // nsfs mounts with a `net:[...]` root) that are irrelevant to the
            // fixed protected targets. Skipping them keeps the canonical check
            // strict for the mounts that matter while allowing honest AVD
            // mountinfo to parse. A required target that only resolves through
            // a skipped non-canonical mount still fails later with "no mount
            // contains fixed target".
            continue;
        }
        let mut security_flags = 0;
        for option in fields[5].split(',') {
            security_flags |= match option {
                "nosuid" => REMOUNT_NOSUID,
                "nodev" => REMOUNT_NODEV,
                "noexec" => REMOUNT_NOEXEC,
                _ => 0,
            };
        }
        let super_options = fields
            .get(separator + 3)
            .and_then(|field| decode_mountinfo_field(field).ok())
            .map(|options| {
                // Drop the mutable read/write markers: a scoped RW->RO
                // remount legitimately flips them between two observations of
                // the same boundary, so they must not participate in identity.
                options
                    .split(',')
                    .filter(|option| !matches!(*option, "rw" | "ro"))
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        mounts.push(RequiredMount {
            mount_id,
            parent_id,
            major_minor: major_minor.to_string(),
            root,
            mount_point,
            source,
            fs_type,
            security_flags,
            super_options,
        });
    }
    let mut required = Vec::new();
    for target in resolved_targets {
        if !target.starts_with('/') {
            return Err("fixed target did not resolve absolutely".to_string());
        }
        let longest = mounts
            .iter()
            .filter(|mount| path_is_within(target, &mount.mount_point))
            .map(|mount| mount.mount_point.len())
            .max()
            .ok_or_else(|| format!("no mount contains fixed target {target}"))?;
        let mut matches = mounts
            .iter()
            .filter(|mount| {
                mount.mount_point.len() == longest && path_is_within(target, &mount.mount_point)
            })
            .collect::<Vec<_>>();
        if matches.len() > 1 {
            // Same-length duplicates are only acceptable as a writable-system
            // overlayfs stack over the SAME mount point: path resolution only
            // sees the topmost mount, so it is the boundary (mirrors the
            // policy-transaction resolver).
            let same_point = matches
                .iter()
                .all(|mount| mount.mount_point == matches[0].mount_point);
            let topmost = matches
                .iter()
                .max_by_key(|mount| mount.mount_id)
                .ok_or_else(|| format!("ambiguous mount for fixed target {target}"))?;
            let physical_base = matches.iter().any(|mount| {
                mount.mount_id != topmost.mount_id
                    && mount.root == "/"
                    && matches!(mount.fs_type.as_str(), "ext4" | "f2fs")
                    && (mount.source == "/dev/root" || mount.source.starts_with("/dev/block/"))
            });
            let stack =
                same_point && matches.len() == 2 && topmost.fs_type == "overlay" && physical_base;
            if !stack {
                return Err(format!("ambiguous mount for fixed target {target}"));
            }
            matches = vec![topmost];
        }
        let mount = matches[0];
        if mount.root != "/" || mount.fs_type == "overlay" {
            // Writable-system boots (AVD/userdebug) stack an overlayfs at the
            // same mount point as (or above) the physical partition: path
            // resolution then only ever sees the overlay, so it is the
            // boundary the one-shot must remount. Admit that exact stack —
            // source "overlay", first lowerdir equal to the mount point
            // (self-stack), writable upper/work present — and require the
            // physical partition (root "/", ext4/f2fs, block source) to cover
            // the same target beneath it. Every other identity stays foreign.
            let lowerdir_first = mount
                .super_options
                .split(',')
                .find_map(|option| option.strip_prefix("lowerdir="))
                .and_then(|lowers| lowers.split(',').next());
            let physical_partition_covers = mounts.iter().any(|physical| {
                physical.mount_id != mount.mount_id
                    && physical.root == "/"
                    && matches!(physical.fs_type.as_str(), "ext4" | "f2fs")
                    && (physical.source == "/dev/root"
                        || physical.source.starts_with("/dev/block/"))
                    && path_is_within(target, &physical.mount_point)
            });
            let self_stack_overlay = mount.fs_type == "overlay"
                && mount.source == "overlay"
                && lowerdir_first == Some(mount.mount_point.as_str())
                && mount.super_options.contains("upperdir=")
                && mount.super_options.contains("workdir=")
                && physical_partition_covers;
            if mount.root != "/" || !self_stack_overlay {
                return Err(format!("foreign mount for fixed target {target}"));
            }
        } else if mount.root != "/"
            || !matches!(mount.fs_type.as_str(), "ext4" | "f2fs")
            || !(mount.source == "/dev/root" || mount.source.starts_with("/dev/block/"))
        {
            return Err(format!("foreign mount for fixed target {target}"));
        }
        if mounts.iter().any(|alias| {
            alias.mount_id != mount.mount_id
                && alias.major_minor == mount.major_minor
                && alias.root == mount.root
                && alias.fs_type == mount.fs_type
        }) {
            return Err("fixed target resolves through an ambiguous superblock alias".to_string());
        }
        if required.iter().any(|entry: &RequiredMount| {
            entry.mount_point != mount.mount_point
                && entry.major_minor == mount.major_minor
                && entry.root == mount.root
                && entry.fs_type == mount.fs_type
        }) {
            return Err(
                "required targets resolve through ambiguous superblock aliases".to_string(),
            );
        }
        if !required
            .iter()
            .any(|entry: &RequiredMount| entry.mount_id == mount.mount_id)
        {
            required.push(mount.clone());
        }
    }
    Ok(required)
}

pub(super) fn read_mountinfo_bounded() -> Result<Vec<u8>, String> {
    let file = File::open("/proc/self/mountinfo")
        .map_err(|error| format!("open fixed mountinfo: {error}"))?;
    let mut bytes = Vec::new();
    file.take((MAX_MOUNTINFO_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read fixed mountinfo: {error}"))?;
    if bytes.len() > MAX_MOUNTINFO_BYTES {
        return Err("mountinfo exceeds byte bound".to_string());
    }
    Ok(bytes)
}

#[cfg(test)]
pub(super) fn remount_required_with<F>(
    mounts: &[RequiredMount],
    mut remount: F,
) -> Result<(), String>
where
    F: FnMut(&RequiredMount) -> Result<(), String>,
{
    for mount in mounts {
        remount(mount)?;
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn remount_verified_with<R, F>(
    mounts: &[RequiredMount],
    resolved_targets: &[&str],
    mut read_mountinfo: R,
    mut remount: F,
) -> Result<(), String>
where
    R: FnMut() -> Result<Vec<u8>, String>,
    F: FnMut(&RequiredMount) -> Result<(), String>,
{
    remount_required_with(mounts, |boundary| {
        let current = resolve_required_mounts(&read_mountinfo()?, resolved_targets)?;
        if current != mounts {
            return Err("required mount identity changed before remount".to_string());
        }
        remount(boundary)
    })
}

#[cfg(test)]
pub(super) fn remount_fixed_verified_with<C, R, F>(
    mounts: &[RequiredMount],
    fixed_targets: &[&str],
    mut canonicalize: C,
    mut read_mountinfo: R,
    mut remount: F,
) -> Result<(), String>
where
    C: FnMut(&str) -> Result<String, String>,
    R: FnMut() -> Result<Vec<u8>, String>,
    F: FnMut(&RequiredMount) -> Result<(), String>,
{
    remount_required_with(mounts, |boundary| {
        let resolved = fixed_targets
            .iter()
            .map(|target| canonicalize(target))
            .collect::<Result<Vec<_>, _>>()?;
        let resolved = resolved.iter().map(String::as_str).collect::<Vec<_>>();
        let current = resolve_required_mounts(&read_mountinfo()?, &resolved)?;
        if current != mounts {
            return Err("fixed target mount topology changed before remount".to_string());
        }
        remount(boundary)
    })
}

pub(super) fn resolve_fixed_target(path: &str) -> Result<String, String> {
    let path = Path::new(path);
    let parent = path
        .parent()
        .ok_or_else(|| "fixed target has no parent".to_string())?;
    let leaf = path
        .file_name()
        .ok_or_else(|| "fixed target has no leaf".to_string())?;
    let parent = fs::canonicalize(parent)
        .map_err(|error| format!("resolve fixed target parent {}: {error}", parent.display()))?;
    let resolved = parent.join(leaf);
    resolved
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| "resolved fixed target is not UTF-8".to_string())
}

#[cfg(any(target_os = "android", target_os = "linux"))]
pub(super) fn remount_boundary(mount: &RequiredMount, read_only: bool) -> Result<(), String> {
    let native = remount_boundary_native_with(
        mount,
        read_only,
        |source, target, fs_type, flags, data| unsafe {
            libc::mount(source, target, fs_type, flags, data)
        },
    );
    {
        native.map_err(|error| error.to_string())
    }
}

#[cfg(test)]
pub(super) fn remount_boundary_with<F>(
    mount: &RequiredMount,
    read_only: bool,
    invoke: F,
) -> Result<(), String>
where
    F: FnOnce(
        *const libc::c_char,
        *const libc::c_char,
        *const libc::c_char,
        libc::c_ulong,
        *const libc::c_void,
    ) -> libc::c_int,
{
    remount_boundary_native_with(mount, read_only, invoke).map_err(|error| error.to_string())
}

#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
fn remount_boundary_native_with<F>(
    mount: &RequiredMount,
    read_only: bool,
    invoke: F,
) -> Result<(), NativeRemountError>
where
    F: FnOnce(
        *const libc::c_char,
        *const libc::c_char,
        *const libc::c_char,
        libc::c_ulong,
        *const libc::c_void,
    ) -> libc::c_int,
{
    let target =
        std::ffi::CString::new(mount.mount_point.as_str()).map_err(|_| NativeRemountError {
            message: "resolved mount point contains NUL".to_string(),
        })?;
    #[cfg(any(target_os = "android", target_os = "linux"))]
    let remount_flag = libc::MS_REMOUNT as u64;
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    let remount_flag = 32_u64;
    let mut flags = remount_flag | mount.security_flags;
    if read_only {
        flags |= 1; // Linux MS_RDONLY ABI value.
    }
    // Pass the recorded source and filesystem type to the kernel instead of
    // NULL. Linux honours `MS_REMOUNT` with NULL source/fs_type on most
    // filesystems, but Android's vendor ext4 boundary on the emulator returns
    // `EPERM` unless the original source device and `ext4` type are supplied.
    let source = std::ffi::CString::new(mount.source.as_str()).map_err(|_| NativeRemountError {
        message: "mount source contains NUL".to_string(),
    })?;
    let fs_type =
        std::ffi::CString::new(mount.fs_type.as_str()).map_err(|_| NativeRemountError {
            message: "mount fs_type contains NUL".to_string(),
        })?;
    let result = invoke(
        source.as_ptr(),
        target.as_ptr(),
        fs_type.as_ptr(),
        flags as libc::c_ulong,
        std::ptr::null(),
    );
    if result == 0 {
        // mount(2) can report success while the boundary stays read-only:
        // on Android 4.4/4.14 kernels MS_REMOUNT|MS_BIND is a silent no-op
        // for a locked boundary, and the rw form only works inside a boot
        // cycle that already opened the mount once (verified on the
        // free-09-chinese 6.0.3 emulator with a writability matrix). The
        // mutation would then die on EROFS far from the cause, so fail here
        // with the real mount state instead.
        if !read_only && boundary_is_read_only(&target) {
            return Err(NativeRemountError {
                message: format!(
                    "remount fixed boundary {} reported success but the mount is still read-only",
                    mount.mount_point
                ),
            });
        }
        return Ok(());
    }
    let os_error = std::io::Error::last_os_error();
    // The kernel ext4 driver logs a successful "re-mounted" while this call
    // still returns EACCES on the emulator, so capture the exact call shape
    // plus the live mount state to see which step actually refused.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        use std::io::Write as _;
        if let Ok(mut log) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/data/voboost/logs/remount-dbg.log")
        {
            let self_ctx = std::fs::read_to_string("/proc/self/attr/current")
                .unwrap_or_else(|_| "unreadable".to_string());
            let mounts = std::fs::read_to_string("/proc/self/mountinfo")
                .unwrap_or_else(|_| "unreadable".to_string());
            let boundary = mounts
                .lines()
                .filter(|line| line.split_whitespace().nth(4) == Some(mount.mount_point.as_str()))
                .collect::<Vec<_>>()
                .join(" | ");
            let _ = writeln!(
                log,
                "remount target={} source={} type={} flags={:#x} rc={} errno={} self={} boundary=[{}]",
                mount.mount_point,
                mount.source,
                mount.fs_type,
                flags,
                result,
                os_error.raw_os_error().unwrap_or(0),
                self_ctx.trim(),
                boundary
            );
        }
    }
    Err(NativeRemountError {
        message: format!("remount fixed boundary {}: {os_error}", mount.mount_point),
    })
}

#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
fn boundary_is_read_only(target: &std::ffi::CStr) -> bool {
    // Host builds (macOS/Windows test runs) have no Android boundary to
    // observe; only a positive RDONLY observation on the device is evidence
    // of a silent remount no-op.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        let mut stats: libc::statfs = unsafe { std::mem::zeroed() };
        return unsafe { libc::statfs(target.as_ptr(), &mut stats) } == 0
            && (stats.f_flags & libc::ST_RDONLY) != 0;
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = target;
        false
    }
}

/// Apply a protected mutation with the production scoped remount backend.
pub(super) fn scoped_remount_with<V, S, M>(
    mounts: &[RequiredMount],
    mut verify: V,
    mut set_read_only: S,
    mutation: M,
) -> Result<(), String>
where
    V: FnMut() -> Result<Vec<RequiredMount>, String>,
    S: FnMut(&RequiredMount, bool) -> Result<(), String>,
    M: FnOnce() -> Result<(), String>,
{
    let mut writable = Vec::new();
    let mut primary = None;
    for mount in mounts {
        match verify().and_then(|current| {
            if current == mounts {
                set_read_only(mount, false)
            } else {
                Err("fixed target mount topology changed before RW remount".to_string())
            }
        }) {
            Ok(()) => writable.push(mount),
            Err(error) => {
                primary = Some(error);
                break;
            }
        }
    }
    if primary.is_none() {
        primary = mutation().err();
    }
    let mut restore = Vec::new();
    for mount in writable.into_iter().rev() {
        let result = verify().and_then(|current| {
            if current.iter().any(|candidate| candidate == mount) {
                set_read_only(mount, true)
            } else {
                Err(format!(
                    "fixed target mount topology changed before RO remount of {}: current {current:?} journaled {mount:?}",
                    mount.mount_point
                ))
            }
        });
        if let Err(error) = result {
            restore.push(error);
        }
    }
    match (primary, restore.is_empty()) {
        (None, true) => Ok(()),
        (Some(error), true) => Err(error),
        (None, false) => Err(format!(
            "protected mutation succeeded; RO restore failed: {}",
            restore.join("; ")
        )),
        (Some(error), false) => Err(format!(
            "{error}; RO restore also failed: {}",
            restore.join("; ")
        )),
    }
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
pub(super) fn remount_boundary(_mount: &RequiredMount, _read_only: bool) -> Result<(), String> {
    Err("remount is supported only on Android/Linux".to_string())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum ProtectedMutationMount {
    SystemInitHook,
    VendorPolicy,
}

impl ProtectedMutationMount {
    pub(super) fn fixed_target(self) -> &'static str {
        match self {
            Self::SystemInitHook => RC_PATH,
            Self::VendorPolicy => PRECOMPILED_PATH,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RemountJournal {
    pub(super) schema_version: u32,
    pub(super) entries: Vec<RemountJournalEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RemountJournalEntry {
    pub(super) target: ProtectedMutationMount,
    pub(super) boundary: RequiredMount,
    #[serde(default)]
    pub(super) block_read_only: Option<bool>,
}

pub(super) fn remount_journal_for(
    target: ProtectedMutationMount,
    mounts: &[RequiredMount],
) -> Result<RemountJournal, String> {
    if mounts.len() != 1 {
        return Err("remount journal boundary count is invalid".to_string());
    }
    Ok(RemountJournal {
        schema_version: 2,
        entries: vec![RemountJournalEntry {
            target,
            boundary: mounts[0].clone(),
            block_read_only: None,
        }],
    })
}

pub(super) fn validate_remount_journal(journal: &RemountJournal) -> Result<(), String> {
    if !matches!(journal.schema_version, 1 | 2)
        || journal.entries.is_empty()
        || journal.entries.len() > 3
    {
        return Err("remount journal fields are invalid".to_string());
    }
    for (index, entry) in journal.entries.iter().enumerate() {
        if journal.entries[..index].iter().any(|prior| {
            prior.target == entry.target || prior.boundary.mount_id == entry.boundary.mount_id
        }) {
            return Err("remount journal contains duplicate authority".to_string());
        }
    }
    Ok(())
}

pub(super) fn publish_remount_journal(
    target: ProtectedMutationMount,
    mounts: &[RequiredMount],
) -> Result<RemountJournal, String> {
    let mut journal = remount_journal_for(target, mounts)?;
    for entry in &mut journal.entries {
        entry.block_read_only = block::capture(&entry.boundary)?;
    }
    let body = serde_json::to_vec(&journal)
        .map_err(|error| format!("serialize remount journal: {error}"))?;
    if body.is_empty() || body.len() as u64 > MAX_REMOUNT_JOURNAL_BYTES {
        return Err("serialized remount journal is oversized".to_string());
    }
    let target = Path::new(remount_journal_path());
    if path_entry_exists(target)? {
        return Err("pending remount journal requires recovery".to_string());
    }
    let temporary = Path::new(remount_journal_temp_path());
    clear_stale_temp(
        temporary,
        MAX_REMOUNT_JOURNAL_BYTES,
        &[0o600],
        &[DATA_CONTEXT, STOCK_DATA_CONTEXT],
    )?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(temporary)
        .map_err(|error| format!("create remount journal: {error}"))?;
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(
            target
                .parent()
                .ok_or_else(|| "remount journal has no parent".to_string())?,
        )
        .map_err(|error| format!("open remount journal parent: {error}"))?;
    let journal_context = file_selinux_context(&parent)?;
    if journal_context != DATA_CONTEXT
        && journal_context != STOCK_DATA_CONTEXT
        && journal_context != RECOVERY_TREE_CONTEXT
    {
        return Err("remount journal parent has a foreign SELinux context".to_string());
    }
    file.write_all(&body)
        .map_err(|error| format!("write remount journal: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("fsync remount journal: {error}"))?;
    set_file_selinux_context(&file, &journal_context)?;
    file.sync_all()
        .map_err(|error| format!("fsync remount journal metadata: {error}"))?;
    fs::rename(temporary, target).map_err(|error| format!("publish remount journal: {error}"))?;
    fsync_parent(target)?;
    Ok(journal)
}

pub(super) fn load_remount_journal() -> Result<RemountJournal, String> {
    let trusted =
        read_regular_nofollow(Path::new(remount_journal_path()), MAX_REMOUNT_JOURNAL_BYTES)?;
    require_root_file(trusted.stamp, 0o600, "remount journal")?;
    let context = trusted.selinux_context.as_deref();
    if context != Some(DATA_CONTEXT)
        && context != Some(STOCK_DATA_CONTEXT)
        && context != Some(RECOVERY_TREE_CONTEXT)
    {
        return Err("remount journal has a foreign SELinux context".to_string());
    }
    let journal: RemountJournal = serde_json::from_slice(&trusted.bytes)
        .map_err(|error| format!("parse remount journal: {error}"))?;
    validate_remount_journal(&journal)?;
    Ok(journal)
}

pub(super) fn recover_pending_remounts() -> Result<(), String> {
    if !path_entry_exists(Path::new(remount_journal_path()))? {
        return Ok(());
    }
    let journal = load_remount_journal()?;
    recover_journaled_boundaries_with(
        &journal.entries,
        |entry| {
            let resolved_target = resolve_fixed_target(entry.target.fixed_target())?;
            resolve_required_mounts(&read_mountinfo_bounded()?, &[resolved_target.as_str()])
        },
        |mount, ro| {
            let entry = journal
                .entries
                .iter()
                .find(|entry| entry.boundary == *mount)
                .ok_or("block protection recovery lost its journaled boundary")?;
            block::remount(mount, ro, entry.block_read_only)
        },
    )?;
    fs::remove_file(remount_journal_path())
        .map_err(|error| format!("remove remount journal: {error}"))?;
    fsync_parent(Path::new(remount_journal_path()))
}

pub(super) fn recover_journaled_boundaries_with<R, S>(
    entries: &[RemountJournalEntry],
    mut resolve: R,
    mut set_read_only: S,
) -> Result<(), String>
where
    R: FnMut(&RemountJournalEntry) -> Result<Vec<RequiredMount>, String>,
    S: FnMut(&RequiredMount, bool) -> Result<(), String>,
{
    let mut errors = Vec::new();
    for entry in entries.iter().rev() {
        let boundary = &entry.boundary;
        let result = (|| {
            let current = resolve(entry)?;
            if current.len() != 1 || current[0] != *boundary {
                return Err(format!(
                    "journaled boundary {} changed before RO recovery: current {current:?} journaled {boundary:?}",
                    boundary.mount_point
                ));
            }
            set_read_only(boundary, true)
        })();
        if let Err(error) = result {
            errors.push(error);
        }
    }
    if !errors.is_empty() {
        return Err(format!("pending RO recovery failed: {}", errors.join("; ")));
    }
    Ok(())
}

pub(super) fn with_protected_mounts_rw<F>(
    target_set: ProtectedMutationMount,
    mutation: F,
) -> Result<(), String>
where
    F: FnOnce() -> Result<(), String>,
{
    let fixed_targets = [target_set.fixed_target()];
    let resolved = fixed_targets
        .iter()
        .map(|target| resolve_fixed_target(target))
        .collect::<Result<Vec<_>, _>>()?;
    let resolved_refs = resolved.iter().map(String::as_str).collect::<Vec<_>>();
    let mountinfo = read_mountinfo_bounded()?;
    let mounts = resolve_required_mounts(&mountinfo, &resolved_refs)?;
    let journal = publish_remount_journal(target_set, &mounts)?;
    let mutation_result = scoped_remount_with(
        &mounts,
        || {
            let resolved = fixed_targets
                .iter()
                .map(|target| resolve_fixed_target(target))
                .collect::<Result<Vec<_>, _>>()?;
            let refs = resolved.iter().map(String::as_str).collect::<Vec<_>>();
            resolve_required_mounts(&read_mountinfo_bounded()?, &refs)
        },
        |mount, ro| {
            let entry = journal
                .entries
                .iter()
                .find(|entry| entry.boundary == *mount)
                .ok_or("block protection lost its journaled boundary")?;
            block::remount(mount, ro, entry.block_read_only)
        },
        mutation,
    );
    let recovery_result = recover_pending_remounts();
    match (mutation_result, recovery_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(recovery)) => Err(recovery),
        (Err(error), Err(recovery)) => Err(format!("{error}; {recovery}")),
    }
}
