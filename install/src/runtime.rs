use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::contract::InstallDescriptor;

const ROOT: &str = "/data/voboost";
const GENERATIONS: &str = "/data/voboost/generations";
const INCOMING: &str = "/data/voboost/generations/next";
const ANDROID_ROOT_FILES: [&str; 11] = [
    "voboost-daemon",
    "voboost-inject",
    "voboost-install",
    "voboost-restore",
    "voboost-uninstall",
    "voboost-selinux",
    "voboost.rc",
    "restore.json",
    "restore.json.sig",
    "libimplant-arm64-v8a.so",
    "libimplant-armeabi-v7a.so",
];
const QNX_ROOT_FILES: [&str; 3] = [
    "voboost-cluster-daemon",
    "voboost-cluster-startup.sh",
    "libvoboost-cluster-inject.so",
];

fn open_directory(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)
        .map_err(|error| format!("open directory {}: {error}", path.display()))
}

fn same_named_directory(path: &Path, file: &File) -> Result<std::fs::Metadata, String> {
    let opened = file
        .metadata()
        .map_err(|error| format!("stat opened directory {}: {error}", path.display()))?;
    let named = fs::symlink_metadata(path)
        .map_err(|error| format!("stat named directory {}: {error}", path.display()))?;
    if !opened.is_dir()
        || !named.is_dir()
        || named.file_type().is_symlink()
        || (opened.dev(), opened.ino()) != (named.dev(), named.ino())
    {
        return Err(format!("directory identity changed: {}", path.display()));
    }
    Ok(opened)
}

fn ensure_directory(
    path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
    require_empty: bool,
) -> Result<(), String> {
    let created = match fs::symlink_metadata(path) {
        Ok(_) => false,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path)
                .map_err(|error| format!("create directory {}: {error}", path.display()))?;
            true
        }
        Err(error) => return Err(format!("inspect directory {}: {error}", path.display())),
    };
    let file = open_directory(path)?;
    if created {
        let result = unsafe { libc::fchown(file.as_raw_fd(), uid, gid) };
        if result != 0 {
            return Err(format!(
                "set directory owner {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        let result = unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) };
        if result != 0 {
            return Err(format!(
                "set directory mode {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
    }
    file.sync_all()
        .map_err(|error| format!("sync directory {}: {error}", path.display()))?;
    let metadata = same_named_directory(path, &file)?;
    if metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.permissions().mode() & 0o7777 != mode
        || metadata.nlink() < 2
    {
        return Err(format!("directory authority differs: {}", path.display()));
    }
    if require_empty
        && fs::read_dir(path)
            .map_err(|error| format!("read directory {}: {error}", path.display()))?
            .next()
            .is_some()
    {
        return Err(format!("directory is not empty: {}", path.display()));
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("directory has no parent: {}", path.display()))?;
    open_directory(parent)?
        .sync_all()
        .map_err(|error| format!("sync directory parent {}: {error}", parent.display()))
}

fn parse_package_uid(output: &crate::fixed_process::BoundedOutput) -> Result<Option<u32>, String> {
    if !output.status.success() || !output.stderr.is_empty() {
        return Err("installed application UID query failed".to_string());
    }
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| "installed application UID is not UTF-8")?;
    if !text.is_empty() && !text.ends_with('\n') {
        return Err("installed application UID output is incomplete".to_string());
    }
    let mut selected = None;
    for line in text.lines() {
        let (package, value) = line
            .strip_prefix("package:")
            .and_then(|line| line.split_once(" uid:"))
            .ok_or("installed application UID output is ambiguous")?;
        if package != "ru.voboost" {
            continue;
        }
        if selected.is_some() {
            return Err("installed application UID output contains duplicate package".to_string());
        }
        if value.is_empty()
            || value.starts_with('0')
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err("installed application UID is non-canonical".to_string());
        }
        let uid = value
            .parse::<u32>()
            .ok()
            .filter(|uid| (10_000..=19_999).contains(uid))
            .ok_or_else(|| "installed application UID is outside user-0 app range".to_string())?;
        selected = Some(uid);
    }
    Ok(selected)
}

fn wait_app_identity(
    timeout: Duration,
    interval: Duration,
    mut probe: impl FnMut(Duration) -> Result<Option<u32>, String>,
) -> Result<(u32, u32), String> {
    let start = std::time::Instant::now();
    loop {
        let remaining = timeout.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            return Err(
                "installed application identity is not ready before cleanup deadline".to_string(),
            );
        }
        if let Some(uid) = probe(remaining)? {
            return Ok((uid, uid));
        }
        std::thread::sleep(interval.min(timeout.saturating_sub(start.elapsed())));
    }
}

fn app_identity() -> Result<(u32, u32), String> {
    wait_app_identity(
        Duration::from_secs(90),
        Duration::from_secs(1),
        |remaining| {
            // PackageManager can still be starting after reboot, or inaccessible
            // from this OEM domain. installd directory ownership is the fallback.
            let pm = crate::fixed_process::output(
                "/system/bin/pm",
                &["list", "packages", "-U", "--user", "0", "ru.voboost"],
                remaining.min(Duration::from_secs(10)),
                4096,
            );
            probe_app_identity(pm, Path::new("/data/data/ru.voboost"))
        },
    )
}

fn probe_app_identity(
    pm: Result<crate::fixed_process::BoundedOutput, String>,
    path: &Path,
) -> Result<Option<u32>, String> {
    if let Ok(output) = pm {
        if output.status.success() && output.stderr.is_empty() && !output.stdout.is_empty() {
            if let Some(uid) = parse_package_uid(&output)? {
                return Ok(Some(uid));
            }
        }
    }
    app_data_uid(path)
}

/// installd creates the user-0 directory with the application UID and GID.
/// Absence is a boot readiness condition; an unsafe existing node is not.
fn app_data_uid(path: &Path) -> Result<Option<u32>, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "inspect installed application data directory: {error}"
            ));
        }
    };
    if !metadata.is_dir()
        || !(10_000..=19_999).contains(&metadata.uid())
        || metadata.gid() != metadata.uid()
        || metadata.mode() & 0o022 != 0
    {
        return Err("installed application data directory authority is invalid".to_string());
    }
    Ok(Some(metadata.uid()))
}

/// Terminal install cleanup hands the fixed incoming staging directory from
/// the consumed install window to the installed application, so the first OTA
/// stages through the normal app-owned path (daemon/src/generation.rs requires
/// an application-owned staging whenever no install transaction is active).
/// The directory must already exist in one of exactly two states: app-owned
/// 0700 (idempotent re-run of a crashed terminal cleanup) or the consumed
/// install-window state the daemon restores after importing — root-owned 0700
/// holding the flat staging residue (imported payload plus the daemon-authored
/// acknowledgement; every member a root-owned exclusive regular file, as the
/// daemon and the app's flat staging contract produce). The application reads
/// the acknowledgement or unlinks the residue in its own directory before
/// restaging; ownership of the files stays root, only the directory transfers.
/// Any other identity is refused rather than taken over.
pub fn prepare_agent_incoming() -> Result<(), String> {
    let (uid, gid) = app_identity()?;
    ensure_directory(Path::new(GENERATIONS), 0, 0, 0o711, false)?;
    let file = open_directory(Path::new(INCOMING))?;
    let metadata = same_named_directory(Path::new(INCOMING), &file)?;
    if metadata.uid() == 0 && metadata.gid() == 0 {
        if metadata.permissions().mode() & 0o7777 != 0o700 {
            return Err(format!(
                "consumed staging directory is not root-owned 0700: {INCOMING}"
            ));
        }
        for entry in fs::read_dir(Path::new(INCOMING))
            .map_err(|error| format!("read staging directory {INCOMING}: {error}"))?
        {
            let entry = entry.map_err(|error| format!("scan staging directory: {error}"))?;
            let name = std::ffi::CString::new(entry.file_name().into_encoded_bytes())
                .map_err(|_| "staging member name is not a C string".to_string())?;
            let mut before: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::fstatat(
                    file.as_raw_fd(),
                    name.as_ptr(),
                    &mut before,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(format!(
                    "stat staging member {}: {}",
                    INCOMING,
                    std::io::Error::last_os_error()
                ));
            }
            // The consumed staging residue is flat: the generation contract has
            // no subdirectories, and links or special nodes never survive the
            // daemon's claimed-import walk. Members stay root-owned and never
            // group/other-writable, so the takeover grants no new authority.
            let mode = before.st_mode as u32;
            if !((mode & libc::S_IFMT as u32) == libc::S_IFREG as u32)
                || before.st_uid != 0
                || before.st_gid != 0
                || mode & (libc::S_IWGRP | libc::S_IWOTH) as u32 != 0
                || before.st_nlink != 1
            {
                return Err(format!(
                    "consumed staging member is not an exclusive root-owned file: {}",
                    entry.file_name().to_string_lossy()
                ));
            }
        }
        file.sync_all()
            .map_err(|error| format!("sync staging directory {INCOMING}: {error}"))?;
        if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
            return Err(format!(
                "claim staging directory {INCOMING}: {}",
                std::io::Error::last_os_error()
            ));
        }
        file.sync_all()
            .map_err(|error| format!("sync staging directory {INCOMING}: {error}"))?;
    }
    ensure_directory(Path::new(INCOMING), uid, gid, 0o700, false)
}

fn verified_apk_input(path: &Path, size: u64, expected: &str) -> Result<File, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("open APK stream: {error}"))?;
    let before = file.metadata().map_err(|error| error.to_string())?;
    if !before.is_file()
        || before.nlink() != 1
        || before.len() != size
        || before.mode() & 0o7777 != 0o600
        || before.uid() != unsafe { libc::geteuid() }
    {
        return Err("APK stream identity differs".into());
    }
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let read = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    if format!("{:x}", hash.finalize()) != expected {
        return Err("APK stream digest differs".into());
    }
    let named = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !named.is_file()
        || named.file_type().is_symlink()
        || (named.dev(), named.ino(), named.len()) != (before.dev(), before.ino(), before.len())
    {
        return Err("APK stream path changed".into());
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    Ok(file)
}

pub fn apply_app(staging: &Path, descriptor: &InstallDescriptor) -> Result<(), String> {
    let apk = descriptor
        .artifacts
        .iter()
        .find(|artifact| artifact.file == "voboost-app.apk")
        .ok_or_else(|| "product manifest lacks voboost-app.apk".to_string())?;
    let apk_path = staging.join("voboost-app.apk");
    let input = verified_apk_input(&apk_path, apk.size, &apk.sha256)?;
    let size = apk.size.to_string();
    let result = crate::fixed_process::output_with_input(
        "/system/bin/pm",
        &["install", "-S", &size],
        Some(input),
        Duration::from_secs(120),
        4096,
    )?;
    let status = result.status.success();
    if !status
        && observe_installed_apk(
            apk.size,
            &apk.sha256,
            descriptor.apk_version_code()?,
            descriptor.apk_certificate_sha256()?,
        )
        .is_err()
    {
        let detail = String::from_utf8_lossy(&result.stderr);
        let detail = if detail.trim().is_empty() {
            String::from_utf8_lossy(&result.stdout)
        } else {
            detail
        };
        let detail: String = detail
            .chars()
            .filter(|c| !c.is_control())
            .take(320)
            .collect();
        return Err(format!("application install failed: {detail}"));
    }
    let status = crate::fixed_process::status(
        "/system/bin/appops",
        &["set", "ru.voboost", "REQUEST_INSTALL_PACKAGES", "allow"],
        Duration::from_secs(10),
    )?;
    if !status {
        return Err("install app-op grant failed".to_string());
    }
    let first = observe_installed_apk(
        apk.size,
        &apk.sha256,
        descriptor.apk_version_code()?,
        descriptor.apk_certificate_sha256()?,
    )?;
    let second = observe_installed_apk(
        apk.size,
        &apk.sha256,
        descriptor.apk_version_code()?,
        descriptor.apk_certificate_sha256()?,
    )?;
    if first != second {
        return Err("installed application changed while preparing agent staging".to_string());
    }
    Ok(())
}

pub fn observe_installed_apk(
    expected_size: u64,
    expected_sha256: &str,
    expected_version_code: u64,
    expected_certificate_sha256: &str,
) -> Result<serde_json::Value, String> {
    let path = crate::installed_apk::observe_installed_apk(expected_size, expected_sha256)?;
    Ok(serde_json::json!({
        "packageName":"ru.voboost",
        "versionCode":expected_version_code,
        "certificateSha256":expected_certificate_sha256,
        "path":path,
        "size":expected_size,
        "sha256":expected_sha256
    }))
}
pub fn apply_native(staging: &Path, descriptor: &InstallDescriptor) -> Result<(), String> {
    for relative in ANDROID_ROOT_FILES {
        let source = staging.join(relative);
        let target = Path::new(ROOT).join(relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let mode = live_mode(relative);
        let bytes = read_descriptor_artifact(&source, relative, 0o600, descriptor)?;
        if relative == "voboost-install" {
            let running = crate::self_executable::read_self_executable(
                &target,
                crate::MAX_SELF_BYTES,
                0o700,
                0,
                0,
            )?;
            if bytes != running
                || !crate::appended_signature_valid(
                    &running,
                    &crate::NATIVE_EXECUTABLE_PUBLIC_KEY,
                    crate::native_executable_signature::NativeExecutableRole::Install,
                )
            {
                return Err("running installer differs from signed staged identity".to_string());
            }
            continue;
        }
        if relative == "voboost-selinux" {
            publish_stock_executable(&target, &bytes, Path::new("/data/local/tmp"))?;
        } else {
            publish_atomic(&target, &bytes, mode)?;
        }
    }
    publish_qnx(staging, descriptor, Path::new(ROOT))?;
    for (name, maximum) in [
        (
            voboost_contract::release::MANIFEST_NAME,
            voboost_contract::release::MAX_MANIFEST_BYTES,
        ),
        (voboost_contract::release::MANIFEST_SIGNATURE_NAME, 64),
    ] {
        let bytes = crate::read_bounded(&staging.join(name), maximum, 0o600)?;
        publish_atomic(&Path::new(ROOT).join(name), &bytes, 0o600)?;
    }
    // Persist static hardware facts before init can start the normal daemon.
    voboost_shared::vehicle_profile::recompute_vehicle_profile(Path::new(ROOT))
        .map_err(|error| format!("prepare installed vehicle facts: {error:#}"))?;
    let rc =
        read_descriptor_artifact(&staging.join("voboost.rc"), "voboost.rc", 0o600, descriptor)?;
    publish_atomic(Path::new("/system/etc/init/voboost.rc"), &rc, 0o644)?;
    Ok(())
}

fn publish_qnx(staging: &Path, descriptor: &InstallDescriptor, root: &Path) -> Result<(), String> {
    for name in QNX_ROOT_FILES {
        let bytes = read_descriptor_artifact(&staging.join(name), name, 0o600, descriptor)?;
        let target = root.join(name);
        publish_atomic(&target, &bytes, live_mode(name))?;
        if read_descriptor_artifact(&target, name, live_mode(name), descriptor)? != bytes {
            return Err("QNX relay publication differs".into());
        }
    }
    Ok(())
}

pub(crate) fn prepare_boot_execution_labels(
    staging: &Path,
    descriptor: &InstallDescriptor,
) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        if fs::read("/sys/fs/selinux/enforce").map_err(|error| error.to_string())? != b"0" {
            return Err("bootstrap label handoff requires the initial provisioning window".into());
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(ROOT)
            .map_err(|error| error.to_string())?;
        let mut context = [0u8; 128];
        let length = unsafe {
            libc::fgetxattr(
                directory.as_raw_fd(),
                c"security.selinux".as_ptr(),
                context.as_mut_ptr().cast(),
                context.len(),
            )
        };
        if length <= 0 || length as usize > context.len() {
            return Err("bootstrap root context is unavailable".into());
        }
        let value = &context[..length as usize];
        let label = value.strip_suffix(&[0]).unwrap_or(value);
        if !matches!(
            label,
            b"u:object_r:system_data_file:s0" | b"u:object_r:system_data_root_file:s0"
        ) {
            return Err("bootstrap root has no supported init entry context".into());
        }
        for name in ["voboost-install", "voboost-selinux"] {
            let expected = read_descriptor_artifact(&staging.join(name), name, 0o600, descriptor)?;
            let path = Path::new(ROOT).join(name);
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&path)
                .map_err(|error| error.to_string())?;
            let meta = file.metadata().map_err(|error| error.to_string())?;
            if !meta.is_file()
                || meta.nlink() != 1
                || meta.uid() != 0
                || meta.gid() != 0
                || meta.mode() & 0o7777 != 0o700
            {
                return Err("bootstrap program identity changed before init handoff".into());
            }
            let mut actual = Vec::new();
            Read::by_ref(&mut file)
                .take(expected.len() as u64 + 1)
                .read_to_end(&mut actual)
                .map_err(|error| error.to_string())?;
            if actual != expected {
                return Err("bootstrap program differs from signed frozen identity".into());
            }
            if unsafe {
                libc::fsetxattr(
                    file.as_raw_fd(),
                    c"security.selinux".as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            } != 0
            {
                return Err(format!(
                    "handoff bootstrap label: {}",
                    std::io::Error::last_os_error()
                ));
            }
            file.sync_all().map_err(|error| error.to_string())?;
            let named = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
            if named.file_type().is_symlink()
                || (named.dev(), named.ino()) != (meta.dev(), meta.ino())
            {
                return Err("bootstrap program was substituted during init handoff".into());
            }
        }
    }
    #[cfg(not(target_os = "android"))]
    let _ = (staging, descriptor);
    Ok(())
}

struct StockTemporary {
    path: PathBuf,
    directory: File,
}

impl Drop for StockTemporary {
    fn drop(&mut self) {
        unsafe {
            libc::unlinkat(self.directory.as_raw_fd(), c"program".as_ptr(), 0);
        }
        if same_named_directory(&self.path, &self.directory).is_ok() {
            let _ = fs::remove_dir(&self.path);
        }
    }
}

fn publish_stock_executable(target: &Path, bytes: &[u8], stock: &Path) -> Result<(), String> {
    publish_stock_executable_checked(target, bytes, stock, verify_stock_execution_label)
}

fn publish_stock_executable_checked(
    target: &Path,
    bytes: &[u8],
    stock: &Path,
    verify_label: impl FnOnce(&File) -> Result<(), String>,
) -> Result<(), String> {
    let stock_directory = open_directory(stock)?;
    same_named_directory(stock, &stock_directory)?;
    let parent = target.parent().ok_or("stock executable has no parent")?;
    let target_directory = open_directory(parent)?;
    let leaf = std::ffi::CString::new(
        target
            .file_name()
            .ok_or("stock executable has no name")?
            .as_encoded_bytes(),
    )
    .map_err(|_| "invalid stock executable name")?;
    let mut template = std::ffi::CString::new(
        stock
            .join("voboost-native.XXXXXX")
            .as_os_str()
            .as_encoded_bytes(),
    )
    .map_err(|_| "invalid stock temporary path")?
    .into_bytes_with_nul();
    if unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) }.is_null() {
        return Err(format!(
            "create stock temporary: {}",
            std::io::Error::last_os_error()
        ));
    }
    template.pop();
    use std::os::unix::ffi::OsStringExt;
    let temporary_path = PathBuf::from(std::ffi::OsString::from_vec(template));
    let temporary = StockTemporary {
        directory: open_directory(&temporary_path)?,
        path: temporary_path,
    };
    same_named_directory(stock, &stock_directory)?;
    let metadata = same_named_directory(&temporary.path, &temporary.directory)?;
    if metadata.permissions().mode() & 0o7777 != 0o700
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.dev()
            != target_directory
                .metadata()
                .map_err(|e| e.to_string())?
                .dev()
    {
        return Err("stock temporary authority or filesystem differs".into());
    }
    let fd = unsafe {
        libc::openat(
            temporary.directory.as_raw_fd(),
            c"program".as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(format!(
            "create stock executable: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| e.to_string())?;
    if unsafe { libc::fchmod(fd, 0o700) } != 0 {
        return Err("set stock executable mode failed".into());
    }
    verify_label(&file)?;
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut observed = Vec::new();
    Read::by_ref(&mut file)
        .take(bytes.len() as u64 + 1)
        .read_to_end(&mut observed)
        .map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if observed != bytes
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o700
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.gid() != unsafe { libc::getegid() }
    {
        return Err("stock executable bytes or authority changed".into());
    }
    same_named_directory(parent, &target_directory)?;
    if let Ok(existing) = fs::symlink_metadata(target) {
        if !existing.is_file() || existing.file_type().is_symlink() || existing.nlink() != 1 {
            return Err("unsafe stock executable destination".into());
        }
    }
    if unsafe {
        libc::renameat(
            temporary.directory.as_raw_fd(),
            c"program".as_ptr(),
            target_directory.as_raw_fd(),
            leaf.as_ptr(),
        )
    } != 0
    {
        return Err(format!(
            "publish stock executable: {}",
            std::io::Error::last_os_error()
        ));
    }
    file.sync_all()
        .and_then(|()| target_directory.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn verify_stock_execution_label(file: &File) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        let mut context = [0u8; 128];
        let length = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                c"security.selinux".as_ptr(),
                context.as_mut_ptr().cast(),
                context.len(),
            )
        };
        if length <= 0
            || length as usize > context.len()
            || context[..length as usize]
                .strip_suffix(&[0])
                .unwrap_or(&context[..length as usize])
                != b"u:object_r:shell_data_file:s0"
        {
            return Err("initial SELinux helper has no stock shell execution label".into());
        }
    }
    #[cfg(not(target_os = "android"))]
    let _ = file;
    Ok(())
}

fn publish_atomic(target: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let parent = target
        .parent()
        .ok_or_else(|| "live target has no parent".to_string())?;
    let leaf = target
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or_else(|| "live target leaf is not UTF-8".to_string())?;
    let temporary = parent.join(format!(".{leaf}.install.tmp"));
    if let Ok(metadata) = fs::symlink_metadata(&temporary) {
        if !metadata.file_type().is_file() || metadata.nlink() != 1 {
            return Err(format!("unsafe live temporary {}", temporary.display()));
        }
        fs::remove_file(&temporary).map_err(|error| error.to_string())?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|error| format!("create live temporary: {error}"))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("sync live temporary: {error}"))?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))
        .map_err(|error| error.to_string())?;
    if crate::read_bounded(&temporary, bytes.len(), mode)? != bytes {
        return Err("live temporary verification failed".to_string());
    }
    fs::rename(&temporary, target).map_err(|error| format!("publish live target: {error}"))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync live parent: {error}"))
}

pub fn verify_native_release(descriptor: &InstallDescriptor) -> Result<(), String> {
    let root = Path::new(ROOT);
    let manifest = crate::read_bounded(
        &root.join(voboost_contract::release::MANIFEST_NAME),
        voboost_contract::release::MAX_MANIFEST_BYTES,
        0o600,
    )?;
    let signature = crate::read_bounded(
        &root.join(voboost_contract::release::MANIFEST_SIGNATURE_NAME),
        64,
        0o600,
    )?;
    let live = voboost_contract::release::verify_manifest_signature(
        &manifest,
        &signature,
        &crate::RELEASE_CATALOG_PUBLIC_KEY,
    )?;
    if &live != descriptor {
        return Err("committed product manifest differs from install authority".into());
    }
    for artifact in descriptor.artifacts.iter().filter(|artifact| {
        artifact.role == voboost_contract::release::ArtifactRole::QnxInit
            || matches!(
                artifact.activation,
                voboost_contract::release::Activation::NativeRuntime
                    | voboost_contract::release::Activation::RestoreAuthority
            )
    }) {
        read_descriptor_artifact(
            &root.join(&artifact.file),
            &artifact.file,
            live_mode(&artifact.file),
            descriptor,
        )?;
    }
    Ok(())
}
pub fn verify_committed(staging: &Path, descriptor: &InstallDescriptor) -> Result<(), String> {
    verify_committed_at(staging, Path::new(ROOT), descriptor)
}
fn verify_committed_at(
    staging: &Path,
    root: &Path,
    descriptor: &InstallDescriptor,
) -> Result<(), String> {
    verify_pairs(staging, root, &ANDROID_ROOT_FILES, descriptor)?;
    verify_pairs(staging, root, &QNX_ROOT_FILES, descriptor)
}
fn verify_pairs(
    staging: &Path,
    root: &Path,
    paths: &[&str],
    descriptor: &InstallDescriptor,
) -> Result<(), String> {
    for relative in paths {
        let expected =
            read_descriptor_artifact(&staging.join(relative), relative, 0o600, descriptor)?;
        let actual = read_descriptor_artifact(
            &root.join(relative),
            relative,
            live_mode(relative),
            descriptor,
        )?;
        if expected != actual {
            return Err(format!("committed {relative} differs"));
        }
    }
    Ok(())
}

pub(crate) fn read_descriptor_artifact(
    path: &Path,
    relative: &str,
    mode: u32,
    descriptor: &InstallDescriptor,
) -> Result<Vec<u8>, String> {
    let artifact = descriptor
        .artifacts
        .iter()
        .find(|artifact| artifact.file == relative)
        .ok_or_else(|| format!("product manifest lacks {relative}"))?;
    let maximum = usize::try_from(artifact.size)
        .map_err(|_| format!("install artifact {relative} size overflows host"))?;
    let bytes = crate::read_bounded(path, maximum, mode)?;
    if bytes.len() as u64 != artifact.size
        || format!("{:x}", Sha256::digest(&bytes)) != artifact.sha256
    {
        return Err(format!(
            "install artifact {relative} differs from product manifest"
        ));
    }
    Ok(bytes)
}

pub(crate) fn live_mode(relative: &str) -> u32 {
    if matches!(relative, "voboost.json" | "voboost.json.sig") {
        0o600
    } else if relative.starts_with("voboost-")
        && !relative.ends_with(".json")
        && !relative.ends_with(".sig")
    {
        0o700
    } else {
        0o644
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn committed_android_inventory_rejects_missing_or_changed_inject() {
        let temp = tempfile::tempdir().unwrap();
        let staging = temp.path().join("staging");
        let root = temp.path().join("root");
        fs::create_dir(&staging).unwrap();
        fs::create_dir(&root).unwrap();
        let mut descriptor = InstallDescriptor::parse(include_bytes!(
            "../../test/fixtures/product-release/voboost/valid/minimal.json"
        ))
        .unwrap();
        for name in ANDROID_ROOT_FILES.into_iter().chain(QNX_ROOT_FILES) {
            let bytes = format!("verified product payload: {name}").into_bytes();
            let item = descriptor
                .artifacts
                .iter_mut()
                .find(|a| a.file == name)
                .unwrap();
            item.size = bytes.len() as u64;
            item.sha256 = format!("{:x}", Sha256::digest(&bytes));
            for (directory, mode) in [(&staging, 0o600), (&root, live_mode(name))] {
                let path = directory.join(name);
                fs::write(&path, &bytes).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
            }
        }
        verify_committed_at(&staging, &root, &descriptor).unwrap();
        let inject = root.join("voboost-inject");
        let original = fs::read(&inject).unwrap();
        fs::remove_file(&inject).unwrap();
        assert!(verify_committed_at(&staging, &root, &descriptor).is_err());
        fs::write(&inject, &original).unwrap();
        fs::set_permissions(&inject, fs::Permissions::from_mode(0o700)).unwrap();
        let mut changed = original;
        changed[0] ^= 1;
        fs::write(&inject, changed).unwrap();
        assert!(verify_committed_at(&staging, &root, &descriptor).is_err());
    }

    #[test]
    fn qnx_relay_publication_retains_exact_bytes_modes_and_generation_separation() {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../build/install-tests");
        fs::create_dir_all(&base).unwrap();
        let temp = tempfile::tempdir_in(base).unwrap();
        let staging = temp.path().join("staging");
        let root = temp.path().join("root");
        fs::create_dir(&staging).unwrap();
        fs::create_dir(&root).unwrap();
        let mut descriptor = InstallDescriptor::parse(include_bytes!(
            "../../test/fixtures/product-release/voboost/valid/minimal.json"
        ))
        .unwrap();
        for name in QNX_ROOT_FILES {
            let bytes = format!("exact signed product payload: {name}").into_bytes();
            let item = descriptor
                .artifacts
                .iter_mut()
                .find(|a| a.file == name)
                .unwrap();
            item.size = bytes.len() as u64;
            item.sha256 = format!("{:x}", Sha256::digest(&bytes));
            let path = staging.join(name);
            fs::write(&path, &bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        publish_qnx(&staging, &descriptor, &root).unwrap();
        for name in QNX_ROOT_FILES {
            assert_eq!(
                fs::read(staging.join(name)).unwrap(),
                fs::read(root.join(name)).unwrap()
            );
            assert_eq!(
                fs::metadata(root.join(name)).unwrap().mode() & 0o7777,
                live_mode(name)
            );
        }
        assert!(!root.join("libvoboost-runtime-cluster.so").exists());
        assert!(!root.join("libagent-font-cyrillic.so").exists());
        let path = staging.join("voboost-cluster-daemon");
        fs::write(&path, b"tampered").unwrap();
        assert!(publish_qnx(&staging, &descriptor, &root).is_err());
    }

    #[test]
    fn stock_executable_publication_retains_the_verified_inode_and_cleans_its_temporary() {
        let root = tempfile::tempdir().unwrap();
        let stock = root.path().join("stock");
        let live = root.path().join("live");
        fs::create_dir(&stock).unwrap();
        fs::create_dir(&live).unwrap();
        let target = live.join("voboost-selinux");
        let inode = std::cell::Cell::new(0);
        publish_stock_executable_checked(&target, b"signed helper", &stock, |file| {
            inode.set(file.metadata().unwrap().ino());
            Ok(())
        })
        .unwrap();
        assert_eq!(fs::metadata(&target).unwrap().ino(), inode.get());
        assert_eq!(fs::read(&target).unwrap(), b"signed helper");
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        assert_eq!(fs::read_dir(&stock).unwrap().count(), 0);
    }

    #[test]
    fn stock_executable_label_rejection_and_hostile_target_preserve_foreign_bytes() {
        let root = tempfile::tempdir().unwrap();
        let stock = root.path().join("stock");
        fs::create_dir(&stock).unwrap();
        let target = root.path().join("voboost-selinux");
        fs::write(&target, b"previous").unwrap();
        assert!(
            publish_stock_executable_checked(&target, b"signed helper", &stock, |_| {
                Err("wrong stock label".into())
            })
            .is_err()
        );
        assert_eq!(fs::read(&target).unwrap(), b"previous");
        fs::remove_file(&target).unwrap();
        let foreign = root.path().join("foreign");
        fs::write(&foreign, b"foreign").unwrap();
        symlink(&foreign, &target).unwrap();
        assert!(
            publish_stock_executable_checked(&target, b"signed helper", &stock, |_| Ok(()))
                .is_err()
        );
        assert_eq!(fs::read(&foreign).unwrap(), b"foreign");
        assert!(fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read_dir(&stock).unwrap().count(), 0);
    }

    #[test]
    fn directory_authority_is_exact_idempotent_and_non_mutating_on_mismatch() {
        let root = tempfile::tempdir().unwrap();
        let generations = root.path().join("generations");
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };

        ensure_directory(&generations, uid, gid, 0o711, false).unwrap();
        ensure_directory(&generations, uid, gid, 0o711, false).unwrap();
        assert_eq!(
            fs::symlink_metadata(&generations)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o711
        );

        fs::set_permissions(&generations, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(ensure_directory(&generations, uid, gid, 0o711, false).is_err());
        assert_eq!(
            fs::symlink_metadata(&generations)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o777
        );
    }

    #[test]
    fn incoming_authority_rejects_content_and_links() {
        let root = tempfile::tempdir().unwrap();
        let generations = root.path().join("generations");
        fs::create_dir(&generations).unwrap();
        fs::set_permissions(&generations, fs::Permissions::from_mode(0o711)).unwrap();
        let incoming = generations.join("next");
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        ensure_directory(&incoming, uid, gid, 0o700, true).unwrap();
        fs::write(incoming.join("foreign"), b"x").unwrap();
        assert!(ensure_directory(&incoming, uid, gid, 0o700, true).is_err());

        fs::remove_file(incoming.join("foreign")).unwrap();
        fs::remove_dir(&incoming).unwrap();
        let outside = root.path().join("outside");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, &incoming).unwrap();
        assert!(ensure_directory(&incoming, uid, gid, 0o700, true).is_err());
        assert!(outside.is_dir());
    }

    #[test]
    fn fixed_process_wait_is_bounded() {
        assert!(
            crate::fixed_process::status("/usr/bin/true", &[], Duration::from_secs(1)).unwrap()
        );
        assert!(
            !crate::fixed_process::status("/usr/bin/false", &[], Duration::from_secs(1)).unwrap()
        );
        assert!(
            crate::fixed_process::status("/bin/sleep", &["1"], Duration::from_millis(1)).is_err()
        );
        assert!(crate::fixed_process::output(
            "/usr/bin/printf",
            &["12345"],
            Duration::from_secs(1),
            4
        )
        .is_err());
    }

    #[test]
    fn app_identity_waits_for_data_after_package_manager_unavailability() {
        let mut attempts = 0;
        let identity = wait_app_identity(Duration::from_secs(1), Duration::ZERO, |_| {
            attempts += 1;
            Ok((attempts == 3).then_some(10_055))
        });
        assert_eq!(identity.unwrap(), (10_055, 10_055));
        assert_eq!(attempts, 3);
    }

    #[test]
    fn app_identity_stops_on_invalid_identity_without_retry() {
        let mut attempts = 0;
        let result = wait_app_identity(Duration::from_secs(1), Duration::ZERO, |_| {
            attempts += 1;
            Err("invalid application directory authority".to_string())
        });
        assert_eq!(
            result.unwrap_err(),
            "invalid application directory authority"
        );
        assert_eq!(attempts, 1);
    }

    #[test]
    fn app_identity_readiness_is_bounded() {
        let start = std::time::Instant::now();
        let result = wait_app_identity(Duration::from_millis(20), Duration::from_millis(5), |_| {
            Ok(None)
        });
        assert!(result.unwrap_err().contains("deadline"));
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn app_identity_data_probe_distinguishes_absence_from_unsafe_nodes() {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../build/install-tests");
        fs::create_dir_all(&base).unwrap();
        let temp = tempfile::tempdir_in(base).unwrap();
        let path = temp.path().join("data");
        assert_eq!(app_data_uid(&path).unwrap(), None);
        fs::write(&path, b"not a directory").unwrap();
        assert!(app_data_uid(&path).is_err());
        fs::remove_file(&path).unwrap();
        symlink(temp.path(), &path).unwrap();
        assert!(app_data_uid(&path).is_err());
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(app_data_uid(&path).is_err());
    }

    #[test]
    fn app_identity_probe_uses_data_only_when_package_query_is_unavailable() {
        use std::os::unix::process::ExitStatusExt;
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../build/install-tests");
        fs::create_dir_all(&base).unwrap();
        let temp = tempfile::tempdir_in(base).unwrap();
        let missing = temp.path().join("missing");
        assert_eq!(
            probe_app_identity(Err("package service unavailable".into()), &missing).unwrap(),
            None
        );
        for (stdout, expected) in [
            (b"".as_slice(), Ok(None)),
            (
                b"package:ru.voboost uid:10055\n".as_slice(),
                Ok(Some(10_055)),
            ),
        ] {
            let pm = crate::fixed_process::BoundedOutput {
                status: std::process::ExitStatus::from_raw(0),
                stdout: stdout.to_vec(),
                stderr: Vec::new(),
            };
            assert_eq!(probe_app_identity(Ok(pm), &missing), expected);
        }
        let malformed = crate::fixed_process::BoundedOutput {
            status: std::process::ExitStatus::from_raw(0),
            stdout: b"package:ru.voboost uid:0\n".to_vec(),
            stderr: Vec::new(),
        };
        assert!(probe_app_identity(Ok(malformed), &missing).is_err());
    }

    #[test]
    fn package_uid_selects_exact_app_among_translation_packages() {
        let output = crate::fixed_process::output(
            "/usr/bin/printf",
            &["package:ru.voboost.translation.settingnetwork uid:10107\npackage:ru.voboost.translation.settingnetwork.a11 uid:10106\npackage:ru.voboost.translation.setting.a11 uid:10110\npackage:ru.voboost.translation.vehiclesetting.a11 uid:10101\npackage:ru.voboost.translation.vehiclesetting uid:10103\npackage:ru.voboost.translation.systemui.a11 uid:10098\npackage:ru.voboost.translation.setting uid:10109\npackage:ru.voboost.translation.bluetoothphone uid:10105\npackage:ru.voboost.translation.systemui uid:10108\npackage:ru.voboost.translation.media uid:10104\npackage:ru.voboost.translation.launcher uid:10102\npackage:ru.voboost.translation.bluetoothphone.a11 uid:10097\npackage:ru.voboost.translation.launcher.a11 uid:10099\npackage:ru.voboost uid:10055\npackage:ru.voboost.translation.media.a11 uid:10100\n"],
            Duration::from_secs(1),
            4096,
        ).unwrap();
        assert_eq!(parse_package_uid(&output).unwrap(), Some(10_055));
    }

    #[test]
    fn package_uid_missing_exact_app_remains_a_readiness_condition() {
        use std::os::unix::process::ExitStatusExt;
        let output = crate::fixed_process::BoundedOutput {
            status: std::process::ExitStatus::from_raw(0),
            stdout: b"package:ru.voboost.translation.setting uid:10056\n".to_vec(),
            stderr: Vec::new(),
        };
        assert_eq!(parse_package_uid(&output).unwrap(), None);
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../build/install-tests");
        fs::create_dir_all(&base).unwrap();
        let temp = tempfile::tempdir_in(base).unwrap();
        assert_eq!(
            probe_app_identity(Ok(output), &temp.path().join("missing")).unwrap(),
            None
        );
    }

    #[test]
    fn package_uid_output_is_exact_and_user_zero_bounded() {
        let output = crate::fixed_process::output(
            "/usr/bin/printf",
            &["package:ru.voboost uid:10001\n"],
            Duration::from_secs(1),
            4096,
        )
        .unwrap();
        assert_eq!(parse_package_uid(&output).unwrap(), Some(10_001));

        for value in [
            "package:ru.voboost uid:9999\n",
            "package:ru.voboost uid:20000\n",
            "package:ru.voboost uid:10001\npackage:ru.voboost uid:10001\n",
            "package:ru.voboost\n",
            "package:ru.voboost uid:010001\n",
            "package:ru.voboost uid:10001\nextra\n",
        ] {
            let output = crate::fixed_process::output(
                "/usr/bin/printf",
                &[value],
                Duration::from_secs(1),
                4096,
            )
            .unwrap();
            assert!(parse_package_uid(&output).is_err(), "{value:?}");
        }
    }
}

#[cfg(test)]
mod apk_stream_tests {
    use super::*;
    #[test]
    fn verified_stream_rewinds_and_rejects_links_size_and_digest_changes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.apk");
        fs::write(&path, b"apk").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let hash = format!("{:x}", Sha256::digest(b"apk"));
        let input = verified_apk_input(&path, 3, &hash).unwrap();
        let output = crate::fixed_process::output_with_input(
            "/bin/cat",
            &[],
            Some(input),
            Duration::from_secs(1),
            3,
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"apk");
        assert!(verified_apk_input(&path, 4, &hash).is_err());
        assert!(verified_apk_input(&path, 3, &"00".repeat(32)).is_err());
        let link = directory.path().join("link.apk");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(verified_apk_input(&link, 3, &hash).is_err());
    }
}
