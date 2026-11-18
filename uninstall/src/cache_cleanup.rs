//! Staged native implementation; caller binds the fixed package path and independently trusted UID.
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use libc::{openat, unlinkat, O_CLOEXEC, O_DIRECTORY, O_NOFOLLOW};
fn owned_name(name: &str) -> bool {
    let base = name
        .strip_suffix(".bak")
        .or_else(|| name.strip_suffix(".new"))
        .unwrap_or(name);
    let Some(hash) = base
        .strip_prefix(".vbi1-")
        .and_then(|v| v.strip_suffix(".bin"))
    else {
        return false;
    };
    hash.len() == 64
        && hash
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}

struct Chain(Vec<(PathBuf, File)>);
impl Chain {
    fn open(path: &Path) -> std::io::Result<Self> {
        let mut entries = vec![(
            PathBuf::from("/"),
            OpenOptions::new()
                .read(true)
                .custom_flags(O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC)
                .open("/")?,
        )];
        for component in path.components() {
            let Component::Normal(name) = component else {
                if component == Component::RootDir {
                    continue;
                }
                return Err(std::io::Error::other("non-canonical cache path"));
            };
            let name = CString::new(name.as_encoded_bytes())
                .map_err(|_| std::io::Error::other("invalid cache name"))?;
            let previous = entries.last().unwrap();
            let fd = unsafe {
                openat(
                    previous.1.as_raw_fd(),
                    name.as_ptr(),
                    O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let next = previous.0.join(component.as_os_str());
            entries.push((next, unsafe { File::from_raw_fd(fd) }));
        }
        Ok(Self(entries))
    }
    fn validate(&self) -> std::io::Result<()> {
        for (path, retained) in &self.0 {
            let live = fs::symlink_metadata(path)?;
            let old = retained.metadata()?;
            if !live.is_dir() || live.dev() != old.dev() || live.ino() != old.ino() {
                return Err(std::io::Error::other("cache directory identity changed"));
            }
        }
        Ok(())
    }
}

pub fn cleanup(package_data: &Path, launcher_uid: u32) -> std::io::Result<usize> {
    let icons = package_data.join("cache/icons");
    let chain = match Chain::open(&icons) {
        Ok(chain) => chain,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let package = chain
        .0
        .iter()
        .find(|(path, _)| path == package_data)
        .ok_or_else(|| std::io::Error::other("package boundary missing"))?;
    let package_meta = package.1.metadata()?;
    for (path, dir) in &chain.0 {
        if path.starts_with(package_data) {
            let meta = dir.metadata()?;
            if meta.uid() != launcher_uid || meta.dev() != package_meta.dev() {
                return Err(std::io::Error::other("foreign cache owner or mount"));
            }
        }
    }
    let directory = &chain.0.last().unwrap().1;
    let mut count = 0;
    for (index, entry) in fs::read_dir(&icons)?.enumerate() {
        if index >= 4096 {
            return Err(std::io::Error::other("cache inventory bound exceeded"));
        }
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str().filter(|name| owned_name(name)) else {
            continue;
        };
        chain.validate()?;
        let meta = fs::symlink_metadata(entry.path())?;
        if meta.uid() != launcher_uid
            || meta.nlink() != 1
            || !(meta.is_file() || meta.file_type().is_symlink())
        {
            return Err(std::io::Error::other("unsafe owned cache entry"));
        }
        let name = CString::new(name).unwrap();
        if unsafe { unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        chain.validate()?;
        count += 1;
    }
    chain.validate()?;
    directory.sync_all()?;
    for (index, entry) in fs::read_dir(&icons)?.enumerate() {
        if index >= 4096 {
            return Err(std::io::Error::other("cache inventory bound exceeded"));
        }
        if entry?.file_name().to_str().is_some_and(owned_name) {
            return Err(std::io::Error::other("owned cache remains"));
        }
    }
    chain.validate()?;
    Ok(count)
}

pub fn cleanup_launcher(transaction_id: Option<&str>) -> std::io::Result<usize> {
    let inventory = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open("/data/system/packages.list")?;
    let meta = inventory.metadata()?;
    if !meta.is_file()
        || meta.nlink() != 1
        || ![0, 1000].contains(&meta.uid())
        || meta.mode() & 0o002 != 0
        || (meta.mode() & 0o020 != 0 && ![0, 1000].contains(&meta.gid()))
        || meta.len() > 4 * 1024 * 1024
    {
        return Err(std::io::Error::other("untrusted package UID inventory"));
    }
    use std::io::Read;
    let mut text = String::new();
    inventory
        .take(4 * 1024 * 1024 + 1)
        .read_to_string(&mut text)?;
    let uid = launcher_uid(&text)?;
    let root = canonical_user_zero_root()?;
    verify_no_resident_daemon()?;
    if let Some(transaction_id) = transaction_id {
        let receipt = read_normal_receipt(transaction_id)?;
        verify_injected_launchers(uid, receipt.acknowledged_identity())?;
        let removed = cleanup(&root.join("com.qinggan.app.launcher"), uid)?;
        verify_injected_launchers(uid, receipt.acknowledged_identity())?;
        verify_no_resident_daemon()?;
        Ok(removed)
    } else {
        verify_recovery_boot()?;
        verify_injected_launchers(uid, None)?;
        let removed = cleanup(&root.join("com.qinggan.app.launcher"), uid)?;
        verify_injected_launchers(uid, None)?;
        verify_no_resident_daemon()?;
        Ok(removed)
    }
}
fn canonical_user_zero_root() -> std::io::Result<PathBuf> {
    let root = Path::new("/data/user/0");
    let meta = fs::symlink_metadata(root)?;
    if meta.file_type().is_symlink() {
        if ![0, 1000].contains(&meta.uid()) || fs::read_link(root)? != Path::new("/data/data") {
            return Err(std::io::Error::other("foreign user-zero data alias"));
        }
        return Ok(PathBuf::from("/data/data"));
    }
    if let Ok(alias) = fs::symlink_metadata("/data/data") {
        if alias.file_type().is_symlink()
            && (![0, 1000].contains(&alias.uid()) || fs::read_link("/data/data")? != root)
        {
            return Err(std::io::Error::other("foreign data alias"));
        }
    }
    if !meta.is_dir() {
        return Err(std::io::Error::other("invalid user-zero data root"));
    }
    Ok(root.to_path_buf())
}

fn process_uid_matches(status: &str, uid: u32) -> std::io::Result<bool> {
    let lines = status
        .lines()
        .filter(|line| line.starts_with("Uid:"))
        .collect::<Vec<_>>();
    if lines.len() != 1 {
        return Err(std::io::Error::other("ambiguous process UID status"));
    }
    let values = lines[0]
        .split_whitespace()
        .skip(1)
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| std::io::Error::other("invalid process UID status"))?;
    if values.len() != 4 {
        return Err(std::io::Error::other("incomplete process UID status"));
    }
    Ok(values.iter().all(|value| *value == uid))
}
fn read_proc_bytes(path: impl AsRef<Path>, maximum: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}
fn proc_identity(pid: u32, uid: u32) -> std::io::Result<Option<String>> {
    let dir = PathBuf::from(format!("/proc/{pid}"));
    let status_bytes = read_proc_bytes(dir.join("status"), 256 * 1024)?;
    let status = std::str::from_utf8(&status_bytes).map_err(std::io::Error::other)?;
    if status.len() > 256 * 1024 {
        return Err(std::io::Error::other("process status bound exceeded"));
    }
    if !process_uid_matches(status, uid)? {
        return Ok(None);
    }
    let cmd = read_proc_bytes(dir.join("cmdline"), 4096)?;
    if cmd.split(|b| *b == 0).next() != Some(b"com.qinggan.app.launcher".as_slice()) {
        return Ok(None);
    }
    if cmd.len() > 4096 {
        return Err(std::io::Error::other("launcher command exceeds bound"));
    }
    let stat = fs::read_to_string(dir.join("stat"))?;
    let tail = stat
        .rsplit_once(") ")
        .ok_or_else(|| std::io::Error::other("invalid process stat"))?
        .1;
    let start = tail
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| std::io::Error::other("missing process starttime"))?;
    if !start.bytes().all(|v| v.is_ascii_digit()) {
        return Err(std::io::Error::other("invalid process starttime"));
    }
    Ok(Some(start.to_owned()))
}
fn injected_launcher(pid: u32, uid: u32) -> std::io::Result<Option<String>> {
    let Some(identity) = proc_identity(pid, uid)? else {
        return Ok(None);
    };
    let maps_bytes = read_proc_bytes(format!("/proc/{pid}/maps"), 8 * 1024 * 1024)?;
    let maps = std::str::from_utf8(&maps_bytes).map_err(std::io::Error::other)?;
    if maps.len() > 8 * 1024 * 1024 {
        return Err(std::io::Error::other("process maps bound exceeded"));
    }
    if !maps.lines().any(|line| {
        line.split_whitespace()
            .skip(5)
            .any(|path| path.starts_with("/data/voboost/"))
    }) {
        return Ok(None);
    }
    Ok(Some(identity))
}
fn read_root_receipt(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let chain = Chain::open(
        path.parent()
            .ok_or_else(|| std::io::Error::other("receipt parent absent"))?,
    )?;
    chain.validate()?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.nlink() != 1
        || meta.mode() & 0o777 != 0o600
        || meta.len() > 8192
    {
        return Err(std::io::Error::other("untrusted cache quiescence receipt"));
    }
    let mut bytes = Vec::new();
    file.take(8193).read_to_end(&mut bytes)?;
    chain.validate()?;
    if bytes.len() > 8192 {
        return Err(std::io::Error::other("cache receipt exceeds bound"));
    }
    Ok(bytes)
}
fn read_normal_receipt(
    transaction_id: &str,
) -> std::io::Result<voboost_contract::icon_cache_quiescence::Receipt> {
    let bytes = read_root_receipt(Path::new("/data/voboost/run/icon-cache-quiescence.json"))?;
    let receipt: voboost_contract::icon_cache_quiescence::Receipt =
        serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    if !receipt.matches(transaction_id, boot.trim()) {
        return Err(std::io::Error::other(
            "cache receipt transaction or boot differs",
        ));
    }
    Ok(receipt)
}
fn verify_recovery_boot() -> std::io::Result<()> {
    let bytes = read_root_receipt(Path::new("/data/voboost/run/icon-cache-reboot.json"))?;
    let checkpoint: voboost_contract::icon_cache_quiescence::RebootCheckpoint =
        serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    if !checkpoint.admits(boot.trim()) {
        return Err(std::io::Error::other(
            "cache recovery requires a canonical different boot",
        ));
    }
    verify_no_resident_daemon()?;
    match fs::symlink_metadata("/system/etc/init/voboost.rc") {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(std::io::Error::other("product startup hook reappeared")),
    }
}
fn resident_daemon_command(command: &[u8]) -> bool {
    let fields = command
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();
    if !matches!(
        fields.first().copied(),
        Some(b"/data/voboost/voboost-daemon" | b"/data/voboost/voboost-inject")
    ) {
        return false;
    }
    !(fields.len() == 2 && [b"--inspect".as_slice(), b"--status".as_slice()].contains(&fields[1]))
}
fn verify_no_resident_daemon() -> std::io::Result<()> {
    for (index, entry) in fs::read_dir("/proc")?.enumerate() {
        if index >= 16384 {
            return Err(std::io::Error::other("process inventory bound exceeded"));
        }
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|v| v.parse::<u32>().ok())
        else {
            continue;
        };
        let command = match read_proc_bytes(format!("/proc/{pid}/cmdline"), 4096) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        if resident_daemon_command(&command) {
            return Err(std::io::Error::other(
                "resident daemon remains during cache purge",
            ));
        }
    }
    Ok(())
}
fn verify_injected_launchers(uid: u32, allowed: Option<(u32, String)>) -> std::io::Result<()> {
    for (index, entry) in fs::read_dir("/proc")?.enumerate() {
        if index >= 16384 {
            return Err(std::io::Error::other("process inventory bound exceeded"));
        }
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|v| v.parse::<u32>().ok())
        else {
            continue;
        };
        let identity = match injected_launcher(pid, uid) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if let Some(identity) = identity {
            if allowed.as_ref() != Some(&(pid, identity)) {
                return Err(std::io::Error::other(
                    "unacknowledged launcher cache writer remains",
                ));
            }
        }
    }
    Ok(())
}
fn launcher_uid(text: &str) -> std::io::Result<u32> {
    let mut uid = None;
    for line in text.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.first() != Some(&"com.qinggan.app.launcher") {
            continue;
        }
        if uid.is_some()
            || fields.len() < 6
            || ![
                "/data/user/0/com.qinggan.app.launcher",
                "/data/data/com.qinggan.app.launcher",
            ]
            .contains(&fields[3])
            || !fields[1].bytes().all(|v| v.is_ascii_digit())
        {
            return Err(std::io::Error::other("ambiguous launcher package UID"));
        }
        uid = Some(
            fields[1]
                .parse::<u32>()
                .map_err(|_| std::io::Error::other("invalid launcher UID"))?,
        );
    }
    uid.filter(|v| *v >= 1000 && *v < 100000)
        .ok_or_else(|| std::io::Error::other("launcher UID unavailable"))
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    fn root() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static ID: AtomicU64 = AtomicU64::new(0);
        let base = option_env!("CACHE_TEST_ROOT")
            .or(option_env!("CARGO_MANIFEST_DIR"))
            .unwrap_or(".");
        let p = PathBuf::from(base).join(format!(
            "cache-cleanup-{}-{}",
            std::process::id(),
            ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }
    #[test]
    fn process_uid_uses_kernel_status_not_dumpable_dependent_proc_owner() {
        assert!(
            process_uid_matches("Name: launcher\nUid:\t1000\t1000\t1000\t1000\n", 1000).unwrap()
        );
        assert!(!process_uid_matches("Uid: 1001 1001 1001 1001\n", 1000).unwrap());
        assert!(process_uid_matches("Uid: 1000 1000\n", 1000).is_err());
        assert!(process_uid_matches("Uid: x 1000 1000 1000\n", 1000).is_err());
        assert!(
            process_uid_matches("Uid: 1000 1000 1000 1000\nUid: 1000 1000 1000 1000\n", 1000)
                .is_err()
        );
    }
    #[test]
    fn trusted_uid_parser() {
        let line =
            "com.qinggan.app.launcher 1000 0 /data/user/0/com.qinggan.app.launcher platform 3003\n";
        assert_eq!(launcher_uid(line).unwrap(), 1000);
        assert!(launcher_uid(&(line.to_owned() + line)).is_err());
        assert!(launcher_uid(&line.replace("1000 0", "bad 0")).is_err());
        assert!(
            launcher_uid(&line.replace("/data/user/0/com.qinggan.app.launcher", "/other")).is_err()
        );
    }
    #[test]
    fn resident_daemon_detection_distinguishes_read_only_inspection() {
        assert!(resident_daemon_command(b"/data/voboost/voboost-daemon\0"));
        assert!(!resident_daemon_command(
            b"/data/voboost/voboost-daemon\0--inspect\0"
        ));
        assert!(!resident_daemon_command(b"com.qinggan.app.launcher\0"));
        assert!(resident_daemon_command(
            b"/data/voboost/voboost-daemon\0--native-worker\0"
        ));
    }
    #[test]
    fn exact_namespace() {
        let n = format!(".vbi1-{}.bin", "a".repeat(64));
        for suffix in ["", ".bak", ".new"] {
            assert!(owned_name(&(n.clone() + suffix)));
        }
        for n in [
            "stock.png",
            ".vbi1-x.bin",
            ".vbi1-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.bin",
            ".vbi1-x.bin.new.bak",
        ] {
            assert!(!owned_name(n));
        }
    }
    #[test]
    fn corrupt_and_atomic_files_removed_foreign_preserved_symlink_target_untouched() {
        let root = root();
        let package = root.join("package");
        let icons = package.join("cache/icons");
        fs::create_dir_all(&icons).unwrap();
        let n = format!(".vbi1-{}.bin", "b".repeat(64));
        fs::write(icons.join(&n), b"corrupt").unwrap();
        fs::write(icons.join(format!("{n}.new")), b"").unwrap();
        fs::write(root.join("target"), b"preserve").unwrap();
        symlink(root.join("target"), icons.join(format!("{n}.bak"))).unwrap();
        fs::write(icons.join("stock.png"), b"stock").unwrap();
        let uid = fs::metadata(&package).unwrap().uid();
        assert_eq!(cleanup(&package, uid).unwrap(), 3);
        assert_eq!(cleanup(&package, uid).unwrap(), 0);
        assert_eq!(fs::read(root.join("target")).unwrap(), b"preserve");
        assert!(icons.join("stock.png").exists());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn owned_hardlinks_and_directories_are_rejected_without_deleting_their_contents() {
        let root = root();
        let package = root.join("package");
        let icons = package.join("cache/icons");
        fs::create_dir_all(&icons).unwrap();
        let name = format!(".vbi1-{}.bin", "d".repeat(64));
        let target = root.join("target");
        fs::write(&target, b"preserve").unwrap();
        fs::hard_link(&target, icons.join(&name)).unwrap();
        let uid = fs::metadata(&package).unwrap().uid();
        assert!(cleanup(&package, uid).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"preserve");
        fs::remove_file(icons.join(&name)).unwrap();
        fs::create_dir(icons.join(&name)).unwrap();
        fs::write(icons.join(&name).join("stock"), b"preserve").unwrap();
        assert!(cleanup(&package, uid).is_err());
        assert!(icons.join(&name).join("stock").exists());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn uid_and_symlink_directory_rejected() {
        let root = root();
        let package = root.join("package");
        fs::create_dir_all(package.join("cache/icons")).unwrap();
        let uid = fs::metadata(&package).unwrap().uid();
        assert!(cleanup(&package, uid + 1).is_err());
        fs::remove_dir(package.join("cache/icons")).unwrap();
        symlink(&root, package.join("cache/icons")).unwrap();
        assert!(cleanup(&package, uid).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
