use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const PROC_SELF_EXE: &str = "/proc/self/exe";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    len: u64,
    ctime: i64,
    ctime_nsec: i64,
}

impl Stamp {
    fn from(metadata: &std::fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            len: metadata.len(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }
}

fn validate(
    metadata: &std::fs::Metadata,
    maximum: usize,
    mode: u32,
    uid: u32,
    gid: u32,
    label: &str,
) -> Result<Stamp, String> {
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o7777 != mode
        || metadata.len() == 0
        || metadata.len() > maximum as u64
    {
        return Err(format!("{label} has a foreign identity"));
    }
    Ok(Stamp::from(metadata))
}

fn read_stable(
    mut file: File,
    maximum: usize,
    mode: u32,
    uid: u32,
    gid: u32,
    label: &str,
) -> Result<(Vec<u8>, Stamp), String> {
    let before = file.metadata().map_err(|error| error.to_string())?;
    let stamp = validate(&before, maximum, mode, uid, gid, label)?;
    let mut bytes = Vec::with_capacity(stamp.len as usize);
    Read::by_ref(&mut file)
        .take(maximum.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {label}: {error}"))?;
    let after = file.metadata().map_err(|error| error.to_string())?;
    if validate(&after, maximum, mode, uid, gid, label)? != stamp
        || bytes.len() as u64 != stamp.len
        || bytes.len() > maximum
    {
        return Err(format!("{label} changed while reading"));
    }
    Ok((bytes, stamp))
}

fn open_named_nofollow(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("open fixed executable {}: {error}", path.display()))
}

pub fn read_self_executable(
    fixed_path: &Path,
    maximum: usize,
    mode: u32,
    uid: u32,
    gid: u32,
) -> Result<Vec<u8>, String> {
    let named = open_named_nofollow(fixed_path)?;
    // /proc/self/exe is a kernel magic symlink. This is the sole reader that
    // intentionally omits O_NOFOLLOW, and its pathname is not caller-controlled.
    let running = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(PROC_SELF_EXE)
        .map_err(|error| format!("open {PROC_SELF_EXE}: {error}"))?;
    let (named_bytes, named_stamp) =
        read_stable(named, maximum, mode, uid, gid, "fixed executable")?;
    let (running_bytes, running_stamp) =
        read_stable(running, maximum, mode, uid, gid, PROC_SELF_EXE)?;
    if named_stamp.dev != running_stamp.dev
        || named_stamp.ino != running_stamp.ino
        || named_bytes != running_bytes
    {
        return Err("running executable differs from fixed executable".to_string());
    }

    // Re-open the name after both reads. An attacker replacing the directory
    // entry cannot change the retained fd, so this final binding detects it.
    let rebound = open_named_nofollow(fixed_path)?;
    let rebound_metadata = rebound.metadata().map_err(|error| error.to_string())?;
    if validate(
        &rebound_metadata,
        maximum,
        mode,
        uid,
        gid,
        "rebound fixed executable",
    )? != named_stamp
    {
        return Err("fixed executable was replaced while reading".to_string());
    }
    Ok(running_bytes)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn production_reader_accepts_proc_magic_link_and_rejects_named_symlink() {
        let current = std::env::current_exe().unwrap();
        let metadata = current.metadata().unwrap();
        let mode = metadata.permissions().mode() & 0o7777;
        let bytes = read_self_executable(
            &current,
            metadata.len() as usize,
            mode,
            metadata.uid(),
            metadata.gid(),
        )
        .unwrap();
        assert_eq!(bytes.len() as u64, metadata.len());

        let temporary =
            std::env::temp_dir().join(format!("voboost-self-exe-symlink-{}", std::process::id()));
        let _ = std::fs::remove_file(&temporary);
        symlink(&current, &temporary).unwrap();
        let error = read_self_executable(
            &temporary,
            metadata.len() as usize,
            mode,
            metadata.uid(),
            metadata.gid(),
        )
        .unwrap_err();
        std::fs::remove_file(&temporary).unwrap();
        assert!(error.contains("open fixed executable"));
    }
}
