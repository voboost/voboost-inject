//! One native mutation lock shared by the resident and offline executors.
use crate::{
    fs::{Dir, Fd},
    Result,
};

const NAME: &str = "operation.lock";
const MARKER: &[u8] = b"voboost-native-operation/1\n";
pub(crate) const BUSY: &str = "native operation busy; no mutation started";

/// Never reopen this inode while holding the guard: POSIX locks are process-owned.
pub(crate) struct Lock {
    _fd: Fd,
}

fn has_managed_state(root: &Dir) -> Result<bool> {
    if crate::install_layout::state_exists(root)?
        || crate::install_layout::read_current(root)?.is_some()
    {
        return Ok(true);
    }
    for member in [
        "startup.original",
        "service.json",
        "generations",
        "uninstall-intent.json",
        "restore.lock",
        "supervisor.delivery",
        "supervisor.revoked",
    ] {
        if root.exists(member)? {
            return Ok(true);
        }
    }
    Ok(false)
}

impl Lock {
    pub(crate) fn existing(root: &Dir) -> Result<Self> {
        Self::open(root, false)
    }
    pub(crate) fn initialize(root: &Dir) -> Result<Self> {
        Self::open(root, true)
    }

    pub(crate) fn wait_existing(root: &Dir) -> Result<Self> {
        for attempt in 0..50 {
            match Self::existing(root) {
                Err(error) if error == BUSY && attempt < 49 => unsafe {
                    libc::usleep(100_000);
                },
                result => return result,
            }
        }
        unreachable!()
    }

    fn open(root: &Dir, initialize: bool) -> Result<Self> {
        let present = root.exists(NAME)?;
        if !present && !initialize {
            return Err("native operation protocol unavailable; authority retained".into());
        }
        if !present && has_managed_state(root)? {
            return Err(
                "native operation protocol cannot be introduced into an existing installation"
                    .into(),
            );
        }
        let mut created = false;
        let fd = if initialize && !present {
            let fd = root.open_file(
                NAME,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )?;
            created = true;
            fd
        } else {
            root.open_file(NAME, libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0)?
        };
        let before = crate::fs::stat(fd.0)?;
        if before.st_mode & libc::S_IFMT != libc::S_IFREG
            || before.st_nlink != 1
            || before.st_uid as u32 != root.owner
            || before.st_mode as u32 & 0o777 != 0o600
        {
            return Err("native operation lock inode rejected".into());
        }
        #[cfg(target_os = "nto")]
        let request = libc::flock {
            l_type: libc::F_WRLCK as libc::c_short,
            l_whence: libc::SEEK_SET as libc::c_short,
            l_zero1: 0,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
            l_sysid: 0,
        };
        #[cfg(not(target_os = "nto"))]
        let request = libc::flock {
            l_type: libc::F_WRLCK as libc::c_short,
            l_whence: libc::SEEK_SET as libc::c_short,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        };
        if unsafe { libc::fcntl(fd.0, libc::F_SETLK, &request) } != 0 {
            return Err(match crate::fs::errno() {
                libc::EACCES | libc::EAGAIN => BUSY.into(),
                errno => alloc::format!("native operation lock failed: errno {errno}"),
            });
        }
        if created {
            crate::fs::write_all(fd.0, MARKER)?;
            if unsafe { libc::fsync(fd.0) } != 0 || unsafe { libc::fsync(root.fd.0) } != 0 {
                return Err("native operation lock publication failed".into());
            }
        }
        if unsafe { libc::lseek(fd.0, 0, libc::SEEK_SET) } != 0 {
            return Err("native operation lock seek failed".into());
        }
        let current = crate::fs::stat(fd.0)?;
        if current.st_size < 0 || current.st_size as usize > MARKER.len() {
            return Err("native operation lock protocol unavailable; authority retained".into());
        }
        let length = current.st_size as usize;
        let mut marker = [0u8; MARKER.len()];
        crate::fs::read_exact(fd.0, &mut marker[..length])?;
        if marker[..length] != MARKER[..length] {
            return Err("native operation lock protocol unavailable; authority retained".into());
        }
        if length != MARKER.len() {
            if !initialize || has_managed_state(root)? {
                return Err(
                    "incomplete operation protocol cannot be repaired in an installed authority"
                        .into(),
                );
            }
            // Repair only our interrupted initial prefix, under the same inode lock.
            if unsafe { libc::ftruncate(fd.0, 0) } != 0
                || unsafe { libc::lseek(fd.0, 0, libc::SEEK_SET) } != 0
            {
                return Err("native operation lock initialization repair failed".into());
            }
            crate::fs::write_all(fd.0, MARKER)?;
            if unsafe { libc::fsync(fd.0) } != 0 || unsafe { libc::fsync(root.fd.0) } != 0 {
                return Err("native operation lock repair publication failed".into());
            }
        }
        let after = crate::fs::stat(fd.0)?;
        if after.st_size as usize != MARKER.len()
            || before.st_dev != after.st_dev
            || before.st_ino != after.st_ino
            || after.st_nlink != 1
        {
            return Err("native operation lock protocol unavailable; authority retained".into());
        }
        Ok(Self { _fd: fd })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn requires_existing_protocol_and_keeps_one_inode_across_uses() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = Dir::open(
            directory.path().to_str().unwrap(),
            crate::fs::uid().unwrap(),
        )
        .unwrap();
        assert!(Lock::existing(&root).is_err());
        let lock = Lock::initialize(&root).unwrap();
        let before = std::fs::metadata(directory.path().join(NAME)).unwrap();
        drop(lock);
        let _next = Lock::existing(&root).unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            before.ino(),
            std::fs::metadata(directory.path().join(NAME))
                .unwrap()
                .ino()
        );
    }

    #[test]
    fn cannot_introduce_a_protocol_marker_into_a_legacy_installation() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = Dir::open(
            directory.path().to_str().unwrap(),
            crate::fs::uid().unwrap(),
        )
        .unwrap();
        root.write("installation.json", b"{}", 0o600).unwrap();
        assert!(Lock::initialize(&root).is_err());
        assert!(!root.exists(NAME).unwrap());
        assert_eq!(root.read("installation.json", 10, 0o600).unwrap(), b"{}");
    }

    #[test]
    fn rejects_a_foreign_marker_without_replacing_its_bytes() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = Dir::open(
            directory.path().to_str().unwrap(),
            crate::fs::uid().unwrap(),
        )
        .unwrap();
        root.write(NAME, b"foreign\n", 0o600).unwrap();
        assert!(Lock::existing(&root).is_err());
        assert_eq!(root.read(NAME, 32, 0o600).unwrap(), b"foreign\n");
    }
    #[test]
    fn excludes_another_process_until_the_current_guard_is_released() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = Dir::open(
            directory.path().to_str().unwrap(),
            crate::fs::uid().unwrap(),
        )
        .unwrap();
        let guard = Lock::initialize(&root).unwrap();
        // After fork the child uses only async-signal-safe libc calls, never allocation.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            let mut request: libc::flock = unsafe { core::mem::zeroed() };
            request.l_type = libc::F_WRLCK as libc::c_short;
            request.l_whence = libc::SEEK_SET as libc::c_short;
            let result = unsafe { libc::fcntl(guard._fd.0, libc::F_SETLK, &request) };
            let error = crate::fs::errno();
            let expected = result == -1 && (error == libc::EACCES || error == libc::EAGAIN);
            unsafe { libc::_exit(if expected { 0 } else { 71 }) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        drop(guard);
        assert!(Lock::existing(&root).is_ok());
    }
    #[test]
    fn resumes_only_an_interrupted_initial_marker_on_the_same_inode() {
        use std::os::unix::fs::MetadataExt;
        for prefix in [b"".as_slice(), &MARKER[..7]] {
            let directory = tempfile::tempdir().unwrap();
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let root = Dir::open(
                directory.path().to_str().unwrap(),
                crate::fs::uid().unwrap(),
            )
            .unwrap();
            root.write(NAME, prefix, 0o600).unwrap();
            let inode = std::fs::metadata(directory.path().join(NAME))
                .unwrap()
                .ino();
            assert!(Lock::existing(&root).is_err());
            drop(Lock::initialize(&root).unwrap());
            assert_eq!(root.read(NAME, 64, 0o600).unwrap(), MARKER);
            assert_eq!(
                inode,
                std::fs::metadata(directory.path().join(NAME))
                    .unwrap()
                    .ino()
            );
        }
    }
}
