// pidfile.rs — descriptor-bound single-instance authority.
//
// Startup trusts only the fixed root zone and run-directory inodes. The
// pidfile is opened without following links, locked, truncated and written
// through one retained descriptor; pathname reopening is verification-only.

use std::fs::{File, Metadata};
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::OnceLock;

const ROOT_ZONE_MODE: u32 = 0o755;
use crate::config::RUN_DIR_MODE;
const PIDFILE_MODE: u32 = 0o600;

static PROCESS_LOCK: OnceLock<PidfileGuard> = OnceLock::new();

/// Retains every descriptor that established the process-lifetime authority.
pub struct PidfileGuard {
    _anchor: File,
    _root_zone: File,
    _run_dir: File,
    _pidfile: File,
}

/// Acquire the exact production lock and retain it until process exit.
pub fn acquire_process_lock() -> io::Result<()> {
    if PROCESS_LOCK.get().is_some() {
        return Ok(());
    }

    if unsafe { libc::geteuid() } != 0 || unsafe { libc::getegid() } != 0 {
        return Err(invalid_data(
            "pidfile authority requires root:root identity",
        ));
    }

    let guard = acquire_with_hook(
        Path::new("/data"),
        "voboost",
        "run",
        crate::config::PID_NAME,
        0,
        0,
        |_| {},
    )?;
    PROCESS_LOCK
        .set(guard)
        .map_err(|_| invalid_data("pidfile authority was initialized concurrently"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AcquireStage {
    DirectoriesReady,
    PidfileOpen,
    Locked,
    Written,
}

fn acquire_with_hook<F>(
    anchor_path: &Path,
    root_name: &str,
    run_name: &str,
    pid_name: &str,
    uid: u32,
    gid: u32,
    mut hook: F,
) -> io::Result<PidfileGuard>
where
    F: FnMut(AcquireStage),
{
    let anchor = open_directory(anchor_path)?;
    let root_zone = open_directory_at(&anchor, root_name)?;
    validate_directory(
        &root_zone.metadata()?,
        uid,
        gid,
        ROOT_ZONE_MODE,
        "root zone",
    )?;
    verify_named_directory(&anchor, root_name, &root_zone)?;

    let run_dir = match open_directory_at(&root_zone, run_name) {
        Ok(run_dir) => run_dir,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let created = create_directory_at(&root_zone, run_name, RUN_DIR_MODE)?;
            let run_dir = open_directory_at(&root_zone, run_name)?;
            if created {
                set_owner_mode(&run_dir, uid, gid, RUN_DIR_MODE)?;
                run_dir.sync_all()?;
                root_zone.sync_all()?;
            }
            run_dir
        }
        Err(error) => return Err(error),
    };
    validate_directory(
        &run_dir.metadata()?,
        uid,
        gid,
        RUN_DIR_MODE,
        "run directory",
    )?;
    verify_named_directory(&root_zone, run_name, &run_dir)?;
    verify_directory_chain(
        anchor_path,
        (root_name, run_name),
        (uid, gid),
        (&anchor, &root_zone, &run_dir),
    )?;
    hook(AcquireStage::DirectoriesReady);

    let (mut pidfile, created) = open_or_create_pidfile(&run_dir, pid_name)?;
    if created {
        set_owner_mode(&pidfile, uid, gid, PIDFILE_MODE)?;
    }
    validate_pidfile(&pidfile.metadata()?, uid, gid)?;
    verify_named_pidfile(&run_dir, pid_name, &pidfile, uid, gid)?;
    hook(AcquireStage::PidfileOpen);

    verify_directory_chain(
        anchor_path,
        (root_name, run_name),
        (uid, gid),
        (&anchor, &root_zone, &run_dir),
    )?;
    flock_exclusive_nonblocking(&pidfile)?;
    verify_named_pidfile(&run_dir, pid_name, &pidfile, uid, gid)?;
    hook(AcquireStage::Locked);

    pidfile.set_len(0)?;
    pidfile.seek(SeekFrom::Start(0))?;
    writeln!(pidfile, "{}", std::process::id())?;
    pidfile.sync_all()?;
    run_dir.sync_all()?;
    hook(AcquireStage::Written);

    validate_pidfile(&pidfile.metadata()?, uid, gid)?;
    verify_named_pidfile(&run_dir, pid_name, &pidfile, uid, gid)?;
    verify_directory_chain(
        anchor_path,
        (root_name, run_name),
        (uid, gid),
        (&anchor, &root_zone, &run_dir),
    )?;

    Ok(PidfileGuard {
        _anchor: anchor,
        _root_zone: root_zone,
        _run_dir: run_dir,
        _pidfile: pidfile,
    })
}

fn open_directory(path: &Path) -> io::Result<File> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| invalid_input("directory path contains NUL"))?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    file_from_fd(fd)
}

fn open_directory_at(parent: &File, name: &str) -> io::Result<File> {
    let name = entry_name(name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    file_from_fd(fd)
}

fn create_directory_at(parent: &File, name: &str, mode: u32) -> io::Result<bool> {
    let name = entry_name(name)?;
    let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), mode as libc::mode_t) };
    if result == 0 {
        Ok(true)
    } else {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::AlreadyExists {
            Ok(false)
        } else {
            Err(error)
        }
    }
}

fn open_or_create_pidfile(run_dir: &File, name: &str) -> io::Result<(File, bool)> {
    let name = entry_name(name)?;
    let flags = libc::O_RDWR
        | libc::O_NOFOLLOW
        | libc::O_CLOEXEC
        | libc::O_NONBLOCK
        | libc::O_CREAT
        | libc::O_EXCL;
    let fd = unsafe { libc::openat(run_dir.as_raw_fd(), name.as_ptr(), flags, PIDFILE_MODE) };
    if fd >= 0 {
        return Ok((unsafe { File::from_raw_fd(fd) }, true));
    }

    let error = io::Error::last_os_error();
    if error.kind() != io::ErrorKind::AlreadyExists {
        return Err(error);
    }
    let fd = unsafe {
        libc::openat(
            run_dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    Ok((file_from_fd(fd)?, false))
}

fn verify_directory_chain(
    anchor_path: &Path,
    names: (&str, &str),
    owner: (u32, u32),
    opened: (&File, &File, &File),
) -> io::Result<()> {
    let (root_name, run_name) = names;
    let (uid, gid) = owner;
    let (anchor, root_zone, run_dir) = opened;
    let current_anchor = open_directory(anchor_path)?;
    require_same_inode(anchor, &current_anchor, "anchor directory was substituted")?;
    let current_root = open_directory_at(&current_anchor, root_name)?;
    validate_directory(
        &current_root.metadata()?,
        uid,
        gid,
        ROOT_ZONE_MODE,
        "root zone",
    )?;
    require_same_inode(root_zone, &current_root, "root zone was substituted")?;
    let current_run = open_directory_at(&current_root, run_name)?;
    validate_directory(
        &current_run.metadata()?,
        uid,
        gid,
        RUN_DIR_MODE,
        "run directory",
    )?;
    require_same_inode(run_dir, &current_run, "run directory was substituted")
}

fn verify_named_directory(parent: &File, name: &str, opened: &File) -> io::Result<()> {
    let current = open_directory_at(parent, name)?;
    require_same_inode(
        opened,
        &current,
        "named directory differs from opened inode",
    )
}

fn verify_named_pidfile(
    run_dir: &File,
    name: &str,
    opened: &File,
    uid: u32,
    gid: u32,
) -> io::Result<()> {
    let name = entry_name(name)?;
    let fd = unsafe {
        libc::openat(
            run_dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    let current = file_from_fd(fd)?;
    validate_pidfile(&current.metadata()?, uid, gid)?;
    require_same_inode(opened, &current, "named pidfile differs from locked inode")
}

fn validate_directory(
    metadata: &Metadata,
    uid: u32,
    gid: u32,
    mode: u32,
    label: &'static str,
) -> io::Result<()> {
    if !metadata.file_type().is_dir() {
        return Err(invalid_data(label));
    }
    if metadata.uid() != uid || metadata.gid() != gid {
        return Err(invalid_data("directory has foreign ownership"));
    }
    if metadata.mode() & 0o7777 != mode {
        return Err(invalid_data("directory has unexpected mode"));
    }
    Ok(())
}

fn validate_pidfile(metadata: &Metadata, uid: u32, gid: u32) -> io::Result<()> {
    if !metadata.file_type().is_file() {
        return Err(invalid_data("pidfile is not a regular file"));
    }
    if metadata.nlink() != 1 {
        return Err(invalid_data("pidfile is not single-link"));
    }
    if metadata.uid() != uid || metadata.gid() != gid {
        return Err(invalid_data("pidfile has foreign ownership"));
    }
    if metadata.mode() & 0o7777 != PIDFILE_MODE {
        return Err(invalid_data("pidfile has unexpected mode"));
    }
    Ok(())
}

fn set_owner_mode(file: &File, uid: u32, gid: u32, mode: u32) -> io::Result<()> {
    let metadata = file.metadata()?;
    if metadata.uid() != uid || metadata.gid() != gid {
        let result = unsafe { libc::fchown(file.as_raw_fd(), uid, gid) };
        cvt(result)?;
    }
    file.set_permissions(std::fs::Permissions::from_mode(mode))
}

fn flock_exclusive_nonblocking(file: &File) -> io::Result<()> {
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    cvt(result)
}

fn require_same_inode(left: &File, right: &File, message: &'static str) -> io::Result<()> {
    let left = left.metadata()?;
    let right = right.metadata()?;
    if left.dev() != right.dev() || left.ino() != right.ino() {
        return Err(invalid_data(message));
    }
    Ok(())
}

fn entry_name(name: &str) -> io::Result<std::ffi::CString> {
    if name.is_empty() || name == "." || name == ".." || name.as_bytes().contains(&b'/') {
        return Err(invalid_input("entry name must be one path component"));
    }
    std::ffi::CString::new(name).map_err(|_| invalid_input("entry name contains NUL"))
}

fn file_from_fd(fd: libc::c_int) -> io::Result<File> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn cvt(result: libc::c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;
    use tempfile::tempdir;

    struct Fixture {
        _temp: tempfile::TempDir,
        anchor: PathBuf,
        root: PathBuf,
        run: PathBuf,
        uid: u32,
        gid: u32,
    }

    impl Fixture {
        fn new(create_run: bool) -> Self {
            let temp = tempdir().unwrap();
            let anchor = temp.path().join("data");
            let root = anchor.join("voboost");
            let run = root.join("run");
            fs::create_dir_all(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(ROOT_ZONE_MODE)).unwrap();
            if create_run {
                fs::create_dir(&run).unwrap();
                fs::set_permissions(&run, fs::Permissions::from_mode(RUN_DIR_MODE)).unwrap();
            }
            Self {
                _temp: temp,
                anchor,
                root,
                run,
                uid: unsafe { libc::geteuid() },
                gid: unsafe { libc::getegid() },
            }
        }

        fn acquire(&self) -> io::Result<PidfileGuard> {
            acquire_with_hook(
                &self.anchor,
                "voboost",
                "run",
                "pid",
                self.uid,
                self.gid,
                |_| {},
            )
        }
    }

    #[test]
    fn creates_exact_safe_run_directory_and_pidfile() {
        let fixture = Fixture::new(false);
        let _guard = fixture.acquire().unwrap();

        let run = fs::metadata(&fixture.run).unwrap();
        assert_eq!(run.mode() & 0o7777, RUN_DIR_MODE);
        assert_eq!(run.uid(), fixture.uid);
        assert_eq!(run.gid(), fixture.gid);
        let pid = fs::metadata(fixture.run.join("pid")).unwrap();
        assert_eq!(pid.mode() & 0o7777, PIDFILE_MODE);
        assert_eq!(pid.nlink(), 1);
    }

    #[test]
    fn rejects_symlink_pidfile_without_touching_target() {
        let fixture = Fixture::new(true);
        let target = fixture.root.join("victim");
        fs::write(&target, b"unchanged").unwrap();
        symlink(&target, fixture.run.join("pid")).unwrap();

        assert!(fixture.acquire().is_err());
        assert_eq!(fs::read(&target).unwrap(), b"unchanged");
    }

    #[test]
    fn rejects_hardlinked_pidfile() {
        let fixture = Fixture::new(true);
        let target = fixture.root.join("target");
        fs::write(&target, b"unchanged").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(PIDFILE_MODE)).unwrap();
        fs::hard_link(&target, fixture.run.join("pid")).unwrap();

        assert!(fixture.acquire().is_err());
        assert_eq!(fs::read(&target).unwrap(), b"unchanged");
    }

    #[test]
    fn rejects_foreign_pidfile_metadata() {
        let fixture = Fixture::new(true);
        let path = fixture.run.join("pid");
        fs::write(&path, b"unchanged").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(PIDFILE_MODE)).unwrap();
        let metadata = fs::metadata(path).unwrap();

        assert!(validate_pidfile(&metadata, fixture.uid.wrapping_add(1), fixture.gid).is_err());
    }

    #[test]
    fn rejects_wrong_pidfile_and_run_modes() {
        let fixture = Fixture::new(true);
        let pid = fixture.run.join("pid");
        fs::write(&pid, b"unchanged").unwrap();
        fs::set_permissions(&pid, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(fixture.acquire().is_err());
        assert_eq!(fs::read(&pid).unwrap(), b"unchanged");

        fs::remove_file(&pid).unwrap();
        fs::set_permissions(&fixture.run, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(fixture.acquire().is_err());
        assert!(!pid.exists());
    }

    #[test]
    fn never_creates_a_missing_root_zone() {
        let fixture = Fixture::new(true);
        fs::remove_dir(&fixture.run).unwrap();
        fs::remove_dir(&fixture.root).unwrap();

        assert!(fixture.acquire().is_err());
        assert!(!fixture.root.exists());
    }

    #[test]
    fn rejects_special_pidfile() {
        let fixture = Fixture::new(true);
        let path = fixture.run.join("pid");
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::mkfifo(path.as_ptr(), PIDFILE_MODE as libc::mode_t) },
            0
        );

        assert!(fixture.acquire().is_err());
    }

    #[test]
    fn rejects_run_directory_path_swap() {
        let fixture = Fixture::new(true);
        let retained = fixture.root.join("run-retained");
        let replacement = fixture.run.clone();
        let result = acquire_with_hook(
            &fixture.anchor,
            "voboost",
            "run",
            "pid",
            fixture.uid,
            fixture.gid,
            |stage| {
                if stage == AcquireStage::Locked {
                    fs::rename(&replacement, &retained).unwrap();
                    fs::create_dir(&replacement).unwrap();
                    fs::set_permissions(&replacement, fs::Permissions::from_mode(RUN_DIR_MODE))
                        .unwrap();
                    let replacement_pid = replacement.join("pid");
                    fs::write(&replacement_pid, b"replacement").unwrap();
                    fs::set_permissions(&replacement_pid, fs::Permissions::from_mode(PIDFILE_MODE))
                        .unwrap();
                }
            },
        );

        assert!(result.is_err());
        assert_eq!(fs::read(replacement.join("pid")).unwrap(), b"replacement");
    }

    #[test]
    fn never_reopens_pidfile_name_for_truncate_or_write() {
        let fixture = Fixture::new(true);
        let victim = fixture.root.join("victim");
        fs::write(&victim, b"unchanged").unwrap();
        let named_pid = fixture.run.join("pid");
        let retained_pid = fixture.run.join("pid-retained");
        let result = acquire_with_hook(
            &fixture.anchor,
            "voboost",
            "run",
            "pid",
            fixture.uid,
            fixture.gid,
            |stage| {
                if stage == AcquireStage::Locked {
                    fs::rename(&named_pid, &retained_pid).unwrap();
                    symlink(&victim, &named_pid).unwrap();
                }
            },
        );

        assert!(result.is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
        assert_eq!(
            fs::read_to_string(retained_pid).unwrap(),
            format!("{}\n", std::process::id())
        );
    }

    #[test]
    fn owner_and_inject_have_independent_exclusive_lifetimes() {
        use voboost_contract::runtime_owner::{INJECT_PID_NAME, OWNER_PID_NAME};
        let fixture = Fixture::new(true);
        let acquire = |name| {
            acquire_with_hook(
                &fixture.anchor,
                "voboost",
                "run",
                name,
                fixture.uid,
                fixture.gid,
                |_| {},
            )
        };
        let owner = acquire(OWNER_PID_NAME).unwrap();
        let inject = acquire(INJECT_PID_NAME).unwrap();
        assert_eq!(
            acquire(OWNER_PID_NAME).err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            acquire(INJECT_PID_NAME).err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(inject);
        let _replacement_inject = acquire(INJECT_PID_NAME).unwrap();
        assert_eq!(
            acquire(OWNER_PID_NAME).err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(owner);
        let _replacement_owner = acquire(OWNER_PID_NAME).unwrap();
    }
    #[test]
    fn rejects_lock_contention() {
        let fixture = Fixture::new(true);
        let _first = fixture.acquire().unwrap();
        let second = fixture.acquire().err().unwrap();

        assert_eq!(second.kind(), io::ErrorKind::WouldBlock);
    }
}
