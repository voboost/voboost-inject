use super::*;

pub(super) const MAX_TERMINAL_TREE_ENTRIES: usize = 4096;

pub(super) fn open_directory_nofollow(path: &Path, label: &str) -> Result<File, String> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("open retained {label}: {error}"))?;
    if !directory
        .metadata()
        .map_err(|error| format!("fstat retained {label}: {error}"))?
        .file_type()
        .is_dir()
    {
        return Err(format!("retained {label} is not a directory"));
    }
    Ok(directory)
}

pub(super) fn fixed_leaf_name(name: &[u8]) -> Result<std::ffi::CString, String> {
    if name.is_empty() || matches!(name, b"." | b"..") || name.contains(&b'/') {
        return Err("directory traversal produced an unsafe leaf name".to_string());
    }
    std::ffi::CString::new(name).map_err(|_| "directory leaf contains NUL".to_string())
}

pub(super) fn openat_directory_nofollow(
    parent: &File,
    name: &[u8],
    label: &str,
) -> Result<File, String> {
    let name = fixed_leaf_name(name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(format!(
            "openat retained {label}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(super) fn directory_entry_names(directory: &File, label: &str) -> Result<Vec<Vec<u8>>, String> {
    let duplicate = unsafe { libc::dup(directory.as_raw_fd()) };
    if duplicate < 0 {
        return Err(format!(
            "dup retained {label}: {}",
            std::io::Error::last_os_error()
        ));
    }
    let raw_stream = unsafe { libc::fdopendir(duplicate) };
    if raw_stream.is_null() {
        unsafe { libc::close(duplicate) };
        return Err(format!(
            "fdopendir retained {label}: {}",
            std::io::Error::last_os_error()
        ));
    }
    let stream = DirectoryStream(raw_stream);
    unsafe { libc::rewinddir(stream.0) };
    let mut names = Vec::new();
    loop {
        clear_thread_errno();
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let errno = thread_errno();
            if errno != 0 {
                return Err(format!(
                    "readdir retained {label}: {}",
                    std::io::Error::from_raw_os_error(errno)
                ));
            }
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        fixed_leaf_name(name)?;
        names.push(name.to_vec());
        if names.len() > MAX_TERMINAL_TREE_ENTRIES {
            return Err("terminal tree exceeds its fixed entry bound".to_string());
        }
    }
    names.sort();
    Ok(names)
}

pub(super) fn statat_nofollow(
    parent: &File,
    name: &[u8],
    label: &str,
) -> Result<libc::stat, String> {
    let name = fixed_leaf_name(name)?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(format!(
            "fstatat retained {label}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(unsafe { stat.assume_init() })
}

pub(super) fn unlinkat_leaf(
    parent: &File,
    name: &[u8],
    directory: bool,
    label: &str,
) -> Result<(), String> {
    let name = fixed_leaf_name(name)?;
    if unsafe {
        libc::unlinkat(
            parent.as_raw_fd(),
            name.as_ptr(),
            if directory { libc::AT_REMOVEDIR } else { 0 },
        )
    } != 0
    {
        return Err(format!(
            "unlinkat retained {label}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

pub(super) fn remove_tree_member_at(
    parent: &File,
    name: &[u8],
    root_device: u64,
    visited: &mut usize,
) -> Result<(), String> {
    *visited = visited
        .checked_add(1)
        .ok_or_else(|| "terminal tree entry count overflow".to_string())?;
    if *visited > MAX_TERMINAL_TREE_ENTRIES {
        return Err("terminal tree exceeds its fixed entry bound".to_string());
    }
    let stat = statat_nofollow(parent, name, "terminal tree member")?;
    if stat.st_dev as u64 != root_device {
        return Err("terminal tree removal refuses a mount boundary".to_string());
    }
    let kind = stat.st_mode & libc::S_IFMT;
    if kind == libc::S_IFDIR {
        let directory = openat_directory_nofollow(parent, name, "terminal tree directory")?;
        let opened = directory
            .metadata()
            .map_err(|error| format!("fstat retained terminal directory: {error}"))?;
        if opened.dev() != stat.st_dev as u64 || opened.ino() != stat.st_ino {
            return Err("terminal directory changed at openat boundary".to_string());
        }
        let removed = remove_entries_with(
            directory_entry_names(&directory, "terminal tree directory")?,
            &[],
            |child| remove_tree_member_at(&directory, child, root_device, visited),
        );
        let synced = directory
            .sync_all()
            .map_err(|error| format!("fsync retained terminal directory: {error}"));
        match (removed, synced) {
            (Ok(()), Ok(())) => (),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => return Err(error),
            (Err(removal), Err(sync)) => return Err(format!("{removal}; {sync}")),
        }
        unlinkat_leaf(parent, name, true, "terminal tree directory")?;
    } else {
        // The root zone is a fixed root-owned directory, so every member that
        // is not a directory is a leaf the uninstall authority may unlink.
        // Regular files, symlinks and the daemon's runtime specials (sockets,
        // fifos, device nodes) all fall under the same descriptor-relative
        // `unlinkat` cut. The earlier `st_dev` check still rejects any member
        // that escapes the root device, so a mount boundary cannot be unlinked
        // here.
        unlinkat_leaf(parent, name, false, "terminal tree leaf")?;
    }
    Ok(())
}

pub(super) fn remove_directory_entries_except(
    directory: &File,
    root_device: u64,
    retained: &[&[u8]],
) -> Result<(), String> {
    let mut visited = 0usize;
    let removed = remove_entries_with(
        directory_entry_names(directory, "terminal root zone")?,
        retained,
        |name| remove_tree_member_at(directory, name, root_device, &mut visited),
    );
    let synced = directory
        .sync_all()
        .map_err(|error| format!("fsync retained root zone: {error}"));
    match (removed, synced) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(removal), Err(sync)) => Err(format!("{removal}; {sync}")),
    }
}

fn remove_entries_with(
    names: Vec<Vec<u8>>,
    retained: &[&[u8]],
    mut remove: impl FnMut(&[u8]) -> Result<(), String>,
) -> Result<(), String> {
    let mut errors = Vec::new();
    for name in names {
        if retained.contains(&name.as_slice()) {
            continue;
        }
        if let Err(error) = remove(&name) {
            errors.push(format!(
                "cleanup member {:?}: {error}",
                String::from_utf8_lossy(&name)
            ));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

pub(super) fn remove_ordinary_zone_entries(
    directories: &RetainedUninstallDirectories,
) -> Result<(), String> {
    let root = directories
        .root
        .metadata()
        .map_err(|error| format!("fstat retained root zone: {error}"))?;
    remove_directory_entries_except(
        &directories.root,
        root.dev(),
        &[
            b"voboost-uninstall",
            b"uninstall",
            b"recovery",
            b"root.json",
            b"operation.json",
            b"operation.lock",
        ],
    )
}

pub(super) fn reboot_terminal() -> Result<(), String> {
    // Terminal uninstall reboot with a forced fallback. The inherited property
    // handshake (sys.powerctl) is still attempted first so a healthy init
    // performs its graceful shutdown, but the emulator gate showed init's
    // post-uninstall shutdown wedging forever after volume shutdown, so the
    // direct reboot(2) syscall fires after a short grace window instead of
    // trusting set-property success.
    super::fixed_process::request_forced_reboot(Duration::from_secs(20))
        .map_err(|error| format!("predicate-bound uninstall reboot request failed: {error}"))
}

pub(super) fn openat_regular_nofollow(directory: &File, name: &str) -> Result<File, String> {
    let name = std::ffi::CString::new(name).map_err(|_| "fixed leaf contains NUL".to_string())?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(format!(
            "openat retained cleanup member: {}",
            std::io::Error::last_os_error()
        ));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    if !file
        .metadata()
        .map_err(|error| format!("fstat openat cleanup member: {error}"))?
        .file_type()
        .is_file()
    {
        return Err("openat cleanup member is not a regular file".to_string());
    }
    Ok(file)
}

pub(super) fn read_retained_bytes(
    file: &File,
    maximum: u64,
    label: &str,
) -> Result<TrustedBytes, String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("fstat retained {label}: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err(format!("retained {label} is not a regular file"));
    }
    let before = FileStamp::from(&metadata);
    if before.len == 0 || before.len > maximum {
        return Err(format!("retained {label} size is invalid"));
    }
    let mut reader = file
        .try_clone()
        .map_err(|error| format!("clone retained {label}: {error}"))?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("seek retained {label}: {error}"))?;
    let mut bytes = Vec::with_capacity(before.len as usize);
    reader
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read retained {label}: {error}"))?;
    let after = FileStamp::from(
        &file
            .metadata()
            .map_err(|error| format!("refstat retained {label}: {error}"))?,
    );
    if before != after || bytes.len() as u64 != before.len {
        return Err(format!("retained {label} changed while reading"));
    }
    Ok(TrustedBytes {
        bytes,
        stamp: before,
        selinux_context: Some(file_selinux_context(file)?),
    })
}

#[cfg(test)]
pub(super) fn retained_exchange_identity_matches(
    expected: FileStamp,
    retained: FileStamp,
    named_or_exchanged: FileStamp,
) -> bool {
    expected == retained && expected == named_or_exchanged
}

pub(super) fn unlinkat_retained(
    directory: &File,
    name: &str,
    retained: &File,
    expected: FileStamp,
    label: &str,
) -> Result<(), String> {
    let retained_now = FileStamp::from(
        &retained
            .metadata()
            .map_err(|error| format!("fstat retained {label}: {error}"))?,
    );
    let named = openat_regular_nofollow(directory, name)?;
    let named_stamp = FileStamp::from(
        &named
            .metadata()
            .map_err(|error| format!("fstatat named {label}: {error}"))?,
    );
    if retained_now != expected || named_stamp != expected {
        return Err(format!("{label} changed at native unlink boundary"));
    }
    let name = std::ffi::CString::new(name).map_err(|_| "fixed leaf contains NUL".to_string())?;
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(format!(
            "unlinkat {label}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod independent_cleanup_tests {
    use super::*;

    #[test]
    fn failed_member_does_not_block_siblings_or_remove_retained_members() {
        let mut removed = Vec::new();
        let result = remove_entries_with(
            [
                b"first".to_vec(),
                b"keep".to_vec(),
                b"second".to_vec(),
                b"third".to_vec(),
            ]
            .to_vec(),
            &[b"keep"],
            |name| {
                removed.push(name.to_vec());
                if name == b"second" {
                    Ok(())
                } else {
                    Err("denied".into())
                }
            },
        );
        assert_eq!(
            removed,
            [b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
        );
        let error = result.unwrap_err();
        assert!(error.contains("first"));
        assert!(error.contains("third"));
        assert!(!error.contains("second"));
        assert!(!error.contains("keep"));
    }
}
