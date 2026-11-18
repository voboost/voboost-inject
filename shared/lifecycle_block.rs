use super::*;

#[cfg(any(target_os = "android", target_os = "linux"))]
fn open_device(mount: &RequiredMount) -> Result<File, String> {
    let path = match fs::canonicalize(&mount.source) {
        Ok(path) => path,
        Err(error)
            if mount.source == "/dev/root" && error.kind() == std::io::ErrorKind::NotFound =>
        {
            // mountinfo uses /dev/root even when no such device node exists.
            // Kernel-owned uevent identifies the node; fstat must still match
            // the exact selected mount's major/minor before any ioctl.
            let path = format!("/sys/dev/block/{}/uevent", mount.major_minor);
            let mut bytes = Vec::new();
            File::open(path)
                .map_err(|error| format!("open root block identity: {error}"))?
                .take(4097)
                .read_to_end(&mut bytes)
                .map_err(|error| format!("read root block identity: {error}"))?;
            if bytes.len() > 4096 {
                return Err("root block identity is oversized".to_string());
            }
            let text =
                std::str::from_utf8(&bytes).map_err(|_| "root block identity is not UTF-8")?;
            let name = device_name(text)?;
            fs::canonicalize(Path::new("/dev/block").join(name))
                .map_err(|error| format!("resolve root block device: {error}"))?
        }
        Err(error) => return Err(format!("resolve protected block device: {error}")),
    };
    if !path.starts_with("/dev/block") {
        return Err("protected block device escaped /dev/block".to_string());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("open protected block device: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("stat protected block device: {error}"))?;
    if metadata.uid() != 0
        || !metadata.file_type().is_block_device()
        || format!(
            "{}:{}",
            libc::major(metadata.rdev()),
            libc::minor(metadata.rdev())
        ) != mount.major_minor
    {
        return Err("protected block device differs from selected mount".to_string());
    }
    Ok(file)
}

#[cfg(any(target_os = "android", target_os = "linux", test))]
fn device_name(text: &str) -> Result<&str, String> {
    let mut names = text
        .lines()
        .filter_map(|line| line.strip_prefix("DEVNAME="));
    let name = names.next().ok_or("root block identity lacks DEVNAME")?;
    if names.next().is_some()
        || name.is_empty()
        || name.len() > 128
        || matches!(name, "." | "..")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err("root block DEVNAME is invalid".to_string());
    }
    Ok(name)
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn read_only(file: &File) -> Result<bool, String> {
    let mut value: libc::c_int = -1;
    if unsafe { libc::ioctl(file.as_raw_fd(), 0x125e as _, &mut value) } != 0 {
        return Err(format!(
            "read protected block read-only flag: {}",
            std::io::Error::last_os_error()
        ));
    }
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err("protected block read-only flag is invalid".to_string()),
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn set_read_only(file: &File, expected: bool) -> Result<(), String> {
    if read_only(file)? != expected {
        let value: libc::c_int = i32::from(expected);
        if unsafe { libc::ioctl(file.as_raw_fd(), 0x125d as _, &value) } != 0 {
            return Err(format!(
                "set protected block read-only flag: {}",
                std::io::Error::last_os_error()
            ));
        }
        if read_only(file)? != expected {
            return Err("protected block read-only flag did not change".to_string());
        }
    }
    Ok(())
}

pub(super) fn capture(mount: &RequiredMount) -> Result<Option<bool>, String> {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    if matches!(mount.fs_type.as_str(), "ext4" | "f2fs") {
        return read_only(&open_device(mount)?).map(Some);
    }
    let _ = mount;
    Ok(None)
}

pub(super) fn remount(
    mount: &RequiredMount,
    ro: bool,
    original: Option<bool>,
) -> Result<(), String> {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    if let Some(original) = original {
        let file = open_device(mount)?;
        return protected_remount_with(
            ro,
            original,
            |value| set_read_only(&file, value),
            |value| remount_boundary(mount, value),
        );
    }
    let _ = original;
    remount_boundary(mount, ro)
}

#[cfg(any(target_os = "android", target_os = "linux", test))]
fn protected_remount_with(
    ro: bool,
    original: bool,
    mut protect: impl FnMut(bool) -> Result<(), String>,
    mut remount: impl FnMut(bool) -> Result<(), String>,
) -> Result<(), String> {
    if ro {
        remount(true)?;
        return protect(original);
    }
    protect(false)?;
    match remount(false) {
        Ok(()) => Ok(()),
        Err(error) => {
            let recovery = remount(true).and_then(|()| protect(original));
            match recovery {
                Ok(()) => Err(error),
                Err(recovery) => Err(format!("{error}; block protection restore: {recovery}")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn readonly_block_is_unlocked_before_rw_and_restored_after_ro() {
        let state = RefCell::new((true, true));
        let protect = |ro| {
            state.borrow_mut().0 = ro;
            Ok(())
        };
        let remount = |ro: bool| {
            let mut state = state.borrow_mut();
            if !ro && state.0 {
                return Err("Permission denied".to_string());
            }
            state.1 = ro;
            Ok(())
        };
        protected_remount_with(false, true, protect, remount).unwrap();
        assert_eq!(*state.borrow(), (false, false));
        protected_remount_with(true, true, protect, remount).unwrap();
        assert_eq!(*state.borrow(), (true, true));
    }

    #[test]
    fn failed_rw_restores_original_block_flag_and_preserves_both_errors() {
        for original in [false, true] {
            let events = RefCell::new(Vec::new());
            let result = protected_remount_with(
                false,
                original,
                |ro| {
                    events.borrow_mut().push(format!("block:{ro}"));
                    Ok(())
                },
                |ro| {
                    events.borrow_mut().push(format!("mount:{ro}"));
                    if ro {
                        Ok(())
                    } else {
                        Err("RW failed".to_string())
                    }
                },
            );
            assert_eq!(result.unwrap_err(), "RW failed");
            assert_eq!(
                *events.borrow(),
                [
                    "block:false",
                    "mount:false",
                    "mount:true",
                    &format!("block:{original}")
                ]
            );
        }
        let result = protected_remount_with(
            false,
            true,
            |_| Ok(()),
            |ro| Err(if ro { "RO failed" } else { "RW failed" }.to_string()),
        );
        let error = result.unwrap_err();
        assert!(error.contains("RW failed") && error.contains("RO failed"));
    }

    #[test]
    fn root_block_name_cannot_supply_paths_or_ambiguous_identity() {
        assert_eq!(
            device_name("MAJOR=254\nMINOR=1\nDEVNAME=vda1\n").unwrap(),
            "vda1"
        );
        for invalid in [
            "",
            "DEVNAME=../vda1",
            "DEVNAME=/dev/block/vda1",
            "DEVNAME=..",
            "DEVNAME=vda1\nDEVNAME=vda2",
            "DEVNAME=vda1\0",
        ] {
            assert!(device_name(invalid).is_err(), "{invalid:?}");
        }
    }
}
