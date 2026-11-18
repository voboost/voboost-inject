//! Read-only block protection around a verified filesystem remount.

#[cfg(any(target_os = "android", target_os = "linux"))]
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

#[derive(Clone, Copy)]
pub struct BlockIdentityRef<'a> {
    pub source: &'a str,
    pub major_minor: &'a str,
    pub fs_type: &'a str,
}

#[cfg(any(target_os = "android", target_os = "linux", test))]
fn valid_device_identity(expected: &str, uid: u32, block: bool, major: i64, minor: i64) -> bool {
    uid == 0 && block && major >= 0 && minor >= 0 && expected == format!("{major}:{minor}")
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn open_device(id: BlockIdentityRef<'_>) -> Result<File, String> {
    let Some((major, minor)) = id.major_minor.split_once(':') else {
        return Err("invalid selected block identity".into());
    };
    let (Ok(major), Ok(minor)) = (major.parse::<u32>(), minor.parse::<u32>()) else {
        return Err("invalid selected block identity".into());
    };
    if id.major_minor != format!("{major}:{minor}") {
        return Err("noncanonical selected block identity".into());
    }
    let path = match fs::canonicalize(id.source) {
        Ok(path) => path,
        Err(error) if id.source == "/dev/root" && error.kind() == std::io::ErrorKind::NotFound => {
            let mut bytes = Vec::new();
            File::open(format!("/sys/dev/block/{}/uevent", id.major_minor))
                .map_err(|error| format!("open root block identity: {error}"))?
                .take(4097)
                .read_to_end(&mut bytes)
                .map_err(|error| error.to_string())?;
            if bytes.len() > 4096 {
                return Err("root block identity is oversized".into());
            }
            let text =
                std::str::from_utf8(&bytes).map_err(|_| "root block identity is not UTF-8")?;
            fs::canonicalize(Path::new("/dev/block").join(device_name(text)?))
                .map_err(|error| format!("resolve root block device: {error}"))?
        }
        Err(error) => return Err(format!("resolve protected block device: {error}")),
    };
    if !path.starts_with("/dev/block") {
        return Err("protected block device escaped /dev/block".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("open protected block device: {error}"))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    #[cfg(all(target_os = "android", target_pointer_width = "32"))]
    let device: libc::dev_t = metadata
        .rdev()
        .try_into()
        .map_err(|_| "protected block device number exceeds native dev_t")?;
    #[cfg(not(all(target_os = "android", target_pointer_width = "32")))]
    let device = metadata.rdev();
    if !valid_device_identity(
        id.major_minor,
        metadata.uid(),
        metadata.file_type().is_block_device(),
        i64::from(libc::major(device)),
        i64::from(libc::minor(device)),
    ) {
        return Err("protected block device differs from selected mount".into());
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
        return Err("root block DEVNAME is invalid".into());
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
        _ => Err("protected block read-only flag is invalid".into()),
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
            return Err("protected block read-only flag did not change".into());
        }
    }
    Ok(())
}

pub fn capture(id: BlockIdentityRef<'_>) -> Result<Option<bool>, String> {
    if matches!(id.fs_type, "ext4" | "f2fs") {
        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            return read_only(&open_device(id)?).map(Some);
        }
        #[cfg(not(any(target_os = "android", target_os = "linux")))]
        {
            return Err("protected block capture requires Linux".into());
        }
    }
    Ok(None)
}

pub fn remount(
    id: BlockIdentityRef<'_>,
    ro: bool,
    original: Option<bool>,
    mut mount: impl FnMut(bool) -> Result<(), String>,
) -> Result<(), String> {
    if matches!(id.fs_type, "ext4" | "f2fs") {
        let original = original.ok_or("missing journaled block protection")?;
        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            let file = open_device(id)?;
            return remount_with(ro, original, |value| set_read_only(&file, value), mount);
        }
        #[cfg(not(any(target_os = "android", target_os = "linux")))]
        {
            let _ = original;
            return Err("protected block remount requires Linux".into());
        }
    }
    mount(ro)
}

/// Restore the original block flag only after the filesystem is read-only.
/// The caller must validate the device identity before supplying `protect`.
#[cfg(any(target_os = "android", target_os = "linux", test))]
fn remount_with(
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
        Err(error) => match remount(true).and_then(|()| protect(original)) {
            Ok(()) => Err(error),
            Err(recovery) => Err(format!("{error}; block protection restore: {recovery}")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn readonly_block_must_be_unlocked_before_writable_mount() {
        let state = RefCell::new((true, true));
        let protect = |ro| {
            state.borrow_mut().0 = ro;
            Ok(())
        };
        let mount = |ro: bool| {
            let mut state = state.borrow_mut();
            if !ro && state.0 {
                return Err("EACCES".into());
            }
            state.1 = ro;
            Ok(())
        };
        remount_with(false, true, protect, mount).unwrap();
        assert_eq!(*state.borrow(), (false, false));
        remount_with(true, true, protect, mount).unwrap();
        assert_eq!(*state.borrow(), (true, true));
    }

    #[test]
    fn failed_readonly_mount_never_reprotects_writable_filesystem() {
        let protected = RefCell::new(false);
        assert!(remount_with(
            true,
            true,
            |ro| {
                *protected.borrow_mut() = ro;
                Ok(())
            },
            |_| Err("RO failed".into())
        )
        .is_err());
        assert!(!*protected.borrow());
    }

    #[test]
    fn original_writable_block_stays_writable_after_filesystem_closes() {
        let events = RefCell::new(Vec::new());
        remount_with(
            true,
            false,
            |ro| {
                events.borrow_mut().push(("block", ro));
                Ok(())
            },
            |ro| {
                events.borrow_mut().push(("mount", ro));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(*events.borrow(), [("mount", true), ("block", false)]);
    }

    #[test]
    fn unlock_failure_prevents_any_writable_mount() {
        let called = RefCell::new(false);
        assert_eq!(
            remount_with(
                false,
                true,
                |_| Err("unlock failed".into()),
                |_| {
                    *called.borrow_mut() = true;
                    Ok(())
                }
            )
            .unwrap_err(),
            "unlock failed"
        );
        assert!(!*called.borrow());
    }

    #[test]
    fn failed_writable_mount_closes_before_restoring_original_and_retains_errors() {
        let events = RefCell::new(Vec::new());
        let error = remount_with(
            false,
            true,
            |ro| {
                events.borrow_mut().push(("block", ro));
                if ro {
                    Err("protection failed".into())
                } else {
                    Ok(())
                }
            },
            |ro| {
                events.borrow_mut().push(("mount", ro));
                if ro {
                    Ok(())
                } else {
                    Err("RW failed".into())
                }
            },
        )
        .unwrap_err();
        assert_eq!(
            *events.borrow(),
            [
                ("block", false),
                ("mount", false),
                ("mount", true),
                ("block", true)
            ]
        );
        assert!(error.contains("RW failed") && error.contains("protection failed"));
    }

    #[test]
    fn absent_original_never_grants_writable_block_authority() {
        let called = RefCell::new(false);
        let id = BlockIdentityRef {
            source: "/dev/block/not-opened",
            major_minor: "1:2",
            fs_type: "ext4",
        };
        assert_eq!(
            remount(id, false, None, |_| {
                *called.borrow_mut() = true;
                Ok(())
            })
            .unwrap_err(),
            "missing journaled block protection"
        );
        assert!(!*called.borrow());
    }

    #[test]
    fn root_identity_rejects_path_and_ambiguous_names() {
        assert_eq!(device_name("MAJOR=254\nDEVNAME=vda1\n").unwrap(), "vda1");
        for invalid in [
            "",
            "DEVNAME=../vda1",
            "DEVNAME=/dev/block/vda1",
            "DEVNAME=..",
            "DEVNAME=vda1\nDEVNAME=vda2",
            "DEVNAME=vda1\0",
        ] {
            assert!(device_name(invalid).is_err());
        }
    }

    #[test]
    fn identity_mismatch_never_matches_selected_block() {
        assert!(valid_device_identity("253:65", 0, true, 253, 65));
        assert!(!valid_device_identity("253:65", 1, true, 253, 65));
        assert!(!valid_device_identity("253:65", 0, false, 253, 65));
        assert!(!valid_device_identity("253:65", 0, true, 253, 66));
        assert!(!valid_device_identity("253:65/../../x", 0, true, 253, 65));
    }

    #[test]
    fn recovery_after_cut_between_unlock_and_mount_restores_both_flags() {
        let state = RefCell::new((true, true));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            remount_with(
                false,
                true,
                |ro| {
                    state.borrow_mut().0 = ro;
                    Ok(())
                },
                |_| panic!("cut after unlock"),
            )
            .unwrap();
        }));
        assert!(result.is_err());
        assert_eq!(*state.borrow(), (false, true));
        remount_with(
            true,
            true,
            |ro| {
                state.borrow_mut().0 = ro;
                Ok(())
            },
            |ro| {
                state.borrow_mut().1 = ro;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(*state.borrow(), (true, true));
    }
}
