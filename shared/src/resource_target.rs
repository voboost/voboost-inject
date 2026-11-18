//! Fixed package discovery with descriptor-relative, no-symlink OEM APK traversal.
use std::{
    ffi::CString,
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    time::Duration,
};

pub fn canonical_target_path(output: &str) -> Result<&str, String> {
    let rows = output.lines().collect::<Vec<_>>();
    if rows.len() != 1 {
        return Err("OEM target requires one installed APK".into());
    }
    let path = rows[0]
        .strip_prefix("package:")
        .ok_or("OEM target prefix absent")?;
    validate_target_path(path)?;
    Ok(path)
}

pub fn validate_target_path(path: &str) -> Result<(), String> {
    if path.len() > 512
        || !path.ends_with(".apk")
        || !["/system/", "/vendor/", "/product/", "/odm/", "/system_ext/"]
            .iter()
            .any(|p| path.starts_with(p))
        || path.bytes().any(|b| b.is_ascii_control())
        || path
            .split('/')
            .skip(1)
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err("OEM target APK path unsafe".into());
    }
    Ok(())
}

pub fn open_target_path(path: &str) -> Result<File, String> {
    validate_target_path(path)?;
    let fd = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let parent = unsafe { File::from_raw_fd(fd) };
    let parts = path.split('/').skip(1).collect::<Vec<_>>();
    open_components(parent, &parts, 0)
}

fn open_components(mut parent: File, parts: &[&str], owner: u32) -> Result<File, String> {
    for (i, part) in parts.iter().enumerate() {
        let last = i + 1 == parts.len();
        let name = CString::new(*part).map_err(|_| "OEM target path NUL")?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | if last { 0 } else { libc::O_DIRECTORY },
            )
        };
        if fd < 0 {
            return Err(format!(
                "open OEM target component: {}",
                std::io::Error::last_os_error()
            ));
        }
        let next = unsafe { File::from_raw_fd(fd) };
        let meta = next.metadata().map_err(|e| e.to_string())?;
        if meta.uid() != owner
            || meta.mode() & 0o022 != 0
            || if last {
                !meta.is_file() || meta.nlink() != 1 || meta.len() == 0
            } else {
                !meta.is_dir()
            }
        {
            return Err("OEM target component ownership or mode unsafe".into());
        }
        parent = next;
    }
    Ok(parent)
}

pub fn discover_target(package: &str) -> Result<(String, File), String> {
    if package != "com.qinggan.app.setting" {
        return Err("unsupported OEM target package".into());
    }
    let output = crate::fixed_process::output(
        "/system/bin/pm",
        &["path", "com.qinggan.app.setting"],
        Duration::from_secs(5),
        4096,
    )?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err("OEM package path query failed".into());
    }
    let text = std::str::from_utf8(&output.stdout).map_err(|_| "OEM target path UTF-8 invalid")?;
    let path = canonical_target_path(text)?.to_owned();
    let file = open_target_path(&path)?;
    Ok((path, file))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_walk_rejects_links_writable_parents_and_special_files() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let project = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.work162");
        let temp = tempfile::Builder::new()
            .prefix("i18n-target-")
            .tempdir_in(project)
            .unwrap();
        let dir = temp.path().join("Setting");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let apk = dir.join("Setting.apk");
        std::fs::write(&apk, b"target-fixture").unwrap();
        std::fs::set_permissions(&apk, std::fs::Permissions::from_mode(0o644)).unwrap();
        let open = || {
            open_components(
                File::open(temp.path()).unwrap(),
                &["Setting", "Setting.apk"],
                unsafe { libc::geteuid() },
            )
        };
        assert_eq!(open().unwrap().metadata().unwrap().len(), 14);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(open().is_err());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::rename(&apk, dir.join("retained.apk")).unwrap();
        symlink("retained.apk", &apk).unwrap();
        assert!(open().is_err());
        std::fs::remove_file(&apk).unwrap();
        std::fs::hard_link(dir.join("retained.apk"), &apk).unwrap();
        assert!(open().is_err());
        std::fs::remove_file(&apk).unwrap();
        let name = CString::new(apk.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(open().is_err());
        std::fs::remove_file(&apk).unwrap();
        std::fs::rename(&dir, temp.path().join("Original")).unwrap();
        symlink("Original", &dir).unwrap();
        assert!(open().is_err());
    }
    #[test]
    fn exact_reported_oem_path_only() {
        assert_eq!(
            canonical_target_path("package:/system/priv-app/Setting/Setting.apk\n").unwrap(),
            "/system/priv-app/Setting/Setting.apk"
        );
        for text in [
            "",
            "package:/system/../data/app/base.apk",
            "package:/data/app/Setting.apk",
            "package:/system//Setting.apk",
            "package:/system/Setting.apk\npackage:/system/split.apk",
            "package:/system/Setting.apk\0",
        ] {
            assert!(canonical_target_path(text).is_err(), "{text:?}");
        }
    }
}
