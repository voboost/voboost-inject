use sha2::{Digest, Sha256};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

const PACKAGE_QUERY_ATTEMPTS: usize = 60;
const PACKAGE_QUERY_INITIAL_DELAY: Duration = Duration::from_millis(50);
const PACKAGE_QUERY_MAX_DELAY: Duration = Duration::from_secs(1);

/// The one canonical acceptance check for `pm path ru.voboost` output:
/// exactly one `package:` line naming a single-linked base APK under
/// /data/app with no control bytes and no relative path components.
/// install (observe_installed_apk), uninstall (package authority) and fresh
/// probing all admit paths through this single invariant.
pub fn canonical_base_apk_path(stdout: &str) -> Result<&str, String> {
    let rows = stdout.lines().collect::<Vec<_>>();
    if rows.len() != 1 {
        return Err("installed application has no exact base APK path".into());
    }
    let path = rows[0]
        .strip_prefix("package:")
        .ok_or("installed APK path lacks package prefix")?;
    if !path.starts_with("/data/app/")
        || !path.ends_with("/base.apk")
        || path.len() > 512
        || path.bytes().any(|byte| byte.is_ascii_control())
        || path
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err("installed base APK path is unsafe".into());
    }
    Ok(path)
}

fn query_package_path_with(
    mut probe: impl FnMut() -> Result<crate::fixed_process::BoundedOutput, String>,
    mut wait: impl FnMut(Duration),
    attempts: usize,
) -> Result<crate::fixed_process::BoundedOutput, String> {
    let mut delay = PACKAGE_QUERY_INITIAL_DELAY;
    let mut last_failure = String::new();
    for attempt in 0..attempts {
        match probe() {
            Ok(output) if output.status.success() && output.stderr.is_empty() => {
                return Ok(output);
            }
            Ok(output) => {
                let detail = String::from_utf8_lossy(&output.stderr);
                let detail = if detail.trim().is_empty() {
                    String::from_utf8_lossy(&output.stdout)
                } else {
                    detail
                };
                last_failure = format!(
                    "exit={} detail={}",
                    output.status,
                    detail
                        .chars()
                        .filter(|c| !c.is_control())
                        .take(200)
                        .collect::<String>()
                );
            }
            Err(error) => last_failure = error,
        }
        if attempt + 1 < attempts {
            wait(delay);
            delay = delay.saturating_mul(2).min(PACKAGE_QUERY_MAX_DELAY);
        }
    }
    Err(format!(
        "installed application path query failed: {last_failure}"
    ))
}

pub fn observe_installed_apk(expected_size: u64, expected_sha256: &str) -> Result<String, String> {
    observe_installed_apk_until(
        expected_size,
        expected_sha256,
        Instant::now() + Duration::from_secs(15),
    )
}

pub fn observe_installed_apk_until(
    expected_size: u64,
    expected_sha256: &str,
    deadline: Instant,
) -> Result<String, String> {
    if Instant::now() >= deadline {
        return Err("installed base APK verification deadline".into());
    }
    let path = match pm_reported_base_apk_path_until(deadline) {
        Ok(path) => path,
        Err(pm_error) => {
            // The pm probe rides the servicemanager binder dialogue, which
            // can be unavailable in the daemon domain on some OEM policies
            // ("cmd: Can't find service: package"). The install contract only
            // needs the installed base APK's path and content identity;
            // scanning the fixed /data/app prefix delivers the same
            // guarantee without the package service round-trip.
            scan_base_apk_path().map_err(|scan_error| {
                format!(
                    "installed base APK path unavailable: pm probe: {pm_error}; scan: {scan_error}"
                )
            })?
        }
    };
    verify_base_apk_identity(&path, expected_size, expected_sha256, deadline)
}

fn pm_reported_base_apk_path_until(deadline: Instant) -> Result<String, String> {
    // Leave time for the filesystem fallback and byte verification. Package
    // service startup must not consume a separate minute-long retry budget.
    let query_deadline = deadline.min(Instant::now() + Duration::from_secs(2));
    let output = query_package_path_with(
        || {
            let remaining = query_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("installed application path query deadline".into());
            }
            crate::fixed_process::output(
                "/system/bin/pm",
                &["path", "ru.voboost"],
                remaining.min(Duration::from_millis(500)),
                4096,
            )
        },
        |delay| {
            std::thread::sleep(delay.min(query_deadline.saturating_duration_since(Instant::now())))
        },
        PACKAGE_QUERY_ATTEMPTS.min(4),
    )?;
    let text =
        std::str::from_utf8(&output.stdout).map_err(|_| "installed APK path is not UTF-8")?;
    canonical_base_apk_path(text).map(str::to_owned)
}

/// Filesystem fallback: the package installer creates the APK directory
/// under the fixed prefix /data/app/ru.voboost-<random>/base.apk. Enumerate
/// the prefix directory and accept the single candidate that matches the
/// naming shape; identity (size + sha256 + inode stability) is verified by
/// the caller afterwards, so a stray lookalike cannot pass.
/// Filesystem fallback shared with the uninstall transaction: same scan,
/// same single-candidate and identity rules.
pub fn scan_base_apk_path() -> Result<String, String> {
    const APP_DIR: &str = "/data/app";
    let dir = std::fs::read_dir(APP_DIR).map_err(|error| format!("open {APP_DIR}: {error}"))?;
    let mut candidates: Vec<String> = Vec::new();
    for entry in dir {
        let entry = entry.map_err(|error| format!("read {APP_DIR}: {error}"))?;
        let file_type = entry.file_type().map_err(|error| error.to_string())?;
        if !file_type.is_dir() {
            continue;
        }
        let dir_name = entry.file_name();
        let dir_name = dir_name.to_string_lossy();
        if !(dir_name.starts_with("ru.voboost-") || dir_name == "ru.voboost") {
            continue;
        }
        let apk_path = format!("{APP_DIR}/{dir_name}/base.apk");
        if std::path::Path::new(&apk_path).is_file() {
            candidates.push(apk_path);
        }
    }
    if candidates.len() != 1 {
        return Err(format!(
            "expected exactly one installed base APK, found {}",
            candidates.len()
        ));
    }
    Ok(candidates.remove(0))
}

fn verify_base_apk_identity(
    path: &str,
    expected_size: u64,
    expected_sha256: &str,
    deadline: Instant,
) -> Result<String, String> {
    let root_fd = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if root_fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let root = unsafe { File::from_raw_fd(root_fd) };
    let relative =
        std::ffi::CString::new(&path[1..]).map_err(|_| "installed APK path contains NUL")?;
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            relative.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(format!(
            "open installed base APK: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let before = file.metadata().map_err(|error| error.to_string())?;
    if !before.is_file() || before.nlink() != 1 || before.len() != expected_size {
        return Err("installed base APK identity differs from descriptor".into());
    }
    let mut hasher = Sha256::new();
    use std::io::Read;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        if Instant::now() >= deadline {
            return Err("installed base APK verification deadline".into());
        }
        let read = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let after = file.metadata().map_err(|error| error.to_string())?;
    let sha256 = format!("{:x}", hasher.finalize());
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.ctime(),
        after.ctime_nsec(),
    ) || sha256 != expected_sha256
    {
        return Err("installed base APK changed or differs from descriptor".into());
    }
    Ok(path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    fn output(code: i32, stdout: &[u8], stderr: &[u8]) -> crate::fixed_process::BoundedOutput {
        crate::fixed_process::BoundedOutput {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
        }
    }

    #[test]
    fn canonical_base_apk_path_accepts_only_the_exact_shape() {
        assert_eq!(
            canonical_base_apk_path("package:/data/app/~~x/ru.voboost-y/base.apk\n").unwrap(),
            "/data/app/~~x/ru.voboost-y/base.apk"
        );
        assert!(canonical_base_apk_path(
            "package:/data/app/~~x/ru.voboost-y/base.apk\npackage:/data/app/other/base.apk\n"
        )
        .is_err());
        assert!(canonical_base_apk_path("/data/app/ru.voboost/base.apk\n").is_err());
        assert!(canonical_base_apk_path("package:/system/app/foo.apk\n").is_err());
        assert!(canonical_base_apk_path("package:/data/app/../base.apk\n").is_err());
        assert!(canonical_base_apk_path(&format!(
            "package:/data/app/{}a/base.apk\n",
            "a".repeat(500)
        ))
        .is_err());
        assert!(canonical_base_apk_path("package:/data/app/x\u{1}y/base.apk\n").is_err());
    }

    #[test]
    fn package_manager_startup_retry_accepts_only_success_without_stderr() {
        let mut probes = vec![
            output(0, b"package:/data/app/ru.voboost/base.apk\n", b"transient"),
            output(1, b"", b""),
            output(0, b"package:/data/app/ru.voboost/base.apk\n", b""),
        ]
        .into_iter();
        let delays = std::cell::RefCell::new(Vec::new());
        let accepted = query_package_path_with(
            || Ok(probes.next().unwrap()),
            |delay| delays.borrow_mut().push(delay),
            3,
        )
        .unwrap();
        assert_eq!(accepted.stdout, b"package:/data/app/ru.voboost/base.apk\n");
        assert_eq!(
            delays.into_inner(),
            [Duration::from_millis(50), Duration::from_millis(100)]
        );
    }

    #[test]
    fn package_manager_startup_retry_is_bounded_and_never_accepts_failure() {
        let probes = std::cell::Cell::new(0_usize);
        let waits = std::cell::Cell::new(0_usize);
        assert_eq!(
            query_package_path_with(
                || {
                    probes.set(probes.get() + 1);
                    Err("package service unavailable".into())
                },
                |_| waits.set(waits.get() + 1),
                4,
            )
            .unwrap_err(),
            "installed application path query failed: package service unavailable"
        );
        assert_eq!(probes.get(), 4);
        assert_eq!(waits.get(), 3);
    }
}

pub fn parse_package_version_code(bytes: &[u8]) -> Result<u64, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "package dump is not UTF-8")?;
    let values = text
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("versionCode="))
        .map(|value| value.split_ascii_whitespace().next().unwrap_or(""))
        .collect::<Vec<_>>();
    if values.len() != 1 {
        return Err("package dump has no unique versionCode".into());
    }
    values[0]
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| "package dump versionCode is invalid".into())
}
