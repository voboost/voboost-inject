use super::*;
static CHILD_TOUCHED: AtomicBool = AtomicBool::new(false);
fn failed_setup() -> std::io::Result<()> {
    CHILD_TOUCHED.store(true, Ordering::Relaxed);
    Err(std::io::Error::from_raw_os_error(libc::EACCES))
}
fn successful_setup() -> std::io::Result<()> {
    CHILD_TOUCHED.store(true, Ordering::Relaxed);
    Ok(())
}
fn marker_command(
    setup: fn() -> std::io::Result<()>,
) -> (Result<BoundedOutput, String>, tempfile::TempDir) {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let marker = directory.path().join("executed");
    let result = run_with_setup(
        "/bin/sh",
        &[
            "-c",
            "printf executed > \"$1\"",
            "_",
            marker.to_str().unwrap(),
        ],
        None,
        Duration::from_secs(2),
        1024,
        None,
        Some(setup),
    );
    (result, directory)
}
#[test]
fn failed_child_setup_never_executes_and_does_not_touch_parent() {
    let (result, directory) = marker_command(failed_setup);
    assert!(result.is_err());
    assert!(!directory.path().join("executed").exists());
    assert!(!CHILD_TOUCHED.load(Ordering::Relaxed));
}
#[test]
fn successful_child_setup_executes_without_touching_parent() {
    let (result, directory) = marker_command(successful_setup);
    assert!(result.unwrap().status.success());
    assert_eq!(
        std::fs::read(directory.path().join("executed")).unwrap(),
        b"executed"
    );
    assert!(!CHILD_TOUCHED.load(Ordering::Relaxed));
}
#[cfg(not(any(target_os = "android", target_os = "linux")))]
#[test]
fn unsupported_capability_abi_fails_before_exec() {
    let (result, directory) = marker_command(crate::child_privileges::drop_for_exec);
    assert!(result.is_err());
    assert!(!directory.path().join("executed").exists());
}
#[cfg(target_os = "linux")]
#[test]
fn linux_child_masks_are_zero_and_parent_keeps_its_masks() {
    fn fields(bytes: &str) -> Vec<&str> {
        bytes
            .lines()
            .filter(|line| {
                ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:", "NoNewPrivs:"]
                    .iter()
                    .any(|prefix| line.starts_with(prefix))
            })
            .collect()
    }
    let before = std::fs::read_to_string("/proc/self/status").unwrap();
    let result = run_with_setup(
        "/bin/cat",
        &["/proc/self/status"],
        None,
        Duration::from_secs(2),
        64 * 1024,
        None,
        Some(crate::child_privileges::drop_for_exec),
    )
    .unwrap();
    assert!(result.status.success());
    let child = String::from_utf8(result.stdout).unwrap();
    let found = fields(&child);
    assert_eq!(found.len(), 5);
    for line in found {
        let (name, value) = line.split_once(':').unwrap();
        assert_eq!(
            value.trim(),
            if name == "NoNewPrivs" {
                "1"
            } else {
                "0000000000000000"
            }
        );
    }
    let after = std::fs::read_to_string("/proc/self/status").unwrap();
    assert_eq!(fields(&before), fields(&after));
}
