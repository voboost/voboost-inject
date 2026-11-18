//! Wait for the real writable data mount before opening persistent stores.
use std::io::{self, Read};
use std::time::{Duration, Instant};

#[cfg(any(target_os = "android", target_os = "linux"))]
pub(super) fn boot_ms() -> io::Result<u64> {
    let mut time: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let seconds = u64::try_from(time.tv_sec).map_err(io::Error::other)?;
    let nanos = u64::try_from(time.tv_nsec).map_err(io::Error::other)?;
    if nanos >= 1_000_000_000 {
        return Err(io::Error::other("invalid boot clock nanoseconds"));
    }
    seconds
        .checked_mul(1000)
        .and_then(|ms| ms.checked_add(nanos / 1_000_000))
        .ok_or_else(|| io::Error::other("boot clock exceeds bound"))
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
pub(super) fn boot_ms() -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "kernel boot clock unavailable",
    ))
}

fn data_mounted(bytes: &[u8]) -> io::Result<bool> {
    let text = std::str::from_utf8(bytes).map_err(io::Error::other)?;
    let mut found = None;
    for line in text.lines() {
        let Some((mount, filesystem)) = line.split_once(" - ") else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid mountinfo",
            ));
        };
        let fields: Vec<_> = mount.split_ascii_whitespace().collect();
        if fields.len() < 6 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "incomplete mountinfo",
            ));
        }
        if fields[4] == "/data" {
            if found.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ambiguous data mount",
                ));
            }
            let filesystem: Vec<_> = filesystem.split_ascii_whitespace().collect();
            if filesystem.len() < 3 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "incomplete data filesystem",
                ));
            }
            found = Some(
                fields[5].split(',').any(|flag| flag == "rw")
                    && filesystem[2].split(',').any(|flag| flag == "rw"),
            );
        }
    }
    Ok(found.unwrap_or(false))
}

pub(super) fn wait_data(stopped: impl Fn() -> bool) -> io::Result<bool> {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if stopped() {
            return Ok(false);
        }
        let mut bytes = Vec::new();
        std::fs::File::open("/proc/self/mountinfo")?
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mountinfo exceeds bound",
            ));
        }
        if data_mounted(&bytes)? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "data mount unavailable",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn root_directory_or_readonly_data_cannot_admit_persistent_writes() {
        let root = b"16 0 253:0 / / ro,relatime - ext4 /dev/root ro\n";
        assert!(!data_mounted(root).unwrap());
        assert!(
            !data_mounted(b"35 16 253:16 / /data ro,nodev - ext4 /dev/block/vdb ro\n").unwrap()
        );
        assert!(data_mounted(b"35 16 253:16 / /data rw,nodev - ext4 /dev/block/vdb rw\n").unwrap());
        assert!(
            !data_mounted(b"35 16 253:16 / /data-other rw - ext4 /dev/block/vdb rw\n").unwrap()
        );
    }
    #[test]
    fn ambiguous_or_truncated_mount_table_is_not_ready() {
        let line = "35 16 253:16 / /data rw - ext4 /dev/block/vdb rw\n";
        assert!(data_mounted(format!("{line}{line}").as_bytes()).is_err());
        assert!(data_mounted(b"35 16 /data rw\n").is_err());
        assert!(data_mounted(&[255]).is_err());
        assert!(!data_mounted(b"35 16 253:16 / /data rw - ext4 /dev/block/vdb ro\n").unwrap());
        assert!(data_mounted(b"35 16 253:16 / /data rw - ext4\n").is_err());
    }
    #[test]
    fn stopping_before_data_wait_does_not_open_persistent_files() {
        assert!(!wait_data(|| true).unwrap());
    }
}
