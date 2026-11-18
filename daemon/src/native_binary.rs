//! Verification of role-signed native executables.

use std::fs::{Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::native_executable_signature::NativeExecutableRole;

#[cfg(test)]
const SIGNATURE_TRAILER_BYTES: usize = 80;
#[cfg(test)]
const SIGNATURE_MAGIC: [u8; 8] = *b"VOBOOST\0";
const READ_CHUNK_BYTES: usize = 16 * 1024;

pub(crate) fn verify_appended_signature(role: NativeExecutableRole, bytes: &[u8]) -> bool {
    crate::native_executable_signature::verify(&crate::trust::NATIVE_EXECUTABLE_PUBKEY, role, bytes)
}

/// Re-authenticate the exact executable backing this process before entering a
/// privileged daemon mode such as `--logs`.
pub(crate) fn verify_current_role(role: NativeExecutableRole) -> Result<(), String> {
    let path = Path::new("/proc/self/exe");
    let metadata =
        std::fs::metadata(path).map_err(|error| format!("inspect current executable: {error}"))?;
    let size = usize::try_from(metadata.len())
        .map_err(|_| "current executable is too large".to_string())?;
    if size == 0 || size > crate::config::MAX_NATIVE_EXECUTABLE_BYTES {
        return Err("current executable size is outside the trusted envelope".to_string());
    }
    let bytes = std::fs::read(path).map_err(|error| format!("read current executable: {error}"))?;
    if bytes.len() != size || !verify_appended_signature(role, &bytes) {
        return Err("current executable role signature rejected".to_string());
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
struct RunningExecutableStamp {
    device: u64,
    inode: u64,
    size: u64,
    links: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl From<&Metadata> for RunningExecutableStamp {
    fn from(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            links: metadata.nlink(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

pub(crate) fn verify_running(
    path: &Path,
    expected_size: usize,
    expected_sha256: &str,
) -> Result<(), String> {
    if expected_size == 0 || expected_size > crate::config::MAX_NATIVE_EXECUTABLE_BYTES {
        return Err("running daemon signed size is outside the bound".to_string());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("open running daemon identity: {error}"))?;
    let before = file
        .metadata()
        .map_err(|error| format!("stat running daemon identity: {error}"))?;
    if !before.file_type().is_file()
        || before.nlink() != 1
        || before.uid() != unsafe { libc::geteuid() }
        || before.gid() != unsafe { libc::getegid() }
        || before.len() != expected_size as u64
        || before.permissions().mode() & 0o777 != 0o700
    {
        return Err("running daemon descriptor metadata rejected".to_string());
    }
    running_executable_post_stat_cut(path)?;
    let mut hasher = Sha256::new();
    let mut total = 0usize;
    let mut chunk = [0u8; READ_CHUNK_BYTES];
    loop {
        let read = file
            .read(&mut chunk)
            .map_err(|error| format!("read running daemon identity: {error}"))?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read);
        if total > expected_size {
            return Err("running daemon grew while hashing".to_string());
        }
        hasher.update(&chunk[..read]);
    }
    let after = file
        .metadata()
        .map_err(|error| format!("restat running daemon identity: {error}"))?;
    if RunningExecutableStamp::from(&before) != RunningExecutableStamp::from(&after)
        || total != expected_size
        || format!("{:x}", hasher.finalize()) != expected_sha256
    {
        return Err("running daemon exact descriptor identity rejected".to_string());
    }
    Ok(())
}

#[cfg(not(test))]
fn running_executable_post_stat_cut(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
thread_local! {
    static GROW_RUNNING_EXECUTABLE_AFTER_STAT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn running_executable_post_stat_cut(path: &Path) -> Result<(), String> {
    GROW_RUNNING_EXECUTABLE_AFTER_STAT.with(|enabled| {
        if !enabled.replace(false) {
            return Ok(());
        }
        use std::io::Write;
        let mut file = OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(|error| format!("grow running daemon test identity: {error}"))?;
        file.write_all(b"x")
            .map_err(|error| format!("grow running daemon test identity: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::fs;
    use tempfile::tempdir;

    const NATIVE_EXECUTABLE_SEED: [u8; 32] =
        hex_literal("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");

    const fn hex_literal(value: &str) -> [u8; 32] {
        let bytes = value.as_bytes();
        let mut output = [0u8; 32];
        let mut index = 0;
        while index < 32 {
            output[index] = (nibble(bytes[index * 2]) << 4) | nibble(bytes[index * 2 + 1]);
            index += 1;
        }
        output
    }

    const fn nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid fixture hex"),
        }
    }

    fn signed(role: NativeExecutableRole, prefix: &[u8]) -> Vec<u8> {
        let transcript = crate::native_executable_signature::transcript(role, prefix).unwrap();
        let signature = SigningKey::from_bytes(&NATIVE_EXECUTABLE_SEED)
            .sign(&transcript)
            .to_bytes();
        let mut bytes = prefix.to_vec();
        bytes.extend_from_slice(&SIGNATURE_MAGIC);
        bytes.extend_from_slice(&(prefix.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&signature);
        bytes
    }

    #[test]
    fn appended_signature_is_role_separated_and_exact() {
        let bytes = signed(NativeExecutableRole::Daemon, b"daemon");
        assert!(verify_appended_signature(
            NativeExecutableRole::Daemon,
            &bytes
        ));
        assert!(!verify_appended_signature(
            NativeExecutableRole::Restore,
            &bytes
        ));
        let mut tampered = bytes.clone();
        tampered[0] ^= 1;
        assert!(!verify_appended_signature(
            NativeExecutableRole::Daemon,
            &tampered
        ));
        assert!(!verify_appended_signature(
            NativeExecutableRole::Daemon,
            &[0u8; SIGNATURE_TRAILER_BYTES]
        ));
    }

    #[test]
    fn running_executable_rejects_wrong_mode_or_link_count() {
        let directory = tempdir().unwrap();
        let executable = directory.path().join("daemon");
        fs::write(&executable, b"daemon").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(verify_running(&executable, 6, &crate::trust::sha256_bytes(b"daemon")).is_err());
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        fs::hard_link(&executable, directory.path().join("second-link")).unwrap();
        assert!(verify_running(&executable, 6, &crate::trust::sha256_bytes(b"daemon")).is_err());
    }

    #[test]
    fn running_executable_rejects_growth_and_wrong_digest() {
        let directory = tempdir().unwrap();
        let executable = directory.path().join("daemon");
        fs::write(&executable, b"daemon").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        GROW_RUNNING_EXECUTABLE_AFTER_STAT.with(|enabled| enabled.set(true));
        assert!(verify_running(&executable, 6, &crate::trust::sha256_bytes(b"daemon")).is_err());

        let exact = directory.path().join("exact");
        fs::write(&exact, b"daemon-a").unwrap();
        fs::set_permissions(&exact, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(verify_running(
            &exact,
            b"daemon-b".len(),
            &crate::trust::sha256_bytes(b"daemon-b")
        )
        .is_err());
    }
}
