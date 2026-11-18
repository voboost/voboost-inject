//! Fixed signed PW courier child. No key or transport option is passed in argv/env.
pub mod actor;

use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom},
    os::fd::{AsRawFd, FromRawFd},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::Path,
    process::{Child, Command, Stdio},
};

/// Caller supplies the identity from the current verified signed product core,
/// not a firmware compatibility hash. The opened inode is pinned through exec.
pub struct VerifiedCode {
    file: File,
}
impl VerifiedCode {
    pub fn admit(path: &Path, size: u64, sha256: &str) -> io::Result<Self> {
        Self::admit_owned(path, size, sha256, 0)
    }
    fn admit_owned(path: &Path, size: u64, sha256: &str, owner: u32) -> io::Result<Self> {
        if path.file_name().and_then(|v| v.to_str()) != Some("agent-common.dex")
            || !(1..=16_777_216).contains(&size)
            || sha256.len() != 64
            || !sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(io::Error::other("PW signed core identity invalid"));
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let before = file.metadata()?;
        if !before.is_file()
            || before.uid() != owner
            || before.mode() & 0o222 != 0
            || before.len() != size
        {
            return Err(io::Error::other("PW core ownership invalid"));
        }
        let mut digest = Sha256::new();
        let mut bytes = [0u8; 8192];
        let mut read = 0u64;
        loop {
            let n = file.read(&mut bytes)?;
            if n == 0 {
                break;
            }
            read = read
                .checked_add(n as u64)
                .ok_or_else(|| io::Error::other("PW core size overflow"))?;
            if read > size {
                return Err(io::Error::other("PW core grew"));
            }
            digest.update(&bytes[..n]);
        }
        let actual = hex::encode(digest.finalize());
        let after = file.metadata()?;
        if read != size
            || actual != sha256
            || before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
        {
            return Err(io::Error::other("PW signed core changed"));
        }
        file.seek(SeekFrom::Start(0))?;
        Ok(Self { file })
    }
    /// The actor owns bounded stderr draining, process-group cancellation and
    /// reaping. Init's ART environment is inherited; secrets use private pipes.
    pub fn spawn(&self) -> io::Result<Child> {
        // Keep the code away from stdin/out/err setup even when the caller had
        // closed standard descriptors. CLOEXEC applies to this extra handle.
        let descriptor = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        let pinned = unsafe { File::from_raw_fd(descriptor) };
        let parent = unsafe { libc::getpid() };
        let mut command = Command::new("/system/bin/app_process");
        command
            .args([
                "-Xint",
                "-Djava.class.path=/proc/self/fd/3",
                "/system/bin",
                "ru.voboost.agents.AgentPwTransportMain",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        unsafe {
            command.pre_exec(move || {
                let code = pinned.as_raw_fd();
                if code != 3 && libc::dup2(code, 3) < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                #[cfg(any(target_os = "android", target_os = "linux"))]
                {
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                        || libc::getppid() != parent
                    {
                        return Err(io::Error::other("PW child parent changed"));
                    }
                }
                #[cfg(not(any(target_os = "android", target_os = "linux")))]
                let _ = parent;
                crate::child_privileges::drop_for_exec()
            });
        }
        command.spawn()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn admits_only_exact_readonly_inode() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent-common.dex");
        std::fs::write(&path, b"test signed core").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        let expected = hex::encode(Sha256::digest(b"test signed core"));
        let owner = unsafe { libc::geteuid() };
        assert!(VerifiedCode::admit_owned(&path, 16, &expected, owner).is_ok());
        assert!(VerifiedCode::admit_owned(&path, 15, &expected, owner).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(VerifiedCode::admit_owned(&path, 16, &expected, owner).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(VerifiedCode::admit_owned(&link, 16, &expected, owner).is_err());
    }
}
