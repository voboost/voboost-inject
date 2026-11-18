use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
#[allow(unused_imports)]
use std::path::PathBuf;
#[allow(unused_imports)]
use std::time::Duration;

use crate::contract::InstallDescriptor;

const POLICY: &str = "/vendor/etc/selinux/precompiled_sepolicy";
#[allow(dead_code)]
const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";
const MAX_POLICY_BYTES: usize = 64 * 1024 * 1024;

pub fn backup(recovery: &Path) -> Result<(), String> {
    let bytes = crate::read_bounded(Path::new(POLICY), MAX_POLICY_BYTES, 0o644)
        .map_err(|error| format!("read pristine policy: {error}"))?;
    let target = recovery.join("precompiled_sepolicy.orig");
    publish(&target, &bytes, 0o600)?;
    publish(
        &recovery.join("policy-sidecars.json"),
        &crate::mount_policy_transaction::sidecar_backup_bytes()?,
        0o600,
    )?;
    let metadata = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 1,
        "size": bytes.len(),
        "sha256": format!("{:x}", Sha256::digest(&bytes)),
        "mode": "0644"
    }))
    .map_err(|error| error.to_string())?;
    publish(&recovery.join("policy.meta.json"), &metadata, 0o600)
}

#[allow(dead_code)]
struct VerifiedProgram {
    path: PathBuf,
    file: File,
    stamp: (u64, u64, u64, i64, i64, u64, u32, u32, u32),
}

#[allow(dead_code)]
impl VerifiedProgram {
    fn verify_unchanged(&self) -> Result<(), String> {
        let opened = self
            .file
            .metadata()
            .map_err(|error| format!("stat opened live SELinux program: {error}"))?;
        let named = fs::symlink_metadata(&self.path)
            .map_err(|error| format!("stat named live SELinux program: {error}"))?;
        if program_stamp(&opened) != self.stamp
            || named.file_type().is_symlink()
            || (named.dev(), named.ino()) != (opened.dev(), opened.ino())
        {
            return Err("live SELinux program identity changed during execution".into());
        }
        Ok(())
    }
}

#[allow(dead_code)]
fn program_stamp(metadata: &fs::Metadata) -> (u64, u64, u64, i64, i64, u64, u32, u32, u32) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.ctime(),
        metadata.ctime_nsec(),
        metadata.nlink(),
        metadata.uid(),
        metadata.gid(),
        metadata.permissions().mode() & 0o7777,
    )
}

#[allow(dead_code)]
fn open_verified_live_program(
    staging: &Path,
    live: &Path,
    descriptor: &InstallDescriptor,
) -> Result<VerifiedProgram, String> {
    let signed = crate::runtime::read_descriptor_artifact(
        &staging.join("voboost-selinux"),
        "voboost-selinux",
        0o600,
        descriptor,
    )?;
    let fd = unsafe {
        libc::open(
            std::ffi::CString::new(live.as_os_str().as_encoded_bytes())
                .map_err(|_| "live SELinux path contains NUL")?
                .as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(format!(
            "open live SELinux program: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let before = file
        .metadata()
        .map_err(|error| format!("stat live SELinux program: {error}"))?;
    #[cfg(target_os = "android")]
    let owner = (0, 0);
    #[cfg(not(target_os = "android"))]
    let owner = unsafe { (libc::geteuid(), libc::getegid()) };
    if !before.is_file()
        || before.nlink() != 1
        || before.uid() != owner.0
        || before.gid() != owner.1
        || before.permissions().mode() & 0o7777 != 0o700
    {
        return Err("live SELinux program has a foreign identity".into());
    }
    let stamp = program_stamp(&before);
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((signed.len() + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read live SELinux program: {error}"))?;
    if bytes != signed {
        return Err("live SELinux program differs from signed frozen identity".into());
    }
    let verified = VerifiedProgram {
        path: live.to_path_buf(),
        file,
        stamp,
    };
    verified.verify_unchanged()?;
    Ok(verified)
}

#[allow(dead_code)]
fn descriptor_executable(file: &File) -> String {
    format!("/proc/self/fd/{}", file.as_raw_fd())
}

pub fn apply(
    staging: &Path,
    recovery: &Path,
    transaction_id: &str,
    descriptor: &InstallDescriptor,
) -> Result<(), String> {
    let selinux = open_verified_live_program(
        staging,
        Path::new("/data/voboost/voboost-selinux"),
        descriptor,
    )?;
    let selinux_fd = selinux.file.as_raw_fd();
    let flags = unsafe { libc::fcntl(selinux_fd, libc::F_GETFD) };
    if flags < 0
        || unsafe { libc::fcntl(selinux_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } != 0
    {
        return Err("retain SELinux program descriptor failed".into());
    }
    let pristine = recovery.join("precompiled_sepolicy.orig");
    let candidate = recovery.join("precompiled_sepolicy.patched");
    let executable = descriptor_executable(&selinux.file);
    let output = crate::fixed_process::output(&executable, &[], Duration::from_secs(35), 4096);
    selinux.verify_unchanged()?;
    require_policy_transformation(output?)?;
    crate::runtime::prepare_boot_execution_labels(staging, descriptor)?;
    let bytes = crate::read_bounded(&candidate, MAX_POLICY_BYTES, 0o600)
        .map_err(|error| format!("read patched policy: {error}"))?;
    let boot_id =
        fs::read_to_string(BOOT_ID).map_err(|error| format!("read install boot ID: {error}"))?;
    let boot_id = boot_id.trim();
    let journal = recovery.join("mount-policy-journal.json");
    let watchdog = crate::mount_policy_transaction::begin(
        "install",
        transaction_id,
        &journal,
        Path::new(POLICY),
        &pristine,
        boot_id,
    )?;
    if let Err(error) =
        crate::mount_policy_transaction::publish_candidate(Path::new(POLICY), &bytes, &journal)
            .and_then(|()| crate::mount_policy_transaction::transfer_to_reboot(&journal, boot_id))
    {
        return match watchdog.abort() {
            Ok(()) => Err(error),
            Err(recovery_error) => Err(format!("{error}; {recovery_error}")),
        };
    }
    watchdog.disarm_for_reboot()
}

fn require_policy_transformation(
    output: crate::fixed_process::BoundedOutput,
) -> Result<(), String> {
    if output.status.success() {
        return Ok(());
    }
    // Leave room for the surrounding operation document and progress envelope.
    let detail: String = String::from_utf8_lossy(&output.stderr)
        .chars()
        .take(512)
        .collect();
    Err(format!(
        "SELinux policy transformation failed (exit {}): {}",
        output
            .status
            .code()
            .map(|code| code.to_string())
            .unwrap_or_else(|| "signal".into()),
        detail.trim()
    ))
}

fn publish(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "policy target has no parent".to_string())?;
    let temporary = parent.join(format!(
        ".{}.install.tmp",
        path.file_name().unwrap().to_string_lossy()
    ));
    let _ = fs::remove_file(&temporary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))
        .map_err(|error| error.to_string())?;
    fs::rename(&temporary, path).map_err(|error| error.to_string())?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_policy_transformation_preserves_the_bounded_exit_and_diagnostic() {
        use std::os::unix::process::ExitStatusExt;
        let error = require_policy_transformation(crate::fixed_process::BoundedOutput {
            status: std::process::ExitStatus::from_raw(3 << 8),
            stdout: Vec::new(),
            stderr: b"voboost-selinux: cannot read /sys/fs/selinux/policy\n".to_vec(),
        })
        .unwrap_err();
        assert_eq!(error, "SELinux policy transformation failed (exit 3): voboost-selinux: cannot read /sys/fs/selinux/policy");
        let oversized = require_policy_transformation(crate::fixed_process::BoundedOutput {
            status: std::process::ExitStatus::from_raw(8 << 8),
            stdout: Vec::new(),
            stderr: vec![0xff; 4096],
        })
        .unwrap_err();
        assert!(
            oversized.len() < 2304,
            "diagnostic can overflow the operation envelope"
        );
    }

    fn descriptor(bytes: &[u8]) -> InstallDescriptor {
        let mut descriptor = crate::contract::tests::descriptor_for_cross_module_tests();
        let artifact = descriptor
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.file == "voboost-selinux")
            .unwrap();
        artifact.size = bytes.len() as u64;
        artifact.sha256 = format!("{:x}", Sha256::digest(bytes));
        descriptor.validate().unwrap();
        descriptor
    }

    fn write_mode(path: &Path, bytes: &[u8], mode: u32) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn signed_frozen_and_live_executable_identity_are_bound_to_one_open_descriptor() {
        let root = tempfile::tempdir().unwrap();
        let staging = root.path().join("frozen");
        fs::create_dir(&staging).unwrap();
        let bytes = b"signed executable bytes";
        write_mode(&staging.join("voboost-selinux"), bytes, 0o600);
        let live = root.path().join("voboost-selinux");
        write_mode(&live, bytes, 0o700);
        let descriptor = descriptor(bytes);

        let verified = open_verified_live_program(&staging, &live, &descriptor).unwrap();
        assert_eq!(
            descriptor_executable(&verified.file),
            format!("/proc/self/fd/{}", verified.file.as_raw_fd())
        );
        verified.verify_unchanged().unwrap();

        let replacement = root.path().join("replacement");
        write_mode(&replacement, bytes, 0o700);
        fs::rename(&replacement, &live).unwrap();
        assert!(verified.verify_unchanged().is_err());
    }

    #[test]
    fn live_selinux_program_rejects_mode_link_and_signed_identity_substitution() {
        let bytes = b"signed executable bytes";
        let descriptor = descriptor(bytes);
        for hostile in ["mode", "symlink", "bytes"] {
            let root = tempfile::tempdir().unwrap();
            let staging = root.path().join("frozen");
            fs::create_dir(&staging).unwrap();
            write_mode(&staging.join("voboost-selinux"), bytes, 0o600);
            let live = root.path().join("voboost-selinux");
            match hostile {
                "mode" => write_mode(&live, bytes, 0o600),
                "symlink" => {
                    let outside = root.path().join("outside");
                    write_mode(&outside, bytes, 0o700);
                    std::os::unix::fs::symlink(&outside, &live).unwrap();
                }
                "bytes" => write_mode(&live, b"substituted executable", 0o700),
                _ => unreachable!(),
            }
            assert!(
                open_verified_live_program(&staging, &live, &descriptor).is_err(),
                "hostile {hostile} executable was accepted"
            );
        }
    }
}
