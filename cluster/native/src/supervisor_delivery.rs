//! Protected startup-delivery intent. A marker is never a supervisor liveness permit.
use crate::{
    config::Config,
    engine::{Authority, ProductRoots},
    fs::Dir,
    Result,
};
use alloc::format;

const MARKER: &str = "supervisor.delivery";
const FENCE: &str = "supervisor.revoked";

/// Disable delivery before any installation bytes can change. An explicit invalid
/// record avoids treating absence/unlink races as an enabled installation.
pub(crate) fn revoke(root: &Dir) -> Result<()> {
    #[cfg(test)]
    let boot = "a".repeat(64);
    #[cfg(not(test))]
    let boot = crate::fs::prepare_supervisor_boot_identity(crate::fs::uid()?)?;
    revoke_for_boot(root, &boot)
}
fn revoke_for_boot(root: &Dir, boot: &str) -> Result<()> {
    if !voboost_contract_core::digest(boot) {
        return Err("supervisor kernel boot unknown".into());
    }
    root.write(FENCE, format!("{boot}\n").as_bytes(), 0o600)?;
    root.write(MARKER, b"VBCSUP1\nDISABLED\n", 0o600)
}

pub(crate) fn prepare(config: Config) -> Result<()> {
    let operation_root = Dir::open(&config.root, crate::fs::uid()?)?;
    let _operation = crate::operation::Lock::existing(&operation_root)?;
    let owner = crate::fs::uid()?;
    let kernel_boot = crate::fs::prepare_supervisor_boot_identity(owner)?;
    let root = Dir::open(&config.root, owner)?;
    require_unrevoked(&root, &kernel_boot)?;
    crate::fs::prepare_boot_identity(&config.boot_identity_file, &config.pair_id, owner)?;
    let installed = crate::install::supervisor_installation(&config)?;
    let authority = Authority::open(config, owner, ProductRoots::default())?;
    // These are integrity bindings to authenticated local installation bytes,
    // never firmware compatibility gates. No PID/liveness is claimed here.
    let marker = format!(
        "VBCSUP1\n{}\n{}\n{}\n{}\n{}\n",
        authority.boot_id,
        installed.identity(),
        authority.config.authority_epoch,
        installed.bootfile(),
        installed.implant_path()
    );
    if marker.len() > 2048 {
        return Err("supervisor marker exceeds bound".into());
    }
    require_unrevoked(&authority.root, &kernel_boot)?;
    authority.root.write(MARKER, marker.as_bytes(), 0o600)?;
    require_unrevoked(&authority.root, &kernel_boot)?;
    // Diagnostic transport failure must not change the admitted OEM startup.
    let _ = crate::diagnostic_ram::prepare(&authority.config.pair_id, owner);
    Ok(())
}

fn fence_allows(bytes: &[u8], current: &str) -> bool {
    let Some(previous) = core::str::from_utf8(bytes)
        .ok()
        .and_then(|value| value.strip_suffix('\n'))
    else {
        return false;
    };
    voboost_contract_core::digest(previous)
        && voboost_contract_core::digest(current)
        && previous != current
}
fn require_unrevoked(root: &Dir, current: &str) -> Result<()> {
    if root.exists(FENCE)? && !fence_allows(&root.read(FENCE, 65, 0o600)?, current) {
        return Err("supervisor delivery revoked in current kernel boot; reboot required".into());
    }
    if root.exists("restore.lock")? {
        return Err("supervisor restore transaction active".into());
    }
    Ok(())
}

use alloc::{ffi::CString, string::String, vec::Vec};
#[cfg(test)]
use core::ffi::c_char;

fn process_path(pid: u64, expected: &str) -> Result<()> {
    if pid == 0 || pid > voboost_contract_core::MAX_SAFE_INTEGER {
        return Err("supervisor PID rejected".into());
    }
    let path =
        CString::new(format!("/proc/{pid}/exefile")).map_err(|_| "supervisor process path NUL")?;
    let fd = crate::fs::Fd(unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    });
    if fd.0 < 0 {
        return Err("supervisor executable pathname unavailable".into());
    }
    let before = crate::fs::stat(fd.0)?;
    if before.st_uid != 0 {
        return Err("supervisor process owner differs".into());
    }
    let mut bytes = [0u8; 514];
    let n = unsafe { libc::read(fd.0, bytes.as_mut_ptr().cast(), bytes.len()) };
    if n <= 0 || n as usize == bytes.len() {
        return Err("supervisor process path bound".into());
    }
    let actual = &bytes[..n as usize];
    let actual = actual.strip_suffix(&[0]).unwrap_or(actual);
    let actual = actual.strip_suffix(b"\n").unwrap_or(actual);
    if actual != expected.as_bytes() || !crate::fs::unchanged(&before, &crate::fs::stat(fd.0)?) {
        return Err("supervisor executable pathname changed or differs".into());
    }
    Ok(())
}

// Host regressions retain the bounded read leaf from the unapplied prototype.
#[cfg(test)]
unsafe fn exact_file(path: *const c_char, expected: &[u8], regular: bool, owner: u32) -> bool {
    let fd = libc::open(path, libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW);
    if fd < 0 {
        return false;
    }
    let mut before: libc::stat = core::mem::zeroed();
    let mut after: libc::stat = core::mem::zeroed();
    let mut buffer = [0u8; 2049];
    let valid = expected.len() < buffer.len()
        && libc::fstat(fd, &mut before) == 0
        && before.st_uid as u32 == owner
        && before.st_mode & 0o777 == 0o600
        && (!regular || before.st_mode & libc::S_IFMT == libc::S_IFREG)
        && (!regular || before.st_nlink == 1)
        && before.st_size == expected.len() as libc::off_t;
    let n = if valid {
        libc::read(fd, buffer.as_mut_ptr().cast(), expected.len() + 1)
    } else {
        -1
    };
    let accepted = n == expected.len() as libc::ssize_t
        && &buffer[..expected.len()] == expected
        && libc::fstat(fd, &mut after) == 0
        && crate::fs::unchanged(&before, &after);
    libc::close(fd);
    accepted
}

/// A fresh authenticated child-parent observation, not a persisted PID claim.
/// The private fields cannot be manufactured by config or a restart journal.
pub(crate) struct SupervisorDeliveryPermit {
    boot: String,
    installation: String,
    executable: String,
    process: voboost_contract_core::cluster::ProcessIdentity,
    generation: Option<String>,
    desired: Option<(u64, String)>,
    receipt: Vec<u8>,
}
fn receipt_matches(
    bytes: &[u8],
    boot: &str,
    installation: &str,
    parent: &voboost_contract_core::cluster::SupervisorObservation,
) -> bool {
    let Ok(text) = core::str::from_utf8(bytes) else {
        return false;
    };
    let mut fields = text.split('\n');
    fields.next() == Some("VBCSUPR1")
        && fields.next() == Some(boot)
        && fields.next() == Some(installation)
        && fields.next().and_then(|s| s.parse::<u64>().ok()) == Some(parent.parent_pid)
        && parent.parent_pid > 1
        && fields.next() == Some("sysmgr")
        && fields.next() == Some(parent.nonce.as_str())
        && voboost_contract_core::digest(&parent.nonce)
        && fields.next() == Some("")
        && fields.next().is_none()
}
fn observed_delivery(a: &Authority, executable: &str) -> Result<SupervisorDeliveryPermit> {
    if !matches!(
        executable,
        "/usr/bin/gauge" | "/usr/bin/point" | "/usr/bin/light"
    ) {
        return Err("supervisor owner executable differs".into());
    }
    require_unrevoked(
        &a.root,
        &crate::fs::read_supervisor_boot_identity(crate::fs::uid()?)?,
    )?;
    let installed = crate::install::supervisor_installation(&a.config)?;
    let expected = format!(
        "VBCSUP1\n{}\n{}\n{}\n{}\n{}\n",
        a.boot_id,
        installed.identity(),
        a.config.authority_epoch,
        installed.bootfile(),
        installed.implant_path()
    );
    if a.root.read(MARKER, 2048, 0o600)? != expected.as_bytes() {
        return Err("supervisor delivery revoked".into());
    }
    let observed = crate::service::observe_owner_for(a, executable)?;
    let parent = observed
        .process
        .supervisor
        .as_ref()
        .ok_or("owner has no fresh supervisor observation")?;
    if parent.parent_pid <= 1 || !voboost_contract_core::digest(&parent.nonce) {
        return Err("supervisor observation invalid".into());
    }
    // Current production owner restart is sysmgr-controlled. clusterboot receipt
    // is separate and cannot authorize stopping an unrelated owner's parent.
    let receipt = a.root.read("supervisor-sysmgr.receipt", 2048, 0o600)?;
    if !receipt_matches(&receipt, &a.boot_id, installed.identity(), parent) {
        return Err("supervisor receipt does not match current parent".into());
    }
    let parent_path = "/usr/bin/sysmgr";
    let parent_file = crate::elf::read(parent_path, 8 * 1024 * 1024)?;
    crate::supervisor_elf::has_execve_jump_slot(&parent_file)?;
    process_path(parent.parent_pid, parent_path)?;
    if a.root.read("supervisor-sysmgr.receipt", 2048, 0o600)? != receipt
        || a.root.read(MARKER, 2048, 0o600)? != expected.as_bytes()
    {
        return Err("supervisor delivery changed during observation".into());
    }
    Ok(SupervisorDeliveryPermit {
        boot: a.boot_id.clone(),
        installation: installed.identity().into(),
        executable: executable.into(),
        process: observed.process,
        generation: a.generation.as_ref().map(|g| g.generation_id.clone()),
        desired: a
            .desired
            .as_ref()
            .map(|d| (d.desired_revision, d.desired_sha256.clone())),
        receipt,
    })
}
pub(crate) fn admit_supervised_owner(
    a: &Authority,
    executable: &str,
) -> Result<SupervisorDeliveryPermit> {
    observed_delivery(a, executable)
}
impl SupervisorDeliveryPermit {
    pub(crate) fn verify_current(&self, a: &Authority, executable: &str) -> Result<()> {
        let now = observed_delivery(a, executable)?;
        if self.boot != now.boot
            || self.installation != now.installation
            || self.executable != now.executable
            || self.process != now.process
            || self.generation != now.generation
            || self.desired != now.desired
            || self.receipt != now.receipt
        {
            return Err("supervisor delivery permit became stale".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn fresh_qnx_boot_reopens_delivery_when_qtime_stays_one() {
        let parent =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build/cluster-test-tmp");
        std::fs::create_dir_all(&parent).unwrap();
        let fixture = tempfile::tempdir_in(parent).unwrap();
        std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = fixture.path().canonicalize().unwrap();
        let owner = crate::fs::uid().unwrap();
        let root = Dir::open(path.to_str().unwrap(), owner).unwrap();

        // Both physical A9 boots report qtime.boot_time == 1.
        let before = "a".repeat(64);
        let after = "b".repeat(64);
        revoke_for_boot(&root, &before).unwrap();
        assert!(require_unrevoked(&root, &before).is_err(), "same QNX boot");
        drop(root);

        // Disk survives the reboot, and reopening the root must admit a fresh QNX boot.
        let root = Dir::open(path.to_str().unwrap(), owner).unwrap();
        assert!(require_unrevoked(&root, &after).is_ok(), "fresh QNX boot");
    }

    #[test]
    fn durable_fence_blocks_late_prepare_write_and_reopens_only_next_boot() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../.work162")
            .join(format!("supervisor-fence-{}", crate::nonce().unwrap()));
        std::fs::create_dir_all(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = std::fs::canonicalize(path).unwrap();
        let owner = crate::fs::uid().unwrap();
        let root = Dir::open(path.to_str().unwrap(), owner).unwrap();
        let before = "a".repeat(64);
        let after = "b".repeat(64);
        revoke_for_boot(&root, &before).unwrap();
        assert_eq!(
            root.read(MARKER, 64, 0o600).unwrap(),
            b"VBCSUP1\nDISABLED\n"
        );
        root.write(MARKER, b"late stale prepare publication", 0o600)
            .unwrap();
        assert!(require_unrevoked(&root, &before).is_err());
        assert!(require_unrevoked(&root, &after).is_ok());
        root.write(FENCE, b"bad fence\n", 0o600).unwrap();
        assert!(require_unrevoked(&root, &after).is_err());
        drop(root);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn revocation_cannot_be_resurrected_in_same_boot_or_by_malformed_fence() {
        let current = "b".repeat(64);
        let record = format!("{current}\n");
        assert!(!fence_allows(record.as_bytes(), &current));
        assert!(fence_allows(record.as_bytes(), &"c".repeat(64)));
        for malformed in [b"".as_slice(), b"1\n", b"bad fence\n", current.as_bytes()] {
            assert!(!fence_allows(malformed, &current));
        }
        assert!(!fence_allows(record.as_bytes(), ""));
    }
    #[test]
    fn receipt_rejects_parent_death_pid_reuse_new_nonce_and_boot() {
        use voboost_contract_core::cluster::SupervisorObservation;
        let nonce = "a".repeat(64);
        let mut parent = SupervisorObservation {
            nonce: nonce.clone(),
            parent_pid: 73,
        };
        let receipt = format!("VBCSUPR1\nboot-a\ninstall-a\n73\nsysmgr\n{nonce}\n");
        assert!(receipt_matches(
            receipt.as_bytes(),
            "boot-a",
            "install-a",
            &parent
        ));
        parent.parent_pid = 1;
        assert!(!receipt_matches(
            receipt.as_bytes(),
            "boot-a",
            "install-a",
            &parent
        ));
        parent.parent_pid = 73;
        parent.nonce = "b".repeat(64);
        assert!(!receipt_matches(
            receipt.as_bytes(),
            "boot-a",
            "install-a",
            &parent
        ));
        parent.nonce = nonce;
        assert!(!receipt_matches(
            receipt.as_bytes(),
            "boot-b",
            "install-a",
            &parent
        ));
        assert!(!receipt_matches(
            receipt.as_bytes(),
            "boot-a",
            "install-b",
            &parent
        ));
        let new = receipt.replace("73\n", "74\n");
        assert!(!receipt_matches(
            new.as_bytes(),
            "boot-a",
            "install-a",
            &parent
        ));
    }
    #[test]
    fn protected_marker_read_rejects_revocation_replacement_and_symlink() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../.work162")
            .join(format!("supervisor-marker-{}", crate::nonce().unwrap()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("marker");
        let name = CString::new(path.to_str().unwrap()).unwrap();
        let owner = crate::fs::uid().unwrap();
        let expected = b"VBCSUP1\ncurrent-boot-install\n";
        std::fs::write(&path, expected).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(unsafe { exact_file(name.as_ptr(), expected, true, owner) });
        std::fs::write(&path, b"VBCSUP1\nDISABLED\n").unwrap();
        assert!(!unsafe { exact_file(name.as_ptr(), expected, true, owner) });
        std::fs::write(&path, expected).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!unsafe { exact_file(name.as_ptr(), expected, true, owner) });
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, b"VBCSUP1\nnew-boot-install\n").unwrap();
        assert!(!unsafe { exact_file(name.as_ptr(), expected, true, owner) });
        let new = b"VBCSUP1\nnew-boot-install\n";
        assert!(unsafe { exact_file(name.as_ptr(), new, true, owner) });
        std::fs::write(&path, b"VBCSUP1\ncurrent-boot-install\nnew-nonce\n").unwrap();
        assert!(!unsafe { exact_file(name.as_ptr(), expected, true, owner) });
        std::fs::remove_file(&path).unwrap();
        assert!(!unsafe { exact_file(name.as_ptr(), expected, true, owner) });
        let target = root.join("target");
        std::fs::write(&target, expected).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &path).unwrap();
        assert!(!unsafe { exact_file(name.as_ptr(), expected, true, owner) });
        std::fs::remove_dir_all(root).unwrap();
    }
}
