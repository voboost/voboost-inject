//! Optional, closed pre-reboot evidence for the fresh install transaction.
use crate::journal::{InstallJournal, InstallPhase};
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::path::Path;
use voboost_shared::secure_fs::Directory;

const ARM: &str = "initial-seeding-arm.json";
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Arm<'a> {
    schema_version: u32,
    transaction_id: &'a str,
    candidate: &'a str,
    prior_boot: &'a str,
}

fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn boot(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        })
}

/// Failure disables this evidence only; it must never change install authority.
pub(super) fn arm(
    root: &Path,
    journal: &InstallJournal,
    current_boot: &str,
    now_ms: u64,
) -> io::Result<()> {
    if journal.schema_version != 1
        || journal.phase != InstallPhase::InstallAgents
        || journal.boot_ids.len() != 1
        || !boot(&journal.boot_ids[0])
        || journal.boot_ids[0] == current_boot
        || !boot(current_boot)
        || !hex64(&journal.transaction_id)
        || !hex64(&journal.manifest_sha256)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "install arm scope differs",
        ));
    }
    let root = Directory::open(root)?;
    root.validate_owner_mode(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        0o755,
    )?;
    // State files are private to the resident owner. The owner verifies their
    // absence in T2 before exposing its socket; the installer never opens them.
    let recovery = root.open_child("recovery")?;
    recovery.validate_owner_mode(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        0o700,
    )?;
    let root = recovery.open_child(&journal.transaction_id)?;
    root.validate_owner_mode(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        0o700,
    )?;
    // Require the existing explicitly armed, accepted emulator installation.
    let frozen = root.open_child("frozen")?;
    frozen.validate_owner_mode(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        0o700,
    )?;
    let staging_bytes = frozen.read_trusted("staging.json", 4096, 0o600)?;
    let staging = voboost_contract::install::StagingDescriptor::parse(&staging_bytes)
        .map_err(io::Error::other)?;
    let activation = staging
        .emulator_acceptance
        .ok_or_else(|| io::Error::other("emulator acceptance not armed"))?;
    let receipt_bytes = root.read_trusted("install-acceptance.json", 4096, 0o600)?;
    let receipt: voboost_contract::install_acceptance::Receipt =
        serde_json::from_slice(&receipt_bytes).map_err(io::Error::other)?;
    if staging.transaction_id != journal.transaction_id
        || staging.manifest_sha256 != journal.manifest_sha256
        || receipt.schema_version != 1
        || receipt.transaction_id != journal.transaction_id
        || receipt.manifest_sha256 != journal.manifest_sha256
        || receipt.attempt_token != activation.attempt_token
        || receipt.boot_id != current_boot
        || receipt.reboot_count != 1
        || receipt.decision != voboost_contract::install_acceptance::Decision::Accept
        || receipt.state != voboost_contract::install_acceptance::State::Accepted
        || receipt
            .expires_monotonic_ms
            .parse::<u64>()
            .ok()
            .filter(|n| *n > now_ms)
            .map(|n| n.to_string())
            != Some(receipt.expires_monotonic_ms.clone())
        || voboost_contract::install_acceptance::bytes(&receipt).map_err(io::Error::other)?
            != receipt_bytes
    {
        return Err(io::Error::other("emulator acceptance correlation differs"));
    }
    let mut bytes = serde_json::to_vec(&Arm {
        schema_version: 1,
        transaction_id: &journal.transaction_id,
        candidate: &journal.manifest_sha256,
        prior_boot: current_boot,
    })
    .map_err(io::Error::other)?;
    bytes.push(b'\n');
    match root.create_new(std::ffi::OsStr::new(ARM), 0o600) {
        Ok(mut file) => {
            file.write_all(&bytes)?;
            file.sync_all()?;
            root.sync_all()
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if root.read_trusted(ARM, 4096, 0o600)? == bytes {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "foreign install arm",
                ))
            }
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    const BOOT: &str = "22222222-2222-4222-8222-222222222222";

    fn journal() -> InstallJournal {
        InstallJournal {
            schema_version: 1,
            transaction_id: "b".repeat(64),
            manifest_sha256: "c".repeat(64),
            phase: InstallPhase::InstallAgents,
            boot_ids: vec!["11111111-1111-4111-8111-111111111111".into()],
        }
    }
    fn root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let recovery = root.path().join("recovery");
        std::fs::create_dir(&recovery).unwrap();
        std::fs::set_permissions(&recovery, std::fs::Permissions::from_mode(0o700)).unwrap();
        let transaction = recovery.join("b".repeat(64));
        std::fs::create_dir(&transaction).unwrap();
        std::fs::set_permissions(&transaction, std::fs::Permissions::from_mode(0o700)).unwrap();
        let frozen = transaction.join("frozen");
        std::fs::create_dir(&frozen).unwrap();
        std::fs::set_permissions(&frozen, std::fs::Permissions::from_mode(0o700)).unwrap();
        let staging = voboost_contract::install::StagingDescriptor {
            schema_version: 1,
            transaction_id: "b".repeat(64),
            release_identity: "1.0.0-beta1".into(),
            manifest_sha256: "c".repeat(64),
            emulator_acceptance: Some(voboost_contract::install::EmulatorAcceptance {
                attempt_token: "d".repeat(64),
            }),
        };
        std::fs::write(
            frozen.join("staging.json"),
            staging.canonical_bytes().unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(
            frozen.join("staging.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let receipt = voboost_contract::install_acceptance::Receipt {
            schema_version: 1,
            transaction_id: "b".repeat(64),
            manifest_sha256: "c".repeat(64),
            attempt_token: "d".repeat(64),
            boot_id: BOOT.into(),
            reboot_count: 1,
            decision: voboost_contract::install_acceptance::Decision::Accept,
            state: voboost_contract::install_acceptance::State::Accepted,
            expires_monotonic_ms: "999999".into(),
        };
        std::fs::write(
            transaction.join("install-acceptance.json"),
            voboost_contract::install_acceptance::bytes(&receipt).unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(
            transaction.join("install-acceptance.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        root
    }
    #[test]
    fn arm_is_bound_to_clean_current_install_and_cannot_be_replaced() {
        let root = root();
        let journal = journal();
        arm(root.path(), &journal, BOOT, 1).unwrap();
        arm(root.path(), &journal, BOOT, 1).unwrap();
        let mut other = journal.clone();
        other.manifest_sha256 = "d".repeat(64);
        assert!(arm(root.path(), &other, BOOT, 1).is_err());
        let saved: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.path().join("recovery").join("b".repeat(64)).join(ARM)).unwrap(),
        )
        .unwrap();
        assert_eq!(saved["candidate"], "c".repeat(64));
        assert_eq!(saved["priorBoot"], BOOT);
    }
    #[test]
    fn wrong_boot_does_not_arm() {
        let root = root();
        let journal = journal();
        assert!(arm(root.path(), &journal, &journal.boot_ids[0], 1).is_err());
        assert!(arm(root.path(), &journal, "unknown", 1).is_err());
    }
    #[test]
    fn malformed_install_journal_cannot_arm_capture() {
        let root = root();
        let mut invalid = journal();
        invalid.schema_version = 2;
        assert!(arm(root.path(), &invalid, BOOT, 1).is_err());
        invalid.schema_version = 1;
        invalid.boot_ids[0] = "not-a-boot".into();
        assert!(arm(root.path(), &invalid, BOOT, 1).is_err());
        assert!(!root
            .path()
            .join("recovery")
            .join("b".repeat(64))
            .join(ARM)
            .exists());
    }

    #[test]
    fn unarmed_acceptance_cannot_create_arm() {
        let root = root();
        std::fs::remove_file(
            root.path()
                .join("recovery")
                .join("b".repeat(64))
                .join("install-acceptance.json"),
        )
        .unwrap();
        assert!(arm(root.path(), &journal(), BOOT, 1).is_err());
        assert!(!root
            .path()
            .join("recovery")
            .join("b".repeat(64))
            .join(ARM)
            .exists());
    }

    #[test]
    fn expired_acceptance_cannot_create_arm() {
        let root = root();
        assert!(arm(root.path(), &journal(), BOOT, 999999).is_err());
        assert!(!root
            .path()
            .join("recovery")
            .join("b".repeat(64))
            .join(ARM)
            .exists());
    }
}
