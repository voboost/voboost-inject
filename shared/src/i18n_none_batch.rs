//! Durable plural reboot identity. The outer journal lock precedes profile locks.
use super::*;
use serde::{Deserialize, Serialize};
use voboost_shared::owned_overlay::Variant;
use voboost_shared::secure_fs::DirectoryTransactionLock;

const TICKET: &str = "none-batch-reboot.json";
const MAX_TICKET: usize = 256 + Variant::ALL.len() * 256;
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Member {
    profile: String,
    generation: String,
    overlay_sha256: String,
}
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Ticket {
    schema: u32,
    boot: String,
    members: Vec<Member>,
}
pub(super) struct Lease {
    directory: Directory,
    _lock: DirectoryTransactionLock,
}
impl Lease {
    /// No creation or relabel: ordinary boots cannot manufacture an authority.
    pub(super) fn open() -> io::Result<Self> {
        let root = Directory::open(Path::new("/data/voboost"))?;
        root.validate_owner_not_writable(0, 0)?;
        let directory = root.open_child("i18n-resource-transaction")?;
        directory.validate_owner_mode(0, 0, 0o700)?;
        let lock = directory.lock_transaction(Duration::from_secs(5))?;
        Ok(Self {
            directory,
            _lock: lock,
        })
    }
    /// Called only after signed collection admission and all-owned absence.
    /// Persist BEFORE the actual request. Identical replay cannot request twice.
    /// Retire only after every signed member has durable terminal absence.
    pub(super) fn finish(&self, members: &[(Variant, Receipt)], boot: &str) -> io::Result<()> {
        finish_in(&self.directory, members, boot)
    }
    pub(super) fn claim(&self, members: &[(Variant, Receipt)], boot: &str) -> io::Result<bool> {
        claim_in(&self.directory, members, boot)
    }
}
fn ticket(members: &[(Variant, Receipt)], boot: &str) -> io::Result<Ticket> {
    if members.is_empty() || members.len() > Variant::ALL.len() || !valid_resource_boot_id(boot) {
        return Err(fail("None batch ticket shape invalid"));
    }
    let mut result = Vec::new();
    let mut previous = None;
    for (variant, receipt) in members {
        if previous.is_some_and(|value| value >= *variant)
            || receipt.schema != 1
            || !hash(&receipt.generation)
            || !hash(&receipt.overlay_sha256)
            || !matches!(
                receipt.phase.as_str(),
                "late-none-request-attempted"
                    | "late-none-final"
                    | "operation-reboot-attempted"
                    | "operation-awaiting-package-absence"
                    | "operation-package-absence-confirmed"
                    | "early-none-awaiting-native-readback"
                    | "early-none-restored-confirmed"
            )
            || (receipt.phase == "operation-awaiting-package-absence"
                && receipt.removal_boot_id.as_deref() == Some(boot))
            || receipt
                .removal_boot_id
                .as_deref()
                .is_none_or(|value| !valid_resource_boot_id(value))
        {
            return Err(fail("None batch ticket member invalid"));
        }
        previous = Some(*variant);
        result.push(Member {
            profile: variant.profile().into(),
            generation: receipt.generation.clone(),
            overlay_sha256: receipt.overlay_sha256.clone(),
        });
    }
    Ok(Ticket {
        schema: 1,
        boot: boot.into(),
        members: result,
    })
}
fn claim_in(directory: &Directory, members: &[(Variant, Receipt)], boot: &str) -> io::Result<bool> {
    let requested = ticket(members, boot)?;
    match directory.read_trusted(TICKET, MAX_TICKET, 0o600) {
        Ok(bytes) => {
            let current: Ticket = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            if current.schema != 1
                || !valid_resource_boot_id(&current.boot)
                || current.members != requested.members
            {
                return Err(fail("None batch ticket authority conflicts"));
            }
            if current.boot == requested.boot {
                return Ok(false);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    directory.write_atomic(
        TICKET,
        &serde_json::to_vec(&requested).map_err(io::Error::other)?,
        0o600,
    )?;
    Ok(true)
}
fn finish_in(directory: &Directory, members: &[(Variant, Receipt)], boot: &str) -> io::Result<()> {
    let requested = ticket(members, boot)?;
    if members.iter().any(|(_, r)| {
        !matches!(
            r.phase.as_str(),
            "late-none-final" | "operation-package-absence-confirmed"
        )
    }) {
        return Err(fail("batch retirement lacks terminal proof"));
    }
    match directory.read_trusted(TICKET, MAX_TICKET, 0o600) {
        Ok(bytes) => {
            let current: Ticket = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            if current.schema != 1
                || !valid_resource_boot_id(&current.boot)
                || current.members != requested.members
            {
                return Err(fail("batch retirement authority differs"));
            }
            directory.unlink(TICKET)?;
            directory.sync_all()
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn members() -> Vec<(Variant, Receipt)> {
        Variant::ALL
            .into_iter()
            .map(|v| {
                (
                    v,
                    Receipt {
                        schema: 1,
                        generation: "a".repeat(64),
                        overlay_sha256: "b".repeat(64),
                        previous_sha256: None,
                        phase: "late-none-request-attempted".into(),
                        removal_boot_id: Some("11111111-1111-4111-8111-111111111111".into()),
                    },
                )
            })
            .collect()
    }
    #[test]
    fn attempted_operation_without_ticket_can_claim_once() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = Directory::open(temporary.path()).unwrap();
        let mut members = members();
        let boot = members[0].1.removal_boot_id.clone().unwrap();
        for (_, receipt) in &mut members {
            receipt.phase = "operation-reboot-attempted".into();
        }
        // One member was removed during an earlier boot and need not be marked
        // attempted again just to bind the full plural collection.
        members[1].1.phase = "operation-awaiting-package-absence".into();
        assert!(claim_in(&directory, &members, &boot).is_err());
        members[1].1.removal_boot_id = Some("22222222-2222-4222-8222-222222222222".into());
        assert!(claim_in(&directory, &members, &boot).unwrap());
        assert!(!claim_in(&directory, &members, &boot).unwrap());
    }
    #[test]
    fn exact_plural_ticket_requests_once_and_rejects_foreign_replay() {
        let t = tempfile::tempdir().unwrap();
        let d = Directory::open(t.path()).unwrap();
        let mut m = members();
        let boot = m[0].1.removal_boot_id.clone().unwrap();
        assert!(claim_in(&d, &m, &boot).unwrap());
        assert!(!claim_in(&d, &m, &boot).unwrap());
        m[1].1.overlay_sha256 = "c".repeat(64);
        assert!(claim_in(&d, &m, &boot).is_err());
    }
    #[test]
    fn existing_russian_only_ticket_remains_replay_compatible() {
        let t = tempfile::tempdir().unwrap();
        let d = Directory::open(t.path()).unwrap();
        let mut russian = members()
            .into_iter()
            .filter(|(variant, _)| variant.owner().agent() == "i18n-ru")
            .collect::<Vec<_>>();
        assert_eq!(russian.len(), 14);
        let boot = russian[0].1.removal_boot_id.clone().unwrap();
        assert!(claim_in(&d, &russian, &boot).unwrap());
        assert!(!claim_in(&d, &russian, &boot).unwrap());
        for (_, receipt) in &mut russian {
            receipt.phase = "late-none-final".into();
        }
        finish_in(&d, &russian, &boot).unwrap();
    }
    #[test]
    fn invalid_or_duplicate_member_cannot_publish_reboot_ticket() {
        let t = tempfile::tempdir().unwrap();
        let d = Directory::open(t.path()).unwrap();
        let mut m = members();
        m[1].0 = m[0].0;
        assert!(claim_in(&d, &m, "11111111-1111-4111-8111-111111111111").is_err());
        assert!(!t.path().join(TICKET).exists());
    }
    #[test]
    fn only_all_terminal_members_retire_ticket_for_successor_generation() {
        let t = tempfile::tempdir().unwrap();
        let d = Directory::open(t.path()).unwrap();
        let mut m = members();
        let boot = m[0].1.removal_boot_id.clone().unwrap();
        assert!(claim_in(&d, &m, &boot).unwrap());
        assert!(finish_in(&d, &m, &boot).is_err());
        for (_, r) in &mut m {
            r.phase = "late-none-final".into();
        }
        finish_in(&d, &m, &boot).unwrap();
        assert!(!t.path().join(TICKET).exists());
        for (_, r) in &mut m {
            r.phase = "late-none-request-attempted".into();
            r.generation = "c".repeat(64);
        }
        assert!(claim_in(&d, &m, &boot).unwrap());
    }

    #[test]
    fn four_member_ticket_rejects_third_and_fourth_authority_changes_without_rewrite() {
        for changed in [2, 3] {
            let t = tempfile::tempdir().unwrap();
            let d = Directory::open(t.path()).unwrap();
            let original: Vec<_> = members().into_iter().take(4).collect();
            assert_eq!(original.len(), 4);
            let boot = original[0].1.removal_boot_id.clone().unwrap();
            assert!(claim_in(&d, &original, &boot).unwrap());
            let before = std::fs::read(t.path().join(TICKET)).unwrap();
            let mut modified = original.clone();
            modified[changed].1.overlay_sha256 = "c".repeat(64);
            assert!(claim_in(&d, &modified, &boot).is_err());
            assert_eq!(std::fs::read(t.path().join(TICKET)).unwrap(), before);
            assert!(!claim_in(&d, &original, &boot).unwrap());
        }
    }

    #[test]
    fn fourth_nonterminal_member_prevents_retirement_of_entire_ticket() {
        let t = tempfile::tempdir().unwrap();
        let d = Directory::open(t.path()).unwrap();
        let mut m: Vec<_> = members().into_iter().take(4).collect();
        assert_eq!(m.len(), 4);
        let boot = m[0].1.removal_boot_id.clone().unwrap();
        assert!(claim_in(&d, &m, &boot).unwrap());
        let before = std::fs::read(t.path().join(TICKET)).unwrap();
        for (_, receipt) in &mut m[..3] {
            receipt.phase = "late-none-final".into();
        }
        assert!(finish_in(&d, &m, &boot).is_err());
        assert_eq!(std::fs::read(t.path().join(TICKET)).unwrap(), before);
        m[3].1.phase = "late-none-final".into();
        finish_in(&d, &m, &boot).unwrap();
        assert!(!t.path().join(TICKET).exists());
    }

    #[test]
    fn six_member_ticket_binds_fifth_and_sixth_authorities_without_rewrite() {
        for changed in [4, 5] {
            let t = tempfile::tempdir().unwrap();
            let d = Directory::open(t.path()).unwrap();
            let original: Vec<_> = members().into_iter().take(6).collect();
            assert_eq!(original.len(), 6);
            let boot = original[0].1.removal_boot_id.clone().unwrap();
            assert!(claim_in(&d, &original, &boot).unwrap());
            let before = std::fs::read(t.path().join(TICKET)).unwrap();
            let mut modified = original.clone();
            modified[changed].1.generation = "c".repeat(64);
            assert!(claim_in(&d, &modified, &boot).is_err());
            assert_eq!(std::fs::read(t.path().join(TICKET)).unwrap(), before);
            assert!(!claim_in(&d, &original, &boot).unwrap());
        }
    }

    #[test]
    fn sixth_nonterminal_member_prevents_six_member_ticket_retirement() {
        let t = tempfile::tempdir().unwrap();
        let d = Directory::open(t.path()).unwrap();
        let mut m: Vec<_> = members().into_iter().take(6).collect();
        assert_eq!(m.len(), 6);
        let boot = m[0].1.removal_boot_id.clone().unwrap();
        assert!(claim_in(&d, &m, &boot).unwrap());
        let before = std::fs::read(t.path().join(TICKET)).unwrap();
        for (_, receipt) in &mut m[..5] {
            receipt.phase = "late-none-final".into();
        }
        assert!(finish_in(&d, &m, &boot).is_err());
        assert_eq!(std::fs::read(t.path().join(TICKET)).unwrap(), before);
        m[5].1.phase = "late-none-final".into();
        finish_in(&d, &m, &boot).unwrap();
        assert!(!t.path().join(TICKET).exists());
    }

    #[test]
    fn all_member_ticket_rejects_last_owner_authority_and_partial_retirement() {
        for changed in [Variant::ALL.len() - 2, Variant::ALL.len() - 1] {
            let t = tempfile::tempdir().unwrap();
            let d = Directory::open(t.path()).unwrap();
            let mut original = members();
            assert_eq!(original.len(), 20);
            let boot = original[0].1.removal_boot_id.clone().unwrap();
            assert!(claim_in(&d, &original, &boot).unwrap());
            let before = std::fs::read(t.path().join(TICKET)).unwrap();
            let mut substituted = original.clone();
            substituted[changed].1.generation = "c".repeat(64);
            assert!(claim_in(&d, &substituted, &boot).is_err());
            assert_eq!(std::fs::read(t.path().join(TICKET)).unwrap(), before);
            assert!(!claim_in(&d, &original, &boot).unwrap());
            for (index, (_, receipt)) in original.iter_mut().enumerate() {
                if index != changed {
                    receipt.phase = "late-none-final".into();
                }
            }
            assert!(finish_in(&d, &original, &boot).is_err());
            assert_eq!(std::fs::read(t.path().join(TICKET)).unwrap(), before);
            original[changed].1.phase = "late-none-final".into();
            finish_in(&d, &original, &boot).unwrap();
            assert!(!t.path().join(TICKET).exists());
        }
    }
}
