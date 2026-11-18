use super::*;
use alloc::{vec, vec::Vec};

#[derive(Default)]
struct Fake {
    calls: Vec<&'static str>,
    failures: Vec<&'static str>,
    readonly: bool,
    changed: bool,
}
impl Fake {
    fn call(&mut self, name: &'static str) -> Result<()> {
        self.calls.push(name);
        if let Some(at) = self.failures.iter().position(|v| *v == name) {
            self.failures.remove(at);
            return Err(alloc::format!("injected {name} failure"));
        }
        Ok(())
    }
}
impl Edit for Fake {
    fn writable(&mut self) -> Result<()> {
        self.call("rw")?;
        self.readonly = false;
        Ok(())
    }
    fn verify_writable(&mut self) -> Result<()> {
        self.call("verify-rw")?;
        assert!(!self.readonly);
        Ok(())
    }
    fn replace(&mut self) -> Result<()> {
        // A write error can happen after the atomic rename actually committed.
        self.changed = true;
        self.call("write")
    }
    fn rollback(&mut self) -> Result<()> {
        self.call("rollback")?;
        self.changed = false;
        Ok(())
    }
    fn readonly(&mut self) -> Result<()> {
        self.call("ro")?;
        self.readonly = true;
        Ok(())
    }
    fn verify_readonly(&mut self) -> Result<()> {
        self.call("verify-ro")?;
        assert!(self.readonly);
        Ok(())
    }
    fn verify_before(&mut self) -> Result<()> {
        self.call("verify-before")?;
        if !self.readonly || self.changed {
            return Err("before/RO differs".into());
        }
        Ok(())
    }
    fn verify_after(&mut self) -> Result<()> {
        self.call("verify-after")?;
        if !self.readonly || !self.changed {
            return Err("after/RO differs".into());
        }
        Ok(())
    }
}
#[test]
fn successful_edit_completes_only_after_verified_ro() {
    let mut edit = Fake {
        readonly: true,
        ..Fake::default()
    };
    assert!(matches!(execute(&mut edit), ExecuteOutcome::Applied));
    assert!(edit.readonly && edit.changed);
    assert_eq!(
        edit.calls,
        [
            "rw",
            "verify-rw",
            "write",
            "ro",
            "verify-ro",
            "verify-after"
        ]
    );
}
#[test]
fn precommit_and_write_failures_rollback_and_restore_ro() {
    for failure in ["rw", "verify-rw", "write"] {
        let mut edit = Fake {
            readonly: true,
            failures: vec![failure],
            ..Fake::default()
        };
        assert!(matches!(execute(&mut edit), ExecuteOutcome::RolledBack(_)));
        assert!(edit.readonly && !edit.changed);
        assert!(edit.calls.contains(&"rollback"));
        assert_eq!(
            &edit.calls[edit.calls.len() - 3..],
            ["ro", "verify-ro", "verify-before"]
        );
    }
}
#[test]
fn proven_rollback_has_recoverable_terminal_outcome() {
    let mut edit = Fake {
        readonly: true,
        failures: vec!["write"],
        ..Fake::default()
    };
    let outcome = execute(&mut edit);
    assert!(edit.readonly && !edit.changed);
    assert!(matches!(outcome, ExecuteOutcome::RolledBack(_)));
}
#[test]
fn failed_ro_completion_rolls_back_instead_of_claiming_success() {
    for failure in ["ro", "verify-ro"] {
        let mut edit = Fake {
            readonly: true,
            failures: vec![failure],
            ..Fake::default()
        };
        assert!(matches!(execute(&mut edit), ExecuteOutcome::RolledBack(_)));
        assert!(edit.readonly && !edit.changed);
        assert!(edit.calls.contains(&"rollback"));
    }
}
#[test]
fn rollback_or_final_ro_failure_is_reported_without_completion() {
    for failures in [
        vec!["write", "rollback"],
        vec!["write", "ro"],
        vec!["ro", "ro"],
    ] {
        let mut edit = Fake {
            readonly: true,
            failures,
            ..Fake::default()
        };
        assert!(matches!(
            execute(&mut edit),
            ExecuteOutcome::RecoveryRequired(_)
        ));
        assert!(edit.calls.contains(&"ro"));
    }
}

fn prepared() -> Journal {
    Journal {
        schema_version: 2,
        transaction_id: "a".repeat(64),
        startup_file: "/scripts/startup_cluster.sh".into(),
        before_sha256: voboost_contract_core::hash(b"exact original"),
        after_sha256: voboost_contract_core::hash(b"exact installed"),
        mount: MountIdentity {
            flags: libc::ST_RDONLY,
            filesystem_id: 17,
            root_device: "17".into(),
            root_inode: 1,
            root_mode: 0o40775,
            root_uid: 0,
            root_gid: 0,
            parent_device: "17".into(),
            parent_inode: 33,
            parent_mode: 0o40755,
            parent_uid: 0,
            parent_gid: 0,
        },
        state: JournalState::Prepared,
    }
}
fn store() -> (tempfile::TempDir, crate::fs::Dir) {
    use std::os::unix::fs::PermissionsExt;
    let base =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build/cluster-test-tmp");
    std::fs::create_dir_all(&base).unwrap();
    let temp = tempfile::tempdir_in(base).unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = std::fs::canonicalize(temp.path()).unwrap();
    let dir = crate::fs::Dir::open(path.to_str().unwrap(), crate::fs::uid().unwrap()).unwrap();
    (temp, dir)
}
fn persist(dir: &crate::fs::Dir, record: &Journal) -> Result<()> {
    dir.write(
        "startup-edit.json",
        &voboost_contract_core::ascii_json(record)?,
        0o600,
    )
}
fn read(dir: &crate::fs::Dir) -> Journal {
    voboost_contract_core::parse_canonical(
        &dir.read("startup-edit.json", 16384, 0o600).unwrap(),
        16384,
    )
    .unwrap()
}
#[test]
fn verified_rollback_persists_terminal_and_next_restore_admission_succeeds() {
    for failure in ["rw", "verify-rw", "write", "ro", "verify-ro"] {
        let (_temp, dir) = store();
        let mut journal = prepared();
        persist(&dir, &journal).unwrap();
        let mut edit = Fake {
            readonly: true,
            failures: vec![failure],
            ..Fake::default()
        };
        assert!(finish_journal(&mut journal, execute(&mut edit), |j| persist(&dir, j)).is_err());
        let mut durable = read(&dir);
        assert_eq!(durable.state, JournalState::RolledBack);
        let identity = durable.mount.clone();
        let before = durable.before_sha256.clone();
        recover_journal(&mut durable, &identity, &before, |j| persist(&dir, j)).unwrap();
        assert_eq!(read(&dir).state, JournalState::RolledBack);
    }
}
#[test]
fn final_journal_write_error_and_crash_are_recovered_from_exact_ro_evidence() {
    for applied in [false, true] {
        let (_temp, dir) = store();
        let mut journal = prepared();
        persist(&dir, &journal).unwrap();
        let outcome = if applied {
            ExecuteOutcome::Applied
        } else {
            ExecuteOutcome::RolledBack("original error".into())
        };
        assert!(finish_journal(&mut journal, outcome, |_| Err(
            "injected final journal write error".into()
        ))
        .is_err());
        let mut durable = read(&dir);
        assert_eq!(durable.state, JournalState::Prepared);
        let identity = durable.mount.clone();
        let current = if applied {
            durable.after_sha256.clone()
        } else {
            durable.before_sha256.clone()
        };
        recover_journal(&mut durable, &identity, &current, |j| persist(&dir, j)).unwrap();
        assert_eq!(
            read(&dir).state,
            if applied {
                JournalState::Applied
            } else {
                JournalState::RolledBack
            }
        );
        // Crash before starting RW and crash after commit/before terminal write
        // have the same on-disk Prepared form and use this same admission path.
    }
}
#[test]
fn uncertain_rollback_or_ro_never_marks_terminal() {
    for failures in [
        vec!["write", "rollback"],
        vec!["write", "ro"],
        vec!["write", "verify-before"],
        vec!["verify-after"],
    ] {
        let (_temp, dir) = store();
        let mut journal = prepared();
        persist(&dir, &journal).unwrap();
        let mut edit = Fake {
            readonly: true,
            failures,
            ..Fake::default()
        };
        let result = execute(&mut edit);
        assert!(matches!(result, ExecuteOutcome::RecoveryRequired(_)));
        assert!(finish_journal(&mut journal, result, |j| persist(&dir, j)).is_err());
        assert_eq!(read(&dir).state, JournalState::Prepared);
    }
}
#[test]
fn recovery_rejects_foreign_identity_flags_path_transaction_and_bytes() {
    let original = prepared();
    let current = original.after_sha256.clone();
    let mutations: &[fn(&mut MountIdentity)] = &[
        |m| m.flags = 0,
        |m| m.flags |= 0x100,
        |m| m.filesystem_id += 1,
        |m| m.root_device = "18".into(),
        |m| m.root_inode += 1,
        |m| m.root_mode ^= 1,
        |m| m.root_uid += 1,
        |m| m.root_gid += 1,
        |m| m.parent_device = "18".into(),
        |m| m.parent_inode += 1,
        |m| m.parent_mode ^= 1,
        |m| m.parent_uid += 1,
        |m| m.parent_gid += 1,
    ];
    for mutate in mutations {
        let mut observed = original.mount.clone();
        mutate(&mut observed);
        assert!(
            recover_journal(&mut original.clone(), &observed, &current, |_| panic!(
                "must not persist foreign recovery"
            ))
            .is_err()
        );
    }
    for mutate in [
        (|j: &mut Journal| j.transaction_id = "../bad".into()) as fn(&mut Journal),
        |j| j.startup_file = "/scripts/other.sh".into(),
        |j| j.before_sha256 = "invalid".into(),
        |j| j.schema_version = 1,
        |j| j.state = JournalState::RolledBack,
    ] {
        let mut previous = original.clone();
        mutate(&mut previous);
        assert!(
            recover_journal(&mut previous, &original.mount, &current, |_| panic!(
                "must not persist invalid recovery"
            ))
            .is_err()
        );
    }
    assert!(recover_journal(
        &mut original.clone(),
        &original.mount,
        &"f".repeat(64),
        |_| panic!("must not persist unknown bytes")
    )
    .is_err());
}
#[test]
fn recovery_terminal_write_must_succeed_before_admission() {
    let mut journal = prepared();
    let identity = journal.mount.clone();
    let before = journal.before_sha256.clone();
    assert!(recover_journal(&mut journal, &identity, &before, |_| Err(
        "injected persist failure".into()
    ))
    .is_err());
}
