//! A saved removal is authoritative only once its targets applied it.
use super::desired::Config;
use super::*;
use crate::native::Host;
use serde_json::json;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use voboost_contract::desired::{Disposition, Field, Input};

const SESSION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOOT: &str = "11111111-1111-4111-8111-111111111111";
const PRODUCER: (i32, u64) = (42, 100);

fn fixture() -> (tempfile::TempDir, Store, &'static str) {
    let root = tempfile::Builder::new()
        .prefix(".owner-withdrawal-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let source = crate::native::CODECS
        .first()
        .expect("native owner tests require generated registry")
        .id;
    let config = json!({
        "schemaVersion": 2, "startup": "interface", "userRevision": 0,
        "fieldRevisions": {},
        "agents": { (source): {"enabled": true, "options": {"intent": "observe"}} }
    });
    Directory::open(root.path())
        .unwrap()
        .write_atomic("agents.json", config.to_string().as_bytes(), 0o600)
        .unwrap();
    let mut store = Store::new(root.path(), SESSION).unwrap();
    store.initialize_native(BOOT).unwrap();
    (root, store, source)
}

fn request(command: Command, request_id: u64) -> Request {
    Request {
        schema_version: SCHEMA,
        session: SESSION.into(),
        request_id,
        command,
    }
}

fn save(store: &mut Store, source: &str, enabled: bool, request_id: u64) -> Outcome {
    let field = Field::Enabled {
        agent: source.into(),
    };
    store
        .dispatch_from(
            request(
                Command::SaveDesired {
                    field,
                    value: enabled.into(),
                    input: Input {
                        boot_id: BOOT.into(),
                        endpoint_epoch: 1,
                        request_id,
                        injector_pid: PRODUCER.0,
                        injector_starttime: PRODUCER.1,
                    },
                },
                request_id,
            ),
            PRODUCER,
        )
        .outcome
}

fn confirm(store: &mut Store, source: &str) -> Outcome {
    store
        .dispatch_from(
            request(
                Command::ConfirmAgentWithdrawn {
                    source: source.into(),
                },
                9,
            ),
            PRODUCER,
        )
        .outcome
}

#[test]
fn saved_off_revokes_native_admission_before_ui_cleanup() {
    let (root, mut store, source) = fixture();
    assert!(Host::enabled(&store, source));
    assert!(matches!(
        save(&mut store, source, false, 2),
        Outcome::DesiredSaved {
            disposition: Disposition::Saved,
            ..
        }
    ));
    let durable = Config::decode(&fs::read(root.path().join("agents.json")).unwrap()).unwrap();
    assert!(!durable.agents[source].enabled);
    assert!(store.desired_off_fences.is_empty());
    assert!(!store.native_enabled().contains(source));
    assert!(!Host::enabled(&store, source));
    assert!(store.admission(source).is_none());
    assert!(matches!(confirm(&mut store, source), Outcome::Withdrawn {}));
    assert!(!store.native_enabled().contains(source));
    assert!(!Host::enabled(&store, source));
    assert!(store.admission(source).is_none());
}

#[test]
fn an_unconfirmed_removal_is_forced_when_its_bound_expires() {
    let (_root, mut store, source) = fixture();
    assert!(matches!(
        save(&mut store, source, false, 2),
        Outcome::DesiredSaved { .. }
    ));
    store.withdrawing.insert(
        source.into(),
        std::time::Instant::now() - std::time::Duration::from_secs(1),
    );
    store.expire_withdrawals();
    assert!(store.withdrawing.is_empty());
    assert!(!store.native_enabled().contains(source));
    assert!(store.admission(source).is_none());
}

#[test]
fn pending_ui_cleanup_never_restores_native_admission() {
    let (_root, mut store, source) = fixture();
    assert!(matches!(
        save(&mut store, source, false, 2),
        Outcome::DesiredSaved { .. }
    ));
    store.expire_withdrawals();
    assert!(!store.native_enabled().contains(source));
    assert!(store.admission(source).is_none());
}

#[test]
fn a_removal_that_never_persisted_stays_a_denial_without_a_withdrawal() {
    let (_root, mut store, source) = fixture();
    let field = Field::Enabled {
        agent: source.into(),
    };
    let input = Input {
        boot_id: BOOT.into(),
        endpoint_epoch: 1,
        request_id: 2,
        injector_pid: PRODUCER.0,
        injector_starttime: PRODUCER.1,
    };
    assert!(store
        .save_desired_with(&field, &false.into(), &input, |_, _| {
            Err(io::Error::other("injected file fsync failure"))
        })
        .is_err());
    assert!(store.desired_off_fences.contains(&field.path()));
    assert!(store.withdrawing.is_empty());
    assert!(!store.native_enabled().contains(source));
    assert!(store.admission(source).is_none());
}

#[test]
fn re_enabling_during_the_window_keeps_the_source_admitted() {
    let (root, mut store, source) = fixture();
    assert!(matches!(
        save(&mut store, source, false, 2),
        Outcome::DesiredSaved {
            disposition: Disposition::Saved,
            ..
        }
    ));
    assert!(!store.withdrawing.is_empty());
    assert!(matches!(
        save(&mut store, source, true, 3),
        Outcome::DesiredSaved {
            disposition: Disposition::Saved,
            ..
        }
    ));
    assert!(store.withdrawing.is_empty());
    let durable = Config::decode(&fs::read(root.path().join("agents.json")).unwrap()).unwrap();
    assert!(durable.agents[source].enabled);
    // A confirmation that arrives after the user re-enabled the agent cannot
    // withdraw it: only a pending removal is confirmable.
    assert!(matches!(confirm(&mut store, source), Outcome::Withdrawn {}));
    assert!(store.withdrawing.is_empty());
}

#[test]
fn a_confirmation_without_a_pending_removal_is_inert() {
    let (_root, mut store, source) = fixture();
    let admitted = store.admission(source).unwrap().lease.revision;
    assert!(matches!(confirm(&mut store, source), Outcome::Withdrawn {}));
    assert!(store.native_enabled().contains(source));
    assert!(Host::enabled(&store, source));
    assert_eq!(store.admission(source).unwrap().lease.revision, admitted);
}

#[test]
fn a_late_ui_choice_cannot_reenable_saved_off() {
    let (root, mut store, source) = fixture();
    save(&mut store, source, false, 2);
    let outcome = store
        .dispatch_from(
            request(
                Command::SaveDesired {
                    field: Field::Option {
                        agent: source.into(),
                        key: "intent".into(),
                    },
                    value: "on".into(),
                    input: Input {
                        boot_id: BOOT.into(),
                        endpoint_epoch: 1,
                        request_id: 3,
                        injector_pid: PRODUCER.0,
                        injector_starttime: PRODUCER.1,
                    },
                },
                3,
            ),
            PRODUCER,
        )
        .outcome;
    assert!(matches!(
        outcome,
        Outcome::DesiredSaved {
            disposition: Disposition::Saved,
            ..
        }
    ));
    let durable = Config::decode(&fs::read(root.path().join("agents.json")).unwrap()).unwrap();
    assert!(!durable.agents[source].enabled);
    assert!(!Host::enabled(&store, source));
    assert!(store.admission(source).is_none());
}
