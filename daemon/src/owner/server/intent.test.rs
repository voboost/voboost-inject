//! Legacy intent WAL must never become a second writer of desired settings.
use super::super::{journal_name, state, Directory};
use super::*;
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use voboost_contract::desired::{Config, Disposition, Field, Input};
use voboost_contract::runtime_owner::{Command, Request, SCHEMA};

const BOOT: &str = "11111111-1111-4111-8111-111111111111";
const NEXT_BOOT: &str = "22222222-2222-4222-8222-222222222222";
const SESSION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn fixture() -> (tempfile::TempDir, Store, &'static str) {
    let root = tempfile::Builder::new()
        .prefix(".intent-test-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let source = super::super::super::native::CODECS
        .iter()
        .find(|codec| codec.pending_journals.contains(&"intent"))
        .expect("native intent tests require generated VOBOOST_NATIVE_REGISTRY")
        .id;
    let config = json!({"schemaVersion":2,"startup":"interface","userRevision":0,
        "fieldRevisions":{},"agents":{
        (source):{"enabled":true,"options":{"intent":"observe"}}
    }});
    Directory::open(root.path())
        .unwrap()
        .write_atomic("agents.json", &serde_json::to_vec(&config).unwrap(), 0o600)
        .unwrap();
    let mut store = Store::new(root.path(), SESSION).unwrap();
    store.initialize_native(BOOT).unwrap();
    (root, store, source)
}
fn record(capture: u64, choice: &str, pending: bool) -> Value {
    json!({"schemaVersion":1,"bootId":BOOT,"captureNs":capture,"pid":42,
        "requestId":capture,"choice":choice,"pending":pending})
}
fn call(store: &mut Store, operation: &str, source: &str, record: Value) -> Value {
    let bytes = serde_json::to_vec(&json!({"schemaVersion":SCHEMA,"session":SESSION,
        "requestId":1,"command":{"operation":operation,"source":source,"key":"intent","record":record}})).unwrap();
    let request = Request::decode(&bytes).expect("legacy command remains decodable");
    serde_json::to_value(store.dispatch(request).outcome).unwrap()
}
fn seed_wal(root: &std::path::Path, source: &str, bytes: &[u8]) {
    state::open_directory(&root.join("state"), true)
        .unwrap()
        .write_atomic(&journal_name(source, "intent").unwrap(), bytes, 0o600)
        .unwrap();
}
fn saved_off(store: &mut Store, source: &str) -> Vec<u8> {
    let result = store
        .dispatch_from(
            Request {
                schema_version: SCHEMA,
                session: SESSION.into(),
                request_id: 10,
                command: Command::SaveDesired {
                    field: Field::Option {
                        agent: source.into(),
                        key: "intent".into(),
                    },
                    value: json!("off"),
                    input: Input {
                        boot_id: BOOT.into(),
                        endpoint_epoch: 1,
                        request_id: 10,
                        injector_pid: 42,
                        injector_starttime: 100,
                    },
                },
            },
            (42, 100),
        )
        .outcome;
    let super::super::Outcome::DesiredSaved {
        revision,
        disposition,
        config,
    } = result
    else {
        panic!("OFF was not saved: {result:?}")
    };
    assert_eq!(revision, 1);
    assert_eq!(disposition, Disposition::Saved);
    let bytes = store.config().unwrap().unwrap();
    assert_eq!(bytes, config.as_bytes());
    assert_eq!(Config::decode(&bytes).unwrap().user_revision, 1);
    bytes
}
fn assert_saved(store: &Store, source: &str, expected: &[u8]) {
    let current = store.config().unwrap().unwrap();
    assert_eq!(
        current, expected,
        "recovery changed authoritative config bytes"
    );
    let config = Config::decode(&current).unwrap();
    assert_eq!(config.user_revision, 1);
    assert_eq!(config.agents[source].options["intent"], "off");
    assert_eq!(
        config.field_revisions[&format!("agents/{source}/options/intent")].revision,
        1
    );
}

#[test]
fn retired_prepare_and_finish_never_write_or_return_saved_receipts() {
    let (root, mut store, source) = fixture();
    let saved = saved_off(&mut store, source);
    for existing in [false, true] {
        if existing {
            seed_wal(
                root.path(),
                source,
                record(100, "on", true).to_string().as_bytes(),
            );
        }
        let previous = store.journal(source, "intent").unwrap();
        let admission = store.native_enabled().clone();
        for capture in [100, 200, 50] {
            for choice in ["on", "off"] {
                for (operation, pending) in [("prepare-intent", true), ("finish-intent", false)] {
                    assert_eq!(
                        call(
                            &mut store,
                            operation,
                            source,
                            record(capture, choice, pending)
                        ),
                        json!({"status":"unavailable"})
                    );
                    assert_saved(&store, source, &saved);
                    assert_eq!(store.journal(source, "intent").unwrap(), previous);
                    assert_eq!(store.native_enabled(), &admission);
                }
            }
        }
    }
}

#[test]
fn stamped_off_supersedes_old_on_and_malformed_wal_during_recovery_or_boot() {
    for busy in [false, true] {
        for wal in [record(100, "on", true).to_string(), "{".into()] {
            let (root, mut store, source) = fixture();
            seed_wal(root.path(), source, wal.as_bytes());
            let saved = saved_off(&mut store, source);
            let guard = busy.then(|| {
                voboost_contract::operation::GenerationGuard::acquire_in(root.path()).unwrap()
            });
            for _ in 0..2 {
                assert!(!store.recover_intent(source, "intent").unwrap());
                store.refresh_native().unwrap();
                assert_saved(&store, source, &saved);
                assert_eq!(
                    store.journal(source, "intent").unwrap().unwrap(),
                    wal.as_bytes()
                );
            }
            for boot in [BOOT, NEXT_BOOT] {
                let mut restarted = Store::new(root.path(), SESSION).unwrap();
                restarted.initialize_native(boot).unwrap();
                assert_saved(&restarted, source, &saved);
            }
            drop(guard);
            assert!(!store.recover_intent(source, "intent").unwrap());
            assert_saved(&store, source, &saved);
            assert_eq!(
                store.journal(source, "intent").unwrap().unwrap(),
                wal.as_bytes()
            );
        }
    }
}

#[test]
fn legacy_pending_wal_without_stamp_cannot_manufacture_user_action() {
    for choice in ["on", "off"] {
        let (root, mut store, source) = fixture();
        let original = store.config().unwrap().unwrap();
        seed_wal(
            root.path(),
            source,
            record(100, choice, true).to_string().as_bytes(),
        );
        assert!(store.recover_intent(source, "intent").is_err());
        store.initialize_native(NEXT_BOOT).unwrap();
        assert_eq!(store.config().unwrap().unwrap(), original);
        assert_eq!(Config::decode(&original).unwrap().user_revision, 0);
        assert!(
            !store.native_enabled().contains(source),
            "unresolved legacy intent must fail closed"
        );
    }
}

#[test]
fn malformed_wal_fails_closed_without_rewriting_user_settings() {
    for wal in [b"{".as_slice(), b"null", b"{}"] {
        let (root, mut store, source) = fixture();
        let original = store.config().unwrap().unwrap();
        seed_wal(root.path(), source, wal);
        assert!(store.recover_intent(source, "intent").is_err());
        store.refresh_native().unwrap();
        assert!(!store.native_enabled().contains(source));
        assert_eq!(store.config().unwrap().unwrap(), original);
        assert_eq!(store.journal(source, "intent").unwrap().unwrap(), wal);
        let mut restarted = Store::new(root.path(), SESSION).unwrap();
        restarted.initialize_native(NEXT_BOOT).unwrap();
        assert!(!restarted.native_enabled().contains(source));
        assert_eq!(restarted.config().unwrap().unwrap(), original);
        assert_eq!(restarted.journal(source, "intent").unwrap().unwrap(), wal);
    }
}

#[test]
fn generic_journal_cannot_replace_legacy_captured_choice() {
    let (root, mut store, source) = fixture();
    let saved = saved_off(&mut store, source);
    let retained = record(100, "on", true).to_string();
    seed_wal(root.path(), source, retained.as_bytes());
    let outcome = store
        .dispatch(Request {
            schema_version: SCHEMA,
            session: SESSION.into(),
            request_id: 11,
            command: Command::ReplaceJournal {
                source: source.into(),
                key: "intent".into(),
                expected: Some(retained.clone()),
                next: record(200, "on", false).to_string(),
            },
        })
        .outcome;
    assert!(matches!(outcome, super::super::Outcome::Unavailable {}));
    assert_eq!(
        store.journal(source, "intent").unwrap().unwrap(),
        retained.as_bytes()
    );
    assert_saved(&store, source, &saved);
}
