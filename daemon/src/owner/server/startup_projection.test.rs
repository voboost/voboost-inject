//! Startup projection through the actual owner dispatch and durable desired document.
use super::*;
use serde_json::json;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use voboost_contract::desired::{Config, Disposition, Field, Input};

const BOOT: &str = "11111111-1111-4111-8111-111111111111";
const NEXT_BOOT: &str = "22222222-2222-4222-8222-222222222222";
const PRODUCER: (i32, u64) = (42, 100);

fn fixture() -> (tempfile::TempDir, Store, serde_json::Value) {
    let root = tempfile::Builder::new()
        .prefix(".startup-projection-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let config = json!({
        "schemaVersion": 2, "startup": "interface", "userRevision": 0,
        "fieldRevisions": {},
        "agents": {
            "agent-a": {"enabled": true, "options": {
                "language": "system", "caption": "Режим 中文",
                "nested": {"list": [true, false, null, 0, -4, "off"]}
            }},
            "agent-b": {"enabled": false, "options": {"selection": "saved"}}
        }
    });
    Config::decode(&serde_json::to_vec(&config).unwrap()).unwrap();
    Directory::open(root.path())
        .unwrap()
        .write_atomic("agents.json", &serde_json::to_vec(&config).unwrap(), 0o600)
        .unwrap();
    let mut store = Store::new(root.path(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    store.initialize_native(BOOT).unwrap();
    (root, store, config)
}

fn save(store: &mut Store, startup: &str, boot: &str, request_id: u64) -> Outcome {
    store
        .dispatch_from(
            Request {
                schema_version: SCHEMA,
                session: store.session().into(),
                request_id,
                command: Command::SaveDesired {
                    field: Field::Startup,
                    value: startup.into(),
                    input: Input {
                        boot_id: boot.into(),
                        endpoint_epoch: 1,
                        request_id,
                        injector_pid: PRODUCER.0,
                        injector_starttime: PRODUCER.1,
                    },
                },
            },
            PRODUCER,
        )
        .outcome
}

fn session(store: &Store) -> serde_json::Value {
    serde_json::from_str(&store.startup_session().unwrap().unwrap()).unwrap()
}

#[test]
fn startup_save_preserves_the_complete_current_configuration_and_running_boot() {
    let (root, mut store, original) = fixture();
    let running = session(&store);
    assert_eq!(
        running,
        json!({"schemaVersion":1,"bootId":BOOT,"startup":"interface"})
    );
    for (index, requested) in ["hidden", "none", "hidden"].into_iter().enumerate() {
        let revision = index as u64 + 1;
        let outcome = save(&mut store, requested, BOOT, revision);
        let Outcome::DesiredSaved {
            revision: saved_revision,
            disposition,
            config,
        } = outcome
        else {
            panic!("startup save failed: {outcome:?}");
        };
        assert_eq!(saved_revision, revision);
        assert_eq!(disposition, Disposition::Saved);
        let durable = fs::read(root.path().join("agents.json")).unwrap();
        assert_eq!(durable, config.as_bytes());
        let desired = Config::decode(&durable).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&durable).unwrap();
        assert_eq!(value["agents"], original["agents"]);
        assert_eq!(desired.startup, requested);
        assert_eq!(desired.user_revision, revision);
        assert_eq!(desired.field_revisions.len(), 1);
        assert_eq!(desired.field_revisions["startup"].revision, revision);
        assert_eq!(desired.field_revisions["startup"].input.boot_id, BOOT);
        assert_eq!(
            desired.field_revisions["startup"].input.injector_pid,
            PRODUCER.0
        );
        assert_eq!(session(&store), running);
        assert_eq!(store.running_startup.as_deref(), Some("interface"));
        assert!(store.desired_off_fences.is_empty());
    }
    store.initialize_native(NEXT_BOOT).unwrap();
    assert_eq!(store.running_startup.as_deref(), Some("hidden"));
    assert_eq!(
        session(&store),
        json!({"schemaVersion":1,"bootId":NEXT_BOOT,"startup":"hidden"})
    );
}

#[test]
fn startup_none_keeps_interface_across_owner_restart_and_applies_on_next_boot() {
    let (root, mut store, _) = fixture();
    assert!(matches!(
        save(&mut store, "none", BOOT, 1),
        Outcome::DesiredSaved {
            disposition: Disposition::Saved,
            ..
        }
    ));
    assert_eq!(store.running_startup.as_deref(), Some("interface"));
    let saved = fs::read(root.path().join("agents.json")).unwrap();
    let mut restarted = Store::new(root.path(), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
    restarted.initialize_native(BOOT).unwrap();
    assert_eq!(restarted.running_startup.as_deref(), Some("interface"));
    restarted.initialize_native(NEXT_BOOT).unwrap();
    assert_eq!(restarted.running_startup.as_deref(), Some("none"));
    assert_eq!(
        session(&restarted),
        json!({"schemaVersion":1,"bootId":NEXT_BOOT,"startup":"none"})
    );
    assert_eq!(fs::read(root.path().join("agents.json")).unwrap(), saved);
    assert!(matches!(
        save(&mut restarted, "interface", BOOT, 2),
        Outcome::Unavailable {}
    ));
    assert_eq!(fs::read(root.path().join("agents.json")).unwrap(), saved);
}

#[test]
fn unknown_configuration_fields_fail_closed_without_rewriting_desired_or_running_boot() {
    for location in ["root", "agent"] {
        let (root, mut store, mut config) = fixture();
        if location == "root" {
            config["unexpected"] = true.into();
        } else {
            config["agents"]["agent-a"]["unexpected"] = true.into();
        }
        let bytes = serde_json::to_vec(&config).unwrap();
        Directory::open(root.path())
            .unwrap()
            .write_atomic("agents.json", &bytes, 0o600)
            .unwrap();
        let running = session(&store);
        assert!(matches!(
            save(&mut store, "none", BOOT, 1),
            Outcome::Unavailable {}
        ));
        assert_eq!(fs::read(root.path().join("agents.json")).unwrap(), bytes);
        assert_eq!(session(&store), running);
        assert_eq!(store.running_startup.as_deref(), Some("interface"));
    }
}
