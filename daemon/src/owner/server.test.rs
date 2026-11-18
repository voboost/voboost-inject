use super::*;
use serde_json::json;
use std::fs;
use std::os::unix::fs::PermissionsExt;
fn root() -> tempfile::TempDir {
    let d = tempfile::Builder::new()
        .prefix(".owner-server-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .unwrap();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o755)).unwrap();
    d
}
fn call(store: &mut Store, session: &str, command: Command) -> Outcome {
    let wire = serde_json::to_vec(&Request {
        schema_version: SCHEMA,
        session: session.into(),
        request_id: 1,
        command,
    })
    .unwrap();
    store.dispatch(Request::decode(&wire).unwrap()).outcome
}
fn stamped_off(bytes: &str, source: &str, key: &str) -> String {
    use voboost_contract::desired::{Config, Field, Input};
    let mut config = Config::decode(bytes.as_bytes()).unwrap();
    config
        .save(
            "11111111-1111-4111-8111-111111111111",
            &Field::Option {
                agent: source.into(),
                key: key.into(),
            },
            &json!("off"),
            &Input {
                boot_id: "11111111-1111-4111-8111-111111111111".into(),
                endpoint_epoch: 2,
                request_id: 99,
                injector_pid: 42,
                injector_starttime: 100,
            },
            &[],
        )
        .unwrap();
    serde_json::to_string(&config).unwrap()
}
const SESSION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn conditional_media_clear_preserves_newer_selection_and_survives_restart() {
    macro_rules! assert_outcome {
        ($actual:expr, $expected:expr) => {
            assert_eq!(
                serde_json::to_value($actual).unwrap(),
                serde_json::to_value($expected).unwrap()
            )
        };
    }
    let root = root();
    let mut store = Store::new(root.path(), SESSION).unwrap();
    let clear = |expected: &str| Command::ClearControllerState {
        source: "media-apps".into(),
        key: "media-selected-package".into(),
        expected: expected.into(),
    };
    assert_outcome!(
        call(&mut store, SESSION, clear("old.app")),
        Outcome::StateCleared { cleared: false }
    );
    for value in ["old.app", "new.app"] {
        assert_outcome!(
            call(
                &mut store,
                SESSION,
                Command::WriteControllerState {
                    source: "media-apps".into(),
                    key: "media-selected-package".into(),
                    value: json!(value),
                }
            ),
            Outcome::Written {}
        );
    }
    assert_outcome!(
        call(&mut store, SESSION, clear("old.app")),
        Outcome::StateCleared { cleared: false }
    );
    assert_outcome!(
        call(
            &mut store,
            SESSION,
            Command::ReadControllerState {
                source: "media-apps".into(),
                key: "media-selected-package".into(),
            }
        ),
        Outcome::State {
            value: Some(json!("new.app"))
        }
    );
    assert_outcome!(
        call(&mut store, SESSION, clear("new.app")),
        Outcome::StateCleared { cleared: true }
    );
    drop(store);
    let mut restarted = Store::new(root.path(), SESSION).unwrap();
    assert_outcome!(
        call(
            &mut restarted,
            SESSION,
            Command::ReadControllerState {
                source: "media-apps".into(),
                key: "media-selected-package".into(),
            }
        ),
        Outcome::State {
            value: Some(json!(""))
        }
    );
    assert_outcome!(
        call(&mut restarted, SESSION, clear("new.app")),
        Outcome::StateCleared { cleared: false }
    );
}
#[test]
fn owner_startup_old_capture_preserves_newer_desired_off_before_native_admission() {
    for codec in super::super::native::CODECS
        .iter()
        .filter(|c| !c.pending_journals.is_empty())
    {
        let root = root();
        let config = json!({"schemaVersion":2,"userRevision":0,"fieldRevisions":{},"startup":"interface","agents":{
                (codec.id):{"enabled":true,"options":{"intent":"on"}},"unrelated":{"enabled":false,"options":{"keep":"value"}}
            }}).to_string();
        let key = codec.pending_journals[0];
        let config = stamped_off(&config, codec.id, key);
        Directory::open(root.path())
            .unwrap()
            .write_atomic("agents.json", config.as_bytes(), 0o600)
            .unwrap();
        let pending = json!({"schemaVersion":1,"bootId":"22222222-2222-4222-8222-222222222222",
                "captureNs":10,"pid":100,"requestId":1,"choice":"on","pending":true})
        .to_string();
        state::open_directory(&root.path().join("state"), true)
            .unwrap()
            .write_atomic(
                &journal_name(codec.id, key).unwrap(),
                pending.as_bytes(),
                0o600,
            )
            .unwrap();
        let mut restarted = Store::new(root.path(), SESSION).unwrap();
        restarted
            .initialize_native("11111111-1111-4111-8111-111111111111")
            .unwrap();
        let expected: serde_json::Value = serde_json::from_str(&config).unwrap();
        assert_eq!(expected["userRevision"], 1);
        let actual: serde_json::Value =
            serde_json::from_slice(&fs::read(root.path().join("agents.json")).unwrap()).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(
            fs::read(root.path().join("agents.json")).unwrap(),
            config.as_bytes()
        );
        let record = voboost_contract::runtime_owner::CapturedIntent::decode(
            &restarted.journal(codec.id, key).unwrap().unwrap(),
        )
        .unwrap();
        // Reading retained legacy evidence never grants it desired authority.
        assert_eq!(record.choice, "on");
        assert!(restarted.native_enabled().contains(codec.id));
        let before = fs::read(root.path().join("agents.json")).unwrap();
        assert!(matches!(
            call(
                &mut restarted,
                SESSION,
                Command::RecoverIntent {
                    source: codec.id.into(),
                    key: key.into()
                }
            ),
            Outcome::Written {}
        ));
        assert_eq!(fs::read(root.path().join("agents.json")).unwrap(), before);
    }
}

#[test]
fn busy_recovery_cannot_promote_unstamped_wal_after_operation_release() {
    for codec in super::super::native::CODECS
        .iter()
        .filter(|c| !c.pending_journals.is_empty())
    {
        let root = root();
        let config = json!({"schemaVersion":2,"userRevision":0,"fieldRevisions":{},"startup":"interface","agents":{
                (codec.id):{"enabled":true,"options":{"intent":"on"}},"unrelated":{"enabled":true,"options":{}}
            }}).to_string();
        let key = codec.pending_journals[0];
        Directory::open(root.path())
            .unwrap()
            .write_atomic("agents.json", config.as_bytes(), 0o600)
            .unwrap();
        let mut owner = Store::new(root.path(), SESSION).unwrap();
        let pending = json!({"schemaVersion":1,"bootId":"11111111-1111-4111-8111-111111111111",
                "captureNs":10,"pid":100,"requestId":1,"choice":"on","pending":true})
        .to_string();
        state::open_directory(&root.path().join("state"), true)
            .unwrap()
            .write_atomic(
                &journal_name(codec.id, key).unwrap(),
                pending.as_bytes(),
                0o600,
            )
            .unwrap();
        let guard = voboost_contract::operation::GenerationGuard::acquire_in(root.path()).unwrap();
        owner
            .initialize_native("11111111-1111-4111-8111-111111111111")
            .unwrap();
        assert!(!owner.native_enabled().contains(codec.id));
        assert!(owner.native_enabled().contains("unrelated"));
        assert_eq!(
            fs::read(root.path().join("agents.json")).unwrap(),
            config.as_bytes()
        );
        assert_eq!(
            owner.journal(codec.id, key).unwrap().unwrap(),
            pending.as_bytes()
        );
        assert!(matches!(
            call(
                &mut owner,
                SESSION,
                Command::RecoverIntent {
                    source: codec.id.into(),
                    key: key.into()
                }
            ),
            Outcome::Unavailable {}
        ));
        drop(guard);
        // Releasing the product operation is not user-input authority.
        assert!(matches!(
            call(
                &mut owner,
                SESSION,
                Command::RecoverIntent {
                    source: codec.id.into(),
                    key: key.into()
                }
            ),
            Outcome::Unavailable {}
        ));
        assert_eq!(
            fs::read(root.path().join("agents.json")).unwrap(),
            config.as_bytes()
        );
        let config = stamped_off(&config, codec.id, key);
        Directory::open(root.path())
            .unwrap()
            .write_atomic("agents.json", config.as_bytes(), 0o600)
            .unwrap();

        assert!(matches!(
            call(
                &mut owner,
                SESSION,
                Command::RecoverIntent {
                    source: codec.id.into(),
                    key: key.into()
                }
            ),
            Outcome::Written {}
        ));
        let recovered: serde_json::Value =
            serde_json::from_slice(&fs::read(root.path().join("agents.json")).unwrap()).unwrap();
        assert_eq!(
            recovered,
            serde_json::from_str::<serde_json::Value>(&config).unwrap()
        );
        assert_eq!(
            fs::read(root.path().join("agents.json")).unwrap(),
            config.as_bytes()
        );
        assert!(matches!(
            call(
                &mut owner,
                SESSION,
                Command::RecoverIntent {
                    source: "unrelated".into(),
                    key: key.into()
                }
            ),
            Outcome::Unavailable {}
        ));
    }
}

#[test]
fn retired_prepare_cannot_publish_or_revoke_current_native_admission() {
    for codec in super::super::native::CODECS
        .iter()
        .filter(|c| !c.pending_journals.is_empty())
    {
        let root = root();
        let config = json!({"schemaVersion":2,"userRevision":0,"fieldRevisions":{},"startup":"interface","agents":{
                (codec.id):{"enabled":true,"options":{}},"unrelated":{"enabled":true,"options":{}}
            }})
            .to_string();
        Directory::open(root.path())
            .unwrap()
            .write_atomic("agents.json", config.as_bytes(), 0o600)
            .unwrap();
        let mut owner = Store::new(root.path(), SESSION).unwrap();
        owner
            .initialize_native("11111111-1111-4111-8111-111111111111")
            .unwrap();
        assert!(owner.native_enabled().contains(codec.id));
        let key = codec.pending_journals[0];
        let state = state::open_directory(&root.path().join("state"), true).unwrap();
        let temporary = format!(".{}.tmp", journal_name(codec.id, key).unwrap());
        state.open_or_create_private_child(&temporary).unwrap();
        let pending = json!({"schemaVersion":1,"bootId":"11111111-1111-4111-8111-111111111111",
                "captureNs":10,"pid":100,"requestId":1,"choice":"off","pending":true})
        .to_string();
        assert!(matches!(
            call(
                &mut owner,
                SESSION,
                Command::PrepareIntent {
                    source: codec.id.into(),
                    key: key.into(),
                    record: serde_json::from_str(&pending).unwrap()
                }
            ),
            Outcome::Unavailable {}
        ));
        assert!(owner.native_enabled().contains(codec.id));
        assert!(owner.native_enabled().contains("unrelated"));
        assert!(owner.journal(codec.id, key).unwrap().is_none());
        assert!(root.path().join("state").join(temporary).is_dir());
    }
}

#[test]
fn retired_capture_commands_preserve_newer_desired_stamps_and_native_sources() {
    for codec in super::super::native::CODECS
        .iter()
        .filter(|c| !c.pending_journals.is_empty())
    {
        let root = root();
        let key = codec.pending_journals[0];
        let before = stamped_off(&json!({"schemaVersion":2,"userRevision":0,"fieldRevisions":{},"startup":"interface","agents":{
                (codec.id):{"enabled":true,"options":{"intent":"on"}},"unrelated":{"enabled":true,"options":{}}
            }}).to_string(), codec.id, key);
        Directory::open(root.path())
            .unwrap()
            .write_atomic("agents.json", before.as_bytes(), 0o600)
            .unwrap();
        let mut owner = Store::new(root.path(), SESSION).unwrap();
        owner
            .initialize_native("11111111-1111-4111-8111-111111111111")
            .unwrap();
        let admitted = owner.native_enabled().clone();
        let record = json!({"schemaVersion":1,"bootId":"11111111-1111-4111-8111-111111111111",
                "captureNs":10,"pid":100,"requestId":1,"choice":"on","pending":true});
        assert!(matches!(
            call(
                &mut owner,
                SESSION,
                Command::PrepareIntent {
                    source: codec.id.into(),
                    key: key.into(),
                    record: serde_json::from_value(record.clone()).unwrap()
                }
            ),
            Outcome::Unavailable {}
        ));
        let mut done = record;
        done["pending"] = false.into();
        assert!(matches!(
            call(
                &mut owner,
                SESSION,
                Command::FinishIntent {
                    source: codec.id.into(),
                    key: key.into(),
                    record: serde_json::from_value(done).unwrap()
                }
            ),
            Outcome::Unavailable {}
        ));
        assert!(matches!(
            call(
                &mut owner,
                SESSION,
                Command::ReplaceJournal {
                    source: codec.id.into(),
                    key: key.into(),
                    expected: None,
                    next: "{\"pending\":false}".into()
                }
            ),
            Outcome::Unavailable {}
        ));
        assert_eq!(
            fs::read(root.path().join("agents.json")).unwrap(),
            before.as_bytes()
        );
        assert!(owner.journal(codec.id, key).unwrap().is_none());
        // A legacy corrupt WAL cannot override the authoritative stamped option.
        state::open_directory(&root.path().join("state"), true)
            .unwrap()
            .write_atomic(
                &journal_name(codec.id, key).unwrap(),
                b"{\"pending\":false}",
                0o600,
            )
            .unwrap();
        owner.refresh_native().unwrap();
        assert_eq!(
            fs::read(root.path().join("agents.json")).unwrap(),
            before.as_bytes()
        );
        assert_eq!(owner.native_enabled(), &admitted);

        assert!(owner.native_enabled().contains("unrelated"));
    }
}

#[test]
fn native_selection_updates_after_commit_but_startup_waits_for_next_boot() {
    let root = root();
    let directory = Directory::open(root.path()).unwrap();
    let before = json!({"schemaVersion":2,"userRevision":0,"fieldRevisions":{},"startup":"interface","agents":{
            "fixture":{"enabled":true,"options":{}},"other":{"enabled":true,"options":{}}
        }})
        .to_string();
    directory
        .write_atomic("agents.json", before.as_bytes(), 0o600)
        .unwrap();
    let boot = "11111111-1111-4111-8111-111111111111";
    let mut owner = Store::new(root.path(), SESSION).unwrap();
    owner.initialize_native(boot).unwrap();
    assert_eq!(owner.native_enabled().len(), 2);
    let next =
        json!({"schemaVersion":2,"userRevision":0,"fieldRevisions":{},"startup":"none","agents":{
            "fixture":{"enabled":false,"options":{}},"other":{"enabled":true,"options":{}}
        }})
        .to_string();
    assert!(matches!(
        call(
            &mut owner,
            SESSION,
            Command::ReplaceConfig {
                expected: Some(before),
                next,
            }
        ),
        Outcome::Written {}
    ));
    assert_eq!(
        owner.native_enabled(),
        &std::collections::BTreeSet::from(["other".into()])
    );
    // Current-boot mode survives replacement of the owner itself.
    let mut replacement = Store::new(root.path(), SESSION).unwrap();
    replacement.initialize_native(boot).unwrap();
    assert_eq!(replacement.native_enabled(), owner.native_enabled());
    replacement
        .initialize_native("22222222-2222-4222-8222-222222222222")
        .unwrap();
    assert!(replacement.native_enabled().is_empty());
}

#[test]
fn native_configuration_failure_clears_admission_without_rewriting_input() {
    let root = root();
    let directory = Directory::open(root.path()).unwrap();
    directory
        .write_atomic("agents.json", b"broken", 0o600)
        .unwrap();
    let mut owner = Store::new(root.path(), SESSION).unwrap();
    assert!(owner
        .initialize_native("11111111-1111-4111-8111-111111111111")
        .is_err());
    assert!(owner.native_enabled().is_empty());
    assert_eq!(
        directory.read_trusted("agents.json", 128, 0o600).unwrap(),
        b"broken"
    );
}
#[test]
fn cluster_mailbox_commit_is_validated_and_compare_and_swap() {
    let root = root();
    let mut owner = Store::new(root.path(), SESSION).unwrap();
    let mailbox: voboost_shared::cluster_mailbox::State = serde_json::from_value(json!({
        "schemaVersion": 1, "androidBootId": "boot",
        "androidDaemonEpoch": "a".repeat(64),
        "catalogSha256": "b".repeat(64), "closureSha256": "c".repeat(64),
        "desiredRevision": 0,
        "desiredSha256": voboost_contract::cluster::desired_digest(&[]).unwrap(),
        "agents": [], "expectedTargets": {}, "snapshotRevision": 1,
        "generation": null, "observed": null, "observedOwnerEpoch": null,
        "deliveryState": "setup-required", "pending": null
    }))
    .unwrap();
    let mailbox =
        String::from_utf8(voboost_contract::domain_core::ascii_json(&mailbox).unwrap()).unwrap();
    assert!(matches!(
        call(
            &mut owner,
            SESSION,
            Command::ReplaceClusterMailbox {
                expected: None,
                next: mailbox.clone(),
            }
        ),
        Outcome::Written {}
    ));
    let path = root.path().join("cluster/mailbox.json");
    assert_eq!(fs::read_to_string(&path).unwrap(), mailbox);
    assert!(matches!(
        call(
            &mut owner,
            SESSION,
            Command::ReplaceClusterMailbox {
                expected: Some(mailbox.clone()),
                next: mailbox.trim_end().into(),
            }
        ),
        Outcome::Unavailable {}
    ));
    assert!(matches!(
        call(
            &mut owner,
            SESSION,
            Command::ReplaceClusterMailbox {
                expected: None,
                next: mailbox.clone(),
            }
        ),
        Outcome::Conflict {}
    ));
    assert!(matches!(
        call(
            &mut owner,
            SESSION,
            Command::ReplaceClusterMailbox {
                expected: Some(mailbox.clone()),
                next: "{}".into(),
            }
        ),
        Outcome::Unavailable {}
    ));
    assert_eq!(fs::read_to_string(&path).unwrap(), mailbox);
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}
#[test]
fn cluster_epoch_belongs_to_owner_incarnation_not_requesting_inject() {
    let root = root();
    let mut owner = Store::new(root.path(), SESSION).unwrap();
    let Outcome::ClusterEpoch { value: first } =
        call(&mut owner, SESSION, Command::ReadClusterEpoch {})
    else {
        panic!("missing owner epoch");
    };
    assert_eq!(first.len(), 64);
    for _ in 0..3 {
        let Outcome::ClusterEpoch { value } =
            call(&mut owner, SESSION, Command::ReadClusterEpoch {})
        else {
            panic!("missing owner epoch");
        };
        assert_eq!(value, first);
    }
    let replacement = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let mut owner = Store::new(root.path(), replacement).unwrap();
    assert!(matches!(
        call(&mut owner, SESSION, Command::ReadClusterEpoch {}),
        Outcome::Unavailable {}
    ));
    let Outcome::ClusterEpoch { value } =
        call(&mut owner, replacement, Command::ReadClusterEpoch {})
    else {
        panic!("missing replacement epoch");
    };
    assert_ne!(value, first);
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}
#[test]
fn startup_save_preserves_agents_and_running_boot_without_resident_inject() {
    let root = root();
    let directory = Directory::open(root.path()).unwrap();
    directory
        .write_atomic(
            "voboost.json",
            br#"{"releaseIdentity":"1.0.0-beta1"}"#,
            0o600,
        )
        .unwrap();
    directory.write_atomic("agents.json", br#"{"schemaVersion":2,"userRevision":0,"fieldRevisions":{},"startup":"interface","agents":{"agent":{"enabled":true,"options":{"value":7}}}}"#, 0o600).unwrap();
    let mut store = Store::new(root.path(), SESSION).unwrap();
    let boot = "11111111-1111-4111-8111-111111111111";
    store.initialize_native(boot).unwrap();
    store.current_producer = Some((42, 100));
    for requested in ["none", "hidden"] {
        let Outcome::StartupSaved {
            startup,
            installed_version,
        } = store.set_startup(requested, boot).unwrap()
        else {
            panic!("not saved");
        };
        assert_eq!(startup, requested);
        assert_eq!(installed_version, "1.0.0-beta1");
        let saved: serde_json::Value =
            serde_json::from_slice(&directory.read_trusted("agents.json", 4096, 0o600).unwrap())
                .unwrap();
        assert_eq!(saved["startup"], requested);
        assert_eq!(saved["agents"]["agent"]["options"]["value"], 7);
        let session: serde_json::Value =
            serde_json::from_str(&store.startup_session().unwrap().unwrap()).unwrap();
        assert_eq!(session["startup"], "interface");
        assert_eq!(session["bootId"], boot);
    }
    let next_boot = "22222222-2222-4222-8222-222222222222";
    store.native_boot = Some(next_boot.into());
    store.set_startup("interface", next_boot).unwrap();
    let session: serde_json::Value =
        serde_json::from_str(&store.startup_session().unwrap().unwrap()).unwrap();
    assert_eq!(session["startup"], "hidden");
    assert_eq!(session["bootId"], next_boot);
}
#[test]
fn startup_save_during_product_operation_preserves_current_boot_and_stamps_next_boot() {
    let root = root();
    let directory = Directory::open(root.path()).unwrap();
    directory
        .write_atomic(
            "voboost.json",
            br#"{"releaseIdentity":"1.0.0-beta1"}"#,
            0o600,
        )
        .unwrap();
    let original = br#"{"schemaVersion":2,"userRevision":0,"fieldRevisions":{},"startup":"interface","agents":{}}"#;
    directory
        .write_atomic("agents.json", original, 0o600)
        .unwrap();
    let mut store = Store::new(root.path(), SESSION).unwrap();
    let boot = "11111111-1111-4111-8111-111111111111";
    store.initialize_native(boot).unwrap();
    store.current_producer = Some((42, 100));
    let session_before = store.startup_session().unwrap();
    let guard = voboost_contract::operation::GenerationGuard::acquire_in(root.path()).unwrap();
    assert!(matches!(
        store.set_startup("none", boot).unwrap(),
        Outcome::StartupSaved { .. }
    ));
    let saved: serde_json::Value =
        serde_json::from_slice(&directory.read_trusted("agents.json", 4096, 0o600).unwrap())
            .unwrap();
    assert_eq!(saved["startup"], "none");
    assert_eq!(saved["userRevision"], 1);
    assert_eq!(saved["fieldRevisions"]["startup"]["revision"], 1);
    assert_eq!(store.startup_session().unwrap(), session_before);
    assert_eq!(store.running_startup.as_deref(), Some("interface"));
    drop(guard);
    assert!(store.set_startup("unexpected", boot).is_err());
    directory
            .write_atomic(
                "agents.json",
                br#"{"schemaVersion":2,"userRevision":0,"fieldRevisions":{},"startup":"interface","startup":"none","agents":{}}"#,
                0o600,
            )
            .unwrap();
    assert!(store.set_startup("hidden", boot).is_err());
    assert_eq!(store.startup_session().unwrap(), session_before);
}
#[test]
fn log_session_is_live_writer_authority_and_does_not_advance_sequence() {
    let root = root();
    let mut store = Store::new(root.path(), SESSION).unwrap();
    assert!(matches!(
        call(&mut store, SESSION, Command::ReadLogSession {}),
        Outcome::Unavailable {}
    ));
    let boot = "11111111-1111-4111-8111-111111111111";
    Directory::open(root.path())
        .unwrap()
        .create_private_child("logs")
        .unwrap();
    let logger = super::super::log::Log::create(&root.path().join("logs"), boot, SESSION).unwrap();
    let mut store = store.with_logger(logger).unwrap();
    for _ in 0..2 {
        let Outcome::LogSession {
            boot_id,
            writer_id,
            sequence,
        } = call(&mut store, SESSION, Command::ReadLogSession {})
        else {
            panic!("missing writer authority");
        };
        assert_eq!(boot_id, boot);
        assert_eq!(writer_id, SESSION);
        assert_eq!(sequence, 0);
    }
    store
        .write_log(
            voboost_contract::runtime_log::Source::daemon(),
            voboost_contract::runtime_log::Record {
                level: voboost_contract::runtime_log::Level::Info,
                component: "test".into(),
                message: "event".into(),
                fields: Default::default(),
            },
        )
        .unwrap();
    assert!(matches!(
        call(&mut store, SESSION, Command::ReadLogSession {}),
        Outcome::LogSession { sequence: 1, .. }
    ));
}
#[test]
fn injection_status_is_fixed_publication_and_rejects_invalid_or_redirected_files() {
    let root = root();
    let mut store = Store::new(root.path(), SESSION).unwrap();
    let bytes = r#"{"schemaVersion":1,"injections":[],"executors":[]}"#.to_string();
    assert!(matches!(
        call(
            &mut store,
            SESSION,
            Command::PublishInjectionStatus {
                bytes: bytes.clone()
            }
        ),
        Outcome::Written {}
    ));
    let target = root.path().join("status.json");
    assert_eq!(fs::read_to_string(&target).unwrap(), bytes);
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
        0o644
    );
    for invalid in [
        "{}",
        r#"{"schemaVersion":1,"schemaVersion":1,"injections":[],"executors":[]}"#,
    ] {
        assert!(matches!(
            call(
                &mut store,
                SESSION,
                Command::PublishInjectionStatus {
                    bytes: invalid.into()
                }
            ),
            Outcome::Unavailable {}
        ));
        assert_eq!(fs::read_to_string(&target).unwrap(), bytes);
    }
    fs::remove_file(&target).unwrap();
    let outside = root.path().join("preserve");
    fs::write(&outside, "preserve").unwrap();
    std::os::unix::fs::symlink(&outside, &target).unwrap();
    assert!(matches!(
        call(
            &mut store,
            SESSION,
            Command::PublishInjectionStatus { bytes }
        ),
        Outcome::Unavailable {}
    ));
    assert_eq!(fs::read_to_string(outside).unwrap(), "preserve");
}
#[test]
fn startup_session_compare_exchange_preserves_newer_fence() {
    let root = root();
    let mut store = Store::new(root.path(), SESSION).unwrap();
    let first = r#"{"schemaVersion":1,"bootId":"11111111-1111-4111-8111-111111111111","startup":"interface"}"#.to_string();
    let second = first.replace("interface", "hidden");
    assert!(matches!(
        call(
            &mut store,
            SESSION,
            Command::ReplaceStartupSession {
                expected: None,
                next: None
            }
        ),
        Outcome::Written {}
    ));
    assert!(!root.path().join("run").exists());
    assert!(matches!(
        call(
            &mut store,
            SESSION,
            Command::ReplaceStartupSession {
                expected: None,
                next: Some(first.clone())
            }
        ),
        Outcome::Written {}
    ));
    assert!(matches!(
        call(
            &mut store,
            SESSION,
            Command::ReplaceStartupSession {
                expected: Some(first.clone()),
                next: Some(second.clone())
            }
        ),
        Outcome::Written {}
    ));
    assert!(matches!(
        call(
            &mut store,
            SESSION,
            Command::ReplaceStartupSession {
                expected: Some(first),
                next: None
            }
        ),
        Outcome::Conflict {}
    ));
    assert!(
        matches!(call(&mut store, SESSION, Command::ReadStartupSession {}), Outcome::StartupSession { bytes: Some(bytes) } if bytes == second)
    );
    assert!(matches!(
        call(
            &mut store,
            SESSION,
            Command::ReplaceStartupSession {
                expected: Some(second),
                next: Some("{}".into())
            }
        ),
        Outcome::Unavailable {}
    ));
}
#[test]
fn append_log_reply_uses_the_recovered_writer_without_changing_owner_session() {
    use voboost_contract::runtime_log::{Level, Record, Source};
    let root = root();
    let logs = root.path().join("logs");
    fs::create_dir(&logs).unwrap();
    fs::set_permissions(&logs, fs::Permissions::from_mode(0o700)).unwrap();
    let logger =
        super::super::log::Log::create(&logs, "11111111-1111-4111-8111-111111111111", SESSION)
            .unwrap();
    let mut store = Store::new(root.path(), SESSION)
        .unwrap()
        .with_logger(logger)
        .unwrap();
    fs::create_dir(logs.join(SESSION).join("debug-00000000000000000000.jsonl")).unwrap();
    let command = || Command::AppendLog {
        source: Source::daemon(),
        record: Record {
            level: Level::Info,
            component: "inject".into(),
            message: "ready".into(),
            fields: Default::default(),
        },
    };
    assert!(matches!(
        call(&mut store, SESSION, command()),
        Outcome::Unavailable {}
    ));
    std::thread::sleep(std::time::Duration::from_millis(300));
    let Outcome::Logged {
        writer_id,
        sequence,
    } = call(&mut store, SESSION, command())
    else {
        panic!("writer recovery did not complete");
    };
    assert_ne!(writer_id, SESSION);
    assert_eq!(sequence, 1);
    assert_eq!(store.session(), SESSION);
    let event: serde_json::Value = serde_json::from_slice(
        &fs::read(
            logs.join(&writer_id)
                .join("debug-00000000000000000000.jsonl"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(event["writerId"], writer_id);
    assert_eq!(event["sequence"], sequence);
    assert!(
        matches!(call(&mut store, SESSION, Command::ReadLogSession {}), Outcome::LogSession { writer_id: actual, sequence: 1, .. } if actual == writer_id)
    );
}

#[test]
fn framed_log_request_commits_through_the_real_store_before_reply() {
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};
    let root = root();
    let logs = root.path().join("logs");
    fs::create_dir(&logs).unwrap();
    fs::set_permissions(&logs, fs::Permissions::from_mode(0o700)).unwrap();
    let logger =
        super::super::log::Log::create(&logs, "11111111-1111-4111-8111-111111111111", SESSION)
            .unwrap();
    let mut store = Store::new(root.path(), SESSION)
        .unwrap()
        .with_logger(logger)
        .unwrap();
    let (mut client, mut server) = UnixStream::pair().unwrap();
    // Native peer authentication is an Android gate; this test starts at framing.
    let worker = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        let bytes = crate::io::read(&mut server, deadline).unwrap();
        let reply = store.dispatch(Request::decode(&bytes).unwrap());
        crate::io::write(&mut server, &serde_json::to_vec(&reply).unwrap(), deadline).unwrap();
    });
    let request = Request {
        schema_version: SCHEMA,
        session: SESSION.into(),
        request_id: 7,
        command: Command::AppendLog {
            source: voboost_contract::runtime_log::Source::daemon(),
            record: voboost_contract::runtime_log::Record {
                level: voboost_contract::runtime_log::Level::Info,
                component: "inject".into(),
                message: "ready".into(),
                fields: Default::default(),
            },
        },
    };
    let deadline = Instant::now() + Duration::from_secs(2);
    crate::io::write(
        &mut client,
        &serde_json::to_vec(&request).unwrap(),
        deadline,
    )
    .unwrap();
    let reply = Reply::decode(&crate::io::read(&mut client, deadline).unwrap(), 7).unwrap();
    assert!(matches!(reply.outcome, Outcome::Logged { sequence: 1, .. }));
    worker.join().unwrap();
    let path = logs.join(SESSION).join("debug-00000000000000000000.jsonl");
    let event: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(event["message"], "ready");
    assert_eq!(event["writerId"], SESSION);
}
#[test]
fn log_requests_use_only_the_owner_session_and_private_tiers() {
    use voboost_contract::runtime_log::{Level, Record, Source};
    let d = root();
    let logs = d.path().join("logs");
    fs::create_dir(&logs).unwrap();
    fs::set_permissions(&logs, fs::Permissions::from_mode(0o700)).unwrap();
    let logger =
        super::super::log::Log::create(&logs, "11111111-1111-4111-8111-111111111111", SESSION)
            .unwrap();
    let mut store = Store::new(d.path(), SESSION)
        .unwrap()
        .with_logger(logger)
        .unwrap();
    let command = || Command::AppendLog {
        source: Source {
            kind: "agent".into(),
            id: Some("vehicle-drive-forced-ev".into()),
        },
        record: Record {
            level: Level::Error,
            component: "agent".into(),
            message: "failed token=private".into(),
            fields: Default::default(),
        },
    };
    assert!(matches!(
        call(&mut store, SESSION, command()),
        Outcome::Logged { sequence: 1, .. }
    ));
    assert!(matches!(
        call(&mut store, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", command()),
        Outcome::Unavailable {}
    ));
    let debug = fs::read(logs.join(SESSION).join("debug-00000000000000000000.jsonl")).unwrap();
    assert_eq!(
        debug,
        fs::read(logs.join(SESSION).join("error-00000000000000000000.jsonl")).unwrap()
    );
    let row: serde_json::Value = serde_json::from_slice(&debug).unwrap();
    assert_eq!(row["writerId"], SESSION);
    assert_eq!(row["source"]["id"], "vehicle-drive-forced-ev");
    assert_eq!(row["message"], "failed token=[REDACTED]");
    assert_eq!(debug.iter().filter(|&&b| b == b'\n').count(), 1);
    assert!(!d.path().join("segment-active.jsonl").exists());
}
#[test]
fn journal_compare_exchange_is_private_and_separate_from_scalar_state() {
    use std::os::unix::fs::MetadataExt;
    let d = root();
    let mut store = Store::new(d.path(), SESSION).unwrap();
    let body = r#"{"pending":true,"choice":"off"}"#.to_string();
    let command = || Command::ReplaceJournal {
        source: "agent".into(),
        key: "intent".into(),
        expected: None,
        next: body.clone(),
    };
    assert!(matches!(
        call(&mut store, SESSION, command()),
        Outcome::Written {}
    ));
    assert!(matches!(
        call(&mut store, SESSION, command()),
        Outcome::Conflict {}
    ));
    let file = d.path().join("state/.agent_intent.journal.json");
    assert_eq!(fs::read(&file).unwrap(), body.as_bytes());
    assert_eq!(fs::metadata(&file).unwrap().mode() & 0o7777, 0o600);
    assert!(matches!(
        call(
            &mut store,
            SESSION,
            Command::ReadState {
                source: "agent".into(),
                key: "intent".into()
            }
        ),
        Outcome::State { value: None }
    ));
    assert!(matches!(
        call(
            &mut store,
            SESSION,
            Command::ReadJournal {
                source: "other".into(),
                key: "intent".into()
            }
        ),
        Outcome::Journal { bytes: None }
    ));
    assert!(matches!(
        call(
            &mut store,
            SESSION,
            Command::ReplaceJournal {
                source: "agent".into(),
                key: "intent".into(),
                expected: Some(body.clone()),
                next: r#"{"a":1,"a":2}"#.into(),
            }
        ),
        Outcome::Unavailable {}
    ));
    assert_eq!(fs::read(&file).unwrap(), body.as_bytes());
}
#[test]
fn journal_rejects_symlink_and_stale_session_without_modification() {
    let d = root();
    let mut store = Store::new(d.path(), SESSION).unwrap();
    let command = || Command::ReplaceJournal {
        source: "agent".into(),
        key: "intent".into(),
        expected: None,
        next: "{}".into(),
    };
    assert!(matches!(
        call(&mut store, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", command()),
        Outcome::Unavailable {}
    ));
    assert!(!d.path().join("state").exists());
    state::open_directory(&d.path().join("state"), true).unwrap();
    let victim = d.path().join("victim");
    fs::write(&victim, b"retained").unwrap();
    std::os::unix::fs::symlink(&victim, d.path().join("state/.agent_intent.journal.json")).unwrap();
    assert!(matches!(
        call(&mut store, SESSION, command()),
        Outcome::Unavailable {}
    ));
    assert_eq!(fs::read(&victim).unwrap(), b"retained");
}
#[test]
fn scalar_missing_commit_and_stale_session_use_real_private_files() {
    let d = root();
    let mut s = Store::new(d.path(), SESSION).unwrap();
    assert!(matches!(
        call(
            &mut s,
            SESSION,
            Command::ReadState {
                source: "agent".into(),
                key: "key".into()
            }
        ),
        Outcome::State { value: None }
    ));
    assert!(matches!(
        call(
            &mut s,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            Command::WriteState {
                source: "agent".into(),
                key: "key".into(),
                value: json!(true)
            }
        ),
        Outcome::Unavailable {}
    ));
    assert!(!d.path().join("state").exists());
    assert!(matches!(
        call(
            &mut s,
            SESSION,
            Command::WriteState {
                source: "agent".into(),
                key: "key".into(),
                value: json!(false)
            }
        ),
        Outcome::Written {}
    ));
    assert!(matches!(
        call(
            &mut s,
            SESSION,
            Command::ReadState {
                source: "agent".into(),
                key: "key".into()
            }
        ),
        Outcome::State {
            value: Some(serde_json::Value::Bool(false))
        }
    ));
}
#[test]
fn configuration_compare_exchange_rejects_lost_updates_and_invalid_schema() {
    let d = root();
    let mut s = Store::new(d.path(), SESSION).unwrap();
    let first = r#"{"schemaVersion":2,"userRevision":0,"fieldRevisions":{},"startup":"interface","agents":{}}"#.to_string();
    assert!(matches!(
        call(
            &mut s,
            SESSION,
            Command::ReplaceConfig {
                expected: None,
                next: first.clone()
            }
        ),
        Outcome::Written {}
    ));
    let first = String::from_utf8(fs::read(d.path().join("agents.json")).unwrap()).unwrap();
    let next = r#"{"schemaVersion":2,"userRevision":0,"fieldRevisions":{},"startup":"hidden","agents":{}}"#.to_string();
    assert!(matches!(
        call(
            &mut s,
            SESSION,
            Command::ReplaceConfig {
                expected: None,
                next: next.clone()
            }
        ),
        Outcome::Conflict {}
    ));
    assert_eq!(
        fs::read(d.path().join("agents.json")).unwrap(),
        first.as_bytes()
    );
    assert!(matches!(
        call(
            &mut s,
            SESSION,
            Command::ReplaceConfig {
                expected: Some(first),
                next: next.clone()
            }
        ),
        Outcome::Written {}
    ));
    assert!(matches!(
        call(
            &mut s,
            SESSION,
            Command::ReplaceConfig {
                expected: Some(next.clone()),
                next: "{}".into()
            }
        ),
        Outcome::Unavailable {}
    ));
    assert_eq!(
        fs::read(d.path().join("agents.json")).unwrap(),
        next.as_bytes()
    );
}
