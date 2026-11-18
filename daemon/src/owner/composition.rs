//! Production wrappers and owner storage. Host connections bypass only peer admission.
#[allow(dead_code)]
#[path = "../state/client.rs"]
mod state_client;

use super::{io, log, owner_client, serve_admitted, server};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use voboost_contract::runtime_log::{AppBatch, Event, Level, Record, Source};
use voboost_shared::native_executable_signature::NativeExecutableRole;

const SESSION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOOT: &str = "11111111-1111-4111-8111-111111111111";
const CONFIG: &str = "{\"schemaVersion\":2,\"startup\":\"interface\",\"agents\":{},\"userRevision\":0,\"fieldRevisions\":{}}";

/// Product-owned case data drives the real framed server and client wrappers.
/// Only native-peer admission is bypassed on the host, as in this module's other cases.
#[test]
fn product_desired_owner_scenario() {
    use serde::Deserialize;
    use voboost_contract::runtime_owner::Command;
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Scenario {
        schema_version: u32,
        boot_id: String,
        steps: Vec<Step>,
    }
    #[derive(Deserialize)]
    #[serde(
        tag = "operation",
        rename_all = "kebab-case",
        rename_all_fields = "camelCase",
        deny_unknown_fields
    )]
    enum Step {
        HoldProductLock,
        ReleaseProductLock,
        SaveDesired {
            field: voboost_contract::desired::Field,
            value: Value,
            input: voboost_contract::desired::Input,
        },
        ReconcileDesired {
            defaults: Value,
        },
        ReadDesired {
            field: voboost_contract::desired::Field,
        },
        RestartOwner {
            boot_id: String,
        },
    }
    let Some(path) = std::env::var_os("VOBOOST_DESIRED_OWNER_SCENARIO") else {
        eprintln!("product scenario not selected; this is not L2 execution evidence");
        return;
    };
    let receipt =
        std::env::var_os("VOBOOST_DESIRED_OWNER_RECEIPT").expect("product receipt path required");
    let scenario: Scenario = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(scenario.schema_version, 1);
    assert!(!scenario.steps.is_empty() && scenario.steps.len() <= 128);
    let fixture = Fixture::new();
    let initial = json!({"schemaVersion":2,"startup":"interface","agents":{
        "launcher":{"enabled":true,"options":{}}
    },"userRevision":0,"fieldRevisions":{}});
    super::secure_fs::Directory::open(fixture.root.path())
        .unwrap()
        .write_atomic("agents.json", &serde_json::to_vec(&initial).unwrap(), 0o600)
        .unwrap();
    fixture
        .store
        .lock()
        .unwrap()
        .initialize_native(&scenario.boot_id)
        .unwrap();
    let mut lease = None;
    let mut exchanges = Vec::new();
    for step in scenario.steps {
        let (operation, command) = match step {
            Step::HoldProductLock => {
                assert!(lease.is_none());
                lease = Some(
                    voboost_contract::operation::GenerationGuard::acquire_in(fixture.root.path())
                        .unwrap(),
                );
                exchanges.push(
                    json!({"operation":"hold-product-lock","outcome":{"status":"lease-held"}}),
                );
                continue;
            }
            Step::ReleaseProductLock => {
                assert!(lease.take().is_some());
                exchanges.push(json!({"operation":"release-product-lock","outcome":{"status":"lease-released"}}));
                continue;
            }
            Step::RestartOwner { boot_id } => {
                let mut restarted =
                    server::Store::new(fixture.root.path(), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                        .unwrap();
                restarted.initialize_native(&boot_id).unwrap();
                *fixture.store.lock().unwrap() = restarted;
                exchanges.push(json!({"operation":"restart-owner","outcome":{"status":"owner-restarted","bootId":boot_id}}));
                continue;
            }
            Step::SaveDesired {
                field,
                value,
                input,
            } => (
                "save-desired",
                Command::SaveDesired {
                    field,
                    value,
                    input,
                },
            ),
            Step::ReconcileDesired { defaults } => (
                "reconcile-desired",
                Command::ReconcileDesired {
                    defaults: serde_json::to_string(&defaults).unwrap(),
                },
            ),
            Step::ReadDesired { field } => ("read-desired", Command::ReadDesired { field }),
        };
        let (outcome, calls) = fixture.run(false, || owner_client::call(command));
        assert_eq!(calls, 1);
        exchanges.push(json!({"operation":operation,"outcome":outcome.unwrap()}));
    }
    drop(lease);
    let config: Value =
        serde_json::from_slice(&fs::read(fixture.root.path().join("agents.json")).unwrap())
            .unwrap();
    fs::write(
        receipt,
        serde_json::to_vec_pretty(
            &json!({"schemaVersion":1,"exchanges":exchanges,"config":config}),
        )
        .unwrap(),
    )
    .unwrap();
}

struct Fixture {
    root: tempfile::TempDir,
    store: Arc<Mutex<server::Store>>,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let logs = root.path().join("logs");
        fs::create_dir(&logs).unwrap();
        fs::set_permissions(&logs, fs::Permissions::from_mode(0o700)).unwrap();
        let logger = log::Log::create(&logs, BOOT, SESSION).unwrap();
        let store = server::Store::new(root.path(), SESSION)
            .unwrap()
            .with_logger(logger)
            .unwrap();
        Self {
            root,
            store: Arc::new(Mutex::new(store)),
        }
    }

    fn run<T>(&self, lose_reply: bool, action: impl FnOnce() -> T) -> (T, usize) {
        let store = self.store.clone();
        let workers = Arc::new(Mutex::new(Vec::new()));
        let pending = workers.clone();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let dispatched = calls.clone();
        let result = owner_client::with_connection(
            move || {
                dispatched.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let (client, mut transport) = UnixStream::pair()?;
                let store = store.clone();
                pending.lock().unwrap().push(std::thread::spawn(move || {
                    if !lose_reply {
                        serve_admitted(
                            &mut transport,
                            &mut store.lock().unwrap(),
                            NativeExecutableRole::Inject,
                        )
                        .unwrap();
                        return;
                    }
                    let (mut relay, mut server) = UnixStream::pair().unwrap();
                    let owner = std::thread::spawn(move || {
                        serve_admitted(
                            &mut server,
                            &mut store.lock().unwrap(),
                            NativeExecutableRole::Inject,
                        )
                        .unwrap();
                    });
                    let deadline = Instant::now() + Duration::from_secs(2);
                    let greeting = io::read(&mut relay, deadline).unwrap();
                    io::write(&mut transport, &greeting, deadline).unwrap();
                    let request = io::read(&mut transport, deadline).unwrap();
                    io::write(&mut relay, &request, deadline).unwrap();
                    // The real server has dispatched and committed before its reply reaches this relay.
                    let _committed_reply = io::read(&mut relay, deadline).unwrap();
                    owner.join().unwrap();
                    transport.shutdown(std::net::Shutdown::Write).unwrap();
                }));
                Ok(client)
            },
            action,
        );
        for worker in workers.lock().unwrap().drain(..) {
            worker.join().unwrap();
        }
        (result, calls.load(std::sync::atomic::Ordering::SeqCst))
    }

    fn events(&self) -> Vec<Event> {
        fs::read_to_string(
            self.root
                .path()
                .join("logs")
                .join(SESSION)
                .join("debug-00000000000000000000.jsonl"),
        )
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
    }
}

fn state_path() -> &'static Path {
    Path::new(voboost_contract::runtime_owner::STATE_DIR)
}

fn config_path() -> PathBuf {
    Path::new(voboost_contract::runtime_owner::ROOT_ZONE).join("agents.json")
}

fn record(message: &str) -> Record {
    Record {
        level: Level::Info,
        component: "composition".into(),
        message: message.into(),
        fields: Default::default(),
    }
}

#[test]
fn state_missing_false_error_and_commit_are_observed_through_production_wrappers() {
    let fixture = Fixture::new();
    fixture.run(false, || {
        assert_eq!(
            state_client::read(state_path(), "media-apps", "armed"),
            state_client::ReadOutcome::Missing
        );
        state_client::write(state_path(), "media-apps_armed", b"false\n").unwrap();
        // Successful ACK cannot precede the actual durable file commit.
        assert_eq!(
            fs::read(fixture.root.path().join("state/media-apps_armed.json")).unwrap(),
            b"false\n"
        );
        assert_eq!(
            state_client::read(state_path(), "media-apps", "armed"),
            state_client::ReadOutcome::Value(Value::Bool(false))
        );
        fs::write(
            fixture.root.path().join("state/media-apps_armed.json"),
            b"corrupt",
        )
        .unwrap();
        assert_eq!(
            state_client::read(state_path(), "media-apps", "armed"),
            state_client::ReadOutcome::Error
        );
    });
    assert_eq!(
        state_client::read(state_path(), "media-apps", "armed"),
        state_client::ReadOutcome::Error
    );
}

#[test]
fn configuration_conflict_keeps_exact_bytes_and_maps_to_would_block() {
    let fixture = Fixture::new();
    fixture.run(false, || {
        assert_eq!(
            owner_client::read_config(&config_path())
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotFound
        );
        owner_client::replace_config(&config_path(), None, CONFIG.as_bytes()).unwrap();
        let before = owner_client::read_config(&config_path()).unwrap();
        assert_eq!(before, CONFIG.as_bytes());
        let next = json!({"schemaVersion":2,"userRevision":0,"fieldRevisions":{},"startup":"hidden","agents":{}}).to_string();
        assert_eq!(
            owner_client::replace_config(&config_path(), Some(b"stale".to_vec()), next.as_bytes())
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(owner_client::read_config(&config_path()).unwrap(), before);
        assert_eq!(
            fs::read(fixture.root.path().join("agents.json")).unwrap(),
            before
        );
        owner_client::replace_config(&config_path(), Some(before), next.as_bytes()).unwrap();
        assert_eq!(
            owner_client::read_config(&config_path()).unwrap(),
            next.as_bytes()
        );
    });
}

#[test]
fn logging_and_app_batch_use_the_actual_owner_writer_and_batch_identity() {
    let fixture = Fixture::new();
    fixture.run(false, || {
        assert_eq!(
            owner_client::append_log(Source::daemon(), record("first")).unwrap(),
            1
        );
        let batch = AppBatch {
            schema_version: 1,
            batch_id: "b".repeat(32),
            records: vec![record("app")],
        };
        let bytes = serde_json::to_vec(&batch).unwrap();
        assert_eq!(
            owner_client::append_app_batch(&bytes).unwrap(),
            batch.batch_id
        );
        assert_eq!(
            owner_client::append_log(Source::daemon(), record("last")).unwrap(),
            3
        );
    });
    let mut events = fixture.events();
    let app_bytes = fs::read_to_string(
        fixture
            .root
            .path()
            .join("logs/batches")
            .join("b".repeat(32))
            .join("debug.jsonl"),
    )
    .unwrap();
    events.extend(
        app_bytes
            .lines()
            .map(|line| serde_json::from_str::<Event>(line).unwrap()),
    );
    events.sort_by_key(|event| event.sequence);
    assert_eq!(events.len(), 3);

    for (index, event) in events.iter().enumerate() {
        assert_eq!(event.writer_id, SESSION);
        assert_eq!(event.boot_id, BOOT);
        assert_eq!(event.sequence, index as u64 + 1);
    }
    assert_eq!(events[1].source.kind, "app");
    assert_eq!(events[1].message, "app");
}

#[test]
fn committed_state_and_log_with_lost_reply_are_not_resent() {
    let fixture = Fixture::new();
    let (result, calls) = fixture.run(true, || {
        state_client::write(state_path(), "media-apps_armed", b"false\n")
    });
    assert!(result.is_err());
    assert_eq!(calls, 1);
    assert_eq!(
        fs::read(fixture.root.path().join("state/media-apps_armed.json")).unwrap(),
        b"false\n"
    );
    let (result, calls) = fixture.run(true, || {
        owner_client::append_log(Source::daemon(), record("committed-without-ack"))
    });
    assert!(result.is_err());
    assert_eq!(calls, 1);
    let events = fixture.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].sequence, 1);
    assert_eq!(events[0].message, "committed-without-ack");
}

#[test]
fn lost_configuration_and_batch_ack_preserve_commit_without_reconnecting() {
    let fixture = Fixture::new();
    let (result, calls) = fixture.run(true, || {
        owner_client::replace_config(&config_path(), None, CONFIG.as_bytes())
    });
    assert!(result.is_err());
    assert_eq!(calls, 1);
    assert_eq!(
        fs::read(fixture.root.path().join("agents.json")).unwrap(),
        CONFIG.as_bytes()
    );
    let batch = AppBatch {
        schema_version: 1,
        batch_id: "c".repeat(32),
        records: vec![record("app-without-ack")],
    };
    let (result, calls) = fixture.run(true, || {
        owner_client::append_app_batch(&serde_json::to_vec(&batch).unwrap())
    });
    assert!(result.is_err());
    assert_eq!(calls, 1);
    let directory = fixture
        .root
        .path()
        .join("logs/batches")
        .join(&batch.batch_id);
    assert_eq!(
        fs::read(directory.join("committed")).unwrap(),
        batch.batch_id.as_bytes()
    );
    let event: Event =
        serde_json::from_slice(&fs::read(directory.join("debug.jsonl")).unwrap()).unwrap();
    assert_eq!(event.sequence, 1);
    assert_eq!(event.writer_id, SESSION);
    assert_eq!(event.message, "app-without-ack");
}

#[test]
fn wrapper_validation_rejects_targets_and_invalid_batches_before_connecting() {
    let fixture = Fixture::new();
    let (_, calls) = fixture.run(false, || {
        assert!(owner_client::read_config(Path::new("/data/voboost/other.json")).is_err());
        assert!(owner_client::replace_config(&config_path(), None, &[0xff]).is_err());
        assert!(owner_client::append_app_batch(b"{}").is_err());
        assert!(state_client::write(Path::new("/other"), "media-apps_armed", b"false").is_err());
    });
    assert_eq!(calls, 0);
}

#[test]
fn captured_choice_lost_saved_ack_is_durable_idempotent_and_has_no_auxiliary_wal() {
    use voboost_contract::desired::{Config, Disposition, Field, Input};
    use voboost_contract::runtime_owner::Outcome;
    let source = super::native::CODECS
        .iter()
        .find(|codec| codec.pending_journals.contains(&"intent"))
        .expect("generated registry")
        .id;
    let fixture = Fixture::new();
    let config = json!({"schemaVersion":2,"userRevision":0,"fieldRevisions":{},"startup":"interface","agents":{
        (source):{"enabled":true,"options":{"intent":"observe"}}
    }}).to_string();
    fixture
        .run(false, || {
            owner_client::replace_config(&config_path(), None, config.as_bytes())
        })
        .0
        .unwrap();
    fixture
        .store
        .lock()
        .unwrap()
        .initialize_native(BOOT)
        .unwrap();
    let field = Field::Option {
        agent: source.into(),
        key: "intent".into(),
    };
    let input = Input {
        boot_id: BOOT.into(),
        endpoint_epoch: 1,
        request_id: 10,
        injector_pid: 0,
        injector_starttime: 0,
    };
    let (result, calls) = fixture.run(true, || {
        owner_client::save_desired(field.clone(), "off".into(), input.clone())
    });
    assert!(result.is_err());
    assert_eq!(calls, 1);
    let bytes = fs::read(fixture.root.path().join("agents.json")).unwrap();
    let saved = Config::decode(&bytes).unwrap();
    assert_eq!(saved.value_at(&field.path()), Some("off".into()));
    assert_eq!(saved.user_revision, 1);
    assert!(!fixture
        .root
        .path()
        .join("state")
        .join(format!(".{source}_intent.journal.json"))
        .exists());
    let (reply, calls) = fixture.run(false, || {
        owner_client::save_desired(field.clone(), "off".into(), input.clone())
    });
    assert_eq!(calls, 1);
    assert!(matches!(
        reply.unwrap(),
        Outcome::DesiredSaved {
            revision: 1,
            disposition: Disposition::Replayed,
            ..
        }
    ));
    assert_eq!(
        fs::read(fixture.root.path().join("agents.json")).unwrap(),
        bytes
    );
}
