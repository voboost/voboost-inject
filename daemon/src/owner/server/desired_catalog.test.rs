//! The desired catalog is read from the generation pointer the inject publishes.
use super::*;
use crate::generation_layout::{
    ACTIVE_POINTER, CATALOG_FILE, CATALOG_SIGNATURE_FILE, GENERATIONS_DIR, GENERATION_DIR_MODE,
    GENERATION_FILE_MODE,
};
use crate::native::Host;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use voboost_contract::agent_catalog::AgentCatalog;
use voboost_contract::desired::{Disposition, Field, Input};

const SESSION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOOT: &str = "11111111-1111-4111-8111-111111111111";
const PRODUCER: (i32, u64) = (42, 100);
/// Host builds embed the RFC 8032 agent-catalog fixture; its seed lives only in
/// test code (`daemon/src/trust.rs`).
const CATALOG_SEED: &str = "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5";

fn signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    hex::decode_to_slice(CATALOG_SEED, &mut seed).unwrap();
    let key = SigningKey::from_bytes(&seed);
    assert_eq!(
        key.verifying_key().to_bytes(),
        crate::native_binary::AGENT_CATALOG_PUBKEY,
        "the test catalog must be signed by the embedded host fixture key"
    );
    key
}

fn checkbox_catalog(entries: &[(&str, &[&str])]) -> AgentCatalog {
    let agents: Vec<serde_json::Value> = entries
        .iter()
        .map(|(id, disables)| {
            json!({
                "id": id,
                "targets": [],
                "activation": {"type": "checkbox", "default": true},
                "disables": disables,
            })
        })
        .collect();
    serde_json::from_value(json!({
        "schemaVersion": 2,
        "supportedAbis": ["arm64-v8a"],
        "agentEntryAbi": {"schemaVersion": 1, "sha256": "11"},
        "core": {"file": "agent-common.dex", "size": 1, "sha256": "22"},
        "agents": agents,
    }))
    .unwrap()
}

struct CatalogFixture {
    root: tempfile::TempDir,
    generation: std::path::PathBuf,
}

impl CatalogFixture {
    fn path(&self) -> &std::path::Path {
        self.root.path()
    }
}

impl Drop for CatalogFixture {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.generation, fs::Permissions::from_mode(0o755));
    }
}

/// Publishes `catalog` exactly the way the inject binary does: the active
/// pointer names a directory carrying the signed catalog bytes.
fn publish(catalog: &AgentCatalog) -> (CatalogFixture, String) {
    let work =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../build/test-owner-catalogs");
    fs::create_dir_all(&work).unwrap();
    let root = tempfile::Builder::new()
        .prefix("catalog-")
        .tempdir_in(work)
        .unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let bytes = catalog.canonical_bytes().unwrap();
    let generation = hex::encode(Sha256::digest(&bytes));
    let generations = root.path().join(GENERATIONS_DIR);
    fs::create_dir(&generations).unwrap();
    fs::set_permissions(&generations, fs::Permissions::from_mode(0o755)).unwrap();
    let directory = generations.join(&generation);
    fs::create_dir(&directory).unwrap();
    let signature = signing_key().sign(&bytes).to_bytes();
    for (name, contents) in [
        (CATALOG_FILE, bytes.clone()),
        (CATALOG_SIGNATURE_FILE, signature.to_vec()),
    ] {
        let path = directory.join(name);
        fs::write(&path, contents).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(GENERATION_FILE_MODE)).unwrap();
    }
    fs::set_permissions(&directory, fs::Permissions::from_mode(GENERATION_DIR_MODE)).unwrap();
    let pointer = generations.join(ACTIVE_POINTER);
    fs::write(&pointer, format!("{generation}\n")).unwrap();
    fs::set_permissions(&pointer, fs::Permissions::from_mode(GENERATION_FILE_MODE)).unwrap();
    (
        CatalogFixture {
            root,
            generation: directory,
        },
        generation,
    )
}

fn write_config(root: &std::path::Path, config: &serde_json::Value) {
    Directory::open(root)
        .unwrap()
        .write_atomic("agents.json", config.to_string().as_bytes(), 0o600)
        .unwrap();
}

fn stamp(revision: u64) -> serde_json::Value {
    json!({
        "revision": revision,
        "input": {
            "bootId": BOOT,
            "endpointEpoch": 1,
            "requestId": revision,
            "injectorPid": PRODUCER.0,
            "injectorStarttime": PRODUCER.1,
        },
        "origins": { "42:100:1": revision },
    })
}

fn native_sources() -> Vec<&'static str> {
    crate::native::CODECS.iter().map(|codec| codec.id).collect()
}

#[test]
fn the_active_catalog_is_read_from_the_published_generation_pointer() {
    assert_eq!(
        ACTIVE_POINTER, "current",
        "the inject binary publishes the active generation as generations/current"
    );
    let source = native_sources()
        .first()
        .copied()
        .expect("native owner tests require generated registry")
        .to_string();
    let (root, generation) = publish(&checkbox_catalog(&[(&source, &[])]));
    let mut store = Store::new(root.path(), SESSION).unwrap();
    assert_eq!(
        store.desired_dependencies(&source).unwrap(),
        Vec::<String>::new()
    );
    assert_eq!(
        store.desired_catalog.as_ref().map(|(id, _)| id.clone()),
        Some(generation)
    );
}

#[test]
fn a_saved_on_keeps_the_native_admission_when_the_catalog_is_published() {
    let source = native_sources()
        .first()
        .copied()
        .expect("native owner tests require generated registry");
    let (root, _) = publish(&checkbox_catalog(&[(source, &[])]));
    write_config(
        root.path(),
        &json!({
            "schemaVersion": 2, "startup": "interface", "userRevision": 0,
            "fieldRevisions": {},
            "agents": { (source): {"enabled": false, "options": {"intent": "observe"}} }
        }),
    );
    let mut store = Store::new(root.path(), SESSION).unwrap();
    store.initialize_native(BOOT).unwrap();
    assert!(!Host::enabled(&store, source));
    assert!(store.admission(source).is_none());

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
    assert!(matches!(
        store.save_desired(&field, &true.into(), &input).unwrap(),
        Outcome::DesiredSaved {
            disposition: Disposition::Saved,
            ..
        }
    ));
    // A published signed catalog is not an unavailable one: fencing the source
    // here revoked the admission that executes the compensating OEM write.
    assert!(store.desired_catalog_fences.is_empty());
    assert!(Host::enabled(&store, source));
    assert!(store.admission(source).is_some());
}

#[test]
fn the_newer_of_two_conflicting_choices_keeps_the_native_admission() {
    let sources = native_sources();
    let (newer, older) = (
        *sources.first().expect("generated registry"),
        *sources.get(1).expect("two generated codecs"),
    );
    let (root, _) = publish(&checkbox_catalog(&[(newer, &[older]), (older, &[])]));
    write_config(
        root.path(),
        &json!({
            "schemaVersion": 2, "startup": "interface", "userRevision": 5,
            "fieldRevisions": {
                format!("agents/{newer}/enabled"): stamp(5),
                format!("agents/{older}/enabled"): stamp(3),
            },
            "agents": {
                (newer): {"enabled": true, "options": {"intent": "observe"}},
                (older): {"enabled": true, "options": {"intent": "observe"}},
            }
        }),
    );
    let mut store = Store::new(root.path(), SESSION).unwrap();
    store.initialize_native(BOOT).unwrap();
    assert!(store.desired_catalog_fences.is_empty());
    let normalized: serde_json::Value =
        serde_json::from_slice(&store.config().unwrap().unwrap()).unwrap();
    assert_eq!(normalized["agents"][older]["enabled"], false);
    assert_eq!(normalized["agents"][newer]["enabled"], true);
    assert_eq!(normalized["userRevision"], 5);
    assert_eq!(
        normalized["fieldRevisions"][format!("agents/{older}/enabled")],
        stamp(3)
    );
    assert!(store.admission(newer).is_some());
    assert!(store.admission(older).is_none());
}
#[test]
fn keyboard_alternatives_persist_exclusively_in_both_directions_and_reopen() {
    let catalog = checkbox_catalog(&[
        ("keyboard-en", &["keyboard-ru"]),
        ("keyboard-ru", &["keyboard-en"]),
    ]);
    let (root, _) = publish(&catalog);
    write_config(
        root.path(),
        &json!({
            "schemaVersion": 2, "startup": "interface", "userRevision": 0,
            "fieldRevisions": {}, "agents": {
                "keyboard-en": {"enabled": false, "options": {}},
                "keyboard-ru": {"enabled": false, "options": {}}
            }
        }),
    );
    for (index, selected) in ["keyboard-ru", "keyboard-en", "keyboard-ru"]
        .iter()
        .enumerate()
    {
        let other = if *selected == "keyboard-en" {
            "keyboard-ru"
        } else {
            "keyboard-en"
        };
        let mut store = Store::new(root.path(), SESSION).unwrap();
        store.initialize_native(BOOT).unwrap();
        let field = Field::Enabled {
            agent: (*selected).into(),
        };
        let input = Input {
            boot_id: BOOT.into(),
            endpoint_epoch: 1,
            request_id: index as u64 + 1,
            injector_pid: PRODUCER.0,
            injector_starttime: PRODUCER.1,
        };
        let Outcome::DesiredSaved {
            revision,
            config,
            disposition,
        } = store.save_desired(&field, &true.into(), &input).unwrap()
        else {
            panic!("enable must return a durable receipt")
        };
        assert_eq!(disposition, Disposition::Saved);
        let config: serde_json::Value = serde_json::from_str(&config).unwrap();
        assert_eq!(config["agents"][selected]["enabled"], true);
        assert_eq!(config["agents"][other]["enabled"], false);
        assert_eq!(
            config["fieldRevisions"][format!("agents/{selected}/enabled")]["revision"],
            revision
        );
        assert_eq!(
            config["fieldRevisions"][format!("agents/{other}/enabled")]["revision"],
            revision
        );
        drop(store);
        let reopened = Store::new(root.path(), SESSION).unwrap();
        let Outcome::DesiredSaved {
            config: readback, ..
        } = reopened.read_desired(&field).unwrap()
        else {
            panic!("reopened owner must return durable state")
        };
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&readback).unwrap(),
            config
        );
        let persisted = fs::read(root.path().join("agents.json")).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&persisted).unwrap(),
            config
        );
    }
}

#[test]
fn localization_agents_persist_independently_in_both_directions() {
    let (root, _) = publish(&checkbox_catalog(&[("i18n-ru", &[]), ("i18n-en", &[])]));
    write_config(
        root.path(),
        &json!({
            "schemaVersion": 2, "startup": "interface", "userRevision": 0,
            "fieldRevisions": {}, "agents": {
                "i18n-ru": {"enabled": false, "options": {}},
                "i18n-en": {"enabled": false, "options": {}}
            }
        }),
    );
    for (index, (agent, enabled, expected_ru, expected_en)) in [
        ("i18n-ru", true, true, false),
        ("i18n-en", true, true, true),
        ("i18n-ru", false, false, true),
        ("i18n-ru", true, true, true),
        ("i18n-en", false, true, false),
    ]
    .iter()
    .enumerate()
    {
        let mut store = Store::new(root.path(), SESSION).unwrap();
        store.initialize_native(BOOT).unwrap();
        let field = Field::Enabled {
            agent: (*agent).into(),
        };
        let input = Input {
            boot_id: BOOT.into(),
            endpoint_epoch: 1,
            request_id: index as u64 + 1,
            injector_pid: PRODUCER.0,
            injector_starttime: PRODUCER.1,
        };
        let Outcome::DesiredSaved {
            config,
            disposition,
            ..
        } = store
            .save_desired(&field, &(*enabled).into(), &input)
            .unwrap()
        else {
            panic!("toggle must return a durable receipt")
        };
        assert_eq!(disposition, Disposition::Saved);
        let config: serde_json::Value = serde_json::from_str(&config).unwrap();
        assert_eq!(config["agents"]["i18n-ru"]["enabled"], *expected_ru);
        assert_eq!(config["agents"]["i18n-en"]["enabled"], *expected_en);
        assert_eq!(config["startup"], "interface");
        drop(store);
        let reopened = Store::new(root.path(), SESSION).unwrap();
        let Outcome::DesiredSaved {
            config: readback, ..
        } = reopened.read_desired(&field).unwrap()
        else {
            panic!("reopened owner must return durable state")
        };
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&readback).unwrap(),
            config
        );
    }
}

#[test]
fn restored_keyboard_conflicts_are_canonical_before_consumers_read_and_after_reopen() {
    for (english, russian, expected) in [
        (Some(5), Some(3), (true, false)),
        (Some(3), Some(5), (false, true)),
        (Some(3), Some(3), (false, false)),
        (Some(3), None, (false, false)),
        (None, None, (false, false)),
    ] {
        let catalog = checkbox_catalog(&[
            ("keyboard-en", &["keyboard-ru"]),
            ("keyboard-ru", &["keyboard-en"]),
            ("i18n-en", &[]),
            ("i18n-ru", &[]),
            ("font-cyrillic", &[]),
        ]);
        let (root, _) = publish(&catalog);
        let mut revisions = serde_json::Map::new();
        revisions.insert("startup".into(), stamp(5));
        for (id, revision) in [("keyboard-en", english), ("keyboard-ru", russian)] {
            if let Some(revision) = revision {
                revisions.insert(format!("agents/{id}/enabled"), stamp(revision));
            }
        }
        write_config(
            root.path(),
            &json!({
                "schemaVersion":2,"startup":"interface","userRevision":5,"fieldRevisions":revisions,
                "agents": {
                    "keyboard-en":{"enabled":true,"options":{}}, "keyboard-ru":{"enabled":true,"options":{}},
                    "i18n-en":{"enabled":true,"options":{}}, "i18n-ru":{"enabled":true,"options":{}},
                    "font-cyrillic":{"enabled":true,"options":{}}
                }
            }),
        );
        let mut store = Store::new(root.path(), SESSION).unwrap();
        store.initialize_native(BOOT).unwrap();
        let normalized: serde_json::Value =
            serde_json::from_slice(&store.config().unwrap().unwrap()).unwrap();
        assert_eq!(normalized["agents"]["keyboard-en"]["enabled"], expected.0);
        assert_eq!(normalized["agents"]["keyboard-ru"]["enabled"], expected.1);
        assert_eq!(normalized["fieldRevisions"], json!(revisions));
        assert_eq!(normalized["userRevision"], 5);
        for id in ["i18n-en", "i18n-ru", "font-cyrillic"] {
            assert_eq!(normalized["agents"][id]["enabled"], true);
        }
        drop(store);
        let mut reopened = Store::new(root.path(), SESSION).unwrap();
        reopened.initialize_native(BOOT).unwrap();
        let Outcome::DesiredSaved { config, .. } = reopened
            .read_desired(&Field::Enabled {
                agent: "keyboard-en".into(),
            })
            .unwrap()
        else {
            panic!("readback unavailable")
        };
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&config).unwrap(),
            normalized
        );
    }
}

#[test]
fn reordered_group_inputs_keep_only_the_last_keyboard_and_preserve_localization_members() {
    let (root, _) = publish(&checkbox_catalog(&[
        ("keyboard-en", &["keyboard-ru"]),
        ("keyboard-ru", &["keyboard-en"]),
        ("i18n-en", &[]),
        ("i18n-ru", &[]),
        ("font-cyrillic", &[]),
    ]));
    write_config(
        root.path(),
        &json!({
            "schemaVersion":2,"startup":"interface","userRevision":0,"fieldRevisions":{},
            "agents": {
                "keyboard-en":{"enabled":false,"options":{}}, "keyboard-ru":{"enabled":false,"options":{}},
                "i18n-en":{"enabled":false,"options":{}}, "i18n-ru":{"enabled":false,"options":{}},
                "font-cyrillic":{"enabled":false,"options":{}}
            }
        }),
    );
    let mut store = Store::new(root.path(), SESSION).unwrap();
    store.initialize_native(BOOT).unwrap();
    for (id, request) in [
        ("i18n-en", 1),
        ("i18n-ru", 3),
        ("keyboard-ru", 4),
        ("font-cyrillic", 5),
        ("keyboard-en", 2),
        ("keyboard-en", 6),
    ] {
        let field = Field::Enabled { agent: id.into() };
        let input = Input {
            boot_id: BOOT.into(),
            endpoint_epoch: 1,
            request_id: request,
            injector_pid: PRODUCER.0,
            injector_starttime: PRODUCER.1,
        };
        let Outcome::DesiredSaved {
            config,
            disposition,
            ..
        } = store.save_desired(&field, &true.into(), &input).unwrap()
        else {
            panic!("save unavailable")
        };
        let config: serde_json::Value = serde_json::from_str(&config).unwrap();
        if request == 2 {
            assert_eq!(disposition, Disposition::Superseded);
        }
        if request >= 4 || request == 2 {
            assert_eq!(config["agents"]["keyboard-en"]["enabled"], request == 6);
            assert_eq!(config["agents"]["keyboard-ru"]["enabled"], request != 6);
        }
    }
    let config: serde_json::Value =
        serde_json::from_slice(&store.config().unwrap().unwrap()).unwrap();
    for id in ["i18n-en", "i18n-ru", "font-cyrillic"] {
        assert_eq!(config["agents"][id]["enabled"], true);
    }
}
