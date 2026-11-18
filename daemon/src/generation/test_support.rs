use super::*;
use ed25519_dalek::{Signer, SigningKey};
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;

pub(crate) const KNOWN_FACTS: &str =
    "{\"schemaVersion\":1,\"facts\":{\"chip\":{\"value\":\"8155\"},\
     \"vehicle\":{\"value\":\"free\"},\"android\":{\"value\":9},\
     \"powertrain\":{\"value\":\"hybrid\"},\"market\":{\"value\":\"china\"}}}";

const TEST_AGENT_CATALOG_SEED: &str =
    "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5";

pub(crate) fn sign_catalog(bytes: &[u8]) -> Vec<u8> {
    let seed: [u8; 32] = hex::decode(TEST_AGENT_CATALOG_SEED)
        .unwrap()
        .try_into()
        .unwrap();
    SigningKey::from_bytes(&seed)
        .sign(bytes)
        .to_bytes()
        .to_vec()
}

pub(crate) struct TestZones {
    pub(crate) _root: tempfile::TempDir,
    pub(crate) store: GenerationStore,
}

pub(crate) fn zones() -> TestZones {
    let root = tempdir().unwrap();
    let zone = root.path().join("zone");
    let incoming = root.path().join("incoming");
    fs::create_dir_all(&incoming).unwrap();
    fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir_all(&zone).unwrap();
    fs::set_permissions(&zone, fs::Permissions::from_mode(0o755)).unwrap();
    let dir = Directory::open(&zone).unwrap();
    dir.prepare_trusted(VEHICLE_PROFILE_FILE, KNOWN_FACTS.as_bytes(), 0o644)
        .unwrap();
    TestZones {
        _root: root,
        store: GenerationStore::new(zone, incoming),
    }
}

fn variant_catalog(variant: u32) -> Vec<u8> {
    let digest = |bytes: &[u8]| {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    };
    let raw = format!(
        r#"{{"schemaVersion":2,"supportedAbis":["arm64-v8a"],"agentEntryAbi":{{"schemaVersion":1,"sha256":"{abi}"}},"core":{{"file":"agent-common.dex","size":4,"sha256":"{core_sha}"}},"agents":[{{"id":"settings","targets":[{{"platform":"android","domain":"android","entryAbi":"android-java-v1","process":"com.qinggan.app.setting","file":"agent-settings.dex","size":5,"sha256":"{agent_sha}","entryClass":"ru.voboost.agents.settings.SettingsAgent","boot":false}}],"status":"unstable","category":"interface","order":0,"activation":{{"type":"config","key":"voboost-startup","value":"interface"}},"disables":[],"options":[],"title":{{"en":"V{variant}","ru":"V{variant}"}},"description":{{"en":"S","ru":"S"}},"applicability":{{"chip":["8155"],"vehicle":["free","dreamer"],"android":[9],"powertrain":["hybrid"],"market":["china"]}}}}]}}"#,
        abi = crate::catalog::AGENT_ENTRY_ABI_SHA256,
        core_sha = digest(b"core"),
        agent_sha = digest(b"agent"),
    );
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let catalog: AgentCatalog = serde_json::from_value(value).unwrap();
    let mut bytes = serde_json::to_vec(&catalog).unwrap();
    bytes.push(b'\n');
    bytes
}

/// Fully verified in-memory identity for daemon-loop tests that do not
/// need root-only immutable-store publication.
pub(crate) fn verified_variant(variant: u32) -> VerifiedGeneration {
    let exact_catalog = variant_catalog(variant);
    let catalog_sha256 = crate::trust::sha256_bytes(&exact_catalog);
    let catalog = AgentCatalog::parse(&exact_catalog).unwrap();
    let facts = crate::selection::VehicleProfileDocument::parse_canonical(KNOWN_FACTS.as_bytes())
        .unwrap()
        .facts;
    let selection =
        crate::selection::SelectionReceipt::compute(&catalog, &catalog_sha256, &facts).unwrap();
    let id = crate::selection::generation_id(&catalog_sha256, &selection.sha256).unwrap();
    VerifiedGeneration {
        id,
        catalog_sha256,
        selection_sha256: selection.sha256.clone(),
        directory: PathBuf::new(),
        catalog,
        selection,
        files: Vec::new(),
    }
}

/// Stage one complete incoming generation; `variant` changes a catalog
/// title so each call produces a distinct generation id.
pub(crate) fn stage_variant(store: &GenerationStore, variant: u32) {
    let catalog = variant_catalog(variant);
    let incoming = &store.incoming;
    let _ = fs::remove_file(incoming.join(ACKNOWLEDGEMENT_FILE));
    fs::write(incoming.join(CATALOG_FILE), &catalog).unwrap();
    fs::write(
        incoming.join(CATALOG_SIGNATURE_FILE),
        sign_catalog(&catalog),
    )
    .unwrap();
    fs::write(incoming.join("agent-common.dex"), b"core").unwrap();
    fs::write(incoming.join("agent-settings.dex"), b"agent").unwrap();
    fs::write(incoming.join(READY_MARKER), b"").unwrap();
}

/// Verified generation identity matching the OEM driver endpoint fixture
/// (agent_log settings_ctx: settings/forced-ev/outing catalog surface), so
/// the committed fixture plan validates and the chain test can correlate the
/// rendered A-frame document against the runtime jar's expected ids.
pub(crate) fn verified_oem_chain() -> VerifiedGeneration {
    let raw = r#"{'serde_skip'}"#;
    let _ = raw;
    // Fixture catalog carries the EXACT production agents metadata identity
    // (stage 011): id/category/status/order/activation/options/applicability
    // are byte-parity with the generated release catalog entries
    // (agents repo src/main/java/.../*.json); only targets' dex file payload
    // facts and the title/description text are fixture-local. A parity
    // control test (daemon tests) pins id/options/activation against the
    // hardcoded production values so fixture drift fails loudly.
    let make = |id: &str,
                category: &str,
                order: i32,
                status: &str,
                activation: serde_json::Value,
                application: &[i32],
                market: &[&str],
                powertrain: &[&str],
                disables: serde_json::Value,
                options: serde_json::Value| {
        let _ = status;
        serde_json::json!({
            "id": id,
            "targets": [{"platform":"android","domain":"android","entryAbi":"android-java-v1","process": process_for(id),
                         "file": format!("{id}.dex"), "size": 5,
                         "sha256": "x", "entryClass": "", "boot": false}],
            "status": status, "category": category, "order": order,
            "activation": activation, "disables": disables, "options": options,
            "title": {"en": "T", "ru": "T"},
            "description": {"en": "D", "ru": "D"},
            "applicability": {"chip": ["8155"], "vehicle": ["free"],
                              "android": application, "powertrain": powertrain,
                              "market": market}
        })
    };
    fn process_for(id: &str) -> &str {
        match id {
            "settings" => "com.qinggan.app.setting",
            "vehicle-drive-forced-ev" => "com.qinggan.systemservice",
            "vehicle-drive-outing" => "com.qinggan.app.vehicle",
            _ => panic!("unknown fixture agent id {id}"),
        }
    }
    let catalog = serde_json::json!({
        "schemaVersion": 2,
        "supportedAbis": ["arm64-v8a"],
        "agentEntryAbi": {"schemaVersion": 1,
            "sha256": crate::catalog::AGENT_ENTRY_ABI_SHA256},
        "core": {"file": "agent-common.dex", "size": 4, "sha256": "core"},
        "agents": [
            // Production identity: SettingsAgent.json
            make("settings", "interface", -1, "unstable",
                 serde_json::json!({"type": "config",
                     "key": "voboost-startup", "value": "interface"}),
                 &[9, 11], &["china", "global"], &["ev", "hybrid"],
                 serde_json::json!([]), serde_json::json!([])),
            // Production identity: VehicleDriveForcedEvAgent.json
            make("vehicle-drive-forced-ev", "vehicle", 23, "stable",
                 serde_json::json!({"type": "checkbox", "default": true}),
                 &[9, 11], &["china", "global"], &["hybrid"],
                 serde_json::json!([]), serde_json::json!([])),
            // Production identity: VehicleDriveOutingAgent.json
            make("vehicle-drive-outing", "vehicle", 27, "unstable",
                 serde_json::json!({"type": "checkbox", "default": false}),
                 &[9, 11], &["china", "global"], &["ev", "hybrid"],
                 serde_json::json!([]), serde_json::json!([
                     {"key": "exit-target", "type": "enum",
                      "values": [
                          {"value": "comfort",
                           "title": {"en": "Comfort", "ru": "Комфорт"}},
                          {"value": "previous",
                           "title": {"en": "Previous mode",
                                     "ru": "Предыдущий режим"}},
                      ],
                      "default": "comfort"},
                     {"key": "above-speed", "type": "enum",
                      "values": [
                          {"value": "exit",
                           "title": {"en": "Exit Outing", "ru": "Выйти из Outing"}},
                          {"value": "keep",
                           "title": {"en": "Keep Outing", "ru": "Оставить Outing"}},
                      ],
                      "default": "exit"}])),
        ]
    });
    let exact = serde_json::to_vec(&catalog).unwrap();
    let digest = crate::trust::sha256_bytes(&exact);
    let parsed: AgentCatalog = serde_json::from_value(catalog).unwrap();
    let facts = crate::selection::VehicleProfileDocument::parse_canonical(KNOWN_FACTS.as_bytes())
        .unwrap()
        .facts;
    let selection = crate::selection::SelectionReceipt::compute(&parsed, &digest, &facts).unwrap();
    let id = generation_id(&digest, &selection.sha256).unwrap();
    VerifiedGeneration {
        id,
        catalog_sha256: digest,
        selection_sha256: selection.sha256.clone(),
        directory: PathBuf::new(),
        catalog: parsed,
        selection,
        files: Vec::new(),
    }
}

pub(crate) fn activate_cluster_variant(
    store: &GenerationStore,
    variant: u32,
) -> VerifiedGeneration {
    activate_variant_inner(store, variant, true)
}
fn activate_variant_inner(
    store: &GenerationStore,
    variant: u32,
    cluster: bool,
) -> VerifiedGeneration {
    stage_variant(store, variant);
    if cluster {
        let mut catalog: AgentCatalog =
            serde_json::from_slice(&fs::read(store.incoming.join(CATALOG_FILE)).unwrap()).unwrap();
        let mut agent = catalog.agents[0].clone();
        agent.id = "font-cyrillic".into();
        agent.order = Some(1);
        agent.activation = Some(crate::catalog::Activation::Checkbox { default: false });
        let target = &mut agent.targets[0];
        target.platform = crate::catalog::TargetPlatform::Qnx;
        target.domain = crate::catalog::TargetDomain::Cluster;
        target.entry_abi = crate::catalog::TargetAbi::VoboostAgent3V1;
        target.entry_class = None;
        target.process = "gauge".into();
        target.file = "libagent-font-cyrillic.so".into();
        target.size = 4;
        target.sha256 = digest(b"font");
        catalog.agents.push(agent);
        catalog.cluster_runtime = Some(crate::catalog::CatalogFile {
            file: "libvoboost-runtime-cluster.so".into(),
            size: 7,
            sha256: digest(b"runtime"),
        });
        let mut bytes = serde_json::to_vec(&catalog).unwrap();
        bytes.push(b'\n');
        fs::write(store.incoming.join(CATALOG_FILE), &bytes).unwrap();
        fs::write(
            store.incoming.join(CATALOG_SIGNATURE_FILE),
            sign_catalog(&bytes),
        )
        .unwrap();
        fs::write(store.incoming.join("libagent-font-cyrillic.so"), b"font").unwrap();
        fs::write(
            store.incoming.join("libvoboost-runtime-cluster.so"),
            b"runtime",
        )
        .unwrap();
    }
    store.ensure_layout().unwrap();
    let catalog_bytes = fs::read(store.incoming.join(CATALOG_FILE)).unwrap();
    let signature = fs::read(store.incoming.join(CATALOG_SIGNATURE_FILE)).unwrap();
    let catalog = AgentCatalog::parse_verified(&catalog_bytes, &signature).unwrap();
    let catalog_sha256 = AgentCatalog::digest(&catalog_bytes);
    let facts = VehicleProfileDocument::parse_canonical(KNOWN_FACTS.as_bytes()).unwrap();
    let selection = SelectionReceipt::compute(&catalog, &catalog_sha256, &facts.facts).unwrap();
    let id = generation_id(&catalog_sha256, &selection.sha256).unwrap();
    let expected = expected_inventory(&catalog, &selection, &catalog_bytes, &signature).unwrap();
    let path = store.root.join(GENERATIONS_DIR).join(&id);
    fs::create_dir(&path).unwrap();
    for file in expected.values() {
        let bytes = if file.file == AGENTS_SELECTED_FILE {
            selection.exact_bytes.clone()
        } else {
            fs::read(store.incoming.join(&file.file)).unwrap()
        };
        fs::write(path.join(&file.file), bytes).unwrap();
        fs::set_permissions(
            path.join(&file.file),
            fs::Permissions::from_mode(GENERATION_FILE_MODE),
        )
        .unwrap();
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(GENERATION_DIR_MODE)).unwrap();
    let next = store.load_generation(&id).unwrap();
    let previous = store.active().ok();
    store
        .commit_activation(previous.as_ref(), next, None)
        .unwrap()
}
