use super::*;
use crate::operation_contract::{Operation, OperationDescriptor, OperationLease};
use std::ffi::CString;
use std::fs::{File, FileTimes, OpenOptions};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
use std::time::UNIX_EPOCH;
use tempfile::tempdir;

// --- activation set-comparison integration tests ---
//
// Ordinary generation tests exercise receipt validation and immutable import.
// The initial-install matrix below separately proves that production computes
// its own receipt from the frozen product closure and root vehicle.json.

const KNOWN_FACTS: &str = "{\"schemaVersion\":1,\"facts\":{\"chip\":{\"value\":\"8155\"},\
     \"vehicle\":{\"value\":\"free\"},\"android\":{\"value\":9},\
     \"powertrain\":{\"value\":\"hybrid\"},\"market\":{\"value\":\"china\"}}}";
const GLOBAL_FACTS: &str = "{\"schemaVersion\":1,\"facts\":{\"chip\":{\"value\":\"8155\"},\
     \"vehicle\":{\"value\":\"free\"},\"android\":{\"value\":9},\
     \"powertrain\":{\"value\":\"hybrid\"},\"market\":{\"value\":\"global\"}}}";

#[test]
fn production_generation_source_requires_correlated_install_authority() {
    assert!(production_generation_source_allowed(true));
    assert!(!production_generation_source_allowed(false));
}

fn operation_descriptor(operation: Operation, salt: char) -> OperationDescriptor {
    let transaction_id = salt.to_string().repeat(64);
    OperationDescriptor::new(
        operation,
        transaction_id.clone(),
        format!(
            "recovery/{transaction_id}/{}-journal.json",
            operation.as_str()
        ),
        "00000000-0000-0000-0000-000000000001".to_string(),
    )
    .unwrap()
}

#[test]
fn install_ack_faults_retry_identically_and_retrigger_fixed_service() {
    let expected = b"{\"schemaVersion\":1,\"transactionId\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"apkSha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"catalogSha256\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"selectionSha256\":\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"generationSha256\":\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"}\n";
    for fault in [
        InstallAckFault::TempWrite,
        InstallAckFault::TempFsync,
        InstallAckFault::Rename,
        InstallAckFault::ParentFsync,
        InstallAckFault::ExactAck,
        InstallAckFault::Start,
        InstallAckFault::Started,
    ] {
        let temporary = tempdir().unwrap();
        let recovery = Directory::open(temporary.path()).unwrap();
        let mut starts = 0;
        publish_install_ack_with(&recovery, expected, Some(fault), || {
            starts += 1;
            Ok(())
        })
        .unwrap_err();

        publish_install_ack_with(&recovery, expected, None, || {
            starts += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(
            fs::read(temporary.path().join("generation-ack.json")).unwrap(),
            expected,
            "retry after {fault:?} changed canonical acknowledgement"
        );
        assert_eq!(
            starts,
            if fault == InstallAckFault::Started {
                2
            } else {
                1
            }
        );
    }
}

struct PendingInstallAck {
    zones: Zones,
    recovery: PathBuf,
    journal: Vec<u8>,
    pointer: OperationDescriptor,
    acknowledgement: crate::generation_contract::GenerationAcknowledgement,
}

fn pending_install_ack() -> PendingInstallAck {
    let zones = zones();
    stage(
        &zones.store.incoming,
        &catalog_bytes("china"),
        &[
            ("agent-common.dex", b"core"),
            ("agent-settings.dex", b"agent"),
        ],
    );
    let active = install_staged_generation_without_pointer(&zones.store);
    fs::remove_file(zones.store.incoming_marker()).unwrap();
    Directory::open(&zones.store.root.join(GENERATIONS_DIR))
        .unwrap()
        .write_atomic(
            ACTIVE_POINTER,
            format!("{}\n", active.id).as_bytes(),
            GENERATION_FILE_MODE,
        )
        .unwrap();
    let mut manifest = voboost_contract::release::Manifest::parse(include_bytes!(
        "../../../test/fixtures/product-release/voboost/valid/minimal.json"
    ))
    .unwrap();
    manifest
        .artifacts
        .iter_mut()
        .find(|a| a.file == CATALOG_FILE)
        .unwrap()
        .sha256 = active.catalog_sha256.clone();
    let manifest_bytes = manifest.canonical_bytes().unwrap();
    let transaction_id = digest(&manifest_bytes);
    let recovery = zones.store.root.join("recovery").join(&transaction_id);
    let frozen = recovery.join("frozen");
    fs::create_dir_all(&frozen).unwrap();
    fs::set_permissions(
        recovery.parent().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&recovery, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&frozen, fs::Permissions::from_mode(0o700)).unwrap();
    Directory::open(&frozen)
        .unwrap()
        .write_atomic("voboost.json", &manifest_bytes, ROOT_FILE_MODE)
        .unwrap();
    // WAL uses its production field order, not serde_json map ordering.
    let journal = format!("{{\"schemaVersion\":1,\"transactionId\":\"{transaction_id}\",\"manifestSha256\":\"{transaction_id}\",\"phase\":\"install-agents\",\"bootIds\":[\"00000000-0000-0000-0000-000000000001\"]}}\n").into_bytes();
    Directory::open(&recovery)
        .unwrap()
        .write_atomic("install-journal.json", &journal, ROOT_FILE_MODE)
        .unwrap();
    let mut pointer = operation_descriptor(Operation::Install, 'a');
    pointer.transaction_id = transaction_id.clone();
    pointer.journal = format!("recovery/{transaction_id}/install-journal.json");
    pointer.phase = "install-agents".into();
    pointer.reboot_count = 1;
    pointer.status_sequence = 19;
    pointer.journal_sha256 = digest(&journal);
    let lease = OperationLease::acquire_in(&zones.store.root, pointer.clone()).unwrap();
    lease.verify_owner().unwrap();
    drop(lease);
    let acknowledgement = crate::generation_contract::GenerationAcknowledgement {
        schema_version: 1,
        transaction_id,
        apk_sha256: manifest.app_artifact().unwrap().sha256.clone(),
        catalog_sha256: active.catalog_sha256,
        selection_sha256: active.selection_sha256,
        generation_sha256: active.id,
    };
    PendingInstallAck {
        zones,
        recovery,
        journal,
        pointer,
        acknowledgement,
    }
}

fn ack_bytes(ack: &crate::generation_contract::GenerationAcknowledgement) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(ack).unwrap();
    bytes.push(b'\n');
    bytes
}

#[test]
fn validated_install_ack_retriggers_after_initial_start_is_a_running_noop() {
    let fixture = pending_install_ack();
    let ack = ack_bytes(&fixture.acknowledgement);
    let running = std::cell::Cell::new(true);
    let wakes = std::cell::Cell::new(0);
    let start = || {
        if !running.get() {
            // The real continuation must be able to claim the install lease immediately.
            let guard =
                GenerationGuard::acquire_install_generation_in(&fixture.zones.store.root).unwrap();
            guard.verify_owner().unwrap();
            wakes.set(wakes.get() + 1);
            running.set(true);
        }
        Ok(())
    };
    // Production publication succeeds even when init treats start as a running no-op.
    publish_install_ack_with(
        &Directory::open(&fixture.recovery).unwrap(),
        &ack,
        None,
        start,
    )
    .unwrap();
    assert_eq!(wakes.get(), 0);
    running.set(false); // Original oneshot exits after its earlier missing-ACK decision.
    assert_eq!(
        fixture
            .zones
            .store
            .prepare_initial_install_with_start(start)
            .unwrap(),
        InitialInstallPreparation::Idle
    );
    assert_eq!(
        wakes.get(),
        1,
        "the next actual watcher preparation must retrigger continuation"
    );
    assert_eq!(
        fs::read(fixture.recovery.join(ACKNOWLEDGEMENT_FILE)).unwrap(),
        ack
    );
    assert_eq!(
        fs::read(fixture.recovery.join("install-journal.json")).unwrap(),
        fixture.journal
    );
    assert!(
        !fixture.zones.store.incoming_marker().exists(),
        "an ACK retry must not restage"
    );
}

#[test]
fn install_ack_retrigger_rejects_malformed_mismatched_foreign_and_advanced_authority() {
    for field in [
        "transaction",
        "apk",
        "catalog",
        "selection",
        "generation",
        "malformed",
        "foreign",
        "advanced",
        "failed",
    ] {
        let mut fixture = pending_install_ack();
        let wrong = "ff".repeat(32);
        match field {
            "transaction" => fixture.acknowledgement.transaction_id = wrong,
            "apk" => fixture.acknowledgement.apk_sha256 = wrong,
            "catalog" => fixture.acknowledgement.catalog_sha256 = wrong,
            "selection" => fixture.acknowledgement.selection_sha256 = wrong,
            "generation" => fixture.acknowledgement.generation_sha256 = wrong,
            "foreign" => {
                fixture.pointer.operation = Operation::Restore;
                fixture.pointer.phase = "restore-inspect".into();
                fixture.pointer.journal = format!(
                    "recovery/{}/restore-journal.json",
                    fixture.pointer.transaction_id
                );
            }
            "failed" => {
                fixture.pointer.outcome = "failed".into();
                fixture.pointer.error =
                    Some(serde_json::json!({"code":"test", "message":"terminal failure"}));
            }
            "advanced" => {
                fixture.journal = String::from_utf8(fixture.journal)
                    .unwrap()
                    .replace("install-agents", "install-reboot-second")
                    .into_bytes();
                fixture.pointer.phase = "install-reboot-second".into();
                fixture.pointer.journal_sha256 = digest(&fixture.journal);
                Directory::open(&fixture.recovery)
                    .unwrap()
                    .write_atomic("install-journal.json", &fixture.journal, ROOT_FILE_MODE)
                    .unwrap();
            }
            _ => {}
        }
        Directory::open(&fixture.zones.store.root)
            .unwrap()
            .write_atomic(
                "operation.json",
                &fixture.pointer.canonical_bytes().unwrap(),
                ROOT_FILE_MODE,
            )
            .unwrap();
        let bytes = if field == "malformed" {
            b"{}\n".to_vec()
        } else {
            ack_bytes(&fixture.acknowledgement)
        };
        Directory::open(&fixture.recovery)
            .unwrap()
            .write_atomic(ACKNOWLEDGEMENT_FILE, &bytes, ROOT_FILE_MODE)
            .unwrap();
        let starts = std::cell::Cell::new(0);
        let result = fixture.zones.store.prepare_initial_install_with_start(|| {
            starts.set(starts.get() + 1);
            Ok(())
        });
        if field == "failed" {
            assert_eq!(result.unwrap(), InitialInstallPreparation::Idle);
        } else {
            assert!(result.is_err(), "{field}");
        }
        assert_eq!(starts.get(), 0, "{field} must not start the service");
    }
}

#[test]
fn install_ack_retrigger_failure_remains_observable_and_retries_unchanged_ack() {
    let fixture = pending_install_ack();
    let ack = ack_bytes(&fixture.acknowledgement);
    Directory::open(&fixture.recovery)
        .unwrap()
        .write_atomic(ACKNOWLEDGEMENT_FILE, &ack, ROOT_FILE_MODE)
        .unwrap();
    let error = fixture
        .zones
        .store
        .prepare_initial_install_with_start(|| bail!("simulated ctl.start refusal"))
        .unwrap_err();
    assert!(format!("{error:#}").contains("simulated ctl.start refusal"));
    let starts = std::cell::Cell::new(0);
    assert_eq!(
        fixture
            .zones
            .store
            .prepare_initial_install_with_retry(
                || {
                    starts.set(starts.get() + 1);
                    Ok(())
                },
                || Ok(false),
                Instant::now() + Duration::from_secs(2)
            )
            .unwrap(),
        InitialInstallPreparation::Idle
    );
    assert_eq!(starts.get(), 1);
    assert_eq!(
        fs::read(fixture.recovery.join(ACKNOWLEDGEMENT_FILE)).unwrap(),
        ack
    );
}

#[test]
fn initial_install_preparation_busy_preserves_staging_and_drops_reader_before_wake() {
    let fixture = pending_install_ack();
    let bytes = ack_bytes(&fixture.acknowledgement);
    Directory::open(&fixture.recovery)
        .unwrap()
        .write_atomic(ACKNOWLEDGEMENT_FILE, &bytes, ROOT_FILE_MODE)
        .unwrap();
    let before = staged_bytes(&fixture.zones.store.incoming);
    let writer = GenerationGuard::acquire_install_generation_in(&fixture.zones.store.root).unwrap();
    let starts = std::cell::Cell::new(0);
    assert_eq!(
        fixture
            .zones
            .store
            .prepare_initial_install_with_start(|| {
                starts.set(starts.get() + 1);
                Ok(())
            })
            .unwrap(),
        InitialInstallPreparation::Busy
    );
    assert_eq!(starts.get(), 0);
    assert_eq!(staged_bytes(&fixture.zones.store.incoming), before);
    drop(writer);
    assert_eq!(
        fixture
            .zones
            .store
            .prepare_initial_install_with_start(|| {
                let lease =
                    GenerationGuard::acquire_install_generation_in(&fixture.zones.store.root)
                        .unwrap();
                lease.verify_owner().unwrap();
                starts.set(starts.get() + 1);
                Ok(())
            })
            .unwrap(),
        InitialInstallPreparation::Idle
    );
    assert_eq!(starts.get(), 1);
}

fn old_prune_candidate(store: &GenerationStore, salt: char) -> (String, PathBuf) {
    store.ensure_layout().unwrap();
    let id = salt.to_string().repeat(64);
    let path = store.root.join(GENERATIONS_DIR).join(&id);
    fs::create_dir(&path).unwrap();
    fs::write(path.join("payload"), b"immutable generation bytes").unwrap();
    File::open(&path)
        .unwrap()
        .set_times(FileTimes::new().set_modified(UNIX_EPOCH))
        .unwrap();
    (id, path)
}

fn tree_bytes(root: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
    fn collect(root: &Path, path: &Path, out: &mut Vec<(PathBuf, Option<Vec<u8>>)>) {
        let mut entries = fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let entry_path = entry.path();
            let relative = entry_path.strip_prefix(root).unwrap().to_path_buf();
            if entry.file_type().unwrap().is_dir() {
                out.push((relative, None));
                collect(root, &entry_path, out);
            } else {
                out.push((relative, Some(fs::read(entry_path).unwrap())));
            }
        }
    }
    let mut result = Vec::new();
    collect(root, root, &mut result);
    result
}

fn replace_operation_lock_path(root: &Path) {
    fs::rename(
        root.join("operation.lock"),
        root.join("operation.lock.displaced"),
    )
    .unwrap();
    let replacement = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("operation.lock"))
        .unwrap();
    replacement.sync_all().unwrap();
}

fn sign_with_release_key(msg: &[u8]) -> Vec<u8> {
    test_support::sign_catalog(msg)
}

fn catalog_bytes(market: &str) -> Vec<u8> {
    let raw = format!(
        r#"{{"schemaVersion":2,"supportedAbis":["arm64-v8a"],"agentEntryAbi":{{"schemaVersion":1,"sha256":"{abi}"}},"core":{{"file":"agent-common.dex","size":4,"sha256":"{core_sha}"}},"agents":[{{"id":"settings","targets":[{{"platform":"android","domain":"android","entryAbi":"android-java-v1","process":"com.qinggan.app.setting","file":"agent-settings.dex","size":5,"sha256":"{agent_sha}","entryClass":"ru.voboost.agents.settings.SettingsAgent","boot":false}}],"status":"unstable","category":"interface","order":0,"activation":{{"type":"config","key":"voboost-startup","value":"interface"}},"disables":[],"options":[],"title":{{"en":"V","ru":"V"}},"description":{{"en":"S","ru":"S"}},"applicability":{{"chip":["8155"],"vehicle":["free","dreamer"],"android":[9],"powertrain":["hybrid"],"market":["{market}"]}}}}]}}"#,
        abi = crate::catalog::AGENT_ENTRY_ABI_SHA256,
        core_sha = digest(b"core"),
        agent_sha = digest(b"agent"),
    );
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    canonical_catalog_bytes(&value)
}

fn canonical_catalog_bytes(value: &serde_json::Value) -> Vec<u8> {
    let catalog: AgentCatalog = serde_json::from_value(value.clone()).unwrap();
    let mut bytes = serde_json::to_vec(&catalog).unwrap();
    bytes.push(b'\n');
    bytes
}

fn catalog_bytes_with_required_artifact() -> Vec<u8> {
    let mut value: serde_json::Value = serde_json::from_slice(&catalog_bytes("china")).unwrap();
    value["agents"][0]["targets"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "platform":"android","domain":"android","entryAbi":"android-java-v1","process":"com.qinggan.app.settingssecond",
            "file":"agent-settings-second.dex",
            "size":2,
            "sha256":digest(b"ui"),
            "entryClass":"ru.voboost.agents.settings.SettingsAgent",
            "boot":false
        }));
    canonical_catalog_bytes(&value)
}

fn catalog_bytes_with_version(version: &str) -> Vec<u8> {
    let mut value: serde_json::Value = serde_json::from_slice(&catalog_bytes("china")).unwrap();
    value["agents"][0]["title"] = serde_json::json!({"en":version,"ru":version});
    canonical_catalog_bytes(&value)
}

fn staged_bytes(incoming: &Path) -> BTreeMap<std::ffi::OsString, Vec<u8>> {
    fs::read_dir(incoming)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            (
                path.file_name().unwrap().to_os_string(),
                fs::read(&path).unwrap(),
            )
        })
        .collect()
}

fn prepare_owner_restored_before_journal(store: &GenerationStore) -> VerifiedGeneration {
    stage(
        &store.incoming,
        &catalog_bytes("china"),
        &[
            ("agent-common.dex", b"core"),
            ("agent-settings.dex", b"agent"),
        ],
    );
    let next = install_staged_generation_without_pointer(store);
    store
        .commit_activation(None, next.clone(), Some(ActivationCrashPoint::Accepted))
        .unwrap_err();
    store.acknowledge_accepted(&next).unwrap();
    fs::remove_file(store.incoming.join(READY_MARKER)).unwrap();
    Directory::open(&store.incoming)
        .unwrap()
        .sync_all()
        .unwrap();
    let mut journal = store.read_activation_journal().unwrap().unwrap();
    journal.claim_phase = ClaimPhase::SnapshotsRemoved;
    store.write_activation_journal(&journal).unwrap();
    next
}

struct Zones {
    _root: tempfile::TempDir,
    store: GenerationStore,
}

fn zones() -> Zones {
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
    Zones {
        _root: root,
        store: GenerationStore::new(zone, incoming),
    }
}

#[test]
fn generation_pointers_use_the_same_readonly_mode_as_installer_verification() {
    let zones = test_support::zones();
    test_support::stage_variant(&zones.store, 1);
    let first = install_staged_generation_without_pointer(&zones.store);
    let first = zones.store.commit_activation(None, first, None).unwrap();
    let current =
        fs::metadata(zones.store.root.join(GENERATIONS_DIR).join(ACTIVE_POINTER)).unwrap();
    assert_eq!(current.permissions().mode() & 0o7777, GENERATION_FILE_MODE);

    test_support::stage_variant(&zones.store, 2);
    let second = install_staged_generation_without_pointer(&zones.store);
    zones
        .store
        .commit_activation(Some(&first), second, None)
        .unwrap();
    for pointer in [ACTIVE_POINTER, PREVIOUS_POINTER] {
        let metadata = fs::metadata(zones.store.root.join(GENERATIONS_DIR).join(pointer)).unwrap();
        assert_eq!(
            metadata.permissions().mode() & 0o7777,
            GENERATION_FILE_MODE,
            "{pointer} mode differs from immutable generation contract"
        );
    }
}

fn stage(incoming: &Path, catalog: &[u8], files: &[(&str, &[u8])]) {
    stage_with_facts(incoming, catalog, files, KNOWN_FACTS);
}

fn staged_generation_id(incoming: &Path) -> String {
    let catalog_bytes = fs::read(incoming.join(CATALOG_FILE)).unwrap();
    let catalog = AgentCatalog::parse(&catalog_bytes).unwrap();
    let facts = VehicleProfileDocument::parse_canonical(KNOWN_FACTS.as_bytes()).unwrap();
    let selection = SelectionReceipt::compute(
        &catalog,
        &AgentCatalog::digest(&catalog_bytes),
        &facts.facts,
    )
    .unwrap();
    generation_id(&AgentCatalog::digest(&catalog_bytes), &selection.sha256).unwrap()
}

fn stage_with_facts(incoming: &Path, catalog: &[u8], files: &[(&str, &[u8])], facts_json: &str) {
    let _ = fs::remove_file(incoming.join(ACKNOWLEDGEMENT_FILE));
    for entry in fs::read_dir(incoming).unwrap().filter_map(Result::ok) {
        let _ = fs::remove_file(entry.path());
    }
    fs::write(incoming.join(CATALOG_FILE), catalog).unwrap();
    fs::write(
        incoming.join(CATALOG_SIGNATURE_FILE),
        sign_with_release_key(catalog),
    )
    .unwrap();
    let parsed = AgentCatalog::parse(catalog).unwrap();
    let facts = VehicleProfileDocument::parse_canonical(facts_json.as_bytes()).unwrap();
    let selection =
        SelectionReceipt::compute(&parsed, &AgentCatalog::digest(catalog), &facts.facts).unwrap();
    fs::write(incoming.join(AGENTS_SELECTED_FILE), selection.exact_bytes).unwrap();
    for (name, bytes) in files {
        fs::write(incoming.join(name), bytes).unwrap();
    }
    fs::write(incoming.join(READY_MARKER), b"").unwrap();
}

fn replace_root_facts(store: &GenerationStore, facts: &str) {
    fs::set_permissions(
        store.root.join(VEHICLE_PROFILE_FILE),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::write(store.root.join(VEHICLE_PROFILE_FILE), facts).unwrap();
    fs::set_permissions(
        store.root.join(VEHICLE_PROFILE_FILE),
        fs::Permissions::from_mode(crate::profile::VEHICLE_PROFILE_MODE),
    )
    .unwrap();
}

fn install_staged_generation_without_pointer(store: &GenerationStore) -> VerifiedGeneration {
    store.ensure_layout().unwrap();
    let catalog_bytes = fs::read(store.incoming.join(CATALOG_FILE)).unwrap();
    let signature = fs::read(store.incoming.join(CATALOG_SIGNATURE_FILE)).unwrap();
    let catalog = AgentCatalog::parse_verified(&catalog_bytes, &signature).unwrap();
    let catalog_sha256 = AgentCatalog::digest(&catalog_bytes);
    let facts = VehicleProfileDocument::parse_canonical(KNOWN_FACTS.as_bytes()).unwrap();
    let selection = SelectionReceipt::compute(&catalog, &catalog_sha256, &facts.facts).unwrap();
    fs::write(
        store.incoming.join(AGENTS_SELECTED_FILE),
        &selection.exact_bytes,
    )
    .unwrap();
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
    store.load_generation(&id).unwrap()
}

fn native_catalog_fixture(bytes: &[u8]) -> Vec<u8> {
    let mut catalog: AgentCatalog = serde_json::from_slice(bytes).unwrap();
    let mut agent = catalog.agents[0].clone();
    agent.id = "font-cyrillic".into();
    agent.order = Some(
        catalog
            .agents
            .iter()
            .filter_map(|a| a.order)
            .max()
            .unwrap_or(0)
            + 1,
    );
    agent.activation = Some(crate::catalog::Activation::Checkbox { default: false });
    agent.targets.truncate(1);
    let target = &mut agent.targets[0];
    target.platform = crate::catalog::TargetPlatform::Qnx;
    target.domain = crate::catalog::TargetDomain::Cluster;
    target.entry_abi = crate::catalog::TargetAbi::VoboostAgent3V1;
    target.entry_class = None;
    target.process = "gauge".into();
    target.file = "libagent-font-cyrillic.so".into();
    target.size = b"fixed-product-artifact".len() as u64;
    target.sha256 = digest(b"fixed-product-artifact");
    catalog.agents.push(agent);
    catalog.cluster_runtime = Some(crate::catalog::CatalogFile {
        file: "libvoboost-runtime-cluster.so".into(),
        size: b"fixed-product-artifact".len() as u64,
        sha256: digest(b"fixed-product-artifact"),
    });
    let mut bytes = serde_json::to_vec(&catalog).unwrap();
    bytes.push(b'\n');
    bytes
}

fn materialize_shared_product_generation(
    store: &GenerationStore,
    exact_catalog: &[u8],
) -> VerifiedGeneration {
    use ed25519_dalek::{Signer, SigningKey};
    use voboost_contract::release::{ArtifactRole, Manifest};

    // Seed the predecessor as a fixture; exercise the production candidate
    // materializer for the new shared catalog below.
    let mut previous_value: serde_json::Value =
        serde_json::from_slice(&catalog_bytes("china")).unwrap();
    previous_value["agents"][0]["title"]["en"] = serde_json::json!("Previous");
    let previous_bytes = canonical_catalog_bytes(&previous_value);
    let previous_catalog = AgentCatalog::parse(&previous_bytes).unwrap();
    let previous_signature = sign_with_release_key(&previous_bytes);
    let facts = VehicleProfileDocument::parse_canonical(KNOWN_FACTS.as_bytes()).unwrap();
    let selection =
        SelectionReceipt::compute(&previous_catalog, &digest(&previous_bytes), &facts.facts)
            .unwrap();
    let previous_id = generation_id(&digest(&previous_bytes), &selection.sha256).unwrap();
    let inventory = expected_inventory(
        &previous_catalog,
        &selection,
        &previous_bytes,
        &previous_signature,
    )
    .unwrap();
    let generations = store.root.join(GENERATIONS_DIR);
    fs::create_dir(&generations).unwrap();
    fs::set_permissions(&generations, fs::Permissions::from_mode(0o700)).unwrap();
    let previous_path = generations.join(&previous_id);
    fs::create_dir(&previous_path).unwrap();
    for file in inventory.values() {
        let bytes = match file.file.as_str() {
            CATALOG_FILE => previous_bytes.as_slice(),
            CATALOG_SIGNATURE_FILE => previous_signature.as_slice(),
            AGENTS_SELECTED_FILE => selection.exact_bytes.as_slice(),
            "agent-common.dex" => b"core",
            "agent-settings.dex" => b"agent",
            _ => unreachable!(),
        };
        fs::write(previous_path.join(&file.file), bytes).unwrap();
        fs::set_permissions(
            previous_path.join(&file.file),
            fs::Permissions::from_mode(GENERATION_FILE_MODE),
        )
        .unwrap();
    }
    fs::set_permissions(
        &previous_path,
        fs::Permissions::from_mode(GENERATION_DIR_MODE),
    )
    .unwrap();
    Directory::open(&generations)
        .unwrap()
        .write_atomic(
            ACTIVE_POINTER,
            format!("{previous_id}\n").as_bytes(),
            GENERATION_FILE_MODE,
        )
        .unwrap();
    let previous = store.load_generation(&previous_id).unwrap();
    let prepared = crate::plan::prepare_canonical_transition(None, &previous, &store.plan).unwrap();
    Directory::open(&store.root)
        .unwrap()
        .write_atomic("agents.json", &prepared.next_bytes, ROOT_FILE_MODE)
        .unwrap();

    let native_catalog = native_catalog_fixture(exact_catalog);
    let exact_catalog = native_catalog.as_slice();
    let signature = sign_with_release_key(exact_catalog);
    let catalog = AgentCatalog::parse(exact_catalog).unwrap();
    let mut manifest = Manifest::parse(include_bytes!(
        "../../../test/fixtures/product-release/voboost/valid/minimal.json"
    ))
    .unwrap();
    for artifact in &mut manifest.artifacts {
        let bytes = match artifact.role {
            ArtifactRole::AgentCatalog => Some(exact_catalog),
            ArtifactRole::AgentCatalogSignature => Some(signature.as_slice()),
            ArtifactRole::AgentCommon => Some(b"core".as_slice()),
            ArtifactRole::AgentModule => Some(b"agent".as_slice()),
            ArtifactRole::QnxRuntime | ArtifactRole::QnxAgentModule => {
                Some(b"fixed-product-artifact".as_slice())
            }
            _ => None,
        };
        if let Some(bytes) = bytes {
            artifact.size = bytes.len() as u64;
            artifact.sha256 = digest(bytes);
        }
    }
    assert_eq!(catalog.agents[0].targets.len(), 2);
    let manifest_bytes = manifest.canonical_bytes().unwrap();
    let manifest_signature = SigningKey::from_bytes(&[12_u8; 32])
        .sign(&manifest_bytes)
        .to_bytes();
    let complete = store.root.join("complete");
    fs::create_dir(&complete).unwrap();
    fs::set_permissions(&complete, fs::Permissions::from_mode(0o700)).unwrap();
    let complete_dir = Directory::open(&complete).unwrap();
    for (name, bytes) in [
        ("voboost.json", manifest_bytes.as_slice()),
        ("voboost.json.sig", manifest_signature.as_slice()),
        (CATALOG_FILE, exact_catalog),
        (CATALOG_SIGNATURE_FILE, signature.as_slice()),
        ("agent-common.dex", b"core".as_slice()),
        ("agent-settings.dex", b"agent".as_slice()),
        (
            "libvoboost-runtime-cluster.so",
            b"fixed-product-artifact".as_slice(),
        ),
        (
            "libagent-font-cyrillic.so",
            b"fixed-product-artifact".as_slice(),
        ),
    ] {
        complete_dir
            .write_atomic(name, bytes, ROOT_FILE_MODE)
            .unwrap();
    }
    let descriptor = operation_descriptor(Operation::Update, 'd');
    let journal = store.root.join(&descriptor.journal);
    fs::create_dir_all(journal.parent().unwrap()).unwrap();
    for directory in [
        store.root.join("recovery"),
        journal.parent().unwrap().to_path_buf(),
    ] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    Directory::open(journal.parent().unwrap())
        .unwrap()
        .write_atomic("update-journal.json", b"{}\n", ROOT_FILE_MODE)
        .unwrap();
    let lease = OperationLease::acquire_in(&store.root, descriptor).unwrap();
    store
        .prepare_product_candidate(
            &complete,
            &Directory::open(journal.parent().unwrap()).unwrap(),
            &lease,
        )
        .unwrap()
}

#[test]
fn shared_agent_module_is_materialized_once_and_bootstrapped_for_each_process() {
    let zones = zones();
    let mut value: serde_json::Value = serde_json::from_slice(&catalog_bytes("china")).unwrap();
    let process = "com.example.shared";
    let mut alias = value["agents"][0]["targets"][0].clone();
    alias["process"] = serde_json::json!(process);
    value["agents"][0]["targets"]
        .as_array_mut()
        .unwrap()
        .push(alias);
    let catalog = canonical_catalog_bytes(&value);
    stage(
        &zones.store.incoming,
        &catalog,
        &[
            ("agent-common.dex", b"core"),
            ("agent-settings.dex", b"agent"),
        ],
    );
    let generation = materialize_shared_product_generation(&zones.store, &catalog);
    assert_eq!(generation.files.len(), 7);
    assert_eq!(fs::read_dir(&generation.directory).unwrap().count(), 7);
    assert_eq!(
        generation
            .files
            .iter()
            .filter(|file| file.file == "agent-settings.dex")
            .count(),
        1
    );
    let plan = crate::plan::Plan::defaults_for(&generation);
    for process in ["com.qinggan.app.setting", process] {
        let bytes =
            crate::runtime::test_support::bootstrap_bytes(&plan, &generation, process).unwrap();
        assert_eq!(&bytes[..8], crate::bootstrap_pipe::MAGIC);
        let manifest_len = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        assert_eq!(u32::from_le_bytes(bytes[12..16].try_into().unwrap()), 2);
        let manifest: serde_json::Value =
            serde_json::from_slice(&bytes[24..24 + manifest_len]).unwrap();
        assert_eq!(manifest["modules"][0]["id"], "settings");
        assert_eq!(
            manifest["modules"][0]["entryClass"],
            "ru.voboost.agents.settings.SettingsAgent"
        );
        assert_eq!(manifest["modules"][0]["fileIndex"], 1);
        let mut cursor = 24 + manifest_len;
        for (name, expected) in [
            ("agents.dex", b"core".as_slice()),
            ("agent-settings.dex", b"agent".as_slice()),
        ] {
            let length = u16::from_le_bytes(bytes[cursor..cursor + 2].try_into().unwrap()) as usize;
            cursor += 2;
            assert_eq!(&bytes[cursor..cursor + length], name.as_bytes());
            cursor += length;
            let size = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
            cursor += 8;
            assert_eq!(&bytes[cursor..cursor + size], expected);
            cursor += size;
        }
        assert_eq!(cursor, bytes.len());
    }
    let retained = zones.store.load_generation(&generation.id).unwrap();
    assert_eq!(retained.catalog.agents[0].targets.len(), 2);
    assert_eq!(retained.files.len(), 7);
    // Immutable production modes are intentionally non-writable; release only
    // these owned fixture directories so TempDir can remove every test member.
    let generations = zones.store.root.join(GENERATIONS_DIR);
    fs::set_permissions(&generations, fs::Permissions::from_mode(0o700)).unwrap();
    for entry in fs::read_dir(&generations).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
}

#[test]
fn product_generation_correlates_unique_modules_and_rejects_duplicate_artifacts() {
    use voboost_contract::release::{ArtifactRole, Manifest};
    let mut catalog = AgentCatalog::parse(&catalog_bytes("china")).unwrap();
    let mut alias = catalog.agents[0].targets[0].clone();
    alias.process = "com.example.shared".into();
    catalog.agents[0].targets.push(alias);
    let mut manifest = Manifest::parse(include_bytes!(
        "../../../test/fixtures/product-release/voboost/valid/minimal.json"
    ))
    .unwrap();
    for artifact in &mut manifest.artifacts {
        match artifact.role {
            ArtifactRole::AgentCommon => {
                artifact.size = catalog.core.size;
                artifact.sha256 = catalog.core.sha256.clone();
            }
            ArtifactRole::AgentModule => {
                artifact.size = catalog.agents[0].targets[0].size;
                artifact.sha256 = catalog.agents[0].targets[0].sha256.clone();
            }
            _ => {}
        }
    }
    let bytes = native_catalog_fixture(&serde_json::to_vec(&catalog).unwrap());
    catalog = serde_json::from_slice(&bytes).unwrap();
    for artifact in &mut manifest.artifacts {
        if matches!(
            artifact.role,
            ArtifactRole::QnxRuntime | ArtifactRole::QnxAgentModule
        ) {
            artifact.size = b"fixed-product-artifact".len() as u64;
            artifact.sha256 = digest(b"fixed-product-artifact");
        }
    }
    correlate_product_generation(&manifest, &catalog).unwrap();
    let module = manifest
        .artifacts
        .iter()
        .find(|file| file.role == ArtifactRole::AgentModule)
        .unwrap()
        .clone();
    let mut duplicate = manifest.clone();
    duplicate.artifacts.push(module);
    assert!(correlate_product_generation(&duplicate, &catalog).is_err());
    let mut mismatched = manifest.clone();
    mismatched
        .artifacts
        .iter_mut()
        .find(|file| file.role == ArtifactRole::AgentModule)
        .unwrap()
        .size += 1;
    assert!(correlate_product_generation(&mismatched, &catalog).is_err());
    let mut files = BTreeMap::new();
    let reserved = GenerationFile {
        file: CATALOG_FILE.into(),
        size: 1,
        sha256: digest(b"x"),
    };
    insert_expected(&mut files, reserved.clone()).unwrap();
    assert!(insert_expected(&mut files, reserved).is_err());
}

#[test]
fn every_activation_crash_window_recovers_exact_pointer_plan_and_ack() {
    let crash_points = [
        ActivationCrashPoint::Prepared,
        ActivationCrashPoint::PointerSwitched,
        ActivationCrashPoint::Activated,
        ActivationCrashPoint::PlanPublished,
        ActivationCrashPoint::PlanJournaled,
        ActivationCrashPoint::Verified,
        ActivationCrashPoint::Accepted,
        ActivationCrashPoint::Acknowledged,
        ActivationCrashPoint::ReadyRemoved,
        ActivationCrashPoint::ClaimOwned,
        ActivationCrashPoint::ClaimOwnerChangedBeforeJournal,
        ActivationCrashPoint::ClaimCatalog,
        ActivationCrashPoint::ClaimSelection,
        ActivationCrashPoint::ClaimAcknowledged,
        ActivationCrashPoint::ClaimReadyRemoved,
        ActivationCrashPoint::ClaimSnapshotsRemoved,
        ActivationCrashPoint::ClaimOwnerRestored,
        ActivationCrashPoint::ClaimOwnerRestoredBeforeJournal,
    ];
    for crash_point in crash_points {
        let zones = test_support::zones();
        test_support::stage_variant(&zones.store, 1);
        let first = install_staged_generation_without_pointer(&zones.store);
        let previous = zones.store.commit_activation(None, first, None).unwrap();
        let previous_plan = fs::read(&zones.store.plan).unwrap();
        test_support::stage_variant(&zones.store, 2);
        let next = install_staged_generation_without_pointer(&zones.store);

        let error = zones
            .store
            .commit_activation(Some(&previous), next, Some(crash_point))
            .unwrap_err();
        assert!(error.to_string().contains("simulated crash"));
        assert!(
            zones
                .store
                .root
                .join(GENERATIONS_DIR)
                .join(ACTIVATION_JOURNAL_FILE)
                .exists(),
            "journal missing at {crash_point:?}"
        );
        assert!(
            zones.store.freeze_for_uninstall().is_err(),
            "uninstall freeze must wait for claim recovery at {crash_point:?}"
        );

        let recovered = zones.store.recover_activation().unwrap().unwrap();
        assert_ne!(recovered.id, previous.id, "pointer did not advance");
        assert_eq!(zones.store.active().unwrap().id, recovered.id);
        let canonical = fs::read(&zones.store.plan).unwrap();
        assert_eq!(
            crate::plan::canonical_identity(&previous_plan),
            crate::plan::canonical_identity(&fs::read(&zones.store.plan).unwrap()),
            "semantically unchanged intent must retain an exact stable identity"
        );
        assert!(crate::plan::validate(&recovered, &canonical).valid);
        let acknowledgement: serde_json::Value = serde_json::from_slice(
            &fs::read(zones.store.incoming.join(ACKNOWLEDGEMENT_FILE)).unwrap(),
        )
        .unwrap();
        assert_eq!(acknowledgement["status"], "accepted");
        assert_eq!(acknowledgement["schemaVersion"], 1);
        assert_eq!(
            acknowledgement["selectionSha256"],
            recovered.selection_sha256
        );
        assert_eq!(acknowledgement["generationId"], recovered.id);
        assert!(!zones.store.incoming_marker().exists());
        for transaction_file in [
            ACTIVATION_JOURNAL_FILE,
            ACTIVATION_NEXT_PLAN_FILE,
            ACTIVATION_PREVIOUS_PLAN_FILE,
        ] {
            assert!(!zones
                .store
                .root
                .join(GENERATIONS_DIR)
                .join(transaction_file)
                .exists());
        }
    }
}

#[test]
fn corrupted_prepared_plan_rolls_back_exact_previous_generation_and_plan() {
    let zones = test_support::zones();
    test_support::stage_variant(&zones.store, 1);
    let first = install_staged_generation_without_pointer(&zones.store);
    let previous = zones.store.commit_activation(None, first, None).unwrap();
    let previous_plan = fs::read(&zones.store.plan).unwrap();
    test_support::stage_variant(&zones.store, 2);
    let next = install_staged_generation_without_pointer(&zones.store);
    let next_selection_sha256 = next.selection_sha256.clone();
    zones
        .store
        .commit_activation(Some(&previous), next, Some(ActivationCrashPoint::Prepared))
        .unwrap_err();
    fs::write(
        zones
            .store
            .root
            .join(GENERATIONS_DIR)
            .join(ACTIVATION_NEXT_PLAN_FILE),
        b"corrupted",
    )
    .unwrap();

    assert!(zones.store.recover_activation().unwrap().is_none());
    assert_eq!(zones.store.active().unwrap().id, previous.id);
    assert_eq!(fs::read(&zones.store.plan).unwrap(), previous_plan);
    let acknowledgement: serde_json::Value =
        serde_json::from_slice(&fs::read(zones.store.incoming.join(ACKNOWLEDGEMENT_FILE)).unwrap())
            .unwrap();
    assert_eq!(acknowledgement["status"], "rejected");
    assert_eq!(acknowledgement["schemaVersion"], 1);
    assert_eq!(acknowledgement["selectionSha256"], next_selection_sha256);
    assert!(acknowledgement.get("generationId").is_none());
    assert!(!zones
        .store
        .root
        .join(GENERATIONS_DIR)
        .join(ACTIVATION_JOURNAL_FILE)
        .exists());
}

#[test]
fn activation_recovery_never_overwrites_a_later_checkbox_off() {
    let zones = test_support::zones();
    test_support::stage_variant(&zones.store, 1);
    let first = install_staged_generation_without_pointer(&zones.store);
    let previous = zones.store.commit_activation(None, first, None).unwrap();
    test_support::stage_variant(&zones.store, 2);
    let next = install_staged_generation_without_pointer(&zones.store);
    zones
        .store
        .commit_activation(Some(&previous), next, Some(ActivationCrashPoint::Prepared))
        .unwrap_err();
    let mut changed =
        voboost_contract::desired::Config::decode(&fs::read(&zones.store.plan).unwrap()).unwrap();
    let boot = "11111111-1111-4111-8111-111111111111";
    changed
        .save(
            boot,
            &voboost_contract::desired::Field::Enabled {
                agent: "vehicle-drive-forced-ev".into(),
            },
            &false.into(),
            &voboost_contract::desired::Input {
                boot_id: boot.into(),
                endpoint_epoch: 1,
                request_id: 9,
                injector_pid: 42,
                injector_starttime: 100,
            },
            &[],
        )
        .unwrap();
    let off = serde_json::to_vec(&changed).unwrap();
    crate::secure_fs::write_atomic_private(&zones.store.plan, &off, ROOT_FILE_MODE).unwrap();

    zones.store.recover_activation().unwrap();
    assert_eq!(fs::read(&zones.store.plan).unwrap(), off);
}

#[test]
fn activation_journal_rejects_path_fields() {
    let zones = test_support::zones();
    zones.store.ensure_layout().unwrap();
    crate::secure_fs::write_atomic_private(
        &zones
            .store
            .root
            .join(GENERATIONS_DIR)
            .join(ACTIVATION_JOURNAL_FILE),
        br#"{"schemaVersion":1,"state":"prepared","previousGeneration":null,"nextGeneration":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","catalogSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","previousPlanSha256":null,"nextPlanSha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","planPath":"/data/local/tmp/hostile"}"#,
        ROOT_FILE_MODE,
    )
    .unwrap();
    assert!(zones.store.recover_activation().is_err());
}

#[test]
fn reject_incoming_quarantines_payload_and_reason() {
    let zones = zones();
    stage(
        &zones.store.incoming,
        &catalog_bytes("china"),
        &[("agent-common.dex", b"core")],
    );
    // Simulate a validation failure (missing selected DEX).
    let error = zones.store.activate_incoming().unwrap_err().to_string();
    let target = zones.store.reject_incoming(&error).unwrap();
    assert!(target.path.join(CATALOG_FILE).exists());
    assert!(target.path.join(READY_MARKER).exists());
    let frozen = target.identity.as_ref().unwrap();
    assert_eq!(
        frozen.0,
        digest(&fs::read(target.path.join(REJECTED_CATALOG_SNAPSHOT)).unwrap())
    );
    assert_eq!(
        frozen.1.as_deref(),
        Some(digest(&fs::read(target.path.join(REJECTED_SELECTION_SNAPSHOT)).unwrap()).as_str())
    );
    let reason = fs::read_to_string(target.path.join(REJECTION_REASON_FILE)).unwrap();
    assert!(!reason.trim().is_empty());
    // The staging area is drained and recreated empty.
    assert!(!zones.store.incoming.join(READY_MARKER).exists());
    assert_eq!(fs::read_dir(&zones.store.incoming).unwrap().count(), 1);
}

#[test]
fn rejection_identity_downgrades_between_read_catalog_mismatch_to_catalog_only() {
    let zones = zones();
    stage(
        &zones.store.incoming,
        &catalog_bytes("china"),
        &[("agent-common.dex", b"core")],
    );
    let before = zones.store.incoming_generation_identity().unwrap();
    let directory = Directory::open(&zones.store.incoming).unwrap();
    let owner = directory.owner().unwrap();
    let replacement = br#"{"schemaVersion":0,"catalogSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","facts":{"chip":{"value":"8155"},"vehicle":{"value":"free"},"android":{"value":9},"powertrain":{"value":"hybrid"},"market":{"value":"china"}},"agents":[]}"#;
    let identity = snapshot_rejected_identity_with(&directory, owner, || {
        fs::write(zones.store.incoming.join(AGENTS_SELECTED_FILE), replacement).unwrap();
    })
    .unwrap();
    assert!(identity.1.is_none());
    assert!(!zones
        .store
        .incoming
        .join(REJECTED_SELECTION_SNAPSHOT)
        .exists());
    assert_ne!(identity, (before.0, Some(before.1)));
}

#[test]
fn rejection_cleanup_preserves_tree_when_node_bound_is_exceeded() {
    let root = tempfile::tempdir().unwrap();
    let tree = root.path().join("rejected-hostile");
    fs::create_dir(&tree).unwrap();
    for index in 0..=MAX_REJECTION_CLEANUP_NODES {
        fs::write(tree.join(format!("node-{index}")), b"x").unwrap();
    }
    assert!(remove_tree_bounded_nofollow(&tree).is_err());
    assert!(tree.is_dir());
    assert!(tree.join("node-0").exists());
}

#[test]
fn rejection_history_scan_is_bounded_and_preserves_diagnostics() {
    let root = tempfile::tempdir().unwrap();
    let history = root.path().join("quarantine");
    fs::create_dir(&history).unwrap();
    for index in 0..3 {
        fs::create_dir(history.join(format!("rejected-{index}"))).unwrap();
    }
    let directory = Directory::open(&history).unwrap();
    assert!(rejected_history_names_bounded(&directory, 2).is_err());
    for index in 0..3 {
        assert!(history.join(format!("rejected-{index}")).is_dir());
    }
}

#[test]
fn rejection_history_coexists_with_crash_left_retired_generation() {
    let root = tempfile::tempdir().unwrap();
    let history = root.path().join("quarantine");
    fs::create_dir(&history).unwrap();
    fs::create_dir(history.join("rejected-7")).unwrap();
    fs::create_dir(history.join(format!("retired-{}", "a".repeat(64)))).unwrap();
    let directory = Directory::open(&history).unwrap();
    assert_eq!(
        rejected_history_names_bounded(&directory, 2).unwrap(),
        vec!["rejected-7"]
    );
    assert!(history.join(format!("retired-{}", "a".repeat(64))).is_dir());
}

#[test]
fn retained_rejection_cleanup_unlinks_intermediate_symlink_without_touching_outside() {
    let root = tempfile::tempdir().unwrap();
    let outside = root.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("sentinel"), b"safe").unwrap();
    let tree = root.path().join("rejected-tree");
    fs::create_dir(&tree).unwrap();
    symlink(&outside, tree.join("nested-link")).unwrap();
    remove_tree_bounded_nofollow(&tree).unwrap();
    assert!(!tree.exists());
    assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"safe");
}

#[test]
fn retained_rejection_cleanup_inspects_fifo_metadata_without_opening_it() {
    let root = tempfile::tempdir().unwrap();
    let outside = root.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("sentinel"), b"safe").unwrap();
    let tree = root.path().join("rejected-tree");
    fs::create_dir(&tree).unwrap();
    let fifo = tree.join("hostile-fifo");
    let fifo_c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);

    let directory = Directory::open(&tree).unwrap();
    assert!(!directory.entry_info_nofollow("hostile-fifo").unwrap().0);
    remove_tree_bounded_nofollow(&tree).unwrap();

    assert!(!tree.exists());
    assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"safe");
}

#[test]
fn bounded_abort_freezes_every_visited_nested_directory_before_preserving_tree() {
    let root = tempfile::tempdir().unwrap();
    let tree = root.path().join("rejected-tree");
    let nested = tree.join("a").join("b");
    fs::create_dir_all(&nested).unwrap();
    fs::set_permissions(tree.join("a"), fs::Permissions::from_mode(0o777)).unwrap();
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o777)).unwrap();
    for index in 0..=MAX_REJECTION_CLEANUP_NODES {
        fs::write(nested.join(format!("node-{index}")), b"x").unwrap();
    }
    assert!(remove_tree_bounded_nofollow(&tree).is_err());
    for directory in [tree.join("a"), nested] {
        let metadata = fs::symlink_metadata(directory).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        assert_eq!(
            (metadata.uid(), metadata.gid()),
            (current_uid(), current_gid())
        );
    }
}

#[test]
fn production_rejection_owner_validation_rejects_root_group_and_daemon() {
    assert!(validate_rejection_owner_production((0, 123), (999, 999)).is_err());
    assert!(validate_rejection_owner_production((123, 0), (999, 999)).is_err());
    assert!(validate_rejection_owner_production((123, 456), (123, 456)).is_err());
    assert!(validate_rejection_owner_production((123, 456), (999, 999)).is_ok());
}

#[test]
fn rejection_recovery_reconciles_rename_next_creation_ack_and_archive_cuts() {
    let zones = zones();
    stage(
        &zones.store.incoming,
        &catalog_bytes("china"),
        &[("agent-common.dex", b"core")],
    );
    let owner = Directory::open(&zones.store.incoming)
        .unwrap()
        .owner()
        .unwrap();
    let generations = zones.store.root.join(GENERATIONS_DIR);
    let rejecting = generations.join(REJECTING_DIR);
    zones.store.ensure_layout().unwrap();
    let base = RejectionJournal {
        schema_version: 1,
        phase: RejectionPhase::Prepared,
        uid: owner.0,
        gid: owner.1,
        reason: "cut".into(),
        archive_name: "rejected-123".into(),
        catalog_sha256: None,
        selection_sha256: None,
    };
    zones.store.write_rejection_journal(&base).unwrap();
    fs::rename(&zones.store.incoming, &rejecting).unwrap();
    Directory::open(&generations).unwrap().sync_all().unwrap();
    let recovered = zones.store.recover_rejection().unwrap().unwrap();
    assert_eq!(recovered.path.file_name().unwrap(), "rejected-123");
    assert!(zones.store.incoming.join(ACKNOWLEDGEMENT_FILE).exists());
    assert!(zones.store.load_rejection_journal().unwrap().is_none());

    let cut = self::zones();
    cut.store.ensure_layout().unwrap();
    let generations = cut.store.root.join(GENERATIONS_DIR);
    let archive_root = generations.join(QUARANTINE_DIR);
    ensure_directory(&archive_root, 0o700).unwrap();
    fs::create_dir(archive_root.join("rejected-456")).unwrap();
    cut.store
        .write_rejection_journal(&RejectionJournal {
            schema_version: 1,
            phase: RejectionPhase::Acked,
            uid: current_uid(),
            gid: current_gid(),
            reason: "cut".into(),
            archive_name: "rejected-456".into(),
            catalog_sha256: None,
            selection_sha256: None,
        })
        .unwrap();
    assert!(cut.store.recover_rejection().unwrap().is_some());
    assert!(cut.store.load_rejection_journal().unwrap().is_none());

    if unsafe { libc::geteuid() } == 0 {
        let raced = self::zones();
        raced.store.ensure_layout().unwrap();
        let generations = raced.store.root.join(GENERATIONS_DIR);
        let archive_root = generations.join(QUARANTINE_DIR);
        ensure_directory(&archive_root, 0o700).unwrap();
        fs::create_dir(archive_root.join("rejected-789")).unwrap();
        let next = Directory::open(&raced.store.incoming).unwrap();
        next.set_owner(12345, 12345).unwrap();
        fs::write(raced.store.incoming.join("new-offer"), b"new").unwrap();
        fs::write(raced.store.incoming.join(".generation-ack.tmp"), b"hostile").unwrap();
        raced
            .store
            .write_rejection_journal(&RejectionJournal {
                schema_version: 1,
                phase: RejectionPhase::Acked,
                uid: 12345,
                gid: 12345,
                reason: "cut".into(),
                archive_name: "rejected-789".into(),
                catalog_sha256: None,
                selection_sha256: None,
            })
            .unwrap();
        assert!(raced.store.recover_rejection().unwrap().is_some());
        assert_eq!(
            fs::read(raced.store.incoming.join("new-offer")).unwrap(),
            b"new"
        );
        assert_eq!(
            fs::read(raced.store.incoming.join(".generation-ack.tmp")).unwrap(),
            b"hostile"
        );
    }
}

#[test]
fn reject_incoming_without_staging_records_reason_only() {
    let zones = zones();
    let target = zones.store.reject_incoming("nothing staged").unwrap();
    assert!(target.path.join(REJECTION_REASON_FILE).exists());
    assert!(zones.store.incoming.is_dir());
}

#[test]
fn reject_incoming_does_not_follow_staged_absolute_reason_symlink() {
    let zones = zones();
    let outside = zones._root.path().join("outside-symlink.txt");
    fs::write(&outside, b"unchanged\n").unwrap();
    symlink(&outside, zones.store.incoming.join(REJECTION_REASON_FILE)).unwrap();

    let target = zones.store.reject_incoming("rejected").unwrap();

    assert_eq!(fs::read(&outside).unwrap(), b"unchanged\n");
    assert_eq!(
        fs::read(target.path.join(REJECTION_REASON_FILE)).unwrap(),
        b"rejected\n"
    );
}

#[test]
fn reject_incoming_does_not_reuse_staged_reason_hardlink() {
    let zones = zones();
    let outside = zones._root.path().join("outside-hardlink.txt");
    fs::write(&outside, b"unchanged\n").unwrap();
    fs::hard_link(&outside, zones.store.incoming.join(REJECTION_REASON_FILE)).unwrap();

    let target = zones.store.reject_incoming("rejected").unwrap();

    assert_eq!(fs::read(&outside).unwrap(), b"unchanged\n");
    assert_eq!(
        fs::read(target.path.join(REJECTION_REASON_FILE)).unwrap(),
        b"rejected\n"
    );
}

#[test]
fn activation_verifies_and_installs_the_exact_selection_receipt() {
    // Import writes into a 0711 generations directory, which requires
    // root's DAC override; skip on non-root hosts.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipped: needs root");
        return;
    }
    let zones = zones();
    stage(
        &zones.store.incoming,
        &catalog_bytes("china"),
        &[
            ("agent-common.dex", b"core"),
            ("agent-settings.dex", b"agent"),
        ],
    );
    let generation = zones.store.activate_incoming().unwrap();
    // The verified app-authored receipt is imported byte-for-byte.
    let expected = SelectionReceipt::compute(
        &generation.catalog,
        &generation.catalog_sha256,
        &generation.selection.receipt.facts,
    )
    .unwrap();
    assert_eq!(generation.selection.exact_bytes, expected.exact_bytes);
    assert!(generation.directory.join(AGENTS_SELECTED_FILE).exists());
    assert_eq!(zones.store.active().unwrap().id, generation.id);
    // The incoming staging area is drained of its marker.
    assert!(!zones.store.incoming.join(READY_MARKER).exists());
}

#[test]
fn disable_all_blocks_a_staged_generation_without_consuming_it() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipped: needs root");
        return;
    }
    let zones = zones();
    stage(
        &zones.store.incoming,
        &catalog_bytes_with_version("1.0.1"),
        &[
            ("agent-common.dex", b"core"),
            ("agent-settings.dex", b"agent"),
        ],
    );
    zones.store.activate_incoming().unwrap();
    let plan_path = zones.store.root.join("agents.json");
    let enabled_plan = fs::read_to_string(&plan_path).unwrap();
    let disabled_plan = enabled_plan.replace("\"startup\":\"interface\"", "\"startup\":\"none\"");
    assert_ne!(enabled_plan, disabled_plan);
    fs::write(&plan_path, disabled_plan).unwrap();
    stage(
        &zones.store.incoming,
        &catalog_bytes_with_version("1.0.2"),
        &[
            ("agent-common.dex", b"core"),
            ("agent-settings.dex", b"agent"),
        ],
    );

    assert!(zones.store.activate_incoming().is_err());
    assert!(zones.store.incoming.join(READY_MARKER).exists());

    fs::write(&plan_path, enabled_plan).unwrap();
    let activated = zones.store.activate_incoming().unwrap();
    assert_eq!(
        activated.catalog.agents[0].title.as_ref().unwrap().en,
        "1.0.2"
    );
}

#[test]
fn same_catalog_new_root_selection_activates_and_retains_prior_generation() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipped: needs root");
        return;
    }
    let zones = zones();
    let catalog = catalog_bytes("china");
    stage(
        &zones.store.incoming,
        &catalog,
        &[
            ("agent-common.dex", b"core"),
            ("agent-settings.dex", b"agent"),
        ],
    );
    let first = zones.store.activate_incoming().unwrap();
    replace_root_facts(&zones.store, GLOBAL_FACTS);
    stage_with_facts(
        &zones.store.incoming,
        &catalog,
        &[("agent-common.dex", b"core")],
        GLOBAL_FACTS,
    );
    let second = zones.store.activate_incoming().unwrap();
    assert_eq!(first.catalog_sha256, second.catalog_sha256);
    assert_ne!(first.selection_sha256, second.selection_sha256);
    assert_ne!(first.id, second.id);
    assert_eq!(zones.store.load_generation(&first.id).unwrap().id, first.id);
}

#[test]
fn recovery_does_not_consume_replaced_same_catalog_different_selection() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipped: needs root");
        return;
    }
    let zones = zones();
    let catalog = catalog_bytes("china");
    stage(
        &zones.store.incoming,
        &catalog,
        &[
            ("agent-common.dex", b"core"),
            ("agent-settings.dex", b"agent"),
        ],
    );
    zones
        .store
        .activate_incoming_impl(Some(ActivationCrashPoint::Accepted))
        .unwrap_err();
    replace_root_facts(&zones.store, GLOBAL_FACTS);
    stage_with_facts(
        &zones.store.incoming,
        &catalog,
        &[("agent-common.dex", b"core")],
        GLOBAL_FACTS,
    );
    let offered = zones.store.incoming_generation_identity().unwrap();
    let offered_files = fs::read_dir(&zones.store.incoming)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            (
                path.file_name().unwrap().to_os_string(),
                fs::read(&path).unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let recovered = zones.store.recover_activation().unwrap().unwrap();
    assert_ne!(offered.1, recovered.selection_sha256);
    assert!(zones.store.incoming.join(READY_MARKER).exists());
    assert!(!zones.store.incoming.join(ACKNOWLEDGEMENT_FILE).exists());
    assert_eq!(zones.store.incoming_generation_identity().unwrap(), offered);
    let after = fs::read_dir(&zones.store.incoming)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            (
                path.file_name().unwrap().to_os_string(),
                fs::read(&path).unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(after, offered_files);
}

#[test]
fn frozen_pair_snapshots_survive_mutation_through_preopened_app_fds() {
    use std::io::{Seek, SeekFrom};

    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipped: needs root");
        return;
    }
    for crash_point in [
        ActivationCrashPoint::ClaimSelection,
        ActivationCrashPoint::ClaimAcknowledged,
        ActivationCrashPoint::ClaimReadyRemoved,
        ActivationCrashPoint::ClaimSnapshotsRemoved,
        ActivationCrashPoint::ClaimOwnerRestored,
        ActivationCrashPoint::ClaimOwnerRestoredBeforeJournal,
    ] {
        let zones = zones();
        stage(
            &zones.store.incoming,
            &catalog_bytes("china"),
            &[
                ("agent-common.dex", b"core"),
                ("agent-settings.dex", b"agent"),
            ],
        );
        let mut catalog_fd = fs::OpenOptions::new()
            .write(true)
            .open(zones.store.incoming.join(CATALOG_FILE))
            .unwrap();
        let mut selection_fd = fs::OpenOptions::new()
            .write(true)
            .open(zones.store.incoming.join(AGENTS_SELECTED_FILE))
            .unwrap();
        zones
            .store
            .activate_incoming_impl(Some(crash_point))
            .unwrap_err();
        catalog_fd.seek(SeekFrom::Start(0)).unwrap();
        catalog_fd.write_all(b"!").unwrap();
        selection_fd.seek(SeekFrom::Start(0)).unwrap();
        selection_fd.write_all(b"!").unwrap();
        let recovered = zones.store.recover_activation().unwrap().unwrap();
        let ack: serde_json::Value = serde_json::from_slice(
            &fs::read(zones.store.incoming.join(ACKNOWLEDGEMENT_FILE)).unwrap(),
        )
        .unwrap();
        assert_eq!(ack["selectionSha256"], recovered.selection_sha256);
        assert!(!zones.store.incoming.join(READY_MARKER).exists());
        assert!(!zones.store.incoming.join(".claim-catalog").exists());
        assert!(!zones.store.incoming.join(".claim-selection").exists());
    }
}

#[test]
fn staging_owner_must_be_unprivileged_and_distinct_from_daemon() {
    assert!(validate_staging_owner((0, current_gid())).is_err());
    assert!(validate_staging_owner((current_uid(), 0)).is_err());
    assert!(validate_staging_owner((current_uid(), current_gid())).is_err());
    let app_uid = current_uid().checked_add(1).unwrap();
    // The representative app identity needs a non-root gid too: under a
    // root-owned test process (su 0 on an Android target) current_gid() is 0,
    // which the validator must reject. Add one so the fixture models a real
    // unprivileged (uid, gid) pair on every host.
    let app_gid = current_gid().checked_add(1).unwrap();
    assert!(validate_staging_owner((app_uid, app_gid)).is_ok());
}

#[test]
fn handback_recovery_preserves_complete_new_offer_and_allows_activation() {
    let zones = zones();
    let old = prepare_owner_restored_before_journal(&zones.store);

    let replacement_catalog = catalog_bytes_with_version("1.0.1");
    stage(
        &zones.store.incoming,
        &replacement_catalog,
        &[
            ("agent-common.dex", b"core"),
            ("agent-settings.dex", b"agent"),
        ],
    );
    let owner = Directory::open(&zones.store.incoming)
        .unwrap()
        .owner()
        .unwrap();
    let replacement = staged_bytes(&zones.store.incoming);

    let recovered = zones.store.recover_activation().unwrap().unwrap();
    assert_eq!(recovered.id, old.id);
    assert_eq!(
        Directory::open(&zones.store.incoming)
            .unwrap()
            .owner()
            .unwrap(),
        owner
    );
    assert_eq!(staged_bytes(&zones.store.incoming), replacement);
    assert!(zones.store.incoming.join(READY_MARKER).exists());
    assert!(!zones.store.incoming.join(ACKNOWLEDGEMENT_FILE).exists());

    let activation = zones
        .store
        .activate_incoming_impl(Some(ActivationCrashPoint::Accepted))
        .unwrap_err();
    if unsafe { libc::geteuid() } == 0 {
        assert!(
            activation.to_string().contains("simulated crash"),
            "{activation:#}"
        );
        let activated = zones.store.active().unwrap();
        assert_ne!(activated.id, recovered.id);
        assert_eq!(
            activated.catalog.agents[0].title.as_ref().unwrap().en,
            "1.0.1"
        );
    } else {
        assert!(activation.to_string().contains("Permission denied"));
    }
}

#[test]
fn handback_recovery_treats_app_claim_names_as_hostile_new_inventory() {
    let zones = zones();
    prepare_owner_restored_before_journal(&zones.store);

    let replacement_catalog = catalog_bytes_with_version("1.0.1");
    stage(
        &zones.store.incoming,
        &replacement_catalog,
        &[
            ("agent-common.dex", b"core"),
            ("agent-settings.dex", b"agent"),
        ],
    );
    fs::write(zones.store.incoming.join(".claim-catalog"), b"hostile").unwrap();
    let replacement = staged_bytes(&zones.store.incoming);

    zones.store.recover_activation().unwrap().unwrap();
    assert_eq!(staged_bytes(&zones.store.incoming), replacement);
    assert_eq!(
        fs::read(zones.store.incoming.join(".claim-catalog")).unwrap(),
        b"hostile"
    );
    let error = zones.store.activate_incoming().unwrap_err().to_string();
    assert!(
        error.contains("inventory") || error.contains("basename"),
        "unexpected error: {error}"
    );
    assert_eq!(
        fs::read(zones.store.incoming.join(".claim-catalog")).unwrap(),
        b"hostile"
    );
}

#[test]
fn missing_selected_dex_is_rejected() {
    let zones = zones();
    // settings is supported for these facts but its DEX is not staged.
    stage(
        &zones.store.incoming,
        &catalog_bytes("china"),
        &[("agent-common.dex", b"core")],
    );
    let error = zones.store.activate_incoming().unwrap_err().to_string();
    assert!(
        error.contains("inventory") || error.contains("agent-settings.dex"),
        "unexpected error: {error}"
    );
}

#[test]
fn unsupported_module_is_retained_but_never_selected_for_injection() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipped: needs root");
        return;
    }
    let zones = zones();
    // Catalog market=global does not match the root China profile. The signed
    // DEX remains in the immutable release closure but is not selected.
    stage(
        &zones.store.incoming,
        &catalog_bytes("global"),
        &[
            ("agent-common.dex", b"core"),
            ("agent-settings.dex", b"agent"),
        ],
    );
    let generation = zones.store.activate_incoming().unwrap();
    assert!(generation.selection.selected_agent_ids.is_empty());
    assert!(generation.directory.join("agent-settings.dex").exists());
    assert!(generation.installed_agent_ids().is_empty());
}

#[test]
fn later_applicability_selection_reuses_the_same_complete_signed_dex_closure() {
    let catalog_bytes = catalog_bytes("china");
    let signature = sign_with_release_key(&catalog_bytes);
    let catalog = AgentCatalog::parse_verified(&catalog_bytes, &signature).unwrap();
    let catalog_sha256 = AgentCatalog::digest(&catalog_bytes);
    let matching = VehicleProfileDocument::parse_canonical(KNOWN_FACTS.as_bytes()).unwrap();
    let unmatched = VehicleProfileDocument::parse_canonical(GLOBAL_FACTS.as_bytes()).unwrap();
    let selected = SelectionReceipt::compute(&catalog, &catalog_sha256, &matching.facts).unwrap();
    let unselected =
        SelectionReceipt::compute(&catalog, &catalog_sha256, &unmatched.facts).unwrap();
    assert_ne!(selected.selected_agent_ids, unselected.selected_agent_ids);
    let selected_files =
        expected_inventory(&catalog, &selected, &catalog_bytes, &signature).unwrap();
    let unselected_files =
        expected_inventory(&catalog, &unselected, &catalog_bytes, &signature).unwrap();
    for file in ["agent-common.dex", "agent-settings.dex"] {
        assert_eq!(selected_files.get(file), unselected_files.get(file));
    }
}

#[test]
fn required_artifact_closure_accepts_exact_and_rejects_missing_or_extra() {
    let catalog = catalog_bytes_with_required_artifact();
    for (case, artifacts, expected_ok) in [
        (
            "exact",
            vec![("voboost-ui-settings-abi-01.apk", &b"ui"[..])],
            true,
        ),
        ("missing", vec![], false),
        (
            "extra",
            vec![("voboost-ui-settings-abi-02.apk", &b"ui"[..])],
            false,
        ),
    ] {
        let zones = zones();
        let mut files = vec![
            ("agent-common.dex", &b"core"[..]),
            ("agent-settings.dex", &b"agent"[..]),
        ];
        files.extend(artifacts);
        stage(&zones.store.incoming, &catalog, &files);
        if expected_ok && unsafe { libc::geteuid() } == 0 {
            let generation = zones.store.activate_incoming().unwrap();
            assert!(generation
                .directory
                .join("voboost-ui-settings-abi-01.apk")
                .exists());
        } else if !expected_ok {
            let error = zones.store.activate_incoming().unwrap_err().to_string();
            assert!(error.contains("inventory"), "{case}: {error}");
            assert!(zones.store.active_id().is_none());
        }
    }
}

#[test]
fn activation_rejects_selected_payload_hash_mismatch_at_signed_size() {
    let zones = zones();
    stage(
        &zones.store.incoming,
        &catalog_bytes("china"),
        &[
            ("agent-common.dex", b"core"),
            ("agent-settings.dex", b"wrong"),
        ],
    );
    let error = zones.store.activate_incoming().unwrap_err().to_string();
    assert!(error.contains("hash mismatch"), "unexpected error: {error}");
    assert!(zones.store.active_id().is_none());
}

#[test]
fn payload_replaced_after_first_validation_leaves_no_store_residue_and_retries() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipped: needs root");
        return;
    }
    let zones = zones();
    let catalog = catalog_bytes("china");
    stage(
        &zones.store.incoming,
        &catalog,
        &[
            ("agent-common.dex", b"core"),
            ("agent-settings.dex", b"agent"),
        ],
    );
    let id = staged_generation_id(&zones.store.incoming);
    let error = zones
        .store
        .activate_incoming_impl_with_hook(None, || {
            fs::write(zones.store.incoming.join("agent-settings.dex"), b"enemy")?;
            Ok(())
        })
        .unwrap_err()
        .to_string();
    assert!(error.contains("changed after validation"), "{error}");
    let generations = zones.store.root.join(GENERATIONS_DIR);
    assert!(!generations.join(&id).exists());
    assert!(!generations.join(format!("next-{id}")).exists());
    assert!(zones.store.retained_generations().unwrap().is_empty());
    assert!(zones.store.prune(&BTreeSet::new()).unwrap().is_empty());

    stage(
        &zones.store.incoming,
        &catalog,
        &[
            ("agent-common.dex", b"core"),
            ("agent-settings.dex", b"agent"),
        ],
    );
    assert_eq!(zones.store.activate_incoming().unwrap().id, id);
}

#[test]
fn hostile_existing_generation_ids_are_never_removed_or_reused() {
    let catalog = catalog_bytes("china");
    for hostile in ["canonical-file", "canonical-symlink", "next-directory"] {
        let zones = zones();
        stage(
            &zones.store.incoming,
            &catalog,
            &[
                ("agent-common.dex", b"core"),
                ("agent-settings.dex", b"agent"),
            ],
        );
        let id = staged_generation_id(&zones.store.incoming);
        zones.store.ensure_layout().unwrap();
        let generations = zones.store.root.join(GENERATIONS_DIR);
        let outside = zones._root.path().join(format!("outside-{hostile}"));
        fs::write(&outside, b"untouched").unwrap();
        let hostile_path = match hostile {
            "canonical-file" => {
                let path = generations.join(&id);
                fs::write(&path, b"hostile").unwrap();
                path
            }
            "canonical-symlink" => {
                let path = generations.join(&id);
                symlink(&outside, &path).unwrap();
                path
            }
            "next-directory" => {
                let path = generations.join(format!("next-{id}"));
                fs::create_dir(&path).unwrap();
                fs::write(path.join("hostile"), b"preserve").unwrap();
                path
            }
            _ => unreachable!(),
        };
        let before = tree_bytes(&generations);
        assert!(zones.store.activate_incoming().is_err(), "{hostile}");
        assert_eq!(tree_bytes(&generations), before, "{hostile}");
        assert!(hostile_path.exists() || hostile == "canonical-symlink");
        assert_eq!(fs::read(&outside).unwrap(), b"untouched");
    }
}

#[test]
fn forged_app_written_selection_document_is_rejected() {
    let zones = zones();
    stage(
        &zones.store.incoming,
        &catalog_bytes("china"),
        &[
            ("agent-common.dex", b"core"),
            ("agent-settings.dex", b"agent"),
            (AGENTS_SELECTED_FILE, br#"{"forged":true}"#),
        ],
    );
    let error = zones.store.activate_incoming().unwrap_err().to_string();
    assert!(error.contains("selection"), "unexpected error: {error}");
}

#[test]
fn activation_without_vehicle_profile_is_rejected() {
    let root = tempdir().unwrap();
    let zone = root.path().join("zone");
    let incoming = root.path().join("incoming");
    fs::create_dir_all(&incoming).unwrap();
    fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir_all(&zone).unwrap();
    fs::set_permissions(&zone, fs::Permissions::from_mode(0o755)).unwrap();
    let store = GenerationStore::new(&zone, &incoming);
    stage(
        &incoming,
        &catalog_bytes("china"),
        &[
            ("agent-common.dex", b"core"),
            ("agent-settings.dex", b"agent"),
        ],
    );
    let error = store.activate_incoming().unwrap_err().to_string();
    assert!(
        error.contains("vehicle.json") || error.contains("profile"),
        "unexpected error: {error}"
    );
    assert!(store.active_id().is_none(), "active pointer must not exist");
    assert!(incoming.join(READY_MARKER).exists());
    assert_eq!(
        fs::read(incoming.join("agent-common.dex")).unwrap(),
        b"core"
    );
    let generations = zone.join(GENERATIONS_DIR);
    assert!(
        fs::read_dir(generations).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("next-")),
        "no trusted generation import may start without root facts"
    );
}

#[test]
fn exact_inventory_rejects_missing_extra_and_linked_entries() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("agents.json"), b"x").unwrap();
    let allowed = BTreeSet::from(["agents.json".to_string()]);
    assert!(validate_exact_directory_inventory(dir.path(), &allowed).is_ok());
    fs::write(dir.path().join("extra.dex"), b"x").unwrap();
    assert!(validate_exact_directory_inventory(dir.path(), &allowed).is_err());
    fs::remove_file(dir.path().join("extra.dex")).unwrap();
    symlink(dir.path().join("agents.json"), dir.path().join("link.dex")).unwrap();
    let linked = BTreeSet::from(["agents.json".to_string(), "link.dex".to_string()]);
    assert!(validate_exact_directory_inventory(dir.path(), &linked).is_err());
}

#[test]
fn description_is_compact_and_sorted() {
    let generation = VerifiedGeneration {
        id: "a".repeat(64),
        catalog_sha256: "b".repeat(64),
        selection_sha256: "c".repeat(64),
        directory: PathBuf::from("/generation"),
        catalog: AgentCatalog::parse(&catalog_bytes("china")).unwrap(),
        selection: VerifiedSelection {
            receipt: serde_json::from_str(&format!(
                r#"{{"schemaVersion":1,"catalogSha256":"{}","facts":{{"chip":{{"value":"8155"}},"vehicle":{{"value":"free"}},"android":{{"value":9}},"powertrain":{{"value":"ev"}},"market":{{"value":"china"}}}},"agents":[{{"id":"settings","result":"supported"}}]}}"#,
                "b".repeat(64)
            ))
            .unwrap(),
            exact_bytes: vec![],
            sha256: "c".repeat(64),
            selected_agent_ids: vec!["settings".to_string()],
        },
        files: vec![GenerationFile {
            file: "agent-common.dex".to_string(),
            size: 1,
            sha256: "d".repeat(64),
        }],
    };
    let json = generation.description_json().unwrap();
    assert!(!json.contains('\n'));
    assert!(json.contains("\"selectionSha256\""));
}

#[test]
fn bootstrap_use_time_read_rejects_absent_symlink_mode_size_hash_and_tamper() {
    let expected_bytes = b"core";
    let expected = GenerationFile {
        file: "agent-common.dex".to_string(),
        size: expected_bytes.len() as u64,
        sha256: digest(expected_bytes),
    };

    for case in [
        "absent", "symlink", "hardlink", "mode", "oversize", "hash", "tamper",
    ] {
        let root = tempdir().unwrap();
        let path = root.path().join(&expected.file);
        if case != "absent" {
            fs::write(&path, expected_bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(GENERATION_FILE_MODE)).unwrap();
        }
        match case {
            "symlink" => {
                fs::remove_file(&path).unwrap();
                fs::write(root.path().join("other.dex"), expected_bytes).unwrap();
                symlink("other.dex", &path).unwrap();
            }
            "hardlink" => {
                fs::remove_file(&path).unwrap();
                let other = root.path().join("other.dex");
                fs::write(&other, expected_bytes).unwrap();
                fs::hard_link(&other, &path).unwrap();
            }
            "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            "oversize" => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                fs::write(&path, b"core!").unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(GENERATION_FILE_MODE))
                    .unwrap();
            }
            "hash" => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                fs::write(&path, b"evil").unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(GENERATION_FILE_MODE))
                    .unwrap();
            }
            "tamper" => {
                fs::set_permissions(root.path(), fs::Permissions::from_mode(GENERATION_DIR_MODE))
                    .unwrap();
                assert_eq!(
                    read_verified_file(
                        root.path(),
                        std::slice::from_ref(&expected),
                        &expected.file,
                    )
                    .unwrap(),
                    expected_bytes
                );
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                fs::write(&path, b"evil").unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(GENERATION_FILE_MODE))
                    .unwrap();
            }
            "absent" => {}
            _ => unreachable!(),
        }
        fs::set_permissions(root.path(), fs::Permissions::from_mode(GENERATION_DIR_MODE)).unwrap();
        assert!(
            read_verified_file(root.path(), std::slice::from_ref(&expected), &expected.file)
                .is_err(),
            "case={case}"
        );
    }
}

#[test]
fn bootstrap_core_module_and_artifact_roles_share_exact_use_time_reader() {
    let root = tempdir().unwrap();
    let roles = [
        ("agent-common.dex", b"core".as_slice()),
        ("agent-settings.dex", b"module".as_slice()),
        ("voboost-ui.apk", b"artifact".as_slice()),
    ];
    let inventory = roles
        .iter()
        .map(|(name, bytes)| {
            fs::write(root.path().join(name), bytes).unwrap();
            fs::set_permissions(
                root.path().join(name),
                fs::Permissions::from_mode(GENERATION_FILE_MODE),
            )
            .unwrap();
            GenerationFile {
                file: (*name).to_string(),
                size: bytes.len() as u64,
                sha256: digest(bytes),
            }
        })
        .collect::<Vec<_>>();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(GENERATION_DIR_MODE)).unwrap();
    for (name, bytes) in roles {
        assert_eq!(
            read_verified_file(root.path(), &inventory, name).unwrap(),
            bytes,
            "role={name}"
        );
    }

    let module = root.path().join("agent-settings.dex");
    fs::set_permissions(&module, fs::Permissions::from_mode(0o644)).unwrap();
    fs::write(&module, b"evil!!").unwrap();
    fs::set_permissions(&module, fs::Permissions::from_mode(GENERATION_FILE_MODE)).unwrap();
    assert!(read_verified_file(root.path(), &inventory, "agent-settings.dex").is_err());
    assert_eq!(
        read_verified_file(root.path(), &inventory, "agent-common.dex").unwrap(),
        b"core"
    );
    assert_eq!(
        read_verified_file(root.path(), &inventory, "voboost-ui.apk").unwrap(),
        b"artifact"
    );
}

#[test]
fn uninstall_freeze_removes_generation_ready_and_leaves_no_transaction() {
    let zones = test_support::zones();
    test_support::stage_variant(&zones.store, 1);
    assert!(zones.store.incoming_marker().exists());
    zones.store.freeze_for_uninstall().unwrap();
    assert!(!zones.store.incoming_marker().exists());
    assert!(zones.store.read_activation_journal().unwrap().is_none());
}

#[test]
fn retained_generation_scan_includes_beyond_previous_and_fails_closed_on_corruption() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipped: needs root");
        return;
    }
    let zones = test_support::zones();
    test_support::stage_variant(&zones.store, 1);
    let oldest = zones.store.activate_incoming().unwrap();
    test_support::stage_variant(&zones.store, 2);
    zones.store.activate_incoming().unwrap();
    test_support::stage_variant(&zones.store, 3);
    zones.store.activate_incoming().unwrap();

    let retained = zones.store.retained_generations().unwrap();
    assert_eq!(retained.len(), 3);
    assert!(retained.iter().any(|generation| generation.id == oldest.id));

    let catalog_path = oldest.directory.join(CATALOG_FILE);
    fs::set_permissions(&catalog_path, fs::Permissions::from_mode(0o644)).unwrap();
    fs::write(&catalog_path, b"{}").unwrap();
    fs::set_permissions(&catalog_path, fs::Permissions::from_mode(0o444)).unwrap();
    assert!(zones.store.retained_generations().is_err());
}

#[test]
fn active_global_operations_leave_prune_tree_byte_exact() {
    for (operation, salt) in [
        (Operation::Install, 'a'),
        (Operation::Update, 'b'),
        (Operation::Restore, 'c'),
        (Operation::Uninstall, 'd'),
    ] {
        let zones = test_support::zones();
        old_prune_candidate(&zones.store, 'a');
        let lease =
            OperationLease::acquire_in(&zones.store.root, operation_descriptor(operation, salt))
                .unwrap();
        let before = tree_bytes(&zones.store.root);
        assert!(zones.store.prune(&BTreeSet::new()).is_err());
        assert_eq!(
            tree_bytes(&zones.store.root),
            before,
            "operation={operation:?}"
        );
        lease.clear().unwrap();
    }
}

#[test]
fn held_prune_guard_fences_all_global_operation_leases() {
    let zones = test_support::zones();
    let (id, _) = old_prune_candidate(&zones.store, 'b');
    let mut checked = false;
    let removed = zones
        .store
        .prune_with_hook(&BTreeSet::new(), |mutation, _| {
            if mutation == PruneMutation::EnsureGenerations {
                for (operation, salt) in [
                    (Operation::Install, '1'),
                    (Operation::Update, '2'),
                    (Operation::Restore, '3'),
                    (Operation::Uninstall, '4'),
                ] {
                    let error = OperationLease::acquire_in(
                        &zones.store.root,
                        operation_descriptor(operation, salt),
                    )
                    .err()
                    .expect("prune guard must fence every global operation");
                    assert_eq!(error, "operation busy");
                }
                checked = true;
            }
            Ok(())
        })
        .unwrap();
    assert!(checked);
    assert_eq!(removed, vec![id]);
}

#[test]
fn prune_revalidates_guard_before_retire_rename() {
    let zones = test_support::zones();
    let (_, candidate) = old_prune_candidate(&zones.store, 'c');
    let error = zones
        .store
        .prune_with_hook(&BTreeSet::new(), |mutation, _| {
            if mutation == PruneMutation::RetireRename {
                replace_operation_lock_path(&zones.store.root);
            }
            Ok(())
        })
        .unwrap_err();
    assert!(error.to_string().contains("identity changed"));
    assert!(candidate.is_dir(), "ownership loss must precede rename");
}

#[test]
fn prune_revalidates_guard_before_retired_delete_and_preserves_recovery() {
    let zones = test_support::zones();
    let (id, candidate) = old_prune_candidate(&zones.store, 'd');
    let retired = zones
        .store
        .root
        .join(GENERATIONS_DIR)
        .join(QUARANTINE_DIR)
        .join(format!("retired-{id}"));
    let error = zones
        .store
        .prune_with_hook(&BTreeSet::new(), |mutation, _| {
            if mutation == PruneMutation::RetireDelete {
                replace_operation_lock_path(&zones.store.root);
            }
            Ok(())
        })
        .unwrap_err();
    assert!(error.to_string().contains("identity changed"));
    assert!(
        !candidate.exists(),
        "rename remains the atomic retirement step"
    );
    assert!(
        retired.is_dir(),
        "failed delete remains recoverable quarantine"
    );
    assert_eq!(
        fs::read(retired.join("payload")).unwrap(),
        b"immutable generation bytes"
    );
}

#[test]
fn initial_install_builds_exact_root_owned_generation_after_every_file_cut() {
    use ed25519_dalek::{Signer, SigningKey};
    use voboost_contract::release::{Artifact, ArtifactRole};

    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct InstallWal<'a> {
        schema_version: u32,
        transaction_id: &'a str,
        manifest_sha256: &'a str,
        phase: &'static str,
        boot_ids: [&'static str; 1],
    }

    let root = tempdir().unwrap();
    let zone = root.path().join("zone");
    let generations = zone.join(GENERATIONS_DIR);
    let incoming = generations.join(NEXT_DIR);
    let transaction_id = "6".repeat(64);
    let recovery = zone.join("recovery").join(&transaction_id);
    let frozen = recovery.join("frozen");
    fs::create_dir_all(&frozen).unwrap();
    fs::set_permissions(&zone, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(zone.join("recovery"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&recovery, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&frozen, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(zone.join(VEHICLE_PROFILE_FILE), KNOWN_FACTS).unwrap();
    fs::set_permissions(
        zone.join(VEHICLE_PROFILE_FILE),
        fs::Permissions::from_mode(crate::profile::VEHICLE_PROFILE_MODE),
    )
    .unwrap();

    let module_names = (0..51)
        .map(|index| format!("agent-settings-{index:02}.dex"))
        .collect::<Vec<_>>();
    let core_bytes = b"root-owned-common".to_vec();
    let module_bytes = module_names
        .iter()
        .map(|name| (name.clone(), format!("root-owned:{name}").into_bytes()))
        .collect::<BTreeMap<_, _>>();
    let targets = module_bytes
        .iter()
        .enumerate()
        .map(|(index, (file, bytes))| {
            serde_json::json!({
                "platform":"android","domain":"android","entryAbi":"android-java-v1",
                "process":format!("com.example.target{index}"),
                "file":file,
                "size":bytes.len(),
                "sha256":digest(bytes),
                "entryClass":"ru.voboost.agents.settings.SettingsAgent",
                "boot":false
            })
        })
        .collect::<Vec<_>>();
    let catalog_value = serde_json::json!({
        "schemaVersion":2,
        "supportedAbis":["arm64-v8a","armeabi-v7a"],
        "agentEntryAbi":{"schemaVersion":1,"sha256":crate::catalog::AGENT_ENTRY_ABI_SHA256},
        "core":{"file":"agent-common.dex","size":core_bytes.len(),"sha256":digest(&core_bytes)},
        "agents":[{
            "id":"settings","targets":targets,"status":"unstable","category":"interface","order":-1,
            "activation":{"type":"config","key":"voboost-startup","value":"interface"},
            "disables":[],"options":[],"title":{"en":"Voboost","ru":"Voboost"},
            "description":{"en":"Settings","ru":"Settings"},
            "applicability":{"chip":["8155","nxp"],"vehicle":["free","dreamer"],"android":[9,11],"powertrain":["ev","hybrid"],"market":["china","global"]}
        }]
    });
    let catalog: AgentCatalog = serde_json::from_value(catalog_value).unwrap();
    let mut catalog_bytes = serde_json::to_vec(&catalog).unwrap();
    catalog_bytes.push(b'\n');
    let catalog_bytes = native_catalog_fixture(&catalog_bytes);
    AgentCatalog::parse(&catalog_bytes).unwrap();
    let catalog_signature = sign_with_release_key(&catalog_bytes);

    let mut manifest = voboost_contract::release::Manifest::parse(include_bytes!(
        "../../../test/fixtures/product-release/voboost/valid/minimal.json"
    ))
    .unwrap();
    manifest
        .artifacts
        .retain(|artifact| artifact.role != ArtifactRole::AgentModule);
    let fixed_artifact_count = manifest.artifacts.len();
    let set_identity = |artifact: &mut Artifact, bytes: &[u8]| {
        artifact.size = bytes.len() as u64;
        artifact.sha256 = digest(bytes);
    };
    for artifact in &mut manifest.artifacts {
        let bytes = match artifact.file.as_str() {
            "agents.json" => catalog_bytes.as_slice(),
            "agents.json.sig" => catalog_signature.as_slice(),
            "agent-common.dex" => core_bytes.as_slice(),
            "restore.json.sig" => &[7_u8; 64],
            _ => b"fixed-product-artifact",
        };
        set_identity(artifact, bytes);
    }
    for (file, bytes) in &module_bytes {
        manifest.artifacts.push(Artifact {
            role: ArtifactRole::AgentModule,
            file: file.clone(),
            size: bytes.len() as u64,
            sha256: digest(bytes),
            activation: voboost_contract::release::Activation::AgentGeneration,
            package_name: None,
            version_code: None,
            certificate_sha256: None,
            abi: None,
            resource: None,
        });
    }
    manifest.artifacts.sort_by_key(|artifact| {
        let rank = match artifact.role {
            ArtifactRole::App => 0,
            ArtifactRole::Daemon => 1,
            ArtifactRole::Inject => 2,
            ArtifactRole::Install => 3,
            ArtifactRole::Restore => 4,
            ArtifactRole::Uninstall => 5,
            ArtifactRole::Selinux => 6,
            ArtifactRole::Init => 7,
            ArtifactRole::RestoreAuthorization => 8,
            ArtifactRole::RestoreSignature => 9,
            ArtifactRole::Implant => 10,
            ArtifactRole::Lsplant => 11,
            ArtifactRole::AgentCatalog => 12,
            ArtifactRole::AgentCatalogSignature => 13,
            ArtifactRole::AgentCommon => 14,
            ArtifactRole::AgentModule => 15,
            ArtifactRole::QnxDaemon => 16,
            ArtifactRole::QnxInit => 17,
            ArtifactRole::QnxImplant => 18,
            ArtifactRole::QnxRuntime => 19,
            ArtifactRole::QnxAgentModule => 20,
            ArtifactRole::ResourceApk => 21,
            ArtifactRole::ResourceLedger => 22,
            ArtifactRole::QnxResourcePack => 23,
            ArtifactRole::QnxResourceLedger => 24,
        };
        (rank, artifact.file.clone())
    });
    manifest.validate().unwrap();
    assert_eq!(
        manifest.artifacts.len(),
        fixed_artifact_count + module_bytes.len()
    );
    let manifest_bytes = manifest.canonical_bytes().unwrap();
    let manifest_signature = SigningKey::from_bytes(&[12_u8; 32])
        .sign(&manifest_bytes)
        .to_bytes()
        .to_vec();

    let write = |name: &str, bytes: &[u8]| {
        fs::write(frozen.join(name), bytes).unwrap();
        fs::set_permissions(frozen.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    };
    write(voboost_contract::release::MANIFEST_NAME, &manifest_bytes);
    write(
        voboost_contract::release::MANIFEST_SIGNATURE_NAME,
        &manifest_signature,
    );
    let staging = voboost_contract::install::StagingDescriptor {
        schema_version: 1,
        transaction_id: transaction_id.clone(),
        release_identity: manifest.release_identity.clone(),
        manifest_sha256: digest(&manifest_bytes),
        emulator_acceptance: None,
    };
    write("staging.json", &staging.canonical_bytes().unwrap());
    for artifact in &manifest.artifacts {
        let bytes = match artifact.file.as_str() {
            "agents.json" => catalog_bytes.as_slice(),
            "agents.json.sig" => catalog_signature.as_slice(),
            "agent-common.dex" => core_bytes.as_slice(),
            "restore.json.sig" => &[7_u8; 64],
            file if module_bytes.contains_key(file) => module_bytes[file].as_slice(),
            _ => b"fixed-product-artifact",
        };
        write(&artifact.file, bytes);
    }
    let expected_frozen = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.file.clone())
        .chain([
            voboost_contract::release::MANIFEST_NAME.into(),
            voboost_contract::release::MANIFEST_SIGNATURE_NAME.into(),
            "staging.json".into(),
        ])
        .collect::<BTreeSet<_>>();
    assert_eq!(expected_frozen.len(), manifest.artifacts.len() + 3);
    let actual_frozen = fs::read_dir(&frozen)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_frozen, expected_frozen);

    let manifest_sha256 = digest(&manifest_bytes);
    let mut journal = serde_json::to_vec(&InstallWal {
        schema_version: 1,
        transaction_id: &transaction_id,
        manifest_sha256: &manifest_sha256,
        phase: "install-agents",
        boot_ids: ["01234567-89ab-cdef-0123-456789abcdef"],
    })
    .unwrap();
    journal.push(b'\n');
    write("../install-journal.json", &journal);
    let pointer = OperationDescriptor {
        schema_version: 1,
        operation: Operation::Install,
        transaction_id: transaction_id.clone(),
        journal: format!("recovery/{transaction_id}/install-journal.json"),
        phase: "install-agents".into(),
        outcome: "running".into(),
        reboot_count: 1,
        boot_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
        status_sequence: 11,
        journal_sha256: digest(&journal),
        error: None,
        installed_apk: None,
    };
    let lease = OperationLease::acquire_in(&zone, pointer).unwrap();
    lease.verify_owner().unwrap();
    drop(lease);
    let store = GenerationStore::new(&zone, &incoming);
    store.prepare_initial_install().unwrap();
    let snapshot = fs::read_dir(&incoming)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            (
                path.file_name().unwrap().to_string_lossy().into_owned(),
                fs::read(path).unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(snapshot.len(), 58);
    assert!(snapshot.contains_key(READY_MARKER));
    assert!(snapshot.contains_key(AGENTS_SELECTED_FILE));
    for cut in 0..snapshot.len() {
        fs::remove_dir_all(&incoming).unwrap();
        fs::create_dir(&incoming).unwrap();
        fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700)).unwrap();
        for (name, bytes) in snapshot
            .iter()
            .filter(|(name, _)| name.as_str() != READY_MARKER)
            .take(cut)
        {
            fs::write(incoming.join(name), bytes).unwrap();
            fs::set_permissions(incoming.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
        store.prepare_initial_install().unwrap();
        assert_eq!(
            fs::read_dir(&incoming).unwrap().count(),
            snapshot.len(),
            "initial generation did not converge after cut {cut}"
        );
    }
}

struct ResourceZones(Zones);
impl std::ops::Deref for ResourceZones {
    type Target = Zones;
    fn deref(&self) -> &Zones {
        &self.0
    }
}
impl Drop for ResourceZones {
    fn drop(&mut self) {
        // Release only directories owned by this fixture before TempDir cleanup.
        let generations = self.0.store.root.join(GENERATIONS_DIR);
        if !generations.exists() {
            return;
        }
        let _ = fs::set_permissions(&generations, fs::Permissions::from_mode(0o700));
        if let Ok(entries) = fs::read_dir(&generations) {
            for entry in entries.flatten() {
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    let _ = fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o700));
                }
            }
        }
    }
}
fn resource_zones() -> ResourceZones {
    ResourceZones(zones())
}

fn stage_resource_generation(store: &GenerationStore, resource_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    stage_resource_generation_with_peer_targets(store, resource_bytes, false)
}
fn stage_resource_generation_with_peer_targets(
    store: &GenerationStore,
    resource_bytes: &[u8],
    peers: bool,
) -> (Vec<u8>, Vec<u8>) {
    stage_resource_generation_for_agent(store, resource_bytes, peers, false)
}
fn stage_resource_generation_for_agent(
    store: &GenerationStore,
    resource_bytes: &[u8],
    peers: bool,
    english: bool,
) -> (Vec<u8>, Vec<u8>) {
    use ed25519_dalek::{Signer, SigningKey};
    use voboost_contract::release::{
        Activation, Artifact, ArtifactRole, Manifest, ResourceFile, ResourceMetadata,
    };
    let owner = if english { "i18n-en" } else { "i18n-ru" };
    let locale = if english { "en" } else { "ru" };
    let package = if english {
        "ru.voboost.translation.setting.a11.en"
    } else {
        "ru.voboost.translation.setting"
    };
    let profile = if english { "setting-a11" } else { "setting-a9" };
    let apk = format!("resource-{owner}-{profile}.apk");
    let ledger_file = format!("resource-{owner}-{profile}.json");
    let mut catalog: AgentCatalog =
        serde_json::from_slice(&native_catalog_fixture(&catalog_bytes("china"))).unwrap();
    catalog.agents[0].id = owner.into();
    catalog.agents[0].activation = Some(crate::catalog::Activation::Checkbox { default: false });
    if peers {
        let target = catalog.agents[0]
            .targets
            .iter()
            .find(|target| target.process == "com.qinggan.app.setting")
            .unwrap()
            .clone();
        for process in ["com.qinggan.app.launcher", "com.qinggan.app.vehiclesetting"] {
            let mut peer = target.clone();
            peer.process = process.into();
            catalog.agents[0].targets.push(peer);
        }
    }
    let mut catalog_bytes = serde_json::to_vec(&catalog).unwrap();
    catalog_bytes.push(b'\n');
    let catalog_signature = sign_with_release_key(&catalog_bytes);
    let ledger = b"resource coverage ledger";
    stage(
        &store.incoming,
        &catalog_bytes,
        &[
            ("agent-common.dex", b"core"),
            ("agent-settings.dex", b"agent"),
            ("libvoboost-runtime-cluster.so", b"fixed-product-artifact"),
            ("libagent-font-cyrillic.so", b"fixed-product-artifact"),
            (apk.as_str(), resource_bytes),
            (ledger_file.as_str(), ledger),
        ],
    );
    let mut manifest = Manifest::parse(include_bytes!(
        "../../../test/fixtures/product-release/voboost/valid/minimal.json"
    ))
    .unwrap();
    for a in &mut manifest.artifacts {
        let data = match a.role {
            ArtifactRole::AgentCatalog => Some(catalog_bytes.as_slice()),
            ArtifactRole::AgentCatalogSignature => Some(catalog_signature.as_slice()),
            ArtifactRole::AgentCommon => Some(b"core".as_slice()),
            ArtifactRole::AgentModule => Some(b"agent".as_slice()),
            ArtifactRole::QnxRuntime | ArtifactRole::QnxAgentModule => {
                Some(b"fixed-product-artifact".as_slice())
            }
            _ => None,
        };
        if let Some(data) = data {
            a.size = data.len() as u64;
            a.sha256 = digest(data);
        }
    }
    manifest.artifacts.push(Artifact {
        role: ArtifactRole::ResourceApk,
        file: apk,
        size: resource_bytes.len() as u64,
        sha256: digest(resource_bytes),
        activation: Activation::AgentGeneration,
        package_name: Some(package.into()),
        version_code: Some(1),
        certificate_sha256: Some("a".repeat(64)),
        abi: None,
        resource: Some(ResourceMetadata {
            owner: owner.into(),
            locale: locale.into(),
            target_package: "com.qinggan.app.setting".into(),
            compatibility_schema: 1,
            overlay_package: package.into(),
            coverage_ledger: ResourceFile {
                file: ledger_file.clone(),
                size: ledger.len() as u64,
                sha256: digest(ledger),
            },
        }),
    });
    manifest.artifacts.push(Artifact {
        role: ArtifactRole::ResourceLedger,
        file: ledger_file.clone(),
        size: ledger.len() as u64,
        sha256: digest(ledger),
        activation: Activation::AgentGeneration,
        package_name: None,
        version_code: None,
        certificate_sha256: None,
        abi: None,
        resource: None,
    });
    let bytes = manifest.canonical_bytes().unwrap();
    let signature = SigningKey::from_bytes(&[12u8; 32])
        .sign(&bytes)
        .to_bytes()
        .to_vec();
    fs::write(store.incoming.join("voboost.json"), &bytes).unwrap();
    fs::write(store.incoming.join("voboost.json.sig"), &signature).unwrap();
    (bytes, signature)
}
fn import_resource_generation_for_host(store: &GenerationStore) -> Result<VerifiedGeneration> {
    store.ensure_layout()?;
    let incoming = Directory::open(&store.incoming)?;
    let catalog_bytes = fs::read(store.incoming.join(CATALOG_FILE))?;
    let signature = fs::read(store.incoming.join(CATALOG_SIGNATURE_FILE))?;
    let catalog = AgentCatalog::parse_verified(&catalog_bytes, &signature)?;
    let catalog_sha = digest(&catalog_bytes);
    let facts = VehicleProfileDocument::parse_canonical(KNOWN_FACTS.as_bytes())?;
    let selection = SelectionReceipt::compute(&catalog, &catalog_sha, &facts.facts)?;
    let resource =
        resources::ResourceProduct::load(&incoming, None, &catalog, &catalog_bytes, &signature)?
            .context("resource binding absent")?;
    let id = resource.generation_id(&catalog_sha, &selection.sha256)?;
    let mut files = expected_inventory(&catalog, &selection, &catalog_bytes, &signature)?;
    resource.extend(&mut files)?;
    let generations = store.root.join(GENERATIONS_DIR);
    fs::set_permissions(&generations, fs::Permissions::from_mode(0o700))?;
    let path = generations.join(&id);
    fs::create_dir(&path)?;
    for file in files.values() {
        let bytes = fs::read(store.incoming.join(&file.file))?;
        ensure!(
            bytes.len() as u64 == file.size && digest(&bytes) == file.sha256,
            "resource host import hash mismatch"
        );
        fs::write(path.join(&file.file), bytes)?;
        fs::set_permissions(
            path.join(&file.file),
            fs::Permissions::from_mode(GENERATION_FILE_MODE),
        )?;
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(GENERATION_DIR_MODE))?;
    fs::set_permissions(&generations, fs::Permissions::from_mode(0o711))?;
    store.load_generation(&id)
}
#[test]
fn resource_generation_preserves_signed_authority_and_exact_files_after_reload() {
    let z = resource_zones();
    stage_resource_generation(&z.store, b"resource-A");
    let generation = import_resource_generation_for_host(&z.store).unwrap();
    assert_eq!(
        generation
            .read_file_exact("resource-i18n-ru-setting-a9.apk")
            .unwrap(),
        b"resource-A"
    );
    assert!(generation
        .files
        .iter()
        .any(|f| f.file == "voboost.json.sig"));
    assert_ne!(
        generation.id,
        generation_id(&generation.catalog_sha256, &generation.selection_sha256).unwrap()
    );
    assert_eq!(
        z.store.load_generation(&generation.id).unwrap().id,
        generation.id
    );
}
#[test]
fn resource_generation_rejects_changed_payload_or_product_signature() {
    for signature in [false, true] {
        let z = resource_zones();
        stage_resource_generation(&z.store, b"resource-A");
        if signature {
            fs::write(z.store.incoming.join("voboost.json.sig"), [0u8; 64]).unwrap();
        } else {
            fs::write(
                z.store.incoming.join("resource-i18n-ru-setting-a9.apk"),
                b"resource-B",
            )
            .unwrap();
        }
        assert!(import_resource_generation_for_host(&z.store).is_err());
        assert!(z.store.active_id().is_none());
    }
}
#[test]
fn resource_generation_identity_changes_with_product_for_same_catalog() {
    let first = resource_zones();
    stage_resource_generation(&first.store, b"resource-A");
    let a = import_resource_generation_for_host(&first.store).unwrap();
    let second = resource_zones();
    stage_resource_generation(&second.store, b"resource-B");
    let b = import_resource_generation_for_host(&second.store).unwrap();
    assert_eq!(a.catalog_sha256, b.catalog_sha256);
    assert_eq!(a.selection_sha256, b.selection_sha256);
    assert_ne!(a.id, b.id);
}
#[test]
fn english_only_resource_bootstrap_uses_english_owner_and_distinct_profile_identity() {
    let zones = resource_zones();
    stage_resource_generation_for_agent(&zones.store, b"resource-English", false, true);
    let generation = import_resource_generation_for_host(&zones.store).unwrap();
    assert!(!generation.installed_agent_ids().contains("i18n-ru"));
    let artifacts = generation
        .resource_bootstrap_artifacts("com.qinggan.app.setting")
        .unwrap();
    assert_eq!(artifacts.len(), 2);
    assert_eq!(artifacts[0].id, "i18n-en:en-setting-a11-apk");
    assert_eq!(artifacts[0].file, "resource-i18n-en-setting-a11.apk");
    assert_eq!(artifacts[1].id, "i18n-en:en-setting-a11-ledger");
    assert_eq!(artifacts[1].file, "resource-i18n-en-setting-a11.json");
    assert!(generation
        .resource_bootstrap_artifacts("com.qinggan.app.launcher")
        .unwrap()
        .is_empty());
}
#[test]
fn resource_bootstrap_never_registers_another_declared_owners_profile() {
    let zones = resource_zones();
    stage_resource_generation_with_peer_targets(&zones.store, b"resource-A", true);
    let generation = import_resource_generation_for_host(&zones.store).unwrap();
    assert!(generation
        .catalog
        .has_target("i18n-ru", "com.qinggan.app.launcher"));
    assert_eq!(
        generation
            .resource_bootstrap_artifacts("com.qinggan.app.setting")
            .unwrap()
            .len(),
        2
    );
    assert!(generation
        .resource_bootstrap_artifacts("com.qinggan.app.launcher")
        .unwrap()
        .is_empty());
    assert!(generation
        .catalog
        .has_target("i18n-ru", "com.qinggan.app.vehiclesetting"));
    assert!(generation
        .resource_bootstrap_artifacts("com.qinggan.app.vehiclesetting")
        .unwrap()
        .is_empty());
    assert!(generation
        .resource_bootstrap_artifacts("com.qinggan.app.launcher/remote")
        .unwrap()
        .is_empty());
}

#[test]
fn resource_generation_bootstrap_registers_exact_owned_artifacts_and_none_fences_them() {
    let z = resource_zones();
    stage_resource_generation(&z.store, b"resource-A");
    let generation = import_resource_generation_for_host(&z.store).unwrap();
    let mut plan = crate::plan::Plan::defaults_for(&generation);
    let bytes = crate::runtime::test_support::bootstrap_bytes(
        &plan,
        &generation,
        "com.qinggan.app.setting",
    )
    .unwrap();
    let length = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let manifest: serde_json::Value = serde_json::from_slice(&bytes[24..24 + length]).unwrap();
    assert_eq!(
        manifest["artifacts"],
        serde_json::json!([{"id":"i18n-ru:setting-a9-apk","fileIndex":2},{"id":"i18n-ru:setting-a9-ledger","fileIndex":3}])
    );
    assert!(generation
        .resource_bootstrap_artifacts("unrelated.process")
        .unwrap()
        .is_empty());
    plan.startup = crate::plan::Startup::None;
    let bytes = crate::runtime::test_support::bootstrap_bytes(
        &plan,
        &generation,
        "com.qinggan.app.setting",
    )
    .unwrap();
    let length = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let manifest: serde_json::Value = serde_json::from_slice(&bytes[24..24 + length]).unwrap();
    assert_eq!(manifest["artifacts"], serde_json::json!([]));
}
#[test]
fn resource_generation_bootstrap_rechecks_exact_payload_before_sealed_fd() {
    let z = resource_zones();
    stage_resource_generation(&z.store, b"resource-A");
    let generation = import_resource_generation_for_host(&z.store).unwrap();
    let plan = crate::plan::Plan::defaults_for(&generation);
    let apk = generation.directory.join("resource-i18n-ru-setting-a9.apk");
    fs::set_permissions(&apk, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&apk, b"resource-B").unwrap();
    fs::set_permissions(&apk, fs::Permissions::from_mode(GENERATION_FILE_MODE)).unwrap();
    assert!(crate::runtime::test_support::bootstrap_bytes(
        &plan,
        &generation,
        "com.qinggan.app.setting"
    )
    .is_err());
}
#[test]
fn resource_generation_rejects_product_catalog_mismatch_and_missing_owner() {
    use ed25519_dalek::{Signer, SigningKey};
    for rebind in [false, true] {
        let z = resource_zones();
        stage_resource_generation(&z.store, b"resource-A");
        let mut catalog: AgentCatalog =
            serde_json::from_slice(&fs::read(z.store.incoming.join(CATALOG_FILE)).unwrap())
                .unwrap();
        catalog.agents[0].id = "other-ru".into();
        let mut catalog_bytes = serde_json::to_vec(&catalog).unwrap();
        catalog_bytes.push(b'\n');
        let signature = sign_with_release_key(&catalog_bytes);
        fs::write(z.store.incoming.join(CATALOG_FILE), &catalog_bytes).unwrap();
        fs::write(z.store.incoming.join(CATALOG_SIGNATURE_FILE), &signature).unwrap();
        if rebind {
            let mut product = voboost_contract::release::Manifest::parse(
                &fs::read(z.store.incoming.join("voboost.json")).unwrap(),
            )
            .unwrap();
            for (name, bytes) in [
                (CATALOG_FILE, catalog_bytes.as_slice()),
                (CATALOG_SIGNATURE_FILE, signature.as_slice()),
            ] {
                let a = product
                    .artifacts
                    .iter_mut()
                    .find(|a| a.file == name)
                    .unwrap();
                a.size = bytes.len() as u64;
                a.sha256 = digest(bytes);
            }
            let bytes = product.canonical_bytes().unwrap();
            let signature = SigningKey::from_bytes(&[12u8; 32]).sign(&bytes).to_bytes();
            fs::write(z.store.incoming.join("voboost.json"), bytes).unwrap();
            fs::write(z.store.incoming.join("voboost.json.sig"), signature).unwrap();
        }
        let error = import_resource_generation_for_host(&z.store)
            .err()
            .unwrap()
            .to_string();
        assert!(
            error.contains(if rebind {
                "resource owner missing"
            } else {
                "resource product catalog binding differs"
            }),
            "{error}"
        );
    }
}

#[test]
fn validated_install_ack_does_not_start_on_every_poll() {
    let fixture = pending_install_ack();
    Directory::open(&fixture.recovery)
        .unwrap()
        .write_atomic(
            ACKNOWLEDGEMENT_FILE,
            &ack_bytes(&fixture.acknowledgement),
            ROOT_FILE_MODE,
        )
        .unwrap();
    let starts = std::cell::Cell::new(0);
    for _ in 0..100 {
        let store = fixture.zones.store.clone();
        store
            .prepare_initial_install_with_start(|| {
                starts.set(starts.get() + 1);
                Ok(())
            })
            .unwrap();
    }
    assert!(
        starts.get() <= 5,
        "100 polls issued {} starts",
        starts.get()
    );
}

#[test]
fn install_ack_retry_is_bounded_backed_off_and_skips_running_service() {
    let fixture = pending_install_ack();
    Directory::open(&fixture.recovery)
        .unwrap()
        .write_atomic(
            ACKNOWLEDGEMENT_FILE,
            &ack_bytes(&fixture.acknowledgement),
            ROOT_FILE_MODE,
        )
        .unwrap();
    let now = Instant::now();
    let starts = std::cell::Cell::new(0);
    let poll = |seconds, running| {
        // New instances use the same root/transaction budget.
        let store = GenerationStore::new(&fixture.zones.store.root, &fixture.zones.store.incoming);
        store
            .prepare_initial_install_with_retry(
                || {
                    starts.set(starts.get() + 1);
                    Ok(())
                },
                || Ok(running),
                now + Duration::from_secs(seconds),
            )
            .unwrap();
    };
    for second in 0..100 {
        poll(second, true);
    }
    assert_eq!(
        starts.get(),
        0,
        "running/restarting service must not consume attempts"
    );
    for (second, expected) in [
        (100, 1),
        (100, 1),
        (101, 2),
        (102, 2),
        (103, 3),
        (106, 3),
        (107, 4),
        (114, 4),
        (115, 5),
        (10000, 5),
    ] {
        poll(second, false);
        assert_eq!(starts.get(), expected, "time {second}");
    }
    assert_eq!(
        fs::read(fixture.recovery.join("install-journal.json")).unwrap(),
        fixture.journal
    );
}

#[test]
fn install_ack_service_probe_failure_does_not_request_start() {
    let fixture = pending_install_ack();
    Directory::open(&fixture.recovery)
        .unwrap()
        .write_atomic(
            ACKNOWLEDGEMENT_FILE,
            &ack_bytes(&fixture.acknowledgement),
            ROOT_FILE_MODE,
        )
        .unwrap();
    let starts = std::cell::Cell::new(0);
    assert!(fixture
        .zones
        .store
        .prepare_initial_install_with_retry(
            || {
                starts.set(starts.get() + 1);
                Ok(())
            },
            || bail!("property unavailable"),
            Instant::now()
        )
        .is_err());
    assert_eq!(starts.get(), 0);
}

#[test]
fn install_ack_start_failures_also_consume_the_bounded_budget() {
    let fixture = pending_install_ack();
    Directory::open(&fixture.recovery)
        .unwrap()
        .write_atomic(
            ACKNOWLEDGEMENT_FILE,
            &ack_bytes(&fixture.acknowledgement),
            ROOT_FILE_MODE,
        )
        .unwrap();
    let now = Instant::now();
    let starts = std::cell::Cell::new(0);
    for second in [0, 1, 3, 7, 15] {
        assert!(fixture
            .zones
            .store
            .prepare_initial_install_with_retry(
                || {
                    starts.set(starts.get() + 1);
                    bail!("ctl.start refused")
                },
                || Ok(false),
                now + Duration::from_secs(second)
            )
            .is_err());
    }
    assert_eq!(starts.get(), 5);
    fixture
        .zones
        .store
        .prepare_initial_install_with_retry(
            || {
                starts.set(starts.get() + 1);
                Ok(())
            },
            || Ok(false),
            now + Duration::from_secs(10000),
        )
        .unwrap();
    assert_eq!(starts.get(), 5);
    assert_eq!(
        fs::read(fixture.recovery.join(ACKNOWLEDGEMENT_FILE)).unwrap(),
        ack_bytes(&fixture.acknowledgement)
    );
}
