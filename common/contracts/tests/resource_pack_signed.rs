//! Real signed-byte admission regressions; no native runtime readiness claim.
use ed25519_dalek::{Signer, SigningKey};
use voboost_contract_core::agent_catalog::AgentCatalog;
use voboost_contract_core::catalog::{Catalog, AGENT_ENTRY_ABI_SHA256, NATIVE_ENTRY_ABI_SHA256};
use voboost_contract_core::hash;
use voboost_contract_core::release::{Abi, Activation, Artifact, ArtifactRole, Manifest};
use voboost_contract_core::resource_pack::{Inputs, OwnedPack};

// ---- pack/ledger fixture: copied verbatim from resource_pack_tests.rs::fixture()
// (that helper is private to the unit-test module, so per the task's
//  "reuse fixture tiny bytes by append draft" clause it is copied here).
fn word(out: &mut Vec<u8>, n: usize) {
    out.extend_from_slice(&(n as u32).to_le_bytes());
}
fn text(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(s.as_bytes());
    out.push(0);
}
fn envelope_fixture(indexed: bool, pool: Vec<u8>, table: Vec<u8>) -> Vec<u8> {
    let names = [
        "/$message_types",
        "/$metaclass_dictionary",
        "/$plugins",
        "/$property_dictionary",
        "/$property_types",
        "/$strings",
        "/Locales/voboost-ru-gauge",
    ];
    let mut payloads = vec![vec![0; 4]; 7];
    payloads[1].clear();
    word(&mut payloads[1], 1);
    text(&mut payloads[1], "Kanzi.ResourceDictionary");
    payloads[5] = pool;
    payloads[6] = table;
    let mut out = b"KZBF".to_vec();
    word(&mut out, if indexed { 3 } else { 0x30003 });
    word(&mut out, 20);
    out.extend_from_slice(b"voboost-localization");
    word(&mut out, 7);
    for name in names {
        text(&mut out, name);
    }
    word(&mut out, 7);
    let mut at = (out.len() + 7 * 24 + 3) & !3;
    for (i, blob) in payloads.iter().enumerate() {
        for n in [
            i,
            if i == 6 { 0 } else { u32::MAX as usize },
            at,
            blob.len(),
            0,
            blob.len(),
        ] {
            word(&mut out, n);
        }
        at = (at + blob.len() + 3) & !3;
    }
    for blob in payloads {
        out.resize((out.len() + 3) & !3, 0);
        out.extend_from_slice(&blob);
    }
    out
}
fn pack_fixture() -> Vec<u8> {
    let mut pool = Vec::new();
    word(&mut pool, 2);
    text(&mut pool, "title");
    text(&mut pool, "res-text:///Value %1");
    let mut table = vec![0; 16];
    word(&mut table, 1);
    word(&mut table, 0);
    word(&mut table, 1);
    envelope_fixture(true, pool, table)
}

fn ledger_fixture() -> Vec<u8> {
    let mut ledger = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 1, "owner": "i18n-ru", "targetProcess": "gauge",
        "format": "KZBF-v3-indexed", "locale": "voboost-ru-gauge",
        "compatibilitySchema": 1,
        "resources": [{"key": "title", "type": "string", "source": "en", "format": ["%1"]}],
        "expectedReadback": {"title": "res-text:///Value %1"},
        "engineAdmission": "unverified",
        "englishKeys": 1, "retainedRussian": 0, "englishFallback": 1,
        "translated": 0, "hanFallback": 0, "stockRussianCoversEnglish": false
    }))
    .unwrap();
    ledger.push(b'\n');
    ledger
}

fn h(c: char) -> String {
    c.to_string().repeat(64)
}

/// Canonical ASCII catalog containing the QNX agent the ledger names as
/// owner (id i18n-ru, kind-less customer agent, Native target on `gauge`).
/// Built through the real AgentCatalog schema so `ascii_json` produces the
/// only byte spelling `Catalog::parse` accepts.
fn qnx_owner_catalog() -> Vec<u8> {
    let raw: AgentCatalog = serde_json::from_value(serde_json::json!({
        "schemaVersion": 2,
        "supportedAbis": ["arm64-v8a"],
        "agentEntryAbi": {"schemaVersion": 1, "sha256": AGENT_ENTRY_ABI_SHA256},
        "core": {"file": "agent-common.dex", "size": 16, "sha256": h('f')},
        "clusterRuntime": {"file": "libvoboost-runtime-cluster.so", "size": 4, "sha256": h('2')},
        "agents": [{
            "id": "i18n-ru",
            "targets": [{
                "process": "gauge",
                "file": "libagent-i18n-ru.so",
                "size": 3, "sha256": h('5'),
                "platform": "qnx", "domain": "cluster",
                "entryAbi": "voboost-agent3-v1", "boot": false
            }],
            "status": "stable", "order": 1,
            "applicability": {"chip": [], "vehicle": [], "android": [], "powertrain": [], "market": []}
        }]
    }))
    .unwrap();
    voboost_contract_core::ascii_json(&raw).unwrap()
}

/// Canonical catalog whose only agent targets an Android process: NO QNX
/// native target exists for `i18n-ru`/`gauge`. This catalog parses cleanly
/// (has_qnx is false and cluster_runtime is None), so OwnedPack::verify
/// advances past Catalog::parse and is rejected by the owner/target check.
fn android_only_catalog() -> Vec<u8> {
    let raw: AgentCatalog = serde_json::from_value(serde_json::json!({
        "schemaVersion": 2,
        "supportedAbis": ["arm64-v8a"],
        "agentEntryAbi": {"schemaVersion": 1, "sha256": AGENT_ENTRY_ABI_SHA256},
        "core": {"file": "agent-common.dex", "size": 16, "sha256": h('f')},
        "agents": [{
            "id": "settings-executor",
            "kind": "executor",
            "surfaces": ["settings"],
            "targets": [{
                "process": "com.example.settings",
                "file": "agent-settings.dex",
                "size": 5, "sha256": h('6'),
                "platform": "android", "domain": "android",
                "entryAbi": "android-java-v1", "entryClass": "ru.voboost.agents.AgentEntry",
                "boot": false
            }]
        }]
    }))
    .unwrap();
    voboost_contract_core::ascii_json(&raw).unwrap()
}

/// Every required-inventory row from the valid/minimal.json corpus (order is
/// the canonical role_rank/file order Manifest::validate enforces), with the
/// agents.json identity bound to the actual catalog bytes and the two QNX
/// resource rows bound to the actual pack/ledger bytes. `with_ledger=false`
/// drops the paired ledger row to exercise the same-stem pairing rejection.
fn manifest(catalog: &[u8], pack: &[u8], ledger: &[u8], with_ledger: bool) -> Manifest {
    let mut m: Manifest = serde_json::from_slice(include_bytes!(
        "../../../test/fixtures/product-release/voboost/valid/minimal.json"
    ))
    .unwrap();
    let catalog_row = m
        .artifacts
        .iter_mut()
        .find(|a| a.file == "agents.json")
        .unwrap();
    catalog_row.size = catalog.len() as u64;
    catalog_row.sha256 = hash(catalog);
    let native = Artifact {
        role: ArtifactRole::QnxAgentModule,
        file: "libagent-i18n-ru.so".into(),
        size: 3,
        sha256: h('5'),
        activation: Activation::AgentGeneration,
        package_name: None,
        version_code: None,
        certificate_sha256: None,
        abi: Some(Abi::QnxAarch64),
        resource: None,
    };
    let at = m
        .artifacts
        .iter()
        .position(|a| a.role == ArtifactRole::QnxAgentModule)
        .unwrap()
        + 1;
    m.artifacts.insert(at, native);
    for (role, file, bytes) in [
        (
            ArtifactRole::QnxResourcePack,
            "qnx-resource-i18n-ru-gauge.kzb",
            pack,
        ),
        (
            ArtifactRole::QnxResourceLedger,
            "qnx-resource-i18n-ru-gauge.json",
            ledger,
        ),
    ] {
        if role == ArtifactRole::QnxResourceLedger && !with_ledger {
            continue;
        }
        m.artifacts.push(Artifact {
            role,
            file: file.into(),
            size: bytes.len() as u64,
            sha256: hash(bytes),
            activation: Activation::AgentGeneration,
            package_name: None,
            version_code: None,
            certificate_sha256: None,
            abi: Some(Abi::QnxAarch64),
            resource: None,
        });
    }
    m
}

/// Real ed25519 authority used by cluster_authority.rs-style fixtures.
fn authority() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn signed_bytes(m: &Manifest, key: &SigningKey) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    let bytes = m.canonical_bytes().unwrap();
    let signature = key.sign(&bytes).to_bytes().to_vec();
    (bytes, signature, *key.verifying_key().as_bytes())
}

fn inputs<'a>(
    manifest: &'a [u8],
    signature: &'a [u8],
    public_key: &'a [u8; 32],
    catalog: &'a [u8],
    pack: &'a [u8],
    ledger: &'a [u8],
) -> Inputs<'a> {
    Inputs {
        manifest,
        signature,
        public_key,
        catalog,
        artifact_file: "qnx-resource-i18n-ru-gauge.kzb",
        pack,
        ledger,
    }
}

#[test]
fn full_signed_chain_accepts_only_inert_owned_bytes() {
    let key = authority();
    let pack = pack_fixture();
    let ledger = ledger_fixture();
    let catalog = qnx_owner_catalog();
    Catalog::parse(&catalog, AGENT_ENTRY_ABI_SHA256, NATIVE_ENTRY_ABI_SHA256).unwrap();
    let m = manifest(&catalog, &pack, &ledger, true);
    m.validate().unwrap();
    let (bytes, sig, pk) = signed_bytes(&m, &key);
    let owned = OwnedPack::verify(inputs(&bytes, &sig, &pk, &catalog, &pack, &ledger)).unwrap();
    assert_eq!(owned.pack(), pack);
    assert_eq!(owned.ledger().engine_admission, "unverified");
}

/// Native target absent from the signed catalog → owner check fails closed.
#[test]
fn native_target_absent_from_catalog_fails_closed() {
    let key = authority();
    let pack = pack_fixture();
    let ledger = ledger_fixture();
    let catalog = android_only_catalog(); // parses cleanly: no QNX targets
    let m = manifest(&catalog, &pack, &ledger, true);
    let (bytes, sig, pk) = signed_bytes(&m, &key);
    let error = OwnedPack::verify(inputs(&bytes, &sig, &pk, &catalog, &pack, &ledger)).unwrap_err();
    assert_eq!(error, "QNX pack owner target absent or ambiguous");
}

/// Ledger claiming a different owner than the enforced identity is rejected
/// even after the manifest is honestly rebuilt and re-signed around it.
#[test]
fn foreign_owner_ledger_rejected_under_honest_resigning() {
    let key = authority();
    let pack = pack_fixture();
    let ledger = ledger_fixture();
    let mut v: serde_json::Value = serde_json::from_slice(&ledger).unwrap();
    v["owner"] = serde_json::json!("font-cyrillic");
    let mut foreign = serde_json::to_vec(&v).unwrap();
    foreign.push(b'\n');
    let catalog = qnx_owner_catalog();
    let m = manifest(&catalog, &pack, &foreign, true);
    let (bytes, sig, pk) = signed_bytes(&m, &key);
    let error =
        OwnedPack::verify(inputs(&bytes, &sig, &pk, &catalog, &pack, &foreign)).unwrap_err();
    assert_eq!(error, "QNX localization identity rejected");
}

/// Any post-signing byte mutation of pack or manifest is rejected.
#[test]
fn tampered_bytes_rejected() {
    let key = authority();
    let pack = pack_fixture();
    let ledger = ledger_fixture();
    let catalog = qnx_owner_catalog();
    let m = manifest(&catalog, &pack, &ledger, true);
    let (bytes, sig, pk) = signed_bytes(&m, &key);
    // tampered pack: signed identity no longer matches presented bytes
    let mut tampered_pack = pack.clone();
    let flip = tampered_pack.len() - 1;
    tampered_pack[flip] ^= 1;
    assert_eq!(
        OwnedPack::verify(inputs(&bytes, &sig, &pk, &catalog, &tampered_pack, &ledger))
            .unwrap_err(),
        "QNX resource differs from signed bytes"
    );
    // tampered ledger bytes
    let mut tampered_ledger = ledger.clone();
    tampered_ledger[10] ^= 1;
    assert_eq!(
        OwnedPack::verify(inputs(&bytes, &sig, &pk, &catalog, &pack, &tampered_ledger))
            .unwrap_err(),
        "QNX resource differs from signed bytes"
    );
    // tampered manifest: signature verification fails first
    let mut tampered_manifest = bytes.clone();
    tampered_manifest[0] ^= 1;
    assert_eq!(
        OwnedPack::verify(inputs(
            &tampered_manifest,
            &sig,
            &pk,
            &catalog,
            &pack,
            &ledger
        ))
        .unwrap_err(),
        "voboost.json signature is invalid"
    );
    // foreign signing key is not the product authority
    let courier = SigningKey::from_bytes(&[8; 32]);
    let forged = courier.sign(&bytes).to_bytes().to_vec();
    assert_eq!(
        OwnedPack::verify(inputs(&bytes, &forged, &pk, &catalog, &pack, &ledger)).unwrap_err(),
        "voboost.json signature is invalid"
    );
}

/// A pack without its same-stem paired ledger row is rejected at manifest
/// validation inside verify (fail closed before any pack parsing).
#[test]
fn pack_without_paired_ledger_row_rejected() {
    let key = authority();
    let pack = pack_fixture();
    let ledger = ledger_fixture();
    let catalog = qnx_owner_catalog();
    let m = manifest(&catalog, &pack, &ledger, false);
    let (bytes, sig, pk) = signed_bytes(&m, &key);
    let error = OwnedPack::verify(inputs(&bytes, &sig, &pk, &catalog, &pack, &ledger)).unwrap_err();
    assert_eq!(
        error,
        "QNX resource requires exact same-stem pack and ledger"
    );
}

#[test]
#[ignore = "requires actual Java-generated input path"]
fn actual_java_pack_has_signed_owned_admission() {
    let base = std::env::var("VOBOOST_QNX_PACK_SAMPLE").expect("set actual generated pack stem");
    let pack = std::fs::read(format!("{base}.kzb")).unwrap();
    let ledger = std::fs::read(format!("{base}.json")).unwrap();
    let catalog = qnx_owner_catalog();
    let key = authority();
    let document = manifest(&catalog, &pack, &ledger, true);
    let (bytes, signature, public) = signed_bytes(&document, &key);
    let owned = OwnedPack::verify(inputs(
        &bytes, &signature, &public, &catalog, &pack, &ledger,
    ))
    .unwrap();
    assert!(matches!(
        owned.ledger().format.as_str(),
        "KZBF-v3-inline" | "KZBF-v3-indexed"
    ));
    assert_eq!(owned.pack(), pack);
    let mut tampered = pack.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(OwnedPack::verify(inputs(
        &bytes, &signature, &public, &catalog, &tampered, &ledger
    ))
    .is_err());
}
