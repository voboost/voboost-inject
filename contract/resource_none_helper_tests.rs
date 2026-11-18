//! Signed resource helper admission tests.

use super::*;
use crate::resource::SignedResourceInputs;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::Digest;

fn hash(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect()
}

/// Exact good APK fixture literal copied from the existing signed tests.
const APK_HEX: &str = "504b0304140000000000447b585d8da308e0640200006402000013000000416e64726f69644d616e69666573742e786d6c030008006402000001001c00100100000b00000000000000000100004800000000000000000000000b00000019000000230000002d0000004e0000007b0000008900000093000000a3000000bd00000008086d616e6966657374000b0b6170706c69636174696f6e0007076f7665726c61790007077061636b616765001e1e72752e766f626f6f73742e7472616e736c6174696f6e2e73657474696e67002a2a687474703a2f2f736368656d61732e616e64726f69642e636f6d2f61706b2f7265732f616e64726f6964000b0b76657273696f6e436f6465000707686173436f6465000d0d7461726765745061636b616765001717636f6d2e71696e6767616e2e6170702e73657474696e6700080869735374617469630080010800340000000000000000000000000000000000000000000000000000001b0201010c00010121000101000000005a050101020110004c00000001000000ffffffffffffffff00000000140014000200000000000000ffffffff03000000ffffffff08000003040000000500000006000000ffffffff0800001001000000020110004c00000001000000ffffffffffffffff020000001400140002000000000000000500000008000000ffffffff0800000309000000050000000a000000ffffffff0800001200000000030110001800000001000000ffffffffffffffff02000000020110003800000001000000ffffffffffffffff010000001400140001000000000000000500000007000000ffffffff0800001200000000030110001800000001000000ffffffffffffffff01000000030110001800000001000000ffffffffffffffff00000000504b0304140000000000447b585dee40e50507000000070000000e0000007265736f75726365732e6172736366697874757265840000000000000064000000000000001a8709715c000000580000003800000007000000646967657374731700000013000000666978747572652063657274696669636174650a00000061747472696275746573000000000a0000007369676e6174757265730a0000007075626c69632d6b6579840000000000000041504b2053696720426c6f636b203432504b01021403140000000000447b585d8da308e06402000064020000130000000000000000000000800100000000416e64726f69644d616e69666573742e786d6c504b01021403140000000000447b585dee40e50507000000070000000e00000000000000000000008001950200007265736f75726365732e61727363504b050600000000020002007d000000540300000000";

fn apk() -> Vec<u8> {
    APK_HEX
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

fn base_manifest() -> Value {
    serde_json::from_slice(include_bytes!(
        "../test/fixtures/product-release/voboost/valid/minimal.json"
    ))
    .unwrap()
}

fn catalog_bytes(module_sha: &str, entry: &str, process: &str, file: &str) -> Vec<u8> {
    let catalog: crate::agent_catalog::AgentCatalog = serde_json::from_value(json!({
        "schemaVersion": 2,
        "supportedAbis": ["arm64-v8a"],
        "agentEntryAbi": {"schemaVersion": 1, "sha256": "a".repeat(64)},
        "core": {"file": "agent-common.dex", "size": 1, "sha256": "b".repeat(64)},
        "agents": [{
            "id": "i18n-ru",
            "targets": [{"platform": "android", "domain": "android", "entryAbi": "android-java-v1",
                "process": process, "file": file,
                "size": MODULE_LEN as u64, "sha256": module_sha,
                "entryClass": entry, "boot": false}]
        }]
    }))
    .unwrap();
    catalog.canonical_bytes().unwrap()
}

const MODULE: &[u8] = b"i18n ru agent dex module bytes";
const MODULE_LEN: usize = MODULE.len();
const MODULE_FILE: &str = "agent-i18n-ru.dex";

fn ledger_bytes() -> Vec<u8> {
    let ledger = json!({
        "schema": 1,
        "targetPackage": "com.qinggan.app.setting",
        "compatibility": {"schemaVersion": 1, "targetPackage": "com.qinggan.app.setting",
            "resources": [{"resource": "string/title", "type": "string", "format": []}]},
        "overlayPackage": "ru.voboost.translation.setting",
        "scope": "admission-subset",
        "resources": [{"resource": "string/title", "source": "ru"}]
    });
    let mut b = serde_json::to_vec(&ledger).unwrap();
    b.push(b'\n');
    b
}

struct Fixture {
    manifest_bytes: Vec<u8>,
    manifest_signature: Vec<u8>,
    product_public_key: [u8; 32],
    catalog: Vec<u8>,
    apk: Vec<u8>,
    ledger: Vec<u8>,
    module: Vec<u8>,
}

fn fixture(catalog: Vec<u8>) -> Fixture {
    let module = MODULE.to_vec();
    let ledger = ledger_bytes();
    let apk = apk();
    let mut m = base_manifest();
    let artifacts = m["artifacts"].as_array_mut().unwrap();
    let cat = artifacts
        .iter_mut()
        .find(|a| a["file"] == "agents.json")
        .unwrap();
    cat["size"] = json!(catalog.len());
    cat["sha256"] = json!(hash(&catalog));
    let module_row = artifacts
        .iter_mut()
        .find(|a| a["file"] == "agent-settings.dex")
        .unwrap();
    module_row["file"] = json!(MODULE_FILE);
    module_row["size"] = json!(module.len());
    module_row["sha256"] = json!(hash(&module));
    let res = json!({"role": "resource-apk", "file": "resource-i18n-ru-setting.apk",
        "size": apk.len(), "sha256": hash(&apk), "activation": "agent-generation",
        "packageName": "ru.voboost.translation.setting", "versionCode": 1,
        "certificateSha256": hash(b"fixture certificate"),
        "resource": {"owner": "i18n-ru", "locale": "ru",
            "targetPackage": "com.qinggan.app.setting", "compatibilitySchema": 1,
            "overlayPackage": "ru.voboost.translation.setting",
            "coverageLedger": {"file": "resource-i18n-ru-setting.json",
                "size": ledger.len(), "sha256": hash(&ledger)}}});
    let ledger_row = json!({"role": "resource-ledger", "file": "resource-i18n-ru-setting.json",
        "size": ledger.len(), "sha256": hash(&ledger), "activation": "agent-generation"});
    artifacts.push(res);
    artifacts.push(ledger_row);
    let m: Manifest = serde_json::from_value(m).unwrap();
    let mut b = serde_json::to_vec(&m).unwrap();
    b.push(b'\n');
    let k = SigningKey::from_bytes(&[73; 32]);
    let sig = k.sign(&b).to_bytes().to_vec();
    Fixture {
        manifest_bytes: b,
        manifest_signature: sig,
        product_public_key: k.verifying_key().to_bytes(),
        catalog,
        apk,
        ledger,
        module,
    }
}

fn good_catalog() -> Vec<u8> {
    catalog_bytes(
        &hash(MODULE),
        I18N_RU_AGENT_ENTRY_CLASS,
        I18N_RU_TARGET_PROCESS,
        MODULE_FILE,
    )
}

fn owned(f: &Fixture) -> Result<OwnedResourceArtifact, String> {
    OwnedResourceArtifact::verify(SignedResourceInputs {
        manifest_bytes: &f.manifest_bytes,
        manifest_signature: &f.manifest_signature,
        product_public_key: &f.product_public_key,
        artifact_file: "resource-i18n-ru-setting.apk",
        catalog_bytes: &f.catalog,
        apk_bytes: &f.apk,
        ledger_bytes: &f.ledger,
    })
    .map_err(|e| e.to_string())
}

#[test]
fn accepts_actual_agent_entry_class_and_exact_module_bytes() {
    let f = fixture(good_catalog());
    let cap = owned(&f).unwrap();
    let v = VerifiedNoneHelper::verify(&cap, &f.module).unwrap();
    assert_eq!(v.module_file(), MODULE_FILE);
    assert_eq!(v.bytes(), f.module.as_slice());
    assert_eq!(v.release_identity(), "1.0.0-beta1");
    assert_eq!(v.manifest_sha256(), hash(&f.manifest_bytes));
    // The fixed None-cleanup class is a separate execution constant and is
    // never the catalog entrypoint.
    assert_ne!(I18N_RU_NONE_CLEANUP_CLASS, I18N_RU_AGENT_ENTRY_CLASS);
}

#[test]
fn catalog_class_swap_breaks_product_signature_and_admission() {
    // Swapping the catalog entryClass to the NoneCleanup class changes the
    // catalog digest: product ownership fails. Helper admission itself only
    // accepts the actual agent class.
    let f = fixture(good_catalog());
    let bad_catalog = catalog_bytes(
        &hash(MODULE),
        I18N_RU_NONE_CLEANUP_CLASS,
        I18N_RU_TARGET_PROCESS,
        MODULE_FILE,
    );
    assert!(owned(&Fixture {
        catalog: bad_catalog,
        ..f
    })
    .is_err());
    // Direct admission-level check with a re-signed manifest is covered by
    // rejects_foreign_catalog_class below; here the stale signature must fail.
}

#[test]
fn rejects_foreign_catalog_class_admission() {
    // Re-sign the manifest against a rogue-class catalog: ownership succeeds,
    // which proves only the product signature is not the defense here.
    let bad_catalog = catalog_bytes(
        &hash(MODULE),
        "ru.voboost.agents.i18n.ru.RogueCleanup",
        I18N_RU_TARGET_PROCESS,
        MODULE_FILE,
    );
    let f = fixture(bad_catalog);
    let cap = owned(&f).unwrap();
    assert!(VerifiedNoneHelper::verify(&cap, &f.module).is_err());
}

#[test]
fn rejects_none_entry_class_admission() {
    // entry_class is nullable in the contract; a None binding must be
    // rejected even when everything else is signed correctly.
    let mut cat: Value = serde_json::from_slice(&good_catalog()).unwrap();
    cat["agents"][0]["targets"][0]
        .as_object_mut()
        .unwrap()
        .remove("entryClass");
    let typed: crate::agent_catalog::AgentCatalog = serde_json::from_value(cat).unwrap();
    let bytes = typed.canonical_bytes().unwrap();
    let f = fixture(bytes);
    let cap = owned(&f).expect("fixture ownership must succeed before helper admission");
    assert!(VerifiedNoneHelper::verify(&cap, &f.module).is_err());
}

#[test]
fn rejects_mutated_module_payload() {
    let f = fixture(good_catalog());
    let cap = owned(&f).unwrap();
    let mut mutated = f.module.clone();
    mutated[0] ^= 0xff;
    assert!(VerifiedNoneHelper::verify(&cap, &mutated).is_err());
    assert!(VerifiedNoneHelper::verify(&cap, &[]).is_err());
}

#[test]
fn rejects_wrong_size_and_oversize_bound() {
    let f = fixture(good_catalog());
    let cap = owned(&f).unwrap();
    let mut wrong_size = f.module.clone();
    wrong_size.push(0u8);
    assert!(VerifiedNoneHelper::verify(&cap, &wrong_size).is_err());
    let huge = vec![0u8; MAX_NONE_HELPER_BYTES + 1];
    assert!(VerifiedNoneHelper::verify(&cap, &huge).is_err());
}

#[test]
fn rejects_foreign_target_process_admission() {
    let bad_catalog = catalog_bytes(
        &hash(MODULE),
        I18N_RU_AGENT_ENTRY_CLASS,
        "com.qinggan.app.other",
        MODULE_FILE,
    );
    let f = fixture(bad_catalog);
    let cap = owned(&f).expect("fixture ownership must succeed before helper admission");
    assert!(VerifiedNoneHelper::verify(&cap, &f.module).is_err());
}
