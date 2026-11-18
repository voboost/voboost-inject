//! Source-generated ZIP/AXML and signer-identity test vector, not a release APK.
//! APK signing-block fixture exercises identity parsing; product Ed25519 signature is genuine.
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
const APK_HEX:&str="504b0304140000000000447b585d8da308e0640200006402000013000000416e64726f69644d616e69666573742e786d6c030008006402000001001c00100100000b00000000000000000100004800000000000000000000000b00000019000000230000002d0000004e0000007b0000008900000093000000a3000000bd00000008086d616e6966657374000b0b6170706c69636174696f6e0007076f7665726c61790007077061636b616765001e1e72752e766f626f6f73742e7472616e736c6174696f6e2e73657474696e67002a2a687474703a2f2f736368656d61732e616e64726f69642e636f6d2f61706b2f7265732f616e64726f6964000b0b76657273696f6e436f6465000707686173436f6465000d0d7461726765745061636b616765001717636f6d2e71696e6767616e2e6170702e73657474696e6700080869735374617469630080010800340000000000000000000000000000000000000000000000000000001b0201010c00010121000101000000005a050101020110004c00000001000000ffffffffffffffff00000000140014000200000000000000ffffffff03000000ffffffff08000003040000000500000006000000ffffffff0800001001000000020110004c00000001000000ffffffffffffffff020000001400140002000000000000000500000008000000ffffffff0800000309000000050000000a000000ffffffff0800001200000000030110001800000001000000ffffffffffffffff02000000020110003800000001000000ffffffffffffffff010000001400140001000000000000000500000007000000ffffffff0800001200000000030110001800000001000000ffffffffffffffff01000000030110001800000001000000ffffffffffffffff00000000504b0304140000000000447b585dee40e50507000000070000000e0000007265736f75726365732e6172736366697874757265840000000000000064000000000000001a8709715c000000580000003800000007000000646967657374731700000013000000666978747572652063657274696669636174650a00000061747472696275746573000000000a0000007369676e6174757265730a0000007075626c69632d6b6579840000000000000041504b2053696720426c6f636b203432504b01021403140000000000447b585d8da308e06402000064020000130000000000000000000000800100000000416e64726f69644d616e69666573742e786d6c504b01021403140000000000447b585dee40e50507000000070000000e00000000000000000000008001950200007265736f75726365732e61727363504b050600000000020002007d000000540300000000";
fn apk() -> Vec<u8> {
    APK_HEX
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn hash(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect()
}
fn base() -> release::Manifest {
    serde_json::from_slice(include_bytes!(
        "../../../voboost/release/fixtures/voboost/valid/minimal.json"
    ))
    .unwrap()
}
fn signed(m: &release::Manifest) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    let mut b = serde_json::to_vec(m).unwrap();
    b.push(b'\n');
    let k = SigningKey::from_bytes(&[73; 32]);
    let sig = k.sign(&b).to_bytes().to_vec();
    (b, sig, k.verifying_key().to_bytes())
}
#[test]
fn no_resources_requires_no_external_probe() {
    let d = tempfile::tempdir().unwrap();
    let dir = Directory::open(d.path()).unwrap();
    let (b, sig, key) = signed(&base());
    let caps = admit_resources(&dir, &b, &sig, &key).unwrap();
    assert!(caps.is_empty());
}
#[test]
fn invalid_signature_rejected_before_resource_reads() {
    let d = tempfile::tempdir().unwrap();
    let dir = Directory::open(d.path()).unwrap();
    let (mut b, sig, key) = signed(&base());
    b.push(b' ');
    assert!(admit_resources(&dir, &b, &sig, &key).is_err());
}
fn fixture() -> (tempfile::TempDir, Vec<u8>, Vec<u8>, [u8; 32]) {
    let dir = tempfile::tempdir().unwrap();
    let catalog:voboost_contract::agent_catalog::AgentCatalog=serde_json::from_value(json!({"schemaVersion":2,"supportedAbis":["arm64-v8a"],"agentEntryAbi":{"schemaVersion":1,"sha256":"a".repeat(64)},"core":{"file":"agent-common.dex","size":1,"sha256":"b".repeat(64)},"agents":[{"id":"i18n-ru","targets":[]}]})).unwrap();
    let catalog = catalog.canonical_bytes().unwrap();
    let ledger = json!({"schema":1,"targetPackage":"com.qinggan.app.setting","compatibility":{"schemaVersion":1,"targetPackage":"com.qinggan.app.setting","resources":[{"resource":"string/title","type":"string","format":[]}]},"overlayPackage":"ru.voboost.translation.setting","scope":"admission-subset","resources":[{"resource":"string/title","source":"ru"}]});
    let mut ledger = serde_json::to_vec(&ledger).unwrap();
    ledger.push(b'\n');
    let apk = apk();
    let mut m = serde_json::to_value(base()).unwrap();
    let artifacts = m["artifacts"].as_array_mut().unwrap();
    let cat = artifacts
        .iter_mut()
        .find(|a| a["file"] == "agents.json")
        .unwrap();
    cat["size"] = json!(catalog.len());
    cat["sha256"] = json!(hash(&catalog));
    artifacts.push(json!({"role":"resource-apk","file":"resource-i18n-ru-setting.apk","size":apk.len(),"sha256":hash(&apk),"activation":"agent-generation","packageName":"ru.voboost.translation.setting","versionCode":1,"certificateSha256":hash(b"fixture certificate"),"resource":{"owner":"i18n-ru","locale":"ru","targetPackage":"com.qinggan.app.setting","compatibilitySchema":1,"overlayPackage":"ru.voboost.translation.setting","coverageLedger":{"file":"resource-i18n-ru-setting.json","size":ledger.len(),"sha256":hash(&ledger)}}}));
    artifacts.push(json!({"role":"resource-ledger","file":"resource-i18n-ru-setting.json","size":ledger.len(),"sha256":hash(&ledger),"activation":"agent-generation"}));
    std::fs::write(dir.path().join("agents.json"), catalog).unwrap();
    std::fs::write(dir.path().join("resource-i18n-ru-setting.apk"), apk).unwrap();
    std::fs::write(dir.path().join("resource-i18n-ru-setting.json"), ledger).unwrap();
    let m: release::Manifest = serde_json::from_value::<Value>(m)
        .and_then(serde_json::from_value)
        .unwrap();
    let (b, sig, key) = signed(&m);
    (dir, b, sig, key)
}
#[test]
fn signed_owned_staging_requires_no_target_identity() {
    let (d, b, sig, key) = fixture();
    let dir = Directory::open(d.path()).unwrap();
    let caps = admit_resources(&dir, &b, &sig, &key).unwrap();
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0].descriptor().owner, "i18n-ru");
    assert_eq!(caps[0].manifest_bytes(), b);
    assert_eq!(caps[0].manifest_signature(), sig);
}
#[test]
fn swapped_staged_apk_is_rejected() {
    let (d, b, sig, key) = fixture();
    std::fs::write(d.path().join("resource-i18n-ru-setting.apk"), b"swapped").unwrap();
    let dir = Directory::open(d.path()).unwrap();
    assert!(admit_resources(&dir, &b, &sig, &key).is_err());
}

#[test]
fn signed_ownership_rejects_wrong_probe_owner() {
    use voboost_contract::resource::{OwnedResourceArtifact, SignedResourceInputs};
    let (d, b, _, _) = fixture();
    let mut manifest: release::Manifest = serde_json::from_slice(&b).unwrap();
    let path = d.path().join("resource-i18n-ru-setting.json");
    let mut ledger: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    ledger["compatibility"]["targetPackage"] = json!("other.owner");
    let mut ledger = serde_json::to_vec(&ledger).unwrap();
    ledger.push(b'\n');
    let digest = hash(&ledger);
    for artifact in &mut manifest.artifacts {
        if let Some(resource) = &mut artifact.resource {
            resource.coverage_ledger.size = ledger.len() as u64;
            resource.coverage_ledger.sha256 = digest.clone();
        }
        if artifact.file == "resource-i18n-ru-setting.json" {
            artifact.size = ledger.len() as u64;
            artifact.sha256 = digest.clone();
        }
    }
    let (bytes, sig, key) = signed(&manifest);
    let catalog = std::fs::read(d.path().join("agents.json")).unwrap();
    let apk = std::fs::read(d.path().join("resource-i18n-ru-setting.apk")).unwrap();
    assert!(OwnedResourceArtifact::verify(SignedResourceInputs {
        manifest_bytes: &bytes,
        manifest_signature: &sig,
        product_public_key: &key,
        artifact_file: "resource-i18n-ru-setting.apk",
        catalog_bytes: &catalog,
        apk_bytes: &apk,
        ledger_bytes: &ledger
    })
    .is_err());
}
