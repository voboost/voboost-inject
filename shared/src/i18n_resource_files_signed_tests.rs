//! Host tests for authenticated replay and None re-entry. No production paths are mutated.
//! Fixtures use real Ed25519 product signing and source-generated APK signer identity bytes.
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use voboost_contract::{release, resource::SignedResourceInputs};
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
fn fixture() -> (tempfile::TempDir, Vec<u8>, Vec<u8>, [u8; 32]) {
    let dir = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
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
    artifacts.push(json!({"role":"resource-apk","file":"resource-i18n-ru-setting-a9.apk","size":apk.len(),"sha256":hash(&apk),"activation":"agent-generation","packageName":"ru.voboost.translation.setting","versionCode":1,"certificateSha256":hash(b"fixture certificate"),"resource":{"owner":"i18n-ru","locale":"ru","targetPackage":"com.qinggan.app.setting","compatibilitySchema":1,"overlayPackage":"ru.voboost.translation.setting","coverageLedger":{"file":"resource-i18n-ru-setting-a9.json","size":ledger.len(),"sha256":hash(&ledger)}}}));
    artifacts.push(json!({"role":"resource-ledger","file":"resource-i18n-ru-setting-a9.json","size":ledger.len(),"sha256":hash(&ledger),"activation":"agent-generation"}));
    std::fs::write(dir.path().join("agents.json"), catalog).unwrap();
    std::fs::write(dir.path().join("resource-i18n-ru-setting-a9.apk"), apk).unwrap();
    std::fs::write(dir.path().join("resource-i18n-ru-setting-a9.json"), ledger).unwrap();
    let m: release::Manifest = serde_json::from_value::<Value>(m)
        .and_then(serde_json::from_value)
        .unwrap();
    let (b, sig, key) = signed(&m);
    (dir, b, sig, key)
}

pub(super) fn capability(next_build: bool) -> OwnedResourceArtifact {
    let (d, mut b, mut sig, key) = fixture();
    let catalog = std::fs::read(d.path().join("agents.json")).unwrap();
    let mut apk = std::fs::read(d.path().join("resource-i18n-ru-setting-a9.apk")).unwrap();
    if next_build {
        // Change the first ZIP entry timestamp in both headers.
        let end = apk.len();
        let central = u32::from_le_bytes(apk[end - 6..end - 2].try_into().unwrap()) as usize;
        apk[10] ^= 1;
        apk[central + 12] ^= 1;
        let mut m: release::Manifest = serde_json::from_slice(&b).unwrap();
        m.release_identity = "1.0.0-beta2".into();
        let artifact = m
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.file == "resource-i18n-ru-setting-a9.apk")
            .unwrap();
        artifact.size = apk.len() as u64;
        artifact.sha256 = hash(&apk);
        let next = signed(&m);
        b = next.0;
        sig = next.1;
    }
    let ledger = std::fs::read(d.path().join("resource-i18n-ru-setting-a9.json")).unwrap();
    OwnedResourceArtifact::verify(SignedResourceInputs {
        manifest_bytes: &b,
        manifest_signature: &sig,
        product_public_key: &key,
        artifact_file: "resource-i18n-ru-setting-a9.apk",
        catalog_bytes: &catalog,
        apk_bytes: &apk,
        ledger_bytes: &ledger,
    })
    .unwrap()
}
fn directories() -> (tempfile::TempDir, Directory, Directory) {
    let t = tempfile::tempdir().unwrap();
    std::fs::create_dir(t.path().join("overlays")).unwrap();
    std::fs::create_dir(t.path().join("journal")).unwrap();
    let overlay = Directory::open(&t.path().join("overlays")).unwrap();
    let journal = Directory::open(&t.path().join("journal")).unwrap();
    (t, overlay, journal)
}
fn install_cap(a: &Directory, j: &Directory, c: &OwnedResourceArtifact) -> io::Result<Receipt> {
    // Public entry point fixes production directories and SELinux label. Host tests exercise
    // the same authenticated transaction implementation through retained test directories.
    install_with_authority(
        a,
        j,
        (
            c.manifest_sha256(),
            &c.artifact().sha256,
            voboost_shared::owned_overlay::Variant::SettingA9,
        ),
        c.apk_bytes(),
        None,
        None,
        Some(c),
    )
}
fn completed_none(a: &Directory, j: &Directory, mut receipt: Receipt) {
    a.unlink(OWNED).unwrap();
    a.sync_all().unwrap();
    receipt.phase = "early-none-awaiting-native-readback".into();
    publish(j, &receipt).unwrap();
}
#[test]
fn signed_stable_replay_preserves_readback_phase() {
    let (_t, a, j) = directories();
    let cap = capability(false);
    let mut receipt = install_cap(&a, &j, &cap).unwrap();
    for phase in [
        "oms-enabled-awaiting-owner-readback",
        "enabled-owner-readback-confirmed",
        "oms-disabled-awaiting-owner-readback",
        "disabled-owner-readback-confirmed",
    ] {
        receipt.phase = phase.into();
        publish(&j, &receipt).unwrap();
        let result = install_cap(&a, &j, &cap).unwrap();
        assert_eq!(result, receipt);
    }
}
#[test]
fn signed_none_allows_exact_same_build_reinstall() {
    let (_t, a, j) = directories();
    let cap = capability(false);
    let receipt = install_cap(&a, &j, &cap).unwrap();
    completed_none(&a, &j, receipt);
    let result = install_cap(&a, &j, &cap).unwrap();
    assert_eq!(result.phase, "awaiting-system-scan");
    assert_eq!(result.generation, cap.manifest_sha256());
    assert_eq!(
        a.read_trusted(OWNED, MAX_APK, 0o644).unwrap(),
        cap.apk_bytes()
    );
    verify_retained_authority(&j, &cap).unwrap();
}
#[test]
fn signed_none_rejects_unexpected_owned_file() {
    let (_t, a, j) = directories();
    let cap = capability(false);
    let mut receipt = install_cap(&a, &j, &cap).unwrap();
    receipt.phase = "early-none-awaiting-native-readback".into();
    publish(&j, &receipt).unwrap();
    assert!(install_cap(&a, &j, &cap)
        .unwrap_err()
        .to_string()
        .contains("unexpectedly present"));
    assert_eq!(
        a.read_trusted(OWNED, MAX_APK, 0o644).unwrap(),
        cap.apk_bytes()
    );
}
#[test]
fn signed_none_rejects_tampered_retained_authority_without_installing() {
    let (_t, a, j) = directories();
    let cap = capability(false);
    let receipt = install_cap(&a, &j, &cap).unwrap();
    completed_none(&a, &j, receipt);
    let slot = authority_slot(&j, cap.manifest_sha256()).unwrap();
    let mut sig = cap.manifest_signature().to_vec();
    sig[0] ^= 1;
    slot.write_atomic("product-manifest.sig", &sig, 0o600)
        .unwrap();
    assert!(install_cap(&a, &j, &cap)
        .unwrap_err()
        .to_string()
        .contains("retained resource authority differs"));
    assert!(
        matches!(a.read_trusted(OWNED,MAX_APK,0o644),Err(e) if e.kind()==io::ErrorKind::NotFound)
    );
    let receipt: Receipt =
        serde_json::from_slice(&j.read_trusted(JOURNAL, 4096, 0o600).unwrap()).unwrap();
    assert_eq!(receipt.phase, "early-none-awaiting-native-readback");
}
#[test]
fn new_signed_build_adopts_only_authenticated_predecessor() {
    let (_t, a, j) = directories();
    let old = capability(false);
    let next = capability(true);
    assert_ne!(old.manifest_sha256(), next.manifest_sha256());
    install_cap(&a, &j, &old).unwrap();
    let result = install_cap(&a, &j, &next).unwrap();
    assert_eq!(result.generation, next.manifest_sha256());
    assert_eq!(
        result.previous_sha256.as_deref(),
        Some(old.artifact().sha256.as_str())
    );
}
#[test]
fn new_signed_build_rejects_forged_predecessor_signature() {
    let (_t, a, j) = directories();
    let old = capability(false);
    let next = capability(true);
    install_cap(&a, &j, &old).unwrap();
    let slot = authority_slot(&j, old.manifest_sha256()).unwrap();
    let mut sig = old.manifest_signature().to_vec();
    sig[0] ^= 1;
    slot.write_atomic("product-manifest.sig", &sig, 0o600)
        .unwrap();
    assert!(install_cap(&a, &j, &next).is_err());
    assert_eq!(
        a.read_trusted(OWNED, MAX_APK, 0o644).unwrap(),
        old.apk_bytes()
    );
}

#[test]
fn none_replay_absent_apk_cannot_skip_pending_remount_recovery() {
    let (_t, overlays, journal) = directories();
    let owned = capability(false);
    let mut receipt = install_cap(&overlays, &journal, &owned).unwrap();
    overlays.unlink(OWNED).unwrap();
    overlays.sync_all().unwrap();
    receipt.phase = "early-none-removing".into();
    publish(&journal, &receipt).unwrap();
    journal
        .write_atomic("remount.json", b"pending protected mount WAL", 0o600)
        .unwrap();
    let result = finish_none_removal(&overlays, &journal, receipt, &owned, || {
        Err(io::Error::other("unverified RO recovery"))
    });
    assert!(result.is_err());
    let retained: Receipt =
        serde_json::from_slice(&journal.read_trusted(JOURNAL, 4096, 0o600).unwrap()).unwrap();
    assert_eq!(retained.phase, "early-none-removing");
    assert_eq!(
        journal.read_trusted("remount.json", 4096, 0o600).unwrap(),
        b"pending protected mount WAL"
    );
}
#[test]
fn none_replay_absent_apk_advances_only_after_verified_remount_recovery() {
    let (_t, overlays, journal) = directories();
    let owned = capability(false);
    let mut receipt = install_cap(&overlays, &journal, &owned).unwrap();
    overlays.unlink(OWNED).unwrap();
    overlays.sync_all().unwrap();
    receipt.phase = "early-none-removing".into();
    publish(&journal, &receipt).unwrap();
    journal
        .write_atomic("remount.json", b"pending protected mount WAL", 0o600)
        .unwrap();
    let mut recovered = false;
    let result = finish_none_removal(&overlays, &journal, receipt, &owned, || {
        journal.unlink("remount.json")?;
        journal.sync_all()?;
        recovered = true;
        Ok(())
    })
    .unwrap();
    assert!(recovered);
    assert_eq!(result.phase, "early-none-awaiting-native-readback");
    assert_eq!(
        journal
            .read_trusted("remount.json", 4096, 0o600)
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn uninstall_recovers_prepared_predecessor_and_staged_successor() {
    let (_t, overlays, journal) = directories();
    let old = capability(false);
    let next = capability(true);
    assert_ne!(old.apk_bytes(), next.apk_bytes());
    let previous = install_cap(&overlays, &journal, &old).unwrap();
    let mut receipt = install_cap(&overlays, &journal, &next).unwrap();
    receipt.phase = "prepared".into();
    publish(&journal, &receipt).unwrap();
    overlays
        .write_atomic(OWNED, old.apk_bytes(), 0o644)
        .unwrap();
    overlays
        .write_atomic(STAGED, next.apk_bytes(), 0o644)
        .unwrap();
    let variant = Variant::SettingA9;
    let read_files = |receipt: &Receipt| {
        operation_ownership::files(
            &overlays,
            &journal,
            variant,
            old.verification_key(),
            receipt,
            &next,
        )
    };
    let (owned, staged) = read_files(&receipt).unwrap();
    assert_eq!(owned.unwrap().bytes, old.apk_bytes());
    assert_eq!(staged.unwrap().bytes, next.apk_bytes());

    receipt.phase = "operation-removing".into();
    assert!(read_files(&receipt).is_ok());
    receipt.phase = "awaiting-system-scan".into();
    assert!(read_files(&receipt).is_err());

    receipt.phase = "prepared".into();
    let slot = authority_slot(&journal, &previous.generation).unwrap();
    let mut signature = old.manifest_signature().to_vec();
    signature[0] ^= 1;
    slot.write_atomic("product-manifest.sig", &signature, 0o600)
        .unwrap();
    assert!(read_files(&receipt).is_err());
    assert_eq!(
        overlays.read_trusted(OWNED, MAX_APK, 0o644).unwrap(),
        old.apk_bytes()
    );
    assert_eq!(
        overlays.read_trusted(STAGED, MAX_APK, 0o644).unwrap(),
        next.apk_bytes()
    );
}

#[test]
fn uninstall_recovers_missing_receipt_only_with_matching_retained_authority() {
    let (_t, overlays, journal) = directories();
    let old = capability(false);
    let next = capability(true);
    install_cap(&overlays, &journal, &old).unwrap();
    retain_authority(&journal, &next).unwrap();
    journal.unlink(JOURNAL).unwrap();
    let recover = || {
        operation_ownership::receipt(
            &journal,
            &overlays,
            Variant::SettingA9,
            old.verification_key(),
        )
    };
    assert_eq!(recover().unwrap().generation, old.manifest_sha256());
    assert!(!journal.entry_exists(JOURNAL).unwrap());

    overlays
        .write_atomic(OWNED, b"foreign bytes", 0o644)
        .unwrap();
    assert!(recover().unwrap_err().to_string().contains(OWNED));
    assert_eq!(
        overlays.read_trusted(OWNED, MAX_APK, 0o644).unwrap(),
        b"foreign bytes"
    );

    overlays
        .write_atomic(OWNED, old.apk_bytes(), 0o644)
        .unwrap();
    let slot = authority_slot(&journal, old.manifest_sha256()).unwrap();
    slot.write_atomic("product-manifest.sig", &[0; 64], 0o600)
        .unwrap();
    assert!(recover().is_err());
    assert!(!journal.entry_exists(JOURNAL).unwrap());
}
