use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ROOT_ZONE_PATH: &str = "/data/voboost";
pub const ROOT_ZONE_MARKER_PATH: &str = "/data/voboost/root.json";
#[allow(dead_code)] // Shared include: only install and uninstall need the exact marker bytes.
pub const ROOT_ZONE_MARKER_BYTES: &[u8] =
    b"{\"schemaVersion\":1,\"owner\":\"voboost\",\"root\":\"/data/voboost\"}\n";
pub const ROOT_ZONE_MARKER_SHA256: &str =
    "06d6cb6392f1fe94cceccdefb28c6ee434da1ab627cb5194a26032188b2519fc";
pub const RC_PATH: &str = "/system/etc/init/voboost.rc";
pub const RC_ARCHIVE_PATH: &str = "/data/voboost/uninstall/system/voboost.rc";
pub const POLICY_PATH: &str = "/vendor/etc/selinux/precompiled_sepolicy";
pub const POLICY_META_PATH: &str = "/data/voboost/uninstall/policy.meta.json";
pub const CURRENT_BASELINE_PATH: &str = "/data/voboost/uninstall/current-baseline.json";
pub const SYSTEM_ARTIFACTS_PATH: &str = "/data/voboost/uninstall/system-artifacts.json";
pub const SYSTEM_STATE_PATH: &str = "/data/voboost/uninstall/system-state.json";
#[allow(dead_code)] // The daemon opens this leaf descriptor-relative.
pub const INSTALL_INVENTORY_PATH: &str = "/data/voboost/uninstall/install-inventory.json";
pub const DAEMON_PATH: &str = "/data/voboost/voboost-daemon";
pub const INJECT_PATH: &str = "/data/voboost/voboost-inject";
pub const UNINSTALL_PATH: &str = "/data/voboost/voboost-uninstall";
pub const RESTORE_PATH: &str = "/data/voboost/voboost-restore";
pub const RESTORE_MANIFEST_PATH: &str = "/data/voboost/restore.json";
pub const RESTORE_MANIFEST_SIGNATURE_PATH: &str = "/data/voboost/restore.json.sig";
pub const SELINUX_PATH: &str = "/data/voboost/voboost-selinux";
pub const MANIFEST_PATH: &str = "/data/voboost/voboost.json";
pub const MANIFEST_SIGNATURE_PATH: &str = "/data/voboost/voboost.json.sig";
pub const PACKAGE_NAME: &str = "ru.voboost";
pub const APP_OP: &str = "REQUEST_INSTALL_PACKAGES";

pub const QNX_RELAY_PATHS: [(&str, &str, &str); 3] = [
    ("/data/voboost/voboost-cluster-daemon", "daemon", "0700"),
    (
        "/data/voboost/voboost-cluster-startup.sh",
        "runtime",
        "0700",
    ),
    (
        "/data/voboost/libvoboost-cluster-inject.so",
        "runtime",
        "0644",
    ),
];

const DOCUMENT_PATHS: [&str; 5] = [
    SYSTEM_ARTIFACTS_PATH,
    CURRENT_BASELINE_PATH,
    POLICY_META_PATH,
    SYSTEM_STATE_PATH,
    RC_ARCHIVE_PATH,
];
const PAYLOAD_PATHS: [(&str, &str, &str); 4] = [
    (
        "/data/voboost/libimplant-arm64-v8a.so",
        "arm64-v8a",
        "implant",
    ),
    (
        "/data/voboost/liblsplant-arm64-v8a.so",
        "arm64-v8a",
        "lsplant",
    ),
    (
        "/data/voboost/libimplant-armeabi-v7a.so",
        "armeabi-v7a",
        "implant",
    ),
    (
        "/data/voboost/liblsplant-armeabi-v7a.so",
        "armeabi-v7a",
        "lsplant",
    ),
];

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommittedInventory {
    pub schema_version: u32,
    pub phase: String,
    pub version: String,
    pub committed_at: String,
    pub documents: Vec<DocumentDigest>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentDigest {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SystemArtifacts {
    pub schema_version: u32,
    pub root: RootArtifact,
    pub init: InitArtifact,
    pub policy: PolicyArtifact,
    pub native: NativeArtifacts,
    pub package: PackageArtifact,
    pub app_op: AppOpArtifact,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RootArtifact {
    pub path: String,
    pub marker_path: String,
    pub marker_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InitArtifact {
    pub path: String,
    pub installed_size: u64,
    pub installed_sha256: String,
    pub archive_path: String,
    pub uid: u32,
    pub gid: u32,
    pub mode: String,
    pub context: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyArtifact {
    pub path: String,
    pub installed_sha256: String,
    pub current_baseline_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeArtifacts {
    pub daemon: SignedArtifact,
    pub inject: SignedArtifact,
    pub installer: SignedArtifact,
    pub uninstaller: SignedArtifact,
    pub restore: SignedArtifact,
    pub restore_manifest: ManifestArtifact,
    pub selinux: SignedArtifact,
    pub manifest: ManifestArtifact,
    pub payload: Vec<PayloadArtifact>,
    pub qnx: Vec<SignedArtifact>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedArtifact {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub signature_role: String,
    pub uid: u32,
    pub gid: u32,
    pub mode: String,
    pub context: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManifestArtifact {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub signature_path: String,
    pub signature_size: u64,
    pub signature_sha256: String,
    pub signature_role: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PayloadArtifact {
    pub path: String,
    pub abi: String,
    pub component: String,
    pub size: u64,
    pub sha256: String,
    pub signature_role: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackageArtifact {
    pub name: String,
    pub version_code: u64,
    pub apk_size: u64,
    pub apk_sha256: String,
    pub certificate_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppOpArtifact {
    pub package: String,
    pub operation: String,
    pub installed_mode: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CurrentBaseline {
    pub schema_version: u32,
    pub policy_sha256: String,
    pub backup_path: String,
    pub metadata_path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyMetadata {
    pub schema_version: u32,
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub uid: u32,
    pub gid: u32,
    pub mode: String,
    pub context: String,
    pub sidecars: Vec<crate::mount_policy_transaction::Sidecar>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SystemState {
    pub schema_version: u32,
    pub root_prior_state: String,
    pub init_prior_state: String,
    pub init_installed_sha256: String,
    pub policy_prior_sha256: String,
    pub policy_installed_sha256: String,
    pub package_prior_state: String,
    pub package_version_code: u64,
    pub app_op_prior_mode: String,
    pub app_op_installed_mode: String,
}

#[derive(Debug)]
#[allow(dead_code)] // Shared include: each binary consumes a different proof subset.
pub struct CommittedContract {
    pub inventory: CommittedInventory,
    pub artifacts: SystemArtifacts,
    pub baseline: CurrentBaseline,
    pub policy_metadata: PolicyMetadata,
    pub system_state: SystemState,
}

fn canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn baseline_backup_path(sha256: &str) -> Result<String, String> {
    if !canonical_sha256(sha256) {
        return Err("policy baseline SHA-256 is not canonical lowercase hex".to_string());
    }
    Ok(format!(
        "/data/voboost/uninstall/baselines/{sha256}/precompiled_sepolicy.orig"
    ))
}

pub fn uninstall_transaction_id(
    contract: &CommittedContract,
    inventory_bytes: &[u8],
) -> Result<String, String> {
    if inventory_bytes.is_empty() || inventory_bytes.len() > 64 * 1024 {
        return Err("install inventory transaction binding is oversized or empty".to_string());
    }
    let inventory_sha256 = sha256_hex(inventory_bytes);
    let uninstaller_sha256 = &contract.artifacts.native.uninstaller.sha256;
    let baseline_sha256 = &contract.baseline.policy_sha256;
    if !canonical_sha256(uninstaller_sha256) || !canonical_sha256(baseline_sha256) {
        return Err("uninstall transaction binding contains a noncanonical digest".to_string());
    }
    let material = format!(
        "voboost-uninstall-transaction-v1\n{inventory_sha256}\n{uninstaller_sha256}\n{baseline_sha256}\n"
    );
    Ok(sha256_hex(material.as_bytes()))
}

fn valid_file(size: u64, sha256: &str) -> bool {
    size > 0 && canonical_sha256(sha256)
}

pub fn parse_committed_inventory(bytes: &[u8]) -> Result<CommittedInventory, String> {
    let value: CommittedInventory = serde_json::from_slice(bytes)
        .map_err(|error| format!("parse install inventory: {error}"))?;
    let valid_version = !value.version.is_empty()
        && value.version.len() <= 128
        && value
            .version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
    let valid_timestamp = !value.committed_at.is_empty()
        && value.committed_at.len() <= 64
        && value
            .committed_at
            .bytes()
            .all(|byte| byte.is_ascii_digit() || b"-:TZ.+".contains(&byte));
    if value.schema_version != 1
        || value.phase != "committed"
        || !valid_version
        || !valid_timestamp
        || value.documents.len() != DOCUMENT_PATHS.len()
    {
        return Err("install inventory is not an exact committed schema-v1 document".to_string());
    }
    for (actual, expected_path) in value.documents.iter().zip(DOCUMENT_PATHS) {
        if actual.path != expected_path || !valid_file(actual.size, &actual.sha256) {
            return Err(format!(
                "install inventory document {} differs from {expected_path}",
                actual.path
            ));
        }
    }
    Ok(value)
}

fn signed_artifact(actual: &SignedArtifact, path: &str, role: &str) -> bool {
    signed_artifact_mode(actual, path, role, "0700")
}
fn signed_artifact_mode(actual: &SignedArtifact, path: &str, role: &str, mode: &str) -> bool {
    actual.path == path
        && actual.signature_role == role
        && valid_file(actual.size, &actual.sha256)
        && actual.uid == 0
        && actual.gid == 0
        && actual.mode == mode
        && !actual.context.is_empty()
        && actual.context.len() <= 128
        && actual.context.starts_with("u:object_r:")
}

fn parse_artifacts(bytes: &[u8]) -> Result<SystemArtifacts, String> {
    let value: SystemArtifacts = serde_json::from_slice(bytes)
        .map_err(|error| format!("parse system artifacts: {error}"))?;
    if value.schema_version != 1
        || value.root.path != ROOT_ZONE_PATH
        || value.root.marker_path != ROOT_ZONE_MARKER_PATH
        || value.root.marker_sha256 != ROOT_ZONE_MARKER_SHA256
        || value.init.path != RC_PATH
        || value.init.archive_path != RC_ARCHIVE_PATH
        || !valid_file(value.init.installed_size, &value.init.installed_sha256)
        || value.init.uid != 0
        || value.init.gid != 0
        || value.init.mode != "0644"
        || value.init.context.is_empty()
        || value.init.context.len() > 128
        || !value.init.context.starts_with("u:object_r:")
        || value.policy.path != POLICY_PATH
        || !canonical_sha256(&value.policy.installed_sha256)
        || !canonical_sha256(&value.policy.current_baseline_sha256)
        || !signed_artifact(&value.native.daemon, DAEMON_PATH, "daemon")
        || !signed_artifact(&value.native.inject, INJECT_PATH, "inject")
        || !signed_artifact(
            &value.native.installer,
            "/data/voboost/voboost-install",
            "install",
        )
        || !signed_artifact(&value.native.uninstaller, UNINSTALL_PATH, "uninstall")
        || !signed_artifact(&value.native.restore, RESTORE_PATH, "restore")
        || value.native.restore_manifest.path != RESTORE_MANIFEST_PATH
        || value.native.restore_manifest.signature_path != RESTORE_MANIFEST_SIGNATURE_PATH
        || value.native.restore_manifest.signature_role != "restore-manifest"
        || !valid_file(
            value.native.restore_manifest.size,
            &value.native.restore_manifest.sha256,
        )
        || !valid_file(
            value.native.restore_manifest.signature_size,
            &value.native.restore_manifest.signature_sha256,
        )
        || value.native.restore_manifest.signature_size != 64
        || !signed_artifact(&value.native.selinux, SELINUX_PATH, "selinux")
        || value.native.manifest.path != MANIFEST_PATH
        || value.native.manifest.signature_path != MANIFEST_SIGNATURE_PATH
        || value.native.manifest.signature_role != "release-catalog"
        || !valid_file(value.native.manifest.size, &value.native.manifest.sha256)
        || !valid_file(
            value.native.manifest.signature_size,
            &value.native.manifest.signature_sha256,
        )
        || !(2..=PAYLOAD_PATHS.len()).contains(&value.native.payload.len())
        || value.package.name != PACKAGE_NAME
        || value.package.version_code == 0
        || value.package.apk_size == 0
        || !canonical_sha256(&value.package.apk_sha256)
        || !canonical_sha256(&value.package.certificate_sha256)
        || value.app_op.package != PACKAGE_NAME
        || value.app_op.operation != APP_OP
        || value.app_op.installed_mode != "allow"
    {
        return Err("system artifacts are not the exact schema-v1 inventory".to_string());
    }
    if value.native.qnx.len() != QNX_RELAY_PATHS.len() {
        return Err("QNX relay inventory is incomplete".into());
    }
    for (actual, (path, role, mode)) in value.native.qnx.iter().zip(QNX_RELAY_PATHS) {
        if !signed_artifact_mode(actual, path, role, mode) {
            return Err(format!("QNX relay inventory differs at {path}"));
        }
    }
    let expected_payload: Vec<_> = PAYLOAD_PATHS
        .into_iter()
        .filter(|(path, _, _)| {
            value
                .native
                .payload
                .iter()
                .any(|actual| actual.path == *path)
        })
        .collect();
    if expected_payload.len() != value.native.payload.len()
        || PAYLOAD_PATHS
            .iter()
            .filter(|(_, _, component)| *component == "implant")
            .any(|(path, _, _)| {
                !value
                    .native
                    .payload
                    .iter()
                    .any(|actual| actual.path == *path)
            })
    {
        return Err("native payload inventory is incomplete or duplicated".into());
    }
    for (actual, (path, abi, component)) in value.native.payload.iter().zip(expected_payload) {
        if actual.path != path
            || actual.abi != abi
            || actual.component != component
            || actual.signature_role != "runtime"
            || !valid_file(actual.size, &actual.sha256)
        {
            return Err(format!(
                "native payload inventory differs at {}",
                actual.path
            ));
        }
    }
    Ok(value)
}

pub fn parse_policy_metadata(bytes: &[u8]) -> Result<PolicyMetadata, String> {
    if bytes.len() > 16 * 1024 {
        return Err("policy metadata exceeds bound".into());
    }
    let value: PolicyMetadata =
        serde_json::from_slice(bytes).map_err(|error| format!("parse policy metadata: {error}"))?;
    if value.schema_version != 2
        || value.path != POLICY_PATH
        || value.size == 0
        || value.size > 64 * 1024 * 1024
        || !canonical_sha256(&value.sha256)
        || value.mode.len() != 4
        || !value.mode.starts_with('0')
        || !value.mode.bytes().all(|byte| matches!(byte, b'0'..=b'7'))
        || value.context.is_empty()
        || value.context.len() > 128
        || !value.context.starts_with("u:object_r:")
        || !value
            .context
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_:,.-".contains(&byte))
        || !crate::mount_policy_transaction::valid_sidecars(&value.sidecars)
    {
        return Err("policy metadata is not the exact schema-v2 document".to_string());
    }
    Ok(value)
}

pub fn parse_committed_contract(
    inventory_bytes: &[u8],
    artifacts_bytes: &[u8],
    baseline_bytes: &[u8],
    policy_metadata_bytes: &[u8],
    system_state_bytes: &[u8],
    rc_archive_bytes: &[u8],
) -> Result<CommittedContract, String> {
    let inventory = parse_committed_inventory(inventory_bytes)?;
    let documents = [
        artifacts_bytes,
        baseline_bytes,
        policy_metadata_bytes,
        system_state_bytes,
        rc_archive_bytes,
    ];
    for (claim, bytes) in inventory.documents.iter().zip(documents) {
        if claim.size != bytes.len() as u64 || claim.sha256 != sha256_hex(bytes) {
            return Err(format!(
                "committed document {} differs from its digest",
                claim.path
            ));
        }
    }
    let artifacts = parse_artifacts(artifacts_bytes)?;
    let baseline: CurrentBaseline = serde_json::from_slice(baseline_bytes)
        .map_err(|error| format!("parse current baseline: {error}"))?;
    let policy_metadata = parse_policy_metadata(policy_metadata_bytes)?;
    let system_state: SystemState = serde_json::from_slice(system_state_bytes)
        .map_err(|error| format!("parse system state: {error}"))?;
    let expected_backup = baseline_backup_path(&baseline.policy_sha256)?;
    if baseline.schema_version != 1
        || baseline.backup_path != expected_backup
        || baseline.metadata_path != POLICY_META_PATH
        || baseline.policy_sha256 != policy_metadata.sha256
        || artifacts.policy.current_baseline_sha256 != baseline.policy_sha256
        || artifacts.init.installed_size != rc_archive_bytes.len() as u64
        || artifacts.init.installed_sha256 != sha256_hex(rc_archive_bytes)
        || system_state.schema_version != 1
        || system_state.root_prior_state != "absent"
        || system_state.init_prior_state != "absent"
        || system_state.package_prior_state != "absent"
        || system_state.package_version_code != artifacts.package.version_code
        || system_state.init_installed_sha256 != artifacts.init.installed_sha256
        || system_state.policy_prior_sha256 != baseline.policy_sha256
        || system_state.policy_installed_sha256 != artifacts.policy.installed_sha256
        || system_state.app_op_prior_mode != "absent"
        || system_state.app_op_installed_mode != artifacts.app_op.installed_mode
    {
        return Err("committed uninstall documents are not mutually consistent".to_string());
    }
    Ok(CommittedContract {
        inventory,
        artifacts,
        baseline,
        policy_metadata,
        system_state,
    })
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn combined_implant_inventory_requires_both_abis_and_rejects_extra_payloads() {
        let (_, documents) = committed_fixture();
        let mut value: serde_json::Value = serde_json::from_slice(&documents[0]).unwrap();
        value["native"]["payload"]
            .as_array_mut()
            .unwrap()
            .retain(|row| row["component"] == "implant");
        let encode = |value: &serde_json::Value| serde_json::to_vec(value).unwrap();
        parse_artifacts(&encode(&value)).unwrap();
        let mut missing = value.clone();
        missing["native"]["payload"].as_array_mut().unwrap().pop();
        assert!(parse_artifacts(&encode(&missing)).is_err());
        let mut duplicate = value.clone();
        duplicate["native"]["payload"][1] = duplicate["native"]["payload"][0].clone();
        assert!(parse_artifacts(&encode(&duplicate)).is_err());
        let mut foreign = value.clone();
        foreign["native"]["payload"][0]["path"] = "/data/voboost/foreign.so".into();
        assert!(parse_artifacts(&encode(&foreign)).is_err());
        let mut reversed = value;
        reversed["native"]["payload"]
            .as_array_mut()
            .unwrap()
            .reverse();
        assert!(parse_artifacts(&encode(&reversed)).is_err());
    }

    #[test]
    fn root_marker_bytes_match_the_committed_digest() {
        assert_eq!(sha256_hex(ROOT_ZONE_MARKER_BYTES), ROOT_ZONE_MARKER_SHA256);
    }

    #[test]
    fn qnx_relay_inventory_requires_exact_paths_order_roles_modes_and_ownership() {
        let (_, documents) = committed_fixture();
        parse_artifacts(&documents[0]).unwrap();
        let baseline: serde_json::Value = serde_json::from_slice(&documents[0]).unwrap();
        let mut variants = Vec::new();
        let mut missing = baseline.clone();
        missing["native"].as_object_mut().unwrap().remove("qnx");
        variants.push(missing);
        let mut short = baseline.clone();
        short["native"]["qnx"].as_array_mut().unwrap().pop();
        variants.push(short);
        let mut duplicate = baseline.clone();
        let row = duplicate["native"]["qnx"][0].clone();
        duplicate["native"]["qnx"][1] = row;
        variants.push(duplicate);
        for (field, value) in [
            ("path", serde_json::json!("/data/voboost/foreign")),
            ("signatureRole", serde_json::json!("install")),
            ("mode", serde_json::json!("0777")),
            ("uid", serde_json::json!(1000)),
            ("gid", serde_json::json!(1000)),
            ("sha256", serde_json::json!("bad")),
        ] {
            let mut bad = baseline.clone();
            bad["native"]["qnx"][0][field] = value;
            variants.push(bad);
        }
        let mut wrong_implant_mode = baseline.clone();
        wrong_implant_mode["native"]["qnx"][2]["mode"] = serde_json::json!("0700");
        variants.push(wrong_implant_mode);
        for bad in variants {
            assert!(parse_artifacts(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
    }

    fn committed_fixture() -> (Vec<u8>, [Vec<u8>; 5]) {
        let prior = "11".repeat(32);
        let installed = "22".repeat(32);
        let rc = b"# >>> voboost-daemon (do not edit)\n".to_vec();
        let payload = PAYLOAD_PATHS.map(|(path, abi, component)| {
            serde_json::json!({
                "path": path,
                "abi": abi,
                "component": component,
                "size": 1,
                "sha256": installed,
                "signatureRole": "runtime",
            })
        });
        let artifacts = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "root": {"path": ROOT_ZONE_PATH, "markerPath": ROOT_ZONE_MARKER_PATH, "markerSha256": ROOT_ZONE_MARKER_SHA256},
            "init": {"path": RC_PATH, "installedSize": rc.len(), "installedSha256": sha256_hex(&rc), "archivePath": RC_ARCHIVE_PATH, "uid": 0, "gid": 0, "mode": "0644", "context": "u:object_r:system_file:s0"},
            "policy": {"path": POLICY_PATH, "installedSha256": installed, "currentBaselineSha256": prior},
            "native": {
                "daemon": {"path": DAEMON_PATH, "size": 1, "sha256": installed, "signatureRole": "daemon", "uid":0, "gid":0, "mode":"0700", "context":"u:object_r:voboost_exec:s0"},
                "inject": {"path": INJECT_PATH, "size": 1, "sha256": installed, "signatureRole": "inject", "uid":0, "gid":0, "mode":"0700", "context":"u:object_r:voboost_exec:s0"},
                "installer": {"path": "/data/voboost/voboost-install", "size": 1, "sha256": installed, "signatureRole": "install", "uid":0, "gid":0, "mode":"0700", "context":"u:object_r:voboost_install_exec:s0"},
                "uninstaller": {"path": UNINSTALL_PATH, "size": 1, "sha256": installed, "signatureRole": "uninstall", "uid":0, "gid":0, "mode":"0700", "context":"u:object_r:voboost_uninstall_exec:s0"},
                "restore": {"path": RESTORE_PATH, "size": 1, "sha256": installed, "signatureRole": "restore", "uid":0, "gid":0, "mode":"0700", "context":"u:object_r:voboost_restore_exec:s0"},
                "restoreManifest": {"path": RESTORE_MANIFEST_PATH, "size": 1, "sha256": installed, "signaturePath": RESTORE_MANIFEST_SIGNATURE_PATH, "signatureSize": 64, "signatureSha256": installed, "signatureRole": "restore-manifest"},
                "selinux": {"path": SELINUX_PATH, "size": 1, "sha256": installed, "signatureRole": "selinux", "uid":0, "gid":0, "mode":"0700", "context":"u:object_r:voboost_selinux_exec:s0"},
                "manifest": {"path": MANIFEST_PATH, "size": 1, "sha256": installed, "signaturePath": MANIFEST_SIGNATURE_PATH, "signatureSize": 1, "signatureSha256": installed, "signatureRole": "release-catalog"},
                "qnx": QNX_RELAY_PATHS.map(|(path,role,mode)| serde_json::json!({"path":path,"size":1,"sha256":installed,"signatureRole":role,"uid":0,"gid":0,"mode":mode,"context":"u:object_r:voboost_data_file:s0"})),
                "payload": payload,
            },
            "package": {"name": PACKAGE_NAME, "versionCode": 1, "apkSize": 1, "apkSha256": installed, "certificateSha256": installed},
            "appOp": {"package": PACKAGE_NAME, "operation": APP_OP, "installedMode": "allow"},
        }))
        .unwrap();
        let baseline = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "policySha256": prior,
            "backupPath": baseline_backup_path(&prior).unwrap(),
            "metadataPath": POLICY_META_PATH,
        }))
        .unwrap();
        let metadata = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "path": POLICY_PATH,
            "size": 3,
            "sha256": prior,
            "uid": 0,
            "gid": 0,
            "mode": "0644",
            "context": "u:object_r:vendor_file:s0",
            "sidecars": crate::mount_policy_transaction::parse_sidecar_backup(include_bytes!("../../test/fixtures/policy-sidecars.json")).unwrap(),
        }))
        .unwrap();
        let state = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "rootPriorState": "absent",
            "initPriorState": "absent",
            "initInstalledSha256": sha256_hex(&rc),
            "policyPriorSha256": prior,
            "policyInstalledSha256": installed,
            "packagePriorState": "absent",
            "packageVersionCode": 1,
            "appOpPriorMode": "absent",
            "appOpInstalledMode": "allow",
        }))
        .unwrap();
        let documents = [artifacts, baseline, metadata, state, rc];
        let claims = documents
            .iter()
            .zip(DOCUMENT_PATHS)
            .map(|(bytes, path)| serde_json::json!({"path": path, "size": bytes.len(), "sha256": sha256_hex(bytes)}))
            .collect::<Vec<_>>();
        let inventory = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "phase": "committed",
            "version": "1.0.0-beta1",
            "committedAt": "2026-08-28T00:00:00Z",
            "documents": claims,
        }))
        .unwrap();
        (inventory, documents)
    }

    #[test]
    fn baseline_path_is_digest_addressed_and_strict() {
        let sha = "11".repeat(32);
        assert_eq!(
            baseline_backup_path(&sha).unwrap(),
            format!("/data/voboost/uninstall/baselines/{sha}/precompiled_sepolicy.orig")
        );
        assert!(baseline_backup_path(&"AA".repeat(32)).is_err());
        assert!(baseline_backup_path("../policy").is_err());
    }

    #[test]
    fn policy_metadata_rejects_unknown_or_noncanonical_fields() {
        let sha = "11".repeat(32);
        let sidecars = crate::mount_policy_transaction::parse_sidecar_backup(include_bytes!(
            "../../test/fixtures/policy-sidecars.json"
        ))
        .unwrap();
        let valid = serde_json::to_string(&serde_json::json!({"schemaVersion":2,"path":POLICY_PATH,"size":3,"sha256":sha,"uid":0,"gid":0,"mode":"0644","context":"u:object_r:vendor_file:s0","sidecars":sidecars})).unwrap();
        assert!(parse_policy_metadata(valid.as_bytes()).is_ok());
        assert!(parse_policy_metadata(valid.replace("0644", "644").as_bytes()).is_err());
        assert!(parse_policy_metadata(valid.replace("}", ",\"extra\":true}").as_bytes()).is_err());
    }

    #[test]
    fn exact_committed_contract_binds_every_document_hash_and_signature_role() {
        let (inventory, documents) = committed_fixture();
        let contract = parse_committed_contract(
            &inventory,
            &documents[0],
            &documents[1],
            &documents[2],
            &documents[3],
            &documents[4],
        )
        .unwrap();
        let transaction = uninstall_transaction_id(&contract, &inventory).unwrap();
        assert!(canonical_sha256(&transaction));
        assert_eq!(
            transaction,
            uninstall_transaction_id(&contract, &inventory).unwrap()
        );

        let substituted_role = String::from_utf8(documents[0].clone())
            .unwrap()
            .replace(
                "\"signatureRole\":\"selinux\"",
                "\"signatureRole\":\"daemon\"",
            )
            .into_bytes();
        assert!(parse_committed_contract(
            &inventory,
            &substituted_role,
            &documents[1],
            &documents[2],
            &documents[3],
            &documents[4],
        )
        .is_err());
        let substituted_restore_role = String::from_utf8(documents[0].clone())
            .unwrap()
            .replace(
                "\"signatureRole\":\"restore\"",
                "\"signatureRole\":\"uninstall\"",
            )
            .into_bytes();
        assert!(parse_committed_contract(
            &inventory,
            &substituted_restore_role,
            &documents[1],
            &documents[2],
            &documents[3],
            &documents[4],
        )
        .is_err());
        let mut substituted_rc = documents[4].clone();
        substituted_rc.push(b'!');
        assert!(parse_committed_contract(
            &inventory,
            &documents[0],
            &documents[1],
            &documents[2],
            &documents[3],
            &substituted_rc,
        )
        .is_err());
    }
}
