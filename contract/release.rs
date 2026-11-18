//! Canonical device-side product manifest and recovery authority.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, VerifyingKey};
use std::fmt;

use semver::Version;
use serde::de::{DeserializeOwned, Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const MANIFEST_NAME: &str = "voboost.json";
pub const MANIFEST_SIGNATURE_NAME: &str = "voboost.json.sig";
pub const RESTORE_NAME: &str = "restore.json";
pub const RESTORE_SIGNATURE_NAME: &str = "restore.json.sig";
pub const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_ARTIFACTS: usize = 1024;
pub const MAX_RELEASE_IDENTITY_BYTES: usize = 128;
pub const MAX_RESTORE_BYTES: usize = 354;
pub const MAX_VERSION_CODE: u64 = 2_100_000_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub release_identity: String,
    pub compatibility: Compatibility,
    pub artifacts: Vec<Artifact>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Compatibility {
    pub installer_protocol: u32,
    pub operation_protocol: u32,
    pub app_daemon_protocol: u32,
    pub agent_catalog_schema: u32,
    pub agent_entry_abi: u32,
    pub implant_abi: u32,
}

impl Compatibility {
    pub fn supports_schema_one(&self) -> bool {
        self.installer_protocol == 1
            && self.operation_protocol == 1
            && self.app_daemon_protocol == 1
            && self.agent_catalog_schema == 2
            && self.agent_entry_abi == 1
            && self.implant_abi == 1
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Artifact {
    pub role: ArtifactRole,
    pub file: String,
    pub size: u64,
    pub sha256: String,
    pub activation: Activation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_code: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abi: Option<Abi>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceMetadata>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceMetadata {
    pub owner: String,
    pub locale: String,
    pub target_package: String,
    pub compatibility_schema: u32,
    pub overlay_package: String,
    pub coverage_ledger: ResourceFile,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceFile {
    pub file: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactRole {
    App,
    Daemon,
    Inject,
    Install,
    Restore,
    Uninstall,
    Selinux,
    Init,
    RestoreAuthorization,
    RestoreSignature,
    Implant,
    Lsplant,
    AgentCatalog,
    AgentCatalogSignature,
    AgentCommon,
    AgentModule,
    QnxDaemon,
    QnxInit,
    QnxImplant,
    QnxRuntime,
    QnxAgentModule,
    ResourceApk,
    ResourceLedger,
    QnxResourcePack,
    QnxResourceLedger,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Activation {
    PackageInstaller,
    NativeRuntime,
    Init,
    RestoreAuthority,
    AgentGeneration,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Abi {
    #[serde(rename = "arm64-v8a")]
    Arm64V8a,
    #[serde(rename = "armeabi-v7a")]
    ArmeabiV7a,
    #[serde(rename = "qnx-aarch64")]
    QnxAarch64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreDocument {
    pub schema_version: u32,
    pub release_identity: String,
    pub source_definition_sha256: String,
    pub restorable_closure_sha256: String,
}

impl Manifest {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_MANIFEST_BYTES {
            return Err("voboost.json byte envelope is invalid".into());
        }
        let manifest: Self = parse_canonical(bytes, "voboost.json")?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 {
            return Err("unsupported voboost.json schemaVersion".into());
        }
        if self.release_identity.len() > MAX_RELEASE_IDENTITY_BYTES {
            return Err("releaseIdentity exceeds byte bound".into());
        }
        canonical_semver(&self.release_identity)?;
        if !self.compatibility.supports_schema_one() {
            return Err("unsupported compatibility contract".into());
        }
        if self.artifacts.is_empty() || self.artifacts.len() > MAX_ARTIFACTS {
            return Err("artifacts count is outside the supported bound".into());
        }
        let mut files = BTreeSet::new();
        let mut roles = BTreeMap::<ArtifactRole, usize>::new();
        let mut previous = None;
        for artifact in &self.artifacts {
            validate_basename(&artifact.file)?;
            if !files.insert(artifact.file.as_str()) {
                return Err(format!("duplicate artifact filename {}", artifact.file));
            }
            *roles.entry(artifact.role).or_default() += 1;
            if artifact.size == 0 || artifact.size > maximum_size(artifact.role) {
                return Err(format!("artifact {} has unsafe size", artifact.file));
            }
            if !lower_hash(&artifact.sha256) {
                return Err(format!("artifact {} has invalid sha256", artifact.file));
            }
            if (artifact.role, artifact.activation, artifact.abi) != classify(&artifact.file)? {
                return Err(format!(
                    "artifact {} metadata does not match its canonical filename",
                    artifact.file
                ));
            }
            let key = (role_rank(artifact.role), artifact.file.as_str());
            if previous.is_some_and(|value| value >= key) {
                return Err("artifacts are not in canonical role/name order".into());
            }
            previous = Some(key);
            if artifact.role == ArtifactRole::ResourceApk {
                let resource = artifact
                    .resource
                    .as_ref()
                    .ok_or("resource APK requires descriptor")?;
                let valid_package = |v: &str| {
                    v.len() <= 255
                        && v.split('.').count() >= 2
                        && v.split('.').all(|s| {
                            !s.is_empty()
                                && s.as_bytes()[0].is_ascii_alphabetic()
                                && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                        })
                };
                if !matches!(
                    (resource.owner.as_str(), resource.locale.as_str()),
                    ("i18n-ru", "ru") | ("i18n-en", "en")
                ) || !artifact
                    .file
                    .starts_with(&format!("resource-{}-", resource.owner))
                    || !valid_package(&resource.target_package)
                    || !valid_package(&resource.overlay_package)
                    || !resource
                        .overlay_package
                        .starts_with("ru.voboost.translation.")
                    || resource.target_package == resource.overlay_package
                    || resource.compatibility_schema != 1
                    || artifact.package_name.as_deref() != Some(resource.overlay_package.as_str())
                    || !artifact
                        .version_code
                        .is_some_and(|v| (1..=MAX_VERSION_CODE).contains(&v))
                    || !artifact
                        .certificate_sha256
                        .as_deref()
                        .is_some_and(lower_hash)
                {
                    return Err("resource APK identity rejected".into());
                }
                let ledger = &resource.coverage_ledger;
                validate_basename(&ledger.file)?;
                if ledger.size == 0
                    || ledger.size > 1024 * 1024
                    || !lower_hash(&ledger.sha256)
                    || !self.artifacts.iter().any(|a| {
                        a.file == ledger.file
                            && a.role == ArtifactRole::ResourceLedger
                            && a.size == ledger.size
                            && a.sha256 == ledger.sha256
                    })
                {
                    return Err("resource ledger absent or identity differs".into());
                }
            } else if artifact.resource.is_some() {
                return Err("resource descriptor on foreign artifact role".into());
            }
            let has_apk = artifact.package_name.is_some()
                || artifact.version_code.is_some()
                || artifact.certificate_sha256.is_some();
            if artifact.role == ArtifactRole::App {
                if artifact.package_name.as_deref() != Some("ru.voboost")
                    || !artifact
                        .version_code
                        .is_some_and(|value| (1..=MAX_VERSION_CODE).contains(&value))
                    || !artifact
                        .certificate_sha256
                        .as_deref()
                        .is_some_and(lower_hash)
                {
                    return Err("app artifact requires exact APK identity metadata".into());
                }
            } else if has_apk && artifact.role != ArtifactRole::ResourceApk {
                return Err("APK metadata is only allowed on role app".into());
            }
        }
        let mut overlay_packages = BTreeSet::new();
        for resource in self.artifacts.iter().filter_map(|a| a.resource.as_ref()) {
            if !overlay_packages.insert(resource.overlay_package.as_str()) {
                return Err("duplicate resource overlay package".into());
            }
        }
        for ledger in self
            .artifacts
            .iter()
            .filter(|a| a.role == ArtifactRole::ResourceLedger)
        {
            if self
                .artifacts
                .iter()
                .filter_map(|a| a.resource.as_ref())
                .filter(|r| r.coverage_ledger.file == ledger.file)
                .count()
                != 1
            {
                return Err("resource ledger must have exactly one resource APK owner".into());
            }
        }
        for artifact in self.artifacts.iter().filter(|a| {
            matches!(
                a.role,
                ArtifactRole::QnxResourcePack | ArtifactRole::QnxResourceLedger
            )
        }) {
            let (suffix, peer_suffix, peer_role) = if artifact.role == ArtifactRole::QnxResourcePack
            {
                (".kzb", ".json", ArtifactRole::QnxResourceLedger)
            } else {
                (".json", ".kzb", ArtifactRole::QnxResourcePack)
            };
            let stem = artifact
                .file
                .strip_suffix(suffix)
                .ok_or("QNX resource suffix rejected")?;
            let peer = format!("{stem}{peer_suffix}");
            if !self
                .artifacts
                .iter()
                .any(|a| a.file == peer && a.role == peer_role)
            {
                return Err("QNX resource requires exact same-stem pack and ledger".into());
            }
        }
        for (role, count) in roles {
            if !matches!(
                role,
                ArtifactRole::Implant
                    | ArtifactRole::Lsplant
                    | ArtifactRole::AgentModule
                    | ArtifactRole::QnxAgentModule
                    | ArtifactRole::ResourceApk
                    | ArtifactRole::ResourceLedger
                    | ArtifactRole::QnxResourcePack
                    | ArtifactRole::QnxResourceLedger
            ) && count != 1
            {
                return Err(format!("singleton role {role:?} appears {count} times"));
            }
        }
        for required in required_inventory() {
            if !files.contains(required) {
                return Err(format!("required artifact {required} is missing"));
            }
        }
        if !self
            .artifacts
            .iter()
            .any(|artifact| artifact.role == ArtifactRole::AgentModule)
        {
            return Err("at least one agent module DEX is required".into());
        }
        Ok(())
    }

    pub fn artifact(&self, file: &str) -> Result<&Artifact, String> {
        self.artifacts
            .iter()
            .find(|artifact| artifact.file == file)
            .ok_or_else(|| format!("voboost.json lacks {file}"))
    }

    pub fn app_artifact(&self) -> Result<&Artifact, String> {
        self.artifact("voboost-app.apk")
    }

    pub fn apk_version_code(&self) -> Result<u64, String> {
        self.app_artifact()?
            .version_code
            .ok_or_else(|| "voboost.json app versionCode is absent".to_string())
    }

    pub fn apk_certificate_sha256(&self) -> Result<&str, String> {
        self.app_artifact()?
            .certificate_sha256
            .as_deref()
            .ok_or_else(|| "voboost.json app certificateSha256 is absent".to_string())
    }

    pub fn agent_catalog_sha256(&self) -> Result<&str, String> {
        Ok(&self.artifact("agents.json")?.sha256)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn digest(&self) -> Result<String, String> {
        Ok(hex::encode(Sha256::digest(self.canonical_bytes()?)))
    }
}

impl RestoreDocument {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_RESTORE_BYTES {
            return Err("restore.json byte envelope is invalid".into());
        }
        let document: Self = parse_canonical(bytes, RESTORE_NAME)?;
        document.validate()?;
        Ok(document)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.release_identity.len() > MAX_RELEASE_IDENTITY_BYTES
            || canonical_semver(&self.release_identity).is_err()
            || !lower_hash(&self.source_definition_sha256)
            || !lower_hash(&self.restorable_closure_sha256)
        {
            return Err("restore.json is invalid".into());
        }
        Ok(())
    }
}

pub fn verify_manifest_signature(
    bytes: &[u8],
    signature: &[u8],
    public_key: &[u8; 32],
) -> Result<Manifest, String> {
    let signature = Signature::from_slice(signature)
        .map_err(|_| "voboost.json signature is not raw Ed25519".to_string())?;
    let key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| "voboost.json public key is invalid".to_string())?;
    key.verify_strict(bytes, &signature)
        .map_err(|_| "voboost.json signature is invalid".to_string())?;
    Manifest::parse(bytes)
}

pub fn verify_restore_authority(
    manifest: &Manifest,
    bytes: &[u8],
    signature: &[u8],
    public_key: &[u8; 32],
) -> Result<RestoreDocument, String> {
    let document = RestoreDocument::parse(bytes)?;
    if document.release_identity != manifest.release_identity
        || document.restorable_closure_sha256 != restorable_closure_sha256(manifest)?
    {
        return Err("restore.json does not bind the product manifest".into());
    }
    let signature = Signature::from_slice(signature)
        .map_err(|_| "restore.json signature is not raw Ed25519".to_string())?;
    let key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| "restore.json public key is invalid".to_string())?;
    key.verify_strict(bytes, &signature)
        .map_err(|_| "restore.json signature is invalid".to_string())?;
    Ok(document)
}

pub fn restorable_closure_sha256(manifest: &Manifest) -> Result<String, String> {
    let rows = manifest
        .artifacts
        .iter()
        .filter(|artifact| {
            !matches!(
                artifact.role,
                ArtifactRole::RestoreAuthorization | ArtifactRole::RestoreSignature
            )
        })
        .collect::<Vec<_>>();
    if rows.is_empty() {
        return Err("restorable closure is empty".into());
    }
    let bytes = serde_json::to_vec(&rows).map_err(|error| error.to_string())?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub fn required_inventory() -> BTreeSet<&'static str> {
    [
        "voboost-app.apk",
        "voboost-daemon",
        "voboost-inject",
        "voboost-install",
        "voboost-restore",
        "voboost-uninstall",
        "voboost-selinux",
        "voboost.rc",
        "restore.json",
        "restore.json.sig",
        "libimplant-arm64-v8a.so",
        "libimplant-armeabi-v7a.so",
        "agents.json",
        "agents.json.sig",
        "agent-common.dex",
        "voboost-cluster-daemon",
        "voboost-cluster-startup.sh",
        "libvoboost-cluster-inject.so",
        "libvoboost-runtime-cluster.so",
        "libagent-font-cyrillic.so",
    ]
    .into_iter()
    .collect()
}

pub fn classify(file: &str) -> Result<(ArtifactRole, Activation, Option<Abi>), String> {
    for (suffix, role) in [
        (".kzb", ArtifactRole::QnxResourcePack),
        (".json", ArtifactRole::QnxResourceLedger),
    ] {
        if let Some(stem) = file
            .strip_prefix("qnx-resource-i18n-ru-")
            .and_then(|s| s.strip_suffix(suffix))
        {
            if !stem.is_empty()
                && stem.len() <= 96
                && stem.split('-').all(|part| {
                    !part.is_empty()
                        && part
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                })
            {
                return Ok((role, Activation::AgentGeneration, Some(Abi::QnxAarch64)));
            }
        }
    }
    for (suffix, role) in [
        (".apk", ArtifactRole::ResourceApk),
        (".json", ArtifactRole::ResourceLedger),
    ] {
        if let Some(stem) = file
            .strip_prefix("resource-i18n-ru-")
            .and_then(|s| s.strip_suffix(suffix))
            .or_else(|| {
                let stem = file
                    .strip_prefix("resource-i18n-en-")?
                    .strip_suffix(suffix)?;
                voboost_contract_core::release::EN_RESOURCE_PROFILES
                    .contains(&stem)
                    .then_some(stem)
            })
        {
            if !stem.is_empty()
                && stem.len() <= 128
                && stem.split('-').all(|s| {
                    !s.is_empty()
                        && s.bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                })
            {
                return Ok((role, Activation::AgentGeneration, None));
            }
        }
    }
    let exact = match file {
        "voboost-cluster-daemon" => Some((
            ArtifactRole::QnxDaemon,
            Activation::NativeRuntime,
            Some(Abi::QnxAarch64),
        )),
        "voboost-cluster-startup.sh" => Some((ArtifactRole::QnxInit, Activation::Init, None)),
        "libvoboost-cluster-inject.so" => Some((
            ArtifactRole::QnxImplant,
            Activation::NativeRuntime,
            Some(Abi::QnxAarch64),
        )),
        "libvoboost-runtime-cluster.so" => Some((
            ArtifactRole::QnxRuntime,
            Activation::AgentGeneration,
            Some(Abi::QnxAarch64),
        )),
        "libagent-font-cyrillic.so" => Some((
            ArtifactRole::QnxAgentModule,
            Activation::AgentGeneration,
            Some(Abi::QnxAarch64),
        )),

        "voboost-app.apk" => Some((ArtifactRole::App, Activation::PackageInstaller, None)),
        "voboost-daemon" => Some((ArtifactRole::Daemon, Activation::NativeRuntime, None)),
        "voboost-inject" => Some((ArtifactRole::Inject, Activation::NativeRuntime, None)),
        "voboost-install" => Some((ArtifactRole::Install, Activation::NativeRuntime, None)),
        "voboost-restore" => Some((ArtifactRole::Restore, Activation::RestoreAuthority, None)),
        "voboost-uninstall" => Some((ArtifactRole::Uninstall, Activation::RestoreAuthority, None)),
        "voboost-selinux" => Some((ArtifactRole::Selinux, Activation::NativeRuntime, None)),
        "voboost.rc" => Some((ArtifactRole::Init, Activation::Init, None)),
        "restore.json" => Some((
            ArtifactRole::RestoreAuthorization,
            Activation::RestoreAuthority,
            None,
        )),
        "restore.json.sig" => Some((
            ArtifactRole::RestoreSignature,
            Activation::RestoreAuthority,
            None,
        )),
        "libimplant-arm64-v8a.so" => Some((
            ArtifactRole::Implant,
            Activation::NativeRuntime,
            Some(Abi::Arm64V8a),
        )),
        "libimplant-armeabi-v7a.so" => Some((
            ArtifactRole::Implant,
            Activation::NativeRuntime,
            Some(Abi::ArmeabiV7a),
        )),
        "liblsplant-arm64-v8a.so" => Some((
            ArtifactRole::Lsplant,
            Activation::NativeRuntime,
            Some(Abi::Arm64V8a),
        )),
        "liblsplant-armeabi-v7a.so" => Some((
            ArtifactRole::Lsplant,
            Activation::NativeRuntime,
            Some(Abi::ArmeabiV7a),
        )),
        "agents.json" => Some((
            ArtifactRole::AgentCatalog,
            Activation::AgentGeneration,
            None,
        )),
        "agents.json.sig" => Some((
            ArtifactRole::AgentCatalogSignature,
            Activation::AgentGeneration,
            None,
        )),
        "agent-common.dex" => Some((ArtifactRole::AgentCommon, Activation::AgentGeneration, None)),
        _ => None,
    };
    if let Some(value) = exact {
        return Ok(value);
    }
    if let Some(module) = file
        .strip_prefix("libagent-")
        .and_then(|value| value.strip_suffix(".so"))
    {
        if !module.is_empty()
            && module.split('-').all(|part| {
                !part.is_empty()
                    && part
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            })
        {
            return Ok((
                ArtifactRole::QnxAgentModule,
                Activation::AgentGeneration,
                Some(Abi::QnxAarch64),
            ));
        }
    }
    if let Some(module) = file
        .strip_prefix("agent-")
        .and_then(|value| value.strip_suffix(".dex"))
    {
        if !module.is_empty()
            && module.split('-').all(|segment| {
                !segment.is_empty()
                    && segment
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            })
        {
            return Ok((ArtifactRole::AgentModule, Activation::AgentGeneration, None));
        }
    }
    Err(format!("unknown product artifact {file:?}"))
}

fn role_rank(role: ArtifactRole) -> u8 {
    match role {
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
    }
}

fn maximum_size(role: ArtifactRole) -> u64 {
    match role {
        ArtifactRole::App => 128 * 1024 * 1024,
        ArtifactRole::ResourceApk => 16 * 1024 * 1024,
        ArtifactRole::ResourceLedger | ArtifactRole::QnxResourceLedger => 1024 * 1024,
        ArtifactRole::QnxResourcePack => 16 * 1024 * 1024,
        ArtifactRole::AgentCatalog | ArtifactRole::RestoreAuthorization => 4 * 1024 * 1024,
        ArtifactRole::AgentCatalogSignature | ArtifactRole::RestoreSignature => 65,
        _ => 64 * 1024 * 1024,
    }
}

fn validate_basename(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 255
        || matches!(value, "." | "..")
        || value.contains('/')
        || value.contains('\\')
        || value.contains('\0')
    {
        return Err("artifact file must be a non-special basename".into());
    }
    Ok(())
}

fn canonical_semver(value: &str) -> Result<Version, String> {
    let version = Version::parse(value).map_err(|_| "releaseIdentity is not SemVer".to_string())?;
    if version.to_string() != value {
        return Err("releaseIdentity is not canonical SemVer".into());
    }
    Ok(version)
}

pub fn lower_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn parse_canonical<T>(bytes: &[u8], label: &str) -> Result<T, String>
where
    T: DeserializeOwned + Serialize,
{
    if !bytes.ends_with(b"\n") || bytes[..bytes.len() - 1].ends_with(b"\n") {
        return Err(format!("{label} must end with exactly one LF"));
    }
    let value = serde_json::from_slice::<UniqueValue>(bytes)
        .map_err(|error| format!("parse {label}: {error}"))?
        .0;
    let parsed: T =
        serde_json::from_value(value).map_err(|error| format!("decode {label}: {error}"))?;
    let mut canonical = serde_json::to_vec(&parsed).map_err(|error| error.to_string())?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err(format!("{label} is not canonical"));
    }
    Ok(parsed)
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueVisitor).map(Self)
    }
}

struct UniqueVisitor;

impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueValue::deserialize(deserializer).map(|value| value.0)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueValue>()? {
            values.push(value.0);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some((key, value)) = map.next_entry::<String, UniqueValue>()? {
            if values.insert(key.clone(), value.0).is_some() {
                return Err(A::Error::custom(format!("duplicate object key {key:?}")));
            }
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    const VALID: &[u8] =
        include_bytes!("../test/fixtures/product-release/voboost/valid/minimal.json");

    #[test]
    fn shared_product_fixture_corpus_matches_canonical_parser() {
        assert!(Manifest::parse(VALID).is_ok());
        assert!(Manifest::parse(include_bytes!(
            "../test/fixtures/product-release/voboost/valid/version-code-max.json"
        ))
        .is_ok());
        for fixture in [
            include_bytes!("../test/fixtures/product-release/voboost/invalid/bad-agent-name.json")
                .as_slice(),
            include_bytes!("../test/fixtures/product-release/voboost/invalid/bad-filename.json")
                .as_slice(),
            include_bytes!("../test/fixtures/product-release/voboost/invalid/duplicate-key.json")
                .as_slice(),
            include_bytes!(
                "../test/fixtures/product-release/voboost/invalid/missing-app-metadata.json"
            )
            .as_slice(),
            include_bytes!("../test/fixtures/product-release/voboost/invalid/native-oversize.json")
                .as_slice(),
            include_bytes!(
                "../test/fixtures/product-release/voboost/invalid/noncanonical-semver.json"
            )
            .as_slice(),
            include_bytes!("../test/fixtures/product-release/voboost/invalid/unknown-field.json")
                .as_slice(),
            include_bytes!(
                "../test/fixtures/product-release/voboost/invalid/wrong-activation.json"
            )
            .as_slice(),
            include_bytes!(
                "../test/fixtures/product-release/voboost/invalid/version-code-zero.json"
            )
            .as_slice(),
            include_bytes!(
                "../test/fixtures/product-release/voboost/invalid/version-code-over-max.json"
            )
            .as_slice(),
        ] {
            assert!(Manifest::parse(fixture).is_err());
        }
    }

    #[test]
    fn product_manifest_signature_is_raw_and_exact_byte_bound() {
        use ed25519_dalek::{Signer, SigningKey};
        let key = SigningKey::from_bytes(&[7; 32]);
        let signature = key.sign(VALID).to_bytes();
        assert!(
            verify_manifest_signature(VALID, &signature, key.verifying_key().as_bytes()).is_ok()
        );
        let mut changed = VALID.to_vec();
        changed.push(b' ');
        assert!(
            verify_manifest_signature(&changed, &signature, key.verifying_key().as_bytes())
                .is_err()
        );
    }

    #[test]
    fn restore_fixture_is_canonical_but_requires_exact_product_binding() {
        let valid = include_bytes!("../test/fixtures/product-release/restore/valid.json");
        let invalid =
            include_bytes!("../test/fixtures/product-release/restore/invalid-bad-digest.json");
        assert!(RestoreDocument::parse(valid).is_ok());
        assert!(RestoreDocument::parse(invalid).is_err());
        let manifest = Manifest::parse(VALID).unwrap();
        let document = RestoreDocument::parse(valid).unwrap();
        assert_ne!(
            document.restorable_closure_sha256,
            restorable_closure_sha256(&manifest).unwrap()
        );
    }

    #[test]
    fn native_modules_share_one_repeatable_role_without_catalog_migration() {
        let mut manifest = Manifest::parse(VALID).unwrap();
        let mut module = manifest
            .artifacts
            .iter()
            .find(|row| row.role == ArtifactRole::QnxAgentModule)
            .unwrap()
            .clone();
        module.file = "libagent-zulu-status.so".into();
        manifest.artifacts.push(module);
        let canonical = manifest.canonical_bytes().unwrap();
        assert!(Manifest::parse(&canonical).is_ok());
        for file in [
            "libagent-.so",
            "libagent-Zulu.so",
            "libagent-zulu--status.so",
        ] {
            assert!(classify(file).is_err());
        }
        manifest.compatibility.agent_catalog_schema = 1;
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn imported_product_schemas_match_contract_bounds() {
        let product: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../test/fixtures/product-release/voboost.schema.json"
        ))
        .unwrap();
        let restore: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../test/fixtures/product-release/restore.schema.json"
        ))
        .unwrap();
        for schema in [&product, &restore] {
            assert_eq!(schema["type"], "object");
            assert_eq!(schema["additionalProperties"], false);
            assert_eq!(schema["properties"]["schemaVersion"]["const"], 1);
        }
        assert_eq!(
            product["properties"]["artifacts"]["maxItems"],
            MAX_ARTIFACTS
        );
        assert_eq!(
            product["$defs"]["artifact"]["properties"]["versionCode"]["maximum"],
            MAX_VERSION_CODE
        );
        assert_eq!(
            restore["properties"]["releaseIdentity"]["maxLength"],
            MAX_RELEASE_IDENTITY_BYTES
        );
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct BoundaryFixture {
        artifacts_max_items: usize,
        release_identity_max_bytes: usize,
        restore_max_bytes: usize,
        version_code_max: u64,
    }

    fn bounds() -> BoundaryFixture {
        serde_json::from_slice(include_bytes!(
            "../test/fixtures/product-release/bounds.json"
        ))
        .unwrap()
    }

    #[test]
    fn manifest_artifact_count_accepts_n_and_rejects_n_plus_one() {
        let bounds = bounds();
        assert_eq!(bounds.artifacts_max_items, MAX_ARTIFACTS);
        let mut manifest = Manifest::parse(VALID).unwrap();
        while manifest.artifacts.len() < MAX_ARTIFACTS {
            let index = manifest.artifacts.len();
            manifest.artifacts.push(Artifact {
                role: ArtifactRole::AgentModule,
                file: format!("agent-z{index:04}.dex"),
                size: 1,
                sha256: format!("{index:064x}"),
                activation: Activation::AgentGeneration,
                package_name: None,
                version_code: None,
                certificate_sha256: None,
                abi: None,
                resource: None,
            });
        }
        manifest
            .artifacts
            .sort_by_key(|artifact| (role_rank(artifact.role), artifact.file.clone()));
        assert!(manifest.validate().is_ok());
        manifest.artifacts.push(Artifact {
            role: ArtifactRole::AgentModule,
            file: "agent-zzzzz.dex".into(),
            size: 1,
            sha256: "f".repeat(64),
            activation: Activation::AgentGeneration,
            package_name: None,
            version_code: None,
            certificate_sha256: None,
            abi: None,
            resource: None,
        });
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn release_identity_length_accepts_n_and_rejects_n_plus_one() {
        let bounds = bounds();
        assert_eq!(
            bounds.release_identity_max_bytes,
            MAX_RELEASE_IDENTITY_BYTES
        );
        let mut manifest = Manifest::parse(VALID).unwrap();
        manifest.release_identity = format!("1.0.0-{}", "a".repeat(122));
        assert_eq!(manifest.release_identity.len(), MAX_RELEASE_IDENTITY_BYTES);
        assert!(manifest.validate().is_ok());
        manifest.release_identity.push('a');
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn version_code_accepts_product_max_and_rejects_zero_or_over_max() {
        assert_eq!(bounds().version_code_max, MAX_VERSION_CODE);
        assert!(Manifest::parse(include_bytes!(
            "../test/fixtures/product-release/voboost/valid/version-code-max.json"
        ))
        .is_ok());
        assert!(Manifest::parse(include_bytes!(
            "../test/fixtures/product-release/voboost/invalid/version-code-zero.json"
        ))
        .is_err());
        assert!(Manifest::parse(include_bytes!(
            "../test/fixtures/product-release/voboost/invalid/version-code-over-max.json"
        ))
        .is_err());
    }

    #[test]
    fn restore_envelope_accepts_n_and_rejects_n_plus_one() {
        let bounds = bounds();
        assert_eq!(bounds.restore_max_bytes, MAX_RESTORE_BYTES);
        let document = RestoreDocument {
            schema_version: 1,
            release_identity: format!("1.0.0-{}", "a".repeat(122)),
            source_definition_sha256: "b".repeat(64),
            restorable_closure_sha256: "c".repeat(64),
        };
        let mut bytes = serde_json::to_vec(&document).unwrap();
        bytes.push(b'\n');
        assert_eq!(bytes.len(), MAX_RESTORE_BYTES);
        assert!(RestoreDocument::parse(&bytes).is_ok());
        bytes.insert(bytes.len() - 1, b' ');
        assert_eq!(bytes.len(), MAX_RESTORE_BYTES + 1);
        assert!(RestoreDocument::parse(&bytes).is_err());
    }
}
