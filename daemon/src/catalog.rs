//! Strict first-release schema 2 agent release catalog.
//!
//! `agents.json` is a signed exact-byte trust document. Signature verification
//! always precedes parsing; no legacy manifest aliases or partial-entry
//! recovery exist in this module.

use std::collections::{HashMap, HashSet};

use anyhow::{bail, ensure, Context, Result};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config;
pub use voboost_contract::agent_catalog::StartupPriority;

pub const SCHEMA_VERSION: u32 = 2;
/// Authoritative exact-byte bound for signed `agents.json`: 1 MiB inclusive.
pub const MAX_CATALOG_BYTES: usize = config::MAX_PLAN_BYTES;
pub const MAX_AGENTS: usize = 64;
pub const MAX_AGENT_TARGETS: usize = 64;
pub const MAX_FILE_BYTES: u64 = 67_108_864;
pub const MAX_RELEASE_BYTES: u64 = 268_435_456;
pub const SIGNATURE_BYTES: usize = 64;
pub const MAX_TARGET_PROCESS_BYTES: usize = 255;
pub const MAX_AGENT_ID_BYTES: usize = 96;
pub const AGENT_ENTRY_ABI_SHA256: &str =
    "8be969ce42ac44bf8c47d60405d6e44e989640f07c867d6ba2e30f33b7acbb13";
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentCatalog {
    pub schema_version: u32,
    pub supported_abis: Vec<String>,
    pub agent_entry_abi: AgentEntryAbi,
    pub core: CatalogFile,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_runtime: Option<CatalogFile>,
    pub agents: Vec<CatalogAgent>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentEntryAbi {
    pub schema_version: u32,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogFile {
    pub file: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogAgent {
    pub id: String,
    /// Mounting kind: None (agent customer) or "executor". Executors are
    /// host-process components: not plan-gated, started once per process
    /// lifetime before the first desired-snapshot reconcile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Surfaces the executor serves (executor kind only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub surfaces: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub startup_priority: Option<StartupPriority>,
    pub targets: Vec<AgentTarget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings_tab: Option<SettingsTab>,
    pub status: Option<AgentStatus>,
    pub category: Option<String>,
    pub order: Option<i32>,
    pub activation: Option<Activation>,
    pub disables: Option<Vec<String>>,
    pub options: Option<Vec<AgentOption>>,
    pub title: Option<LocaleMap>,
    pub description: Option<LocaleMap>,
    pub applicability: Option<Applicability>,
}

impl CatalogAgent {
    pub fn is_executor(&self) -> bool {
        self.kind.as_deref() == Some("executor")
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettingsTab {
    pub tag: String,
    pub order: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentTarget {
    pub process: String,
    pub file: String,
    pub size: u64,
    pub sha256: String,
    pub platform: TargetPlatform,
    pub domain: TargetDomain,
    pub entry_abi: TargetAbi,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_class: Option<String>,
    pub boot: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum TargetPlatform {
    Android,
    Qnx,
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum TargetDomain {
    Android,
    Cluster,
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub enum TargetAbi {
    #[serde(rename = "android-java-v1")]
    AndroidJavaV1,
    #[serde(rename = "voboost-agent3-v1")]
    VoboostAgent3V1,
}
impl AgentTarget {
    pub fn is_android(&self) -> bool {
        self.platform == TargetPlatform::Android
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AgentStatus {
    Stable,
    Unstable,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum Activation {
    Checkbox {
        default: bool,
    },
    Config {
        key: String,
        value: String,
    },
    /// Always runs when its target process is injected; never a user toggle
    /// and never surfaced in the Settings projection. Deserialized strictly
    /// from `{"type":"technical"}` and fail-closed on any other shape.
    /// Declared as an empty struct variant because serde ignores
    /// `deny_unknown_fields` on unit variants of internally tagged enums.
    Technical {},
}

#[derive(Debug, Clone, Serialize)]
pub struct LocaleMap {
    pub en: String,
    pub ru: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zh: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentOption {
    pub key: String,
    #[serde(rename = "type")]
    pub option_type: String,
    pub default: String,
    pub values: Vec<AgentOptionValue>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentOptionValue {
    pub value: String,
    pub title: LocaleMap,
}

impl<'de> Deserialize<'de> for LocaleMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct LocaleVisitor;
        impl<'de> Visitor<'de> for LocaleVisitor {
            type Value = LocaleMap;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a locale map ordered en, ru, then optional zh")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let first: Option<String> = map.next_key()?;
                if first.as_deref() != Some("en") {
                    return Err(de::Error::custom("locale map must start with en"));
                }
                let en: String = map.next_value()?;
                let second: Option<String> = map.next_key()?;
                if second.as_deref() != Some("ru") {
                    return Err(de::Error::custom("locale map must contain ru second"));
                }
                let ru: String = map.next_value()?;
                let zh = match map.next_key::<String>()? {
                    None => None,
                    Some(key) if key == "zh" => Some(map.next_value()?),
                    Some(_) => return Err(de::Error::custom("locale map has an extra field")),
                };
                if map.next_key::<String>()?.is_some() {
                    return Err(de::Error::custom("locale map has an extra field"));
                }
                Ok(LocaleMap { en, ru, zh })
            }
        }
        deserializer.deserialize_map(LocaleVisitor)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Applicability {
    pub chip: Vec<String>,
    pub vehicle: Vec<String>,
    pub android: Vec<u8>,
    pub powertrain: Vec<String>,
    pub market: Vec<String>,
}

impl AgentCatalog {
    pub fn parse_verified(exact_bytes: &[u8], signature: &[u8]) -> Result<Self> {
        ensure!(
            exact_bytes.len() <= MAX_CATALOG_BYTES,
            "catalog exceeds byte bound"
        );
        ensure!(
            signature.len() == SIGNATURE_BYTES,
            "catalog signature must be raw 64-byte Ed25519"
        );
        let catalog = Self::parse(exact_bytes)?;
        ensure!(
            crate::trust::verify_signature(
                crate::trust::SignatureRole::AgentCatalog,
                exact_bytes,
                signature,
            ),
            "catalog signature rejected"
        );
        Ok(catalog)
    }

    pub fn parse(exact_bytes: &[u8]) -> Result<Self> {
        ensure!(
            exact_bytes.len() <= MAX_CATALOG_BYTES,
            "catalog exceeds byte bound"
        );
        voboost_contract::agent_catalog::AgentCatalog::parse(exact_bytes)
            .map_err(anyhow::Error::msg)
            .context("catalog differs from shared producer/installer framing")?;
        let catalog: Self =
            serde_json::from_slice(exact_bytes).context("catalog is not exact supported JSON")?;
        catalog.validate()?;
        Ok(catalog)
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_internal()
    }

    fn validate_internal(&self) -> Result<()> {
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "unsupported catalog schema"
        );
        ensure!(
            self.agent_entry_abi.schema_version == 1
                && self.agent_entry_abi.sha256 == AGENT_ENTRY_ABI_SHA256,
            "catalog AgentEntry ABI is incompatible with implant"
        );
        ensure!(
            !self.supported_abis.is_empty(),
            "supportedAbis must not be empty"
        );
        ensure!(
            unique(&self.supported_abis)
                && self
                    .supported_abis
                    .iter()
                    .all(|abi| matches!(abi.as_str(), "arm64-v8a" | "armeabi-v7a")),
            "invalid or duplicate supported ABI"
        );
        validate_file(&self.core)?;
        ensure!(
            self.core.file == "agent-common.dex",
            "core file must be agent-common.dex"
        );
        ensure!(
            !self.agents.is_empty() && self.agents.len() <= MAX_AGENTS,
            "invalid agent count"
        );

        let mut ids = HashSet::new();
        let mut files = HashMap::new();
        let mut casefold_files = HashSet::new();
        let mut total = self.core.size;

        casefold_files.insert(self.core.file.to_ascii_lowercase());

        let mut previous_order: Option<(i32, &str)> = None;
        let mut settings_tab_tags = HashSet::new();
        let mut settings_tab_orders = HashSet::new();
        for agent in &self.agents {
            validate_id(&agent.id, MAX_AGENT_ID_BYTES, true)?;
            ensure!(ids.insert(agent.id.as_str()), "duplicate agent id");
            ensure!(
                !agent.targets.is_empty() && agent.targets.len() <= MAX_AGENT_TARGETS,
                "invalid targets"
            );
            let mut target_processes = HashSet::new();
            for target in &agent.targets {
                validate_basename(&target.file)?;
                validate_size_digest(target.size, &target.sha256)?;
                match (target.platform, target.domain, target.entry_abi) {
                    (TargetPlatform::Android, TargetDomain::Android, TargetAbi::AndroidJavaV1) => {
                        if !(agent.id == "launcher" && target.process == "system_server") {
                            validate_process(&target.process)?;
                        }
                        ensure!(
                            target.file.starts_with("agent-") && target.file.ends_with(".dex"),
                            "Android target file is not a versionless agent DEX"
                        );
                        if agent.is_executor() {
                            validate_executor_entry_class(
                                target
                                    .entry_class
                                    .as_deref()
                                    .context("Android entryClass required")?,
                            )?;
                        } else {
                            validate_entry_class(
                                target
                                    .entry_class
                                    .as_deref()
                                    .context("Android entryClass required")?,
                            )?;
                        }
                    }
                    (TargetPlatform::Qnx, TargetDomain::Cluster, TargetAbi::VoboostAgent3V1) => {
                        ensure!(!agent.is_executor(), "native executor unsupported");
                        ensure!(
                            matches!(target.process.as_str(), "gauge" | "point" | "light"),
                            "unsupported QNX process"
                        );
                        ensure!(
                            target.file == format!("libagent-{}.so", agent.id),
                            "QNX target file is not a versionless agent ELF"
                        );
                        ensure!(target.entry_class.is_none(), "native target has entryClass");
                    }
                    _ => bail!("incompatible target platform/domain/entryAbi"),
                }
                ensure!(!target.boot, "boot target is unsupported");
                ensure!(
                    target_processes.insert((target.domain, target.process.as_str())),
                    "duplicate target process"
                );
                let identity = (
                    agent.id.as_str(),
                    target.size,
                    target.sha256.as_str(),
                    target.entry_class.as_deref(),
                    target.platform,
                    target.domain,
                    target.entry_abi,
                );
                if let Some(previous) = files.get(target.file.as_str()) {
                    ensure!(*previous == identity, "conflicting target file identity");
                } else {
                    ensure!(
                        casefold_files.insert(target.file.to_ascii_lowercase()),
                        "core or case-folded target file collision"
                    );
                    files.insert(target.file.as_str(), identity);
                    total = total
                        .checked_add(target.size)
                        .context("release size overflow")?;
                }
            }
            if agent.is_executor() {
                // Executor record: {id, target DEX identities, entryClass, surfaces}.
                // Everything agent-shaped must be absent; executors are never
                // plan-gated, displayed, or applicability-filtered.
                ensure!(
                    agent.status.is_none()
                        && agent.category.is_none()
                        && agent.order.is_none()
                        && agent.activation.is_none()
                        && agent.disables.is_none()
                        && agent.options.is_none()
                        && agent.title.is_none()
                        && agent.description.is_none()
                        && agent.applicability.is_none()
                        && agent.settings_tab.is_none(),
                    "executor entry carries agent-only fields: {}",
                    agent.id
                );
                ensure!(
                    !agent.surfaces.is_empty() && agent.surfaces.len() <= 16,
                    "invalid executor surfaces"
                );
                let mut surfaces = HashSet::new();
                for surface in &agent.surfaces {
                    validate_id(surface, 64, false).context("invalid executor surface")?;
                    ensure!(
                        surfaces.insert(surface.as_str()),
                        "duplicate executor surface"
                    );
                }
                continue;
            }
            // Agent (customer) record: every agent-shaped field is required.
            let category = agent
                .category
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("agent category is required: {}", agent.id))?;
            validate_id(category, 64, false)?;
            let order = agent
                .order
                .ok_or_else(|| anyhow::anyhow!("agent order is required: {}", agent.id))?;
            let current_order = (order, agent.id.as_str());
            ensure!(
                previous_order.is_none_or(|previous| previous < current_order),
                "catalog agents are not ordered by order then id"
            );
            previous_order = Some(current_order);
            let status = agent
                .status
                .ok_or_else(|| anyhow::anyhow!("agent status is required: {}", agent.id))?;
            let activation = agent
                .activation
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("agent activation is required: {}", agent.id))?;
            let disables = agent
                .disables
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("agent disables are required: {}", agent.id))?;
            ensure!(unique(disables), "duplicate disables");
            validate_locale(
                agent
                    .title
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("agent title is required: {}", agent.id))?,
            )?;
            validate_locale(
                agent.description.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("agent description is required: {}", agent.id)
                })?,
            )?;
            validate_activation(activation)?;
            validate_options(
                agent
                    .options
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("agent options are required: {}", agent.id))?,
            )?;
            let applicability = agent
                .applicability
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("agent applicability is required: {}", agent.id))?;
            if let Some(tab) = &agent.settings_tab {
                validate_id(&tab.tag, 64, false)?;
                ensure!(tab.tag != "voboost", "reserved settings tab tag");
                ensure!((1..=64).contains(&tab.order), "invalid settings tab order");
                ensure!(
                    agent.id != "settings",
                    "settings cannot declare an extension tab"
                );
                ensure!(
                    matches!(activation, Activation::Checkbox { .. }),
                    "settings tab owner must use checkbox activation"
                );
                ensure!(
                    settings_tab_tags.insert(tab.tag.as_str()),
                    "duplicate settings tab tag"
                );
                ensure!(
                    settings_tab_orders.insert(tab.order),
                    "duplicate settings tab order"
                );
            }
            if status == AgentStatus::Unstable {
                ensure!(
                    !matches!(activation, Activation::Checkbox { default: true }),
                    "unstable agent must default off"
                );
            }
            if self.schema_version == SCHEMA_VERSION && status == AgentStatus::Stable {
                ensure!(
                    STABLE_AGENT_IDS.contains(&agent.id.as_str()),
                    "unknown stable agent id"
                );
            }
            if agent.id == "settings" {
                ensure!(
                    matches!(
                        activation,
                        Activation::Config { key, value }
                            if key == "voboost-startup" && value == "interface"
                    ),
                    "settings must use the interface startup gate"
                );
            } else {
                // Technical activation is reserved for non-host agents; the
                // settings branch above already fails closed on it because
                // config activation is required there.
                ensure!(
                    !matches!(activation, Activation::Config { .. }),
                    "only the settings agent may use config activation"
                );
            }
            validate_applicability(applicability)?;
        }

        for agent in &self.agents {
            if let Some(disables) = &agent.disables {
                for disabled in disables {
                    ensure!(disabled != &agent.id, "agent disables itself");
                    ensure!(ids.contains(disabled.as_str()), "unknown disabled agent");
                }
            }
        }
        let has_native = self
            .agents
            .iter()
            .flat_map(|a| &a.targets)
            .any(|t| !t.is_android());
        ensure!(
            has_native == self.cluster_runtime.is_some(),
            "clusterRuntime must match QNX targets"
        );
        if let Some(runtime) = &self.cluster_runtime {
            validate_file(runtime)?;
            ensure!(
                runtime.file == "libvoboost-runtime-cluster.so",
                "invalid clusterRuntime file"
            );
            ensure!(
                casefold_files.insert(runtime.file.to_ascii_lowercase()),
                "runtime file collision"
            );
            total = total
                .checked_add(runtime.size)
                .context("release size overflow")?;
        }
        ensure!(
            total <= MAX_RELEASE_BYTES,
            "catalog release exceeds total size bound"
        );
        Ok(())
    }

    pub fn find(&self, id: &str) -> Option<&CatalogAgent> {
        self.agents.iter().find(|agent| agent.id == id)
    }

    pub fn has_target(&self, id: &str, process: &str) -> bool {
        self.find(id).is_some_and(|agent| {
            agent
                .targets
                .iter()
                .any(|target| target.is_android() && target.process == process)
        })
    }

    pub fn target(&self, id: &str, process: &str) -> Option<&AgentTarget> {
        self.find(id)?
            .targets
            .iter()
            .find(|target| target.is_android() && target.process == process)
    }

    pub fn ids_for_process(&self, process: &str) -> Vec<&str> {
        self.agents
            .iter()
            .filter(|agent| {
                agent
                    .targets
                    .iter()
                    .any(|target| target.is_android() && target.process == process)
            })
            .map(|agent| agent.id.as_str())
            .collect()
    }

    pub fn processes(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        self.agents
            .iter()
            .flat_map(|agent| agent.targets.iter())
            .filter(|target| target.is_android() && seen.insert(target.process.as_str()))
            .map(|target| target.process.clone())
            .collect()
    }

    pub fn digest(exact_bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(exact_bytes))
    }
}

// Exactly the release-profile.json stableAgents roster (the producer owns
// the roster; this constant is its daemon-side mirror). The
// stable_roster_matches_release_profile test fails the build when the two
// copies drift apart.
pub const STABLE_AGENT_IDS: [&str; 18] = [
    "settings",
    "font-cyrillic",
    "keyboard-ru",
    "keyboard-en",
    "launcher",
    "vehicle-drive-forced-ev",
    "vehicle-drive-pedestrian-warning",
    "phone",
    "media-apps",
    "media-popup-external-apps",
    "steering-media-app-switcher",
    "steering-media-session",
    "settings-engineering-menu",
    "login-activation-skip",
    "vehicle-display-auto-lift",
    "vehicle-drive-outing",
    "i18n-ru",
    "i18n-en",
];

fn validate_file(file: &CatalogFile) -> Result<()> {
    validate_basename(&file.file)?;
    validate_size_digest(file.size, &file.sha256)
}

fn validate_size_digest(size: u64, digest: &str) -> Result<()> {
    ensure!((1..=MAX_FILE_BYTES).contains(&size), "invalid file size");
    ensure!(is_sha256(digest), "invalid lowercase SHA-256");
    Ok(())
}

pub fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

pub fn validate_basename(value: &str) -> Result<()> {
    ensure!((1..=128).contains(&value.len()), "invalid basename length");
    let bytes = value.as_bytes();
    ensure!(
        bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit(),
        "invalid basename prefix"
    );
    ensure!(
        bytes.iter().all(|byte| byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'.' | b'_' | b'-')),
        "unsafe basename"
    );
    ensure!(value != "." && value != "..", "unsafe basename");
    let stem = value.split('.').next().unwrap_or(value);
    ensure!(
        !matches!(
            stem,
            "con"
                | "prn"
                | "aux"
                | "nul"
                | "com1"
                | "com2"
                | "com3"
                | "com4"
                | "com5"
                | "com6"
                | "com7"
                | "com8"
                | "com9"
                | "lpt1"
                | "lpt2"
                | "lpt3"
                | "lpt4"
                | "lpt5"
                | "lpt6"
                | "lpt7"
                | "lpt8"
                | "lpt9"
        ),
        "Windows-reserved basename"
    );
    Ok(())
}

pub fn validate_id(value: &str, max: usize, forbid_voboost: bool) -> Result<()> {
    ensure!((1..=max).contains(&value.len()), "invalid id length");
    let bytes = value.as_bytes();
    ensure!(bytes[0].is_ascii_lowercase(), "id must start lowercase");
    ensure!(
        bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-'),
        "invalid id"
    );
    if forbid_voboost {
        ensure!(!value.starts_with("voboost-"), "reserved agent id prefix");
    }
    Ok(())
}

/// Executor entry classes live anywhere under ru.voboost. (the ui.qinggan
/// executor sits outside the agents namespace by design).
fn validate_executor_entry_class(value: &str) -> Result<()> {
    ensure!(value.len() <= 255, "entry class too long");
    ensure!(
        value.starts_with("ru.voboost."),
        "executor entry class outside the voboost namespace"
    );
    ensure!(
        value.split('.').all(|part| {
            !part.is_empty()
                && part
                    .as_bytes()
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        }),
        "invalid executor entry class"
    );
    Ok(())
}

fn validate_entry_class(value: &str) -> Result<()> {
    ensure!(value.len() <= 255, "entry class too long");
    ensure!(
        value.starts_with("ru.voboost.agents.") && value.ends_with("Agent"),
        "entry class outside agent namespace"
    );
    ensure!(
        value.split('.').all(|part| {
            !part.is_empty()
                && part
                    .as_bytes()
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        }),
        "invalid entry class"
    );
    Ok(())
}

pub(crate) fn validate_process(value: &str) -> Result<()> {
    ensure!(
        (1..=MAX_TARGET_PROCESS_BYTES).contains(&value.len()),
        "invalid target process length"
    );
    let (package, suffix) = value
        .split_once(':')
        .map_or((value, None), |(p, s)| (p, Some(s)));
    ensure!(
        package.contains('.'),
        "target process must be an Android package"
    );
    ensure!(
        package.split('.').all(valid_process_component),
        "invalid package process"
    );
    if let Some(suffix) = suffix {
        ensure!(
            valid_process_component(suffix),
            "invalid private process suffix"
        );
        ensure!(
            !suffix.contains('.'),
            "private process suffix must be one component"
        );
    }
    Ok(())
}

fn valid_process_component(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && (bytes[0].is_ascii_lowercase() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

fn validate_locale(locale: &LocaleMap) -> Result<()> {
    for value in [&locale.en, &locale.ru] {
        ensure!((1..=512).contains(&value.len()), "invalid localized text");
    }
    if let Some(value) = &locale.zh {
        ensure!((1..=512).contains(&value.len()), "invalid localized text");
    }
    Ok(())
}

fn validate_activation(activation: &Activation) -> Result<()> {
    match activation {
        Activation::Checkbox { default: _ } => Ok(()),
        Activation::Config { key, value } => {
            ensure!(
                key == "voboost-startup",
                "unsupported activation config key"
            );
            ensure!(value == "interface", "unsupported activation config value");
            Ok(())
        }
        Activation::Technical {} => Ok(()),
    }
}

fn validate_options(options: &[AgentOption]) -> Result<()> {
    ensure!(options.len() <= 32, "too many agent options");
    let mut keys = HashSet::new();
    for option in options {
        validate_id(&option.key, 64, false)?;
        ensure!(keys.insert(option.key.as_str()), "duplicate option key");
        ensure!(option.option_type == "enum", "unsupported option type");
        ensure!(
            !option.values.is_empty() && option.values.len() <= 64,
            "invalid option value count"
        );
        ensure!(
            !option.default.is_empty() && option.default.len() <= 128,
            "invalid option default"
        );
        let mut values = HashSet::new();
        for value in &option.values {
            ensure!(
                !value.value.is_empty() && value.value.len() <= 128,
                "invalid option value"
            );
            ensure!(
                values.insert(value.value.as_str()),
                "duplicate option value"
            );
            validate_locale(&value.title)?;
        }
        ensure!(
            values.contains(option.default.as_str()),
            "option default is not listed"
        );
    }
    Ok(())
}

fn validate_applicability(value: &Applicability) -> Result<()> {
    validate_string_axis(&value.chip, &["8155", "nxp"])?;
    validate_string_axis(&value.vehicle, &["free", "dreamer"])?;
    validate_axis(&value.android, &[9, 11])?;
    validate_string_axis(&value.powertrain, &["ev", "hybrid"])?;
    validate_string_axis(&value.market, &["china", "global"])
}

fn validate_string_axis(values: &[String], allowed: &[&str]) -> Result<()> {
    ensure!(
        !values.is_empty() && unique(values),
        "invalid applicability axis"
    );
    if values
        .iter()
        .any(|value| !allowed.contains(&value.as_str()))
    {
        bail!("unknown applicability value");
    }
    Ok(())
}

fn validate_axis<T: Eq + std::hash::Hash>(values: &[T], allowed: &[T]) -> Result<()> {
    ensure!(
        !values.is_empty() && unique(values),
        "invalid applicability axis"
    );
    if values.iter().any(|value| !allowed.contains(value)) {
        bail!("unknown applicability value");
    }
    Ok(())
}

fn unique<T: Eq + std::hash::Hash>(values: &[T]) -> bool {
    let mut seen = HashSet::new();
    values.iter().all(|value| seen.insert(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chinese_locale_preserves_legacy_maps_and_rejects_malformed_extensions() {
        let legacy = r#"{"en":"Settings","ru":"Настройки"}"#;
        let parsed: LocaleMap = serde_json::from_str(legacy).unwrap();
        assert!(parsed.zh.is_none());
        assert_eq!(serde_json::to_string(&parsed).unwrap(), legacy);
        let chinese: LocaleMap =
            serde_json::from_str(r#"{"en":"Settings","ru":"Настройки","zh":"设置"}"#).unwrap();
        validate_locale(&chinese).unwrap();
        assert_eq!(chinese.zh.as_deref(), Some("设置"));
        for invalid in [
            r#"{"en":"Settings","ru":"Настройки","zh":null}"#,
            r#"{"en":"Settings","zh":"设置","ru":"Настройки"}"#,
            r#"{"en":"Settings","ru":"Настройки","zh":"设置","zh":"另一项"}"#,
            r#"{"en":"Settings","ru":"Настройки","zh":"设置","de":"Einstellungen"}"#,
        ] {
            assert!(serde_json::from_str::<LocaleMap>(invalid).is_err());
        }
        let empty: LocaleMap =
            serde_json::from_str(r#"{"en":"Settings","ru":"Настройки","zh":""}"#).unwrap();
        assert!(validate_locale(&empty).is_err());
    }

    const SHA: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn base_fixture_value() -> serde_json::Value {
        serde_json::from_str(&format!(
            r#"{{"schemaVersion":2,"supportedAbis":["arm64-v8a","armeabi-v7a"],"agentEntryAbi":{{"schemaVersion":1,"sha256":"{AGENT_ENTRY_ABI_SHA256}"}},"core":{{"file":"agent-common.dex","size":3,"sha256":"{SHA}"}},"agents":[{{"id":"settings","targets":[{{"platform":"android","domain":"android","entryAbi":"android-java-v1","process":"com.qinggan.app.setting","file":"agent-settings.dex","size":3,"sha256":"{SHA}","entryClass":"ru.voboost.agents.settings.SettingsAgent","boot":false}}],"status":"unstable","category":"interface","order":-1,"activation":{{"type":"config","key":"voboost-startup","value":"interface"}},"disables":[],"options":[],"title":{{"en":"Voboost","ru":"Voboost"}},"description":{{"en":"Settings","ru":"Settings"}},"applicability":{{"chip":["8155","nxp"],"vehicle":["free","dreamer"],"android":[9,11],"powertrain":["ev","hybrid"],"market":["china","global"]}}}}]}}"#
        ))
        .unwrap()
    }

    fn schema_1_fixture() -> serde_json::Value {
        base_fixture_value()
    }

    fn schema_1_bytes(value: &serde_json::Value) -> Vec<u8> {
        let mut bytes = match serde_json::from_value::<AgentCatalog>(value.clone()) {
            Ok(catalog) => serde_json::to_vec(&catalog).unwrap(),
            Err(_) => serde_json::to_vec(value).unwrap(),
        };
        bytes.push(b'\n');
        bytes
    }

    fn fixture() -> Vec<u8> {
        schema_1_bytes(&schema_1_fixture())
    }

    fn target_fixture(count: usize) -> serde_json::Value {
        serde_json::Value::Array(
            (0..count)
                .map(|index| {
                    serde_json::json!({
                        "platform":"android", "domain":"android", "entryAbi":"android-java-v1",
                        "process": format!("com.example.target{index}"),
                        "file": format!("agent-settings-{index}.dex"),
                        "size": 3,
                        "sha256": SHA,
                        "entryClass": "ru.voboost.agents.settings.SettingsAgent",
                        "boot": false,
                    })
                })
                .collect(),
        )
    }

    fn settings_tab_fixture() -> serde_json::Value {
        let mut value = schema_1_fixture();
        let agent = &mut value["agents"][0];
        agent["id"] = serde_json::json!("logs");
        agent["targets"][0]["file"] = serde_json::json!("agent-logs.dex");
        agent["targets"][0]["entryClass"] = serde_json::json!("ru.voboost.agents.logs.LogsAgent");
        agent["status"] = serde_json::json!("unstable");
        agent["order"] = serde_json::json!(34);
        agent["activation"] = serde_json::json!({"type": "checkbox", "default": false});
        agent["settingsTab"] = serde_json::json!({
            "tag": "logs",
            "order": 1
        });
        value
    }

    #[test]
    fn canonical_fixture_parses() {
        let catalog = AgentCatalog::parse(&fixture()).unwrap();
        assert_eq!(catalog.schema_version, 2);
        assert_eq!(catalog.agents[0].targets[0].file, "agent-settings.dex");
    }

    #[test]
    fn settings_tab_is_closed_unique_and_checkbox_owned() {
        let canonical = settings_tab_fixture();
        let parsed = AgentCatalog::parse(&schema_1_bytes(&canonical)).unwrap();
        let tab = parsed.agents[0].settings_tab.as_ref().unwrap();
        assert_eq!(tab.tag, "logs");

        for (field, value) in [
            ("tag", serde_json::json!("voboost")),
            ("order", serde_json::json!(0)),
        ] {
            let mut rejected = canonical.clone();
            rejected["agents"][0]["settingsTab"][field] = value;
            assert!(AgentCatalog::parse(&schema_1_bytes(&rejected)).is_err());
        }

        let mut config_owned = canonical.clone();
        config_owned["agents"][0]["activation"] =
            serde_json::json!({"type": "config", "key": "voboost-startup", "value": "interface"});
        assert!(AgentCatalog::parse(&schema_1_bytes(&config_owned)).is_err());

        let mut duplicate = canonical.clone();
        let mut second = duplicate["agents"][0].clone();
        second["id"] = serde_json::json!("logs-second");
        second["targets"][0]["file"] = serde_json::json!("agent-logs-second.dex");
        second["targets"][0]["entryClass"] =
            serde_json::json!("ru.voboost.agents.logs.LogsSecondAgent");
        second["order"] = serde_json::json!(35);
        duplicate["agents"].as_array_mut().unwrap().push(second);
        assert!(AgentCatalog::parse(&schema_1_bytes(&duplicate)).is_err());
    }

    #[test]
    fn shared_agent_module_accepts_exact_aliases_and_counts_unique_bytes() {
        let mut value = schema_1_fixture();
        let mut targets = Vec::new();
        for index in 0..5 {
            let mut target = value["agents"][0]["targets"][0].clone();
            target["process"] = serde_json::json!(format!("com.example.target{index}"));
            target["size"] = serde_json::json!(MAX_FILE_BYTES);
            targets.push(target);
        }
        value["agents"][0]["targets"] = serde_json::json!(targets);
        let catalog = AgentCatalog::parse(&schema_1_bytes(&value)).unwrap();
        assert_eq!(catalog.agents[0].targets.len(), 5);
        let repeated_bytes: u64 = catalog.agents[0]
            .targets
            .iter()
            .map(|target| target.size)
            .sum();
        assert!(repeated_bytes > MAX_RELEASE_BYTES);

        // Previously retained generations used one distinct file per target.
        value["agents"][0]["targets"] = target_fixture(51);
        AgentCatalog::parse(&schema_1_bytes(&value)).unwrap();
    }

    #[test]
    fn shared_agent_module_rejects_conflicting_identity_and_foreign_aliases() {
        for field in ["size", "sha256", "entryClass", "file", "process"] {
            let mut value = schema_1_fixture();
            let mut alias = value["agents"][0]["targets"][0].clone();
            alias["process"] = serde_json::json!("com.example.second");
            alias[field] = match field {
                "size" => serde_json::json!(4),
                "sha256" => serde_json::json!("f".repeat(64)),
                "entryClass" => serde_json::json!("ru.voboost.agents.settings.OtherAgent"),
                "file" => serde_json::json!("agent-Settings.dex"),
                "process" => value["agents"][0]["targets"][0]["process"].clone(),
                _ => unreachable!(),
            };
            value["agents"][0]["targets"]
                .as_array_mut()
                .unwrap()
                .push(alias);
            assert!(
                AgentCatalog::parse(&schema_1_bytes(&value)).is_err(),
                "{field}"
            );
        }
        let mut foreign = settings_tab_fixture();
        foreign["agents"][0]["targets"][0]["file"] = serde_json::json!("agent-settings.dex");
        foreign["agents"][0]["targets"][0]["entryClass"] =
            schema_1_fixture()["agents"][0]["targets"][0]["entryClass"].clone();
        let mut value = schema_1_fixture();
        value["agents"]
            .as_array_mut()
            .unwrap()
            .push(foreign["agents"][0].clone());
        let error = AgentCatalog::parse(&schema_1_bytes(&value))
            .unwrap_err()
            .to_string();
        assert!(error.contains("target file"), "{error}");

        for reserved in [
            "agent-common.dex",
            "agent-Common.dex",
            "agents.json",
            "generation.json",
        ] {
            let mut value = schema_1_fixture();
            value["agents"][0]["targets"][0]["file"] = serde_json::json!(reserved);
            assert!(
                AgentCatalog::parse(&schema_1_bytes(&value)).is_err(),
                "{reserved}"
            );
        }
    }

    #[test]
    fn catalog_byte_bound_is_exactly_one_mib_inclusive() {
        assert_eq!(MAX_CATALOG_BYTES, 1_048_576);
        let at_limit = vec![b' '; MAX_CATALOG_BYTES];
        let at_limit_error = AgentCatalog::parse(&at_limit).unwrap_err().to_string();
        assert!(!at_limit_error.contains("exceeds byte bound"));
        let over_limit = vec![b' '; MAX_CATALOG_BYTES + 1];
        assert!(AgentCatalog::parse(&over_limit)
            .unwrap_err()
            .to_string()
            .contains("exceeds byte bound"));
    }

    #[test]
    fn schema_1_has_no_firmware_or_apk_identity_fields() {
        let value = schema_1_fixture();
        assert!(AgentCatalog::parse(&schema_1_bytes(&value)).is_ok());

        for unsupported_schema in [0, 1, 3, 6] {
            let mut rejected = value.clone();
            rejected["schemaVersion"] = serde_json::json!(unsupported_schema);
            assert!(AgentCatalog::parse(&schema_1_bytes(&rejected)).is_err());
        }
        for (field, field_value) in [
            ("package", serde_json::json!("com.qinggan.app.setting")),
            (
                "baseApkPaths",
                serde_json::json!(["/system/app/Setting.apk"]),
            ),
            ("signerCertificateSha256", serde_json::json!(SHA)),
        ] {
            let mut rejected = value.clone();
            rejected["agents"][0]["targets"][0]
                .as_object_mut()
                .unwrap()
                .insert(field.to_string(), field_value);
            assert!(AgentCatalog::parse(&schema_1_bytes(&rejected)).is_err());
        }
        for field in [
            "targetIdentityProfiles",
            "firmwareProfiles",
            "buildFingerprints",
        ] {
            let mut rejected = value.clone();
            rejected
                .as_object_mut()
                .unwrap()
                .insert(field.to_string(), serde_json::json!([]));
            assert!(AgentCatalog::parse(&schema_1_bytes(&rejected)).is_err());
        }
    }

    #[test]
    fn schema_1_rejects_legacy_embedded_artifact_contract() {
        let canonical = schema_1_fixture();
        assert!(AgentCatalog::parse(&schema_1_bytes(&canonical)).is_ok());

        let mut legacy = canonical;
        legacy["artifacts"] = serde_json::json!([{
            "id": "voboost-ui:settings-abi-01",
            "file": "voboost-ui-settings-abi-01.apk",
            "type": "android-resources",
            "size": 3,
            "sha256": SHA
        }]);
        assert!(AgentCatalog::parse(&schema_1_bytes(&legacy)).is_err());
    }

    #[test]
    fn agent_target_count_enforces_n_minus_one_n_and_n_plus_one() {
        for count in [MAX_AGENT_TARGETS - 1, MAX_AGENT_TARGETS] {
            let mut value = schema_1_fixture();
            value["agents"][0]["targets"] = target_fixture(count);
            assert!(AgentCatalog::parse(&schema_1_bytes(&value)).is_ok());
        }

        let mut excessive = schema_1_fixture();
        excessive["agents"][0]["targets"] = target_fixture(MAX_AGENT_TARGETS + 1);
        assert!(AgentCatalog::parse(&schema_1_bytes(&excessive)).is_err());
    }

    #[test]
    fn agent_targets_remain_non_empty_unique_and_exact() {
        let mut empty = schema_1_fixture();
        empty["agents"][0]["targets"] = serde_json::json!([]);
        assert!(AgentCatalog::parse(&schema_1_bytes(&empty)).is_err());

        let mut duplicate = schema_1_fixture();
        let mut duplicate_target = duplicate["agents"][0]["targets"][0].clone();
        duplicate_target["file"] = serde_json::json!("agent-settings-second.dex");
        duplicate["agents"][0]["targets"] = serde_json::json!([
            duplicate["agents"][0]["targets"][0].clone(),
            duplicate_target
        ]);
        assert!(AgentCatalog::parse(&schema_1_bytes(&duplicate)).is_err());

        let mut boot = schema_1_fixture();
        boot["agents"][0]["targets"][0]["boot"] = serde_json::json!(true);
        assert!(AgentCatalog::parse(&schema_1_bytes(&boot)).is_err());

        let mut wildcard = schema_1_fixture();
        wildcard["agents"][0]["targets"][0]["process"] = serde_json::json!("com.example.*");
        assert!(AgentCatalog::parse(&schema_1_bytes(&wildcard)).is_err());

        let mut system_server = schema_1_fixture();
        system_server["agents"][0]["targets"][0]["process"] = serde_json::json!("system_server");
        assert!(AgentCatalog::parse(&schema_1_bytes(&system_server)).is_err());
    }

    #[test]
    fn current_release_stable_set_is_exactly_the_allowed_ids() {
        let mut current = schema_1_fixture();
        // agents[0] is the settings host and is itself a stable id, so the
        // settings roster entry flips it in place instead of pushing a
        // duplicate; every other stable id is added on top of it.
        let mut template = current["agents"][0].clone();
        template["status"] = serde_json::json!("unstable");
        for (order, id) in STABLE_AGENT_IDS.iter().enumerate() {
            if *id == "settings" {
                current["agents"][0]["status"] = serde_json::json!("stable");
                continue;
            }
            let mut agent = template.clone();
            agent["status"] = serde_json::json!("stable");
            agent["id"] = serde_json::json!(id);
            agent["targets"][0]["process"] =
                serde_json::json!(format!("com.example.target{order}"));
            agent["targets"][0]["file"] = serde_json::json!(format!("agent-{id}.dex"));
            agent["targets"][0]["entryClass"] =
                serde_json::json!(format!("ru.voboost.agents.fixture.Stable{order}Agent"));
            agent["order"] = serde_json::json!(order);
            agent["activation"] = serde_json::json!({"type": "checkbox", "default": false});
            current["agents"].as_array_mut().unwrap().push(agent);
        }
        let parsed = AgentCatalog::parse(&schema_1_bytes(&current)).unwrap();
        let stable: HashSet<&str> = parsed
            .agents
            .iter()
            .filter(|agent| agent.status == Some(AgentStatus::Stable))
            .map(|agent| agent.id.as_str())
            .collect();
        assert_eq!(stable.len(), STABLE_AGENT_IDS.len());
        assert!(STABLE_AGENT_IDS.iter().all(|id| stable.contains(id)));

        let mut partial = current.clone();
        partial["agents"].as_array_mut().unwrap().pop();
        assert!(AgentCatalog::parse(&schema_1_bytes(&partial)).is_ok());

        let mut unknown = current;
        let last = unknown["agents"].as_array().map(Vec::len).unwrap_or(0) - 1;
        unknown["agents"][last]["id"] = serde_json::json!("unknown-stable");
        assert!(AgentCatalog::parse(&schema_1_bytes(&unknown)).is_err());
    }

    #[test]
    fn stable_roster_matches_release_profile() {
        let profile_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../voboost-agents/release-profile.json");
        let profile = std::fs::read_to_string(&profile_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", profile_path.display()));
        let profile: serde_json::Value =
            serde_json::from_str(&profile).expect("parse release-profile.json");
        let roster = profile["stableAgents"]
            .as_array()
            .expect("release-profile.json has a stableAgents array");
        let roster: std::collections::BTreeSet<&str> = roster
            .iter()
            .map(|id| id.as_str().expect("stable agent id is a string"))
            .collect();
        let mirror: std::collections::BTreeSet<&str> = STABLE_AGENT_IDS.iter().copied().collect();
        assert_eq!(
            roster, mirror,
            "STABLE_AGENT_IDS must mirror release-profile.json stableAgents exactly"
        );
    }

    #[test]
    fn hermetic_producer_signature_authenticates_exact_schema_bytes() {
        use ed25519_dalek::{Signer, SigningKey};

        let exact_bytes = fixture();
        let signing = SigningKey::from_bytes(&[0x71; 32]);
        let signature = signing.sign(&exact_bytes);
        signing
            .verifying_key()
            .verify_strict(&exact_bytes, &signature)
            .unwrap();
        assert_eq!(
            AgentCatalog::parse(&exact_bytes).unwrap().schema_version,
            SCHEMA_VERSION
        );

        let mut changed = exact_bytes;
        changed[0] ^= 1;
        assert!(signing
            .verifying_key()
            .verify_strict(&changed, &signature)
            .is_err());
    }

    #[test]
    fn unknown_and_duplicate_fields_fail_closed() {
        let unknown = String::from_utf8(fixture()).unwrap().replacen(
            "\"schemaVersion\":1",
            "\"schemaVersion\":1,\"unexpected\":true",
            1,
        );
        assert!(AgentCatalog::parse(unknown.as_bytes()).is_err());
        let duplicate = String::from_utf8(fixture()).unwrap().replacen(
            "\"schemaVersion\":1",
            "\"schemaVersion\":1,\"schemaVersion\":1",
            1,
        );
        assert!(AgentCatalog::parse(duplicate.as_bytes()).is_err());
    }

    #[test]
    fn monolith_and_unresolved_artifact_fail_closed() {
        let monolith = String::from_utf8(fixture())
            .unwrap()
            .replace("agent-settings.dex", "settings.dex");
        assert!(AgentCatalog::parse(monolith.as_bytes()).is_err());
        let mut legacy = schema_1_fixture();
        legacy["agents"][0]["requiresArtifacts"] = serde_json::json!(["missing"]);
        assert!(AgentCatalog::parse(&schema_1_bytes(&legacy)).is_err());
    }

    #[test]
    fn technical_activation_is_strict_and_reserved_for_non_hosts() {
        let mut technical = schema_1_fixture();
        technical["agents"][0]["id"] = serde_json::json!("ui-qinggan");
        technical["agents"][0]["targets"][0]["file"] = serde_json::json!("agent-ui-qinggan.dex");
        technical["agents"][0]["targets"][0]["entryClass"] =
            serde_json::json!("ru.voboost.agents.uiqinggan.UiQingganAgent");
        technical["agents"][0]["activation"] = serde_json::json!({"type": "technical"});
        let parsed = AgentCatalog::parse(&schema_1_bytes(&technical)).unwrap();
        assert!(matches!(
            parsed.agents[0].activation,
            Some(Activation::Technical {})
        ));

        // Fail-closed on any other shape.
        for rejected_activation in [
            serde_json::json!({"type": "technical", "default": false}),
            serde_json::json!({"type": "Technical"}),
            serde_json::json!({"type": "technical", "key": "voboost-startup"}),
            serde_json::json!("technical"),
        ] {
            let mut rejected = technical.clone();
            rejected["agents"][0]["activation"] = rejected_activation;
            assert!(
                AgentCatalog::parse(&schema_1_bytes(&rejected)).is_err(),
                "non-exact technical shape must fail closed"
            );
        }

        // The config-only-for-hosts rule stays intact: config is still
        // rejected for non-host agents, and hosts may not be technical.
        let mut config_host = technical.clone();
        config_host["agents"][0]["activation"] =
            serde_json::json!({"type": "config", "key": "voboost-startup", "value": "interface"});
        assert!(AgentCatalog::parse(&schema_1_bytes(&config_host)).is_err());

        // Technical activation on the settings host fails closed: the host
        // must use the interface startup gate (config), so technical is
        // rejected by the same rule shape.
        let mut technical_settings = schema_1_fixture();
        technical_settings["agents"][0]["activation"] = serde_json::json!({"type": "technical"});
        assert!(AgentCatalog::parse(&schema_1_bytes(&technical_settings)).is_err());

        // Technical agents carry no settings tab (checkbox-owned rule).
        let mut tabbed = technical.clone();
        tabbed["agents"][0]["settingsTab"] = serde_json::json!({"tag": "ui", "order": 1});
        assert!(AgentCatalog::parse(&schema_1_bytes(&tabbed)).is_err());
    }

    #[test]
    fn lowercase_digest_and_flat_basename_are_strict() {
        assert!(is_sha256(SHA));
        assert!(!is_sha256(&SHA.to_uppercase()));
        assert!(validate_basename("keyboard-ru.dex").is_ok());
        assert!(validate_basename("../keyboard-ru.dex").is_err());
    }
    #[test]
    fn mixed_targets_are_one_agent_and_native_never_enters_android_dispatch() {
        let mut value = schema_1_fixture();
        value["agents"][0]["targets"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "platform":"qnx", "domain":"cluster", "entryAbi":"voboost-agent3-v1",
                "process":"gauge", "file":"libagent-settings.so", "size":3,
                "sha256":SHA, "boot":false
            }));
        value["clusterRuntime"] =
            serde_json::json!({"file":"libvoboost-runtime-cluster.so","size":3,"sha256":SHA});
        let catalog = AgentCatalog::parse(&schema_1_bytes(&value)).unwrap();
        assert_eq!(catalog.agents.len(), 1);
        assert!(!catalog.processes().contains(&"gauge".to_string()));
        assert!(catalog.target("settings", "gauge").is_none());
        for (field, invalid) in [
            ("platform", "android"),
            ("domain", "android"),
            ("entryAbi", "android-java-v1"),
            ("entryClass", ""),
        ] {
            let mut invalid_catalog = value.clone();
            invalid_catalog["agents"][0]["targets"][1][field] = serde_json::json!(invalid);
            assert!(
                AgentCatalog::parse(&schema_1_bytes(&invalid_catalog)).is_err(),
                "{field}"
            );
        }
        value.as_object_mut().unwrap().remove("clusterRuntime");
        assert!(AgentCatalog::parse(&schema_1_bytes(&value)).is_err());
    }
    #[test]
    fn schema_one_and_missing_platform_are_rejected() {
        let mut value = schema_1_fixture();
        value["schemaVersion"] = serde_json::json!(1);
        assert!(AgentCatalog::parse(&schema_1_bytes(&value)).is_err());
        value["schemaVersion"] = serde_json::json!(2);
        value["agents"][0]["targets"][0]
            .as_object_mut()
            .unwrap()
            .remove("platform");
        assert!(AgentCatalog::parse(&schema_1_bytes(&value)).is_err());
    }
    #[test]
    fn system_server_is_scoped_to_signed_launcher_target() {
        let mut value = schema_1_fixture();
        value["agents"][0]["id"] = serde_json::json!("launcher");
        value["agents"][0]["activation"] = serde_json::json!({"type":"checkbox","default":false});
        value["agents"][0]["targets"][0]["process"] = serde_json::json!("system_server");
        assert!(AgentCatalog::parse(&schema_1_bytes(&value))
            .unwrap()
            .has_target("launcher", "system_server"));
        value["agents"][0]["id"] = serde_json::json!("font-cyrillic");
        assert!(AgentCatalog::parse(&schema_1_bytes(&value)).is_err());
        value["agents"][0]["id"] = serde_json::json!("launcher");
        value["agents"][0]["targets"][0]["process"] = serde_json::json!("surfaceflinger");
        assert!(AgentCatalog::parse(&schema_1_bytes(&value)).is_err());
        assert!(validate_process("system_server").is_err());
    }
}
