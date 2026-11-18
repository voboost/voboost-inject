//! Shared exact-byte schema-one agent catalog framing.
//!
//! Release producer, installer and resident daemon must agree on field order,
//! compact JSON spelling, the terminal LF and ASCII-only Unicode escaping.

use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};

pub const MAX_CATALOG_BYTES: usize = 1024 * 1024;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StartupPriority {
    Vehicle,
    Interface,
    Applications,
    Background,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogAgent {
    pub id: String,
    /// None (agent customer) or "executor": host-process component that is
    /// not plan-gated and carries no user-facing metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub surfaces: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub startup_priority: Option<StartupPriority>,
    pub targets: Vec<AgentTarget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings_tab: Option<SettingsTab>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<AgentStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activation: Option<Activation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disables: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<AgentOption>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<LocaleMap>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<LocaleMap>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applicability: Option<Applicability>,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettingsTab {
    pub tag: String,
    pub order: u32,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
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
    /// and never surfaced in the Settings projection. Exact shape
    /// `{"type":"technical"}` (empty struct variant so that
    /// `deny_unknown_fields` is actually enforced by serde).
    Technical {},
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocaleMap {
    pub en: String,
    pub ru: String,
    #[serde(
        default,
        deserialize_with = "optional_locale_text",
        skip_serializing_if = "Option::is_none"
    )]
    pub zh: Option<String>,
}

fn optional_locale_text<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if !(1..=512).contains(&value.len()) {
        return Err(serde::de::Error::custom("invalid localized text"));
    }
    Ok(Some(value))
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Applicability {
    pub chip: Vec<String>,
    pub vehicle: Vec<String>,
    pub android: Vec<u8>,
    pub powertrain: Vec<String>,
    pub market: Vec<String>,
}
