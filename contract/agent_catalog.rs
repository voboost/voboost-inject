//! Shared exact-byte schema-one agent catalog framing.
//!
//! Release producer, installer and resident daemon must agree on field order,
//! compact JSON spelling, the terminal LF and ASCII-only Unicode escaping.

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

impl AgentCatalog {
    pub fn parse(exact_bytes: &[u8]) -> Result<Self, String> {
        if exact_bytes.len() > MAX_CATALOG_BYTES {
            return Err("catalog exceeds byte bound".into());
        }
        let catalog: Self = serde_json::from_slice(exact_bytes)
            .map_err(|error| format!("catalog is not exact schema-one JSON: {error}"))?;
        if catalog.schema_version != 2 {
            return Err("unsupported catalog schema".into());
        }
        if exact_bytes.last() != Some(&b'\n') {
            return Err("schema-one catalog must end in exactly one LF".into());
        }
        if catalog.canonical_bytes()? != exact_bytes {
            return Err("schema-one catalog is not compact canonical JSON".into());
        }
        Ok(catalog)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        let compact = serde_json::to_string(self)
            .map_err(|error| format!("serialize canonical schema-one catalog: {error}"))?;
        let mut canonical = String::with_capacity(compact.len() + 1);
        for character in compact.chars() {
            if character.is_ascii() {
                canonical.push(character);
            } else {
                let value = character as u32;
                if value <= 0xffff {
                    use std::fmt::Write as _;
                    write!(canonical, "\\u{value:04x}").expect("write to String");
                } else {
                    let scalar = value - 0x1_0000;
                    let high = 0xd800 + (scalar >> 10);
                    let low = 0xdc00 + (scalar & 0x3ff);
                    use std::fmt::Write as _;
                    write!(canonical, "\\u{high:04x}\\u{low:04x}").expect("write to String");
                }
            }
        }
        canonical.push('\n');
        Ok(canonical.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn startup_priority_round_trips_only_closed_signed_values() {
        for (name, priority) in [
            ("vehicle", StartupPriority::Vehicle),
            ("interface", StartupPriority::Interface),
            ("applications", StartupPriority::Applications),
            ("background", StartupPriority::Background),
        ] {
            let mut catalog = fixture();
            catalog.agents[0].startup_priority = Some(priority);
            let bytes = catalog.canonical_bytes().unwrap();
            assert_eq!(
                AgentCatalog::parse(&bytes).unwrap().agents[0].startup_priority,
                Some(priority)
            );
            let text = String::from_utf8(bytes).unwrap();
            for invalid in ["critical", "VEHICLE", "", "0"] {
                assert!(AgentCatalog::parse(
                    text.replace(
                        &format!("\"startupPriority\":\"{name}\""),
                        &format!("\"startupPriority\":\"{invalid}\"")
                    )
                    .as_bytes()
                )
                .is_err());
            }
        }
    }

    #[test]
    fn optional_chinese_locale_is_bounded_and_legacy_serialization_is_unchanged() {
        let legacy = r#"{"en":"Settings","ru":"Настройки"}"#;
        let parsed: super::LocaleMap = serde_json::from_str(legacy).unwrap();
        assert_eq!(serde_json::to_string(&parsed).unwrap(), legacy);
        let parsed: super::LocaleMap =
            serde_json::from_str(r#"{"en":"Settings","ru":"Настройки","zh":"设置"}"#).unwrap();
        assert_eq!(parsed.zh.as_deref(), Some("设置"));
        for invalid in [
            r#"{"en":"Settings","ru":"Настройки","zh":null}"#,
            r#"{"en":"Settings","ru":"Настройки","zh":""}"#,
            r#"{"en":"Settings","ru":"Настройки","de":"Settings"}"#,
        ] {
            assert!(serde_json::from_str::<super::LocaleMap>(invalid).is_err());
        }
    }
    use super::*;

    fn fixture() -> AgentCatalog {
        serde_json::from_value(serde_json::json!({
            "schemaVersion": 2,
            "supportedAbis": ["arm64-v8a"],
            "agentEntryAbi": {"schemaVersion": 1, "sha256": "11"},
            "core": {"file": "agent-common.dex", "size": 1, "sha256": "22"},
            "agents": [{
                "id": "settings",
                "targets": [{"platform":"android","domain":"android","entryAbi":"android-java-v1","process": "com.qinggan.app.setting", "file": "agent-settings.dex", "size": 1, "sha256": "33", "entryClass": "ru.voboost.SettingsAgent", "boot": false}],
                "status": "stable",
                "category": "interface",
                "order": 0,
                "activation": {"type": "config", "key": "voboost-startup", "value": "interface"},
                "disables": [],
                "options": [],
                "title": {"en": "Settings", "ru": "Настройки"},
                "description": {"en": "Settings", "ru": "Настройки"},
                "applicability": {"chip": ["8155"], "vehicle": ["free"], "android": [9], "powertrain": ["hybrid"], "market": ["china"]}
            }]
        }))
        .unwrap()
    }

    #[test]
    fn producer_field_order_ascii_escaping_and_terminal_lf_are_exact() {
        let bytes = fixture().canonical_bytes().unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.starts_with(
            "{\"schemaVersion\":2,\"supportedAbis\":[\"arm64-v8a\"],\"agentEntryAbi\":"
        ));
        assert!(text.contains("\\u041d\\u0430\\u0441\\u0442\\u0440\\u043e\\u0439\\u043a\\u0438"));
        assert!(text.ends_with("\n"));
        AgentCatalog::parse(&bytes).unwrap();
    }

    #[test]
    fn reordered_unknown_duplicate_and_noncanonical_catalogs_fail_closed() {
        let bytes = fixture().canonical_bytes().unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let reordered = text.replacen(
            "{\"schemaVersion\":2,\"supportedAbis\":",
            "{\"supportedAbis\":",
            1,
        );
        let reordered = reordered.replacen(
            "[\"arm64-v8a\"],\"agentEntryAbi\":",
            "[\"arm64-v8a\"],\"schemaVersion\":1,\"agentEntryAbi\":",
            1,
        );
        assert!(AgentCatalog::parse(reordered.as_bytes()).is_err());
        assert!(AgentCatalog::parse(
            text.replace("\"core\":{", "\"unknown\":0,\"core\":{")
                .as_bytes()
        )
        .is_err());
        assert!(AgentCatalog::parse(
            text.replace(
                "\"schemaVersion\":1,",
                "\"schemaVersion\":1,\"schemaVersion\":1,"
            )
            .as_bytes()
        )
        .is_err());
        assert!(AgentCatalog::parse(text.trim_end().as_bytes()).is_err());
    }
}
