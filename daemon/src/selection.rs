//! Strict first-release schema 1 VehicleProfile and agent selection receipt.
//!
//! The receipt is deterministic producer output, not a trust root. The daemon
//! compares it with root-owned facts and recomputes every applicability result.

use std::collections::HashSet;

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::catalog::{AgentCatalog, Applicability};

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_SELECTION_BYTES: usize = 262_144;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelectionReceipt {
    pub schema_version: u32,
    pub catalog_sha256: String,
    pub facts: VehicleProfile,
    pub agents: Vec<AgentSelection>,
}

pub use voboost_shared::vehicle_profile::{
    AndroidVersion, Chip, Fact, Known, Market, Powertrain, Unknown, UnknownReason, Vehicle,
    VehicleProfile, VehicleProfileDocument, MAX_VEHICLE_PROFILE_BYTES,
    VEHICLE_PROFILE_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentSelection {
    pub id: String,
    pub result: ApplicabilityResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_reasons: Option<Vec<UnknownAxis>>,
}

/// One unknown-axis entry of an `unknown` result: `{axis, reason}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnknownAxis {
    pub axis: Axis,
    pub reason: UnknownReason,
}

/// The five profile axes, in the fixed canonical order used by every
/// `unknownReasons` array.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Axis {
    Chip,
    Vehicle,
    Android,
    Powertrain,
    Market,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApplicabilityResult {
    Supported,
    Unknown,
    Unsupported,
}

#[derive(Debug, Clone)]
pub struct VerifiedSelection {
    pub receipt: SelectionReceipt,
    pub exact_bytes: Vec<u8>,
    pub sha256: String,
    pub selected_agent_ids: Vec<String>,
}

impl SelectionReceipt {
    pub fn parse_canonical(exact_bytes: &[u8]) -> Result<Self> {
        ensure!(
            exact_bytes.len() <= MAX_SELECTION_BYTES,
            "selection exceeds byte bound"
        );
        let receipt: Self =
            serde_json::from_slice(exact_bytes).context("selection is not exact supported JSON")?;
        ensure!(
            receipt.schema_version == SCHEMA_VERSION,
            "unsupported selection schema"
        );
        let canonical = serde_json::to_vec(&receipt).context("serialize canonical selection")?;
        ensure!(
            canonical == exact_bytes,
            "selection is not canonical compact JSON or has noncanonical field order"
        );
        Ok(receipt)
    }

    pub fn verify(
        exact_bytes: &[u8],
        catalog: &AgentCatalog,
        catalog_sha256: &str,
        root_facts: &VehicleProfile,
    ) -> Result<VerifiedSelection> {
        Self::verify_impl(exact_bytes, catalog, catalog_sha256, root_facts)
    }

    fn verify_impl(
        exact_bytes: &[u8],
        catalog: &AgentCatalog,
        catalog_sha256: &str,
        root_facts: &VehicleProfile,
    ) -> Result<VerifiedSelection> {
        let receipt = Self::parse_canonical(exact_bytes)?;
        ensure!(
            receipt.catalog_sha256 == catalog_sha256,
            "selection catalog digest mismatch"
        );
        ensure!(
            &receipt.facts == root_facts,
            "selection facts differ from root facts"
        );
        ensure!(
            receipt.agents.len() == catalog.agents.len(),
            "selection does not cover exact catalog agent set"
        );
        let mut seen = HashSet::new();
        let mut selected_agent_ids = Vec::new();
        for (entry, agent) in receipt.agents.iter().zip(&catalog.agents) {
            ensure!(
                entry.id == agent.id,
                "selection order or agent set differs from catalog"
            );
            ensure!(seen.insert(entry.id.as_str()), "duplicate selection result");
            // Executors are not applicability-filtered: they always install.
            let recomputed = if agent.is_executor() {
                ApplicabilityResult::Supported
            } else {
                evaluate(
                    agent.applicability.as_ref().expect("validated catalog"),
                    root_facts,
                )
            };
            ensure!(
                entry.result == recomputed,
                "selection applicability result mismatch"
            );
            if recomputed == ApplicabilityResult::Unknown {
                ensure!(
                    entry.unknown_reasons.as_deref() == Some(unknown_axes(root_facts).as_slice()),
                    "selection unknownReasons differ from the root facts"
                );
            } else {
                ensure!(
                    entry.unknown_reasons.is_none(),
                    "unknownReasons are only valid on unknown results"
                );
            }
            if matches!(
                recomputed,
                ApplicabilityResult::Supported | ApplicabilityResult::Unknown
            ) {
                selected_agent_ids.push(agent.id.clone());
            }
        }
        Ok(VerifiedSelection {
            receipt,
            exact_bytes: exact_bytes.to_vec(),
            sha256: digest(exact_bytes),
            selected_agent_ids,
        })
    }

    /// Recompute the canonical receipt expected from the app producer using
    /// the verified catalog and root-owned facts. The daemon uses this helper
    /// for parity and tests; activation verifies the exact app-written bytes.
    /// Every `unknown` result carries one `{axis, reason}` entry per unknown
    /// axis in the fixed axis order.
    pub fn compute(
        catalog: &AgentCatalog,
        catalog_sha256: &str,
        root_facts: &VehicleProfile,
    ) -> Result<VerifiedSelection> {
        Self::compute_impl(catalog, catalog_sha256, root_facts)
    }

    fn compute_impl(
        catalog: &AgentCatalog,
        catalog_sha256: &str,
        root_facts: &VehicleProfile,
    ) -> Result<VerifiedSelection> {
        let reasons = unknown_axes(root_facts);
        let agents = catalog
            .agents
            .iter()
            .map(|agent| {
                let result = if agent.is_executor() {
                    ApplicabilityResult::Supported
                } else {
                    evaluate(
                        agent.applicability.as_ref().expect("validated catalog"),
                        root_facts,
                    )
                };
                let unknown_reasons =
                    (result == ApplicabilityResult::Unknown).then(|| reasons.clone());
                AgentSelection {
                    id: agent.id.clone(),
                    result,
                    unknown_reasons,
                }
            })
            .collect();
        let receipt = Self {
            schema_version: SCHEMA_VERSION,
            catalog_sha256: catalog_sha256.to_string(),
            facts: root_facts.clone(),
            agents,
        };
        let exact_bytes = serde_json::to_vec(&receipt).context("serialize computed selection")?;
        Self::verify_impl(&exact_bytes, catalog, catalog_sha256, root_facts)
    }
}

/// The `{axis, reason}` entries for the currently unknown axes, in the fixed
/// canonical order chip, vehicle, android, powertrain, market.
pub fn unknown_axes(facts: &VehicleProfile) -> Vec<UnknownAxis> {
    let mut axes = Vec::new();
    macro_rules! push_unknown {
        ($axis:expr, $fact:expr) => {
            if let Fact::Unknown(Unknown { unknown }) = $fact {
                axes.push(UnknownAxis {
                    axis: $axis,
                    reason: *unknown,
                });
            }
        };
    }
    push_unknown!(Axis::Chip, &facts.chip);
    push_unknown!(Axis::Vehicle, &facts.vehicle);
    push_unknown!(Axis::Android, &facts.android);
    push_unknown!(Axis::Powertrain, &facts.powertrain);
    push_unknown!(Axis::Market, &facts.market);
    axes
}

pub fn evaluate(applicability: &Applicability, facts: &VehicleProfile) -> ApplicabilityResult {
    let outcomes = [
        contains_fact(&applicability.chip, &facts.chip, Chip::as_str),
        contains_fact(&applicability.vehicle, &facts.vehicle, Vehicle::as_str),
        contains_fact(
            &applicability.android,
            &facts.android,
            AndroidVersion::as_u8,
        ),
        contains_fact(
            &applicability.powertrain,
            &facts.powertrain,
            Powertrain::as_str,
        ),
        contains_fact(&applicability.market, &facts.market, Market::as_str),
    ];
    if outcomes.contains(&AxisResult::Mismatch) {
        ApplicabilityResult::Unsupported
    } else if outcomes.contains(&AxisResult::Unknown) {
        ApplicabilityResult::Unknown
    } else {
        ApplicabilityResult::Supported
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AxisResult {
    Match,
    Mismatch,
    Unknown,
}

fn contains_fact<T, U: PartialEq>(allowed: &[U], fact: &Fact<T>, map: fn(T) -> U) -> AxisResult
where
    T: Copy,
{
    match fact {
        Fact::Known(Known { value }) if allowed.contains(&map(*value)) => AxisResult::Match,
        Fact::Known(_) => AxisResult::Mismatch,
        Fact::Unknown(_) => AxisResult::Unknown,
    }
}

pub fn generation_id(catalog_sha256: &str, selection_sha256: &str) -> Result<String> {
    ensure!(
        crate::catalog::is_sha256(catalog_sha256) && crate::catalog::is_sha256(selection_sha256),
        "generation inputs must be lowercase SHA-256"
    );
    let input = format!("{catalog_sha256}\n{selection_sha256}\n");
    Ok(digest(input.as_bytes()))
}

pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn facts() -> VehicleProfile {
        VehicleProfile {
            chip: Fact::Known(Known {
                value: Chip::Qualcomm8155,
            }),
            vehicle: Fact::Unknown(Unknown {
                unknown: UnknownReason::ProbeUnavailable,
            }),
            android: Fact::Known(Known {
                value: AndroidVersion::Nine,
            }),
            powertrain: Fact::Known(Known {
                value: Powertrain::Hybrid,
            }),
            market: Fact::Known(Known {
                value: Market::China,
            }),
        }
    }

    fn applicability() -> Applicability {
        Applicability {
            chip: vec!["8155".to_string()],
            vehicle: vec!["free".to_string(), "dreamer".to_string()],
            android: vec![9],
            powertrain: vec!["hybrid".to_string()],
            market: vec!["china".to_string()],
        }
    }

    #[test]
    fn known_mismatch_wins_over_unknown() {
        let mut value = applicability();
        value.market = vec!["global".to_string()];
        assert_eq!(evaluate(&value, &facts()), ApplicabilityResult::Unsupported);
    }

    #[test]
    fn no_mismatch_with_unknown_is_unknown() {
        assert_eq!(
            evaluate(&applicability(), &facts()),
            ApplicabilityResult::Unknown
        );
    }

    #[test]
    fn exact_all_known_match_is_supported() {
        let mut value = facts();
        value.vehicle = Fact::Known(Known {
            value: Vehicle::Free,
        });
        assert_eq!(
            evaluate(&applicability(), &value),
            ApplicabilityResult::Supported
        );
    }

    #[test]
    fn canonical_receipt_rejects_whitespace_and_newline() {
        let compact = format!(
            r#"{{"schemaVersion":1,"catalogSha256":"{SHA}","facts":{{"chip":{{"value":"8155"}},"vehicle":{{"unknown":"probe-unavailable"}},"android":{{"value":9}},"powertrain":{{"value":"hybrid"}},"market":{{"value":"china"}}}},"agents":[]}}"#
        );
        assert!(SelectionReceipt::parse_canonical(compact.as_bytes()).is_ok());
        for unsupported_schema in [0, 2] {
            let invalid = compact.replacen(
                "\"schemaVersion\":1",
                &format!("\"schemaVersion\":{unsupported_schema}"),
                1,
            );
            assert!(SelectionReceipt::parse_canonical(invalid.as_bytes()).is_err());
        }
        assert!(SelectionReceipt::parse_canonical(format!("{compact}\n").as_bytes()).is_err());
        assert!(SelectionReceipt::parse_canonical(
            compact
                .replacen("\"schemaVersion\":1", "\"schemaVersion\": 1", 1)
                .as_bytes()
        )
        .is_err());
    }

    #[test]
    fn generation_id_uses_frozen_ascii_formula() {
        assert_eq!(
            generation_id(SHA, SHA).unwrap(),
            digest(format!("{SHA}\n{SHA}\n").as_bytes())
        );
    }

    #[test]
    fn same_catalog_with_changed_root_facts_has_distinct_selection_and_generation_identity() {
        let catalog = catalog();
        let first_facts = facts();
        let mut changed_facts = first_facts.clone();
        changed_facts.vehicle = Fact::Known(Known {
            value: Vehicle::Free,
        });
        let first = SelectionReceipt::compute(&catalog, SHA, &first_facts).unwrap();
        let changed = SelectionReceipt::compute(&catalog, SHA, &changed_facts).unwrap();
        assert_ne!(first.sha256, changed.sha256);
        assert_ne!(
            generation_id(SHA, &first.sha256).unwrap(),
            generation_id(SHA, &changed.sha256).unwrap()
        );
    }

    fn catalog() -> AgentCatalog {
        let value: serde_json::Value = serde_json::from_str(&format!(
                r#"{{"schemaVersion":2,"supportedAbis":["arm64-v8a"],"agentEntryAbi":{{"schemaVersion":1,"sha256":"{}"}},"core":{{"file":"agent-common.dex","size":1,"sha256":"{}"}},"agents":[{{"id":"settings","targets":[{{"platform":"android","domain":"android","entryAbi":"android-java-v1","process":"com.qinggan.app.setting","file":"agent-settings.dex","size":1,"sha256":"{}","entryClass":"ru.voboost.agents.settings.SettingsAgent","boot":false}}],"status":"unstable","category":"interface","order":0,"activation":{{"type":"config","key":"voboost-startup","value":"interface"}},"disables":[],"options":[],"title":{{"en":"V","ru":"V"}},"description":{{"en":"S","ru":"S"}},"applicability":{{"chip":["8155"],"vehicle":["free","dreamer"],"android":[9],"powertrain":["hybrid"],"market":["china"]}}}}]}}"#,
                crate::catalog::AGENT_ENTRY_ABI_SHA256,
                "d".repeat(64),
                "e".repeat(64)
            ))
        .unwrap();
        AgentCatalog::parse(&canonical_catalog_bytes(value)).unwrap()
    }

    fn canonical_catalog_bytes(value: serde_json::Value) -> Vec<u8> {
        let catalog: AgentCatalog = serde_json::from_value(value).unwrap();
        let mut bytes = serde_json::to_vec(&catalog).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn correlated_agent(
        id: &str,
        entry_class: &str,
        process: &str,
        category: &str,
        order: i32,
    ) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "targets": [{"platform":"android","domain":"android","entryAbi":"android-java-v1","process": process, "file":format!("agent-{id}.dex"),"size":1,"sha256":"e".repeat(64),"entryClass":entry_class,"boot": false}],
            "status": "stable",
            "category": category,
            "order": order,
            "activation": {"type": "checkbox", "default": false},
            "disables": [],
            "options": [],
            "title": {"en": id, "ru": id},
            "description": {"en": id, "ru": id},
            "applicability": {
                "chip": ["8155"],
                "vehicle": ["free"],
                "android": [9],
                "powertrain": ["hybrid"],
                "market": ["china"],
            },
        })
    }

    fn correlated_stable_catalog() -> AgentCatalog {
        let value = serde_json::json!({
            "schemaVersion": 2,
            "supportedAbis": ["arm64-v8a"],
            "agentEntryAbi": {
                "schemaVersion": 1,
                "sha256": crate::catalog::AGENT_ENTRY_ABI_SHA256,
            },
            "core": {"file": "agent-common.dex", "size": 1, "sha256": "d".repeat(64)},
            "agents": [
                {
                    "id": "settings",
                    "targets": [{"platform":"android","domain":"android","entryAbi":"android-java-v1","process": "com.qinggan.app.setting","file":"agent-settings.dex","size":1,"sha256":"e".repeat(64),"entryClass":"ru.voboost.agents.settings.SettingsAgent", "boot": false}],
                    "status": "unstable",
                    "category": "interface",
                    "order": -1,
                    "activation": {
                        "type": "config",
                        "key": "voboost-startup",
                        "value": "interface",
                    },
                    "disables": [],
                    "options": [],
                    "title": {"en": "settings", "ru": "settings"},
                    "description": {"en": "settings", "ru": "settings"},
                    "applicability": {
                        "chip": ["8155"],
                        "vehicle": ["free"],
                        "android": [9],
                        "powertrain": ["hybrid"],
                        "market": ["china"],
                    },
                },
                correlated_agent(
                    "font-cyrillic",
                    "ru.voboost.agents.font.cyrillic.FontCyrillicAgent",
                    "com.qinggan.app.setting",
                    "interface",
                    0,
                ),
                correlated_agent(
                    "keyboard-ru",
                    "ru.voboost.agents.keyboard.ru.KeyboardRuAgent",
                    "com.qinggan.app.qgime",
                    "interface",
                    1,
                ),
                correlated_agent(
                    "keyboard-en",
                    "ru.voboost.agents.keyboard.en.KeyboardEnAgent",
                    "com.qinggan.app.qgime",
                    "interface",
                    2,
                ),
                correlated_agent(
                    "vehicle-drive-pedestrian-warning",
                    "ru.voboost.agents.vehicle.drive.pedestrianwarning.VehicleDrivePedestrianWarningAgent",
                    "com.qinggan.systemservice",
                    "vehicle",
                    24,
                ),
            ],
        });
        AgentCatalog::parse(&canonical_catalog_bytes(value)).unwrap()
    }

    fn free09_unknown_powertrain_facts() -> VehicleProfile {
        VehicleProfile {
            chip: Fact::Known(Known {
                value: Chip::Qualcomm8155,
            }),
            vehicle: Fact::Known(Known {
                value: Vehicle::Free,
            }),
            android: Fact::Known(Known {
                value: AndroidVersion::Nine,
            }),
            powertrain: Fact::Unknown(Unknown {
                unknown: UnknownReason::ProbeUnavailable,
            }),
            market: Fact::Known(Known {
                value: Market::China,
            }),
        }
    }

    #[test]
    fn compute_marks_unknown_with_fixed_order_reasons() {
        let verified = SelectionReceipt::compute(&catalog(), SHA, &facts()).unwrap();
        assert_eq!(verified.selected_agent_ids, vec!["settings".to_string()]);
        let entry = &verified.receipt.agents[0];
        assert_eq!(entry.result, ApplicabilityResult::Unknown);
        assert_eq!(
            entry.unknown_reasons.as_deref(),
            Some(
                &[UnknownAxis {
                    axis: Axis::Vehicle,
                    reason: UnknownReason::ProbeUnavailable,
                }][..]
            )
        );
        // The canonical receipt bytes carry the schema's {axis, reason} shape.
        let text = String::from_utf8(verified.exact_bytes.clone()).unwrap();
        assert!(
            text.contains(r#""unknownReasons":[{"axis":"vehicle","reason":"probe-unavailable"}]"#)
        );
    }

    #[test]
    fn schema_one_canonical_bytes_and_sha256_match_cross_language_golden() {
        const GOLDEN: &[u8] = br#"{"schemaVersion":1,"catalogSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","facts":{"chip":{"unknown":"permission-denied"},"vehicle":{"value":"free"},"android":{"value":9},"powertrain":{"value":"hybrid"},"market":{"value":"china"}},"agents":[{"id":"settings","result":"unknown","unknownReasons":[{"axis":"chip","reason":"permission-denied"}]}]}"#;
        const GOLDEN_SHA256: &str =
            "8650cdc8e2c89a071c1a65ffc45c0bdcf5027c06b7c37ee3d2c79ddfb8a37b84";

        let facts = VehicleProfile {
            chip: Fact::Unknown(Unknown {
                unknown: UnknownReason::PermissionDenied,
            }),
            vehicle: Fact::Known(Known {
                value: Vehicle::Free,
            }),
            android: Fact::Known(Known {
                value: AndroidVersion::Nine,
            }),
            powertrain: Fact::Known(Known {
                value: Powertrain::Hybrid,
            }),
            market: Fact::Known(Known {
                value: Market::China,
            }),
        };
        let catalog_sha256 = "a".repeat(64);
        let computed = SelectionReceipt::compute(&catalog(), &catalog_sha256, &facts).unwrap();
        assert_eq!(computed.exact_bytes, GOLDEN);
        assert_eq!(computed.sha256, GOLDEN_SHA256);
        let verified =
            SelectionReceipt::verify(GOLDEN, &catalog(), &catalog_sha256, &facts).unwrap();
        assert_eq!(verified.sha256, GOLDEN_SHA256);
    }

    #[test]
    fn compute_all_known_match_has_no_reasons() {
        let mut profile = facts();
        profile.vehicle = Fact::Known(Known {
            value: Vehicle::Free,
        });
        let verified = SelectionReceipt::compute(&catalog(), SHA, &profile).unwrap();
        let entry = &verified.receipt.agents[0];
        assert_eq!(entry.result, ApplicabilityResult::Supported);
        assert!(entry.unknown_reasons.is_none());
        assert!(!String::from_utf8(verified.exact_bytes)
            .unwrap()
            .contains("unknownReasons"));
    }

    #[test]
    fn unknown_powertrain_keeps_agents_for_runtime_contract_selection() {
        let catalog = correlated_stable_catalog();
        let selection =
            SelectionReceipt::compute(&catalog, SHA, &free09_unknown_powertrain_facts()).unwrap();
        assert_eq!(
            selection.selected_agent_ids,
            vec![
                "settings".to_string(),
                "font-cyrillic".to_string(),
                "keyboard-ru".to_string(),
                "keyboard-en".to_string(),
                "vehicle-drive-pedestrian-warning".to_string(),
            ]
        );
        assert!(selection.receipt.agents.iter().all(|entry| {
            entry.result == ApplicabilityResult::Unknown
                && entry.unknown_reasons.as_deref()
                    == Some(
                        &[UnknownAxis {
                            axis: Axis::Powertrain,
                            reason: UnknownReason::ProbeUnavailable,
                        }][..],
                    )
        }));
    }

    #[test]
    fn known_ev_mismatch_excludes_hybrid_only_agents() {
        let catalog = correlated_stable_catalog();
        let mut facts = free09_unknown_powertrain_facts();
        facts.powertrain = Fact::Known(Known {
            value: Powertrain::Ev,
        });
        let selection = SelectionReceipt::compute(&catalog, SHA, &facts).unwrap();
        assert!(selection.selected_agent_ids.is_empty());
        assert!(selection
            .receipt
            .agents
            .iter()
            .all(|entry| entry.result == ApplicabilityResult::Unsupported));
    }

    #[test]
    fn verify_rejects_wrong_or_spurious_reasons() {
        // Correct result but wrong reasons.
        let mut receipt = SelectionReceipt::compute(&catalog(), SHA, &facts())
            .unwrap()
            .receipt;
        receipt.agents[0].unknown_reasons = Some(vec![UnknownAxis {
            axis: Axis::Market,
            reason: UnknownReason::ProbeUnavailable,
        }]);
        let bytes = serde_json::to_vec(&receipt).unwrap();
        assert!(SelectionReceipt::verify(&bytes, &catalog(), SHA, &facts()).is_err());
        // Spurious reasons on a supported result.
        let mut profile = facts();
        profile.vehicle = Fact::Known(Known {
            value: Vehicle::Free,
        });
        let mut supported = SelectionReceipt::compute(&catalog(), SHA, &profile)
            .unwrap()
            .receipt;
        supported.agents[0].unknown_reasons = Some(vec![UnknownAxis {
            axis: Axis::Vehicle,
            reason: UnknownReason::ProbeUnavailable,
        }]);
        let bytes = serde_json::to_vec(&supported).unwrap();
        assert!(SelectionReceipt::verify(&bytes, &catalog(), SHA, &profile).is_err());
    }

    #[test]
    fn verify_rejects_every_receipt_correlation_forgery() {
        let catalog = catalog();
        let root_facts = facts();
        let valid = SelectionReceipt::compute(&catalog, SHA, &root_facts)
            .unwrap()
            .receipt;
        let rejects = |receipt: SelectionReceipt| {
            let bytes = serde_json::to_vec(&receipt).unwrap();
            assert!(SelectionReceipt::verify(&bytes, &catalog, SHA, &root_facts).is_err());
        };

        let mut forged = valid.clone();
        forged.catalog_sha256 = "0".repeat(64);
        rejects(forged);
        let mut forged = valid.clone();
        forged.facts.market = Fact::Known(Known {
            value: Market::Global,
        });
        rejects(forged);
        let mut forged = valid.clone();
        forged.agents[0].result = ApplicabilityResult::Unsupported;
        forged.agents[0].unknown_reasons = None;
        rejects(forged);
        let mut forged = valid.clone();
        forged.agents[0].id = "font-cyrillic".to_string();
        rejects(forged);
        let mut forged = valid.clone();
        forged.agents.clear();
        rejects(forged);
        let mut forged = valid;
        forged.agents.push(forged.agents[0].clone());
        rejects(forged);
    }
}
