//! Current Android property probes evaluated against agent-owned applicability metadata.
use std::collections::BTreeMap;

pub(super) struct Profile {
    facts: BTreeMap<&'static str, serde_json::Value>,
    property_powertrain: Option<serde_json::Value>,
    hardware_powertrain: bool,
}

impl Profile {
    pub(super) fn current() -> Self {
        Self::probe(|name| {
            super::inputs::property(name)
                .ok()
                .filter(|value| !value.is_empty())
        })
    }
    pub(super) fn probe(mut property: impl FnMut(&str) -> Option<String>) -> Self {
        let mut facts = BTreeMap::new();
        let mut chip = None;
        let mut conflict = false;
        for key in ["ro.product.board", "ro.board.platform", "ro.hardware"] {
            let Some(raw) = property(key) else {
                continue;
            };
            let value = raw.trim().to_ascii_lowercase();
            let mapped = match value.as_str() {
                "sa8155" | "msmnile" | "msmnile_gvmq" => Some("8155"),
                "imx8" | "nxp" => Some("nxp"),
                _ => None,
            };
            if mapped.is_none()
                && ["sa8155", "msmnile", "msmnile_gvmq", "imx8", "nxp"]
                    .iter()
                    .any(|token| value.contains(token))
            {
                conflict = true;
            }
            if let Some(value) = mapped {
                if chip.is_some_and(|previous| previous != value) {
                    conflict = true;
                }
                chip = Some(value);
            }
        }
        if !conflict {
            if let Some(chip) = chip {
                facts.insert("chip", chip.into());
            }
        }
        let mut vehicle = None;
        let mut conflict = false;
        for key in [
            "ro.build.product_3rdparty",
            "ro.build.product",
            "ro.product.device",
        ] {
            let Some(raw) = property(key) else {
                continue;
            };
            let raw = raw.trim().to_ascii_lowercase();
            let mapped = match raw.as_str() {
                "f0506h" | "f0501h" | "f6802h" | "f6805h" | "f6811" => Some("free"),
                "f0505h" | "f6804h" => Some("dreamer"),
                _ => None,
            };
            if let Some(value) = mapped {
                if vehicle.is_some_and(|previous| previous != value) {
                    conflict = true;
                }
                vehicle = Some(value);
            } else if vehicle.is_some() && raw != "msmnile_gvmq" {
                conflict = true;
            }
        }
        if !conflict {
            if let Some(vehicle) = vehicle {
                facts.insert("vehicle", vehicle.into());
            }
        }
        if let Some(android) = property("ro.build.version.release")
            .and_then(|value| value.trim().split('.').next()?.parse::<u64>().ok())
        {
            facts.insert("android", android.into());
        }
        if let Some(powertrain) =
            property("persist.sys.qg.powertrain").and_then(|value| {
                match value.trim().to_ascii_lowercase().as_str() {
                    "ev" | "electric" => Some("ev"),
                    "hybrid" | "reev" => Some("hybrid"),
                    _ => None,
                }
            })
        {
            facts.insert("powertrain", powertrain.into());
        }
        if let Some(market) = property("ro.product.locale").and_then(|value| {
            match value.trim().to_ascii_lowercase().as_str() {
                "zh-cn" => Some("china"),
                "ru-ru" | "ar-sa" => Some("global"),
                _ => None,
            }
        }) {
            facts.insert("market", market.into());
        }
        Self {
            property_powertrain: facts.get("powertrain").cloned(),
            hardware_powertrain: false,
            facts,
        }
    }

    pub(super) fn observe_powertrain(&mut self, value: Option<&'static str>) {
        self.hardware_powertrain = value.is_some();
        let observed = value.map(serde_json::Value::from);
        match (&self.property_powertrain, observed) {
            (Some(property), Some(observed)) if *property != observed => {
                self.facts.remove("powertrain");
            }
            (_, Some(observed)) => {
                self.facts.insert("powertrain", observed);
            }
            (Some(property), None) => {
                self.facts.insert("powertrain", property.clone());
            }
            (None, None) => {
                self.facts.remove("powertrain");
            }
        }
    }

    pub(super) fn needs_powertrain_probe(&self, applicability: &str) -> bool {
        if self.hardware_powertrain {
            return false;
        }
        let mut hypothetical = Self {
            facts: self.facts.clone(),
            property_powertrain: self.property_powertrain.clone(),
            hardware_powertrain: true,
        };
        hypothetical.facts.insert("powertrain", "hybrid".into());
        !self.permits(applicability) && hypothetical.permits(applicability)
    }

    pub(super) fn permits(&self, applicability: &str) -> bool {
        self.reason(applicability).is_none()
    }

    pub(super) fn reason(&self, applicability: &str) -> Option<String> {
        let Ok(serde_json::Value::Object(axes)) = serde_json::from_str(applicability) else {
            return Some("Native applicability metadata is invalid".into());
        };
        if axes.is_empty() {
            return Some("Native applicability metadata is empty".into());
        }
        let mut missing = None;
        for (axis, values) in axes {
            if !matches!(
                axis.as_str(),
                "chip" | "vehicle" | "android" | "powertrain" | "market"
            ) {
                return Some("Native applicability contains an unknown axis".into());
            }
            let Some(values) = values.as_array().filter(|values| !values.is_empty()) else {
                return Some("Native applicability values are invalid".into());
            };
            let full_powertrain = axis == "powertrain"
                && values.len() == 2
                && ["ev", "hybrid"]
                    .iter()
                    .all(|value| values.contains(&serde_json::Value::from(*value)));
            if axis == "powertrain" && !full_powertrain && !self.hardware_powertrain {
                missing.get_or_insert_with(|| {
                    "Installed native powertrain hardware fact is unavailable".into()
                });
                continue;
            }
            if let Some(actual) = self.facts.get(axis.as_str()) {
                if !values.contains(actual) {
                    return Some(format!("Native {} probe does not match this agent", axis));
                }
            } else {
                let full_domain = match axis.as_str() {
                    "powertrain" => Some(["ev", "hybrid"]),
                    "market" => Some(["china", "global"]),
                    _ => None,
                };
                if !full_domain.is_some_and(|domain| {
                    values.len() == domain.len()
                        && domain
                            .iter()
                            .all(|value| values.contains(&serde_json::Value::from(*value)))
                }) {
                    missing.get_or_insert_with(|| {
                        format!("Required native {} probe is unavailable", axis)
                    });
                }
            }
        }
        missing
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const APPLICABILITY: &str = r#"{"chip":["8155"],"vehicle":["free"],"android":[9,11],"powertrain":["hybrid"],"market":["china","global"]}"#;
    fn profile(chip: &str, android: &str, vehicle: &str) -> Profile {
        let properties = BTreeMap::from([
            ("ro.product.board", chip),
            ("ro.build.version.release", android),
            ("ro.build.product_3rdparty", vehicle),
            ("persist.sys.qg.powertrain", "hybrid"),
            ("ro.product.locale", "zh-CN"),
        ]);
        let mut profile = Profile::probe(|key| properties.get(key).map(|value| value.to_string()));
        profile.observe_powertrain(Some("hybrid"));
        profile
    }
    #[test]
    fn installed_hybrid_fact_admits_native_owner_and_bad_cache_never_does() {
        use std::os::unix::fs::PermissionsExt;
        use voboost_shared::vehicle_profile as facts;
        struct Properties(BTreeMap<&'static str, &'static str>);
        impl facts::PropSource for Properties {
            fn prop(&self, key: &str) -> Option<String> {
                self.0.get(key).map(|value| value.to_string())
            }
        }
        let properties = Properties(BTreeMap::from([
            ("ro.product.board", "sa8155"),
            ("ro.build.version.release", "9"),
            ("ro.build.product", "f0506h"),
            ("ro.product.locale", "zh-CN"),
        ]));
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("vehicle.json");
        let mut installed = facts::resolve(&properties);
        installed.powertrain = facts::Fact::Known(facts::Known {
            value: facts::Powertrain::Hybrid,
        });
        std::fs::write(&path, facts::canonical_bytes(&installed).unwrap()).unwrap();
        std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(facts::VEHICLE_PROFILE_MODE),
        )
        .unwrap();
        let mut owner = Profile::probe(|key| facts::PropSource::prop(&properties, key));
        assert!(!owner.permits(APPLICABILITY));
        owner.observe_powertrain(facts::cached_powertrain_with(root.path(), &properties).unwrap());
        assert!(owner.permits(APPLICABILITY));
        std::fs::write(&path, b"{}").unwrap();
        let mut restarted = Profile::probe(|key| facts::PropSource::prop(&properties, key));
        restarted.observe_powertrain(
            facts::cached_powertrain_with(root.path(), &properties)
                .ok()
                .flatten(),
        );
        assert!(!restarted.permits(APPLICABILITY));
    }

    #[test]
    fn restricted_powertrain_requires_matching_hardware_probe() {
        let properties = BTreeMap::from([
            ("ro.product.board", "sa8155"),
            ("ro.build.version.release", "9"),
            ("ro.build.product", "f0506h"),
            ("persist.sys.qg.powertrain", "hybrid"),
        ]);
        let mut profile = Profile::probe(|key| properties.get(key).map(|value| value.to_string()));
        assert!(!profile.permits(APPLICABILITY));
        assert!(profile.needs_powertrain_probe(APPLICABILITY));
        assert!(profile.permits(r#"{"powertrain":["ev","hybrid"]}"#));
        profile.observe_powertrain(Some("ev"));
        assert!(!profile.permits(APPLICABILITY));
        profile.observe_powertrain(Some("hybrid"));
        assert!(profile.permits(APPLICABILITY));
    }
    #[test]
    fn property_facts_admit_a9_a11_and_reject_nxp_and_other_android() {
        assert!(profile("sa8155", "9", "f0506h").permits(APPLICABILITY));
        assert!(profile("msmnile_gvmq", "11", "f6802h").permits(APPLICABILITY));
        assert!(!profile("imx8", "9", "f0501h").permits(APPLICABILITY));
        assert!(!profile("sa8155", "10", "f0506h").permits(APPLICABILITY));
        assert!(!profile("unknown", "9", "f0506h").permits(APPLICABILITY));
    }
    #[test]
    fn ambiguous_property_facts_and_malformed_metadata_never_admit_native_execution() {
        let conflicting = Profile::probe(|key| match key {
            "ro.product.board" => Some("sa8155".into()),
            "ro.board.platform" => Some("nxp".into()),
            _ => None,
        });
        assert!(!conflicting.permits(r#"{"chip":["8155"]}"#));
        let known = profile("sa8155", "9", "f0506h");
        for invalid in [
            "{}",
            "[]",
            r#"{"firmware":["build"]}"#,
            r#"{"chip":[]}"#,
            r#"{"chip":"8155"}"#,
        ] {
            assert!(!known.permits(invalid));
        }
        assert!(!profile("prefix-sa8155", "9", "f0506h").permits(APPLICABILITY));
    }
    #[test]
    fn actual_generated_native_codecs_exclude_nxp_without_narrowing_supported_a9_a11() {
        assert!(
            !super::super::CODECS.is_empty(),
            "native registry prerequisite missing"
        );
        for codec in super::super::CODECS {
            assert!(
                profile("sa8155", "9", "f0506h").permits(codec.applicability),
                "A9 {}",
                codec.id
            );
            assert!(
                profile("msmnile_gvmq", "11", "f6802h").permits(codec.applicability),
                "A11 {}",
                codec.id
            );
            assert!(
                !profile("imx8", "9", "f0501h").permits(codec.applicability),
                "NXP {}",
                codec.id
            );
            assert!(
                !profile("sa8155", "10", "f0506h").permits(codec.applicability),
                "Android10 {}",
                codec.id
            );
            assert!(
                !profile("sa8155", "9", "f0505h").permits(codec.applicability),
                "Dreamer9 {}",
                codec.id
            );
            assert!(
                !profile("msmnile_gvmq", "11", "f6804h").permits(codec.applicability),
                "Dreamer11 {}",
                codec.id
            );
        }
    }
    #[test]
    fn absent_powertrain_and_market_do_not_block_an_agent_covering_their_complete_domains() {
        let properties = BTreeMap::from([
            ("ro.product.board", "sa8155"),
            ("ro.build.version.release", "9"),
            ("ro.build.product", "f0506h"),
        ]);
        let mut profile = Profile::probe(|key| properties.get(key).map(|value| value.to_string()));
        assert!(profile.permits(r#"{"chip":["8155"],"vehicle":["free"],"android":[9,11],"powertrain":["ev","hybrid"],"market":["china","global"]}"#));
        assert!(!profile.permits(APPLICABILITY));
        profile.observe_powertrain(Some("hybrid"));
        assert!(profile.permits(APPLICABILITY));
        profile.observe_powertrain(Some("ev"));
        assert!(!profile.permits(APPLICABILITY));
    }
}
