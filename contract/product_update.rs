//! Canonical product-update WAL shared by the daemon and fixed recovery helper.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::status::{OtaCandidateHandle, MAX_STATUS_BYTES};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProductActivationClass {
    PackageInstaller,
    AgentGeneration,
    NativeRuntime,
    RestoreAuthority,
    Init,
    MetadataOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProductUpdatePhase {
    Copying,
    Pending,
    Reconstructing,
    Reconstructed,
    ApkInstallRequested,
    ApkObserved,
    GenerationPrepared,
    RecoveryPrepared,
    RestoreSwitched,
    GenerationSwitched,
    NativePrepared,
    NativeRebootRequired,
    NativePostReboot,
    NativeRollbackRebootRequired,
    SystemPrepared,
    SystemHelperRequested,
    SystemSwitched,
    SystemRebootRequired,
    SystemPostReboot,
    SystemRollbackRebootRequired,
    SystemRollbackPostReboot,
    InventoryPublished,
    ManifestPublished,
    ProductVerified,
    /// Late rollback discovered after the candidate was durably published:
    /// the observer projection already advanced past the native-rollback slot,
    /// so the rollback publishes at a monotone position instead of rewinding.
    LateRollbackRebootRequired,
    Complete,
    RolledBack,
}

/// Origin of a product proposal. An automatic OTA proposal from the
/// installed app must be strictly newer in the active channel. An explicit
/// offline update carries the operator's expected-active content identity:
/// it may apply different content at an equal SemVer in the same channel,
/// never a lower SemVer, and must fail closed when the active product
/// changed since inspection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum ProductUpdateOrigin {
    Ota,
    OfflineExplicit {
        expected_active_manifest_sha256: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductUpdateJournal {
    pub schema_version: u32,
    pub operation: String,
    pub origin: ProductUpdateOrigin,
    pub candidate: OtaCandidateHandle,
    pub activation_classes: Vec<ProductActivationClass>,
    pub generation_only: bool,
    pub apk_only: bool,
    pub native_plan: bool,
    pub system_plan: bool,
    pub phase: ProductUpdatePhase,
    pub previous_generation: Option<String>,
    pub next_generation: Option<String>,
    pub failure: Option<String>,
    pub pre_reboot_boot_id: Option<String>,
    pub post_reboot_boot_id: Option<String>,
    pub rollback_boot_id: Option<String>,
    pub system_init_previous_sha256: Option<String>,
    pub system_init_candidate_sha256: Option<String>,
    pub policy_previous_sha256: Option<String>,
    pub policy_baseline_sha256: Option<String>,
    pub policy_candidate_sha256: Option<String>,
}

impl ProductUpdateJournal {
    pub fn new(candidate: &OtaCandidateHandle) -> Self {
        let activation_classes = activation_classes(candidate).unwrap_or_default();
        Self {
            schema_version: 1,
            operation: "product-update-proposal".to_string(),
            generation_only: is_generation_only_plan(&activation_classes),
            apk_only: is_apk_only_plan(candidate, &activation_classes),
            native_plan: is_native_plan(candidate, &activation_classes),
            system_plan: is_system_plan(candidate, &activation_classes),
            candidate: candidate.clone(),
            activation_classes,
            phase: ProductUpdatePhase::Copying,
            origin: ProductUpdateOrigin::Ota,
            previous_generation: None,
            next_generation: None,
            failure: None,
            pre_reboot_boot_id: None,
            post_reboot_boot_id: None,
            rollback_boot_id: None,
            system_init_previous_sha256: None,
            system_init_candidate_sha256: None,
            policy_previous_sha256: None,
            policy_baseline_sha256: None,
            policy_candidate_sha256: None,
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        let native_phase = matches!(
            self.phase,
            ProductUpdatePhase::NativePrepared
                | ProductUpdatePhase::NativeRebootRequired
                | ProductUpdatePhase::NativePostReboot
                | ProductUpdatePhase::NativeRollbackRebootRequired
                | ProductUpdatePhase::SystemPrepared
                | ProductUpdatePhase::SystemHelperRequested
                | ProductUpdatePhase::SystemSwitched
                | ProductUpdatePhase::SystemRebootRequired
                | ProductUpdatePhase::SystemPostReboot
                | ProductUpdatePhase::SystemRollbackRebootRequired
                | ProductUpdatePhase::SystemRollbackPostReboot
        );
        let post_reboot_phase = matches!(
            self.phase,
            ProductUpdatePhase::NativePostReboot
                | ProductUpdatePhase::NativeRollbackRebootRequired
                | ProductUpdatePhase::SystemPostReboot
                | ProductUpdatePhase::SystemRollbackRebootRequired
                | ProductUpdatePhase::SystemRollbackPostReboot
                | ProductUpdatePhase::LateRollbackRebootRequired
        );
        let rollback_post_reboot_phase = self.phase == ProductUpdatePhase::SystemRollbackPostReboot;
        let system_hashes = [
            &self.system_init_previous_sha256,
            &self.system_init_candidate_sha256,
            &self.policy_previous_sha256,
            &self.policy_baseline_sha256,
            &self.policy_candidate_sha256,
        ];
        let system_prepared = matches!(
            self.phase,
            ProductUpdatePhase::SystemPrepared
                | ProductUpdatePhase::SystemHelperRequested
                | ProductUpdatePhase::SystemSwitched
                | ProductUpdatePhase::SystemRebootRequired
                | ProductUpdatePhase::SystemPostReboot
                | ProductUpdatePhase::SystemRollbackRebootRequired
                | ProductUpdatePhase::SystemRollbackPostReboot
        );
        let system_policy_ready = matches!(
            self.phase,
            ProductUpdatePhase::SystemHelperRequested
                | ProductUpdatePhase::SystemSwitched
                | ProductUpdatePhase::SystemRebootRequired
                | ProductUpdatePhase::SystemPostReboot
                | ProductUpdatePhase::SystemRollbackRebootRequired
                | ProductUpdatePhase::SystemRollbackPostReboot
        );
        if self.schema_version != 1
            || self.operation != "product-update-proposal"
            || matches!(&self.origin, ProductUpdateOrigin::OfflineExplicit {
                expected_active_manifest_sha256,
            } if !canonical_sha256(expected_active_manifest_sha256))
            || self.activation_classes != activation_classes(&self.candidate)?
            || self.generation_only != is_generation_only_plan(&self.activation_classes)
            || self.apk_only != is_apk_only_plan(&self.candidate, &self.activation_classes)
            || self.native_plan != is_native_plan(&self.candidate, &self.activation_classes)
            || self.system_plan != is_system_plan(&self.candidate, &self.activation_classes)
            || self
                .previous_generation
                .as_deref()
                .is_some_and(|value| !canonical_sha256(value))
            || self
                .next_generation
                .as_deref()
                .is_some_and(|value| !canonical_sha256(value))
            || (self.phase == ProductUpdatePhase::RolledBack
                && self.failure.as_deref() != Some("product activation rolled back"))
            || (self.phase != ProductUpdatePhase::RolledBack && self.failure.is_some())
            || self
                .pre_reboot_boot_id
                .as_deref()
                .is_some_and(|value| !canonical_boot_id(value))
            || self
                .post_reboot_boot_id
                .as_deref()
                .is_some_and(|value| !canonical_boot_id(value))
            || self
                .rollback_boot_id
                .as_deref()
                .is_some_and(|value| !canonical_boot_id(value))
            || self.post_reboot_boot_id.is_some()
                && self.post_reboot_boot_id == self.pre_reboot_boot_id
            || self.rollback_boot_id.is_some()
                && (self.rollback_boot_id == self.pre_reboot_boot_id
                    || self.rollback_boot_id == self.post_reboot_boot_id)
            || (native_phase && self.pre_reboot_boot_id.is_none())
            || (post_reboot_phase && self.post_reboot_boot_id.is_none())
            || (rollback_post_reboot_phase && self.rollback_boot_id.is_none())
            || (self.rollback_boot_id.is_some()
                && (self.post_reboot_boot_id.is_none()
                    || !matches!(
                        self.phase,
                        ProductUpdatePhase::SystemRollbackPostReboot
                            | ProductUpdatePhase::LateRollbackRebootRequired
                            | ProductUpdatePhase::RolledBack
                    )))
            || (self.phase == ProductUpdatePhase::RolledBack
                && self.post_reboot_boot_id.is_some()
                && self.rollback_boot_id.is_none())
            || (!self.native_plan
                && !self.system_plan
                && (self.pre_reboot_boot_id.is_some()
                    || self.post_reboot_boot_id.is_some()
                    || self.rollback_boot_id.is_some()))
            || system_hashes
                .iter()
                .filter_map(|value| value.as_deref())
                .any(|value| !canonical_sha256(value))
            || (!self.system_plan && system_hashes.iter().any(|value| value.is_some()))
            || (system_prepared
                && [
                    &self.system_init_previous_sha256,
                    &self.system_init_candidate_sha256,
                    &self.policy_previous_sha256,
                    &self.policy_baseline_sha256,
                ]
                .iter()
                .any(|value| value.is_none()))
            || (system_policy_ready && self.policy_candidate_sha256.is_none())
            || (self.phase == ProductUpdatePhase::SystemPrepared
                && self.policy_candidate_sha256.is_some())
        {
            return Err("product proposal journal header is invalid".into());
        }
        let mut bytes = serde_json::to_vec(self)
            .map_err(|error| format!("serialize product proposal journal: {error}"))?;
        bytes.push(b'\n');
        if bytes.len() > MAX_STATUS_BYTES {
            return Err("product proposal journal exceeds byte bound".into());
        }
        Ok(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_STATUS_BYTES {
            return Err("product proposal journal byte envelope is invalid".into());
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("parse product proposal journal: {error}"))?;
        if value.canonical_bytes()? != bytes {
            return Err("product proposal journal is not canonical".into());
        }
        Ok(value)
    }
}

/// Label of an executable restored by the init-owned system helper.
pub fn system_rollback_context(file: &str) -> Option<&'static str> {
    match file {
        "voboost-daemon" | "voboost-inject" => Some("u:object_r:voboost_exec:s0"),
        "voboost-install" => Some("u:object_r:voboost_install_exec:s0"),
        "voboost-restore" => Some("u:object_r:system_file:s0"),
        "voboost-uninstall" => Some("u:object_r:voboost_uninstall_exec:s0"),
        _ => None,
    }
}

pub fn activation_classes(
    candidate: &OtaCandidateHandle,
) -> Result<Vec<ProductActivationClass>, String> {
    if candidate.artifacts.is_empty() {
        return Ok(vec![ProductActivationClass::MetadataOnly]);
    }
    let mut classes = BTreeSet::new();
    for identity in &candidate.artifacts {
        let (_, activation, _) = crate::release::classify(&identity.file)?;
        classes.insert(match activation {
            crate::release::Activation::PackageInstaller => {
                ProductActivationClass::PackageInstaller
            }
            crate::release::Activation::AgentGeneration => ProductActivationClass::AgentGeneration,
            crate::release::Activation::NativeRuntime => ProductActivationClass::NativeRuntime,
            crate::release::Activation::RestoreAuthority => {
                ProductActivationClass::RestoreAuthority
            }
            crate::release::Activation::Init => ProductActivationClass::Init,
        });
    }
    Ok(classes.into_iter().collect())
}

pub fn is_generation_only_plan(classes: &[ProductActivationClass]) -> bool {
    classes.contains(&ProductActivationClass::AgentGeneration)
        && classes.iter().all(|class| {
            matches!(
                class,
                ProductActivationClass::AgentGeneration | ProductActivationClass::RestoreAuthority
            )
        })
}

pub fn is_apk_only_plan(
    candidate: &OtaCandidateHandle,
    classes: &[ProductActivationClass],
) -> bool {
    classes.contains(&ProductActivationClass::PackageInstaller)
        && classes.iter().all(|class| {
            matches!(
                class,
                ProductActivationClass::PackageInstaller | ProductActivationClass::RestoreAuthority
            )
        })
        && exact_restore_pair(candidate, true)
}

pub fn is_native_plan(candidate: &OtaCandidateHandle, classes: &[ProductActivationClass]) -> bool {
    classes.contains(&ProductActivationClass::NativeRuntime)
        && !classes.contains(&ProductActivationClass::Init)
        && !candidate
            .artifacts
            .iter()
            .any(|artifact| artifact.file == "voboost-selinux")
        && classes.iter().all(|class| {
            matches!(
                class,
                ProductActivationClass::PackageInstaller
                    | ProductActivationClass::AgentGeneration
                    | ProductActivationClass::NativeRuntime
                    | ProductActivationClass::RestoreAuthority
            )
        })
        && exact_restore_pair(candidate, false)
}

pub fn is_system_plan(candidate: &OtaCandidateHandle, classes: &[ProductActivationClass]) -> bool {
    let changes_system = candidate
        .artifacts
        .iter()
        .any(|artifact| matches!(artifact.file.as_str(), "voboost.rc" | "voboost-selinux"));
    changes_system
        && classes.iter().all(|class| {
            matches!(
                class,
                ProductActivationClass::PackageInstaller
                    | ProductActivationClass::AgentGeneration
                    | ProductActivationClass::NativeRuntime
                    | ProductActivationClass::RestoreAuthority
                    | ProductActivationClass::Init
            )
        })
        && exact_restore_pair(candidate, false)
}

fn exact_restore_pair(candidate: &OtaCandidateHandle, exact_three: bool) -> bool {
    let files = candidate
        .artifacts
        .iter()
        .map(|artifact| artifact.file.as_str())
        .collect::<BTreeSet<_>>();
    files.contains("restore.json")
        && files.contains("restore.json.sig")
        && (!exact_three
            || files == BTreeSet::from(["voboost-app.apk", "restore.json", "restore.json.sig"]))
}

fn canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn canonical_boot_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_plan_requires_changed_init_or_policy_and_restore_pair() {
        let identity = |file: &str| crate::status::CandidateArtifactIdentity {
            file: file.to_string(),
            size: 1,
            sha256: "a".repeat(64),
        };
        for system in ["voboost.rc", "voboost-selinux"] {
            let candidate = OtaCandidateHandle {
                transaction_id: "b".repeat(64),
                release_identity: "1.0.0-beta2".into(),
                manifest_sha256: "c".repeat(64),
                artifacts: [system, "restore.json", "restore.json.sig"]
                    .into_iter()
                    .map(identity)
                    .collect(),
            };
            let classes = activation_classes(&candidate).unwrap();
            assert!(is_system_plan(&candidate, &classes));
            assert!(!is_native_plan(&candidate, &classes));
        }
    }

    #[test]
    fn journal_enforces_distinct_ordered_reboot_epochs() {
        let identity = |file: &str| crate::status::CandidateArtifactIdentity {
            file: file.to_string(),
            size: 1,
            sha256: "a".repeat(64),
        };
        let candidate = OtaCandidateHandle {
            transaction_id: "b".repeat(64),
            release_identity: "1.0.0-beta2".into(),
            manifest_sha256: "c".repeat(64),
            artifacts: ["voboost-daemon", "restore.json", "restore.json.sig"]
                .into_iter()
                .map(identity)
                .collect(),
        };
        let mut journal = ProductUpdateJournal::new(&candidate);
        journal.pre_reboot_boot_id = Some("00000000-0000-0000-0000-000000000001".into());
        journal.post_reboot_boot_id = Some("00000000-0000-0000-0000-000000000002".into());
        journal.phase = ProductUpdatePhase::NativeRollbackRebootRequired;
        assert!(journal.canonical_bytes().is_ok());

        journal.phase = ProductUpdatePhase::RolledBack;
        journal.failure = Some("product activation rolled back".into());
        assert!(journal.canonical_bytes().is_err());
        journal.rollback_boot_id = Some("00000000-0000-0000-0000-000000000002".into());
        assert!(journal.canonical_bytes().is_err());
        journal.rollback_boot_id = Some("00000000-0000-0000-0000-000000000003".into());
        assert!(journal.canonical_bytes().is_ok());
    }
}
