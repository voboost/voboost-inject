use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[allow(clippy::enum_variant_names)] // Operation-first names are the external WAL vocabulary.
pub enum InstallPhase {
    InstallPrepare,
    InstallPolicyBackup,
    InstallRuntimeApply,
    InstallApp,
    InstallPolicyApply,
    InstallRebootFirst,
    InstallAgents,
    InstallRebootSecond,
    InstallRuntimeVerify,
    InstallInventoryCommit,
    InstallCleanup,
    InstallComplete,
}

impl InstallPhase {
    pub const fn status_sequence(self) -> u64 {
        self as u64 + 1
    }

    pub const fn next(self) -> Option<Self> {
        use InstallPhase::*;
        Some(match self {
            InstallPrepare => InstallPolicyBackup,
            InstallPolicyBackup => InstallRuntimeApply,
            // Native/init files and the APK-owned incoming directory must be
            // durable before the policy is activated and reboot one hands
            // continuation to Android init.
            InstallRuntimeApply => InstallApp,
            InstallApp => InstallPolicyApply,
            InstallPolicyApply => InstallRebootFirst,
            InstallRebootFirst => InstallAgents,
            InstallAgents => InstallRebootSecond,
            InstallRebootSecond => InstallRuntimeVerify,
            InstallRuntimeVerify => InstallInventoryCommit,
            InstallInventoryCommit => InstallCleanup,
            InstallCleanup => InstallComplete,
            InstallComplete => return None,
        })
    }

    pub const fn requires_reboot(self) -> bool {
        matches!(self, Self::InstallRebootFirst | Self::InstallRebootSecond)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstallJournal {
    pub schema_version: u32,
    pub transaction_id: String,
    pub manifest_sha256: String,
    pub phase: InstallPhase,
    pub boot_ids: Vec<String>,
}

impl InstallJournal {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}
