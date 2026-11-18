//! Fixed helper receipts for protected Init/SELinux product activation.

use serde::{Deserialize, Serialize};

pub const SYSTEM_SWITCH_ACK: &str = "system-switch-ack.json";
pub const SYSTEM_POST_BOOT_ACK: &str = "system-post-boot-ack.json";
pub const SYSTEM_FAILURE_ACK: &str = "system-failure-ack.json";
pub const SYSTEM_ROLLBACK_ACK: &str = "system-rollback-ack.json";
pub const POLICY_PREPARE_ACK: &str = "policy-prepare-ack.json";
pub const MAX_SYSTEM_ACK_BYTES: usize = 4096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SystemSwitchAck {
    pub schema_version: u32,
    pub transaction_id: String,
    pub boot_id: String,
    pub init_previous_sha256: String,
    pub init_candidate_sha256: String,
    pub policy_previous_sha256: String,
    pub policy_baseline_sha256: String,
    pub policy_candidate_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SystemPostBootAck {
    pub schema_version: u32,
    pub transaction_id: String,
    pub boot_id: String,
    pub init_candidate_sha256: String,
    pub policy_candidate_sha256: String,
    pub enforcing: bool,
    pub daemon_domain: String,
    pub loaded_policy_verified: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyPrepareAck {
    pub schema_version: u32,
    pub transaction_id: String,
    pub boot_id: String,
    pub policy_baseline_sha256: String,
    pub policy_candidate_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SystemFailureAck {
    pub schema_version: u32,
    pub transaction_id: String,
    pub boot_id: String,
    pub phase: String,
    pub reboot_required: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SystemRollbackAck {
    pub schema_version: u32,
    pub transaction_id: String,
    pub boot_id: String,
    pub init_previous_sha256: String,
    pub policy_previous_sha256: String,
    pub enforcing: bool,
    pub daemon_domain: String,
}

impl SystemSwitchAck {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        parse_canonical(bytes, |value: &Self| {
            value.schema_version == 1
                && canonical_sha256(&value.transaction_id)
                && canonical_boot_id(&value.boot_id)
                && [
                    &value.init_previous_sha256,
                    &value.init_candidate_sha256,
                    &value.policy_previous_sha256,
                    &value.policy_baseline_sha256,
                    &value.policy_candidate_sha256,
                ]
                .into_iter()
                .all(|value| canonical_sha256(value))
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        canonical(self)
    }
}

impl SystemPostBootAck {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        parse_canonical(bytes, |value: &Self| {
            value.schema_version == 1
                && canonical_sha256(&value.transaction_id)
                && canonical_boot_id(&value.boot_id)
                && canonical_sha256(&value.init_candidate_sha256)
                && canonical_sha256(&value.policy_candidate_sha256)
                && value.enforcing
                && value.daemon_domain == "u:r:voboost:s0"
                && value.loaded_policy_verified
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        canonical(self)
    }
}

impl PolicyPrepareAck {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        parse_canonical(bytes, |value: &Self| {
            value.schema_version == 1
                && canonical_sha256(&value.transaction_id)
                && canonical_boot_id(&value.boot_id)
                && canonical_sha256(&value.policy_baseline_sha256)
                && canonical_sha256(&value.policy_candidate_sha256)
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        canonical(self)
    }
}

impl SystemFailureAck {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        parse_canonical(bytes, |value: &Self| {
            value.schema_version == 1
                && canonical_sha256(&value.transaction_id)
                && canonical_boot_id(&value.boot_id)
                && matches!(
                    value.phase.as_str(),
                    "system-prepared" | "system-helper-requested" | "system-post-reboot"
                )
                && value.reboot_required == (value.phase == "system-post-reboot")
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        canonical(self)
    }
}

impl SystemRollbackAck {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        parse_canonical(bytes, |value: &Self| {
            value.schema_version == 1
                && canonical_sha256(&value.transaction_id)
                && canonical_boot_id(&value.boot_id)
                && canonical_sha256(&value.init_previous_sha256)
                && canonical_sha256(&value.policy_previous_sha256)
                && value.enforcing
                && value.daemon_domain == "u:r:voboost:s0"
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        canonical(self)
    }
}

fn parse_canonical<T>(bytes: &[u8], valid: impl FnOnce(&T) -> bool) -> Result<T, String>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if bytes.is_empty() || bytes.len() > MAX_SYSTEM_ACK_BYTES {
        return Err("system helper receipt byte envelope is invalid".into());
    }
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| format!("parse system helper receipt: {error}"))?;
    if !valid(&value) || canonical(&value)? != bytes {
        return Err("system helper receipt is not canonical".into());
    }
    Ok(value)
}

fn canonical(value: &impl Serialize) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    if bytes.len() > MAX_SYSTEM_ACK_BYTES {
        return Err("system helper receipt exceeds byte bound".into());
    }
    Ok(bytes)
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
    fn helper_receipts_bind_transaction_boot_init_policy_and_loaded_state() {
        let value = SystemSwitchAck {
            schema_version: 1,
            transaction_id: "1".repeat(64),
            boot_id: "00000000-0000-0000-0000-000000000001".into(),
            init_previous_sha256: "2".repeat(64),
            init_candidate_sha256: "3".repeat(64),
            policy_previous_sha256: "4".repeat(64),
            policy_baseline_sha256: "5".repeat(64),
            policy_candidate_sha256: "6".repeat(64),
        };
        assert_eq!(
            SystemSwitchAck::parse(&value.canonical_bytes().unwrap()).unwrap(),
            value
        );
        let mut hostile = value.canonical_bytes().unwrap();
        hostile.extend_from_slice(b" ");
        assert!(SystemSwitchAck::parse(&hostile).is_err());

        let post = SystemPostBootAck {
            schema_version: 1,
            transaction_id: "1".repeat(64),
            boot_id: "00000000-0000-0000-0000-000000000002".into(),
            init_candidate_sha256: "3".repeat(64),
            policy_candidate_sha256: "6".repeat(64),
            enforcing: true,
            daemon_domain: "u:r:voboost:s0".into(),
            loaded_policy_verified: true,
        };
        assert!(SystemPostBootAck::parse(&post.canonical_bytes().unwrap()).is_ok());
        let mut wrong_enforcing = post.clone();
        wrong_enforcing.enforcing = false;
        let mut wrong_domain = post.clone();
        wrong_domain.daemon_domain = "u:r:init:s0".into();
        let mut wrong_loaded = post;
        wrong_loaded.loaded_policy_verified = false;
        for hostile in [wrong_enforcing, wrong_domain, wrong_loaded] {
            assert!(SystemPostBootAck::parse(&hostile.canonical_bytes().unwrap()).is_err());
        }
        let failure = SystemFailureAck {
            schema_version: 1,
            transaction_id: "1".repeat(64),
            boot_id: "00000000-0000-0000-0000-000000000002".into(),
            phase: "system-post-reboot".into(),
            reboot_required: true,
        };
        assert!(SystemFailureAck::parse(&failure.canonical_bytes().unwrap()).is_ok());
        let mut hostile = failure;
        hostile.reboot_required = false;
        assert!(SystemFailureAck::parse(&hostile.canonical_bytes().unwrap()).is_err());
    }
}
