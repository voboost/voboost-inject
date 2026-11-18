//! Canonical initial-install documents shared by privileged binaries.

use serde::{Deserialize, Serialize};

pub const STAGING_DESCRIPTOR_NAME: &str = "staging.json";
pub const MAX_STAGING_DESCRIPTOR_BYTES: usize = 4096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StagingDescriptor {
    pub schema_version: u32,
    pub transaction_id: String,
    pub release_identity: String,
    pub manifest_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emulator_acceptance: Option<EmulatorAcceptance>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmulatorAcceptance {
    pub attempt_token: String,
}

impl StagingDescriptor {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        parse_canonical(
            bytes,
            MAX_STAGING_DESCRIPTOR_BYTES,
            "install staging descriptor",
            Self::validate,
        )
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || !lower_hash(&self.transaction_id)
            || self.release_identity.is_empty()
            || self.release_identity.len() > crate::release::MAX_RELEASE_IDENTITY_BYTES
            || semver::Version::parse(&self.release_identity)
                .ok()
                .is_none_or(|version| version.to_string() != self.release_identity)
            || !lower_hash(&self.manifest_sha256)
            || self
                .emulator_acceptance
                .as_ref()
                .is_some_and(|arm| !lower_hash(&arm.attempt_token))
        {
            return Err("install staging descriptor is invalid".to_string());
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

pub(crate) fn parse_canonical<T>(
    bytes: &[u8],
    max: usize,
    label: &str,
    validate: impl FnOnce(&T) -> Result<(), String>,
) -> Result<T, String>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if bytes.is_empty() || bytes.len() > max || bytes.last() != Some(&b'\n') {
        return Err(format!("{label} byte envelope is invalid"));
    }
    let value = serde_json::from_slice(bytes).map_err(|error| format!("parse {label}: {error}"))?;
    validate(&value)?;
    let mut canonical =
        serde_json::to_vec(&value).map_err(|error| format!("serialize {label}: {error}"))?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err(format!("{label} is not canonical"));
    }
    Ok(value)
}

pub fn lower_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opt_in_is_canonical_closed_and_absence_preserves_schema_one_bytes() {
        let mut value = StagingDescriptor {
            schema_version: 1,
            transaction_id: "1".repeat(64),
            release_identity: "1.0.0-beta1".into(),
            manifest_sha256: "2".repeat(64),
            emulator_acceptance: None,
        };
        let ordinary = value.canonical_bytes().unwrap();
        assert!(!String::from_utf8(ordinary.clone())
            .unwrap()
            .contains("emulatorAcceptance"));
        value.emulator_acceptance = Some(EmulatorAcceptance {
            attempt_token: "3".repeat(64),
        });
        let armed = value.canonical_bytes().unwrap();
        assert_eq!(StagingDescriptor::parse(&armed).unwrap(), value);
        value.emulator_acceptance.as_mut().unwrap().attempt_token = "../bad".into();
        assert!(value.validate().is_err());
        assert!(StagingDescriptor::parse(
            String::from_utf8(armed)
                .unwrap()
                .replace("\"attemptToken\":", "\"extra\":true,\"attemptToken\":")
                .as_bytes()
        )
        .is_err());
    }

    #[test]
    fn staging_descriptor_binds_transaction_release_and_product_manifest() {
        let value = StagingDescriptor {
            schema_version: 1,
            transaction_id: "1".repeat(64),
            release_identity: "1.0.0-beta1".into(),
            manifest_sha256: "2".repeat(64),
            emulator_acceptance: None,
        };
        let bytes = value.canonical_bytes().unwrap();
        assert_eq!(StagingDescriptor::parse(&bytes).unwrap(), value);
        assert!(StagingDescriptor::parse(&bytes[..bytes.len() - 1]).is_err());
        let mut path = value;
        path.transaction_id = "../transaction".into();
        assert!(path.validate().is_err());
    }
}
