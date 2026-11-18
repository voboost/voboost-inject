//! Canonical generation documents shared by privileged binaries.

use serde::{Deserialize, Serialize};

use crate::install::{lower_hash, parse_canonical};

pub const MAX_GENERATION_ACK_BYTES: usize = 4096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenerationAcknowledgement {
    pub schema_version: u32,
    pub transaction_id: String,
    pub apk_sha256: String,
    pub catalog_sha256: String,
    pub selection_sha256: String,
    pub generation_sha256: String,
}

impl GenerationAcknowledgement {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        parse_canonical(
            bytes,
            MAX_GENERATION_ACK_BYTES,
            "generation acknowledgement",
            |value: &Self| value.validate(),
        )
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || !lower_hash(&self.transaction_id)
            || !lower_hash(&self.apk_sha256)
            || !lower_hash(&self.catalog_sha256)
            || !lower_hash(&self.selection_sha256)
            || !lower_hash(&self.generation_sha256)
        {
            return Err("generation acknowledgement is invalid".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acknowledgement_binds_install_identity_closure() {
        let bytes = concat!(
            "{\"schemaVersion\":1,",
            "\"transactionId\":\"1111111111111111111111111111111111111111111111111111111111111111\",",
            "\"apkSha256\":\"2222222222222222222222222222222222222222222222222222222222222222\",",
            "\"catalogSha256\":\"3333333333333333333333333333333333333333333333333333333333333333\",",
            "\"selectionSha256\":\"4444444444444444444444444444444444444444444444444444444444444444\",",
            "\"generationSha256\":\"5555555555555555555555555555555555555555555555555555555555555555\"}\n"
        );
        assert!(GenerationAcknowledgement::parse(bytes.as_bytes()).is_ok());
        assert!(GenerationAcknowledgement::parse(
            bytes.replace("\"apkSha256\"", "\"apkHash\"").as_bytes()
        )
        .is_err());
    }
}
