use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Command {
    pub schema_version: u32,
    pub operation: String,
    pub request_id: String,
    pub generation_id: String,
    pub catalog_sha256: String,
    pub document_generation: i64,
}
fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
impl Command {
    pub fn validate(&self) -> bool {
        self.schema_version == 1
            && self.operation == "launcher-cache-quiesce"
            && hex64(&self.request_id)
            && hex64(&self.catalog_sha256)
            && hex64(&self.generation_id)
            && self.document_generation >= 0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Proof {
    Acknowledged {
        pid: i32,
        starttime: u64,
        #[serde(rename = "endpointEpoch")]
        endpoint_epoch: u64,
        command: Command,
    },
    NoEndpoint {},
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub schema_version: u32,
    pub transaction_id: String,
    pub boot_id: String,
    pub process: String,
    pub proof: Proof,
}
impl Receipt {
    pub fn matches(&self, transaction_id: &str, boot_id: &str) -> bool {
        self.schema_version == 1
            && hex64(transaction_id)
            && crate::operation::canonical_boot_id(boot_id)
            && self.transaction_id == transaction_id
            && self.boot_id == boot_id
            && self.process == "com.qinggan.app.launcher"
            && match &self.proof {
                Proof::Acknowledged {
                    pid,
                    starttime,
                    endpoint_epoch,
                    command,
                } => *pid > 0 && *starttime > 0 && *endpoint_epoch > 0 && command.validate(),
                Proof::NoEndpoint {} => true,
            }
    }
    pub fn acknowledged_identity(&self) -> Option<(u32, String)> {
        match &self.proof {
            Proof::Acknowledged { pid, starttime, .. } => {
                Some((*pid as u32, starttime.to_string()))
            }
            Proof::NoEndpoint {} => None,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RebootCheckpoint {
    pub schema_version: u32,
    pub prior_boot_id: String,
}
impl RebootCheckpoint {
    pub fn admits(&self, current_boot: &str) -> bool {
        self.schema_version == 1
            && crate::operation::canonical_boot_id(&self.prior_boot_id)
            && crate::operation::canonical_boot_id(current_boot)
            && self.prior_boot_id != current_boot
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_six_field_command_fixture_and_generation_validation() {
        let fixture = include_str!("fixtures/icon-cache-quiescence.json");
        let command: Command = serde_json::from_str(fixture).unwrap();
        assert!(command.validate());
        assert_eq!(serde_json::to_string(&command).unwrap(), fixture.trim_end());
        for invalid in [
            "g".to_owned(),
            "C".repeat(64),
            "c".repeat(63),
            "c".repeat(65),
            "z".repeat(64),
        ] {
            let mut wrong = command.clone();
            wrong.generation_id = invalid;
            assert!(!wrong.validate());
        }
    }
    #[test]
    fn durable_receipt_binds_transaction_boot_and_exact_command() {
        let mut receipt = Receipt {
            schema_version: 1,
            transaction_id: "a".repeat(64),
            boot_id: "11111111-1111-1111-1111-111111111111".to_owned(),
            process: "com.qinggan.app.launcher".to_owned(),
            proof: Proof::Acknowledged {
                pid: 123,
                starttime: 456,
                endpoint_epoch: 7,
                command: Command {
                    schema_version: 1,
                    operation: "launcher-cache-quiesce".to_owned(),
                    request_id: "a".repeat(64),
                    generation_id: "c".repeat(64),
                    catalog_sha256: "b".repeat(64),
                    document_generation: 0,
                },
            },
        };
        assert!(receipt.matches(&"a".repeat(64), "11111111-1111-1111-1111-111111111111"));
        assert!(!receipt.matches(&"c".repeat(64), "11111111-1111-1111-1111-111111111111"));
        assert!(!receipt.matches(&"a".repeat(64), "22222222-2222-2222-2222-222222222222"));
        if let Proof::Acknowledged { command, .. } = &mut receipt.proof {
            command.operation = "execute".to_owned();
        }
        assert!(!receipt.matches(&"a".repeat(64), "11111111-1111-1111-1111-111111111111"));
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(
            serde_json::from_str::<Receipt>(&json.replacen('{', "{\"path\":\"/other\",", 1))
                .is_err()
        );
        assert!(
            serde_json::from_str::<Receipt>(&json.replacen('{', "{\"schemaVersion\":1,", 1))
                .is_err()
        );
    }
    #[test]
    fn recovery_checkpoint_requires_canonical_different_boot() {
        let mut checkpoint = RebootCheckpoint {
            schema_version: 1,
            prior_boot_id: "11111111-1111-1111-1111-111111111111".to_owned(),
        };
        assert!(!checkpoint.admits(&checkpoint.prior_boot_id));
        assert!(checkpoint.admits("22222222-2222-2222-2222-222222222222"));
        checkpoint.prior_boot_id = "corrupt".to_owned();
        assert!(!checkpoint.admits("22222222-2222-2222-2222-222222222222"));
    }
    #[test]
    fn absent_endpoint_receipt_is_explicit_and_does_not_forge_an_ack_identity() {
        let receipt = Receipt {
            schema_version: 1,
            transaction_id: "a".repeat(64),
            boot_id: "11111111-1111-1111-1111-111111111111".to_owned(),
            process: "com.qinggan.app.launcher".to_owned(),
            proof: Proof::NoEndpoint {},
        };
        assert!(receipt.matches(&"a".repeat(64), "11111111-1111-1111-1111-111111111111"));
        assert_eq!(receipt.acknowledged_identity(), None);
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(serde_json::from_str::<Receipt>(&json.replace(
            "\"kind\":\"no-endpoint\"",
            "\"kind\":\"no-endpoint\",\"pid\":123"
        ))
        .is_err());
    }
}
