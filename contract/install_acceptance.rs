//! Closed emulator install observer wire types.
use serde::{Deserialize, Serialize};
const MAX: usize = 4096;
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub transaction_id: String,
    pub manifest_sha256: String,
    pub attempt_token: String,
    pub boot_id: String,
    pub reboot_count: u32,
    pub decision: Decision,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    Status,
    Accept,
    Reject,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    Waiting,
    Accepted,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub schema_version: u32,
    pub transaction_id: String,
    pub manifest_sha256: String,
    pub attempt_token: String,
    pub boot_id: String,
    pub reboot_count: u32,
    pub decision: Decision,
    pub state: State,
    pub expires_monotonic_ms: String,
}

pub fn bytes(value: &impl Serialize) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn canonical_boot_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

impl Request {
    pub fn parse(input: &[u8]) -> Result<Self, String> {
        if input.is_empty() || input.len() > MAX || input.last() != Some(&b'\n') {
            return Err("invalid acceptance request envelope".into());
        }
        let request: Self = serde_json::from_slice(input).map_err(|error| error.to_string())?;
        request.validate()?;
        if bytes(&request)? != input {
            return Err("noncanonical acceptance request".into());
        }
        Ok(request)
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.reboot_count != 1
            || !crate::install::lower_hash(&self.transaction_id)
            || !crate::install::lower_hash(&self.manifest_sha256)
            || !crate::install::lower_hash(&self.attempt_token)
            || !canonical_boot_id(&self.boot_id)
        {
            return Err("invalid install acceptance identity".into());
        }
        Ok(())
    }
}
