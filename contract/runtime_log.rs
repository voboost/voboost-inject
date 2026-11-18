//! Producer data, independent of file ownership and transport.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Event {
    pub schema_version: u8,
    pub boot_id: String,
    pub writer_id: String,
    pub sequence: u64,
    pub timestamp: String,
    pub level: Level,
    pub source: Source,
    pub component: String,
    pub message: String,
    pub fields: std::collections::BTreeMap<String, String>,
}

pub const MAX_RECORD_BYTES: usize = 16 * 1024;
pub const MAX_BATCH_RECORDS: usize = 64;
pub const MAX_BATCH_BYTES: usize = 256 * 1024;
pub const MAX_BATCH_RECEIPTS: usize = 4096;
pub const MAX_BATCH_RECEIPT_BYTES: u64 = 32 * 1024 * 1024;
pub const TIER_NAMES: [&str; 3] = ["debug", "info", "error"];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppBatch {
    pub schema_version: u8,
    pub batch_id: String,
    pub records: Vec<Record>,
}
impl AppBatch {
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() || bytes.len() > MAX_BATCH_BYTES {
            return Err("app batch exceeds bound");
        }
        let mut batch: Self = serde_json::from_slice(bytes).map_err(|_| "invalid app batch")?;
        if batch.schema_version != 1
            || batch.batch_id.len() != 32
            || !batch
                .batch_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || batch.records.is_empty()
            || batch.records.len() > MAX_BATCH_RECORDS
            || batch.records.iter().any(|r| !r.valid())
        {
            return Err("invalid app batch");
        }
        for record in &mut batch.records {
            record.message = redact(&record.message);
            for value in record.fields.values_mut() {
                *value = redact(value);
            }
        }
        if batch.records.iter().any(|record| !record.valid())
            || !serde_json::to_vec(&batch).is_ok_and(|bytes| bytes.len() <= MAX_BATCH_BYTES)
        {
            return Err("redacted app batch exceeds bound");
        }
        Ok(batch)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Debug,
    Info,
    Error,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Source {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}
impl Source {
    pub fn daemon() -> Self {
        Self {
            kind: "daemon".into(),
            id: None,
        }
    }
    pub fn qnx(session: String) -> Self {
        Self {
            kind: "qnx".into(),
            id: Some(session),
        }
    }
    pub fn valid(&self) -> bool {
        match (self.kind.as_str(), &self.id) {
            ("qnx", Some(session)) => crate::cluster_log::valid_source_session(session),
            ("daemon" | "app", None) => true,
            ("agent", Some(id)) => {
                !id.is_empty()
                    && id.len() <= 128
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            }
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub level: Level,
    pub component: String,
    pub message: String,
    #[serde(default)]
    pub fields: HashMap<String, String>,
}
impl Record {
    pub fn valid(&self) -> bool {
        !self.component.is_empty()
            && self.component.len() <= 64
            && !self.component.chars().any(char::is_control)
            && self.message.len() <= 8 * 1024
            && !self
                .message
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
            && self.fields.len() <= 32
            && self.fields.iter().all(|(key, value)| {
                !key.is_empty()
                    && key.len() <= 64
                    && value.len() <= 1024
                    && !key.chars().any(char::is_control)
                    && !value.chars().any(char::is_control)
            })
            && serde_json::to_vec(self).is_ok_and(|bytes| bytes.len() <= MAX_RECORD_BYTES)
    }
}

pub fn redact(value: &str) -> String {
    let mut out = value.to_string();
    for key in ["token=", "password=", "secret="] {
        let mut offset = 0;
        while let Some(found) = out[offset..].to_ascii_lowercase().find(key) {
            let start = offset + found + key.len();
            let end = out[start..]
                .find(char::is_whitespace)
                .map_or(out.len(), |n| start + n);
            out.replace_range(start..end, "[REDACTED]");
            offset = start + "[REDACTED]".len();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn redaction_expansion_cannot_create_an_unreplayable_batch() {
        let bytes = serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"batchId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","records":[{"level":"info","component":"app","message":"token=x ".repeat(900),"fields":{}}]})).unwrap();
        assert!(bytes.len() < MAX_BATCH_BYTES);
        assert!(AppBatch::decode(&bytes).is_err());
    }
    #[test]
    fn app_batch_receipt_material_contains_only_redacted_producer_text() {
        let bytes=br#"{"schemaVersion":1,"batchId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","records":[{"level":"info","component":"app","message":"token=private","fields":{"context":"password=hidden"}}]}"#;
        let batch = AppBatch::decode(bytes).unwrap();
        assert_eq!(batch.records[0].message, "token=[REDACTED]");
        assert_eq!(batch.records[0].fields["context"], "password=[REDACTED]");
        let encoded = serde_json::to_string(&batch).unwrap();
        assert!(!encoded.contains("private"));
        assert!(!encoded.contains("hidden"));
    }
    #[test]
    fn app_batch_rejects_invalid_identity_empty_records_and_oversized_input() {
        let record = Record {
            level: Level::Info,
            component: "app".into(),
            message: "event".into(),
            fields: HashMap::new(),
        };
        let mut batch = AppBatch {
            schema_version: 1,
            batch_id: "a".repeat(32),
            records: vec![record.clone()],
        };
        assert!(AppBatch::decode(&serde_json::to_vec(&batch).unwrap()).is_ok());
        batch.records.clear();
        assert!(AppBatch::decode(&serde_json::to_vec(&batch).unwrap()).is_err());
        batch.records = vec![record; MAX_BATCH_RECORDS + 1];
        assert!(AppBatch::decode(&serde_json::to_vec(&batch).unwrap()).is_err());
        assert!(AppBatch::decode(&vec![b' '; MAX_BATCH_BYTES + 1]).is_err());
    }
    #[test]
    fn sources_and_records_reject_unbound_identity_and_oversized_context() {
        assert!(Source::daemon().valid());
        for source in [
            Source {
                kind: "agent".into(),
                id: None,
            },
            Source {
                kind: "app".into(),
                id: Some("agent".into()),
            },
            Source {
                kind: "shell".into(),
                id: None,
            },
        ] {
            assert!(!source.valid());
        }
        let mut record = Record {
            level: Level::Debug,
            component: "owner".into(),
            message: "event".into(),
            fields: HashMap::new(),
        };
        assert!(record.valid());
        record.fields.insert("private\nkey".into(), "value".into());
        assert!(!record.valid());
        record.fields.clear();
        record.message = "x".repeat(8 * 1024 + 1);
        assert!(!record.valid());
    }
    #[test]
    fn repeated_credentials_and_unicode_context_are_redacted() {
        assert_eq!(
            redact("name token=one TOKEN=two password=three secret=four"),
            "name token=[REDACTED] TOKEN=[REDACTED] password=[REDACTED] secret=[REDACTED]"
        );
        assert_eq!(
            redact("имя token=значение next"),
            "имя token=[REDACTED] next"
        );
    }
}
