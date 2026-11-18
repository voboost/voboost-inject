//! Transient log pull over the paired mTLS channel. Android returns the durable
//! watermark in its next pull, so the QNX listener never waits for disk writes.
use crate::{ascii_json, identifier, parse_canonical, printable, Result, MAX_DOCUMENT_BYTES};
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use serde::{Deserialize, Serialize};

pub const MAX_FRAME_BYTES: usize = MAX_DOCUMENT_BYTES;
pub const MAX_REQUEST_BYTES: usize = 256;
pub const MAX_EVENTS: usize = 8;
pub const MAX_TIMESTAMP_BYTES: usize = 32;
pub const MAX_SOURCE_BYTES: usize = 64;
pub const MAX_SESSION_BYTES: usize = 64;
pub const MAX_COMPONENT_BYTES: usize = 64;
pub const MAX_MESSAGE_BYTES: usize = 512;
pub const MAX_FIELDS: usize = 4;
pub const MAX_FIELD_KEY_BYTES: usize = 64;
pub const MAX_FIELD_VALUE_BYTES: usize = 128;

const OPERATION: &str = "clusterLog";
pub const HELLO: &[u8] = b"{\"protocolVersion\":1,\"operation\":\"clusterLog\"}\n";

pub fn valid_source_session(value: &str) -> bool {
    identifier(value, MAX_SESSION_BYTES)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Request {
    /// The latest watermark durably persisted by the authenticated Android peer.
    pub ack: Option<Ack>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireRequest {
    protocol_version: u8,
    operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ack: Option<Ack>,
}

impl Request {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if let Some(ack) = &self.ack {
            ack.validate()?;
        }
        ascii_json(&WireRequest {
            protocol_version: 1,
            operation: OPERATION.into(),
            ack: self.ack.clone(),
        })
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let wire: WireRequest = parse_canonical(bytes, MAX_REQUEST_BYTES)?;
        if wire.protocol_version != 1 || wire.operation != OPERATION {
            return Err("invalid cluster log request".into());
        }
        if let Some(ack) = &wire.ack {
            ack.validate()?;
        }
        Ok(Self { ack: wire.ack })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(
    tag = "status",
    content = "batch",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum Response {
    Idle,
    Batch(Batch),
}

impl Response {
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = ascii_json(self)?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err("cluster log response exceeds frame bound".into());
        }
        Ok(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let response: Self = parse_canonical(bytes, MAX_FRAME_BYTES)?;
        response.validate()?;
        Ok(response)
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Idle => Ok(()),
            Self::Batch(batch) => batch.validate(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Batch {
    /// QNX generates a fresh identity each time the source starts.
    pub source_session: String,
    /// Starts at one and increases after each matching ACK. Retries are immutable.
    pub sequence: u64,
    /// Events lost since the previous batch was prepared, including during disconnects.
    pub dropped: u64,
    pub events: Vec<Event>,
}

impl Batch {
    pub fn validate(&self) -> Result<()> {
        if !valid_source_session(&self.source_session)
            || self.sequence == 0
            || self.sequence > crate::MAX_SAFE_INTEGER
            || self.dropped > crate::MAX_SAFE_INTEGER
            || (self.events.is_empty() && self.dropped == 0)
            || self.events.len() > MAX_EVENTS
        {
            return Err("invalid cluster log batch".into());
        }
        for event in &self.events {
            event.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ack {
    pub source_session: String,
    pub sequence: u64,
}

impl Ack {
    pub fn validate(&self) -> Result<()> {
        if !valid_source_session(&self.source_session)
            || self.sequence == 0
            || self.sequence > crate::MAX_SAFE_INTEGER
        {
            return Err("invalid cluster log acknowledgement".into());
        }
        Ok(())
    }

    pub fn matches(&self, batch: &Batch) -> bool {
        self.source_session == batch.source_session && self.sequence == batch.sequence
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Debug,
    Info,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Event {
    pub timestamp: String,
    pub level: Level,
    pub source: String,
    pub component: String,
    pub message: String,
    pub fields: BTreeMap<String, String>,
}

impl Event {
    pub fn validate(&self) -> Result<()> {
        if !printable(&self.timestamp, MAX_TIMESTAMP_BYTES)
            || !printable(&self.source, MAX_SOURCE_BYTES)
            || !printable(&self.component, MAX_COMPONENT_BYTES)
            || !valid_text(&self.message, MAX_MESSAGE_BYTES)
            || self.fields.len() > MAX_FIELDS
            || self.fields.iter().any(|(key, value)| {
                key.is_empty()
                    || !valid_text(key, MAX_FIELD_KEY_BYTES)
                    || key.chars().any(char::is_control)
                    || !valid_text(value, MAX_FIELD_VALUE_BYTES)
            })
        {
            return Err("invalid cluster log event".into());
        }
        Ok(())
    }
}

fn valid_text(value: &str, max_bytes: usize) -> bool {
    value.len() <= max_bytes
        && value
            .chars()
            .all(|ch| !ch.is_control() || matches!(ch, '\n' | '\t'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch() -> Batch {
        Batch {
            source_session: "0b9c63ef".into(),
            sequence: 7,
            dropped: 2,
            events: alloc::vec![Event {
                timestamp: "2026-11-09T14:00:00.000Z".into(),
                level: Level::Error,
                source: "preload:29".into(),
                component: "controller".into(),
                message: "ошибка\n".into(),
                fields: BTreeMap::from([("reason".into(), "test".into())]),
            }],
        }
    }

    #[test]
    fn request_is_separate_and_accepts_only_canonical_watermark() {
        let batch = batch();
        let mut ack = Ack {
            source_session: batch.source_session.clone(),
            sequence: batch.sequence,
        };
        assert_eq!(Request::default().encode().unwrap(), HELLO);
        assert_eq!(Request::parse(HELLO).unwrap(), Request::default());
        assert!(Request::parse(crate::pw_live::HELLO).is_err());
        assert!(Request::parse(
            b"{\"protocolVersion\":1,\"operation\":\"clusterLog\",\"ack\":null}\n"
        )
        .is_err());
        assert!(Request::parse(
            b"{\"protocolVersion\":1,\"operation\":\"clusterLog\",\"extra\":1}\n"
        )
        .is_err());
        let request = Request {
            ack: Some(ack.clone()),
        };
        assert_eq!(Request::parse(&request.encode().unwrap()).unwrap(), request);
        assert!(ack.matches(&batch));
        ack.sequence -= 1;
        assert!(!ack.matches(&batch));
        ack.sequence = batch.sequence;
        ack.source_session = "other-source".into();
        assert!(!ack.matches(&batch));
        ack.source_session = "../invalid".into();
        assert!(Request { ack: Some(ack) }.encode().is_err());
    }

    #[test]
    fn batches_and_loss_only_round_trip_and_reject_invalid_identity() {
        let mut batch = batch();
        let response = Response::Batch(batch.clone());
        let bytes = response.encode().unwrap();
        assert_eq!(Response::parse(&bytes).unwrap(), response);
        assert_eq!(
            Response::parse(&Response::Idle.encode().unwrap()).unwrap(),
            Response::Idle
        );
        batch.events.clear();
        assert!(Response::Batch(batch.clone()).encode().is_ok());
        batch.dropped = 0;
        assert!(Response::parse(&ascii_json(&Response::Batch(batch.clone())).unwrap()).is_err());
        batch.dropped = 1;
        batch.sequence = 0;
        assert!(Response::Batch(batch.clone()).encode().is_err());
        batch.sequence = crate::MAX_SAFE_INTEGER + 1;
        assert!(Response::Batch(batch).encode().is_err());
        assert!(Response::parse(&alloc::vec![b' '; MAX_FRAME_BYTES + 1]).is_err());
    }

    #[test]
    fn maximum_structured_batch_fits_existing_frame_and_rejects_excess() {
        let mut batch = batch();
        let mut event = batch.events.pop().unwrap();
        event.message = "é".repeat(MAX_MESSAGE_BYTES / 2);
        event.fields = (0..MAX_FIELDS)
            .map(|i| {
                (
                    alloc::format!("{i}{}", "é".repeat((MAX_FIELD_KEY_BYTES - 1) / 2)),
                    "é".repeat(MAX_FIELD_VALUE_BYTES / 2),
                )
            })
            .collect();
        batch.events = alloc::vec![event.clone(); MAX_EVENTS];
        let bytes = Response::Batch(batch.clone()).encode().unwrap();
        assert!(crate::wire::frame(&bytes).is_ok());
        batch.events.push(event.clone());
        assert!(Response::Batch(batch).encode().is_err());
        event.fields.insert("one-more".into(), "value".into());
        assert!(event.validate().is_err());
        event.fields.clear();
        event.fields.insert("bad\tkey".into(), "value".into());
        assert!(event.validate().is_err());
        event.fields.clear();
        event.message.push('x');
        assert!(event.validate().is_err());
    }
}
