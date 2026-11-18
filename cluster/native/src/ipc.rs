use crate::Result;
use alloc::{string::String, vec::Vec};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use voboost_contract_core::{
    ascii_json,
    cluster::{ObservedAgent, ProcessIdentity},
    digest, parse_canonical, MAX_SAFE_INTEGER,
};
pub const PREFIX: &[u8] = b"VOBOOST_CLUSTER_IPC_V1\0";
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Request,
    Response,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum Body {
    Hello {},
    Register {
        process: ProcessIdentity,
    },
    Apply {
        #[serde(
            default,
            rename = "globalLocale",
            skip_serializing_if = "Option::is_none"
        )]
        global_locale: Option<voboost_contract_core::cluster::GlobalLocale>,
        #[serde(default, rename = "globalLocaleDeadlineMs")]
        global_locale_deadline_ms: u64,
        #[serde(rename = "generationId")]
        generation_id: String,
        #[serde(rename = "desiredRevision")]
        desired_revision: u64,
        #[serde(rename = "desiredSha256")]
        desired_sha256: String,
        agents: Vec<voboost_contract_core::cluster::DesiredAgent>,
    },
    PwLive {
        proof: Option<voboost_contract_core::pw_live::Proof>,
        #[serde(rename = "deadlineMs")]
        deadline_ms: u64,
    },
    Observe {},
    Stop {},
    Snapshot {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        supervisor: Option<voboost_contract_core::cluster::SupervisorObservation>,
        #[serde(rename = "generationId")]
        generation_id: Option<String>,
        #[serde(rename = "desiredRevision")]
        desired_revision: u64,
        #[serde(rename = "desiredSha256")]
        desired_sha256: String,
        agents: Vec<ObservedAgent>,
        stopped: bool,
    },
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Message {
    pub schema_version: u32,
    pub daemon_nonce: String,
    pub controller_nonce: String,
    pub direction: Direction,
    pub sequence: u64,
    pub body: Body,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    message: Message,
    mac: String,
}
impl Message {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || !digest(&self.daemon_nonce)
            || !digest(&self.controller_nonce)
            || self.sequence > MAX_SAFE_INTEGER
        {
            return Err("invalid IPC epoch/counter".into());
        }
        match &self.body {
            Body::Apply {
                global_locale,
                global_locale_deadline_ms,
                generation_id,
                desired_revision,
                desired_sha256,
                agents,
            } if (*global_locale_deadline_ms > MAX_SAFE_INTEGER)
                || (global_locale.is_some() && *global_locale_deadline_ms == 0)
                || global_locale
                    .as_ref()
                    .is_some_and(|v| v.validate().is_err())
                || !digest(generation_id)
                || !digest(desired_sha256)
                || *desired_revision > MAX_SAFE_INTEGER
                || agents.len() > 64
                || agents.windows(2).any(|pair| pair[0].id >= pair[1].id) =>
            {
                Err("invalid IPC authority reference".into())
            }
            Body::PwLive { proof, deadline_ms }
                if *deadline_ms > MAX_SAFE_INTEGER
                    || (proof.is_none() && *deadline_ms != 0)
                    || (proof.is_some() && *deadline_ms == 0)
                    || proof.as_ref().is_some_and(|p| p.validate().is_err()) =>
            {
                Err("invalid IPC PW live observation".into())
            }
            Body::Snapshot {
                supervisor,
                generation_id,
                desired_revision,
                desired_sha256,
                agents,
                ..
            } if supervisor.as_ref().is_some_and(|s| {
                s.parent_pid <= 1 || s.parent_pid > MAX_SAFE_INTEGER || !digest(&s.nonce)
            }) || generation_id
                .as_deref()
                .map(|v| !digest(v))
                .unwrap_or(false)
                || !digest(desired_sha256)
                || *desired_revision > MAX_SAFE_INTEGER
                || agents.len() > 64 =>
            {
                Err("invalid IPC observation".into())
            }
            _ => Ok(()),
        }
    }
    pub fn hello(bytes: &[u8], secret: &[u8; 32], controller: &str) -> Result<Self> {
        let envelope: Envelope = parse_canonical(bytes, 65536)?;
        if !matches!(envelope.message.body, Body::Hello {}) {
            return Err("IPC session hello required".into());
        }
        Self::open(
            bytes,
            secret,
            &envelope.message.daemon_nonce,
            controller,
            Direction::Request,
            0,
        )
    }
    pub fn seal(&self, secret: &[u8; 32]) -> Result<Vec<u8>> {
        self.validate()?;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| "IPC secret")?;
        mac.update(PREFIX);
        mac.update(&ascii_json(self)?);
        let envelope = Envelope {
            message: self.clone(),
            mac: hex::encode(mac.finalize().into_bytes()),
        };
        let b = ascii_json(&envelope)?;
        if b.len() > 65536 {
            return Err("IPC frame bound".into());
        }
        Ok(b)
    }
    pub fn open(
        bytes: &[u8],
        secret: &[u8; 32],
        daemon: &str,
        controller: &str,
        direction: Direction,
        sequence: u64,
    ) -> Result<Self> {
        let e: Envelope = parse_canonical(bytes, 65536)?;
        e.message.validate()?;
        if !digest(&e.mac) {
            return Err("IPC MAC must be lowercase raw32 hex".into());
        }
        if e.message.daemon_nonce != daemon
            || e.message.controller_nonce != controller
            || e.message.direction != direction
            || e.message.sequence != sequence
        {
            return Err("stale IPC session/direction/counter".into());
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| "IPC secret")?;
        mac.update(PREFIX);
        mac.update(&ascii_json(&e.message)?);
        mac.verify_slice(&hex::decode(e.mac).map_err(|_| "IPC MAC hex")?)
            .map_err(|_| "IPC authentication rejected")?;
        Ok(e.message)
    }
}
pub fn advance(sequence: u64) -> Result<u64> {
    sequence
        .checked_add(1)
        .filter(|s| *s <= MAX_SAFE_INTEGER)
        .ok_or_else(|| "IPC counter exhausted".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pw_live_has_strict_separate_variant_and_revoke_bounds() {
        let mut m = Message {
            schema_version: 1,
            daemon_nonce: "a".repeat(64),
            controller_nonce: "b".repeat(64),
            direction: Direction::Request,
            sequence: 1,
            body: Body::PwLive {
                proof: None,
                deadline_ms: 0,
            },
        };
        assert!(m.validate().is_ok());
        let bytes = m.seal(&[7; 32]).unwrap();
        assert!(matches!(
            Message::open(
                &bytes,
                &[7; 32],
                &m.daemon_nonce,
                &m.controller_nonce,
                Direction::Request,
                1
            )
            .unwrap()
            .body,
            Body::PwLive {
                proof: None,
                deadline_ms: 0
            }
        ));
        m.body = Body::PwLive {
            proof: None,
            deadline_ms: 1,
        };
        assert!(m.validate().is_err());
        assert!(parse_canonical::<Body>(
            br#"{"kind":"pwLive","proof":null,"deadlineMs":0,"globalLocale":null}"#,
            4096
        )
        .is_err());
        assert!(parse_canonical::<Body>(
            br#"{"kind":"observe","proof":null,"deadlineMs":0}"#,
            4096
        )
        .is_err());
    }
    #[test]
    fn ipc_mac_binds_nonce_direction_sequence_and_exact_bytes() {
        let m = Message {
            schema_version: 1,
            daemon_nonce: "a".repeat(64),
            controller_nonce: "b".repeat(64),
            direction: Direction::Request,
            sequence: 1,
            body: Body::Observe {},
        };
        let bytes = m.seal(&[7; 32]).unwrap();
        Message::open(
            &bytes,
            &[7; 32],
            &m.daemon_nonce,
            &m.controller_nonce,
            Direction::Request,
            1,
        )
        .unwrap();
        assert!(Message::open(
            &bytes,
            &[8; 32],
            &m.daemon_nonce,
            &m.controller_nonce,
            Direction::Request,
            1
        )
        .is_err());
        assert!(Message::open(
            &bytes,
            &[7; 32],
            &"c".repeat(64),
            &m.controller_nonce,
            Direction::Request,
            1
        )
        .is_err());
        assert!(Message::open(
            &bytes,
            &[7; 32],
            &m.daemon_nonce,
            &m.controller_nonce,
            Direction::Response,
            1
        )
        .is_err());
        assert!(Message::open(
            &bytes,
            &[7; 32],
            &m.daemon_nonce,
            &m.controller_nonce,
            Direction::Request,
            2
        )
        .is_err());
        let mut changed = bytes.clone();
        changed.insert(1, b' ');
        assert!(Message::open(
            &changed,
            &[7; 32],
            &m.daemon_nonce,
            &m.controller_nonce,
            Direction::Request,
            1
        )
        .is_err());
        assert!(advance(MAX_SAFE_INTEGER).is_err());
    }
}
