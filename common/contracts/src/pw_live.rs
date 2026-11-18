//! Transient PW proof. Deliberately distinct from durable Desired/Request envelopes.
use crate::{
    ascii_json,
    cluster::{envelope_json, sign_envelope, verify_signature},
    digest, parse_canonical, Result, MAX_SAFE_INTEGER,
};
use alloc::{string::String, vec::Vec};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
/// Resolves initial observation through the daemon-owned saved agent choice.
/// Explicit user input always takes precedence over previously saved arming.
pub fn effective_intent(intent: &str, armed: Option<bool>) -> &str {
    match (intent, armed) {
        ("observe", Some(true)) => "on",
        ("observe", Some(false)) => "off",
        _ => intent,
    }
}
#[cfg(test)]
mod effective_intent_tests {
    #[test]
    fn saved_choice_does_not_override_explicit_input() {
        for (intent, armed, expected) in [
            ("observe", Some(true), "on"),
            ("observe", Some(false), "off"),
            ("observe", None, "observe"),
            ("off", Some(true), "off"),
            ("on", Some(false), "on"),
        ] {
            assert_eq!(super::effective_intent(intent, armed), expected);
        }
    }
}
pub const TRANSCRIPT: &[u8] = b"VOBOOST_CLUSTER_PW_LIVE_V1\0";
pub const MAX_SOURCE_AGE_MS: u64 = 3_000;
pub const CHALLENGE_MILLIS: u64 = 2_000;
pub const HELLO: &[u8] = b"{\"protocolVersion\":1,\"operation\":\"pwLive\"}\n";
pub const ACK: &[u8] = b"{\"status\":\"accepted\"}\n";
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "request", rename_all = "camelCase", deny_unknown_fields)]
pub enum LocalRequest {
    ClusterPwLiveProof {
        #[serde(rename = "protocolVersion")]
        protocol_version: u32,
        #[serde(rename = "requestId")]
        request_id: String,
        challenge: Challenge,
    },
}
impl LocalRequest {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let request: Self = parse_canonical(bytes, 4096)?;
        let Self::ClusterPwLiveProof {
            protocol_version,
            request_id,
            challenge,
        } = &request;
        if *protocol_version != 1 || !digest(request_id) {
            return Err("invalid PW local identity".into());
        }
        challenge.validate()?;
        Ok(request)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "response", rename_all = "camelCase", deny_unknown_fields)]
pub enum LocalResponse {
    ClusterPwLiveProof {
        #[serde(rename = "protocolVersion")]
        protocol_version: u32,
        #[serde(rename = "requestId")]
        request_id: String,
        /// Missing means unavailable/unknown. No app-chosen actual state.
        #[serde(skip_serializing_if = "Option::is_none")]
        proof: Option<String>,
    },
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Challenge {
    pub schema_version: u32,
    pub native_boot: String,
    pub native_epoch: String,
    pub nonce: String,
    pub pair_id: String,
    pub generation_id: String,
    pub desired_revision: u64,
    pub desired_sha256: String,
    pub desired_disabled: bool,
}
impl Challenge {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.desired_revision == 0
            || self.desired_revision > MAX_SAFE_INTEGER
            || [
                &self.native_boot,
                &self.native_epoch,
                &self.nonce,
                &self.pair_id,
                &self.generation_id,
                &self.desired_sha256,
            ]
            .iter()
            .any(|v| !digest(v))
        {
            return Err("invalid PW native challenge".into());
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Actual {
    Unknown,
    Enabled,
    Disabled,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Proof {
    pub challenge: Challenge,
    pub endpoint_identity: u64,
    pub document_generation: u64,
    pub lifecycle_generation: u64,
    pub observation_sequence: u64,
    pub source_age_ms: u64,
    pub desired_disabled: bool,
    pub actual: Actual,
}
impl Proof {
    pub fn validate(&self) -> Result<()> {
        self.challenge.validate()?;
        if [
            self.endpoint_identity,
            self.document_generation,
            self.lifecycle_generation,
            self.observation_sequence,
        ]
        .iter()
        .any(|v| *v == 0 || *v > MAX_SAFE_INTEGER)
            || self.source_age_ms > MAX_SOURCE_AGE_MS
            || self.desired_disabled != self.challenge.desired_disabled
        {
            return Err("invalid PW live source".into());
        }
        Ok(())
    }
    /// The root signer must independently check current config and require a read
    /// sampled after receiving this challenge. An app-supplied observation is invalid.
    pub fn sign(&self, key: &SigningKey) -> Result<Vec<u8>> {
        self.validate()?;
        sign_envelope(&ascii_json(self)?, TRANSCRIPT, key)
    }
    pub fn verify(bytes: &[u8], key: &VerifyingKey) -> Result<Self> {
        let json = envelope_json(bytes)?;
        verify_signature(json, &bytes[4 + json.len()..], TRANSCRIPT, key)?;
        let proof: Self = parse_canonical(json, 4096)?;
        proof.validate()?;
        Ok(proof)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn proof() -> Proof {
        Proof {
            challenge: Challenge {
                schema_version: 1,
                native_boot: "1".repeat(64),
                native_epoch: "2".repeat(64),
                nonce: "3".repeat(64),
                pair_id: "4".repeat(64),
                generation_id: "5".repeat(64),
                desired_revision: 1,
                desired_sha256: "6".repeat(64),
                desired_disabled: true,
            },
            endpoint_identity: 1,
            document_generation: 1,
            lifecycle_generation: 1,
            observation_sequence: 1,
            source_age_ms: 0,
            desired_disabled: true,
            actual: Actual::Unknown,
        }
    }
    #[test]
    fn signed_unknown_is_not_assumed_disabled() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let p = proof();
        assert_eq!(
            Proof::verify(&p.sign(&key).unwrap(), &key.verifying_key()).unwrap(),
            p
        );
    }
    #[test]
    fn separate_transcript_and_key() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let p = proof();
        let bytes = p.sign(&key).unwrap();
        assert!(Proof::verify(&bytes, &SigningKey::from_bytes(&[8; 32]).verifying_key()).is_err());
        let other = sign_envelope(
            &ascii_json(&p).unwrap(),
            crate::cluster::REQUEST_TRANSCRIPT,
            &key,
        )
        .unwrap();
        assert!(Proof::verify(&other, &key.verifying_key()).is_err());
    }
    #[test]
    fn strict_bounds() {
        let mut p = proof();
        p.source_age_ms = MAX_SOURCE_AGE_MS + 1;
        assert!(p.validate().is_err());
        p = proof();
        p.observation_sequence = 0;
        assert!(p.validate().is_err());
        let mut json = ascii_json(&proof()).unwrap();
        json.pop();
        let mut text = alloc::string::String::from_utf8(json).unwrap();
        text.pop();
        text.push_str(",\"extra\":1}\n");
        let key = SigningKey::from_bytes(&[7; 32]);
        assert!(Proof::verify(
            &sign_envelope(text.as_bytes(), TRANSCRIPT, &key).unwrap(),
            &key.verifying_key()
        )
        .is_err());
    }
    #[test]
    fn local_proof_request_is_separate_strict_and_bounded() {
        let request = LocalRequest::ClusterPwLiveProof {
            protocol_version: 1,
            request_id: "7".repeat(64),
            challenge: proof().challenge,
        };
        let bytes = ascii_json(&request).unwrap();
        assert!(LocalRequest::parse(&bytes).is_ok());
        assert!(crate::wire::LocalRequest::parse(&bytes).is_err());
        let mut json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        json["extra"] = serde_json::Value::Bool(true);
        assert!(LocalRequest::parse(&ascii_json(&json).unwrap()).is_err());
        let oversized = alloc::vec![b' '; 4097];
        assert!(LocalRequest::parse(&oversized).is_err());
        let invalid = LocalRequest::ClusterPwLiveProof {
            protocol_version: 2,
            request_id: "7".repeat(64),
            challenge: proof().challenge,
        };
        assert!(LocalRequest::parse(&ascii_json(&invalid).unwrap()).is_err());
    }
}
