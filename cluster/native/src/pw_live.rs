//! Connection-local one-use challenge. No disk state, no durable desired mutation.
use crate::Result;
use ed25519_dalek::VerifyingKey;
use voboost_contract_core::pw_live::{Challenge, Proof, CHALLENGE_MILLIS, MAX_SOURCE_AGE_MS};
pub struct Pending {
    challenge: Option<Challenge>,
    issued_ms: u64,
    deadline_ms: u64,
}
pub struct Accepted {
    pub proof: Proof,
    /// Native monotonic expiry; source age and total network time reduce it.
    pub expires_ms: u64,
}
fn active(a: &crate::engine::Authority, nonce: alloc::string::String) -> Result<Challenge> {
    if a.root.exists("restore.lock")? {
        return Err("PW restore is fenced".into());
    }
    let generation = a.generation.as_ref().ok_or("PW generation absent")?;
    let desired = a.desired.as_ref().ok_or("PW config absent")?;
    let pw = desired
        .agents
        .iter()
        .find(|v| v.id == "vehicle-drive-pedestrian-warning")
        .ok_or("PW visual agent not selected")?;
    Ok(Challenge {
        schema_version: 1,
        native_boot: voboost_contract_core::hash(a.boot_id.as_bytes()),
        native_epoch: a.daemon_epoch.clone(),
        nonce,
        pair_id: a.config.pair_id.clone(),
        generation_id: generation.generation_id.clone(),
        desired_revision: desired.desired_revision,
        desired_sha256: desired.desired_sha256.clone(),
        desired_disabled: pw.enabled,
    })
}
/// Distinct bounded TLS exchange; ordinary generation/locale courier remains unchanged.
pub fn exchange(a: &mut crate::engine::Authority, stream: &crate::tls::Stream) -> Result<()> {
    let _operation = crate::operation::Lock::existing(&a.root)?;
    a.live_pw = None; // A failed/new observation cannot preserve older suppression.
    let now = crate::engine::monotonic_ms().ok_or("PW native clock unavailable")?;
    let challenge = active(a, crate::nonce()?)?;
    let mut pending = Pending::new(challenge.clone(), now)?;
    let deadline = now
        .checked_add(CHALLENGE_MILLIS)
        .ok_or("PW deadline overflow")?;
    stream.write_frame_before(&voboost_contract_core::ascii_json(&challenge)?, deadline)?;
    let bytes = stream.frame_before(deadline, 8192)?;
    let key = VerifyingKey::from_bytes(&crate::key(&a.config.android_public_key)?)
        .map_err(|_| "PW peer key")?;
    let current = active(a, challenge.nonce.clone())?;
    let now = crate::engine::monotonic_ms().ok_or("PW native clock unavailable")?;
    let accepted = pending.consume(&bytes, &key, &current, now)?;
    let completed = crate::engine::monotonic_ms().ok_or("PW native clock unavailable")?;
    if completed >= deadline
        || completed >= accepted.expires_ms
        || active(a, challenge.nonce.clone())? != current
    {
        return Err("PW proof expired during verification".into());
    }
    a.live_pw = Some(accepted);
    stream.write_frame_before(voboost_contract_core::pw_live::ACK, deadline)
}
impl Pending {
    /// Caller supplies native CSPRNG nonce, native process incarnation and active
    /// authenticated generation/config. Never construct these from courier input.
    pub fn new(challenge: Challenge, now_ms: u64) -> Result<Self> {
        challenge.validate()?;
        let deadline_ms = now_ms
            .checked_add(CHALLENGE_MILLIS)
            .ok_or("PW clock overflow")?;
        Ok(Self {
            challenge: Some(challenge),
            issued_ms: now_ms,
            deadline_ms,
        })
    }
    pub fn challenge(&self) -> Option<&Challenge> {
        self.challenge.as_ref()
    }
    /// Consume BEFORE verification: malformed/signature failures cannot reuse the
    /// challenge. active must be freshly read from current authority at receipt.
    pub fn consume(
        &mut self,
        bytes: &[u8],
        key: &VerifyingKey,
        active: &Challenge,
        now_ms: u64,
    ) -> Result<Accepted> {
        let challenge = self
            .challenge
            .take()
            .ok_or("PW challenge already consumed")?;
        if now_ms < self.issued_ms || now_ms >= self.deadline_ms || &challenge != active {
            return Err("PW challenge expired or authority changed".into());
        }
        let proof = Proof::verify(bytes, key)?;
        if proof.challenge != challenge {
            return Err("PW challenge mismatch".into());
        }
        // Conservative bound: charge the entire native exchange time in addition
        // to the root-measured source age; clocks never cross OS boundaries.
        let budget = MAX_SOURCE_AGE_MS
            .checked_sub(proof.source_age_ms)
            .and_then(|v| v.checked_sub(now_ms - self.issued_ms))
            .filter(|v| *v > 0)
            .ok_or("PW observation expired in transit")?;
        let expires_ms = now_ms
            .checked_add(budget)
            .ok_or("PW lease clock overflow")?;
        Ok(Accepted { proof, expires_ms })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use voboost_contract_core::pw_live::Actual;
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
            source_age_ms: 100,
            desired_disabled: true,
            actual: Actual::Disabled,
        }
    }
    #[test]
    fn one_use_and_conservative_expiry() {
        let p = proof();
        let k = SigningKey::from_bytes(&[7; 32]);
        let bytes = p.sign(&k).unwrap();
        let mut gate = Pending::new(p.challenge.clone(), 100).unwrap();
        let accepted = gate
            .consume(&bytes, &k.verifying_key(), &p.challenge, 200)
            .unwrap();
        assert_eq!(accepted.expires_ms, 3000);
        assert!(gate
            .consume(&bytes, &k.verifying_key(), &p.challenge, 201)
            .is_err());
    }
    #[test]
    fn invalid_signature_burns_nonce() {
        let p = proof();
        let k = SigningKey::from_bytes(&[7; 32]);
        let mut gate = Pending::new(p.challenge.clone(), 100).unwrap();
        assert!(gate
            .consume(b"bad", &k.verifying_key(), &p.challenge, 110)
            .is_err());
        assert!(gate
            .consume(&p.sign(&k).unwrap(), &k.verifying_key(), &p.challenge, 111)
            .is_err());
    }
    #[test]
    fn stale_authority_clock_and_transit_expiry() {
        let p = proof();
        let k = SigningKey::from_bytes(&[7; 32]);
        let bytes = p.sign(&k).unwrap();
        for now in [99, 2100] {
            let mut gate = Pending::new(p.challenge.clone(), 100).unwrap();
            assert!(gate
                .consume(&bytes, &k.verifying_key(), &p.challenge, now)
                .is_err());
        }
        let mut aged = p.clone();
        aged.source_age_ms = 2900;
        let mut gate = Pending::new(aged.challenge.clone(), 100).unwrap();
        assert!(gate
            .consume(
                &aged.sign(&k).unwrap(),
                &k.verifying_key(),
                &aged.challenge,
                200
            )
            .is_err());
        let mut gate = Pending::new(p.challenge.clone(), 100).unwrap();
        let mut changed = p.challenge.clone();
        changed.desired_revision += 1;
        assert!(gate
            .consume(&bytes, &k.verifying_key(), &changed, 101)
            .is_err());
    }
}
