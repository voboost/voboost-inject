//! Device-authorized requests and QNX-authenticated observations. TLS is courier identity only.
use crate::{
    ascii_json,
    catalog::{validate_string_map, Domain},
    digest,
    generation::GenerationIdentity,
    hash, identifier, parse_canonical, printable, Result, MAX_DOCUMENT_BYTES, MAX_SAFE_INTEGER,
};
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
pub const DESIRED_TRANSCRIPT: &[u8] = b"VOBOOST_CLUSTER_DESIRED_V1\0";
pub const REQUEST_TRANSCRIPT: &[u8] = b"VOBOOST_CLUSTER_REQUEST_V1\0";
pub const RECEIPT_TRANSCRIPT: &[u8] = b"VOBOOST_CLUSTER_RECEIPT_V1\0";
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RequestKind {
    Generation,
    Desired,
    Observe,
    Uninstall,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredAgent {
    pub id: String,
    pub enabled: bool,
    pub options: BTreeMap<String, String>,
}
/// Confirmed Android Binder readback, independently signed from module intent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GlobalLocale {
    pub locale: u32,
    pub revision: u64,
    pub endpoint_identity: u64,
    pub lifecycle_generation: u64,
    pub document_generation: u64,
}
impl GlobalLocale {
    pub fn validate(&self) -> Result<()> {
        if !(1..=3).contains(&self.locale)
            || [
                self.revision,
                self.endpoint_identity,
                self.lifecycle_generation,
                self.document_generation,
            ]
            .iter()
            .any(|v| *v == 0 || *v > MAX_SAFE_INTEGER)
        {
            return Err("invalid confirmed global locale".into());
        }
        Ok(())
    }
    pub fn follows(&self, old: &Self) -> bool {
        self.lifecycle_generation > old.lifecycle_generation
            || (self.lifecycle_generation == old.lifecycle_generation
                && self.endpoint_identity == old.endpoint_identity
                && self.document_generation >= old.document_generation
                && (self.revision > old.revision || (self.revision == old.revision && self == old)))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub kind: RequestKind,
    pub pair_id: String,
    pub domain: Domain,
    pub authority_epoch: String,
    pub transaction_id: String,
    pub catalog_sha256: String,
    pub closure_sha256: String,
    pub challenge: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_manifest_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<crate::wire::WireFile>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desired_revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desired_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agents: Option<Vec<DesiredAgent>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub global_locale: Option<GlobalLocale>,
}
impl Request {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.domain != Domain::Cluster
            || ![
                &self.pair_id,
                &self.authority_epoch,
                &self.transaction_id,
                &self.catalog_sha256,
                &self.closure_sha256,
                &self.challenge,
            ]
            .iter()
            .all(|s| digest(s))
        {
            return Err("invalid request authority".into());
        }
        if let Some(locale) = &self.global_locale {
            if self.kind != RequestKind::Desired {
                return Err("global locale outside desired".into());
            }
            locale.validate()?;
        }
        match self.kind {
            RequestKind::Generation => {
                if self.desired_revision.is_some()
                    || self.desired_sha256.is_some()
                    || self.agents.is_some()
                    || !self
                        .release_manifest_sha256
                        .as_deref()
                        .map(digest)
                        .unwrap_or(false)
                {
                    return Err("invalid generation request fields".into());
                }
                crate::wire::validate_files(
                    self.files.as_deref().ok_or("generation files missing")?,
                    false,
                )?;
            }
            RequestKind::Desired => {
                if self.files.is_some() || self.release_manifest_sha256.is_some() {
                    return Err("invalid desired request fields".into());
                }
                validate_revision(self.desired_revision, self.desired_sha256.as_deref())?;
                let agents = self.agents.as_deref().ok_or("desired agents missing")?;
                validate_desired(agents)?;
                if self.desired_sha256.as_deref() != Some(desired_digest(agents)?.as_str()) {
                    return Err("desired digest mismatch".into());
                }
            }
            RequestKind::Uninstall => {
                if self.files.is_some()
                    || self.agents.is_some()
                    || !self
                        .release_manifest_sha256
                        .as_deref()
                        .map(digest)
                        .unwrap_or(false)
                {
                    return Err("invalid uninstall request fields".into());
                }
                validate_revision(self.desired_revision, self.desired_sha256.as_deref())?;
            }
            RequestKind::Observe => {
                if self.files.is_some()
                    || self.release_manifest_sha256.is_some()
                    || self.agents.is_some()
                {
                    return Err("invalid observe request fields".into());
                }
                validate_revision(self.desired_revision, self.desired_sha256.as_deref())?;
            }
        }
        Ok(())
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = parse_canonical(bytes, MAX_DOCUMENT_BYTES - 68)?;
        value.validate()?;
        Ok(value)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = ascii_json(self)?;
        if bytes.len() + 68 > MAX_DOCUMENT_BYTES {
            return Err("signed request JSON exceeds bound".into());
        }
        Ok(bytes)
    }
    pub fn transcript(&self) -> &'static [u8] {
        match self.kind {
            RequestKind::Desired => DESIRED_TRANSCRIPT,
            _ => REQUEST_TRANSCRIPT,
        }
    }
    pub fn sign(&self, key: &SigningKey) -> Result<Vec<u8>> {
        sign_envelope(&self.canonical_bytes()?, self.transcript(), key)
    }
    pub fn verify(envelope: &[u8], key: &VerifyingKey) -> Result<Self> {
        let bytes = envelope_json(envelope)?;
        let value = Self::parse(bytes)?;
        verify_signature(bytes, &envelope[4 + bytes.len()..], value.transcript(), key)?;
        Ok(value)
    }
}
fn validate_revision(revision: Option<u64>, sha: Option<&str>) -> Result<()> {
    if revision.map(|r| r <= MAX_SAFE_INTEGER).unwrap_or(false) && sha.map(digest).unwrap_or(false)
    {
        Ok(())
    } else {
        Err("invalid desired revision/digest".into())
    }
}
pub fn validate_desired(agents: &[DesiredAgent]) -> Result<()> {
    if agents.len() > 64 {
        return Err("desired agent bound exceeded".into());
    }
    let mut prior = "";
    for a in agents {
        if !identifier(&a.id, 96) || a.id.as_str() <= prior {
            return Err("desired IDs not unique/sorted".into());
        }
        validate_string_map(&a.options)?;
        prior = &a.id;
    }
    Ok(())
}
pub fn desired_digest(agents: &[DesiredAgent]) -> Result<String> {
    validate_desired(agents)?;
    Ok(hash(&ascii_json(agents)?))
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReceiptKind {
    Generation,
    Desired,
    Observed,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObservedState {
    WaitingProcess,
    Injecting,
    Loaded,
    WaitingUi,
    Applied,
    Restoring,
    Disabled,
    Failed,
    Quarantined,
    ReloadRequired,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupervisorObservation {
    pub nonce: String,
    pub parent_pid: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: u64,
    pub birth_identity: String,
    pub executable_sha256: String,
    pub endpoint_epoch: String,
    pub lifecycle_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supervisor: Option<SupervisorObservation>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedAgent {
    pub id: String,
    #[serde(rename = "targetProcess")]
    pub target_process: String,
    pub state: ObservedState,
    pub reason: String,
    pub process: Option<ProcessIdentity>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub schema_version: u32,
    pub kind: ReceiptKind,
    pub pair_id: String,
    pub domain: Domain,
    pub authority_epoch: String,
    pub transaction_id: String,
    pub catalog_sha256: String,
    pub closure_sha256: String,
    pub selection_sha256: String,
    pub generation_id: String,
    pub desired_revision: u64,
    pub desired_sha256: String,
    pub challenge: String,
    pub daemon_epoch: String,
    pub boot_id: String,
    pub observation_revision: u64,
    pub agents: Vec<ObservedAgent>,
}
fn validate_observed_rows(rows: &[ObservedAgent]) -> Result<()> {
    if rows.len() > 64 {
        return Err("observed target count bound".into());
    }
    let mut prior = None;
    let mut owners = BTreeMap::new();
    let mut pids = BTreeMap::new();
    for a in rows {
        if !identifier(&a.id, 96)
            || !matches!(a.target_process.as_str(), "gauge" | "point" | "light")
            || prior.is_some_and(|p| (a.id.as_str(), a.target_process.as_str()) <= p)
            || !printable(&a.reason, 128)
        {
            return Err("invalid observed row".into());
        }
        prior = Some((a.id.as_str(), a.target_process.as_str()));
        if let Some(p) = &a.process {
            if owners
                .insert(a.target_process.as_str(), p)
                .is_some_and(|old| old != p)
                || pids
                    .insert(p.pid, a.target_process.as_str())
                    .is_some_and(|old| old != a.target_process)
            {
                return Err("inconsistent observed process owners".into());
            }
            if p.pid == 0
                || p.pid > MAX_SAFE_INTEGER
                || p.lifecycle_generation == 0
                || p.lifecycle_generation > MAX_SAFE_INTEGER
                || p.supervisor.as_ref().is_some_and(|s| {
                    s.parent_pid <= 1 || s.parent_pid > MAX_SAFE_INTEGER || !digest(&s.nonce)
                })
                || ![&p.birth_identity, &p.executable_sha256, &p.endpoint_epoch]
                    .iter()
                    .all(|s| digest(s))
            {
                return Err("invalid process epoch".into());
            }
        } else if matches!(
            a.state,
            ObservedState::Injecting
                | ObservedState::Loaded
                | ObservedState::WaitingUi
                | ObservedState::Applied
                | ObservedState::Restoring
                | ObservedState::ReloadRequired
        ) {
            return Err("live observed state lacks process identity".into());
        }
    }
    Ok(())
}
impl Receipt {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.domain != Domain::Cluster
            || ![
                &self.pair_id,
                &self.authority_epoch,
                &self.transaction_id,
                &self.catalog_sha256,
                &self.closure_sha256,
                &self.selection_sha256,
                &self.generation_id,
                &self.desired_sha256,
                &self.challenge,
                &self.daemon_epoch,
            ]
            .iter()
            .all(|s| digest(s))
            || !printable(&self.boot_id, 128)
            || self.desired_revision > MAX_SAFE_INTEGER
            || self.observation_revision == 0
            || self.observation_revision > MAX_SAFE_INTEGER
            || self.agents.len() > 64
        {
            return Err("invalid receipt envelope".into());
        }
        if self.identity().generation_id()? != self.generation_id {
            return Err("receipt generation digest mismatch".into());
        }
        validate_observed_rows(&self.agents)?;
        Ok(())
    }
    pub fn identity(&self) -> GenerationIdentity {
        GenerationIdentity {
            domain: self.domain,
            catalog_sha256: self.catalog_sha256.clone(),
            selection_sha256: self.selection_sha256.clone(),
            closure_sha256: self.closure_sha256.clone(),
        }
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = parse_canonical(bytes, MAX_DOCUMENT_BYTES - 68)?;
        value.validate()?;
        Ok(value)
    }
    pub fn sign(&self, key: &SigningKey) -> Result<Vec<u8>> {
        self.validate()?;
        sign_envelope(&ascii_json(self)?, RECEIPT_TRANSCRIPT, key)
    }
    pub fn verify(envelope: &[u8], key: &VerifyingKey) -> Result<Self> {
        let bytes = envelope_json(envelope)?;
        verify_signature(bytes, &envelope[4 + bytes.len()..], RECEIPT_TRANSCRIPT, key)?;
        Self::parse(bytes)
    }
    pub fn correlate(&self, request: &Request, accepted_generation: Option<&str>) -> Result<()> {
        self.validate()?;
        request.validate()?;
        if self.pair_id != request.pair_id
            || self.authority_epoch != request.authority_epoch
            || self.transaction_id != request.transaction_id
            || self.catalog_sha256 != request.catalog_sha256
            || self.closure_sha256 != request.closure_sha256
            || self.challenge != request.challenge
        {
            return Err("receipt does not correlate to current authority/challenge".into());
        }
        match request.kind {
            RequestKind::Generation if self.kind == ReceiptKind::Generation => {}
            RequestKind::Desired | RequestKind::Observe => {
                if accepted_generation != Some(self.generation_id.as_str())
                    || Some(self.desired_revision) != request.desired_revision
                    || Some(self.desired_sha256.as_str()) != request.desired_sha256.as_deref()
                    || self.kind
                        != match request.kind {
                            RequestKind::Desired => ReceiptKind::Desired,
                            _ => ReceiptKind::Observed,
                        }
                {
                    return Err("receipt desired/generation mismatch".into());
                }
            }
            _ => return Err("receipt kind mismatch".into()),
        }
        Ok(())
    }
}
pub(crate) fn envelope_json(envelope: &[u8]) -> Result<&[u8]> {
    if envelope.len() < 68 || envelope.len() > MAX_DOCUMENT_BYTES {
        return Err("signed envelope bound".into());
    }
    let size = u32::from_be_bytes(envelope[..4].try_into().map_err(|_| "frame length")?) as usize;
    if size == 0 || size.checked_add(68) != Some(envelope.len()) {
        return Err("signed envelope framing mismatch".into());
    }
    Ok(&envelope[4..4 + size])
}
pub(crate) fn verify_signature(
    bytes: &[u8],
    signature: &[u8],
    prefix: &[u8],
    key: &VerifyingKey,
) -> Result<()> {
    let signature = Signature::from_slice(signature).map_err(|_| "invalid raw signature")?;
    let mut transcript = prefix.to_vec();
    transcript.extend_from_slice(bytes);
    key.verify_strict(&transcript, &signature)
        .map_err(|_| "device authority signature rejected".into())
}
pub(crate) fn sign_envelope(bytes: &[u8], prefix: &[u8], key: &SigningKey) -> Result<Vec<u8>> {
    if bytes.len() + 68 > MAX_DOCUMENT_BYTES {
        return Err("signed envelope too large".into());
    }
    let mut transcript = prefix.to_vec();
    transcript.extend_from_slice(bytes);
    let signature = key.sign(&transcript);
    let mut out = (bytes.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    out.extend_from_slice(&signature.to_bytes());
    Ok(out)
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptedDesired {
    pub authority_epoch: String,
    pub catalog_sha256: String,
    pub closure_sha256: String,
    pub desired_revision: u64,
    pub desired_sha256: String,
    pub agents: Vec<DesiredAgent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub global_locale: Option<GlobalLocale>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DesiredAdmission {
    Changed,
    Idempotent,
}
impl AcceptedDesired {
    pub fn admit(
        current: Option<&Self>,
        request: &Request,
        pair_epoch: &str,
        catalog: &str,
        closure: &str,
    ) -> Result<(Self, DesiredAdmission)> {
        request.validate()?;
        if request.kind != RequestKind::Desired
            || request.authority_epoch != pair_epoch
            || request.catalog_sha256 != catalog
            || request.closure_sha256 != closure
        {
            return Err("desired is not bound to accepted authority/closure".into());
        }
        let next = Self {
            authority_epoch: request.authority_epoch.clone(),
            catalog_sha256: catalog.into(),
            closure_sha256: closure.into(),
            desired_revision: request.desired_revision.ok_or("revision missing")?,
            desired_sha256: request.desired_sha256.clone().ok_or("digest missing")?,
            agents: request.agents.clone().ok_or("agents missing")?,
            global_locale: request.global_locale.clone(),
        };
        if let Some(old) = current {
            if old.authority_epoch != pair_epoch {
                return Err("authority rotation requires explicit paired operation".into());
            }
            if let (Some(next_locale), Some(old_locale)) = (&next.global_locale, &old.global_locale)
            {
                if !next_locale.follows(old_locale) {
                    return Err("global locale rollback/conflict".into());
                }
            }
            if next.desired_revision < old.desired_revision {
                return Err("desired rollback rejected".into());
            }
            if next.desired_revision == old.desired_revision {
                if next.desired_sha256 != old.desired_sha256
                    || next.global_locale != old.global_locale
                {
                    return Err("same desired revision changed intent bytes".into());
                }
                if next.catalog_sha256 == old.catalog_sha256
                    && next.closure_sha256 == old.closure_sha256
                {
                    return Ok((old.clone(), DesiredAdmission::Idempotent));
                }
                // The independently admitted current catalog/closure was checked above.
                // A generation change does not create a new user intent revision.
            }
        }
        Ok((next, DesiredAdmission::Changed))
    }
}
/// Independent Settings publication; never hashed into multimedia desired.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterAgentState {
    pub id: String,
    pub targets: Vec<ObservedAgent>,
    pub enabled: bool,
    pub options: BTreeMap<String, String>,
    pub state: ObservedState,
    pub reason: String,
    pub process: Option<ProcessIdentity>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeliveryState {
    Idle,
    Pending,
    SetupRequired,
    Unavailable,
    Failed,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClusterSnapshot {
    pub schema_version: u32,
    pub domain: Domain,
    pub snapshot_revision: u64,
    pub catalog_sha256: String,
    pub generation_id: Option<String>,
    pub desired_revision: u64,
    pub desired_sha256: String,
    pub observation_revision: u64,
    pub boot_id: Option<String>,
    pub daemon_epoch: Option<String>,
    pub delivery_state: DeliveryState,
    pub agents: Vec<ClusterAgentState>,
}
impl ClusterSnapshot {
    pub fn validate(&self) -> Result<()> {
        if self.snapshot_revision == 0
            || self.snapshot_revision > MAX_SAFE_INTEGER
            || self.schema_version != 1
            || self.domain != Domain::Cluster
            || !digest(&self.catalog_sha256)
            || !digest(&self.desired_sha256)
            || self
                .generation_id
                .as_deref()
                .map(|s| !digest(s))
                .unwrap_or(false)
            || self.desired_revision > MAX_SAFE_INTEGER
            || self.observation_revision > MAX_SAFE_INTEGER
            || self
                .boot_id
                .as_deref()
                .map(|s| !printable(s, 128))
                .unwrap_or(false)
            || self
                .daemon_epoch
                .as_deref()
                .map(|s| !digest(s))
                .unwrap_or(false)
            || self.agents.len() > 64
        {
            return Err("invalid cluster snapshot".into());
        }
        let desired: Vec<DesiredAgent> = self
            .agents
            .iter()
            .map(|a| DesiredAgent {
                id: a.id.clone(),
                enabled: a.enabled,
                options: a.options.clone(),
            })
            .collect();
        if desired_digest(&desired)? != self.desired_sha256 {
            return Err("snapshot desired projection digest mismatch".into());
        }
        for a in &self.agents {
            validate_observed_rows(&a.targets)?;
            if a.targets.is_empty() || a.targets.iter().any(|t| t.id != a.id) {
                return Err("snapshot target set invalid".into());
            }
            let expected_process = if a.targets.len() == 1 {
                a.targets[0].process.clone()
            } else {
                None
            };
            if a.process != expected_process {
                return Err("snapshot aggregate process differs from targets".into());
            }
            if !printable(&a.reason, 128) {
                return Err("invalid snapshot reason".into());
            }
            if a.state == ObservedState::Applied
                && (!matches!(&self.delivery_state, DeliveryState::Idle)
                    || self.generation_id.is_none()
                    || self.boot_id.is_none()
                    || self.daemon_epoch.is_none()
                    || self.observation_revision == 0
                    || a.targets
                        .iter()
                        .any(|t| t.state != ObservedState::Applied || t.process.is_none())
                    || !a.enabled)
            {
                return Err("applied snapshot lacks current domain/process authority".into());
            }
        }
        Ok(())
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = parse_canonical(bytes, MAX_DOCUMENT_BYTES)?;
        value.validate()?;
        Ok(value)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = ascii_json(self)?;
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err("cluster snapshot exceeds byte bound".into());
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod system_locale_tests {
    use super::*;
    fn locale() -> GlobalLocale {
        GlobalLocale {
            locale: 3,
            revision: 10,
            endpoint_identity: 5,
            lifecycle_generation: 7,
            document_generation: 2,
        }
    }
    #[test]
    fn bounds_and_replay_fences() {
        let old = locale();
        assert!(old.validate().is_ok());
        assert!(old.follows(&old));
        let mut next = old.clone();
        next.locale = 1;
        assert!(!next.follows(&old));
        next.revision += 1;
        assert!(next.follows(&old));
        next.endpoint_identity += 1;
        assert!(!next.follows(&old));
        next.lifecycle_generation += 1;
        next.revision = 1;
        assert!(next.follows(&old));
        next.locale = 0;
        assert!(next.validate().is_err());
        next.locale = 1;
        next.document_generation = 0;
        assert!(next.validate().is_err());
    }
    #[test]
    fn absent_observation_preserves_intent_digest() {
        let agents = alloc::vec![DesiredAgent {
            id: "i18n-ru".into(),
            enabled: true,
            options: BTreeMap::new()
        }];
        assert_eq!(
            desired_digest(&agents).unwrap(),
            hash(&ascii_json(&agents).unwrap())
        );
        let serialized = ascii_json(&locale()).unwrap();
        let mut parsed: GlobalLocale = serde_json::from_slice(&serialized).unwrap();
        assert_eq!(parsed, locale());
        parsed.revision = 0;
        assert!(parsed.validate().is_err());
    }
}
