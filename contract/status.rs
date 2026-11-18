//! Narrow channel-independent app/daemon OTA boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::fd::FromRawFd;
use std::os::unix::fs::{FileExt, MetadataExt};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::release::Artifact;
use crate::release::{lower_hash, Manifest};

pub const MAX_STATUS_BYTES: usize = 512 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActiveArtifactIdentity {
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActiveReleaseIdentity {
    pub channel: String,
    pub release_identity: String,
    pub artifacts: BTreeMap<String, ActiveArtifactIdentity>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidateArtifactIdentity {
    pub file: String,
    pub size: u64,
    pub sha256: String,
}

/// Opaque operation identity. It is never interpreted as a path or command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OtaCandidateHandle {
    pub transaction_id: String,
    pub release_identity: String,
    pub manifest_sha256: String,
    pub artifacts: Vec<CandidateArtifactIdentity>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidateArtifactDescriptor {
    pub fd: i32,
    pub file: String,
    pub size: u64,
    pub sha256: String,
}

/// Transport adapter shape for already-opened descriptors. Integers are
/// descriptor slots in the receiving process, never filesystem paths.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidateDescriptorHandoff {
    pub manifest_fd: i32,
    pub signature_fd: i32,
    pub artifacts: Vec<CandidateArtifactDescriptor>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum DaemonProposalResult {
    Accepted,
    InstallApk,
    Pending,
    Rejected { reason: String },
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "request", deny_unknown_fields)]
pub enum DaemonOtaRequest {
    #[serde(rename = "activeRelease")]
    ActiveRelease,
    #[serde(rename = "propose")]
    Propose { candidate: OtaCandidateHandle },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalAcknowledgement {
    pub transaction_id: String,
    pub release_identity: String,
    pub manifest_sha256: String,
    pub outcome: TerminalOutcome,
}

/// Terminal outcome of a previously proposed OTA transaction, replayed by
/// the daemon through `activeRelease` so the app can retire its durable
/// PROPOSED/READY record. `complete` retires an exact-identity transaction;
/// `rejected` is informational and never authorizes retirement by itself.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TerminalOutcome {
    #[serde(rename = "complete")]
    Complete,
    #[serde(rename = "rejected")]
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ActiveReleaseResult {
    Active {
        identity: ActiveReleaseIdentity,
        /// Terminal acknowledgement of a previously proposed transaction.
        /// `None` while no update has been proposed (or after the terminal
        /// has been consumed by an exact-identity reconcile).
        #[serde(skip_serializing_if = "Option::is_none")]
        terminal: Option<TerminalAcknowledgement>,
    },
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "response", deny_unknown_fields)]
pub enum DaemonOtaResponse {
    #[serde(rename = "activeRelease")]
    ActiveRelease { result: ActiveReleaseResult },
    #[serde(rename = "propose")]
    Propose { result: DaemonProposalResult },
}

pub trait InstalledClosure {
    fn inventory(&mut self) -> Result<BTreeSet<String>, String>;
    fn read(&mut self, artifact: &Artifact) -> Result<Vec<u8>, String>;
}

pub struct VerifiedDescriptorCandidate {
    manifest: Manifest,
    manifest_bytes: Vec<u8>,
    signature_bytes: Vec<u8>,
}

pub struct MetadataOnlyManifestCommit(VerifiedDescriptorCandidate);

impl VerifiedDescriptorCandidate {
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    pub fn signature_bytes(&self) -> &[u8] {
        &self.signature_bytes
    }
}

impl MetadataOnlyManifestCommit {
    pub fn manifest(&self) -> &Manifest {
        &self.0.manifest
    }

    pub fn manifest_bytes(&self) -> &[u8] {
        &self.0.manifest_bytes
    }

    pub fn signature_bytes(&self) -> &[u8] {
        &self.0.signature_bytes
    }
}

impl ActiveReleaseIdentity {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_STATUS_BYTES {
            return Err("active release identity exceeds byte bound".into());
        }
        let value: Self = crate::release::parse_canonical(bytes, "active release identity")?;
        value.validate()?;
        Ok(value)
    }

    pub fn from_manifest(channel: String, manifest: &Manifest) -> Result<Self, String> {
        let artifacts = manifest
            .artifacts
            .iter()
            .map(|artifact| {
                (
                    artifact.file.clone(),
                    ActiveArtifactIdentity {
                        size: artifact.size,
                        sha256: artifact.sha256.clone(),
                    },
                )
            })
            .collect();
        let value = Self {
            channel,
            release_identity: manifest.release_identity.clone(),
            artifacts,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        let version = semver::Version::parse(&self.release_identity).ok();
        let channel_matches = version
            .as_ref()
            .is_some_and(|version| match self.channel.as_str() {
                "stable" => version.pre.is_empty(),
                "beta" => !version.pre.is_empty() && version.pre.as_str().starts_with("beta"),
                _ => false,
            });
        if !matches!(self.channel.as_str(), "stable" | "beta")
            || !canonical_semver(&self.release_identity)
            || !channel_matches
            || self.artifacts.is_empty()
            || self.artifacts.len() > crate::release::MAX_ARTIFACTS
            || self.release_identity.len() > crate::release::MAX_RELEASE_IDENTITY_BYTES
            || self.artifacts.iter().any(|(file, artifact)| {
                invalid_basename(file) || artifact.size == 0 || !lower_hash(&artifact.sha256)
            })
        {
            return Err("active release identity is invalid".into());
        }
        Ok(())
    }
}

impl OtaCandidateHandle {
    pub fn parse(bytes: &[u8], manifest: &Manifest) -> Result<Self, String> {
        if bytes.len() > MAX_STATUS_BYTES {
            return Err("OTA candidate handle exceeds byte bound".into());
        }
        let value: Self = crate::release::parse_canonical(bytes, "OTA candidate handle")?;
        value.validate(manifest)?;
        Ok(value)
    }

    pub fn validate(&self, manifest: &Manifest) -> Result<(), String> {
        if !lower_hash(&self.transaction_id)
            || !lower_hash(&self.manifest_sha256)
            || self.transaction_id == self.manifest_sha256
            || self.manifest_sha256 != manifest.digest()?
            || self.release_identity != manifest.release_identity
            || self.artifacts.len() > crate::release::MAX_ARTIFACTS
        {
            return Err("OTA candidate identity is invalid".into());
        }
        let expected = manifest
            .artifacts
            .iter()
            .filter_map(|artifact| {
                self.artifacts
                    .iter()
                    .any(|candidate| candidate.file == artifact.file)
                    .then_some(CandidateArtifactIdentity {
                        file: artifact.file.clone(),
                        size: artifact.size,
                        sha256: artifact.sha256.clone(),
                    })
            })
            .collect::<Vec<_>>();
        if expected != self.artifacts {
            return Err(
                "OTA candidate artifacts are unknown, altered, duplicate or reordered".into(),
            );
        }
        Ok(())
    }
}

impl CandidateDescriptorHandoff {
    pub fn parse(bytes: &[u8], candidate: &OtaCandidateHandle) -> Result<Self, String> {
        if bytes.len() > MAX_STATUS_BYTES {
            return Err("candidate descriptor handoff exceeds byte bound".into());
        }
        let value: Self = crate::release::parse_canonical(bytes, "candidate descriptor handoff")?;
        value.validate(candidate)?;
        Ok(value)
    }

    pub fn validate(&self, candidate: &OtaCandidateHandle) -> Result<(), String> {
        if self.manifest_fd < 0
            || self.signature_fd < 0
            || self.manifest_fd == self.signature_fd
            || self.artifacts.len() != candidate.artifacts.len()
        {
            return Err("candidate descriptor count or manifest pair is invalid".into());
        }
        let mut descriptors =
            std::collections::BTreeSet::from([self.manifest_fd, self.signature_fd]);
        for (descriptor, identity) in self.artifacts.iter().zip(&candidate.artifacts) {
            if descriptor.fd < 0
                || !descriptors.insert(descriptor.fd)
                || descriptor.file != identity.file
                || descriptor.size != identity.size
                || descriptor.sha256 != identity.sha256
            {
                return Err("candidate artifact descriptor identity is invalid".into());
            }
        }
        Ok(())
    }

    pub fn verify_open_descriptors(
        &self,
        candidate: &OtaCandidateHandle,
        product_public_key: &[u8; 32],
    ) -> Result<VerifiedDescriptorCandidate, String> {
        self.validate(candidate)?;
        let manifest_read = read_descriptor(
            self.manifest_fd,
            crate::release::MAX_MANIFEST_BYTES,
            "voboost.json",
        )?;
        let signature_read = read_descriptor(self.signature_fd, 64, "voboost.json.sig")?;
        let mut identities =
            std::collections::BTreeSet::from([manifest_read.identity, signature_read.identity]);
        if identities.len() != 2 {
            return Err("manifest and signature descriptors alias one inode".into());
        }
        if signature_read.bytes.len() != 64 {
            return Err("voboost.json.sig must contain exactly 64 bytes".into());
        }
        let manifest = crate::release::verify_manifest_signature(
            &manifest_read.bytes,
            &signature_read.bytes,
            product_public_key,
        )?;
        candidate.validate(&manifest)?;
        for descriptor in &self.artifacts {
            let identity = verify_artifact_descriptor(
                descriptor.fd,
                descriptor.size,
                &descriptor.sha256,
                &descriptor.file,
            )?;
            if !identities.insert(identity) {
                return Err(format!("candidate descriptor aliases {}", descriptor.file));
            }
        }
        Ok(VerifiedDescriptorCandidate {
            manifest,
            manifest_bytes: manifest_read.bytes,
            signature_bytes: signature_read.bytes,
        })
    }

    pub fn verify_metadata_only_installed_closure<C: InstalledClosure>(
        &self,
        candidate: &OtaCandidateHandle,
        active: &ActiveReleaseIdentity,
        product_public_key: &[u8; 32],
        installed: &mut C,
    ) -> Result<MetadataOnlyManifestCommit, String> {
        if !candidate.artifacts.is_empty() || !self.artifacts.is_empty() {
            return Err("metadata-only verification received changed artifact descriptors".into());
        }
        let verified = self.verify_open_descriptors(candidate, product_public_key)?;
        active.validate()?;
        let candidate_version = semver::Version::parse(&candidate.release_identity)
            .map_err(|_| "candidate release identity is invalid".to_string())?;
        let active_version = semver::Version::parse(&active.release_identity)
            .map_err(|_| "active release identity is invalid".to_string())?;
        let candidate_channel = if candidate_version.pre.is_empty() {
            "stable"
        } else if candidate_version.pre.as_str().starts_with("beta") {
            "beta"
        } else {
            return Err("candidate release channel is unsupported".into());
        };
        if candidate_channel != active.channel || candidate_version <= active_version {
            return Err(
                "metadata-only candidate is not strictly newer in the active channel".into(),
            );
        }
        let expected_active = verified
            .manifest
            .artifacts
            .iter()
            .map(|artifact| {
                (
                    artifact.file.clone(),
                    ActiveArtifactIdentity {
                        size: artifact.size,
                        sha256: artifact.sha256.clone(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        if active.artifacts != expected_active {
            return Err("active artifact identities differ from metadata-only manifest".into());
        }
        let expected = verified
            .manifest
            .artifacts
            .iter()
            .map(|artifact| artifact.file.clone())
            .collect::<BTreeSet<_>>();
        if installed.inventory()? != expected {
            return Err("installed product closure inventory differs".into());
        }
        for artifact in &verified.manifest.artifacts {
            let bytes = installed.read(artifact)?;
            if bytes.len() as u64 != artifact.size
                || hex::encode(Sha256::digest(&bytes)) != artifact.sha256
            {
                return Err(format!(
                    "installed product artifact differs for {}",
                    artifact.file
                ));
            }
        }
        Ok(MetadataOnlyManifestCommit(verified))
    }
}

struct DescriptorRead {
    bytes: Vec<u8>,
    identity: (u64, u64),
}

fn verify_artifact_descriptor(
    fd: i32,
    expected_size: u64,
    expected_sha256: &str,
    label: &str,
) -> Result<(u64, u64), String> {
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(format!("duplicate {label} descriptor failed"));
    }
    let file = unsafe { File::from_raw_fd(duplicate) };
    let before = file
        .metadata()
        .map_err(|error| format!("stat {label} descriptor: {error}"))?;
    if !before.is_file() || before.nlink() != 1 || before.len() != expected_size {
        return Err(format!("{label} descriptor identity is unsafe"));
    }
    let mut offset = 0_u64;
    let mut chunk = [0_u8; 64 * 1024];
    let mut digest = Sha256::new();
    while offset < expected_size {
        let wanted = usize::try_from((expected_size - offset).min(chunk.len() as u64))
            .map_err(|_| format!("{label} descriptor chunk size overflows"))?;
        let read = file
            .read_at(&mut chunk[..wanted], offset)
            .map_err(|error| format!("read {label} descriptor: {error}"))?;
        if read == 0 {
            return Err(format!("{label} descriptor ended before declared size"));
        }
        digest.update(&chunk[..read]);
        offset = offset
            .checked_add(read as u64)
            .ok_or_else(|| format!("{label} descriptor offset overflows"))?;
    }
    if file
        .read_at(&mut chunk[..1], expected_size)
        .map_err(|error| format!("read {label} descriptor boundary: {error}"))?
        != 0
    {
        return Err(format!("{label} descriptor exceeds declared size"));
    }
    if hex::encode(digest.finalize()) != expected_sha256 {
        return Err(format!("candidate descriptor bytes differ for {label}"));
    }
    let after = file
        .metadata()
        .map_err(|error| format!("restat {label} descriptor: {error}"))?;
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.ctime(),
        after.ctime_nsec(),
    ) {
        return Err(format!("{label} descriptor changed while reading"));
    }
    Ok((before.dev(), before.ino()))
}

fn read_descriptor(fd: i32, maximum: usize, label: &str) -> Result<DescriptorRead, String> {
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(format!("duplicate {label} descriptor failed"));
    }
    let file = unsafe { File::from_raw_fd(duplicate) };
    let before = file
        .metadata()
        .map_err(|error| format!("stat {label} descriptor: {error}"))?;
    if !before.is_file() || before.nlink() != 1 || before.len() > maximum as u64 {
        return Err(format!("{label} descriptor identity is unsafe"));
    }
    let mut bytes = vec![0; before.len() as usize];
    file.read_exact_at(&mut bytes, 0)
        .map_err(|error| format!("read {label} descriptor: {error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("restat {label} descriptor: {error}"))?;
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.ctime(),
        after.ctime_nsec(),
    ) {
        return Err(format!("{label} descriptor changed while reading"));
    }
    Ok(DescriptorRead {
        bytes,
        identity: (before.dev(), before.ino()),
    })
}

impl DaemonProposalResult {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_STATUS_BYTES {
            return Err("daemon proposal result exceeds byte bound".into());
        }
        let value: Self = crate::release::parse_canonical(bytes, "daemon proposal result")?;
        if let Self::Rejected { reason } = &value {
            if reason.is_empty() || reason.len() > 512 || reason.chars().any(char::is_control) {
                return Err("daemon rejection reason is invalid".into());
            }
        }
        Ok(value)
    }
}

impl DaemonOtaRequest {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_STATUS_BYTES {
            return Err("daemon OTA request exceeds byte bound".into());
        }
        crate::release::parse_canonical(bytes, "daemon OTA request")
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        canonical_bytes(self)
    }
}

impl DaemonOtaResponse {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_STATUS_BYTES {
            return Err("daemon OTA response exceeds byte bound".into());
        }
        let value: Self = crate::release::parse_canonical(bytes, "daemon OTA response")?;
        match &value {
            Self::ActiveRelease {
                result: ActiveReleaseResult::Active { identity, terminal },
            } => {
                identity.validate()?;
                if let Some(ack) = terminal {
                    if ack.transaction_id.is_empty()
                        || ack.transaction_id.len() > 128
                        || ack.transaction_id.chars().any(char::is_control)
                    {
                        return Err("terminal acknowledgement transaction id is invalid".into());
                    }
                    if !canonical_semver(&ack.release_identity) {
                        return Err("terminal acknowledgement release identity is invalid".into());
                    }
                    if !ack
                        .manifest_sha256
                        .chars()
                        .all(|character| character.is_ascii_hexdigit())
                        || ack.manifest_sha256.len() != 64
                    {
                        return Err("terminal acknowledgement manifest sha is invalid".into());
                    }
                }
            }
            Self::Propose { result } => {
                let bytes = canonical_bytes(result)?;
                DaemonProposalResult::parse(&bytes)?;
            }
            Self::ActiveRelease {
                result: ActiveReleaseResult::Unavailable,
            } => {}
        }
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        canonical_bytes(self)
    }
}

fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    if bytes.len() > MAX_STATUS_BYTES {
        return Err("daemon OTA value exceeds byte bound".into());
    }
    Ok(bytes)
}

fn canonical_semver(value: &str) -> bool {
    semver::Version::parse(value)
        .ok()
        .is_some_and(|version| version.to_string() == value)
}

fn invalid_basename(value: &str) -> bool {
    value.is_empty()
        || value.len() > 255
        || matches!(value, "." | "..")
        || value.contains('/')
        || value.contains('\\')
        || value.contains('\0')
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::io::Write;
    use std::os::fd::AsRawFd;

    #[test]
    fn daemon_ota_wire_is_canonical_bounded_and_path_free() {
        let active_request = DaemonOtaRequest::ActiveRelease;
        assert_eq!(
            active_request.canonical_bytes().unwrap(),
            include_bytes!("../test/fixtures/product-release/status/request-active.json")
        );
        assert_eq!(
            DaemonOtaRequest::parse(b"{\"request\":\"activeRelease\"}\n").unwrap(),
            active_request
        );
        assert!(DaemonOtaRequest::parse(b"{\"request\":\"activeRelease\"}").is_err());
        assert!(
            DaemonOtaRequest::parse(b"{\"request\":\"activeRelease\",\"path\":\"/tmp/x\"}\n")
                .is_err()
        );

        let manifest = Manifest::parse(include_bytes!(
            "../test/fixtures/product-release/voboost/valid/minimal.json"
        ))
        .unwrap();
        let candidate = OtaCandidateHandle::parse(
            include_bytes!("../test/fixtures/product-release/status/proposal.json"),
            &manifest,
        )
        .unwrap();
        assert_eq!(
            DaemonOtaRequest::Propose { candidate }
                .canonical_bytes()
                .unwrap(),
            include_bytes!("../test/fixtures/product-release/status/request-proposal.json")
        );
        let unavailable = DaemonOtaResponse::parse(include_bytes!(
            "../test/fixtures/product-release/status/response-unavailable.json"
        ))
        .unwrap();
        assert_eq!(
            DaemonOtaResponse::parse(&unavailable.canonical_bytes().unwrap()).unwrap(),
            unavailable
        );
        let pending = DaemonOtaResponse::parse(include_bytes!(
            "../test/fixtures/product-release/status/response-pending.json"
        ))
        .unwrap();
        assert_eq!(
            pending.canonical_bytes().unwrap(),
            include_bytes!("../test/fixtures/product-release/status/response-pending.json")
        );
        assert!(DaemonOtaResponse::parse(include_bytes!(
            "../test/fixtures/product-release/status/response-active.json"
        ))
        .is_ok());
    }

    #[test]
    fn candidate_is_opaque_transaction_and_exact_ordered_manifest_subset() {
        let manifest = Manifest::parse(include_bytes!(
            "../test/fixtures/product-release/voboost/valid/minimal.json"
        ))
        .unwrap();
        let mut candidate = OtaCandidateHandle {
            transaction_id: "a".repeat(64),
            release_identity: manifest.release_identity.clone(),
            manifest_sha256: manifest.digest().unwrap(),
            artifacts: vec![
                CandidateArtifactIdentity {
                    file: "voboost-daemon".into(),
                    size: 2,
                    sha256: "1".repeat(64),
                },
                CandidateArtifactIdentity {
                    file: "agent-settings.dex".into(),
                    size: 17,
                    sha256: "0123456789abcdef".repeat(4),
                },
            ],
        };
        assert!(candidate.validate(&manifest).is_ok());
        candidate.artifacts.reverse();
        assert!(candidate.validate(&manifest).is_err());
        candidate.artifacts = vec![CandidateArtifactIdentity {
            file: "foreign".into(),
            size: 1,
            sha256: "1".repeat(64),
        }];
        assert!(candidate.validate(&manifest).is_err());
        candidate.transaction_id = "a".repeat(32);
        assert!(candidate.validate(&manifest).is_err());
        candidate.transaction_id = candidate.manifest_sha256.clone();
        assert!(candidate.validate(&manifest).is_err());
    }

    #[test]
    fn shared_status_fixtures_are_canonical_and_strict() {
        assert!(ActiveReleaseIdentity::parse(include_bytes!(
            "../test/fixtures/product-release/status/active.json"
        ))
        .is_ok());
        let manifest = Manifest::parse(include_bytes!(
            "../test/fixtures/product-release/voboost/valid/minimal.json"
        ))
        .unwrap();
        assert!(OtaCandidateHandle::parse(
            include_bytes!("../test/fixtures/product-release/status/proposal.json"),
            &manifest,
        )
        .is_ok());
        assert!(DaemonProposalResult::parse(include_bytes!(
            "../test/fixtures/product-release/status/result-rejected.json"
        ))
        .is_ok());
        assert!(OtaCandidateHandle::parse(
            include_bytes!("../test/fixtures/product-release/status/proposal-duplicate-key.json"),
            &manifest,
        )
        .is_err());
        assert!(OtaCandidateHandle::parse(
            include_bytes!(
                "../test/fixtures/product-release/status/proposal-transaction-equals-manifest.json"
            ),
            &manifest,
        )
        .is_err());
        let candidate = OtaCandidateHandle::parse(
            include_bytes!("../test/fixtures/product-release/status/proposal.json"),
            &manifest,
        )
        .unwrap();
        assert!(CandidateDescriptorHandoff::parse(
            include_bytes!("../test/fixtures/product-release/status/descriptors.json"),
            &candidate,
        )
        .is_ok());
        assert!(CandidateDescriptorHandoff::parse(
            include_bytes!("../test/fixtures/product-release/status/descriptors-aliased.json"),
            &candidate,
        )
        .is_err());
        let metadata = OtaCandidateHandle::parse(
            include_bytes!("../test/fixtures/product-release/status/proposal-metadata-only.json"),
            &manifest,
        )
        .unwrap();
        assert!(CandidateDescriptorHandoff::parse(
            include_bytes!(
                "../test/fixtures/product-release/status/descriptors-metadata-only.json"
            ),
            &metadata,
        )
        .is_ok());
        assert!(CandidateDescriptorHandoff::parse(
            include_bytes!(
                "../test/fixtures/product-release/status/descriptors-missing-manifest.json"
            ),
            &metadata,
        )
        .is_err());
        assert!(CandidateDescriptorHandoff::parse(
            include_bytes!(
                "../test/fixtures/product-release/status/descriptors-missing-signature.json"
            ),
            &metadata,
        )
        .is_err());
        assert!(OtaCandidateHandle::parse(
            include_bytes!("../test/fixtures/product-release/status/proposal-stale-release.json"),
            &manifest,
        )
        .is_err());
    }

    #[test]
    fn install_apk_result_is_exact_kotlin_compatible_fixture() {
        let fixture =
            include_bytes!("../test/fixtures/product-release/status/result-install-apk.json");
        assert_eq!(
            DaemonProposalResult::parse(fixture).unwrap(),
            DaemonProposalResult::InstallApk
        );
        assert_eq!(
            canonical_bytes(&DaemonProposalResult::InstallApk).unwrap(),
            fixture
        );
        for hostile in [
            br#"{"status":"installApk"}\n"#.as_slice(),
            br#"{"status":"install-apk","path":"/data/local/tmp/app.apk"}\n"#.as_slice(),
            br#"{ "status":"install-apk"}\n"#.as_slice(),
        ] {
            assert!(DaemonProposalResult::parse(hostile).is_err());
        }
    }

    #[test]
    fn open_descriptor_handoff_binds_manifest_signature_and_changed_bodies() {
        let mut manifest = Manifest::parse(include_bytes!(
            "../test/fixtures/product-release/voboost/valid/minimal.json"
        ))
        .unwrap();
        let daemon_bytes = b"daemon-body";
        let agent_bytes = b"agent-body";
        for (file, bytes) in [
            ("voboost-daemon", daemon_bytes.as_slice()),
            ("agent-settings.dex", agent_bytes.as_slice()),
        ] {
            let artifact = manifest
                .artifacts
                .iter_mut()
                .find(|artifact| artifact.file == file)
                .unwrap();
            artifact.size = bytes.len() as u64;
            artifact.sha256 = hex::encode(Sha256::digest(bytes));
        }
        let manifest_bytes = manifest.canonical_bytes().unwrap();
        let key = SigningKey::from_bytes(&[7; 32]);
        let signature = key.sign(&manifest_bytes).to_bytes();
        let directory = tempfile::tempdir().unwrap();
        let write = |name: &str, bytes: &[u8]| {
            let mut file = File::options()
                .read(true)
                .write(true)
                .create_new(true)
                .open(directory.path().join(name))
                .unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
            file
        };
        let manifest_file = write("manifest", &manifest_bytes);
        let signature_file = write("signature", &signature);
        let daemon_file = write("daemon", daemon_bytes);
        let agent_file = write("agent", agent_bytes);
        let candidate = OtaCandidateHandle {
            transaction_id: "a".repeat(64),
            release_identity: manifest.release_identity.clone(),
            manifest_sha256: manifest.digest().unwrap(),
            artifacts: ["voboost-daemon", "agent-settings.dex"]
                .into_iter()
                .map(|file| {
                    let artifact = manifest.artifact(file).unwrap();
                    CandidateArtifactIdentity {
                        file: file.into(),
                        size: artifact.size,
                        sha256: artifact.sha256.clone(),
                    }
                })
                .collect(),
        };
        let handoff = CandidateDescriptorHandoff {
            manifest_fd: manifest_file.as_raw_fd(),
            signature_fd: signature_file.as_raw_fd(),
            artifacts: [daemon_file.as_raw_fd(), agent_file.as_raw_fd()]
                .into_iter()
                .zip(&candidate.artifacts)
                .map(|(fd, identity)| CandidateArtifactDescriptor {
                    fd,
                    file: identity.file.clone(),
                    size: identity.size,
                    sha256: identity.sha256.clone(),
                })
                .collect(),
        };
        assert!(handoff
            .verify_open_descriptors(&candidate, key.verifying_key().as_bytes())
            .is_ok());
        std::fs::write(directory.path().join("agent"), b"substitution").unwrap();
        assert!(handoff
            .verify_open_descriptors(&candidate, key.verifying_key().as_bytes())
            .is_err());
    }

    #[test]
    fn metadata_only_wire_requires_manifest_signature_and_current_release() {
        let manifest = Manifest::parse(include_bytes!(
            "../test/fixtures/product-release/voboost/valid/minimal.json"
        ))
        .unwrap();
        let metadata = OtaCandidateHandle::parse(
            include_bytes!("../test/fixtures/product-release/status/proposal-metadata-only.json"),
            &manifest,
        )
        .unwrap();
        assert!(CandidateDescriptorHandoff::parse(
            include_bytes!(
                "../test/fixtures/product-release/status/descriptors-metadata-only.json"
            ),
            &metadata,
        )
        .is_ok());
        assert!(CandidateDescriptorHandoff::parse(
            include_bytes!(
                "../test/fixtures/product-release/status/descriptors-missing-manifest.json"
            ),
            &metadata,
        )
        .is_err());
        assert!(CandidateDescriptorHandoff::parse(
            include_bytes!(
                "../test/fixtures/product-release/status/descriptors-missing-signature.json"
            ),
            &metadata,
        )
        .is_err());
        assert!(OtaCandidateHandle::parse(
            include_bytes!("../test/fixtures/product-release/status/proposal-stale-release.json"),
            &manifest,
        )
        .is_err());
        for active in [
            include_bytes!("../test/fixtures/product-release/status/active.json").as_slice(),
            include_bytes!(
                "../test/fixtures/product-release/status/active-strictly-older-beta.json"
            )
            .as_slice(),
            include_bytes!("../test/fixtures/product-release/status/active-newer-beta.json")
                .as_slice(),
            include_bytes!(
                "../test/fixtures/product-release/status/active-cross-channel-stable.json"
            )
            .as_slice(),
        ] {
            assert!(ActiveReleaseIdentity::parse(active).is_ok());
        }
        assert!(ActiveReleaseIdentity::parse(include_bytes!(
            "../test/fixtures/product-release/status/active-malformed.json"
        ))
        .is_err());
    }

    struct MapClosure {
        files: BTreeMap<String, Vec<u8>>,
        reads: usize,
    }

    impl MapClosure {
        fn new(files: BTreeMap<String, Vec<u8>>) -> Self {
            Self { files, reads: 0 }
        }
    }

    impl InstalledClosure for MapClosure {
        fn inventory(&mut self) -> Result<BTreeSet<String>, String> {
            self.reads += 1;
            Ok(self.files.keys().cloned().collect())
        }

        fn read(&mut self, artifact: &Artifact) -> Result<Vec<u8>, String> {
            self.reads += 1;
            self.files
                .get(&artifact.file)
                .cloned()
                .ok_or_else(|| format!("missing installed {}", artifact.file))
        }
    }

    #[test]
    fn metadata_only_commit_requires_strictly_newer_same_channel_and_exact_installed_closure() {
        let mut manifest = Manifest::parse(include_bytes!(
            "../test/fixtures/product-release/voboost/valid/minimal.json"
        ))
        .unwrap();
        let mut installed = BTreeMap::new();
        for artifact in &mut manifest.artifacts {
            let bytes = format!("installed:{}", artifact.file).into_bytes();
            artifact.size = bytes.len() as u64;
            artifact.sha256 = hex::encode(Sha256::digest(&bytes));
            installed.insert(artifact.file.clone(), bytes);
        }
        let manifest_bytes = manifest.canonical_bytes().unwrap();
        let key = SigningKey::from_bytes(&[11; 32]);
        let signature = key.sign(&manifest_bytes).to_bytes();
        let directory = tempfile::tempdir().unwrap();
        let write = |name: &str, bytes: &[u8]| {
            let mut file = File::options()
                .read(true)
                .write(true)
                .create_new(true)
                .open(directory.path().join(name))
                .unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
            file
        };
        let manifest_file = write("manifest", &manifest_bytes);
        let signature_file = write("signature", &signature);
        let candidate = OtaCandidateHandle {
            transaction_id: "a".repeat(64),
            release_identity: manifest.release_identity.clone(),
            manifest_sha256: manifest.digest().unwrap(),
            artifacts: Vec::new(),
        };
        let handoff = CandidateDescriptorHandoff {
            manifest_fd: manifest_file.as_raw_fd(),
            signature_fd: signature_file.as_raw_fd(),
            artifacts: Vec::new(),
        };
        let active_artifacts = manifest
            .artifacts
            .iter()
            .map(|artifact| {
                (
                    artifact.file.clone(),
                    ActiveArtifactIdentity {
                        size: artifact.size,
                        sha256: artifact.sha256.clone(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut active = ActiveReleaseIdentity::parse(include_bytes!(
            "../test/fixtures/product-release/status/active-strictly-older-beta.json"
        ))
        .unwrap();
        active.artifacts = active_artifacts.clone();
        let mut closure = MapClosure::new(installed.clone());
        let commit = handoff
            .verify_metadata_only_installed_closure(
                &candidate,
                &active,
                key.verifying_key().as_bytes(),
                &mut closure,
            )
            .unwrap();
        assert_eq!(commit.manifest(), &manifest);
        assert_eq!(commit.manifest_bytes(), manifest_bytes);
        assert_eq!(commit.signature_bytes(), signature);

        let first = manifest.artifacts[0].file.clone();
        let mut substituted = MapClosure::new(installed.clone());
        substituted.files.insert(first, b"substitution".to_vec());
        assert!(handoff
            .verify_metadata_only_installed_closure(
                &candidate,
                &active,
                key.verifying_key().as_bytes(),
                &mut substituted,
            )
            .is_err());

        let mut extra = MapClosure::new(installed);
        extra.files.insert("foreign".into(), b"foreign".to_vec());
        assert!(handoff
            .verify_metadata_only_installed_closure(
                &candidate,
                &active,
                key.verifying_key().as_bytes(),
                &mut extra,
            )
            .is_err());

        let parse = |bytes: &[u8]| {
            let mut value: ActiveReleaseIdentity = serde_json::from_slice(bytes).unwrap();
            value.artifacts = active_artifacts.clone();
            value
        };
        let mut incomplete_active = active.clone();
        incomplete_active.artifacts.pop_first();
        for invalid in [
            parse(include_bytes!(
                "../test/fixtures/product-release/status/active.json"
            )),
            parse(include_bytes!(
                "../test/fixtures/product-release/status/active-newer-beta.json"
            )),
            parse(include_bytes!(
                "../test/fixtures/product-release/status/active-cross-channel-stable.json"
            )),
            parse(include_bytes!(
                "../test/fixtures/product-release/status/active-malformed.json"
            )),
            incomplete_active,
        ] {
            let mut unread = MapClosure::new(closure.files.clone());
            assert!(handoff
                .verify_metadata_only_installed_closure(
                    &candidate,
                    &invalid,
                    key.verifying_key().as_bytes(),
                    &mut unread,
                )
                .is_err());
            assert_eq!(
                unread.reads, 0,
                "monotonic rejection read installed closure"
            );
        }
    }
}
