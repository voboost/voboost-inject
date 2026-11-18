//! Domain-native installation evidence. Unknown boot state is represented by null.
use crate::{
    catalog::{Domain, FileIdentity},
    digest, parse_canonical, printable, safe_path, Result, MAX_DOCUMENT_BYTES, MAX_SAFE_INTEGER,
};
use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Operation {
    Install,
    Update,
    Restore,
    Uninstall,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Prepare,
    Verify,
    Stage,
    Install,
    Restore,
    Uninstall,
    Cleanup,
    Complete,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Pending,
    SetupRequired,
    Completed,
    Failed,
    ReloadRequired,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RootScope {
    Persistent,
    Volatile,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersistentRoot {
    pub path: String,
    pub scope: RootScope,
    pub device_id: String,
    pub owner_uid: u32,
    pub mode: u32,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartupProof {
    pub path: String,
    pub original_sha256: String,
    pub installed_sha256: String,
    pub restored_sha256: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreProof {
    pub verified: bool,
    pub proof_sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AbsenceStartup {
    pub path: String,
    pub original_sha256: String,
    pub restored_sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AbsenceChecks {
    pub daemon_process_absent: bool,
    pub autostart_removed: bool,
    pub native_payload_absent: bool,
    pub persistent_state_absent: bool,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResidentRestore {
    Restored,
    ReloadRequired,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum InstalledEvidence {
    #[serde(rename = "qnx-restored")]
    QnxRestored {
        startup: AbsenceStartup,
        #[serde(rename = "restoreFenceSha256")]
        restore_fence_sha256: String,
        #[serde(rename = "residentRestore")]
        resident_restore: ResidentRestore,
        reason: String,
    },
    #[serde(rename = "qnx-absence")]
    QnxAbsence {
        startup: AbsenceStartup,
        checks: AbsenceChecks,
        #[serde(rename = "proofSha256")]
        proof_sha256: String,
    },

    #[serde(rename = "android-apk")]
    AndroidApk {
        #[serde(rename = "certificateSha256")]
        certificate_sha256: String,
        #[serde(rename = "packageName")]
        package_name: String,
        path: String,
        sha256: String,
        size: u64,
        #[serde(rename = "versionCode")]
        version_code: u64,
    },
    #[serde(rename = "qnx-native")]
    QnxNative {
        files: Vec<FileIdentity>,
        #[serde(rename = "persistentRoot")]
        persistent_root: PersistentRoot,
        startup: StartupProof,
        restore: RestoreProof,
    },
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DomainOperationReport {
    pub schema_version: u32,
    pub domain: Domain,
    pub operation: Operation,
    pub phase: Phase,
    pub outcome: Outcome,
    pub transaction_id: String,
    pub release_manifest_sha256: String,
    pub catalog_sha256: String,
    pub generation_id: Option<String>,
    pub desired_revision: u64,
    pub desired_sha256: String,
    pub boot_id: Option<String>,
    pub daemon_epoch: Option<String>,
    pub installed_evidence: Option<InstalledEvidence>,
}
impl DomainOperationReport {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = parse_canonical(bytes, MAX_DOCUMENT_BYTES)?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 2
            || ![
                &self.transaction_id,
                &self.release_manifest_sha256,
                &self.catalog_sha256,
                &self.desired_sha256,
            ]
            .iter()
            .all(|s| digest(s))
            || self
                .generation_id
                .as_deref()
                .map(|s| !digest(s))
                .unwrap_or(false)
            || self.desired_revision > MAX_SAFE_INTEGER
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
        {
            return Err("invalid domain report identity".into());
        }
        // A post-reboot one-shot absence verifier is not a running daemon.
        // Its signed, fully checked QNX absence evidence is the completion
        // authority; fabricating a daemon incarnation would be misleading.
        let one_shot_absence = self.domain == Domain::Cluster
            && self.operation == Operation::Uninstall
            && self.boot_id.is_none()
            && self.daemon_epoch.is_none()
            && matches!(
                self.installed_evidence,
                Some(InstalledEvidence::QnxAbsence { .. })
            );
        if (self.outcome == Outcome::Completed) != (self.phase == Phase::Complete)
            || self.outcome == Outcome::Completed
                && ((!one_shot_absence && (self.boot_id.is_none() || self.daemon_epoch.is_none()))
                    || (self.operation != Operation::Uninstall && self.generation_id.is_none())
                    || (self.installed_evidence.is_none()
                        && !(self.operation == Operation::Uninstall
                            && self.domain == Domain::Multimedia)))
        {
            return Err("completed domain operation lacks daemon observation".into());
        }
        if let Some(e) = &self.installed_evidence {
            match (self.domain, e) {
                (
                    Domain::Cluster,
                    InstalledEvidence::QnxRestored {
                        startup,
                        restore_fence_sha256,
                        reason,
                        ..
                    },
                ) => {
                    if self.operation != Operation::Uninstall
                        || self.phase != Phase::Uninstall
                        || self.outcome != Outcome::ReloadRequired
                        || self.boot_id.is_none()
                        || self.daemon_epoch.is_none()
                        || !safe_path(&startup.path)
                        || !digest(&startup.original_sha256)
                        || startup.original_sha256 != startup.restored_sha256
                        || !digest(restore_fence_sha256)
                        || !printable(reason, 128)
                    {
                        return Err("native uninstall preparation is not proven".into());
                    }
                }
                (
                    Domain::Cluster,
                    InstalledEvidence::QnxAbsence {
                        startup,
                        checks,
                        proof_sha256,
                    },
                ) => {
                    if self.operation != Operation::Uninstall
                        || self.outcome != Outcome::Completed
                        || !safe_path(&startup.path)
                        || !digest(&startup.original_sha256)
                        || startup.original_sha256 != startup.restored_sha256
                        || !digest(proof_sha256)
                        || !checks.daemon_process_absent
                        || !checks.autostart_removed
                        || !checks.native_payload_absent
                        || !checks.persistent_state_absent
                    {
                        return Err("native absence is not proven".into());
                    }
                }

                (
                    Domain::Multimedia,
                    InstalledEvidence::AndroidApk {
                        certificate_sha256,
                        package_name,
                        path,
                        sha256,
                        size,
                        version_code,
                    },
                ) => {
                    if (self.operation == Operation::Uninstall
                        && self.outcome == Outcome::Completed)
                        || !digest(certificate_sha256)
                        || !digest(sha256)
                        || !safe_path(path)
                        || !printable(package_name, 255)
                        || *size == 0
                        || *version_code == 0
                        || *version_code > MAX_SAFE_INTEGER
                    {
                        return Err("invalid Android installed evidence".into());
                    }
                }
                (
                    Domain::Cluster,
                    InstalledEvidence::QnxNative {
                        files,
                        persistent_root,
                        startup,
                        restore,
                    },
                ) => {
                    if (self.operation == Operation::Uninstall
                        && self.outcome == Outcome::Completed)
                        || files.is_empty()
                        || files.len() > 252
                        || !safe_path(&persistent_root.path)
                        || !printable(&persistent_root.device_id, 128)
                        || persistent_root.owner_uid != 0
                        || persistent_root.mode != 448
                        || !safe_path(&startup.path)
                        || !digest(&startup.original_sha256)
                        || !digest(&startup.installed_sha256)
                        || startup
                            .restored_sha256
                            .as_deref()
                            .map(|s| !digest(s))
                            .unwrap_or(false)
                        || !digest(&restore.proof_sha256)
                    {
                        return Err("invalid native installed evidence".into());
                    }
                    let mut prior = "";
                    for f in files {
                        f.validate()?;
                        if f.file.as_str() <= prior {
                            return Err("native installed file order invalid".into());
                        }
                        prior = &f.file;
                    }
                    if self.outcome == Outcome::Completed
                        && (persistent_root.scope != RootScope::Persistent
                            || !restore.verified
                            || self.generation_id.is_none()
                            || startup
                                .restored_sha256
                                .as_deref()
                                .map(|value| value != startup.original_sha256)
                                .unwrap_or(false))
                    {
                        return Err("native install is not durable and restore verified".into());
                    }
                    if matches!(self.operation, Operation::Restore | Operation::Uninstall)
                        && self.outcome == Outcome::Completed
                        && startup.restored_sha256.as_deref()
                            != Some(startup.original_sha256.as_str())
                    {
                        return Err("startup restore is not proven".into());
                    }
                }
                _ => return Err("installed evidence domain mismatch".into()),
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticatedReport {
    pub schema_version: u32,
    pub pair_id: String,
    pub authority_epoch: String,
    pub challenge: String,
    pub report: DomainOperationReport,
}
impl AuthenticatedReport {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || ![&self.pair_id, &self.authority_epoch, &self.challenge]
                .iter()
                .all(|s| digest(s))
        {
            return Err("invalid signed operation authority".into());
        }
        self.report.validate()
    }
    pub fn sign(&self, key: &ed25519_dalek::SigningKey) -> Result<Vec<u8>> {
        self.validate()?;
        crate::cluster::sign_envelope(
            &crate::ascii_json(self)?,
            b"VOBOOST_DOMAIN_OPERATION_V2\0",
            key,
        )
    }
    pub fn verify(
        envelope: &[u8],
        key: &ed25519_dalek::VerifyingKey,
        pair: &str,
        epoch: &str,
        challenge: &str,
        transaction: &str,
        product: &str,
    ) -> Result<Self> {
        let bytes = crate::cluster::envelope_json(envelope)?;
        crate::cluster::verify_signature(
            bytes,
            &envelope[4 + bytes.len()..],
            b"VOBOOST_DOMAIN_OPERATION_V2\0",
            key,
        )?;
        let value: Self = parse_canonical(bytes, MAX_DOCUMENT_BYTES - 68)?;
        value.validate()?;
        if value.pair_id != pair
            || value.authority_epoch != epoch
            || value.challenge != challenge
            || value.report.transaction_id != transaction
            || value.report.release_manifest_sha256 != product
        {
            return Err("signed operation receipt is stale or unrelated".into());
        }
        Ok(value)
    }
}

/// Exact signed QNX preparation shared by Android root and offline recovery.
pub fn verify_qnx_restoration(
    bytes: &[u8],
    key: &ed25519_dalek::VerifyingKey,
    request: &crate::cluster::Request,
) -> Result<()> {
    let value = AuthenticatedReport::verify(
        bytes,
        key,
        &request.pair_id,
        &request.authority_epoch,
        &request.challenge,
        &request.transaction_id,
        request
            .release_manifest_sha256
            .as_deref()
            .ok_or("uninstall product absent")?,
    )?;
    let report = value.report;
    if request.kind != crate::cluster::RequestKind::Uninstall
        || report.domain != Domain::Cluster
        || report.operation != Operation::Uninstall
        || report.phase != Phase::Uninstall
        || report.outcome != Outcome::ReloadRequired
        || report.catalog_sha256 != request.catalog_sha256
    {
        return Err("QNX uninstall report is not correlated preparation".into());
    }
    let Some(InstalledEvidence::QnxRestored {
        startup,
        restore_fence_sha256,
        ..
    }) = report.installed_evidence
    else {
        return Err("QNX uninstall lacks exact restore evidence".into());
    };
    if startup.path != "/scripts/startup_cluster.sh"
        || startup.original_sha256
            != "c26b4913707a1e96933f48a07d6957857cc52853a7e405eb29b2adab9b84f47a"
        || restore_fence_sha256 != crate::hash(&crate::ascii_json(&request.transaction_id)?)
    {
        return Err("QNX uninstall startup or fence differs".into());
    }
    Ok(())
}
