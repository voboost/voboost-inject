//! Derived signed Cluster outbox. The canonical Plan is the sole desired-state authority.
#[path = "cluster_uninstall_bridge.rs"]
pub(crate) mod uninstall_bridge;
#[path = "cluster_uninstall_finalize.rs"]
mod uninstall_finalize;
use crate::secure_fs::Directory;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
#[cfg(test)]
use voboost_contract::cluster_wire::Transport;
use voboost_contract::{
    cluster::{
        self, ClusterAgentState, ClusterSnapshot, DeliveryState, DesiredAgent, ObservedState,
        Receipt, Request, RequestKind,
    },
    cluster_wire::{
        self, BlobIdentity, LocalRequest, LocalResponse, ResultStatus, TakeResult,
        TransportOutcome, WireFile, WireRole,
    },
    domain_catalog::{Catalog, Domain},
};
pub use voboost_shared::cluster_mailbox::Provision;
use voboost_shared::cluster_mailbox::{Lease, Pending, State, INITIAL_MAILBOX};

const STATE_FILE: &str = "mailbox.json";
const PROVISION_FILE: &str = "provision.json";
const SEED_FILE: &str = "device-signing.seed";
const CREDENTIAL_FILE: &str = "transport.p12";
const REQUEST_FILE: &str = "request.vbc";
const UNINSTALL_REPORT: &str = "uninstall-report.vbc";
pub(crate) const UNINSTALL_PENDING: &str =
    "Cluster uninstall pending signed absence; authority retained";
pub(crate) const UNINSTALL_FAILED: &str = "Cluster removal preparation failed: ";

enum FinalizationEvent {
    Progress(String),
    Finished(Result<Vec<u8>>),
}

struct FinalizationJob {
    transaction: String,
    events: std::sync::mpsc::Receiver<FinalizationEvent>,
    terminal: bool,
    failure: Option<String>,
    request_nonce: Option<String>,
    receipt: Option<Vec<u8>>,
}

fn import_worker_receipt(
    job: &mut FinalizationJob,
    import: impl FnOnce(&[u8]) -> Result<()>,
) -> Result<()> {
    if let Some(bytes) = &job.receipt {
        import(bytes)?;
        job.receipt = None;
    }
    Ok(())
}

#[derive(Default)]
struct FinalizationGate {
    job: Option<FinalizationJob>,
}

impl FinalizationGate {
    fn retry_failed(&mut self, transaction: &str) -> bool {
        if self.job.as_ref().is_some_and(|job| {
            job.transaction == transaction
                && job.terminal
                && job.failure.is_some()
                && job.receipt.is_none()
        }) {
            self.job = None;
            true
        } else {
            false
        }
    }

    fn retry_publication(&mut self, transaction: &str, nonce: Option<&str>) -> bool {
        if nonce.is_some()
            && self
                .job
                .as_ref()
                .is_some_and(|job| job.request_nonce.as_deref() != nonce)
        {
            return self.retry_failed(transaction);
        }
        false
    }

    fn poll(&mut self, transaction: &str, export: Vec<u8>, nonce: Option<&str>) -> Result<()> {
        self.retry_publication(transaction, nonce);
        if let Some(job) = &mut self.job {
            if job.transaction != transaction {
                return Err("another retained Cluster finalization owns the worker".into());
            }
            if job.terminal {
                if let Some(error) = &job.failure {
                    return Err(format!("{UNINSTALL_FAILED}{error}"));
                }
                if job.receipt.is_some() {
                    import_worker_receipt(job, uninstall_bridge::import_verified_bytes_production)?;
                    crate::uninstall::record_cluster_progress(
                        "cluster-restored",
                        "signed native absence verified",
                    );
                }
                return Ok(());
            }
            while let Ok(event) = job.events.try_recv() {
                match event {
                    FinalizationEvent::Progress(reason) => {
                        crate::uninstall::record_cluster_progress("cluster-removing", &reason);
                    }
                    FinalizationEvent::Finished(result) => {
                        job.terminal = true;
                        match result {
                            Ok(bytes) => {
                                // The worker returns only after native finish ACK. Recheck
                                // retained authority on this thread before publication.
                                job.receipt = Some(bytes);
                                import_worker_receipt(
                                    job,
                                    uninstall_bridge::import_verified_bytes_production,
                                )?;
                                crate::uninstall::record_cluster_progress(
                                    "cluster-restored",
                                    "signed native absence verified",
                                );
                            }
                            Err(error) => {
                                job.failure = Some(error.clone());
                                crate::uninstall::record_cluster_progress("cluster-failed", &error);
                                crate::log::err(
                                    "cluster",
                                    &format!("retained uninstall worker failed: {error}"),
                                );
                            }
                        }
                    }
                }
            }
            // Terminal failures retain authority and request, without spawning
            // duplicate destructive work on every one-second daemon poll.
            return match &job.failure {
                Some(error) => Err(format!("{UNINSTALL_FAILED}{error}")),
                None => Ok(()),
            };
        }
        let (send, events) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("cluster-uninstall".into())
            .spawn(move || {
                let result = uninstall_finalize::run(&export, |reason| {
                    let _ = send.send(FinalizationEvent::Progress(reason.into()));
                });
                let _ = send.send(FinalizationEvent::Finished(result));
            })
            .map_err(|e| format!("start retained Cluster worker: {e}"))?;
        self.job = Some(FinalizationJob {
            transaction: transaction.into(),
            events,
            terminal: false,
            failure: None,
            request_nonce: nonce.map(str::to_owned),
            receipt: None,
        });
        Ok(())
    }
}

static UNINSTALL_WORKER: OnceLock<Mutex<FinalizationGate>> = OnceLock::new();

#[cfg(not(test))]
pub(crate) fn retry_failed_uninstall() -> Result<bool> {
    let export = uninstall_bridge::export_device_production()?;
    let value: serde_json::Value = serde_json::from_slice(&export).map_err(|e| e.to_string())?;
    let transaction = value["request"]["transactionId"]
        .as_str()
        .ok_or("Cluster retry lacks retained transaction")?;
    if value["state"] != "restored" {
        return Ok(false);
    }
    Ok(UNINSTALL_WORKER
        .get_or_init(|| Mutex::new(FinalizationGate::default()))
        .lock()
        .map_err(|_| "Cluster worker gate poisoned")?
        .retry_failed(transaction))
}

fn continue_uninstall_finalization() -> Result<()> {
    let nonce = crate::uninstall::desktop_request_nonce()?;
    let export = uninstall_bridge::export_device_production()?;
    let value: serde_json::Value = serde_json::from_slice(&export).map_err(|e| e.to_string())?;
    if value["state"] != "restored" {
        return Ok(());
    }
    let transaction = value["request"]["transactionId"]
        .as_str()
        .ok_or("restored Cluster request lacks transaction")?;
    UNINSTALL_WORKER
        .get_or_init(|| Mutex::new(FinalizationGate::default()))
        .lock()
        .map_err(|_| "Cluster worker gate poisoned")?
        .poll(transaction, export.clone(), nonce.as_deref())
}

#[cfg(test)]
mod finalization_worker_gate_tests {
    use super::*;

    fn gate(terminal: bool) -> (FinalizationGate, std::sync::mpsc::Sender<FinalizationEvent>) {
        let (sender, events) = std::sync::mpsc::channel();
        (
            FinalizationGate {
                job: Some(FinalizationJob {
                    transaction: "retained-tx".into(),
                    events,
                    terminal,
                    failure: None,
                    request_nonce: None,
                    receipt: None,
                }),
            },
            sender,
        )
    }

    #[test]
    fn pending_worker_is_not_replaced_by_repeated_poll() {
        let (mut gate, _sender) = gate(false);
        for _ in 0..5 {
            gate.poll("retained-tx", b"not a second worker input".to_vec(), None)
                .unwrap();
        }
        assert!(!gate.job.as_ref().unwrap().terminal);
    }

    #[test]
    fn completed_or_failed_worker_is_not_automatically_restarted() {
        let (mut gate, _sender) = gate(true);
        gate.poll("retained-tx", vec![], None).unwrap();
        assert!(gate.job.as_ref().unwrap().terminal);
    }

    #[test]
    fn failed_worker_returns_a_terminal_error_instead_of_endless_pending() {
        let (mut gate, _sender) = gate(true);
        gate.job.as_mut().unwrap().failure = Some("local receipt unavailable".into());
        for _ in 0..3 {
            assert_eq!(
                gate.poll("retained-tx", vec![], None).unwrap_err(),
                format!("{UNINSTALL_FAILED}local receipt unavailable")
            );
            assert!(gate.job.as_ref().unwrap().terminal);
        }
        assert!(gate.retry_failed("retained-tx"));
        assert!(gate.job.is_none());
    }

    #[test]
    fn a_new_durable_publication_retries_the_resident_worker_not_the_cli_gate() {
        let mut cli = FinalizationGate::default();
        let (mut resident, _sender) = gate(true);
        let job = resident.job.as_mut().unwrap();
        job.failure = Some("receipt unavailable".into());
        job.request_nonce = Some("original-publication".into());
        assert!(!cli.retry_failed("retained-tx"));
        assert!(!resident.retry_publication("retained-tx", Some("original-publication")));
        assert!(!resident.retry_publication("retained-tx", None));
        assert!(!resident.retry_publication("another-tx", Some("new-publication")));
        assert!(resident.retry_publication("retained-tx", Some("new-publication")));
        assert!(resident.job.is_none());
    }

    #[test]
    fn another_transaction_cannot_replace_retained_worker() {
        let (mut gate, _sender) = gate(false);
        assert!(gate.poll("different-tx", vec![], None).is_err());
        assert_eq!(gate.job.unwrap().transaction, "retained-tx");
    }

    #[test]
    fn guarded_import_failure_retains_acknowledged_receipt_for_retry() {
        let (mut gate, _sender) = gate(true);
        let job = gate.job.as_mut().unwrap();
        job.receipt = Some(b"acknowledged signed receipt".to_vec());
        assert!(import_worker_receipt(job, |_| Err("operation busy".into())).is_err());
        assert!(job.receipt.is_some());
        import_worker_receipt(job, |bytes| {
            assert_eq!(bytes, b"acknowledged signed receipt");
            Ok(())
        })
        .unwrap();
        assert!(job.receipt.is_none());
        assert!(job.terminal);
    }

    #[test]
    fn explicit_retry_only_reopens_failed_same_transaction_without_receipt() {
        let (mut gate, _sender) = gate(false);
        assert!(!gate.retry_failed("retained-tx"));
        let job = gate.job.as_mut().unwrap();
        job.terminal = true;
        assert!(!gate.retry_failed("retained-tx"));
        gate.job.as_mut().unwrap().failure = Some("local receipt unavailable".into());
        assert!(!gate.retry_failed("other-tx"));
        gate.job.as_mut().unwrap().receipt = Some(vec![1]);
        assert!(!gate.retry_failed("retained-tx"));
        gate.job.as_mut().unwrap().receipt = None;
        assert!(gate.retry_failed("retained-tx"));
        assert!(gate.job.is_none());
    }
}
const MAX_STATE_BYTES: usize = 256 * 1024;
const MAX_SAFE: u64 = 9_007_199_254_740_991;
type Result<T> = std::result::Result<T, String>;
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    voboost_contract::domain_core::ascii_json(value)
}
fn hash(bytes: &[u8]) -> String {
    crate::trust::sha256_bytes(bytes)
}
fn parse<T: Serialize + serde::de::DeserializeOwned>(bytes: &[u8], maximum: usize) -> Result<T> {
    voboost_contract::domain_core::parse_canonical(bytes, maximum)
}
fn bump(value: u64) -> Result<u64> {
    value
        .checked_add(1)
        .filter(|v| *v <= MAX_SAFE)
        .ok_or_else(|| "cluster revision exhausted".into())
}
fn raw32(text: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(text).map_err(|_| "invalid device public key")?;
    bytes
        .try_into()
        .map_err(|_| "device public key must be raw32".into())
}
fn random_id() -> Result<String> {
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| format!("cluster entropy: {e}"))?;
    Ok(hex::encode(bytes))
}
#[cfg(not(test))]
fn boot_id() -> Result<String> {
    let value = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|e| format!("cluster boot identity: {e}"))?;
    let value = value.trim();
    if value.is_empty() || value.len() > 128 || !value.is_ascii() {
        return Err("invalid Android boot identity".into());
    }
    Ok(value.into())
}
#[cfg(test)]
fn boot_id() -> Result<String> {
    Ok("host-fixture-boot".into())
}
#[cfg(test)]
fn daemon_epoch() -> Result<String> {
    static EPOCH: OnceLock<Result<String>> = OnceLock::new();
    EPOCH.get_or_init(random_id).clone()
}
#[cfg(not(test))]
fn daemon_epoch() -> Result<String> {
    crate::owner_client::cluster_epoch()
        .map_err(|error| format!("Cluster runtime owner unavailable: {error}"))
}
fn monotonic_ms() -> Result<u64> {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    #[cfg(any(target_os = "android", target_os = "linux"))]
    let clock_id = libc::CLOCK_BOOTTIME;
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    let clock_id = libc::CLOCK_MONOTONIC;
    if unsafe { libc::clock_gettime(clock_id, &mut ts) } != 0 || ts.tv_sec < 0 || ts.tv_nsec < 0 {
        return Err("cluster monotonic clock unavailable".into());
    }
    u64::try_from(ts.tv_sec)
        .ok()
        .and_then(|s| s.checked_mul(1000))
        .and_then(|s| s.checked_add(ts.tv_nsec as u64 / 1_000_000))
        .ok_or_else(|| "cluster clock overflow".into())
}

trait StateSnapshot {
    fn snapshot(&self) -> Result<ClusterSnapshot>;
}
impl StateSnapshot for State {
    fn snapshot(&self) -> Result<ClusterSnapshot> {
        let current = self.observed.as_ref().filter(|r| {
            matches!(&self.delivery_state, DeliveryState::Idle)
                && self.observed_owner_epoch.as_deref() == Some(self.android_daemon_epoch.as_str())
                && r.catalog_sha256 == self.catalog_sha256
                && r.closure_sha256 == self.closure_sha256
                && self
                    .generation
                    .as_ref()
                    .is_some_and(|g| g.generation_id == r.generation_id)
                && r.desired_revision == self.desired_revision
                && r.desired_sha256 == self.desired_sha256
        });
        let rows = self
            .agents
            .iter()
            .map(|a| {
                let targets: Vec<cluster::ObservedAgent> = self
                    .expected_targets
                    .get(&a.id)
                    .ok_or("snapshot expected target inventory missing")
                    .map(|expected| {
                        expected
                            .iter()
                            .map(|target| {
                                current
                                    .and_then(|r| {
                                        r.agents.iter().find(|row| {
                                            row.id == a.id && &row.target_process == target
                                        })
                                    })
                                    .cloned()
                                    .unwrap_or_else(|| cluster::ObservedAgent {
                                        id: a.id.clone(),
                                        target_process: target.clone(),
                                        state: ObservedState::WaitingProcess,
                                        reason: "awaiting-qnx-target-ack".into(),
                                        process: None,
                                    })
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let all_applied = !targets.is_empty()
                    && targets.iter().all(|t| t.state == ObservedState::Applied);
                let all_disabled = !targets.is_empty()
                    && targets.iter().all(|t| t.state == ObservedState::Disabled);
                let state = if a.enabled && all_applied {
                    ObservedState::Applied
                } else if !a.enabled && all_disabled {
                    ObservedState::Disabled
                } else if targets.iter().any(|t| t.state == ObservedState::Failed) {
                    ObservedState::Failed
                } else if targets
                    .iter()
                    .any(|t| t.state == ObservedState::Quarantined)
                {
                    ObservedState::Quarantined
                } else if targets.len() == 1 {
                    targets[0].state
                } else {
                    ObservedState::WaitingProcess
                };
                let reason = if targets.len() == 1 {
                    targets[0].reason.clone()
                } else if all_applied && a.enabled {
                    "all-targets-applied".into()
                } else if all_disabled && !a.enabled {
                    "all-targets-disabled".into()
                } else {
                    "awaiting-all-targets".into()
                };
                let process = if targets.len() == 1 {
                    targets[0].process.clone()
                } else {
                    None
                };
                ClusterAgentState {
                    id: a.id.clone(),
                    enabled: a.enabled,
                    options: a.options.clone(),
                    state,
                    reason,
                    process,
                    targets,
                }
            })
            .collect();
        let value = ClusterSnapshot {
            schema_version: 1,
            domain: Domain::Cluster,
            snapshot_revision: self.snapshot_revision,
            catalog_sha256: self.catalog_sha256.clone(),
            generation_id: self.generation.as_ref().map(|r| r.generation_id.clone()),
            desired_revision: self.desired_revision,
            desired_sha256: self.desired_sha256.clone(),
            observation_revision: current.map(|r| r.observation_revision).unwrap_or(0),
            boot_id: current.map(|r| r.boot_id.clone()),
            daemon_epoch: current.map(|r| r.daemon_epoch.clone()),
            delivery_state: self.delivery_state.clone(),
            agents: rows,
        };
        value.validate()?;
        Ok(value)
    }
}
pub struct Handoff {
    pub response: LocalResponse,
    pub descriptors: Vec<File>,
}
pub struct Store {
    path: PathBuf,
    owner: u32,
    epoch: Option<String>,
}
impl Store {
    pub fn production() -> Self {
        Self {
            path: Path::new(crate::config::ROOT_ZONE).join("cluster"),
            owner: 0,
            epoch: None,
        }
    }
    #[cfg(test)]
    fn at(path: &Path) -> Self {
        Self {
            path: path.into(),
            owner: unsafe { libc::geteuid() },
            epoch: Some("f".repeat(64)),
        }
    }
    fn directory(&self) -> Result<Directory> {
        let parent = self.path.parent().ok_or("Cluster root has no parent")?;
        let name = self
            .path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or("Cluster root invalid")?;
        let root = Directory::open(parent).map_err(|e| e.to_string())?;
        root.validate_owner_not_writable(self.owner, unsafe { libc::getegid() })
            .map_err(|e| e.to_string())?;
        let dir = root
            .open_or_create_private_child(name)
            .map_err(|e| e.to_string())?;
        dir.validate_owner_mode(self.owner, unsafe { libc::getegid() }, 0o700)
            .map_err(|e| e.to_string())?;
        Ok(dir)
    }
    fn mailbox(&self, _dir: &Directory) -> Result<Option<Vec<u8>>> {
        #[cfg(test)]
        {
            match _dir.read_trusted(STATE_FILE, MAX_STATE_BYTES, 0o600) {
                Ok(bytes) => Ok(Some(bytes)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error.to_string()),
            }
        }
        #[cfg(not(test))]
        {
            match crate::owner_client::call(
                voboost_contract::runtime_owner::Command::ReadClusterMailbox {},
            )
            .map_err(|error| error.to_string())?
            {
                voboost_contract::runtime_owner::Outcome::ClusterMailbox { bytes } => {
                    Ok(bytes.map(String::into_bytes))
                }
                _ => Err("cluster mailbox owner unavailable".into()),
            }
        }
    }
    fn load(&self, dir: &Directory) -> Result<Option<State>> {
        let Some(bytes) = self.mailbox(dir)? else {
            if dir
                .entry_exists(PROVISION_FILE)
                .map_err(|e| e.to_string())?
            {
                return Err("provisioned Cluster mailbox missing; authority retained".into());
            }
            return Ok(None);
        };
        if bytes == INITIAL_MAILBOX {
            return Ok(None);
        }
        let mut value: State = parse(&bytes, MAX_STATE_BYTES)?;
        value.validate()?;
        let epoch = self.epoch.clone().map(Ok).unwrap_or_else(daemon_epoch)?;
        let boot = boot_id()?;
        if value.android_daemon_epoch != epoch || value.android_boot_id != boot {
            value.android_daemon_epoch = epoch;
            value.android_boot_id = boot;
            if value.global_locale.take().is_some() {
                value.desired_revision = bump(value.desired_revision)?;
                if !value
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.request.kind == RequestKind::Uninstall)
                {
                    value.pending = None;
                }
            }
            value.observed_owner_epoch = None;
            if let Some(pending) = value.pending.as_mut() {
                pending.lease = None;
            }
            value.delivery_state = if dir
                .entry_exists(PROVISION_FILE)
                .map_err(|e| e.to_string())?
            {
                DeliveryState::Pending
            } else {
                DeliveryState::SetupRequired
            };
            value.snapshot_revision = bump(value.snapshot_revision)?;
            self.persist(dir, &value)?;
        }
        // Provision may have committed immediately before a crash. Complete the
        // setup transition under the same mailbox lock without changing intent.
        if matches!(value.delivery_state, DeliveryState::SetupRequired)
            && dir
                .entry_exists(PROVISION_FILE)
                .map_err(|e| e.to_string())?
        {
            self.provision(dir)?;
            value.observed_owner_epoch = None;
            value.delivery_state = DeliveryState::Pending;
            value.snapshot_revision = bump(value.snapshot_revision)?;
            self.persist(dir, &value)?;
        }
        Ok(Some(value))
    }

    fn persist(&self, dir: &Directory, state: &State) -> Result<()> {
        state.validate()?;
        let bytes = encode(state)?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err("durable Cluster state exceeds byte bound".into());
        }
        let snapshot = state.snapshot()?.canonical_bytes()?;
        if snapshot.len() + 2 > crate::config::MAX_DOWNLINK_FRAME_BYTES {
            return Err("Cluster K snapshot exceeds resident pipe budget".into());
        }
        // This single atomic document is the commit point; K is derived from it.
        #[cfg(test)]
        {
            dir.write_atomic(STATE_FILE, &bytes, 0o600)
                .map_err(|e| e.to_string())
        }
        #[cfg(not(test))]
        {
            let expected = self
                .mailbox(dir)?
                .map(String::from_utf8)
                .transpose()
                .map_err(|error| error.to_string())?;
            match crate::owner_client::call(
                voboost_contract::runtime_owner::Command::ReplaceClusterMailbox {
                    expected,
                    next: String::from_utf8(bytes).map_err(|e| e.to_string())?,
                },
            )
            .map_err(|e| e.to_string())?
            {
                voboost_contract::runtime_owner::Outcome::Written {} => Ok(()),
                _ => Err("cluster mailbox owner did not commit state".into()),
            }
        }
    }
    fn write_artifact(
        &self,
        dir: &Directory,
        artifact: voboost_contract::runtime_owner::ClusterArtifact,
        bytes: &[u8],
    ) -> Result<()> {
        #[cfg(test)]
        {
            dir.write_atomic(artifact.file(), bytes, 0o600)
                .map_err(|error| error.to_string())
        }
        #[cfg(not(test))]
        {
            let _ = dir;
            match crate::owner_client::call(
                voboost_contract::runtime_owner::Command::WriteClusterArtifact {
                    artifact,
                    bytes: bytes.into(),
                },
            )
            .map_err(|error| error.to_string())?
            {
                voboost_contract::runtime_owner::Outcome::Written {} => Ok(()),
                _ => Err("cluster artifact owner did not commit document".into()),
            }
        }
    }
    fn provision(&self, dir: &Directory) -> Result<Option<(Provision, SigningKey)>> {
        if !dir
            .entry_exists(PROVISION_FILE)
            .map_err(|e| e.to_string())?
        {
            return Ok(None);
        }
        let provision: Provision = parse(
            &dir.read_trusted(PROVISION_FILE, 16 * 1024, 0o600)
                .map_err(|e| e.to_string())?,
            16 * 1024,
        )?;
        provision.validate()?;
        let mut bytes = dir
            .read_trusted(SEED_FILE, 32, 0o600)
            .map_err(|e| e.to_string())?;
        let mut seed: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| "device seed must be raw32")?;
        let key = SigningKey::from_bytes(&seed);
        seed.fill(0);
        bytes.fill(0);
        if key.verifying_key().to_bytes() != raw32(&provision.android_public_key)? {
            return Err("desired authority seed is not the paired Android key".into());
        }
        provision.validate_roles(&[
            &crate::trust::AGENT_CATALOG_PUBKEY,
            &crate::trust::RELEASE_CATALOG_PUBKEY,
            &crate::trust::NATIVE_EXECUTABLE_PUBKEY,
            &crate::trust::RESTORE_PUBLIC_KEY,
        ])?;
        Ok(Some((provision, key)))
    }
    pub fn project(
        &self,
        catalog: &Catalog,
        catalog_sha: &str,
        agents: Vec<DesiredAgent>,
    ) -> Result<bool> {
        let dir = self.directory()?;
        let _lock = dir
            .lock_transaction(Duration::from_millis(20))
            .map_err(|e| e.to_string())?;
        self.project_locked(&dir, catalog, catalog_sha, agents, None)
    }
    // The caller holds the mailbox lock. An initial uninstall is committed
    // together with its first State, so no generation can escape between them.
    fn project_locked(
        &self,
        dir: &Directory,
        catalog: &Catalog,
        catalog_sha: &str,
        agents: Vec<DesiredAgent>,
        uninstall_product: Option<&str>,
    ) -> Result<bool> {
        if uninstall_product.is_some() {
            self.provision(dir)?.ok_or("pairing absent")?;
            if !dir.entry_exists(STATE_FILE).map_err(|e| e.to_string())?
                || dir
                    .read_trusted(STATE_FILE, MAX_STATE_BYTES, 0o600)
                    .map_err(|e| e.to_string())?
                    != INITIAL_MAILBOX
            {
                return Ok(false);
            }
        }
        let old = self.load(dir)?;
        if old.as_ref().is_some_and(|s| {
            s.pending
                .as_ref()
                .is_some_and(|p| p.request.kind == RequestKind::Uninstall)
        }) {
            return Ok(false);
        }
        let closure = voboost_contract::domain_generation::closure_digest(
            &catalog.closure(Domain::Cluster)?,
        )?;
        let desired_sha = cluster::desired_digest(&agents)?;
        let mut expected_targets = BTreeMap::new();
        for agent in catalog
            .agents
            .iter()
            .filter(|a| a.domain == Domain::Cluster)
        {
            let processes: BTreeSet<String> = agent
                .targets
                .iter()
                .map(|t| t.process().to_owned())
                .collect();
            if processes.is_empty()
                || processes
                    .iter()
                    .any(|p| !matches!(p.as_str(), "gauge" | "point" | "light"))
            {
                return Err("unsupported catalog Cluster process".into());
            }
            expected_targets.insert(agent.id.clone(), processes.into_iter().collect());
        }
        if agents.iter().any(|a| !expected_targets.contains_key(&a.id)) {
            return Err("desired Cluster agent absent from catalog".into());
        }
        if old.as_ref().is_some_and(|s| {
            s.catalog_sha256 == catalog_sha
                && s.closure_sha256 == closure
                && s.desired_sha256 == desired_sha
        }) {
            return Ok(false);
        }
        let same_closure = old
            .as_ref()
            .is_some_and(|s| s.catalog_sha256 == catalog_sha && s.closure_sha256 == closure);
        let provisioned = self.provision(dir)?.is_some();
        let mut state = State {
            global_locale: None,
            schema_version: 1,
            android_boot_id: boot_id()?,
            android_daemon_epoch: self.epoch.clone().map(Ok).unwrap_or_else(daemon_epoch)?,
            catalog_sha256: catalog_sha.into(),
            closure_sha256: closure,
            desired_revision: old
                .as_ref()
                .map(|s| bump(s.desired_revision))
                .transpose()?
                .unwrap_or(1),
            desired_sha256: desired_sha,
            expected_targets,
            agents,
            snapshot_revision: old
                .as_ref()
                .map(|s| bump(s.snapshot_revision))
                .transpose()?
                .unwrap_or(1),
            generation: old
                .as_ref()
                .filter(|_| same_closure)
                .and_then(|s| s.generation.clone()),
            observed: old
                .as_ref()
                .filter(|_| same_closure)
                .and_then(|s| s.observed.clone()),
            observed_owner_epoch: None,
            delivery_state: if provisioned {
                DeliveryState::Pending
            } else {
                DeliveryState::SetupRequired
            },
            pending: None,
        };
        if let Some(product) = uninstall_product {
            let (provision, key) = self.provision(dir)?.ok_or("pairing absent")?;
            self.queue_uninstall(dir, &mut state, &provision, &key, product)?;
        } else {
            self.persist(dir, &state)?;
        }
        Ok(true)
    }
    fn project_locale(&self, mut observation: Option<cluster::GlobalLocale>) -> Result<bool> {
        if let Some(locale) = &observation {
            locale.validate()?;
        }
        let dir = self.directory()?;
        let _lock = dir
            .lock_transaction(Duration::from_millis(20))
            .map_err(|e| e.to_string())?;
        let Some(mut state) = self.load(&dir)? else {
            return Ok(false);
        };
        if let Some(next) = observation.as_mut() {
            next.lifecycle_generation = match &state.global_locale {
                Some(old) if old.endpoint_identity == next.endpoint_identity => {
                    old.lifecycle_generation
                }
                _ => bump(state.desired_revision)?,
            };
        }
        if state
            .pending
            .as_ref()
            .is_some_and(|p| p.request.kind == RequestKind::Uninstall)
            || state.global_locale == observation
        {
            return Ok(false);
        }
        if let (Some(next), Some(old)) = (&observation, &state.global_locale) {
            if !next.follows(old) {
                return Err("global locale projection rollback/conflict".into());
            }
        }
        state.global_locale = observation;
        state.desired_revision = bump(state.desired_revision)?;
        state.snapshot_revision = bump(state.snapshot_revision)?;
        state.pending = None;
        state.delivery_state = DeliveryState::Pending;
        self.persist(&dir, &state)?;
        Ok(true)
    }
    pub fn snapshot(&self) -> Result<Option<ClusterSnapshot>> {
        let dir = self.directory()?;
        let _lock = dir
            .lock_transaction(Duration::from_millis(20))
            .map_err(|e| e.to_string())?;
        self.load(&dir)?.map(|s| s.snapshot()).transpose()
    }
    fn request(&self, state: &State, provision: &Provision, kind: RequestKind) -> Result<Request> {
        Ok(Request {
            global_locale: if kind == RequestKind::Desired {
                state.global_locale.clone()
            } else {
                None
            },
            schema_version: 1,
            kind,
            pair_id: provision.pair_id.clone(),
            domain: Domain::Cluster,
            authority_epoch: provision.authority_epoch.clone(),
            transaction_id: random_id()?,
            catalog_sha256: state.catalog_sha256.clone(),
            closure_sha256: state.closure_sha256.clone(),
            challenge: random_id()?,
            release_manifest_sha256: None,
            files: None,
            desired_revision: if kind == RequestKind::Generation {
                None
            } else {
                Some(state.desired_revision)
            },
            desired_sha256: if kind == RequestKind::Generation {
                None
            } else {
                Some(state.desired_sha256.clone())
            },
            agents: if kind == RequestKind::Desired {
                Some(state.agents.clone())
            } else {
                None
            },
        })
    }

    /// Destructive Android cleanup cannot outrun persistent cluster restoration.
    /// A prepared report is deliberately not an absence receipt.
    fn prepare_uninstall(&self, product: &str) -> Result<bool> {
        self.prepare_uninstall_initial(product, || {
            Err("provisioned Cluster state unavailable; uninstall authority retained".into())
        })
    }
    fn prepare_uninstall_initial(
        &self,
        product: &str,
        initial: impl FnOnce() -> Result<(Catalog, String, Vec<DesiredAgent>)>,
    ) -> Result<bool> {
        let dir = self.directory()?;
        let _lock = dir
            .lock_transaction(Duration::from_millis(20))
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::TimedOut {
                    UNINSTALL_PENDING.into()
                } else {
                    error.to_string()
                }
            })?;
        let Some((provision, key)) = self.provision(&dir)? else {
            for name in [
                SEED_FILE,
                CREDENTIAL_FILE,
                UNINSTALL_REPORT,
                "uninstall-final-report.vbc",
                "uninstall-provisional-report.vbc",
                "uninstall-delivery-owner.json",
            ] {
                if dir.entry_exists(name).map_err(|e| e.to_string())? {
                    return Err(
                        "partial Cluster pairing retained; cannot prove no native installation"
                            .into(),
                    );
                }
            }
            return Ok(true);
        };
        let mut state = match self.load(&dir)? {
            Some(state) => state,
            None => {
                let (catalog, catalog_sha, agents) = initial()?;
                if !self.project_locked(&dir, &catalog, &catalog_sha, agents, Some(product))? {
                    return Err("initial Cluster authority changed".into());
                }
                return Ok(false);
            }
        };
        if let Some(pending) = state
            .pending
            .as_ref()
            .filter(|p| p.request.kind == RequestKind::Uninstall)
        {
            if pending.request.release_manifest_sha256.as_deref() != Some(product) {
                return Err(
                    "retained Cluster uninstall belongs to another installed product".into(),
                );
            }
            if uninstall_bridge::completion_verified(&dir, &provision, &pending.request)? {
                return Ok(true);
            }
        }
        if dir
            .entry_exists(UNINSTALL_REPORT)
            .map_err(|e| e.to_string())?
        {
            let pending = state
                .pending
                .as_ref()
                .ok_or("Cluster uninstall report lost request authority")?;
            verify_uninstall_report(
                &dir.read_trusted(UNINSTALL_REPORT, 65536, 0o600)
                    .map_err(|e| e.to_string())?,
                &provision,
                &pending.request,
            )?;
            return Ok(false);
        }
        if state.pending.as_ref().map(|p| p.request.kind) != Some(RequestKind::Uninstall) {
            if state
                .pending
                .as_ref()
                .and_then(|p| p.lease.as_ref())
                .is_some_and(|l| {
                    l.boot_id == boot_id().unwrap_or_default()
                        && monotonic_ms().map(|now| now < l.until_ms).unwrap_or(true)
                })
            {
                return Err(UNINSTALL_PENDING.into());
            }
            self.queue_uninstall(&dir, &mut state, &provision, &key, product)?;
        }
        Ok(false)
    }
    fn queue_uninstall(
        &self,
        dir: &Directory,
        state: &mut State,
        provision: &Provision,
        key: &SigningKey,
        product: &str,
    ) -> Result<()> {
        let retained = voboost_shared::cluster_mailbox::read_signed_request(dir, provision, key)?;
        let (request, bytes) = match retained {
            Some((request, bytes)) if request.kind == RequestKind::Uninstall => {
                if request.release_manifest_sha256.as_deref() != Some(product)
                    || request.catalog_sha256 != state.catalog_sha256
                    || request.closure_sha256 != state.closure_sha256
                {
                    return Err("orphan Cluster uninstall differs from retained authority".into());
                }
                (request, bytes)
            }
            _ => {
                let mut request = self.request(state, provision, RequestKind::Uninstall)?;
                request.release_manifest_sha256 = Some(product.into());
                let bytes = request.sign(key)?;
                self.write_artifact(
                    dir,
                    voboost_contract::runtime_owner::ClusterArtifact::Request,
                    &bytes,
                )?;
                (request, bytes)
            }
        };
        state.pending = Some(Pending {
            request,
            files: vec![WireFile {
                role: WireRole::Request,
                file: REQUEST_FILE.into(),
                size: bytes.len() as u64,
                sha256: hash(&bytes),
            }],
            lease: None,
        });
        state.delivery_state = DeliveryState::Pending;
        self.persist(dir, state)
    }
    pub fn take(
        &self,
        request_id: &str,
        artifacts: impl FnMut() -> Result<(String, Vec<(WireFile, File)>)>,
    ) -> Result<Handoff> {
        self.take_inner(request_id, false, artifacts)
    }
    fn take_inner(
        &self,
        request_id: &str,
        uninstall_only: bool,
        mut artifacts: impl FnMut() -> Result<(String, Vec<(WireFile, File)>)>,
    ) -> Result<Handoff> {
        if !voboost_contract::release::lower_hash(request_id) {
            return Err("invalid local Cluster request ID".into());
        }
        let dir = self.directory()?;
        let _lock = dir
            .lock_transaction(Duration::from_millis(20))
            .map_err(|e| e.to_string())?;
        let empty = |result| Handoff {
            response: LocalResponse::Take {
                protocol_version: 1,
                request_id: request_id.into(),
                result,
            },
            descriptors: Vec::new(),
        };
        let Some(mut state) = self.load(&dir)? else {
            return Ok(empty(TakeResult::Empty {}));
        };
        let Some((provision, key)) = self.provision(&dir)? else {
            return Ok(empty(TakeResult::SetupRequired {}));
        };
        let retained =
            voboost_shared::cluster_mailbox::read_signed_request(&dir, &provision, &key)?;
        let committed_uninstall = state
            .pending
            .as_ref()
            .filter(|p| p.request.kind == RequestKind::Uninstall);
        if let Some(pending) = committed_uninstall {
            let (request, _) = retained
                .as_ref()
                .ok_or("committed Cluster uninstall request missing")?;
            if encode(request)? != encode(&pending.request)? {
                return Err("committed Cluster uninstall request differs".into());
            }
        } else if retained
            .as_ref()
            .is_some_and(|(request, _)| request.kind == RequestKind::Uninstall)
        {
            return Err("orphan Cluster uninstall authority retained".into());
        }
        if uninstall_only
            && state.pending.as_ref().map(|p| p.request.kind) != Some(RequestKind::Uninstall)
        {
            return Ok(empty(TakeResult::Empty {}));
        }
        if dir
            .entry_exists(UNINSTALL_REPORT)
            .map_err(|e| e.to_string())?
        {
            return Ok(empty(TakeResult::Empty {}));
        }
        let now = monotonic_ms()?;
        let boot = boot_id()?;
        if state
            .pending
            .as_ref()
            .and_then(|p| p.lease.as_ref())
            .map(|l| l.boot_id == boot && now < l.until_ms)
            .unwrap_or(false)
        {
            return Ok(empty(TakeResult::Busy {}));
        }
        let mut payloads = Vec::new();
        let first_lease = state.pending.is_none();
        if first_lease {
            let kind = if state.generation.is_none() {
                RequestKind::Generation
            } else if state
                .observed
                .as_ref()
                .map(|r| {
                    r.desired_revision == state.desired_revision
                        && r.desired_sha256 == state.desired_sha256
                })
                .unwrap_or(false)
            {
                RequestKind::Observe
            } else {
                RequestKind::Desired
            };
            let mut request = self.request(&state, &provision, kind)?;
            if kind == RequestKind::Generation {
                let (product, files) = artifacts()?;
                request.release_manifest_sha256 = Some(product);
                request.files = Some(files.iter().map(|(d, _)| d.clone()).collect());
                payloads = files;
            }
            let bytes = request.sign(&key)?;
            self.write_artifact(
                &dir,
                voboost_contract::runtime_owner::ClusterArtifact::Request,
                &bytes,
            )?;
            let mut files = vec![WireFile {
                role: WireRole::Request,
                file: REQUEST_FILE.into(),
                size: bytes.len() as u64,
                sha256: hash(&bytes),
            }];
            if let Some(artifacts) = &request.files {
                files.extend(artifacts.clone());
            }
            state.pending = Some(Pending {
                request,
                files,
                lease: None,
            });
        }
        let pending = state.pending.as_mut().ok_or("pending request missing")?;
        if !first_lease && pending.request.kind != RequestKind::Uninstall {
            pending.request.challenge = random_id()?;
        }
        let signed = pending.request.sign(&key)?;
        self.write_artifact(
            &dir,
            voboost_contract::runtime_owner::ClusterArtifact::Request,
            &signed,
        )?;
        pending.files[0].size = signed.len() as u64;
        pending.files[0].sha256 = hash(&signed);
        if pending.request.pair_id != provision.pair_id
            || pending.request.authority_epoch != provision.authority_epoch
        {
            return Err("pairing rotation requires explicit mailbox migration".into());
        }
        if pending.files.len() > 1 && payloads.is_empty() {
            let (product, files) = artifacts()?;
            if pending.request.release_manifest_sha256.as_deref() != Some(product.as_str())
                || pending.request.files.as_ref()
                    != Some(&files.iter().map(|(d, _)| d.clone()).collect::<Vec<_>>())
            {
                return Err("retained generation delivery differs from queued authority".into());
            }
            payloads = files;
        }
        let request_bytes = dir
            .read_trusted(REQUEST_FILE, 65536, 0o600)
            .map_err(|e| e.to_string())?;
        if request_bytes.len() as u64 != pending.files[0].size
            || hash(&request_bytes) != pending.files[0].sha256
        {
            return Err("queued signed request bytes changed".into());
        }
        Request::verify(&request_bytes, &key.verifying_key())?;
        let credentials = dir
            .read_trusted(CREDENTIAL_FILE, 65536, 0o600)
            .map_err(|e| e.to_string())?;
        if credentials.len() as u64 != provision.transport.credentials.size
            || hash(&credentials) != provision.transport.credentials.sha256
        {
            return Err("paired transport credentials identity mismatch".into());
        }
        let mut descriptors = vec![dir
            .open_trusted_file(REQUEST_FILE, pending.files[0].size, 0o600)
            .map_err(|e| e.to_string())?];
        descriptors.extend(payloads.into_iter().map(|(_, fd)| fd));
        descriptors.push(
            dir.open_trusted_file(CREDENTIAL_FILE, credentials.len() as u64, 0o600)
                .map_err(|e| e.to_string())?,
        );
        for (file, identity) in descriptors.iter().zip(&pending.files) {
            verify_descriptor(file, identity, self.owner)?;
        }
        verify_descriptor(
            descriptors.last().ok_or("credentials descriptor absent")?,
            &WireFile {
                role: WireRole::Request,
                file: CREDENTIAL_FILE.into(),
                size: provision.transport.credentials.size,
                sha256: provision.transport.credentials.sha256.clone(),
            },
            self.owner,
        )?;
        let mut identities = pending.files.clone();
        identities.push(WireFile {
            role: WireRole::Request,
            file: CREDENTIAL_FILE.into(),
            size: provision.transport.credentials.size,
            sha256: provision.transport.credentials.sha256.clone(),
        });
        descriptors = descriptors
            .iter()
            .zip(&identities)
            .map(|(file, identity)| courier_copy(&dir, file, identity, self.owner))
            .collect::<Result<Vec<_>>>()?;
        let lease = Lease {
            id: random_id()?,
            boot_id: boot,
            until_ms: monotonic_ms()?
                .checked_add(cluster_wire::LEASE_MILLIS)
                .ok_or("lease clock overflow")?,
        };
        let result = TakeResult::Ready {
            lease_id: lease.id.clone(),
            transaction_id: pending.request.transaction_id.clone(),
            lease_millis: cluster_wire::LEASE_MILLIS,
            transport: provision.transport,
            files: pending.files.clone(),
        };
        result.validate()?;
        if result.descriptor_count() != descriptors.len() {
            return Err("outbox descriptor closure mismatch".into());
        }
        pending.lease = Some(lease);
        state.delivery_state = DeliveryState::Pending;
        state.snapshot_revision = bump(state.snapshot_revision)?;
        self.persist(&dir, &state)?;
        Ok(empty(result).with_descriptors(descriptors))
    }
    pub fn result(&self, request: &LocalRequest, receipt: Option<&File>) -> Result<LocalResponse> {
        let LocalRequest::Result {
            request_id,
            lease_id,
            transaction_id,
            transport_outcome,
            receipt: identity,
            ..
        } = request
        else {
            return Err("not a Cluster result".into());
        };
        request.validate()?;
        let dir = self.directory()?;
        let _lock = dir
            .lock_transaction(Duration::from_millis(20))
            .map_err(|e| e.to_string())?;
        let mut state = self.load(&dir)?.ok_or("Cluster state absent")?;
        let pending = state.pending.as_ref().ok_or("no pending Cluster lease")?;
        let lease = pending.lease.as_ref().ok_or("no issued Cluster lease")?;
        if &lease.id != lease_id
            || &pending.request.transaction_id != transaction_id
            || lease.boot_id != boot_id()?
            || monotonic_ms()? > lease.until_ms
        {
            return Err("Cluster result lease is stale".into());
        }
        match transport_outcome {
            TransportOutcome::Delivered => {
                let (provision, _) = self.provision(&dir)?.ok_or("pairing absent")?;
                let identity = identity.as_ref().ok_or("receipt identity missing")?;
                let bytes = read_receipt(receipt.ok_or("receipt descriptor missing")?, identity)?;
                if pending.request.kind == RequestKind::Uninstall {
                    verify_uninstall_report(&bytes, &provision, &pending.request)?;
                    self.write_artifact(
                        &dir,
                        voboost_contract::runtime_owner::ClusterArtifact::UninstallReport,
                        &bytes,
                    )?;
                    state
                        .pending
                        .as_mut()
                        .ok_or("uninstall pending missing")?
                        .lease = None;
                    state.delivery_state = DeliveryState::Idle;
                    self.persist(&dir, &state)?;
                    return Ok(LocalResponse::Result {
                        protocol_version: 1,
                        request_id: request_id.clone(),
                        result: ResultStatus::Recorded {},
                    });
                }
                let observed = Receipt::verify(
                    &bytes,
                    &VerifyingKey::from_bytes(&raw32(&provision.qnx_public_key)?)
                        .map_err(|_| "invalid QNX authority")?,
                )?;
                observed.correlate(
                    &pending.request,
                    state.generation.as_ref().map(|g| g.generation_id.as_str()),
                )?;
                state.validate_receipt_targets(&observed)?;
                if let Some(old) = &state.observed {
                    if observed.boot_id == old.boot_id
                        && observed.daemon_epoch == old.daemon_epoch
                        && observed.generation_id == old.generation_id
                        && observed.observation_revision < old.observation_revision
                    {
                        return Err("QNX observation revision regressed".into());
                    }
                    if observed.boot_id == old.boot_id
                        && observed.daemon_epoch == old.daemon_epoch
                        && observed.generation_id == old.generation_id
                        && observed.observation_revision == old.observation_revision
                        && observed.agents != old.agents
                    {
                        return Err("QNX observation revision conflicts with retained rows".into());
                    }
                }
                if observed.kind == cluster::ReceiptKind::Generation {
                    state.generation = Some(observed);
                } else {
                    state.observed_owner_epoch = Some(state.android_daemon_epoch.clone());
                    state.observed = Some(observed);
                }
                self.write_artifact(
                    &dir,
                    voboost_contract::runtime_owner::ClusterArtifact::Receipt,
                    &bytes,
                )?;
                state.pending = None;
                state.delivery_state = DeliveryState::Idle;
            }
            TransportOutcome::Unavailable | TransportOutcome::Failed => {
                if receipt.is_some() {
                    return Err("failed transport carries receipt".into());
                }
                state.pending.as_mut().ok_or("pending missing")?.lease = None;
                state.delivery_state = if *transport_outcome == TransportOutcome::Unavailable {
                    DeliveryState::Unavailable
                } else {
                    DeliveryState::Failed
                };
            }
        }
        state.snapshot_revision = bump(state.snapshot_revision)?;
        self.persist(&dir, &state)?;
        Ok(LocalResponse::Result {
            protocol_version: 1,
            request_id: request_id.clone(),
            result: ResultStatus::Recorded {},
        })
    }
}
impl Handoff {
    fn with_descriptors(mut self, descriptors: Vec<File>) -> Self {
        self.descriptors = descriptors;
        self
    }
}
fn read_receipt(file: &File, identity: &BlobIdentity) -> Result<Vec<u8>> {
    identity.validate()?;
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    let before = file.metadata().map_err(|e| e.to_string())?;
    if flags < 0
        || flags & libc::O_ACCMODE != libc::O_RDONLY
        || !before.is_file()
        || before.nlink() != 1
        || before.len() != identity.size
    {
        return Err("receipt descriptor is not bounded readonly regular file".into());
    }
    let mut bytes = vec![0u8; identity.size as usize];
    file.read_exact_at(&mut bytes, 0)
        .map_err(|e| e.to_string())?;
    let after = file.metadata().map_err(|e| e.to_string())?;
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
    ) || hash(&bytes) != identity.sha256
    {
        return Err("receipt descriptor changed or digest mismatch".into());
    }
    Ok(bytes)
}

fn projected_catalog(generation: &crate::generation::VerifiedGeneration) -> Result<Catalog> {
    let dir = Directory::open(&generation.directory).map_err(|e| e.to_string())?;
    let bytes = dir
        .read_trusted("agents.json", crate::catalog::MAX_CATALOG_BYTES, 0o444)
        .map_err(|e| e.to_string())?;
    if hash(&bytes) != generation.catalog_sha256 {
        return Err("active catalog bytes changed".into());
    }
    Catalog::parse(
        &bytes,
        crate::catalog::AGENT_ENTRY_ABI_SHA256,
        voboost_contract::domain_catalog::NATIVE_ENTRY_ABI_SHA256,
    )
}

/// No public mutation API exists. Recompute every row from the admitted canonical Plan.
fn desired_agents(
    generation: &crate::generation::VerifiedGeneration,
    plan: &crate::plan::Plan,
) -> Result<Vec<DesiredAgent>> {
    desired_agents_with_saved(generation, plan, |source| {
        match crate::state::read(
            Path::new(crate::config::STATE_DIR),
            source,
            "pedestrian-warning-armed",
        ) {
            crate::state::ReadOutcome::Value(serde_json::Value::Bool(value)) => Ok(Some(value)),
            crate::state::ReadOutcome::Missing => Ok(None),
            _ => Err("saved pedestrian-warning choice unavailable".into()),
        }
    })
}

fn desired_agents_with_saved(
    generation: &crate::generation::VerifiedGeneration,
    plan: &crate::plan::Plan,
    mut saved_choice: impl FnMut(&str) -> Result<Option<bool>>,
) -> Result<Vec<DesiredAgent>> {
    if !plan.valid
        || plan.catalog_sha256 != generation.catalog_sha256
        || plan.generation_id != generation.id
    {
        return Err("Cluster projection requires current valid canonical Plan".into());
    }
    let mut agents = Vec::new();
    for agent in &generation.catalog.agents {
        if !agent
            .targets
            .iter()
            .any(|t| t.domain == crate::catalog::TargetDomain::Cluster)
        {
            continue;
        }
        let entry = plan.entries.iter().find(|p| p.id == agent.id);
        let mut options = BTreeMap::new();
        for option in agent.options.as_deref().unwrap_or(&[]) {
            let value = entry
                .and_then(|e| e.config.get(&option.key))
                .and_then(serde_json::Value::as_str)
                .unwrap_or(&option.default);
            if !option.values.iter().any(|v| v.value == value) {
                return Err("invalid projected native option".into());
            }
            let saved = if agent.id == "vehicle-drive-pedestrian-warning"
                && option.key == "intent"
                && value == "observe"
                && !plan.disable_all
                && entry.is_some_and(|entry| entry.enabled)
            {
                saved_choice(&agent.id)?
            } else {
                None
            };
            let value = if agent.id == "vehicle-drive-pedestrian-warning" && option.key == "intent"
            {
                voboost_contract::cluster_pw_live::effective_intent(value, saved)
            } else {
                value
            };
            options.insert(option.key.clone(), value.to_string());
        }
        agents.push(DesiredAgent {
            id: agent.id.clone(),
            enabled: !plan.disable_all && entry.is_some_and(|e| e.enabled),
            options,
        });
    }
    agents.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(agents)
}

/// Project only authenticated current Binder readback; None revokes prior proof.
pub(crate) fn project_global_locale(
    generation: &crate::generation::VerifiedGeneration,
    endpoint: Option<&crate::agent_log::EndpointContext>,
) -> Result<bool> {
    use crate::agent_events::global_locale::{self, GlobalLanguage};
    if generation.catalog.cluster_runtime.is_none() {
        return Ok(false);
    }
    let observed = endpoint
        .and_then(global_locale::latest)
        .filter(|o| o.binding.catalog_sha256 == generation.catalog_sha256);
    let value = observed
        .map(|o| -> Result<cluster::GlobalLocale> {
            let parse = |s: &str| {
                s.parse::<u64>()
                    .map_err(|_| "global locale endpoint identity malformed".to_string())
            };
            let identity = serde_json::to_vec(&(
                daemon_epoch()?,
                &o.binding.target_pid,
                &o.binding.target_starttime,
                &o.binding.endpoint_epoch,
                &o.binding.generation_id,
                &o.binding.catalog_sha256,
            ))
            .map_err(|e| e.to_string())?;
            let digest = voboost_contract::domain_core::hash(&identity);
            let endpoint = u64::from_str_radix(&digest[..13], 16)
                .map_err(|_| "global locale identity digest".to_string())?;
            Ok(cluster::GlobalLocale {
                locale: match o.language {
                    GlobalLanguage::English => 1,
                    GlobalLanguage::Chinese => 2,
                    GlobalLanguage::Russian => 3,
                },
                revision: o.observed_at_boot_ms,
                endpoint_identity: endpoint,
                lifecycle_generation: endpoint,
                document_generation: parse(&o.binding.desired_document_generation)?,
            })
        })
        .transpose()?;
    let changed = Store::production().project_locale(value)?;
    wake_if_changed(changed, wake_courier);
    Ok(changed)
}

pub(crate) fn pw_worker_selection(
    generation: &crate::generation::VerifiedGeneration,
    plan: &crate::plan::Plan,
) -> Option<String> {
    let agents = desired_agents(generation, plan).ok()?;
    if !agents
        .iter()
        .any(|a| a.id == "vehicle-drive-pedestrian-warning" && a.enabled)
    {
        return None;
    }
    cluster::desired_digest(&agents).ok()
}
pub(crate) fn pw_actor_config(
    generation: &crate::generation::VerifiedGeneration,
    plan: &crate::plan::Plan,
) -> Option<crate::control_plane::pw_transport::Config> {
    let read = || -> Result<_> {
        let desired = pw_worker_selection(generation, plan).ok_or("PW visual target disabled")?;
        let store = Store::production();
        let directory = store.directory()?;
        let state: State = parse(
            &directory
                .read_trusted(STATE_FILE, MAX_STATE_BYTES, 0o600)
                .map_err(|e| e.to_string())?,
            MAX_STATE_BYTES,
        )?;
        state.validate()?;
        if state.android_daemon_epoch != daemon_epoch()?
            || state.catalog_sha256 != generation.catalog_sha256
            || state.desired_sha256 != desired
            || state.generation.is_none()
        {
            return Err("PW config not acknowledged".into());
        }
        let (provision, _) = store.provision(&directory)?.ok_or("PW pairing absent")?;
        crate::control_plane::pw_transport::Config::read_paired(&directory, provision.transport)
            .map_err(|error| error.to_string())
    };
    read().ok()
}

fn project(
    generation: &crate::generation::VerifiedGeneration,
    plan: &crate::plan::Plan,
) -> Result<bool> {
    if generation.catalog.cluster_runtime.is_none() {
        return Ok(false);
    }
    let changed = Store::production().project(
        &projected_catalog(generation)?,
        &generation.catalog_sha256,
        desired_agents(generation, plan)?,
    )?;
    wake_if_changed(changed, wake_courier);

    Ok(true)
}

fn verify_uninstall_report(bytes: &[u8], provision: &Provision, request: &Request) -> Result<()> {
    if request.pair_id != provision.pair_id || request.authority_epoch != provision.authority_epoch
    {
        return Err("QNX uninstall request differs from retained provision".into());
    }
    voboost_contract::domain_core::domain_operation::verify_qnx_restoration(
        bytes,
        &VerifyingKey::from_bytes(&raw32(&provision.qnx_public_key)?)
            .map_err(|_| "invalid QNX uninstall authority")?,
        request,
    )
}

pub(crate) fn prepare_android_uninstall(
    lease: Option<&crate::operation_contract::OperationLease>,
) -> Result<()> {
    retain_pending_cluster_before_android(prepare_uninstall(lease), || {
        let inventory = crate::uninstall::CommittedInventoryProof::load()?;
        inventory.revalidate()?;
        uninstall_bridge::export_device_production()?;
        if !crate::cluster_recovery_snapshot::preserve_if_pending(
            Path::new(crate::config::ROOT_ZONE),
            inventory.transaction_id(),
        )? {
            return Err("pending QNX removal has no retained recovery snapshot".into());
        }
        inventory.revalidate()
    })
}

fn retain_pending_cluster_before_android(
    result: Result<()>,
    retain: impl FnOnce() -> Result<()>,
) -> Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(error) if error == UNINSTALL_PENDING => retain(),
        Err(error) => Err(error),
    }
}

fn prepare_uninstall_guard(
    root: &Path,
    lease: Option<&crate::operation_contract::OperationLease>,
) -> Result<Option<crate::operation_contract::GenerationGuard>> {
    if let Some(lease) = lease {
        lease.verify_owner_in(root)?;
        let current = lease
            .read_live_projection()?
            .ok_or("uninstall operation authority missing")?;
        if current.operation != crate::operation_contract::Operation::Uninstall {
            return Err("operation lease is not an uninstall".into());
        }
        Ok(None)
    } else {
        Ok(Some(
            crate::operation_contract::GenerationGuard::acquire_in(root)?,
        ))
    }
}

fn prepare_uninstall(lease: Option<&crate::operation_contract::OperationLease>) -> Result<()> {
    let guard = prepare_uninstall_guard(Path::new(crate::config::ROOT_ZONE), lease)?;
    crate::product_candidate::ProductCandidateStore::production().ensure_idle_for_uninstall()?;
    let store = Store::production();
    // A root product without cluster provisioning has no QNX authority to revoke.
    let dir = store.directory()?;
    if !dir
        .entry_exists(PROVISION_FILE)
        .map_err(|e| e.to_string())?
    {
        store.prepare_uninstall(&"0".repeat(64))?;
        return Ok(());
    }
    let manifest = crate::installed_product::load_manifest()?;
    let product = manifest.digest()?;
    // The mailbox lock remains held while the verified initial authority is
    // loaded and until the pending uninstall is durably committed.
    let prepared = store.prepare_uninstall_initial(&product, || {
        let generation = crate::generation::GenerationStore::production()
            .active()
            .map_err(|e| e.to_string())?;
        if manifest.agent_catalog_sha256()? != generation.catalog_sha256 {
            return Err("active product/catalog authority differs".into());
        }
        let plan = crate::plan::read_runtime_and_validate(&generation);
        Ok((
            projected_catalog(&generation)?,
            generation.catalog_sha256.clone(),
            desired_agents(&generation, &plan)?,
        ))
    })?;
    if let Some(guard) = &guard {
        guard.verify_owner()?;
    }
    if let Some(lease) = lease {
        lease.verify_owner()?;
    }
    drop(guard);
    match prepared {
        true => Ok(()),
        false => {
            if let Err(error) = continue_uninstall_finalization() {
                if error.starts_with(UNINSTALL_FAILED) {
                    return Err(error);
                }
                crate::log::debug(
                    "cluster",
                    &format!("retained uninstall continuation pending: {error}"),
                );
            }
            // A transient wake failure must not turn durable asynchronous work
            // into a terminal Settings rollback. The next bounded poll retries.
            if !dir
                .entry_exists(UNINSTALL_REPORT)
                .map_err(|e| e.to_string())?
            {
                if let Err(error) = wake_courier() {
                    crate::log::debug(
                        "cluster",
                        &format!("uninstall courier wake pending: {error}"),
                    );
                }
            }
            Err(UNINSTALL_PENDING.into())
        }
    }
}

fn wake_if_changed(changed: bool, wake: impl FnOnce() -> Result<()>) {
    if changed {
        if let Err(error) = wake() {
            crate::log::err("cluster", &format!("courier wake unavailable: {error}"));
        }
    }
}
#[cfg(target_os = "android")]
fn wake_courier() -> Result<()> {
    let output = crate::fixed_process::output(
        "/system/bin/cmd",
        &[
            "activity",
            "broadcast",
            "--user",
            "0",
            "--receiver-foreground",
            "--include-stopped-packages",
            "-n",
            "ru.voboost/.ClusterWakeReceiver",
            "-a",
            "ru.voboost.CLUSTER_DELIVERY_WAKE",
        ],
        Duration::from_secs(2),
        4096,
    )?;
    if output.status.success() && output.stderr.is_empty() {
        Ok(())
    } else {
        Err("fixed Cluster broadcast failed".into())
    }
}
#[cfg(not(target_os = "android"))]
fn wake_courier() -> Result<()> {
    Ok(())
}

pub(crate) fn take_production(request_id: &str) -> Result<Handoff> {
    let guard = crate::operation_contract::GenerationGuard::acquire_in(Path::new(
        crate::config::ROOT_ZONE,
    ))?;
    let generation = crate::generation::GenerationStore::production()
        .active()
        .map_err(|e| e.to_string())?;
    let plan = crate::plan::read_runtime_and_validate(&generation);
    let projected = project(&generation, &plan)?;
    let store = Store::production();
    let handoff = if projected {
        store.take(request_id, || production_artifacts(&generation))?
    } else {
        store.take_inner(request_id, true, || production_artifacts(&generation))?
    };
    guard.verify_owner()?;
    Ok(handoff)
}
pub(crate) fn result_production(
    request: &LocalRequest,
    receipt: Option<&File>,
) -> Result<LocalResponse> {
    Store::production().result(request, receipt)
}

/// Root-only provisioning shares the generation writer lock with install and removal.
pub(crate) fn provision_production(source: &Path) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("Cluster provisioning requires root".into());
    }
    let guard = crate::operation_contract::GenerationGuard::acquire_in(Path::new(
        crate::config::ROOT_ZONE,
    ))?;
    Store::production().import_provision(source)?;
    guard.verify_owner()?;
    wake_courier()
}

fn production_artifacts(
    generation: &crate::generation::VerifiedGeneration,
) -> Result<(String, Vec<(WireFile, File)>)> {
    let manifest = crate::installed_product::load_manifest()?;
    if manifest.agent_catalog_sha256()? != generation.catalog_sha256 {
        return Err("active product/catalog authority differs".into());
    }
    let catalog = projected_catalog(generation)?;
    let declared = catalog.closure(Domain::Cluster)?;
    let mut product: Vec<_> = manifest
        .artifacts
        .iter()
        .filter(|a| {
            matches!(
                serde_json::to_string(&a.role).ok().as_deref(),
                Some("\"qnx-runtime\"") | Some("\"qnx-agent-module\"")
            )
        })
        .map(|a| voboost_contract::domain_catalog::FileIdentity {
            file: a.file.clone(),
            size: a.size,
            sha256: a.sha256.clone(),
        })
        .collect();
    product.sort_by(|a, b| a.file.cmp(&b.file));
    if product != declared {
        return Err("signed product and Cluster catalog closure differ".into());
    }
    let root = Directory::open(Path::new(crate::config::ROOT_ZONE)).map_err(|e| e.to_string())?;
    let resident = Directory::open(&generation.directory).map_err(|e| e.to_string())?;
    let mut files = Vec::new();
    for (name, role) in [
        ("voboost.json", WireRole::ReleaseManifest),
        ("voboost.json.sig", WireRole::ReleaseManifestSignature),
    ] {
        let maximum = if name.ends_with(".sig") {
            64
        } else {
            voboost_contract::release::MAX_MANIFEST_BYTES
        };
        let bytes = root
            .read_trusted(name, maximum, 0o600)
            .map_err(|e| e.to_string())?;
        files.push((
            WireFile {
                role,
                file: name.into(),
                size: bytes.len() as u64,
                sha256: hash(&bytes),
            },
            root.open_trusted_file(name, bytes.len() as u64, 0o600)
                .map_err(|e| e.to_string())?,
        ));
    }
    for (name, role) in [
        ("agents.json", WireRole::AgentCatalog),
        ("agents.json.sig", WireRole::AgentCatalogSignature),
    ] {
        let artifact = manifest.artifact(name)?;
        resident
            .verify_trusted_digest(name, artifact.size, &artifact.sha256, 0o444)
            .map_err(|e| e.to_string())?;
        files.push((
            WireFile {
                role,
                file: name.into(),
                size: artifact.size,
                sha256: artifact.sha256.clone(),
            },
            resident
                .open_trusted_file(name, artifact.size, 0o444)
                .map_err(|e| e.to_string())?,
        ));
    }
    for artifact in &manifest.artifacts {
        let role_text = serde_json::to_string(&artifact.role).map_err(|e| e.to_string())?;
        if !role_text.starts_with("\"qnx-") {
            continue;
        }
        let role: WireRole =
            serde_json::from_str(&role_text).map_err(|_| "unsupported QNX wire role")?;
        let mode = if matches!(role_text.as_str(), "\"qnx-daemon\"" | "\"qnx-init\"") {
            0o700
        } else {
            0o644
        };
        let (authority, mode) = if matches!(
            role_text.as_str(),
            "\"qnx-runtime\""
                | "\"qnx-agent-module\""
                | "\"qnx-resource-pack\""
                | "\"qnx-resource-ledger\""
        ) {
            (&resident, 0o444)
        } else {
            (&root, mode)
        };
        authority
            .verify_trusted_digest(&artifact.file, artifact.size, &artifact.sha256, mode)
            .map_err(|e| e.to_string())?;
        files.push((
            WireFile {
                role,
                file: artifact.file.clone(),
                size: artifact.size,
                sha256: artifact.sha256.clone(),
            },
            authority
                .open_trusted_file(&artifact.file, artifact.size, mode)
                .map_err(|e| e.to_string())?,
        ));
    }
    Ok((manifest.digest()?, files))
}

/// Advance the signed outbox even when no settings process is connected.
pub(crate) fn reconcile_snapshot(
    generation: &crate::generation::VerifiedGeneration,
    plan: &crate::plan::Plan,
) -> Result<Option<ClusterSnapshot>> {
    if !project(generation, plan)? {
        return Ok(None);
    }
    Store::production().snapshot()
}

/// Publish independently verified observations; desired writes never claim Applied.
pub(crate) fn push_snapshot(snapshot: &ClusterSnapshot, epoch: u64, fd: i32) -> Result<()> {
    static PUBLISHED: OnceLock<Mutex<BTreeMap<u64, u64>>> = OnceLock::new();
    let mut values = PUBLISHED
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .map_err(|_| "Cluster publication lock")?;
    if values.get(&epoch) == Some(&snapshot.snapshot_revision) {
        return Ok(());
    }
    let mut frame = b"K|".to_vec();
    frame.extend_from_slice(&snapshot.canonical_bytes()?);
    if !crate::downlink::enqueue_frame(fd, &frame) {
        return Err("Cluster snapshot downlink backpressure".into());
    }
    values.insert(epoch, snapshot.snapshot_revision);
    Ok(())
}

fn courier_copy(dir: &Directory, source: &File, identity: &WireFile, owner: u32) -> Result<File> {
    const NAME: &str = "courier-copy";
    verify_descriptor(source, identity, owner)?;
    dir.write_atomic_from_descriptor(
        NAME,
        source.as_raw_fd(),
        identity.size,
        &identity.sha256,
        0o600,
    )
    .map_err(|error| error.to_string())?;
    let result = (|| {
        let copy = dir
            .open_trusted_labeled_file(
                NAME,
                identity.size,
                0o600,
                "u:object_r:voboost_cluster_lease_file:s0",
            )
            .map_err(|error| error.to_string())?;
        verify_descriptor(&copy, identity, owner)?;
        dir.unlink(NAME).map_err(|error| error.to_string())?;
        if copy.metadata().map_err(|error| error.to_string())?.nlink() != 0 {
            return Err("courier copy still has a filesystem name".into());
        }
        Ok(copy)
    })();
    if result.is_err() {
        let _ = dir.unlink(NAME);
    }
    result
}

fn verify_descriptor(file: &File, identity: &WireFile, owner: u32) -> Result<()> {
    use sha2::{Digest, Sha256};
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    let before = file.metadata().map_err(|e| e.to_string())?;
    if flags < 0
        || flags & libc::O_ACCMODE != libc::O_RDONLY
        || !before.is_file()
        || before.nlink() != 1
        || before.uid() != owner
        || before.len() != identity.size
    {
        return Err("outgoing Cluster descriptor authority mismatch".into());
    }
    let mut sha = Sha256::new();
    let mut offset = 0u64;
    let mut buffer = [0u8; 65536];
    while offset < identity.size {
        let limit = (identity.size - offset).min(buffer.len() as u64) as usize;
        let read = file
            .read_at(&mut buffer[..limit], offset)
            .map_err(|e| e.to_string())?;
        if read == 0 {
            return Err("outgoing Cluster descriptor shortened".into());
        }
        sha.update(&buffer[..read]);
        offset += read as u64;
    }
    let after = file.metadata().map_err(|e| e.to_string())?;
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.ctime(),
        before.ctime_nsec(),
        before.nlink(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.ctime(),
        after.ctime_nsec(),
        after.nlink(),
    ) || hex::encode(sha.finalize()) != identity.sha256
    {
        return Err("outgoing Cluster descriptor digest changed".into());
    }
    Ok(())
}

impl Store {
    /// Import already provisioned device material from one protected directory.
    /// It never creates keys, rotates a pairing, or accepts signing input from an app.
    pub fn import_provision(&self, source: &Path) -> Result<()> {
        if !source.is_absolute() || source.as_os_str().len() > 512 {
            return Err("protected Cluster provisioning directory must be absolute".into());
        }
        let input = Directory::open(source).map_err(|e| e.to_string())?;
        input
            .validate_owner_mode(self.owner, unsafe { libc::getegid() }, 0o700)
            .map_err(|e| e.to_string())?;
        let provision_bytes = input
            .read_trusted(PROVISION_FILE, 16 * 1024, 0o600)
            .map_err(|e| e.to_string())?;
        let provision: Provision = parse(&provision_bytes, 16 * 1024)?;
        provision.validate()?;
        let mut seed = input
            .read_trusted(SEED_FILE, 32, 0o600)
            .map_err(|e| e.to_string())?;
        let mut raw: [u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| "device seed must be raw32")?;
        let key = SigningKey::from_bytes(&raw);
        raw.fill(0);
        if key.verifying_key().to_bytes() != raw32(&provision.android_public_key)? {
            seed.fill(0);
            return Err("provided signing seed is not the paired device authority".into());
        }
        if provision
            .validate_roles(&[
                &crate::trust::AGENT_CATALOG_PUBKEY,
                &crate::trust::RELEASE_CATALOG_PUBKEY,
                &crate::trust::NATIVE_EXECUTABLE_PUBKEY,
                &crate::trust::RESTORE_PUBLIC_KEY,
            ])
            .is_err()
        {
            seed.fill(0);
            return Err("device signing authority cannot be a release role".into());
        }
        let credentials = input
            .read_trusted(CREDENTIAL_FILE, 65536, 0o600)
            .map_err(|e| e.to_string())?;
        if credentials.len() as u64 != provision.transport.credentials.size
            || hash(&credentials) != provision.transport.credentials.sha256
        {
            seed.fill(0);
            return Err("provided credentials identity mismatch".into());
        }
        let dir = self.directory()?;
        let _lock = dir
            .lock_transaction(Duration::from_millis(20))
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::TimedOut {
                    "operation busy".into()
                } else {
                    error.to_string()
                }
            })?;
        let material = voboost_contract::runtime_owner::ClusterPairing {
            provision: provision_bytes,
            seed,
            credentials,
        };
        #[cfg(not(test))]
        {
            match crate::owner_client::call(
                voboost_contract::runtime_owner::Command::ImportClusterPairing { material },
            )
            .map_err(|error| error.to_string())?
            {
                voboost_contract::runtime_owner::Outcome::Written {} => (),
                _ => return Err("cluster pairing owner did not commit provision".into()),
            };
        }
        #[cfg(test)]
        crate::owner_cluster::import(&dir, &material).map_err(|error| error.to_string())?;
        self.load(&dir)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provisioning_retries_the_same_stage_after_the_mailbox_is_unlocked() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let input = tmp.path().join("input");
        provision_input(&input);
        let store = Store::at(&tmp.path().join("cluster"));
        let dir = store.directory().unwrap();
        {
            let _lock = dir.lock_transaction(Duration::from_millis(20)).unwrap();
            assert_eq!(
                store.import_provision(&input).unwrap_err(),
                "operation busy"
            );
            assert!(!dir.entry_exists(PROVISION_FILE).unwrap());
        }
        store.import_provision(&input).unwrap();
        assert!(dir.entry_exists(PROVISION_FILE).unwrap());
    }

    #[test]
    fn courier_copy_is_readonly_unlinked_and_independent() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let dir = Directory::open(tmp.path()).unwrap();
        let bytes = vec![0x5a; 140000];
        dir.write_atomic("original", &bytes, 0o600).unwrap();
        let source = dir
            .open_trusted_file("original", bytes.len() as u64, 0o600)
            .unwrap();
        let identity = WireFile {
            role: WireRole::Request,
            file: "request.vbc".into(),
            size: bytes.len() as u64,
            sha256: hash(&bytes),
        };
        let copy = courier_copy(&dir, &source, &identity, unsafe { libc::geteuid() }).unwrap();
        assert_eq!(copy.metadata().unwrap().nlink(), 0);
        assert_ne!(
            copy.metadata().unwrap().ino(),
            source.metadata().unwrap().ino()
        );
        assert!(copy.write_at(b"x", 0).is_err());
        let mut actual = Vec::new();
        copy.try_clone().unwrap().read_to_end(&mut actual).unwrap();
        assert_eq!(actual, bytes);
        assert_eq!(
            dir.read_trusted("original", bytes.len(), 0o600).unwrap(),
            bytes
        );
        assert!(!dir.entry_exists("courier-copy").unwrap());
        assert!(!dir.entry_exists(".courier-copy.tmp").unwrap());
        assert_eq!(source.metadata().unwrap().nlink(), 1);
    }

    #[test]
    fn courier_copy_rejects_changed_identity_without_exposing_a_name() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let dir = Directory::open(tmp.path()).unwrap();
        dir.write_atomic("original", b"verified", 0o600).unwrap();
        let source = dir.open_trusted_file("original", 8, 0o600).unwrap();
        let mut identity = WireFile {
            role: WireRole::Request,
            file: "request.vbc".into(),
            size: 8,
            sha256: hash(b"different"),
        };
        assert!(courier_copy(&dir, &source, &identity, unsafe { libc::geteuid() }).is_err());
        identity.sha256 = hash(b"verified");
        identity.size = 7;
        assert!(courier_copy(&dir, &source, &identity, unsafe { libc::geteuid() }).is_err());
        identity.size = 8;
        assert!(courier_copy(&dir, &source, &identity, unsafe { libc::geteuid() } + 1).is_err());
        assert!(!dir.entry_exists("courier-copy").unwrap());
        assert!(!dir.entry_exists(".courier-copy.tmp").unwrap());
    }

    #[test]
    fn confirmed_locale_projection_revokes_and_fences_replay() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let store = Store::at(&tmp.path().join("cluster"));
        let g = generation();
        store.project(&core(&g), &g.catalog_sha256, vec![]).unwrap();
        let initial = store.snapshot().unwrap().unwrap();
        let locale = cluster::GlobalLocale {
            locale: 3,
            revision: 100,
            endpoint_identity: 5,
            lifecycle_generation: 1,
            document_generation: 1,
        };
        assert!(store.project_locale(Some(locale.clone())).unwrap());
        assert!(!store.project_locale(Some(locale.clone())).unwrap());
        let snapshot = store.snapshot().unwrap().unwrap();
        assert!(snapshot.desired_revision > initial.desired_revision);
        assert_eq!(snapshot.desired_sha256, initial.desired_sha256);
        let mut bad = locale.clone();
        bad.locale = 1;
        assert!(store.project_locale(Some(bad.clone())).is_err());
        bad.revision = 99;
        assert!(store.project_locale(Some(bad)).is_err());
        assert!(store.project_locale(None).unwrap());
        let mut new = locale;
        new.endpoint_identity = 6;
        new.revision = 1;
        assert!(store.project_locale(Some(new)).unwrap());
        let dir = store.directory().unwrap();
        let value = store.load(&dir).unwrap().unwrap();
        assert!(value.global_locale.unwrap().lifecycle_generation > 1);
    }

    #[test]
    fn locale_epoch_migration_preserves_pending_uninstall() {
        for boot_changed in [false, true] {
            let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
            let input = tmp.path().join("input");
            let provision = provision_input(&input);
            let store = Store::at(&tmp.path().join("cluster"));
            store.import_provision(&input).unwrap();
            let generation = generation();
            store
                .project(&core(&generation), &generation.catalog_sha256, vec![])
                .unwrap();
            store
                .project_locale(Some(cluster::GlobalLocale {
                    locale: 3,
                    revision: 100,
                    endpoint_identity: 5,
                    lifecycle_generation: 1,
                    document_generation: 1,
                }))
                .unwrap();
            assert!(!store.prepare_uninstall(&"a".repeat(64)).unwrap());
            store
                .take(&"d".repeat(64), || panic!("uninstall has no artifacts"))
                .unwrap();
            let dir = store.directory().unwrap();
            let mut before = store.load(&dir).unwrap().unwrap();
            let pending = before.pending.as_ref().unwrap();
            assert!(pending.lease.is_some());
            let original_request = encode(&pending.request).unwrap();
            let signed = dir.read_trusted(REQUEST_FILE, 65536, 0o600).unwrap();
            if boot_changed {
                before.android_boot_id = "prior-host-boot".into();
            }
            store.persist(&dir, &before).unwrap();
            let restarted = Store {
                epoch: if boot_changed {
                    store.epoch.clone()
                } else {
                    Some("e".repeat(64))
                },
                ..Store::at(&store.path)
            };
            let after = restarted.load(&dir).unwrap().unwrap();
            assert!(after.global_locale.is_none());
            assert_eq!(after.desired_revision, before.desired_revision + 1);
            assert_eq!(after.snapshot_revision, before.snapshot_revision + 1);
            let pending = after
                .pending
                .as_ref()
                .expect("uninstall authority survived migration");
            assert!(pending.lease.is_none());
            assert_eq!(encode(&pending.request).unwrap(), original_request);
            assert_eq!(
                dir.read_trusted(REQUEST_FILE, 65536, 0o600).unwrap(),
                signed
            );
            let key =
                VerifyingKey::from_bytes(&raw32(&provision.android_public_key).unwrap()).unwrap();
            assert_eq!(
                encode(&Request::verify(&signed, &key).unwrap()).unwrap(),
                original_request
            );
            assert!(!restarted.prepare_uninstall(&"a".repeat(64)).unwrap());
            let handoff = restarted
                .take(&"e".repeat(64), || panic!("uninstall has no artifacts"))
                .unwrap();
            assert!(matches!(
                handoff.response,
                LocalResponse::Take {
                    result: TakeResult::Ready { .. },
                    ..
                }
            ));
            let retried = restarted.load(&dir).unwrap().unwrap();
            assert_eq!(
                encode(&retried.pending.unwrap().request).unwrap(),
                original_request
            );
            assert_eq!(
                dir.read_trusted(REQUEST_FILE, 65536, 0o600).unwrap(),
                signed
            );
        }
    }

    #[test]
    fn uninstall_waits_for_current_cluster_delivery() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let input = tmp.path().join("input");
        provision_input(&input);
        let store = Store::at(&tmp.path().join("cluster"));
        store.import_provision(&input).unwrap();
        let generation = generation();
        store
            .project(&core(&generation), &generation.catalog_sha256, vec![])
            .unwrap();
        let dir = store.directory().unwrap();
        let mut state = store.load(&dir).unwrap().unwrap();
        let (provision, key) = store.provision(&dir).unwrap().unwrap();
        let request = store
            .request(&state, &provision, RequestKind::Observe)
            .unwrap();
        let bytes = request.sign(&key).unwrap();
        store
            .write_artifact(
                &dir,
                voboost_contract::runtime_owner::ClusterArtifact::Request,
                &bytes,
            )
            .unwrap();
        state.pending = Some(Pending {
            request,
            files: vec![WireFile {
                role: WireRole::Request,
                file: REQUEST_FILE.into(),
                size: bytes.len() as u64,
                sha256: hash(&bytes),
            }],
            lease: Some(Lease {
                id: "b".repeat(64),
                boot_id: boot_id().unwrap(),
                until_ms: monotonic_ms().unwrap() + 30_000,
            }),
        });
        store.persist(&dir, &state).unwrap();
        let product = "a".repeat(64);
        assert_eq!(
            store.prepare_uninstall(&product).unwrap_err(),
            UNINSTALL_PENDING
        );
        assert_eq!(dir.read_trusted(REQUEST_FILE, 65536, 0o600).unwrap(), bytes);
        let retained = store.load(&dir).unwrap().unwrap().pending.unwrap();
        assert_eq!(retained.request.kind, RequestKind::Observe);
        assert_eq!(retained.lease.unwrap().id, "b".repeat(64));
        state
            .pending
            .as_mut()
            .unwrap()
            .lease
            .as_mut()
            .unwrap()
            .until_ms = 0;
        store.persist(&dir, &state).unwrap();
        {
            let _lock = dir.lock_transaction(Duration::from_millis(20)).unwrap();
            assert_eq!(
                store.prepare_uninstall(&product).unwrap_err(),
                UNINSTALL_PENDING
            );
        }
        assert!(!store.prepare_uninstall(&product).unwrap());
        let pending = store.load(&dir).unwrap().unwrap().pending.unwrap();
        assert_eq!(pending.request.kind, RequestKind::Uninstall);
        assert!(pending.lease.is_none());
    }

    #[test]
    fn uninstall_retry_keeps_challenge_and_fences_expired_local_lease() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let input = tmp.path().join("input");
        provision_input(&input);
        let store = Store::at(&tmp.path().join("cluster"));
        store.import_provision(&input).unwrap();
        let generation = generation();
        store
            .project(&core(&generation), &generation.catalog_sha256, vec![])
            .unwrap();
        assert!(!store.prepare_uninstall(&"a".repeat(64)).unwrap());
        let first = store
            .take(&"d".repeat(64), || panic!("uninstall has no artifacts"))
            .unwrap();
        let LocalResponse::Take {
            result:
                TakeResult::Ready {
                    lease_id,
                    transaction_id,
                    ..
                },
            ..
        } = first.response
        else {
            panic!("uninstall delivery missing")
        };
        let busy = store
            .take(&"e".repeat(64), || {
                panic!("active lease must not issue artifacts")
            })
            .unwrap();
        assert!(matches!(
            busy.response,
            LocalResponse::Take {
                result: TakeResult::Busy {},
                ..
            }
        ));
        assert!(busy.descriptors.is_empty());

        let dir = store.directory().unwrap();
        let mut state = store.load(&dir).unwrap().unwrap();
        let signed = dir.read_trusted(REQUEST_FILE, 65536, 0o600).unwrap();
        state
            .pending
            .as_mut()
            .unwrap()
            .lease
            .as_mut()
            .unwrap()
            .until_ms = 0;
        store.persist(&dir, &state).unwrap();
        let second = store
            .take(&"e".repeat(64), || panic!("uninstall has no artifacts"))
            .unwrap();
        let LocalResponse::Take {
            result:
                TakeResult::Ready {
                    lease_id: next_lease,
                    transaction_id: next_transaction,
                    ..
                },
            ..
        } = second.response
        else {
            panic!("uninstall retry missing")
        };
        assert_ne!(lease_id, next_lease);
        assert_eq!(transaction_id, next_transaction);
        assert_eq!(
            dir.read_trusted(REQUEST_FILE, 65536, 0o600).unwrap(),
            signed
        );
        let stale = LocalRequest::Result {
            protocol_version: 1,
            request_id: "f".repeat(64),
            lease_id,
            transaction_id,
            transport_outcome: TransportOutcome::Failed,
            receipt: None,
        };
        assert!(store.result(&stale, None).unwrap_err().contains("stale"));
    }

    #[test]
    fn observe_retry_still_rotates_challenge() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let input = tmp.path().join("input");
        provision_input(&input);
        let store = Store::at(&tmp.path().join("cluster"));
        store.import_provision(&input).unwrap();
        let generation = generation();
        store
            .project(&core(&generation), &generation.catalog_sha256, vec![])
            .unwrap();
        let dir = store.directory().unwrap();
        let mut state = store.load(&dir).unwrap().unwrap();
        let (provision, key) = store.provision(&dir).unwrap().unwrap();
        let request = store
            .request(&state, &provision, RequestKind::Observe)
            .unwrap();
        let signed = request.sign(&key).unwrap();
        dir.write_atomic(REQUEST_FILE, &signed, 0o600).unwrap();
        state.pending = Some(Pending {
            request,
            files: vec![WireFile {
                role: WireRole::Request,
                file: REQUEST_FILE.into(),
                size: signed.len() as u64,
                sha256: hash(&signed),
            }],
            lease: None,
        });
        store.persist(&dir, &state).unwrap();
        let roles = [
            &crate::trust::AGENT_CATALOG_PUBKEY,
            &crate::trust::RELEASE_CATALOG_PUBKEY,
            &crate::trust::NATIVE_EXECUTABLE_PUBKEY,
            &crate::trust::RESTORE_PUBLIC_KEY,
        ];
        voboost_shared::cluster_mailbox::reject_pending_uninstall(tmp.path(), &roles).unwrap();
        store
            .take(&"d".repeat(64), || panic!("observe has no artifacts"))
            .unwrap();
        let mut state = store.load(&dir).unwrap().unwrap();
        let previous = state.pending.as_ref().unwrap().request.challenge.clone();
        state
            .pending
            .as_mut()
            .unwrap()
            .lease
            .as_mut()
            .unwrap()
            .until_ms = 0;
        store.persist(&dir, &state).unwrap();
        store
            .take(&"e".repeat(64), || panic!("observe has no artifacts"))
            .unwrap();
        assert_ne!(
            store
                .load(&dir)
                .unwrap()
                .unwrap()
                .pending
                .unwrap()
                .request
                .challenge,
            previous
        );
    }

    #[test]
    fn locale_epoch_migration_invalidates_other_pending_requests() {
        for kind in [
            RequestKind::Generation,
            RequestKind::Desired,
            RequestKind::Observe,
        ] {
            for has_locale in [true, false] {
                let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
                let input = tmp.path().join("input");
                provision_input(&input);
                let store = Store::at(&tmp.path().join("cluster"));
                store.import_provision(&input).unwrap();
                let generation = generation();
                store
                    .project(&core(&generation), &generation.catalog_sha256, vec![])
                    .unwrap();
                if has_locale {
                    store
                        .project_locale(Some(cluster::GlobalLocale {
                            locale: 3,
                            revision: 100,
                            endpoint_identity: 5,
                            lifecycle_generation: 1,
                            document_generation: 1,
                        }))
                        .unwrap();
                }
                let dir = store.directory().unwrap();
                let mut state = store.load(&dir).unwrap().unwrap();
                let (provision, _) = store.provision(&dir).unwrap().unwrap();
                let mut request = store.request(&state, &provision, kind).unwrap();
                if kind == RequestKind::Generation {
                    request.release_manifest_sha256 = Some("a".repeat(64));
                    request.files = Some(vec![WireFile {
                        role: WireRole::QnxDaemon,
                        file: "voboost-cluster-daemon".into(),
                        size: 1,
                        sha256: "a".repeat(64),
                    }]);
                }
                state.pending = Some(Pending {
                    request,
                    files: vec![WireFile {
                        role: WireRole::Request,
                        file: REQUEST_FILE.into(),
                        size: 1,
                        sha256: "a".repeat(64),
                    }],
                    lease: Some(Lease {
                        id: "b".repeat(64),
                        boot_id: "prior".into(),
                        until_ms: 1,
                    }),
                });
                store.persist(&dir, &state).unwrap();
                let restarted = Store {
                    epoch: Some("e".repeat(64)),
                    ..Store::at(&store.path)
                };
                let after = restarted.load(&dir).unwrap().unwrap();
                assert!(after.global_locale.is_none());
                assert_eq!(
                    after.desired_revision,
                    state.desired_revision + u64::from(has_locale)
                );
                if has_locale {
                    assert!(after.pending.is_none(), "{kind:?}");
                } else {
                    assert_eq!(after.pending.as_ref().unwrap().request.kind, kind);
                    assert!(after.pending.unwrap().lease.is_none());
                }
            }
        }
    }

    #[test]
    fn shared_fence_reads_strict_mailbox_without_mutating_it() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let store = Store::at(&tmp.path().join("cluster"));
        let roles = [
            &crate::trust::AGENT_CATALOG_PUBKEY,
            &crate::trust::RELEASE_CATALOG_PUBKEY,
            &crate::trust::NATIVE_EXECUTABLE_PUBKEY,
            &crate::trust::RESTORE_PUBLIC_KEY,
        ];
        let check =
            || voboost_shared::cluster_mailbox::reject_pending_uninstall(tmp.path(), &roles);
        assert!(check().is_ok());
        let generation = generation();
        store
            .project(&core(&generation), &generation.catalog_sha256, vec![])
            .unwrap();
        assert!(check().is_ok());
        let input = tmp.path().join("input");
        provision_input(&input);
        store.import_provision(&input).unwrap();
        assert!(check().is_ok());
        assert!(!store.prepare_uninstall(&"a".repeat(64)).unwrap());
        let before = std::fs::read(store.path.join(STATE_FILE)).unwrap();
        assert!(check().unwrap_err().contains("uninstall pending"));
        assert_eq!(std::fs::read(store.path.join(STATE_FILE)).unwrap(), before);
        std::fs::remove_file(store.path.join(STATE_FILE)).unwrap();
        assert!(check().is_err());
    }

    #[test]
    fn shared_fence_accepts_signed_retry_crash_cut_for_non_uninstall_requests() {
        for kind in [
            RequestKind::Generation,
            RequestKind::Desired,
            RequestKind::Observe,
        ] {
            let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
            let input = tmp.path().join("input");
            provision_input(&input);
            let store = Store::at(&tmp.path().join("cluster"));
            store.import_provision(&input).unwrap();
            let generation = generation();
            store
                .project(&core(&generation), &generation.catalog_sha256, vec![])
                .unwrap();
            let dir = store.directory().unwrap();
            let mut state = store.load(&dir).unwrap().unwrap();
            let (provision, key) = store.provision(&dir).unwrap().unwrap();
            let mut request = store.request(&state, &provision, kind).unwrap();
            if kind == RequestKind::Generation {
                request.release_manifest_sha256 = Some("a".repeat(64));
                request.files = Some(vec![WireFile {
                    role: WireRole::QnxDaemon,
                    file: "voboost-cluster-daemon".into(),
                    size: 1,
                    sha256: "a".repeat(64),
                }]);
            }
            let old_signed = request.sign(&key).unwrap();
            dir.write_atomic(REQUEST_FILE, &old_signed, 0o600).unwrap();
            state.pending = Some(Pending {
                request: request.clone(),
                files: vec![WireFile {
                    role: WireRole::Request,
                    file: REQUEST_FILE.into(),
                    size: old_signed.len() as u64,
                    sha256: hash(&old_signed),
                }],
                lease: None,
            });
            store.persist(&dir, &state).unwrap();
            let before = dir
                .read_trusted(STATE_FILE, MAX_STATE_BYTES, 0o600)
                .unwrap();
            // Exact cut in take: signed retry is published, mailbox commit has not happened.
            request.challenge = random_id().unwrap();
            let retry_signed = request.sign(&key).unwrap();
            dir.write_atomic(REQUEST_FILE, &retry_signed, 0o600)
                .unwrap();
            let roles = [
                &crate::trust::AGENT_CATALOG_PUBKEY,
                &crate::trust::RELEASE_CATALOG_PUBKEY,
                &crate::trust::NATIVE_EXECUTABLE_PUBKEY,
                &crate::trust::RESTORE_PUBLIC_KEY,
            ];
            assert!(
                voboost_shared::cluster_mailbox::reject_pending_uninstall(tmp.path(), &roles)
                    .is_ok(),
                "{kind:?}"
            );
            assert_eq!(
                dir.read_trusted(STATE_FILE, MAX_STATE_BYTES, 0o600)
                    .unwrap(),
                before
            );
            assert_eq!(
                dir.read_trusted(REQUEST_FILE, 65536, 0o600).unwrap(),
                retry_signed
            );
        }
    }

    #[test]
    fn shared_fence_retains_uninstall_request_without_committed_pending() {
        for initializing in [false, true] {
            let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
            let input = tmp.path().join("input");
            provision_input(&input);
            let store = Store::at(&tmp.path().join("cluster"));
            store.import_provision(&input).unwrap();
            let dir = store.directory().unwrap();
            let initial = dir
                .read_trusted(STATE_FILE, MAX_STATE_BYTES, 0o600)
                .unwrap();
            let generation = generation();
            store
                .project(&core(&generation), &generation.catalog_sha256, vec![])
                .unwrap();
            let projected = dir
                .read_trusted(STATE_FILE, MAX_STATE_BYTES, 0o600)
                .unwrap();
            assert!(!store.prepare_uninstall(&"a".repeat(64)).unwrap());
            let signed = dir.read_trusted(REQUEST_FILE, 65536, 0o600).unwrap();
            // Reproduce the cut after publishing request and before mailbox commit.
            dir.write_atomic(
                STATE_FILE,
                if initializing { &initial } else { &projected },
                0o600,
            )
            .unwrap();
            let old = dir
                .read_trusted(STATE_FILE, MAX_STATE_BYTES, 0o600)
                .unwrap();
            let roles = [
                &crate::trust::AGENT_CATALOG_PUBKEY,
                &crate::trust::RELEASE_CATALOG_PUBKEY,
                &crate::trust::NATIVE_EXECUTABLE_PUBKEY,
                &crate::trust::RESTORE_PUBLIC_KEY,
            ];
            assert!(
                voboost_shared::cluster_mailbox::reject_pending_uninstall(tmp.path(), &roles)
                    .is_err()
            );
            assert_eq!(
                dir.read_trusted(STATE_FILE, MAX_STATE_BYTES, 0o600)
                    .unwrap(),
                old
            );
            assert_eq!(
                dir.read_trusted(REQUEST_FILE, 65536, 0o600).unwrap(),
                signed
            );
            if !initializing {
                dir.write_atomic("fixture-native", b"native", 0o600)
                    .unwrap();
                let file = WireFile {
                    role: WireRole::QnxDaemon,
                    file: "fixture-native".into(),
                    size: 6,
                    sha256: hash(b"native"),
                };
                let result = store.take(&"d".repeat(64), || {
                    Ok((
                        "a".repeat(64),
                        vec![(
                            file.clone(),
                            dir.open_trusted_file("fixture-native", 6, 0o600).unwrap(),
                        )],
                    ))
                });
                assert!(result.is_err(), "take overwrote an orphan uninstall");
                assert_eq!(
                    dir.read_trusted(REQUEST_FILE, 65536, 0o600).unwrap(),
                    signed
                );
                assert!(voboost_shared::cluster_mailbox::reject_pending_uninstall(
                    tmp.path(),
                    &roles
                )
                .is_err());
            }
            assert!(store
                .prepare_uninstall_initial(&"b".repeat(64), || Ok((
                    core(&generation),
                    generation.catalog_sha256.clone(),
                    vec![]
                )))
                .is_err());
            assert_eq!(
                dir.read_trusted(REQUEST_FILE, 65536, 0o600).unwrap(),
                signed
            );
            let prepared = store
                .prepare_uninstall_initial(&"a".repeat(64), || {
                    Ok((core(&generation), generation.catalog_sha256.clone(), vec![]))
                })
                .unwrap();
            assert!(!prepared);
            assert_eq!(
                dir.read_trusted(REQUEST_FILE, 65536, 0o600).unwrap(),
                signed
            );
            let pending = store.load(&dir).unwrap().unwrap().pending.unwrap();
            let provision = store.provision(&dir).unwrap().unwrap().0;
            let key =
                VerifyingKey::from_bytes(&raw32(&provision.android_public_key).unwrap()).unwrap();
            assert_eq!(
                encode(&pending.request).unwrap(),
                encode(&Request::verify(&signed, &key).unwrap()).unwrap()
            );
        }
    }

    #[test]
    fn orphan_uninstall_cannot_be_overwritten_over_existing_ordinary_pending() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let input = tmp.path().join("input");
        provision_input(&input);
        let store = Store::at(&tmp.path().join("cluster"));
        store.import_provision(&input).unwrap();
        let generation = generation();
        store
            .project(&core(&generation), &generation.catalog_sha256, vec![])
            .unwrap();
        let dir = store.directory().unwrap();
        dir.write_atomic("fixture-native", b"native", 0o600)
            .unwrap();
        let file = WireFile {
            role: WireRole::QnxDaemon,
            file: "fixture-native".into(),
            size: 6,
            sha256: hash(b"native"),
        };
        store
            .take(&"d".repeat(64), || {
                Ok((
                    "a".repeat(64),
                    vec![(
                        file.clone(),
                        dir.open_trusted_file("fixture-native", 6, 0o600).unwrap(),
                    )],
                ))
            })
            .unwrap();
        let mut ordinary = store.load(&dir).unwrap().unwrap();
        ordinary.pending.as_mut().unwrap().lease = None;
        store.persist(&dir, &ordinary).unwrap();
        let before = dir
            .read_trusted(STATE_FILE, MAX_STATE_BYTES, 0o600)
            .unwrap();
        assert!(!store.prepare_uninstall(&"a".repeat(64)).unwrap());
        let signed = dir.read_trusted(REQUEST_FILE, 65536, 0o600).unwrap();
        dir.write_atomic(STATE_FILE, &before, 0o600).unwrap();
        assert!(store
            .take(&"e".repeat(64), || panic!("must not deliver generation"))
            .is_err());
        assert_eq!(
            dir.read_trusted(REQUEST_FILE, 65536, 0o600).unwrap(),
            signed
        );
        assert!(!store.prepare_uninstall(&"a".repeat(64)).unwrap());
        assert_eq!(
            dir.read_trusted(REQUEST_FILE, 65536, 0o600).unwrap(),
            signed
        );
        assert_eq!(
            store
                .load(&dir)
                .unwrap()
                .unwrap()
                .pending
                .unwrap()
                .request
                .kind,
            RequestKind::Uninstall
        );
    }

    #[test]
    fn shared_fence_accepts_completed_generation_with_retained_request_file() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let input = tmp.path().join("input");
        let provision = provision_input(&input);
        let store = Store::at(&tmp.path().join("cluster"));
        store.import_provision(&input).unwrap();
        let generation = generation();
        store
            .project(&core(&generation), &generation.catalog_sha256, vec![])
            .unwrap();
        let dir = store.directory().unwrap();
        dir.write_atomic("fixture-native", b"native", 0o600)
            .unwrap();
        let file = WireFile {
            role: WireRole::QnxDaemon,
            file: "fixture-native".into(),
            size: 6,
            sha256: hash(b"native"),
        };
        let handoff = store
            .take(&"d".repeat(64), || {
                Ok((
                    "a".repeat(64),
                    vec![(
                        file.clone(),
                        dir.open_trusted_file("fixture-native", 6, 0o600).unwrap(),
                    )],
                ))
            })
            .unwrap();
        let LocalResponse::Take {
            result:
                TakeResult::Ready {
                    lease_id,
                    transaction_id,
                    ..
                },
            ..
        } = handoff.response
        else {
            panic!("generation missing")
        };
        let state = store.load(&dir).unwrap().unwrap();
        let request = &state.pending.as_ref().unwrap().request;
        let identity = voboost_contract::domain_generation::GenerationIdentity {
            domain: Domain::Cluster,
            catalog_sha256: request.catalog_sha256.clone(),
            selection_sha256: "7".repeat(64),
            closure_sha256: request.closure_sha256.clone(),
        };
        let receipt = Receipt {
            schema_version: 1,
            kind: cluster::ReceiptKind::Generation,
            pair_id: provision.pair_id,
            domain: Domain::Cluster,
            authority_epoch: provision.authority_epoch,
            transaction_id: transaction_id.clone(),
            catalog_sha256: request.catalog_sha256.clone(),
            closure_sha256: request.closure_sha256.clone(),
            selection_sha256: identity.selection_sha256.clone(),
            generation_id: identity.generation_id().unwrap(),
            desired_revision: 0,
            desired_sha256: cluster::desired_digest(&[]).unwrap(),
            challenge: request.challenge.clone(),
            daemon_epoch: "b".repeat(64),
            boot_id: "qnx-boot".into(),
            observation_revision: 1,
            agents: vec![],
        };
        let bytes = receipt.sign(&SigningKey::from_bytes(&[74; 32])).unwrap();
        dir.write_atomic("generation-receipt", &bytes, 0o600)
            .unwrap();
        let descriptor = dir
            .open_trusted_file("generation-receipt", bytes.len() as u64, 0o600)
            .unwrap();
        let result = LocalRequest::Result {
            protocol_version: 1,
            request_id: "e".repeat(64),
            lease_id,
            transaction_id,
            transport_outcome: TransportOutcome::Delivered,
            receipt: Some(BlobIdentity {
                size: bytes.len() as u64,
                sha256: hash(&bytes),
            }),
        };
        store.result(&result, Some(&descriptor)).unwrap();
        assert!(store.load(&dir).unwrap().unwrap().pending.is_none());
        assert!(dir.entry_exists(REQUEST_FILE).unwrap());
        let roles = [
            &crate::trust::AGENT_CATALOG_PUBKEY,
            &crate::trust::RELEASE_CATALOG_PUBKEY,
            &crate::trust::NATIVE_EXECUTABLE_PUBKEY,
            &crate::trust::RESTORE_PUBLIC_KEY,
        ];
        voboost_shared::cluster_mailbox::reject_pending_uninstall(tmp.path(), &roles).unwrap();
    }

    #[test]
    fn shared_fence_rejects_unsafe_or_malformed_authority() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let store = Store::at(&tmp.path().join("cluster"));
        let input = tmp.path().join("input");
        provision_input(&input);
        store.import_provision(&input).unwrap();
        let generation = generation();
        store
            .project(&core(&generation), &generation.catalog_sha256, vec![])
            .unwrap();
        let roles = [
            &crate::trust::AGENT_CATALOG_PUBKEY,
            &crate::trust::RELEASE_CATALOG_PUBKEY,
            &crate::trust::NATIVE_EXECUTABLE_PUBKEY,
            &crate::trust::RESTORE_PUBLIC_KEY,
        ];
        let check =
            || voboost_shared::cluster_mailbox::reject_pending_uninstall(tmp.path(), &roles);
        let dir = store.directory().unwrap();
        for name in [STATE_FILE, PROVISION_FILE, SEED_FILE, CREDENTIAL_FILE] {
            let old = std::fs::read(store.path.join(name)).unwrap();
            dir.write_atomic(name, b"malformed", 0o600).unwrap();
            assert!(check().is_err(), "{name}");
            dir.write_atomic(name, &old, 0o600).unwrap();
        }
        std::fs::set_permissions(
            store.path.join(STATE_FILE),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(check().is_err());
        std::fs::set_permissions(
            store.path.join(STATE_FILE),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(check().is_ok());
    }

    #[test]
    fn uninstall_preparation_reuses_only_its_own_lease() {
        use crate::operation_contract::{Operation, OperationDescriptor, OperationLease};
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let other = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        for dir in [root.path(), other.path()] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let tx = "a".repeat(64);
        let descriptor = OperationDescriptor::new(
            Operation::Uninstall,
            tx.clone(),
            format!("recovery/{tx}/uninstall-journal.json"),
            "00000000-0000-0000-0000-000000000001".into(),
        )
        .unwrap();
        let lease = OperationLease::acquire_in(root.path(), descriptor).unwrap();
        assert!(prepare_uninstall_guard(root.path(), Some(&lease))
            .unwrap()
            .is_none());
        assert!(prepare_uninstall_guard(other.path(), Some(&lease)).is_err());
        assert!(crate::operation_contract::GenerationGuard::acquire_in(root.path()).is_err());
        lease.verify_owner().unwrap();
    }

    #[test]
    fn uninstall_keeps_unprovisioned_path_but_rejects_partial_authority() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let store = Store::at(&tmp.path().join("cluster"));
        assert!(store.prepare_uninstall(&"a".repeat(64)).unwrap());
        store
            .directory()
            .unwrap()
            .write_atomic(SEED_FILE, &[73; 32], 0o600)
            .unwrap();
        assert!(store
            .prepare_uninstall(&"a".repeat(64))
            .unwrap_err()
            .contains("partial"));
    }

    #[test]
    fn uninstall_queues_signed_request_and_rejects_forged_or_complete_reports() {
        use voboost_contract::domain_core::domain_operation::{
            AbsenceStartup, AuthenticatedReport, DomainOperationReport, InstalledEvidence,
            Operation, Outcome, Phase,
        };
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let provision = provision_input(&tmp.path().join("input"));
        let store = Store::at(&tmp.path().join("cluster"));
        store.import_provision(&tmp.path().join("input")).unwrap();
        let g = generation();
        store.project(&core(&g), &g.catalog_sha256, vec![]).unwrap();
        assert!(!store.prepare_uninstall(&"a".repeat(64)).unwrap());
        let handoff = store
            .take(&"d".repeat(64), || {
                panic!("uninstall cannot deliver artifacts")
            })
            .unwrap();
        let LocalResponse::Take {
            result:
                TakeResult::Ready {
                    lease_id,
                    transaction_id,
                    ..
                },
            ..
        } = handoff.response
        else {
            panic!("signed uninstall delivery missing");
        };
        let dir = store.directory().unwrap();
        let state = store.load(&dir).unwrap().unwrap();
        let request = &state.pending.as_ref().unwrap().request;
        assert_eq!(request.kind, RequestKind::Uninstall);
        let signed = dir.read_trusted(REQUEST_FILE, 65536, 0o600).unwrap();
        assert_eq!(
            Request::verify(
                &signed,
                &VerifyingKey::from_bytes(&raw32(&provision.android_public_key).unwrap()).unwrap()
            )
            .unwrap()
            .kind,
            RequestKind::Uninstall
        );
        let mut report = AuthenticatedReport {
            schema_version: 1,
            pair_id: provision.pair_id.clone(),
            authority_epoch: provision.authority_epoch.clone(),
            challenge: request.challenge.clone(),
            report: DomainOperationReport {
                schema_version: 2,
                domain: Domain::Cluster,
                operation: Operation::Uninstall,
                phase: Phase::Uninstall,
                outcome: Outcome::ReloadRequired,
                transaction_id: request.transaction_id.clone(),
                release_manifest_sha256: "a".repeat(64),
                catalog_sha256: request.catalog_sha256.clone(),
                generation_id: None,
                desired_revision: 0,
                desired_sha256: cluster::desired_digest(&[]).unwrap(),
                boot_id: Some("new-qnx-boot".into()),
                daemon_epoch: Some("b".repeat(64)),
                installed_evidence: Some(InstalledEvidence::QnxRestored {
                    startup: AbsenceStartup {
                        path: "/scripts/startup_cluster.sh".into(),
                        original_sha256:
                            "c26b4913707a1e96933f48a07d6957857cc52853a7e405eb29b2adab9b84f47a"
                                .into(),
                        restored_sha256:
                            "c26b4913707a1e96933f48a07d6957857cc52853a7e405eb29b2adab9b84f47a"
                                .into(),
                    },
                    restore_fence_sha256: hash(&encode(&request.transaction_id).unwrap()),
                    resident_restore:
                        voboost_contract::domain_core::domain_operation::ResidentRestore::Restored,
                    reason: "restored; reboot required".into(),
                }),
            },
        };
        let key = SigningKey::from_bytes(&[74; 32]);
        let bytes = report.sign(&key).unwrap();
        verify_uninstall_report(&bytes, &provision, request).unwrap();
        let forged = report.sign(&SigningKey::from_bytes(&[75; 32])).unwrap();
        assert!(verify_uninstall_report(&forged, &provision, request).is_err());
        report.challenge = "c".repeat(64);
        assert!(verify_uninstall_report(&report.sign(&key).unwrap(), &provision, request).is_err());
        report.challenge = request.challenge.clone();
        report.report.outcome = Outcome::Completed;
        report.report.phase = Phase::Complete;
        assert!(report.sign(&key).is_err());
        dir.write_atomic("test-uninstall-receipt", &forged, 0o600)
            .unwrap();
        let mut result = LocalRequest::Result {
            protocol_version: 1,
            request_id: "e".repeat(64),
            lease_id,
            transaction_id,
            transport_outcome: TransportOutcome::Delivered,
            receipt: Some(BlobIdentity {
                size: forged.len() as u64,
                sha256: hash(&forged),
            }),
        };
        let bad_fd = dir
            .open_trusted_file("test-uninstall-receipt", forged.len() as u64, 0o600)
            .unwrap();
        assert!(store.result(&result, Some(&bad_fd)).is_err());
        assert!(!dir.entry_exists(UNINSTALL_REPORT).unwrap());
        dir.write_atomic("test-uninstall-receipt", &bytes, 0o600)
            .unwrap();
        if let LocalRequest::Result { receipt, .. } = &mut result {
            *receipt = Some(BlobIdentity {
                size: bytes.len() as u64,
                sha256: hash(&bytes),
            });
        }
        let good_fd = dir
            .open_trusted_file("test-uninstall-receipt", bytes.len() as u64, 0o600)
            .unwrap();
        assert!(matches!(
            store.result(&result, Some(&good_fd)).unwrap(),
            LocalResponse::Result {
                result: ResultStatus::Recorded {},
                ..
            }
        ));
        // Restore is asynchronous progress, not rollback or permission to
        // remove Android authority. A subsequent Settings poll must continue.
        assert!(!store.prepare_uninstall(&"a".repeat(64)).unwrap());
        assert!(!crate::preparation_resolved(&Ok(
            crate::PrepareUninstallOutcome::PendingCluster
        )));
        assert!(crate::preparation_resolved(&Ok(
            crate::PrepareUninstallOutcome::Committed
        )));
        assert!(dir.entry_exists(PROVISION_FILE).unwrap());
        assert!(dir.entry_exists(SEED_FILE).unwrap());
        assert!(matches!(
            store
                .take(&"d".repeat(64), || panic!(
                    "uninstall must not ship artifacts"
                ))
                .unwrap()
                .response,
            LocalResponse::Take {
                result: TakeResult::Empty {},
                ..
            }
        ));
        // A changed plan must not erase the pending uninstall or restart delivery.
        assert!(!store.project(&core(&g), &g.catalog_sha256, vec![]).unwrap());
    }

    pub(super) fn provision_input(path: &Path) -> Provision {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let seed = [73; 32];
        let credentials = b"bounded fixture credentials";
        let provision = Provision {
            schema_version: 1,
            pair_id: "1".repeat(64),
            authority_epoch: "2".repeat(64),
            android_public_key: hex::encode(
                SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
            ),
            qnx_public_key: hex::encode(
                SigningKey::from_bytes(&[74; 32]).verifying_key().to_bytes(),
            ),
            transport: Transport {
                host: "192.0.2.1".into(),
                port: 9443,
                server_certificate_sha256: "3".repeat(64),
                client_certificate_sha256: "4".repeat(64),
                credentials: BlobIdentity {
                    size: credentials.len() as u64,
                    sha256: hash(credentials),
                },
            },
        };
        let dir = Directory::open(path).unwrap();
        dir.write_atomic(PROVISION_FILE, &encode(&provision).unwrap(), 0o600)
            .unwrap();
        dir.write_atomic(SEED_FILE, &seed, 0o600).unwrap();
        dir.write_atomic(CREDENTIAL_FILE, credentials, 0o600)
            .unwrap();
        provision
    }
    #[test]
    fn initializing_uninstall_excludes_concurrent_generation() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let input = tmp.path().join("input");
        provision_input(&input);
        let store = Store::at(&tmp.path().join("cluster"));
        store.import_provision(&input).unwrap();
        let generation = generation();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let preparing = Store::at(&store.path);
        let worker = std::thread::spawn(move || {
            preparing.prepare_uninstall_initial(&"a".repeat(64), || {
                entered_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
                Ok((core(&generation), generation.catalog_sha256, vec![]))
            })
        });
        entered_rx.recv().unwrap();
        let other = Store::at(&store.path);
        let contender = std::thread::spawn(move || {
            other.take(&"d".repeat(64), || Err("generation was requested".into()))
        });
        let result = contender.join().unwrap();
        assert!(matches!(result, Err(ref e) if !e.contains("generation was requested")));
        resume_tx.send(()).unwrap();
        assert!(!worker.join().unwrap().unwrap());
        let handoff = store
            .take(&"e".repeat(64), || {
                panic!("generation must not be produced")
            })
            .unwrap();
        assert!(matches!(
            handoff.response,
            LocalResponse::Take {
                result: TakeResult::Ready { .. },
                ..
            }
        ));
        let state = store.load(&store.directory().unwrap()).unwrap().unwrap();
        assert_eq!(state.pending.unwrap().request.kind, RequestKind::Uninstall);
    }

    #[test]
    fn fresh_pair_uninstall_can_be_prepared_without_prior_projection() {
        for has_runtime in [true, false] {
            let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
            let input = tmp.path().join("input");
            let provision = provision_input(&input);
            let store = Store::at(&tmp.path().join("cluster"));
            store.import_provision(&input).unwrap();
            let generation = if has_runtime {
                generation()
            } else {
                crate::plan::test_fixtures::settings_generation()
            };
            assert_eq!(generation.catalog.cluster_runtime.is_some(), has_runtime);
            let empty = store
                .take_inner(&"c".repeat(64), true, || {
                    panic!("must not create generation")
                })
                .unwrap();
            assert!(matches!(
                empty.response,
                LocalResponse::Take {
                    result: TakeResult::Empty {},
                    ..
                }
            ));
            assert!(!store
                .prepare_uninstall_initial(&"a".repeat(64), || Ok((
                    core(&generation),
                    generation.catalog_sha256.clone(),
                    vec![]
                )))
                .unwrap());
            assert!(!store
                .prepare_uninstall_initial(&"a".repeat(64), || Ok((
                    core(&generation),
                    generation.catalog_sha256.clone(),
                    vec![]
                )))
                .unwrap());
            let handoff = store
                .take_inner(&"d".repeat(64), true, || {
                    panic!("uninstall has no artifacts")
                })
                .unwrap();
            assert!(matches!(
                handoff.response,
                LocalResponse::Take {
                    result: TakeResult::Ready { .. },
                    ..
                }
            ));
            let dir = store.directory().unwrap();
            let signed = dir.read_trusted(REQUEST_FILE, 65536, 0o600).unwrap();
            let key =
                VerifyingKey::from_bytes(&raw32(&provision.android_public_key).unwrap()).unwrap();
            let request = Request::verify(&signed, &key).unwrap();
            assert_eq!(request.kind, RequestKind::Uninstall);
            assert_eq!(request.catalog_sha256, generation.catalog_sha256);
            assert_eq!(
                request.release_manifest_sha256.as_deref(),
                Some("a".repeat(64).as_str())
            );
        }
    }

    #[test]
    fn missing_provisioned_mailbox_cannot_recreate_authority() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let input = tmp.path().join("input");
        provision_input(&input);
        let store = Store::at(&tmp.path().join("cluster"));
        let generation = generation();
        store
            .project(&core(&generation), &generation.catalog_sha256, vec![])
            .unwrap();
        store.import_provision(&input).unwrap();
        std::fs::remove_file(store.path.join(STATE_FILE)).unwrap();
        assert!(store
            .project(&core(&generation), &generation.catalog_sha256, vec![])
            .is_err());
        assert!(!store.path.join(STATE_FILE).exists());
    }
    #[test]
    fn lost_mailbox_with_pending_uninstall_retains_authority() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let input = tmp.path().join("input");
        provision_input(&input);
        let store = Store::at(&tmp.path().join("cluster"));
        store.import_provision(&input).unwrap();
        let generation = generation();
        store
            .project(&core(&generation), &generation.catalog_sha256, vec![])
            .unwrap();
        assert!(!store.prepare_uninstall(&"a".repeat(64)).unwrap());
        assert!(store
            .load(&store.directory().unwrap())
            .unwrap()
            .unwrap()
            .pending
            .is_some());
        std::fs::remove_file(store.path.join(STATE_FILE)).unwrap();
        assert!(store
            .project(&core(&generation), &generation.catalog_sha256, vec![])
            .is_err());
        assert!(store.prepare_uninstall(&"a".repeat(64)).is_err());
        assert!(store
            .take(&"d".repeat(64), || panic!("must not deliver"))
            .is_err());
        assert!(store.import_provision(&input).is_err());
        assert!(!store.path.join(STATE_FILE).exists());
    }

    #[test]
    fn fresh_pairing_and_interrupted_imports_initialize_before_provision() {
        for step in 0..4 {
            let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
            let input = tmp.path().join("input");
            provision_input(&input);
            let store = Store::at(&tmp.path().join("cluster"));
            let dir = store.directory().unwrap();
            let source = Directory::open(&input).unwrap();
            if step >= 1 {
                dir.write_atomic(SEED_FILE, &[73; 32], 0o600).unwrap();
            }
            if step >= 2 {
                let credentials = source.read_trusted(CREDENTIAL_FILE, 65536, 0o600).unwrap();
                dir.write_atomic(CREDENTIAL_FILE, &credentials, 0o600)
                    .unwrap();
            }
            if step >= 3 {
                dir.write_atomic(STATE_FILE, INITIAL_MAILBOX, 0o600)
                    .unwrap();
            }
            store.import_provision(&input).unwrap();
            assert_eq!(
                dir.read_trusted(STATE_FILE, MAX_STATE_BYTES, 0o600)
                    .unwrap(),
                INITIAL_MAILBOX
            );
            store.import_provision(&input).unwrap();
            let generation = generation();
            assert!(store
                .project(&core(&generation), &generation.catalog_sha256, vec![])
                .unwrap());
            let state = store.load(&dir).unwrap().unwrap();
            assert_eq!(state.desired_revision, 1);
            assert!(matches!(state.delivery_state, DeliveryState::Pending));
        }
    }

    #[test]
    fn existing_state_survives_pairing_and_exact_recovery() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let input = tmp.path().join("input");
        provision_input(&input);
        let store = Store::at(&tmp.path().join("cluster"));
        let generation = generation();
        store
            .project(&core(&generation), &generation.catalog_sha256, vec![])
            .unwrap();
        let dir = store.directory().unwrap();
        let before = store.load(&dir).unwrap().unwrap();
        store.import_provision(&input).unwrap();
        let paired = store.load(&dir).unwrap().unwrap();
        assert_eq!(paired.desired_revision, before.desired_revision);
        assert!(matches!(paired.delivery_state, DeliveryState::Pending));
        let retained = dir
            .read_trusted(STATE_FILE, MAX_STATE_BYTES, 0o600)
            .unwrap();
        std::fs::remove_file(store.path.join(CREDENTIAL_FILE)).unwrap();
        store.import_provision(&input).unwrap();
        assert_eq!(
            dir.read_trusted(STATE_FILE, MAX_STATE_BYTES, 0o600)
                .unwrap(),
            retained
        );
    }

    #[test]
    fn interrupted_commit_recovers_setup_state_without_resetting_intent() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let input = tmp.path().join("input");
        provision_input(&input);
        let store = Store::at(&tmp.path().join("cluster"));
        let generation = generation();
        store
            .project(&core(&generation), &generation.catalog_sha256, vec![])
            .unwrap();
        let dir = store.directory().unwrap();
        let before = store.load(&dir).unwrap().unwrap();
        assert!(matches!(
            before.delivery_state,
            DeliveryState::SetupRequired
        ));
        let source = Directory::open(&input).unwrap();
        for (name, max) in [
            (SEED_FILE, 32),
            (CREDENTIAL_FILE, 65536),
            (PROVISION_FILE, 16384),
        ] {
            dir.write_atomic(name, &source.read_trusted(name, max, 0o600).unwrap(), 0o600)
                .unwrap();
        }
        store.import_provision(&input).unwrap();
        let after = store.load(&dir).unwrap().unwrap();
        assert!(matches!(after.delivery_state, DeliveryState::Pending));
        assert_eq!(after.desired_revision, before.desired_revision);
        assert_eq!(after.snapshot_revision, before.snapshot_revision + 1);
    }

    #[test]
    fn pairing_and_projection_use_same_mailbox_lock() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let input = tmp.path().join("input");
        provision_input(&input);
        let store = Store::at(&tmp.path().join("cluster"));
        let dir = store.directory().unwrap();
        let lock = dir.lock_transaction(Duration::from_millis(20)).unwrap();
        let generation = generation();
        assert!(store.import_provision(&input).is_err());
        assert!(store
            .project(&core(&generation), &generation.catalog_sha256, vec![])
            .is_err());
        assert!(!store.path.join(PROVISION_FILE).exists());
        assert!(!store.path.join(STATE_FILE).exists());
        drop(lock);
        store.import_provision(&input).unwrap();
    }

    #[test]
    fn legacy_provision_without_mailbox_is_never_initialized_by_retry() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let input = tmp.path().join("input");
        provision_input(&input);
        let store = Store::at(&tmp.path().join("cluster"));
        store.import_provision(&input).unwrap();
        std::fs::remove_file(store.path.join(STATE_FILE)).unwrap();
        assert!(store.snapshot().is_err());
        assert!(store.import_provision(&input).is_err());
        assert!(!store.path.join(STATE_FILE).exists());
    }

    #[test]
    fn provisioning_is_immutable_and_exact_retry_preserves_delivery() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let input = tmp.path().join("input");
        let provision = provision_input(&input);
        let store = Store::at(&tmp.path().join("cluster"));
        store.import_provision(&input).unwrap();
        let generation = generation();
        store
            .project(&core(&generation), &generation.catalog_sha256, vec![])
            .unwrap();
        let dir = store.directory().unwrap();
        let seed_inode = dir
            .open_trusted_file(SEED_FILE, 32, 0o600)
            .unwrap()
            .metadata()
            .unwrap()
            .ino();
        // An exact retry must not clear an in-flight lease or rewrite its durable state.
        let retained = dir
            .read_trusted(STATE_FILE, MAX_STATE_BYTES, 0o600)
            .unwrap();
        store.import_provision(&input).unwrap();
        assert_eq!(
            dir.read_trusted(STATE_FILE, MAX_STATE_BYTES, 0o600)
                .unwrap(),
            retained
        );
        assert_eq!(
            seed_inode,
            dir.open_trusted_file(SEED_FILE, 32, 0o600)
                .unwrap()
                .metadata()
                .unwrap()
                .ino()
        );
        let mut changed = provision;
        changed.authority_epoch = "5".repeat(64);
        Directory::open(&input)
            .unwrap()
            .write_atomic(PROVISION_FILE, &encode(&changed).unwrap(), 0o600)
            .unwrap();
        assert!(store
            .import_provision(&input)
            .unwrap_err()
            .contains("immutable"));
        assert_eq!(
            dir.read_trusted(STATE_FILE, MAX_STATE_BYTES, 0o600)
                .unwrap(),
            retained
        );
    }
    #[test]
    fn pairing_rejects_each_role_for_android_and_qnx_authority() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let provision = provision_input(&tmp.path().join("input"));
        let roles = [
            &crate::trust::AGENT_CATALOG_PUBKEY,
            &crate::trust::RELEASE_CATALOG_PUBKEY,
            &crate::trust::NATIVE_EXECUTABLE_PUBKEY,
            &crate::trust::RESTORE_PUBLIC_KEY,
        ];
        provision.validate_roles(&roles).unwrap();
        for role in roles {
            for android in [true, false] {
                let mut value = provision.clone();
                if android {
                    value.android_public_key = hex::encode(role);
                } else {
                    value.qnx_public_key = hex::encode(role);
                }
                assert!(value.validate_roles(&roles).is_err());
            }
        }
    }

    #[test]
    fn provisioning_rejects_unpaired_seed_and_recovers_partial_import() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let input = tmp.path().join("input");
        provision_input(&input);
        let store = Store::at(&tmp.path().join("cluster"));
        let dir = store.directory().unwrap();
        dir.write_atomic(SEED_FILE, &[73; 32], 0o600).unwrap();
        store.import_provision(&input).unwrap();
        assert!(store.provision(&dir).unwrap().is_some());
        Directory::open(&input)
            .unwrap()
            .write_atomic(SEED_FILE, &[75; 32], 0o600)
            .unwrap();
        assert!(store
            .import_provision(&input)
            .unwrap_err()
            .contains("paired device"));
        assert_eq!(dir.read_trusted(SEED_FILE, 32, 0o600).unwrap(), [73; 32]);
    }
    pub(super) fn generation() -> crate::generation::VerifiedGeneration {
        let mut g = crate::plan::test_fixtures::settings_generation();
        let agent = &mut g.catalog.agents[1];
        agent.id = "font-cyrillic".into();
        let mut target = agent.targets[0].clone();
        target.platform = crate::catalog::TargetPlatform::Qnx;
        target.domain = crate::catalog::TargetDomain::Cluster;
        target.entry_abi = crate::catalog::TargetAbi::VoboostAgent3V1;
        target.entry_class = None;
        target.process = "gauge".into();
        target.file = "libagent-font-cyrillic.so".into();
        agent.targets.push(target);
        g.catalog.cluster_runtime = Some(crate::catalog::CatalogFile {
            file: "libvoboost-runtime-cluster.so".into(),
            size: 1,
            sha256: "a".repeat(64),
        });
        g
    }
    pub(super) fn core(g: &crate::generation::VerifiedGeneration) -> Catalog {
        let mut bytes = serde_json::to_vec(&g.catalog).unwrap();
        bytes.push(b'\n');
        Catalog::parse(
            &bytes,
            crate::catalog::AGENT_ENTRY_ABI_SHA256,
            voboost_contract::domain_catalog::NATIVE_ENTRY_ABI_SHA256,
        )
        .unwrap()
    }
    #[test]
    fn pedestrian_warning_startup_projects_saved_choice_and_preserves_explicit_off() {
        let mut g = generation();
        let agent = g
            .catalog
            .agents
            .iter_mut()
            .find(|agent| agent.id == "font-cyrillic")
            .unwrap();
        agent.id = "vehicle-drive-pedestrian-warning".into();
        agent.options = Some(
            serde_json::from_value(serde_json::json!([{
                "key":"intent", "type":"enum", "default":"observe",
                "values":[{"value":"observe","title":{"en":"Observe","ru":"Наблюдать","zh":"观察"}},
                          {"value":"on","title":{"en":"On","ru":"Включено","zh":"开启"}},
                          {"value":"off","title":{"en":"Off","ru":"Выключено","zh":"关闭"}}]
            }]))
            .unwrap(),
        );
        let mut p = crate::plan::Plan::defaults_for(&g);
        p.entries.push(crate::plan::PlanEntry {
            id: "vehicle-drive-pedestrian-warning".into(),
            enabled: true,
            config: serde_json::json!({}),
        });
        for (saved, expected) in [(Some(true), "on"), (Some(false), "off"), (None, "observe")] {
            let agents = desired_agents_with_saved(&g, &p, |source| {
                assert_eq!(source, "vehicle-drive-pedestrian-warning");
                Ok(saved)
            })
            .unwrap();
            assert_eq!(agents[0].options["intent"], expected);
        }
        assert!(desired_agents_with_saved(&g, &p, |_| Err("unavailable".into())).is_err());
        p.entries
            .iter_mut()
            .find(|entry| entry.id == "vehicle-drive-pedestrian-warning")
            .unwrap()
            .config = serde_json::json!({"intent":"off"});
        let agents = desired_agents_with_saved(&g, &p, |_| {
            panic!("explicit OFF must not depend on saved state")
        })
        .unwrap();
        assert_eq!(agents[0].options["intent"], "off");
    }

    #[test]
    fn canonical_plan_is_only_projection_authority() {
        let g = generation();
        let mut p = crate::plan::Plan::defaults_for(&g);
        p.entries.push(crate::plan::PlanEntry {
            id: "font-cyrillic".into(),
            enabled: false,
            config: serde_json::json!({}),
        });
        p.entries
            .iter_mut()
            .find(|e| e.id == "font-cyrillic")
            .unwrap()
            .enabled = true;
        let enabled = desired_agents(&g, &p).unwrap();
        assert_eq!(enabled.len(), 1);
        assert!(enabled[0].enabled);
        p.disable_all = true;
        assert!(!desired_agents(&g, &p).unwrap()[0].enabled);
        p.disable_all = false;
        p.valid = false;
        assert!(desired_agents(&g, &p).is_err());
        p.valid = true;
        p.catalog_sha256 = "f".repeat(64);
        assert!(desired_agents(&g, &p).is_err());
    }
    #[test]
    fn projection_is_idempotent_and_never_claims_applied() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::at(&tmp.path().join("cluster"));
        let g = generation();
        let c = core(&g);
        let mut p = crate::plan::Plan::defaults_for(&g);
        p.entries.push(crate::plan::PlanEntry {
            id: "font-cyrillic".into(),
            enabled: false,
            config: serde_json::json!({}),
        });
        let calls = std::cell::Cell::new(0);
        let changed = store
            .project(&c, &g.catalog_sha256, desired_agents(&g, &p).unwrap())
            .unwrap();
        wake_if_changed(changed, || {
            calls.set(calls.get() + 1);
            Ok(())
        });
        let first = store.snapshot().unwrap().unwrap();
        let changed = store
            .project(&c, &g.catalog_sha256, desired_agents(&g, &p).unwrap())
            .unwrap();
        wake_if_changed(changed, || {
            calls.set(calls.get() + 1);
            Ok(())
        });
        assert_eq!(calls.get(), 1);
        let repeat = store.snapshot().unwrap().unwrap();
        assert_eq!(first.snapshot_revision, repeat.snapshot_revision);
        p.entries
            .iter_mut()
            .find(|e| e.id == "font-cyrillic")
            .unwrap()
            .enabled = true;
        store
            .project(&c, &g.catalog_sha256, desired_agents(&g, &p).unwrap())
            .unwrap();
        let updated = store.snapshot().unwrap().unwrap();
        assert!(updated.desired_revision > first.desired_revision);
        assert!(updated.agents[0].enabled);
        assert_ne!(updated.agents[0].state, ObservedState::Applied);
        assert!(matches!(
            updated.delivery_state,
            DeliveryState::SetupRequired
        ));
    }
    #[test]
    fn malformed_courier_request_has_no_mutation_api() {
        for op in ["clusterMutate", "clusterCheckbox", "clusterDeliveryTake"] {
            let bytes = format!("{{\"op\":\"{op}\",\"enabled\":true}}\n");
            assert!(LocalRequest::parse(bytes.as_bytes()).is_err());
        }
    }
    #[test]
    fn actual_projection_parser_matches_signed_mixed_catalog_target_gates() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let mut g = generation();
        g.directory = tmp.path().to_path_buf();
        let mut bytes = serde_json::to_vec(&g.catalog).unwrap();
        bytes.push(b'\n');
        g.catalog_sha256 = hash(&bytes);
        std::fs::write(tmp.path().join("agents.json"), &bytes).unwrap();
        std::fs::set_permissions(
            tmp.path().join("agents.json"),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        assert!(crate::catalog::AgentCatalog::parse(&bytes).is_ok());
        assert!(projected_catalog(&g).is_ok());
        for field in ["platform", "domain", "entryAbi", "boot"] {
            let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            value["agents"][1]["targets"][1][field] = if field == "boot" {
                serde_json::json!(true)
            } else {
                serde_json::json!("android")
            };
            let mut bad = serde_json::to_vec(&value).unwrap();
            bad.push(b'\n');
            assert!(crate::catalog::AgentCatalog::parse(&bad).is_err());
            assert!(Catalog::parse(
                &bad,
                crate::catalog::AGENT_ENTRY_ABI_SHA256,
                voboost_contract::domain_catalog::NATIVE_ENTRY_ABI_SHA256
            )
            .is_err());
        }
    }
}

#[cfg(test)]
pub(crate) fn test_queue_cluster_uninstall(root: &Path, product: &str) {
    let input = root.join("cluster-test-input");
    tests::provision_input(&input);
    let store = Store::at(&root.join("cluster"));
    store.import_provision(&input).unwrap();
    let generation = tests::generation();
    store
        .project(
            &tests::core(&generation),
            &generation.catalog_sha256,
            vec![],
        )
        .unwrap();
    assert!(!store.prepare_uninstall(product).unwrap());
}

#[cfg(test)]
mod multi_target_projection_tests {
    use super::*;
    fn fixture() -> State {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let store = Store::at(&tmp.path().join("cluster"));
        let mut g = super::tests::generation();
        let agent = g
            .catalog
            .agents
            .iter_mut()
            .find(|a| a.id == "font-cyrillic")
            .unwrap();
        let native = agent
            .targets
            .iter()
            .find(|t| t.process == "gauge")
            .unwrap()
            .clone();
        for process in ["light", "point"] {
            let mut target = native.clone();
            target.process = process.into();
            agent.targets.push(target);
        }
        g.catalog.validate().unwrap();
        let desired = vec![DesiredAgent {
            id: "font-cyrillic".into(),
            enabled: true,
            options: BTreeMap::new(),
        }];
        store
            .project(&super::tests::core(&g), &g.catalog_sha256, desired)
            .unwrap();
        let dir = store.directory().unwrap();
        let mut state = store.load(&dir).unwrap().unwrap();
        let identity = voboost_contract::domain_generation::GenerationIdentity {
            domain: Domain::Cluster,
            catalog_sha256: state.catalog_sha256.clone(),
            closure_sha256: state.closure_sha256.clone(),
            selection_sha256: "7".repeat(64),
        };
        let receipt:Receipt=serde_json::from_value(serde_json::json!({"schemaVersion":1,"kind":"observed","pairId":"1".repeat(64),"domain":"cluster","authorityEpoch":"2".repeat(64),"transactionId":"3".repeat(64),"catalogSha256":state.catalog_sha256,"closureSha256":state.closure_sha256,"selectionSha256":"7".repeat(64),"generationId":identity.generation_id().unwrap(),"desiredRevision":state.desired_revision,"desiredSha256":state.desired_sha256,"challenge":"4".repeat(64),"daemonEpoch":"5".repeat(64),"bootId":"current-qnx-boot","observationRevision":1,"agents":[{"id":"font-cyrillic","targetProcess":"gauge","state":"applied","reason":"actual-readback","process":{"pid":42,"birthIdentity":"8".repeat(64),"executableSha256":"9".repeat(64),"endpointEpoch":"a".repeat(64),"lifecycleGeneration":1}}]})).unwrap();
        let mut generation = receipt.clone();
        generation.kind = cluster::ReceiptKind::Generation;
        state.generation = Some(generation);
        state.observed = Some(receipt);
        state.observed_owner_epoch = Some(state.android_daemon_epoch.clone());
        state.delivery_state = DeliveryState::Idle;
        state
    }
    #[test]
    fn new_android_owner_requires_fresh_correlated_native_receipt() {
        let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let input = temp.path().join("input");
        super::tests::provision_input(&input);
        let store = Store::at(&temp.path().join("cluster"));
        store.import_provision(&input).unwrap();
        let dir = store.directory().unwrap();
        let mut original = fixture();
        original
            .expected_targets
            .get_mut("font-cyrillic")
            .unwrap()
            .truncate(1);
        let old_receipt = original.observed.as_ref().unwrap().clone();
        store.persist(&dir, &original).unwrap();
        assert_eq!(
            store.snapshot().unwrap().unwrap().agents[0].state,
            ObservedState::Applied
        );
        let restarted = Store {
            epoch: Some("e".repeat(64)),
            ..Store::at(&store.path)
        };
        let unavailable = restarted.snapshot().unwrap().unwrap();
        assert_eq!(unavailable.agents[0].state, ObservedState::WaitingProcess);
        assert!(unavailable.boot_id.is_none());
        assert!(unavailable.daemon_epoch.is_none());
        assert_eq!(unavailable.observation_revision, 0);
        let mut migrated = restarted.load(&dir).unwrap().unwrap();
        migrated.snapshot_revision = bump(migrated.snapshot_revision).unwrap();
        restarted.persist(&dir, &migrated).unwrap();
        assert_eq!(
            restarted.snapshot().unwrap().unwrap().observation_revision,
            0
        );
        let handoff = restarted
            .take(&"d".repeat(64), || panic!("observe has no artifacts"))
            .unwrap();
        let LocalResponse::Take {
            result:
                TakeResult::Ready {
                    lease_id,
                    transaction_id,
                    ..
                },
            ..
        } = handoff.response
        else {
            panic!("observe request unavailable")
        };
        let state = restarted.load(&dir).unwrap().unwrap();
        let pending = state.pending.as_ref().unwrap().request.clone();
        assert_eq!(pending.kind, RequestKind::Observe);
        assert_ne!(pending.challenge, old_receipt.challenge);
        let submit = |receipt: &Receipt| {
            let bytes = receipt.sign(&SigningKey::from_bytes(&[74; 32])).unwrap();
            dir.write_atomic("observe-test-receipt", &bytes, 0o600)
                .unwrap();
            let file = dir
                .open_trusted_file("observe-test-receipt", bytes.len() as u64, 0o600)
                .unwrap();
            let request = LocalRequest::Result {
                protocol_version: 1,
                request_id: "f".repeat(64),
                lease_id: lease_id.clone(),
                transaction_id: transaction_id.clone(),
                transport_outcome: TransportOutcome::Delivered,
                receipt: Some(BlobIdentity {
                    size: bytes.len() as u64,
                    sha256: hash(&bytes),
                }),
            };
            restarted.result(&request, Some(&file))
        };
        assert!(submit(&old_receipt).is_err());
        assert_eq!(
            restarted.snapshot().unwrap().unwrap().observation_revision,
            0
        );
        let mut fresh = old_receipt;
        fresh.transaction_id = pending.transaction_id;
        fresh.challenge = pending.challenge;
        fresh.desired_revision = pending.desired_revision.unwrap();
        fresh.desired_sha256 = pending.desired_sha256.unwrap();
        fresh.observation_revision += 1;
        submit(&fresh).unwrap();
        let current = restarted.snapshot().unwrap().unwrap();
        assert_eq!(current.boot_id.as_deref(), Some(fresh.boot_id.as_str()));
        assert_eq!(
            current.daemon_epoch.as_deref(),
            Some(fresh.daemon_epoch.as_str())
        );
        assert_eq!(current.observation_revision, fresh.observation_revision);
        assert_eq!(current.agents[0].state, ObservedState::Applied);
        assert_eq!(current.agents[0].process, fresh.agents[0].process);
    }

    #[test]
    fn first_owner_applied_does_not_mean_all_three_targets_applied() {
        let state = fixture();
        let snapshot = state.snapshot().unwrap();
        assert_ne!(
            snapshot.agents[0].state,
            ObservedState::Applied,
            "gauge alone cannot prove light and point"
        );
    }
    #[test]
    fn all_three_current_targets_applied_and_single_target_identity_preserved() {
        let mut state = fixture();
        let first = state.observed.as_ref().unwrap().agents[0].clone();
        state.observed.as_mut().unwrap().agents = ["gauge", "light", "point"]
            .into_iter()
            .enumerate()
            .map(|(i, name)| {
                let mut row = first.clone();
                row.target_process = name.into();
                let p = row.process.as_mut().unwrap();
                p.pid += i as u64;
                p.birth_identity = format!("{:064x}", p.pid);
                row
            })
            .collect();
        state.observed.as_ref().unwrap().validate().unwrap();
        let snapshot = state.snapshot().unwrap();
        assert_eq!(snapshot.agents[0].state, ObservedState::Applied);
        assert_eq!(snapshot.agents[0].targets.len(), 3);
        assert!(snapshot.agents[0].process.is_none());
        state
            .expected_targets
            .get_mut("font-cyrillic")
            .unwrap()
            .truncate(1);
        state.observed.as_mut().unwrap().agents.truncate(1);
        let snapshot = state.snapshot().unwrap();
        assert_eq!(snapshot.agents[0].state, ObservedState::Applied);
        assert_eq!(
            snapshot.agents[0].process,
            state.observed.as_ref().unwrap().agents[0].process
        );
    }
    #[test]
    fn stale_catalog_generation_desired_or_android_owner_never_publish_applied() {
        for change in 0..5 {
            let mut state = fixture();
            let row = state.observed.as_ref().unwrap().agents[0].clone();
            state
                .expected_targets
                .get_mut("font-cyrillic")
                .unwrap()
                .truncate(1);
            match change {
                0 => state.observed.as_mut().unwrap().catalog_sha256 = "a".repeat(64),
                1 => state.observed.as_mut().unwrap().generation_id = "b".repeat(64),
                2 => state.observed.as_mut().unwrap().desired_revision += 1,
                3 => state.observed.as_mut().unwrap().desired_sha256 = "c".repeat(64),
                _ => state.observed_owner_epoch = Some("d".repeat(64)),
            };
            let snapshot = state.snapshot().unwrap();
            assert_eq!(snapshot.agents[0].state, ObservedState::WaitingProcess);
            assert_ne!(snapshot.agents[0].process, row.process);
        }
    }
    #[test]
    fn foreign_targets_duplicate_rows_or_shared_pid_are_rejected() {
        let mut state = fixture();
        let receipt = state.observed.as_ref().unwrap().clone();
        let mut bad = receipt.clone();
        bad.agents[0].target_process = "other".into();
        assert!(bad.validate().is_err());
        assert!(state.validate_receipt_targets(&bad).is_err());
        let mut bad = receipt.clone();
        bad.agents.push(bad.agents[0].clone());
        assert!(bad.validate().is_err());
        let mut bad = receipt.clone();
        let mut other = bad.agents[0].clone();
        other.target_process = "light".into();
        bad.agents.push(other);
        assert!(
            bad.validate().is_err(),
            "one PID cannot witness different executables"
        );
        let mut bad = receipt;
        bad.agents[0].id = "foreign-agent".into();
        assert!(state.validate_receipt_targets(&bad).is_err());
        state
            .expected_targets
            .get_mut("font-cyrillic")
            .unwrap()
            .truncate(1);
        state.observed.as_mut().unwrap().agents[0]
            .process
            .as_mut()
            .unwrap()
            .pid = 0;
        assert!(state.validate().is_err());
    }
}

#[cfg(test)]
mod independent_android_removal_tests {
    use super::*;
    #[test]
    fn pending_cluster_requires_retention_but_integrity_failures_are_not_bypassed() {
        let retained = std::cell::Cell::new(0);
        retain_pending_cluster_before_android(Err(UNINSTALL_PENDING.into()), || {
            retained.set(retained.get() + 1);
            Ok(())
        })
        .unwrap();
        assert_eq!(retained.get(), 1);
        assert_eq!(
            retain_pending_cluster_before_android(Err(UNINSTALL_PENDING.into()), || Err(
                "snapshot failed".into()
            ))
            .unwrap_err(),
            "snapshot failed"
        );
        assert_eq!(
            retain_pending_cluster_before_android(Err("signature invalid".into()), || panic!(
                "integrity failure cannot authorize cleanup"
            ))
            .unwrap_err(),
            "signature invalid"
        );
        retain_pending_cluster_before_android(Ok(()), || panic!("completed QNX needs no snapshot"))
            .unwrap();
    }
}
