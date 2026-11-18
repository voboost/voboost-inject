//! Root-owned immutable agent generations.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
#[cfg(test)]
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};

use crate::catalog::{self, AgentCatalog};
use crate::operation_contract::{GenerationGuard, OperationLease};
use crate::secure_fs::Directory;
use crate::selection::{
    digest, generation_id, SelectionReceipt, VehicleProfileDocument, VerifiedSelection,
};

mod resources;

// The generation store layout is shared with the owner daemon, which reads the
// active catalog to expand a saved checkbox into its signed dependencies.
pub use crate::generation_layout::{
    ACTIVE_POINTER, CATALOG_FILE, CATALOG_SIGNATURE_FILE, GENERATIONS_DIR,
};
use crate::generation_layout::{GENERATION_DIR_MODE, GENERATION_FILE_MODE};
pub use voboost_contract::domain_core::install_layout::PREVIOUS as PREVIOUS_POINTER;
pub const AGENTS_SELECTED_FILE: &str = "agents-selected.json";
pub const VEHICLE_PROFILE_FILE: &str = "vehicle.json";
pub const READY_MARKER: &str = "ready";
pub const QUARANTINE_DIR: &str = rejection::QUARANTINE_DIR;
pub const NEXT_DIR: &str = "next";
pub const REJECTION_REASON_FILE: &str = rejection::REJECTION_REASON_FILE;
pub const ACKNOWLEDGEMENT_FILE: &str = "generation-ack.json";
const ACTIVATION_JOURNAL_FILE: &str = ".activation.json";
const ACTIVATION_NEXT_PLAN_FILE: &str = ".activation-agents.next";
const ACTIVATION_PREVIOUS_PLAN_FILE: &str = ".activation-agents.previous";
pub(crate) const PRODUCT_NEXT_PLAN_FILE: &str = "product-agents.next";
pub(crate) const PRODUCT_PREVIOUS_PLAN_FILE: &str = "product-agents.previous";

const ROOT_FILE_MODE: u32 = 0o600;

const fn production_generation_source_allowed(install_authorized: bool) -> bool {
    install_authorized
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PruneMutation {
    EnsureGenerations,
    EnsureQuarantine,
    RemoveQuarantine,
    RemoveNext,
    RetireRename,
    RetireDelete,
}

fn ensure_prune_directory<F>(
    guard: &GenerationGuard,
    before_mutation: &mut F,
    mutation: PruneMutation,
    path: &Path,
    mode: u32,
) -> Result<()>
where
    F: FnMut(PruneMutation, &Path) -> Result<()>,
{
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            ensure!(meta.file_type().is_dir(), "trusted path is not a directory");
            ensure!(
                meta.uid() == current_uid() && meta.gid() == current_gid(),
                "directory owner mismatch"
            );
            ensure!(
                meta.permissions().mode() & 0o022 == 0,
                "trusted directory is group/world writable"
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            authorize_prune_mutation(guard, before_mutation, mutation, path)?;
            fs::create_dir(path).with_context(|| format!("create {}", path.display()))?;
        }
        Err(error) => return Err(error.into()),
    }
    authorize_prune_mutation(guard, before_mutation, mutation, path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn authorize_prune_mutation<F>(
    guard: &GenerationGuard,
    before_mutation: &mut F,
    mutation: PruneMutation,
    path: &Path,
) -> Result<()>
where
    F: FnMut(PruneMutation, &Path) -> Result<()>,
{
    guard.verify_owner().map_err(anyhow::Error::msg)?;
    before_mutation(mutation, path)?;
    guard.verify_owner().map_err(anyhow::Error::msg)
}

mod operation_coordination;
mod rejection;

#[cfg(test)]
use rejection::{
    rejected_history_names_bounded, remove_tree_bounded_nofollow, snapshot_rejected_identity_with,
    validate_rejection_owner_production, RejectionJournal, RejectionPhase,
    MAX_REJECTION_CLEANUP_NODES, REJECTED_CATALOG_SNAPSHOT, REJECTED_SELECTION_SNAPSHOT,
};
use rejection::{ClaimPhase, REJECTING_DIR, REJECTION_JOURNAL_FILE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitialInstallPreparation {
    Busy,
    Idle,
    Staged,
}

#[derive(Debug, Clone)]
pub struct GenerationStore {
    log_identity: std::sync::Arc<std::sync::Mutex<(String, Option<String>)>>,
    observations: std::sync::Arc<std::sync::Mutex<crate::transition_log::Transitions>>,
    root: PathBuf,
    incoming: PathBuf,
    plan: PathBuf,
}

#[derive(Debug, Clone)]
pub struct VerifiedGeneration {
    pub id: String,
    pub catalog_sha256: String,
    pub selection_sha256: String,
    pub directory: PathBuf,
    pub catalog: AgentCatalog,
    pub selection: VerifiedSelection,
    pub files: Vec<GenerationFile>,
}

#[derive(Debug)]
pub struct RejectedIncoming {
    pub path: PathBuf,
    pub identity: Option<(String, Option<String>)>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GenerationFile {
    pub file: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerationDescription<'a> {
    pub schema_version: u32,
    pub generation_id: &'a str,
    pub catalog_sha256: &'a str,
    pub selection_sha256: &'a str,
    pub files: &'a [GenerationFile],
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GenerationAcknowledgement<'a> {
    schema_version: u32,
    status: &'a str,
    catalog_sha256: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    selection_sha256: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generation_id: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum ActivationState {
    Prepared,
    Activated,
    PlanPublished,
    Verified,
    Accepted,
    RolledBack,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ActivationJournal {
    schema_version: u32,
    state: ActivationState,
    previous_generation: Option<String>,
    next_generation: String,
    catalog_sha256: String,
    selection_sha256: String,
    staging_owner: StagingOwner,
    claim_phase: ClaimPhase,
    previous_plan_sha256: Option<String>,
    next_plan_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StagingOwner {
    uid: u32,
    gid: u32,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActivationCrashPoint {
    Prepared,
    PointerSwitched,
    Activated,
    PlanPublished,
    PlanJournaled,
    Verified,
    Accepted,
    Acknowledged,
    ReadyRemoved,
    ClaimOwned,
    ClaimOwnerChangedBeforeJournal,
    ClaimCatalog,
    ClaimSelection,
    ClaimAcknowledged,
    ClaimReadyRemoved,
    ClaimSnapshotsRemoved,
    ClaimOwnerRestored,
    ClaimOwnerRestoredBeforeJournal,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallAckFault {
    TempWrite,
    TempFsync,
    Rename,
    ParentFsync,
    ExactAck,
    Start,
    Started,
}

// Process-wide: recreating the store in every watcher poll must not reset this budget.
const INSTALL_START_LIMIT: u32 = 5;
#[derive(Default)]
struct InstallStartRetry {
    attempts: u32,
    next: Option<Instant>,
}

fn reserve_install_start(root: &Path, transaction: &str, now: Instant) -> Result<bool> {
    static RETRIES: OnceLock<Mutex<BTreeMap<PathBuf, (String, InstallStartRetry)>>> =
        OnceLock::new();
    let mut retries = RETRIES
        .get_or_init(Mutex::default)
        .lock()
        .map_err(|_| anyhow::anyhow!("install continuation retry state poisoned"))?;
    let (recorded, retry) = retries
        .entry(root.to_path_buf())
        .or_insert_with(|| (transaction.to_owned(), InstallStartRetry::default()));
    if recorded != transaction {
        *recorded = transaction.to_owned();
        *retry = InstallStartRetry::default();
    }
    if retry.attempts >= INSTALL_START_LIMIT || retry.next.is_some_and(|next| now < next) {
        return Ok(false);
    }
    retry.next = Some(now + Duration::from_secs(1 << retry.attempts));
    retry.attempts += 1;
    Ok(true)
}

fn install_service_running() -> Result<bool> {
    #[cfg(target_os = "android")]
    {
        unsafe extern "C" {
            fn __system_property_get(
                name: *const libc::c_char,
                value: *mut libc::c_char,
            ) -> libc::c_int;
        }
        let mut value = [0 as libc::c_char; 92];
        let length = unsafe {
            __system_property_get(c"init.svc.voboost-install".as_ptr(), value.as_mut_ptr())
        };
        ensure!(
            length > 0 && (length as usize) < value.len(),
            "install service state unavailable"
        );
        let state = unsafe { std::ffi::CStr::from_ptr(value.as_ptr()) }.to_str()?;
        match state {
            "running" | "restarting" => Ok(true),
            "stopped" => Ok(false),
            _ => bail!("unsupported install service state"),
        }
    }
    #[cfg(not(target_os = "android"))]
    {
        Ok(false)
    }
}

fn start_install_continuation() -> Result<()> {
    #[cfg(target_os = "android")]
    {
        use std::ffi::CString;
        unsafe extern "C" {
            fn __system_property_set(
                name: *const libc::c_char,
                value: *const libc::c_char,
            ) -> libc::c_int;
        }
        let name = CString::new("ctl.start")?;
        let value = CString::new("voboost-install")?;
        ensure!(
            unsafe { __system_property_set(name.as_ptr(), value.as_ptr()) } == 0,
            "ctl.start voboost-install failed"
        );
    }
    Ok(())
}

fn publish_install_ack_with<F>(
    recovery: &Directory,
    bytes: &[u8],
    fault: Option<InstallAckFault>,
    mut start_install: F,
) -> Result<()>
where
    F: FnMut() -> Result<()>,
{
    if fault == Some(InstallAckFault::TempWrite) {
        bail!("simulated generation acknowledgement temp write failure");
    }
    recovery
        .prepare_trusted(".generation-ack.tmp", bytes, ROOT_FILE_MODE)
        .context("prepare install generation acknowledgement")?;
    if fault == Some(InstallAckFault::TempFsync) {
        bail!("simulated crash after generation acknowledgement temp fsync");
    }
    if fault == Some(InstallAckFault::Rename) {
        bail!("simulated generation acknowledgement rename failure");
    }
    recovery
        .rename(".generation-ack.tmp", "generation-ack.json")
        .context("publish install generation acknowledgement")?;
    if fault == Some(InstallAckFault::ParentFsync) {
        bail!("simulated crash before generation acknowledgement parent fsync");
    }
    recovery
        .sync_all()
        .context("sync install generation acknowledgement parent")?;
    if fault == Some(InstallAckFault::ExactAck) {
        bail!("simulated crash after exact generation acknowledgement");
    }
    if fault == Some(InstallAckFault::Start) {
        bail!("simulated ctl.start voboost-install failure");
    }
    start_install()?;
    if fault == Some(InstallAckFault::Started) {
        bail!("simulated crash after ctl.start voboost-install");
    }
    Ok(())
}

impl GenerationStore {
    pub(crate) fn set_log_generation(&self, generation: &str) {
        let changed = if let Ok(mut identity) = self.log_identity.lock() {
            if identity.0 == generation {
                false
            } else {
                identity.0 = generation.into();
                true
            }
        } else {
            false
        };
        if changed {
            if let Ok(mut log) = self.observations.lock() {
                log.clear();
            }
        }
    }
    pub(crate) fn set_log_operation(&self, operation: Option<&str>) {
        let changed = if let Ok(mut identity) = self.log_identity.lock() {
            if identity.1.as_deref() == operation {
                false
            } else {
                identity.1 = operation.map(str::to_string);
                true
            }
        } else {
            false
        };
        if changed {
            if let Ok(mut log) = self.observations.lock() {
                log.clear();
            }
        }
    }
    fn log_context(&self) -> String {
        self.log_identity
            .lock()
            .map(|identity| {
                format!(
                    "generation={} operation={}",
                    identity.0,
                    identity.1.as_deref().unwrap_or("unobserved")
                )
            })
            .unwrap_or_else(|_| "unobserved".into())
    }
    pub(crate) fn observe_log_result<T>(&self, scope: &'static str, result: &Result<T>) {
        let identity = self.log_context();
        if let Ok(mut log) = self.observations.lock() {
            match result {
                Ok(_) => log.resolved(scope),
                Err(error) if error.to_string() == "operation busy" => {
                    log.waiting(scope, &identity, "operation busy")
                }
                Err(error) => log.failed(scope, &identity, &format!("{error:#}")),
            }
        }
    }
    pub(crate) fn observe_log_wait(&self, scope: &'static str, reason: &str) {
        let identity = self.log_context();
        if let Ok(mut log) = self.observations.lock() {
            log.waiting(scope, &identity, reason);
        }
    }
    pub(crate) fn observe_log_resolved(&self, scope: &'static str) {
        if let Ok(mut log) = self.observations.lock() {
            log.resolved(scope);
        }
    }

    pub fn production() -> Self {
        Self::new(crate::config::ROOT_ZONE, crate::config::INCOMING_DIR)
    }

    pub fn new(root: impl Into<PathBuf>, incoming: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            observations: Default::default(),
            log_identity: Default::default(),
            plan: root.join("agents.json"),
            root,
            incoming: incoming.into(),
        }
    }

    pub fn activate_incoming(&self) -> Result<VerifiedGeneration> {
        ensure!(
            !crate::uninstall::prepared_marker_valid(),
            "generation activation blocked by prepared uninstall"
        );
        ensure!(
            !self.activation_kill_switch_active(),
            "generation activation blocked by kill-switch"
        );
        self.activate_incoming_impl(None)
    }

    pub(crate) fn activation_kill_switch_active(&self) -> bool {
        if self.root.join("run/disable").exists() {
            return true;
        }
        self.active()
            .ok()
            .map(|generation| crate::plan::read_runtime_and_validate(&generation))
            .is_some_and(|plan| plan.valid && plan.disable_all)
    }

    /// Freeze the fixed generation staging marker after crash recovery and
    /// before uninstall authority can be published.
    pub fn freeze_for_uninstall(&self) -> Result<()> {
        self.ensure_layout()?;
        ensure!(
            self.read_activation_journal()?.is_none(),
            "generation activation journal remains during uninstall freeze"
        );
        let incoming = match Directory::open(&self.incoming) {
            Ok(dir) => dir,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        match incoming.unlink(READY_MARKER) {
            Ok(()) => incoming.sync_all()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        ensure!(
            matches!(
                incoming.read_untrusted(READY_MARKER, 0),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            ),
            "generation ready marker survived uninstall freeze"
        );
        Ok(())
    }

    fn activate_incoming_impl(
        &self,
        crash_point: Option<ActivationCrashPoint>,
    ) -> Result<VerifiedGeneration> {
        self.activate_incoming_impl_with_hook(crash_point, || Ok(()))
    }

    fn activate_incoming_impl_with_hook<F>(
        &self,
        crash_point: Option<ActivationCrashPoint>,
        after_first_validation: F,
    ) -> Result<VerifiedGeneration>
    where
        F: FnOnce() -> Result<()>,
    {
        let guard = self.acquire_generation_guard()?;
        guard.verify_owner().map_err(anyhow::Error::msg)?;
        #[cfg(not(test))]
        let install_context = {
            let install = self.install_generation_context()?;
            ensure!(
                production_generation_source_allowed(install.is_some()),
                "app-authored generation staging is disabled"
            );
            install
        };
        ensure!(
            !self.activation_kill_switch_active(),
            "generation activation blocked by kill-switch"
        );
        self.ensure_layout()?;
        if let Some(recovered) = self.recover_activation_guarded()? {
            return Ok(recovered);
        }
        let incoming = Directory::open(&self.incoming).context("open fixed incoming directory")?;
        let (incoming_uid, incoming_gid) = incoming.owner().context("incoming owner")?;
        #[cfg(not(test))]
        if install_context.is_none() {
            validate_staging_owner((incoming_uid, incoming_gid))?;
        } else {
            ensure!(
                (incoming_uid, incoming_gid) == (current_uid(), current_gid()),
                "initial generation staging is not daemon-owned"
            );
        }
        incoming
            .validate_owner_mode(incoming_uid, incoming_gid, 0o700)
            .context("incoming owner/mode")?;
        let marker = incoming
            .read_untrusted(READY_MARKER, 0)
            .context("ready marker missing or unsafe")?;
        ensure!(marker.is_empty(), "ready marker must be empty");

        // Authenticate and validate the catalog before opening any payload or
        // consulting the app-authored selection receipt.
        let catalog_bytes = incoming
            .read_untrusted(CATALOG_FILE, catalog::MAX_CATALOG_BYTES)
            .context("read catalog")?;
        let signature = incoming
            .read_untrusted(CATALOG_SIGNATURE_FILE, catalog::SIGNATURE_BYTES)
            .context("read catalog signature")?;
        let catalog = AgentCatalog::parse_verified(&catalog_bytes, &signature)?;
        let catalog_sha256 = AgentCatalog::digest(&catalog_bytes);

        // Root-owned facts are the only vehicle profile authority. The
        // app-authored receipt is untrusted and must match these exact facts.
        let root = Directory::open(&self.root).context("open root zone")?;
        let facts_bytes = root
            .read_trusted(
                VEHICLE_PROFILE_FILE,
                crate::selection::MAX_VEHICLE_PROFILE_BYTES,
                crate::profile::VEHICLE_PROFILE_MODE,
            )
            .context("root-owned vehicle.json missing; wait for daemon profile resolution")?;
        let facts = VehicleProfileDocument::parse_canonical(&facts_bytes)?;
        // Product release freshness is owned by signed voboost.json. The
        // independently signed catalog has no component version.
        let previous_generation = self.active().ok();
        match previous_generation.as_ref() {
            Some(_) => {}
            None => {
                // A pointer exists (active_id is Some) only when a generation
                // was activated before. If it now fails to load, the active
                // generation is corrupted — refuse rather than silently
                // dropping anti-rollback. First install has no pointer → None.
                ensure!(
                    self.active_id().is_none(),
                    "anti-rollback: active generation is corrupted; manual recovery required"
                );
            }
        }
        let selection_bytes = incoming
            .read_untrusted(AGENTS_SELECTED_FILE, crate::selection::MAX_SELECTION_BYTES)
            .context("read app-authored selection receipt")?;
        let selection =
            SelectionReceipt::verify(&selection_bytes, &catalog, &catalog_sha256, &facts.facts)?;
        let resource = resources::ResourceProduct::load(
            &incoming,
            None,
            &catalog,
            &catalog_bytes,
            &signature,
        )?;
        let id =
            resources::generation_identity(resource.as_ref(), &catalog_sha256, &selection.sha256)?;
        self.ensure_no_active_global_operation()?;

        let mut expected = expected_inventory(&catalog, &selection, &catalog_bytes, &signature)?;
        if let Some(resource) = &resource {
            resource.extend(&mut expected)?;
        }
        let mut allowed: BTreeSet<String> = expected.keys().cloned().collect();
        allowed.insert(READY_MARKER.to_string());
        validate_exact_directory_inventory(&self.incoming, &allowed)?;

        for expected_file in expected.values() {
            let bytes = incoming
                .read_untrusted(&expected_file.file, expected_file.size as usize)
                .with_context(|| format!("read staged {}", expected_file.file))?;
            ensure!(
                bytes.len() as u64 == expected_file.size && digest(&bytes) == expected_file.sha256,
                "staged file size or hash mismatch: {}",
                expected_file.file
            );
        }
        after_first_validation()?;

        // The app owns incoming/ and may replace a pathname after the first
        // validation. Re-open and authenticate a complete second snapshot,
        // then import only those exact in-memory bytes. Never copy from a
        // third, unchecked open of an untrusted pathname.
        validate_exact_directory_inventory(&self.incoming, &allowed)?;
        let mut authenticated = BTreeMap::new();
        for expected_file in expected.values() {
            let bytes = incoming
                .read_untrusted(&expected_file.file, expected_file.size as usize)
                .with_context(|| format!("re-read staged {}", expected_file.file))?;
            ensure!(
                bytes.len() as u64 == expected_file.size && digest(&bytes) == expected_file.sha256,
                "staged file changed after validation: {}",
                expected_file.file
            );
            authenticated.insert(expected_file.file.clone(), bytes);
        }

        let generation_dir = self.root.join(GENERATIONS_DIR).join(&id);
        if generation_dir.exists() {
            let verified = self.load_generation(&id)?;
            ensure!(
                verified.catalog_sha256 == catalog_sha256
                    && verified.selection_sha256 == selection.sha256,
                "existing generation identity collision"
            );
            return self.commit_activation(previous_generation.as_ref(), verified, crash_point);
        }

        let temp_name = format!("next-{id}");
        let generations_path = self.root.join(GENERATIONS_DIR);
        let temp_path = generations_path.join(&temp_name);
        fs::create_dir(&temp_path).context("create generation import directory")?;
        fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o700))?;
        let created = fs::symlink_metadata(&temp_path)?;
        let created_identity = (created.dev(), created.ino());
        let publication = (|| -> Result<VerifiedGeneration> {
            let temp = Directory::open(&temp_path)?;
            for expected_file in expected.values() {
                let bytes = authenticated
                    .get(&expected_file.file)
                    .context("authenticated generation snapshot is incomplete")?;
                temp.prepare_trusted(&expected_file.file, bytes, GENERATION_FILE_MODE)?;
            }
            temp.sync_all()?;
            fs::set_permissions(&temp_path, fs::Permissions::from_mode(GENERATION_DIR_MODE))?;

            let generations = Directory::open(&generations_path)?;
            generations.rename(&temp_name, &id)?;
            generations.sync_all()?;
            self.load_generation(&id)
        })();
        let imported = match publication {
            Ok(imported) => imported,
            Err(error) => {
                let cleanup_path = if temp_path.exists() {
                    &temp_path
                } else {
                    &generation_dir
                };
                cleanup_created_generation(cleanup_path, created_identity)
                    .context("clean failed generation import")?;
                return Err(error);
            }
        };
        self.commit_activation(previous_generation.as_ref(), imported, crash_point)
    }

    fn commit_activation(
        &self,
        previous: Option<&VerifiedGeneration>,
        next: VerifiedGeneration,
        crash_point: Option<ActivationCrashPoint>,
    ) -> Result<VerifiedGeneration> {
        let prepared = crate::plan::prepare_canonical_transition(previous, &next, &self.plan)
            .map_err(anyhow::Error::msg)?;
        let next_plan = crate::plan::validate(&next, &prepared.next_bytes);
        ensure!(next_plan.valid, "prepared canonical plan is invalid");
        crate::runtime::validate_generation_representability(&next, &next_plan)
            .map_err(anyhow::Error::msg)?;
        let generations = self.root.join(GENERATIONS_DIR);
        let generation_dir = Directory::open(&generations)?;
        generation_dir.write_atomic(
            ACTIVATION_NEXT_PLAN_FILE,
            &prepared.next_bytes,
            ROOT_FILE_MODE,
        )?;
        match prepared.previous_bytes.as_deref() {
            Some(bytes) => {
                generation_dir.write_atomic(ACTIVATION_PREVIOUS_PLAN_FILE, bytes, ROOT_FILE_MODE)?
            }
            None => match generation_dir.unlink(ACTIVATION_PREVIOUS_PLAN_FILE) {
                Ok(()) => generation_dir.sync_all()?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            },
        }
        let staging_owner = Directory::open(&self.incoming)?.owner()?;
        #[cfg(not(test))]
        if self.install_generation_context()?.is_none() {
            validate_staging_owner(staging_owner)?;
        } else {
            ensure!(
                staging_owner == (current_uid(), current_gid()),
                "initial generation staging is not daemon-owned"
            );
        }
        let journal = ActivationJournal {
            schema_version: 1,
            state: ActivationState::Prepared,
            previous_generation: previous.map(|generation| generation.id.clone()),
            next_generation: next.id.clone(),
            catalog_sha256: next.catalog_sha256.clone(),
            selection_sha256: next.selection_sha256.clone(),
            staging_owner: StagingOwner {
                uid: staging_owner.0,
                gid: staging_owner.1,
            },
            claim_phase: ClaimPhase::None,
            previous_plan_sha256: prepared
                .previous_bytes
                .as_deref()
                .map(crate::plan::canonical_identity),
            next_plan_sha256: crate::plan::canonical_identity(&prepared.next_bytes),
        };
        self.write_activation_journal(&journal)?;
        self.ensure_no_active_global_operation()?;
        if crash_point == Some(ActivationCrashPoint::Prepared) {
            bail!("simulated crash after prepared journal");
        }
        match self.finish_activation(journal.clone(), crash_point) {
            Ok(generation) => Ok(generation),
            Err(error) if crash_point.is_some() => Err(error),
            Err(error) => {
                if self
                    .read_activation_journal()?
                    .is_some_and(|durable| durable.state == ActivationState::Accepted)
                {
                    return Err(error.context("accepted activation cleanup deferred"));
                }
                self.rollback_activation(&journal)
                    .with_context(|| format!("activation failed ({error}); rollback failed"))?;
                Err(error)
            }
        }
    }

    /// Recover a root-owned activation transaction before accepting another
    /// app staging marker. Journal fields are identities only; every accessed
    /// path below is a daemon constant.
    pub fn recover_activation(&self) -> Result<Option<VerifiedGeneration>> {
        let guard = self.acquire_generation_guard()?;
        guard.verify_owner().map_err(anyhow::Error::msg)?;
        self.recover_activation_guarded()
    }

    fn recover_activation_guarded(&self) -> Result<Option<VerifiedGeneration>> {
        self.ensure_layout()?;
        let Some(journal) = self.read_activation_journal()? else {
            // generation cleanup — no global operation to complete
            return Ok(None);
        };
        self.ensure_no_active_global_operation()?;
        if journal.state == ActivationState::RolledBack {
            self.rollback_activation(&journal)?;
            return Ok(None);
        }
        match self.finish_activation(journal.clone(), None) {
            Ok(generation) => Ok(Some(generation)),
            Err(error) => {
                if self
                    .read_activation_journal()?
                    .is_some_and(|durable| durable.state == ActivationState::Accepted)
                {
                    return Err(error.context("accepted activation cleanup deferred"));
                }
                self.rollback_activation(&journal).with_context(|| {
                    format!("activation recovery failed ({error}); rollback failed")
                })?;
                Ok(None)
            }
        }
    }

    pub fn accepted_activation_pending_cleanup(&self) -> bool {
        self.read_activation_journal()
            .ok()
            .flatten()
            .is_some_and(|journal| journal.state == ActivationState::Accepted)
    }

    fn finish_activation(
        &self,
        mut journal: ActivationJournal,
        crash_point: Option<ActivationCrashPoint>,
    ) -> Result<VerifiedGeneration> {
        self.validate_activation_journal(&journal)?;
        let next = self.load_generation(&journal.next_generation)?;
        ensure!(
            next.catalog_sha256 == journal.catalog_sha256
                && next.selection_sha256 == journal.selection_sha256,
            "activation catalog/selection identity mismatch"
        );
        let active = self.active_id();
        if active.as_deref() != Some(journal.next_generation.as_str()) {
            ensure!(
                journal.state == ActivationState::Prepared
                    && active.as_deref() == journal.previous_generation.as_deref(),
                "activation pointer does not match journal"
            );
            self.activate_pointer(&journal.next_generation)?;
        }
        if crash_point == Some(ActivationCrashPoint::PointerSwitched) {
            bail!("simulated crash after pointer switch");
        }
        if journal.state == ActivationState::Prepared {
            journal.state = ActivationState::Activated;
            self.write_activation_journal(&journal)?;
        }
        if crash_point == Some(ActivationCrashPoint::Activated) {
            bail!("simulated crash after activated journal");
        }

        let generations = Directory::open(&self.root.join(GENERATIONS_DIR))?;
        let next_plan = generations.read_trusted(
            ACTIVATION_NEXT_PLAN_FILE,
            crate::config::MAX_PLAN_BYTES,
            ROOT_FILE_MODE,
        )?;
        ensure!(
            crate::plan::canonical_identity(&next_plan) == journal.next_plan_sha256,
            "prepared canonical plan identity mismatch"
        );
        let previous_plan = if journal.previous_generation.is_some() {
            Some(generations.read_trusted(
                ACTIVATION_PREVIOUS_PLAN_FILE,
                crate::config::MAX_PLAN_BYTES,
                ROOT_FILE_MODE,
            )?)
        } else {
            None
        };
        let publication =
            crate::plan::publish_prepared_canonical(&self.plan, &next, previous_plan, &next_plan)
                .map_err(anyhow::Error::msg)?;
        if crash_point == Some(ActivationCrashPoint::PlanPublished) {
            bail!("simulated crash after plan publication");
        }
        if journal.state != ActivationState::PlanPublished
            && journal.state != ActivationState::Verified
            && journal.state != ActivationState::Accepted
        {
            journal.state = ActivationState::PlanPublished;
            self.write_activation_journal(&journal)?;
        }
        if crash_point == Some(ActivationCrashPoint::PlanJournaled) {
            bail!("simulated crash after plan-published journal");
        }

        // The journal's exact proposed-default identity was verified above.
        // Mutable user fields instead require the owner's typed receipt,
        // exact stamp preservation, and the trusted-default semantic relation.
        crate::plan::verify_published_canonical(&self.plan, &next, &publication)
            .map_err(anyhow::Error::msg)?;
        if journal.state != ActivationState::Accepted {
            journal.state = ActivationState::Verified;
            self.write_activation_journal(&journal)?;
            if crash_point == Some(ActivationCrashPoint::Verified) {
                bail!("simulated crash after verified journal");
            }
            journal.state = ActivationState::Accepted;
            self.write_activation_journal(&journal)?;
            if crash_point == Some(ActivationCrashPoint::Accepted) {
                bail!("simulated crash after accepted journal");
            }
        }

        self.complete_install_generation_ack(&journal, &next)?;

        self.complete_matching_incoming("accepted", &mut journal, Some(&next.id), crash_point)?;
        if crash_point == Some(ActivationCrashPoint::Acknowledged) {
            bail!("simulated crash after activation acknowledgement");
        }
        if crash_point == Some(ActivationCrashPoint::ReadyRemoved) {
            bail!("simulated crash after ready removal");
        }
        self.clear_activation_transaction()?;
        // generation committed — no global operation to complete
        Ok(next)
    }

    fn complete_install_generation_ack(
        &self,
        journal: &ActivationJournal,
        generation: &VerifiedGeneration,
    ) -> Result<()> {
        let Some(install) = self.install_generation_context()? else {
            return Ok(());
        };
        ensure!(
            journal.state == ActivationState::Accepted,
            "install acknowledgement requires accepted activation"
        );
        ensure!(
            generation.id == journal.next_generation
                && generation.catalog_sha256 == install.catalog_sha256
                && generation.selection_sha256 == journal.selection_sha256,
            "install generation identity differs from frozen descriptor"
        );
        crate::installed_apk::observe_installed_apk(install.apk_size, &install.apk_sha256)
            .map_err(anyhow::Error::msg)?;
        let acknowledgement = crate::generation_contract::GenerationAcknowledgement {
            schema_version: 1,
            transaction_id: install.transaction_id.clone(),
            apk_sha256: install.apk_sha256,
            catalog_sha256: generation.catalog_sha256.clone(),
            selection_sha256: generation.selection_sha256.clone(),
            generation_sha256: generation.id.clone(),
        };
        acknowledgement.validate().map_err(anyhow::Error::msg)?;
        let mut bytes = serde_json::to_vec(&acknowledgement)?;
        bytes.push(b'\n');
        let recovery = Directory::open(&self.root.join("recovery").join(&install.transaction_id))?;
        publish_install_ack_with(&recovery, &bytes, None, || {
            crate::log::info(
                "main",
                &format!(
                    "install generation acknowledgement durable transaction={} generation={}; requesting continuation",
                    install.transaction_id, generation.id
                ),
            );
            start_install_continuation()
        })
    }

    fn rollback_activation(&self, journal: &ActivationJournal) -> Result<()> {
        // Code rollback owns a verified previous generation/default proposal,
        // not replacement or deletion of the sole user-authority document.
        let mut rolled_back = journal.clone();
        rolled_back.state = ActivationState::RolledBack;
        self.write_activation_journal(&rolled_back)?;
        if self.active_id().as_deref() == Some(journal.next_generation.as_str()) {
            if let Some(previous) = journal.previous_generation.as_deref() {
                self.activate_pointer(previous)?;
            } else {
                let generations = Directory::open(&self.root.join(GENERATIONS_DIR))?;
                generations.unlink(ACTIVE_POINTER)?;
                let _ = generations.unlink(PREVIOUS_POINTER);
                generations.sync_all()?;
            }
        }
        if let Some(expected) = journal.previous_plan_sha256.as_deref() {
            let generations = Directory::open(&self.root.join(GENERATIONS_DIR))?;
            let bytes = generations.read_trusted(
                ACTIVATION_PREVIOUS_PLAN_FILE,
                crate::config::MAX_PLAN_BYTES,
                ROOT_FILE_MODE,
            )?;
            ensure!(
                crate::plan::canonical_identity(&bytes) == expected,
                "previous canonical plan identity mismatch"
            );
            let previous = self.load_generation(
                journal
                    .previous_generation
                    .as_deref()
                    .context("rollback generation missing")?,
            )?;
            let publication =
                crate::plan::publish_prepared_canonical(&self.plan, &previous, None, &bytes)
                    .map_err(anyhow::Error::msg)?;
            crate::plan::verify_published_canonical(&self.plan, &previous, &publication)
                .map_err(anyhow::Error::msg)?;
        }
        self.complete_matching_incoming("rejected", &mut rolled_back, None, None)?;
        self.clear_activation_transaction()?;
        Ok(())
    }

    fn validate_activation_journal(&self, journal: &ActivationJournal) -> Result<()> {
        ensure!(
            journal.schema_version == 1,
            "activation journal schema mismatch"
        );
        ensure!(
            catalog::is_sha256(&journal.next_generation)
                && catalog::is_sha256(&journal.catalog_sha256)
                && catalog::is_sha256(&journal.selection_sha256)
                && catalog::is_sha256(&journal.next_plan_sha256),
            "activation journal next identity is invalid"
        );
        ensure!(
            journal
                .previous_generation
                .as_deref()
                .is_none_or(catalog::is_sha256)
                && journal
                    .previous_plan_sha256
                    .as_deref()
                    .is_none_or(catalog::is_sha256),
            "activation journal previous identity is invalid"
        );
        ensure!(
            journal.previous_generation.is_some() == journal.previous_plan_sha256.is_some(),
            "activation journal previous generation/plan mismatch"
        );
        Ok(())
    }

    fn read_activation_journal(&self) -> Result<Option<ActivationJournal>> {
        let generations = Directory::open(&self.root.join(GENERATIONS_DIR))?;
        let bytes = match generations.read_trusted(ACTIVATION_JOURNAL_FILE, 1024, ROOT_FILE_MODE) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let strict: crate::strict_json::StrictValue =
            serde_json::from_slice(&bytes).context("parse strict activation journal")?;
        strict
            .validate(crate::strict_json::ValueLimits {
                max_depth: 2,
                max_total_nodes: 16,
                max_object_properties: 10,
                max_array_items: 0,
                max_string_bytes: 64,
            })
            .map_err(anyhow::Error::msg)?;
        let journal: ActivationJournal =
            serde_json::from_value(strict.0).context("decode activation journal")?;
        self.validate_activation_journal(&journal)?;
        Ok(Some(journal))
    }

    fn write_activation_journal(&self, journal: &ActivationJournal) -> Result<()> {
        let mut bytes = serde_json::to_vec(journal)?;
        bytes.push(b'\n');
        Directory::open(&self.root.join(GENERATIONS_DIR))?.write_atomic(
            ACTIVATION_JOURNAL_FILE,
            &bytes,
            ROOT_FILE_MODE,
        )?;
        Ok(())
    }

    fn clear_activation_transaction(&self) -> Result<()> {
        let generations = Directory::open(&self.root.join(GENERATIONS_DIR))?;
        for name in [
            ACTIVATION_NEXT_PLAN_FILE,
            ACTIVATION_PREVIOUS_PLAN_FILE,
            ACTIVATION_JOURNAL_FILE,
        ] {
            match generations.unlink(name) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        generations.sync_all()?;
        Ok(())
    }

    /// The `ready` completion marker path inside this store's
    /// incoming directory.
    pub fn incoming_marker(&self) -> PathBuf {
        self.incoming.join(READY_MARKER)
    }

    /// Cheap discovery only. Full authority verification still runs before use.
    pub(crate) fn incoming_work_present(&self) -> bool {
        [
            self.incoming_marker(),
            self.root
                .join(GENERATIONS_DIR)
                .join(rejection::REJECTION_JOURNAL_FILE),
            self.root
                .join(GENERATIONS_DIR)
                .join(ACTIVATION_JOURNAL_FILE),
        ]
        .iter()
        .any(|path| fs::symlink_metadata(path).is_ok())
            || Directory::open(&self.root)
                .and_then(|root| root.read_trusted("operation.json", 4096, ROOT_FILE_MODE))
                .ok()
                .and_then(|bytes| {
                    crate::operation_contract::OperationDescriptor::parse(&bytes).ok()
                })
                .is_some_and(|operation| {
                    operation.operation == crate::operation_contract::Operation::Install
                        && operation.outcome != "complete"
                        && operation.outcome != "failed"
                })
    }

    /// Build the first generation from the root-owned frozen product closure.
    /// The app supplies no receipt and owns none of this staging authority.
    pub fn prepare_initial_install(&self) -> Result<InitialInstallPreparation> {
        self.prepare_initial_install_with_start(start_install_continuation)
    }

    fn prepare_initial_install_with_start<F>(
        &self,
        start_install: F,
    ) -> Result<InitialInstallPreparation>
    where
        F: FnMut() -> Result<()>,
    {
        self.prepare_initial_install_with_retry(
            start_install,
            install_service_running,
            Instant::now(),
        )
    }

    fn prepare_initial_install_with_retry<F, S>(
        &self,
        mut start_install: F,
        service_running: S,
        now: Instant,
    ) -> Result<InitialInstallPreparation>
    where
        F: FnMut() -> Result<()>,
        S: FnOnce() -> Result<bool>,
    {
        let observer = match crate::operation_contract::observe_current_in(&self.root)
            .map_err(anyhow::Error::msg)?
        {
            crate::operation_contract::CurrentOperationObservation::Busy => {
                return Ok(InitialInstallPreparation::Busy)
            }
            crate::operation_contract::CurrentOperationObservation::Snapshot(snapshot) => snapshot,
        };
        if observer.descriptor().is_none() {
            return Ok(InitialInstallPreparation::Idle);
        }
        if observer.descriptor().is_some_and(|value| {
            value.operation == crate::operation_contract::Operation::Install
                && value.outcome == "failed"
        }) {
            return Ok(InitialInstallPreparation::Idle);
        }
        let Some(install) = self.install_generation_context()? else {
            return Ok(InitialInstallPreparation::Idle);
        };
        let recovery = Directory::open(&self.root.join("recovery").join(&install.transaction_id))?;
        match recovery.read_trusted(
            ACKNOWLEDGEMENT_FILE,
            crate::generation_contract::MAX_GENERATION_ACK_BYTES,
            ROOT_FILE_MODE,
        ) {
            Ok(bytes) => {
                let acknowledgement =
                    crate::generation_contract::GenerationAcknowledgement::parse(&bytes)
                        .map_err(anyhow::Error::msg)?;
                ensure!(
                    acknowledgement.transaction_id == install.transaction_id
                        && acknowledgement.apk_sha256 == install.apk_sha256
                        && acknowledgement.catalog_sha256 == install.catalog_sha256,
                    "install generation acknowledgement differs from install authority"
                );
                let active = self.active()?;
                ensure!(
                    active.id == acknowledgement.generation_sha256
                        && active.catalog_sha256 == acknowledgement.catalog_sha256
                        && active.selection_sha256 == acknowledgement.selection_sha256,
                    "install generation acknowledgement differs from active generation"
                );
                observer.verify_owner().map_err(anyhow::Error::msg)?;
                drop(observer);
                if service_running()?
                    || !reserve_install_start(&self.root, &install.transaction_id, now)?
                {
                    return Ok(InitialInstallPreparation::Idle);
                }
                crate::log::debug(
                    "main",
                    &format!(
                        "validated install generation acknowledgement retry transaction={} generation={}",
                        install.transaction_id, acknowledgement.generation_sha256
                    ),
                );
                start_install().context("retry validated install generation continuation")?;
                return Ok(InitialInstallPreparation::Idle);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        self.ensure_layout()?;
        let frozen_path = self
            .root
            .join("recovery")
            .join(&install.transaction_id)
            .join("frozen");
        let frozen = Directory::open(&frozen_path).context("open frozen product closure")?;
        frozen
            .validate_owner_mode(current_uid(), current_gid(), 0o700)
            .context("frozen product closure owner/mode")?;
        let manifest_bytes = frozen.read_trusted(
            voboost_contract::release::MANIFEST_NAME,
            voboost_contract::release::MAX_MANIFEST_BYTES,
            ROOT_FILE_MODE,
        )?;
        let manifest_signature = frozen.read_trusted(
            voboost_contract::release::MANIFEST_SIGNATURE_NAME,
            64,
            ROOT_FILE_MODE,
        )?;
        let manifest = voboost_contract::release::verify_manifest_signature(
            &manifest_bytes,
            &manifest_signature,
            &crate::trust::release_catalog_public_key(),
        )
        .map_err(anyhow::Error::msg)?;
        ensure!(
            manifest.digest().map_err(anyhow::Error::msg)?
                == crate::trust::sha256_bytes(&manifest_bytes),
            "frozen product manifest digest differs"
        );
        let catalog_bytes =
            frozen.read_trusted(CATALOG_FILE, catalog::MAX_CATALOG_BYTES, ROOT_FILE_MODE)?;
        let signature = frozen.read_trusted(
            CATALOG_SIGNATURE_FILE,
            catalog::SIGNATURE_BYTES,
            ROOT_FILE_MODE,
        )?;
        let catalog = AgentCatalog::parse_verified(&catalog_bytes, &signature)?;
        let catalog_sha256 = AgentCatalog::digest(&catalog_bytes);
        ensure!(
            catalog_sha256 == install.catalog_sha256,
            "frozen catalog differs from product manifest"
        );
        correlate_product_generation(&manifest, &catalog)?;
        let root = Directory::open(&self.root)?;
        let facts_bytes = root
            .read_trusted(
                VEHICLE_PROFILE_FILE,
                crate::selection::MAX_VEHICLE_PROFILE_BYTES,
                crate::profile::VEHICLE_PROFILE_MODE,
            )
            .context("read root-owned vehicle.json for initial generation")?;
        let facts = VehicleProfileDocument::parse_canonical(&facts_bytes)?;
        let selection = SelectionReceipt::compute(&catalog, &catalog_sha256, &facts.facts)?;
        let resource = resources::ResourceProduct::verified(
            manifest,
            manifest_bytes,
            manifest_signature,
            &catalog,
            &catalog_bytes,
            &signature,
        )?;
        let mut expected = expected_inventory(&catalog, &selection, &catalog_bytes, &signature)?;
        if let Some(resource) = &resource {
            resource.extend(&mut expected)?;
        }

        if !self.incoming.exists() {
            fs::create_dir(&self.incoming).context("create root initial generation staging")?;
            fs::set_permissions(&self.incoming, fs::Permissions::from_mode(0o700))?;
            Directory::open(
                self.incoming
                    .parent()
                    .context("initial staging parent absent")?,
            )?
            .sync_all()?;
        }
        let incoming = Directory::open(&self.incoming)?;
        incoming
            .validate_owner_mode(current_uid(), current_gid(), 0o700)
            .context("root initial generation staging owner/mode")?;
        let mut allowed = expected.keys().cloned().collect::<BTreeSet<_>>();
        allowed.insert(READY_MARKER.to_string());
        let actual = incoming.entry_names_bounded(allowed.len())?;
        ensure!(
            actual.iter().all(|name| allowed.contains(name)),
            "root initial generation staging contains a foreign member"
        );
        for expected_file in expected.values() {
            let bytes = if expected_file.file == AGENTS_SELECTED_FILE {
                selection.exact_bytes.as_slice()
            } else {
                let source = frozen.read_trusted(
                    &expected_file.file,
                    expected_file.size as usize,
                    ROOT_FILE_MODE,
                )?;
                ensure!(
                    source.len() as u64 == expected_file.size
                        && digest(&source) == expected_file.sha256,
                    "frozen generation member differs: {}",
                    expected_file.file
                );
                incoming.prepare_trusted(&expected_file.file, &source, ROOT_FILE_MODE)?;
                continue;
            };
            incoming.prepare_trusted(&expected_file.file, bytes, ROOT_FILE_MODE)?;
        }
        match incoming.read_trusted(READY_MARKER, 0, ROOT_FILE_MODE) {
            Ok(bytes) => ensure!(bytes.is_empty(), "initial ready marker is not empty"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                incoming.prepare_trusted(READY_MARKER, b"", ROOT_FILE_MODE)?
            }
            Err(error) => return Err(error.into()),
        }
        incoming.sync_all()?;
        observer.verify_owner().map_err(anyhow::Error::msg)?;
        Ok(InitialInstallPreparation::Staged)
    }

    /// Materialize an immutable generation from a daemon-owned complete
    /// product candidate. The caller owns the global update lease; this method
    /// prepares bytes only and never changes the active pointer or plan.
    pub(crate) fn prepare_product_candidate(
        &self,
        complete_path: &Path,
        recovery: &Directory,
        lease: &OperationLease,
    ) -> Result<VerifiedGeneration> {
        lease.verify_owner().map_err(anyhow::Error::msg)?;
        self.ensure_layout()?;
        let complete = Directory::open(complete_path).context("open complete product candidate")?;
        complete
            .validate_owner_mode(current_uid(), current_gid(), 0o700)
            .context("complete product candidate owner/mode")?;
        let manifest_bytes = complete.read_trusted(
            voboost_contract::release::MANIFEST_NAME,
            voboost_contract::release::MAX_MANIFEST_BYTES,
            ROOT_FILE_MODE,
        )?;
        let manifest_signature = complete.read_trusted(
            voboost_contract::release::MANIFEST_SIGNATURE_NAME,
            64,
            ROOT_FILE_MODE,
        )?;
        let manifest = voboost_contract::release::verify_manifest_signature(
            &manifest_bytes,
            &manifest_signature,
            &crate::trust::release_catalog_public_key(),
        )
        .map_err(anyhow::Error::msg)?;
        let catalog_bytes =
            complete.read_trusted(CATALOG_FILE, catalog::MAX_CATALOG_BYTES, ROOT_FILE_MODE)?;
        let signature = complete.read_trusted(
            CATALOG_SIGNATURE_FILE,
            catalog::SIGNATURE_BYTES,
            ROOT_FILE_MODE,
        )?;
        let catalog = AgentCatalog::parse_verified(&catalog_bytes, &signature)?;
        correlate_product_generation(&manifest, &catalog)?;
        let catalog_sha256 = AgentCatalog::digest(&catalog_bytes);
        let root = Directory::open(&self.root)?;
        let facts_bytes = root.read_trusted(
            VEHICLE_PROFILE_FILE,
            crate::selection::MAX_VEHICLE_PROFILE_BYTES,
            crate::profile::VEHICLE_PROFILE_MODE,
        )?;
        let facts = VehicleProfileDocument::parse_canonical(&facts_bytes)?;
        let selection = SelectionReceipt::compute(&catalog, &catalog_sha256, &facts.facts)?;
        let resource = resources::ResourceProduct::verified(
            manifest,
            manifest_bytes,
            manifest_signature,
            &catalog,
            &catalog_bytes,
            &signature,
        )?;
        let id =
            resources::generation_identity(resource.as_ref(), &catalog_sha256, &selection.sha256)?;
        let mut expected = expected_inventory(&catalog, &selection, &catalog_bytes, &signature)?;
        if let Some(resource) = &resource {
            resource.extend(&mut expected)?;
        }

        let generation_path = self.root.join(GENERATIONS_DIR).join(&id);
        let next = if generation_path.exists() {
            self.load_generation(&id)?
        } else {
            let temporary_name = format!("next-{id}");
            let generations_path = self.root.join(GENERATIONS_DIR);
            let temporary_path = generations_path.join(&temporary_name);
            fs::set_permissions(&generations_path, fs::Permissions::from_mode(0o700))
                .context("open product generation store mutation window")?;
            let publication = (|| -> Result<VerifiedGeneration> {
                fs::create_dir(&temporary_path).context("create product generation directory")?;
                fs::set_permissions(&temporary_path, fs::Permissions::from_mode(0o700))?;
                let temporary = Directory::open(&temporary_path)?;
                for expected_file in expected.values() {
                    lease.verify_owner().map_err(anyhow::Error::msg)?;
                    if expected_file.file == AGENTS_SELECTED_FILE {
                        temporary.prepare_trusted(
                            &expected_file.file,
                            &selection.exact_bytes,
                            GENERATION_FILE_MODE,
                        )?;
                        continue;
                    }
                    let source = complete.open_trusted_file(
                        &expected_file.file,
                        expected_file.size,
                        ROOT_FILE_MODE,
                    )?;
                    temporary
                        .write_atomic_from_descriptor(
                            &expected_file.file,
                            std::os::fd::AsRawFd::as_raw_fd(&source),
                            expected_file.size,
                            &expected_file.sha256,
                            GENERATION_FILE_MODE,
                        )
                        .with_context(|| {
                            format!("copy product generation member {}", expected_file.file)
                        })?;
                }
                temporary.sync_all()?;
                lease.verify_owner().map_err(anyhow::Error::msg)?;
                let generations = Directory::open(&generations_path)?;
                generations
                    .rename(&temporary_name, &id)
                    .context("publish immutable product generation")?;
                fs::set_permissions(
                    &generation_path,
                    fs::Permissions::from_mode(GENERATION_DIR_MODE),
                )?;
                generations.sync_all()?;
                self.load_generation(&id)
            })();
            if publication.is_err() {
                for cleanup in [&temporary_path, &generation_path] {
                    if let Ok(metadata) = fs::symlink_metadata(cleanup) {
                        cleanup_created_generation(cleanup, (metadata.dev(), metadata.ino()))
                            .context("clean failed product generation")?;
                    }
                }
            }
            fs::set_permissions(&generations_path, fs::Permissions::from_mode(0o711))
                .context("close product generation store mutation window")?;
            publication?
        };
        let previous = self.active()?;
        let prepared =
            crate::plan::prepare_canonical_transition(Some(&previous), &next, &self.plan)
                .map_err(anyhow::Error::msg)?;
        ensure!(
            crate::plan::validate(&next, &prepared.next_bytes).valid,
            "prepared product generation plan is invalid"
        );
        crate::runtime::validate_generation_representability(
            &next,
            &crate::plan::validate(&next, &prepared.next_bytes),
        )
        .map_err(anyhow::Error::msg)?;
        recovery.write_atomic(PRODUCT_NEXT_PLAN_FILE, &prepared.next_bytes, ROOT_FILE_MODE)?;
        let previous_bytes = prepared
            .previous_bytes
            .context("active generation lacks a rollback plan")?;
        recovery.write_atomic(PRODUCT_PREVIOUS_PLAN_FILE, &previous_bytes, ROOT_FILE_MODE)?;
        recovery.sync_all()?;
        lease.verify_owner().map_err(anyhow::Error::msg)?;
        Ok(next)
    }

    pub(crate) fn switch_product_candidate(
        &self,
        next_id: &str,
        recovery: &Directory,
        lease: &OperationLease,
    ) -> Result<VerifiedGeneration> {
        lease.verify_owner().map_err(anyhow::Error::msg)?;
        let next = self.load_generation(next_id)?;
        let next_plan = recovery.read_trusted(
            PRODUCT_NEXT_PLAN_FILE,
            crate::config::MAX_PLAN_BYTES,
            ROOT_FILE_MODE,
        )?;
        ensure!(
            crate::plan::validate(&next, &next_plan).valid,
            "candidate generation plan verification failed"
        );
        if self.active_id().as_deref() != Some(next_id) {
            let generations = self.root.join(GENERATIONS_DIR);
            fs::set_permissions(&generations, fs::Permissions::from_mode(0o700))?;
            let switched = self.activate_pointer(next_id);
            fs::set_permissions(&generations, fs::Permissions::from_mode(0o711))?;
            switched?;
        }
        lease.verify_owner().map_err(anyhow::Error::msg)?;
        let previous_plan = recovery.read_trusted(
            PRODUCT_PREVIOUS_PLAN_FILE,
            crate::config::MAX_PLAN_BYTES,
            ROOT_FILE_MODE,
        )?;
        let publication = crate::plan::publish_prepared_canonical(
            &self.plan,
            &next,
            Some(previous_plan),
            &next_plan,
        )
        .map_err(anyhow::Error::msg)?;
        crate::plan::verify_published_canonical(&self.plan, &next, &publication)
            .map_err(anyhow::Error::msg)?;
        lease.verify_owner().map_err(anyhow::Error::msg)?;
        Ok(next)
    }

    pub(crate) fn rollback_product_candidate(
        &self,
        previous_id: &str,
        recovery: &Directory,
        lease: &OperationLease,
    ) -> Result<VerifiedGeneration> {
        lease.verify_owner().map_err(anyhow::Error::msg)?;
        let previous = self.load_generation(previous_id)?;
        if self.active_id().as_deref() != Some(previous_id) {
            let generations = self.root.join(GENERATIONS_DIR);
            fs::set_permissions(&generations, fs::Permissions::from_mode(0o700))?;
            let switched = self.activate_pointer(previous_id);
            fs::set_permissions(&generations, fs::Permissions::from_mode(0o711))?;
            switched?;
        }
        let previous_plan = recovery.read_trusted(
            PRODUCT_PREVIOUS_PLAN_FILE,
            crate::config::MAX_PLAN_BYTES,
            ROOT_FILE_MODE,
        )?;
        let next_plan = recovery.read_trusted(
            PRODUCT_NEXT_PLAN_FILE,
            crate::config::MAX_PLAN_BYTES,
            ROOT_FILE_MODE,
        )?;
        let publication = crate::plan::publish_prepared_canonical(
            &self.plan,
            &previous,
            Some(next_plan),
            &previous_plan,
        )
        .map_err(anyhow::Error::msg)?;
        crate::plan::verify_published_canonical(&self.plan, &previous, &publication)
            .map_err(anyhow::Error::msg)?;
        lease.verify_owner().map_err(anyhow::Error::msg)?;
        Ok(previous)
    }

    /// Best-effort identity of the transaction currently offered by the app.
    /// This does not authenticate or accept the catalog; it is used only to
    /// correlate a rejection acknowledgement after the directory is moved to
    /// quarantine.
    pub fn incoming_catalog_sha256(&self) -> Option<String> {
        let incoming = Directory::open(&self.incoming).ok()?;
        let bytes = incoming
            .read_untrusted(CATALOG_FILE, catalog::MAX_CATALOG_BYTES)
            .ok()?;
        Some(AgentCatalog::digest(&bytes))
    }

    pub fn incoming_generation_identity(&self) -> Option<(String, String)> {
        let incoming = Directory::open(&self.incoming).ok()?;
        read_incoming_identity(&incoming)
    }

    /// Publish daemon-owned completion of a generation transaction. The file
    /// lives in the freshly consumed/recreated incoming directory so the app
    /// can correlate it with its staged catalog. It is never an authority for
    /// daemon activation; the signed catalog and root-owned generation remain
    /// the authority.
    pub fn acknowledge_accepted(&self, generation: &VerifiedGeneration) -> Result<()> {
        let guard = self.acquire_generation_guard()?;
        guard.verify_owner().map_err(anyhow::Error::msg)?;
        self.write_acknowledgement(
            "accepted",
            &generation.catalog_sha256,
            Some(&generation.selection_sha256),
            Some(&generation.id),
        )
    }

    pub fn acknowledge_rejected(
        &self,
        catalog_sha256: &str,
        selection_sha256: Option<&str>,
    ) -> Result<()> {
        let guard = self.acquire_generation_guard()?;
        guard.verify_owner().map_err(anyhow::Error::msg)?;
        self.write_acknowledgement("rejected", catalog_sha256, selection_sha256, None)
    }

    fn write_acknowledgement(
        &self,
        status: &str,
        catalog_sha256: &str,
        selection_sha256: Option<&str>,
        generation_id: Option<&str>,
    ) -> Result<()> {
        ensure!(
            matches!(status, "accepted" | "rejected"),
            "invalid generation acknowledgement status"
        );
        ensure!(
            catalog_sha256.len() == 64
                && catalog_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "invalid generation acknowledgement catalog digest"
        );
        ensure!(
            selection_sha256.is_none_or(catalog::is_sha256),
            "invalid generation acknowledgement selection digest"
        );
        ensure!(
            (status == "accepted" && selection_sha256.is_some() && generation_id.is_some())
                || (status == "rejected" && generation_id.is_none()),
            "generation acknowledgement fields do not match status"
        );
        let incoming = Directory::open(&self.incoming).context("open acknowledgement directory")?;
        self.write_acknowledgement_to(
            &incoming,
            status,
            catalog_sha256,
            selection_sha256,
            generation_id,
        )
    }

    fn write_acknowledgement_to(
        &self,
        incoming: &Directory,
        status: &str,
        catalog_sha256: &str,
        selection_sha256: Option<&str>,
        generation_id: Option<&str>,
    ) -> Result<()> {
        let acknowledgement = GenerationAcknowledgement {
            schema_version: 1,
            status,
            catalog_sha256,
            selection_sha256,
            generation_id,
        };
        let mut bytes = serde_json::to_vec(&acknowledgement)?;
        bytes.push(b'\n');
        incoming
            .prepare_trusted(".generation-ack.tmp", &bytes, 0o644)
            .context("prepare generation acknowledgement")?;
        incoming
            .rename(".generation-ack.tmp", ACKNOWLEDGEMENT_FILE)
            .context("publish generation acknowledgement")?;
        incoming
            .sync_all()
            .context("sync generation acknowledgement")?;
        Ok(())
    }

    pub fn active(&self) -> Result<VerifiedGeneration> {
        let id = self.read_pointer(ACTIVE_POINTER)?;
        self.load_generation(&id)
    }

    /// Re-open and verify one immutable resident generation named by a
    /// target-originated rebind identity. The fixed generations directory and
    /// strict digest-shaped id prevent identity-controlled path traversal.
    pub fn resident(&self, id: &str) -> Result<VerifiedGeneration> {
        ensure!(catalog::is_sha256(id), "resident generation id is invalid");
        self.load_generation(id)
    }

    /// Verify every immutable generation still retained in the root store.
    /// Discovery/GC must use this complete set rather than only current and
    /// previous: a passive resident can outlive multiple catalog cutovers.
    pub fn retained_generations(&self) -> Result<Vec<VerifiedGeneration>> {
        self.ensure_layout()?;
        let generations = self.root.join(GENERATIONS_DIR);
        let mut retained = Vec::new();
        for entry in fs::read_dir(&generations).context("list retained generations")? {
            let entry = entry.context("read retained generation entry")?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if catalog::is_sha256(&name) {
                ensure!(
                    entry.file_type()?.is_dir(),
                    "retained generation is not a directory"
                );
                retained.push(
                    self.load_generation(&name)
                        .with_context(|| format!("verify retained generation {name}"))?,
                );
                continue;
            }
            let allowed_file = matches!(
                name.as_str(),
                ACTIVE_POINTER
                    | PREVIOUS_POINTER
                    | ACTIVATION_JOURNAL_FILE
                    | ACTIVATION_NEXT_PLAN_FILE
                    | ACTIVATION_PREVIOUS_PLAN_FILE
                    | REJECTION_JOURNAL_FILE
            );
            let allowed_directory = name == NEXT_DIR
                || name == QUARANTINE_DIR
                || name == REJECTING_DIR
                || name.strip_prefix("next-").is_some_and(catalog::is_sha256);
            ensure!(
                allowed_file || allowed_directory,
                "unexpected retained generation-store entry {name}"
            );
        }
        retained.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(retained)
    }

    /// The currently active generation id, or `None` when no generation has
    /// ever been activated (first install).
    pub fn active_id(&self) -> Option<String> {
        self.read_pointer(ACTIVE_POINTER).ok()
    }

    pub fn rollback(&self) -> Result<VerifiedGeneration> {
        let guard = self.acquire_generation_guard()?;
        guard.verify_owner().map_err(anyhow::Error::msg)?;
        let previous = self.read_pointer(PREVIOUS_POINTER)?;
        self.load_generation(&previous)?;
        self.activate_pointer(&previous)?;
        self.load_generation(&previous)
    }

    pub fn describe_active(&self) -> Result<String> {
        self.active()?.description_json()
    }

    /// Remove immutable generations that cannot be reached by rollback or a
    /// live resident. Rename into a root-only quarantine first, then delete;
    /// a crash can only leave harmless quarantine content retried next pass.
    pub fn prune(&self, resident_ids: &BTreeSet<String>) -> Result<Vec<String>> {
        self.prune_with_hook(resident_ids, |_, _| Ok(()))
    }

    fn prune_with_hook<F>(
        &self,
        resident_ids: &BTreeSet<String>,
        mut before_mutation: F,
    ) -> Result<Vec<String>>
    where
        F: FnMut(PruneMutation, &Path) -> Result<()>,
    {
        let guard = self.acquire_generation_guard()?;
        let generations = self.root.join(GENERATIONS_DIR);
        ensure_prune_directory(
            &guard,
            &mut before_mutation,
            PruneMutation::EnsureGenerations,
            &generations,
            0o711,
        )?;
        let mut keep = resident_ids.clone();
        if let Ok(id) = self.read_pointer(ACTIVE_POINTER) {
            keep.insert(id);
        }
        if let Ok(id) = self.read_pointer(PREVIOUS_POINTER) {
            keep.insert(id);
        }
        let quarantine = generations.join(QUARANTINE_DIR);
        ensure_prune_directory(
            &guard,
            &mut before_mutation,
            PruneMutation::EnsureQuarantine,
            &quarantine,
            0o700,
        )?;
        for entry in fs::read_dir(&quarantine)? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with("retired-")
                && entry.file_type()?.is_dir()
            {
                authorize_prune_mutation(
                    &guard,
                    &mut before_mutation,
                    PruneMutation::RemoveQuarantine,
                    &entry.path(),
                )?;
                fs::remove_dir_all(entry.path())?;
            }
        }
        let mut removed = Vec::new();
        for entry in fs::read_dir(&generations)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(id) = name.strip_prefix("next-") {
                if catalog::is_sha256(id) && entry.file_type()?.is_dir() {
                    authorize_prune_mutation(
                        &guard,
                        &mut before_mutation,
                        PruneMutation::RemoveNext,
                        &entry.path(),
                    )?;
                    fs::remove_dir_all(entry.path())?;
                }
                continue;
            }
            if name == NEXT_DIR
                || name == QUARANTINE_DIR
                || !catalog::is_sha256(&name)
                || keep.contains(&name)
            {
                continue;
            }
            ensure!(
                entry.file_type()?.is_dir(),
                "generation GC candidate is not a directory"
            );
            // Grace period: a resident process may run from this generation
            // while its status file is missing/corrupted (so
            // resident_generation_id returned None and the id is not in
            // `keep`). If the generation was activated recently, a resident
            // could still be mmap-ing its DEX. Skip removal for any directory
            // whose mtime is younger than the grace window; prune will retry
            // on a later pass once the resident has exited or recovered.
            const PRUNE_GRACE: Duration = Duration::from_secs(24 * 60 * 60);
            match entry.metadata().and_then(|m| m.modified()) {
                Ok(mtime)
                    if SystemTime::now()
                        .duration_since(mtime)
                        .map(|age| age < PRUNE_GRACE)
                        .unwrap_or(false) =>
                {
                    continue;
                }
                _ => {}
            }
            let target = quarantine.join(format!("retired-{name}"));
            authorize_prune_mutation(
                &guard,
                &mut before_mutation,
                PruneMutation::RetireRename,
                &entry.path(),
            )?;
            fs::rename(entry.path(), &target)?;
            authorize_prune_mutation(
                &guard,
                &mut before_mutation,
                PruneMutation::RetireDelete,
                &target,
            )?;
            fs::remove_dir_all(&target)?;
            removed.push(name);
        }
        Ok(removed)
    }

    fn ensure_layout(&self) -> Result<()> {
        ensure_directory(&self.root, 0o755)?;
        ensure_directory(&self.root.join(GENERATIONS_DIR), 0o711)?;
        Ok(())
    }

    fn activate_pointer(&self, id: &str) -> Result<()> {
        ensure!(catalog::is_sha256(id), "invalid generation pointer value");
        self.load_generation(id)?;
        let root = Directory::open(&self.root.join(GENERATIONS_DIR))?;
        let temp = ".current.tmp";
        root.prepare_trusted(temp, format!("{id}\n").as_bytes(), GENERATION_FILE_MODE)?;
        let _activation =
            root.activate(temp, ACTIVE_POINTER, PREVIOUS_POINTER, GENERATION_FILE_MODE)?;
        // The previous pointer is the rollback contract, not a disposable
        // activation backup. Dropping the handle closes its directory fd but
        // intentionally leaves both durable pointer files in place.
        Ok(())
    }

    fn read_pointer(&self, name: &str) -> Result<String> {
        let root = Directory::open(&self.root.join(GENERATIONS_DIR))?;
        let bytes = root.read_trusted(name, 65, GENERATION_FILE_MODE)?;
        let value = std::str::from_utf8(&bytes).context("generation pointer is not UTF-8")?;
        let id = value
            .strip_suffix('\n')
            .context("generation pointer lacks newline")?;
        ensure!(catalog::is_sha256(id), "invalid generation pointer digest");
        Ok(id.to_string())
    }

    fn load_generation(&self, id: &str) -> Result<VerifiedGeneration> {
        ensure!(catalog::is_sha256(id), "invalid generation id");
        let path = self.root.join(GENERATIONS_DIR).join(id);
        let meta = fs::symlink_metadata(&path).context("stat generation")?;
        ensure!(meta.file_type().is_dir(), "generation is not a directory");
        ensure!(
            meta.uid() == current_uid() && meta.gid() == current_gid(),
            "generation owner mismatch"
        );
        ensure!(
            meta.permissions().mode() & 0o777 == GENERATION_DIR_MODE,
            "generation mode mismatch"
        );
        let dir = Directory::open(&path)?;
        let catalog_bytes = dir.read_trusted(
            CATALOG_FILE,
            catalog::MAX_CATALOG_BYTES,
            GENERATION_FILE_MODE,
        )?;
        let signature = dir.read_trusted(
            CATALOG_SIGNATURE_FILE,
            catalog::SIGNATURE_BYTES,
            GENERATION_FILE_MODE,
        )?;
        let catalog = AgentCatalog::parse_verified(&catalog_bytes, &signature)?;
        let catalog_sha256 = AgentCatalog::digest(&catalog_bytes);
        let selection_bytes = dir.read_trusted(
            AGENTS_SELECTED_FILE,
            crate::selection::MAX_SELECTION_BYTES,
            GENERATION_FILE_MODE,
        )?;
        let frozen = SelectionReceipt::parse_canonical(&selection_bytes)?;
        let selection =
            SelectionReceipt::verify(&selection_bytes, &catalog, &catalog_sha256, &frozen.facts)?;
        let resource = resources::ResourceProduct::load(
            &dir,
            Some(GENERATION_FILE_MODE),
            &catalog,
            &catalog_bytes,
            &signature,
        )?;
        let recomputed_id =
            resources::generation_identity(resource.as_ref(), &catalog_sha256, &selection.sha256)?;
        ensure!(
            recomputed_id == id,
            "generation directory identity mismatch"
        );
        let mut expected = expected_inventory(&catalog, &selection, &catalog_bytes, &signature)?;
        if let Some(resource) = &resource {
            resource.extend(&mut expected)?;
        }
        let allowed: BTreeSet<String> = expected.keys().cloned().collect();
        validate_exact_directory_inventory(&path, &allowed)?;
        let mut files = Vec::new();
        for expected_file in expected.values() {
            let bytes = dir.read_trusted(
                &expected_file.file,
                expected_file.size as usize,
                GENERATION_FILE_MODE,
            )?;
            ensure!(
                bytes.len() as u64 == expected_file.size && digest(&bytes) == expected_file.sha256,
                "active generation file mismatch: {}",
                expected_file.file
            );
            files.push(expected_file.clone());
        }
        files.sort_by(|left, right| left.file.cmp(&right.file));
        Ok(VerifiedGeneration {
            id: id.to_string(),
            catalog_sha256,
            selection_sha256: selection.sha256.clone(),
            directory: path,
            catalog,
            selection,
            files,
        })
    }
}

fn read_incoming_identity(incoming: &Directory) -> Option<(String, String)> {
    let catalog_bytes = incoming
        .read_untrusted(CATALOG_FILE, catalog::MAX_CATALOG_BYTES)
        .ok()?;
    let selection_bytes = incoming
        .read_untrusted(AGENTS_SELECTED_FILE, crate::selection::MAX_SELECTION_BYTES)
        .ok()?;
    Some((
        AgentCatalog::digest(&catalog_bytes),
        digest(&selection_bytes),
    ))
}

impl VerifiedGeneration {
    pub fn description_json(&self) -> Result<String> {
        serde_json::to_string(&GenerationDescription {
            schema_version: 1,
            generation_id: &self.id,
            catalog_sha256: &self.catalog_sha256,
            selection_sha256: &self.selection_sha256,
            files: &self.files,
        })
        .context("serialize generation description")
    }

    pub fn installed_agent_ids(&self) -> HashSet<&str> {
        self.selection
            .selected_agent_ids
            .iter()
            .map(String::as_str)
            .collect()
    }

    /// Re-open one resident generation payload through the immutable
    /// directory boundary and re-check the exact activation inventory entry
    /// at use time. This catches post-activation corruption before bytes enter
    /// a bootstrap envelope.
    pub fn read_file_exact(&self, name: &str) -> Result<Vec<u8>> {
        read_verified_file(&self.directory, &self.files, name)
    }
}

fn read_verified_file(
    directory: &Path,
    inventory: &[GenerationFile],
    name: &str,
) -> Result<Vec<u8>> {
    crate::catalog::validate_basename(name)?;
    let expected = inventory
        .iter()
        .find(|file| file.file == name)
        .with_context(|| format!("generation inventory has no {name}"))?;
    ensure!(
        expected.size <= crate::catalog::MAX_FILE_BYTES,
        "generation file exceeds catalog bound: {name}"
    );
    let expected_size = usize::try_from(expected.size)
        .with_context(|| format!("generation file size does not fit memory: {name}"))?;
    let dir = Directory::open(directory).context("open resident generation directory")?;
    dir.validate_owner_mode(current_uid(), current_gid(), GENERATION_DIR_MODE)
        .context("resident generation directory owner/mode")?;
    let bytes = dir
        .read_trusted(name, expected_size, GENERATION_FILE_MODE)
        .with_context(|| format!("read resident generation file: {name}"))?;
    ensure!(
        bytes.len() == expected_size && digest(&bytes) == expected.sha256,
        "resident generation file exact bytes mismatch: {name}"
    );
    Ok(bytes)
}

fn expected_inventory(
    catalog: &AgentCatalog,
    selection: &VerifiedSelection,
    catalog_bytes: &[u8],
    signature: &[u8],
) -> Result<BTreeMap<String, GenerationFile>> {
    catalog.validate()?;
    let mut files = BTreeMap::new();
    insert_expected(
        &mut files,
        GenerationFile {
            file: CATALOG_FILE.to_string(),
            size: catalog_bytes.len() as u64,
            sha256: digest(catalog_bytes),
        },
    )?;
    insert_expected(
        &mut files,
        GenerationFile {
            file: CATALOG_SIGNATURE_FILE.to_string(),
            size: signature.len() as u64,
            sha256: digest(signature),
        },
    )?;
    insert_expected(
        &mut files,
        GenerationFile {
            file: AGENTS_SELECTED_FILE.to_string(),
            size: selection.exact_bytes.len() as u64,
            sha256: selection.sha256.clone(),
        },
    )?;
    insert_expected(
        &mut files,
        GenerationFile {
            file: catalog.core.file.clone(),
            size: catalog.core.size,
            sha256: catalog.core.sha256.clone(),
        },
    )?;
    if let Some(runtime) = &catalog.cluster_runtime {
        insert_expected(
            &mut files,
            GenerationFile {
                file: runtime.file.clone(),
                size: runtime.size,
                sha256: runtime.sha256.clone(),
            },
        )?;
    }
    for agent in &catalog.agents {
        let mut modules = HashSet::new();
        for target in &agent.targets {
            // Validation permits only exact aliases within this logical agent.
            // Reserved/core names still go through the collision-rejecting insert.
            if !modules.insert(target.file.as_str()) {
                continue;
            }
            insert_expected(
                &mut files,
                GenerationFile {
                    file: target.file.clone(),
                    size: target.size,
                    sha256: target.sha256.clone(),
                },
            )?;
        }
    }
    Ok(files)
}

fn correlate_product_generation(
    manifest: &voboost_contract::release::Manifest,
    catalog: &AgentCatalog,
) -> Result<()> {
    catalog.validate()?;
    let core = manifest
        .artifact(&catalog.core.file)
        .map_err(anyhow::Error::msg)?;
    ensure!(
        core.role == voboost_contract::release::ArtifactRole::AgentCommon
            && core.size == catalog.core.size
            && core.sha256 == catalog.core.sha256,
        "catalog core differs from product manifest"
    );
    if let Some(runtime) = &catalog.cluster_runtime {
        let declared = manifest
            .artifact(&runtime.file)
            .map_err(anyhow::Error::msg)?;
        ensure!(
            declared.role == voboost_contract::release::ArtifactRole::QnxRuntime
                && declared.size == runtime.size
                && declared.sha256 == runtime.sha256,
            "catalog native runtime differs from product"
        );
    }
    let product_modules = manifest
        .artifacts
        .iter()
        .filter(|artifact| {
            matches!(
                artifact.role,
                voboost_contract::release::ArtifactRole::AgentModule
                    | voboost_contract::release::ArtifactRole::QnxAgentModule
            )
        })
        .collect::<Vec<_>>();
    let product = product_modules
        .iter()
        .map(|artifact| {
            (
                artifact.file.as_str(),
                (artifact.size, artifact.sha256.as_str()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let targets = catalog
        .agents
        .iter()
        .flat_map(|agent| &agent.targets)
        .map(|target| (target.file.as_str(), (target.size, target.sha256.as_str())))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        product.len() == product_modules.len() && targets == product,
        "catalog target closure differs from product manifest"
    );
    Ok(())
}

fn insert_expected(
    files: &mut BTreeMap<String, GenerationFile>,
    file: GenerationFile,
) -> Result<()> {
    ensure!(
        files.insert(file.file.clone(), file).is_none(),
        "expected generation filename collision"
    );
    Ok(())
}

fn validate_exact_directory_inventory(path: &Path, allowed: &BTreeSet<String>) -> Result<()> {
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(path).context("list generation directory")? {
        ensure!(
            actual.len() < allowed.len(),
            "generation physical inventory has extra entries"
        );
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().context("non-UTF8 generation entry")?;
        crate::catalog::validate_basename(name)?;
        let meta = fs::symlink_metadata(entry.path())?;
        ensure!(
            meta.file_type().is_file() && meta.nlink() == 1,
            "generation entry is not a single-link regular file"
        );
        ensure!(actual.insert(name.to_string()), "duplicate directory entry");
        ensure!(
            allowed.contains(name),
            "generation physical inventory has an unknown entry"
        );
    }
    ensure!(&actual == allowed, "generation physical inventory mismatch");
    Ok(())
}

fn cleanup_created_generation(path: &Path, identity: (u64, u64)) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        metadata.file_type().is_dir()
            && metadata.dev() == identity.0
            && metadata.ino() == identity.1,
        "generation import cleanup target changed identity"
    );
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    fs::remove_dir_all(path)?;
    Ok(())
}

fn ensure_directory(path: &Path, mode: u32) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            ensure!(meta.file_type().is_dir(), "trusted path is not a directory");
            ensure!(
                meta.uid() == current_uid() && meta.gid() == current_gid(),
                "directory owner mismatch"
            );
            ensure!(
                meta.permissions().mode() & 0o022 == 0,
                "trusted directory is group/world writable"
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).with_context(|| format!("create {}", path.display()))?;
        }
        Err(error) => return Err(error.into()),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn current_gid() -> u32 {
    unsafe { libc::getegid() }
}

fn validate_staging_owner(owner: (u32, u32)) -> Result<()> {
    ensure!(
        owner.0 != 0 && owner.1 != 0,
        "incoming owner must be an unprivileged app identity"
    );
    ensure!(
        owner != (current_uid(), current_gid()),
        "incoming owner must differ from the daemon identity"
    );
    Ok(())
}

/// Host-test fixtures shared with the main.rs daemon-loop state-machine
/// tests: a real two-generation store with release-key-signed catalogs.
#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod discovery_tests {
    use super::*;
    #[test]
    fn idle_discovery_does_not_validate_the_active_generation() {
        let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let incoming = root.path().join("incoming");
        fs::create_dir(&incoming).unwrap();
        fs::create_dir(root.path().join(GENERATIONS_DIR)).unwrap();
        // An unreadable/corrupt current generation is not work admission.
        fs::write(
            root.path().join(GENERATIONS_DIR).join("current"),
            b"invalid pointer",
        )
        .unwrap();
        let store = GenerationStore::new(root.path(), &incoming);
        assert!(!store.incoming_work_present());
        fs::write(incoming.join(READY_MARKER), b"").unwrap();
        assert!(store.incoming_work_present());
    }
}
