//! Durable admission of descriptor-verified product OTA candidates.
//!
//! Descriptor admission, complete-candidate reconstruction and crash-safe
//! product activation. Generation, APK, common-native and protected
//! Init/SELinux plans all run under the shared global operation lease.

use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use voboost_contract::status::{
    CandidateDescriptorHandoff, OtaCandidateHandle, VerifiedDescriptorCandidate, MAX_STATUS_BYTES,
};

use crate::operation_contract::GenerationGuard;
use crate::{
    operation_contract::{Operation, OperationDescriptor, OperationLease},
    secure_fs::Directory,
};

const INSTALL_ROOT: &str = "install";
/// Staging root for the explicit offline update: the host stages the complete
/// signed closure here BEFORE admission. It must not live under INSTALL_ROOT:
/// admit() treats an existing install/<transaction> without a proposal
/// journal as an inconsistent state, and the offline staging is exactly that
/// until admission adopts it through its descriptor handoff.
const OFFLINE_STAGING_ROOT: &str = "install-offline";
const RECOVERY_ROOT: &str = "recovery";
const CANDIDATE: &str = "candidate";
const COMPLETE_CANDIDATE: &str = "complete-candidate";
const JOURNAL: &str = "product-proposal.json";
const JOURNAL_TEMP: &str = ".product-proposal.json.tmp";
const TERMINAL_RECEIPT: &str = "product-update-terminal.json";
const MANIFEST: &str = "voboost.json";
const SIGNATURE: &str = "voboost.json.sig";
const FILE_MODE: u32 = 0o600;
const MAX_DURABLE_PROPOSALS: usize = 1;
const PREVIOUS: &str = "product-previous";
const INVENTORY: &str = voboost_shared::installed_state::LEGACY_FILE;
const INSTALLED_STATE: &str = voboost_contract::domain_core::install_layout::STATE;
const ARTIFACTS: &str = "system-artifacts.json";
const SYSTEM_STATE: &str = "system-state.json";
const NEXT_INVENTORY: &str = "install-inventory.next";
const NEXT_ARTIFACTS: &str = "system-artifacts.next";
const NEXT_BASELINE: &str = "current-baseline.next";
const NEXT_POLICY_META: &str = "policy.meta.next";
const NEXT_SYSTEM_STATE: &str = "system-state.next";
const NEXT_RC_ARCHIVE: &str = "voboost.rc.next";
const SYSTEM_HELPER_SERVICE: &[u8] =
    b"service voboost-system-update /data/voboost/voboost-restore --product-system-update\n";
const SYSTEM_HELPER_SERVICE_EMULATOR: &[u8] =
    b"service voboost-system-update /system/xbin/su 0 /data/voboost/voboost-restore --product-system-update\n";

use voboost_shared::uninstall_contract;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Admission {
    Pending,
    Accepted,
    InstallApk,
    RebootRequired,
    MetadataOnlyUnavailable,
    TransactionCollision,
    UnsupportedActivationClass,
    ActivationFailed,
    ApkIdentityInvalid,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProductCrashCut {
    GenerationPrepared,
    RestoreSignature,
    GenerationSwitched,
    InventoryArtifacts,
    ManifestSignature,
    NativeMember(usize),
    NativeBeforeReboot,
    NativeRebootPublished,
    NativePostVerified,
    /// The terminal journal write of a Complete transition happened, but the
    /// observer projection publish did not (the R24 terminal WAL→projection
    /// cut).
    CompleteJournalWritten,
}

pub(crate) struct ProductCandidateStore {
    root: PathBuf,
    reconstruct: bool,
}

use voboost_contract::product_update::{
    activation_classes, is_native_plan, ProductActivationClass,
    ProductUpdateJournal as ProposalJournal, ProductUpdateOrigin,
    ProductUpdatePhase as ProposalPhase,
};
#[cfg(test)]
use voboost_contract::product_update::{is_apk_only_plan, is_generation_only_plan};

fn plan_requires_apk(journal: &ProposalJournal) -> bool {
    journal
        .activation_classes
        .contains(&ProductActivationClass::PackageInstaller)
}

fn plan_requires_generation(journal: &ProposalJournal) -> bool {
    journal
        .activation_classes
        .contains(&ProductActivationClass::AgentGeneration)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObservedApkState {
    Active,
    Candidate,
    Invalid,
}

fn observed_apk_state(
    root_path: &Path,
    candidate: &voboost_contract::release::Manifest,
) -> Result<ObservedApkState, String> {
    let candidate_apk = candidate.artifact("voboost-app.apk")?;
    if crate::installed_product::installed_apk_matches_in(candidate_apk, root_path) {
        return Ok(ObservedApkState::Candidate);
    }
    let active = crate::installed_product::load_manifest_in(root_path)?;
    if crate::installed_product::installed_apk_matches_in(
        active.artifact("voboost-app.apk")?,
        root_path,
    ) {
        Ok(ObservedApkState::Active)
    } else {
        Ok(ObservedApkState::Invalid)
    }
}

fn prepare_apk_rollback(
    root_path: &Path,
    recovery: &Directory,
    lease: &OperationLease,
) -> Result<(), String> {
    lease.verify_owner()?;
    let root = Directory::open(root_path).map_err(|e| e.to_string())?;
    let active = crate::installed_product::load_manifest_in(root_path)?;
    let artifact = active.artifact("voboost-app.apk")?;
    let previous = recovery
        .open_or_create_private_child(PREVIOUS)
        .map_err(|e| e.to_string())?;
    for name in [MANIFEST, SIGNATURE] {
        let bytes = root
            .read_trusted(
                name,
                voboost_contract::release::MAX_MANIFEST_BYTES,
                FILE_MODE,
            )
            .map_err(|e| e.to_string())?;
        if previous.entry_exists(name).map_err(|e| e.to_string())? {
            if previous
                .read_trusted(name, bytes.len(), FILE_MODE)
                .map_err(|e| e.to_string())?
                != bytes
            {
                return Err("previous APK manifest authority changed".into());
            }
        } else {
            previous
                .write_atomic(name, &bytes, FILE_MODE)
                .map_err(|e| e.to_string())?;
        }
    }
    if previous
        .entry_exists("voboost-app.apk")
        .map_err(|e| e.to_string())?
    {
        return previous
            .verify_trusted_digest(
                "voboost-app.apk",
                artifact.size,
                &artifact.sha256,
                FILE_MODE,
            )
            .map_err(|e| e.to_string());
    }
    let (path, _) = crate::installed_product::verify_installed_apk_identity_until(
        artifact,
        root_path,
        std::time::Instant::now() + std::time::Duration::from_secs(15),
    )?;
    #[cfg(target_os = "android")]
    let input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| e.to_string())?;
    #[cfg(not(target_os = "android"))]
    let input = {
        let _ = path;
        root.open_trusted_file("voboost-app.apk.host-observed", artifact.size, FILE_MODE)
            .map_err(|e| e.to_string())?
    };
    lease.verify_owner()?;
    previous
        .write_atomic_from_descriptor(
            "voboost-app.apk",
            input.as_raw_fd(),
            artifact.size,
            &artifact.sha256,
            FILE_MODE,
        )
        .map_err(|e| e.to_string())?;
    lease.verify_owner()
}

fn previous_apk_restored(root_path: &Path, recovery: &Directory) -> Result<bool, String> {
    let previous = recovery.open_child(PREVIOUS).map_err(|e| e.to_string())?;
    let bytes = previous
        .read_trusted(
            MANIFEST,
            voboost_contract::release::MAX_MANIFEST_BYTES,
            FILE_MODE,
        )
        .map_err(|e| e.to_string())?;
    let signature = previous
        .read_trusted(SIGNATURE, 64, FILE_MODE)
        .map_err(|e| e.to_string())?;
    let manifest = voboost_contract::release::verify_manifest_signature(
        &bytes,
        &signature,
        &crate::trust::release_catalog_public_key(),
    )?;
    Ok(crate::installed_product::installed_apk_matches_in(
        manifest.artifact("voboost-app.apk")?,
        root_path,
    ))
}

fn reject_cluster_uninstall(root: &Path) -> Result<(), String> {
    voboost_shared::cluster_mailbox::reject_pending_uninstall(
        root,
        &[
            &crate::trust::AGENT_CATALOG_PUBKEY,
            &crate::trust::RELEASE_CATALOG_PUBKEY,
            &crate::trust::NATIVE_EXECUTABLE_PUBKEY,
            &crate::trust::RESTORE_PUBLIC_KEY,
        ],
    )
}

impl ProductCandidateStore {
    pub(crate) fn production() -> Self {
        Self {
            root: PathBuf::from(crate::config::ROOT_ZONE),
            reconstruct: true,
        }
    }

    pub(crate) fn ensure_idle_for_uninstall(&self) -> Result<(), String> {
        if durable_proposal_present(
            self.root
                .to_str()
                .ok_or_else(|| "product root path is not UTF-8".to_string())?,
        )? {
            return Err("product update transaction is still active".into());
        }
        let root = match Directory::open(&self.root) {
            Ok(root) => root,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.to_string()),
        };
        if root.entry_exists("run").map_err(|e| e.to_string())? {
            let run = root.open_child("run").map_err(|e| e.to_string())?;
            if run
                .entry_exists("restore-prepare")
                .map_err(|e| e.to_string())?
            {
                return Err("unleased restore preparation requires recovery".into());
            }
        }
        if root
            .entry_exists(RECOVERY_ROOT)
            .map_err(|e| e.to_string())?
        {
            let recovery = root.open_child(RECOVERY_ROOT).map_err(|e| e.to_string())?;
            recovery
                .validate_owner_mode(
                    unsafe { libc::geteuid() },
                    unsafe { libc::getegid() },
                    0o700,
                )
                .map_err(|e| e.to_string())?;
            for name in recovery
                .entry_names_bounded(257)
                .map_err(|e| e.to_string())?
            {
                let transaction = recovery.open_child(&name).map_err(|e| e.to_string())?;
                for member in [
                    "install-journal.json",
                    ".install-journal.json.tmp",
                    "update-journal.json",
                    ".update-journal.json.tmp",
                    "fresh-state.json",
                    ".fresh-state.json.tmp",
                    "restore-journal.json",
                    ".restore-journal.json.tmp",
                ] {
                    if transaction
                        .entry_exists(member)
                        .map_err(|e| e.to_string())?
                    {
                        return Err("install or restore transaction requires recovery".into());
                    }
                }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn at(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            reconstruct: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn at_reconstructing(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            reconstruct: true,
        }
    }

    pub(crate) fn recover_product_activation(&self) -> Result<Option<Admission>, String> {
        let root = match Directory::open(&self.root) {
            Ok(root) => root,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.to_string()),
        };
        let recovery = match root.open_child(RECOVERY_ROOT) {
            Ok(recovery) => recovery,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.to_string()),
        };
        let mut found = None;
        for transaction_id in recovery
            .entry_names_bounded(257)
            .map_err(|error| error.to_string())?
        {
            let transaction = match recovery.open_child(&transaction_id) {
                Ok(transaction) => transaction,
                Err(error) if error.kind() == std::io::ErrorKind::NotADirectory => continue,
                Err(error) => return Err(error.to_string()),
            };
            let bytes = match transaction.read_trusted(JOURNAL, MAX_STATUS_BYTES, FILE_MODE) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let bytes =
                        match root.read_trusted(TERMINAL_RECEIPT, MAX_STATUS_BYTES, FILE_MODE) {
                            Ok(bytes) => bytes,
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                            Err(error) => return Err(error.to_string()),
                        };
                    let terminal = ProposalJournal::parse(&bytes)?;
                    if terminal.candidate.transaction_id != transaction_id
                        || !matches!(
                            terminal.phase,
                            ProposalPhase::Complete | ProposalPhase::RolledBack
                        )
                    {
                        continue;
                    }
                    bytes
                }
                Err(error) => return Err(error.to_string()),
            };
            let journal = ProposalJournal::parse(&bytes)?;
            if journal.candidate.transaction_id != transaction_id {
                return Err("product update directory and WAL identity differ".into());
            }
            if found.replace(journal).is_some() {
                return Err("multiple durable product updates require recovery".into());
            }
        }
        let Some(journal) = found else {
            return Ok(None);
        };
        let transaction = recovery
            .open_child(&journal.candidate.transaction_id)
            .map_err(|error| error.to_string())?;
        if matches!(
            journal.phase,
            ProposalPhase::Complete | ProposalPhase::RolledBack
        ) && crate::operation_contract::read_current_in(&self.root)
            .ok()
            .flatten()
            .is_some_and(|operation| operation.outcome == "complete")
        {
            let lock = crate::operation_contract::RawOperationLock::acquire_in(&self.root)?;
            let operation = crate::operation_contract::read_current_in(&self.root)?
                .ok_or("terminal product operation is absent")?;
            if operation.operation != Operation::Update
                || operation.outcome != "complete"
                || operation.transaction_id != journal.candidate.transaction_id
                || operation.phase != format!("update-product-{}", phase_name(journal.phase))
                || operation.journal_sha256
                    != crate::trust::sha256_bytes(&journal.canonical_bytes()?)
            {
                return Err("terminal product cleanup differs from operation authority".into());
            }
            let manifest = load_manifest_from_directory(&root)?;
            if journal.phase == ProposalPhase::Complete
                && (manifest.digest()? != journal.candidate.manifest_sha256
                    || manifest.release_identity != journal.candidate.release_identity)
            {
                return Err("terminal product cleanup differs from active manifest".into());
            }
            let install = root
                .open_child(INSTALL_ROOT)
                .map_err(|error| error.to_string())?;
            cleanup_product_transaction(
                &root,
                &install,
                &recovery,
                &transaction,
                &transaction,
                &manifest,
                &journal.candidate,
            )?;
            lock.verify_owner()?;
            return Ok(Some(if journal.phase == ProposalPhase::Complete {
                Admission::Accepted
            } else {
                Admission::ActivationFailed
            }));
        }
        if !journal.generation_only
            && !journal.apk_only
            && !journal.native_plan
            && !journal.system_plan
        {
            return Ok(Some(Admission::Pending));
        }
        if journal.phase == ProposalPhase::Copying {
            return Ok(Some(Admission::Pending));
        }
        let candidate = journal.candidate.clone();
        let mut durable_phase = journal.phase;
        if matches!(
            journal.phase,
            ProposalPhase::Pending | ProposalPhase::Reconstructing
        ) {
            let guard = GenerationGuard::acquire_in(&self.root)?;
            reject_cluster_uninstall(&self.root)?;
            let current = ProposalJournal::parse(
                &transaction
                    .read_trusted(JOURNAL, MAX_STATUS_BYTES, FILE_MODE)
                    .map_err(|error| error.to_string())?,
            )?;
            if current != journal {
                return Err("product update WAL changed before reconstruction".into());
            }
            let install = root
                .open_child(INSTALL_ROOT)
                .map_err(|error| error.to_string())?;
            let install_tx = install
                .open_child(&candidate.transaction_id)
                .map_err(|error| error.to_string())?;
            let changed = install_tx
                .open_child(CANDIDATE)
                .map_err(|error| error.to_string())?;
            let manifest = verify_durable_candidate(&changed, &candidate)?;
            let mut resumed = journal.clone();
            resumed.phase = ProposalPhase::Reconstructing;
            write_journal(&transaction, &resumed)?;
            reconstruct_complete(
                &self.root,
                &install_tx,
                &changed,
                &manifest,
                &journal.origin,
            )
            .map_err(|error| format!("autonomous complete-candidate reconstruction: {error}"))?;
            guard.verify_owner()?;
            resumed.phase = ProposalPhase::Reconstructed;
            write_journal(&transaction, &resumed)?;
            guard.verify_owner()?;
            durable_phase = ProposalPhase::Reconstructed;
        }
        for step in 0..20 {
            match continue_generation_only(&self.root, &candidate)
                .map_err(|error| format!("recover product activation step {step}: {error}"))?
            {
                Admission::Pending => {
                    let next = ProposalJournal::parse(
                        &transaction
                            .read_trusted(JOURNAL, MAX_STATUS_BYTES, FILE_MODE)
                            .map_err(|error| error.to_string())?,
                    )?;
                    if next.phase == durable_phase {
                        return Ok(Some(Admission::Pending));
                    }
                    durable_phase = next.phase;
                }
                terminal => return Ok(Some(terminal)),
            }
        }
        Err("product activation recovery exceeded phase-advance bound".into())
    }

    pub(crate) fn admit(
        &self,
        candidate: &OtaCandidateHandle,
        verified: &VerifiedDescriptorCandidate,
        handoff: &CandidateDescriptorHandoff,
        origin: &ProductUpdateOrigin,
    ) -> Result<Admission, String> {
        if verified.manifest().digest()? != candidate.manifest_sha256
            || verified.manifest().release_identity != candidate.release_identity
            || handoff.artifacts.len() != candidate.artifacts.len()
        {
            return Err("verified product candidate identity differs".into());
        }
        if let ProductUpdateOrigin::OfflineExplicit {
            expected_active_manifest_sha256,
        } = origin
        {
            // The operator's intent is bound to the inspected active content
            // identity. Any drift (including another completed update) is a
            // conflict that must fail closed before any mutation.
            let active = crate::installed_product::load_manifest_in(&self.root)?;
            if active.digest()? != *expected_active_manifest_sha256 {
                return Err("active product content changed since offline inspection".into());
            }
        }

        if let Some(result) = read_terminal_result(&self.root, candidate)? {
            return Ok(result);
        }
        if let Some(active) = crate::operation_contract::read_document_in(&self.root)? {
            if active.operation == Operation::Update
                && active.transaction_id == candidate.transaction_id
            {
                return continue_generation_only(&self.root, candidate);
            }
            if active.outcome != "complete" {
                return Err("operation busy".into());
            }
        }

        // The shared kernel lock excludes install/update/restore/uninstall and
        // generation mutation for the complete root-admission window. No
        // operation.json is published yet because activation is deliberately
        // not started by this bounded slice.
        let guard = GenerationGuard::acquire_in(&self.root)?;
        guard.verify_owner()?;
        reject_cluster_uninstall(&self.root)?;
        if let ProductUpdateOrigin::OfflineExplicit {
            expected_active_manifest_sha256,
        } = origin
        {
            if crate::installed_product::load_manifest_in(&self.root)?.digest()?
                != *expected_active_manifest_sha256
            {
                return Err("active product content changed since offline inspection".into());
            }
        }

        let root = Directory::open(&self.root)
            .map_err(|error| format!("open product candidate root: {error}"))?;
        let install_root = root
            .open_or_create_private_child(INSTALL_ROOT)
            .map_err(|error| format!("open product install root: {error}"))?;
        let recovery_root = root
            .open_or_create_private_child(RECOVERY_ROOT)
            .map_err(|error| format!("open product recovery root: {error}"))?;
        let install_exists = install_root
            .entry_exists(&candidate.transaction_id)
            .map_err(|error| format!("inspect product install transaction: {error}"))?;
        let recovery_exists = recovery_root
            .entry_exists(&candidate.transaction_id)
            .map_err(|error| format!("inspect product recovery transaction: {error}"))?;

        let mut journal = if recovery_exists {
            let recovery_tx = recovery_root
                .open_child(&candidate.transaction_id)
                .map_err(|error| format!("open product recovery transaction: {error}"))?;
            let existing = match recovery_tx.read_trusted(JOURNAL, MAX_STATUS_BYTES, FILE_MODE) {
                Ok(bytes) => ProposalJournal::parse(&bytes)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    recover_unpublished_journal(&recovery_tx, candidate)?
                }
                Err(error) => {
                    return Err(format!("read product proposal journal: {error}"));
                }
            };
            if existing.candidate != *candidate {
                return Ok(Admission::TransactionCollision);
            }
            if existing.origin != *origin {
                return Err("product proposal origin differs from the request".into());
            }
            existing
        } else {
            if install_exists {
                return Err("product install transaction exists without proposal journal".into());
            }
            if candidate.artifacts.is_empty() {
                return Ok(Admission::MetadataOnlyUnavailable);
            }
            if count_durable_proposals(&recovery_root)? >= MAX_DURABLE_PROPOSALS {
                return Err("durable product proposal bound reached".into());
            }
            let recovery_tx = recovery_root
                .create_private_child(&candidate.transaction_id)
                .map_err(|error| format!("create product recovery transaction: {error}"))?;
            let mut value = ProposalJournal::new(candidate);
            value.origin = origin.clone();
            write_journal(&recovery_tx, &value)?;
            value
        };

        let recovery_tx = recovery_root
            .open_child(&candidate.transaction_id)
            .map_err(|error| format!("reopen product recovery transaction: {error}"))?;
        let install_tx = install_root
            .open_or_create_private_child(&candidate.transaction_id)
            .map_err(|error| format!("open product install transaction: {error}"))?;
        let candidate_dir = install_tx
            .open_or_create_private_child(CANDIDATE)
            .map_err(|error| format!("open product candidate directory: {error}"))?;

        if journal.phase == ProposalPhase::Copying {
            candidate_dir
                .write_atomic(MANIFEST, verified.manifest_bytes(), FILE_MODE)
                .map_err(|error| format!("persist product manifest: {error}"))?;
            candidate_dir
                .write_atomic(SIGNATURE, verified.signature_bytes(), FILE_MODE)
                .map_err(|error| format!("persist product manifest signature: {error}"))?;
            for (identity, descriptor) in candidate.artifacts.iter().zip(&handoff.artifacts) {
                candidate_dir
                    .write_atomic_from_descriptor(
                        &identity.file,
                        descriptor.fd,
                        identity.size,
                        &identity.sha256,
                        FILE_MODE,
                    )
                    .map_err(|error| {
                        format!("persist product artifact {}: {error}", identity.file)
                    })?;
            }
            candidate_dir
                .sync_all()
                .map_err(|error| format!("sync product candidate directory: {error}"))?;
            verify_candidate_directory(&candidate_dir, candidate, verified)?;
            guard.verify_owner()?;
            journal.phase = ProposalPhase::Pending;
            write_journal(&recovery_tx, &journal)?;
        } else {
            verify_candidate_directory(&candidate_dir, candidate, verified)?;
        }

        if !self.reconstruct {
            return Ok(Admission::Pending);
        }
        if matches!(
            journal.phase,
            ProposalPhase::Pending | ProposalPhase::Reconstructing
        ) {
            journal.phase = ProposalPhase::Reconstructing;
            write_journal(&recovery_tx, &journal)?;
            reconstruct_complete(
                &self.root,
                &install_tx,
                &candidate_dir,
                verified.manifest(),
                &journal.origin,
            )?;
            guard.verify_owner()?;
            journal.phase = ProposalPhase::Reconstructed;
            write_journal(&recovery_tx, &journal)?;
        } else {
            verify_complete(
                &install_tx
                    .open_child(COMPLETE_CANDIDATE)
                    .map_err(|e| e.to_string())?,
                verified.manifest(),
            )?;
        }
        recovery_tx
            .sync_all()
            .map_err(|error| format!("sync product proposal recovery: {error}"))?;
        guard.verify_owner()?;
        if !journal.generation_only
            && !journal.apk_only
            && !journal.native_plan
            && !journal.system_plan
        {
            retire_unactivated_candidate(
                &install_root,
                &recovery_root,
                &install_tx,
                &recovery_tx,
                verified.manifest(),
                candidate,
            )?;
            guard.verify_owner()?;
            return Ok(Admission::UnsupportedActivationClass);
        }
        drop(guard);
        continue_generation_only(&self.root, candidate)
    }
}

fn continue_generation_only(
    root_path: &Path,
    candidate: &OtaCandidateHandle,
) -> Result<Admission, String> {
    continue_generation_only_with_cut(root_path, candidate, None)
}

fn continue_generation_only_with_cut(
    root_path: &Path,
    candidate: &OtaCandidateHandle,
    crash_cut: Option<ProductCrashCut>,
) -> Result<Admission, String> {
    let operation = crate::operation_contract::RawOperationLock::acquire_in(root_path)?;
    let root = Directory::open(root_path).map_err(|error| error.to_string())?;
    let install_root = root
        .open_child(INSTALL_ROOT)
        .map_err(|error| error.to_string())?;
    let recovery_root = root
        .open_child(RECOVERY_ROOT)
        .map_err(|error| error.to_string())?;
    let install_tx = install_root
        .open_child(&candidate.transaction_id)
        .map_err(|error| error.to_string())?;
    let recovery_tx = recovery_root
        .open_child(&candidate.transaction_id)
        .map_err(|error| error.to_string())?;
    let mut journal = ProposalJournal::parse(
        &recovery_tx
            .read_trusted(JOURNAL, MAX_STATUS_BYTES, FILE_MODE)
            .map_err(|error| error.to_string())?,
    )?;
    if journal.candidate != *candidate {
        return Ok(Admission::TransactionCollision);
    }
    if !matches!(
        journal.phase,
        ProposalPhase::Complete | ProposalPhase::RolledBack
    ) {
        reject_cluster_uninstall(root_path)?;
    }
    operation.verify_owner()?;
    if !journal.generation_only && !journal.apk_only && !journal.native_plan && !journal.system_plan
    {
        return Ok(Admission::UnsupportedActivationClass);
    }
    let complete_path = root_path
        .join(INSTALL_ROOT)
        .join(&candidate.transaction_id)
        .join(COMPLETE_CANDIDATE);
    let complete = Directory::open(&complete_path).map_err(|error| error.to_string())?;
    let manifest_bytes = complete
        .read_trusted(
            MANIFEST,
            voboost_contract::release::MAX_MANIFEST_BYTES,
            FILE_MODE,
        )
        .map_err(|error| error.to_string())?;
    let signature = complete
        .read_trusted(SIGNATURE, 64, FILE_MODE)
        .map_err(|error| error.to_string())?;
    let manifest = voboost_contract::release::verify_manifest_signature(
        &manifest_bytes,
        &signature,
        &crate::trust::release_catalog_public_key(),
    )?;
    if manifest.digest()? != candidate.manifest_sha256
        || manifest.release_identity != candidate.release_identity
    {
        return Ok(Admission::TransactionCollision);
    }
    verify_complete(&complete, &manifest)?;

    if journal.native_plan
        && journal.phase == ProposalPhase::Reconstructed
        && verify_native_candidate_preflight(&complete, &manifest, candidate).is_err()
    {
        retire_unactivated_candidate(
            &install_root,
            &recovery_root,
            &install_tx,
            &recovery_tx,
            &manifest,
            candidate,
        )?;
        return Ok(Admission::UnsupportedActivationClass);
    }
    if journal.system_plan
        && journal.phase == ProposalPhase::Reconstructed
        && verify_system_candidate_preflight(root_path, &complete, &manifest, candidate).is_err()
    {
        retire_unactivated_candidate(
            &install_root,
            &recovery_root,
            &install_tx,
            &recovery_tx,
            &manifest,
            candidate,
        )?;
        return Ok(Admission::UnsupportedActivationClass);
    }

    if plan_requires_apk(&journal) && journal.phase == ProposalPhase::Reconstructed {
        let lease = admit_update_with_guard(operation, &journal)?;
        if journal.system_plan {
            if let Err(error) = prepare_apk_rollback(root_path, &recovery_tx, &lease) {
                publish_system_failure(&journal, &lease, &error)?;
                return Err(error);
            }
        }
        match observed_apk_state(root_path, &manifest)? {
            ObservedApkState::Candidate => {
                transition(
                    &recovery_tx,
                    &lease,
                    &mut journal,
                    ProposalPhase::ApkObserved,
                )?;
                return Ok(Admission::Pending);
            }
            ObservedApkState::Active => {
                transition(
                    &recovery_tx,
                    &lease,
                    &mut journal,
                    ProposalPhase::ApkInstallRequested,
                )?;
                return Ok(Admission::InstallApk);
            }
            ObservedApkState::Invalid => {
                retire_unactivated_candidate(
                    &install_root,
                    &recovery_root,
                    &install_tx,
                    &recovery_tx,
                    &manifest,
                    candidate,
                )?;
                return Ok(Admission::ApkIdentityInvalid);
            }
        }
    }
    let lease = admit_update_with_guard(operation, &journal)?;

    let durable_phase = journal.phase;
    let outcome = (|| -> Result<Admission, String> {
        match journal.phase {
            ProposalPhase::ApkInstallRequested => match observed_apk_state(root_path, &manifest)? {
                ObservedApkState::Candidate => {
                    transition(
                        &recovery_tx,
                        &lease,
                        &mut journal,
                        ProposalPhase::ApkObserved,
                    )?;
                    Ok(Admission::Pending)
                }
                ObservedApkState::Active => Ok(Admission::InstallApk),
                ObservedApkState::Invalid => Ok(Admission::ApkIdentityInvalid),
            },
            ProposalPhase::ApkObserved => {
                if journal.system_plan {
                    prepare_native_transition(
                        root_path,
                        &recovery_tx,
                        &complete_path,
                        &manifest,
                        &mut journal,
                        &lease,
                    )?;
                    prepare_system_authority(
                        root_path,
                        &recovery_tx,
                        &complete,
                        &manifest,
                        &mut journal,
                    )?;
                    transition(
                        &recovery_tx,
                        &lease,
                        &mut journal,
                        ProposalPhase::SystemPrepared,
                    )?;
                    return Ok(Admission::Pending);
                }
                if journal.native_plan {
                    prepare_native_transition(
                        root_path,
                        &recovery_tx,
                        &complete_path,
                        &manifest,
                        &mut journal,
                        &lease,
                    )?;
                    transition(
                        &recovery_tx,
                        &lease,
                        &mut journal,
                        ProposalPhase::NativePrepared,
                    )?;
                    return Ok(Admission::Pending);
                }
                prepare_recovery_authority(
                    &root,
                    &recovery_tx,
                    &complete,
                    &manifest,
                    &manifest_bytes,
                    &signature,
                    true,
                )?;
                transition(
                    &recovery_tx,
                    &lease,
                    &mut journal,
                    ProposalPhase::RecoveryPrepared,
                )?;
                Ok(Admission::Pending)
            }
            ProposalPhase::Reconstructed => {
                if journal.system_plan {
                    prepare_native_transition(
                        root_path,
                        &recovery_tx,
                        &complete_path,
                        &manifest,
                        &mut journal,
                        &lease,
                    )?;
                    prepare_system_authority(
                        root_path,
                        &recovery_tx,
                        &complete,
                        &manifest,
                        &mut journal,
                    )?;
                    transition(
                        &recovery_tx,
                        &lease,
                        &mut journal,
                        ProposalPhase::SystemPrepared,
                    )?;
                    return Ok(Admission::Pending);
                }
                if journal.native_plan {
                    prepare_native_transition(
                        root_path,
                        &recovery_tx,
                        &complete_path,
                        &manifest,
                        &mut journal,
                        &lease,
                    )?;
                    transition(
                        &recovery_tx,
                        &lease,
                        &mut journal,
                        ProposalPhase::NativePrepared,
                    )?;
                    return Ok(Admission::Pending);
                }
                let generations = crate::generation::GenerationStore::new(
                    root_path,
                    root_path.join("generations/next"),
                );
                let previous = generations.active().map_err(|error| error.to_string())?;
                let next = generations
                    .prepare_product_candidate(&complete_path, &recovery_tx, &lease)
                    .map_err(|error| format!("{error:#}"))?;
                maybe_crash(crash_cut, ProductCrashCut::GenerationPrepared);
                journal.previous_generation = Some(previous.id);
                journal.next_generation = Some(next.id);
                transition(
                    &recovery_tx,
                    &lease,
                    &mut journal,
                    ProposalPhase::GenerationPrepared,
                )?;
                Ok(Admission::Pending)
            }
            ProposalPhase::NativePrepared => {
                if plan_requires_generation(&journal) {
                    let next = journal
                        .next_generation
                        .as_deref()
                        .ok_or_else(|| "product generation identity is absent".to_string())?;
                    crate::generation::GenerationStore::new(
                        root_path,
                        root_path.join("generations/next"),
                    )
                    .switch_product_candidate(next, &recovery_tx, &lease)
                    .map_err(|error| error.to_string())?;
                }
                publish_restore_pair(&root, &complete, &manifest, &lease, crash_cut)?;
                switch_native_members(&root, &complete, &manifest, candidate, &lease, crash_cut)?;
                crate::installed_product::verify_candidate_closure_in(&manifest, false, root_path)?;
                maybe_crash(crash_cut, ProductCrashCut::NativeBeforeReboot);
                transition(
                    &recovery_tx,
                    &lease,
                    &mut journal,
                    ProposalPhase::NativeRebootRequired,
                )?;
                maybe_crash(crash_cut, ProductCrashCut::NativeRebootPublished);
                Ok(Admission::RebootRequired)
            }
            ProposalPhase::NativeRebootRequired => {
                let pre_reboot = journal
                    .pre_reboot_boot_id
                    .as_deref()
                    .ok_or_else(|| "native update pre-reboot boot ID is absent".to_string())?;
                let current = product_boot_id_in(root_path)?;
                if current == pre_reboot {
                    return Ok(Admission::RebootRequired);
                }
                journal.post_reboot_boot_id = Some(current);
                let next_phase = if journal.system_plan {
                    ProposalPhase::SystemPostReboot
                } else {
                    ProposalPhase::NativePostReboot
                };
                transition(&recovery_tx, &lease, &mut journal, next_phase)?;
                if journal.system_plan {
                    start_system_helper()?;
                }
                Ok(Admission::Pending)
            }
            ProposalPhase::NativePostReboot => {
                verify_running_product(root_path, &manifest)?;
                crate::installed_product::verify_candidate_closure_in(&manifest, false, root_path)?;
                maybe_crash(crash_cut, ProductCrashCut::NativePostVerified);
                publish_uninstall_inventory(&root, &recovery_tx, crash_cut)?;
                verify_uninstall_inventory(&root, &manifest)?;
                transition(
                    &recovery_tx,
                    &lease,
                    &mut journal,
                    ProposalPhase::InventoryPublished,
                )?;
                Ok(Admission::Pending)
            }
            ProposalPhase::NativeRollbackRebootRequired => {
                let rollback_from = journal
                    .post_reboot_boot_id
                    .as_deref()
                    .ok_or_else(|| "native rollback boot ID is absent".to_string())?;
                let current = product_boot_id_in(root_path)?;
                if current == rollback_from {
                    return Ok(Admission::RebootRequired);
                }
                let active = crate::installed_product::load_manifest_in(root_path)?;
                verify_running_product(root_path, &active)?;
                crate::installed_product::verify_candidate_closure_in(&active, true, root_path)?;
                verify_uninstall_inventory(&root, &active)?;
                journal.rollback_boot_id = Some(current);
                journal.failure = Some("product activation rolled back".into());
                transition(
                    &recovery_tx,
                    &lease,
                    &mut journal,
                    ProposalPhase::RolledBack,
                )?;
                Ok(Admission::ActivationFailed)
            }
            ProposalPhase::LateRollbackRebootRequired => {
                // The rollback disk replacement happened before this phase
                // was published; the fresh boot was requested only to leave
                // the retired candidate daemon. When it lands, the rolled-back
                // product already runs: converge terminal on the rollback
                // boot without re-verifying the retired candidate daemon.
                let rollback_from = journal
                    .post_reboot_boot_id
                    .as_deref()
                    .ok_or_else(|| "late rollback boot ID is absent".to_string())?;
                let current = product_boot_id_in(root_path)?;
                if current == rollback_from {
                    return Ok(Admission::RebootRequired);
                }
                let active = crate::installed_product::load_manifest_in(root_path)?;
                crate::installed_product::verify_candidate_closure_in(&active, true, root_path)?;
                verify_uninstall_inventory(&root, &active)?;
                journal.rollback_boot_id = Some(current);
                journal.failure = Some("product activation rolled back".to_string());
                transition(
                    &recovery_tx,
                    &lease,
                    &mut journal,
                    ProposalPhase::RolledBack,
                )?;
                Ok(Admission::ActivationFailed)
            }
            ProposalPhase::SystemPrepared => {
                if let Some(failure) = read_system_failure_ack(&recovery_tx)? {
                    verify_system_failure(&journal, &failure, "system-prepared", false)?;
                    if plan_requires_apk(&journal)
                        && !previous_apk_restored(root_path, &recovery_tx)?
                    {
                        return Err("previous APK was not restored by the system helper".into());
                    }
                    let active = crate::installed_product::load_manifest_in(root_path)?;
                    crate::installed_product::verify_candidate_closure_in(
                        &active, true, root_path,
                    )?;
                    journal.failure = Some("product activation rolled back".into());
                    transition(
                        &recovery_tx,
                        &lease,
                        &mut journal,
                        ProposalPhase::RolledBack,
                    )?;
                    return Ok(Admission::ActivationFailed);
                }
                let Some(ack) = read_policy_prepare_ack(&recovery_tx)? else {
                    start_system_helper()?;
                    return Ok(Admission::Pending);
                };
                if ack.transaction_id != candidate.transaction_id
                    || Some(ack.boot_id.as_str()) != journal.pre_reboot_boot_id.as_deref()
                    || Some(ack.policy_baseline_sha256.as_str())
                        != journal.policy_baseline_sha256.as_deref()
                {
                    return Err("policy prepare receipt differs from product WAL".into());
                }
                let policy = recovery_tx
                    .open_child(PREVIOUS)
                    .map_err(|error| error.to_string())?
                    .read_trusted("policy-candidate", 64 * 1024 * 1024, FILE_MODE)
                    .map_err(|error| error.to_string())?;
                if crate::trust::sha256_bytes(&policy) != ack.policy_candidate_sha256 {
                    return Err("prepared candidate policy differs from receipt".into());
                }
                journal.policy_candidate_sha256 = Some(ack.policy_candidate_sha256);
                let previous = recovery_tx
                    .open_child(PREVIOUS)
                    .map_err(|error| error.to_string())?;
                let init = previous
                    .read_trusted("system-init-candidate", 1024 * 1024, FILE_MODE)
                    .map_err(|error| error.to_string())?;
                let init_sha256 = crate::trust::sha256_bytes(&init);
                if Some(init_sha256.as_str()) != journal.system_init_candidate_sha256.as_deref() {
                    return Err("prepared candidate init differs from product WAL".into());
                }
                prepare_uninstall_inventory(
                    &root,
                    &previous,
                    &manifest,
                    &manifest_bytes,
                    &signature,
                    Some(SystemInventoryCandidate {
                        init: &init,
                        policy: &policy,
                    }),
                )?;
                previous.sync_all().map_err(|error| error.to_string())?;
                transition(
                    &recovery_tx,
                    &lease,
                    &mut journal,
                    ProposalPhase::SystemHelperRequested,
                )?;
                start_system_helper()?;
                Ok(Admission::Pending)
            }
            ProposalPhase::SystemHelperRequested => {
                if let Some(failure) = read_system_failure_ack(&recovery_tx)? {
                    verify_system_failure(&journal, &failure, "system-helper-requested", false)?;
                    if plan_requires_apk(&journal)
                        && !previous_apk_restored(root_path, &recovery_tx)?
                    {
                        return Err("previous APK was not restored by the system helper".into());
                    }
                    let active = crate::installed_product::load_manifest_in(root_path)?;
                    crate::installed_product::verify_candidate_closure_in(
                        &active, true, root_path,
                    )?;
                    journal.failure = Some("product activation rolled back".into());
                    transition(
                        &recovery_tx,
                        &lease,
                        &mut journal,
                        ProposalPhase::RolledBack,
                    )?;
                    return Ok(Admission::ActivationFailed);
                }
                let Some(ack) = read_system_switch_ack(&recovery_tx)? else {
                    start_system_helper()?;
                    return Ok(Admission::Pending);
                };
                if ack.transaction_id != candidate.transaction_id
                    || Some(ack.boot_id.as_str()) != journal.pre_reboot_boot_id.as_deref()
                    || Some(ack.init_previous_sha256.as_str())
                        != journal.system_init_previous_sha256.as_deref()
                    || Some(ack.init_candidate_sha256.as_str())
                        != journal.system_init_candidate_sha256.as_deref()
                    || Some(ack.policy_previous_sha256.as_str())
                        != journal.policy_previous_sha256.as_deref()
                    || Some(ack.policy_baseline_sha256.as_str())
                        != journal.policy_baseline_sha256.as_deref()
                    || Some(ack.policy_candidate_sha256.as_str())
                        != journal.policy_candidate_sha256.as_deref()
                {
                    return Err("system helper switch receipt differs from product WAL".into());
                }
                transition(
                    &recovery_tx,
                    &lease,
                    &mut journal,
                    ProposalPhase::SystemSwitched,
                )?;
                Ok(Admission::Pending)
            }
            ProposalPhase::SystemSwitched => {
                if plan_requires_generation(&journal) {
                    let next = journal
                        .next_generation
                        .as_deref()
                        .ok_or_else(|| "product generation identity is absent".to_string())?;
                    crate::generation::GenerationStore::new(
                        root_path,
                        root_path.join("generations/next"),
                    )
                    .switch_product_candidate(next, &recovery_tx, &lease)
                    .map_err(|error| error.to_string())?;
                }
                publish_restore_pair(&root, &complete, &manifest, &lease, crash_cut)?;
                switch_native_members(&root, &complete, &manifest, candidate, &lease, crash_cut)?;
                crate::installed_product::verify_candidate_closure_in(&manifest, false, root_path)?;
                transition(
                    &recovery_tx,
                    &lease,
                    &mut journal,
                    ProposalPhase::SystemRebootRequired,
                )?;
                Ok(Admission::RebootRequired)
            }
            ProposalPhase::SystemRebootRequired => {
                let pre_reboot = journal
                    .pre_reboot_boot_id
                    .as_deref()
                    .ok_or_else(|| "system update pre-reboot boot ID is absent".to_string())?;
                let current = product_boot_id_in(root_path)?;
                if current == pre_reboot {
                    return Ok(Admission::RebootRequired);
                }
                journal.post_reboot_boot_id = Some(current);
                transition(
                    &recovery_tx,
                    &lease,
                    &mut journal,
                    ProposalPhase::SystemPostReboot,
                )?;
                start_system_helper()?;
                Ok(Admission::Pending)
            }
            ProposalPhase::SystemPostReboot => {
                if let Some(failure) = read_system_failure_ack(&recovery_tx)? {
                    verify_system_failure(&journal, &failure, "system-post-reboot", true)?;
                    if !rollback_system_common(
                        root_path,
                        &root,
                        &recovery_tx,
                        &manifest,
                        candidate,
                        &journal,
                        &lease,
                    )? {
                        start_system_helper()?;
                        return Ok(Admission::Pending);
                    }
                    transition(
                        &recovery_tx,
                        &lease,
                        &mut journal,
                        ProposalPhase::SystemRollbackRebootRequired,
                    )?;
                    return Ok(Admission::RebootRequired);
                }
                let Some(ack) = read_system_post_boot_ack(&recovery_tx)? else {
                    start_system_helper()?;
                    return Ok(Admission::Pending);
                };
                if ack.transaction_id != candidate.transaction_id
                    || Some(ack.boot_id.as_str()) != journal.post_reboot_boot_id.as_deref()
                    || Some(ack.init_candidate_sha256.as_str())
                        != journal.system_init_candidate_sha256.as_deref()
                    || Some(ack.policy_candidate_sha256.as_str())
                        != journal.policy_candidate_sha256.as_deref()
                {
                    return Err("system post-boot receipt differs from product WAL".into());
                }
                verify_running_product(root_path, &manifest)?;
                crate::installed_product::verify_candidate_closure_in(&manifest, false, root_path)?;
                publish_uninstall_inventory(&root, &recovery_tx, crash_cut)?;
                verify_uninstall_inventory(&root, &manifest)?;
                transition(
                    &recovery_tx,
                    &lease,
                    &mut journal,
                    ProposalPhase::InventoryPublished,
                )?;
                Ok(Admission::Pending)
            }
            ProposalPhase::SystemRollbackRebootRequired => {
                let rollback_from = journal
                    .post_reboot_boot_id
                    .as_deref()
                    .ok_or_else(|| "system rollback boot ID is absent".to_string())?;
                let current = product_boot_id_in(root_path)?;
                if current == rollback_from {
                    return Ok(Admission::RebootRequired);
                }
                journal.rollback_boot_id = Some(current);
                transition(
                    &recovery_tx,
                    &lease,
                    &mut journal,
                    ProposalPhase::SystemRollbackPostReboot,
                )?;
                start_system_helper()?;
                Ok(Admission::Pending)
            }
            ProposalPhase::SystemRollbackPostReboot => {
                let Some(ack) = read_system_rollback_ack(&recovery_tx)? else {
                    start_system_helper()?;
                    return Ok(Admission::Pending);
                };
                let current = product_boot_id_in(root_path)?;
                let rollback_boot = journal
                    .rollback_boot_id
                    .as_deref()
                    .ok_or_else(|| "system rollback post-boot ID is absent".to_string())?;
                if ack.transaction_id != candidate.transaction_id
                    || ack.boot_id != current
                    || ack.boot_id != rollback_boot
                    || Some(ack.init_previous_sha256.as_str())
                        != journal.system_init_previous_sha256.as_deref()
                    || Some(ack.policy_previous_sha256.as_str())
                        != journal.policy_previous_sha256.as_deref()
                {
                    return Err("system rollback receipt differs from product WAL".into());
                }
                let active = crate::installed_product::load_manifest_in(root_path)?;
                verify_running_product(root_path, &active)?;
                crate::installed_product::verify_candidate_closure_in(&active, true, root_path)?;
                verify_uninstall_inventory(&root, &active)?;
                journal.failure = Some("product activation rolled back".into());
                transition(
                    &recovery_tx,
                    &lease,
                    &mut journal,
                    ProposalPhase::RolledBack,
                )?;
                Ok(Admission::ActivationFailed)
            }
            ProposalPhase::GenerationPrepared => {
                prepare_recovery_authority(
                    &root,
                    &recovery_tx,
                    &complete,
                    &manifest,
                    &manifest_bytes,
                    &signature,
                    true,
                )?;
                transition(
                    &recovery_tx,
                    &lease,
                    &mut journal,
                    ProposalPhase::RecoveryPrepared,
                )?;
                Ok(Admission::Pending)
            }
            ProposalPhase::RecoveryPrepared => {
                publish_restore_pair(&root, &complete, &manifest, &lease, crash_cut)?;
                transition(
                    &recovery_tx,
                    &lease,
                    &mut journal,
                    ProposalPhase::RestoreSwitched,
                )?;
                Ok(Admission::Pending)
            }
            ProposalPhase::RestoreSwitched => {
                if journal.apk_only {
                    publish_uninstall_inventory(&root, &recovery_tx, crash_cut)?;
                    crate::installed_product::verify_candidate_closure_in(
                        &manifest, false, root_path,
                    )?;
                    verify_uninstall_inventory(&root, &manifest)?;
                    transition(
                        &recovery_tx,
                        &lease,
                        &mut journal,
                        ProposalPhase::InventoryPublished,
                    )?;
                    return Ok(Admission::Pending);
                }
                let next = journal
                    .next_generation
                    .as_deref()
                    .ok_or_else(|| "product generation identity is absent".to_string())?;
                crate::generation::GenerationStore::new(
                    root_path,
                    root_path.join("generations/next"),
                )
                .switch_product_candidate(next, &recovery_tx, &lease)
                .map_err(|error| error.to_string())?;
                maybe_crash(crash_cut, ProductCrashCut::GenerationSwitched);
                transition(
                    &recovery_tx,
                    &lease,
                    &mut journal,
                    ProposalPhase::GenerationSwitched,
                )?;
                Ok(Admission::Pending)
            }
            ProposalPhase::GenerationSwitched => {
                publish_uninstall_inventory(&root, &recovery_tx, crash_cut)?;
                crate::installed_product::verify_candidate_closure_in(&manifest, false, root_path)?;
                verify_uninstall_inventory(&root, &manifest)?;
                transition(
                    &recovery_tx,
                    &lease,
                    &mut journal,
                    ProposalPhase::InventoryPublished,
                )?;
                Ok(Admission::Pending)
            }
            ProposalPhase::InventoryPublished => {
                publish_product_manifest(&root, &complete, &lease, crash_cut)?;
                transition(
                    &recovery_tx,
                    &lease,
                    &mut journal,
                    ProposalPhase::ManifestPublished,
                )?;
                Ok(Admission::Pending)
            }
            ProposalPhase::ManifestPublished => {
                crate::installed_product::verify_candidate_closure_in(&manifest, true, root_path)?;
                verify_uninstall_inventory(&root, &manifest)?;
                transition(
                    &recovery_tx,
                    &lease,
                    &mut journal,
                    ProposalPhase::ProductVerified,
                )?;
                Ok(Admission::Pending)
            }
            ProposalPhase::ProductVerified => {
                transition_with_cut(
                    &recovery_tx,
                    &lease,
                    &mut journal,
                    ProposalPhase::Complete,
                    crash_cut,
                )?;
                cleanup_product_transaction(
                    &root,
                    &install_root,
                    &recovery_root,
                    &install_tx,
                    &recovery_tx,
                    &manifest,
                    candidate,
                )?;
                lease.finish()?;
                Ok(Admission::Accepted)
            }
            ProposalPhase::Complete => {
                cleanup_product_transaction(
                    &root,
                    &install_root,
                    &recovery_root,
                    &install_tx,
                    &recovery_tx,
                    &manifest,
                    candidate,
                )?;
                lease.finish()?;
                Ok(Admission::Accepted)
            }
            ProposalPhase::RolledBack => {
                cleanup_product_transaction(
                    &root,
                    &install_root,
                    &recovery_root,
                    &install_tx,
                    &recovery_tx,
                    &manifest,
                    candidate,
                )?;
                lease.finish()?;
                Ok(Admission::ActivationFailed)
            }
            ProposalPhase::Copying | ProposalPhase::Pending | ProposalPhase::Reconstructing => {
                Err("product activation started before reconstruction completed".into())
            }
        }
    })();
    if journal.generation_only
        && outcome.is_err()
        && durable_phase >= ProposalPhase::RecoveryPrepared
        && durable_phase < ProposalPhase::Complete
    {
        rollback_generation_only(root_path, &root, &recovery_tx, &mut journal, &lease)?;
        return Ok(Admission::ActivationFailed);
    }
    if journal.native_plan
        && outcome.is_err()
        && durable_phase >= ProposalPhase::NativePrepared
        && durable_phase < ProposalPhase::Complete
        && durable_phase != ProposalPhase::NativeRollbackRebootRequired
    {
        if plan_requires_apk(&journal) {
            // Mixed APK/native failure contract (R13): the APK was already
            // replaced out-of-band by PackageInstaller, so rolling the
            // native members back to the previous release would leave a
            // manifest that names the old native artifacts while the new
            // APK runs - a mixed product the update-rollback convergence
            // guarantee forbids accepting. The only contract-compliant
            // recovery is forward: converge the transaction to the
            // complete candidate release. Native members, restore pair,
            // uninstall inventory and manifest pair are re-derived from
            // the verified complete closure (idempotent writes), so a
            // crash inside the convergence replays the same branch.
            return converge_mixed_forward(
                root_path,
                &root,
                &recovery_tx,
                &complete,
                &manifest,
                candidate,
                &manifest_bytes,
                &signature,
                &mut journal,
                &lease,
            );
        }
        return rollback_native_product(
            root_path,
            &root,
            &recovery_tx,
            &manifest,
            candidate,
            &mut journal,
            &lease,
        );
    }
    if journal.system_plan
        && !matches!(
            journal.phase,
            ProposalPhase::Complete | ProposalPhase::RolledBack
        )
    {
        if let Err(error) = &outcome {
            // A failed preparation may have changed only the in-memory proposal.
            // Project the durable WAL so diagnostics cannot mask the original error.
            let durable = ProposalJournal::parse(
                &recovery_tx
                    .read_trusted(JOURNAL, MAX_STATUS_BYTES, FILE_MODE)
                    .map_err(|error| error.to_string())?,
            )?;
            if durable.candidate != journal.candidate {
                return Err("product WAL authority changed while reporting failure".into());
            }
            publish_system_failure(&durable, &lease, error)?;
        }
    }
    outcome
}

/// Forward convergence for a failed mixed APK/native activation (R13).
/// Re-derives every live member from the verified complete candidate
/// closure and terminates the transaction. Returns `ActivationFailed`: the
/// attempt failed, but the durable product converges to the complete
/// candidate release instead of a mixed old/new product. When the live host
/// APK observation cannot prove the candidate APK identity, fails closed
/// with an explicit error (the transaction stays durable and a newer
/// channel release may supersede it).
#[allow(clippy::too_many_arguments)]
fn converge_mixed_forward(
    root_path: &Path,
    root: &Directory,
    recovery_tx: &Directory,
    complete: &Directory,
    manifest: &voboost_contract::release::Manifest,
    candidate: &OtaCandidateHandle,
    manifest_bytes: &[u8],
    manifest_signature: &[u8],
    journal: &mut ProposalJournal,
    lease: &OperationLease,
) -> Result<Admission, String> {
    if observed_apk_state(root_path, manifest)? != ObservedApkState::Candidate {
        return Err(
            "mixed activation failure cannot prove the candidate APK is live; refusing a mixed-product rollback"
                .into(),
        );
    }
    publish_restore_pair(root, complete, manifest, lease, None)?;
    switch_native_members(root, complete, manifest, candidate, lease, None)?;
    crate::installed_product::verify_candidate_closure_in(manifest, false, root_path)?;
    publish_uninstall_inventory(root, recovery_tx, None)?;
    crate::installed_product::verify_candidate_closure_in(manifest, true, root_path)?;
    verify_uninstall_inventory(root, manifest)?;
    let expected_manifest_sha256 = crate::trust::sha256_bytes(manifest_bytes);
    let expected_signature_sha256 = crate::trust::sha256_bytes(manifest_signature);
    publish_product_manifest(root, complete, lease, None)?;
    if root
        .verify_trusted_digest(
            MANIFEST,
            manifest_bytes.len() as u64,
            &expected_manifest_sha256,
            0o600,
        )
        .is_err()
        || root
            .verify_trusted_digest(
                SIGNATURE,
                manifest_signature.len() as u64,
                &expected_signature_sha256,
                0o600,
            )
            .is_err()
    {
        return Err("mixed forward convergence republished a divergent manifest pair".into());
    }
    let recovered = crate::installed_product::load_manifest_in(root_path)?;
    crate::installed_product::verify_candidate_closure_in(&recovered, true, root_path)?;
    verify_uninstall_inventory(root, &recovered)?;
    if recovered.digest()? != manifest.digest()? {
        return Err("mixed forward convergence republished a divergent manifest".into());
    }
    // The journal contract admits `failure` only in the RolledBack phase, so
    // the converged-forward terminal is a plain Complete: the transaction
    // converged to the complete candidate release. The attempt's failure is
    // reported to this caller via the returned Admission only.
    transition(recovery_tx, lease, journal, ProposalPhase::Complete)?;
    Ok(Admission::ActivationFailed)
}

/// Mixed APK/native rollback target: the APK identity that was already
/// observed live (replaced out-of-band by PackageInstaller) before the
/// native activation failed. A native rollback is only admitted when the
/// preserved previous manifest still names this exact APK identity, so the
#[cfg(test)]
fn acquire_update_lease(root: &Path, journal: &ProposalJournal) -> Result<OperationLease, String> {
    let guard = crate::operation_contract::RawOperationLock::acquire_in(root)?;
    if !matches!(
        journal.phase,
        ProposalPhase::Complete | ProposalPhase::RolledBack
    ) {
        reject_cluster_uninstall(root)?;
    }
    admit_update_with_guard(guard, journal)
}

fn admit_update_with_guard(
    guard: crate::operation_contract::RawOperationLock,
    journal: &ProposalJournal,
) -> Result<OperationLease, String> {
    let terminal = operation_projection(journal)?;
    let live = guard.read_live_projection()?;
    if matches!(
        journal.phase,
        ProposalPhase::Complete | ProposalPhase::RolledBack
    ) && live.as_ref().is_some_and(|current| {
        current.operation == terminal.operation
            && current.transaction_id == terminal.transaction_id
            && current.journal == terminal.journal
            && current.journal_sha256 != terminal.journal_sha256
    }) {
        let previous_phase = match journal.phase {
            ProposalPhase::Complete => ProposalPhase::ProductVerified,
            ProposalPhase::RolledBack => ProposalPhase::LateRollbackRebootRequired,
            _ => unreachable!(),
        };
        let mut predecessor_journal = journal.clone();
        predecessor_journal.phase = previous_phase;
        let previous = operation_projection(&predecessor_journal)?;
        if live.as_ref() == Some(&previous) {
            return guard.reconcile_terminal(&previous, &terminal);
        }
    }
    guard.admit(terminal)
}

fn transition(
    recovery: &Directory,
    lease: &OperationLease,
    journal: &mut ProposalJournal,
    phase: ProposalPhase,
) -> Result<(), String> {
    transition_with_cut(recovery, lease, journal, phase, None)
}

fn transition_with_cut(
    recovery: &Directory,
    lease: &OperationLease,
    journal: &mut ProposalJournal,
    phase: ProposalPhase,
    crash_cut: Option<ProductCrashCut>,
) -> Result<(), String> {
    lease.verify_owner()?;
    journal.phase = phase;
    write_journal(recovery, journal)?;
    if phase == ProposalPhase::Complete {
        maybe_crash(crash_cut, ProductCrashCut::CompleteJournalWritten);
    }
    lease.publish(&operation_projection(journal)?)
}

fn publish_system_failure(
    journal: &ProposalJournal,
    lease: &OperationLease,
    error: &str,
) -> Result<(), String> {
    let mut failed = operation_projection(journal)?;
    failed.outcome = "failed".into();
    failed.status_sequence += (3 - failed.status_sequence % 3) % 3;
    let mut message = String::new();
    for character in error.chars() {
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if message.len() + character.len_utf8() > 512 {
            break;
        }
        message.push(character);
    }
    if message.trim().is_empty() {
        message = "System update failed".into();
    }
    failed.error = Some(serde_json::json!({
        "code": "product-system-update-failed",
        "message": message,
    }));
    if lease
        .read_live_projection()?
        .as_ref()
        .is_some_and(|current| {
            current.outcome == "failed"
                && current.transaction_id == failed.transaction_id
                && current.phase == failed.phase
                && current.journal_sha256 == failed.journal_sha256
        })
    {
        return Ok(());
    }
    lease.publish(&failed)
}

fn operation_projection(journal: &ProposalJournal) -> Result<OperationDescriptor, String> {
    let index = match journal.phase {
        ProposalPhase::Copying => 1,
        ProposalPhase::Pending => 2,
        ProposalPhase::Reconstructing => 3,
        ProposalPhase::Reconstructed => 4,
        ProposalPhase::ApkInstallRequested => 5,
        ProposalPhase::ApkObserved => 6,
        ProposalPhase::GenerationPrepared => 7,
        ProposalPhase::RecoveryPrepared => 8,
        ProposalPhase::RestoreSwitched => 9,
        ProposalPhase::GenerationSwitched => 10,
        ProposalPhase::NativePrepared => 11,
        ProposalPhase::NativeRebootRequired => 12,
        ProposalPhase::NativePostReboot => 13,
        ProposalPhase::NativeRollbackRebootRequired => 14,
        ProposalPhase::SystemPrepared => 15,
        ProposalPhase::SystemHelperRequested => 16,
        ProposalPhase::SystemSwitched => 17,
        ProposalPhase::SystemRebootRequired => 18,
        ProposalPhase::SystemPostReboot => 19,
        ProposalPhase::SystemRollbackRebootRequired => 20,
        ProposalPhase::SystemRollbackPostReboot => 21,
        ProposalPhase::InventoryPublished => 22,
        ProposalPhase::ManifestPublished => 23,
        ProposalPhase::ProductVerified => 24,
        ProposalPhase::LateRollbackRebootRequired => 25,
        ProposalPhase::Complete => 26,
        ProposalPhase::RolledBack => 26,
    };
    let transaction_id = journal.candidate.transaction_id.clone();
    let mut descriptor = OperationDescriptor::new(
        Operation::Update,
        transaction_id.clone(),
        format!("recovery/{transaction_id}/{JOURNAL}"),
        product_boot_id()?,
    )?;
    descriptor.phase = format!("update-product-{}", phase_name(journal.phase));
    descriptor.outcome = match journal.phase {
        ProposalPhase::Complete => "complete".into(),
        ProposalPhase::RolledBack => "complete".into(),
        ProposalPhase::NativeRebootRequired
        | ProposalPhase::NativeRollbackRebootRequired
        | ProposalPhase::LateRollbackRebootRequired
        | ProposalPhase::SystemRebootRequired
        | ProposalPhase::SystemRollbackRebootRequired => "reboot-required".into(),
        _ => "running".into(),
    };
    descriptor.status_sequence = if matches!(descriptor.outcome.as_str(), "complete" | "failed") {
        index * 3
    } else if descriptor.outcome == "reboot-required" {
        index * 3 - 1
    } else {
        index * 3 - 2
    };
    descriptor.reboot_count = u32::from(journal.post_reboot_boot_id.is_some())
        + u32::from(journal.rollback_boot_id.is_some());
    if let Some(boot_id) = journal
        .rollback_boot_id
        .as_ref()
        .or(journal.post_reboot_boot_id.as_ref())
        .or(journal.pre_reboot_boot_id.as_ref())
    {
        descriptor.boot_id.clone_from(boot_id);
    }
    descriptor.journal_sha256 = crate::trust::sha256_bytes(&journal.canonical_bytes()?);
    descriptor.validate()?;
    Ok(descriptor)
}

fn product_boot_id() -> Result<String, String> {
    #[cfg(target_os = "android")]
    {
        crate::operation_contract::current_boot_id()
    }
    #[cfg(not(target_os = "android"))]
    {
        Ok("00000000-0000-0000-0000-000000000001".into())
    }
}

fn product_boot_id_in(root: &Path) -> Result<String, String> {
    #[cfg(target_os = "android")]
    {
        let _ = root;
        crate::operation_contract::current_boot_id()
    }
    #[cfg(not(target_os = "android"))]
    {
        let directory = Directory::open(root).map_err(|error| error.to_string())?;
        let bytes = directory
            .read_trusted("boot-id.host", 37, FILE_MODE)
            .map_err(|error| error.to_string())?;
        let value = std::str::from_utf8(&bytes)
            .map_err(|_| "host boot ID is not UTF-8")?
            .strip_suffix('\n')
            .ok_or("host boot ID lacks newline")?;
        if !canonical_boot_id(value) {
            return Err("host boot ID is invalid".into());
        }
        Ok(value.to_string())
    }
}

fn phase_name(phase: ProposalPhase) -> &'static str {
    match phase {
        ProposalPhase::Copying => "copying",
        ProposalPhase::Pending => "pending",
        ProposalPhase::Reconstructing => "reconstructing",
        ProposalPhase::Reconstructed => "reconstructed",
        ProposalPhase::ApkInstallRequested => "apk-install-requested",
        ProposalPhase::ApkObserved => "apk-observed",
        ProposalPhase::GenerationPrepared => "generation-prepared",
        ProposalPhase::RecoveryPrepared => "recovery-prepared",
        ProposalPhase::RestoreSwitched => "restore-switched",
        ProposalPhase::GenerationSwitched => "generation-switched",
        ProposalPhase::NativePrepared => "native-prepared",
        ProposalPhase::NativeRebootRequired => "native-reboot-required",
        ProposalPhase::NativePostReboot => "native-post-reboot",
        ProposalPhase::NativeRollbackRebootRequired => "native-rollback-reboot-required",
        ProposalPhase::SystemPrepared => "system-prepared",
        ProposalPhase::SystemHelperRequested => "system-helper-requested",
        ProposalPhase::SystemSwitched => "system-switched",
        ProposalPhase::SystemRebootRequired => "system-reboot-required",
        ProposalPhase::SystemPostReboot => "system-post-reboot",
        ProposalPhase::SystemRollbackRebootRequired => "system-rollback-reboot-required",
        ProposalPhase::SystemRollbackPostReboot => "system-rollback-post-reboot",
        ProposalPhase::InventoryPublished => "inventory-published",
        ProposalPhase::ManifestPublished => "manifest-published",
        ProposalPhase::ProductVerified => "product-verified",
        ProposalPhase::LateRollbackRebootRequired => "late-rollback-reboot-required",
        ProposalPhase::Complete => "complete",
        ProposalPhase::RolledBack => "rolled-back",
    }
}

fn prepare_recovery_authority(
    root: &Directory,
    recovery: &Directory,
    complete: &Directory,
    manifest: &voboost_contract::release::Manifest,
    manifest_bytes: &[u8],
    manifest_signature: &[u8],
    prepare_inventory: bool,
) -> Result<(), String> {
    let previous = recovery
        .open_or_create_private_child(PREVIOUS)
        .map_err(|error| error.to_string())?;
    for name in ["restore.json", "restore.json.sig", MANIFEST, SIGNATURE] {
        let mode = if matches!(name, MANIFEST | SIGNATURE) {
            0o600
        } else {
            0o644
        };
        let bytes = root
            .read_trusted(
                name,
                if name.ends_with(".sig") {
                    64
                } else {
                    voboost_contract::release::MAX_MANIFEST_BYTES
                },
                mode,
            )
            .map_err(|error| format!("snapshot active {name}: {error}"))?;
        previous
            .write_atomic(name, &bytes, FILE_MODE)
            .map_err(|error| format!("persist previous {name}: {error}"))?;
    }
    let uninstall = root
        .open_child("uninstall")
        .map_err(|error| error.to_string())?;
    let (inventory_dir, inventory_name) =
        voboost_shared::installed_state::location(root).map_err(|error| error.to_string())?;
    let other_inventory_name = if inventory_name == INVENTORY {
        INSTALLED_STATE
    } else {
        INVENTORY
    };
    if previous
        .entry_exists(other_inventory_name)
        .map_err(|error| error.to_string())?
    {
        return Err("installed state path changed during transaction snapshot".into());
    }
    let inventory = inventory_dir
        .read_trusted(inventory_name, 1024 * 1024, FILE_MODE)
        .map_err(|error| error.to_string())?;
    previous
        .write_atomic(inventory_name, &inventory, FILE_MODE)
        .map_err(|error| error.to_string())?;
    for name in [ARTIFACTS, SYSTEM_STATE] {
        let bytes = uninstall
            .read_trusted(name, 1024 * 1024, FILE_MODE)
            .map_err(|error| format!("read uninstall {name}: {error}"))?;
        previous
            .write_atomic(name, &bytes, FILE_MODE)
            .map_err(|error| format!("snapshot uninstall {name}: {error}"))?;
    }
    let restore = manifest.artifact("restore.json")?;
    let restore_signature = manifest.artifact("restore.json.sig")?;
    let restore_bytes = complete
        .read_trusted("restore.json", restore.size as usize, FILE_MODE)
        .map_err(|error| error.to_string())?;
    let restore_signature_bytes = complete
        .read_trusted(
            "restore.json.sig",
            restore_signature.size as usize,
            FILE_MODE,
        )
        .map_err(|error| error.to_string())?;
    crate::trust::verify_product_restore_authority(
        manifest,
        &restore_bytes,
        &restore_signature_bytes,
    )?;
    if prepare_inventory {
        prepare_uninstall_inventory(
            root,
            &previous,
            manifest,
            manifest_bytes,
            manifest_signature,
            None,
        )?;
    }
    previous.sync_all().map_err(|error| error.to_string())
}

struct SystemInventoryCandidate<'a> {
    init: &'a [u8],
    policy: &'a [u8],
}

fn update_inventory_claim(
    inventory: &mut uninstall_contract::CommittedInventory,
    path: &str,
    bytes: &[u8],
) -> Result<(), String> {
    let claim = inventory
        .documents
        .iter_mut()
        .find(|document| document.path == path)
        .ok_or_else(|| format!("uninstall inventory lacks {path} claim"))?;
    claim.size = bytes.len() as u64;
    claim.sha256 = crate::trust::sha256_bytes(bytes);
    Ok(())
}

fn prepare_uninstall_inventory(
    root: &Directory,
    previous: &Directory,
    manifest: &voboost_contract::release::Manifest,
    manifest_bytes: &[u8],
    manifest_signature: &[u8],
    system_candidate: Option<SystemInventoryCandidate<'_>>,
) -> Result<(), String> {
    let uninstall = root
        .open_child("uninstall")
        .map_err(|error| error.to_string())?;
    let inventory_bytes = voboost_shared::installed_state::read(root, 64 * 1024)
        .map_err(|error| error.to_string())?;
    let artifacts_bytes = uninstall
        .read_trusted(ARTIFACTS, 1024 * 1024, FILE_MODE)
        .map_err(|error| error.to_string())?;
    let baseline = uninstall
        .read_trusted("current-baseline.json", 1024 * 1024, FILE_MODE)
        .map_err(|error| error.to_string())?;
    let policy = uninstall
        .read_trusted("policy.meta.json", 1024 * 1024, FILE_MODE)
        .map_err(|error| error.to_string())?;
    let system_state = uninstall
        .read_trusted(SYSTEM_STATE, 1024 * 1024, FILE_MODE)
        .map_err(|error| error.to_string())?;
    let system = uninstall
        .open_child("system")
        .map_err(|error| error.to_string())?;
    let rc = system
        .read_trusted("voboost.rc", 1024 * 1024, FILE_MODE)
        .map_err(|error| error.to_string())?;
    let current = uninstall_contract::parse_committed_contract(
        &inventory_bytes,
        &artifacts_bytes,
        &baseline,
        &policy,
        &system_state,
        &rc,
    )?;
    let active = load_manifest_from_directory(root)?;
    if current.inventory.version != active.release_identity {
        return Err("uninstall inventory differs from active product manifest".into());
    }
    let mut inventory = current.inventory;
    let mut artifacts = current.artifacts;
    let mut next_system_state = current.system_state;
    let next_rc = if let Some(candidate) = &system_candidate {
        let expected = manifest.artifact("voboost.rc")?;
        if candidate.init.len() as u64 != expected.size
            || crate::trust::sha256_bytes(candidate.init) != expected.sha256
        {
            return Err("candidate init inventory identity differs from manifest".into());
        }
        artifacts.init.installed_size = candidate.init.len() as u64;
        artifacts.init.installed_sha256 = crate::trust::sha256_bytes(candidate.init);
        artifacts.policy.installed_sha256 = crate::trust::sha256_bytes(candidate.policy);
        artifacts.policy.current_baseline_sha256 = current.baseline.policy_sha256.clone();
        next_system_state.init_installed_sha256 = artifacts.init.installed_sha256.clone();
        next_system_state.policy_prior_sha256 = current.baseline.policy_sha256.clone();
        next_system_state.policy_installed_sha256 = artifacts.policy.installed_sha256.clone();
        candidate.init.to_vec()
    } else {
        rc.clone()
    };
    let restore = manifest.artifact("restore.json")?;
    let restore_signature = manifest.artifact("restore.json.sig")?;
    artifacts.native.restore_manifest.size = restore.size;
    artifacts
        .native
        .restore_manifest
        .sha256
        .clone_from(&restore.sha256);
    artifacts.native.restore_manifest.signature_size = restore_signature.size;
    artifacts
        .native
        .restore_manifest
        .signature_sha256
        .clone_from(&restore_signature.sha256);
    artifacts.native.manifest.size = manifest_bytes.len() as u64;
    artifacts.native.manifest.sha256 = crate::trust::sha256_bytes(manifest_bytes);
    artifacts.native.manifest.signature_size = manifest_signature.len() as u64;
    artifacts.native.manifest.signature_sha256 = crate::trust::sha256_bytes(manifest_signature);
    let app = manifest.artifact("voboost-app.apk")?;
    artifacts.package.version_code = app
        .version_code
        .ok_or_else(|| "candidate APK versionCode is absent".to_string())?;
    artifacts.package.apk_size = app.size;
    artifacts.package.apk_sha256.clone_from(&app.sha256);
    artifacts.package.certificate_sha256 = app
        .certificate_sha256
        .clone()
        .ok_or_else(|| "candidate APK certificate is absent".to_string())?;
    let update_signed =
        |target: &mut uninstall_contract::SignedArtifact, name: &str| -> Result<(), String> {
            let artifact = manifest.artifact(name)?;
            target.size = artifact.size;
            target.sha256.clone_from(&artifact.sha256);
            Ok(())
        };
    update_signed(&mut artifacts.native.daemon, "voboost-daemon")?;
    update_signed(&mut artifacts.native.inject, "voboost-inject")?;
    update_signed(&mut artifacts.native.installer, "voboost-install")?;
    update_signed(&mut artifacts.native.restore, "voboost-restore")?;
    update_signed(&mut artifacts.native.uninstaller, "voboost-uninstall")?;
    update_signed(&mut artifacts.native.selinux, "voboost-selinux")?;
    for payload in &mut artifacts.native.payload {
        let name = payload
            .path
            .strip_prefix("/data/voboost/")
            .ok_or_else(|| "uninstall payload path is outside product root".to_string())?;
        let artifact = manifest.artifact(name)?;
        payload.size = artifact.size;
        payload.sha256.clone_from(&artifact.sha256);
    }
    for relay in &mut artifacts.native.qnx {
        let name = relay
            .path
            .strip_prefix("/data/voboost/")
            .ok_or("QNX relay outside product root")?
            .to_string();
        update_signed(relay, &name)?;
    }
    next_system_state.package_version_code = artifacts.package.version_code;
    let next_artifacts = serde_json::to_vec(&artifacts).map_err(|error| error.to_string())?;
    let next_system_state_bytes =
        serde_json::to_vec(&next_system_state).map_err(|error| error.to_string())?;
    for (path, bytes) in [
        (
            uninstall_contract::SYSTEM_ARTIFACTS_PATH,
            next_artifacts.as_slice(),
        ),
        (
            uninstall_contract::CURRENT_BASELINE_PATH,
            baseline.as_slice(),
        ),
        (uninstall_contract::POLICY_META_PATH, policy.as_slice()),
        (
            uninstall_contract::SYSTEM_STATE_PATH,
            next_system_state_bytes.as_slice(),
        ),
        (uninstall_contract::RC_ARCHIVE_PATH, next_rc.as_slice()),
    ] {
        update_inventory_claim(&mut inventory, path, bytes)?;
    }
    inventory.version.clone_from(&manifest.release_identity);
    inventory.committed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs()
        .to_string();
    let next_inventory = serde_json::to_vec(&inventory).map_err(|error| error.to_string())?;
    uninstall_contract::parse_committed_contract(
        &next_inventory,
        &next_artifacts,
        &baseline,
        &policy,
        &next_system_state_bytes,
        &next_rc,
    )?;
    previous
        .write_atomic(NEXT_ARTIFACTS, &next_artifacts, FILE_MODE)
        .and_then(|()| previous.write_atomic(NEXT_BASELINE, &baseline, FILE_MODE))
        .and_then(|()| previous.write_atomic(NEXT_POLICY_META, &policy, FILE_MODE))
        .and_then(|()| {
            previous.write_atomic(NEXT_SYSTEM_STATE, &next_system_state_bytes, FILE_MODE)
        })
        .and_then(|()| previous.write_atomic(NEXT_RC_ARCHIVE, &next_rc, FILE_MODE))
        .and_then(|()| previous.write_atomic(NEXT_INVENTORY, &next_inventory, FILE_MODE))
        .map_err(|error| error.to_string())
}

fn prepare_native_transition(
    root_path: &Path,
    recovery: &Directory,
    complete_path: &Path,
    manifest: &voboost_contract::release::Manifest,
    journal: &mut ProposalJournal,
    lease: &OperationLease,
) -> Result<(), String> {
    let root = Directory::open(root_path).map_err(|error| error.to_string())?;
    let complete = Directory::open(complete_path).map_err(|error| error.to_string())?;
    let manifest_bytes = complete
        .read_trusted(
            MANIFEST,
            voboost_contract::release::MAX_MANIFEST_BYTES,
            FILE_MODE,
        )
        .map_err(|error| error.to_string())?;
    let manifest_signature = complete
        .read_trusted(SIGNATURE, 64, FILE_MODE)
        .map_err(|error| error.to_string())?;
    if plan_requires_generation(journal) {
        let generations =
            crate::generation::GenerationStore::new(root_path, root_path.join("generations/next"));
        let previous = generations.active().map_err(|error| error.to_string())?;
        let next = generations
            .prepare_product_candidate(complete_path, recovery, lease)
            .map_err(|error| format!("{error:#}"))?;
        journal.previous_generation = Some(previous.id);
        journal.next_generation = Some(next.id);
    }
    prepare_recovery_authority(
        &root,
        recovery,
        &complete,
        manifest,
        &manifest_bytes,
        &manifest_signature,
        !journal.system_plan,
    )?;
    prepare_native_authority(&root, recovery, &complete, manifest, &journal.candidate)?;
    journal.pre_reboot_boot_id = Some(product_boot_id_in(root_path)?);
    Ok(())
}

fn prepare_native_authority(
    root: &Directory,
    recovery: &Directory,
    complete: &Directory,
    manifest: &voboost_contract::release::Manifest,
    candidate: &OtaCandidateHandle,
) -> Result<(), String> {
    let previous = recovery
        .open_child(PREVIOUS)
        .map_err(|error| error.to_string())?;
    let active = load_manifest_from_directory(root)?;
    for artifact in changed_native_artifacts(manifest, candidate)? {
        if artifact.file == "voboost.rc" {
            return Err("changed init requires the protected init transaction".into());
        }
        let old = active.artifact(&artifact.file)?;
        let crate::installed_product::InstalledAuthority::RootFlat { mode } =
            crate::installed_product::authority(old)
        else {
            return Err(format!(
                "{} is not root-flat native authority",
                artifact.file
            ));
        };
        root.verify_trusted_digest(&old.file, old.size, &old.sha256, mode)
            .map_err(|error| format!("verify previous {}: {error}", old.file))?;
        let old_bytes = root
            .read_trusted(&old.file, old.size as usize, mode)
            .map_err(|error| error.to_string())?;
        previous
            .write_atomic(&old.file, &old_bytes, FILE_MODE)
            .map_err(|error| error.to_string())?;
        let candidate_bytes = complete
            .read_trusted(&artifact.file, artifact.size as usize, FILE_MODE)
            .map_err(|error| error.to_string())?;
        if let Some(role) = executable_role(&artifact.file) {
            if !crate::native_binary::verify_appended_signature(role, &candidate_bytes) {
                return Err(format!(
                    "candidate executable role signature rejected: {}",
                    artifact.file
                ));
            }
        }
    }
    previous.sync_all().map_err(|error| error.to_string())
}

fn verify_native_candidate_preflight(
    complete: &Directory,
    manifest: &voboost_contract::release::Manifest,
    candidate: &OtaCandidateHandle,
) -> Result<(), String> {
    for artifact in changed_native_artifacts(manifest, candidate)? {
        if artifact.file == "voboost.rc" {
            return Err("changed init requires the protected init transaction".into());
        }
        let bytes = complete
            .read_trusted(&artifact.file, artifact.size as usize, FILE_MODE)
            .map_err(|error| error.to_string())?;
        if let Some(role) = executable_role(&artifact.file) {
            if !crate::native_binary::verify_appended_signature(role, &bytes) {
                return Err(format!(
                    "candidate executable role signature rejected: {}",
                    artifact.file
                ));
            }
        }
    }
    Ok(())
}

fn verify_system_candidate_preflight(
    root_path: &Path,
    complete: &Directory,
    manifest: &voboost_contract::release::Manifest,
    candidate: &OtaCandidateHandle,
) -> Result<(), String> {
    let active = crate::installed_product::load_manifest_in(root_path)?;
    if candidate
        .artifacts
        .iter()
        .any(|artifact| artifact.file == "voboost-restore")
    {
        return Err("system update requires the preinstalled stable restore helper".into());
    }
    let active_restore = active.artifact("voboost-restore")?;
    let candidate_restore = manifest.artifact("voboost-restore")?;
    if active_restore.size != candidate_restore.size
        || active_restore.sha256 != candidate_restore.sha256
    {
        return Err("system update restore helper identity changed".into());
    }
    if candidate
        .artifacts
        .iter()
        .any(|artifact| artifact.file == "voboost-selinux")
    {
        let artifact = manifest.artifact("voboost-selinux")?;
        let bytes = complete
            .read_trusted(&artifact.file, artifact.size as usize, FILE_MODE)
            .map_err(|error| error.to_string())?;
        if !crate::native_binary::verify_appended_signature(
            crate::native_executable_signature::NativeExecutableRole::Selinux,
            &bytes,
        ) {
            return Err("candidate SELinux helper role signature rejected".into());
        }
    }
    Ok(())
}

fn prepare_system_authority(
    root_path: &Path,
    recovery: &Directory,
    complete: &Directory,
    manifest: &voboost_contract::release::Manifest,
    journal: &mut ProposalJournal,
) -> Result<(), String> {
    let previous = recovery
        .open_child(PREVIOUS)
        .map_err(|error| error.to_string())?;
    #[cfg(target_os = "android")]
    let init_path = Path::new("/system/etc/init/voboost.rc");
    #[cfg(not(target_os = "android"))]
    let init_path = root_path.join("system-init.host");
    #[cfg(not(target_os = "android"))]
    let init_path = init_path.as_path();
    #[cfg(target_os = "android")]
    let policy_path = Path::new("/vendor/etc/selinux/precompiled_sepolicy");
    #[cfg(not(target_os = "android"))]
    let policy_path = root_path.join("policy.host");
    #[cfg(not(target_os = "android"))]
    let policy_path = policy_path.as_path();
    let previous_init = read_protected_file(init_path, 1024 * 1024, 0o644)?;
    if !previous_init
        .windows(SYSTEM_HELPER_SERVICE.len())
        .any(|window| window == SYSTEM_HELPER_SERVICE)
        && !previous_init
            .windows(SYSTEM_HELPER_SERVICE_EMULATOR.len())
            .any(|window| window == SYSTEM_HELPER_SERVICE_EMULATOR)
    {
        return Err("installed init lacks the fixed product-system helper service".into());
    }
    let previous_policy = read_protected_file(policy_path, 64 * 1024 * 1024, 0o644)?;
    let candidate_init = if journal
        .candidate
        .artifacts
        .iter()
        .any(|artifact| artifact.file == "voboost.rc")
    {
        let artifact = manifest.artifact("voboost.rc")?;
        complete
            .read_trusted(&artifact.file, artifact.size as usize, FILE_MODE)
            .map_err(|error| error.to_string())?
    } else {
        previous_init.clone()
    };
    let baseline = read_policy_baseline(root_path)?;
    previous
        .write_atomic("system-init-previous", &previous_init, FILE_MODE)
        .and_then(|()| previous.write_atomic("system-init-candidate", &candidate_init, FILE_MODE))
        .and_then(|()| previous.write_atomic("policy-previous", &previous_policy, FILE_MODE))
        .and_then(|()| previous.write_atomic("policy-baseline", &baseline, FILE_MODE))
        .map_err(|error| error.to_string())?;
    let root = Directory::open(root_path).map_err(|error| error.to_string())?;
    let active = crate::installed_product::load_manifest_in(root_path)?;
    for name in ["voboost.rc", "voboost-selinux"] {
        let artifact = active.artifact(name)?;
        let crate::installed_product::InstalledAuthority::RootFlat { mode } =
            crate::installed_product::authority(artifact)
        else {
            return Err(format!(
                "{name} is not root-flat protected-system authority"
            ));
        };
        let bytes = root
            .read_trusted(name, artifact.size as usize, mode)
            .map_err(|error| error.to_string())?;
        if crate::trust::sha256_bytes(&bytes) != artifact.sha256 {
            return Err(format!(
                "previous {name} differs from active product manifest"
            ));
        }
        if name == "voboost.rc" && bytes != previous_init {
            return Err("root init copy differs from protected init hook".into());
        }
        if name == "voboost-selinux"
            && !crate::native_binary::verify_appended_signature(
                crate::native_executable_signature::NativeExecutableRole::Selinux,
                &bytes,
            )
        {
            return Err("installed SELinux helper lacks its role signature".into());
        }
        previous
            .write_atomic(name, &bytes, FILE_MODE)
            .map_err(|error| error.to_string())?;
    }
    previous.sync_all().map_err(|error| error.to_string())?;
    journal.system_init_previous_sha256 = Some(crate::trust::sha256_bytes(&previous_init));
    journal.system_init_candidate_sha256 = Some(crate::trust::sha256_bytes(&candidate_init));
    journal.policy_previous_sha256 = Some(crate::trust::sha256_bytes(&previous_policy));
    journal.policy_baseline_sha256 = Some(crate::trust::sha256_bytes(&baseline));
    journal.policy_candidate_sha256 = None;
    Ok(())
}

fn read_policy_baseline(root_path: &Path) -> Result<Vec<u8>, String> {
    #[cfg(not(target_os = "android"))]
    {
        read_protected_file(
            &root_path.join("policy-baseline.host"),
            64 * 1024 * 1024,
            0o600,
        )
    }
    #[cfg(target_os = "android")]
    {
        let root = Directory::open(root_path).map_err(|error| error.to_string())?;
        let uninstall = root
            .open_child("uninstall")
            .map_err(|error| error.to_string())?;
        let bytes = uninstall
            .read_trusted("current-baseline.json", 1024 * 1024, FILE_MODE)
            .map_err(|error| error.to_string())?;
        let baseline: uninstall_contract::CurrentBaseline = serde_json::from_slice(&bytes)
            .map_err(|error| format!("parse current policy baseline: {error}"))?;
        let expected = uninstall_contract::baseline_backup_path(&baseline.policy_sha256)?;
        if baseline.backup_path != expected {
            return Err("current policy baseline path is not digest-addressed".into());
        }
        let value = read_protected_file(Path::new(&baseline.backup_path), 64 * 1024 * 1024, 0o600)?;
        if crate::trust::sha256_bytes(&value) != baseline.policy_sha256 {
            return Err("OEM policy baseline identity differs".into());
        }
        Ok(value)
    }
}

fn read_protected_file(path: &Path, maximum: usize, mode: u32) -> Result<Vec<u8>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("open protected {}: {error}", path.display()))?;
    let before = file.metadata().map_err(|error| error.to_string())?;
    if !before.file_type().is_file()
        || before.nlink() != 1
        || before.permissions().mode() & 0o7777 != mode
        || before.len() == 0
        || before.len() > maximum as u64
        || (cfg!(target_os = "android") && (before.uid() != 0 || before.gid() != 0))
    {
        return Err(format!("protected {} identity is unsafe", path.display()));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.by_ref()
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let after = file.metadata().map_err(|error| error.to_string())?;
    if bytes.len() as u64 != before.len()
        || (
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
        )
    {
        return Err(format!(
            "protected {} changed while reading",
            path.display()
        ));
    }
    Ok(bytes)
}

fn changed_native_artifacts<'a>(
    manifest: &'a voboost_contract::release::Manifest,
    candidate: &OtaCandidateHandle,
) -> Result<Vec<&'a voboost_contract::release::Artifact>, String> {
    let changed = candidate
        .artifacts
        .iter()
        .map(|artifact| artifact.file.as_str())
        .collect::<BTreeSet<_>>();
    let mut artifacts = manifest
        .artifacts
        .iter()
        .filter(|artifact| {
            changed.contains(artifact.file.as_str())
                && matches!(
                    crate::installed_product::authority(artifact),
                    crate::installed_product::InstalledAuthority::RootFlat { .. }
                )
                && !matches!(artifact.file.as_str(), "restore.json" | "restore.json.sig")
                && !matches!(artifact.file.as_str(), "voboost.rc" | "voboost-selinux")
        })
        .collect::<Vec<_>>();
    artifacts.sort_by_key(|artifact| (artifact.file == "voboost-daemon", artifact.file.as_str()));
    Ok(artifacts)
}

fn executable_role(name: &str) -> Option<crate::native_executable_signature::NativeExecutableRole> {
    use crate::native_executable_signature::NativeExecutableRole;
    match name {
        "voboost-daemon" => Some(NativeExecutableRole::Daemon),
        "voboost-inject" => Some(NativeExecutableRole::Inject),
        "voboost-install" => Some(NativeExecutableRole::Install),
        "voboost-restore" => Some(NativeExecutableRole::Restore),
        "voboost-uninstall" => Some(NativeExecutableRole::Uninstall),
        "voboost-selinux" => Some(NativeExecutableRole::Selinux),
        _ => None,
    }
}

fn switch_native_members(
    root: &Directory,
    complete: &Directory,
    manifest: &voboost_contract::release::Manifest,
    candidate: &OtaCandidateHandle,
    lease: &OperationLease,
    crash_cut: Option<ProductCrashCut>,
) -> Result<(), String> {
    for (index, artifact) in changed_native_artifacts(manifest, candidate)?
        .into_iter()
        .enumerate()
    {
        lease.verify_owner()?;
        let crate::installed_product::InstalledAuthority::RootFlat { mode } =
            crate::installed_product::authority(artifact)
        else {
            return Err("native switch authority changed".into());
        };
        let bytes = complete
            .read_trusted(&artifact.file, artifact.size as usize, FILE_MODE)
            .map_err(|error| error.to_string())?;
        root.write_atomic(&artifact.file, &bytes, mode)
            .map_err(|error| format!("switch native {}: {error}", artifact.file))?;
        maybe_crash(crash_cut, ProductCrashCut::NativeMember(index));
    }
    Ok(())
}

fn verify_running_product(
    root_path: &Path,
    manifest: &voboost_contract::release::Manifest,
) -> Result<(), String> {
    #[cfg(all(target_os = "android", not(test)))]
    {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        let mut owner = crate::owner_client::connect(deadline)
            .map_err(|error| format!("authenticate product runtime owner: {error}"))?;
        let (pid, starttime) = crate::owner_peer::process_identity(&owner)
            .map_err(|error| format!("read product runtime owner identity: {error}"))?;
        let ready = crate::owner_io::request::<voboost_contract::runtime_owner::Outcome>(
            &mut owner,
            voboost_contract::runtime_owner::Command::ReadConfig {},
            deadline,
        )
        .map_err(|error| format!("read product runtime owner: {error}"))?;
        if !matches!(
            ready,
            voboost_contract::runtime_owner::Outcome::Config { .. }
        ) {
            return Err("product runtime owner did not confirm readiness".into());
        }
        verify_running_product_paths(
            root_path,
            manifest,
            &Path::new("/proc").join(pid.to_string()).join("exe"),
            Path::new("/proc/self/exe"),
        )?;
        if crate::owner_peer::process_identity(&owner)
            .map_err(|error| format!("reread product runtime owner identity: {error}"))?
            != (pid, starttime)
        {
            return Err("product runtime owner changed during verification".into());
        }
        Ok(())
    }
    #[cfg(any(not(target_os = "android"), test))]
    verify_running_product_paths(
        root_path,
        manifest,
        &root_path.join("voboost-daemon.host-running"),
        &root_path.join("voboost-inject.host-running"),
    )
}

fn verify_running_product_paths(
    root_path: &Path,
    manifest: &voboost_contract::release::Manifest,
    daemon_path: &Path,
    inject_path: &Path,
) -> Result<(), String> {
    let daemon = manifest.artifact("voboost-daemon")?;
    let size = usize::try_from(daemon.size)
        .map_err(|_| "candidate daemon size overflows host".to_string())?;
    crate::native_binary::verify_running(daemon_path, size, &daemon.sha256)?;

    let inject = manifest.artifact("voboost-inject")?;
    let root = Directory::open(root_path).map_err(|error| format!("open product root: {error}"))?;
    let installed = root
        .open_trusted_file(&inject.file, inject.size, 0o700)
        .and_then(|file| file.metadata())
        .map_err(|error| format!("inspect installed injection host: {error}"))?;
    let running = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(inject_path)
        .and_then(|file| file.metadata())
        .map_err(|error| format!("inspect running injection host: {error}"))?;
    if (running.dev(), running.ino()) != (installed.dev(), installed.ino()) {
        return Err("running injection host differs from installed executable".into());
    }
    Ok(())
}

fn publish_restore_pair(
    root: &Directory,
    complete: &Directory,
    manifest: &voboost_contract::release::Manifest,
    lease: &OperationLease,
    crash_cut: Option<ProductCrashCut>,
) -> Result<(), String> {
    for name in ["restore.json.sig", "restore.json"] {
        lease.verify_owner()?;
        let artifact = manifest.artifact(name)?;
        let bytes = complete
            .read_trusted(name, artifact.size as usize, FILE_MODE)
            .map_err(|error| error.to_string())?;
        root.write_atomic(name, &bytes, 0o644)
            .map_err(|error| format!("publish {name}: {error}"))?;
        if name == "restore.json.sig" {
            maybe_crash(crash_cut, ProductCrashCut::RestoreSignature);
        }
    }
    Ok(())
}

fn inventory_snapshot_name(previous: &Directory) -> Result<&'static str, String> {
    let canonical = previous
        .entry_exists(INSTALLED_STATE)
        .map_err(|error| error.to_string())?;
    let legacy = previous
        .entry_exists(INVENTORY)
        .map_err(|error| error.to_string())?;
    match (canonical, legacy) {
        (true, false) => Ok(INSTALLED_STATE),
        (false, true) => Ok(INVENTORY),
        _ => Err("transaction must contain exactly one installed state snapshot".into()),
    }
}

fn publish_uninstall_inventory(
    root: &Directory,
    recovery: &Directory,
    crash_cut: Option<ProductCrashCut>,
) -> Result<(), String> {
    let previous = recovery
        .open_child(PREVIOUS)
        .map_err(|error| error.to_string())?;
    let uninstall = root
        .open_child("uninstall")
        .map_err(|error| error.to_string())?;
    for (source, target) in [
        (NEXT_ARTIFACTS, ARTIFACTS),
        (NEXT_BASELINE, "current-baseline.json"),
        (NEXT_POLICY_META, "policy.meta.json"),
        (NEXT_SYSTEM_STATE, SYSTEM_STATE),
    ] {
        let bytes = previous
            .read_trusted(source, 1024 * 1024, FILE_MODE)
            .map_err(|error| error.to_string())?;
        uninstall
            .write_atomic(target, &bytes, FILE_MODE)
            .map_err(|error| error.to_string())?;
        if target == ARTIFACTS {
            maybe_crash(crash_cut, ProductCrashCut::InventoryArtifacts);
        }
    }
    let system = uninstall
        .open_child("system")
        .map_err(|error| error.to_string())?;
    let rc = previous
        .read_trusted(NEXT_RC_ARCHIVE, 1024 * 1024, FILE_MODE)
        .map_err(|error| error.to_string())?;
    system
        .write_atomic("voboost.rc", &rc, FILE_MODE)
        .map_err(|error| error.to_string())?;
    let inventory = previous
        .read_trusted(NEXT_INVENTORY, 64 * 1024, FILE_MODE)
        .map_err(|error| error.to_string())?;
    voboost_shared::installed_state::replace(root, inventory_snapshot_name(&previous)?, &inventory)
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn publish_product_manifest(
    root: &Directory,
    complete: &Directory,
    lease: &OperationLease,
    crash_cut: Option<ProductCrashCut>,
) -> Result<(), String> {
    for name in [SIGNATURE, MANIFEST] {
        lease.verify_owner()?;
        let bytes = complete
            .read_trusted(
                name,
                if name == SIGNATURE {
                    64
                } else {
                    voboost_contract::release::MAX_MANIFEST_BYTES
                },
                FILE_MODE,
            )
            .map_err(|error| error.to_string())?;
        root.write_atomic(name, &bytes, 0o600)
            .map_err(|error| format!("publish {name}: {error}"))?;
        if name == SIGNATURE {
            maybe_crash(crash_cut, ProductCrashCut::ManifestSignature);
        }
    }
    Ok(())
}

fn maybe_crash(requested: Option<ProductCrashCut>, current: ProductCrashCut) {
    if requested == Some(current) {
        panic!("injected product activation crash after {current:?}");
    }
}

fn rollback_generation_only(
    root_path: &Path,
    root: &Directory,
    recovery: &Directory,
    journal: &mut ProposalJournal,
    lease: &OperationLease,
) -> Result<(), String> {
    let previous = recovery
        .open_child(PREVIOUS)
        .map_err(|error| error.to_string())?;
    let previous_generation = journal
        .previous_generation
        .as_deref()
        .ok_or_else(|| "rollback generation identity is absent".to_string())?;
    crate::generation::GenerationStore::new(root_path, root_path.join("generations/next"))
        .rollback_product_candidate(previous_generation, recovery, lease)
        .map_err(|error| error.to_string())?;
    for name in ["restore.json.sig", "restore.json"] {
        lease.verify_owner()?;
        let bytes = previous
            .read_trusted(
                name,
                voboost_contract::release::MAX_MANIFEST_BYTES,
                FILE_MODE,
            )
            .map_err(|error| error.to_string())?;
        root.write_atomic(name, &bytes, 0o644)
            .map_err(|error| error.to_string())?;
    }
    let uninstall = root
        .open_child("uninstall")
        .map_err(|error| error.to_string())?;
    let inventory_name = inventory_snapshot_name(&previous)?;
    for name in [ARTIFACTS, SYSTEM_STATE, inventory_name] {
        lease.verify_owner()?;
        let bytes = previous
            .read_trusted(name, 1024 * 1024, FILE_MODE)
            .map_err(|error| error.to_string())?;
        if name == inventory_name {
            voboost_shared::installed_state::replace(root, inventory_name, &bytes)
        } else {
            uninstall.write_atomic(name, &bytes, FILE_MODE)
        }
        .map_err(|error| error.to_string())?;
    }
    for name in [SIGNATURE, MANIFEST] {
        lease.verify_owner()?;
        let bytes = previous
            .read_trusted(
                name,
                if name == SIGNATURE {
                    64
                } else {
                    voboost_contract::release::MAX_MANIFEST_BYTES
                },
                FILE_MODE,
            )
            .map_err(|error| error.to_string())?;
        root.write_atomic(name, &bytes, FILE_MODE)
            .map_err(|error| error.to_string())?;
    }
    let active = crate::installed_product::load_manifest_in(root_path)?;
    crate::installed_product::verify_candidate_closure_in(&active, true, root_path)?;
    verify_uninstall_inventory(root, &active)?;
    journal.failure = Some("product activation rolled back".into());
    transition(recovery, lease, journal, ProposalPhase::RolledBack)
}

fn rollback_native_product(
    root_path: &Path,
    root: &Directory,
    recovery: &Directory,
    manifest: &voboost_contract::release::Manifest,
    candidate: &OtaCandidateHandle,
    journal: &mut ProposalJournal,
    lease: &OperationLease,
) -> Result<Admission, String> {
    let previous = recovery
        .open_child(PREVIOUS)
        .map_err(|error| error.to_string())?;
    if plan_requires_generation(journal) {
        let previous_generation = journal
            .previous_generation
            .as_deref()
            .ok_or_else(|| "rollback generation identity is absent".to_string())?;
        crate::generation::GenerationStore::new(root_path, root_path.join("generations/next"))
            .rollback_product_candidate(previous_generation, recovery, lease)
            .map_err(|error| error.to_string())?;
    }
    for artifact in changed_native_artifacts(manifest, candidate)? {
        lease.verify_owner()?;
        let crate::installed_product::InstalledAuthority::RootFlat { mode } =
            crate::installed_product::authority(artifact)
        else {
            return Err("native rollback authority changed".into());
        };
        let bytes = previous
            .read_trusted(
                &artifact.file,
                crate::config::MAX_NATIVE_EXECUTABLE_BYTES,
                FILE_MODE,
            )
            .map_err(|error| error.to_string())?;
        root.write_atomic(&artifact.file, &bytes, mode)
            .map_err(|error| error.to_string())?;
    }
    for name in ["restore.json.sig", "restore.json"] {
        let bytes = previous
            .read_trusted(
                name,
                voboost_contract::release::MAX_MANIFEST_BYTES,
                FILE_MODE,
            )
            .map_err(|error| error.to_string())?;
        root.write_atomic(name, &bytes, 0o644)
            .map_err(|error| error.to_string())?;
    }
    let uninstall = root
        .open_child("uninstall")
        .map_err(|error| error.to_string())?;
    let inventory_name = inventory_snapshot_name(&previous)?;
    for name in [ARTIFACTS, SYSTEM_STATE, inventory_name] {
        let bytes = previous
            .read_trusted(name, 1024 * 1024, FILE_MODE)
            .map_err(|error| error.to_string())?;
        if name == inventory_name {
            voboost_shared::installed_state::replace(root, inventory_name, &bytes)
        } else {
            uninstall.write_atomic(name, &bytes, FILE_MODE)
        }
        .map_err(|error| error.to_string())?;
    }
    for name in [SIGNATURE, MANIFEST] {
        let bytes = previous
            .read_trusted(
                name,
                if name == SIGNATURE {
                    64
                } else {
                    voboost_contract::release::MAX_MANIFEST_BYTES
                },
                FILE_MODE,
            )
            .map_err(|error| error.to_string())?;
        root.write_atomic(name, &bytes, FILE_MODE)
            .map_err(|error| error.to_string())?;
    }
    if journal.post_reboot_boot_id.is_some() {
        // A late rollback is discovered only after the candidate was durably
        // published past the native-rollback projection slot. Rewinding the
        // observer projection there is forbidden by the monotonic guard (and
        // would wedge the operation), so a durable post-reboot rollback at
        // InventoryPublished or later publishes forward at the monotone
        // late-rollback slot instead.
        let late_rollback = matches!(
            journal.phase,
            ProposalPhase::InventoryPublished
                | ProposalPhase::ManifestPublished
                | ProposalPhase::ProductVerified
        );
        transition(
            recovery,
            lease,
            journal,
            if late_rollback {
                ProposalPhase::LateRollbackRebootRequired
            } else {
                ProposalPhase::NativeRollbackRebootRequired
            },
        )?;
        return Ok(Admission::RebootRequired);
    }
    let active = crate::installed_product::load_manifest_in(root_path)?;
    crate::installed_product::verify_candidate_closure_in(&active, true, root_path)?;
    verify_uninstall_inventory(root, &active)?;
    journal.failure = Some("product activation rolled back".into());
    transition(recovery, lease, journal, ProposalPhase::RolledBack)?;
    Ok(Admission::ActivationFailed)
}

fn rollback_system_common(
    root_path: &Path,
    root: &Directory,
    recovery: &Directory,
    manifest: &voboost_contract::release::Manifest,
    candidate: &OtaCandidateHandle,
    journal: &ProposalJournal,
    lease: &OperationLease,
) -> Result<bool, String> {
    if plan_requires_apk(journal) && !previous_apk_restored(root_path, recovery)? {
        return Ok(false);
    }
    let previous = recovery
        .open_child(PREVIOUS)
        .map_err(|error| error.to_string())?;
    let active = crate::installed_product::load_manifest_in(root_path)?;
    if active.digest()? == manifest.digest()? {
        return Err("candidate manifest was published before protected-system verification".into());
    }
    let artifacts = changed_native_artifacts(manifest, candidate)?;
    for artifact in &artifacts {
        let Some(context) =
            voboost_contract::product_update::system_rollback_context(&artifact.file)
        else {
            continue;
        };
        lease.verify_owner()?;
        let old = previous
            .read_trusted(
                &artifact.file,
                crate::config::MAX_NATIVE_EXECUTABLE_BYTES,
                FILE_MODE,
            )
            .map_err(|error| format!("read previous {}: {error}", artifact.file))?;
        let current = root
            .read_trusted_snapshot(
                &artifact.file,
                crate::config::MAX_NATIVE_EXECUTABLE_BYTES,
                0o700,
                context,
            )
            .map_err(|error| format!("read installed {}: {error}", artifact.file))?;
        if current.bytes != old {
            return Ok(false);
        }
    }
    if plan_requires_generation(journal) {
        let previous_generation = journal
            .previous_generation
            .as_deref()
            .ok_or_else(|| "rollback generation identity is absent".to_string())?;
        crate::generation::GenerationStore::new(root_path, root_path.join("generations/next"))
            .rollback_product_candidate(previous_generation, recovery, lease)
            .map_err(|error| error.to_string())?;
    }
    for artifact in artifacts {
        if voboost_contract::product_update::system_rollback_context(&artifact.file).is_some() {
            continue;
        }
        lease.verify_owner()?;
        let crate::installed_product::InstalledAuthority::RootFlat { mode } =
            crate::installed_product::authority(artifact)
        else {
            return Err("system rollback native authority changed".into());
        };
        let bytes = previous
            .read_trusted(
                &artifact.file,
                crate::config::MAX_NATIVE_EXECUTABLE_BYTES,
                FILE_MODE,
            )
            .map_err(|error| error.to_string())?;
        root.write_atomic(&artifact.file, &bytes, mode)
            .map_err(|error| error.to_string())?;
    }
    for name in ["restore.json.sig", "restore.json"] {
        lease.verify_owner()?;
        let bytes = previous
            .read_trusted(
                name,
                voboost_contract::release::MAX_MANIFEST_BYTES,
                FILE_MODE,
            )
            .map_err(|error| error.to_string())?;
        root.write_atomic(name, &bytes, 0o644)
            .map_err(|error| error.to_string())?;
    }
    Ok(true)
}

fn verify_uninstall_inventory(
    root: &Directory,
    manifest: &voboost_contract::release::Manifest,
) -> Result<(), String> {
    let uninstall = root
        .open_child("uninstall")
        .map_err(|error| error.to_string())?;
    let inventory = voboost_shared::installed_state::read(root, 64 * 1024)
        .map_err(|error| error.to_string())?;
    let artifacts = uninstall
        .read_trusted(ARTIFACTS, 1024 * 1024, FILE_MODE)
        .map_err(|error| error.to_string())?;
    let baseline = uninstall
        .read_trusted("current-baseline.json", 1024 * 1024, FILE_MODE)
        .map_err(|error| error.to_string())?;
    let policy = uninstall
        .read_trusted("policy.meta.json", 1024 * 1024, FILE_MODE)
        .map_err(|error| error.to_string())?;
    let state = uninstall
        .read_trusted("system-state.json", 1024 * 1024, FILE_MODE)
        .map_err(|error| error.to_string())?;
    let system = uninstall
        .open_child("system")
        .map_err(|error| error.to_string())?;
    let rc = system
        .read_trusted("voboost.rc", 1024 * 1024, FILE_MODE)
        .map_err(|error| error.to_string())?;
    let committed = uninstall_contract::parse_committed_contract(
        &inventory, &artifacts, &baseline, &policy, &state, &rc,
    )?;
    if committed.inventory.version != manifest.release_identity
        || committed.artifacts.native.manifest.sha256 != manifest.digest()?
    {
        return Err("uninstall inventory is not bound to active product manifest".into());
    }
    Ok(())
}

fn load_manifest_from_directory(
    root: &Directory,
) -> Result<voboost_contract::release::Manifest, String> {
    let bytes = root
        .read_trusted(
            MANIFEST,
            voboost_contract::release::MAX_MANIFEST_BYTES,
            FILE_MODE,
        )
        .map_err(|error| error.to_string())?;
    let signature = root
        .read_trusted(SIGNATURE, 64, FILE_MODE)
        .map_err(|error| error.to_string())?;
    voboost_contract::release::verify_manifest_signature(
        &bytes,
        &signature,
        &crate::trust::release_catalog_public_key(),
    )
}

fn read_terminal_result(
    root_path: &Path,
    candidate: &OtaCandidateHandle,
) -> Result<Option<Admission>, String> {
    let Some(operation) = crate::operation_contract::read_current_in(root_path)? else {
        return Ok(None);
    };
    if operation.operation != Operation::Update
        || operation.transaction_id != candidate.transaction_id
    {
        return Ok(None);
    }
    if operation.outcome != "complete" {
        return Ok(None);
    }
    let root = Directory::open(root_path).map_err(|error| error.to_string())?;
    for parent in [INSTALL_ROOT, RECOVERY_ROOT] {
        if let Ok(directory) = root.open_child(parent) {
            if directory
                .entry_exists(&candidate.transaction_id)
                .map_err(|error| error.to_string())?
            {
                return Ok(None);
            }
        }
    }
    let bytes = root
        .read_trusted(
            MANIFEST,
            voboost_contract::release::MAX_MANIFEST_BYTES,
            FILE_MODE,
        )
        .map_err(|error| error.to_string())?;
    let signature = root
        .read_trusted(SIGNATURE, 64, FILE_MODE)
        .map_err(|error| error.to_string())?;
    let manifest = voboost_contract::release::verify_manifest_signature(
        &bytes,
        &signature,
        &crate::trust::release_catalog_public_key(),
    )?;
    if operation.phase == "update-product-rolled-back" {
        crate::installed_product::verify_candidate_closure_in(&manifest, true, root_path)?;
        verify_uninstall_inventory(&root, &manifest)?;
        return Ok(Some(Admission::ActivationFailed));
    }
    if manifest.digest()? == candidate.manifest_sha256
        && manifest.release_identity == candidate.release_identity
    {
        Ok(Some(Admission::Accepted))
    } else {
        Ok(Some(Admission::TransactionCollision))
    }
}

fn cleanup_product_transaction(
    root: &Directory,
    install_root: &Directory,
    recovery_root: &Directory,
    _install_tx: &Directory,
    _recovery_tx: &Directory,
    manifest: &voboost_contract::release::Manifest,
    candidate: &OtaCandidateHandle,
) -> Result<(), String> {
    // Persist the exact terminal WAL before deleting its transaction directory.
    // Keep the receipt outside the directory-only recovery transaction inventory.
    let bytes = match _recovery_tx.read_trusted(JOURNAL, MAX_STATUS_BYTES, FILE_MODE) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => root
            .read_trusted(TERMINAL_RECEIPT, MAX_STATUS_BYTES, FILE_MODE)
            .map_err(|error| error.to_string())?,
        Err(error) => return Err(error.to_string()),
    };
    let journal = ProposalJournal::parse(&bytes)?;
    if journal.candidate != *candidate
        || !matches!(
            journal.phase,
            ProposalPhase::Complete | ProposalPhase::RolledBack
        )
    {
        return Err("product cleanup requires an exact terminal journal".into());
    }
    root.write_atomic(TERMINAL_RECEIPT, &bytes, FILE_MODE)
        .map_err(|error| error.to_string())?;
    if install_root
        .entry_exists(&candidate.transaction_id)
        .map_err(|error| error.to_string())?
    {
        let install_tx = install_root
            .open_child(&candidate.transaction_id)
            .map_err(|error| error.to_string())?;
        if install_tx
            .entry_exists(CANDIDATE)
            .map_err(|error| error.to_string())?
        {
            let directory = install_tx
                .open_child(CANDIDATE)
                .map_err(|error| error.to_string())?;
            for name in candidate
                .artifacts
                .iter()
                .map(|artifact| artifact.file.as_str())
                .chain([MANIFEST, SIGNATURE])
            {
                unlink_optional(&directory, name)?;
            }
            directory.sync_all().map_err(|error| error.to_string())?;
            install_tx
                .remove_child_dir(CANDIDATE)
                .map_err(|error| error.to_string())?;
        }
        if install_tx
            .entry_exists(COMPLETE_CANDIDATE)
            .map_err(|error| error.to_string())?
        {
            let directory = install_tx
                .open_child(COMPLETE_CANDIDATE)
                .map_err(|error| error.to_string())?;
            for name in manifest
                .artifacts
                .iter()
                .map(|artifact| artifact.file.as_str())
                .chain(
                    candidate
                        .artifacts
                        .iter()
                        .map(|artifact| artifact.file.as_str()),
                )
                .chain([MANIFEST, SIGNATURE])
            {
                unlink_optional(&directory, name)?;
            }
            directory.sync_all().map_err(|error| error.to_string())?;
            install_tx
                .remove_child_dir(COMPLETE_CANDIDATE)
                .map_err(|error| error.to_string())?;
        }
        install_tx.sync_all().map_err(|error| error.to_string())?;
        install_root
            .remove_child_dir(&candidate.transaction_id)
            .map_err(|error| error.to_string())?;
    }
    install_root.sync_all().map_err(|error| error.to_string())?;

    if recovery_root
        .entry_exists(&candidate.transaction_id)
        .map_err(|error| error.to_string())?
    {
        let recovery_tx = recovery_root
            .open_child(&candidate.transaction_id)
            .map_err(|error| error.to_string())?;
        if recovery_tx
            .entry_exists(PREVIOUS)
            .map_err(|error| error.to_string())?
        {
            let previous = recovery_tx
                .open_child(PREVIOUS)
                .map_err(|error| error.to_string())?;
            for name in [
                "restore.json",
                "restore.json.sig",
                MANIFEST,
                SIGNATURE,
                INVENTORY,
                INSTALLED_STATE,
                ARTIFACTS,
                SYSTEM_STATE,
                NEXT_INVENTORY,
                NEXT_ARTIFACTS,
                NEXT_BASELINE,
                NEXT_POLICY_META,
                NEXT_SYSTEM_STATE,
                NEXT_RC_ARCHIVE,
                "policy-baseline",
                "policy-previous",
                "policy-candidate",
                "system-init-previous",
                "system-init-candidate",
            ] {
                unlink_optional(&previous, name)?;
            }
            let classes = activation_classes(candidate)?;
            if is_native_plan(candidate, &classes)
                || voboost_contract::product_update::is_system_plan(candidate, &classes)
            {
                for artifact in changed_native_artifacts(manifest, candidate)? {
                    unlink_optional(&previous, &artifact.file)?;
                }
            }
            if voboost_contract::product_update::is_system_plan(
                candidate,
                &activation_classes(candidate)?,
            ) {
                for name in ["voboost.rc", "voboost-selinux", "voboost-app.apk"] {
                    unlink_optional(&previous, name)?;
                }
            }
            previous.sync_all().map_err(|error| error.to_string())?;
            recovery_tx
                .remove_child_dir(PREVIOUS)
                .map_err(|error| error.to_string())?;
        }
        for name in [
            crate::generation::PRODUCT_NEXT_PLAN_FILE,
            crate::generation::PRODUCT_PREVIOUS_PLAN_FILE,
            voboost_contract::system_update::SYSTEM_SWITCH_ACK,
            voboost_contract::system_update::SYSTEM_POST_BOOT_ACK,
            voboost_contract::system_update::SYSTEM_FAILURE_ACK,
            voboost_contract::system_update::SYSTEM_ROLLBACK_ACK,
            voboost_contract::system_update::POLICY_PREPARE_ACK,
            JOURNAL,
        ] {
            unlink_optional(&recovery_tx, name)?;
        }
        recovery_tx.sync_all().map_err(|error| error.to_string())?;
        recovery_root
            .remove_child_dir(&candidate.transaction_id)
            .map_err(|error| error.to_string())?;
    }
    recovery_root.sync_all().map_err(|error| error.to_string())
}

pub(crate) fn terminal_acknowledgement_in(
    root_path: &Path,
) -> Result<Option<voboost_contract::status::TerminalAcknowledgement>, String> {
    use voboost_contract::status::{TerminalAcknowledgement, TerminalOutcome};
    let Some(operation) = crate::operation_contract::read_current_in(root_path)? else {
        return Ok(None);
    };
    if operation.operation != Operation::Update || operation.outcome != "complete" {
        return Ok(None);
    }
    let root = Directory::open(root_path).map_err(|error| error.to_string())?;
    let bytes = match root.read_trusted(TERMINAL_RECEIPT, MAX_STATUS_BYTES, FILE_MODE) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    if crate::trust::sha256_bytes(&bytes) != operation.journal_sha256 {
        return Ok(None);
    }
    let journal = ProposalJournal::parse(&bytes)?;
    if operation.transaction_id != journal.candidate.transaction_id {
        return Ok(None);
    }
    for parent in [INSTALL_ROOT, RECOVERY_ROOT] {
        if let Ok(directory) = root.open_child(parent) {
            if directory
                .entry_exists(&operation.transaction_id)
                .map_err(|error| error.to_string())?
            {
                return Ok(None);
            }
        }
    }
    let outcome = match journal.phase {
        ProposalPhase::Complete if operation.phase == "update-product-complete" => {
            let manifest = load_manifest_from_directory(&root)?;
            if manifest.release_identity != journal.candidate.release_identity
                || manifest.digest()? != journal.candidate.manifest_sha256
            {
                return Ok(None);
            }
            TerminalOutcome::Complete
        }
        ProposalPhase::RolledBack if operation.phase == "update-product-rolled-back" => {
            TerminalOutcome::Rejected
        }
        _ => return Ok(None),
    };
    Ok(Some(TerminalAcknowledgement {
        transaction_id: journal.candidate.transaction_id,
        release_identity: journal.candidate.release_identity,
        manifest_sha256: journal.candidate.manifest_sha256,
        outcome,
    }))
}

fn retire_unactivated_candidate(
    install_root: &Directory,
    recovery_root: &Directory,
    install_tx: &Directory,
    recovery_tx: &Directory,
    manifest: &voboost_contract::release::Manifest,
    candidate: &OtaCandidateHandle,
) -> Result<(), String> {
    for (name, members) in [
        (
            CANDIDATE,
            candidate
                .artifacts
                .iter()
                .map(|artifact| artifact.file.as_str())
                .chain([MANIFEST, SIGNATURE])
                .collect::<Vec<_>>(),
        ),
        (
            COMPLETE_CANDIDATE,
            manifest
                .artifacts
                .iter()
                .map(|artifact| artifact.file.as_str())
                .chain([MANIFEST, SIGNATURE])
                .collect::<Vec<_>>(),
        ),
    ] {
        let directory = install_tx
            .open_child(name)
            .map_err(|error| error.to_string())?;
        for member in members {
            unlink_optional(&directory, member)?;
        }
        directory.sync_all().map_err(|error| error.to_string())?;
        install_tx
            .remove_child_dir(name)
            .map_err(|error| error.to_string())?;
    }
    unlink_optional(recovery_tx, JOURNAL)?;
    unlink_optional(recovery_tx, JOURNAL_TEMP)?;
    install_tx.sync_all().map_err(|error| error.to_string())?;
    recovery_tx.sync_all().map_err(|error| error.to_string())?;
    install_root
        .remove_child_dir(&candidate.transaction_id)
        .map_err(|error| error.to_string())?;
    recovery_root
        .remove_child_dir(&candidate.transaction_id)
        .map_err(|error| error.to_string())?;
    install_root.sync_all().map_err(|error| error.to_string())?;
    recovery_root.sync_all().map_err(|error| error.to_string())
}

fn unlink_optional(directory: &Directory, name: &str) -> Result<(), String> {
    match directory.unlink(name) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(not(target_os = "android"))]
fn canonical_boot_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
            }
        })
}

fn reconstruct_complete(
    root_path: &Path,
    install_tx: &Directory,
    changed_dir: &Directory,
    candidate: &voboost_contract::release::Manifest,
    origin: &ProductUpdateOrigin,
) -> Result<(), String> {
    let active = crate::installed_product::load_manifest_in(root_path)?;
    let active_version =
        semver::Version::parse(&active.release_identity).map_err(|e| e.to_string())?;
    let candidate_version =
        semver::Version::parse(&candidate.release_identity).map_err(|e| e.to_string())?;
    let same_channel = candidate_version.pre.is_empty() == active_version.pre.is_empty();
    let version_allowed = match origin {
        // Automatic OTA admission stays strictly newer in the active channel.
        ProductUpdateOrigin::Ota => candidate_version > active_version,
        // An explicit offline update applies different content at an equal
        // SemVer in the same channel; a lower SemVer is always rejected.
        ProductUpdateOrigin::OfflineExplicit { .. } => candidate_version >= active_version,
    };
    if !version_allowed || !same_channel {
        return Err(match origin {
            ProductUpdateOrigin::Ota => {
                "product candidate is not newer in the active channel".to_string()
            }
            ProductUpdateOrigin::OfflineExplicit { .. } => "offline product candidate is below the active version or changes the release channel".to_string(),
        });
    }
    let complete = install_tx
        .open_or_create_private_child(COMPLETE_CANDIDATE)
        .map_err(|e| format!("open complete product candidate: {e}"))?;
    for name in [MANIFEST, SIGNATURE] {
        let size = if name == MANIFEST {
            candidate.canonical_bytes()?.len() as u64
        } else {
            64
        };
        let source = changed_dir
            .open_trusted_file(name, size, FILE_MODE)
            .map_err(|e| e.to_string())?;
        complete
            .write_atomic_from_descriptor(
                name,
                source.as_raw_fd(),
                size,
                &crate::trust::sha256_bytes(
                    &changed_dir
                        .read_trusted(name, size as usize, FILE_MODE)
                        .map_err(|e| e.to_string())?,
                ),
                FILE_MODE,
            )
            .map_err(|e| e.to_string())?;
    }
    let changed = changed_dir
        .entry_names_bounded(candidate.artifacts.len() + 3)
        .map_err(|e| e.to_string())?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let root = Directory::open(root_path).map_err(|e| e.to_string())?;
    let generation =
        crate::generation::GenerationStore::new(root_path, root_path.join("generations/next"))
            .active()
            .map_err(|e| e.to_string())?;
    for artifact in &candidate.artifacts {
        let source = if changed.contains(&artifact.file) {
            changed_dir
                .open_trusted_file(&artifact.file, artifact.size, FILE_MODE)
                .map_err(|e| e.to_string())?
        } else {
            let previous = active.artifact(&artifact.file)?;
            if previous.size != artifact.size || previous.sha256 != artifact.sha256 {
                return Err(format!(
                    "unchanged artifact identity differs for {}",
                    artifact.file
                ));
            }
            match crate::installed_product::authority(artifact) {
                crate::installed_product::InstalledAuthority::RootFlat { mode } => root
                    .open_trusted_file(&artifact.file, artifact.size, mode)
                    .map_err(|e| format!("open unchanged root {}: {e}", artifact.file))?,
                crate::installed_product::InstalledAuthority::ActiveGeneration => {
                    Directory::open(&generation.directory)
                        .and_then(|d| d.open_trusted_file(&artifact.file, artifact.size, 0o444))
                        .map_err(|e| format!("open unchanged generation {}: {e}", artifact.file))?
                }
                crate::installed_product::InstalledAuthority::InstalledApk => {
                    let authority =
                        crate::installed_product::installed_package_authority_in(root_path)?;
                    if authority.apk_size != artifact.size
                        || authority.apk_sha256 != artifact.sha256
                    {
                        return Err("installed APK identity differs".into());
                    }
                    #[cfg(target_os = "android")]
                    {
                        let path = crate::installed_apk::observe_installed_apk(
                            artifact.size,
                            &artifact.sha256,
                        )?;
                        OpenOptions::new()
                            .read(true)
                            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                            .open(path)
                            .map_err(|e| e.to_string())?
                    }
                    #[cfg(not(target_os = "android"))]
                    {
                        root.open_trusted_file(
                            "voboost-app.apk.host-observed",
                            artifact.size,
                            FILE_MODE,
                        )
                        .map_err(|e| format!("open host-observed APK: {e}"))?
                    }
                }
            }
        };
        complete
            .write_atomic_from_descriptor(
                &artifact.file,
                source.as_raw_fd(),
                artifact.size,
                &artifact.sha256,
                FILE_MODE,
            )
            .map_err(|e| format!("reconstruct {}: {e}", artifact.file))?;
    }
    complete.sync_all().map_err(|e| e.to_string())?;
    verify_complete(&complete, candidate)
}

fn verify_complete(
    directory: &Directory,
    manifest: &voboost_contract::release::Manifest,
) -> Result<(), String> {
    let expected = manifest
        .artifacts
        .iter()
        .map(|a| a.file.clone())
        .chain([MANIFEST.to_string(), SIGNATURE.to_string()])
        .collect::<BTreeSet<_>>();
    let actual = directory
        .entry_names_bounded(expected.len() + 1)
        .map_err(|e| e.to_string())?
        .into_iter()
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err("complete product candidate inventory differs".into());
    }
    let manifest_bytes = directory
        .read_trusted(
            MANIFEST,
            voboost_contract::release::MAX_MANIFEST_BYTES,
            FILE_MODE,
        )
        .map_err(|e| e.to_string())?;
    let signature = directory
        .read_trusted(SIGNATURE, 64, FILE_MODE)
        .map_err(|e| e.to_string())?;
    let reparsed = voboost_contract::release::verify_manifest_signature(
        &manifest_bytes,
        &signature,
        &crate::trust::release_catalog_public_key(),
    )?;
    if &reparsed != manifest
        || reparsed.digest()? != manifest.digest()?
        || reparsed.release_identity != manifest.release_identity
    {
        return Err("complete product candidate manifest differs from WAL authority".into());
    }
    for artifact in &manifest.artifacts {
        directory
            .verify_trusted_digest(&artifact.file, artifact.size, &artifact.sha256, FILE_MODE)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn recover_unpublished_journal(
    recovery_tx: &Directory,
    candidate: &OtaCandidateHandle,
) -> Result<ProposalJournal, String> {
    let names = recovery_tx
        .entry_names_bounded(2)
        .map_err(|error| format!("enumerate incomplete product proposal journal: {error}"))?;
    if names.iter().any(|name| name != JOURNAL_TEMP) {
        return Err("recovery transaction is not a product proposal".into());
    }
    if names.iter().any(|name| name == JOURNAL_TEMP) {
        if let Ok(bytes) = recovery_tx.read_trusted(JOURNAL_TEMP, MAX_STATUS_BYTES, FILE_MODE) {
            if let Ok(existing) = ProposalJournal::parse(&bytes) {
                if existing.candidate != *candidate {
                    return Ok(existing);
                }
                recovery_tx
                    .rename(JOURNAL_TEMP, JOURNAL)
                    .map_err(|error| format!("recover product proposal journal rename: {error}"))?;
                recovery_tx
                    .sync_all()
                    .map_err(|error| format!("recover product proposal journal sync: {error}"))?;
                return Ok(existing);
            }
        }
        recovery_tx
            .unlink(JOURNAL_TEMP)
            .map_err(|error| format!("remove incomplete product proposal journal: {error}"))?;
        recovery_tx
            .sync_all()
            .map_err(|error| format!("sync incomplete product proposal cleanup: {error}"))?;
    }
    let journal = ProposalJournal::new(candidate);
    write_journal(recovery_tx, &journal)?;
    Ok(journal)
}

fn count_durable_proposals(recovery: &Directory) -> Result<usize, String> {
    let mut count = 0;
    for name in recovery
        .entry_names_bounded(257)
        .map_err(|error| format!("enumerate product recovery root: {error}"))?
    {
        let transaction = match recovery.open_child(&name) {
            Ok(transaction) => transaction,
            Err(error) if error.kind() == std::io::ErrorKind::NotADirectory => continue,
            Err(error) => return Err(format!("open durable product proposal: {error}")),
        };
        let bytes = match transaction.read_trusted(JOURNAL, MAX_STATUS_BYTES, FILE_MODE) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("read durable product proposal: {error}")),
        };
        let journal = ProposalJournal::parse(&bytes)?;
        if journal.candidate.transaction_id != name {
            return Err("product proposal directory and WAL identity differ".into());
        }
        count += 1;
    }
    Ok(count)
}

fn write_journal(directory: &Directory, journal: &ProposalJournal) -> Result<(), String> {
    directory
        .write_atomic(JOURNAL, &journal.canonical_bytes()?, FILE_MODE)
        .map_err(|error| format!("write product proposal journal: {error}"))
}

/// True when a descriptor-originated product proposal owns shared transaction
/// space. Other privileged operations must not interpret, clean or replace its
/// candidate/WAL.
pub(crate) fn durable_proposal_present(root_zone: &str) -> Result<bool, String> {
    let root = match Directory::open(Path::new(root_zone)) {
        Ok(root) => root,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("open product proposal root: {error}")),
    };
    let recovery = match root.open_child(RECOVERY_ROOT) {
        Ok(recovery) => recovery,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("open product proposal recovery root: {error}")),
    };
    recovery
        .validate_owner_mode(
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o700,
        )
        .map_err(|error| format!("validate product proposal recovery root: {error}"))?;
    for transaction_id in recovery
        .entry_names_bounded(MAX_DURABLE_PROPOSALS + 1)
        .map_err(|error| format!("enumerate product proposal recovery root: {error}"))?
    {
        let transaction = recovery
            .open_child(&transaction_id)
            .map_err(|error| format!("open product proposal transaction: {error}"))?;
        let bytes = match transaction.read_trusted(JOURNAL, MAX_STATUS_BYTES, FILE_MODE) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("read product proposal transaction: {error}")),
        };
        // Strict product recovery validates the schema and directory binding.
        // This read only establishes that the product operation owns the space.
        let _ = bytes;
        return Ok(true);
    }
    Ok(false)
}

pub(crate) fn pending_apk_peer_authority(
) -> Result<Option<voboost_contract::release::Artifact>, String> {
    pending_apk_peer_authority_in(Path::new(crate::config::ROOT_ZONE))
}

/// Deterministic transaction identity for an explicit offline product update:
/// bound to the exact candidate manifest content, so repeating the same
/// operator intent re-enters the same durable transaction idempotently
/// instead of creating a second proposal.
fn offline_update_transaction_id(manifest_sha256: &str) -> String {
    crate::trust::sha256_bytes(format!("voboost-offline-update-v1:{manifest_sha256}").as_bytes())
}

/// Admission entry for the explicit offline product update from the host
/// installer. The staged transaction directory must contain exactly the
/// signed candidate closure (manifest, signature, and every artifact the
/// manifest names); descriptors are verified against the release trust root
/// before admission, and the operator's expected-active content identity is
/// enforced against the live active manifest before any mutation.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConsumedOfflineStage {
    schema_version: u32,
    stage_transaction_id: String,
    operation_transaction_id: String,
    manifest_sha256: String,
    terminal: bool,
}
impl ConsumedOfflineStage {
    fn for_candidate(stage: &str, candidate: &OtaCandidateHandle) -> Self {
        Self {
            schema_version: 1,
            stage_transaction_id: stage.into(),
            operation_transaction_id: candidate.transaction_id.clone(),
            manifest_sha256: candidate.manifest_sha256.clone(),
            terminal: false,
        }
    }
    fn matches(&self, stage: &str, candidate: &OtaCandidateHandle) -> bool {
        let mut expected = Self::for_candidate(stage, candidate);
        expected.terminal = self.terminal;
        *self == expected
    }
}
pub(crate) fn prepare_offline_stage(stage: &str) -> Result<(), String> {
    prepare_offline_stage_in(Path::new(crate::config::ROOT_ZONE), stage)
}
fn prepare_offline_stage_in(root_path: &Path, stage: &str) -> Result<(), String> {
    if !voboost_contract::release::lower_hash(stage) {
        return Err("offline stage must be lowercase hex64".into());
    }
    let guard = GenerationGuard::acquire_in(root_path)?;
    reject_cluster_uninstall(root_path)?;
    let root = Directory::open(root_path).map_err(|e| e.to_string())?;
    root.validate_owner_not_writable(unsafe { libc::geteuid() }, unsafe { libc::getegid() })
        .map_err(|e| e.to_string())?;
    let staging = root
        .open_or_create_private_child(OFFLINE_STAGING_ROOT)
        .map_err(|e| e.to_string())?;
    for name in staging
        .entry_names_bounded(257)
        .map_err(|e| e.to_string())?
    {
        let sibling = staging.open_child(&name).map_err(|e| e.to_string())?;
        sibling
            .validate_owner_mode(
                unsafe { libc::geteuid() },
                unsafe { libc::getegid() },
                0o700,
            )
            .map_err(|e| e.to_string())?;
        if name == stage {
            if !sibling
                .entry_names_bounded(1)
                .map_err(|e| e.to_string())?
                .is_empty()
            {
                return Err("requested offline stage already contains recoverable input".into());
            }
            continue;
        }
        if !voboost_contract::release::lower_hash(&name) {
            return Err("foreign offline stage".into());
        }
        let mut receipt: Option<ConsumedOfflineStage> = if sibling
            .entry_exists(".consumed.json")
            .map_err(|e| e.to_string())?
        {
            Some(
                serde_json::from_slice(
                    &sibling
                        .read_trusted(".consumed.json", 1024, FILE_MODE)
                        .map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?,
            )
        } else {
            None
        };
        let bytes = sibling
            .read_trusted(
                MANIFEST,
                voboost_contract::release::MAX_MANIFEST_BYTES,
                FILE_MODE,
            )
            .map_err(|e| e.to_string())?;
        let signature = sibling
            .read_trusted(SIGNATURE, 64, FILE_MODE)
            .map_err(|e| e.to_string())?;
        let manifest = voboost_contract::release::verify_manifest_signature(
            &bytes,
            &signature,
            &crate::trust::release_catalog_public_key(),
        )?;
        let manifest_sha256 = manifest.digest()?;
        if let Some(receipt) = &receipt {
            if receipt.schema_version != 1
                || receipt.stage_transaction_id != name
                || !voboost_contract::release::lower_hash(&receipt.operation_transaction_id)
                || receipt.manifest_sha256 != manifest_sha256
            {
                return Err("consumed stage authority binding differs".into());
            }
        }
        let mut expected: BTreeSet<String> =
            manifest.artifacts.iter().map(|a| a.file.clone()).collect();
        expected.extend([MANIFEST.into(), SIGNATURE.into()]);
        if receipt.is_some() {
            expected.insert(".consumed.json".into());
        }
        let actual = sibling
            .entry_names_bounded(expected.len() + 1)
            .map_err(|e| e.to_string())?
            .into_iter()
            .collect::<BTreeSet<_>>();
        if actual != expected {
            return Err("consumed stage signed closure differs".into());
        }
        for artifact in &manifest.artifacts {
            sibling
                .verify_trusted_digest(&artifact.file, artifact.size, &artifact.sha256, FILE_MODE)
                .map_err(|e| e.to_string())?;
        }
        if let Some(receipt) = receipt.as_mut() {
            if !receipt.terminal {
                let operation = crate::operation_contract::read_current_in(root_path)?
                    .ok_or("consumed stage lifecycle unproven")?;
                if operation.operation != Operation::Update
                    || operation.transaction_id != receipt.operation_transaction_id
                    || operation.outcome != "complete"
                {
                    return Err("consumed stage lifecycle is not terminal".into());
                }
                receipt.terminal = true;
                sibling
                    .write_atomic(
                        ".consumed.json",
                        &serde_json::to_vec(&receipt).map_err(|e| e.to_string())?,
                        FILE_MODE,
                    )
                    .map_err(|e| e.to_string())?;
            }
        } else {
            // A complete upload can precede admission. Keep its entire signed
            // closure, but never bypass an operation still running or failed:
            // it may own recovery state even without a consumption receipt.
            if crate::operation_contract::read_current_in(root_path)?
                .is_some_and(|operation| operation.outcome != "complete")
            {
                return Err("unconsumed stage lifecycle is not idle".into());
            }
        }
    }
    guard.verify_owner()?;
    staging
        .open_or_create_private_child(stage)
        .map_err(|e| e.to_string())?;
    guard.verify_owner()
}

pub(crate) fn apply_offline_product(
    expected_active_manifest_sha256: &str,
    staged_transaction_id: &str,
) -> Result<Admission, String> {
    apply_offline_product_in(
        &ProductCandidateStore::production(),
        Path::new(crate::config::ROOT_ZONE),
        expected_active_manifest_sha256,
        staged_transaction_id,
    )
}

fn apply_offline_product_in(
    store: &ProductCandidateStore,
    root_path: &Path,
    expected_active_manifest_sha256: &str,
    staged_transaction_id: &str,
) -> Result<Admission, String> {
    apply_offline_product_mode_in(
        store,
        root_path,
        expected_active_manifest_sha256,
        staged_transaction_id,
        false,
    )
}

// The system-update worker executes the installed restore helper. A reapply
// may retain that exact signed authority, but cannot replace its own worker.
fn verify_reapply_restore_authority(
    root: &Directory,
    active: &voboost_contract::release::Manifest,
    candidate: &voboost_contract::release::Manifest,
) -> Result<(), String> {
    let previous = active.artifact("voboost-restore")?;
    let next = candidate.artifact("voboost-restore")?;
    if previous.size != next.size || previous.sha256 != next.sha256 {
        return Err("reinstall requires the preinstalled stable restore helper".into());
    }
    let bytes = root
        .read_trusted("voboost-restore", previous.size as usize, 0o700)
        .map_err(|error| format!("read reinstall restore authority: {error}"))?;
    if crate::trust::sha256_bytes(&bytes) != previous.sha256
        || !crate::native_binary::verify_appended_signature(
            crate::native_executable_signature::NativeExecutableRole::Restore,
            &bytes,
        )
    {
        return Err("installed reinstall restore authority failed verification".into());
    }
    Ok(())
}

pub(crate) fn reapply_offline_product(expected: &str, stage: &str) -> Result<Admission, String> {
    apply_offline_product_mode_in(
        &ProductCandidateStore::production(),
        Path::new(crate::config::ROOT_ZONE),
        expected,
        stage,
        true,
    )
}
fn apply_offline_product_mode_in(
    store: &ProductCandidateStore,
    root_path: &Path,
    expected_active_manifest_sha256: &str,
    staged_transaction_id: &str,
    reapply: bool,
) -> Result<Admission, String> {
    if reapply && !voboost_contract::release::lower_hash(staged_transaction_id) {
        return Err("reapply stage transaction must be lowercase hex64".into());
    }
    if expected_active_manifest_sha256.len() != 64
        || !expected_active_manifest_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("expected active manifest sha256 is invalid".into());
    }
    if staged_transaction_id.is_empty()
        || staged_transaction_id.len() > 128
        || staged_transaction_id
            .bytes()
            .any(|byte| byte == b'/' || byte == b'\0' || byte.is_ascii_control())
    {
        return Err("staged transaction id is invalid".into());
    }
    let root = Directory::open(root_path).map_err(|error| format!("open product root: {error}"))?;
    let staging_root = root
        .open_or_create_private_child(OFFLINE_STAGING_ROOT)
        .map_err(|error| format!("open offline staging root: {error}"))?;
    if reapply
        && !staging_root
            .entry_exists(staged_transaction_id)
            .map_err(|e| e.to_string())?
    {
        let recovery = root
            .open_child(RECOVERY_ROOT)
            .and_then(|d| d.open_child(staged_transaction_id))
            .map_err(|e| {
                format!("reapply staged closure and retained transaction unavailable: {e}")
            })?;
        let journal = ProposalJournal::parse(
            &recovery
                .read_trusted(JOURNAL, MAX_STATUS_BYTES, FILE_MODE)
                .map_err(|e| e.to_string())?,
        )?;
        let expected_origin = ProductUpdateOrigin::OfflineExplicit {
            expected_active_manifest_sha256: expected_active_manifest_sha256.to_string(),
        };
        if journal.origin != expected_origin
            || journal.candidate.transaction_id != staged_transaction_id
            || journal.phase == ProposalPhase::Copying
        {
            return Err("reapply transaction lacks matching durable admission".into());
        }
        if let Some(result) = read_terminal_result(root_path, &journal.candidate)? {
            return Ok(result);
        }
        if let Some(active) = crate::operation_contract::read_document_in(root_path)? {
            if active.transaction_id != staged_transaction_id && active.outcome != "complete" {
                return Err("operation busy".into());
            }
        }
        return store
            .recover_product_activation()?
            .ok_or_else(|| "retained reapply transaction unavailable".into());
    }
    let staged = staging_root
        .open_child(staged_transaction_id)
        .map_err(|error| format!("open staged offline closure: {error}"))?;
    let manifest_bytes = staged
        .read_trusted(
            MANIFEST,
            voboost_contract::release::MAX_MANIFEST_BYTES,
            FILE_MODE,
        )
        .map_err(|error| format!("read staged product manifest: {error}"))?;
    let manifest = voboost_contract::release::Manifest::parse(&manifest_bytes)?;
    let manifest_sha256 = manifest.digest()?;
    // The staged closure is complete, but the activation plan is derived from
    // the changed subset: artifacts whose trusted identity differs from the
    // active manifest (or that the active manifest does not name). Unchanged
    // artifacts are reused from their installed authorities by trusted hash.
    // Reapply refreshes every member except its verified, retained system
    // transaction worker; that helper cannot replace itself during execution.
    let active_manifest = crate::installed_product::load_manifest_in(root_path)?;
    if reapply {
        verify_reapply_restore_authority(&root, &active_manifest, &manifest)?;
    }
    let candidate = OtaCandidateHandle {
        transaction_id: if reapply {
            staged_transaction_id.to_string()
        } else {
            offline_update_transaction_id(&manifest_sha256)
        },
        release_identity: manifest.release_identity.clone(),
        manifest_sha256: manifest_sha256.clone(),
        artifacts: manifest
            .artifacts
            .iter()
            .filter(|artifact| {
                (reapply && artifact.file != "voboost-restore")
                    || active_manifest.artifact(&artifact.file).is_err()
                    || active_manifest
                        .artifact(&artifact.file)
                        .is_ok_and(|previous| {
                            previous.size != artifact.size || previous.sha256 != artifact.sha256
                        })
            })
            .map(
                |artifact| voboost_contract::status::CandidateArtifactIdentity {
                    file: artifact.file.clone(),
                    size: artifact.size,
                    sha256: artifact.sha256.clone(),
                },
            )
            .collect(),
    };
    let mut expected_names: BTreeSet<String> = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.file.clone())
        .collect();
    expected_names.insert(MANIFEST.to_string());
    expected_names.insert(SIGNATURE.to_string());
    let mut terminal_receipt = false;
    if staged
        .entry_exists(".consumed.json")
        .map_err(|e| e.to_string())?
    {
        let receipt: ConsumedOfflineStage = serde_json::from_slice(
            &staged
                .read_trusted(".consumed.json", 1024, FILE_MODE)
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        if !receipt.matches(staged_transaction_id, &candidate) {
            return Err("consumed offline stage receipt binding differs".into());
        }
        terminal_receipt = receipt.terminal;
        expected_names.insert(".consumed.json".into());
    }
    let actual_names = staged
        .entry_names_bounded(expected_names.len() + 1)
        .map_err(|error| format!("enumerate staged offline closure: {error}"))?
        .into_iter()
        .collect::<BTreeSet<_>>();
    if actual_names != expected_names {
        return Err("staged offline closure differs from the signed manifest".into());
    }
    let signature_len = staged
        .metadata_trusted(SIGNATURE, FILE_MODE)
        .map_err(|error| format!("stat staged signature: {error}"))?
        .1;
    if signature_len != 64 {
        return Err("staged voboost.json.sig must contain exactly 64 bytes".into());
    }
    let mut descriptors = Vec::new();
    let manifest_file = staged
        .open_trusted_file(MANIFEST, manifest_bytes.len() as u64, FILE_MODE)
        .map_err(|error| format!("open staged product manifest: {error}"))?;
    let signature_file = staged
        .open_trusted_file(SIGNATURE, 64, FILE_MODE)
        .map_err(|error| format!("open staged product signature: {error}"))?;
    for artifact in &candidate.artifacts {
        descriptors.push((
            artifact.file.clone(),
            artifact.size,
            artifact.sha256.clone(),
            staged
                .open_trusted_file(&artifact.file, artifact.size, FILE_MODE)
                .map_err(|error| format!("open staged artifact {}: {error}", artifact.file))?,
        ));
    }
    let handoff = CandidateDescriptorHandoff {
        manifest_fd: manifest_file.as_raw_fd(),
        signature_fd: signature_file.as_raw_fd(),
        artifacts: descriptors
            .iter()
            .map(|(file, size, sha256, file_handle)| {
                voboost_contract::status::CandidateArtifactDescriptor {
                    fd: file_handle.as_raw_fd(),
                    file: file.clone(),
                    size: *size,
                    sha256: sha256.clone(),
                }
            })
            .collect(),
    };
    let verified = handoff
        .verify_open_descriptors(&candidate, &crate::trust::release_catalog_public_key())
        .map_err(|error| format!("staged offline closure verification: {error}"))?;
    if terminal_receipt {
        let guard = GenerationGuard::acquire_in(root_path)?;
        if crate::installed_product::load_manifest_in(root_path)?.digest()?
            != expected_active_manifest_sha256
        {
            return Err("active product content changed since offline inspection".into());
        }
        guard.verify_owner()?;
        return Ok(Admission::Accepted);
    }
    let origin = ProductUpdateOrigin::OfflineExplicit {
        expected_active_manifest_sha256: expected_active_manifest_sha256.to_string(),
    };
    let admission = store.admit(&candidate, &verified, &handoff, &origin)?;
    if matches!(
        admission,
        Admission::Pending
            | Admission::Accepted
            | Admission::InstallApk
            | Admission::RebootRequired
    ) {
        // Receipt is written only after the verified closure is durably retained by admission.
        // Preserve stage bytes for recovery; this marker never authorizes an activation.
        let receipt = ConsumedOfflineStage::for_candidate(staged_transaction_id, &candidate);
        staged
            .write_atomic(
                ".consumed.json",
                &serde_json::to_vec(&receipt).map_err(|e| e.to_string())?,
                FILE_MODE,
            )
            .map_err(|e| e.to_string())?;
    }
    Ok(admission)
}

pub(crate) fn reboot_required() -> bool {
    crate::operation_contract::read_current_in(Path::new(crate::config::ROOT_ZONE))
        .ok()
        .flatten()
        .is_some_and(|operation| {
            operation.operation == Operation::Update
                && operation.outcome == "reboot-required"
                && operation.journal.ends_with("/product-proposal.json")
        })
}

pub(crate) fn authorize_reboot() -> Result<bool, String> {
    authorize_reboot_in(Path::new(crate::config::ROOT_ZONE))
}

fn authorize_reboot_in(root_path: &Path) -> Result<bool, String> {
    let Some(operation) = crate::operation_contract::read_current_in(root_path)? else {
        return Ok(false);
    };
    if operation.operation != Operation::Update
        || operation.outcome != "reboot-required"
        || !operation.journal.ends_with("/product-proposal.json")
    {
        return Ok(false);
    }
    let root = Directory::open(root_path).map_err(|error| error.to_string())?;
    let recovery = root
        .open_child(RECOVERY_ROOT)
        .and_then(|directory| directory.open_child(&operation.transaction_id))
        .map_err(|error| error.to_string())?;
    let journal = ProposalJournal::parse(
        &recovery
            .read_trusted(JOURNAL, MAX_STATUS_BYTES, FILE_MODE)
            .map_err(|error| error.to_string())?,
    )?;
    if journal.candidate.transaction_id != operation.transaction_id
        || !matches!(
            journal.phase,
            ProposalPhase::NativeRebootRequired
                | ProposalPhase::NativeRollbackRebootRequired
                | ProposalPhase::SystemRebootRequired
                | ProposalPhase::SystemRollbackRebootRequired
        )
    {
        return Err("product reboot WAL authority is invalid".into());
    }
    let expected_boot = match journal.phase {
        ProposalPhase::NativeRebootRequired => journal.pre_reboot_boot_id.as_deref(),
        ProposalPhase::NativeRollbackRebootRequired => journal.post_reboot_boot_id.as_deref(),
        ProposalPhase::SystemRebootRequired => journal.pre_reboot_boot_id.as_deref(),
        ProposalPhase::SystemRollbackRebootRequired => journal.post_reboot_boot_id.as_deref(),
        _ => None,
    }
    .ok_or_else(|| "product reboot boot ID authority is absent".to_string())?;
    if product_boot_id_in(root_path)? != expected_boot {
        return Err("product reboot request is not on its authorized boot".into());
    }
    Ok(true)
}

fn read_system_switch_ack(
    recovery: &Directory,
) -> Result<Option<voboost_contract::system_update::SystemSwitchAck>, String> {
    match recovery.read_trusted(
        voboost_contract::system_update::SYSTEM_SWITCH_ACK,
        voboost_contract::system_update::MAX_SYSTEM_ACK_BYTES,
        FILE_MODE,
    ) {
        Ok(bytes) => voboost_contract::system_update::SystemSwitchAck::parse(&bytes).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

fn read_policy_prepare_ack(
    recovery: &Directory,
) -> Result<Option<voboost_contract::system_update::PolicyPrepareAck>, String> {
    match recovery.read_trusted(
        voboost_contract::system_update::POLICY_PREPARE_ACK,
        voboost_contract::system_update::MAX_SYSTEM_ACK_BYTES,
        FILE_MODE,
    ) {
        Ok(bytes) => voboost_contract::system_update::PolicyPrepareAck::parse(&bytes).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

fn read_system_post_boot_ack(
    recovery: &Directory,
) -> Result<Option<voboost_contract::system_update::SystemPostBootAck>, String> {
    match recovery.read_trusted(
        voboost_contract::system_update::SYSTEM_POST_BOOT_ACK,
        voboost_contract::system_update::MAX_SYSTEM_ACK_BYTES,
        FILE_MODE,
    ) {
        Ok(bytes) => voboost_contract::system_update::SystemPostBootAck::parse(&bytes).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

fn read_system_failure_ack(
    recovery: &Directory,
) -> Result<Option<voboost_contract::system_update::SystemFailureAck>, String> {
    match recovery.read_trusted(
        voboost_contract::system_update::SYSTEM_FAILURE_ACK,
        voboost_contract::system_update::MAX_SYSTEM_ACK_BYTES,
        FILE_MODE,
    ) {
        Ok(bytes) => voboost_contract::system_update::SystemFailureAck::parse(&bytes).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

fn verify_system_failure(
    journal: &ProposalJournal,
    ack: &voboost_contract::system_update::SystemFailureAck,
    phase: &str,
    reboot_required: bool,
) -> Result<(), String> {
    if ack.transaction_id != journal.candidate.transaction_id
        || ack.phase != phase
        || ack.reboot_required != reboot_required
        || (phase == "system-post-reboot"
            && Some(ack.boot_id.as_str()) != journal.post_reboot_boot_id.as_deref())
        || (phase != "system-post-reboot"
            && Some(ack.boot_id.as_str()) != journal.pre_reboot_boot_id.as_deref())
    {
        Err("system failure receipt differs from product WAL".into())
    } else {
        Ok(())
    }
}

fn read_system_rollback_ack(
    recovery: &Directory,
) -> Result<Option<voboost_contract::system_update::SystemRollbackAck>, String> {
    match recovery.read_trusted(
        voboost_contract::system_update::SYSTEM_ROLLBACK_ACK,
        voboost_contract::system_update::MAX_SYSTEM_ACK_BYTES,
        FILE_MODE,
    ) {
        Ok(bytes) => voboost_contract::system_update::SystemRollbackAck::parse(&bytes).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

fn start_system_helper() -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        use std::ffi::CString;
        unsafe extern "C" {
            fn __system_property_set(
                name: *const libc::c_char,
                value: *const libc::c_char,
            ) -> libc::c_int;
        }
        let name = CString::new("ctl.start").map_err(|error| error.to_string())?;
        let value = CString::new("voboost-system-update").map_err(|error| error.to_string())?;
        if unsafe { __system_property_set(name.as_ptr(), value.as_ptr()) } != 0 {
            return Err("ctl.start voboost-system-update failed".into());
        }
    }
    Ok(())
}

fn pending_apk_peer_authority_in(
    root_path: &Path,
) -> Result<Option<voboost_contract::release::Artifact>, String> {
    let root = match Directory::open(root_path) {
        Ok(root) => root,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let recovery = match root.open_child(RECOVERY_ROOT) {
        Ok(recovery) => recovery,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let mut authority = None;
    for transaction_id in recovery
        .entry_names_bounded(257)
        .map_err(|error| error.to_string())?
    {
        let transaction = match recovery.open_child(&transaction_id) {
            Ok(transaction) => transaction,
            Err(error) if error.kind() == std::io::ErrorKind::NotADirectory => continue,
            Err(error) => return Err(error.to_string()),
        };
        let bytes = match transaction.read_trusted(JOURNAL, MAX_STATUS_BYTES, FILE_MODE) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.to_string()),
        };
        let journal = ProposalJournal::parse(&bytes)?;
        if !journal.apk_only
            || journal.candidate.transaction_id != transaction_id
            || matches!(
                journal.phase,
                ProposalPhase::Copying
                    | ProposalPhase::Pending
                    | ProposalPhase::Reconstructing
                    | ProposalPhase::Reconstructed
                    | ProposalPhase::Complete
                    | ProposalPhase::RolledBack
            )
        {
            continue;
        }
        if authority.is_some() {
            return Err("multiple APK product authorities are active".into());
        }
        let complete = root
            .open_child(INSTALL_ROOT)
            .and_then(|install| install.open_child(&transaction_id))
            .and_then(|install| install.open_child(COMPLETE_CANDIDATE))
            .map_err(|error| error.to_string())?;
        let manifest_bytes = complete
            .read_trusted(
                MANIFEST,
                voboost_contract::release::MAX_MANIFEST_BYTES,
                FILE_MODE,
            )
            .map_err(|error| error.to_string())?;
        let signature = complete
            .read_trusted(SIGNATURE, 64, FILE_MODE)
            .map_err(|error| error.to_string())?;
        let manifest = voboost_contract::release::verify_manifest_signature(
            &manifest_bytes,
            &signature,
            &crate::trust::release_catalog_public_key(),
        )?;
        if manifest.digest()? != journal.candidate.manifest_sha256
            || manifest.release_identity != journal.candidate.release_identity
        {
            return Err("pending APK peer authority differs from product WAL".into());
        }
        authority = Some(manifest.artifact("voboost-app.apk")?.clone());
    }
    Ok(authority)
}

fn verify_candidate_directory(
    directory: &Directory,
    candidate: &OtaCandidateHandle,
    verified: &VerifiedDescriptorCandidate,
) -> Result<(), String> {
    let expected = std::iter::once(MANIFEST.to_string())
        .chain(std::iter::once(SIGNATURE.to_string()))
        .chain(
            candidate
                .artifacts
                .iter()
                .map(|artifact| artifact.file.clone()),
        )
        .collect::<BTreeSet<_>>();
    let actual = directory
        .entry_names_bounded(expected.len() + 1)
        .map_err(|error| format!("enumerate product candidate: {error}"))?
        .into_iter()
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err("root-owned product candidate inventory differs".into());
    }
    require_bytes(directory, MANIFEST, verified.manifest_bytes())?;
    require_bytes(directory, SIGNATURE, verified.signature_bytes())?;
    for identity in &candidate.artifacts {
        directory
            .verify_trusted_digest(&identity.file, identity.size, &identity.sha256, FILE_MODE)
            .map_err(|error| {
                format!(
                    "verify persisted product candidate {}: {error}",
                    identity.file
                )
            })?;
    }
    Ok(())
}

fn verify_durable_candidate(
    directory: &Directory,
    candidate: &OtaCandidateHandle,
) -> Result<voboost_contract::release::Manifest, String> {
    let manifest_bytes = directory
        .read_trusted(
            MANIFEST,
            voboost_contract::release::MAX_MANIFEST_BYTES,
            FILE_MODE,
        )
        .map_err(|error| error.to_string())?;
    let signature = directory
        .read_trusted(SIGNATURE, 64, FILE_MODE)
        .map_err(|error| error.to_string())?;
    let manifest = voboost_contract::release::verify_manifest_signature(
        &manifest_bytes,
        &signature,
        &crate::trust::release_catalog_public_key(),
    )?;
    if manifest.digest()? != candidate.manifest_sha256
        || manifest.release_identity != candidate.release_identity
    {
        return Err("durable candidate identity differs from WAL".into());
    }
    let expected = candidate
        .artifacts
        .iter()
        .map(|artifact| artifact.file.clone())
        .chain([MANIFEST.to_string(), SIGNATURE.to_string()])
        .collect::<BTreeSet<_>>();
    let actual = directory
        .entry_names_bounded(expected.len() + 1)
        .map_err(|error| error.to_string())?
        .into_iter()
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err("durable candidate inventory differs from WAL".into());
    }
    for artifact in &candidate.artifacts {
        directory
            .verify_trusted_digest(&artifact.file, artifact.size, &artifact.sha256, FILE_MODE)
            .map_err(|error| error.to_string())?;
    }
    Ok(manifest)
}

fn require_bytes(directory: &Directory, name: &str, expected: &[u8]) -> Result<(), String> {
    let maximum = expected.len();
    let actual = directory
        .read_trusted(name, maximum, FILE_MODE)
        .map_err(|error| format!("verify persisted product candidate {name}: {error}"))?;
    if actual != expected {
        return Err(format!("persisted product candidate {name} differs"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_receipt_survives_cleanup_and_rejects_staging_or_tampering() {
        let fixture = product_fixture();
        let store = ProductCandidateStore {
            root: fixture.root.clone(),
            reconstruct: true,
        };
        assert!(terminal_acknowledgement_in(&fixture.root)
            .unwrap()
            .is_none());
        for _ in 0..20 {
            if continue_generation_only(&fixture.root, &fixture.candidate).unwrap()
                == Admission::Accepted
            {
                break;
            }
        }
        let receipt = terminal_acknowledgement_in(&fixture.root)
            .unwrap()
            .expect("cleaned update must replay its exact terminal identity");
        assert_eq!(receipt.transaction_id, fixture.candidate.transaction_id);
        assert_eq!(receipt.manifest_sha256, fixture.candidate.manifest_sha256);
        assert_eq!(receipt.release_identity, fixture.candidate.release_identity);
        assert_eq!(
            receipt.outcome,
            voboost_contract::status::TerminalOutcome::Complete
        );
        // Discovery must ignore the retained regular receipt file.
        assert_eq!(store.recover_product_activation().unwrap(), None);
        assert!(!durable_proposal_present(fixture.root.to_str().unwrap()).unwrap());
        store.ensure_idle_for_uninstall().unwrap();
        // Reproduce cleanup interruption after removing the WAL, including a
        // partially cleaned install closure. Recovery uses the retained exact
        // terminal receipt under the same operation lock.
        for partial_install in [false, true] {
            let root = Directory::open(&fixture.root).unwrap();
            root.open_child(RECOVERY_ROOT)
                .unwrap()
                .open_or_create_private_child(&fixture.candidate.transaction_id)
                .unwrap();
            if partial_install {
                let install = root
                    .open_child(INSTALL_ROOT)
                    .unwrap()
                    .open_or_create_private_child(&fixture.candidate.transaction_id)
                    .unwrap();
                let complete = install
                    .open_or_create_private_child(COMPLETE_CANDIDATE)
                    .unwrap();
                complete
                    .write_atomic("voboost-app.apk", b"remaining staged artifact", FILE_MODE)
                    .unwrap();
            }
            assert_eq!(
                store.recover_product_activation().unwrap(),
                Some(Admission::Accepted)
            );
            assert!(terminal_acknowledgement_in(&fixture.root)
                .unwrap()
                .is_some());
            store.ensure_idle_for_uninstall().unwrap();
        }
        let staged = fixture
            .root
            .join(INSTALL_ROOT)
            .join(&fixture.candidate.transaction_id);
        std::fs::create_dir(&staged).unwrap();
        assert!(terminal_acknowledgement_in(&fixture.root)
            .unwrap()
            .is_none());
        std::fs::remove_dir(staged).unwrap();
        let root = Directory::open(&fixture.root).unwrap();
        root.write_atomic(TERMINAL_RECEIPT, b"changed receipt", FILE_MODE)
            .unwrap();
        assert!(terminal_acknowledgement_in(&fixture.root)
            .unwrap()
            .is_none());
    }

    struct ProductFixture {
        _active: crate::generation::test_support::TestZones,
        _candidate: crate::generation::test_support::TestZones,
        root: PathBuf,
        candidate: OtaCandidateHandle,
        candidate_generation_id: String,
    }

    struct ApkFixture {
        _active: crate::generation::test_support::TestZones,
        root: PathBuf,
        candidate: OtaCandidateHandle,
        old_manifest_sha256: String,
        old_restore: Vec<u8>,
        new_apk: Vec<u8>,
        new_version_code: u64,
        new_certificate_sha256: String,
    }

    struct NativeFixture {
        _active: crate::generation::test_support::TestZones,
        _candidate: Option<crate::generation::test_support::TestZones>,
        root: PathBuf,
        candidate: OtaCandidateHandle,
        native_members: usize,
        old_manifest_sha256: String,
        old_daemon: Vec<u8>,
        new_daemon: Vec<u8>,
        new_apk: Option<(Vec<u8>, u64, String)>,
        candidate_generation_id: String,
    }

    struct SystemFixture {
        _base: ProductFixture,
        root: PathBuf,
        candidate: OtaCandidateHandle,
        old_manifest_sha256: String,
        daemon: Vec<u8>,
        init_candidate: Vec<u8>,
        selinux_candidate: Vec<u8>,
        policy_previous: Vec<u8>,
        policy_baseline: Vec<u8>,
        policy_candidate: Vec<u8>,
    }

    fn signed_product_closure(
        generation: &crate::generation::VerifiedGeneration,
        release_identity: &str,
    ) -> (
        voboost_contract::release::Manifest,
        std::collections::BTreeMap<String, Vec<u8>>,
        Vec<u8>,
        Vec<u8>,
    ) {
        signed_product_closure_with_app(
            generation,
            release_identity,
            b"fixture:voboost-app.apk",
            1,
            &"a".repeat(64),
        )
    }

    fn signed_product_closure_with_app(
        generation: &crate::generation::VerifiedGeneration,
        release_identity: &str,
        app_bytes: &[u8],
        app_version_code: u64,
        app_certificate_sha256: &str,
    ) -> (
        voboost_contract::release::Manifest,
        std::collections::BTreeMap<String, Vec<u8>>,
        Vec<u8>,
        Vec<u8>,
    ) {
        use ed25519_dalek::{Signer, SigningKey};

        let mut manifest = voboost_contract::release::Manifest::parse(include_bytes!(
            "../../test/fixtures/product-release/voboost/valid/minimal.json"
        ))
        .unwrap();
        manifest.release_identity = release_identity.to_string();
        let mut bodies = std::collections::BTreeMap::new();
        for artifact in &mut manifest.artifacts {
            let bytes = if artifact.role == voboost_contract::release::ArtifactRole::App {
                artifact.version_code = Some(app_version_code);
                artifact.certificate_sha256 = Some(app_certificate_sha256.to_string());
                app_bytes.to_vec()
            } else if artifact.file == "voboost.rc" {
                include_bytes!("../../config/voboost.rc").to_vec()
            } else if artifact.file == "voboost-selinux" {
                signed_executable(
                    crate::native_executable_signature::NativeExecutableRole::Selinux,
                    b"\x7fELF-fixture-voboost-selinux",
                )
            } else {
                match crate::installed_product::authority(artifact) {
                    crate::installed_product::InstalledAuthority::ActiveGeneration => {
                        generation.read_file_exact(&artifact.file).unwrap()
                    }
                    _ => format!("fixture:{}", artifact.file).into_bytes(),
                }
            };
            artifact.size = bytes.len() as u64;
            artifact.sha256 = crate::trust::sha256_bytes(&bytes);
            bodies.insert(artifact.file.clone(), bytes);
        }
        let restore = voboost_contract::release::RestoreDocument {
            schema_version: 1,
            release_identity: release_identity.to_string(),
            source_definition_sha256: "d".repeat(64),
            restorable_closure_sha256: voboost_contract::release::restorable_closure_sha256(
                &manifest,
            )
            .unwrap(),
        };
        let mut restore_bytes = serde_json::to_vec(&restore).unwrap();
        restore_bytes.push(b'\n');
        const RESTORE_SEED: [u8; 32] = [
            0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b, 0xed, 0xb7, 0x44, 0x2f, 0x31, 0xdc,
            0xb7, 0xb1, 0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f, 0x09, 0x4b, 0x85, 0xce, 0x3a, 0x2e,
            0x0b, 0x44, 0x58, 0xf7,
        ];
        let restore_signature = SigningKey::from_bytes(&RESTORE_SEED)
            .sign(&restore_bytes)
            .to_bytes()
            .to_vec();
        for (name, bytes) in [
            ("restore.json", restore_bytes),
            ("restore.json.sig", restore_signature),
        ] {
            let artifact = manifest
                .artifacts
                .iter_mut()
                .find(|item| item.file == name)
                .unwrap();
            artifact.size = bytes.len() as u64;
            artifact.sha256 = crate::trust::sha256_bytes(&bytes);
            bodies.insert(name.to_string(), bytes);
        }
        manifest.validate().unwrap();
        let manifest_bytes = manifest.canonical_bytes().unwrap();
        let manifest_signature = SigningKey::from_bytes(&[12; 32])
            .sign(&manifest_bytes)
            .to_bytes()
            .to_vec();
        (manifest, bodies, manifest_bytes, manifest_signature)
    }

    fn signed_executable(
        role: crate::native_executable_signature::NativeExecutableRole,
        prefix: &[u8],
    ) -> Vec<u8> {
        use ed25519_dalek::{Signer, SigningKey};

        const EXECUTABLE_SEED: [u8; 32] = [
            0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11,
            0x4e, 0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed,
            0x4f, 0xb8, 0xa6, 0xfb,
        ];
        let transcript = crate::native_executable_signature::transcript(role, prefix).unwrap();
        let mut bytes = prefix.to_vec();
        bytes.extend_from_slice(b"VOBOOST\0");
        bytes.extend_from_slice(&(prefix.len() as u64).to_le_bytes());
        bytes.extend_from_slice(
            &SigningKey::from_bytes(&EXECUTABLE_SEED)
                .sign(&transcript)
                .to_bytes(),
        );
        bytes
    }

    fn resign_product(
        manifest: &mut voboost_contract::release::Manifest,
        bodies: &mut std::collections::BTreeMap<String, Vec<u8>>,
    ) -> (Vec<u8>, Vec<u8>) {
        use ed25519_dalek::{Signer, SigningKey};

        let restore = voboost_contract::release::RestoreDocument {
            schema_version: 1,
            release_identity: manifest.release_identity.clone(),
            source_definition_sha256: "d".repeat(64),
            restorable_closure_sha256: voboost_contract::release::restorable_closure_sha256(
                manifest,
            )
            .unwrap(),
        };
        let mut restore_bytes = serde_json::to_vec(&restore).unwrap();
        restore_bytes.push(b'\n');
        const RESTORE_SEED: [u8; 32] = [
            0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b, 0xed, 0xb7, 0x44, 0x2f, 0x31, 0xdc,
            0xb7, 0xb1, 0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f, 0x09, 0x4b, 0x85, 0xce, 0x3a, 0x2e,
            0x0b, 0x44, 0x58, 0xf7,
        ];
        let restore_signature = SigningKey::from_bytes(&RESTORE_SEED)
            .sign(&restore_bytes)
            .to_bytes()
            .to_vec();
        for (name, bytes) in [
            ("restore.json", restore_bytes),
            ("restore.json.sig", restore_signature),
        ] {
            let artifact = manifest
                .artifacts
                .iter_mut()
                .find(|item| item.file == name)
                .unwrap();
            artifact.size = bytes.len() as u64;
            artifact.sha256 = crate::trust::sha256_bytes(&bytes);
            bodies.insert(name.to_string(), bytes);
        }
        manifest.validate().unwrap();
        let bytes = manifest.canonical_bytes().unwrap();
        let signature = SigningKey::from_bytes(&[12; 32])
            .sign(&bytes)
            .to_bytes()
            .to_vec();
        (bytes, signature)
    }

    fn write_product_inventory(
        root: &Path,
        manifest: &voboost_contract::release::Manifest,
        manifest_bytes: &[u8],
        manifest_signature: &[u8],
    ) {
        use std::os::unix::fs::PermissionsExt;

        let artifact = |name: &str, role: &str| {
            let item = manifest.artifact(name).unwrap();
            serde_json::json!({"path":format!("/data/voboost/{name}"),"size":item.size,"sha256":item.sha256,"signatureRole":role,"uid":0,"gid":0,"mode":"0700","context":"u:object_r:voboost_fixture:s0"})
        };
        let restore = manifest.artifact("restore.json").unwrap();
        let restore_signature = manifest.artifact("restore.json.sig").unwrap();
        let apk = manifest.artifact("voboost-app.apk").unwrap();
        let payload = [
            ("libimplant-arm64-v8a.so", "arm64-v8a", "implant"),
            ("libimplant-armeabi-v7a.so", "armeabi-v7a", "implant"),
        ]
        .map(|(name, abi, component)| {
            let item = manifest.artifact(name).unwrap();
            serde_json::json!({"path":format!("/data/voboost/{name}"),"abi":abi,"component":component,"size":item.size,"sha256":item.sha256,"signatureRole":"runtime"})
        });
        let rc = b"# fixture\n";
        let prior = "1".repeat(64);
        let installed = "2".repeat(64);
        let artifacts = serde_json::to_vec(&serde_json::json!({
            "schemaVersion":1,
            "root":{"path":uninstall_contract::ROOT_ZONE_PATH,"markerPath":uninstall_contract::ROOT_ZONE_MARKER_PATH,"markerSha256":uninstall_contract::ROOT_ZONE_MARKER_SHA256},
            "init":{"path":uninstall_contract::RC_PATH,"installedSize":rc.len(),"installedSha256":crate::trust::sha256_bytes(rc),"archivePath":uninstall_contract::RC_ARCHIVE_PATH,"uid":0,"gid":0,"mode":"0644","context":"u:object_r:system_file:s0"},
            "policy":{"path":uninstall_contract::POLICY_PATH,"installedSha256":installed,"currentBaselineSha256":prior},
            "native":{"daemon":artifact("voboost-daemon","daemon"),"inject":artifact("voboost-inject","inject"),"installer":artifact("voboost-install","install"),"uninstaller":artifact("voboost-uninstall","uninstall"),"restore":artifact("voboost-restore","restore"),"restoreManifest":{"path":uninstall_contract::RESTORE_MANIFEST_PATH,"size":restore.size,"sha256":restore.sha256,"signaturePath":uninstall_contract::RESTORE_MANIFEST_SIGNATURE_PATH,"signatureSize":restore_signature.size,"signatureSha256":restore_signature.sha256,"signatureRole":"restore-manifest"},"selinux":artifact("voboost-selinux","selinux"),"manifest":{"path":uninstall_contract::MANIFEST_PATH,"size":manifest_bytes.len(),"sha256":crate::trust::sha256_bytes(manifest_bytes),"signaturePath":uninstall_contract::MANIFEST_SIGNATURE_PATH,"signatureSize":manifest_signature.len(),"signatureSha256":crate::trust::sha256_bytes(manifest_signature),"signatureRole":"release-catalog"},"payload":payload,"qnx":uninstall_contract::QNX_RELAY_PATHS.map(|(path,role,mode)| {let name=path.strip_prefix("/data/voboost/").unwrap();let mut value=artifact(name,role);value["mode"]=serde_json::json!(mode);value})},
            "package":{"name":"ru.voboost","versionCode":apk.version_code.unwrap(),"apkSize":apk.size,"apkSha256":apk.sha256,"certificateSha256":apk.certificate_sha256.as_ref().unwrap()},
            "appOp":{"package":"ru.voboost","operation":"REQUEST_INSTALL_PACKAGES","installedMode":"allow"}
        })).unwrap();
        let baseline = serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"policySha256":prior,"backupPath":uninstall_contract::baseline_backup_path(&prior).unwrap(),"metadataPath":uninstall_contract::POLICY_META_PATH})).unwrap();
        let sidecars = voboost_shared::mount_policy_transaction::parse_sidecar_backup(
            include_bytes!("../../test/fixtures/policy-sidecars.json"),
        )
        .unwrap();
        let policy = serde_json::to_vec(&serde_json::json!({"schemaVersion":2,"path":uninstall_contract::POLICY_PATH,"size":1,"sha256":prior,"uid":0,"gid":0,"mode":"0644","context":"u:object_r:vendor_file:s0","sidecars":sidecars})).unwrap();
        let state = serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"rootPriorState":"absent","initPriorState":"absent","initInstalledSha256":crate::trust::sha256_bytes(rc),"policyPriorSha256":prior,"policyInstalledSha256":installed,"packagePriorState":"absent","packageVersionCode":apk.version_code.unwrap(),"appOpPriorMode":"absent","appOpInstalledMode":"allow"})).unwrap();
        let documents = [
            (
                uninstall_contract::SYSTEM_ARTIFACTS_PATH,
                artifacts.as_slice(),
            ),
            (
                uninstall_contract::CURRENT_BASELINE_PATH,
                baseline.as_slice(),
            ),
            (uninstall_contract::POLICY_META_PATH, policy.as_slice()),
            (uninstall_contract::SYSTEM_STATE_PATH, state.as_slice()),
            (uninstall_contract::RC_ARCHIVE_PATH, rc.as_slice()),
        ];
        let claims = documents.map(|(path, bytes)| serde_json::json!({"path":path,"size":bytes.len(),"sha256":crate::trust::sha256_bytes(bytes)}));
        let inventory = serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"phase":"committed","version":manifest.release_identity,"committedAt":"1","documents":claims})).unwrap();
        let uninstall = root.join("uninstall");
        let system = uninstall.join("system");
        std::fs::create_dir_all(&system).unwrap();
        std::fs::set_permissions(&uninstall, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&system, std::fs::Permissions::from_mode(0o700)).unwrap();
        for (path, bytes) in [
            (uninstall.join(INVENTORY), inventory.as_slice()),
            (uninstall.join(ARTIFACTS), artifacts.as_slice()),
            (uninstall.join("current-baseline.json"), baseline.as_slice()),
            (uninstall.join("policy.meta.json"), policy.as_slice()),
            (uninstall.join("system-state.json"), state.as_slice()),
            (system.join("voboost.rc"), rc.as_slice()),
        ] {
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn write_host_apk_observation(
        root: &Directory,
        bytes: &[u8],
        version_code: u64,
        certificate_sha256: &str,
        path: &str,
    ) {
        root.write_atomic("voboost-app.apk.host-observed", bytes, FILE_MODE)
            .unwrap();
        let mut observation = serde_json::to_vec(&crate::installed_product::HostApkObservation {
            path: path.to_string(),
            version_code,
            certificate_sha256: certificate_sha256.to_string(),
        })
        .unwrap();
        observation.push(b'\n');
        root.write_atomic(
            "voboost-app.apk.host-observed.json",
            &observation,
            FILE_MODE,
        )
        .unwrap();
    }

    fn set_host_boot_and_running(root: &Directory, boot_id: &str, daemon: &[u8]) {
        root.write_atomic("boot-id.host", format!("{boot_id}\n").as_bytes(), FILE_MODE)
            .unwrap();
        root.write_atomic("voboost-daemon.host-running", daemon, 0o700)
            .unwrap();
    }

    fn product_fixture() -> ProductFixture {
        let active = crate::generation::test_support::zones();
        let active_generation =
            crate::generation::test_support::activate_cluster_variant(&active.store, 1);
        let root = active_generation
            .directory
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let candidate_zone = crate::generation::test_support::zones();
        let candidate_generation =
            crate::generation::test_support::activate_cluster_variant(&candidate_zone.store, 2);
        let (old_manifest, old_bodies, old_manifest_bytes, old_signature) =
            signed_product_closure(&active_generation, "1.0.0-beta1");
        let (new_manifest, new_bodies, new_manifest_bytes, new_signature) =
            signed_product_closure(&candidate_generation, "1.0.0-beta2");
        let root_directory = Directory::open(&root).unwrap();
        for artifact in &old_manifest.artifacts {
            if let crate::installed_product::InstalledAuthority::RootFlat { mode } =
                crate::installed_product::authority(artifact)
            {
                root_directory
                    .write_atomic(&artifact.file, &old_bodies[&artifact.file], mode)
                    .unwrap();
            }
        }
        std::os::unix::fs::symlink("voboost-inject", root.join("voboost-inject.host-running"))
            .unwrap();
        let app = old_manifest.artifact("voboost-app.apk").unwrap();
        write_host_apk_observation(
            &root_directory,
            &old_bodies["voboost-app.apk"],
            app.version_code.unwrap(),
            app.certificate_sha256.as_deref().unwrap(),
            "/data/app/ru.voboost/base.apk",
        );
        root_directory
            .write_atomic(MANIFEST, &old_manifest_bytes, 0o600)
            .unwrap();
        root_directory
            .write_atomic(SIGNATURE, &old_signature, 0o600)
            .unwrap();
        write_product_inventory(&root, &old_manifest, &old_manifest_bytes, &old_signature);
        let changed_names = [
            "restore.json",
            "restore.json.sig",
            "agents.json",
            "agents.json.sig",
        ];
        let candidate = OtaCandidateHandle {
            transaction_id: "a".repeat(64),
            release_identity: new_manifest.release_identity.clone(),
            manifest_sha256: new_manifest.digest().unwrap(),
            artifacts: new_manifest
                .artifacts
                .iter()
                .filter(|artifact| changed_names.contains(&artifact.file.as_str()))
                .map(
                    |artifact| voboost_contract::status::CandidateArtifactIdentity {
                        file: artifact.file.clone(),
                        size: artifact.size,
                        sha256: artifact.sha256.clone(),
                    },
                )
                .collect(),
        };
        let install_root = root_directory
            .open_or_create_private_child(INSTALL_ROOT)
            .unwrap();
        let recovery_root = root_directory
            .open_or_create_private_child(RECOVERY_ROOT)
            .unwrap();
        let install = install_root
            .open_or_create_private_child(&candidate.transaction_id)
            .unwrap();
        let recovery = recovery_root
            .open_or_create_private_child(&candidate.transaction_id)
            .unwrap();
        let changed = install.open_or_create_private_child(CANDIDATE).unwrap();
        changed
            .write_atomic(MANIFEST, &new_manifest_bytes, FILE_MODE)
            .unwrap();
        changed
            .write_atomic(SIGNATURE, &new_signature, FILE_MODE)
            .unwrap();
        for artifact in &candidate.artifacts {
            changed
                .write_atomic(&artifact.file, &new_bodies[&artifact.file], FILE_MODE)
                .unwrap();
        }
        let complete = install
            .open_or_create_private_child(COMPLETE_CANDIDATE)
            .unwrap();
        complete
            .write_atomic(MANIFEST, &new_manifest_bytes, FILE_MODE)
            .unwrap();
        complete
            .write_atomic(SIGNATURE, &new_signature, FILE_MODE)
            .unwrap();
        for artifact in &new_manifest.artifacts {
            complete
                .write_atomic(&artifact.file, &new_bodies[&artifact.file], FILE_MODE)
                .unwrap();
        }
        let mut journal = ProposalJournal::new(&candidate);
        journal.phase = ProposalPhase::Reconstructed;
        write_journal(&recovery, &journal).unwrap();
        ProductFixture {
            _active: active,
            _candidate: candidate_zone,
            root,
            candidate,
            candidate_generation_id: candidate_generation.id,
        }
    }

    fn apk_fixture() -> ApkFixture {
        let active = crate::generation::test_support::zones();
        let generation =
            crate::generation::test_support::activate_cluster_variant(&active.store, 1);
        let root = generation
            .directory
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let old_certificate = "a".repeat(64);
        let new_certificate = "b".repeat(64);
        let (old_manifest, old_bodies, old_manifest_bytes, old_signature) =
            signed_product_closure_with_app(
                &generation,
                "1.0.0-beta1",
                b"old-apk",
                1,
                &old_certificate,
            );
        let (new_manifest, new_bodies, new_manifest_bytes, new_signature) =
            signed_product_closure_with_app(
                &generation,
                "1.0.0-beta2",
                b"new-apk",
                2,
                &new_certificate,
            );
        let root_directory = Directory::open(&root).unwrap();
        for artifact in &old_manifest.artifacts {
            if let crate::installed_product::InstalledAuthority::RootFlat { mode } =
                crate::installed_product::authority(artifact)
            {
                root_directory
                    .write_atomic(&artifact.file, &old_bodies[&artifact.file], mode)
                    .unwrap();
            }
        }
        write_host_apk_observation(
            &root_directory,
            &old_bodies["voboost-app.apk"],
            1,
            &old_certificate,
            "/data/app/ru.voboost/base.apk",
        );
        root_directory
            .write_atomic(MANIFEST, &old_manifest_bytes, FILE_MODE)
            .unwrap();
        root_directory
            .write_atomic(SIGNATURE, &old_signature, FILE_MODE)
            .unwrap();
        write_product_inventory(&root, &old_manifest, &old_manifest_bytes, &old_signature);
        let changed_names = ["voboost-app.apk", "restore.json", "restore.json.sig"];
        let candidate = OtaCandidateHandle {
            transaction_id: "c".repeat(64),
            release_identity: new_manifest.release_identity.clone(),
            manifest_sha256: new_manifest.digest().unwrap(),
            artifacts: new_manifest
                .artifacts
                .iter()
                .filter(|artifact| changed_names.contains(&artifact.file.as_str()))
                .map(
                    |artifact| voboost_contract::status::CandidateArtifactIdentity {
                        file: artifact.file.clone(),
                        size: artifact.size,
                        sha256: artifact.sha256.clone(),
                    },
                )
                .collect(),
        };
        let install_root = root_directory
            .open_or_create_private_child(INSTALL_ROOT)
            .unwrap();
        let recovery_root = root_directory
            .open_or_create_private_child(RECOVERY_ROOT)
            .unwrap();
        let install = install_root
            .open_or_create_private_child(&candidate.transaction_id)
            .unwrap();
        let recovery = recovery_root
            .open_or_create_private_child(&candidate.transaction_id)
            .unwrap();
        let changed = install.open_or_create_private_child(CANDIDATE).unwrap();
        changed
            .write_atomic(MANIFEST, &new_manifest_bytes, FILE_MODE)
            .unwrap();
        changed
            .write_atomic(SIGNATURE, &new_signature, FILE_MODE)
            .unwrap();
        for artifact in &candidate.artifacts {
            changed
                .write_atomic(&artifact.file, &new_bodies[&artifact.file], FILE_MODE)
                .unwrap();
        }
        let complete = install
            .open_or_create_private_child(COMPLETE_CANDIDATE)
            .unwrap();
        complete
            .write_atomic(MANIFEST, &new_manifest_bytes, FILE_MODE)
            .unwrap();
        complete
            .write_atomic(SIGNATURE, &new_signature, FILE_MODE)
            .unwrap();
        for artifact in &new_manifest.artifacts {
            complete
                .write_atomic(&artifact.file, &new_bodies[&artifact.file], FILE_MODE)
                .unwrap();
        }
        let mut journal = ProposalJournal::new(&candidate);
        assert!(journal.apk_only);
        assert!(!journal.generation_only);
        journal.phase = ProposalPhase::Reconstructed;
        write_journal(&recovery, &journal).unwrap();
        ApkFixture {
            _active: active,
            root,
            candidate,
            old_manifest_sha256: old_manifest.digest().unwrap(),
            old_restore: old_bodies["restore.json"].clone(),
            new_apk: new_bodies["voboost-app.apk"].clone(),
            new_version_code: 2,
            new_certificate_sha256: new_certificate,
        }
    }

    #[test]
    fn post_reboot_requires_both_running_executables() {
        let fixture = product_fixture();
        let manifest = crate::installed_product::load_manifest_in(&fixture.root).unwrap();
        let daemon_path = fixture.root.join("voboost-daemon");
        let inject_path = fixture.root.join("voboost-inject");
        assert!(
            verify_running_product_paths(&fixture.root, &manifest, &daemon_path, &inject_path)
                .is_ok()
        );

        let error =
            verify_running_product_paths(&fixture.root, &manifest, &daemon_path, &daemon_path)
                .unwrap_err();
        assert!(error.contains("running injection host differs"));

        let error =
            verify_running_product_paths(&fixture.root, &manifest, &inject_path, &inject_path)
                .unwrap_err();
        assert!(error.contains("running daemon"));

        let previous_inject = fixture.root.join("previous-inject");
        std::fs::rename(&inject_path, &previous_inject).unwrap();
        let bytes = std::fs::read(&previous_inject).unwrap();
        Directory::open(&fixture.root)
            .unwrap()
            .write_atomic("voboost-inject", &bytes, 0o700)
            .unwrap();
        let error =
            verify_running_product_paths(&fixture.root, &manifest, &daemon_path, &previous_inject)
                .unwrap_err();
        assert!(error.contains("running injection host differs"));
    }

    fn native_fixture(change_agent: bool, change_apk: bool) -> NativeFixture {
        let active = crate::generation::test_support::zones();
        let active_generation =
            crate::generation::test_support::activate_cluster_variant(&active.store, 1);
        let root = active_generation
            .directory
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let candidate_zone = change_agent.then(crate::generation::test_support::zones);
        let candidate_generation = match candidate_zone.as_ref() {
            Some(zone) => crate::generation::test_support::activate_cluster_variant(&zone.store, 2),
            None => active_generation.clone(),
        };
        let old_certificate = "a".repeat(64);
        let new_certificate = if change_apk {
            "b".repeat(64)
        } else {
            old_certificate.clone()
        };
        let (mut old_manifest, mut old_bodies, _, _) = signed_product_closure_with_app(
            &active_generation,
            "1.0.0-beta1",
            b"old-apk",
            1,
            &old_certificate,
        );
        let (mut new_manifest, mut new_bodies, _, _) = signed_product_closure_with_app(
            &candidate_generation,
            "1.0.0-beta2",
            if change_apk { b"new-apk" } else { b"old-apk" },
            if change_apk { 2 } else { 1 },
            &new_certificate,
        );
        for (manifest, bodies, variant) in [
            (&mut old_manifest, &mut old_bodies, "old"),
            (&mut new_manifest, &mut new_bodies, "new"),
        ] {
            for name in [
                "voboost-daemon",
                "voboost-install",
                "voboost-restore",
                "voboost-uninstall",
            ] {
                let role = executable_role(name).unwrap();
                let bytes = signed_executable(role, format!("\x7fELF-{variant}-{name}").as_bytes());
                let artifact = manifest
                    .artifacts
                    .iter_mut()
                    .find(|item| item.file == name)
                    .unwrap();
                artifact.size = bytes.len() as u64;
                artifact.sha256 = crate::trust::sha256_bytes(&bytes);
                bodies.insert(name.to_string(), bytes);
            }
            for name in ["libimplant-arm64-v8a.so", "libimplant-armeabi-v7a.so"] {
                let bytes = format!("native-{variant}-{name}").into_bytes();
                let artifact = manifest
                    .artifacts
                    .iter_mut()
                    .find(|item| item.file == name)
                    .unwrap();
                artifact.size = bytes.len() as u64;
                artifact.sha256 = crate::trust::sha256_bytes(&bytes);
                bodies.insert(name.to_string(), bytes);
            }
        }
        let (old_manifest_bytes, old_signature) =
            resign_product(&mut old_manifest, &mut old_bodies);
        let (new_manifest_bytes, new_signature) =
            resign_product(&mut new_manifest, &mut new_bodies);
        let root_directory = Directory::open(&root).unwrap();
        for artifact in &old_manifest.artifacts {
            if let crate::installed_product::InstalledAuthority::RootFlat { mode } =
                crate::installed_product::authority(artifact)
            {
                root_directory
                    .write_atomic(&artifact.file, &old_bodies[&artifact.file], mode)
                    .unwrap();
            }
        }
        std::os::unix::fs::symlink("voboost-inject", root.join("voboost-inject.host-running"))
            .unwrap();
        write_host_apk_observation(
            &root_directory,
            &old_bodies["voboost-app.apk"],
            1,
            &old_certificate,
            "/data/app/ru.voboost/base.apk",
        );
        root_directory
            .write_atomic(MANIFEST, &old_manifest_bytes, FILE_MODE)
            .unwrap();
        root_directory
            .write_atomic(SIGNATURE, &old_signature, FILE_MODE)
            .unwrap();
        root_directory
            .write_atomic(
                "boot-id.host",
                b"00000000-0000-0000-0000-000000000001\n",
                FILE_MODE,
            )
            .unwrap();
        root_directory
            .write_atomic(
                "voboost-daemon.host-running",
                &old_bodies["voboost-daemon"],
                0o700,
            )
            .unwrap();
        write_product_inventory(&root, &old_manifest, &old_manifest_bytes, &old_signature);
        let candidate = OtaCandidateHandle {
            transaction_id: "e".repeat(64),
            release_identity: new_manifest.release_identity.clone(),
            manifest_sha256: new_manifest.digest().unwrap(),
            artifacts: new_manifest
                .artifacts
                .iter()
                .zip(&old_manifest.artifacts)
                .filter(|(new, old)| new.size != old.size || new.sha256 != old.sha256)
                .map(
                    |(artifact, _)| voboost_contract::status::CandidateArtifactIdentity {
                        file: artifact.file.clone(),
                        size: artifact.size,
                        sha256: artifact.sha256.clone(),
                    },
                )
                .collect(),
        };
        assert!(is_native_plan(
            &candidate,
            &activation_classes(&candidate).unwrap()
        ));
        let install_root = root_directory
            .open_or_create_private_child(INSTALL_ROOT)
            .unwrap();
        let recovery_root = root_directory
            .open_or_create_private_child(RECOVERY_ROOT)
            .unwrap();
        let install = install_root
            .open_or_create_private_child(&candidate.transaction_id)
            .unwrap();
        let recovery = recovery_root
            .open_or_create_private_child(&candidate.transaction_id)
            .unwrap();
        let changed = install.open_or_create_private_child(CANDIDATE).unwrap();
        changed
            .write_atomic(MANIFEST, &new_manifest_bytes, FILE_MODE)
            .unwrap();
        changed
            .write_atomic(SIGNATURE, &new_signature, FILE_MODE)
            .unwrap();
        for artifact in &candidate.artifacts {
            changed
                .write_atomic(&artifact.file, &new_bodies[&artifact.file], FILE_MODE)
                .unwrap();
        }
        let complete = install
            .open_or_create_private_child(COMPLETE_CANDIDATE)
            .unwrap();
        complete
            .write_atomic(MANIFEST, &new_manifest_bytes, FILE_MODE)
            .unwrap();
        complete
            .write_atomic(SIGNATURE, &new_signature, FILE_MODE)
            .unwrap();
        for artifact in &new_manifest.artifacts {
            complete
                .write_atomic(&artifact.file, &new_bodies[&artifact.file], FILE_MODE)
                .unwrap();
        }
        let mut journal = ProposalJournal::new(&candidate);
        journal.phase = ProposalPhase::Reconstructed;
        write_journal(&recovery, &journal).unwrap();
        let native_members = changed_native_artifacts(&new_manifest, &candidate)
            .unwrap()
            .len();
        NativeFixture {
            native_members,
            _active: active,
            _candidate: candidate_zone,
            root,
            candidate,
            old_manifest_sha256: old_manifest.digest().unwrap(),
            old_daemon: old_bodies["voboost-daemon"].clone(),
            new_daemon: new_bodies["voboost-daemon"].clone(),
            new_apk: change_apk
                .then(|| (new_bodies["voboost-app.apk"].clone(), 2, new_certificate)),
            candidate_generation_id: candidate_generation.id,
        }
    }

    fn system_fixture() -> SystemFixture {
        system_fixture_with_inject(false)
    }

    fn system_fixture_with_inject(change_inject: bool) -> SystemFixture {
        system_fixture_with_apk(change_inject, false)
    }

    fn system_fixture_with_apk(change_inject: bool, change_apk: bool) -> SystemFixture {
        let mut base = product_fixture();
        let root = Directory::open(&base.root).unwrap();
        let old_manifest = crate::installed_product::load_manifest_in(&base.root).unwrap();
        let old_manifest_sha256 = old_manifest.digest().unwrap();
        let daemon_artifact = old_manifest.artifact("voboost-daemon").unwrap();
        let daemon = root
            .read_trusted("voboost-daemon", daemon_artifact.size as usize, 0o700)
            .unwrap();
        let install = root
            .open_child(INSTALL_ROOT)
            .unwrap()
            .open_child(&base.candidate.transaction_id)
            .unwrap();
        let complete = install.open_child(COMPLETE_CANDIDATE).unwrap();
        let mut manifest = voboost_contract::release::Manifest::parse(
            &complete
                .read_trusted(
                    MANIFEST,
                    voboost_contract::release::MAX_MANIFEST_BYTES,
                    FILE_MODE,
                )
                .unwrap(),
        )
        .unwrap();
        let mut bodies = manifest
            .artifacts
            .iter()
            .map(|artifact| {
                (
                    artifact.file.clone(),
                    complete
                        .read_trusted(&artifact.file, artifact.size as usize, FILE_MODE)
                        .unwrap(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        let init_candidate =
            b"# candidate product init\nservice voboost-daemon /data/voboost/voboost-daemon\n"
                .to_vec();
        let selinux_candidate = signed_executable(
            crate::native_executable_signature::NativeExecutableRole::Selinux,
            b"\x7fELF-candidate-voboost-selinux",
        );
        let inject_candidate = signed_executable(
            crate::native_executable_signature::NativeExecutableRole::Inject,
            b"\x7fELF-candidate-voboost-inject",
        );
        let mut system_members = vec![
            ("voboost.rc", init_candidate.as_slice()),
            ("voboost-selinux", selinux_candidate.as_slice()),
        ];
        if change_inject {
            system_members.push(("voboost-inject", inject_candidate.as_slice()));
        }
        if change_apk {
            system_members.push(("voboost-app.apk", b"mixed-system-candidate-apk".as_slice()));
            manifest
                .artifacts
                .iter_mut()
                .find(|a| a.file == "voboost-app.apk")
                .unwrap()
                .version_code = Some(2);
        }
        for &(name, bytes) in &system_members {
            let artifact = manifest
                .artifacts
                .iter_mut()
                .find(|artifact| artifact.file == name)
                .unwrap();
            artifact.size = bytes.len() as u64;
            artifact.sha256 = crate::trust::sha256_bytes(bytes);
            bodies.insert(name.into(), bytes.to_vec());
        }
        let (manifest_bytes, signature) = resign_product(&mut manifest, &mut bodies);
        complete
            .write_atomic(MANIFEST, &manifest_bytes, FILE_MODE)
            .unwrap();
        complete
            .write_atomic(SIGNATURE, &signature, FILE_MODE)
            .unwrap();
        for &(name, _) in &system_members {
            complete
                .write_atomic(name, &bodies[name], FILE_MODE)
                .unwrap();
        }
        let changed = install.open_child(CANDIDATE).unwrap();
        changed
            .write_atomic(MANIFEST, &manifest_bytes, FILE_MODE)
            .unwrap();
        changed
            .write_atomic(SIGNATURE, &signature, FILE_MODE)
            .unwrap();
        for &(name, _) in &system_members {
            changed
                .write_atomic(name, &bodies[name], FILE_MODE)
                .unwrap();
        }
        for &(name, _) in &system_members {
            let artifact = manifest.artifact(name).unwrap();
            base.candidate
                .artifacts
                .push(voboost_contract::status::CandidateArtifactIdentity {
                    file: name.into(),
                    size: artifact.size,
                    sha256: artifact.sha256.clone(),
                });
        }
        for identity in &mut base.candidate.artifacts {
            let artifact = manifest.artifact(&identity.file).unwrap();
            identity.size = artifact.size;
            identity.sha256.clone_from(&artifact.sha256);
            complete
                .write_atomic(&artifact.file, &bodies[&artifact.file], FILE_MODE)
                .unwrap();
            changed
                .write_atomic(&artifact.file, &bodies[&artifact.file], FILE_MODE)
                .unwrap();
        }
        base.candidate.manifest_sha256 = manifest.digest().unwrap();
        let recovery = root
            .open_child(RECOVERY_ROOT)
            .unwrap()
            .open_child(&base.candidate.transaction_id)
            .unwrap();
        let mut journal = ProposalJournal::new(&base.candidate);
        journal.phase = ProposalPhase::Reconstructed;
        write_journal(&recovery, &journal).unwrap();
        let active_init = root.read_trusted("voboost.rc", 1024 * 1024, 0o644).unwrap();
        let policy_previous = b"current patched policy".to_vec();
        let policy_baseline = b"pristine OEM policy".to_vec();
        let policy_candidate = b"candidate patched policy".to_vec();
        for (name, bytes, mode) in [
            ("system-init.host", active_init.as_slice(), 0o644),
            ("policy.host", policy_previous.as_slice(), 0o644),
            ("policy-baseline.host", policy_baseline.as_slice(), 0o600),
        ] {
            root.write_atomic(name, bytes, mode).unwrap();
        }
        root.write_atomic(
            "boot-id.host",
            b"00000000-0000-0000-0000-000000000001\n",
            FILE_MODE,
        )
        .unwrap();
        root.write_atomic("voboost-daemon.host-running", &daemon, 0o700)
            .unwrap();
        SystemFixture {
            root: base.root.clone(),
            candidate: base.candidate.clone(),
            _base: base,
            old_manifest_sha256,
            daemon,
            init_candidate,
            selinux_candidate,
            policy_previous,
            policy_baseline,
            policy_candidate,
        }
    }

    fn rewrite_candidate_daemon(fixture: &mut NativeFixture, daemon_bytes: Vec<u8>) {
        let root = Directory::open(&fixture.root).unwrap();
        let install = root
            .open_child(INSTALL_ROOT)
            .unwrap()
            .open_child(&fixture.candidate.transaction_id)
            .unwrap();
        let complete = install.open_child(COMPLETE_CANDIDATE).unwrap();
        let mut manifest = voboost_contract::release::Manifest::parse(
            &complete
                .read_trusted(
                    MANIFEST,
                    voboost_contract::release::MAX_MANIFEST_BYTES,
                    FILE_MODE,
                )
                .unwrap(),
        )
        .unwrap();
        let mut bodies = manifest
            .artifacts
            .iter()
            .map(|artifact| {
                (
                    artifact.file.clone(),
                    complete
                        .read_trusted(&artifact.file, artifact.size as usize, FILE_MODE)
                        .unwrap(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        let daemon = manifest
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.file == "voboost-daemon")
            .unwrap();
        daemon.size = daemon_bytes.len() as u64;
        daemon.sha256 = crate::trust::sha256_bytes(&daemon_bytes);
        bodies.insert("voboost-daemon".into(), daemon_bytes);
        let (manifest_bytes, signature) = resign_product(&mut manifest, &mut bodies);
        complete
            .write_atomic(MANIFEST, &manifest_bytes, FILE_MODE)
            .unwrap();
        complete
            .write_atomic(SIGNATURE, &signature, FILE_MODE)
            .unwrap();
        let changed = install.open_child(CANDIDATE).unwrap();
        changed
            .write_atomic(MANIFEST, &manifest_bytes, FILE_MODE)
            .unwrap();
        changed
            .write_atomic(SIGNATURE, &signature, FILE_MODE)
            .unwrap();
        fixture.candidate.manifest_sha256 = manifest.digest().unwrap();
        for identity in &mut fixture.candidate.artifacts {
            let artifact = manifest.artifact(&identity.file).unwrap();
            identity.size = artifact.size;
            identity.sha256.clone_from(&artifact.sha256);
            complete
                .write_atomic(&artifact.file, &bodies[&artifact.file], FILE_MODE)
                .unwrap();
            changed
                .write_atomic(&artifact.file, &bodies[&artifact.file], FILE_MODE)
                .unwrap();
        }
        let recovery = root
            .open_child(RECOVERY_ROOT)
            .unwrap()
            .open_child(&fixture.candidate.transaction_id)
            .unwrap();
        let mut journal = ProposalJournal::new(&fixture.candidate);
        journal.phase = ProposalPhase::Reconstructed;
        write_journal(&recovery, &journal).unwrap();
    }

    #[test]
    fn system_inventory_is_deferred_until_init_and_policy_candidate_are_known() {
        let fixture = product_fixture();
        let root = Directory::open(&fixture.root).unwrap();
        let recovery = root
            .open_child(RECOVERY_ROOT)
            .unwrap()
            .open_child(&fixture.candidate.transaction_id)
            .unwrap();
        let complete = root
            .open_child(INSTALL_ROOT)
            .unwrap()
            .open_child(&fixture.candidate.transaction_id)
            .unwrap()
            .open_child(COMPLETE_CANDIDATE)
            .unwrap();
        let manifest_bytes = complete
            .read_trusted(
                MANIFEST,
                voboost_contract::release::MAX_MANIFEST_BYTES,
                FILE_MODE,
            )
            .unwrap();
        let signature = complete.read_trusted(SIGNATURE, 64, FILE_MODE).unwrap();
        let manifest = voboost_contract::release::verify_manifest_signature(
            &manifest_bytes,
            &signature,
            &crate::trust::release_catalog_public_key(),
        )
        .unwrap();
        prepare_recovery_authority(
            &root,
            &recovery,
            &complete,
            &manifest,
            &manifest_bytes,
            &signature,
            false,
        )
        .unwrap();
        let previous = recovery.open_child(PREVIOUS).unwrap();
        assert!(!previous.entry_exists(NEXT_INVENTORY).unwrap());

        let init_artifact = manifest.artifact("voboost.rc").unwrap();
        let init = complete
            .read_trusted("voboost.rc", init_artifact.size as usize, FILE_MODE)
            .unwrap();
        let policy = b"derived candidate policy";
        let uninstall = root.open_child("uninstall").unwrap();
        let old_baseline = uninstall
            .read_trusted("current-baseline.json", 1024 * 1024, FILE_MODE)
            .unwrap();
        let old_policy_meta = uninstall
            .read_trusted("policy.meta.json", 1024 * 1024, FILE_MODE)
            .unwrap();
        prepare_uninstall_inventory(
            &root,
            &previous,
            &manifest,
            &manifest_bytes,
            &signature,
            Some(SystemInventoryCandidate {
                init: &init,
                policy,
            }),
        )
        .unwrap();
        publish_uninstall_inventory(&root, &recovery, None).unwrap();
        verify_uninstall_inventory(&root, &manifest).unwrap();

        let inventory = uninstall
            .read_trusted(INVENTORY, 64 * 1024, FILE_MODE)
            .unwrap();
        let artifacts = uninstall
            .read_trusted(ARTIFACTS, 1024 * 1024, FILE_MODE)
            .unwrap();
        let baseline = uninstall
            .read_trusted("current-baseline.json", 1024 * 1024, FILE_MODE)
            .unwrap();
        let policy_meta = uninstall
            .read_trusted("policy.meta.json", 1024 * 1024, FILE_MODE)
            .unwrap();
        let state = uninstall
            .read_trusted(SYSTEM_STATE, 1024 * 1024, FILE_MODE)
            .unwrap();
        let archived_init = uninstall
            .open_child("system")
            .unwrap()
            .read_trusted("voboost.rc", 1024 * 1024, FILE_MODE)
            .unwrap();
        let committed = uninstall_contract::parse_committed_contract(
            &inventory,
            &artifacts,
            &baseline,
            &policy_meta,
            &state,
            &archived_init,
        )
        .unwrap();
        assert_eq!(archived_init, init);
        assert_eq!(baseline, old_baseline);
        assert_eq!(policy_meta, old_policy_meta);
        assert_eq!(
            committed.artifacts.init.installed_sha256,
            crate::trust::sha256_bytes(&init)
        );
        assert_eq!(
            committed.artifacts.policy.installed_sha256,
            crate::trust::sha256_bytes(policy)
        );
        assert_eq!(
            committed.system_state.init_installed_sha256,
            committed.artifacts.init.installed_sha256
        );
        assert_eq!(
            committed.system_state.policy_installed_sha256,
            committed.artifacts.policy.installed_sha256
        );
    }

    fn system_recovery(fixture: &SystemFixture) -> Directory {
        Directory::open(&fixture.root)
            .unwrap()
            .open_child(RECOVERY_ROOT)
            .unwrap()
            .open_child(&fixture.candidate.transaction_id)
            .unwrap()
    }

    fn publish_policy_prepare_fixture(fixture: &SystemFixture) {
        let recovery = system_recovery(fixture);
        let previous = recovery.open_child(PREVIOUS).unwrap();
        previous
            .write_atomic("policy-candidate", &fixture.policy_candidate, FILE_MODE)
            .unwrap();
        let ack = voboost_contract::system_update::PolicyPrepareAck {
            schema_version: 1,
            transaction_id: fixture.candidate.transaction_id.clone(),
            boot_id: "00000000-0000-0000-0000-000000000001".into(),
            policy_baseline_sha256: crate::trust::sha256_bytes(&fixture.policy_baseline),
            policy_candidate_sha256: crate::trust::sha256_bytes(&fixture.policy_candidate),
        };
        recovery
            .write_atomic(
                voboost_contract::system_update::POLICY_PREPARE_ACK,
                &ack.canonical_bytes().unwrap(),
                FILE_MODE,
            )
            .unwrap();
    }

    fn publish_system_switch_fixture(fixture: &SystemFixture) {
        let root = Directory::open(&fixture.root).unwrap();
        root.write_atomic("system-init.host", &fixture.init_candidate, 0o644)
            .unwrap();
        root.write_atomic("policy.host", &fixture.policy_candidate, 0o644)
            .unwrap();
        root.write_atomic("voboost.rc", &fixture.init_candidate, 0o644)
            .unwrap();
        root.write_atomic("voboost-selinux", &fixture.selinux_candidate, 0o700)
            .unwrap();
        let recovery = system_recovery(fixture);
        let ack = voboost_contract::system_update::SystemSwitchAck {
            schema_version: 1,
            transaction_id: fixture.candidate.transaction_id.clone(),
            boot_id: "00000000-0000-0000-0000-000000000001".into(),
            init_previous_sha256: recovery
                .open_child(PREVIOUS)
                .unwrap()
                .read_trusted("system-init-previous", 1024 * 1024, FILE_MODE)
                .map(|bytes| crate::trust::sha256_bytes(&bytes))
                .unwrap(),
            init_candidate_sha256: crate::trust::sha256_bytes(&fixture.init_candidate),
            policy_previous_sha256: crate::trust::sha256_bytes(&fixture.policy_previous),
            policy_baseline_sha256: crate::trust::sha256_bytes(&fixture.policy_baseline),
            policy_candidate_sha256: crate::trust::sha256_bytes(&fixture.policy_candidate),
        };
        recovery
            .write_atomic(
                voboost_contract::system_update::SYSTEM_SWITCH_ACK,
                &ack.canonical_bytes().unwrap(),
                FILE_MODE,
            )
            .unwrap();
    }

    fn publish_system_post_boot_fixture(fixture: &SystemFixture, boot: &str) {
        let recovery = system_recovery(fixture);
        let ack = voboost_contract::system_update::SystemPostBootAck {
            schema_version: 1,
            transaction_id: fixture.candidate.transaction_id.clone(),
            boot_id: boot.into(),
            init_candidate_sha256: crate::trust::sha256_bytes(&fixture.init_candidate),
            policy_candidate_sha256: crate::trust::sha256_bytes(&fixture.policy_candidate),
            enforcing: true,
            daemon_domain: "u:r:voboost:s0".into(),
            loaded_policy_verified: true,
        };
        recovery
            .write_atomic(
                voboost_contract::system_update::SYSTEM_POST_BOOT_ACK,
                &ack.canonical_bytes().unwrap(),
                FILE_MODE,
            )
            .unwrap();
    }

    fn assert_system_phase(fixture: &SystemFixture, expected: ProposalPhase) {
        let journal = ProposalJournal::parse(
            &system_recovery(fixture)
                .read_trusted(JOURNAL, MAX_STATUS_BYTES, FILE_MODE)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(journal.phase, expected);
    }

    #[test]
    fn system_helper_waits_survive_restarts_and_accept_late_receipts() {
        let fixture = system_fixture();
        let store = ProductCandidateStore {
            root: fixture.root.clone(),
            reconstruct: true,
        };

        assert_eq!(
            store.recover_product_activation().unwrap(),
            Some(Admission::Pending)
        );
        assert_system_phase(&fixture, ProposalPhase::SystemPrepared);
        for _ in 0..25 {
            assert_eq!(
                store.recover_product_activation().unwrap(),
                Some(Admission::Pending)
            );
        }

        publish_policy_prepare_fixture(&fixture);
        assert_eq!(
            store.recover_product_activation().unwrap(),
            Some(Admission::Pending)
        );
        assert_system_phase(&fixture, ProposalPhase::SystemHelperRequested);
        for _ in 0..25 {
            assert_eq!(
                store.recover_product_activation().unwrap(),
                Some(Admission::Pending)
            );
        }

        publish_system_switch_fixture(&fixture);
        assert_eq!(
            store.recover_product_activation().unwrap(),
            Some(Admission::RebootRequired)
        );
        let root = Directory::open(&fixture.root).unwrap();
        set_host_boot_and_running(
            &root,
            "00000000-0000-0000-0000-000000000002",
            &fixture.daemon,
        );
        assert_eq!(
            store.recover_product_activation().unwrap(),
            Some(Admission::Pending)
        );
        assert_system_phase(&fixture, ProposalPhase::SystemPostReboot);
        for _ in 0..25 {
            assert_eq!(
                store.recover_product_activation().unwrap(),
                Some(Admission::Pending)
            );
        }

        publish_system_post_boot_fixture(&fixture, "00000000-0000-0000-0000-000000000002");
        assert_eq!(
            store.recover_product_activation().unwrap(),
            Some(Admission::Accepted)
        );
    }

    #[test]
    fn mixed_system_rollback_waits_for_previous_apk_and_restores_the_complete_product() {
        let fixture = system_fixture_with_apk(true, true);
        let root = Directory::open(&fixture.root).unwrap();
        let store = || ProductCandidateStore {
            root: fixture.root.clone(),
            reconstruct: true,
        };
        let old = crate::installed_product::load_manifest_in(&fixture.root).unwrap();
        assert_eq!(
            store().recover_product_activation().unwrap(),
            Some(Admission::InstallApk)
        );
        let recovery = system_recovery(&fixture);
        let previous = recovery.open_child(PREVIOUS).unwrap();
        let old_apk = previous
            .read_trusted("voboost-app.apk", 1024 * 1024, FILE_MODE)
            .unwrap();
        assert_eq!(
            crate::trust::sha256_bytes(&old_apk),
            old.artifact("voboost-app.apk").unwrap().sha256
        );
        let complete = root
            .open_child(INSTALL_ROOT)
            .unwrap()
            .open_child(&fixture.candidate.transaction_id)
            .unwrap()
            .open_child(COMPLETE_CANDIDATE)
            .unwrap();
        let new = voboost_contract::release::Manifest::parse(
            &complete
                .read_trusted(MANIFEST, 1024 * 1024, FILE_MODE)
                .unwrap(),
        )
        .unwrap();
        let apk = new.artifact("voboost-app.apk").unwrap();
        write_host_apk_observation(
            &root,
            &complete
                .read_trusted("voboost-app.apk", 1024 * 1024, FILE_MODE)
                .unwrap(),
            apk.version_code.unwrap(),
            apk.certificate_sha256.as_deref().unwrap(),
            "/data/app/ru.voboost/base.apk",
        );
        let journal = ProposalJournal::parse(
            &recovery
                .read_trusted(JOURNAL, MAX_STATUS_BYTES, FILE_MODE)
                .unwrap(),
        )
        .unwrap();
        let lease = acquire_update_lease(&fixture.root, &journal).unwrap();
        prepare_apk_rollback(&fixture.root, &recovery, &lease).unwrap();
        assert_eq!(
            previous
                .read_trusted("voboost-app.apk", 1024 * 1024, FILE_MODE)
                .unwrap(),
            old_apk
        );
        drop(lease);
        assert_eq!(
            store().recover_product_activation().unwrap(),
            Some(Admission::Pending)
        );
        assert_eq!(
            store().recover_product_activation().unwrap(),
            Some(Admission::Pending)
        );
        publish_policy_prepare_fixture(&fixture);
        assert_eq!(
            store().recover_product_activation().unwrap(),
            Some(Admission::Pending)
        );
        publish_system_switch_fixture(&fixture);
        assert_eq!(
            store().recover_product_activation().unwrap(),
            Some(Admission::RebootRequired)
        );
        set_host_boot_and_running(
            &root,
            "00000000-0000-0000-0000-000000000002",
            &fixture.daemon,
        );
        assert_eq!(
            store().recover_product_activation().unwrap(),
            Some(Admission::Pending)
        );
        for (source, target, mode) in [
            ("system-init-previous", "system-init.host", 0o644),
            ("policy-previous", "policy.host", 0o644),
            ("voboost.rc", "voboost.rc", 0o644),
            ("voboost-selinux", "voboost-selinux", 0o700),
        ] {
            root.write_atomic(
                target,
                &previous
                    .read_trusted(source, 64 * 1024 * 1024, FILE_MODE)
                    .unwrap(),
                mode,
            )
            .unwrap();
        }
        let failure = voboost_contract::system_update::SystemFailureAck {
            schema_version: 1,
            transaction_id: fixture.candidate.transaction_id.clone(),
            boot_id: "00000000-0000-0000-0000-000000000002".into(),
            phase: "system-post-reboot".into(),
            reboot_required: true,
        };
        recovery
            .write_atomic(
                voboost_contract::system_update::SYSTEM_FAILURE_ACK,
                &failure.canonical_bytes().unwrap(),
                FILE_MODE,
            )
            .unwrap();
        for _ in 0..2 {
            assert_eq!(
                store().recover_product_activation().unwrap(),
                Some(Admission::Pending)
            );
        }
        assert_system_phase(&fixture, ProposalPhase::SystemPostReboot);
        let apk = old.artifact("voboost-app.apk").unwrap();
        write_host_apk_observation(
            &root,
            &old_apk,
            apk.version_code.unwrap(),
            apk.certificate_sha256.as_deref().unwrap(),
            "/data/app/ru.voboost/base.apk",
        );
        assert_eq!(
            store().recover_product_activation().unwrap(),
            Some(Admission::Pending)
        );
        root.write_atomic(
            "voboost-inject",
            &previous
                .read_trusted("voboost-inject", 1024 * 1024, FILE_MODE)
                .unwrap(),
            0o700,
        )
        .unwrap();
        assert_eq!(
            store().recover_product_activation().unwrap(),
            Some(Admission::RebootRequired)
        );
        set_host_boot_and_running(
            &root,
            "00000000-0000-0000-0000-000000000003",
            &fixture.daemon,
        );
        assert_eq!(
            store().recover_product_activation().unwrap(),
            Some(Admission::Pending)
        );
        let ack = voboost_contract::system_update::SystemRollbackAck {
            schema_version: 1,
            transaction_id: fixture.candidate.transaction_id.clone(),
            boot_id: "00000000-0000-0000-0000-000000000003".into(),
            init_previous_sha256: crate::trust::sha256_bytes(
                &previous
                    .read_trusted("system-init-previous", 1024 * 1024, FILE_MODE)
                    .unwrap(),
            ),
            policy_previous_sha256: crate::trust::sha256_bytes(&fixture.policy_previous),
            enforcing: true,
            daemon_domain: "u:r:voboost:s0".into(),
        };
        recovery
            .write_atomic(
                voboost_contract::system_update::SYSTEM_ROLLBACK_ACK,
                &ack.canonical_bytes().unwrap(),
                FILE_MODE,
            )
            .unwrap();
        assert_eq!(
            store().recover_product_activation().unwrap(),
            Some(Admission::ActivationFailed)
        );
        let restored = crate::installed_product::load_manifest_in(&fixture.root).unwrap();
        assert_eq!(restored.digest().unwrap(), fixture.old_manifest_sha256);
        crate::installed_product::verify_candidate_closure_in(&restored, true, &fixture.root)
            .unwrap();
        verify_uninstall_inventory(&root, &restored).unwrap();
        assert_eq!(
            store().recover_product_activation().unwrap(),
            Some(Admission::ActivationFailed)
        );
    }

    #[test]
    fn system_failure_projection_preserves_the_journal_and_survives_reacquisition() {
        let fixture = system_fixture_with_inject(true);
        let store = ProductCandidateStore {
            root: fixture.root.clone(),
            reconstruct: true,
        };
        let root = Directory::open(&fixture.root).unwrap();
        assert_eq!(
            store.recover_product_activation().unwrap(),
            Some(Admission::Pending)
        );
        publish_policy_prepare_fixture(&fixture);
        assert_eq!(
            store.recover_product_activation().unwrap(),
            Some(Admission::Pending)
        );
        publish_system_switch_fixture(&fixture);
        assert_eq!(
            store.recover_product_activation().unwrap(),
            Some(Admission::RebootRequired)
        );
        set_host_boot_and_running(
            &root,
            "00000000-0000-0000-0000-000000000002",
            &fixture.daemon,
        );
        assert_eq!(
            store.recover_product_activation().unwrap(),
            Some(Admission::Pending)
        );

        let recovery = system_recovery(&fixture);
        let bytes = recovery
            .read_trusted(JOURNAL, MAX_STATUS_BYTES, FILE_MODE)
            .unwrap();
        let journal = ProposalJournal::parse(&bytes).unwrap();
        let lease = acquire_update_lease(&fixture.root, &journal).unwrap();
        let diagnostic = "Ошибка системного обновления. \n\t\0".repeat(100);
        publish_system_failure(&journal, &lease, &diagnostic).unwrap();
        let failed = crate::operation_contract::read_current_in(&fixture.root)
            .unwrap()
            .unwrap();
        assert_eq!(failed.outcome, "failed");
        assert!(
            failed.error.as_ref().unwrap()["message"]
                .as_str()
                .unwrap()
                .len()
                <= 512
        );
        assert!(!failed.error.as_ref().unwrap()["message"]
            .as_str()
            .unwrap()
            .chars()
            .any(char::is_control));
        assert_eq!(failed.phase, "update-product-system-post-reboot");
        assert_eq!(failed.transaction_id, fixture.candidate.transaction_id);
        assert_eq!(
            failed.error.as_ref().unwrap()["code"],
            "product-system-update-failed"
        );
        assert_eq!(
            recovery
                .read_trusted(JOURNAL, MAX_STATUS_BYTES, FILE_MODE)
                .unwrap(),
            bytes
        );
        drop(lease);
        let lease = acquire_update_lease(&fixture.root, &journal).unwrap();
        publish_system_failure(&journal, &lease, &diagnostic).unwrap();
        publish_system_failure(
            &journal,
            &lease,
            "later detail must not replace the first failure",
        )
        .unwrap();
        assert_eq!(
            crate::operation_contract::read_current_in(&fixture.root)
                .unwrap()
                .unwrap(),
            failed
        );
    }

    #[test]
    fn system_rollback_helper_wait_survives_restarts_and_accepts_late_receipt() {
        let fixture = system_fixture_with_inject(true);
        let store = ProductCandidateStore {
            root: fixture.root.clone(),
            reconstruct: true,
        };
        let root = Directory::open(&fixture.root).unwrap();
        assert_eq!(
            store.recover_product_activation().unwrap(),
            Some(Admission::Pending)
        );
        publish_policy_prepare_fixture(&fixture);
        assert_eq!(
            store.recover_product_activation().unwrap(),
            Some(Admission::Pending)
        );
        publish_system_switch_fixture(&fixture);
        assert_eq!(
            store.recover_product_activation().unwrap(),
            Some(Admission::RebootRequired)
        );
        set_host_boot_and_running(
            &root,
            "00000000-0000-0000-0000-000000000002",
            &fixture.daemon,
        );
        assert_eq!(
            store.recover_product_activation().unwrap(),
            Some(Admission::Pending)
        );

        let recovery = system_recovery(&fixture);
        let previous = recovery.open_child(PREVIOUS).unwrap();
        for (source, target, mode) in [
            ("system-init-previous", "system-init.host", 0o644),
            ("policy-previous", "policy.host", 0o644),
            ("voboost.rc", "voboost.rc", 0o644),
            ("voboost-selinux", "voboost-selinux", 0o700),
        ] {
            let bytes = previous
                .read_trusted(source, 64 * 1024 * 1024, FILE_MODE)
                .unwrap();
            root.write_atomic(target, &bytes, mode).unwrap();
        }
        let failure = voboost_contract::system_update::SystemFailureAck {
            schema_version: 1,
            transaction_id: fixture.candidate.transaction_id.clone(),
            boot_id: "00000000-0000-0000-0000-000000000002".into(),
            phase: "system-post-reboot".into(),
            reboot_required: true,
        };
        recovery
            .write_atomic(
                voboost_contract::system_update::SYSTEM_FAILURE_ACK,
                &failure.canonical_bytes().unwrap(),
                FILE_MODE,
            )
            .unwrap();
        let candidate_inject = root.read_trusted("voboost-inject", 1024, 0o700).unwrap();
        let old_inject = previous
            .read_trusted("voboost-inject", 1024, FILE_MODE)
            .unwrap();
        assert_ne!(candidate_inject, old_inject);
        assert_eq!(
            store.recover_product_activation().unwrap(),
            Some(Admission::Pending)
        );
        assert_system_phase(&fixture, ProposalPhase::SystemPostReboot);
        assert_eq!(
            root.read_trusted("voboost-inject", 1024, 0o700).unwrap(),
            candidate_inject
        );
        root.write_atomic("voboost-inject", &old_inject, 0o700)
            .unwrap();
        assert_eq!(
            store.recover_product_activation().unwrap(),
            Some(Admission::RebootRequired)
        );
        set_host_boot_and_running(
            &root,
            "00000000-0000-0000-0000-000000000003",
            &fixture.daemon,
        );
        assert_eq!(
            store.recover_product_activation().unwrap(),
            Some(Admission::Pending)
        );
        assert_system_phase(&fixture, ProposalPhase::SystemRollbackPostReboot);
        for _ in 0..25 {
            assert_eq!(
                store.recover_product_activation().unwrap(),
                Some(Admission::Pending)
            );
        }

        let rollback = voboost_contract::system_update::SystemRollbackAck {
            schema_version: 1,
            transaction_id: fixture.candidate.transaction_id.clone(),
            boot_id: "00000000-0000-0000-0000-000000000003".into(),
            init_previous_sha256: crate::trust::sha256_bytes(
                &previous
                    .read_trusted("system-init-previous", 1024 * 1024, FILE_MODE)
                    .unwrap(),
            ),
            policy_previous_sha256: crate::trust::sha256_bytes(&fixture.policy_previous),
            enforcing: true,
            daemon_domain: "u:r:voboost:s0".into(),
        };
        let mut wrong = rollback.clone();
        wrong.transaction_id = "f".repeat(64);
        recovery
            .write_atomic(
                voboost_contract::system_update::SYSTEM_ROLLBACK_ACK,
                &wrong.canonical_bytes().unwrap(),
                FILE_MODE,
            )
            .unwrap();
        assert!(store
            .recover_product_activation()
            .unwrap_err()
            .contains("system rollback receipt differs from product WAL"));
        assert_system_phase(&fixture, ProposalPhase::SystemRollbackPostReboot);
        recovery
            .write_atomic(
                voboost_contract::system_update::SYSTEM_ROLLBACK_ACK,
                &rollback.canonical_bytes().unwrap(),
                FILE_MODE,
            )
            .unwrap();
        assert_eq!(
            store.recover_product_activation().unwrap(),
            Some(Admission::ActivationFailed)
        );
    }

    #[test]
    fn system_helper_wrong_receipt_correction_progresses_same_wal() {
        let fixture = system_fixture();
        let store = ProductCandidateStore {
            root: fixture.root.clone(),
            reconstruct: true,
        };
        assert_eq!(
            store.recover_product_activation().unwrap(),
            Some(Admission::Pending)
        );
        publish_policy_prepare_fixture(&fixture);
        let recovery = system_recovery(&fixture);
        let mut ack = voboost_contract::system_update::PolicyPrepareAck::parse(
            &recovery
                .read_trusted(
                    voboost_contract::system_update::POLICY_PREPARE_ACK,
                    voboost_contract::system_update::MAX_SYSTEM_ACK_BYTES,
                    FILE_MODE,
                )
                .unwrap(),
        )
        .unwrap();
        let valid = ack.clone();
        ack.transaction_id = "f".repeat(64);
        recovery
            .write_atomic(
                voboost_contract::system_update::POLICY_PREPARE_ACK,
                &ack.canonical_bytes().unwrap(),
                FILE_MODE,
            )
            .unwrap();
        assert!(store
            .recover_product_activation()
            .unwrap_err()
            .contains("policy prepare receipt differs from product WAL"));
        assert_system_phase(&fixture, ProposalPhase::SystemPrepared);
        recovery
            .write_atomic(
                voboost_contract::system_update::POLICY_PREPARE_ACK,
                &valid.canonical_bytes().unwrap(),
                FILE_MODE,
            )
            .unwrap();
        assert_eq!(
            store.recover_product_activation().unwrap(),
            Some(Admission::Pending)
        );
        assert_system_phase(&fixture, ProposalPhase::SystemHelperRequested);
    }

    #[test]
    fn system_plan_cleanup_removes_preserved_native_members() {
        let fixture = system_fixture();
        let root = Directory::open(&fixture.root).unwrap();
        let install_root = root.open_child(INSTALL_ROOT).unwrap();
        let recovery_root = root.open_child(RECOVERY_ROOT).unwrap();
        let install = install_root
            .open_child(&fixture.candidate.transaction_id)
            .unwrap();
        let recovery = recovery_root
            .open_child(&fixture.candidate.transaction_id)
            .unwrap();
        let complete = install.open_child(COMPLETE_CANDIDATE).unwrap();
        let manifest = load_manifest_from_directory(&complete).unwrap();
        let mut candidate = fixture.candidate.clone();
        let daemon = manifest.artifact("voboost-daemon").unwrap();
        candidate
            .artifacts
            .push(voboost_contract::status::CandidateArtifactIdentity {
                file: daemon.file.clone(),
                size: daemon.size,
                sha256: daemon.sha256.clone(),
            });
        let classes = activation_classes(&candidate).unwrap();
        assert!(voboost_contract::product_update::is_system_plan(
            &candidate, &classes
        ));
        assert!(!is_native_plan(&candidate, &classes));
        let previous = recovery.open_or_create_private_child(PREVIOUS).unwrap();
        previous
            .write_atomic("voboost-daemon", &fixture.daemon, FILE_MODE)
            .unwrap();
        previous.sync_all().unwrap();
        let mut journal = ProposalJournal::parse(
            &recovery
                .read_trusted(JOURNAL, MAX_STATUS_BYTES, FILE_MODE)
                .unwrap(),
        )
        .unwrap();
        journal.candidate = candidate.clone();
        journal.phase = ProposalPhase::Complete;
        write_journal(&recovery, &journal).unwrap();
        cleanup_product_transaction(
            &root,
            &install_root,
            &recovery_root,
            &install,
            &recovery,
            &manifest,
            &candidate,
        )
        .unwrap();
        assert!(!install_root
            .entry_exists(&candidate.transaction_id)
            .unwrap());
        assert!(!recovery_root
            .entry_exists(&candidate.transaction_id)
            .unwrap());
    }

    #[test]
    fn system_init_policy_one_reboot_and_rollback_matrix() {
        let fixture = system_fixture();
        let root = Directory::open(&fixture.root).unwrap();
        assert_eq!(
            continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
            Admission::Pending
        );
        let journal = ProposalJournal::parse(
            &system_recovery(&fixture)
                .read_trusted(JOURNAL, MAX_STATUS_BYTES, FILE_MODE)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(journal.phase, ProposalPhase::SystemPrepared);
        assert_eq!(
            crate::installed_product::load_manifest_in(&fixture.root)
                .unwrap()
                .digest()
                .unwrap(),
            fixture.old_manifest_sha256
        );

        publish_policy_prepare_fixture(&fixture);
        assert_eq!(
            continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
            Admission::Pending
        );
        publish_system_switch_fixture(&fixture);
        assert_eq!(
            continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
            Admission::Pending
        );
        assert_eq!(
            continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
            Admission::RebootRequired
        );
        assert!(authorize_reboot_in(&fixture.root).unwrap());
        assert_eq!(
            crate::installed_product::load_manifest_in(&fixture.root)
                .unwrap()
                .digest()
                .unwrap(),
            fixture.old_manifest_sha256
        );

        set_host_boot_and_running(
            &root,
            "00000000-0000-0000-0000-000000000002",
            &fixture.daemon,
        );
        assert_eq!(
            continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
            Admission::Pending
        );
        publish_system_post_boot_fixture(&fixture, "00000000-0000-0000-0000-000000000002");
        assert_eq!(
            continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
            Admission::Pending
        );
        assert_eq!(
            crate::installed_product::load_manifest_in(&fixture.root)
                .unwrap()
                .digest()
                .unwrap(),
            fixture.old_manifest_sha256
        );
        while continue_generation_only(&fixture.root, &fixture.candidate).unwrap()
            != Admission::Accepted
        {}
        let active = crate::installed_product::load_manifest_in(&fixture.root).unwrap();
        assert_eq!(active.release_identity, fixture.candidate.release_identity);
        crate::installed_product::verify_candidate_closure_in(&active, true, &fixture.root)
            .unwrap();
        verify_uninstall_inventory(&root, &active).unwrap();
        assert_eq!(
            read_terminal_result(&fixture.root, &fixture.candidate).unwrap(),
            Some(Admission::Accepted)
        );
        let operation = crate::operation_contract::read_current_in(&fixture.root)
            .unwrap()
            .unwrap();
        assert_eq!(operation.reboot_count, 1);
        assert_eq!(operation.boot_id, "00000000-0000-0000-0000-000000000002");

        for mutation in ["boot", "baseline", "candidate"] {
            let fixture = system_fixture();
            assert_eq!(
                continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
                Admission::Pending
            );
            publish_policy_prepare_fixture(&fixture);
            let recovery = system_recovery(&fixture);
            let mut ack = voboost_contract::system_update::PolicyPrepareAck {
                schema_version: 1,
                transaction_id: fixture.candidate.transaction_id.clone(),
                boot_id: "00000000-0000-0000-0000-000000000001".into(),
                policy_baseline_sha256: crate::trust::sha256_bytes(&fixture.policy_baseline),
                policy_candidate_sha256: crate::trust::sha256_bytes(&fixture.policy_candidate),
            };
            match mutation {
                "boot" => ack.boot_id = "00000000-0000-0000-0000-000000000009".into(),
                "baseline" => ack.policy_baseline_sha256 = "f".repeat(64),
                "candidate" => ack.policy_candidate_sha256 = "f".repeat(64),
                _ => unreachable!(),
            }
            recovery
                .write_atomic(
                    voboost_contract::system_update::POLICY_PREPARE_ACK,
                    &ack.canonical_bytes().unwrap(),
                    FILE_MODE,
                )
                .unwrap();
            assert!(continue_generation_only(&fixture.root, &fixture.candidate).is_err());
        }

        let fixture = system_fixture();
        let root = Directory::open(&fixture.root).unwrap();
        assert_eq!(
            continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
            Admission::Pending
        );
        publish_policy_prepare_fixture(&fixture);
        assert_eq!(
            continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
            Admission::Pending
        );
        publish_system_switch_fixture(&fixture);
        assert_eq!(
            continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
            Admission::Pending
        );
        assert_eq!(
            continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
            Admission::RebootRequired
        );
        set_host_boot_and_running(
            &root,
            "00000000-0000-0000-0000-000000000002",
            &fixture.daemon,
        );
        assert_eq!(
            continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
            Admission::Pending
        );
        let recovery = system_recovery(&fixture);
        let previous = recovery.open_child(PREVIOUS).unwrap();
        for (source, target, mode) in [
            ("system-init-previous", "system-init.host", 0o644),
            ("policy-previous", "policy.host", 0o644),
            ("voboost.rc", "voboost.rc", 0o644),
            ("voboost-selinux", "voboost-selinux", 0o700),
        ] {
            let bytes = previous
                .read_trusted(source, 64 * 1024 * 1024, FILE_MODE)
                .unwrap();
            root.write_atomic(target, &bytes, mode).unwrap();
        }
        let failure = voboost_contract::system_update::SystemFailureAck {
            schema_version: 1,
            transaction_id: fixture.candidate.transaction_id.clone(),
            boot_id: "00000000-0000-0000-0000-000000000002".into(),
            phase: "system-post-reboot".into(),
            reboot_required: true,
        };
        recovery
            .write_atomic(
                voboost_contract::system_update::SYSTEM_FAILURE_ACK,
                &failure.canonical_bytes().unwrap(),
                FILE_MODE,
            )
            .unwrap();
        assert_eq!(
            continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
            Admission::RebootRequired
        );
        assert!(authorize_reboot_in(&fixture.root).unwrap());
        set_host_boot_and_running(
            &root,
            "00000000-0000-0000-0000-000000000003",
            &fixture.daemon,
        );
        assert_eq!(
            continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
            Admission::Pending
        );
        let operation = crate::operation_contract::read_current_in(&fixture.root)
            .unwrap()
            .unwrap();
        assert_eq!(operation.reboot_count, 2);
        assert_eq!(operation.boot_id, "00000000-0000-0000-0000-000000000003");
        let rollback = voboost_contract::system_update::SystemRollbackAck {
            schema_version: 1,
            transaction_id: fixture.candidate.transaction_id.clone(),
            boot_id: "00000000-0000-0000-0000-000000000003".into(),
            init_previous_sha256: crate::trust::sha256_bytes(
                &previous
                    .read_trusted("system-init-previous", 1024 * 1024, FILE_MODE)
                    .unwrap(),
            ),
            policy_previous_sha256: crate::trust::sha256_bytes(&fixture.policy_previous),
            enforcing: true,
            daemon_domain: "u:r:voboost:s0".into(),
        };
        recovery
            .write_atomic(
                voboost_contract::system_update::SYSTEM_ROLLBACK_ACK,
                &rollback.canonical_bytes().unwrap(),
                FILE_MODE,
            )
            .unwrap();
        assert_eq!(
            continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
            Admission::ActivationFailed
        );
        let active = crate::installed_product::load_manifest_in(&fixture.root).unwrap();
        assert_eq!(active.digest().unwrap(), fixture.old_manifest_sha256);
        crate::installed_product::verify_candidate_closure_in(&active, true, &fixture.root)
            .unwrap();
        assert_eq!(
            continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
            Admission::ActivationFailed
        );
        assert_eq!(
            read_terminal_result(&fixture.root, &fixture.candidate).unwrap(),
            Some(Admission::ActivationFailed)
        );
        let receipt = terminal_acknowledgement_in(&fixture.root).unwrap().unwrap();
        assert_eq!(receipt.transaction_id, fixture.candidate.transaction_id);
        assert_eq!(
            receipt.outcome,
            voboost_contract::status::TerminalOutcome::Rejected
        );
        let operation = crate::operation_contract::read_current_in(&fixture.root)
            .unwrap()
            .unwrap();
        assert_eq!(operation.reboot_count, 2);
        assert_eq!(operation.boot_id, "00000000-0000-0000-0000-000000000003");
    }

    #[test]
    fn proposal_journal_is_canonical_and_rejects_unknown_fields() {
        let candidate = OtaCandidateHandle {
            transaction_id: "a".repeat(64),
            release_identity: "1.0.0-beta2".into(),
            manifest_sha256: "b".repeat(64),
            artifacts: Vec::new(),
        };
        let journal = ProposalJournal::new(&candidate);
        assert_eq!(
            ProposalJournal::parse(&journal.canonical_bytes().unwrap()).unwrap(),
            journal
        );
        assert!(ProposalJournal::parse(
            br#"{"schemaVersion":1,"operation":"product-update-proposal","candidate":{},"phase":"copying","extra":true}\n"#,
        )
        .is_err());
    }

    #[test]
    fn product_operation_projection_tracks_forward_and_rollback_boots() {
        let identity = |file: &str| voboost_contract::status::CandidateArtifactIdentity {
            file: file.to_string(),
            size: 1,
            sha256: "b".repeat(64),
        };
        let candidate = OtaCandidateHandle {
            transaction_id: "a".repeat(64),
            release_identity: "1.0.0-beta2".into(),
            manifest_sha256: "c".repeat(64),
            artifacts: ["voboost-daemon", "restore.json", "restore.json.sig"]
                .into_iter()
                .map(identity)
                .collect(),
        };
        let mut journal = ProposalJournal::new(&candidate);
        journal.pre_reboot_boot_id = Some("00000000-0000-0000-0000-000000000001".into());
        journal.post_reboot_boot_id = Some("00000000-0000-0000-0000-000000000002".into());
        journal.phase = ProposalPhase::Complete;
        let forward = operation_projection(&journal).unwrap();
        assert_eq!(forward.reboot_count, 1);
        assert_eq!(forward.boot_id, "00000000-0000-0000-0000-000000000002");

        journal.rollback_boot_id = Some("00000000-0000-0000-0000-000000000003".into());
        journal.failure = Some("product activation rolled back".into());
        journal.phase = ProposalPhase::RolledBack;
        let native_rollback = operation_projection(&journal).unwrap();
        assert_eq!(native_rollback.reboot_count, 2);
        assert_eq!(
            native_rollback.boot_id,
            "00000000-0000-0000-0000-000000000003"
        );

        let mut system_candidate = candidate;
        system_candidate.artifacts = ["voboost.rc", "restore.json", "restore.json.sig"]
            .into_iter()
            .map(identity)
            .collect();
        let mut system_rollback = ProposalJournal::new(&system_candidate);
        system_rollback.pre_reboot_boot_id = journal.pre_reboot_boot_id;
        system_rollback.post_reboot_boot_id = journal.post_reboot_boot_id;
        system_rollback.rollback_boot_id = journal.rollback_boot_id;
        system_rollback.failure = journal.failure;
        system_rollback.phase = ProposalPhase::RolledBack;
        let system_rollback = operation_projection(&system_rollback).unwrap();
        assert_eq!(system_rollback.reboot_count, 2);
        assert_eq!(
            system_rollback.boot_id,
            "00000000-0000-0000-0000-000000000003"
        );
    }

    #[test]
    fn product_activation_plan_is_derived_only_from_changed_manifest_basenames() {
        let identity = |file: &str| {
            let (_, _, _) = voboost_contract::release::classify(file).unwrap();
            voboost_contract::status::CandidateArtifactIdentity {
                file: file.to_string(),
                size: 1,
                sha256: "b".repeat(64),
            }
        };
        let candidate = OtaCandidateHandle {
            transaction_id: "a".repeat(64),
            release_identity: "1.0.0-beta2".into(),
            manifest_sha256: "c".repeat(64),
            artifacts: [
                "voboost-app.apk",
                "voboost-daemon",
                "restore.json",
                "agent-settings.dex",
            ]
            .into_iter()
            .map(identity)
            .collect(),
        };
        assert_eq!(
            activation_classes(&candidate).unwrap(),
            vec![
                ProductActivationClass::PackageInstaller,
                ProductActivationClass::AgentGeneration,
                ProductActivationClass::NativeRuntime,
                ProductActivationClass::RestoreAuthority,
            ]
        );
        let metadata = OtaCandidateHandle {
            artifacts: Vec::new(),
            ..candidate
        };
        assert_eq!(
            activation_classes(&metadata).unwrap(),
            vec![ProductActivationClass::MetadataOnly]
        );
    }

    #[test]
    fn realistic_one_agent_release_keeps_restore_pair_atomic_without_reboot() {
        let candidate = OtaCandidateHandle {
            transaction_id: "a".repeat(64),
            release_identity: "1.0.0-beta2".into(),
            manifest_sha256: "c".repeat(64),
            artifacts: ["restore.json", "restore.json.sig", "agent-settings.dex"]
                .into_iter()
                .map(|file| voboost_contract::status::CandidateArtifactIdentity {
                    file: file.to_string(),
                    size: 1,
                    sha256: "b".repeat(64),
                })
                .collect(),
        };
        let classes = activation_classes(&candidate).unwrap();
        assert_eq!(
            classes,
            vec![
                ProductActivationClass::AgentGeneration,
                ProductActivationClass::RestoreAuthority,
            ]
        );
        assert!(is_generation_only_plan(&classes));
        for forbidden in ["voboost-app.apk", "voboost-daemon", "voboost.rc"] {
            let mut hostile = candidate.clone();
            hostile
                .artifacts
                .push(voboost_contract::status::CandidateArtifactIdentity {
                    file: forbidden.into(),
                    size: 1,
                    sha256: "d".repeat(64),
                });
            assert!(!is_generation_only_plan(
                &activation_classes(&hostile).unwrap()
            ));
        }
    }

    #[test]
    fn apk_only_plan_requires_exact_app_and_restore_pair_without_mixed_roles() {
        let identity = |file: &str| voboost_contract::status::CandidateArtifactIdentity {
            file: file.to_string(),
            size: 1,
            sha256: "b".repeat(64),
        };
        let candidate = OtaCandidateHandle {
            transaction_id: "a".repeat(64),
            release_identity: "1.0.0-beta2".into(),
            manifest_sha256: "c".repeat(64),
            artifacts: ["voboost-app.apk", "restore.json", "restore.json.sig"]
                .into_iter()
                .map(identity)
                .collect(),
        };
        let classes = activation_classes(&candidate).unwrap();
        assert!(is_apk_only_plan(&candidate, &classes));
        for missing in ["restore.json", "restore.json.sig"] {
            let mut hostile = candidate.clone();
            hostile
                .artifacts
                .retain(|artifact| artifact.file != missing);
            assert!(!is_apk_only_plan(
                &hostile,
                &activation_classes(&hostile).unwrap()
            ));
        }
        for mixed in ["agent-settings.dex", "voboost-daemon", "voboost.rc"] {
            let mut hostile = candidate.clone();
            hostile.artifacts.push(identity(mixed));
            assert!(!is_apk_only_plan(
                &hostile,
                &activation_classes(&hostile).unwrap()
            ));
        }
    }

    #[test]
    fn native_product_plan_accepts_native_and_mixed_but_rejects_init() {
        let identity = |file: &str| voboost_contract::status::CandidateArtifactIdentity {
            file: file.to_string(),
            size: 1,
            sha256: "b".repeat(64),
        };
        for extra in [None, Some("agent-settings.dex"), Some("voboost-app.apk")] {
            let mut files = vec![
                "voboost-daemon",
                "libimplant-arm64-v8a.so",
                "restore.json",
                "restore.json.sig",
            ];
            files.extend(extra);
            let candidate = OtaCandidateHandle {
                transaction_id: "a".repeat(64),
                release_identity: "1.0.0-beta2".into(),
                manifest_sha256: "c".repeat(64),
                artifacts: files.into_iter().map(identity).collect(),
            };
            assert!(is_native_plan(
                &candidate,
                &activation_classes(&candidate).unwrap()
            ));
        }
        let candidate = OtaCandidateHandle {
            transaction_id: "a".repeat(64),
            release_identity: "1.0.0-beta2".into(),
            manifest_sha256: "c".repeat(64),
            artifacts: [
                "voboost-daemon",
                "voboost.rc",
                "restore.json",
                "restore.json.sig",
            ]
            .into_iter()
            .map(identity)
            .collect(),
        };
        assert!(!is_native_plan(
            &candidate,
            &activation_classes(&candidate).unwrap()
        ));
        let candidate = OtaCandidateHandle {
            artifacts: [
                "voboost-daemon",
                "voboost-selinux",
                "restore.json",
                "restore.json.sig",
            ]
            .into_iter()
            .map(identity)
            .collect(),
            ..candidate
        };
        assert!(!is_native_plan(
            &candidate,
            &activation_classes(&candidate).unwrap()
        ));
    }

    #[test]
    fn generation_only_crash_cuts_converge_and_accept_only_terminal_replay() {
        use std::os::unix::fs::PermissionsExt;

        let candidate = OtaCandidateHandle {
            transaction_id: "a".repeat(64),
            release_identity: "1.0.0-beta2".into(),
            manifest_sha256: "c".repeat(64),
            artifacts: ["restore.json", "restore.json.sig", "agent-settings.dex"]
                .into_iter()
                .map(|file| voboost_contract::status::CandidateArtifactIdentity {
                    file: file.to_string(),
                    size: 1,
                    sha256: "b".repeat(64),
                })
                .collect(),
        };
        let temporary = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let root = Directory::open(temporary.path()).unwrap();
        let recovery = root.open_or_create_private_child(RECOVERY_ROOT).unwrap();
        let transaction = recovery
            .open_or_create_private_child(&candidate.transaction_id)
            .unwrap();
        let mut journal = ProposalJournal::new(&candidate);
        journal.phase = ProposalPhase::Reconstructed;
        journal.previous_generation = Some("d".repeat(64));
        journal.next_generation = Some("e".repeat(64));
        write_journal(&transaction, &journal).unwrap();
        let lease = acquire_update_lease(temporary.path(), &journal).unwrap();
        for phase in [
            ProposalPhase::GenerationPrepared,
            ProposalPhase::RecoveryPrepared,
            ProposalPhase::RestoreSwitched,
            ProposalPhase::GenerationSwitched,
            ProposalPhase::InventoryPublished,
            ProposalPhase::ManifestPublished,
            ProposalPhase::ProductVerified,
        ] {
            transition(&transaction, &lease, &mut journal, phase).unwrap();
            let projection = crate::operation_contract::read_current_in(temporary.path())
                .unwrap()
                .unwrap();
            assert_eq!(projection.transaction_id, candidate.transaction_id);
            assert_eq!(
                projection.journal,
                format!("recovery/{}/{}", candidate.transaction_id, JOURNAL)
            );
            assert_eq!(projection.outcome, "running");
        }
        assert!(ProposalPhase::InventoryPublished < ProposalPhase::ManifestPublished);
        transition(&transaction, &lease, &mut journal, ProposalPhase::Complete).unwrap();
        let terminal = crate::operation_contract::read_current_in(temporary.path())
            .unwrap()
            .unwrap();
        assert_eq!(terminal.outcome, "complete");
        assert_eq!(terminal.transaction_id, candidate.transaction_id);

        let rolled_back_root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            rolled_back_root.path(),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let root = Directory::open(rolled_back_root.path()).unwrap();
        let recovery = root.open_or_create_private_child(RECOVERY_ROOT).unwrap();
        let transaction = recovery
            .open_or_create_private_child(&candidate.transaction_id)
            .unwrap();
        let mut rolled_back = ProposalJournal::new(&candidate);
        rolled_back.phase = ProposalPhase::RecoveryPrepared;
        rolled_back.previous_generation = Some("d".repeat(64));
        rolled_back.next_generation = Some("e".repeat(64));
        write_journal(&transaction, &rolled_back).unwrap();
        let lease = acquire_update_lease(rolled_back_root.path(), &rolled_back).unwrap();
        rolled_back.failure = Some("product activation rolled back".into());
        transition(
            &transaction,
            &lease,
            &mut rolled_back,
            ProposalPhase::RolledBack,
        )
        .unwrap();
        assert_eq!(
            crate::operation_contract::read_current_in(rolled_back_root.path())
                .unwrap()
                .unwrap()
                .outcome,
            "complete"
        );
    }

    #[test]
    fn generation_only_filesystem_restarts_converge_at_every_durable_phase() {
        for completed_phases in 0..7 {
            let fixture = product_fixture();
            for _ in 0..completed_phases {
                assert_eq!(
                    continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
                    Admission::Pending
                );
            }
            let recovered = ProductCandidateStore {
                root: fixture.root.clone(),
                reconstruct: true,
            }
            .recover_product_activation()
            .unwrap();
            assert_eq!(recovered, Some(Admission::Accepted));
            let active = crate::installed_product::load_manifest_in(&fixture.root).unwrap();
            assert_eq!(active.release_identity, fixture.candidate.release_identity);
            crate::installed_product::verify_candidate_closure_in(&active, true, &fixture.root)
                .unwrap();
            verify_uninstall_inventory(&Directory::open(&fixture.root).unwrap(), &active).unwrap();
            let generation = crate::generation::GenerationStore::new(
                &fixture.root,
                fixture.root.join("generations/next"),
            )
            .active()
            .unwrap();
            assert_eq!(generation.id, fixture.candidate_generation_id);
            assert_eq!(
                read_terminal_result(&fixture.root, &fixture.candidate).unwrap(),
                Some(Admission::Accepted)
            );
        }
        for (cut, preceding_phases) in [
            (ProductCrashCut::GenerationPrepared, 0),
            (ProductCrashCut::RestoreSignature, 2),
            (ProductCrashCut::GenerationSwitched, 3),
            (ProductCrashCut::InventoryArtifacts, 4),
            (ProductCrashCut::ManifestSignature, 5),
        ] {
            let fixture = product_fixture();
            for _ in 0..preceding_phases {
                assert_eq!(
                    continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
                    Admission::Pending
                );
            }
            assert!(std::panic::catch_unwind(|| {
                continue_generation_only_with_cut(&fixture.root, &fixture.candidate, Some(cut))
                    .unwrap();
            })
            .is_err());
            assert_eq!(
                ProductCandidateStore {
                    root: fixture.root.clone(),
                    reconstruct: true,
                }
                .recover_product_activation()
                .unwrap(),
                Some(Admission::Accepted)
            );
            let active = crate::installed_product::load_manifest_in(&fixture.root).unwrap();
            assert_eq!(active.release_identity, fixture.candidate.release_identity);
            crate::installed_product::verify_candidate_closure_in(&active, true, &fixture.root)
                .unwrap();
            verify_uninstall_inventory(&Directory::open(&fixture.root).unwrap(), &active).unwrap();
            assert_eq!(
                read_terminal_result(&fixture.root, &fixture.candidate).unwrap(),
                Some(Admission::Accepted)
            );
        }
    }

    #[test]
    fn generation_only_terminal_cut_between_journal_and_projection_converges() {
        // R24: a crash after the Complete journal write but before the
        // terminal projection publish leaves the shared descriptor at
        // ProductVerified while the WAL names Complete. The generic acquire
        // rejects the terminal projection over the stale one; only the
        // exact derived predecessor may be reconciled, and recovery must
        // converge to the accepted complete product.
        let fixture = product_fixture();
        // Generation-only matrix: ProductVerified is the sixth Pending step.
        for _ in 0..7 {
            assert_eq!(
                continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
                Admission::Pending
            );
        }
        // Inject the terminal cut on the next (Complete) transition.
        assert!(std::panic::catch_unwind(|| {
            continue_generation_only_with_cut(
                &fixture.root,
                &fixture.candidate,
                Some(ProductCrashCut::CompleteJournalWritten),
            )
            .unwrap();
        })
        .is_err());
        // The WAL is terminal while the projection is one publication
        // behind: the unmodified store recovery must converge.
        assert_eq!(
            ProductCandidateStore {
                root: fixture.root.clone(),
                reconstruct: true,
            }
            .recover_product_activation()
            .unwrap(),
            Some(Admission::Accepted)
        );
        let active = crate::installed_product::load_manifest_in(&fixture.root).unwrap();
        assert_eq!(active.release_identity, fixture.candidate.release_identity);
        crate::installed_product::verify_candidate_closure_in(&active, true, &fixture.root)
            .unwrap();
        verify_uninstall_inventory(&Directory::open(&fixture.root).unwrap(), &active).unwrap();
        assert_eq!(
            read_terminal_result(&fixture.root, &fixture.candidate).unwrap(),
            Some(Admission::Accepted)
        );
    }

    #[test]
    fn generation_only_live_failure_rolls_back_complete_old_product() {
        let fixture = product_fixture();
        let old_manifest = crate::installed_product::load_manifest_in(&fixture.root).unwrap();
        let old_generation = crate::generation::GenerationStore::new(
            &fixture.root,
            fixture.root.join("generations/next"),
        )
        .active()
        .unwrap();
        let root = Directory::open(&fixture.root).unwrap();
        let old_restore = root.read_trusted("restore.json", 4096, 0o644).unwrap();
        for _ in 0..4 {
            assert_eq!(
                continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
                Admission::Pending
            );
        }
        let recovery = root
            .open_child(RECOVERY_ROOT)
            .unwrap()
            .open_child(&fixture.candidate.transaction_id)
            .unwrap();
        recovery
            .open_child(PREVIOUS)
            .unwrap()
            .write_atomic(NEXT_INVENTORY, b"{}", FILE_MODE)
            .unwrap();
        assert_eq!(
            recovery
                .open_child(PREVIOUS)
                .unwrap()
                .read_trusted(NEXT_INVENTORY, 16, FILE_MODE)
                .unwrap(),
            b"{}"
        );
        assert_eq!(
            continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
            Admission::ActivationFailed
        );
        let restored = crate::installed_product::load_manifest_in(&fixture.root).unwrap();
        assert_eq!(restored.digest().unwrap(), old_manifest.digest().unwrap());
        crate::installed_product::verify_candidate_closure_in(&restored, true, &fixture.root)
            .unwrap();
        verify_uninstall_inventory(&root, &restored).unwrap();
        assert_eq!(
            crate::generation::GenerationStore::new(
                &fixture.root,
                fixture.root.join("generations/next"),
            )
            .active()
            .unwrap()
            .id,
            old_generation.id
        );
        assert_eq!(
            root.read_trusted("restore.json", 4096, 0o644).unwrap(),
            old_restore
        );
        assert_eq!(
            continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
            Admission::ActivationFailed
        );
        assert_eq!(
            crate::operation_contract::read_current_in(&fixture.root)
                .unwrap()
                .unwrap()
                .outcome,
            "complete"
        );
        assert_eq!(
            read_terminal_result(&fixture.root, &fixture.candidate).unwrap(),
            Some(Admission::ActivationFailed)
        );
    }

    #[test]
    fn apk_only_cancel_restart_duplicate_and_exact_replacement_continue_once() {
        let fixture = apk_fixture();
        let root = Directory::open(&fixture.root).unwrap();
        assert_eq!(
            continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
            Admission::InstallApk
        );
        let pending_peer = pending_apk_peer_authority_in(&fixture.root)
            .unwrap()
            .unwrap();
        assert_eq!(pending_peer.file, "voboost-app.apk");
        assert_eq!(
            continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
            Admission::InstallApk
        );
        assert_eq!(
            ProductCandidateStore {
                root: fixture.root.clone(),
                reconstruct: true,
            }
            .recover_product_activation()
            .unwrap(),
            Some(Admission::InstallApk)
        );
        assert_eq!(
            crate::installed_product::load_manifest_in(&fixture.root)
                .unwrap()
                .digest()
                .unwrap(),
            fixture.old_manifest_sha256
        );
        assert_eq!(
            root.read_trusted("restore.json", 4096, 0o644).unwrap(),
            fixture.old_restore
        );

        write_host_apk_observation(
            &root,
            &fixture.new_apk,
            fixture.new_version_code,
            &fixture.new_certificate_sha256,
            "/data/app/ru.voboost/base.apk",
        );
        assert_eq!(
            continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
            Admission::Pending
        );
        assert_eq!(
            continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
            Admission::Pending
        );
        assert_eq!(
            ProductCandidateStore {
                root: fixture.root.clone(),
                reconstruct: true,
            }
            .recover_product_activation()
            .unwrap(),
            Some(Admission::Accepted)
        );
        let active = crate::installed_product::load_manifest_in(&fixture.root).unwrap();
        assert_eq!(active.release_identity, fixture.candidate.release_identity);
        crate::installed_product::verify_candidate_closure_in(&active, true, &fixture.root)
            .unwrap();
        verify_uninstall_inventory(&root, &active).unwrap();
        assert_eq!(
            read_terminal_result(&fixture.root, &fixture.candidate).unwrap(),
            Some(Admission::Accepted)
        );
        assert!(pending_apk_peer_authority_in(&fixture.root)
            .unwrap()
            .is_none());
    }

    #[test]
    fn apk_only_wrong_path_certificate_version_size_and_hash_fail_closed() {
        for hostile in ["path", "certificate", "version", "size", "hash"] {
            let fixture = apk_fixture();
            let root = Directory::open(&fixture.root).unwrap();
            assert_eq!(
                continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
                Admission::InstallApk
            );
            let (bytes, version, certificate, path) = match hostile {
                "path" => (
                    fixture.new_apk.clone(),
                    fixture.new_version_code,
                    fixture.new_certificate_sha256.clone(),
                    "/data/local/tmp/base.apk",
                ),
                "certificate" => (
                    fixture.new_apk.clone(),
                    fixture.new_version_code,
                    "f".repeat(64),
                    "/data/app/ru.voboost/base.apk",
                ),
                "version" => (
                    fixture.new_apk.clone(),
                    fixture.new_version_code + 1,
                    fixture.new_certificate_sha256.clone(),
                    "/data/app/ru.voboost/base.apk",
                ),
                "size" => (
                    b"short".to_vec(),
                    fixture.new_version_code,
                    fixture.new_certificate_sha256.clone(),
                    "/data/app/ru.voboost/base.apk",
                ),
                "hash" => (
                    b"bad-apk".to_vec(),
                    fixture.new_version_code,
                    fixture.new_certificate_sha256.clone(),
                    "/data/app/ru.voboost/base.apk",
                ),
                _ => unreachable!(),
            };
            write_host_apk_observation(&root, &bytes, version, &certificate, path);
            assert_eq!(
                continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
                Admission::ApkIdentityInvalid,
                "{hostile}"
            );
            assert_eq!(
                crate::installed_product::load_manifest_in(&fixture.root)
                    .unwrap()
                    .digest()
                    .unwrap(),
                fixture.old_manifest_sha256,
                "{hostile}"
            );
            assert_eq!(
                root.read_trusted("restore.json", 4096, 0o644).unwrap(),
                fixture.old_restore,
                "{hostile}"
            );
            assert_ne!(
                crate::operation_contract::read_current_in(&fixture.root)
                    .unwrap()
                    .unwrap()
                    .outcome,
                "complete"
            );
        }
    }

    #[test]
    fn apk_only_post_replacement_crash_cuts_converge_forward() {
        for (cut, preceding_after_observation) in [
            (ProductCrashCut::RestoreSignature, 1),
            (ProductCrashCut::InventoryArtifacts, 2),
            (ProductCrashCut::ManifestSignature, 3),
        ] {
            let fixture = apk_fixture();
            let root = Directory::open(&fixture.root).unwrap();
            assert_eq!(
                continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
                Admission::InstallApk
            );
            write_host_apk_observation(
                &root,
                &fixture.new_apk,
                fixture.new_version_code,
                &fixture.new_certificate_sha256,
                "/data/app/ru.voboost/base.apk",
            );
            assert_eq!(
                continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
                Admission::Pending
            );
            for _ in 0..preceding_after_observation {
                assert_eq!(
                    continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
                    Admission::Pending
                );
            }
            assert!(std::panic::catch_unwind(|| {
                continue_generation_only_with_cut(&fixture.root, &fixture.candidate, Some(cut))
                    .unwrap();
            })
            .is_err());
            assert_eq!(
                ProductCandidateStore {
                    root: fixture.root.clone(),
                    reconstruct: true,
                }
                .recover_product_activation()
                .unwrap(),
                Some(Admission::Accepted)
            );
            let active = crate::installed_product::load_manifest_in(&fixture.root).unwrap();
            assert_eq!(active.release_identity, fixture.candidate.release_identity);
            assert_ne!(active.digest().unwrap(), fixture.old_manifest_sha256);
            crate::installed_product::verify_candidate_closure_in(&active, true, &fixture.root)
                .unwrap();
            verify_uninstall_inventory(&root, &active).unwrap();
        }
    }

    #[test]
    fn late_commit_error_after_inventory_published_converges_through_rollback() {
        let fixture = native_fixture(false, false);
        let root = Directory::open(&fixture.root).unwrap();
        let install = voboost_shared::installed_state::prepare_canonical(&root).unwrap();
        let candidate = fixture.candidate.clone();
        // Legitimate chain into the durable late-commit phases.
        assert_eq!(
            continue_generation_only(&fixture.root, &candidate).unwrap(),
            Admission::Pending
        );
        assert_eq!(
            continue_generation_only(&fixture.root, &candidate).unwrap(),
            Admission::RebootRequired
        );
        assert!(authorize_reboot_in(&fixture.root).unwrap());
        set_host_boot_and_running(
            &root,
            "00000000-0000-0000-0000-000000000002",
            &fixture.new_daemon,
        );
        assert_eq!(
            continue_generation_only(&fixture.root, &candidate).unwrap(),
            Admission::Pending
        );
        // Durable phase InventoryPublished (seq64): publish the manifest,
        // then inject a commit-verification error on ManifestPublished by
        // corrupting the published uninstall inventory the next phase
        // verifies. The rollback transition then regresses the sequence
        // (NativeRollbackRebootRequired is seq41) and the lease rejects it.
        assert_eq!(
            continue_generation_only(&fixture.root, &candidate).unwrap(),
            Admission::Pending
        );
        // Durable phase InventoryPublished (seq64) → ManifestPublished (seq67).
        assert_eq!(
            continue_generation_only(&fixture.root, &candidate).unwrap(),
            Admission::Pending
        );
        install.unlink(INSTALLED_STATE).unwrap();
        // The commit-verification failure must publish a monotone late
        // rollback (LateRollbackRebootRequired, seq74) instead of rewinding
        // to the native-rollback slot (seq41) that the lease rejects.
        assert_eq!(
            continue_generation_only(&fixture.root, &candidate).unwrap(),
            Admission::RebootRequired
        );
        let projection = crate::operation_contract::read_current_in(&fixture.root)
            .unwrap()
            .unwrap();
        assert_eq!(
            projection.phase,
            "update-product-late-rollback-reboot-required"
        );
        assert_eq!(projection.outcome, "reboot-required");
        assert_eq!(projection.status_sequence, 74);
        assert_eq!(projection.boot_id, "00000000-0000-0000-0000-000000000002");
        // The rollback disk replacement happened in the old boot; after the
        // requested reboot lands, the operation converges terminal without
        // ever leaving WAL and observer projection divergent.
        set_host_boot_and_running(
            &root,
            "00000000-0000-0000-0000-000000000003",
            &fixture.old_daemon,
        );
        assert_eq!(
            ProductCandidateStore {
                root: fixture.root.clone(),
                reconstruct: false,
            }
            .recover_product_activation()
            .unwrap(),
            Some(Admission::ActivationFailed)
        );
        let active = crate::installed_product::load_manifest_in(&fixture.root).unwrap();
        assert_eq!(active.digest().unwrap(), fixture.old_manifest_sha256);
        crate::installed_product::verify_candidate_closure_in(&active, true, &fixture.root)
            .unwrap();
        verify_uninstall_inventory(&Directory::open(&fixture.root).unwrap(), &active).unwrap();
        let terminal = crate::operation_contract::read_current_in(&fixture.root)
            .unwrap()
            .unwrap();
        assert_eq!(terminal.phase, "update-product-rolled-back");
        assert_eq!(terminal.outcome, "complete");
        assert_eq!(terminal.status_sequence, 78);
        assert_eq!(terminal.reboot_count, 2);
        // The terminal RolledBack dispatch runs the durable cleanup so the
        // retained terminal result is readable for later callers.
        assert_eq!(
            continue_generation_only(&fixture.root, &candidate).unwrap(),
            Admission::ActivationFailed
        );
        assert_eq!(
            read_terminal_result(&fixture.root, &candidate).unwrap(),
            Some(Admission::ActivationFailed)
        );
    }

    #[test]
    fn native_only_reboot_and_rollback_cuts_converge_old_or_new() {
        let member_count = native_fixture(false, false).native_members;
        assert!(member_count > 0);
        for crash_cut in std::iter::once(None)
            .chain((0..member_count).map(|index| Some(ProductCrashCut::NativeMember(index))))
            .chain([
                Some(ProductCrashCut::NativeBeforeReboot),
                Some(ProductCrashCut::NativeRebootPublished),
            ])
        {
            let fixture = native_fixture(false, false);
            let root = Directory::open(&fixture.root).unwrap();
            assert_eq!(
                continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
                Admission::Pending
            );
            let switched = || {
                continue_generation_only_with_cut(&fixture.root, &fixture.candidate, crash_cut)
                    .unwrap()
            };
            if crash_cut.is_some() {
                assert!(std::panic::catch_unwind(switched).is_err());
                assert_eq!(
                    ProductCandidateStore {
                        root: fixture.root.clone(),
                        reconstruct: true,
                    }
                    .recover_product_activation()
                    .unwrap(),
                    Some(Admission::RebootRequired)
                );
            } else {
                assert_eq!(switched(), Admission::RebootRequired);
            }
            assert!(authorize_reboot_in(&fixture.root).unwrap());
            assert_eq!(
                ProductCandidateStore {
                    root: fixture.root.clone(),
                    reconstruct: true,
                }
                .recover_product_activation()
                .unwrap(),
                Some(Admission::RebootRequired)
            );
            assert_eq!(
                crate::installed_product::load_manifest_in(&fixture.root)
                    .unwrap()
                    .digest()
                    .unwrap(),
                fixture.old_manifest_sha256
            );
            set_host_boot_and_running(
                &root,
                "00000000-0000-0000-0000-000000000002",
                &fixture.new_daemon,
            );
            assert!(authorize_reboot_in(&fixture.root).is_err());
            assert_eq!(
                ProductCandidateStore {
                    root: fixture.root.clone(),
                    reconstruct: true,
                }
                .recover_product_activation()
                .unwrap(),
                Some(Admission::Accepted)
            );
            let active = crate::installed_product::load_manifest_in(&fixture.root).unwrap();
            assert_eq!(active.release_identity, fixture.candidate.release_identity);
            crate::installed_product::verify_candidate_closure_in(&active, true, &fixture.root)
                .unwrap();
            verify_running_product(&fixture.root, &active).unwrap();
            verify_uninstall_inventory(&root, &active).unwrap();
        }

        for (cut, post_reboot_steps) in [
            (ProductCrashCut::NativePostVerified, 0),
            (ProductCrashCut::InventoryArtifacts, 0),
            (ProductCrashCut::ManifestSignature, 1),
        ] {
            let fixture = native_fixture(false, false);
            let root = Directory::open(&fixture.root).unwrap();
            assert_eq!(
                continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
                Admission::Pending
            );
            assert_eq!(
                continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
                Admission::RebootRequired
            );
            set_host_boot_and_running(
                &root,
                "00000000-0000-0000-0000-000000000002",
                &fixture.new_daemon,
            );
            assert_eq!(
                continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
                Admission::Pending
            );
            for _ in 0..post_reboot_steps {
                assert_eq!(
                    continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
                    Admission::Pending
                );
            }
            assert!(std::panic::catch_unwind(|| {
                continue_generation_only_with_cut(&fixture.root, &fixture.candidate, Some(cut))
                    .unwrap();
            })
            .is_err());
            assert_eq!(
                ProductCandidateStore {
                    root: fixture.root.clone(),
                    reconstruct: true,
                }
                .recover_product_activation()
                .unwrap(),
                Some(Admission::Accepted)
            );
            let active = crate::installed_product::load_manifest_in(&fixture.root).unwrap();
            assert_eq!(active.release_identity, fixture.candidate.release_identity);
            verify_running_product(&fixture.root, &active).unwrap();
        }

        let fixture = native_fixture(false, false);
        let root = Directory::open(&fixture.root).unwrap();
        assert_eq!(
            continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
            Admission::Pending
        );
        assert_eq!(
            continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
            Admission::RebootRequired
        );
        set_host_boot_and_running(
            &root,
            "00000000-0000-0000-0000-000000000002",
            b"invalid-running-daemon",
        );
        assert_eq!(
            ProductCandidateStore {
                root: fixture.root.clone(),
                reconstruct: true,
            }
            .recover_product_activation()
            .unwrap(),
            Some(Admission::RebootRequired)
        );
        assert!(authorize_reboot_in(&fixture.root).unwrap());
        assert_eq!(
            crate::installed_product::load_manifest_in(&fixture.root)
                .unwrap()
                .digest()
                .unwrap(),
            fixture.old_manifest_sha256
        );
        set_host_boot_and_running(
            &root,
            "00000000-0000-0000-0000-000000000003",
            &fixture.old_daemon,
        );
        assert_eq!(
            ProductCandidateStore {
                root: fixture.root.clone(),
                reconstruct: true,
            }
            .recover_product_activation()
            .unwrap(),
            Some(Admission::ActivationFailed)
        );
        let active = crate::installed_product::load_manifest_in(&fixture.root).unwrap();
        assert_eq!(active.digest().unwrap(), fixture.old_manifest_sha256);
        crate::installed_product::verify_candidate_closure_in(&active, true, &fixture.root)
            .unwrap();
        verify_running_product(&fixture.root, &active).unwrap();
        let operation = crate::operation_contract::read_current_in(&fixture.root)
            .unwrap()
            .unwrap();
        assert_eq!(operation.reboot_count, 2);
        assert_eq!(operation.boot_id, "00000000-0000-0000-0000-000000000003");
    }

    #[test]
    fn agent_native_and_apk_native_mixed_transactions_commit_one_product() {
        for (change_agent, change_apk) in [(true, false), (false, true)] {
            let fixture = native_fixture(change_agent, change_apk);
            let root = Directory::open(&fixture.root).unwrap();
            if let Some((apk, version, certificate)) = &fixture.new_apk {
                assert_eq!(
                    continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
                    Admission::InstallApk
                );
                write_host_apk_observation(
                    &root,
                    apk,
                    *version,
                    certificate,
                    "/data/app/ru.voboost/base.apk",
                );
                assert_eq!(
                    continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
                    Admission::Pending
                );
            }
            assert_eq!(
                continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
                Admission::Pending
            );
            assert_eq!(
                continue_generation_only(&fixture.root, &fixture.candidate).unwrap(),
                Admission::RebootRequired
            );
            set_host_boot_and_running(
                &root,
                "00000000-0000-0000-0000-000000000002",
                &fixture.new_daemon,
            );
            assert_eq!(
                ProductCandidateStore {
                    root: fixture.root.clone(),
                    reconstruct: true,
                }
                .recover_product_activation()
                .unwrap(),
                Some(Admission::Accepted)
            );
            let active = crate::installed_product::load_manifest_in(&fixture.root).unwrap();
            assert_eq!(active.release_identity, fixture.candidate.release_identity);
            assert_eq!(
                crate::generation::GenerationStore::new(
                    &fixture.root,
                    fixture.root.join("generations/next"),
                )
                .active()
                .unwrap()
                .id,
                fixture.candidate_generation_id
            );
            crate::installed_product::verify_candidate_closure_in(&active, true, &fixture.root)
                .unwrap();
        }
    }

    #[test]
    fn mixed_apk_native_activation_failure_rolls_forward_to_the_observed_candidate_apk() {
        // Mixed APK/native rollback contract: the APK was already replaced
        // out-of-band by PackageInstaller when the native activation fails.
        // The previous manifest cannot be republished alone (it names the old
        // APK identity, so accepting it means a mixed old/new product), so
        // the rollback must converge forward to the complete candidate
        // release and terminate ActivationFailed without leaving a durable
        // proposal behind.
        let fixture = native_fixture(false, true);
        let root = Directory::open(&fixture.root).unwrap();
        let candidate = fixture.candidate.clone();
        let (new_apk, new_version, new_certificate) = fixture.new_apk.clone().unwrap();
        assert_eq!(
            continue_generation_only(&fixture.root, &candidate).unwrap(),
            Admission::InstallApk
        );
        write_host_apk_observation(
            &root,
            &new_apk,
            new_version,
            &new_certificate,
            "/data/app/ru.voboost/base.apk",
        );
        assert_eq!(
            continue_generation_only(&fixture.root, &candidate).unwrap(),
            Admission::Pending
        );
        // ApkObserved → NativePrepared → NativeRebootRequired.
        assert_eq!(
            continue_generation_only(&fixture.root, &candidate).unwrap(),
            Admission::Pending
        );
        assert_eq!(
            continue_generation_only(&fixture.root, &candidate).unwrap(),
            Admission::RebootRequired
        );
        assert!(authorize_reboot_in(&fixture.root).unwrap());
        set_host_boot_and_running(
            &root,
            "00000000-0000-0000-0000-000000000002",
            &fixture.new_daemon,
        );
        // NativePostReboot → InventoryPublished.
        assert_eq!(
            continue_generation_only(&fixture.root, &candidate).unwrap(),
            Admission::Pending
        );
        assert_eq!(
            continue_generation_only(&fixture.root, &candidate).unwrap(),
            Admission::Pending
        );
        // Commit-verification failure while the new APK is already live on
        // the host: publish the manifest (one Pending), then the
        // ManifestPublished commit verification must fail on the missing
        // uninstall inventory and trigger the forward-converging mixed
        // rollback.
        let uninstall = root.open_child("uninstall").unwrap();
        uninstall.unlink(INVENTORY).unwrap();
        assert_eq!(
            continue_generation_only(&fixture.root, &candidate).unwrap(),
            Admission::Pending
        );
        assert_eq!(
            continue_generation_only(&fixture.root, &candidate).unwrap(),
            Admission::ActivationFailed
        );
        // Forward convergence: the active manifest is the complete candidate
        // release (old APK identity must not be accepted), the closure and
        // uninstall inventory verify, and the operation is terminal.
        let active = crate::installed_product::load_manifest_in(&fixture.root).unwrap();
        assert_eq!(active.release_identity, candidate.release_identity);
        assert_ne!(active.digest().unwrap(), fixture.old_manifest_sha256);
        crate::installed_product::verify_candidate_closure_in(&active, true, &fixture.root)
            .unwrap();
        let root = Directory::open(&fixture.root).unwrap();
        verify_uninstall_inventory(&root, &active).unwrap();
        // The transaction converged to the complete candidate release, so the
        // terminal result the app later polls is Accepted (the attempt that
        // failed is reported once to the invoking pass as
        // ActivationFailed above). No durable proposal remains.
        // The terminal Complete dispatch runs the durable cleanup so the
        // retained terminal result is readable for later callers.
        assert_eq!(
            continue_generation_only(&fixture.root, &candidate).unwrap(),
            Admission::Accepted
        );
        assert_eq!(
            read_terminal_result(&fixture.root, &candidate).unwrap(),
            Some(Admission::Accepted)
        );
        assert_eq!(
            crate::operation_contract::read_current_in(&fixture.root)
                .unwrap()
                .unwrap()
                .phase,
            "update-product-complete"
        );
    }

    #[test]
    fn mixed_apk_native_rollback_fails_closed_without_the_observed_candidate_apk() {
        // The forward-converging mixed rollback requires the durable host
        // APK observation of the candidate APK. Removing it (the host never
        // observed the candidate live) must fail closed instead of rolling
        // back to a mixed product or accepting the previous manifest.
        let fixture = native_fixture(false, true);
        let root = Directory::open(&fixture.root).unwrap();
        let candidate = fixture.candidate.clone();
        let (new_apk, new_version, new_certificate) = fixture.new_apk.clone().unwrap();
        assert_eq!(
            continue_generation_only(&fixture.root, &candidate).unwrap(),
            Admission::InstallApk
        );
        write_host_apk_observation(
            &root,
            &new_apk,
            new_version,
            &new_certificate,
            "/data/app/ru.voboost/base.apk",
        );
        assert_eq!(
            continue_generation_only(&fixture.root, &candidate).unwrap(),
            Admission::Pending
        );
        // ApkObserved → NativePrepared → NativeRebootRequired.
        assert_eq!(
            continue_generation_only(&fixture.root, &candidate).unwrap(),
            Admission::Pending
        );
        assert_eq!(
            continue_generation_only(&fixture.root, &candidate).unwrap(),
            Admission::RebootRequired
        );
        assert!(authorize_reboot_in(&fixture.root).unwrap());
        set_host_boot_and_running(
            &root,
            "00000000-0000-0000-0000-000000000002",
            &fixture.new_daemon,
        );
        // NativePostReboot → InventoryPublished.
        assert_eq!(
            continue_generation_only(&fixture.root, &candidate).unwrap(),
            Admission::Pending
        );
        assert_eq!(
            continue_generation_only(&fixture.root, &candidate).unwrap(),
            Admission::Pending
        );
        // Remove the host APK observation (and its JSON) so the mixed
        // rollback cannot prove the candidate APK identity, then trigger the
        // same commit-verification failure. Failure must be an explicit
        // error, not a rolled-back or accepted product.
        root.unlink("voboost-app.apk.host-observed").unwrap();
        root.unlink("voboost-app.apk.host-observed.json").unwrap();
        let uninstall = root.open_child("uninstall").unwrap();
        uninstall.unlink(INVENTORY).unwrap();
        assert_eq!(
            continue_generation_only(&fixture.root, &candidate).unwrap(),
            Admission::Pending
        );
        assert!(continue_generation_only(&fixture.root, &candidate).is_err());
    }

    #[test]
    fn native_wrong_signer_hash_abi_and_boot_id_fail_closed() {
        let mut signer = native_fixture(false, false);
        rewrite_candidate_daemon(
            &mut signer,
            signed_executable(
                crate::native_executable_signature::NativeExecutableRole::Install,
                b"\x7fELF-wrong-role-daemon",
            ),
        );
        assert_eq!(
            continue_generation_only(&signer.root, &signer.candidate).unwrap(),
            Admission::UnsupportedActivationClass
        );
        assert_eq!(
            crate::installed_product::load_manifest_in(&signer.root)
                .unwrap()
                .digest()
                .unwrap(),
            signer.old_manifest_sha256
        );
        assert!(crate::operation_contract::read_current_in(&signer.root)
            .unwrap()
            .is_none());

        let hash = native_fixture(false, false);
        let root = Directory::open(&hash.root).unwrap();
        let complete = root
            .open_child(INSTALL_ROOT)
            .unwrap()
            .open_child(&hash.candidate.transaction_id)
            .unwrap()
            .open_child(COMPLETE_CANDIDATE)
            .unwrap();
        complete
            .write_atomic("libimplant-arm64-v8a.so", b"wrong-hash", FILE_MODE)
            .unwrap();
        assert!(continue_generation_only(&hash.root, &hash.candidate).is_err());
        assert_eq!(
            crate::installed_product::load_manifest_in(&hash.root)
                .unwrap()
                .digest()
                .unwrap(),
            hash.old_manifest_sha256
        );

        let mut abi = voboost_contract::release::Manifest::parse(include_bytes!(
            "../../test/fixtures/product-release/voboost/valid/minimal.json"
        ))
        .unwrap();
        abi.artifacts
            .iter_mut()
            .find(|artifact| artifact.file == "libimplant-arm64-v8a.so")
            .unwrap()
            .abi = Some(voboost_contract::release::Abi::ArmeabiV7a);
        assert!(abi.validate().is_err());

        let boot = native_fixture(false, false);
        let root = Directory::open(&boot.root).unwrap();
        assert_eq!(
            continue_generation_only(&boot.root, &boot.candidate).unwrap(),
            Admission::Pending
        );
        assert_eq!(
            continue_generation_only(&boot.root, &boot.candidate).unwrap(),
            Admission::RebootRequired
        );
        root.write_atomic("boot-id.host", b"not-a-boot-id\n", FILE_MODE)
            .unwrap();
        assert_eq!(
            ProductCandidateStore {
                root: boot.root.clone(),
                reconstruct: true,
            }
            .recover_product_activation()
            .unwrap(),
            Some(Admission::ActivationFailed)
        );
        assert_eq!(
            crate::installed_product::load_manifest_in(&boot.root)
                .unwrap()
                .digest()
                .unwrap(),
            boot.old_manifest_sha256
        );
    }

    #[test]
    fn legacy_overlap_blocks_update_recovery_without_changing_authority() {
        let fixture = product_fixture();
        let product = crate::installed_product::load_manifest_in(&fixture.root)
            .unwrap()
            .digest()
            .unwrap();
        crate::cluster_control::test_queue_cluster_uninstall(&fixture.root, &product);
        let wal = fixture
            .root
            .join(RECOVERY_ROOT)
            .join(&fixture.candidate.transaction_id)
            .join(JOURNAL);
        let mailbox = fixture.root.join("cluster/mailbox.json");
        let before_wal = std::fs::read(&wal).unwrap();
        let before_mailbox = std::fs::read(&mailbox).unwrap();
        let before_manifest = std::fs::read(fixture.root.join(MANIFEST)).unwrap();
        let store = ProductCandidateStore::at_reconstructing(&fixture.root);
        assert!(store
            .recover_product_activation()
            .unwrap_err()
            .contains("uninstall pending"));
        assert_eq!(std::fs::read(wal).unwrap(), before_wal);
        assert_eq!(std::fs::read(mailbox).unwrap(), before_mailbox);
        assert_eq!(
            std::fs::read(fixture.root.join(MANIFEST)).unwrap(),
            before_manifest
        );
    }

    #[test]
    fn uninstall_waits_for_existing_product_wal_then_binds_recovered_manifest() {
        let fixture = product_fixture();
        let store = ProductCandidateStore::at_reconstructing(&fixture.root);
        let guard = GenerationGuard::acquire_in(&fixture.root).unwrap();
        assert!(store.ensure_idle_for_uninstall().is_err());
        assert!(!fixture.root.join("cluster").exists());
        drop(guard);
        assert_eq!(
            store.recover_product_activation().unwrap(),
            Some(Admission::Accepted)
        );
        let current = crate::installed_product::load_manifest_in(&fixture.root)
            .unwrap()
            .digest()
            .unwrap();
        let guard = GenerationGuard::acquire_in(&fixture.root).unwrap();
        store.ensure_idle_for_uninstall().unwrap();
        crate::cluster_control::test_queue_cluster_uninstall(&fixture.root, &current);
        drop(guard);
        assert!(reject_cluster_uninstall(&fixture.root).is_err());
        assert_eq!(
            crate::installed_product::load_manifest_in(&fixture.root)
                .unwrap()
                .digest()
                .unwrap(),
            current
        );
    }

    #[test]
    fn pending_durable_candidate_recovers_without_app_descriptors() {
        let fixture = product_fixture();
        let root = Directory::open(&fixture.root).unwrap();
        let install_root = root.open_child(INSTALL_ROOT).unwrap();
        let install = install_root
            .open_child(&fixture.candidate.transaction_id)
            .unwrap();
        let complete = install.open_child(COMPLETE_CANDIDATE).unwrap();
        let manifest = voboost_contract::release::Manifest::parse(
            &complete
                .read_trusted(
                    MANIFEST,
                    voboost_contract::release::MAX_MANIFEST_BYTES,
                    FILE_MODE,
                )
                .unwrap(),
        )
        .unwrap();
        for name in manifest
            .artifacts
            .iter()
            .map(|artifact| artifact.file.as_str())
            .chain([MANIFEST, SIGNATURE])
        {
            complete.unlink(name).unwrap();
        }
        install.remove_child_dir(COMPLETE_CANDIDATE).unwrap();
        let recovery = root
            .open_child(RECOVERY_ROOT)
            .unwrap()
            .open_child(&fixture.candidate.transaction_id)
            .unwrap();
        let mut journal = ProposalJournal::parse(
            &recovery
                .read_trusted(JOURNAL, MAX_STATUS_BYTES, FILE_MODE)
                .unwrap(),
        )
        .unwrap();
        journal.phase = ProposalPhase::Pending;
        write_journal(&recovery, &journal).unwrap();
        assert_eq!(
            ProductCandidateStore {
                root: fixture.root.clone(),
                reconstruct: true,
            }
            .recover_product_activation()
            .unwrap(),
            Some(Admission::Accepted)
        );
        let active = crate::installed_product::load_manifest_in(&fixture.root).unwrap();
        assert_eq!(active.release_identity, fixture.candidate.release_identity);
        crate::installed_product::verify_candidate_closure_in(&active, true, &fixture.root)
            .unwrap();
    }

    #[test]
    fn product_proposal_bound_counts_only_exact_product_wals() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let root = Directory::open(temporary.path()).unwrap();
        let recovery = root.open_or_create_private_child(RECOVERY_ROOT).unwrap();
        let legacy = recovery
            .open_or_create_private_child(&"1".repeat(64))
            .unwrap();
        legacy
            .write_atomic("update-journal.json", b"legacy", FILE_MODE)
            .unwrap();
        assert_eq!(count_durable_proposals(&recovery).unwrap(), 0);
        let candidate = OtaCandidateHandle {
            transaction_id: "2".repeat(64),
            release_identity: "1.0.0-beta2".into(),
            manifest_sha256: "3".repeat(64),
            artifacts: vec![voboost_contract::status::CandidateArtifactIdentity {
                file: "agent-settings.dex".into(),
                size: 1,
                sha256: "4".repeat(64),
            }],
        };
        let transaction = recovery
            .open_or_create_private_child(&candidate.transaction_id)
            .unwrap();
        write_journal(&transaction, &ProposalJournal::new(&candidate)).unwrap();
        assert_eq!(count_durable_proposals(&recovery).unwrap(), 1);
        assert_eq!(MAX_DURABLE_PROPOSALS, 1);
    }

    #[test]
    fn unsupported_activation_class_retires_inactive_transaction() {
        use std::os::unix::fs::PermissionsExt;

        let manifest = voboost_contract::release::Manifest::parse(include_bytes!(
            "../../test/fixtures/product-release/voboost/valid/minimal.json"
        ))
        .unwrap();
        let daemon = manifest.artifact("voboost-daemon").unwrap();
        let candidate = OtaCandidateHandle {
            transaction_id: "a".repeat(64),
            release_identity: manifest.release_identity.clone(),
            manifest_sha256: manifest.digest().unwrap(),
            artifacts: vec![voboost_contract::status::CandidateArtifactIdentity {
                file: daemon.file.clone(),
                size: daemon.size,
                sha256: daemon.sha256.clone(),
            }],
        };
        let temporary = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let root = Directory::open(temporary.path()).unwrap();
        let install_root = root.open_or_create_private_child(INSTALL_ROOT).unwrap();
        let recovery_root = root.open_or_create_private_child(RECOVERY_ROOT).unwrap();
        let install = install_root
            .open_or_create_private_child(&candidate.transaction_id)
            .unwrap();
        let recovery = recovery_root
            .open_or_create_private_child(&candidate.transaction_id)
            .unwrap();
        let changed = install.open_or_create_private_child(CANDIDATE).unwrap();
        for name in [MANIFEST, SIGNATURE, "voboost-daemon"] {
            changed.write_atomic(name, b"", FILE_MODE).unwrap();
        }
        let complete = install
            .open_or_create_private_child(COMPLETE_CANDIDATE)
            .unwrap();
        for name in manifest
            .artifacts
            .iter()
            .map(|artifact| artifact.file.as_str())
            .chain([MANIFEST, SIGNATURE])
        {
            complete.write_atomic(name, b"", FILE_MODE).unwrap();
        }
        write_journal(&recovery, &ProposalJournal::new(&candidate)).unwrap();
        retire_unactivated_candidate(
            &install_root,
            &recovery_root,
            &install,
            &recovery,
            &manifest,
            &candidate,
        )
        .unwrap();
        assert!(!install_root
            .entry_exists(&candidate.transaction_id)
            .unwrap());
        assert!(!recovery_root
            .entry_exists(&candidate.transaction_id)
            .unwrap());
        assert!(crate::operation_contract::read_current_in(temporary.path())
            .unwrap()
            .is_none());
    }

    #[test]
    fn root_open_failure_is_not_misreported_as_pending() {
        let temporary = tempfile::tempdir().unwrap();
        let missing = temporary.path().join("missing");
        let store = ProductCandidateStore::at(&missing);
        assert_eq!(store.root, missing);
        assert!(matches!(
            Directory::open(&store.root),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        ));
    }

    #[test]
    fn uninstall_fence_requires_product_candidate_authority_to_be_idle() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().unwrap();
        let store = ProductCandidateStore::at(temporary.path());
        assert!(store.ensure_idle_for_uninstall().is_ok());

        let transaction = temporary.path().join(RECOVERY_ROOT).join("candidate");
        std::fs::create_dir_all(&transaction).unwrap();
        std::fs::set_permissions(
            temporary.path().join(RECOVERY_ROOT),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::write(transaction.join(JOURNAL), b"active").unwrap();
        std::fs::set_permissions(
            transaction.join(JOURNAL),
            std::fs::Permissions::from_mode(FILE_MODE),
        )
        .unwrap();
        assert_eq!(
            store.ensure_idle_for_uninstall().unwrap_err(),
            "product update transaction is still active"
        );
    }

    #[test]
    fn uninstall_rejects_unleased_install_and_restore_recovery() {
        use std::os::unix::fs::PermissionsExt;
        for member in [
            "install-journal.json",
            ".install-journal.json.tmp",
            "update-journal.json",
            ".update-journal.json.tmp",
            "fresh-state.json",
            "restore-journal.json",
            ".restore-journal.json.tmp",
        ] {
            let temporary = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
            let recovery = temporary.path().join("recovery");
            let transaction = recovery.join("transaction");
            std::fs::create_dir_all(&transaction).unwrap();
            std::fs::set_permissions(&recovery, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(&transaction, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::write(transaction.join(member), b"retained").unwrap();
            assert!(
                ProductCandidateStore::at(temporary.path())
                    .ensure_idle_for_uninstall()
                    .is_err(),
                "{member}"
            );
        }
        let temporary = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        std::fs::create_dir_all(temporary.path().join("run/restore-prepare")).unwrap();
        assert!(ProductCandidateStore::at(temporary.path())
            .ensure_idle_for_uninstall()
            .is_err());
    }

    #[test]
    fn descriptor_admission_uses_fixed_chunks_without_aggregate_body_buffers() {
        let contract = include_str!("../../contract/status.rs");
        let verifier = contract
            .split("fn verify_artifact_descriptor(")
            .nth(1)
            .unwrap()
            .split("fn read_descriptor(")
            .next()
            .unwrap();
        assert!(verifier.contains("[0_u8; 64 * 1024]"));
        assert!(!verifier.contains("vec!["));

        let secure = include_str!("../../shared/src/secure_fs.rs");
        let copier = secure
            .split("pub fn write_atomic_from_descriptor(")
            .nth(1)
            .unwrap()
            .split("pub fn verify_trusted_digest(")
            .next()
            .unwrap();
        assert!(copier.contains("[0_u8; 64 * 1024]"));
        assert!(!copier.contains("Vec<"));
    }

    #[test]
    fn complete_candidate_inventory_rejects_missing_extra_link_and_hash() {
        use ed25519_dalek::{Signer, SigningKey};
        use sha2::{Digest, Sha256};
        use std::os::unix::fs::symlink;

        let mut manifest = voboost_contract::release::Manifest::parse(include_bytes!(
            "../../test/fixtures/product-release/voboost/valid/minimal.json"
        ))
        .unwrap();
        assert_ne!(manifest.artifacts.len(), 67);
        let temporary = tempfile::tempdir().unwrap();
        let directory = Directory::open(temporary.path()).unwrap();
        for artifact in &mut manifest.artifacts {
            let bytes = artifact.file.as_bytes();
            artifact.size = bytes.len() as u64;
            artifact.sha256 = hex::encode(Sha256::digest(bytes));
            directory
                .write_atomic(&artifact.file, bytes, FILE_MODE)
                .unwrap();
        }
        let manifest_bytes = manifest.canonical_bytes().unwrap();
        let signature = SigningKey::from_bytes(&[12; 32])
            .sign(&manifest_bytes)
            .to_bytes();
        directory
            .write_atomic(MANIFEST, &manifest_bytes, FILE_MODE)
            .unwrap();
        directory
            .write_atomic(SIGNATURE, &signature, FILE_MODE)
            .unwrap();
        assert!(verify_complete(&directory, &manifest).is_ok());
        directory.write_atomic("extra", b"x", FILE_MODE).unwrap();
        assert!(verify_complete(&directory, &manifest).is_err());
        directory.unlink("extra").unwrap();
        let victim = &manifest.artifacts[0];
        directory.unlink(&victim.file).unwrap();
        symlink("voboost.json", temporary.path().join(&victim.file)).unwrap();
        assert!(verify_complete(&directory, &manifest).is_err());
    }

    struct OfflineFixture {
        _active: crate::generation::test_support::TestZones,
        _candidate: crate::generation::test_support::TestZones,
        root: PathBuf,
        active_manifest: voboost_contract::release::Manifest,
        new_manifest: voboost_contract::release::Manifest,
        new_bodies: std::collections::BTreeMap<String, Vec<u8>>,
        new_manifest_bytes: Vec<u8>,
        new_signature: Vec<u8>,
    }

    fn offline_fixture(active_identity: &str, candidate_identity: &str) -> OfflineFixture {
        let active = crate::generation::test_support::zones();
        let active_generation =
            crate::generation::test_support::activate_cluster_variant(&active.store, 1);
        let root = active_generation
            .directory
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let candidate_zone = crate::generation::test_support::zones();
        let candidate_generation =
            crate::generation::test_support::activate_cluster_variant(&candidate_zone.store, 2);
        let (old_manifest, old_bodies, old_manifest_bytes, old_signature) =
            signed_product_closure(&active_generation, active_identity);
        let (new_manifest, new_bodies, new_manifest_bytes, new_signature) =
            signed_product_closure(&candidate_generation, candidate_identity);
        let root_directory = Directory::open(&root).unwrap();
        for artifact in &old_manifest.artifacts {
            if let crate::installed_product::InstalledAuthority::RootFlat { mode } =
                crate::installed_product::authority(artifact)
            {
                root_directory
                    .write_atomic(&artifact.file, &old_bodies[&artifact.file], mode)
                    .unwrap();
            }
        }
        let app = old_manifest.artifact("voboost-app.apk").unwrap();
        write_host_apk_observation(
            &root_directory,
            &old_bodies["voboost-app.apk"],
            app.version_code.unwrap(),
            app.certificate_sha256.as_deref().unwrap(),
            "/data/app/ru.voboost/base.apk",
        );
        root_directory
            .write_atomic(MANIFEST, &old_manifest_bytes, 0o600)
            .unwrap();
        root_directory
            .write_atomic(SIGNATURE, &old_signature, 0o600)
            .unwrap();
        write_product_inventory(&root, &old_manifest, &old_manifest_bytes, &old_signature);
        OfflineFixture {
            _active: active,
            _candidate: candidate_zone,
            root,
            active_manifest: old_manifest,
            new_manifest,
            new_bodies,
            new_manifest_bytes,
            new_signature,
        }
    }

    fn stage_full_closure(root: &Path, staged_name: &str, fixture: &OfflineFixture) {
        let root_directory = Directory::open(root).unwrap();
        let staging_root = root_directory
            .open_or_create_private_child(OFFLINE_STAGING_ROOT)
            .unwrap();
        let staged = staging_root
            .open_or_create_private_child(staged_name)
            .unwrap();
        staged
            .write_atomic(MANIFEST, &fixture.new_manifest_bytes, FILE_MODE)
            .unwrap();
        staged
            .write_atomic(SIGNATURE, &fixture.new_signature, FILE_MODE)
            .unwrap();
        for artifact in &fixture.new_manifest.artifacts {
            staged
                .write_atomic(
                    &artifact.file,
                    &fixture.new_bodies[&artifact.file],
                    FILE_MODE,
                )
                .unwrap();
        }
    }

    #[test]
    fn offline_origin_policy_separates_strict_ota_from_explicit_equal_content() {
        let fixture = offline_fixture("1.0.0-beta1", "1.0.0-beta1");
        let root_directory = Directory::open(&fixture.root).unwrap();
        let install_root = root_directory
            .open_or_create_private_child(INSTALL_ROOT)
            .unwrap();
        let install_tx = install_root
            .open_or_create_private_child("offline-eq")
            .unwrap();
        let changed = install_tx.open_or_create_private_child(CANDIDATE).unwrap();
        changed
            .write_atomic(MANIFEST, &fixture.new_manifest_bytes, FILE_MODE)
            .unwrap();
        changed
            .write_atomic(SIGNATURE, &fixture.new_signature, FILE_MODE)
            .unwrap();
        for name in [
            "restore.json",
            "restore.json.sig",
            "agents.json",
            "agents.json.sig",
        ] {
            changed
                .write_atomic(name, &fixture.new_bodies[name], FILE_MODE)
                .unwrap();
        }
        let origin = ProductUpdateOrigin::OfflineExplicit {
            expected_active_manifest_sha256: fixture.active_manifest.digest().unwrap(),
        };
        // Automatic OTA admission still requires a strictly newer release.
        assert!(reconstruct_complete(
            &fixture.root,
            &install_tx,
            &changed,
            &fixture.new_manifest,
            &ProductUpdateOrigin::Ota
        )
        .unwrap_err()
        .contains("not newer"));
        // The explicit offline origin admits different content at an equal
        // SemVer in the same channel.
        assert!(reconstruct_complete(
            &fixture.root,
            &install_tx,
            &changed,
            &fixture.new_manifest,
            &origin
        )
        .is_ok());
    }

    #[test]
    fn offline_origin_never_applies_a_lower_release() {
        let fixture = offline_fixture("1.0.0-beta2", "1.0.0-beta1");
        let root_directory = Directory::open(&fixture.root).unwrap();
        let install_root = root_directory
            .open_or_create_private_child(INSTALL_ROOT)
            .unwrap();
        let install_tx = install_root
            .open_or_create_private_child("offline-lower")
            .unwrap();
        let changed = install_tx.open_or_create_private_child(CANDIDATE).unwrap();
        changed
            .write_atomic(MANIFEST, &fixture.new_manifest_bytes, FILE_MODE)
            .unwrap();
        changed
            .write_atomic(SIGNATURE, &fixture.new_signature, FILE_MODE)
            .unwrap();
        for name in [
            "restore.json",
            "restore.json.sig",
            "agents.json",
            "agents.json.sig",
        ] {
            changed
                .write_atomic(name, &fixture.new_bodies[name], FILE_MODE)
                .unwrap();
        }
        let origin = ProductUpdateOrigin::OfflineExplicit {
            expected_active_manifest_sha256: fixture.active_manifest.digest().unwrap(),
        };
        let lower = reconstruct_complete(
            &fixture.root,
            &install_tx,
            &changed,
            &fixture.new_manifest,
            &origin,
        )
        .unwrap_err();
        assert!(lower.contains("below the active version"), "{lower}");
    }

    #[test]
    fn offline_stage_preparation_preserves_verified_abandoned_upload() {
        let fixture = offline_fixture("1.0.0-beta1", "1.0.0-beta1");
        // Force reinstall allocates a fresh random hex64 intent, independent
        // of the signed manifest digest.
        let old = "7".repeat(64);
        let next = "8".repeat(64);
        stage_full_closure(&fixture.root, &old, &fixture);
        let path = fixture.root.join(OFFLINE_STAGING_ROOT).join(&old);
        let before: std::collections::BTreeMap<_, _> = std::fs::read_dir(&path)
            .unwrap()
            .map(|e| {
                let p = e.unwrap().path();
                (
                    p.file_name().unwrap().to_owned(),
                    std::fs::read(&p).unwrap(),
                )
            })
            .collect();
        prepare_offline_stage_in(&fixture.root, &next).unwrap();
        let after: std::collections::BTreeMap<_, _> = std::fs::read_dir(&path)
            .unwrap()
            .map(|e| {
                let p = e.unwrap().path();
                (
                    p.file_name().unwrap().to_owned(),
                    std::fs::read(&p).unwrap(),
                )
            })
            .collect();
        assert_eq!(before, after);
        let root = Directory::open(&fixture.root).unwrap();
        let mut operation = OperationDescriptor::new(
            Operation::Update,
            old.clone(),
            format!("recovery/{old}/product-proposal.json"),
            "00000000-0000-0000-0000-000000000001".into(),
        )
        .unwrap();
        for (transaction, outcome) in [
            (old.clone(), "running"),
            ("9".repeat(64), "running"),
            (old.clone(), "failed"),
        ] {
            operation.transaction_id = transaction;
            operation.journal = format!(
                "recovery/{}/product-proposal.json",
                operation.transaction_id
            );
            operation.outcome = outcome.into();
            operation.error = (outcome == "failed")
                .then(|| serde_json::json!({"code":"test", "message":"retained failure"}));
            root.write_atomic(
                "operation.json",
                &operation.canonical_bytes().unwrap(),
                FILE_MODE,
            )
            .unwrap();
            assert!(prepare_offline_stage_in(&fixture.root, &next).is_err());
        }
        operation.outcome = "complete".into();
        operation.error = None;
        operation.phase = "update-product-complete".into();
        root.write_atomic(
            "operation.json",
            &operation.canonical_bytes().unwrap(),
            FILE_MODE,
        )
        .unwrap();
        prepare_offline_stage_in(&fixture.root, &next).unwrap();
        let directory = Directory::open(&path).unwrap();
        directory
            .write_atomic(SIGNATURE, &[0; 64], FILE_MODE)
            .unwrap();
        assert!(prepare_offline_stage_in(&fixture.root, &next).is_err());
        directory
            .write_atomic(SIGNATURE, &fixture.new_signature, FILE_MODE)
            .unwrap();
        let artifact = &fixture.new_manifest.artifacts[0];
        directory
            .write_atomic(&artifact.file, b"tampered", FILE_MODE)
            .unwrap();
        assert!(prepare_offline_stage_in(&fixture.root, &next).is_err());
        std::fs::remove_file(path.join(&artifact.file)).unwrap();
        assert!(prepare_offline_stage_in(&fixture.root, &next).is_err());
        directory
            .write_atomic(
                &artifact.file,
                &fixture.new_bodies[&artifact.file],
                FILE_MODE,
            )
            .unwrap();
        let foreign = "foreign-stage";
        std::fs::rename(&path, fixture.root.join(OFFLINE_STAGING_ROOT).join(foreign)).unwrap();
        assert!(prepare_offline_stage_in(&fixture.root, &next).is_err());
    }

    #[test]
    fn offline_stage_preparation_requires_verified_terminal_consumption_and_preserves_bytes() {
        let fixture = offline_fixture("1.0.0-beta1", "1.0.0-beta1");
        let old = "6".repeat(64);
        let next = "8".repeat(64);
        stage_full_closure(&fixture.root, &old, &fixture);
        let directory =
            Directory::open(&fixture.root.join(OFFLINE_STAGING_ROOT).join(&old)).unwrap();
        let receipt = ConsumedOfflineStage {
            schema_version: 1,
            stage_transaction_id: old.clone(),
            operation_transaction_id: old.clone(),
            manifest_sha256: fixture.new_manifest.digest().unwrap(),
            terminal: false,
        };
        directory
            .write_atomic(
                ".consumed.json",
                &serde_json::to_vec(&receipt).unwrap(),
                FILE_MODE,
            )
            .unwrap();
        assert!(prepare_offline_stage_in(&fixture.root, &next).is_err());
        assert!(!fixture.root.join(OFFLINE_STAGING_ROOT).join(&next).exists());
        let mut operation = OperationDescriptor::new(
            Operation::Update,
            old.clone(),
            format!("recovery/{old}/product-proposal.json"),
            "00000000-0000-0000-0000-000000000001".into(),
        )
        .unwrap();
        operation.phase = "update-product-complete".into();
        operation.outcome = "complete".into();
        operation.status_sequence = 2;
        let root = Directory::open(&fixture.root).unwrap();
        root.write_atomic(
            "operation.json",
            &operation.canonical_bytes().unwrap(),
            FILE_MODE,
        )
        .unwrap();
        prepare_offline_stage_in(&fixture.root, &next).unwrap();
        assert!(fixture.root.join(OFFLINE_STAGING_ROOT).join(&next).is_dir());
        assert_eq!(
            directory
                .read_trusted(
                    MANIFEST,
                    voboost_contract::release::MAX_MANIFEST_BYTES,
                    FILE_MODE
                )
                .unwrap(),
            fixture.new_manifest_bytes
        );
        let terminal: ConsumedOfflineStage = serde_json::from_slice(
            &directory
                .read_trusted(".consumed.json", 1024, FILE_MODE)
                .unwrap(),
        )
        .unwrap();
        assert!(terminal.terminal);
        operation.transaction_id = "9".repeat(64);
        operation.journal = format!(
            "recovery/{}/product-proposal.json",
            operation.transaction_id
        );
        root.write_atomic(
            "operation.json",
            &operation.canonical_bytes().unwrap(),
            FILE_MODE,
        )
        .unwrap();
        prepare_offline_stage_in(&fixture.root, &next).unwrap();
        directory
            .write_atomic("foreign", b"preserved", FILE_MODE)
            .unwrap();
        assert!(prepare_offline_stage_in(&fixture.root, &next).is_err());
        assert_eq!(
            directory.read_trusted("foreign", 9, FILE_MODE).unwrap(),
            b"preserved"
        );
    }

    #[test]
    fn offline_stage_preparation_rejects_bad_signatures_and_receipt_binding_without_removal() {
        let fixture = offline_fixture("1.0.0-beta1", "1.0.0-beta1");
        let old = "6".repeat(64);
        let next = "8".repeat(64);
        stage_full_closure(&fixture.root, &old, &fixture);
        let directory =
            Directory::open(&fixture.root.join(OFFLINE_STAGING_ROOT).join(&old)).unwrap();
        let mut receipt = ConsumedOfflineStage {
            schema_version: 1,
            stage_transaction_id: old.clone(),
            operation_transaction_id: old.clone(),
            manifest_sha256: fixture.new_manifest.digest().unwrap(),
            terminal: true,
        };
        directory
            .write_atomic(
                ".consumed.json",
                &serde_json::to_vec(&receipt).unwrap(),
                FILE_MODE,
            )
            .unwrap();
        directory
            .write_atomic(SIGNATURE, &[0; 64], FILE_MODE)
            .unwrap();
        assert!(prepare_offline_stage_in(&fixture.root, &next).is_err());
        assert!(fixture
            .root
            .join(OFFLINE_STAGING_ROOT)
            .join(&old)
            .join(MANIFEST)
            .exists());
        assert!(!fixture.root.join(OFFLINE_STAGING_ROOT).join(&next).exists());
        directory
            .write_atomic(SIGNATURE, &fixture.new_signature, FILE_MODE)
            .unwrap();
        receipt.manifest_sha256 = "e".repeat(64);
        directory
            .write_atomic(
                ".consumed.json",
                &serde_json::to_vec(&receipt).unwrap(),
                FILE_MODE,
            )
            .unwrap();
        assert!(prepare_offline_stage_in(&fixture.root, &next).is_err());
    }

    #[test]
    #[ignore = "pending approved damaged-generation repair hook; current RED retained in .work162/force-damaged-generation-red.log"]
    fn offline_full_candidate_reconstructs_with_a_damaged_unchanged_agent_payload() {
        use std::os::unix::fs::PermissionsExt;
        let mut fixture = offline_fixture("1.0.0-beta1", "1.0.0-beta1");
        let generation = crate::generation::GenerationStore::new(
            &fixture.root,
            fixture.root.join("generations/next"),
        )
        .active()
        .unwrap();
        let payload = generation
            .files
            .iter()
            .find(|file| {
                !matches!(
                    file.file.as_str(),
                    "agents.json" | "agents.json.sig" | "agents-selected.json"
                ) && fixture
                    .active_manifest
                    .artifact(&file.file)
                    .is_ok_and(|artifact| {
                        matches!(
                            crate::installed_product::authority(artifact),
                            crate::installed_product::InstalledAuthority::ActiveGeneration
                        )
                    })
            })
            .unwrap();
        let original = generation.read_file_exact(&payload.file).unwrap();
        let artifact = fixture
            .new_manifest
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.file == payload.file)
            .unwrap();
        artifact.size = payload.size;
        artifact.sha256 = payload.sha256.clone();
        fixture.new_bodies.insert(payload.file.clone(), original);
        (fixture.new_manifest_bytes, fixture.new_signature) =
            resign_product(&mut fixture.new_manifest, &mut fixture.new_bodies);
        let tx = "9".repeat(64);
        stage_full_closure(&fixture.root, &tx, &fixture);
        let root = Directory::open(&fixture.root).unwrap();
        let install = root
            .open_or_create_private_child(INSTALL_ROOT)
            .unwrap()
            .open_or_create_private_child(&tx)
            .unwrap();
        let staged = root
            .open_child(OFFLINE_STAGING_ROOT)
            .unwrap()
            .open_child(&tx)
            .unwrap();
        let path = generation.directory.join(&payload.file);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, b"damaged payload").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        let origin = ProductUpdateOrigin::OfflineExplicit {
            expected_active_manifest_sha256: fixture.active_manifest.digest().unwrap(),
        };
        reconstruct_complete(
            &fixture.root,
            &install,
            &staged,
            &fixture.new_manifest,
            &origin,
        )
        .unwrap();
        let complete = install.open_child(COMPLETE_CANDIDATE).unwrap();
        complete
            .verify_trusted_digest(&payload.file, payload.size, &payload.sha256, FILE_MODE)
            .unwrap();
    }

    #[test]
    fn explicit_reapply_uses_fresh_intent_full_closure_and_retains_consumed_stage() {
        let mut fixture = offline_fixture("1.0.0-beta1", "1.0.0-beta1");
        let root = Directory::open(&fixture.root).unwrap();
        let helper = signed_executable(
            crate::native_executable_signature::NativeExecutableRole::Restore,
            b"\x7fELF-stable-restore",
        );
        for manifest in [&mut fixture.active_manifest, &mut fixture.new_manifest] {
            let artifact = manifest
                .artifacts
                .iter_mut()
                .find(|artifact| artifact.file == "voboost-restore")
                .unwrap();
            artifact.size = helper.len() as u64;
            artifact.sha256 = crate::trust::sha256_bytes(&helper);
        }
        let selinux = signed_executable(
            crate::native_executable_signature::NativeExecutableRole::Selinux,
            b"\x7fELF-stable-selinux",
        );
        for manifest in [&mut fixture.active_manifest, &mut fixture.new_manifest] {
            let artifact = manifest
                .artifacts
                .iter_mut()
                .find(|artifact| artifact.file == "voboost-selinux")
                .unwrap();
            artifact.size = selinux.len() as u64;
            artifact.sha256 = crate::trust::sha256_bytes(&selinux);
        }
        fixture.new_bodies.insert("voboost-selinux".into(), selinux);
        let mut active_bodies = fixture.new_bodies.clone();
        active_bodies.insert("voboost-restore".into(), helper.clone());
        let (active_bytes, active_signature) =
            resign_product(&mut fixture.active_manifest, &mut active_bodies);
        root.write_atomic(MANIFEST, &active_bytes, FILE_MODE)
            .unwrap();
        root.write_atomic(SIGNATURE, &active_signature, FILE_MODE)
            .unwrap();
        root.write_atomic("voboost-restore", &helper, 0o700)
            .unwrap();
        fixture.new_bodies.insert("voboost-restore".into(), helper);
        (fixture.new_manifest_bytes, fixture.new_signature) =
            resign_product(&mut fixture.new_manifest, &mut fixture.new_bodies);
        let tx = "7".repeat(64);
        stage_full_closure(&fixture.root, &tx, &fixture);
        let store = ProductCandidateStore::at(&fixture.root);
        let expected = fixture.active_manifest.digest().unwrap();
        crate::cluster_control::test_queue_cluster_uninstall(&fixture.root, &expected);
        let retained = std::fs::read(fixture.root.join("cluster/mailbox.json")).unwrap();
        assert!(
            apply_offline_product_mode_in(&store, &fixture.root, &expected, &tx, true)
                .unwrap_err()
                .contains("uninstall pending")
        );
        assert_eq!(
            std::fs::read(fixture.root.join("cluster/mailbox.json")).unwrap(),
            retained
        );
        assert!(!fixture.root.join(RECOVERY_ROOT).join(&tx).exists());
        // Each test owns this disposable product root; the second half verifies
        // the previously supported reapply path when Cluster is unprovisioned.
        std::fs::remove_dir_all(fixture.root.join("cluster")).unwrap();
        std::fs::remove_dir_all(fixture.root.join("cluster-test-input")).unwrap();
        assert_eq!(
            apply_offline_product_mode_in(&store, &fixture.root, &expected, &tx, true).unwrap(),
            Admission::Pending
        );
        assert!(fixture
            .root
            .join(OFFLINE_STAGING_ROOT)
            .join(&tx)
            .join(".consumed.json")
            .exists());
        let recovery = Directory::open(&fixture.root.join(RECOVERY_ROOT).join(&tx)).unwrap();
        let journal = ProposalJournal::parse(
            &recovery
                .read_trusted(JOURNAL, MAX_STATUS_BYTES, FILE_MODE)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(journal.candidate.transaction_id, tx);
        assert_eq!(
            journal.candidate.artifacts.len(),
            fixture.new_manifest.artifacts.len() - 1
        );
        assert!(journal.system_plan);
        assert!(!journal
            .candidate
            .artifacts
            .iter()
            .any(|artifact| artifact.file == "voboost-restore"));
        let complete = Directory::open(&fixture.root.join(OFFLINE_STAGING_ROOT).join(&tx)).unwrap();
        verify_system_candidate_preflight(
            &fixture.root,
            &complete,
            &fixture.new_manifest,
            &journal.candidate,
        )
        .unwrap();
        let mut changed = fixture.new_manifest.clone();
        changed
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.file == "voboost-restore")
            .unwrap()
            .sha256 = "a".repeat(64);
        assert!(
            verify_reapply_restore_authority(&root, &fixture.active_manifest, &changed).is_err()
        );
        root.write_atomic("voboost-restore", b"tampered", 0o700)
            .unwrap();
        assert!(verify_reapply_restore_authority(
            &root,
            &fixture.active_manifest,
            &fixture.new_manifest
        )
        .is_err());
        root.write_atomic(
            "voboost-restore",
            &fixture.new_bodies["voboost-restore"],
            0o700,
        )
        .unwrap();
        assert_eq!(
            apply_offline_product_mode_in(&store, &fixture.root, &expected, &tx, true).unwrap(),
            Admission::Pending
        );
        assert!(
            apply_offline_product_mode_in(&store, &fixture.root, &"e".repeat(64), &tx, true)
                .is_err()
        );
        assert!(
            apply_offline_product_mode_in(&store, &fixture.root, &expected, "not-hex", true)
                .is_err()
        );
    }

    #[test]
    fn offline_apply_cannot_change_product_while_cluster_uninstall_pending() {
        let fixture = offline_fixture("1.0.0-beta1", "1.0.0-beta1");
        stage_full_closure(&fixture.root, "staged-tx", &fixture);
        let expected = fixture.active_manifest.digest().unwrap();
        let guard = crate::operation_contract::RawOperationLock::acquire_in(&fixture.root).unwrap();
        crate::cluster_control::test_queue_cluster_uninstall(&fixture.root, &expected);
        let root = fixture.root.clone();
        let old_manifest = std::fs::read(root.join(MANIFEST)).unwrap();
        let concurrent_root = root.clone();
        let concurrent_expected = expected.clone();
        let concurrent = std::thread::spawn(move || {
            let store = ProductCandidateStore::at_reconstructing(&concurrent_root);
            apply_offline_product_in(&store, &concurrent_root, &concurrent_expected, "staged-tx")
        })
        .join()
        .unwrap();
        assert!(matches!(concurrent, Err(ref error) if error.contains("operation busy")));
        drop(guard);
        let result = std::thread::spawn(move || {
            let store = ProductCandidateStore::at_reconstructing(&root);
            apply_offline_product_in(&store, &root, &expected, "staged-tx")
        })
        .join()
        .unwrap();
        assert!(
            result.is_err(),
            "update admitted with pending uninstall: {result:?}"
        );
        assert_eq!(
            std::fs::read(fixture.root.join(MANIFEST)).unwrap(),
            old_manifest
        );
    }

    #[test]
    fn offline_apply_entry_verifies_closure_checks_intent_and_repeats_idempotently() {
        let fixture = offline_fixture("1.0.0-beta1", "1.0.0-beta1");
        stage_full_closure(&fixture.root, "staged-tx", &fixture);
        let store = ProductCandidateStore::at_reconstructing(&fixture.root);
        // A drifted expected-active identity is refused before any mutation.
        let drift = apply_offline_product_in(&store, &fixture.root, &"e".repeat(64), "staged-tx")
            .unwrap_err();
        assert!(drift.contains("active product content changed"), "{drift}");
        let expected = fixture.active_manifest.digest().unwrap();
        let first = apply_offline_product_in(&store, &fixture.root, &expected, "staged-tx");
        assert!(
            first.is_ok(),
            "equal-content offline admission failed: {first:?}"
        );
        assert_ne!(
            first.unwrap(),
            Admission::UnsupportedActivationClass,
            "generation-only equal-content candidate must activate"
        );
        // Repeating the exact same operator intent re-enters the same durable
        // transaction instead of creating a second proposal.
        let repeat = apply_offline_product_in(&store, &fixture.root, &expected, "staged-tx");
        assert!(repeat.is_ok(), "idempotent repeat failed: {repeat:?}");

        // The staged closure must match the signed manifest exactly.
        let root_directory = Directory::open(&fixture.root).unwrap();
        let staged = root_directory
            .open_child(OFFLINE_STAGING_ROOT)
            .unwrap()
            .open_child("staged-tx")
            .unwrap();
        std::fs::write(
            fixture
                .root
                .join(OFFLINE_STAGING_ROOT)
                .join("staged-tx")
                .join("extra"),
            b"x",
        )
        .unwrap();
        drop(staged);
        assert!(
            apply_offline_product_in(&store, &fixture.root, &expected, "staged-tx")
                .unwrap_err()
                .contains("staged offline closure differs")
        );
    }
}
