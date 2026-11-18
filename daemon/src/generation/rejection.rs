use std::ffi::OsStr;
use std::fs;
use std::io::Write;
#[cfg(test)]
use std::path::Path;

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};

use super::{
    current_gid, current_uid, ensure_directory, read_incoming_identity, ActivationCrashPoint,
    ActivationJournal, GenerationStore, RejectedIncoming, AGENTS_SELECTED_FILE, CATALOG_FILE,
    GENERATIONS_DIR, READY_MARKER, ROOT_FILE_MODE,
};
use crate::catalog::{self, AgentCatalog};
use crate::secure_fs::Directory;
use crate::selection::{digest, SelectionReceipt};

pub(super) const QUARANTINE_DIR: &str = "quarantine";
pub(super) const REJECTING_DIR: &str = "rejecting";
pub(super) const REJECTION_JOURNAL_FILE: &str = ".rejection.json";
pub(super) const REJECTION_REASON_FILE: &str = "rejection.txt";
pub(super) const REJECTED_CATALOG_SNAPSHOT: &str = ".rejected-catalog";
pub(super) const REJECTED_SELECTION_SNAPSHOT: &str = ".rejected-selection";

const MAX_REJECTION_REASON_BYTES: usize = 4 * 1024;
pub(super) const MAX_REJECTION_CLEANUP_NODES: usize = 1024;
const MAX_REJECTION_HISTORY_ENTRIES: usize = 1024;
const MAX_REJECTION_CLEANUP_DEPTH: usize = 16;
const MAX_REJECTION_CLEANUP_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) enum ClaimPhase {
    None,
    Owned,
    CatalogFrozen,
    PairFrozen,
    Acknowledged,
    ReadyRemoved,
    SnapshotsRemoved,
    Restored,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub(super) enum RejectionPhase {
    Prepared,
    Claimed,
    Snapshotted,
    NextReady,
    Acked,
    HandedOff,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RejectionJournal {
    pub(super) schema_version: u32,
    pub(super) phase: RejectionPhase,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) reason: String,
    pub(super) archive_name: String,
    pub(super) catalog_sha256: Option<String>,
    pub(super) selection_sha256: Option<String>,
}

impl GenerationStore {
    pub(super) fn load_rejection_journal(&self) -> Result<Option<RejectionJournal>> {
        if fs::symlink_metadata(self.root.join(GENERATIONS_DIR).join(REJECTION_JOURNAL_FILE))
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            return Ok(None);
        }
        let generations = Directory::open(&self.root.join(GENERATIONS_DIR))?;
        let bytes = match generations.read_trusted(REJECTION_JOURNAL_FILE, 8192, ROOT_FILE_MODE) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let strict: crate::strict_json::StrictValue = serde_json::from_slice(&bytes)?;
        strict
            .validate(crate::strict_json::ValueLimits {
                max_depth: 2,
                max_total_nodes: 16,
                max_object_properties: 10,
                max_array_items: 0,
                max_string_bytes: MAX_REJECTION_REASON_BYTES,
            })
            .map_err(anyhow::Error::msg)?;
        let journal: RejectionJournal = serde_json::from_value(strict.0)?;
        validate_rejection_owner((journal.uid, journal.gid))?;
        ensure!(
            journal.schema_version == 1,
            "invalid rejection journal schema"
        );
        ensure!(
            journal.reason.len() < MAX_REJECTION_REASON_BYTES,
            "rejection reason oversized"
        );
        ensure!(
            journal
                .archive_name
                .strip_prefix("rejected-")
                .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())),
            "invalid rejection archive name"
        );
        ensure!(
            journal
                .catalog_sha256
                .as_deref()
                .is_none_or(catalog::is_sha256),
            "invalid rejection catalog identity"
        );
        ensure!(
            journal
                .selection_sha256
                .as_deref()
                .is_none_or(catalog::is_sha256),
            "invalid rejection selection identity"
        );
        ensure!(
            journal.selection_sha256.is_none() || journal.catalog_sha256.is_some(),
            "selection without catalog identity"
        );
        ensure!(
            journal.phase >= RejectionPhase::Snapshotted || journal.catalog_sha256.is_none(),
            "rejection identity published before snapshots"
        );
        Ok(Some(journal))
    }

    pub(super) fn write_rejection_journal(&self, journal: &RejectionJournal) -> Result<()> {
        let mut bytes = serde_json::to_vec(journal)?;
        bytes.push(b'\n');
        Directory::open(&self.root.join(GENERATIONS_DIR))?.write_atomic(
            REJECTION_JOURNAL_FILE,
            &bytes,
            ROOT_FILE_MODE,
        )?;
        Ok(())
    }

    /// Consume a failed staging transaction so it is never reprocessed.
    ///
    /// The whole `next/` directory is renamed (one atomic operation, no
    /// per-entry handling of untrusted names) into `quarantine/rejected-<ns>/`
    /// with a `rejection.txt` describing the validation failure, and a fresh
    /// empty `next/` is recreated with the trusted layout. After this the
    /// `ready` marker is gone, so neither the startup path nor the
    /// runtime watcher retries the same rejected content forever.
    pub fn reject_incoming(&self, reason: &str) -> Result<RejectedIncoming> {
        let guard = self.acquire_generation_guard()?;
        guard.verify_owner().map_err(anyhow::Error::msg)?;
        self.ensure_layout()?;
        ensure!(
            self.load_rejection_journal()?.is_none(),
            "rejection recovery is pending"
        );
        let incoming = Directory::open(&self.incoming).context("open rejected incoming")?;
        let (uid, gid) = incoming.owner().context("incoming owner")?;
        validate_rejection_owner((uid, gid))?;
        let mut end = reason.len().min(MAX_REJECTION_REASON_BYTES - 1);
        while !reason.is_char_boundary(end) {
            end -= 1;
        }
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        self.write_rejection_journal(&RejectionJournal {
            schema_version: 1,
            phase: RejectionPhase::Prepared,
            uid,
            gid,
            reason: reason[..end].to_string(),
            archive_name: format!("rejected-{stamp}"),
            catalog_sha256: None,
            selection_sha256: None,
        })?;
        self.recover_rejection_guarded()?
            .context("rejection recovery produced no result")
    }

    pub fn recover_rejection(&self) -> Result<Option<RejectedIncoming>> {
        let guard = self.acquire_generation_guard()?;
        guard.verify_owner().map_err(anyhow::Error::msg)?;
        self.recover_rejection_guarded()
    }

    fn recover_rejection_guarded(&self) -> Result<Option<RejectedIncoming>> {
        let generations = self.root.join(GENERATIONS_DIR);
        let rejecting_path = generations.join(REJECTING_DIR);
        let Some(mut journal) = self.load_rejection_journal()? else {
            ensure!(
                fs::symlink_metadata(&rejecting_path)
                    .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
                "fixed rejecting slot exists without journal"
            );
            return Ok(None);
        };
        if journal.phase == RejectionPhase::Prepared {
            let next_exists = fs::symlink_metadata(&self.incoming).is_ok();
            let rejecting_exists = fs::symlink_metadata(&rejecting_path).is_ok();
            match (next_exists, rejecting_exists) {
                (true, false) => fs::rename(&self.incoming, &rejecting_path)
                    .context("claim incoming for rejection")?,
                (false, true) => {}
                _ => bail!("prepared rejection has ambiguous next/rejecting cut"),
            }
            Directory::open(&generations)?.sync_all()?;
            journal.phase = RejectionPhase::Claimed;
            self.write_rejection_journal(&journal)?;
        }
        if journal.phase == RejectionPhase::Claimed {
            let rejecting =
                Directory::open(&rejecting_path).context("open fixed rejecting slot")?;
            rejecting.set_owner(current_uid(), current_gid())?;
            rejecting.set_mode(0o700)?;
            rejecting.sync_all()?;
            let identity = snapshot_rejected_identity(&rejecting, (journal.uid, journal.gid));
            let mut record = journal.reason.as_bytes().to_vec();
            record.push(b'\n');
            if fs::symlink_metadata(rejecting_path.join(REJECTION_REASON_FILE)).is_ok() {
                rejecting.unlink(REJECTION_REASON_FILE)?;
                rejecting.sync_all()?;
            }
            rejecting.prepare_trusted(REJECTION_REASON_FILE, &record, ROOT_FILE_MODE)?;
            rejecting.sync_all()?;
            if let Some((catalog, selection)) = identity {
                journal.catalog_sha256 = Some(catalog);
                journal.selection_sha256 = selection;
            }
            journal.phase = RejectionPhase::Snapshotted;
            self.write_rejection_journal(&journal)?;
        }
        if journal.phase == RejectionPhase::Snapshotted {
            if !self.incoming.exists() {
                fs::create_dir(&self.incoming)?;
            }
            let incoming = Directory::open(&self.incoming)?;
            let metadata = fs::symlink_metadata(&self.incoming)?;
            ensure!(
                metadata.file_type().is_dir(),
                "recreated next is not a directory"
            );
            ensure!(
                fs::read_dir(&self.incoming)?.next().is_none(),
                "recreated next is not empty"
            );
            ensure!(
                incoming.owner()? == (current_uid(), current_gid()),
                "pre-ack next is not daemon-owned"
            );
            incoming.set_mode(0o700)?;
            incoming.sync_all()?;
            Directory::open(&generations)?.sync_all()?;
            journal.phase = RejectionPhase::NextReady;
            self.write_rejection_journal(&journal)?;
        }
        if journal.phase == RejectionPhase::NextReady {
            if let Some(catalog) = journal.catalog_sha256.as_deref() {
                self.write_acknowledgement(
                    "rejected",
                    catalog,
                    journal.selection_sha256.as_deref(),
                    None,
                )?;
            }
            journal.phase = RejectionPhase::Acked;
            self.write_rejection_journal(&journal)?;
        }
        if journal.phase == RejectionPhase::Acked {
            let rejected_root = generations.join(QUARANTINE_DIR);
            ensure_directory(&rejected_root, 0o700)?;
            let target = rejected_root.join(&journal.archive_name);
            match (
                fs::symlink_metadata(&rejecting_path).is_ok(),
                fs::symlink_metadata(&target).is_ok(),
            ) {
                (true, false) => {
                    fs::rename(&rejecting_path, &target).context("archive durable rejection")?
                }
                (false, true) => {}
                _ => bail!("acked rejection has ambiguous rejecting/archive cut"),
            }
            Directory::open(&rejected_root)?.sync_all()?;
            let rejected_directory = Directory::open(&rejected_root)?;
            let mut rejected =
                rejected_history_names_bounded(&rejected_directory, MAX_REJECTION_HISTORY_ENTRIES)?;
            rejected.sort();
            let excess = rejected.len().saturating_sub(3);
            for name in rejected.into_iter().take(excess) {
                if name != journal.archive_name {
                    remove_child_tree_bounded(&rejected_directory, &name)?;
                }
            }
            let incoming = Directory::open(&self.incoming)?;
            match incoming.owner()? {
                owner if owner == (current_uid(), current_gid()) => {
                    incoming.set_owner(journal.uid, journal.gid)?;
                    incoming.set_mode(0o700)?;
                    incoming.sync_all()?;
                }
                owner if owner == (journal.uid, journal.gid) => {}
                _ => bail!("post-ack next owner is foreign"),
            }
            journal.phase = RejectionPhase::HandedOff;
            self.write_rejection_journal(&journal)?;
        }
        if journal.phase == RejectionPhase::HandedOff {
            let target = generations.join(QUARANTINE_DIR).join(&journal.archive_name);
            Directory::open(&generations)?.unlink(REJECTION_JOURNAL_FILE)?;
            Directory::open(&generations)?.sync_all()?;
            return Ok(Some(RejectedIncoming {
                path: target,
                identity: journal
                    .catalog_sha256
                    .map(|catalog| (catalog, journal.selection_sha256)),
            }));
        }
        Ok(None)
    }

    pub(super) fn complete_matching_incoming(
        &self,
        status: &str,
        journal: &mut ActivationJournal,
        generation_id: Option<&str>,
        crash_point: Option<ActivationCrashPoint>,
    ) -> Result<bool> {
        let catalog_sha256 = journal.catalog_sha256.clone();
        let selection_sha256 = journal.selection_sha256.clone();
        let original_owner = (journal.staging_owner.uid, journal.staging_owner.gid);
        let incoming = Directory::open(&self.incoming)?;
        if journal.claim_phase == ClaimPhase::None {
            let observed_owner = incoming.owner()?;
            if observed_owner == original_owner {
                let identity = read_incoming_identity(&incoming);
                if identity.as_ref()
                    != Some(&(catalog_sha256.to_string(), selection_sha256.to_string()))
                {
                    return Ok(false);
                }
                incoming.set_owner(current_uid(), current_gid())?;
                incoming.set_mode(0o700)?;
                incoming.sync_all()?;
                if crash_point == Some(ActivationCrashPoint::ClaimOwnerChangedBeforeJournal) {
                    bail!("simulated crash after owner claim before journal");
                }
            } else {
                ensure!(
                    observed_owner == (current_uid(), current_gid()),
                    "incoming owner changed"
                );
            }
            journal.claim_phase = ClaimPhase::Owned;
            self.write_activation_journal(journal)?;
        } else if journal.claim_phase == ClaimPhase::SnapshotsRemoved
            && incoming.owner()? == original_owner
        {
            journal.claim_phase = ClaimPhase::Restored;
            self.write_activation_journal(journal)?;
        } else {
            ensure!(
                journal.claim_phase == ClaimPhase::Restored
                    || incoming.owner()? == (current_uid(), current_gid()),
                "claimed incoming owner is foreign"
            );
        }
        if crash_point == Some(ActivationCrashPoint::ClaimOwned) {
            bail!("simulated crash after incoming ownership claim");
        }
        if journal.claim_phase == ClaimPhase::Owned {
            let bytes =
                match incoming.read_trusted(".claim-catalog", catalog::MAX_CATALOG_BYTES, 0o400) {
                    Ok(bytes) => bytes,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        let bytes = incoming.read_untrusted_owned(
                            CATALOG_FILE,
                            catalog::MAX_CATALOG_BYTES,
                            original_owner,
                        )?;
                        if AgentCatalog::digest(&bytes) != catalog_sha256 {
                            incoming.set_owner(original_owner.0, original_owner.1)?;
                            incoming.set_mode(0o700)?;
                            incoming.sync_all()?;
                            journal.claim_phase = ClaimPhase::None;
                            self.write_activation_journal(journal)?;
                            return Ok(false);
                        }
                        incoming.prepare_trusted(".claim-catalog", &bytes, 0o400)?;
                        bytes
                    }
                    Err(error) => return Err(error.into()),
                };
            ensure!(
                AgentCatalog::digest(&bytes) == catalog_sha256,
                "catalog snapshot mismatch"
            );
            journal.claim_phase = ClaimPhase::CatalogFrozen;
            self.write_activation_journal(journal)?;
        }
        if crash_point == Some(ActivationCrashPoint::ClaimCatalog) {
            bail!("simulated crash after catalog claim snapshot");
        }
        if journal.claim_phase == ClaimPhase::CatalogFrozen {
            let catalog_snapshot =
                incoming.read_trusted(".claim-catalog", catalog::MAX_CATALOG_BYTES, 0o400)?;
            ensure!(
                AgentCatalog::digest(&catalog_snapshot) == catalog_sha256,
                "catalog snapshot mismatch"
            );
            let selection = match incoming.read_trusted(
                ".claim-selection",
                crate::selection::MAX_SELECTION_BYTES,
                0o400,
            ) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let bytes = incoming.read_untrusted_owned(
                        AGENTS_SELECTED_FILE,
                        crate::selection::MAX_SELECTION_BYTES,
                        original_owner,
                    )?;
                    if digest(&bytes) != selection_sha256 {
                        incoming.unlink(".claim-catalog")?;
                        incoming.set_owner(original_owner.0, original_owner.1)?;
                        incoming.set_mode(0o700)?;
                        incoming.sync_all()?;
                        journal.claim_phase = ClaimPhase::None;
                        self.write_activation_journal(journal)?;
                        return Ok(false);
                    }
                    incoming.prepare_trusted(".claim-selection", &bytes, 0o400)?;
                    bytes
                }
                Err(error) => return Err(error.into()),
            };
            ensure!(
                digest(&selection) == selection_sha256,
                "selection snapshot mismatch"
            );
            journal.claim_phase = ClaimPhase::PairFrozen;
            self.write_activation_journal(journal)?;
        }
        if crash_point == Some(ActivationCrashPoint::ClaimSelection) {
            bail!("simulated crash after selection claim snapshot");
        }
        if journal.claim_phase == ClaimPhase::PairFrozen {
            ensure!(
                digest(&incoming.read_trusted(
                    ".claim-catalog",
                    catalog::MAX_CATALOG_BYTES,
                    0o400
                )?) == catalog_sha256,
                "catalog snapshot mismatch"
            );
            ensure!(
                digest(&incoming.read_trusted(
                    ".claim-selection",
                    crate::selection::MAX_SELECTION_BYTES,
                    0o400
                )?) == selection_sha256,
                "selection snapshot mismatch"
            );
            self.write_acknowledgement_to(
                &incoming,
                status,
                &catalog_sha256,
                Some(&selection_sha256),
                generation_id,
            )?;
            journal.claim_phase = ClaimPhase::Acknowledged;
            self.write_activation_journal(journal)?;
        }
        if crash_point == Some(ActivationCrashPoint::ClaimAcknowledged) {
            bail!("simulated crash after claimed acknowledgement");
        }
        if journal.claim_phase == ClaimPhase::Acknowledged {
            match incoming.unlink(READY_MARKER) {
                Ok(()) => incoming.sync_all()?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            journal.claim_phase = ClaimPhase::ReadyRemoved;
            self.write_activation_journal(journal)?;
        }
        if crash_point == Some(ActivationCrashPoint::ClaimReadyRemoved) {
            bail!("simulated crash after claimed ready removal");
        }
        if journal.claim_phase == ClaimPhase::ReadyRemoved {
            for name in [".claim-catalog", ".claim-selection"] {
                match incoming.unlink(name) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            incoming.sync_all()?;
            journal.claim_phase = ClaimPhase::SnapshotsRemoved;
            self.write_activation_journal(journal)?;
        }
        if crash_point == Some(ActivationCrashPoint::ClaimSnapshotsRemoved) {
            bail!("simulated crash after claim snapshot cleanup");
        }
        if journal.claim_phase == ClaimPhase::SnapshotsRemoved {
            incoming.set_owner(original_owner.0, original_owner.1)?;
            incoming.set_mode(0o700)?;
            incoming.sync_all()?;
            if crash_point == Some(ActivationCrashPoint::ClaimOwnerRestoredBeforeJournal) {
                bail!("simulated crash after owner restore before journal");
            }
            journal.claim_phase = ClaimPhase::Restored;
            self.write_activation_journal(journal)?;
        }
        if crash_point == Some(ActivationCrashPoint::ClaimOwnerRestored) {
            bail!("simulated crash after claim owner restore");
        }
        Ok(true)
    }
}

#[cfg(test)]
pub(super) fn remove_tree_bounded_nofollow(root: &Path) -> Result<()> {
    let parent = root
        .parent()
        .context("rejection cleanup root has no parent")?;
    let name = root
        .file_name()
        .and_then(|v| v.to_str())
        .context("invalid rejection cleanup leaf")?;
    let parent = Directory::open(parent)?;
    remove_child_tree_bounded(&parent, name)
}

fn remove_child_tree_bounded(parent: &Directory, name: &str) -> Result<()> {
    enum FrozenEntry {
        File(String),
        Dir(String, Box<FrozenDir>),
    }
    struct FrozenDir {
        directory: Directory,
        entries: Vec<FrozenEntry>,
    }
    fn freeze(
        directory: Directory,
        depth: usize,
        nodes: &mut usize,
        bytes: &mut u64,
    ) -> Result<FrozenDir> {
        ensure!(
            depth <= MAX_REJECTION_CLEANUP_DEPTH,
            "rejection cleanup depth bound exceeded"
        );
        directory.set_owner(current_uid(), current_gid())?;
        directory.set_mode(0o700)?;
        directory.sync_all()?;
        let names =
            directory.entry_names_bounded(MAX_REJECTION_CLEANUP_NODES.saturating_sub(*nodes))?;
        let mut entries = Vec::new();
        for name in names {
            *nodes += 1;
            ensure!(
                *nodes <= MAX_REJECTION_CLEANUP_NODES,
                "rejection cleanup node bound exceeded"
            );
            let (is_dir, len) = directory.entry_info_nofollow(&name)?;
            *bytes = bytes
                .checked_add(len)
                .context("rejection cleanup byte overflow")?;
            ensure!(
                *bytes <= MAX_REJECTION_CLEANUP_BYTES,
                "rejection cleanup byte bound exceeded"
            );
            if is_dir {
                let child = directory.open_child(&name)?;
                entries.push(FrozenEntry::Dir(
                    name,
                    Box::new(freeze(child, depth + 1, nodes, bytes)?),
                ));
            } else {
                entries.push(FrozenEntry::File(name));
            }
        }
        Ok(FrozenDir { directory, entries })
    }
    fn remove(frozen: FrozenDir) -> Result<()> {
        for entry in frozen.entries {
            match entry {
                FrozenEntry::File(name) => frozen.directory.unlink(&name)?,
                FrozenEntry::Dir(name, child) => {
                    remove(*child)?;
                    frozen.directory.remove_child_dir(&name)?;
                }
            }
            frozen.directory.sync_all()?;
        }
        Ok(())
    }
    let directory = parent.open_child(name)?;
    let mut nodes = 0;
    let mut bytes = 0;
    let frozen = freeze(directory, 0, &mut nodes, &mut bytes)?;
    remove(frozen)?;
    parent.remove_child_dir(name)?;
    parent.sync_all()?;
    Ok(())
}

pub(super) fn rejected_history_names_bounded(
    directory: &Directory,
    maximum: usize,
) -> Result<Vec<String>> {
    let names = directory.entry_names_bounded(maximum)?;
    let mut rejected = Vec::new();
    for name in &names {
        let canonical = if let Some(suffix) = name.strip_prefix("rejected-") {
            let valid = !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit());
            if valid {
                rejected.push(name.clone());
            }
            valid
        } else if let Some(suffix) = name.strip_prefix("retired-") {
            suffix.len() == 64
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        } else {
            false
        };
        ensure!(canonical, "non-canonical quarantine entry {name}");
        ensure!(
            directory.entry_info_nofollow(name)?.0,
            "quarantine entry is not a directory: {name}"
        );
    }
    Ok(rejected)
}

pub(super) fn snapshot_rejected_identity(
    rejected: &Directory,
    owner: (u32, u32),
) -> Option<(String, Option<String>)> {
    snapshot_rejected_identity_with(rejected, owner, || {})
}

pub(super) fn snapshot_rejected_identity_with(
    rejected: &Directory,
    owner: (u32, u32),
    between_member_reads: impl FnOnce(),
) -> Option<(String, Option<String>)> {
    let catalog = rejected
        .read_untrusted_owned(CATALOG_FILE, catalog::MAX_CATALOG_BYTES, owner)
        .ok()?;
    between_member_reads();
    let selection = rejected
        .read_untrusted_owned(
            AGENTS_SELECTED_FILE,
            crate::selection::MAX_SELECTION_BYTES,
            owner,
        )
        .ok()
        .and_then(|bytes| {
            let parsed = SelectionReceipt::parse_canonical(&bytes).ok()?;
            (parsed.catalog_sha256 == AgentCatalog::digest(&catalog)).then_some(bytes)
        });
    snapshot_rejected_member(rejected, REJECTED_CATALOG_SNAPSHOT, &catalog)?;
    if let Some(selection) = selection.as_ref() {
        snapshot_rejected_member(rejected, REJECTED_SELECTION_SNAPSHOT, selection)?;
    }
    rejected.sync_all().ok()?;
    Some((
        AgentCatalog::digest(&catalog),
        selection.as_deref().map(digest),
    ))
}

fn snapshot_rejected_member(rejected: &Directory, name: &str, bytes: &[u8]) -> Option<()> {
    match rejected.create_new(OsStr::new(name), ROOT_FILE_MODE) {
        Ok(mut file) => {
            file.write_all(bytes).ok()?;
            file.sync_all().ok()?;
            Some(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (rejected
            .read_trusted(name, bytes.len(), ROOT_FILE_MODE)
            .ok()?
            .as_slice()
            == bytes)
            .then_some(()),
        Err(_) => None,
    }
}

pub(super) fn validate_rejection_owner(owner: (u32, u32)) -> Result<()> {
    #[cfg(test)]
    if owner == (current_uid(), current_gid()) {
        return Ok(());
    }
    validate_rejection_owner_production(owner, (current_uid(), current_gid()))
}

pub(super) fn validate_rejection_owner_production(
    owner: (u32, u32),
    daemon: (u32, u32),
) -> Result<()> {
    ensure!(
        owner.0 != 0 && owner.1 != 0,
        "rejection owner must be unprivileged"
    );
    ensure!(
        owner != daemon,
        "rejection owner must differ from daemon identity"
    );
    Ok(())
}
