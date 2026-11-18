//! Combined global operation document shared by install, update, restore and
//! uninstall system programs. It admits one correlated WAL and publishes the
//! installer-visible state. The verified WAL phase remains the continuation
//! decision.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// Path of the combined global operation document in the Voboost root directory.
pub const OPERATION_DESCRIPTOR_PATH: &str = "/data/voboost/operation.json";
pub const OPERATION_LOCK_PATH: &str = "/data/voboost/operation.lock";
/// Maximum byte size of the operation document.
pub const MAX_OPERATION_DESCRIPTOR_BYTES: usize = 4096;

/// The four global system operations.
///
/// `Generation` is NOT a global operation — it has its own WAL and is not
/// coordinated through this descriptor.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Operation {
    Install,
    Update,
    Restore,
    Uninstall,
}

/// Combined authority and observable state for an operation-specific WAL.
/// An active operation is never interrupted
/// mid-mutation — it first recovers, rolls back, or commits. A new operation
/// receives `busy` and retries after the terminal state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationDescriptor {
    pub schema_version: u32,
    pub operation: Operation,
    pub transaction_id: String,
    /// Path to the operation-specific journal inside `recovery/<transaction-id>/`.
    pub journal: String,
    pub phase: String,
    pub outcome: String,
    pub reboot_count: u32,
    pub boot_id: String,
    pub status_sequence: u64,
    pub journal_sha256: String,
    pub error: Option<Value>,
    pub installed_apk: Option<Value>,
}

impl OperationDescriptor {
    pub fn new(
        operation: Operation,
        transaction_id: String,
        journal: String,
        boot_id: String,
    ) -> Result<Self, String> {
        let value = Self {
            schema_version: 1,
            operation,
            transaction_id,
            journal,
            phase: format!("{}-prepare", operation.as_str()),
            outcome: "running".to_string(),
            reboot_count: 0,
            boot_id,
            status_sequence: 1,
            journal_sha256: "0".repeat(64),
            error: None,
            installed_apk: None,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        let expected_journal = format!(
            "recovery/{}/{}-journal.json",
            self.transaction_id,
            self.operation.as_str()
        );
        let product_update_journal =
            format!("recovery/{}/product-proposal.json", self.transaction_id);
        if self.schema_version != 1
            || !canonical_hash(&self.transaction_id)
            || (self.journal != expected_journal
                && !(self.operation == Operation::Update && self.journal == product_update_journal))
            || self.phase.is_empty()
            || !matches!(
                self.outcome.as_str(),
                "running" | "reboot-required" | "complete" | "failed"
            )
            || !canonical_boot_id(&self.boot_id)
            || self.status_sequence == 0
            || !canonical_hash(&self.journal_sha256)
        {
            return Err("operation document is invalid".to_string());
        }
        if self.operation == Operation::Uninstall
            && (self.outcome == "complete"
                || matches!(
                    self.phase.as_str(),
                    "uninstall-reboot" | "uninstall-complete"
                ))
        {
            return Err(
                "uninstall completion exists only as an external absence receipt".to_string(),
            );
        }
        match (self.outcome.as_str(), &self.error) {
            ("failed", Some(error)) if valid_error(error) => {}
            ("failed", _) => return Err("failed operation document lacks a valid error".into()),
            (_, None) => {}
            (_, Some(_)) => return Err("non-failed operation document contains error".into()),
        }
        match (&self.operation, self.outcome.as_str(), &self.installed_apk) {
            (Operation::Install, "complete", Some(apk)) if valid_installed_apk(apk) => {}
            (Operation::Install, "complete", _) => {
                return Err("complete install document lacks a valid APK identity".into())
            }
            (_, _, None) => {}
            _ => return Err("operation document APK identity is invalid".into()),
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut bytes =
            serde_json::to_vec(self).map_err(|e| format!("serialize operation descriptor: {e}"))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_OPERATION_DESCRIPTOR_BYTES {
            return Err("operation descriptor byte envelope is invalid".to_string());
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|e| format!("parse operation descriptor: {e}"))?;
        value.validate()?;
        if value.canonical_bytes()? != bytes {
            return Err("operation descriptor is not canonical".to_string());
        }
        Ok(value)
    }

    /// True if this descriptor authorizes the given operation and transaction.
    /// A terminal descriptor (Complete) does not authorize further work.
    pub fn authorizes(&self, operation: Operation, transaction_id: &str) -> bool {
        self.operation == operation && self.transaction_id == transaction_id
    }

    fn same_authority(&self, other: &Self) -> bool {
        self.operation == other.operation
            && self.transaction_id == other.transaction_id
            && self.journal == other.journal
    }
}

impl Operation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Update => "update",
            Self::Restore => "restore",
            Self::Uninstall => "uninstall",
        }
    }
}

/// Held global-operation lease. Dropping it releases the kernel lock but never
/// changes the operation document.
pub struct OperationLease {
    root: File,
    lock: File,
    lock_identity: (u64, u64),
    descriptor: OperationDescriptor,
}

/// Exclusive operation lock retained across pre-WAL checks and admission.
/// The raw guard does not authorize mutation by itself; callers must verify the
/// current operation and their own recovery authority before writing.
pub struct RawOperationLock {
    root: File,
    lock: File,
    lock_identity: (u64, u64),
}
impl RawOperationLock {
    pub fn acquire_in(root: &Path) -> Result<Self, String> {
        let root = open_root(root)?;
        let lock = open_or_create_at(&root, "operation.lock", 0o600)?;
        require_trusted_file(&lock, 0o600, "operation lock")?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("operation busy".into());
        }
        require_trusted_file(&lock, 0o600, "operation lock")?;
        let metadata = lock
            .metadata()
            .map_err(|e| format!("stat operation lock: {e}"))?;
        let guard = Self {
            root,
            lock,
            lock_identity: (metadata.dev(), metadata.ino()),
        };
        guard.verify_owner()?;
        Ok(guard)
    }
    pub fn verify_owner(&self) -> Result<(), String> {
        require_root(&self.root)?;
        require_trusted_file(&self.lock, 0o600, "operation lock")?;
        let path = open_at(
            &self.root,
            "operation.lock",
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        )
        .map_err(|e| format!("reopen operation lock: {e}"))?;
        require_trusted_file(&path, 0o600, "operation lock path")?;
        let metadata = path
            .metadata()
            .map_err(|e| format!("stat operation lock path: {e}"))?;
        if (metadata.dev(), metadata.ino()) != self.lock_identity {
            return Err("operation lock pathname identity changed".into());
        }
        if unsafe { libc::flock(self.lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("operation lock ownership lost".into());
        }
        Ok(())
    }
    /// Inspect the current projection while retaining the same lock.
    pub fn read_live_projection(&self) -> Result<Option<OperationDescriptor>, String> {
        self.verify_owner()?;
        read_descriptor(&self.root)
    }
    pub fn admit(self, requested: OperationDescriptor) -> Result<OperationLease, String> {
        OperationLease::from_held(self, requested)
    }
    pub fn reconcile_terminal(
        self,
        previous: &OperationDescriptor,
        terminal: &OperationDescriptor,
    ) -> Result<OperationLease, String> {
        OperationLease::reconcile_from_held(self, previous, terminal)
    }
}

/// Held exclusion barrier for generation mutations. Generation deliberately
/// has no operation descriptor, but it shares the same kernel lock so global
/// operations cannot be published across its check/mutate window.
pub struct GenerationGuard {
    root: File,
    lock: File,
    lock_identity: (u64, u64),
    allow_install_descriptor: bool,
    install_descriptor: Option<OperationDescriptor>,
    terminal_descriptor: Option<OperationDescriptor>,
}

impl GenerationGuard {
    pub fn acquire_in(root: &Path) -> Result<Self, String> {
        let root = open_root(root)?;
        let lock = open_or_create_at(&root, "operation.lock", 0o600)?;
        require_trusted_file(&lock, 0o600, "operation lock")?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("operation busy".to_string());
        }
        require_trusted_file(&lock, 0o600, "operation lock")?;
        let terminal_descriptor = match read_verified_descriptor(&root)? {
            Some(descriptor) if descriptor.outcome == "complete" => {
                let cleanup = terminal_cleanup_detail(&root, &descriptor)?;
                if !cleanup.is_complete() {
                    return Err(format!("operation busy: {}", cleanup.detail()));
                }
                Some(descriptor)
            }
            Some(_) => return Err("operation busy".to_string()),
            None => None,
        };
        let metadata = lock
            .metadata()
            .map_err(|error| format!("stat operation lock: {error}"))?;
        Ok(Self {
            root,
            lock,
            lock_identity: (metadata.dev(), metadata.ino()),
            allow_install_descriptor: false,
            install_descriptor: None,
            terminal_descriptor,
        })
    }

    /// Promote an idle barrier after its caller durably stages an authenticated WAL.
    /// The same kernel lock remains held across journal creation and publication.
    pub fn admit_operation(self, requested: OperationDescriptor) -> Result<OperationLease, String> {
        self.admit_operation_with(requested, atomic_write_descriptor, &mut false)
    }

    /// `possibly_admitted` is false for verified pre-publication rejection.
    /// A post-publication read failure remains unknown, never fabricated absence.
    pub fn admit_operation_tracked(
        self,
        requested: OperationDescriptor,
        possibly_admitted: &mut bool,
    ) -> Result<OperationLease, String> {
        self.admit_operation_with(requested, atomic_write_descriptor, possibly_admitted)
    }

    fn admit_operation_with(
        self,
        mut requested: OperationDescriptor,
        publish: impl FnOnce(&File, &OperationDescriptor) -> Result<(), String>,
        possibly_admitted: &mut bool,
    ) -> Result<OperationLease, String> {
        *possibly_admitted = false;
        requested.validate()?;
        self.verify_owner()?;
        if self.allow_install_descriptor {
            return Err("active install generation cannot admit another operation".into());
        }
        if let Some(terminal) = &self.terminal_descriptor {
            let cleanup = terminal_cleanup_detail(&self.root, terminal)?;
            if !cleanup.is_complete() {
                return Err(format!("operation busy: {}", cleanup.detail()));
            }
        }
        requested.journal_sha256 = hash_journal(&self.root, &requested.journal)?;
        if let Err(error) = publish(&self.root, &requested) {
            *possibly_admitted = match read_verified_descriptor(&self.root) {
                Ok(Some(current)) if current.same_authority(&requested) => true,
                Ok(current) if current == self.terminal_descriptor => false,
                _ => true,
            };
            return Err(error);
        }
        *possibly_admitted = true;
        let lease = OperationLease {
            root: self.root,
            lock: self.lock,
            lock_identity: self.lock_identity,
            descriptor: requested,
        };
        lease.verify_owner()?;
        Ok(lease)
    }

    pub fn acquire_install_generation_in(root: &Path) -> Result<Self, String> {
        let root = open_root(root)?;
        let lock = open_or_create_at(&root, "operation.lock", 0o600)?;
        require_trusted_file(&lock, 0o600, "operation lock")?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("operation busy".to_string());
        }
        let descriptor =
            read_verified_descriptor(&root)?.ok_or("install generation descriptor absent")?;
        if descriptor.operation != Operation::Install {
            return Err("operation busy".to_string());
        }
        let metadata = lock
            .metadata()
            .map_err(|error| format!("stat operation lock: {error}"))?;
        Ok(Self {
            root,
            lock,
            lock_identity: (metadata.dev(), metadata.ino()),
            allow_install_descriptor: true,
            install_descriptor: Some(descriptor),
            terminal_descriptor: None,
        })
    }

    pub fn verify_owner(&self) -> Result<(), String> {
        require_root(&self.root)?;
        require_trusted_file(&self.lock, 0o600, "operation lock")?;
        let path_lock = open_at(
            &self.root,
            "operation.lock",
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        )
        .map_err(|error| format!("reopen operation lock: {error}"))?;
        require_trusted_file(&path_lock, 0o600, "operation lock path")?;
        let metadata = path_lock
            .metadata()
            .map_err(|error| format!("stat operation lock path: {error}"))?;
        if (metadata.dev(), metadata.ino()) != self.lock_identity {
            return Err("operation lock pathname identity changed".to_string());
        }
        match read_verified_descriptor(&self.root)? {
            None if !self.allow_install_descriptor && self.terminal_descriptor.is_none() => {}
            Some(descriptor)
                if !self.allow_install_descriptor
                    && self
                        .terminal_descriptor
                        .as_ref()
                        .is_some_and(|expected| expected == &descriptor) => {}
            Some(descriptor)
                if self.allow_install_descriptor
                    && self
                        .install_descriptor
                        .as_ref()
                        .is_some_and(|expected| expected.same_authority(&descriptor)) => {}
            _ => return Err("operation descriptor changed during generation mutation".to_string()),
        }
        if unsafe { libc::flock(self.lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("operation lock ownership lost".to_string());
        }
        Ok(())
    }
}

impl OperationLease {
    /// Acquire the fixed lock and publish `operation.json` after the caller has
    /// durably created the operation WAL. Existing work is recovery-first: an
    /// identical descriptor resumes, while every different descriptor is busy.
    pub fn acquire_in(root: &Path, requested: OperationDescriptor) -> Result<Self, String> {
        Self::acquire_in_checked(root, requested, || Ok(()))
    }

    /// Run admission under the held operation lock before any descriptor write.
    pub fn acquire_in_checked(
        root: &Path,
        requested: OperationDescriptor,
        check: impl FnOnce() -> Result<(), String>,
    ) -> Result<Self, String> {
        requested.validate()?;
        let guard = RawOperationLock::acquire_in(root)?;
        check()?;
        guard.admit(requested)
    }

    fn from_held(guard: RawOperationLock, requested: OperationDescriptor) -> Result<Self, String> {
        requested.validate()?;
        guard.verify_owner()?;
        let RawOperationLock {
            root,
            lock,
            lock_identity,
        } = guard;
        let mut requested = requested;
        match read_descriptor(&root)? {
            // Reacquisition never rewinds an observer-visible phase or
            // sequence. The verified current document remains authoritative
            // for the same WAL, including a retained terminal result whose
            // journal has already been removed.
            Some(current) if current.same_authority(&requested) => {
                if current.outcome == "complete" {
                    if read_verified_descriptor(&root)?.as_ref() != Some(&current) {
                        return Err("terminal operation document is not verified".to_string());
                    }
                    requested = current;
                } else {
                    let journal_sha256 = hash_journal(&root, &requested.journal)?;
                    if current.journal_sha256 == journal_sha256 {
                        requested = current;
                    } else if requested.journal_sha256 == journal_sha256
                        && requested.status_sequence >= current.status_sequence
                        && requested.reboot_count >= current.reboot_count
                        && requested.outcome != "complete"
                    {
                        // A crash can occur after the operation WAL rename and
                        // before its observer projection is replaced. Only the
                        // same authority may reconcile that gap, and only to a
                        // caller-supplied projection whose digest matches the
                        // current WAL without moving either counter backwards.
                        atomic_write_descriptor(&root, &requested)?;
                    } else {
                        return Err("operation document and recovery WAL diverged".to_string());
                    }
                }
            }
            Some(current) if current.outcome != "complete" => {
                return Err("operation busy".to_string())
            }
            Some(current) => {
                let cleanup = terminal_cleanup_detail(&root, &current)?;
                if !cleanup.is_complete() {
                    return Err(format!("operation busy: {}", cleanup.detail()));
                }
                requested.journal_sha256 = hash_journal(&root, &requested.journal)?;
                atomic_write_descriptor(&root, &requested)?;
            }
            None => {
                requested.journal_sha256 = hash_journal(&root, &requested.journal)?;
                atomic_write_descriptor(&root, &requested)?;
            }
        }
        let lease = Self {
            root,
            lock,
            lock_identity,
            descriptor: requested,
        };
        lease.verify_owner()?;
        Ok(lease)
    }

    /// Re-read the root pointer before each live mutation.
    pub fn verify_owner(&self) -> Result<(), String> {
        self.verify_path_and_descriptor()?;
        let result = unsafe { libc::flock(self.lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return Err("operation lock ownership lost".to_string());
        }
        Ok(())
    }

    /// Verify that this lease owns the exact requested product root.
    pub fn verify_owner_in(&self, root: &Path) -> Result<(), String> {
        self.verify_owner()?;
        let named = open_root(root)?;
        let held = self
            .root
            .metadata()
            .map_err(|e| format!("stat held operation root: {e}"))?;
        let current = named
            .metadata()
            .map_err(|e| format!("stat requested operation root: {e}"))?;
        if (held.dev(), held.ino()) != (current.dev(), current.ino()) {
            return Err("operation lease belongs to another product root".into());
        }
        Ok(())
    }

    pub fn release_for_install_generation(&self) -> Result<(), String> {
        self.verify_path_and_descriptor()?;
        if self.descriptor.operation != Operation::Install {
            return Err("only install may release for generation activation".to_string());
        }
        if unsafe { libc::flock(self.lock.as_raw_fd(), libc::LOCK_UN) } != 0 {
            return Err(format!(
                "release install generation lock: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    /// Reconcile the terminal WAL→projection cut of one writer grammar
    /// (R24). The durable WAL may already have reached its terminal phase
    /// while the observer projection still shows the immediately preceding
    /// publication: the terminal journal write and the projection publish
    /// are two durable steps, and a crash between them leaves the shared
    /// descriptor one publication behind the WAL. The caller derives both
    /// descriptors from the same durable WAL — `previous` must be the exact
    /// bit-for-bit publication that preceded the terminal one, `terminal`
    /// the exact publication that the interrupted writer owes. Only this
    /// proven prefix may be replaced by its derivable successor; every
    /// other combination keeps diverging. The general monotonic publish
    /// guard is untouched: this is not a publish, it is a proof-checked
    /// completion of one already-ordered write.
    pub fn reconcile_terminal_cut_in(
        root: &Path,
        previous: &OperationDescriptor,
        terminal: &OperationDescriptor,
    ) -> Result<Self, String> {
        Self::reconcile_terminal_cut_in_checked(root, previous, terminal, || Ok(()))
    }

    /// Check admission under the same lock before reconciling a terminal cut.
    pub fn reconcile_terminal_cut_in_checked(
        root: &Path,
        previous: &OperationDescriptor,
        terminal: &OperationDescriptor,
        check: impl FnOnce() -> Result<(), String>,
    ) -> Result<Self, String> {
        previous.validate()?;
        terminal.validate()?;
        if !previous.same_authority(terminal)
            || !matches!(terminal.outcome.as_str(), "complete" | "failed")
            || previous.outcome == "complete"
            || previous.status_sequence >= terminal.status_sequence
        {
            return Err("terminal cut reconciliation proof is invalid".into());
        }
        let guard = RawOperationLock::acquire_in(root)?;
        check()?;
        guard.reconcile_terminal(previous, terminal)
    }

    fn reconcile_from_held(
        guard: RawOperationLock,
        previous: &OperationDescriptor,
        terminal: &OperationDescriptor,
    ) -> Result<Self, String> {
        previous.validate()?;
        terminal.validate()?;
        if !previous.same_authority(terminal)
            || !matches!(terminal.outcome.as_str(), "complete" | "failed")
            || previous.outcome == "complete"
            || previous.status_sequence >= terminal.status_sequence
        {
            return Err("terminal cut reconciliation proof is invalid".to_string());
        }
        guard.verify_owner()?;
        let RawOperationLock {
            root,
            lock,
            lock_identity,
        } = guard;
        if read_descriptor(&root)?.as_ref() != Some(previous) {
            return Err("terminal cut predecessor differs from the live projection".to_string());
        }
        // The terminal document must bind the exact durable WAL, and the
        // predecessor must not: the WAL moved to its terminal phase between
        // the two publications.
        if hash_journal(&root, &terminal.journal)? != terminal.journal_sha256 {
            return Err("terminal document does not bind the live WAL".to_string());
        }
        if hash_journal(&root, &previous.journal)? == previous.journal_sha256 {
            return Err("terminal cut predecessor still binds the live WAL".to_string());
        }
        atomic_write_descriptor(&root, terminal)?;
        let lease = Self {
            root,
            lock,
            lock_identity,
            descriptor: terminal.clone(),
        };
        lease.verify_owner()?;
        Ok(lease)
    }

    /// Read the live observer projection bound to this lease's root. The
    /// returned document is the unverified canonical descriptor: recovery
    /// programs compare it against a derived expectation instead of
    /// trusting it.
    pub fn read_live_projection(&self) -> Result<Option<OperationDescriptor>, String> {
        self.verify_lock_path()?;
        read_descriptor(&self.root)
    }

    /// Publish the next observable projection of the same operation WAL.
    pub fn publish(&self, next: &OperationDescriptor) -> Result<(), String> {
        next.validate()?;
        if !next.same_authority(&self.descriptor) {
            return Err("operation projection changed authority".to_string());
        }
        self.verify_lock_path()?;
        let current = read_descriptor(&self.root)?
            .ok_or_else(|| "operation descriptor disappeared".to_string())?;
        if !current.same_authority(next) || current.outcome == "complete" {
            return Err("operation projection is no longer active".to_string());
        }
        if hash_journal(&self.root, &next.journal)? != next.journal_sha256 {
            return Err("operation projection does not bind the current WAL".to_string());
        }
        if next.status_sequence < current.status_sequence
            || next.reboot_count < current.reboot_count
        {
            return Err("operation projection moved a counter backwards".to_string());
        }
        if next.status_sequence == current.status_sequence {
            return if next == &current {
                retain_install_progress(&self.root, next)
            } else {
                Err("operation projection changed without advancing sequence".to_string())
            };
        }
        if unsafe { libc::flock(self.lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("operation lock ownership lost".to_string());
        }
        atomic_write_descriptor(&self.root, next)?;
        if read_verified_descriptor(&self.root)?.as_ref() != Some(next) {
            return Err("operation projection publication did not persist exact bytes".to_string());
        }
        Ok(())
    }

    fn verify_path_and_descriptor(&self) -> Result<(), String> {
        self.verify_lock_path()?;
        let current = read_verified_descriptor(&self.root)?
            .ok_or_else(|| "operation descriptor disappeared".to_string())?;
        if !current.same_authority(&self.descriptor) {
            return Err("operation ownership changed".to_string());
        }
        Ok(())
    }

    fn verify_lock_path(&self) -> Result<(), String> {
        require_root(&self.root)?;
        require_trusted_file(&self.lock, 0o600, "operation lock")?;
        let path_lock = open_at(
            &self.root,
            "operation.lock",
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        )
        .map_err(|error| format!("reopen operation lock: {error}"))?;
        require_trusted_file(&path_lock, 0o600, "operation lock path")?;
        let path_metadata = path_lock
            .metadata()
            .map_err(|error| format!("stat operation lock path: {error}"))?;
        if (path_metadata.dev(), path_metadata.ino()) != self.lock_identity {
            return Err("operation lock pathname identity changed".to_string());
        }
        Ok(())
    }

    /// Verify a successful cleanup while retaining the terminal descriptor.
    /// The caller must publish `complete` while the correlated WAL still
    /// exists, then remove only the operation-owned transient members.
    pub fn finish(&self) -> Result<(), String> {
        self.verify_owner()?;
        let current = read_verified_descriptor(&self.root)?
            .ok_or_else(|| "operation descriptor disappeared".to_string())?;
        if !current.same_authority(&self.descriptor) || current.outcome != "complete" {
            return Err("operation terminal result is not complete".to_string());
        }
        if !terminal_cleanup_complete(&self.root, &current)? {
            return Err("operation terminal cleanup is incomplete".to_string());
        }
        self.root
            .sync_all()
            .map_err(|error| format!("sync operation directory: {error}"))
    }

    /// Remove an abandoned or uninstall-owned descriptor after verified cleanup.
    pub fn clear(&self) -> Result<(), String> {
        self.verify_owner()?;
        unlink_at(&self.root, "operation.json")?;
        self.root
            .sync_all()
            .map_err(|error| format!("sync operation directory: {error}"))
    }
}

fn hash_journal(root: &File, relative: &str) -> Result<String, String> {
    let mut parts = relative.split('/');
    let (Some(recovery_name), Some(transaction_id), Some(journal_name), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("operation journal path is not exact".to_string());
    };
    if recovery_name != "recovery" || !canonical_hash(transaction_id) || journal_name.contains('/')
    {
        return Err("operation journal path is not exact".to_string());
    }
    let opened = (|| -> Result<File, std::io::Error> {
        let recovery = open_at(
            root,
            recovery_name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        )?;
        require_trusted_directory(&recovery, 0o700, "operation recovery root")
            .map_err(std::io::Error::other)?;
        let transaction = open_at(
            &recovery,
            transaction_id,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        )?;
        require_trusted_directory(&transaction, 0o700, "operation recovery transaction")
            .map_err(std::io::Error::other)?;
        open_at(
            &transaction,
            journal_name,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        )
    })();
    let mut journal = match opened {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok("0".repeat(64)),
        Err(error) => return Err(format!("read operation journal: {error}")),
    };
    require_trusted_file(&journal, 0o600, "operation journal")?;
    let before = stamp(&journal)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut journal)
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read operation journal: {error}"))?;
    if bytes.len() > 64 * 1024 || before != stamp(&journal)? {
        return Err("operation journal byte envelope or identity changed".to_string());
    }
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

/// Option-style outcome of [`terminal_cleanup_complete`] that names the exact
/// residue blocking the terminal state. Only the guard admission path logs
/// this detail; the boolean predicate alone keeps the success contract.
enum TerminalCleanup {
    Complete,
    Residue(String),
}

impl TerminalCleanup {
    fn is_complete(&self) -> bool {
        matches!(self, TerminalCleanup::Complete)
    }

    fn detail(&self) -> String {
        match self {
            TerminalCleanup::Complete => "cleanup is complete".to_string(),
            TerminalCleanup::Residue(member) => member.clone(),
        }
    }
}

fn terminal_cleanup_complete(
    root: &File,
    descriptor: &OperationDescriptor,
) -> Result<bool, String> {
    Ok(terminal_cleanup_detail(root, descriptor)?.is_complete())
}

fn terminal_cleanup_detail(
    root: &File,
    descriptor: &OperationDescriptor,
) -> Result<TerminalCleanup, String> {
    for parent_name in ["install", "recovery"] {
        let parent = match open_at(
            root,
            parent_name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        ) {
            Ok(parent) => parent,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("open terminal {parent_name} root: {error}")),
        };
        require_trusted_directory(&parent, 0o700, "terminal operation transaction root")?;
        match open_at(
            &parent,
            &descriptor.transaction_id,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        ) {
            Ok(transaction) => {
                require_trusted_directory(&transaction, 0o700, "terminal operation transaction")?;
                return Ok(TerminalCleanup::Residue(format!(
                    "{parent_name}/{} transaction directory remains",
                    descriptor.transaction_id
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("open terminal operation transaction: {error}")),
        }
        if parent_name == "recovery" {
            match open_at(
                &parent,
                "install-terminal.json",
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0,
            ) {
                Ok(_) => {
                    return Ok(TerminalCleanup::Residue(
                        "recovery/install-terminal.json remains".to_string(),
                    ))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("open install terminal intent: {error}")),
            }
        }
    }
    Ok(TerminalCleanup::Complete)
}

/// Read and validate the active operation pointer without creating or changing
/// any member. Recovery programs use this before consulting fresh inputs.
pub fn read_active_in(root: &Path) -> Result<Option<OperationDescriptor>, String> {
    let root = open_root(root)?;
    Ok(read_verified_descriptor(&root)?.filter(|descriptor| descriptor.outcome != "complete"))
}

/// Read the active or last completed operation for an observer.
pub fn read_current_in(root: &Path) -> Result<Option<OperationDescriptor>, String> {
    let root = open_root(root)?;
    read_verified_descriptor(&root)
}

/// A consistent observer snapshot, or contention with a retained operation writer.
pub enum CurrentOperationObservation {
    Busy,
    Snapshot(Box<CurrentOperationSnapshot>),
}

pub struct CurrentOperationSnapshot {
    root: File,
    lock: Option<File>,
    descriptor: Option<OperationDescriptor>,
}

impl CurrentOperationSnapshot {
    pub fn descriptor(&self) -> Option<&OperationDescriptor> {
        self.descriptor.as_ref()
    }

    pub fn verify_owner(&self) -> Result<(), String> {
        require_root(&self.root)?;
        if let Some(lock) = &self.lock {
            require_trusted_file(lock, 0o600, "operation observer lock")?;
            let named = open_at(
                &self.root,
                "operation.lock",
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0,
            )
            .map_err(|error| format!("reopen operation observer lock: {error}"))?;
            require_trusted_file(&named, 0o600, "operation observer lock path")?;
            let held = lock.metadata().map_err(|error| error.to_string())?;
            let observed = named.metadata().map_err(|error| error.to_string())?;
            if (held.dev(), held.ino()) != (observed.dev(), observed.ino()) {
                return Err("operation observer lock pathname identity changed".into());
            }
        }
        Ok(())
    }
}

/// Retain the existing shared operation lock through pointer/WAL verification and caller reads.
/// No lock is created. Only actual flock contention is Busy; corruption remains an error.
pub fn observe_current_in(root: &Path) -> Result<CurrentOperationObservation, String> {
    let root = open_root(root)?;
    let lock = match open_at(
        &root,
        "operation.lock",
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0,
    ) {
        Ok(lock) => Some(lock),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("open operation observer lock: {error}")),
    };
    if let Some(lock) = &lock {
        require_trusted_file(lock, 0o600, "operation observer lock")?;
        loop {
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if error.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(CurrentOperationObservation::Busy);
            }
            return Err(format!("acquire operation observer lock: {error}"));
        }
    } else {
        if read_descriptor(&root)?.is_some() {
            return Err("operation descriptor exists without observer lock".into());
        }
        // This is an absence observation, not a retained lock. Never re-read a
        // newly published descriptor without joining its writer's lock epoch.
        return Ok(CurrentOperationObservation::Snapshot(Box::new(
            CurrentOperationSnapshot {
                root,
                lock: None,
                descriptor: None,
            },
        )));
    }
    let mut snapshot = CurrentOperationSnapshot {
        root,
        lock,
        descriptor: None,
    };
    snapshot.verify_owner()?;
    snapshot.descriptor = read_verified_descriptor(&snapshot.root)?;
    snapshot.verify_owner()?;
    Ok(CurrentOperationObservation::Snapshot(Box::new(snapshot)))
}

/// Read only the canonical authority/projection document. Recovery code may
/// use this to locate its WAL after a crash between the WAL rename and status
/// replacement, but it must reconcile the exact WAL under `OperationLease`
/// before continuing any mutation.
pub fn read_document_in(root: &Path) -> Result<Option<OperationDescriptor>, String> {
    let root = open_root(root)?;
    read_descriptor(&root)
}

fn expected_owner() -> (u32, u32) {
    #[cfg(target_os = "android")]
    {
        (0, 0)
    }
    #[cfg(not(target_os = "android"))]
    {
        unsafe { (libc::geteuid(), libc::getegid()) }
    }
}

fn stamp(file: &File) -> Result<(u64, u64, u64, i64, i64), String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("stat trusted file: {error}"))?;
    Ok((
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    ))
}

fn require_trusted_file(file: &File, mode: u32, what: &str) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("stat {what}: {error}"))?;
    let (uid, gid) = expected_owner();
    if !trusted_file_identity(
        metadata.file_type().is_file(),
        metadata.nlink(),
        metadata.uid(),
        metadata.gid(),
        metadata.permissions().mode() & 0o7777,
        uid,
        gid,
        mode,
    ) {
        return Err(format!("{what} has a foreign identity"));
    }
    Ok(())
}

fn require_trusted_directory(directory: &File, mode: u32, what: &str) -> Result<(), String> {
    let metadata = directory
        .metadata()
        .map_err(|error| format!("stat {what}: {error}"))?;
    let (uid, gid) = expected_owner();
    if !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.permissions().mode() & 0o7777 != mode
    {
        return Err(format!("{what} has a foreign identity"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn trusted_file_identity(
    regular: bool,
    nlink: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
) -> bool {
    regular && nlink == 1 && uid == expected_uid && gid == expected_gid && mode == expected_mode
}

fn c_name(name: &str) -> Result<CString, String> {
    CString::new(name).map_err(|_| "operation leaf contains NUL".to_string())
}

fn open_at(root: &File, name: &str, flags: i32, mode: u32) -> Result<File, std::io::Error> {
    let name = CString::new(name).expect("fixed leaf");
    let fd = unsafe { libc::openat(root.as_raw_fd(), name.as_ptr(), flags, mode) };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn open_root(path: &Path) -> Result<File, String> {
    let bytes = path.as_os_str().as_encoded_bytes();
    let path = CString::new(bytes).map_err(|_| "operation root contains NUL".to_string())?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(format!(
            "open operation root: {}",
            std::io::Error::last_os_error()
        ));
    }
    let root = unsafe { File::from_raw_fd(fd) };
    require_root(&root)?;
    Ok(root)
}

fn require_root(root: &File) -> Result<(), String> {
    let metadata = root
        .metadata()
        .map_err(|error| format!("stat operation root: {error}"))?;
    let (uid, gid) = expected_owner();
    if !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.permissions().mode() & 0o7777 != 0o755
    {
        return Err("operation root has a foreign identity".to_string());
    }
    Ok(())
}

fn open_or_create_at(root: &File, name: &str, mode: u32) -> Result<File, String> {
    match open_at(
        root,
        name,
        libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0,
    ) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => open_at(
            root,
            name,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode,
        )
        .map_err(|error| format!("create {name}: {error}")),
        Err(error) => Err(format!("open {name}: {error}")),
    }
}

fn read_descriptor(root: &File) -> Result<Option<OperationDescriptor>, String> {
    let mut file = match open_at(
        root,
        "operation.json",
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0,
    ) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("open operation descriptor: {error}")),
    };
    require_trusted_file(&file, 0o600, "operation descriptor")?;
    let before = stamp(&file)?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take((MAX_OPERATION_DESCRIPTOR_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read operation descriptor: {error}"))?;
    require_trusted_file(&file, 0o600, "operation descriptor")?;
    if before != stamp(&file)? {
        return Err("operation descriptor changed while reading".to_string());
    }
    OperationDescriptor::parse(&bytes).map(Some)
}

fn read_verified_descriptor(root: &File) -> Result<Option<OperationDescriptor>, String> {
    let Some(document) = read_descriptor(root)? else {
        return Ok(None);
    };
    let actual_journal_sha256 = hash_journal(root, &document.journal)?;
    if actual_journal_sha256 != document.journal_sha256
        && !(document.outcome == "complete" && actual_journal_sha256 == "0".repeat(64))
    {
        return Err(format!(
            "operation journal digest differs from operation document: {} != {}",
            actual_journal_sha256, document.journal_sha256
        ));
    }
    Ok(Some(document))
}

fn atomic_write_descriptor(root: &File, descriptor: &OperationDescriptor) -> Result<(), String> {
    // A crash may leave the exclusively-created temporary behind before the
    // rename.  Reconcile it through the already-open root directory: an exact
    // canonical temporary is the interrupted publication we were asked to
    // resume; any other trusted temporary is stale and may be unlinked.  A
    // foreign/special/link-shaped entry remains a hard failure.
    match open_at(
        root,
        ".operation.json.tmp",
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0,
    ) {
        Ok(mut temporary) => {
            require_trusted_file(&temporary, 0o600, "operation descriptor temporary")?;
            let before = stamp(&temporary)?;
            let mut bytes = Vec::new();
            std::io::Read::by_ref(&mut temporary)
                .take((MAX_OPERATION_DESCRIPTOR_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|error| format!("read operation descriptor temporary: {error}"))?;
            require_trusted_file(&temporary, 0o600, "operation descriptor temporary")?;
            if before != stamp(&temporary)? {
                return Err("operation descriptor temporary changed while reading".to_string());
            }
            if OperationDescriptor::parse(&bytes).as_ref() == Ok(descriptor) {
                let from = c_name(".operation.json.tmp")?;
                let to = c_name("operation.json")?;
                if unsafe {
                    libc::renameat(
                        root.as_raw_fd(),
                        from.as_ptr(),
                        root.as_raw_fd(),
                        to.as_ptr(),
                    )
                } != 0
                {
                    return Err(format!(
                        "publish recovered operation descriptor: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                root.sync_all()
                    .map_err(|error| format!("sync operation directory: {error}"))?;
                return retain_install_progress(root, descriptor);
            }
            unlink_at(root, ".operation.json.tmp")?;
            root.sync_all()
                .map_err(|error| format!("sync removed stale operation temporary: {error}"))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("open operation descriptor temporary: {error}")),
    }
    let mut file = open_at(
        root,
        ".operation.json.tmp",
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0o600,
    )
    .map_err(|error| format!("create operation descriptor temporary: {error}"))?;
    require_trusted_file(&file, 0o600, "operation descriptor temporary")?;
    file.write_all(&descriptor.canonical_bytes()?)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("write operation descriptor temporary: {error}"))?;
    require_trusted_file(&file, 0o600, "operation descriptor temporary")?;
    let from = c_name(".operation.json.tmp")?;
    let to = c_name("operation.json")?;
    if unsafe {
        libc::renameat(
            root.as_raw_fd(),
            from.as_ptr(),
            root.as_raw_fd(),
            to.as_ptr(),
        )
    } != 0
    {
        return Err(format!(
            "publish operation descriptor: {}",
            std::io::Error::last_os_error()
        ));
    }
    root.sync_all()
        .map_err(|error| format!("sync operation directory: {error}"))?;
    retain_install_progress(root, descriptor)
}

/// Diagnostic publications survive boot and terminal WAL cleanup. They never
/// authorize execution: the canonical projection and WAL still own that.
fn retain_install_progress(root: &File, descriptor: &OperationDescriptor) -> Result<(), String> {
    if descriptor.operation != Operation::Install {
        return Ok(());
    }
    let name = c_name("logs")?;
    if unsafe { libc::mkdirat(root.as_raw_fd(), name.as_ptr(), 0o700) } != 0
        && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err("cannot create install progress directory".into());
    }
    let logs = open_at(
        root,
        "logs",
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0,
    )
    .map_err(|error| format!("open install progress directory: {error}"))?;
    require_trusted_directory(&logs, 0o700, "install progress directory")?;
    let mut file = open_at(
        &logs,
        "install-progress.jsonl",
        libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0o600,
    )
    .map_err(|error| format!("open install progress: {error}"))?;
    require_trusted_file(&file, 0o600, "install progress")?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 65536 {
        return Err("install progress byte bound exceeded".into());
    }
    // Repair only an interrupted trailing append; all complete records remain.
    let complete = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1);
    bytes.truncate(complete);
    if let Some(first) = bytes
        .split(|byte| *byte == b'\n')
        .next()
        .filter(|line| !line.is_empty())
    {
        let value: Value = serde_json::from_slice(first)
            .map_err(|error| format!("parse install progress: {error}"))?;
        if value["transactionId"].as_str() != Some(&descriptor.transaction_id) {
            bytes.clear();
        }
    }
    let message = descriptor
        .error
        .as_ref()
        .and_then(|value| value["message"].as_str())
        .map(|message| {
            message
                .chars()
                .filter(|c| !c.is_control())
                .take(384)
                .collect::<String>()
        });
    let mut next = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 1, "transactionId": descriptor.transaction_id,
        "phase": descriptor.phase, "outcome": descriptor.outcome,
        "rebootCount": descriptor.reboot_count, "bootId": descriptor.boot_id,
        "statusSequence": descriptor.status_sequence, "message": message
    }))
    .map_err(|error| error.to_string())?;
    next.push(b'\n');
    let duplicate = bytes.ends_with(&next);
    file.set_len(bytes.len() as u64)
        .map_err(|error| error.to_string())?;
    file.seek(SeekFrom::End(0))
        .map_err(|error| error.to_string())?;
    if !duplicate {
        if bytes.len() + next.len() > 65536 {
            return Err("install progress byte bound exceeded".into());
        }
        file.write_all(&next)
            .map_err(|error| format!("write install progress: {error}"))?;
    }
    file.sync_all()
        .and_then(|()| logs.sync_all())
        .and_then(|()| root.sync_all())
        .map_err(|error| format!("sync install progress: {error}"))
}

fn unlink_at(root: &File, name: &str) -> Result<(), String> {
    let name = c_name(name)?;
    if unsafe { libc::unlinkat(root.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(format!(
            "remove operation descriptor: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn canonical_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn canonical_boot_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

pub fn current_boot_id() -> Result<String, String> {
    let value = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| format!("read boot ID: {error}"))?;
    let value = value
        .strip_suffix('\n')
        .ok_or_else(|| "boot ID lacks final newline".to_string())?;
    if !canonical_boot_id(value) {
        return Err("boot ID is invalid".to_string());
    }
    Ok(value.to_string())
}

fn valid_error(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.len() == 2
        && object
            .get("code")
            .and_then(Value::as_str)
            .is_some_and(|v| !v.is_empty())
        && object
            .get("message")
            .and_then(Value::as_str)
            .is_some_and(|v| !v.is_empty() && v.len() <= 512)
}

fn valid_installed_apk(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    let path = object.get("path").and_then(Value::as_str).unwrap_or("");
    object.len() == 6
        && object.get("packageName").and_then(Value::as_str) == Some("ru.voboost")
        && object
            .get("versionCode")
            .and_then(Value::as_u64)
            .is_some_and(|v| v > 0)
        && object
            .get("certificateSha256")
            .and_then(Value::as_str)
            .is_some_and(canonical_hash)
        && path.starts_with("/data/app/")
        && path.ends_with("/base.apk")
        && path.len() <= 512
        && path
            .split('/')
            .skip(1)
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && object
            .get("size")
            .and_then(Value::as_u64)
            .is_some_and(|v| v > 0)
        && object
            .get("sha256")
            .and_then(Value::as_str)
            .is_some_and(canonical_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        root
    }

    fn descriptor(operation: Operation) -> OperationDescriptor {
        let transaction_id = "11".repeat(32);
        OperationDescriptor::new(
            operation,
            transaction_id.clone(),
            format!(
                "recovery/{transaction_id}/{}-journal.json",
                operation.as_str()
            ),
            "00000000-0000-0000-0000-000000000001".to_string(),
        )
        .unwrap()
    }

    #[test]
    fn raw_lock_promotes_prepared_wal_without_unlocking() {
        let root = root();
        let requested = descriptor(Operation::Update);
        let guard = RawOperationLock::acquire_in(root.path()).unwrap();
        let other = root.path().to_path_buf();
        assert!(
            std::thread::spawn(move || RawOperationLock::acquire_in(&other).is_err())
                .join()
                .unwrap()
        );
        let transaction = root.path().join("recovery").join(&requested.transaction_id);
        std::fs::create_dir_all(&transaction).unwrap();
        std::fs::set_permissions(
            transaction.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::set_permissions(&transaction, std::fs::Permissions::from_mode(0o700)).unwrap();
        let journal = root.path().join(&requested.journal);
        std::fs::write(&journal, b"prepared WAL\n").unwrap();
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
        let lease = guard.admit(requested.clone()).unwrap();
        lease.verify_owner().unwrap();
        let other = root.path().to_path_buf();
        assert!(
            std::thread::spawn(move || RawOperationLock::acquire_in(&other).is_err())
                .join()
                .unwrap()
        );
        drop(lease);
        let guard = RawOperationLock::acquire_in(root.path()).unwrap();
        guard.admit(requested).unwrap().verify_owner().unwrap();
    }

    #[test]
    fn checked_lease_holds_lock_and_rejects_before_descriptor_publication() {
        let root = root();
        let requested = descriptor(Operation::Update);
        let result = OperationLease::acquire_in_checked(root.path(), requested, || {
            assert!(GenerationGuard::acquire_in(root.path()).is_err());
            Err("fence rejected".into())
        });
        assert!(matches!(result, Err(ref e) if e == "fence rejected"));
        assert!(!root.path().join("operation.json").exists());
        assert!(GenerationGuard::acquire_in(root.path()).is_ok());
    }

    #[test]
    fn guarded_admission_distinguishes_known_rejection_from_unreadable_outcome() {
        for unknown in [false, true] {
            let root = root();
            let requested = descriptor(Operation::Restore);
            let transaction = root.path().join("recovery").join(&requested.transaction_id);
            std::fs::create_dir_all(&transaction).unwrap();
            std::fs::set_permissions(
                transaction.parent().unwrap(),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            std::fs::set_permissions(&transaction, std::fs::Permissions::from_mode(0o700)).unwrap();
            let journal = root.path().join(&requested.journal);
            std::fs::write(&journal, b"authenticated WAL\n").unwrap();
            std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
            let guard = GenerationGuard::acquire_in(root.path()).unwrap();
            let mut possibly_admitted = true;
            let result = guard.admit_operation_with(
                requested,
                |_, _| {
                    if unknown {
                        let path = root.path().join("operation.json");
                        std::fs::write(&path, b"unreadable publication").unwrap();
                        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                            .unwrap();
                    }
                    Err("injected publication failure".into())
                },
                &mut possibly_admitted,
            );
            assert!(result.is_err());
            assert_eq!(possibly_admitted, unknown);
            assert_eq!(std::fs::read(&journal).unwrap(), b"authenticated WAL\n");
            if !unknown {
                assert!(read_current_in(root.path()).unwrap().is_none());
                assert!(GenerationGuard::acquire_in(root.path()).is_ok());
            }
        }
    }

    #[test]
    fn guarded_admission_post_publication_error_retains_real_authority() {
        let root = root();
        let requested = descriptor(Operation::Restore);
        let transaction = root.path().join("recovery").join(&requested.transaction_id);
        std::fs::create_dir_all(&transaction).unwrap();
        std::fs::set_permissions(
            transaction.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::set_permissions(&transaction, std::fs::Permissions::from_mode(0o700)).unwrap();
        let journal = root.path().join(&requested.journal);
        std::fs::write(&journal, b"authenticated WAL\n").unwrap();
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
        let guard = GenerationGuard::acquire_in(root.path()).unwrap();
        let mut possibly_admitted = false;
        let result = guard.admit_operation_with(
            requested.clone(),
            |root, descriptor| {
                atomic_write_descriptor(root, descriptor)?;
                Err("injected directory sync failure after descriptor rename".into())
            },
            &mut possibly_admitted,
        );
        assert!(possibly_admitted);
        assert!(result.is_err());
        let current = read_current_in(root.path()).unwrap().unwrap();
        assert!(current.same_authority(&requested));
        assert!(GenerationGuard::acquire_in(root.path()).is_err());
        assert_eq!(std::fs::read(&journal).unwrap(), b"authenticated WAL\n");
    }

    #[test]
    fn serialized_observation_reports_busy_during_wal_pointer_cut_and_rejects_stable_corruption() {
        let temporary = root();
        let requested = descriptor(Operation::Install);
        let transaction = temporary
            .path()
            .join("recovery")
            .join(&requested.transaction_id);
        std::fs::create_dir_all(&transaction).unwrap();
        std::fs::set_permissions(
            transaction.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::set_permissions(&transaction, std::fs::Permissions::from_mode(0o700)).unwrap();
        let journal = temporary.path().join(&requested.journal);
        std::fs::write(&journal, b"old WAL\n").unwrap();
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
        let lease = OperationLease::acquire_in(temporary.path(), requested).unwrap();
        let old = read_current_in(temporary.path()).unwrap().unwrap();
        let (cut_tx, cut_rx) = std::sync::mpsc::channel();
        let (publish_tx, publish_rx) = std::sync::mpsc::channel();
        let writer_journal = journal.clone();
        let writer = std::thread::spawn(move || {
            let temp = writer_journal.with_extension("tmp");
            let mut file = File::create(&temp).unwrap();
            std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600)).unwrap();
            file.write_all(b"new WAL\n").unwrap();
            file.sync_all().unwrap();
            std::fs::rename(&temp, &writer_journal).unwrap();
            File::open(writer_journal.parent().unwrap())
                .unwrap()
                .sync_all()
                .unwrap();
            cut_tx.send(()).unwrap();
            publish_rx.recv().unwrap();
            let mut next = old;
            next.phase = "install-agents".into();
            next.reboot_count = 1;
            next.status_sequence += 1;
            next.journal_sha256 = format!("{:x}", Sha256::digest(b"new WAL\n"));
            lease.publish(&next).unwrap();
            next
        });
        cut_rx.recv().unwrap();
        assert!(
            read_current_in(temporary.path())
                .unwrap_err()
                .contains("journal digest differs"),
            "the old reader reproduces the torn publication"
        );
        assert!(matches!(
            observe_current_in(temporary.path()).unwrap(),
            CurrentOperationObservation::Busy
        ));
        publish_tx.send(()).unwrap();
        let expected = writer.join().unwrap();
        let observed = observe_current_in(temporary.path()).unwrap();
        let CurrentOperationObservation::Snapshot(snapshot) = observed else {
            panic!("writer ended");
        };
        assert_eq!(snapshot.descriptor(), Some(&expected));
        drop(snapshot);
        std::fs::write(&journal, b"stable corruption\n").unwrap();
        assert!(observe_current_in(temporary.path())
            .err()
            .unwrap()
            .contains("journal digest differs"));
    }

    #[test]
    fn serialized_observation_preserves_lock_identity_and_absence_boundaries() {
        let temporary = root();
        let CurrentOperationObservation::Snapshot(empty) =
            observe_current_in(temporary.path()).unwrap()
        else {
            panic!("empty root");
        };
        assert!(empty.descriptor().is_none());
        assert!(!temporary.path().join("operation.lock").exists());
        let lease =
            OperationLease::acquire_in(temporary.path(), descriptor(Operation::Install)).unwrap();
        assert!(
            empty.descriptor().is_none(),
            "the lockless snapshot never observes a later publication"
        );
        drop(empty);
        drop(lease);
        let CurrentOperationObservation::Snapshot(snapshot) =
            observe_current_in(temporary.path()).unwrap()
        else {
            panic!("not busy");
        };
        std::fs::rename(
            temporary.path().join("operation.lock"),
            temporary.path().join("old.lock"),
        )
        .unwrap();
        let replacement = File::create(temporary.path().join("operation.lock")).unwrap();
        std::fs::set_permissions(
            temporary.path().join("operation.lock"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(snapshot.verify_owner().is_err());
        drop(snapshot);
        drop(replacement);
        std::fs::set_permissions(
            temporary.path().join("operation.lock"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(observe_current_in(temporary.path()).is_err());
        std::fs::remove_file(temporary.path().join("operation.lock")).unwrap();
        std::os::unix::fs::symlink(
            temporary.path().join("old.lock"),
            temporary.path().join("operation.lock"),
        )
        .unwrap();
        assert!(observe_current_in(temporary.path()).is_err());
        std::fs::remove_file(temporary.path().join("operation.lock")).unwrap();
        assert!(
            observe_current_in(temporary.path()).is_err(),
            "descriptor without lock is corrupt, not an unlocked snapshot"
        );
    }

    #[test]
    fn install_progress_survives_boots_replays_once_and_repairs_partial_append() {
        let temporary = root();
        let directory = open_root(temporary.path()).unwrap();
        let mut report = descriptor(Operation::Install);
        retain_install_progress(&directory, &report).unwrap();
        retain_install_progress(&directory, &report).unwrap();
        let path = temporary.path().join("logs/install-progress.jsonl");
        let first = std::fs::read(&path).unwrap();
        assert_eq!(first.iter().filter(|byte| **byte == b'\n').count(), 1);
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .append(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .unwrap()
            .write_all(b"{\"partial\"")
            .unwrap();
        report.phase = "install-agents".into();
        report.status_sequence = 19;
        report.reboot_count = 1;
        report.boot_id = "00000000-0000-0000-0000-000000000002".into();
        retain_install_progress(&directory, &report).unwrap();
        drop(directory);
        let directory = open_root(temporary.path()).unwrap();
        report.phase = "install-complete".into();
        report.outcome = "complete".into();
        report.status_sequence = 36;
        report.reboot_count = 2;
        report.boot_id = "00000000-0000-0000-0000-000000000003".into();
        retain_install_progress(&directory, &report).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let events: Vec<Value> = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        assert_eq!(
            events
                .iter()
                .map(|event| event["phase"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["install-prepare", "install-agents", "install-complete"]
        );
        report.transaction_id = "22".repeat(32);
        retain_install_progress(&directory, &report).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 1);
        assert!(!String::from_utf8(bytes).unwrap().contains(&"11".repeat(32)));
    }

    #[test]
    fn install_progress_rejects_linked_file_and_directory_without_overwriting() {
        let temporary = root();
        let directory = open_root(temporary.path()).unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), temporary.path().join("logs")).unwrap();
        assert!(retain_install_progress(&directory, &descriptor(Operation::Install)).is_err());
        assert!(!outside.path().join("install-progress.jsonl").exists());
        std::fs::remove_file(temporary.path().join("logs")).unwrap();
        retain_install_progress(&directory, &descriptor(Operation::Install)).unwrap();
        let log = temporary.path().join("logs/install-progress.jsonl");
        std::fs::remove_file(&log).unwrap();
        let target = outside.path().join("target");
        std::fs::write(&target, b"retain me").unwrap();
        std::os::unix::fs::symlink(&target, &log).unwrap();
        assert!(retain_install_progress(&directory, &descriptor(Operation::Install)).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"retain me");
    }

    #[test]
    fn schema_one_is_canonical_strict() {
        let value = descriptor(Operation::Install);
        let bytes = value.canonical_bytes().unwrap();
        assert_eq!(OperationDescriptor::parse(&bytes).unwrap(), value);
        // Non-canonical key order is rejected.
        let reordered = String::from_utf8(bytes.clone())
            .unwrap()
            .replace("{\"schemaVersion\":1,\"operation\"", "{\"operation\"")
            .replace(
                "\"install\",\"transactionId\"",
                "\"install\",\"schemaVersion\":1,\"transactionId\"",
            );
        assert!(OperationDescriptor::parse(reordered.as_bytes()).is_err());
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            OperationDescriptor::parse(text.replace("\"statusSequence\":1,", "").as_bytes())
                .is_err()
        );
        assert!(OperationDescriptor::parse(
            text.replace(&"0".repeat(64), &"A".repeat(64)).as_bytes()
        )
        .is_err());
    }

    #[test]
    fn operation_contract_consumes_the_product_wire_golden_bytes() {
        let bytes = include_bytes!("../test/fixtures/wire/operation-install-complete.json");
        let descriptor = OperationDescriptor::parse(bytes).unwrap();
        assert_eq!(descriptor.operation, Operation::Install);
        assert_eq!(descriptor.transaction_id, "55".repeat(32));
        assert_eq!(descriptor.status_sequence, 36);
        assert_eq!(descriptor.canonical_bytes().unwrap(), bytes);
    }

    #[test]
    fn unknown_field_is_rejected() {
        let raw = descriptor(Operation::Install).canonical_bytes().unwrap();
        // Insert an unknown field.
        let s = String::from_utf8(raw.clone()).unwrap();
        let injected = s.replace('\n', ",\"extra\":1\n");
        assert!(OperationDescriptor::parse(injected.as_bytes()).is_err());
    }

    #[test]
    fn four_operations_round_trip() {
        for op in [
            Operation::Install,
            Operation::Update,
            Operation::Restore,
            Operation::Uninstall,
        ] {
            let d = descriptor(op);
            let bytes = d.canonical_bytes().unwrap();
            assert_eq!(OperationDescriptor::parse(&bytes).unwrap(), d);
        }
    }

    #[test]
    fn authorizes_only_matching_operation_and_transaction() {
        let d = descriptor(Operation::Install);
        assert!(d.authorizes(Operation::Install, &"11".repeat(32)));
        assert!(!d.authorizes(Operation::Update, &"11".repeat(32)));
        assert!(!d.authorizes(Operation::Install, &"22".repeat(32)));
    }

    #[test]
    fn journal_must_start_with_recovery() {
        let bad = OperationDescriptor::new(
            Operation::Install,
            "11".repeat(32),
            "install/abc/journal.json".to_string(),
            "00000000-0000-0000-0000-000000000001".to_string(),
        );
        assert!(bad.is_err());
    }

    #[test]
    fn journal_is_bound_to_operation_and_transaction() {
        let transaction_id = "11".repeat(32);
        assert!(OperationDescriptor::new(
            Operation::Install,
            transaction_id.clone(),
            format!("recovery/{transaction_id}/restore-journal.json"),
            "00000000-0000-0000-0000-000000000001".to_string(),
        )
        .is_err());
    }

    #[test]
    fn descriptor_admitted_product_update_reuses_its_single_proposal_wal() {
        let transaction_id = "11".repeat(32);
        assert!(OperationDescriptor::new(
            Operation::Update,
            transaction_id.clone(),
            format!("recovery/{transaction_id}/product-proposal.json"),
            "00000000-0000-0000-0000-000000000001".to_string(),
        )
        .is_ok());
        assert!(OperationDescriptor::new(
            Operation::Install,
            transaction_id.clone(),
            format!("recovery/{transaction_id}/product-proposal.json"),
            "00000000-0000-0000-0000-000000000001".to_string(),
        )
        .is_err());
        assert!(OperationDescriptor::new(
            Operation::Update,
            transaction_id.clone(),
            format!("recovery/{transaction_id}/another.json"),
            "00000000-0000-0000-0000-000000000001".to_string(),
        )
        .is_err());
    }

    #[test]
    fn lease_is_recovery_first_and_busy_for_another_operation() {
        let temporary = root();
        let first = descriptor(Operation::Restore);
        let lease = OperationLease::acquire_in(temporary.path(), first.clone()).unwrap();
        lease.verify_owner().unwrap();
        assert!(
            OperationLease::acquire_in(temporary.path(), descriptor(Operation::Update)).is_err()
        );
        let mut terminal = first;
        terminal.phase = "restore-complete".to_string();
        terminal.outcome = "complete".to_string();
        terminal.status_sequence += 1;
        atomic_write_descriptor(&lease.root, &terminal).unwrap();
        lease.finish().unwrap();
        assert_eq!(read_current_in(temporary.path()).unwrap(), Some(terminal));
        assert!(read_active_in(temporary.path()).unwrap().is_none());
        drop(lease);

        let next = descriptor(Operation::Update);
        let next_lease = OperationLease::acquire_in(temporary.path(), next.clone()).unwrap();
        next_lease.verify_owner().unwrap();
        assert_eq!(read_active_in(temporary.path()).unwrap(), Some(next));
        assert!(temporary.path().join("operation.lock").exists());
    }

    #[test]
    fn completed_operation_remains_readable_after_exact_journal_cleanup() {
        let temporary = root();
        let first = descriptor(Operation::Install);
        let lease = OperationLease::acquire_in(temporary.path(), first.clone()).unwrap();
        let mut terminal = first;
        terminal.phase = "install-complete".to_string();
        terminal.outcome = "complete".to_string();
        terminal.status_sequence += 1;
        terminal.installed_apk = Some(serde_json::json!({
            "packageName": "ru.voboost",
            "versionCode": 1,
            "certificateSha256": "33".repeat(32),
            "path": "/data/app/ru.voboost/base.apk",
            "size": 1,
            "sha256": "44".repeat(32)
        }));
        atomic_write_descriptor(&lease.root, &terminal).unwrap();

        assert_eq!(read_current_in(temporary.path()).unwrap(), Some(terminal));
        assert!(read_active_in(temporary.path()).unwrap().is_none());
    }

    #[test]
    fn generation_guard_blocks_global_operation_acquisition() {
        let temporary = root();
        let guard = GenerationGuard::acquire_in(temporary.path()).unwrap();
        guard.verify_owner().unwrap();
        assert!(
            OperationLease::acquire_in(temporary.path(), descriptor(Operation::Install))
                .err()
                .unwrap()
                .contains("busy")
        );
        assert!(!temporary.path().join("operation.json").exists());
    }

    #[test]
    fn terminal_residue_blocks_generation_and_the_next_operation() {
        let temporary = root();
        let first = descriptor(Operation::Restore);
        let lease = OperationLease::acquire_in(temporary.path(), first.clone()).unwrap();
        let mut terminal = first;
        terminal.phase = "restore-complete".to_string();
        terminal.outcome = "complete".to_string();
        terminal.status_sequence += 1;
        atomic_write_descriptor(&lease.root, &terminal).unwrap();
        drop(lease);

        let recovery = temporary.path().join("recovery");
        let transaction = recovery.join(&terminal.transaction_id);
        std::fs::create_dir(&recovery).unwrap();
        std::fs::create_dir(&transaction).unwrap();
        std::fs::set_permissions(&recovery, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&transaction, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(GenerationGuard::acquire_in(temporary.path()).is_err());
        assert!(
            OperationLease::acquire_in(temporary.path(), descriptor(Operation::Update)).is_err()
        );
        std::fs::remove_dir(&transaction).unwrap();
        std::fs::remove_dir(&recovery).unwrap();
        assert!(GenerationGuard::acquire_in(temporary.path()).is_ok());
    }

    #[test]
    fn global_operation_lease_blocks_generation_guard_acquisition() {
        let temporary = root();
        let lease =
            OperationLease::acquire_in(temporary.path(), descriptor(Operation::Restore)).unwrap();
        lease.verify_owner().unwrap();
        assert!(GenerationGuard::acquire_in(temporary.path())
            .err()
            .unwrap()
            .contains("busy"));
    }

    #[test]
    fn install_generation_guard_blocks_competing_leases_and_descriptor_changes() {
        let temporary = root();
        let install = descriptor(Operation::Install);
        let lease = OperationLease::acquire_in(temporary.path(), install).unwrap();
        lease.release_for_install_generation().unwrap();

        let guard = GenerationGuard::acquire_install_generation_in(temporary.path()).unwrap();
        guard.verify_owner().unwrap();
        assert!(
            OperationLease::acquire_in(temporary.path(), descriptor(Operation::Update))
                .err()
                .unwrap()
                .contains("busy")
        );

        std::fs::write(
            temporary.path().join("operation.json"),
            OperationDescriptor::new(
                Operation::Install,
                "22".repeat(32),
                format!("recovery/{}/install-journal.json", "22".repeat(32)),
                "00000000-0000-0000-0000-000000000001".to_string(),
            )
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            guard.verify_owner().unwrap_err(),
            "operation descriptor changed during generation mutation"
        );
    }

    #[test]
    fn lease_revalidation_detects_descriptor_toctou() {
        let temporary = root();
        let lease =
            OperationLease::acquire_in(temporary.path(), descriptor(Operation::Install)).unwrap();
        std::fs::write(
            temporary.path().join("operation.json"),
            descriptor(Operation::Update).canonical_bytes().unwrap(),
        )
        .unwrap();
        assert!(lease.verify_owner().is_err());
    }

    #[test]
    fn lease_revalidation_detects_lock_path_replacement() {
        let temporary = root();
        let lease =
            OperationLease::acquire_in(temporary.path(), descriptor(Operation::Install)).unwrap();
        std::fs::rename(
            temporary.path().join("operation.lock"),
            temporary.path().join("operation.lock.displaced"),
        )
        .unwrap();
        std::fs::write(temporary.path().join("operation.lock"), b"").unwrap();
        std::fs::set_permissions(
            temporary.path().join("operation.lock"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert_eq!(
            lease.verify_owner().unwrap_err(),
            "operation lock pathname identity changed"
        );
    }

    #[test]
    fn dropped_lease_preserves_crash_recovery_authority() {
        let temporary = root();
        let requested = descriptor(Operation::Restore);
        let lease = OperationLease::acquire_in(temporary.path(), requested.clone()).unwrap();
        drop(lease);
        assert!(temporary.path().join("operation.json").exists());
        let resumed = OperationLease::acquire_in(temporary.path(), requested).unwrap();
        resumed.verify_owner().unwrap();
    }

    #[test]
    fn terminal_cut_reconciles_only_the_exact_predecessor_to_the_terminal_document() {
        let temporary = root();
        let transaction_id = "11".repeat(32);
        let recovery = temporary.path().join("recovery");
        let transaction = recovery.join(&transaction_id);
        std::fs::create_dir(&recovery).unwrap();
        std::fs::create_dir(&transaction).unwrap();
        std::fs::set_permissions(&recovery, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&transaction, std::fs::Permissions::from_mode(0o700)).unwrap();
        let journal = transaction.join("restore-journal.json");
        std::fs::write(&journal, b"pre-terminal\n").unwrap();
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();

        // The predecessor publication bound the pre-terminal WAL.
        let requested = descriptor(Operation::Restore);
        let lease = OperationLease::acquire_in(temporary.path(), requested).unwrap();
        let predecessor = read_current_in(temporary.path()).unwrap().unwrap();
        drop(lease);

        // The terminal WAL write happened; the projection publish did not.
        std::fs::write(&journal, b"terminal\n").unwrap();
        let mut document = predecessor.clone();
        document.phase = "restore-complete".to_string();
        document.outcome = "complete".to_string();
        document.status_sequence = predecessor.status_sequence + 1;
        document.journal_sha256 = format!("{:x}", Sha256::digest(b"terminal\n"));

        // The generic acquire rejects the terminal projection over the stale
        // predecessor: the WAL moved past the published one.
        assert!(OperationLease::acquire_in(temporary.path(), document.clone()).is_err());

        let blocked = OperationLease::reconcile_terminal_cut_in_checked(
            temporary.path(),
            &predecessor,
            &document,
            || {
                assert!(GenerationGuard::acquire_in(temporary.path()).is_err());
                Err("fence rejected".into())
            },
        );
        assert!(matches!(blocked, Err(ref e) if e == "fence rejected"));
        assert_eq!(
            read_document_in(temporary.path()).unwrap(),
            Some(predecessor.clone())
        );

        // The narrow R24 reconcile replaces exactly the predecessor with the
        // terminal document and hands back a verified lease.
        let lease =
            OperationLease::reconcile_terminal_cut_in(temporary.path(), &predecessor, &document)
                .unwrap();
        lease.verify_owner().unwrap();
        assert_eq!(
            read_current_in(temporary.path()).unwrap(),
            Some(document.clone())
        );
        drop(lease);

        // Replaying the reconcile after the terminal document is live fails:
        // the predecessor is no longer the live projection.
        assert!(OperationLease::reconcile_terminal_cut_in(
            temporary.path(),
            &predecessor,
            &document
        )
        .is_err());
    }

    #[test]
    fn terminal_cut_reconcile_rejects_forgeries() {
        let temporary = root();
        let transaction_id = "11".repeat(32);
        let recovery = temporary.path().join("recovery");
        let transaction = recovery.join(&transaction_id);
        std::fs::create_dir(&recovery).unwrap();
        std::fs::create_dir(&transaction).unwrap();
        std::fs::set_permissions(&recovery, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&transaction, std::fs::Permissions::from_mode(0o700)).unwrap();
        let journal = transaction.join("restore-journal.json");
        std::fs::write(&journal, b"pre-terminal\n").unwrap();
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();

        let lease =
            OperationLease::acquire_in(temporary.path(), descriptor(Operation::Restore)).unwrap();
        let predecessor = read_current_in(temporary.path()).unwrap().unwrap();
        drop(lease);

        std::fs::write(&journal, b"terminal\n").unwrap();
        let mut terminal = predecessor.clone();
        terminal.phase = "restore-complete".to_string();
        terminal.outcome = "complete".to_string();
        terminal.status_sequence = predecessor.status_sequence + 1;
        terminal.journal_sha256 = format!("{:x}", Sha256::digest(b"terminal\n"));

        // A predecessor that does not bind the pre-terminal WAL cannot be
        // proven: reconstructing it from the live WAL binds the terminal
        // bytes, so the reconcile must reject it.
        let mut forged_previous = predecessor.clone();
        forged_previous.journal_sha256 = format!("{:x}", Sha256::digest(b"terminal\n"));
        forged_previous.phase = "restore-cleanup".to_string();
        assert!(OperationLease::reconcile_terminal_cut_in(
            temporary.path(),
            &forged_previous,
            &terminal
        )
        .is_err());

        // A terminal document that does not bind the live WAL is rejected.
        let mut foreign_terminal = terminal.clone();
        foreign_terminal.journal_sha256 = format!("{:x}", Sha256::digest(b"foreign\n"));
        assert!(OperationLease::reconcile_terminal_cut_in(
            temporary.path(),
            &predecessor,
            &foreign_terminal
        )
        .is_err());

        // A nonterminal successor never satisfies the reconcile.
        let mut nonterminal = terminal.clone();
        nonterminal.outcome = "running".to_string();
        assert!(OperationLease::reconcile_terminal_cut_in(
            temporary.path(),
            &predecessor,
            &nonterminal
        )
        .is_err());

        // The live projection survived untouched (the verified read still
        // reports the stale digest, so this asserts on the raw document).
        assert_eq!(
            read_document_in(temporary.path()).unwrap(),
            Some(predecessor)
        );
    }

    #[test]
    fn stale_projection_reconciles_only_to_the_current_monotonic_wal() {
        let temporary = root();
        let transaction_id = "11".repeat(32);
        let recovery = temporary.path().join("recovery");
        let transaction = recovery.join(&transaction_id);
        std::fs::create_dir(&recovery).unwrap();
        std::fs::create_dir(&transaction).unwrap();
        std::fs::set_permissions(&recovery, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&transaction, std::fs::Permissions::from_mode(0o700)).unwrap();
        let journal = transaction.join("restore-journal.json");
        std::fs::write(&journal, b"first\n").unwrap();
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();

        let requested = descriptor(Operation::Restore);
        let lease = OperationLease::acquire_in(temporary.path(), requested).unwrap();
        let current = read_current_in(temporary.path()).unwrap().unwrap();
        drop(lease);

        std::fs::write(&journal, b"second\n").unwrap();
        let mut recovered = current.clone();
        recovered.phase = "restore-policy-backup".to_string();
        recovered.status_sequence += 1;
        recovered.journal_sha256 = format!("{:x}", Sha256::digest(b"second\n"));
        let resumed = OperationLease::acquire_in(temporary.path(), recovered.clone()).unwrap();
        resumed.verify_owner().unwrap();
        assert_eq!(
            read_current_in(temporary.path()).unwrap(),
            Some(recovered.clone())
        );

        drop(resumed);
        let mut rewind = current;
        rewind.journal_sha256 = format!("{:x}", Sha256::digest(b"second\n"));
        let unchanged = OperationLease::acquire_in(temporary.path(), rewind).unwrap();
        assert_eq!(read_current_in(temporary.path()).unwrap(), Some(recovered));
        drop(unchanged);
    }

    #[test]
    fn held_lease_publishes_the_next_wal_projection_without_a_gap_rewind() {
        let temporary = root();
        let transaction_id = "11".repeat(32);
        let recovery = temporary.path().join("recovery");
        let transaction = recovery.join(&transaction_id);
        std::fs::create_dir(&recovery).unwrap();
        std::fs::create_dir(&transaction).unwrap();
        std::fs::set_permissions(&recovery, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&transaction, std::fs::Permissions::from_mode(0o700)).unwrap();
        let journal = transaction.join("restore-journal.json");
        std::fs::write(&journal, b"first\n").unwrap();
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();

        let lease =
            OperationLease::acquire_in(temporary.path(), descriptor(Operation::Restore)).unwrap();
        let mut next = read_current_in(temporary.path()).unwrap().unwrap();
        std::fs::write(&journal, b"second\n").unwrap();
        next.phase = "restore-firmware-verify".to_string();
        next.status_sequence += 1;
        next.journal_sha256 = format!("{:x}", Sha256::digest(b"second\n"));
        lease.publish(&next).unwrap();
        assert_eq!(read_current_in(temporary.path()).unwrap(), Some(next));
    }

    #[test]
    fn terminal_handoff_is_an_exclusive_baton() {
        let temporary = root();
        let requested = descriptor(Operation::Uninstall);
        let primary = OperationLease::acquire_in(temporary.path(), requested.clone()).unwrap();
        assert!(OperationLease::acquire_in(temporary.path(), requested.clone()).is_err());
        drop(primary);
        let successor = OperationLease::acquire_in(temporary.path(), requested).unwrap();
        successor.verify_owner().unwrap();
    }

    #[test]
    fn crash_left_exact_descriptor_temporary_is_adopted_fd_relatively() {
        let temporary = root();
        let requested = descriptor(Operation::Restore);
        std::fs::write(
            temporary.path().join(".operation.json.tmp"),
            requested.canonical_bytes().unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(
            temporary.path().join(".operation.json.tmp"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let lease = OperationLease::acquire_in(temporary.path(), requested).unwrap();
        lease.verify_owner().unwrap();
        assert!(!temporary.path().join(".operation.json.tmp").exists());
        assert!(temporary.path().join("operation.json").exists());
    }

    #[test]
    fn crash_left_stale_trusted_temporary_is_replaced_but_link_is_rejected() {
        let temporary = root();
        std::fs::write(
            temporary.path().join(".operation.json.tmp"),
            descriptor(Operation::Install).canonical_bytes().unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(
            temporary.path().join(".operation.json.tmp"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let requested = descriptor(Operation::Update);
        let lease = OperationLease::acquire_in(temporary.path(), requested.clone()).unwrap();
        lease.clear().unwrap();

        use std::os::unix::fs::symlink;
        let outside = temporary.path().join("outside");
        std::fs::write(&outside, requested.canonical_bytes().unwrap()).unwrap();
        symlink(&outside, temporary.path().join(".operation.json.tmp")).unwrap();
        assert!(OperationLease::acquire_in(temporary.path(), requested).is_err());
    }

    #[test]
    fn lease_rejects_permissive_lock_descriptor_and_root() {
        let temporary = root();
        std::fs::write(temporary.path().join("operation.lock"), b"").unwrap();
        std::fs::set_permissions(
            temporary.path().join("operation.lock"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(
            OperationLease::acquire_in(temporary.path(), descriptor(Operation::Install)).is_err()
        );

        let temporary = root();
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            OperationLease::acquire_in(temporary.path(), descriptor(Operation::Install)).is_err()
        );

        let temporary = root();
        std::fs::write(
            temporary.path().join("operation.json"),
            descriptor(Operation::Install).canonical_bytes().unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(
            temporary.path().join("operation.json"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(
            OperationLease::acquire_in(temporary.path(), descriptor(Operation::Install)).is_err()
        );
    }

    #[test]
    fn lease_rejects_symlink_and_hardlink_members() {
        use std::os::unix::fs::symlink;
        let temporary = root();
        let outside = temporary.path().join("outside");
        std::fs::write(&outside, b"").unwrap();
        symlink(&outside, temporary.path().join("operation.lock")).unwrap();
        assert!(
            OperationLease::acquire_in(temporary.path(), descriptor(Operation::Install)).is_err()
        );

        let temporary = root();
        let outside = temporary.path().join("outside");
        std::fs::write(&outside, b"").unwrap();
        std::fs::hard_link(&outside, temporary.path().join("operation.lock")).unwrap();
        assert!(
            OperationLease::acquire_in(temporary.path(), descriptor(Operation::Install)).is_err()
        );

        let temporary = root();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), temporary.path().join("recovery")).unwrap();
        assert!(
            OperationLease::acquire_in(temporary.path(), descriptor(Operation::Restore)).is_err()
        );
    }

    #[test]
    fn trusted_identity_rejects_wrong_uid_gid_mode_and_link_count() {
        assert!(trusted_file_identity(true, 1, 0, 0, 0o600, 0, 0, 0o600));
        assert!(!trusted_file_identity(true, 1, 1, 0, 0o600, 0, 0, 0o600));
        assert!(!trusted_file_identity(true, 1, 0, 1, 0o600, 0, 0, 0o600));
        assert!(!trusted_file_identity(true, 1, 0, 0, 0o644, 0, 0, 0o600));
        assert!(!trusted_file_identity(true, 2, 0, 0, 0o600, 0, 0, 0o600));
    }
}
