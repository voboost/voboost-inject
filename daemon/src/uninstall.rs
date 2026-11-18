//! Fail-closed in-car uninstall preparation.
//!
//! The root marker is the irreversible preparation commit. It is published
//! after ephemeral live cleanup is proved and before either update-plane ready
//! marker is removed. Once committed, freeze/trigger failures remain in the
//! uninstall-frozen retry path and never roll back into normal daemon work.

use std::fs::{File, OpenOptions};
use std::io::Read;
#[cfg(any(target_os = "android", target_os = "linux"))]
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::{
    config, log,
    operation_contract::{Operation, OperationDescriptor, OperationLease},
    secure_fs::{Directory, TrustedSnapshot},
};

const UNINSTALL_CHILD: &str = "uninstall";
const RECOVERY_CHILD: &str = "recovery";
const MARKER_FILE: &str = "uninstall_do.json";
const STATUS_FILE: &str = "status.json";
const OPERATION_STATUS_FILE: &str = "operation.json";
const DESKTOP_REQUEST_FILE: &str = "desktop-uninstall-request";
const DESKTOP_RESULT_FILE: &str = "desktop-uninstall-result.json";
const DESKTOP_AUTHORITY_FILE: &str = "desktop-uninstall-authority.json";
pub(crate) const PREPARATION_OPERATION_BUSY: &str = "uninstall preparation operation busy";
const SYSTEM_ARTIFACTS_FILE: &str = "system-artifacts.json";
const CURRENT_BASELINE_FILE: &str = "current-baseline.json";
const POLICY_META_FILE: &str = "policy.meta.json";
const SYSTEM_STATE_FILE: &str = "system-state.json";
const SYSTEM_CHILD: &str = "system";
const RC_ARCHIVE_FILE: &str = "voboost.rc";
const MARKER_BYTES: &[u8] = b"{\"schemaVersion\":1,\"prepared\":true}\n";
const INITIAL_JOURNAL_BYTES: &[u8] = b"{\"schemaVersion\":1,\"phase\":\"uninstall-prepare\"}";
const INIT_CONTROL_PROPERTY: &str = "ctl.start";
const INIT_SERVICE: &str = "voboost-uninstall";
const MAX_INVENTORY_BYTES: usize = 64 * 1024;
const MAX_INSTALLED_POLICY_BYTES: usize = 64 * 1024 * 1024;
use crate::selinux_backend::{DATA_CONTEXT, PROTECTED_CONTEXT, RESULT_CONTEXT};

fn desktop_request_directory() -> String {
    voboost_contract::uninstall_request::DESKTOP_REQUEST_PATH
        .rsplit_once('/')
        .map(|(parent, _)| parent.to_string())
        .expect("contract desktop request path has a parent")
}

use voboost_shared::uninstall_contract;

/// An opaque proof token created only after the daemon has completed its
/// bounded resident cleanup protocol.
pub(crate) struct CleanupProof(());

pub(crate) struct CommittedInventoryProof {
    root: Directory,
    dir: Directory,
    system_dir: Directory,
    snapshot: InventorySnapshot,
    transaction_id: String,
    #[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
    package: InstalledPackageAuthority,
}

#[derive(Clone)]
#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
pub(crate) struct InstalledPackageAuthority {
    pub(crate) apk_size: u64,
    pub(crate) apk_sha256: String,
    pub(crate) certificate_sha256: String,
}

#[derive(Debug, Eq, PartialEq)]
struct InventorySnapshot {
    inventory: TrustedSnapshot,
    artifacts: TrustedSnapshot,
    baseline: TrustedSnapshot,
    policy_metadata: TrustedSnapshot,
    system_state: TrustedSnapshot,
    rc_archive: TrustedSnapshot,
    /// Set when at least one document no longer carries the compile-time
    /// inventory label and was admitted through the degraded root-owned
    /// identity contract instead. Explicit uninstall must not keep a damaged
    /// product installed because of its own labeling defect.
    context_degraded: bool,
}

impl CommittedInventoryProof {
    pub(crate) fn load() -> Result<Self, String> {
        let dir = open_uninstall_dir_existing(Path::new(config::ROOT_ZONE))
            .map_err(|error| format!("open committed inventory authority: {error}"))?;
        let system_dir = dir
            .open_child(SYSTEM_CHILD)
            .map_err(|error| format!("open committed init archive: {error}"))?;
        system_dir
            .validate_owner_mode(
                unsafe { libc::geteuid() },
                unsafe { libc::getegid() },
                0o700,
            )
            .map_err(|error| format!("validate committed init archive: {error}"))?;
        let root =
            Directory::open(Path::new(config::ROOT_ZONE)).map_err(|error| error.to_string())?;
        let snapshot = read_committed_inventory(&root, &dir, &system_dir)?;
        let contract = uninstall_contract::parse_committed_contract(
            &snapshot.inventory.bytes,
            &snapshot.artifacts.bytes,
            &snapshot.baseline.bytes,
            &snapshot.policy_metadata.bytes,
            &snapshot.system_state.bytes,
            &snapshot.rc_archive.bytes,
        )?;
        let transaction_id =
            uninstall_contract::uninstall_transaction_id(&contract, &snapshot.inventory.bytes)?;
        let package = InstalledPackageAuthority {
            apk_size: contract.artifacts.package.apk_size,
            apk_sha256: contract.artifacts.package.apk_sha256.clone(),
            certificate_sha256: contract.artifacts.package.certificate_sha256.clone(),
        };
        Ok(Self {
            root,
            dir,
            system_dir,
            snapshot,
            transaction_id,
            package,
        })
    }

    /// Whether the loaded inventory was admitted through the degraded
    /// root-owned identity contract after a strict label mismatch.
    pub(crate) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }
    pub(crate) fn context_degraded(&self) -> bool {
        self.snapshot.context_degraded
    }

    pub(crate) fn revalidate(&self) -> Result<(), String> {
        let current = read_committed_inventory(&self.root, &self.dir, &self.system_dir)?;
        if current != self.snapshot {
            return Err("committed inventory identity or bytes changed during preparation".into());
        }
        Ok(())
    }
}

#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
pub(crate) fn installed_package_authority() -> Result<InstalledPackageAuthority, String> {
    let proof = CommittedInventoryProof::load()?;
    proof.revalidate()?;
    Ok(proof.package.clone())
}

/// Revalidate the committed reverse authority against both the active signed
/// product manifest and the protected files it describes. This is read-only;
/// callers must retain the global generation guard so the observation cannot
/// race a product transaction.
pub(crate) fn verify_committed_installed_authority(
    manifest: &voboost_contract::release::Manifest,
) -> Result<(), String> {
    let proof = CommittedInventoryProof::load()?;
    let contract = uninstall_contract::parse_committed_contract(
        &proof.snapshot.inventory.bytes,
        &proof.snapshot.artifacts.bytes,
        &proof.snapshot.baseline.bytes,
        &proof.snapshot.policy_metadata.bytes,
        &proof.snapshot.system_state.bytes,
        &proof.snapshot.rc_archive.bytes,
    )?;
    if contract.inventory.version != manifest.release_identity
        || contract.artifacts.native.manifest.sha256 != manifest.digest()?
    {
        return Err("committed recovery authority differs from active product manifest".into());
    }

    let compare = |name: &str, size: u64, sha256: &str| -> Result<(), String> {
        let artifact = manifest.artifact(name)?;
        if artifact.size != size || artifact.sha256 != sha256 {
            return Err(format!("committed recovery identity differs for {name}"));
        }
        Ok(())
    };
    compare(
        "voboost-daemon",
        contract.artifacts.native.daemon.size,
        &contract.artifacts.native.daemon.sha256,
    )?;
    compare(
        "voboost-inject",
        contract.artifacts.native.inject.size,
        &contract.artifacts.native.inject.sha256,
    )?;
    compare(
        "voboost-install",
        contract.artifacts.native.installer.size,
        &contract.artifacts.native.installer.sha256,
    )?;
    compare(
        "voboost-restore",
        contract.artifacts.native.restore.size,
        &contract.artifacts.native.restore.sha256,
    )?;
    compare(
        "voboost-uninstall",
        contract.artifacts.native.uninstaller.size,
        &contract.artifacts.native.uninstaller.sha256,
    )?;
    compare(
        "voboost-selinux",
        contract.artifacts.native.selinux.size,
        &contract.artifacts.native.selinux.sha256,
    )?;
    compare(
        "voboost.rc",
        contract.artifacts.init.installed_size,
        &contract.artifacts.init.installed_sha256,
    )?;
    compare(
        "restore.json",
        contract.artifacts.native.restore_manifest.size,
        &contract.artifacts.native.restore_manifest.sha256,
    )?;
    compare(
        "restore.json.sig",
        contract.artifacts.native.restore_manifest.signature_size,
        &contract.artifacts.native.restore_manifest.signature_sha256,
    )?;
    let app = manifest.app_artifact()?;
    if contract.artifacts.package.version_code != app.version_code.unwrap_or_default()
        || contract.artifacts.package.apk_size != app.size
        || contract.artifacts.package.apk_sha256 != app.sha256
        || contract.artifacts.package.certificate_sha256
            != app.certificate_sha256.as_deref().unwrap_or_default()
    {
        return Err("committed recovery APK identity differs from active product manifest".into());
    }
    for payload in &contract.artifacts.native.payload {
        let name = payload
            .path
            .strip_prefix("/data/voboost/")
            .ok_or_else(|| "committed payload path is outside product root".to_string())?;
        compare(name, payload.size, &payload.sha256)?;
    }

    for relay in &contract.artifacts.native.qnx {
        let name = relay
            .path
            .strip_prefix("/data/voboost/")
            .ok_or("committed QNX relay outside product root")?;
        compare(name, relay.size, &relay.sha256)?;
    }

    verify_inventory_file(
        &contract.artifacts.init.path,
        contract.artifacts.init.installed_size,
        &contract.artifacts.init.installed_sha256,
        contract.artifacts.init.uid,
        contract.artifacts.init.gid,
        &contract.artifacts.init.mode,
        &contract.artifacts.init.context,
    )?;
    verify_installed_policy_file(
        &contract.policy_metadata,
        &contract.artifacts.policy.installed_sha256,
    )?;
    if contract.system_state.policy_installed_sha256 != contract.artifacts.policy.installed_sha256 {
        return Err("committed policy identities disagree".into());
    }
    for artifact in [
        &contract.artifacts.native.daemon,
        &contract.artifacts.native.inject,
        &contract.artifacts.native.installer,
        &contract.artifacts.native.restore,
        &contract.artifacts.native.uninstaller,
        &contract.artifacts.native.selinux,
    ]
    .into_iter()
    .chain(contract.artifacts.native.qnx.iter())
    {
        verify_inventory_file(
            &artifact.path,
            artifact.size,
            &artifact.sha256,
            artifact.uid,
            artifact.gid,
            &artifact.mode,
            &artifact.context,
        )?;
    }
    let marker = Directory::open(Path::new(config::ROOT_ZONE))
        .and_then(|root| root.read_trusted("root.json", 4096, 0o600))
        .map_err(|error| format!("read installed root marker: {error}"))?;
    if crate::trust::sha256_bytes(&marker) != uninstall_contract::ROOT_ZONE_MARKER_SHA256 {
        return Err("installed root marker differs from committed authority".into());
    }

    crate::selinux_backend::verify_runtime_preconditions()?;

    proof.revalidate()
}

/// The committed policy check differs from every other installed artifact:
/// `policy.meta.json` records the PRISTINE rollback target that uninstall and
/// restore will republish, while the live `/vendor` file carries the INSTALLED
/// (transformed) policy produced by the machine install. Verify the live file
/// against the committed installed identity; ownership, mode, and context come
/// from the stat captured at inventory commit.
fn verify_installed_policy_file(
    metadata: &uninstall_contract::PolicyMetadata,
    installed_sha256: &str,
) -> Result<(), String> {
    let path = &metadata.path;
    let mode = u32::from_str_radix(&metadata.mode, 8)
        .map_err(|_| format!("invalid committed mode for {path}"))?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("open committed installed path {path}: {error}"))?;
    let before = file
        .metadata()
        .map_err(|error| format!("stat committed installed path {path}: {error}"))?;
    if !before.file_type().is_file()
        || before.nlink() != 1
        || before.uid() != metadata.uid
        || before.gid() != metadata.gid
        || before.permissions().mode() & 0o7777 != mode
    {
        return Err(format!("committed installed metadata differs for {path}"));
    }
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut chunk)
            .map_err(|error| format!("read committed installed path {path}: {error}"))?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count as u64);
        if total > MAX_INSTALLED_POLICY_BYTES as u64 {
            return Err(format!(
                "committed installed path grew while reading {path}"
            ));
        }
        hasher.update(&chunk[..count]);
    }
    let after = file
        .metadata()
        .map_err(|error| format!("restat committed installed path {path}: {error}"))?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || format!("{:x}", hasher.finalize()) != installed_sha256
    {
        return Err(format!("committed installed bytes differ for {path}"));
    }
    if read_selinux_context(&file, path)? != metadata.context {
        return Err(format!("committed SELinux context differs for {path}"));
    }
    Ok(())
}

fn verify_inventory_file(
    path: &str,
    expected_size: u64,
    expected_sha256: &str,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: &str,
    expected_context: &str,
) -> Result<(), String> {
    let mode = u32::from_str_radix(expected_mode, 8)
        .map_err(|_| format!("invalid committed mode for {path}"))?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("open committed installed path {path}: {error}"))?;
    let before = file
        .metadata()
        .map_err(|error| format!("stat committed installed path {path}: {error}"))?;
    if !before.file_type().is_file()
        || before.nlink() != 1
        || before.uid() != expected_uid
        || before.gid() != expected_gid
        || before.permissions().mode() & 0o7777 != mode
        || before.len() != expected_size
    {
        return Err(format!("committed installed metadata differs for {path}"));
    }
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut chunk)
            .map_err(|error| format!("read committed installed path {path}: {error}"))?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count as u64);
        if total > expected_size {
            return Err(format!(
                "committed installed path grew while reading {path}"
            ));
        }
        hasher.update(&chunk[..count]);
    }
    let after = file
        .metadata()
        .map_err(|error| format!("restat committed installed path {path}: {error}"))?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || total != expected_size
        || format!("{:x}", hasher.finalize()) != expected_sha256
    {
        return Err(format!("committed installed bytes changed for {path}"));
    }
    if read_selinux_context(&file, path)? != expected_context {
        return Err(format!("committed SELinux context differs for {path}"));
    }
    Ok(())
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn read_selinux_context(file: &File, path: &str) -> Result<String, String> {
    let name = b"security.selinux\0";
    let size = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr().cast(),
            std::ptr::null_mut(),
            0,
        )
    };
    if size <= 1 || size > 128 {
        return Err(format!(
            "installed SELinux context is unavailable for {path}"
        ));
    }
    let mut bytes = vec![0_u8; size as usize];
    if unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr().cast(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    } != size
    {
        return Err(format!("read installed SELinux context for {path}"));
    }
    if bytes.last() == Some(&0) {
        bytes.pop();
    }
    String::from_utf8(bytes)
        .map_err(|_| format!("installed SELinux context is not UTF-8 for {path}"))
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn read_selinux_context(_file: &File, path: &str) -> Result<String, String> {
    Err(format!(
        "installed SELinux context observation is unavailable for {path}"
    ))
}

pub(crate) fn cleanup_proved() -> CleanupProof {
    CleanupProof(())
}

/// Accept only the exact root-owned marker contract. Presence of a malformed,
/// symlinked, oversized, or incorrectly-mode file never freezes authority.
pub fn prepared_marker_valid() -> bool {
    prepared_authority().is_ok()
}

fn prepared_authority() -> Result<CommittedInventoryProof, String> {
    let proof = CommittedInventoryProof::load()?;
    let recovery =
        open_recovery_transaction_existing(Path::new(config::ROOT_ZONE), &proof.transaction_id)
            .map_err(|error| format!("open uninstall recovery authority: {error}"))?;
    let marker = recovery
        .read_trusted_snapshot(MARKER_FILE, MARKER_BYTES.len(), 0o600, DATA_CONTEXT)
        .map_err(|error| format!("read prepared marker: {error}"))?;
    if marker.bytes != MARKER_BYTES {
        return Err("prepared marker bytes differ from the exact contract".to_string());
    }
    let root = Directory::open(Path::new(config::ROOT_ZONE))
        .map_err(|error| format!("open prepared operation root: {error}"))?;
    root.validate_owner_mode(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        0o755,
    )
    .map_err(|error| format!("validate prepared operation root: {error}"))?;
    let descriptor = OperationDescriptor::parse(
        &root
            .read_trusted("operation.json", 4096, 0o600)
            .map_err(|error| format!("read prepared operation descriptor: {error}"))?,
    )?;
    if !descriptor.authorizes(Operation::Uninstall, &proof.transaction_id) {
        return Err("prepared marker lacks its correlated uninstall lease".to_string());
    }
    proof.revalidate()?;
    Ok(proof)
}

// Socket authentication tests do not publish to the Android data directory.
#[cfg(test)]
static SETTINGS_REQUEST: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
pub fn settings_request_accepted() -> bool {
    SETTINGS_REQUEST.load(std::sync::atomic::Ordering::Acquire)
}

/// Host-test seam: reset the in-memory settings request between cases.
#[cfg(test)]
pub(crate) fn reset_settings_request_for_test() {
    SETTINGS_REQUEST.store(false, std::sync::atomic::Ordering::Release);
}

/// Accept the Settings-host uninstall request delivered over the daemon
/// socket. Busy when an earlier request is still unconsumed or a prepared
/// uninstall authority is already committed; both stay idempotent for the
/// retrying client.
pub fn handle_settings_request() -> Result<(), String> {
    #[cfg(test)]
    {
        if SETTINGS_REQUEST.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return Err("uninstall already requested".into());
        }
        Ok(())
    }
    #[cfg(not(test))]
    {
        if request_present() || prepared_marker_valid() {
            return if crate::cluster_control::retry_failed_uninstall().unwrap_or(false) {
                Ok(())
            } else {
                Err("uninstall already requested".into())
            };
        }
        publish_desktop_request_with_authority().map(|_| ())
    }
}

/// A request is present when the stable desktop CLI published its exact
/// empty regular file through the root-owned run area or the Settings host
/// delivered an accepted socket request. Mere path existence is
/// insufficient for the file channel.
pub fn request_present() -> bool {
    desktop_request_present()
}

pub(crate) fn desktop_request_present() -> bool {
    Directory::open(Path::new(&desktop_request_directory()))
        .and_then(|dir| dir.read_untrusted(DESKTOP_REQUEST_FILE, 0))
        .is_ok_and(|bytes| bytes.is_empty())
}

/// Requested authority is not a durable prepared-operation observation.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DesktopUninstallAdmission {
    schema_version: u32,
    operation: String,
    state: String,
    transaction_id: String,
    boot_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    manifest_sha256: Option<String>,
}

pub(crate) struct DesktopRequestPublication {
    pub(crate) authority: Option<DesktopUninstallAdmission>,
    _guard: Option<crate::operation_contract::GenerationGuard>,
}

pub(crate) fn publish_desktop_request_with_authority() -> Result<DesktopRequestPublication, String>
{
    // The guard is shared with install/update/global operations. A damaged or
    // busy product retains legacy recovery admission, never fabricated authority.
    let guarded =
        crate::operation_contract::GenerationGuard::acquire_in(Path::new(config::ROOT_ZONE));
    let authority = guarded.as_ref().ok().and_then(|guard| {
        let proof = CommittedInventoryProof::load().ok()?;
        let boot_id = voboost_contract::operation::current_boot_id().ok()?;
        guard.verify_owner().ok()?;
        proof.revalidate().ok()?;
        Some(DesktopUninstallAdmission {
            schema_version: 2,
            operation: "uninstall".into(),
            state: "requested".into(),
            transaction_id: proof.transaction_id.clone(),
            boot_id,
            request_nonce: Some(new_request_nonce().ok()?),
            manifest_sha256: Some(
                crate::installed_product::load_manifest()
                    .ok()?
                    .digest()
                    .ok()?,
            ),
        })
    });
    // Persist the same authority before exposing the empty request marker.
    // Resident preparation must validate it against its freshly loaded proof;
    // the global guard alone cannot cover the later consumer scheduling gap.
    if let Some(authority) = &authority {
        let root = Directory::open(Path::new(config::ROOT_ZONE)).map_err(|e| e.to_string())?;
        let dir = root
            .open_or_create_child_with_mode("run", config::RUN_DIR_MODE)
            .map_err(|e| e.to_string())?;
        let bytes = serde_json::to_vec(authority).map_err(|e| e.to_string())?;
        match dir.read_trusted(DESKTOP_AUTHORITY_FILE, 1024, 0o600) {
            Ok(existing) => {
                let existing_authority = desktop_authority_for_inventory(
                    &existing,
                    &authority.transaction_id,
                    &authority.boot_id,
                    authority.manifest_sha256.as_deref(),
                )?;
                // Resume the same publication identity; never replace a pending nonce.
                publish_desktop_request()?;
                return Ok(DesktopRequestPublication {
                    authority: Some(existing_authority),
                    _guard: guarded.ok(),
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "existing desktop uninstall authority is invalid: {error}"
                ))
            }
        }
        dir.write_atomic(DESKTOP_AUTHORITY_FILE, &bytes, 0o600)
            .map_err(|e| e.to_string())?;
        dir.sync_all().map_err(|e| e.to_string())?;
        if dir
            .read_trusted(DESKTOP_AUTHORITY_FILE, 1024, 0o600)
            .map_err(|e| e.to_string())?
            != bytes
        {
            return Err("desktop uninstall authority changed before publication".into());
        }
    }
    // Keep the guard alive through exact marker publication.
    publish_desktop_request()?;
    Ok(DesktopRequestPublication {
        authority,
        _guard: guarded.ok(),
    })
}

pub(crate) fn desktop_request_nonce() -> Result<Option<String>, String> {
    validate_desktop_authority(&CommittedInventoryProof::load()?)
}

fn validate_desktop_authority(
    inventory: &CommittedInventoryProof,
) -> Result<Option<String>, String> {
    let dir =
        Directory::open(Path::new(&desktop_request_directory())).map_err(|e| e.to_string())?;
    // Settings and legacy producers have no extra authority; keep their exact
    // original request semantics. Only the file channel binds this sidecar.
    if !dir
        .read_untrusted(DESKTOP_REQUEST_FILE, 0)
        .is_ok_and(|b| b.is_empty())
    {
        return Ok(None);
    }
    let bytes = match dir.read_trusted(DESKTOP_AUTHORITY_FILE, 1024, 0o600) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read desktop uninstall authority: {e}")),
    };
    let manifest = crate::installed_product::load_manifest()?.digest()?;
    desktop_authority_for_inventory(
        &bytes,
        &inventory.transaction_id,
        &voboost_contract::operation::current_boot_id()?,
        Some(&manifest),
    )
    .map(|authority| authority.request_nonce)
}

#[cfg(test)]
fn validate_desktop_authority_bytes(
    bytes: &[u8],
    transaction: &str,
    boot: &str,
) -> Result<(), String> {
    desktop_authority_for_inventory(bytes, transaction, boot, None).map(|_| ())
}

fn desktop_authority_for_inventory(
    bytes: &[u8],
    transaction: &str,
    boot: &str,
    manifest: Option<&str>,
) -> Result<DesktopUninstallAdmission, String> {
    let authority: DesktopUninstallAdmission = serde_json::from_slice(bytes)
        .map_err(|_| "desktop uninstall authority schema is invalid")?;
    let canonical = serde_json::to_vec(&authority).map_err(|e| e.to_string())?;
    // The original boot correlates the desktop's publication and result.
    // A versioned request for this exact installed product survives reboot.
    let same_manifest = authority.schema_version == 2
        && manifest.is_some_and(|active| authority.manifest_sha256.as_deref() == Some(active));
    if canonical != bytes
        || !matches!(authority.schema_version, 1 | 2)
        || authority.operation != "uninstall"
        || authority.state != "requested"
        || authority.transaction_id != transaction
        || !crate::startup_session::canonical_boot_id(&authority.boot_id)
        || (authority.boot_id != boot && !same_manifest)
        || (authority.schema_version == 2 && manifest.is_some() && !same_manifest)
        || (authority.schema_version == 2
            && (authority
                .request_nonce
                .as_deref()
                .is_none_or(|v| !is_sha256(v))
                || authority
                    .manifest_sha256
                    .as_deref()
                    .is_none_or(|v| !is_sha256(v))))
        || (authority.schema_version == 1
            && (authority.request_nonce.is_some() || authority.manifest_sha256.is_some()))
    {
        return Err("desktop uninstall authority differs from committed inventory or boot".into());
    }
    Ok(authority)
}

/// Random per-publication correlation, never derived from predictable time/PID.
fn new_request_nonce() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| format!("uninstall request nonce: {e}"))?;
    Ok(hex::encode(bytes))
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DesktopPreparationResult {
    schema_version: u32,
    operation: String,
    state: String,
    transaction_id: String,
    boot_id: String,
    request_nonce: String,
    manifest_sha256: String,
    reason: String,
}

/// Called only after complete compensation, BEFORE request/authority consumption.
/// Recovery may contain foreign evidence; this result never opens that namespace.
pub(crate) fn record_rolled_back_result(reason: &str) -> Result<(), String> {
    record_preparation_result(reason, "prepare-rolled-back")
}

pub(crate) fn record_rejected_result(reason: &str) -> Result<(), String> {
    record_preparation_result(reason, "prepare-failed")
}

fn record_preparation_result(reason: &str, state: &str) -> Result<(), String> {
    let dir =
        Directory::open(Path::new(&desktop_request_directory())).map_err(|e| e.to_string())?;
    dir.validate_owner_mode(0, 0, config::RUN_DIR_MODE)
        .map_err(|e| e.to_string())?;
    let authority_bytes = match dir.read_trusted(DESKTOP_AUTHORITY_FILE, 1024, 0o600) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()), // Settings/legacy
        Err(e) => return Err(format!("read uninstall result request: {e}")),
    };
    let proof = CommittedInventoryProof::load()?;
    let boot = voboost_contract::operation::current_boot_id()?;
    let manifest = crate::installed_product::load_manifest()?.digest()?;
    let authority = desktop_authority_for_inventory(
        &authority_bytes,
        proof.transaction_id(),
        &boot,
        Some(&manifest),
    )?;
    if authority.schema_version != 2 {
        return Err("uninstall result request manifest differs from active product".into());
    }
    let nonce = authority
        .request_nonce
        .ok_or("missing uninstall request nonce")?;
    if !is_sha256(&nonce) {
        return Err("invalid uninstall request nonce".into());
    }
    proof.revalidate()?;
    let result = DesktopPreparationResult {
        schema_version: 1,
        operation: "uninstall".into(),
        state: state.into(),
        transaction_id: proof.transaction_id().into(),
        boot_id: authority.boot_id,
        request_nonce: nonce,
        manifest_sha256: manifest,
        reason: reason.chars().take(256).collect(),
    };
    let bytes = serde_json::to_vec(&result).map_err(|e| e.to_string())?;
    // An existing result must already be trusted; never replace foreign/symlinked evidence.
    match dir.read_trusted_snapshot(DESKTOP_RESULT_FILE, 2048, 0o600, RESULT_CONTEXT) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("untrusted existing uninstall result: {e}")),
    }
    dir.prepare_trusted_with_existing_label(
        ".desktop-uninstall-result.json.tmp",
        &bytes,
        0o600,
        RESULT_CONTEXT,
    )
    .and_then(|_| dir.rename(".desktop-uninstall-result.json.tmp", DESKTOP_RESULT_FILE))
    .and_then(|_| dir.sync_all())
    .map_err(|e| format!("publish uninstall preparation result: {e}"))?;
    let published = dir
        .read_trusted_snapshot(DESKTOP_RESULT_FILE, 2048, 0o600, RESULT_CONTEXT)
        .map_err(|e| format!("verify uninstall preparation result: {e}"))?;
    if published.bytes != bytes {
        return Err("uninstall preparation result changed before request consumption".into());
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Fixed read-only management endpoint. Absence is not success or an error result.
pub(crate) fn inspect_desktop_result() -> Result<serde_json::Value, String> {
    let dir =
        Directory::open(Path::new(&desktop_request_directory())).map_err(|e| e.to_string())?;
    dir.validate_owner_mode(0, 0, config::RUN_DIR_MODE)
        .map_err(|e| e.to_string())?;
    let snapshot = match dir.read_trusted_snapshot(DESKTOP_RESULT_FILE, 2048, 0o600, RESULT_CONTEXT)
    {
        Ok(value) => value,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(serde_json::json!({"schemaVersion":1,"state":"absent"}))
        }
        Err(e) => return Err(format!("uninstall result trust rejected: {e}")),
    };
    let manifest = crate::installed_product::load_manifest()?.digest()?;
    let proof = CommittedInventoryProof::load()?;
    let Some(value) = parse_preparation_result(&snapshot.bytes, &manifest, proof.transaction_id())?
    else {
        return Ok(serde_json::json!({"schemaVersion":1,"state":"absent"}));
    };
    let current = dir
        .read_trusted_snapshot(DESKTOP_RESULT_FILE, 2048, 0o600, RESULT_CONTEXT)
        .map_err(|e| e.to_string())?;
    if current != snapshot {
        return Err("uninstall result changed during observation".into());
    }
    proof.revalidate()?;
    serde_json::to_value(value).map_err(|e| e.to_string())
}

fn parse_preparation_result(
    bytes: &[u8],
    manifest: &str,
    transaction: &str,
) -> Result<Option<DesktopPreparationResult>, String> {
    let value: DesktopPreparationResult =
        serde_json::from_slice(bytes).map_err(|_| "uninstall result schema rejected")?;
    if serde_json::to_vec(&value).map_err(|e| e.to_string())? != bytes
        || value.schema_version != 1
        || value.operation != "uninstall"
        || !matches!(
            value.state.as_str(),
            "prepare-rolled-back" | "prepare-failed"
        )
        || !is_sha256(&value.request_nonce)
        || !is_sha256(&value.transaction_id)
        || value.reason.len() > 1024
        || !is_sha256(&value.manifest_sha256)
    {
        return Err("uninstall result identity rejected".into());
    }
    if !crate::startup_session::canonical_boot_id(&value.boot_id)
        || value.manifest_sha256 != manifest
        || value.transaction_id != transaction
    {
        return Ok(None);
    }
    Ok(Some(value))
}

/// Publish the durable request shared by authenticated Settings and desktop CLI.
/// The resident daemon normally creates the run directory at startup; an
/// install that never completed has no resident daemon, and the explicit
/// desktop uninstall has priority over it, so the missing run directory is
/// created here instead of failing the request.
pub fn publish_desktop_request() -> Result<(), String> {
    let root = Directory::open(Path::new(config::ROOT_ZONE))
        .map_err(|error| format!("open root zone: {error}"))?;
    let run_leaf = desktop_request_directory()
        .rsplit_once('/')
        .and_then(|(parent, leaf)| {
            if parent == config::ROOT_ZONE {
                Some(leaf.to_string())
            } else {
                None
            }
        })
        .ok_or("desktop uninstall request directory is not a root-zone child")?;
    let dir = root
        .open_or_create_child_with_mode(&run_leaf, config::RUN_DIR_MODE)
        .map_err(|error| format!("open desktop uninstall request directory: {error}"))?;
    if dir
        .read_untrusted(DESKTOP_REQUEST_FILE, 0)
        .is_ok_and(|bytes| bytes.is_empty())
    {
        return Ok(());
    }
    dir.write_atomic(DESKTOP_REQUEST_FILE, b"", 0o600)
        .map_err(|error| format!("publish desktop uninstall request: {error}"))?;
    dir.sync_all()
        .map_err(|error| format!("sync desktop uninstall request: {error}"))?;
    if dir
        .read_untrusted(DESKTOP_REQUEST_FILE, 0)
        .is_ok_and(|bytes| bytes.is_empty())
    {
        Ok(())
    } else {
        let _ = dir.unlink(DESKTOP_REQUEST_FILE);
        let _ = dir.sync_all();
        Err("desktop uninstall request did not retain its exact root-owned contract".to_string())
    }
}

/// Consume a request only after durable commit, complete pre-commit rollback,
/// or while retrying an already committed prepared authority. Incomplete
/// compensation keeps the request as the activation fence for another attempt.
pub fn consume_request() -> Result<(), String> {
    #[cfg(test)]
    SETTINGS_REQUEST.store(false, std::sync::atomic::Ordering::Release);
    let dir = Directory::open(Path::new(&desktop_request_directory()))
        .map_err(|error| format!("open uninstall request directory: {error}"))?;
    match dir.unlink(DESKTOP_REQUEST_FILE) {
        Ok(()) => dir
            .sync_all()
            .map_err(|error| format!("sync uninstall request removal: {error}"))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("remove uninstall request: {error}")),
    }
    match dir.unlink(DESKTOP_AUTHORITY_FILE) {
        Ok(()) => dir.sync_all().map_err(|e| e.to_string())?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("remove desktop uninstall authority: {e}")),
    }
    match dir.read_untrusted(DESKTOP_REQUEST_FILE, 0) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err("uninstall request survived consumption".to_string()),
        Err(error) => Err(format!("verify uninstall request removal: {error}")),
    }
}

/// Freeze both update planes after durable prepared authority has committed.
pub fn freeze_update_planes(store: &crate::generation::GenerationStore) -> Result<(), String> {
    crate::product_candidate::ProductCandidateStore::production().ensure_idle_for_uninstall()?;
    store
        .freeze_for_uninstall()
        .map_err(|error| format!("freeze generation staging: {error}"))
}

/// Publish the durable root authority. The proof parameter prevents any call
/// site from crossing this irreversible boundary before resident cleanup.
///
/// A filesystem operation may report an error after the atomic rename became
/// durable. In that ambiguous cut, exact prepared authority is the source of
/// truth: a successfully revalidated marker is committed and must not be
/// cleared by the caller.
pub(crate) fn publish_prepared(
    _proof: CleanupProof,
    inventory: &CommittedInventoryProof,
) -> Result<OperationLease, String> {
    let mut retained_lease = None;
    let publication = (|| {
        crate::cluster_control::prepare_android_uninstall(None)?;
        inventory.revalidate()?;
        let _ = validate_desktop_authority(inventory)?;
        let recovery = open_or_create_recovery_transaction(
            Path::new(config::ROOT_ZONE),
            &inventory.transaction_id,
        )
        .map_err(|error| format!("open uninstall recovery transaction: {error}"))?;
        write_fixed_labeled(
            &recovery,
            "uninstall-journal.json",
            INITIAL_JOURNAL_BYTES,
            DATA_CONTEXT,
        )
        .map_err(|error| format!("publish initial uninstall WAL: {error}"))?;
        let lease = acquire_uninstall_operation(&inventory.transaction_id)?;
        lease.verify_owner()?;
        // Validate both identities under the acquired global operation lock,
        // before publishing the irreversible preparation marker.
        inventory.revalidate()?;
        let _ = validate_desktop_authority(inventory)?;
        write_fixed_labeled(&recovery, MARKER_FILE, MARKER_BYTES, DATA_CONTEXT)
            .map_err(|error| format!("publish marker: {error}"))?;
        let marker = recovery
            .read_trusted_snapshot(MARKER_FILE, MARKER_BYTES.len(), 0o600, DATA_CONTEXT)
            .map_err(|error| format!("re-read published marker: {error}"))?;
        inventory.revalidate()?;
        if marker.bytes != MARKER_BYTES {
            return Err("published uninstall marker failed exact verification".into());
        }
        retained_lease = Some(lease);
        Ok(())
    })();
    resolve_prepared_publication(publication, prepared_marker_valid())?;
    retained_lease.ok_or_else(|| "prepared uninstall lost its operation lease".to_string())
}

fn acquire_uninstall_operation(transaction_id: &str) -> Result<OperationLease, String> {
    acquire_prepared_operation(
        Path::new(config::ROOT_ZONE),
        transaction_id,
        voboost_contract::operation::current_boot_id()?,
    )
}

fn acquire_prepared_operation(
    root: &Path,
    transaction_id: &str,
    boot_id: String,
) -> Result<OperationLease, String> {
    let descriptor = OperationDescriptor::new(
        Operation::Uninstall,
        transaction_id.to_string(),
        format!("recovery/{}/uninstall-journal.json", transaction_id),
        boot_id,
    )?;
    OperationLease::acquire_in(root, descriptor).map_err(|error| {
        if error == "operation busy" {
            PREPARATION_OPERATION_BUSY.to_string()
        } else {
            error
        }
    })
}

fn resolve_prepared_publication(
    publication: Result<(), String>,
    prepared_authority_valid: bool,
) -> Result<(), String> {
    match publication {
        Ok(()) if prepared_authority_valid => Ok(()),
        Ok(()) => Err(
            "published uninstall marker is not reachable through exact prepared authority"
                .to_string(),
        ),
        Err(error) if prepared_authority_valid => {
            log::err(
                "uninstall",
                &format!("prepared marker committed despite ambiguous publication result: {error}"),
            );
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// Retry the post-commit destructive freezes and fixed init trigger. Returning
/// an error never revokes prepared authority; callers must remain frozen and
/// retry this exact operation.
pub fn retry_committed_prepared(store: &crate::generation::GenerationStore) -> Result<(), String> {
    if !prepared_marker_valid() {
        return Err("exact prepared uninstall marker is absent".to_string());
    }
    let proof = CommittedInventoryProof::load()?;
    let lease = acquire_uninstall_operation(&proof.transaction_id)?;
    retry_committed_prepared_with_lease(store, &lease)
}

pub(crate) fn retry_committed_prepared_with_lease(
    store: &crate::generation::GenerationStore,
    lease: &OperationLease,
) -> Result<(), String> {
    retry_committed_actions(
        || {
            lease.verify_owner()?;
            freeze_update_planes(store)
        },
        || {
            lease.verify_owner()?;
            trigger_prepared(lease)
        },
    )
}

fn retry_committed_actions<Freeze, Trigger>(freeze: Freeze, trigger: Trigger) -> Result<(), String>
where
    Freeze: FnOnce() -> Result<(), String>,
    Trigger: FnOnce() -> Result<(), String>,
{
    freeze()?;
    trigger()
}

/// Retry a previously prepared operation after reboot without accepting any
/// new update/injection work first.
pub fn trigger_prepared(lease: &OperationLease) -> Result<(), String> {
    if !prepared_marker_valid() {
        return Err("exact prepared uninstall marker is absent".to_string());
    }
    crate::cluster_control::prepare_android_uninstall(Some(lease))?;
    if crate::fixed_process::set_property(INIT_CONTROL_PROPERTY, INIT_SERVICE).is_err() {
        record_status("trigger-failed", "ctl.start voboost-uninstall failed");
        return Err("ctl.start voboost-uninstall failed".to_string());
    }
    record_status("triggered", "resident cleanup proved");
    log::ok("uninstall", "prepare durable; voboost-uninstall triggered");
    Ok(())
}

pub fn record_failure(reason: &str) {
    record_status("prepare-failed", reason);
}

pub(crate) fn record_cluster_progress(state: &str, reason: &str) {
    record_status(state, reason);
}

fn record_status(state: &str, reason: &str) {
    let bounded = reason.chars().take(256).collect::<String>();
    let mut bytes = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 1,
        "state": state,
        "reason": bounded,
    }))
    .unwrap_or_else(|_| b"{\"schemaVersion\":1,\"state\":\"prepare-failed\"}".to_vec());
    bytes.push(b'\n');
    let result = (|| {
        let proof = CommittedInventoryProof::load()?;
        let dir = open_or_create_recovery_transaction(
            Path::new(config::ROOT_ZONE),
            &proof.transaction_id,
        )
        .map_err(|error| format!("open uninstall recovery status: {error}"))?;
        write_fixed(&dir, STATUS_FILE, &bytes)
            .map_err(|error| format!("write uninstall recovery status: {error}"))?;
        // Cluster transport reports progress before Android admission creates its WAL.
        // Keep that progress durable without claiming an Android operation lease.
        if !dir
            .entry_exists("uninstall-journal.json")
            .map_err(|e| e.to_string())?
        {
            return Ok(());
        }
        let journal = dir
            .read_trusted("uninstall-journal.json", 4096, 0o600)
            .map_err(|error| format!("read uninstall WAL for status: {error}"))?;
        let journal_sha256 = format!("{:x}", Sha256::digest(&journal));
        let operation_status = OperationDescriptor {
            schema_version: 1,
            operation: Operation::Uninstall,
            transaction_id: proof.transaction_id.clone(),
            journal: format!("recovery/{}/uninstall-journal.json", proof.transaction_id),
            phase: "uninstall-prepare".to_string(),
            outcome: "running".to_string(),
            reboot_count: 0,
            boot_id: voboost_contract::operation::current_boot_id()?,
            status_sequence: 1,
            journal_sha256,
            error: None,
            installed_apk: None,
        }
        .canonical_bytes()?;
        let root = Directory::open(Path::new(config::ROOT_ZONE))
            .map_err(|error| format!("open root operation status: {error}"))?;
        write_fixed(&root, OPERATION_STATUS_FILE, &operation_status)
            .map_err(|error| format!("write root operation status: {error}"))
    })();
    if let Err(error) = result {
        log::err("uninstall", &format!("status write failed: {error}"));
    }
}

#[cfg(test)]
fn open_uninstall_dir_at(root_path: &Path) -> std::io::Result<Directory> {
    let root = Directory::open(root_path)?;
    root.validate_owner_not_writable(unsafe { libc::geteuid() }, unsafe { libc::getegid() })?;
    root.open_or_create_private_child(UNINSTALL_CHILD)
}

fn open_uninstall_dir_existing(root_path: &Path) -> std::io::Result<Directory> {
    let root = Directory::open(root_path)?;
    root.validate_owner_not_writable(unsafe { libc::geteuid() }, unsafe { libc::getegid() })?;
    let child = root.open_child(UNINSTALL_CHILD)?;
    child.validate_owner_mode(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        0o700,
    )?;
    Ok(child)
}

fn valid_transaction_name(transaction_id: &str) -> bool {
    transaction_id.len() == 64
        && transaction_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn validate_only_recovery_transaction(
    recovery_root: &Directory,
    transaction_id: &str,
) -> std::io::Result<()> {
    let names = recovery_root.entry_names_bounded(2)?;
    if names.iter().all(|name| name == transaction_id) && names.len() <= 1 {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "foreign or multiple recovery transactions are present",
        ))
    }
}

fn open_or_create_recovery_transaction(
    root_path: &Path,
    transaction_id: &str,
) -> std::io::Result<Directory> {
    if !valid_transaction_name(transaction_id) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid uninstall transaction id",
        ));
    }
    let root = Directory::open(root_path)?;
    root.validate_owner_not_writable(unsafe { libc::geteuid() }, unsafe { libc::getegid() })?;
    let recovery_root = root.open_or_create_private_child(RECOVERY_CHILD)?;
    validate_only_recovery_transaction(&recovery_root, transaction_id)?;
    let transaction = recovery_root.open_or_create_private_child(transaction_id)?;
    validate_only_recovery_transaction(&recovery_root, transaction_id)?;
    Ok(transaction)
}

fn open_recovery_transaction_existing(
    root_path: &Path,
    transaction_id: &str,
) -> std::io::Result<Directory> {
    if !valid_transaction_name(transaction_id) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid uninstall transaction id",
        ));
    }
    let root = Directory::open(root_path)?;
    root.validate_owner_not_writable(unsafe { libc::geteuid() }, unsafe { libc::getegid() })?;
    let recovery_root = root.open_child(RECOVERY_CHILD)?;
    recovery_root.validate_owner_mode(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        0o700,
    )?;
    validate_only_recovery_transaction(&recovery_root, transaction_id)?;
    let transaction = recovery_root.open_child(transaction_id)?;
    transaction.validate_owner_mode(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        0o700,
    )?;
    Ok(transaction)
}

fn write_fixed(dir: &Directory, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    dir.validate_optional_trusted_file(name, 0o600)?;
    let temp = format!(".{name}.tmp");
    dir.prepare_trusted(&temp, bytes, 0o600)?;
    dir.rename(&temp, name)?;
    dir.sync_all()
}

fn write_fixed_labeled(
    dir: &Directory,
    name: &str,
    bytes: &[u8],
    context: &str,
) -> std::io::Result<()> {
    dir.validate_optional_trusted_file(name, 0o600)?;
    let temp = format!(".{name}.tmp");
    dir.prepare_trusted_labeled(&temp, bytes, 0o600, context)?;
    dir.rename(&temp, name)?;
    dir.sync_all()
}

/// Strict read first. A root-owned mode-0600 single-link document whose only
/// defect is a mismatched SELinux context is still Voboost-owned state created
/// by a prior install of this product; explicit uninstall admits it through
/// the degraded identity contract and records the degradation. Every other
/// failure remains fatal.
fn read_protected_snapshot_degraded(
    dir: &Directory,
    name: &str,
    context_degraded: &mut bool,
) -> Result<TrustedSnapshot, String> {
    match dir.read_trusted_snapshot(name, MAX_INVENTORY_BYTES, 0o600, PROTECTED_CONTEXT) {
        Ok(snapshot) => Ok(snapshot),
        Err(error)
            if error
                .to_string()
                .contains(crate::secure_fs::SELINUX_CONTEXT_MISMATCH_MESSAGE) =>
        {
            let snapshot = dir
                .read_trusted_snapshot_any_context(name, MAX_INVENTORY_BYTES, 0o600)
                .map_err(|retry| format!("read committed authority {name}: {retry}"))?;
            *context_degraded = true;
            Ok(snapshot)
        }
        Err(error) => Err(format!("read committed authority {name}: {error}")),
    }
}

fn read_committed_inventory(
    root: &Directory,
    dir: &Directory,
    system_dir: &Directory,
) -> Result<InventorySnapshot, String> {
    let mut context_degraded = false;
    let mut read_document = |dir: &Directory, name: &str| {
        read_protected_snapshot_degraded(dir, name, &mut context_degraded)
    };
    let (inventory_dir, inventory_file) =
        voboost_shared::installed_state::location(root).map_err(|error| error.to_string())?;
    let snapshot = InventorySnapshot {
        inventory: read_document(&inventory_dir, inventory_file)?,
        artifacts: read_document(dir, SYSTEM_ARTIFACTS_FILE)?,
        baseline: read_document(dir, CURRENT_BASELINE_FILE)?,
        policy_metadata: read_document(dir, POLICY_META_FILE)?,
        system_state: read_document(dir, SYSTEM_STATE_FILE)?,
        rc_archive: read_document(system_dir, RC_ARCHIVE_FILE)?,
        context_degraded,
    };
    uninstall_contract::parse_committed_contract(
        &snapshot.inventory.bytes,
        &snapshot.artifacts.bytes,
        &snapshot.baseline.bytes,
        &snapshot.policy_metadata.bytes,
        &snapshot.system_state.bytes,
        &snapshot.rc_archive.bytes,
    )?;
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    #[test]
    fn preparation_failure_keeps_the_original_request_boot_across_producer_restart() {
        let manifest = "8".repeat(64);
        let result = super::DesktopPreparationResult {
            schema_version: 1,
            operation: "uninstall".into(),
            state: "prepare-failed".into(),
            transaction_id: "1".repeat(64),
            boot_id: "00000000-0000-0000-0000-000000000001".into(),
            request_nonce: "2".repeat(64),
            manifest_sha256: manifest.clone(),
            reason: "Cluster receipt unavailable; retry removal".into(),
        };
        let bytes = serde_json::to_vec(&result).unwrap();
        let replay = super::parse_preparation_result(&bytes, &manifest, &result.transaction_id)
            .unwrap()
            .unwrap();
        assert_eq!(replay.boot_id, result.boot_id);
        assert_eq!(replay.request_nonce, result.request_nonce);
        assert_eq!(replay.state, "prepare-failed");
        assert!(
            super::parse_preparation_result(&bytes, &"9".repeat(64), &result.transaction_id)
                .unwrap()
                .is_none()
        );
        assert!(
            super::parse_preparation_result(&bytes, &manifest, &"9".repeat(64))
                .unwrap()
                .is_none()
        );
    }
    use super::*;

    #[test]
    fn preparation_result_snapshot_rejects_symlink_hardlink_and_foreign_mode() {
        let root = tempfile::tempdir().unwrap();
        let dir = Directory::open(root.path()).unwrap();
        let target = root.path().join("target");
        std::fs::write(&target, b"{}").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let reply = root.path().join(DESKTOP_RESULT_FILE);
        std::os::unix::fs::symlink(&target, &reply).unwrap();
        assert!(dir
            .read_trusted_snapshot(DESKTOP_RESULT_FILE, 2048, 0o600, RESULT_CONTEXT)
            .is_err());
        std::fs::remove_file(&reply).unwrap();
        std::fs::hard_link(&target, &reply).unwrap();
        assert!(dir
            .read_trusted_snapshot(DESKTOP_RESULT_FILE, 2048, 0o600, RESULT_CONTEXT)
            .is_err());
        std::fs::remove_file(&reply).unwrap();
        std::fs::write(&reply, b"{}").unwrap();
        std::fs::set_permissions(&reply, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(dir
            .read_trusted_snapshot(DESKTOP_RESULT_FILE, 2048, 0o600, RESULT_CONTEXT)
            .is_err());
    }

    #[test]
    fn desktop_v2_authority_requires_exact_nonce_manifest_boot_and_inventory() {
        let boot = "00000000-0000-0000-0000-000000000001";
        let tx = "4".repeat(64);
        let mut authority = DesktopUninstallAdmission {
            schema_version: 2,
            operation: "uninstall".into(),
            state: "requested".into(),
            transaction_id: tx.clone(),
            boot_id: boot.into(),
            request_nonce: Some("5".repeat(64)),
            manifest_sha256: Some("6".repeat(64)),
        };
        assert!(validate_desktop_authority_bytes(
            &serde_json::to_vec(&authority).unwrap(),
            &tx,
            boot
        )
        .is_ok());
        authority.request_nonce = Some("../foreign".into());
        assert!(validate_desktop_authority_bytes(
            &serde_json::to_vec(&authority).unwrap(),
            &tx,
            boot
        )
        .is_err());
        authority.request_nonce = None;
        assert!(validate_desktop_authority_bytes(
            &serde_json::to_vec(&authority).unwrap(),
            &tx,
            boot
        )
        .is_err());
    }

    #[test]
    fn desktop_request_survives_a_reboot_for_the_same_installed_inventory() {
        let original = "00000000-0000-0000-0000-000000000001";
        let current = "00000000-0000-0000-0000-000000000002";
        let tx = "4".repeat(64);
        let manifest = "6".repeat(64);
        let nonce = "5".repeat(64);
        let bytes = serde_json::to_vec(&DesktopUninstallAdmission {
            schema_version: 2,
            operation: "uninstall".into(),
            state: "requested".into(),
            transaction_id: tx.clone(),
            boot_id: original.into(),
            request_nonce: Some(nonce.clone()),
            manifest_sha256: Some(manifest.clone()),
        })
        .unwrap();
        let resumed =
            desktop_authority_for_inventory(&bytes, &tx, current, Some(&manifest)).unwrap();
        assert_eq!(resumed.boot_id, original);
        assert_eq!(resumed.request_nonce, Some(nonce));
        assert!(desktop_authority_for_inventory(&bytes, &tx, current, None).is_err());
        assert!(
            desktop_authority_for_inventory(&bytes, &tx, current, Some(&"7".repeat(64))).is_err()
        );
        assert!(
            desktop_authority_for_inventory(&bytes, &"8".repeat(64), current, Some(&manifest))
                .is_err()
        );
    }

    #[test]
    fn preparation_result_never_uses_recovery_and_requires_protected_producer() {
        let source = include_str!("uninstall.rs");
        let publisher = source
            .split("pub(crate) fn record_rolled_back_result")
            .nth(1)
            .unwrap()
            .split("fn is_sha256")
            .next()
            .unwrap();
        assert!(!publisher.contains("open_or_create_recovery"));
        assert!(publisher.contains("read_trusted_snapshot("));
        let compact = publisher
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();
        assert!(compact.contains("prepare_trusted_with_existing_label("));
        assert!(publisher.contains("proof.revalidate()?"));
        let reader = source
            .split("pub(crate) fn inspect_desktop_result")
            .nth(1)
            .unwrap()
            .split("pub fn publish_desktop_request()")
            .next()
            .unwrap();
        assert!(reader.contains("dir.validate_owner_mode(0, 0, config::RUN_DIR_MODE)"));
        assert_eq!(reader.matches("read_trusted_snapshot(").count(), 2);
        assert!(reader.contains("current != snapshot"));
    }

    #[test]
    fn desktop_requested_authority_serializes_distinct_from_prepared_report() {
        let authority = DesktopUninstallAdmission {
            schema_version: 1,
            operation: "uninstall".into(),
            state: "requested".into(),
            transaction_id: "4".repeat(64),
            boot_id: "00000000-0000-0000-0000-000000000001".into(),
            request_nonce: None,
            manifest_sha256: None,
        };
        let value = serde_json::to_value(&authority).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 5);
        assert_eq!(value["state"], "requested");
        assert_eq!(value["operation"], "uninstall");
        assert!(value.get("prepared").is_none());
        assert!(value.get("outcome").is_none());
        assert!(value.get("statusSequence").is_none());
    }

    #[test]
    fn desktop_authority_rejects_inventory_substitution_and_boot_change() {
        let tx = "4".repeat(64);
        let boot = "00000000-0000-0000-0000-000000000001";
        let bytes = serde_json::to_vec(&DesktopUninstallAdmission {
            schema_version: 1,
            operation: "uninstall".into(),
            state: "requested".into(),
            transaction_id: tx.clone(),
            boot_id: boot.into(),
            request_nonce: None,
            manifest_sha256: None,
        })
        .unwrap();
        assert!(validate_desktop_authority_bytes(&bytes, &tx, boot).is_ok());
        assert!(validate_desktop_authority_bytes(&bytes, &"5".repeat(64), boot).is_err());
        assert!(validate_desktop_authority_bytes(
            &bytes,
            &tx,
            "00000000-0000-0000-0000-000000000002"
        )
        .is_err());
        assert!(validate_desktop_authority_bytes(b"{}", &tx, boot).is_err());
        let duplicate = String::from_utf8(bytes.clone()).unwrap().replace(
            "\"schemaVersion\":1",
            "\"schemaVersion\":1,\"schemaVersion\":1",
        );
        assert!(validate_desktop_authority_bytes(duplicate.as_bytes(), &tx, boot).is_err());
    }

    #[test]
    fn desktop_management_dispatch_holds_global_guard_through_write_and_flush() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let tx = "4".repeat(64);
        let boot = "00000000-0000-0000-0000-000000000001";
        let recovery = root.path().join("recovery").join(&tx);
        std::fs::create_dir_all(&recovery).unwrap();
        std::fs::set_permissions(
            root.path().join("recovery"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::set_permissions(&recovery, std::fs::Permissions::from_mode(0o700)).unwrap();
        let journal = recovery.join("uninstall-journal.json");
        std::fs::write(&journal, INITIAL_JOURNAL_BYTES).unwrap();
        std::fs::set_permissions(journal, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(root.path().join(DESKTOP_REQUEST_FILE), b"").unwrap();
        std::fs::write(
            root.path().join(DESKTOP_AUTHORITY_FILE),
            b"retained-authority",
        )
        .unwrap();
        let guard = crate::operation_contract::GenerationGuard::acquire_in(root.path()).unwrap();
        struct Writer<'a> {
            root: &'a Path,
            bytes: Vec<u8>,
            flushed: bool,
        }
        impl std::io::Write for Writer<'_> {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                assert!(crate::operation_contract::GenerationGuard::acquire_in(self.root).is_err());
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                let error = acquire_prepared_operation(
                    self.root,
                    &"4".repeat(64),
                    "00000000-0000-0000-0000-000000000001".into(),
                )
                .err()
                .unwrap();
                assert_eq!(error, PREPARATION_OPERATION_BUSY);
                assert!(!crate::preparation_resolved(&Ok(
                    crate::PrepareUninstallOutcome::PendingOperation
                )));
                assert!(self.root.join(DESKTOP_REQUEST_FILE).exists());
                assert_eq!(
                    std::fs::read(self.root.join(DESKTOP_AUTHORITY_FILE)).unwrap(),
                    b"retained-authority"
                );
                self.flushed = true;
                Ok(())
            }
        }
        let mut writer = Writer {
            root: root.path(),
            bytes: Vec::new(),
            flushed: false,
        };
        let publication = DesktopRequestPublication {
            authority: Some(DesktopUninstallAdmission {
                schema_version: 1,
                operation: "uninstall".into(),
                state: "requested".into(),
                transaction_id: "4".repeat(64),
                boot_id: "00000000-0000-0000-0000-000000000001".into(),
                request_nonce: None,
                manifest_sha256: None,
            }),
            _guard: Some(guard),
        };
        assert_eq!(
            crate::management::write_desktop_uninstall_admission(publication, &mut writer),
            0
        );
        assert!(writer.flushed);
        assert_eq!(writer.bytes.last(), Some(&b'\n'));
        let lease = acquire_prepared_operation(root.path(), &tx, boot.into()).unwrap();
        lease.verify_owner().unwrap();
        let report = crate::operation_contract::read_document_in(root.path())
            .unwrap()
            .unwrap();
        assert_eq!(report.transaction_id, tx);
        assert_eq!(report.boot_id, boot);
        assert!(root.path().join(DESKTOP_REQUEST_FILE).exists());
    }

    #[test]
    fn marker_content_is_exact_and_bounded() {
        assert_eq!(MARKER_BYTES, b"{\"schemaVersion\":1,\"prepared\":true}\n");
        assert!(MARKER_BYTES.len() < 128);
    }

    #[test]
    fn committed_authority_contexts_follow_only_the_compile_time_profile() {
        assert!(!PROTECTED_CONTEXT.is_empty());
        assert!(!DATA_CONTEXT.is_empty());
    }

    #[test]
    fn degraded_admission_matches_only_the_exact_context_mismatch() {
        let mismatch = || {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "read committed authority install-inventory.json: trusted file has unexpected SELinux context",
            )
        };
        let other = || {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "trusted file has no bounded SELinux context",
            )
        };
        for error in [mismatch(), mismatch()] {
            assert!(error
                .to_string()
                .contains(crate::secure_fs::SELINUX_CONTEXT_MISMATCH_MESSAGE));
        }
        assert!(
            !other()
                .to_string()
                .contains(crate::secure_fs::SELINUX_CONTEXT_MISMATCH_MESSAGE),
            "a missing context must stay fatal, not silently degrade"
        );
    }

    #[test]
    fn uninstall_request_uses_the_root_run_contract() {
        assert_eq!(
            format!("{}/{}", desktop_request_directory(), DESKTOP_REQUEST_FILE),
            "/data/voboost/run/desktop-uninstall-request"
        );
    }

    #[test]
    fn cleanup_proof_is_required_by_publication_signature() {
        let _proof: CleanupProof = cleanup_proved();
    }

    #[test]
    fn prepared_publication_cut_uses_durable_authority_as_commit_truth() {
        assert!(resolve_prepared_publication(Ok(()), true).is_ok());
        assert!(resolve_prepared_publication(Ok(()), false).is_err());
        assert!(resolve_prepared_publication(Err("before rename".into()), false).is_err());
        assert!(resolve_prepared_publication(Err("after rename".into()), true).is_ok());
    }

    #[test]
    fn committed_ready_marker_freeze_failure_blocks_init_trigger() {
        let trigger_called = std::cell::Cell::new(false);
        let freeze_failure = retry_committed_actions(
            || Err("native or generation freeze cut".into()),
            || {
                trigger_called.set(true);
                Ok(())
            },
        );
        assert!(freeze_failure.is_err());
        assert!(!trigger_called.get());
    }

    #[test]
    fn committed_init_trigger_failure_remains_retryable() {
        let trigger_failure = retry_committed_actions(|| Ok(()), || Err("ctl.start cut".into()));
        assert!(trigger_failure.is_err());
        assert!(retry_committed_actions(|| Ok(()), || Ok(())).is_ok());
    }

    #[test]
    fn fixed_init_trigger_is_exact() {
        assert_eq!(INIT_CONTROL_PROPERTY, "ctl.start");
        assert_eq!(INIT_SERVICE, "voboost-uninstall");
    }

    #[test]
    fn uninstall_directory_rejects_symlink_parent() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        symlink(target.path(), root.path().join(UNINSTALL_CHILD)).unwrap();
        assert!(open_uninstall_dir_at(root.path()).is_err());
    }

    #[test]
    fn opened_uninstall_directory_is_stable_across_parent_path_swap() {
        let root = tempfile::tempdir().unwrap();
        let original = open_uninstall_dir_at(root.path()).unwrap();
        let moved = root.path().join("uninstall-old");
        std::fs::rename(root.path().join(UNINSTALL_CHILD), &moved).unwrap();
        std::fs::create_dir(root.path().join(UNINSTALL_CHILD)).unwrap();
        write_fixed(&original, STATUS_FILE, b"stable\n").unwrap();
        assert_eq!(std::fs::read(moved.join(STATUS_FILE)).unwrap(), b"stable\n");
        assert!(!root.path().join(UNINSTALL_CHILD).join(STATUS_FILE).exists());
    }

    #[test]
    fn prepared_operation_state_uses_only_the_correlated_recovery_transaction() {
        let root = tempfile::tempdir().unwrap();
        let transaction_id = "11".repeat(32);
        let recovery = open_or_create_recovery_transaction(root.path(), &transaction_id).unwrap();
        write_fixed(&recovery, MARKER_FILE, MARKER_BYTES).unwrap();
        assert_eq!(
            std::fs::read(
                root.path()
                    .join(RECOVERY_CHILD)
                    .join(&transaction_id)
                    .join(MARKER_FILE)
            )
            .unwrap(),
            MARKER_BYTES
        );
        assert!(!root.path().join(UNINSTALL_CHILD).join(MARKER_FILE).exists());
        assert!(open_recovery_transaction_existing(root.path(), &transaction_id).is_ok());

        let recovery_root = Directory::open(&root.path().join(RECOVERY_CHILD)).unwrap();
        recovery_root
            .create_private_child(&"22".repeat(32))
            .unwrap();
        assert!(open_recovery_transaction_existing(root.path(), &transaction_id).is_err());
    }

    #[test]
    fn uninstall_authority_rejects_foreign_hard_link() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let dir = open_uninstall_dir_at(root.path()).unwrap();
        let foreign = root.path().join("foreign");
        std::fs::write(&foreign, b"foreign").unwrap();
        std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(
            &foreign,
            root.path().join(UNINSTALL_CHILD).join(MARKER_FILE),
        )
        .unwrap();
        assert!(write_fixed(&dir, MARKER_FILE, MARKER_BYTES).is_err());
        assert_eq!(std::fs::read(&foreign).unwrap(), b"foreign");
    }
}
