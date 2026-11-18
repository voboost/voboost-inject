use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use voboost_contract::resource_none_helper;
use voboost_shared::diagnostic_log::{
    self, Level as DiagnosticLevel, Service as DiagnosticService,
};
#[path = "../../shared/src/i18n_resource_files.rs"]
mod i18n_resource_files;
mod selinux_backend;
use std::time::Duration;

use voboost_shared::installed_apk;
use voboost_shared::mount_policy_transaction;
use voboost_shared::native_executable_signature;
mod product_system;
mod request;
use voboost_shared::protected_system_transaction;
#[allow(unused_imports)]
use voboost_shared::secure_fs;
use voboost_shared::self_executable;
#[allow(unused_imports)]
use voboost_shared::uninstall_contract;

include!(concat!(env!("OUT_DIR"), "/embedded_keys.rs"));

use operation_contract::{read_active_in, Operation, OperationDescriptor, OperationLease};
use voboost_contract::operation as operation_contract;

use voboost_shared::fixed_process;

const STABLE: &str = "/data/voboost/voboost-restore";
const DESCRIPTOR: &str = "/data/voboost/restore.json";
const DESCRIPTOR_SIG: &str = "/data/voboost/restore.json.sig";
const INVENTORY: &str = "/data/voboost/uninstall/install-inventory.json";
const INSTALL_STATE: &str = "/data/voboost/install/state.json";

fn installed_inventory_path() -> Result<&'static str, String> {
    let path = voboost_shared::installed_state::path(Path::new("/data/voboost"))
        .map_err(|error| error.to_string())?;
    if path == Path::new(INSTALL_STATE) {
        Ok(INSTALL_STATE)
    } else if path == Path::new(INVENTORY) {
        Ok(INVENTORY)
    } else {
        Err("installed state path differs".into())
    }
}
const SYSTEM_ARTIFACTS: &str = "/data/voboost/uninstall/system-artifacts.json";
const CURRENT_BASELINE: &str = "/data/voboost/uninstall/current-baseline.json";
const POLICY_META: &str = "/data/voboost/uninstall/policy.meta.json";
const SYSTEM_STATE: &str = "/data/voboost/uninstall/system-state.json";
const INIT_ARCHIVE: &str = "/data/voboost/uninstall/system/voboost.rc";
const INIT_HOOK: &str = "/system/etc/init/voboost.rc";
const POLICY: &str = "/vendor/etc/selinux/precompiled_sepolicy";
const SELINUX: &str = "/data/voboost/voboost-selinux";
const RECOVERY: &str = "/data/voboost/recovery";
const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";
const MAX_POLICY: u64 = 64 * 1024 * 1024;
const MAX_DOCUMENT: u64 = 1024 * 1024;
#[cfg(any(target_os = "android", target_os = "linux"))]
const SELINUX_XATTR: &[u8] = b"security.selinux\0";
const PRODUCT_ROOT: &str = "/data/voboost";
const ACTIVE_GENERATION: &str = "/data/voboost/generations/current";

use voboost_contract::release::{ArtifactRole, Manifest, RestoreDocument};
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Artifact {
    path: Option<String>,
    size: u64,
    sha256: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ArchivedInitMetadata {
    path: String,
    installed_size: u64,
    installed_sha256: String,
    archive_path: String,
    uid: u32,
    gid: u32,
    mode: String,
    context: String,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
#[allow(clippy::enum_variant_names)] // Operation-first names are the external WAL vocabulary.
enum Phase {
    RestorePrepare,
    RestoreFirmwareVerify,
    RestorePolicyBackup,
    RestorePolicyApply,
    RestoreRebootFirst,
    RestoreRuntimeApply,
    RestoreRebootSecond,
    RestoreRuntimeVerify,
    RestoreInventoryCommit,
    RestoreCleanup,
    RestoreComplete,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Journal {
    schema_version: u32,
    phase: Phase,
    transaction_id: String,
    restore_document_sha256: String,
    restore_signature_sha256: String,
    product_manifest_sha256: String,
    restorable_closure_sha256: String,
    install_inventory_sha256: String,
    release_identity: String,
    pristine_policy: Artifact,
    patched_policy: Option<Artifact>,
    first_boot_id: String,
    second_boot_id: Option<String>,
}
struct Paths {
    root: PathBuf,
    journal: PathBuf,
    baseline: PathBuf,
    patched: PathBuf,
    commit_root: PathBuf,
    commit_journal: PathBuf,
    remount_wal: PathBuf,
    policy_mount_wal: PathBuf,
    authorization: PathBuf,
    product_target: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunMode {
    Request,
    InitContinuation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum InitAdmission {
    Noop,
    Resume(String),
    Cleanup(String),
}

impl RunMode {
    fn may_create(self) -> bool {
        self == Self::Request
    }
}

fn select_existing_or_create<T>(
    mode: RunMode,
    existing: Option<T>,
    create: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    match existing {
        Some(value) => Ok(value),
        None if mode.may_create() => create(),
        None => Err("admitted active restore disappeared".into()),
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommitMember {
    path: String,
    temporary_path: String,
    old: Artifact,
    target: Artifact,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommitJournal {
    schema_version: u32,
    transaction_id: String,
    old_baseline_path: String,
    new_baseline_path: String,
    members: Vec<CommitMember>,
}

fn post_second_boot(first: &str, second: &str, current: &str) -> Result<(), String> {
    if first == second || second == current {
        Err("restore has not reached a distinct post-second-reboot boot".into())
    } else {
        Ok(())
    }
}

fn artifact_matches(bytes: &[u8], artifact: &Artifact) -> bool {
    bytes.len() as u64 == artifact.size && digest(bytes) == artifact.sha256
}

/// The install-committed pristine policy baseline: the metadata the install
/// committed and the exact baseline bytes the install archived under
/// /data/voboost/uninstall/baselines/<sha>/. Returns None when no committed
/// baseline exists (a restore over a machine that never had the product
/// installed keeps using the live policy bytes as the firmware baseline).
fn installed_policy_baseline() -> Option<Artifact> {
    let meta: serde_json::Value = serde_json::from_slice(
        &crate::read_bound(Path::new(POLICY_META), MAX_DOCUMENT, 0o600).ok()?,
    )
    .ok()?;
    let sha256 = meta.get("sha256").and_then(|v| v.as_str())?.to_owned();
    if hex(&sha256).is_err() {
        return None;
    }
    let backup_path = match uninstall_contract::baseline_backup_path(&sha256) {
        Ok(value) => value,
        Err(_) => return None,
    };
    let backup = match crate::read_bound(Path::new(&backup_path), MAX_POLICY, 0o600) {
        Ok(bytes) => bytes,
        Err(_) => return None,
    };
    if digest(&backup) != sha256 {
        return None;
    }
    Some(Artifact {
        path: Some(POLICY.to_string()),
        size: backup.len() as u64,
        sha256,
    })
}

/// Result-typed pairing of the committed baseline artifact and its exact
/// bytes, used by firmware_verify when the live policy differs from the
/// journaled pristine baseline and the committed archive must exist.
fn installed_policy_baseline_pair() -> Option<(Artifact, Vec<u8>)> {
    let artifact = installed_policy_baseline()?;
    let backup_path = uninstall_contract::baseline_backup_path(&artifact.sha256).ok()?;
    let backup = crate::read_bound(Path::new(&backup_path), MAX_POLICY, 0o600).ok()?;
    if digest(&backup) != artifact.sha256 {
        return None;
    }
    Some((artifact, backup))
}

impl Paths {
    fn new(tx: &str) -> Result<Self, String> {
        hex(tx)?;
        let root = Path::new(RECOVERY).join(tx);
        Ok(Self {
            journal: root.join("restore-journal.json"),
            baseline: root.join("oem-policy-baseline"),
            patched: root.join("voboost-policy.patched"),
            commit_root: root.join("inventory-commit"),
            commit_journal: root.join("inventory-commit.json"),
            remount_wal: root.join("init-remount.json"),
            policy_mount_wal: root.join("policy-mount.json"),
            authorization: root.join("authorization"),
            product_target: root.join("product-target"),
            root,
        })
    }
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hex(value: &str) -> Result<(), String> {
    (value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then_some(())
    .ok_or_else(|| "non-canonical SHA-256".into())
}
fn read_bound(path: &Path, maximum: u64, mode: u32) -> Result<Vec<u8>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    let before = file.metadata().map_err(|e| e.to_string())?;
    // Trusted-file owner: root on Android, the effective user on the host
    // builds (the test suites and the Linux root harness — uid 0 there).
    #[cfg(target_os = "android")]
    let (owner_uid, owner_gid) = (0, 0);
    #[cfg(not(target_os = "android"))]
    let (owner_uid, owner_gid) = (unsafe { libc::geteuid() }, unsafe { libc::getegid() });
    if !before.is_file()
        || before.uid() != owner_uid
        || before.gid() != owner_gid
        || before.nlink() != 1
        || before.mode() & 0o7777 != mode
        || before.len() == 0
        || before.len() > maximum
    {
        return Err(format!("{} has a foreign identity", path.display()));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
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
    ) || bytes.len() as u64 != before.len()
        || bytes.len() as u64 > maximum
    {
        return Err(format!("{} changed while reading", path.display()));
    }
    Ok(bytes)
}
fn io_failure(action: &str, path: &Path, error: impl std::fmt::Display) -> String {
    format!("{action} {}: {error}", path.display())
}

fn sync_parent(path: &Path) -> Result<(), String> {
    File::open(path.parent().ok_or("path has no parent")?)
        .and_then(|f| f.sync_all())
        .map_err(|e| io_failure("sync parent of", path, e))
}
fn atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let temp = path.with_file_name(format!(
        ".{}.tmp",
        path.file_name().ok_or("missing leaf")?.to_string_lossy()
    ));
    if temp.exists() {
        fs::remove_file(&temp).map_err(|e| io_failure("remove stale temporary", &temp, e))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&temp)
        .map_err(|e| io_failure("create temporary", &temp, e))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| io_failure("write/sync temporary", &temp, e))?;
    fs::rename(&temp, path).map_err(|e| io_failure("commit temporary to", path, e))?;
    sync_parent(path)
}
fn json<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    Ok(bytes)
}
fn mkdir(path: &Path) -> Result<(), String> {
    if !path.exists() {
        fs::create_dir(path).map_err(|e| io_failure("create recovery directory", path, e))?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|e| io_failure("set recovery directory permissions", path, e))?;
    sync_parent(path)
}
fn verify_raw_restore_signature(bytes: &[u8], signature: &[u8]) -> Result<(), String> {
    VerifyingKey::from_bytes(&RESTORE_PUBLIC_KEY)
        .map_err(|_| "restore.json public key is invalid".to_string())?
        .verify_strict(
            bytes,
            &Signature::from_slice(signature)
                .map_err(|_| "restore.json signature is not raw Ed25519".to_string())?,
        )
        .map_err(|_| "restore.json signature is invalid".to_string())
}

fn verify_product_authority(
    manifest_bytes: &[u8],
    manifest_signature: &[u8],
    restore_bytes: &[u8],
    restore_signature: &[u8],
) -> Result<(Manifest, RestoreDocument), String> {
    let manifest = voboost_contract::release::verify_manifest_signature(
        manifest_bytes,
        manifest_signature,
        &RELEASE_CATALOG_PUBLIC_KEY,
    )?;
    verify_artifact_bytes(&manifest, "restore.json", restore_bytes)?;
    verify_artifact_bytes(&manifest, "restore.json.sig", restore_signature)?;
    verify_raw_restore_signature(restore_bytes, restore_signature)?;
    let restore = voboost_contract::release::verify_restore_authority(
        &manifest,
        restore_bytes,
        restore_signature,
        &RESTORE_PUBLIC_KEY,
    )?;
    Ok((manifest, restore))
}

fn fixed_product_authority() -> Result<(Manifest, RestoreDocument, [Vec<u8>; 4]), String> {
    let manifest = read_bound(
        Path::new(PRODUCT_ROOT)
            .join(voboost_contract::release::MANIFEST_NAME)
            .as_path(),
        voboost_contract::release::MAX_MANIFEST_BYTES as u64,
        0o600,
    )?;
    let manifest_signature = read_bound(
        Path::new(PRODUCT_ROOT)
            .join(voboost_contract::release::MANIFEST_SIGNATURE_NAME)
            .as_path(),
        64,
        0o600,
    )?;
    let restore = read_bound(Path::new(DESCRIPTOR), 4096, 0o644)?;
    let restore_signature = read_bound(Path::new(DESCRIPTOR_SIG), 64, 0o644)?;
    let (product, document) =
        verify_product_authority(&manifest, &manifest_signature, &restore, &restore_signature)?;
    Ok((
        product,
        document,
        [manifest, manifest_signature, restore, restore_signature],
    ))
}

fn verify_artifact_bytes(manifest: &Manifest, name: &str, bytes: &[u8]) -> Result<(), String> {
    let artifact = manifest.artifact(name)?;
    if artifact.size != bytes.len() as u64 || artifact.sha256 != digest(bytes) {
        return Err(format!("installed {name} differs from voboost.json"));
    }
    Ok(())
}
fn verify_self() -> Result<(), String> {
    let bytes =
        self_executable::read_self_executable(Path::new(STABLE), 8 * 1024 * 1024, 0o700, 0, 0)
            .map_err(|error| format!("verify restore executable {STABLE}: {error}"))?;
    if bytes.len() < 80 {
        return Err("signature trailer absent".into());
    }
    let trailer = &bytes[bytes.len() - 80..];
    let size = checked_trailer_prefix(
        u64::from_le_bytes(trailer[8..16].try_into().map_err(|_| "bad trailer")?),
        (bytes.len() - 80) as u64,
    )?;
    if &trailer[..8] != b"VOBOOST\0" {
        return Err("bad signature trailer".into());
    }
    VerifyingKey::from_bytes(&NATIVE_EXECUTABLE_PUBKEY)
        .map_err(|e| e.to_string())?
        .verify(
            &native_executable_signature::transcript(
                native_executable_signature::NativeExecutableRole::Restore,
                &bytes[..size],
            )
            .ok_or("signature transcript overflow")?,
            &Signature::from_slice(&trailer[16..]).map_err(|e| e.to_string())?,
        )
        .map_err(|_| "executable signature is invalid".into())
}

fn checked_trailer_prefix(appended_offset: u64, actual_prefix: u64) -> Result<usize, String> {
    if appended_offset != actual_prefix {
        return Err("bad signature trailer".into());
    }
    usize::try_from(appended_offset)
        .map_err(|_| "signature trailer offset exceeds address space".into())
}
fn boot_id() -> Result<String, String> {
    let text = fs::read_to_string(BOOT_ID)
        .map_err(|e| io_failure("read boot identity", Path::new(BOOT_ID), e))?;
    let id = text.strip_suffix('\n').ok_or("boot id lacks newline")?;
    (id.len() == 36)
        .then(|| id.to_string())
        .ok_or_else(|| "invalid boot id".into())
}
#[cfg(not(test))]
fn operation_boot_id() -> Result<String, String> {
    boot_id()
}
#[cfg(test)]
fn operation_boot_id() -> Result<String, String> {
    Ok("00000000-0000-0000-0000-000000000001".to_string())
}
fn command(program: &str, args: &[&str]) -> Result<(), String> {
    fixed_process::status(program, args, Duration::from_secs(35))?
        .then_some(())
        .ok_or_else(|| format!("{program} failed"))
}
fn persist_journal(paths: &Paths, journal: &Journal) -> Result<(), String> {
    atomic(&paths.journal, &json(journal)?)?;
    Ok(())
}

fn persist(paths: &Paths, journal: &Journal, lease: &OperationLease) -> Result<(), String> {
    persist_journal(paths, journal)?;
    lease.publish(&restore_operation_document(journal, None)?)
}

fn restore_operation_document(
    journal: &Journal,
    failure: Option<&str>,
) -> Result<OperationDescriptor, String> {
    let (normal_outcome, reboot_count) = match journal.phase {
        Phase::RestoreRebootFirst => ("reboot-required", 1),
        Phase::RestoreRebootSecond => ("reboot-required", 2),
        Phase::RestoreComplete => ("complete", 2),
        Phase::RestoreRuntimeVerify | Phase::RestoreInventoryCommit | Phase::RestoreCleanup => {
            ("running", 2)
        }
        Phase::RestoreRuntimeApply => ("running", 1),
        _ => ("running", 0),
    };
    let outcome = if failure.is_some() {
        "failed"
    } else {
        normal_outcome
    };
    let offset = match outcome {
        "running" => 1,
        "reboot-required" => 2,
        "complete" | "failed" => 3,
        _ => return Err("restore operation outcome is invalid".to_string()),
    };
    let error = failure.map(|message| {
        let message = bounded_restore_error(message);
        serde_json::json!({
            "code": "restore-failed",
            "message": if message.is_empty() { "internal restore failure".to_string() } else { message }
        })
    });
    Ok(OperationDescriptor {
        schema_version: 1,
        operation: Operation::Restore,
        transaction_id: journal.transaction_id.clone(),
        journal: format!("recovery/{}/restore-journal.json", journal.transaction_id),
        phase: serde_json::to_value(journal.phase)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string(),
        outcome: outcome.to_string(),
        reboot_count,
        boot_id: operation_boot_id()?,
        status_sequence: (journal.phase as u64) * 3 + offset,
        journal_sha256: digest(&json(journal)?),
        error,
        installed_apk: None,
    })
}
fn validate_journal(journal: &Journal) -> Result<(), String> {
    if journal.schema_version != 1
        || journal.release_identity.is_empty()
        || journal.release_identity.len() > voboost_contract::release::MAX_RELEASE_IDENTITY_BYTES
        || journal
            .release_identity
            .bytes()
            .any(|byte| byte.is_ascii_control())
        || journal.pristine_policy.path.as_deref() != Some(POLICY)
    {
        return Err("restore journal contract is invalid".into());
    }
    for value in [
        &journal.transaction_id,
        &journal.restore_document_sha256,
        &journal.restore_signature_sha256,
        &journal.product_manifest_sha256,
        &journal.restorable_closure_sha256,
        &journal.install_inventory_sha256,
        &journal.pristine_policy.sha256,
    ] {
        hex(value)?;
    }
    if let Some(patched) = &journal.patched_policy {
        if patched.path.as_deref() != Some(POLICY) {
            return Err("restore patched-policy binding is invalid".into());
        }
        hex(&patched.sha256)?;
    }
    if matches!(
        journal.phase,
        Phase::RestorePolicyApply
            | Phase::RestoreRebootFirst
            | Phase::RestoreRuntimeApply
            | Phase::RestoreRebootSecond
            | Phase::RestoreRuntimeVerify
            | Phase::RestoreInventoryCommit
            | Phase::RestoreCleanup
            | Phase::RestoreComplete
    ) && journal.patched_policy.is_none()
    {
        return Err("restore journal lacks the expected patched policy".into());
    }
    Ok(())
}

fn operation_transaction_id(
    restore_bytes: &[u8],
    signature: &[u8],
    manifest_sha256: &str,
    boot_id: &str,
) -> String {
    let mut material = Vec::with_capacity(
        restore_bytes.len() + signature.len() + manifest_sha256.len() + boot_id.len(),
    );
    material.extend_from_slice(restore_bytes);
    material.extend_from_slice(signature);
    material.extend_from_slice(manifest_sha256.as_bytes());
    material.extend_from_slice(boot_id.as_bytes());
    digest(&material)
}

fn stage_product_authority(
    paths: &Paths,
    authority: &[Vec<u8>; 4],
    lease: &OperationLease,
) -> Result<(), String> {
    lease.verify_owner()?;
    mkdir(&paths.authorization)?;
    for (name, bytes) in [
        (voboost_contract::release::MANIFEST_NAME, &authority[0]),
        (
            voboost_contract::release::MANIFEST_SIGNATURE_NAME,
            &authority[1],
        ),
        (voboost_contract::release::RESTORE_NAME, &authority[2]),
        (
            voboost_contract::release::RESTORE_SIGNATURE_NAME,
            &authority[3],
        ),
    ] {
        lease.verify_owner()?;
        let path = paths.authorization.join(name);
        if path.exists() {
            if read_bound(
                &path,
                voboost_contract::release::MAX_MANIFEST_BYTES as u64,
                0o600,
            )? != *bytes
            {
                return Err("product authority collision".into());
            }
        } else {
            atomic(&path, bytes)?;
        }
    }
    Ok(())
}

fn root_flat_mode(role: ArtifactRole) -> Option<u32> {
    match role {
        ArtifactRole::Daemon
        | ArtifactRole::Inject
        | ArtifactRole::Install
        | ArtifactRole::Restore
        | ArtifactRole::Uninstall
        | ArtifactRole::Selinux
        | ArtifactRole::QnxDaemon
        | ArtifactRole::QnxInit => Some(0o700),
        ArtifactRole::Init
        | ArtifactRole::Implant
        | ArtifactRole::Lsplant
        | ArtifactRole::QnxImplant => Some(0o644),
        _ => None,
    }
}

fn active_generation_directory() -> Result<PathBuf, String> {
    let pointer = read_bound(Path::new(ACTIVE_GENERATION), 65, 0o444)?;
    let id = std::str::from_utf8(&pointer)
        .map_err(|_| "active generation pointer is not UTF-8")?
        .strip_suffix('\n')
        .ok_or("active generation pointer lacks newline")?;
    hex(id)?;
    let path = Path::new(PRODUCT_ROOT).join("generations").join(id);
    let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.permissions().mode() & 0o7777 != 0o555
    {
        return Err("active generation directory has a foreign identity".into());
    }
    Ok(path)
}

fn read_installed_apk(artifact: &voboost_contract::release::Artifact) -> Result<Vec<u8>, String> {
    let path = installed_apk::observe_installed_apk(artifact.size, &artifact.sha256)?;
    let path = std::ffi::CString::new(path).map_err(|_| "installed APK path contains NUL")?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(format!(
            "open installed APK closure: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let before = file.metadata().map_err(|error| error.to_string())?;
    if !before.is_file() || before.nlink() != 1 || before.len() != artifact.size {
        return Err("installed APK closure identity differs".into());
    }
    let maximum = artifact
        .size
        .checked_add(1)
        .ok_or("installed APK size overflow")?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let after = file.metadata().map_err(|error| error.to_string())?;
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
        return Err("installed APK changed while staging restore closure".into());
    }
    if bytes.len() as u64 != artifact.size || digest(&bytes) != artifact.sha256 {
        return Err("installed APK closure differs from voboost.json".into());
    }
    Ok(bytes)
}

fn read_live_product_artifact(
    artifact: &voboost_contract::release::Artifact,
    generation: Option<&Path>,
) -> Result<Vec<u8>, String> {
    read_live_product_artifact_in(Path::new(PRODUCT_ROOT), artifact, generation)
}

fn read_live_product_artifact_in(
    root: &Path,
    artifact: &voboost_contract::release::Artifact,
    generation: Option<&Path>,
) -> Result<Vec<u8>, String> {
    if artifact.role == ArtifactRole::App {
        return read_installed_apk(artifact);
    }
    let (path, mode) = if matches!(
        artifact.role,
        ArtifactRole::AgentCatalog
            | ArtifactRole::AgentCatalogSignature
            | ArtifactRole::AgentCommon
            | ArtifactRole::AgentModule
            | ArtifactRole::QnxRuntime
            | ArtifactRole::QnxAgentModule
            | ArtifactRole::ResourceApk
            | ArtifactRole::ResourceLedger
            | ArtifactRole::QnxResourcePack
            | ArtifactRole::QnxResourceLedger
    ) {
        (
            generation
                .ok_or("product manifest requires an active generation")?
                .join(&artifact.file),
            0o444,
        )
    } else {
        (
            root.join(&artifact.file),
            root_flat_mode(artifact.role)
                .ok_or_else(|| format!("{} has no installed restore authority", artifact.file))?,
        )
    };
    let bytes = read_bound(&path, artifact.size, mode)?;
    if bytes.len() as u64 != artifact.size || digest(&bytes) != artifact.sha256 {
        return Err(format!(
            "installed {} differs from voboost.json",
            artifact.file
        ));
    }
    Ok(bytes)
}

fn stage_product_closure(
    paths: &Paths,
    manifest: &Manifest,
    lease: &OperationLease,
) -> Result<(), String> {
    mkdir(&paths.product_target)?;
    let needs_generation = manifest.artifacts.iter().any(|artifact| {
        matches!(
            artifact.role,
            ArtifactRole::AgentCatalog
                | ArtifactRole::AgentCatalogSignature
                | ArtifactRole::AgentCommon
                | ArtifactRole::AgentModule
                | ArtifactRole::QnxRuntime
                | ArtifactRole::QnxAgentModule
                | ArtifactRole::ResourceApk
                | ArtifactRole::ResourceLedger
                | ArtifactRole::QnxResourcePack
                | ArtifactRole::QnxResourceLedger
        )
    });
    let generation = needs_generation
        .then(active_generation_directory)
        .transpose()?;
    for artifact in manifest.artifacts.iter().filter(|artifact| {
        !matches!(
            artifact.role,
            ArtifactRole::RestoreAuthorization | ArtifactRole::RestoreSignature
        )
    }) {
        lease.verify_owner()?;
        let bytes = read_live_product_artifact(artifact, generation.as_deref())?;
        let staged = paths.product_target.join(&artifact.file);
        if staged.exists() {
            if read_bound(&staged, artifact.size, 0o600)? != bytes {
                return Err("restore product target collision".into());
            }
        } else {
            atomic(&staged, &bytes)?;
        }
    }
    Ok(())
}

fn staged_product_authority(
    paths: &Paths,
    journal: &Journal,
) -> Result<(Manifest, RestoreDocument), String> {
    let manifest = read_bound(
        &paths
            .authorization
            .join(voboost_contract::release::MANIFEST_NAME),
        voboost_contract::release::MAX_MANIFEST_BYTES as u64,
        0o600,
    )?;
    let manifest_signature = read_bound(
        &paths
            .authorization
            .join(voboost_contract::release::MANIFEST_SIGNATURE_NAME),
        64,
        0o600,
    )?;
    let restore = read_bound(
        &paths
            .authorization
            .join(voboost_contract::release::RESTORE_NAME),
        voboost_contract::release::MAX_RESTORE_BYTES as u64,
        0o600,
    )?;
    let restore_signature = read_bound(
        &paths
            .authorization
            .join(voboost_contract::release::RESTORE_SIGNATURE_NAME),
        64,
        0o600,
    )?;
    let (manifest_value, restore_value) =
        verify_product_authority(&manifest, &manifest_signature, &restore, &restore_signature)?;
    if digest(&manifest) != journal.product_manifest_sha256
        || digest(&restore) != journal.restore_document_sha256
        || digest(&restore_signature) != journal.restore_signature_sha256
        || manifest_value.release_identity != journal.release_identity
        || restore_value.restorable_closure_sha256 != journal.restorable_closure_sha256
    {
        return Err("staged product authority differs from restore journal".into());
    }
    verify_restorable_closure_with(&manifest_value, |artifact| {
        read_bound(
            &paths.product_target.join(&artifact.file),
            artifact.size,
            0o600,
        )
    })?;
    let staged_init = read_bound(
        &paths.product_target.join("voboost.rc"),
        manifest_value.artifact("voboost.rc")?.size,
        0o600,
    )?;
    if read_bound(Path::new(INIT_ARCHIVE), MAX_DOCUMENT, 0o600)? != staged_init {
        return Err("committed init archive differs from voboost.json".into());
    }
    Ok((manifest_value, restore_value))
}

fn verify_restorable_closure_with(
    manifest: &Manifest,
    mut read: impl FnMut(&voboost_contract::release::Artifact) -> Result<Vec<u8>, String>,
) -> Result<(), String> {
    for artifact in manifest.artifacts.iter().filter(|artifact| {
        !matches!(
            artifact.role,
            ArtifactRole::RestoreAuthorization | ArtifactRole::RestoreSignature
        )
    }) {
        verify_artifact_bytes(manifest, &artifact.file, &read(artifact)?)?;
    }
    Ok(())
}

fn apply_target_product_closure(
    paths: &Paths,
    manifest: &Manifest,
    transaction_id: &str,
) -> Result<(), String> {
    for artifact in manifest
        .artifacts
        .iter()
        .filter(|artifact| root_flat_mode(artifact.role).is_some())
    {
        let mode = root_flat_mode(artifact.role).unwrap();
        let live = Path::new(PRODUCT_ROOT).join(&artifact.file);
        let staged = read_bound(
            &paths.product_target.join(&artifact.file),
            artifact.size,
            0o600,
        )?;
        publish_exact(&live, &staged, &live, transaction_id)?;
        let applied = read_bound(&live, artifact.size, mode)?;
        verify_artifact_bytes(manifest, &artifact.file, &applied)?;
    }
    Ok(())
}

fn verify_live_product_closure(paths: &Paths, manifest: &Manifest) -> Result<(), String> {
    let needs_generation = manifest.artifacts.iter().any(|artifact| {
        matches!(
            artifact.role,
            ArtifactRole::AgentCatalog
                | ArtifactRole::AgentCatalogSignature
                | ArtifactRole::AgentCommon
                | ArtifactRole::AgentModule
                | ArtifactRole::QnxRuntime
                | ArtifactRole::QnxAgentModule
                | ArtifactRole::ResourceApk
                | ArtifactRole::ResourceLedger
                | ArtifactRole::QnxResourcePack
                | ArtifactRole::QnxResourceLedger
        )
    });
    let generation = needs_generation
        .then(active_generation_directory)
        .transpose()?;
    for artifact in manifest.artifacts.iter().filter(|artifact| {
        !matches!(
            artifact.role,
            ArtifactRole::RestoreAuthorization | ArtifactRole::RestoreSignature
        )
    }) {
        let staged = read_bound(
            &paths.product_target.join(&artifact.file),
            artifact.size,
            0o600,
        )?;
        let live = read_live_product_artifact(artifact, generation.as_deref())?;
        if live != staged {
            return Err(format!(
                "installed {} changed from the staged restore target",
                artifact.file
            ));
        }
    }
    Ok(())
}

/// Publish a complete Prepare directory atomically from private run staging.
/// Interrupted mkdir/write cuts stay outside the recovery transaction namespace.
fn stage_prepare(
    root_path: &Path,
    journal: &Journal,
    guard: &operation_contract::GenerationGuard,
) -> Result<(), String> {
    guard.verify_owner()?;
    let root = secure_fs::Directory::open(root_path).map_err(|e| e.to_string())?;
    let run = root.open_child("run").map_err(|e| e.to_string())?;
    run.validate_owner_mode(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        0o755,
    )
    .map_err(|e| e.to_string())?;
    let stage = run
        .open_or_create_private_child("restore-prepare")
        .map_err(|e| e.to_string())?;
    let names = stage.entry_names_bounded(3).map_err(|e| e.to_string())?;
    for name in names {
        if name != "restore-journal.json" && name != ".restore-journal.json.tmp" {
            return Err("restore Prepare staging has foreign members".into());
        }
        stage
            .validate_optional_trusted_file(&name, 0o600)
            .map_err(|e| e.to_string())?;
    }
    let bytes = json(journal)?;
    stage
        .write_atomic("restore-journal.json", &bytes, 0o600)
        .map_err(|e| e.to_string())?;
    if stage.entry_names_bounded(2).map_err(|e| e.to_string())? != ["restore-journal.json"]
        || stage
            .read_trusted("restore-journal.json", 4096, 0o600)
            .map_err(|e| e.to_string())?
            != bytes
    {
        return Err("restore Prepare staging differs before publication".into());
    }
    let recovery = root
        .open_or_create_private_child("recovery")
        .map_err(|e| e.to_string())?;
    if !recovery
        .entry_names_bounded(1)
        .map_err(|e| e.to_string())?
        .is_empty()
    {
        return Err("restore recovery namespace changed before Prepare publication".into());
    }
    guard.verify_owner()?;
    run.rename_to("restore-prepare", &recovery, &journal.transaction_id)
        .map_err(|e| format!("publish complete restore Prepare directory: {e}"))?;
    guard.verify_owner()
}

/// Reconcile only a fully authenticated, never-admitted Prepare WAL.
/// Caller retains the idle global barrier; active operations never reach here.
fn reconcile_unleased_prepare(
    root_path: &Path,
    expected: &Journal,
    authority: &[Vec<u8>; 4],
    guard: &operation_contract::GenerationGuard,
) -> Result<Option<Journal>, String> {
    guard.verify_owner()?;
    let root = secure_fs::Directory::open(root_path).map_err(|e| e.to_string())?;
    let recovery = match root.open_child("recovery") {
        Ok(dir) => dir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("open unleased restore recovery: {e}")),
    };
    recovery
        .validate_owner_mode(
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o700,
        )
        .map_err(|e| e.to_string())?;
    let names = recovery.entry_names_bounded(2).map_err(|e| e.to_string())?;
    if names.is_empty() {
        return Ok(None);
    }
    if names.len() != 1 || hex(&names[0]).is_err() {
        return Err("unleased restore recovery has foreign or multiple members".into());
    }
    let name = &names[0];
    let dir = recovery
        .open_child(name)
        .map_err(|e| format!("open unleased restore transaction: {e}"))?;
    dir.validate_owner_mode(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        0o700,
    )
    .map_err(|e| e.to_string())?;
    if dir.entry_names_bounded(2).map_err(|e| e.to_string())? != ["restore-journal.json"] {
        return Err("unleased restore transaction has foreign or advanced members".into());
    }
    let bytes = dir
        .read_trusted("restore-journal.json", 4096, 0o600)
        .map_err(|e| e.to_string())?;
    let journal: Journal = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parse unleased restore prepare: {e}"))?;
    validate_journal(&journal)?;
    let mut authenticated = expected.clone();
    authenticated.first_boot_id = journal.first_boot_id.clone();
    // Bind the old boot to the signed authority; never borrow the current boot.
    if journal.first_boot_id.len() != 36
        || !journal.first_boot_id.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
    {
        return Err("unleased restore prepare has invalid boot identity".into());
    }
    authenticated.transaction_id = operation_transaction_id(
        &authority[2],
        &authority[3],
        &expected.product_manifest_sha256,
        &journal.first_boot_id,
    );
    if journal != authenticated || name != &authenticated.transaction_id || json(&journal)? != bytes
    {
        return Err("unleased restore prepare differs from installed signed authority".into());
    }
    guard.verify_owner()?;
    // Re-read before adopting the exact sole member; never recursively clean.
    if dir
        .read_trusted("restore-journal.json", 4096, 0o600)
        .map_err(|e| e.to_string())?
        != bytes
        || dir.entry_names_bounded(2).map_err(|e| e.to_string())? != ["restore-journal.json"]
    {
        return Err("unleased restore prepare changed during reconciliation".into());
    }
    // Adopt the authenticated WAL without a destructive cleanup crash cut.
    // Promotion publishes its descriptor while the same global lock is held.
    guard.verify_owner()?;
    Ok(Some(journal))
}

fn active_restore() -> Result<Option<(Paths, Journal)>, String> {
    let Some(pointer) = read_active_in(Path::new("/data/voboost"))? else {
        return Ok(None);
    };
    if pointer.operation != Operation::Restore {
        return Err("another global operation is active".into());
    }
    let paths = Paths::new(&pointer.transaction_id)?;
    if pointer.journal != format!("recovery/{}/restore-journal.json", pointer.transaction_id)
        || paths.journal != Path::new("/data/voboost").join(&pointer.journal)
    {
        return Err("active restore pointer does not name its fixed journal".into());
    }
    let journal: Journal = serde_json::from_slice(&read_bound(&paths.journal, 4096, 0o600)?)
        .map_err(|e| format!("parse active restore journal: {e}"))?;
    validate_journal(&journal)?;
    if journal.transaction_id != pointer.transaction_id {
        return Err("active restore pointer and journal disagree".into());
    }
    Ok(Some((paths, journal)))
}
fn reject_cluster_uninstall(root: &Path) -> Result<(), String> {
    voboost_shared::cluster_mailbox::reject_pending_uninstall(
        root,
        &[
            &AGENT_CATALOG_PUBLIC_KEY,
            &RELEASE_CATALOG_PUBLIC_KEY,
            &NATIVE_EXECUTABLE_PUBKEY,
            &RESTORE_PUBLIC_KEY,
        ],
    )
}
fn acquire(journal: &Journal) -> Result<OperationLease, String> {
    let descriptor = OperationDescriptor::new(
        Operation::Restore,
        journal.transaction_id.clone(),
        format!("recovery/{}/restore-journal.json", journal.transaction_id),
        boot_id()?,
    )?;
    acquire_restore_in(Path::new(PRODUCT_ROOT), descriptor)
}
fn acquire_restore_in(
    root: &Path,
    descriptor: OperationDescriptor,
) -> Result<OperationLease, String> {
    OperationLease::acquire_in_checked(root, descriptor, || reject_cluster_uninstall(root))
}

fn bootstrap_authority(paths: &Paths, journal: &Journal) -> Result<[Vec<u8>; 4], String> {
    let globals = (
        Path::new(PRODUCT_ROOT)
            .join(voboost_contract::release::MANIFEST_NAME)
            .exists(),
        Path::new(PRODUCT_ROOT)
            .join(voboost_contract::release::MANIFEST_SIGNATURE_NAME)
            .exists(),
        Path::new(DESCRIPTOR).exists(),
        Path::new(DESCRIPTOR_SIG).exists(),
    );
    let authority = match globals {
        (true, true, true, true) => [
            read_bound(
                &Path::new(PRODUCT_ROOT).join(voboost_contract::release::MANIFEST_NAME),
                voboost_contract::release::MAX_MANIFEST_BYTES as u64,
                0o600,
            )?,
            read_bound(
                &Path::new(PRODUCT_ROOT).join(voboost_contract::release::MANIFEST_SIGNATURE_NAME),
                64,
                0o600,
            )?,
            read_bound(Path::new(DESCRIPTOR), 4096, 0o644)?,
            read_bound(Path::new(DESCRIPTOR_SIG), 64, 0o644)?,
        ],
        (false, false, false, false) => [
            read_bound(
                &paths
                    .authorization
                    .join(voboost_contract::release::MANIFEST_NAME),
                voboost_contract::release::MAX_MANIFEST_BYTES as u64,
                0o600,
            )?,
            read_bound(
                &paths
                    .authorization
                    .join(voboost_contract::release::MANIFEST_SIGNATURE_NAME),
                64,
                0o600,
            )?,
            read_bound(
                &paths
                    .authorization
                    .join(voboost_contract::release::RESTORE_NAME),
                voboost_contract::release::MAX_RESTORE_BYTES as u64,
                0o600,
            )?,
            read_bound(
                &paths
                    .authorization
                    .join(voboost_contract::release::RESTORE_SIGNATURE_NAME),
                64,
                0o600,
            )?,
        ],
        _ => return Err("product authority pair is incomplete".into()),
    };
    let (manifest, restore) =
        verify_product_authority(&authority[0], &authority[1], &authority[2], &authority[3])?;
    if digest(&authority[0]) != journal.product_manifest_sha256
        || digest(&authority[2]) != journal.restore_document_sha256
        || digest(&authority[3]) != journal.restore_signature_sha256
        || manifest.release_identity != journal.release_identity
        || restore.restorable_closure_sha256 != journal.restorable_closure_sha256
        || operation_transaction_id(
            &authority[2],
            &authority[3],
            &journal.product_manifest_sha256,
            &journal.first_boot_id,
        ) != journal.transaction_id
    {
        return Err("restore bootstrap authority differs from durable journal".into());
    }
    Ok(authority)
}
fn advance(j: &mut Journal, expected: Phase, next: Phase) -> Result<(), String> {
    if j.phase != expected {
        return Err("non-monotonic restore phase".into());
    }
    j.phase = next;
    Ok(())
}
#[cfg(any(target_os = "android", target_os = "linux"))]
fn copy_selinux_context(source: &File, target: &File) -> Result<(), String> {
    let size = unsafe {
        libc::fgetxattr(
            source.as_raw_fd(),
            SELINUX_XATTR.as_ptr().cast(),
            std::ptr::null_mut(),
            0,
        )
    };
    if size <= 0 || size > 256 {
        return Err("source SELinux context is invalid".into());
    }
    let mut context = vec![0u8; size as usize];
    if unsafe {
        libc::fgetxattr(
            source.as_raw_fd(),
            SELINUX_XATTR.as_ptr().cast(),
            context.as_mut_ptr().cast(),
            context.len(),
        )
    } != size
        || unsafe {
            libc::fsetxattr(
                target.as_raw_fd(),
                SELINUX_XATTR.as_ptr().cast(),
                context.as_ptr().cast(),
                context.len(),
                0,
            )
        } != 0
    {
        return Err("copy SELinux context failed".into());
    }
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn copy_selinux_context(_source: &File, _target: &File) -> Result<(), String> {
    Ok(())
}

fn copy_metadata(source: &File, target: &File) -> Result<(), String> {
    let metadata = source.metadata().map_err(|e| e.to_string())?;
    if unsafe { libc::fchown(target.as_raw_fd(), metadata.uid(), metadata.gid()) } != 0
        || unsafe {
            libc::fchmod(
                target.as_raw_fd(),
                (metadata.mode() & 0o7777) as libc::mode_t,
            )
        } != 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    copy_selinux_context(source, target)
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn rename_replace(parent: &File, from: &std::ffi::CStr, to: &std::ffi::CStr) -> Result<(), String> {
    if unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            parent.as_raw_fd(),
            from.as_ptr(),
            parent.as_raw_fd(),
            to.as_ptr(),
            0,
        )
    } != 0
    {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn rename_replace(parent: &File, from: &std::ffi::CStr, to: &std::ffi::CStr) -> Result<(), String> {
    if unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            from.as_ptr(),
            parent.as_raw_fd(),
            to.as_ptr(),
        )
    } != 0
    {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

fn publish_exact(
    path: &Path,
    bytes: &[u8],
    metadata_source: &Path,
    transaction_id: &str,
) -> Result<(), String> {
    let source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(metadata_source)
        .map_err(|e| e.to_string())?;
    let parent =
        File::open(path.parent().ok_or("target lacks parent")?).map_err(|e| e.to_string())?;
    let name = path
        .file_name()
        .ok_or("target lacks leaf")?
        .to_string_lossy();
    hex(transaction_id)?;
    let temp_name = format!(".{name}.restore-{transaction_id}.tmp");
    let temp_path = path.with_file_name(&temp_name);
    if temp_path.exists() {
        let stale = read_bound(
            &temp_path,
            MAX_DOCUMENT,
            source.metadata().map_err(|e| e.to_string())?.mode() & 0o7777,
        )?;
        if stale != bytes {
            return Err("foreign restore temporary".into());
        }
        fs::remove_file(&temp_path).map_err(|e| e.to_string())?;
    }
    let mut temp = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp_path)
        .map_err(|e| e.to_string())?;
    temp.write_all(bytes).map_err(|e| e.to_string())?;
    copy_metadata(&source, &temp)?;
    temp.sync_all().map_err(|e| e.to_string())?;
    let temp_c = std::ffi::CString::new(temp_name).map_err(|e| e.to_string())?;
    let target_c = std::ffi::CString::new(name.as_bytes()).map_err(|e| e.to_string())?;
    if let Err(error) = rename_replace(&parent, &temp_c, &target_c) {
        return Err(format!("publish {}: {error}", path.display()));
    }
    parent.sync_all().map_err(|e| e.to_string())
}

fn archived_init_metadata() -> Result<ArchivedInitMetadata, String> {
    let bytes = read_bound(Path::new(SYSTEM_ARTIFACTS), MAX_DOCUMENT, 0o600)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let metadata: ArchivedInitMetadata = serde_json::from_value(
        value
            .get("init")
            .cloned()
            .ok_or("system artifacts lacks init metadata")?,
    )
    .map_err(|e| e.to_string())?;
    if metadata.path != INIT_HOOK
        || metadata.archive_path != INIT_ARCHIVE
        || metadata.uid != 0
        || metadata.gid != 0
        || metadata.mode != "0644"
        || metadata.context.is_empty()
        || metadata.context.len() > 128
        || !metadata.context.starts_with("u:object_r:")
    {
        return Err("archived init metadata is invalid".into());
    }
    Ok(metadata)
}

fn validate_archived_init_authority(
    bytes: &[u8],
    metadata: &ArchivedInitMetadata,
) -> Result<(), String> {
    if bytes.len() as u64 != metadata.installed_size || digest(bytes) != metadata.installed_sha256 {
        return Err("archived init bytes differ from metadata".into());
    }
    Ok(())
}

fn restore_init_hook(paths: &Paths, transaction_id: &str) -> Result<(), String> {
    let committed = read_bound(Path::new(INIT_ARCHIVE), MAX_DOCUMENT, 0o600)?;
    let metadata = archived_init_metadata()?;
    validate_archived_init_authority(&committed, &metadata)?;
    let publication = protected_system_transaction::Publication {
        target: Path::new(INIT_HOOK),
        remount_wal: &paths.remount_wal,
        transaction_id,
        temporary_namespace: "restore",
        candidate: &committed,
        maximum_bytes: MAX_DOCUMENT,
        identity: protected_system_transaction::FileIdentity {
            uid: metadata.uid,
            gid: metadata.gid,
            mode: 0o644,
            selinux_context: Some(&metadata.context),
        },
        previous: protected_system_transaction::PreviousIdentity::Contains(
            b"# voboost-uninstall recovery hook",
        ),
    };
    protected_system_transaction::publish(&publication)?;
    protected_system_transaction::verify(&publication)
}

fn publish_policy(
    bytes: &[u8],
    paths: &Paths,
    transaction_id: &str,
    boot_id: &str,
) -> Result<(), String> {
    let watchdog = mount_policy_transaction::begin(
        "restore",
        transaction_id,
        &paths.policy_mount_wal,
        Path::new(POLICY),
        &paths.baseline,
        boot_id,
    )?;
    if let Err(error) = mount_policy_transaction::publish_candidate(
        Path::new(POLICY),
        bytes,
        &paths.policy_mount_wal,
    )
    .and_then(|()| mount_policy_transaction::transfer_to_reboot(&paths.policy_mount_wal, boot_id))
    {
        return match watchdog.abort() {
            Ok(()) => Err(error),
            Err(recovery_error) => Err(format!("{error}; {recovery_error}")),
        };
    }
    watchdog.disarm_for_reboot()
}

fn prepare_policy_target(paths: &Paths, journal: &mut Journal) -> Result<(), String> {
    command(SELINUX, &[])?;
    let patched = read_bound(&paths.patched, MAX_POLICY, 0o600)?;
    journal.patched_policy = Some(Artifact {
        path: Some(POLICY.into()),
        size: patched.len() as u64,
        sha256: digest(&patched),
    });
    let bound = journal
        .patched_policy
        .as_ref()
        .ok_or("missing patch binding")?;
    if !artifact_matches(&patched, bound) {
        return Err("staged policy changed".into());
    }
    publish_policy(
        &patched,
        paths,
        &journal.transaction_id,
        &journal.first_boot_id,
    )
}

fn value_mut<'a>(
    value: &'a mut serde_json::Value,
    path: &[&str],
) -> Result<&'a mut serde_json::Value, String> {
    let mut current = value;
    for field in path {
        current = current
            .get_mut(*field)
            .ok_or_else(|| format!("missing JSON field {field}"))?;
    }
    Ok(current)
}

fn set_string(
    value: &mut serde_json::Value,
    path: &[&str],
    replacement: String,
) -> Result<(), String> {
    let target = value_mut(value, path)?;
    if !target.is_string() {
        return Err("inventory document field has wrong type".into());
    }
    *target = serde_json::Value::String(replacement);
    Ok(())
}

fn set_number(
    value: &mut serde_json::Value,
    path: &[&str],
    replacement: u64,
) -> Result<(), String> {
    let target = value_mut(value, path)?;
    if !target.is_number() {
        return Err("inventory document field has wrong type".into());
    }
    *target = replacement.into();
    Ok(())
}

fn bound(bytes: &[u8]) -> Artifact {
    Artifact {
        path: None,
        size: bytes.len() as u64,
        sha256: digest(bytes),
    }
}

fn validate_document_claims(
    inventory: &serde_json::Value,
    documents: &[(&str, &[u8])],
) -> Result<(), String> {
    let claims = inventory
        .get("documents")
        .and_then(|v| v.as_array())
        .ok_or("inventory documents missing")?;
    if claims.len() != documents.len() {
        return Err("inventory document count is not five".into());
    }
    for (claim, (path, bytes)) in claims.iter().zip(documents) {
        if claim.get("path").and_then(|v| v.as_str()) != Some(path)
            || claim.get("size").and_then(|v| v.as_u64()) != Some(bytes.len() as u64)
            || claim.get("sha256").and_then(|v| v.as_str()) != Some(digest(bytes).as_str())
        {
            return Err(format!("inventory claim for {path} differs"));
        }
    }
    Ok(())
}

fn inventory_artifact_matches(
    manifest: &Manifest,
    name: &str,
    size: u64,
    sha256: &str,
) -> Result<(), String> {
    let artifact = manifest.artifact(name)?;
    if artifact.size != size || artifact.sha256 != sha256 {
        return Err(format!("committed inventory differs for {name}"));
    }
    Ok(())
}

fn verify_committed_inventory(
    manifest: &Manifest,
    authority: &[Vec<u8>; 4],
) -> Result<Vec<u8>, String> {
    let inventory = read_bound(Path::new(installed_inventory_path()?), MAX_DOCUMENT, 0o600)?;
    let artifacts = read_bound(Path::new(SYSTEM_ARTIFACTS), MAX_DOCUMENT, 0o600)?;
    let baseline = read_bound(Path::new(CURRENT_BASELINE), MAX_DOCUMENT, 0o600)?;
    let policy = read_bound(Path::new(POLICY_META), MAX_DOCUMENT, 0o600)?;
    let state = read_bound(Path::new(SYSTEM_STATE), MAX_DOCUMENT, 0o600)?;
    let init = read_bound(Path::new(INIT_ARCHIVE), MAX_DOCUMENT, 0o600)?;
    let committed = uninstall_contract::parse_committed_contract(
        &inventory, &artifacts, &baseline, &policy, &state, &init,
    )?;
    if committed.inventory.version != manifest.release_identity {
        return Err("committed uninstall inventory differs from voboost.json".into());
    }
    let native = &committed.artifacts.native;
    for (name, installed) in [
        ("voboost-daemon", &native.daemon),
        ("voboost-inject", &native.inject),
        ("voboost-install", &native.installer),
        ("voboost-uninstall", &native.uninstaller),
        ("voboost-restore", &native.restore),
        ("voboost-selinux", &native.selinux),
    ] {
        inventory_artifact_matches(manifest, name, installed.size, &installed.sha256)?;
    }
    inventory_artifact_matches(
        manifest,
        "voboost.rc",
        committed.artifacts.init.installed_size,
        &committed.artifacts.init.installed_sha256,
    )?;
    for (path, size, sha256) in native
        .payload
        .iter()
        .map(|row| (&row.path, row.size, &row.sha256))
        .chain(
            native
                .qnx
                .iter()
                .map(|row| (&row.path, row.size, &row.sha256)),
        )
    {
        let name = Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("committed payload path lacks a basename")?;
        inventory_artifact_matches(manifest, name, size, sha256)?;
    }
    let app = manifest.app_artifact()?;
    if committed.artifacts.package.apk_size != app.size
        || committed.artifacts.package.apk_sha256 != app.sha256
        || committed.artifacts.package.version_code != manifest.apk_version_code()?
        || committed.artifacts.package.certificate_sha256 != manifest.apk_certificate_sha256()?
    {
        return Err("committed package inventory differs from voboost.json".into());
    }
    if native.manifest.size != authority[0].len() as u64
        || native.manifest.sha256 != digest(&authority[0])
        || native.manifest.signature_size != authority[1].len() as u64
        || native.manifest.signature_sha256 != digest(&authority[1])
        || native.restore_manifest.size != authority[2].len() as u64
        || native.restore_manifest.sha256 != digest(&authority[2])
        || native.restore_manifest.signature_size != authority[3].len() as u64
        || native.restore_manifest.signature_sha256 != digest(&authority[3])
    {
        return Err("committed product authority inventory differs".into());
    }
    Ok(inventory)
}

/// RF2 helper: replay a durable commit journal belonging to this exact
/// transaction. A crash after the inventory member of this transaction was
/// renamed into place but before the phase advanced resumes `runtime_verify`,
/// which re-enters the commit; the durable commit journal proves the
/// members this transaction already published, so replaying it retires the
/// side temporaries and the already-committed documents stand — instead of
/// wedging on the H0 gate against an install inventory this transaction
/// itself already replaced. A foreign transaction's journal is rejected.
fn replay_committed_inventory(
    paths: &Paths,
    transaction_id: &str,
    commit_bytes: &[u8],
) -> Result<(), String> {
    let commit: CommitJournal = serde_json::from_slice(commit_bytes)
        .map_err(|e| format!("parse restore commit journal: {e}"))?;
    if commit.transaction_id != transaction_id {
        return Err("restore commit journal belongs to another transaction".into());
    }
    resume_inventory_commit(paths, &commit)?;
    if commit.old_baseline_path != commit.new_baseline_path
        && Path::new(&commit.old_baseline_path).exists()
    {
        fs::remove_file(&commit.old_baseline_path).map_err(|e| e.to_string())?;
        sync_parent(Path::new(&commit.old_baseline_path))?;
    }
    Ok(())
}

/// RF3 helper: an existing digest-path backup is trusted only after proving
/// its exact bytes — publication ties the inventory to this baseline for
/// every later uninstall, so residue or corruption from an interrupted
/// earlier attempt must fail closed instead of being adopted silently.
fn verify_existing_baseline_backup(path: &Path, pristine: &[u8]) -> Result<(), String> {
    let existing = read_bound(path, MAX_POLICY, 0o600)?;
    if existing != pristine {
        return Err("existing digest-path baseline differs from journal".into());
    }
    Ok(())
}

fn commit_inventory(paths: &Paths, journal: &Journal) -> Result<(), String> {
    let old_inventory = read_bound(Path::new(installed_inventory_path()?), MAX_DOCUMENT, 0o600)?;
    if digest(&old_inventory) != journal.install_inventory_sha256 {
        if paths.commit_journal.exists() {
            return replay_committed_inventory(
                paths,
                &journal.transaction_id,
                &read_bound(&paths.commit_journal, MAX_DOCUMENT, 0o600)?,
            );
        }
        return Err("install inventory changed since restore started".into());
    }
    let old_artifacts = read_bound(Path::new(SYSTEM_ARTIFACTS), MAX_DOCUMENT, 0o600)?;
    let old_baseline = read_bound(Path::new(CURRENT_BASELINE), MAX_DOCUMENT, 0o600)?;
    let old_meta = read_bound(Path::new(POLICY_META), MAX_DOCUMENT, 0o600)?;
    let old_state = read_bound(Path::new(SYSTEM_STATE), MAX_DOCUMENT, 0o600)?;
    let init_archive = read_bound(Path::new(INIT_ARCHIVE), MAX_DOCUMENT, 0o600)?;
    let old_docs = [
        (SYSTEM_ARTIFACTS, old_artifacts.as_slice()),
        (CURRENT_BASELINE, old_baseline.as_slice()),
        (POLICY_META, old_meta.as_slice()),
        (SYSTEM_STATE, old_state.as_slice()),
        (INIT_ARCHIVE, init_archive.as_slice()),
    ];
    let mut inventory: serde_json::Value =
        serde_json::from_slice(&old_inventory).map_err(|e| e.to_string())?;
    validate_document_claims(&inventory, &old_docs)?;
    let pristine = read_bound(&paths.baseline, MAX_POLICY, 0o600)?;
    let patched = journal
        .patched_policy
        .as_ref()
        .ok_or("missing patched policy binding")?;
    if digest(&pristine) != journal.pristine_policy.sha256
        || pristine.len() as u64 != journal.pristine_policy.size
    {
        return Err("pristine policy staging differs from journal".into());
    }
    let baseline_directory =
        Path::new("/data/voboost/uninstall/baselines").join(&journal.pristine_policy.sha256);
    if !baseline_directory.exists() {
        fs::create_dir(&baseline_directory).map_err(|e| e.to_string())?;
        fs::set_permissions(&baseline_directory, fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
        sync_parent(&baseline_directory)?;
    }
    let new_baseline = baseline_directory.join("precompiled_sepolicy.orig");
    if !new_baseline.exists() {
        publish_exact(
            &new_baseline,
            &pristine,
            Path::new(&old_baseline_path(&old_baseline)?),
            &journal.transaction_id,
        )?;
    } else {
        verify_existing_baseline_backup(&new_baseline, &pristine)?;
    }
    let mut artifacts: serde_json::Value =
        serde_json::from_slice(&old_artifacts).map_err(|e| e.to_string())?;
    let mut baseline: serde_json::Value =
        serde_json::from_slice(&old_baseline).map_err(|e| e.to_string())?;
    let mut meta: serde_json::Value =
        serde_json::from_slice(&old_meta).map_err(|e| e.to_string())?;
    let mut state: serde_json::Value =
        serde_json::from_slice(&old_state).map_err(|e| e.to_string())?;
    set_string(
        &mut artifacts,
        &["policy", "installedSha256"],
        patched.sha256.clone(),
    )?;
    set_string(
        &mut artifacts,
        &["policy", "currentBaselineSha256"],
        journal.pristine_policy.sha256.clone(),
    )?;
    set_string(
        &mut baseline,
        &["policySha256"],
        journal.pristine_policy.sha256.clone(),
    )?;
    set_string(
        &mut baseline,
        &["backupPath"],
        new_baseline.to_string_lossy().into_owned(),
    )?;
    set_number(&mut meta, &["size"], journal.pristine_policy.size)?;
    set_string(
        &mut meta,
        &["sha256"],
        journal.pristine_policy.sha256.clone(),
    )?;
    set_string(
        &mut state,
        &["policyPriorSha256"],
        journal.pristine_policy.sha256.clone(),
    )?;
    set_string(
        &mut state,
        &["policyInstalledSha256"],
        patched.sha256.clone(),
    )?;
    let targets = [
        serde_json::to_vec(&artifacts).map_err(|e| e.to_string())?,
        serde_json::to_vec(&baseline).map_err(|e| e.to_string())?,
        serde_json::to_vec(&meta).map_err(|e| e.to_string())?,
        serde_json::to_vec(&state).map_err(|e| e.to_string())?,
    ];
    let claims = value_mut(&mut inventory, &["documents"])?
        .as_array_mut()
        .ok_or("inventory documents wrong type")?;
    for (claim, bytes) in claims[..4].iter_mut().zip(&targets) {
        set_number(claim, &["size"], bytes.len() as u64)?;
        set_string(claim, &["sha256"], digest(bytes))?;
    }
    let inventory_target = serde_json::to_vec(&inventory).map_err(|e| e.to_string())?;
    let new_docs = [
        (SYSTEM_ARTIFACTS, targets[0].as_slice()),
        (CURRENT_BASELINE, targets[1].as_slice()),
        (POLICY_META, targets[2].as_slice()),
        (SYSTEM_STATE, targets[3].as_slice()),
        (INIT_ARCHIVE, init_archive.as_slice()),
    ];
    validate_document_claims(&inventory, &new_docs)?;
    mkdir(&paths.commit_root)?;
    let old_baseline_path = old_baseline_path(&old_baseline)?;
    let stable_old = [
        &old_artifacts,
        &old_baseline,
        &old_meta,
        &old_state,
        &old_inventory,
    ];
    let stable_target = [
        &targets[0],
        &targets[1],
        &targets[2],
        &targets[3],
        &inventory_target,
    ];
    let paths_order = [
        SYSTEM_ARTIFACTS,
        CURRENT_BASELINE,
        POLICY_META,
        SYSTEM_STATE,
        installed_inventory_path()?,
    ];
    let mut members = Vec::new();
    for ((path, old), target) in paths_order.iter().zip(stable_old).zip(stable_target) {
        let temporary = paths.commit_root.join(
            Path::new(path)
                .file_name()
                .ok_or("commit path lacks leaf")?,
        );
        if !temporary.exists() {
            publish_exact(&temporary, target, Path::new(path), &journal.transaction_id)?;
        } else if read_bound(&temporary, MAX_DOCUMENT, 0o600)? != *target {
            return Err("staged commit member changed".into());
        }
        members.push(CommitMember {
            path: (*path).into(),
            temporary_path: temporary.to_string_lossy().into_owned(),
            old: bound(old),
            target: bound(target),
        });
    }
    let commit = CommitJournal {
        schema_version: 1,
        transaction_id: journal.transaction_id.clone(),
        old_baseline_path: old_baseline_path.clone(),
        new_baseline_path: new_baseline.to_string_lossy().into_owned(),
        members,
    };
    atomic(&paths.commit_journal, &json(&commit)?)?;
    resume_inventory_commit(paths, &commit)?;
    if old_baseline_path != commit.new_baseline_path && Path::new(&old_baseline_path).exists() {
        fs::remove_file(&old_baseline_path).map_err(|e| e.to_string())?;
        sync_parent(Path::new(&old_baseline_path))?;
    }
    Ok(())
}

fn old_baseline_path(bytes: &[u8]) -> Result<String, String> {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .map_err(|e| e.to_string())?
        .get("backupPath")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| "baseline backupPath missing".into())
}

fn resume_inventory_commit(paths: &Paths, commit: &CommitJournal) -> Result<(), String> {
    if commit.schema_version != 1
        || !canonical_commit_members(paths, commit)
        || commit.members.len() != 5
        || commit.members.last().map(|m| m.path.as_str()) != Some(installed_inventory_path()?)
    {
        return Err("commit does not publish inventory last".into());
    }
    for member in &commit.members {
        let stable = read_bound(Path::new(&member.path), MAX_DOCUMENT, 0o600)?;
        if bound(&stable) == member.target {
            retire_committed_temporary(Path::new(&member.temporary_path), &member.target)?;
            continue;
        }
        if bound(&stable) != member.old {
            return Err("stable commit member is foreign".into());
        }
        let staged = read_bound(Path::new(&member.temporary_path), MAX_DOCUMENT, 0o600)?;
        if bound(&staged) != member.target {
            return Err("staged commit member is foreign".into());
        }
        fs::rename(&member.temporary_path, &member.path).map_err(|e| e.to_string())?;
        sync_parent(Path::new(&member.path))?;
    }
    let inventory_bytes = read_bound(Path::new(installed_inventory_path()?), MAX_DOCUMENT, 0o600)?;
    let inventory: serde_json::Value =
        serde_json::from_slice(&inventory_bytes).map_err(|e| e.to_string())?;
    let docs = [
        SYSTEM_ARTIFACTS,
        CURRENT_BASELINE,
        POLICY_META,
        SYSTEM_STATE,
        INIT_ARCHIVE,
    ]
    .map(|path| read_bound(Path::new(path), MAX_DOCUMENT, 0o600).map(|bytes| (path, bytes)))
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    let refs = docs
        .iter()
        .map(|(p, b)| (*p, b.as_slice()))
        .collect::<Vec<_>>();
    validate_document_claims(&inventory, &refs)
}

fn retire_committed_temporary(path: &Path, target: &Artifact) -> Result<(), String> {
    retire_committed_temporary_with(
        path,
        target,
        |path| match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("inspect committed temporary: {error}")),
            Ok(_) => read_bound(path, MAX_DOCUMENT, 0o600).map(Some),
        },
        |path| {
            fs::remove_file(path).map_err(|error| format!("retire committed temporary: {error}"))
        },
        sync_parent,
    )
}

fn retire_committed_temporary_with<Read, Remove, Sync>(
    path: &Path,
    target: &Artifact,
    mut read: Read,
    mut remove: Remove,
    mut sync: Sync,
) -> Result<(), String>
where
    Read: FnMut(&Path) -> Result<Option<Vec<u8>>, String>,
    Remove: FnMut(&Path) -> Result<(), String>,
    Sync: FnMut(&Path) -> Result<(), String>,
{
    let Some(staged) = read(path)? else {
        return Ok(());
    };
    if bound(&staged) != *target {
        return Err("committed temporary member is foreign".into());
    }
    remove(path)?;
    sync(path)
}

fn canonical_commit_members(paths: &Paths, commit: &CommitJournal) -> bool {
    let installed = match commit.members.last().map(|member| member.path.as_str()) {
        Some(INVENTORY) => INVENTORY,
        Some(INSTALL_STATE) => INSTALL_STATE,
        _ => return false,
    };
    let expected = [
        SYSTEM_ARTIFACTS,
        CURRENT_BASELINE,
        POLICY_META,
        SYSTEM_STATE,
        installed,
    ];
    commit.members.iter().zip(expected).all(|(member, path)| {
        member.path == path
            && member.temporary_path
                == paths
                    .commit_root
                    .join(Path::new(path).file_name().unwrap_or_default())
                    .to_string_lossy()
    })
}

fn cleanup_restore_payload(paths: &Paths) -> Result<(), String> {
    for path in [
        &paths.commit_journal,
        &paths.remount_wal,
        &paths.policy_mount_wal,
        &paths.patched,
        &paths.baseline,
    ] {
        if path.exists() {
            fs::remove_file(path).map_err(|e| format!("remove {}: {e}", path.display()))?;
            sync_parent(path)?;
        }
    }
    if paths.commit_root.exists() {
        if fs::read_dir(&paths.commit_root)
            .map_err(|e| e.to_string())?
            .next()
            .is_some()
        {
            return Err("commit temporary directory is not empty".into());
        }
        fs::remove_dir(&paths.commit_root).map_err(|e| e.to_string())?;
        sync_parent(&paths.commit_root)?;
    }
    if paths.product_target.exists() {
        let manifest = read_bound(
            &paths
                .authorization
                .join(voboost_contract::release::MANIFEST_NAME),
            voboost_contract::release::MAX_MANIFEST_BYTES as u64,
            0o600,
        )?;
        let manifest_signature = read_bound(
            &paths
                .authorization
                .join(voboost_contract::release::MANIFEST_SIGNATURE_NAME),
            64,
            0o600,
        )?;
        let restore = read_bound(
            &paths
                .authorization
                .join(voboost_contract::release::RESTORE_NAME),
            voboost_contract::release::MAX_RESTORE_BYTES as u64,
            0o600,
        )?;
        let restore_signature = read_bound(
            &paths
                .authorization
                .join(voboost_contract::release::RESTORE_SIGNATURE_NAME),
            64,
            0o600,
        )?;
        let (manifest, _) =
            verify_product_authority(&manifest, &manifest_signature, &restore, &restore_signature)?;
        for artifact in manifest.artifacts.iter().filter(|artifact| {
            !matches!(
                artifact.role,
                ArtifactRole::RestoreAuthorization | ArtifactRole::RestoreSignature
            )
        }) {
            let path = paths.product_target.join(&artifact.file);
            if path.exists() {
                fs::remove_file(path).map_err(|e| e.to_string())?;
            }
        }
        if fs::read_dir(&paths.product_target)
            .map_err(|e| e.to_string())?
            .next()
            .is_some()
        {
            return Err("restore product target contains foreign input".into());
        }
        fs::remove_dir(&paths.product_target).map_err(|e| e.to_string())?;
        sync_parent(&paths.product_target)?;
    }
    if paths.authorization.exists() {
        for name in [
            "restore.json",
            "restore.json.sig",
            "voboost.json",
            "voboost.json.sig",
        ] {
            let path = paths.authorization.join(name);
            if path.exists() {
                fs::remove_file(&path).map_err(|e| e.to_string())?;
            }
        }
        if fs::read_dir(&paths.authorization)
            .map_err(|e| e.to_string())?
            .next()
            .is_some()
        {
            return Err("restore trust transaction contains foreign input".into());
        }
        fs::remove_dir(&paths.authorization).map_err(|e| e.to_string())?;
        sync_parent(&paths.authorization)?;
    }
    Ok(())
}

fn cleanup_restore_control(paths: &Paths) -> Result<(), String> {
    if paths.journal.exists() {
        fs::remove_file(&paths.journal)
            .map_err(|e| format!("remove {}: {e}", paths.journal.display()))?;
        sync_parent(&paths.journal)?;
    }
    if paths.root.exists() {
        if fs::read_dir(&paths.root)
            .map_err(|e| e.to_string())?
            .next()
            .is_some()
        {
            return Err("restore control directory contains foreign residue".into());
        }
        fs::remove_dir(&paths.root).map_err(|e| e.to_string())?;
        sync_parent(&paths.root)?;
    }
    Ok(())
}

fn recover_terminal() -> Result<bool, String> {
    let root = Path::new("/data/voboost");
    let Some(pointer) = operation_contract::read_current_in(root)? else {
        return Ok(false);
    };
    if pointer.operation != Operation::Restore {
        return Ok(false);
    }
    let paths = Paths::new(&pointer.transaction_id)?;
    if paths.journal.exists() {
        if pointer.outcome != "complete" {
            return Ok(false);
        }
        let journal: Journal = serde_json::from_slice(&read_bound(&paths.journal, 4096, 0o600)?)
            .map_err(|error| format!("parse terminal restore journal: {error}"))?;
        validate_journal(&journal)?;
        if journal.transaction_id != pointer.transaction_id
            || journal.phase != Phase::RestoreComplete
            || digest(&json(&journal)?) != pointer.journal_sha256
        {
            return Err("terminal restore journal differs from operation authority".into());
        }
        let lease = OperationLease::acquire_in(root, pointer)?;
        cleanup_restore_payload(&paths)?;
        cleanup_restore_control(&paths)?;
        lease.finish()?;
        return Ok(true);
    }
    if pointer.outcome != "complete" {
        return Err("active restore operation names a missing journal".into());
    }
    // This is the unique cut after exact terminal member cleanup and before
    // operation.json removal. Any residue makes the state non-terminal.
    if paths.commit_journal.exists()
        || paths.commit_root.exists()
        || paths.remount_wal.exists()
        || paths.policy_mount_wal.exists()
        || paths.authorization.exists()
        || paths.product_target.exists()
    {
        return Err("restore pointer names a missing journal with foreign residue".into());
    }
    if paths.root.exists() {
        if fs::read_dir(&paths.root)
            .map_err(|e| e.to_string())?
            .next()
            .is_some()
        {
            return Err("restore pointer names a nonempty terminal transaction".into());
        }
        fs::remove_dir(&paths.root).map_err(|e| e.to_string())?;
        sync_parent(&paths.root)?;
    }
    OperationLease::acquire_in(root, pointer)?.finish()?;
    Ok(true)
}

fn init_admission_with(
    root: &Path,
    read_journal: impl FnOnce(&Path) -> Result<Vec<u8>, String>,
) -> Result<InitAdmission, String> {
    let Some(pointer) = operation_contract::read_document_in(root)? else {
        return Ok(InitAdmission::Noop);
    };
    if pointer.operation != Operation::Restore {
        return Ok(InitAdmission::Noop);
    }
    if pointer.outcome == "complete" {
        return Ok(InitAdmission::Cleanup(pointer.transaction_id));
    }
    let journal_path = root.join(&pointer.journal);
    let bytes = read_journal(&journal_path)?;
    let journal: Journal = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse init restore journal: {error}"))?;
    validate_journal(&journal)?;
    if journal.transaction_id != pointer.transaction_id
        || pointer.journal != format!("recovery/{}/restore-journal.json", pointer.transaction_id)
    {
        return Err("init restore authority is not correlated".into());
    }
    if pointer.outcome == "failed" {
        Ok(InitAdmission::Noop)
    } else {
        Ok(InitAdmission::Resume(pointer.transaction_id))
    }
}

fn init_admission_in(root: &Path) -> Result<InitAdmission, String> {
    init_admission_with(root, |path| read_bound(path, 4096, 0o600))
}

fn reconcile_restore_projection(admitted_transaction: Option<&str>) -> Result<bool, String> {
    let root = Path::new("/data/voboost");
    let Some(pointer) = operation_contract::read_document_in(root)? else {
        return Ok(false);
    };
    if pointer.operation != Operation::Restore {
        return Ok(false);
    }
    if admitted_transaction.is_some_and(|transaction_id| pointer.transaction_id != transaction_id) {
        return Err("admitted restore authority changed before reconciliation".into());
    }
    let paths = Paths::new(&pointer.transaction_id)?;
    if !paths.journal.exists() {
        return if pointer.outcome == "complete" {
            Ok(false)
        } else {
            Err("nonterminal restore operation names a missing journal".into())
        };
    }
    let bytes = read_bound(&paths.journal, 4096, 0o600)?;
    if digest(&bytes) == pointer.journal_sha256 {
        return Ok(false);
    }
    let mut journal: Journal = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse restore recovery WAL: {error}"))?;
    validate_journal(&journal)?;
    if journal.transaction_id != pointer.transaction_id || json(&journal)? != bytes {
        return Err("restore recovery WAL differs from operation authority".into());
    }
    let recovered = restore_operation_document(&journal, None)?;
    if recovered.operation != pointer.operation
        || recovered.transaction_id != pointer.transaction_id
        || recovered.journal != pointer.journal
    {
        return Err("restore recovery projection changed operation authority".into());
    }
    let mut reconciled_terminal = false;
    let lease = match if journal.phase == Phase::RestoreComplete {
        OperationLease::acquire_in(root, recovered.clone())
    } else {
        OperationLease::acquire_in_checked(root, recovered.clone(), || {
            reject_cluster_uninstall(root)
        })
    } {
        Ok(lease) => lease,
        // R24 terminal WAL→projection cut: the RestoreComplete WAL write and
        // the terminal projection publish are two durable steps. The pre-cut
        // projection is derivable bit-for-bit from the same durable WAL
        // (the terminal write changed only the journal phase), so only the
        // exact predecessor publication may be reconciled to the terminal
        // one.
        Err(error)
            if error.contains("operation document and recovery WAL diverged")
                && journal.phase == Phase::RestoreComplete =>
        {
            let phase = journal.phase;
            journal.phase = Phase::RestoreCleanup;
            let previous = restore_operation_document(&journal, None)?;
            journal.phase = phase;
            reconciled_terminal = true;
            OperationLease::reconcile_terminal_cut_in(root, &previous, &recovered)?
        }
        Err(error) => return Err(error),
    };
    lease.verify_owner()?;
    Ok(reconciled_terminal)
}

/// Best-effort durable diagnostic for the init product-system helper. The
/// Update-operation lease is owned by the daemon, so `publish_restore_failure`
/// cannot project this failure and the original reason is otherwise lost.
/// This writes one bounded JSON document through the descriptor-relative
/// trusted-publish primitive (no symlink following, fresh 0o600 root-owned
/// inode, `/data/voboost` 0o755, `logs` 0o700). It never touches the WAL, the
/// operation authority, or the exit status: every error path is swallowed so
/// the original failure is never masked.
fn record_product_system_error(error: &str) {
    let _ = record_product_system_error_in(Path::new(PRODUCT_ROOT), error);
}

fn record_product_system_error_in(root_path: &Path, error: &str) -> std::io::Result<()> {
    let root = secure_fs::Directory::open(root_path)?;
    root.validate_owner_mode(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        0o755,
    )?;
    let logs = root.open_or_create_child_with_mode("logs", 0o700)?;
    logs.validate_owner_mode(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        0o700,
    )?;
    let mut message = bounded_restore_error(error);
    if message.is_empty() {
        message = "internal product-system helper failure".to_string();
    }
    // Fixed field order; the error text rides the existing bounded pipeline
    // (control characters stripped, 512 bytes maximum, UTF-8 safe).
    #[derive(Serialize)]
    struct Error<'a> {
        code: &'a str,
        message: &'a str,
    }
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct ProductSystemError<'a> {
        schema_version: u32,
        operation: &'a str,
        error: Error<'a>,
    }
    let document = ProductSystemError {
        schema_version: 1,
        operation: "product-system-update",
        error: Error {
            code: "product-system-helper-failed",
            message: &message,
        },
    };
    let mut bytes = serde_json::to_vec(&document).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    logs.validate_optional_trusted_file("product-system-error.json", 0o600)?;
    logs.write_atomic("product-system-error.json", &bytes, 0o600)
}

fn publish_restore_failure(
    message: &str,
    expected_transaction: Option<&str>,
) -> Result<(), String> {
    let root = Path::new("/data/voboost");
    let Some(pointer) = operation_contract::read_document_in(root)? else {
        return Ok(());
    };
    if pointer.operation != Operation::Restore
        || matches!(pointer.outcome.as_str(), "complete" | "failed")
    {
        return Ok(());
    }
    if expected_transaction.is_some_and(|expected| pointer.transaction_id != expected) {
        return Err("restore failure transaction authority changed".into());
    }
    let paths = Paths::new(&pointer.transaction_id)?;
    let bytes = read_bound(&paths.journal, 4096, 0o600)?;
    let journal: Journal = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse failed restore WAL: {error}"))?;
    validate_journal(&journal)?;
    if journal.transaction_id != pointer.transaction_id || json(&journal)? != bytes {
        return Err("failed restore WAL differs from operation authority".to_string());
    }
    let running = restore_operation_document(&journal, None)?;
    let lease =
        OperationLease::acquire_in_checked(root, running, || reject_cluster_uninstall(root))?;
    lease.publish(&restore_operation_document(&journal, Some(message))?)
}

// Direct admission failures have no authenticated restore transaction. Never
// rewrite a previous Install (or terminal Restore) just to report this attempt.
fn bounded_restore_error(error: &str) -> String {
    let mut message = String::new();
    for character in error.chars().filter(|c| !c.is_control()) {
        if message.len() + character.len_utf8() > 512 {
            break;
        }
        message.push(character);
    }
    message
}

fn restore_pre_transaction_failure_bytes(error: &str) -> Vec<u8> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Failure<'a> {
        schema_version: u32,
        operation: &'a str,
        failure_type: &'a str,
        error: Error<'a>,
    }
    #[derive(Serialize)]
    struct Error<'a> {
        code: &'a str,
        message: &'a str,
    }
    let message = bounded_restore_error(error);
    let message = if message.is_empty() {
        "internal restore failure"
    } else {
        &message
    };
    let mut bytes = serde_json::to_vec(&Failure {
        schema_version: 1,
        operation: "restore",
        failure_type: "pre-transaction",
        error: Error {
            code: "restore-pre-transaction-failed",
            message,
        },
    })
    .expect("serialize bounded restore failure");
    bytes.push(b'\n');
    bytes
}

fn report_restore_failure_with(
    transaction_id: Option<&str>,
    error: &str,
    publish: impl FnOnce(&str, &str) -> Result<(), String>,
    emit: impl FnOnce(&[u8]),
) {
    if let Some(transaction_id) = transaction_id {
        let _ = publish(transaction_id, error);
    } else {
        emit(&restore_pre_transaction_failure_bytes(error));
    }
}

trait RestoreActions {
    fn verify_owner(&mut self) -> Result<(), String>;
    fn persist(&mut self, journal: &Journal) -> Result<(), String>;
    fn firmware_verify(&mut self, journal: &Journal) -> Result<(), String>;
    fn policy_backup(&mut self, journal: &mut Journal) -> Result<(), String>;
    fn policy_apply(&mut self, journal: &Journal) -> Result<(), String>;
    fn runtime_apply(&mut self, journal: &Journal) -> Result<(), String>;
    fn post_second_boot(&mut self, journal: &Journal, now: &str) -> Result<(), String>;
    fn runtime_verify(&mut self, journal: &Journal) -> Result<(), String>;
    fn cleanup_payload(&mut self) -> Result<(), String>;
    fn cleanup_control(&mut self) -> Result<(), String>;
    fn finish(&mut self) -> Result<(), String>;
    fn boot_id(&mut self) -> Result<String, String>;
    fn reboot(&mut self) -> Result<(), String>;
}

struct DeviceRestoreActions<'a> {
    paths: &'a Paths,
    lease: &'a OperationLease,
}

impl RestoreActions for DeviceRestoreActions<'_> {
    fn verify_owner(&mut self) -> Result<(), String> {
        self.lease.verify_owner()
    }

    fn persist(&mut self, journal: &Journal) -> Result<(), String> {
        persist(self.paths, journal, self.lease)
    }

    fn firmware_verify(&mut self, journal: &Journal) -> Result<(), String> {
        let policy = read_bound(Path::new(POLICY), MAX_POLICY, 0o644)?;
        // An installed machine boots the install-patched policy: the live
        // bytes then legitimately differ from the journal's committed
        // pristine baseline, and this phase must still stage the pristine
        // bytes (from the committed baseline archive) for the later commit
        // and patch work. The exact identity check remains for the only
        // other supported shape — a restore over a machine whose live
        // policy already equals the journaled pristine baseline.
        if artifact_matches(&policy, &journal.pristine_policy) {
            return atomic(&self.paths.baseline, &policy);
        }
        let (_, baseline_bytes) = installed_policy_baseline_pair()
            .ok_or("live policy differs from the journaled pristine baseline".to_string())?;
        if !artifact_matches(&baseline_bytes, &journal.pristine_policy) {
            return Err("committed baseline differs from the journaled pristine baseline".into());
        }
        atomic(&self.paths.baseline, &baseline_bytes)
    }

    fn policy_backup(&mut self, journal: &mut Journal) -> Result<(), String> {
        prepare_policy_target(self.paths, journal)
    }

    fn policy_apply(&mut self, journal: &Journal) -> Result<(), String> {
        restore_init_hook(self.paths, &journal.transaction_id)
    }

    fn runtime_apply(&mut self, journal: &Journal) -> Result<(), String> {
        i18n_resource_files::cleanup_for_operation(
            &RELEASE_CATALOG_PUBLIC_KEY,
            self.lease,
            Operation::Restore,
        )
        .map_err(|error| format!("owned resource cleanup: {error}"))?;
        let (manifest, _) = staged_product_authority(self.paths, journal)?;
        apply_target_product_closure(self.paths, &manifest, &journal.transaction_id)?;
        verify_live_product_closure(self.paths, &manifest)
    }

    fn post_second_boot(&mut self, journal: &Journal, now: &str) -> Result<(), String> {
        let live = read_bound(Path::new(POLICY), MAX_POLICY, 0o644)?;
        let bound = journal
            .patched_policy
            .as_ref()
            .ok_or("missing patch binding")?;
        post_second_boot(
            &journal.first_boot_id,
            journal
                .second_boot_id
                .as_deref()
                .ok_or("missing second boot")?,
            now,
        )?;
        if !artifact_matches(&live, bound) {
            return Err("post-boot policy differs".into());
        }
        let committed_init = read_bound(Path::new(INIT_ARCHIVE), MAX_DOCUMENT, 0o600)?;
        let live_init = read_bound(Path::new(INIT_HOOK), MAX_DOCUMENT, 0o644)?;
        if live_init != committed_init {
            return Err("post-boot init hook differs from committed inventory".into());
        }
        Ok(())
    }

    fn runtime_verify(&mut self, journal: &Journal) -> Result<(), String> {
        i18n_resource_files::verify_operation_absence(
            &RELEASE_CATALOG_PUBLIC_KEY,
            self.lease,
            Operation::Restore,
        )
        .map_err(|error| format!("owned resource post-boot absence: {error}"))?;
        let (manifest, _) = staged_product_authority(self.paths, journal)?;
        verify_live_product_closure(self.paths, &manifest)?;
        commit_inventory(self.paths, journal)?;
        self.lease.verify_owner()
    }

    fn cleanup_payload(&mut self) -> Result<(), String> {
        cleanup_restore_payload(self.paths)
    }

    fn cleanup_control(&mut self) -> Result<(), String> {
        cleanup_restore_control(self.paths)
    }

    fn finish(&mut self) -> Result<(), String> {
        self.lease.finish()
    }

    fn boot_id(&mut self) -> Result<String, String> {
        boot_id()
    }

    fn reboot(&mut self) -> Result<(), String> {
        fixed_process::request_reboot()
    }
}

fn drive_restore_phases(
    journal: &mut Journal,
    actions: &mut impl RestoreActions,
) -> Result<(), String> {
    loop {
        actions.verify_owner()?;
        let (expected, next) = match journal.phase {
            Phase::RestorePrepare => (Phase::RestorePrepare, Phase::RestoreFirmwareVerify),
            Phase::RestoreFirmwareVerify => {
                actions.firmware_verify(journal)?;
                (Phase::RestoreFirmwareVerify, Phase::RestorePolicyBackup)
            }
            Phase::RestorePolicyBackup => {
                actions.policy_backup(journal)?;
                (Phase::RestorePolicyBackup, Phase::RestorePolicyApply)
            }
            Phase::RestorePolicyApply => {
                actions.policy_apply(journal)?;
                advance(
                    journal,
                    Phase::RestorePolicyApply,
                    Phase::RestoreRebootFirst,
                )?;
                actions.persist(journal)?;
                return actions.reboot();
            }
            Phase::RestoreRebootFirst => {
                let now = actions.boot_id()?;
                if now == journal.first_boot_id {
                    return actions.reboot();
                }
                journal.second_boot_id = Some(now);
                (Phase::RestoreRebootFirst, Phase::RestoreRuntimeApply)
            }
            Phase::RestoreRuntimeApply => {
                actions.runtime_apply(journal)?;
                advance(
                    journal,
                    Phase::RestoreRuntimeApply,
                    Phase::RestoreRebootSecond,
                )?;
                actions.persist(journal)?;
                return actions.reboot();
            }
            Phase::RestoreRebootSecond => {
                let now = actions.boot_id()?;
                if Some(now.as_str()) == journal.second_boot_id.as_deref() {
                    return actions.reboot();
                }
                actions.post_second_boot(journal, &now)?;
                (Phase::RestoreRebootSecond, Phase::RestoreRuntimeVerify)
            }
            Phase::RestoreRuntimeVerify => {
                actions.runtime_verify(journal)?;
                (Phase::RestoreRuntimeVerify, Phase::RestoreInventoryCommit)
            }
            Phase::RestoreInventoryCommit => (Phase::RestoreInventoryCommit, Phase::RestoreCleanup),
            Phase::RestoreCleanup => {
                actions.cleanup_payload()?;
                advance(journal, Phase::RestoreCleanup, Phase::RestoreComplete)?;
                actions.persist(journal)?;
                actions.cleanup_control()?;
                actions.finish()?;
                return Ok(());
            }
            Phase::RestoreComplete => {
                actions.cleanup_payload()?;
                actions.cleanup_control()?;
                actions.finish()?;
                return Ok(());
            }
        };
        advance(journal, expected, next)?;
        actions.persist(journal)?;
    }
}

fn run(
    mode: RunMode,
    authenticated_transaction: &mut Option<String>,
    request: Option<&request::Request>,
    reply: &mut request::ReplyTracking,
) -> Result<(), String> {
    let admission = if mode == RunMode::InitContinuation {
        init_admission_in(Path::new(PRODUCT_ROOT))?
    } else {
        InitAdmission::Resume(String::new())
    };
    match &admission {
        InitAdmission::Noop => return Ok(()),
        InitAdmission::Cleanup(transaction_id) => {
            let current = operation_contract::read_document_in(Path::new(PRODUCT_ROOT))?
                .ok_or("admitted terminal restore disappeared")?;
            if current.operation != Operation::Restore
                || current.transaction_id != *transaction_id
                || current.outcome != "complete"
            {
                return Err("admitted terminal restore authority changed".into());
            }
            if !recover_terminal()? {
                return Err("admitted terminal restore disappeared".into());
            }
            return Ok(());
        }
        InitAdmission::Resume(_) => {}
    }
    let admitted_transaction = match &admission {
        InitAdmission::Resume(transaction_id) if mode == RunMode::InitContinuation => {
            Some(transaction_id.as_str())
        }
        _ => None,
    };
    if reconcile_restore_projection(admitted_transaction)
        .map_err(|error| format!("reconcile restore projection: {error}"))?
    {
        // The projection was just reconciled to the terminal cut: the
        // descriptor is now complete, so this run routes through the
        // verified terminal cleanup instead of resuming an active
        // restore that no longer exists.
        if let InitAdmission::Resume(transaction_id) = &admission {
            let current = operation_contract::read_document_in(Path::new(PRODUCT_ROOT))?
                .ok_or("reconciled terminal restore disappeared")?;
            if current.operation != Operation::Restore
                || current.transaction_id != *transaction_id
                || current.outcome != "complete"
            {
                return Err("reconciled terminal restore authority changed".into());
            }
        }
        if !recover_terminal()? {
            return Err("reconciled terminal restore is not terminal".into());
        }
        if let Some(request) = request {
            let current = operation_contract::read_document_in(Path::new(PRODUCT_ROOT))?
                .ok_or("reconciled restore admission lost operation authority")?;
            if current.operation != Operation::Restore || current.outcome != "complete" {
                return Err("reconciled restore admission is not terminal".into());
            }
            reply.publish_with(Some(&current.transaction_id), None, |transaction, error| {
                request::publish(request, transaction, error)
            })?;
        }
        return Ok(());
    }
    if mode == RunMode::Request {
        let _ = recover_terminal()?;
    }
    let current_boot = boot_id()?;
    let active = active_restore()?;
    if let Some((_, journal)) = &active {
        if mode == RunMode::InitContinuation {
            let InitAdmission::Resume(transaction_id) = &admission else {
                return Err("init restore admission changed".into());
            };
            if journal.transaction_id != *transaction_id {
                return Err("admitted active restore authority changed".into());
            }
        }
    }
    let mut preparation_guard = None;
    let (paths, mut journal) = select_existing_or_create(mode, active, || {
        let guard = operation_contract::GenerationGuard::acquire_in(Path::new(PRODUCT_ROOT))?;
        reject_cluster_uninstall(Path::new(PRODUCT_ROOT))?;
        let (manifest, restore, authority) = fixed_product_authority()
            .map_err(|error| format!("verify installed restore authority: {error}"))?;
        let manifest_sha256 = digest(&authority[0]);
        let tx = operation_transaction_id(
            &authority[2],
            &authority[3],
            &manifest_sha256,
            &current_boot,
        );
        let paths = Paths::new(&tx)?;
        let inventory = verify_committed_inventory(&manifest, &authority)
            .map_err(|error| format!("verify committed restore inventory: {error}"))?;
        let policy = read_bound(Path::new(POLICY), MAX_POLICY, 0o644)?;
        // The uninstall baseline must survive a restore performed over an
        // installed product: the live policy at restore start is the
        // install-patched one (voboost types inside), so binding the
        // "pristine" journal artifact to the live bytes turns the patched
        // policy into the baseline every later uninstall would restore
        // (the v95–v97 policy absence failures: uninstall faithfully
        // republished the patched bytes as pristine). The install-time
        // committed baseline is authoritative on an installed machine;
        // live bytes may stand in only when no committed baseline exists.
        let pristine_policy = installed_policy_baseline().unwrap_or_else(|| Artifact {
            path: Some(POLICY.to_string()),
            size: policy.len() as u64,
            sha256: digest(&policy),
        });
        mkdir(Path::new(RECOVERY))?;
        let j = Journal {
            schema_version: 1,
            phase: Phase::RestorePrepare,
            transaction_id: tx,
            restore_document_sha256: digest(&authority[2]),
            restore_signature_sha256: digest(&authority[3]),
            product_manifest_sha256: manifest_sha256,
            restorable_closure_sha256: restore.restorable_closure_sha256,
            install_inventory_sha256: digest(&inventory),
            release_identity: manifest.release_identity,
            pristine_policy,
            patched_policy: None,
            first_boot_id: current_boot.clone(),
            second_boot_id: None,
        };
        validate_journal(&j)?;
        if let Some(orphan) =
            reconcile_unleased_prepare(Path::new(PRODUCT_ROOT), &j, &authority, &guard)?
        {
            let paths = Paths::new(&orphan.transaction_id)?;
            preparation_guard = Some(guard);
            return Ok((paths, orphan));
        }
        guard.verify_owner()?;
        stage_prepare(Path::new(PRODUCT_ROOT), &j, &guard)?;
        preparation_guard = Some(guard);
        Ok((paths, j))
    })?;
    let lease = if let Some(guard) = preparation_guard {
        let descriptor = OperationDescriptor::new(
            Operation::Restore,
            journal.transaction_id.clone(),
            format!("recovery/{}/restore-journal.json", journal.transaction_id),
            boot_id()?,
        )?;
        let mut possibly_admitted = false;
        let result = guard.admit_operation_tracked(descriptor, &mut possibly_admitted);
        if possibly_admitted {
            *authenticated_transaction = Some(journal.transaction_id.clone());
        }
        result
    } else {
        // This branch was selected from the verified active Restore pointer.
        *authenticated_transaction = Some(journal.transaction_id.clone());
        acquire(&journal)
    }
    .map_err(|error| format!("acquire restore operation lease: {error}"))?;
    *authenticated_transaction = Some(journal.transaction_id.clone());
    lease.verify_owner()?;
    if read_bound(&paths.journal, 4096, 0o600)? != json(&journal)? {
        return Err("restore WAL changed before lease acquisition".into());
    }
    if let Some(request) = request {
        persist(&paths, &journal, &lease)?;
        reply.publish_with(Some(&journal.transaction_id), None, |transaction, error| {
            request::publish(request, transaction, error)
        })?;
    }
    let authority = bootstrap_authority(&paths, &journal)?;
    let (manifest, _) =
        verify_product_authority(&authority[0], &authority[1], &authority[2], &authority[3])?;
    stage_product_authority(&paths, &authority, &lease)?;
    stage_product_closure(&paths, &manifest, &lease)?;
    lease.verify_owner()?;
    staged_product_authority(&paths, &journal)?;
    lease.verify_owner()?;
    if paths.commit_journal.exists() {
        replay_committed_inventory(
            &paths,
            &journal.transaction_id,
            &read_bound(&paths.commit_journal, MAX_DOCUMENT, 0o600)?,
        )?;
    }
    protected_system_transaction::recover_pending(
        Path::new(INIT_HOOK),
        &paths.remount_wal,
        &journal.transaction_id,
    )?;
    lease.verify_owner()?;
    if mount_policy_transaction::consume_startup(&paths.policy_mount_wal, &current_boot)? {
        lease.verify_owner()?;
        return fixed_process::request_reboot();
    }
    drive_restore_phases(
        &mut journal,
        &mut DeviceRestoreActions {
            paths: &paths,
            lease: &lease,
        },
    )
}
fn dispatch_request(
    taken: Result<Option<request::Request>, String>,
) -> Result<(RunMode, Option<request::Request>), String> {
    match taken? {
        Some(request) => Ok((RunMode::Request, Some(request))),
        None => Ok((RunMode::InitContinuation, None)),
    }
}

fn main() {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.as_slice() == ["--product-system-update"] {
        #[cfg(target_os = "android")]
        if unsafe { libc::geteuid() } != 0
            || !invoked_by_init()
            || std::env::current_exe().ok().as_deref() != Some(Path::new(STABLE))
        {
            std::process::exit(2);
        }
        if let Err(error) = verify_self().and_then(|_| product_system::run()) {
            // Best-effort durable reason; never masks the original failure
            // and never mutates the WAL or the operation authority.
            record_product_system_error(&error);
            std::process::exit(12);
        }
        return;
    }
    let dispatch = arguments.as_slice() == ["--init-dispatch"];
    let mut mode = if arguments.is_empty() {
        RunMode::Request
    } else if dispatch || arguments.as_slice() == ["--init-continuation"] {
        RunMode::InitContinuation
    } else {
        std::process::exit(2);
    };
    #[cfg(target_os = "android")]
    if unsafe { libc::geteuid() } != 0
        || std::env::current_exe().ok().as_deref() != Some(Path::new(STABLE))
    {
        std::process::exit(2);
    }
    #[cfg(target_os = "android")]
    if mode == RunMode::InitContinuation && !invoked_by_init() {
        std::process::exit(2);
    }
    #[cfg(target_os = "android")]
    if arguments.is_empty() {
        if let Err(error) = verify_self() {
            let _ = std::io::stdout().write_all(&restore_pre_transaction_failure_bytes(&error));
            let _ = std::io::stdout().flush();
            std::process::exit(12);
        }
        match request::relay() {
            Ok(request::Admission::Accepted) => return,
            Ok(request::Admission::Rejected(bytes)) => {
                let _ = std::io::stdout().write_all(&bytes);
                let _ = std::io::stdout().flush();
                std::process::exit(12);
            }
            Err(error) => {
                diagnostic_log::stderr(
                    DiagnosticService::Restore,
                    DiagnosticLevel::Error,
                    "restore",
                    &error,
                    &[],
                );
                std::process::exit(75);
            }
        }
    }
    let request = if dispatch {
        if let Err(error) = verify_self() {
            diagnostic_log::stderr(
                DiagnosticService::Restore,
                DiagnosticLevel::Error,
                "restore",
                &error,
                &[],
            );
            std::process::exit(12);
        }
        match dispatch_request(request::take()) {
            Ok((selected, request)) => {
                mode = selected;
                request
            }
            Err(error) => {
                diagnostic_log::stderr(
                    DiagnosticService::Restore,
                    DiagnosticLevel::Error,
                    "restore.request",
                    &error,
                    &[("continuation", "not-run")],
                );
                std::process::exit(12);
            }
        }
    } else {
        None
    };
    // A failed self check must never produce a trusted admission reply.
    if let Err(error) = verify_self() {
        diagnostic_log::stderr(
            DiagnosticService::Restore,
            DiagnosticLevel::Error,
            "restore",
            &error,
            &[],
        );
        std::process::exit(12);
    }
    let mut authenticated_transaction = None;
    let mut reply = request::ReplyTracking::default();
    if let Err(error) = run(
        mode,
        &mut authenticated_transaction,
        request.as_ref(),
        &mut reply,
    ) {
        // The init worker does not relay stderr. Carry bounded metadata through
        // the existing authenticated operation error read by the desktop CLI.
        let error = restore_error_for_report(&error);
        if let Some(request) = &request {
            if let Err(publication_error) = reply.finish_failure_with(
                authenticated_transaction.as_deref(),
                &error,
                |transaction| {
                    let current = operation_contract::read_document_in(Path::new(PRODUCT_ROOT))?
                        .ok_or("restore admission lost its operation authority")?;
                    if current.operation != Operation::Restore
                        || current.transaction_id != transaction
                    {
                        return Err(
                            "restore admission differs from the real operation authority".into(),
                        );
                    }
                    Ok(())
                },
                |transaction, error| request::publish(request, transaction, error),
            ) {
                diagnostic_log::stderr(
                    DiagnosticService::Restore,
                    DiagnosticLevel::Error,
                    "restore.admission-reply",
                    &publication_error,
                    &[("recoveryMutation", "not-replayed")],
                );
            }
        }
        diagnostic_log::stderr(
            DiagnosticService::Restore,
            DiagnosticLevel::Error,
            "restore",
            &error,
            &[],
        );
        report_restore_failure_with(
            authenticated_transaction.as_deref(),
            &error,
            |transaction, error| publish_restore_failure(error, Some(transaction)),
            |bytes| {
                let _ = std::io::stdout().write_all(bytes);
                let _ = std::io::stdout().flush();
            },
        );
        std::process::exit(12);
    }
}

fn restore_error_for_report(error: &str) -> String {
    let Some(diagnostic) = restore_cil_error_diagnostic(error) else {
        return bounded_restore_error(error);
    };
    // Keep the original first cause intact at the beginning of the same
    // schema-bound message; only optional trailing metadata may be truncated.
    restore_error_with_diagnostic(error, &diagnostic)
}

fn restore_error_with_diagnostic(error: &str, diagnostic: &str) -> String {
    // The source path is already present in the first cause. Avoid repeating
    // it so caller and source-label metadata fit before optional parent data.
    let source = error
        .strip_prefix("open platform CIL digest ")
        .and_then(|value| value.split_once(": ").map(|(path, _)| path));
    let diagnostic = match source {
        Some(source) => diagnostic.replacen(&format!("path={source} "), "source ", 1),
        None => diagnostic.to_string(),
    };
    bounded_restore_error(&format!("{error}; {diagnostic}"))
}

// Error-only, bounded metadata census. Never reads digest contents or changes labels.
fn restore_cil_error_diagnostic(error: &str) -> Option<String> {
    const SOURCES: [&str; 4] = [
        "/system/etc/selinux/plat_and_mapping_sepolicy.cil.sha256",
        "/system/etc/selinux/plat_sepolicy_and_mapping.sha256",
        "/system_ext/etc/selinux/system_ext_sepolicy_and_mapping.sha256",
        "/product/etc/selinux/product_sepolicy_and_mapping.sha256",
    ];
    let path = SOURCES
        .into_iter()
        .find(|path| error.starts_with(&format!("open platform CIL digest {path}: ")))?;
    let caller = File::open("/proc/self/attr/current").and_then(|file| {
        let mut bytes = Vec::new();
        file.take(129).read_to_end(&mut bytes)?;
        Ok(bytes)
    });
    let caller = caller
        .map(|bytes| diagnostic_label(&bytes))
        .unwrap_or_else(|error| format!("unavailable:{:?}", error.raw_os_error()));
    Some(format!(
        "restore-cil-open diagnostic caller={caller}; {}; {}",
        diagnostic_path_metadata(Path::new(path)),
        diagnostic_path_metadata(Path::new(path).parent().expect("fixed CIL parent"))
    ))
}

fn diagnostic_label(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(128)
        .filter_map(|byte| {
            (byte.is_ascii_alphanumeric() || b"_:,.-".contains(byte)).then_some(*byte as char)
        })
        .collect()
}

fn diagnostic_path_metadata(path: &Path) -> String {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            return format!(
                "path={} metadata=unavailable:{:?}",
                path.display(),
                error.raw_os_error()
            );
        }
    };
    #[cfg(any(target_os = "android", target_os = "linux"))]
    let label = {
        use std::os::unix::ffi::OsStrExt;
        let name =
            std::ffi::CString::new(path.as_os_str().as_bytes()).expect("fixed path has no NUL");
        let mut bytes = [0u8; 128];
        let count = unsafe {
            libc::lgetxattr(
                name.as_ptr(),
                SELINUX_XATTR.as_ptr().cast(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if count < 0 {
            format!(
                "unavailable:{:?}",
                std::io::Error::last_os_error().raw_os_error()
            )
        } else {
            diagnostic_label(&bytes[..count as usize])
        }
    };
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    let label = "unavailable:unsupported-host".to_string();
    format!(
        "path={} uid={} gid={} mode={:04o} links={} symlink={} label={label}",
        path.display(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode() & 0o7777,
        metadata.nlink(),
        metadata.file_type().is_symlink()
    )
}

#[cfg(target_os = "android")]
fn invoked_by_init() -> bool {
    (unsafe { libc::getppid() == 1 })
        && fs::read_to_string("/proc/self/attr/current")
            .is_ok_and(|context| context.trim_end_matches(['\0', '\n']) == "u:r:voboost_restore:s0")
}

#[cfg(test)]
mod tests {
    #[test]
    fn restore_admission_rejects_partial_cluster_before_descriptor() {
        use super::*;
        let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let cluster = root.path().join("cluster");
        std::fs::create_dir(&cluster).unwrap();
        std::fs::set_permissions(&cluster, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(cluster.join("provision.json"), b"malformed").unwrap();
        std::fs::set_permissions(
            cluster.join("provision.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let descriptor = OperationDescriptor::new(
            Operation::Restore,
            "a".repeat(64),
            format!("recovery/{}/restore-journal.json", "a".repeat(64)),
            "00000000-0000-0000-0000-000000000001".into(),
        )
        .unwrap();
        assert!(acquire_restore_in(root.path(), descriptor).is_err());
        assert!(!root.path().join("operation.json").exists());
    }

    use super::*;
    #[test]
    fn cil_failure_diagnostic_is_fixed_bounded_and_has_no_digest_contents() {
        assert!(
            restore_cil_error_diagnostic("open platform CIL digest /caller/chosen: denied")
                .is_none()
        );
        assert!(restore_cil_error_diagnostic("unrelated failure").is_none());
        let output = restore_cil_error_diagnostic("open platform CIL digest /system/etc/selinux/plat_and_mapping_sepolicy.cil.sha256: denied").unwrap();
        assert!(output.len() < 1024);
        assert!(output.contains("caller=") && output.contains("/system/etc/selinux"));
        assert!(!output.contains("denied"));
        assert_eq!(
            diagnostic_label(b"u:object_r:sepolicy_file:s0\n\0\x1b"),
            "u:object_r:sepolicy_file:s0"
        );
        assert_eq!(diagnostic_label(&[b'a'; 512]).len(), 128);
    }
    #[test]
    fn cil_census_reaches_authenticated_operation_error_without_stderr_relay() {
        let original = "open platform CIL digest /system/etc/selinux/plat_and_mapping_sepolicy.cil.sha256: Permission denied (os error 13)";
        let message = restore_error_for_report(original);
        assert!(message.starts_with(original));
        assert!(message.contains("restore-cil-open diagnostic caller="));
        assert!(message.len() <= 512 && !message.chars().any(char::is_control));
        let actual_context = "restore-cil-open diagnostic caller=u:r:voboost_restore:s0; path=/system/etc/selinux/plat_and_mapping_sepolicy.cil.sha256 uid=0 gid=0 mode=0644 links=1 symlink=false label=u:object_r:sepolicy_file:s0; ";
        let bounded = restore_error_with_diagnostic(
            original,
            &format!("{actual_context}{}", "parent".repeat(512)),
        );
        assert_eq!(bounded.len(), 512);
        assert!(bounded.starts_with(original));
        assert!(bounded.contains("caller=u:r:voboost_restore:s0"));
        assert!(bounded.contains("source uid=0 gid=0 mode=0644"));
        assert!(bounded.contains("label=u:object_r:sepolicy_file:s0"));
        let journal = sample();
        report_restore_failure_with(
            Some(&journal.transaction_id),
            &message,
            |transaction, error| {
                assert_eq!(transaction, journal.transaction_id);
                let document = restore_operation_document(&journal, Some(error)).unwrap();
                let wire = serde_json::to_vec(&document).unwrap();
                let desktop: serde_json::Value = serde_json::from_slice(&wire).unwrap();
                assert_eq!(desktop["error"]["message"], message);
                assert_eq!(desktop["outcome"], "failed");
                assert_eq!(desktop["error"]["code"], "restore-failed");
                Ok(())
            },
            |_| panic!("authenticated diagnostic cannot use pre-transaction stdout"),
        );
        assert_eq!(restore_error_for_report("other failure"), "other failure");
    }

    #[test]
    fn cil_diagnostic_metadata_does_not_follow_symlinks_or_read_contents() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("digest");
        fs::write(&file, "PRIVATE-DIGEST-CONTENTS").unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        let output = diagnostic_path_metadata(&link);
        assert!(output.contains("symlink=true"));
        assert!(!output.contains("PRIVATE-DIGEST-CONTENTS"));
        assert!(
            diagnostic_path_metadata(&root.path().join("absent")).contains("metadata=unavailable")
        );
    }

    #[test]
    fn failed_request_take_cannot_select_mutating_continuation() {
        let result = dispatch_request(Err("consume request: sync denied".into()));
        assert!(matches!(result, Err(error) if error == "consume request: sync denied"));
        let (mode, request) = dispatch_request(Ok(None)).unwrap();
        assert_eq!(mode, RunMode::InitContinuation);
        assert!(request.is_none());
    }

    #[test]
    fn product_system_error_log_is_bounded_canonical_and_never_masks_failure() {
        // Deterministic serialization: bounded error text, fixed field order,
        // no transaction or path authority, and the original cause preserved
        // at the front of the message.
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let cause = "product system helper operation authority is invalid";
        record_product_system_error_in(root.path(), &format!("{cause}\n{}", "界".repeat(1000)))
            .unwrap();
        let log = root.path().join("logs").join("product-system-error.json");
        let metadata = fs::symlink_metadata(&log).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(
            fs::symlink_metadata(root.path().join("logs"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        let bytes = fs::read(&log).unwrap();
        assert!(bytes.len() <= 2048);
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            "{\"schemaVersion\":1,\"operation\":\"product-system-update\",\"error\":{\"code\":\"product-system-helper-failed\",\"message\":\"product system helper operation authority is invalid".to_string() + &"界".repeat((512 - cause.len()) / 3) + "\"}}\n"
        );
        // A second failure replaces only this fixed diagnostic; a foreign
        // symlink at the name is never followed (write_atomic publishes a
        // fresh trusted inode). Empty causes never produce an empty message.
        record_product_system_error_in(root.path(), "\n\r").unwrap();
        let value: serde_json::Value = serde_json::from_slice(&fs::read(&log).unwrap()).unwrap();
        assert_eq!(
            value["error"]["message"],
            "internal product-system helper failure"
        );
        assert_eq!(value["operation"], "product-system-update");
        assert!(value.get("transactionId").is_none());
        // A hostile symlink at the fixed name is never followed: the
        // trusted-publish contract rejects a foreign entry and leaves the
        // symlink target untouched.
        let outside = root.path().join("outside");
        fs::write(&outside, b"ORIGINAL").unwrap();
        fs::remove_file(&log).unwrap();
        std::os::unix::fs::symlink(&outside, &log).unwrap();
        assert!(record_product_system_error_in(root.path(), "cause").is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"ORIGINAL");
        assert!(fs::symlink_metadata(&log).unwrap().file_type().is_symlink());
        // Foreign root identity fails closed without touching anything.
        let foreign = tempfile::tempdir().unwrap();
        fs::set_permissions(foreign.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(record_product_system_error_in(foreign.path(), "cause").is_err());
        assert!(!foreign.path().join("logs").exists());
        // The swallowed caller never propagates an error to the caller that
        // must keep its own exit status: record_product_system_error returns
        // () even when the directory contract rejects the write.
        record_product_system_error_in(std::path::Path::new("/nonexistent-voboost-test"), "x")
            .unwrap_err();
    }

    #[test]
    fn restore_error_limit_is_bytes_and_preserves_utf8() {
        assert_eq!(bounded_restore_error(&"a".repeat(600)).len(), 512);
        assert_eq!(bounded_restore_error(&"я".repeat(600)), "я".repeat(256));
        assert_eq!(
            bounded_restore_error(&format!("{}界", "a".repeat(511))),
            "a".repeat(511)
        );
        assert_eq!(bounded_restore_error("bad\ninput\0"), "badinput");
    }

    #[test]
    fn io_diagnostics_retain_stage_path_and_errno_in_pretransaction_response() {
        let error = io_failure(
            "set recovery directory permissions",
            Path::new("/data/voboost/recovery"),
            std::io::Error::from_raw_os_error(13),
        );
        assert!(error.starts_with("set recovery directory permissions /data/voboost/recovery: "));
        assert!(error.contains("os error 13"));
        let value: serde_json::Value =
            serde_json::from_slice(&restore_pre_transaction_failure_bytes(&error)).unwrap();
        assert_eq!(value["error"]["message"], error);
        assert_eq!(value["failureType"], "pre-transaction");
        assert!(value.get("transactionId").is_none());
    }

    #[test]
    fn restore_pre_transaction_failure_is_bounded_canonical_and_has_no_transaction() {
        let bytes = restore_pre_transaction_failure_bytes("bad\ninput");
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            "{\"schemaVersion\":1,\"operation\":\"restore\",\"failureType\":\"pre-transaction\",\"error\":{\"code\":\"restore-pre-transaction-failed\",\"message\":\"badinput\"}}\n"
        );
        let value: serde_json::Value =
            serde_json::from_slice(&restore_pre_transaction_failure_bytes(&"界".repeat(1000)))
                .unwrap();
        assert_eq!(value["error"]["message"].as_str().unwrap().len(), 510);
        assert!(value.get("transactionId").is_none());
        let empty: serde_json::Value =
            serde_json::from_slice(&restore_pre_transaction_failure_bytes("\n\r")).unwrap();
        assert_eq!(empty["error"]["message"], "internal restore failure");
    }

    #[test]
    fn restore_admission_failure_preserves_cause_without_publishing_old_install() {
        let old = tempfile::tempdir().unwrap();
        write_admission_fixture(old.path(), Operation::Install, "complete");
        let pointer = old.path().join("operation.json");
        let before = fs::read(&pointer).unwrap();
        let mut output = Vec::new();
        report_restore_failure_with(
            None,
            "signed inventory rejected",
            |_, _| panic!("pre-transaction failure must not overwrite previous operation"),
            |bytes| output.extend_from_slice(bytes),
        );
        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["error"]["message"], "signed inventory rejected");
        assert_eq!(fs::read(&pointer).unwrap(), before);
        report_restore_failure_with(
            Some("authenticated-restore"),
            "stage failed",
            |id, message| {
                assert_eq!(id, "authenticated-restore");
                assert_eq!(message, "stage failed");
                Ok(())
            },
            |_| panic!("authenticated failure cannot lose transaction authority"),
        );
    }

    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;

    const RESTORE_SEED: [u8; 32] = [
        0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b, 0xed, 0xb7, 0x44, 0x2f, 0x31, 0xdc, 0xb7,
        0xb1, 0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f, 0x09, 0x4b, 0x85, 0xce, 0x3a, 0x2e, 0x0b, 0x44,
        0x58, 0xf7,
    ];

    #[derive(Default)]
    struct ScriptedRestoreActions {
        boot_id: String,
        fail: Option<Phase>,
        current: Option<Phase>,
        executed: Vec<Phase>,
        persisted: Vec<Phase>,
        reboots: usize,
        finished: usize,
    }

    impl ScriptedRestoreActions {
        fn action(&mut self, phase: Phase) -> Result<(), String> {
            self.current = Some(phase);
            self.executed.push(phase);
            if self.fail == Some(phase) {
                Err(format!("injected {phase:?} failure"))
            } else {
                Ok(())
            }
        }
    }

    impl RestoreActions for ScriptedRestoreActions {
        fn verify_owner(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn persist(&mut self, journal: &Journal) -> Result<(), String> {
            self.persisted.push(journal.phase);
            Ok(())
        }
        fn firmware_verify(&mut self, _journal: &Journal) -> Result<(), String> {
            self.action(Phase::RestoreFirmwareVerify)
        }
        fn policy_backup(&mut self, journal: &mut Journal) -> Result<(), String> {
            self.action(Phase::RestorePolicyBackup)?;
            journal.patched_policy = Some(Artifact {
                path: Some(POLICY.into()),
                size: 1,
                sha256: "1".repeat(64),
            });
            Ok(())
        }
        fn policy_apply(&mut self, _journal: &Journal) -> Result<(), String> {
            self.action(Phase::RestorePolicyApply)
        }
        fn runtime_apply(&mut self, _journal: &Journal) -> Result<(), String> {
            self.action(Phase::RestoreRuntimeApply)
        }
        fn post_second_boot(&mut self, _journal: &Journal, _now: &str) -> Result<(), String> {
            self.action(Phase::RestoreRebootSecond)
        }
        fn runtime_verify(&mut self, _journal: &Journal) -> Result<(), String> {
            self.action(Phase::RestoreRuntimeVerify)
        }
        fn cleanup_payload(&mut self) -> Result<(), String> {
            self.action(Phase::RestoreCleanup)
        }
        fn cleanup_control(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn finish(&mut self) -> Result<(), String> {
            self.finished += 1;
            Ok(())
        }
        fn boot_id(&mut self) -> Result<String, String> {
            Ok(self.boot_id.clone())
        }
        fn reboot(&mut self) -> Result<(), String> {
            self.reboots += 1;
            Ok(())
        }
    }
    fn sample() -> Journal {
        Journal {
            schema_version: 1,
            phase: Phase::RestorePrepare,
            transaction_id: "a".repeat(64),
            restore_document_sha256: "b".repeat(64),
            restore_signature_sha256: "c".repeat(64),
            product_manifest_sha256: "f".repeat(64),
            restorable_closure_sha256: "9".repeat(64),
            install_inventory_sha256: "d".repeat(64),
            release_identity: "1.0.0-beta1".into(),
            pristine_policy: Artifact {
                path: Some(POLICY.into()),
                size: 1,
                sha256: "e".repeat(64),
            },
            patched_policy: None,
            first_boot_id: "00000000-0000-0000-0000-000000000000".into(),
            second_boot_id: None,
        }
    }

    fn orphan_fixture() -> (tempfile::TempDir, Journal, [Vec<u8>; 4]) {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let authority = [
            b"manifest".to_vec(),
            b"signature".to_vec(),
            b"restore".to_vec(),
            b"restore-signature".to_vec(),
        ];
        let mut journal = sample();
        journal.product_manifest_sha256 = digest(&authority[0]);
        journal.restore_document_sha256 = digest(&authority[2]);
        journal.restore_signature_sha256 = digest(&authority[3]);
        journal.transaction_id = operation_transaction_id(
            &authority[2],
            &authority[3],
            &journal.product_manifest_sha256,
            &journal.first_boot_id,
        );
        let recovery = root.path().join("recovery");
        fs::create_dir(&recovery).unwrap();
        fs::set_permissions(&recovery, fs::Permissions::from_mode(0o700)).unwrap();
        let dir = recovery.join(&journal.transaction_id);
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(dir.join("restore-journal.json"), json(&journal).unwrap()).unwrap();
        fs::set_permissions(
            dir.join("restore-journal.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        (root, journal, authority)
    }

    #[test]
    fn interrupted_prepare_staging_publishes_only_complete_recovery_directory() {
        for cut in ["empty", "temporary", "complete"] {
            let (root, journal, authority) = orphan_fixture();
            let recovery = root.path().join("recovery");
            fs::remove_file(
                recovery
                    .join(&journal.transaction_id)
                    .join("restore-journal.json"),
            )
            .unwrap();
            fs::remove_dir(recovery.join(&journal.transaction_id)).unwrap();
            fs::create_dir(root.path().join("run")).unwrap();
            fs::set_permissions(root.path().join("run"), fs::Permissions::from_mode(0o755))
                .unwrap();
            let stage = root.path().join("run/restore-prepare");
            fs::create_dir(&stage).unwrap();
            fs::set_permissions(&stage, fs::Permissions::from_mode(0o700)).unwrap();
            if cut != "empty" {
                let name = if cut == "temporary" {
                    ".restore-journal.json.tmp"
                } else {
                    "restore-journal.json"
                };
                fs::write(stage.join(name), b"interrupted staging").unwrap();
                fs::set_permissions(stage.join(name), fs::Permissions::from_mode(0o600)).unwrap();
            }
            let guard = operation_contract::GenerationGuard::acquire_in(root.path()).unwrap();
            stage_prepare(root.path(), &journal, &guard).unwrap();
            assert!(!stage.exists());
            assert_eq!(
                reconcile_unleased_prepare(root.path(), &journal, &authority, &guard).unwrap(),
                Some(journal)
            );
        }
    }

    #[test]
    fn exact_unleased_prepare_is_adopted_without_cleanup_under_idle_barrier() {
        let (root, journal, authority) = orphan_fixture();
        let mut current = journal.clone();
        current.first_boot_id = "00000000-0000-0000-0000-000000000001".into();
        current.transaction_id = operation_transaction_id(
            &authority[2],
            &authority[3],
            &current.product_manifest_sha256,
            &current.first_boot_id,
        );
        let guard = operation_contract::GenerationGuard::acquire_in(root.path()).unwrap();
        assert_eq!(
            reconcile_unleased_prepare(root.path(), &current, &authority, &guard).unwrap(),
            Some(journal.clone())
        );
        assert_eq!(
            fs::read(
                root.path()
                    .join("recovery")
                    .join(&journal.transaction_id)
                    .join("restore-journal.json")
            )
            .unwrap(),
            json(&journal).unwrap()
        );
        assert!(!root.path().join("operation.json").exists());
        guard.verify_owner().unwrap();
    }

    #[test]
    fn unleased_prepare_rejects_foreign_corrupt_advanced_and_link_without_mutation() {
        for variant in ["foreign", "corrupt", "advanced", "extra", "link"] {
            let (root, expected, authority) = orphan_fixture();
            let dir = root.path().join("recovery").join(&expected.transaction_id);
            let path = dir.join("restore-journal.json");
            match variant {
                "foreign" => {
                    let mut j = expected.clone();
                    j.product_manifest_sha256 = "1".repeat(64);
                    fs::write(&path, json(&j).unwrap()).unwrap();
                }
                "corrupt" => fs::write(&path, b"broken").unwrap(),
                "advanced" => {
                    let mut j = expected.clone();
                    j.phase = Phase::RestoreFirmwareVerify;
                    fs::write(&path, json(&j).unwrap()).unwrap();
                }
                "extra" => fs::write(dir.join("other"), b"untouched").unwrap(),
                "link" => {
                    fs::remove_file(&path).unwrap();
                    std::os::unix::fs::symlink("outside", &path).unwrap();
                }
                _ => unreachable!(),
            }
            let before = fs::symlink_metadata(&path).unwrap();
            let bytes = fs::read(&path).ok();
            let guard = operation_contract::GenerationGuard::acquire_in(root.path()).unwrap();
            assert!(
                reconcile_unleased_prepare(root.path(), &expected, &authority, &guard).is_err(),
                "{variant}"
            );
            assert_eq!(fs::symlink_metadata(&path).unwrap().ino(), before.ino());
            assert_eq!(fs::read(&path).ok(), bytes);
            assert!(!root.path().join("operation.json").exists());
        }
    }

    #[test]
    fn prepare_promotion_retains_lock_and_active_operation_is_not_orphan_cleanup() {
        let (root, journal, authority) = orphan_fixture();
        let guard = operation_contract::GenerationGuard::acquire_in(root.path()).unwrap();
        assert!(operation_contract::GenerationGuard::acquire_in(root.path()).is_err());
        let descriptor = OperationDescriptor::new(
            Operation::Restore,
            journal.transaction_id.clone(),
            format!("recovery/{}/restore-journal.json", journal.transaction_id),
            journal.first_boot_id.clone(),
        )
        .unwrap();
        let lease = guard.admit_operation(descriptor).unwrap();
        lease.verify_owner().unwrap();
        assert!(operation_contract::GenerationGuard::acquire_in(root.path()).is_err());
        drop(lease);
        // Even after process/lock release, publication makes this admitted work.
        assert!(operation_contract::GenerationGuard::acquire_in(root.path()).is_err());
        assert_eq!(
            fs::read(
                root.path()
                    .join("recovery")
                    .join(&journal.transaction_id)
                    .join("restore-journal.json")
            )
            .unwrap(),
            json(&journal).unwrap()
        );
        assert_eq!(authority[0], b"manifest");
    }

    #[test]
    fn restore_resource_members_require_generation_and_never_root_shadow_files() {
        let root = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let generation = root.path().join("generation");
        fs::create_dir(&generation).unwrap();
        let (manifest, _, _) = reborn_authority();
        let template = manifest.artifact("libvoboost-runtime-cluster.so").unwrap();
        for (role, file) in [
            (
                ArtifactRole::ResourceApk,
                "resource-i18n-ru-setting-a11.apk",
            ),
            (
                ArtifactRole::ResourceLedger,
                "resource-i18n-ru-setting-a11.json",
            ),
            (
                ArtifactRole::QnxResourcePack,
                "qnx-resource-i18n-ru-a11-gauge.kzb",
            ),
            (
                ArtifactRole::QnxResourceLedger,
                "qnx-resource-i18n-ru-a11-gauge.json",
            ),
        ] {
            let bytes = b"generation-owned resource bytes";
            let mut artifact = template.clone();
            artifact.role = role;
            artifact.file = file.into();
            artifact.size = bytes.len() as u64;
            artifact.sha256 = digest(bytes);
            let live = generation.join(file);
            fs::write(&live, bytes).unwrap();
            fs::set_permissions(&live, fs::Permissions::from_mode(0o444)).unwrap();
            fs::write(root.path().join(file), b"root shadow is not authority").unwrap();
            assert_eq!(
                read_live_product_artifact_in(root.path(), &artifact, Some(&generation)).unwrap(),
                bytes
            );
            assert!(read_live_product_artifact_in(root.path(), &artifact, None).is_err());
        }
    }
    #[test]
    fn restore_reads_installer_qnx_root_and_generation_layout() {
        let root = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let generation = root.path().join("generations").join("candidate");
        fs::create_dir_all(&generation).unwrap();
        let (manifest, bodies, _) = reborn_authority();
        for (file, generation_member, mode) in [
            ("voboost-cluster-daemon", false, 0o700),
            ("voboost-cluster-startup.sh", false, 0o700),
            ("libvoboost-cluster-inject.so", false, 0o644),
            ("libvoboost-runtime-cluster.so", true, 0o444),
            ("libagent-font-cyrillic.so", true, 0o444),
        ] {
            let artifact = manifest.artifact(file).unwrap();
            let parent = if generation_member {
                &generation
            } else {
                root.path()
            };
            let path = parent.join(file);
            fs::write(&path, &bodies[file]).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                read_live_product_artifact_in(root.path(), artifact, Some(&generation)).unwrap(),
                bodies[file],
                "{file}",
            );
            if generation_member {
                assert!(read_live_product_artifact_in(root.path(), artifact, None).is_err());
                assert_eq!(root_flat_mode(artifact.role), None);
            }
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(
                read_live_product_artifact_in(root.path(), artifact, Some(&generation)).is_err()
            );
            fs::write(&path, vec![b'x'; artifact.size as usize]).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                read_live_product_artifact_in(root.path(), artifact, Some(&generation)).is_err()
            );
        }
    }

    #[test]
    fn restore_root_inventory_covers_signed_qnx_relay_closure() {
        let (manifest, bodies, authority) = reborn_authority();
        verify_product_authority(&authority[0], &authority[1], &authority[2], &authority[3])
            .unwrap();
        for (file, mode) in [
            ("voboost-cluster-daemon", 0o700),
            ("voboost-cluster-startup.sh", 0o700),
            ("libvoboost-cluster-inject.so", 0o644),
        ] {
            let artifact = manifest
                .artifacts
                .iter()
                .find(|row| row.file == file)
                .unwrap();
            assert_eq!(root_flat_mode(artifact.role), Some(mode), "{file}");
            let bytes = &bodies[file];
            verify_artifact_bytes(&manifest, file, bytes).unwrap();
            inventory_artifact_matches(&manifest, file, artifact.size, &artifact.sha256).unwrap();
            assert!(inventory_artifact_matches(
                &manifest,
                file,
                artifact.size + 1,
                &artifact.sha256,
            )
            .is_err());
            assert!(
                inventory_artifact_matches(&manifest, file, artifact.size, &"0".repeat(64))
                    .is_err()
            );
            let mut changed = bytes.clone();
            changed[0] ^= 1;
            assert!(verify_artifact_bytes(&manifest, file, &changed).is_err());
        }
        for role in [
            ArtifactRole::App,
            ArtifactRole::RestoreAuthorization,
            ArtifactRole::RestoreSignature,
            ArtifactRole::AgentCatalog,
            ArtifactRole::AgentCatalogSignature,
            ArtifactRole::AgentCommon,
            ArtifactRole::AgentModule,
            ArtifactRole::QnxRuntime,
            ArtifactRole::QnxAgentModule,
        ] {
            assert_eq!(root_flat_mode(role), None);
        }
    }

    fn reborn_authority() -> (Manifest, BTreeMap<String, Vec<u8>>, [Vec<u8>; 4]) {
        let mut manifest = Manifest::parse(include_bytes!(
            "../../test/fixtures/product-release/voboost/valid/minimal.json"
        ))
        .unwrap();
        let mut bodies = BTreeMap::new();
        for (index, artifact) in manifest.artifacts.iter_mut().enumerate() {
            if matches!(
                artifact.role,
                ArtifactRole::RestoreAuthorization | ArtifactRole::RestoreSignature
            ) {
                continue;
            }
            let bytes = format!("reborn:{}:{index}", artifact.file).into_bytes();
            artifact.size = bytes.len() as u64;
            artifact.sha256 = digest(&bytes);
            bodies.insert(artifact.file.clone(), bytes);
        }
        let restore = RestoreDocument {
            schema_version: 1,
            release_identity: manifest.release_identity.clone(),
            source_definition_sha256: "d".repeat(64),
            restorable_closure_sha256: voboost_contract::release::restorable_closure_sha256(
                &manifest,
            )
            .unwrap(),
        };
        let mut restore_bytes = serde_json::to_vec(&restore).unwrap();
        restore_bytes.push(b'\n');
        let restore_signature = SigningKey::from_bytes(&RESTORE_SEED)
            .sign(&restore_bytes)
            .to_bytes()
            .to_vec();
        for (name, bytes) in [
            ("restore.json", &restore_bytes),
            ("restore.json.sig", &restore_signature),
        ] {
            let artifact = manifest
                .artifacts
                .iter_mut()
                .find(|artifact| artifact.file == name)
                .unwrap();
            artifact.size = bytes.len() as u64;
            artifact.sha256 = digest(bytes);
        }
        manifest.validate().unwrap();
        let manifest_bytes = manifest.canonical_bytes().unwrap();
        let manifest_signature = SigningKey::from_bytes(&[12; 32])
            .sign(&manifest_bytes)
            .to_bytes()
            .to_vec();
        (
            manifest,
            bodies,
            [
                manifest_bytes,
                manifest_signature,
                restore_bytes,
                restore_signature,
            ],
        )
    }

    #[test]
    fn known_defect_absent_target_allows_deletion_without_authority() {
        let temp = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let root = temp.path().join("recovery");
        fs::create_dir(&root).unwrap();
        let baseline = root.join("oem-policy-baseline");
        fs::write(&baseline, b"baseline").unwrap();
        let paths = Paths {
            journal: root.join("restore-journal.json"),
            baseline: baseline.clone(),
            patched: root.join("voboost-policy.patched"),
            commit_root: root.join("inventory-commit"),
            commit_journal: root.join("inventory-commit.json"),
            remount_wal: root.join("init-remount.json"),
            policy_mount_wal: root.join("policy-mount.json"),
            authorization: root.join("authorization"),
            product_target: temp.path().join("product-target"),
            root,
        };
        // Characterizes a known defect, not the desired cleanup contract.
        cleanup_restore_payload(&paths).unwrap();
        assert!(!baseline.exists());
    }

    #[test]
    fn invalid_manifest_signature_preserves_product_target_member() {
        let temp = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let root = temp.path().join("recovery");
        let authorization = root.join("authorization");
        let product_target = temp.path().join("product-target");
        fs::create_dir_all(&authorization).unwrap();
        fs::create_dir(&product_target).unwrap();
        let (manifest, bodies, authority) = reborn_authority();
        for (name, bytes) in [
            ("voboost.json", &authority[0]),
            ("voboost.json.sig", &vec![0; 64]),
            ("restore.json", &authority[2]),
            ("restore.json.sig", &authority[3]),
        ] {
            let path = authorization.join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let artifact = manifest
            .artifacts
            .iter()
            .find(|a| bodies.contains_key(&a.file))
            .unwrap();
        let member = product_target.join(&artifact.file);
        fs::write(&member, &bodies[&artifact.file]).unwrap();
        let paths = Paths {
            journal: root.join("restore-journal.json"),
            baseline: root.join("oem-policy-baseline"),
            patched: root.join("voboost-policy.patched"),
            commit_root: root.join("inventory-commit"),
            commit_journal: root.join("inventory-commit.json"),
            remount_wal: root.join("init-remount.json"),
            policy_mount_wal: root.join("policy-mount.json"),
            authorization,
            product_target,
            root,
        };
        assert!(cleanup_restore_payload(&paths).is_err());
        assert!(member.exists());
    }

    #[test]
    fn reborn_authority_requires_raw_restore_and_active_product_binding() {
        let (manifest, _, authority) = reborn_authority();
        let (verified, restore) =
            verify_product_authority(&authority[0], &authority[1], &authority[2], &authority[3])
                .unwrap();
        assert_eq!(verified, manifest);
        assert_eq!(restore.release_identity, manifest.release_identity);

        let mut wrong_restore_signature = authority[3].clone();
        wrong_restore_signature[0] ^= 1;
        assert!(verify_product_authority(
            &authority[0],
            &authority[1],
            &authority[2],
            &wrong_restore_signature,
        )
        .is_err());

        let transcript_signature = SigningKey::from_bytes(&RESTORE_SEED)
            .sign(&[b"restore\0".as_slice(), authority[2].as_slice()].concat())
            .to_bytes();
        assert!(verify_raw_restore_signature(&authority[2], &transcript_signature).is_err());

        let mut other_manifest = manifest.clone();
        other_manifest.release_identity = "1.0.0-beta2".into();
        let other_manifest_bytes = other_manifest.canonical_bytes().unwrap();
        let other_manifest_signature = SigningKey::from_bytes(&[12; 32])
            .sign(&other_manifest_bytes)
            .to_bytes();
        assert!(verify_product_authority(
            &other_manifest_bytes,
            &other_manifest_signature,
            &authority[2],
            &authority[3],
        )
        .is_err());
    }

    #[test]
    fn every_reborn_restorable_row_is_flat_and_exactly_verified() {
        let (manifest, bodies, _) = reborn_authority();
        let expected = manifest
            .artifacts
            .iter()
            .filter(|artifact| {
                !matches!(
                    artifact.role,
                    ArtifactRole::RestoreAuthorization | ArtifactRole::RestoreSignature
                )
            })
            .map(|artifact| artifact.file.clone())
            .collect::<Vec<_>>();
        assert!(expected
            .iter()
            .all(|name| Path::new(name).components().count() == 1));
        verify_restorable_closure_with(&manifest, |artifact| {
            Ok(bodies.get(&artifact.file).unwrap().clone())
        })
        .unwrap();
        for corrupted in &expected {
            assert!(
                verify_restorable_closure_with(&manifest, |artifact| {
                    let mut bytes = bodies.get(&artifact.file).unwrap().clone();
                    if &artifact.file == corrupted {
                        bytes[0] ^= 1;
                    }
                    Ok(bytes)
                })
                .is_err(),
                "accepted corrupt {corrupted}"
            );
        }
    }

    #[test]
    fn production_restore_driver_crosses_two_boots_and_completes_exact_order() {
        let mut journal = sample();
        let mut actions = ScriptedRestoreActions {
            boot_id: journal.first_boot_id.clone(),
            ..Default::default()
        };
        drive_restore_phases(&mut journal, &mut actions).unwrap();
        assert_eq!(journal.phase, Phase::RestoreRebootFirst);
        assert_eq!(actions.reboots, 1);
        drive_restore_phases(&mut journal, &mut actions).unwrap();
        assert_eq!(journal.phase, Phase::RestoreRebootFirst);
        assert_eq!(actions.reboots, 2);

        actions.boot_id = "00000000-0000-0000-0000-000000000001".into();
        drive_restore_phases(&mut journal, &mut actions).unwrap();
        assert_eq!(journal.phase, Phase::RestoreRebootSecond);
        assert_eq!(actions.reboots, 3);
        drive_restore_phases(&mut journal, &mut actions).unwrap();
        assert_eq!(journal.phase, Phase::RestoreRebootSecond);
        assert_eq!(actions.reboots, 4);

        actions.boot_id = "00000000-0000-0000-0000-000000000002".into();
        drive_restore_phases(&mut journal, &mut actions).unwrap();
        assert_eq!(journal.phase, Phase::RestoreComplete);
        assert_eq!(actions.finished, 1);
        assert_eq!(
            actions.executed,
            [
                Phase::RestoreFirmwareVerify,
                Phase::RestorePolicyBackup,
                Phase::RestorePolicyApply,
                Phase::RestoreRuntimeApply,
                Phase::RestoreRebootSecond,
                Phase::RestoreRuntimeVerify,
                Phase::RestoreCleanup,
            ]
        );
    }

    #[test]
    fn production_restore_driver_retries_every_failed_mutating_phase() {
        for phase in [
            Phase::RestoreFirmwareVerify,
            Phase::RestorePolicyBackup,
            Phase::RestorePolicyApply,
            Phase::RestoreRuntimeApply,
            Phase::RestoreRebootSecond,
            Phase::RestoreRuntimeVerify,
            Phase::RestoreCleanup,
        ] {
            let mut journal = sample();
            journal.phase = phase;
            journal.patched_policy = Some(Artifact {
                path: Some(POLICY.into()),
                size: 1,
                sha256: "1".repeat(64),
            });
            if matches!(
                phase,
                Phase::RestoreRuntimeApply
                    | Phase::RestoreRebootSecond
                    | Phase::RestoreRuntimeVerify
                    | Phase::RestoreCleanup
            ) {
                journal.second_boot_id = Some("00000000-0000-0000-0000-000000000001".into());
            }
            let mut actions = ScriptedRestoreActions {
                boot_id: "00000000-0000-0000-0000-000000000002".into(),
                fail: Some(phase),
                ..Default::default()
            };
            assert!(
                drive_restore_phases(&mut journal, &mut actions).is_err(),
                "{phase:?}"
            );
            assert_eq!(journal.phase, phase, "{phase:?} advanced after failure");
            actions.fail = None;
            drive_restore_phases(&mut journal, &mut actions).unwrap();
            assert!(
                actions
                    .executed
                    .iter()
                    .filter(|value| **value == phase)
                    .count()
                    >= 2
            );
        }
    }

    #[test]
    fn restore_status_reserves_running_reboot_and_terminal_slots() {
        for (phase, normal_offset) in [
            (Phase::RestorePrepare, 1_u64),
            (Phase::RestoreRebootFirst, 2),
            (Phase::RestoreCleanup, 1),
            (Phase::RestoreComplete, 3),
        ] {
            let mut journal = sample();
            journal.phase = phase;
            if matches!(
                phase,
                Phase::RestoreRebootFirst | Phase::RestoreCleanup | Phase::RestoreComplete
            ) {
                journal.patched_policy = Some(Artifact {
                    path: Some(POLICY.to_string()),
                    size: 1,
                    sha256: "1".repeat(64),
                });
            }
            let number = phase as u64 + 1;
            assert_eq!(
                restore_operation_document(&journal, None)
                    .unwrap()
                    .status_sequence,
                (number - 1) * 3 + normal_offset
            );
            let failed = restore_operation_document(&journal, Some("failed\nreason")).unwrap();
            assert_eq!(failed.status_sequence, number * 3);
            assert_eq!(failed.outcome, "failed");
            assert!(!failed.error.unwrap()["message"]
                .as_str()
                .unwrap()
                .contains('\n'));
        }
    }
    #[test]
    fn phase_skip_fails() {
        let mut j = sample();
        assert!(advance(
            &mut j,
            Phase::RestorePolicyBackup,
            Phase::RestoreRebootFirst
        )
        .is_err());
    }
    #[test]
    fn arm32_high_bit_trailer_offset_cannot_truncate_to_prefix() {
        let prefix = 0x1234_u64;
        let forged = (1_u64 << 32) | prefix;
        assert!(checked_trailer_prefix(forged, prefix).is_err());
        assert_eq!(
            checked_trailer_prefix(prefix, prefix).unwrap(),
            prefix as usize
        );
    }
    #[test]
    fn schema_one_restore_phases_match_architecture_exactly() {
        let phases = [
            Phase::RestorePrepare,
            Phase::RestoreFirmwareVerify,
            Phase::RestorePolicyBackup,
            Phase::RestorePolicyApply,
            Phase::RestoreRebootFirst,
            Phase::RestoreRuntimeApply,
            Phase::RestoreRebootSecond,
            Phase::RestoreRuntimeVerify,
            Phase::RestoreInventoryCommit,
            Phase::RestoreCleanup,
            Phase::RestoreComplete,
        ];
        let expected = [
            "restore-prepare",
            "restore-firmware-verify",
            "restore-policy-backup",
            "restore-policy-apply",
            "restore-reboot-first",
            "restore-runtime-apply",
            "restore-reboot-second",
            "restore-runtime-verify",
            "restore-inventory-commit",
            "restore-cleanup",
            "restore-complete",
        ];
        let serialized = phases
            .iter()
            .map(|phase| serde_json::to_string(phase).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            serialized,
            expected
                .iter()
                .map(|phase| format!("\"{phase}\""))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            serialized
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            phases.len(),
            "restore phase vocabulary contains a duplicate"
        );
        for (phase, encoded) in phases.iter().zip(&serialized) {
            assert_eq!(serde_json::from_str::<Phase>(encoded).unwrap(), *phase);
        }
        for rejected in [
            "\"restore\"",
            "\"restore_prepare\"",
            "\"prepare\"",
            "\"RestorePrepare\"",
            "null",
        ] {
            assert!(serde_json::from_str::<Phase>(rejected).is_err());
        }
        let mut j = sample();
        for pair in phases.windows(2) {
            advance(&mut j, pair[0], pair[1]).unwrap();
            assert_eq!(
                serde_json::from_slice::<Journal>(&json(&j).unwrap()).unwrap(),
                j
            );
        }
    }

    #[test]
    fn archived_init_authority_binds_exact_installed_size_and_digest() {
        let bytes = b"service voboost /data/voboost/voboost-daemon\n";
        let mut metadata = ArchivedInitMetadata {
            path: INIT_HOOK.to_string(),
            installed_size: bytes.len() as u64,
            installed_sha256: digest(bytes),
            archive_path: INIT_ARCHIVE.to_string(),
            uid: 0,
            gid: 0,
            mode: "0644".to_string(),
            context: "u:object_r:system_file:s0".to_string(),
        };
        assert!(validate_archived_init_authority(bytes, &metadata).is_ok());
        metadata.installed_size += 1;
        assert!(validate_archived_init_authority(bytes, &metadata).is_err());
        metadata.installed_size -= 1;
        metadata.installed_sha256 = "0".repeat(64);
        assert!(validate_archived_init_authority(bytes, &metadata).is_err());
    }

    #[test]
    fn distinct_two_boot_ids_are_required() {
        assert!(post_second_boot("boot-a", "boot-a", "boot-c").is_err());
        assert!(post_second_boot("boot-a", "boot-b", "boot-b").is_err());
        assert!(post_second_boot("boot-a", "boot-b", "boot-c").is_ok());
    }

    #[test]
    fn policy_mismatch_is_rejected() {
        let expected = Artifact {
            path: Some(POLICY.into()),
            size: 7,
            sha256: digest(b"patched"),
        };
        assert!(artifact_matches(b"patched", &expected));
        assert!(!artifact_matches(b"foreign", &expected));
    }

    #[test]
    fn inventory_is_the_last_commit_member() {
        let paths = [
            SYSTEM_ARTIFACTS,
            CURRENT_BASELINE,
            POLICY_META,
            SYSTEM_STATE,
            INVENTORY,
        ];
        assert_eq!(paths.len(), 5);
        assert_eq!(paths.last(), Some(&INVENTORY));
    }

    #[test]
    fn committed_inventory_replay_rejects_a_foreign_transaction() {
        // RF2: only this transaction's durable commit journal may drive the
        // idempotent replay; a foreign one fails closed before any member
        // is touched.
        let paths = Paths::new(&"a".repeat(64)).unwrap();
        let foreign = serde_json::json!({
            "schemaVersion": 1,
            "transactionId": "b".repeat(64),
            "oldBaselinePath": "/data/voboost/uninstall/baselines/old",
            "newBaselinePath": "/data/voboost/uninstall/baselines/new",
            "members": [],
        });
        let error = replay_committed_inventory(
            &paths,
            &"a".repeat(64),
            serde_json::to_vec(&foreign).unwrap().as_slice(),
        )
        .unwrap_err();
        assert_eq!(
            error,
            "restore commit journal belongs to another transaction"
        );
        let corrupt = serde_json::json!({"schemaVersion": 2});
        assert!(replay_committed_inventory(
            &paths,
            &"a".repeat(64),
            serde_json::to_vec(&corrupt).unwrap().as_slice()
        )
        .is_err());
    }

    #[test]
    fn existing_digest_path_baseline_backup_is_verified_by_exact_bytes() {
        // RF3: an interrupted earlier attempt may leave residue at the
        // digest-path backup target. Only exact pristine bytes and a trusted
        // 0o600 regular identity are adopted; corrupted or foreign residue
        // fails closed instead of tying the inventory to a bad baseline.
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let target = directory.path().join("precompiled_sepolicy.orig");
        assert!(verify_existing_baseline_backup(&target, b"pristine").is_err());

        std::fs::write(&target, b"pristine").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        verify_existing_baseline_backup(&target, b"pristine").unwrap();

        std::fs::write(&target, b"committed residue").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            verify_existing_baseline_backup(&target, b"pristine").unwrap_err(),
            "existing digest-path baseline differs from journal"
        );

        let relaxed = directory.path().join("relaxed.orig");
        std::fs::write(&relaxed, b"pristine").unwrap();
        std::fs::set_permissions(&relaxed, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(verify_existing_baseline_backup(&relaxed, b"pristine").is_err());
    }

    #[test]
    fn committed_inventory_replay_retires_only_exact_duplicate_temporaries() {
        let target = bound(b"new inventory");
        let path = Path::new("inventory-commit/install-inventory.json");
        let mut removed = 0;
        let mut synced = 0;
        retire_committed_temporary_with(
            path,
            &target,
            |_| Ok(Some(b"new inventory".to_vec())),
            |_| {
                removed += 1;
                Ok(())
            },
            |_| {
                synced += 1;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!((removed, synced), (1, 1));

        retire_committed_temporary_with(
            path,
            &target,
            |_| Ok(None),
            |_| panic!("absent committed temporary was removed"),
            |_| panic!("absent committed temporary was synced"),
        )
        .unwrap();

        assert!(retire_committed_temporary_with(
            path,
            &target,
            |_| Ok(Some(b"foreign inventory".to_vec())),
            |_| panic!("foreign committed temporary was removed"),
            |_| panic!("foreign committed temporary was synced"),
        )
        .is_err());
    }

    #[test]
    fn transaction_identity_binds_signed_restore_authority_and_starting_boot() {
        let descriptor = b"canonical descriptor\n";
        let signature = [7_u8; 64];
        let boot = "00000000-0000-0000-0000-000000000001";
        let manifest = "f".repeat(64);
        let first = operation_transaction_id(descriptor, &signature, &manifest, boot);
        assert_eq!(
            first,
            operation_transaction_id(descriptor, &signature, &manifest, boot)
        );
        assert_ne!(
            first,
            operation_transaction_id(b"other descriptor\n", &signature, &manifest, boot)
        );
        let mut other_signature = signature;
        other_signature[0] ^= 1;
        assert_ne!(
            first,
            operation_transaction_id(descriptor, &other_signature, &manifest, boot)
        );
        assert_ne!(
            first,
            operation_transaction_id(descriptor, &signature, &"e".repeat(64), boot)
        );
        assert_ne!(
            first,
            operation_transaction_id(
                descriptor,
                &signature,
                &manifest,
                "00000000-0000-0000-0000-000000000002"
            )
        );
    }

    #[test]
    fn crash_cut_sidecars_are_transaction_namespaced_without_collision() {
        let a = Paths::new(&"a".repeat(64)).unwrap();
        let b = Paths::new(&"b".repeat(64)).unwrap();
        for path in [
            &a.journal,
            &a.baseline,
            &a.patched,
            &a.commit_root,
            &a.commit_journal,
            &a.remount_wal,
            &a.policy_mount_wal,
            &a.product_target,
        ] {
            assert!(path.starts_with(&a.root));
            assert!(!path.starts_with(&b.root));
        }
        assert!(a.authorization.ends_with("authorization"));
        assert!(a.authorization.starts_with(&a.root));
        assert_ne!(a.authorization, b.authorization);
        for forbidden in [
            "restore-commit",
            "restore-commit.json",
            "restore-init-remount.json",
            "restore-mount-policy.json",
        ] {
            assert!(!a
                .root
                .parent()
                .unwrap()
                .join(forbidden)
                .starts_with(&a.root));
        }
    }

    #[test]
    fn every_bootstrap_cut_preserves_exact_retry_authority() {
        #[derive(Clone, Copy)]
        struct BootstrapState {
            wal: bool,
            lease: bool,
            fixed_descriptor: bool,
            fixed_signature: bool,
            staged_descriptor: bool,
            staged_signature: bool,
        }
        let actions: [fn(&mut BootstrapState); 5] = [
            |state| state.lease = true,
            |state| state.staged_descriptor = true,
            |state| state.staged_signature = true,
            |state| state.fixed_descriptor = false,
            |state| state.fixed_signature = false,
        ];
        for cut in 0..=actions.len() {
            let mut state = BootstrapState {
                wal: true,
                lease: false,
                fixed_descriptor: true,
                fixed_signature: true,
                staged_descriptor: false,
                staged_signature: false,
            };
            for action in actions.iter().take(cut) {
                action(&mut state);
            }
            assert!(state.wal, "cut {cut} lost the correlated restore WAL");
            assert!(
                state.fixed_descriptor || state.staged_descriptor,
                "cut {cut} lost the signed descriptor"
            );
            assert!(
                state.fixed_signature || state.staged_signature,
                "cut {cut} lost the descriptor signature"
            );
            if !state.lease {
                assert!(state.fixed_descriptor && state.fixed_signature);
            }
            if !state.fixed_descriptor || !state.fixed_signature {
                assert!(state.lease && state.staged_descriptor && state.staged_signature);
            }
        }
    }

    #[test]
    fn foreign_lease_after_wal_persist_keeps_fixed_signed_retry_inputs() {
        let wal_transaction = "a".repeat(64);
        let requested_transaction = operation_transaction_id(
            b"descriptor\n",
            &[7_u8; 64],
            &"c".repeat(64),
            "00000000-0000-0000-0000-000000000001",
        );
        let foreign_transaction = "b".repeat(64);
        assert_ne!(requested_transaction, foreign_transaction);
        assert_eq!(wal_transaction.len(), requested_transaction.len());

        // A busy/foreign acquisition performs none of the under-lease staging
        // or retirement actions. The exact signed input pair remains the retry
        // authority for the already durable transaction WAL.
        let fixed_descriptor = true;
        let fixed_signature = true;
        let staged_descriptor = false;
        let staged_signature = false;
        assert!(fixed_descriptor && fixed_signature);
        assert!(!staged_descriptor && !staged_signature);
    }

    fn write_admission_fixture(
        root: &Path,
        operation: Operation,
        outcome: &str,
    ) -> OperationDescriptor {
        fs::set_permissions(root, fs::Permissions::from_mode(0o755)).unwrap();
        let transaction_id = "a".repeat(64);
        let journal_relative = format!(
            "recovery/{transaction_id}/{}-journal.json",
            operation.as_str()
        );
        let mut descriptor = OperationDescriptor::new(
            operation,
            transaction_id.clone(),
            journal_relative.clone(),
            "00000000-0000-0000-0000-000000000001".into(),
        )
        .unwrap();
        if operation == Operation::Restore {
            let recovery = root.join("recovery");
            let transaction = recovery.join(&transaction_id);
            fs::create_dir(&recovery).unwrap();
            fs::set_permissions(&recovery, fs::Permissions::from_mode(0o700)).unwrap();
            fs::create_dir(&transaction).unwrap();
            fs::set_permissions(&transaction, fs::Permissions::from_mode(0o700)).unwrap();
            let bytes = json(&sample()).unwrap();
            fs::write(root.join(&journal_relative), &bytes).unwrap();
            fs::set_permissions(
                root.join(&journal_relative),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            descriptor.journal_sha256 = digest(&bytes);
        }
        descriptor.outcome = outcome.into();
        if operation == Operation::Install && outcome == "complete" {
            descriptor.phase = "install-complete".into();
            descriptor.installed_apk = Some(serde_json::json!({
                "packageName": "ru.voboost",
                "versionCode": 1,
                "certificateSha256": "b".repeat(64),
                "path": "/data/app/ru.voboost-fixture/base.apk",
                "size": 1,
                "sha256": "c".repeat(64)
            }));
        }
        if outcome == "failed" {
            descriptor.error = Some(serde_json::json!({
                "code": "restore-failed",
                "message": "injected failure"
            }));
        }
        fs::write(
            root.join("operation.json"),
            descriptor.canonical_bytes().unwrap(),
        )
        .unwrap();
        fs::set_permissions(
            root.join("operation.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        descriptor
    }

    fn admit_fixture(root: &Path) -> Result<InitAdmission, String> {
        init_admission_with(root, |path| {
            fs::read(path).map_err(|error| error.to_string())
        })
    }

    #[test]
    fn init_admission_uses_verified_temp_state_without_creator_side_effects() {
        let absent = tempfile::tempdir().unwrap();
        fs::set_permissions(absent.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(admit_fixture(absent.path()).unwrap(), InitAdmission::Noop);

        let other = tempfile::tempdir().unwrap();
        write_admission_fixture(other.path(), Operation::Install, "running");
        assert_eq!(admit_fixture(other.path()).unwrap(), InitAdmission::Noop);

        for (outcome, resumes) in [
            ("running", true),
            ("reboot-required", true),
            ("failed", false),
        ] {
            let state = tempfile::tempdir().unwrap();
            write_admission_fixture(state.path(), Operation::Restore, outcome);
            let mut created = 0;
            let admission = admit_fixture(state.path()).unwrap();
            if matches!(admission, InitAdmission::Resume(_)) {
                assert!(select_existing_or_create(
                    RunMode::InitContinuation,
                    None::<usize>,
                    || {
                        created += 1;
                        Ok(1)
                    },
                )
                .is_err());
            }
            assert_eq!(matches!(admission, InitAdmission::Resume(_)), resumes);
            assert_eq!(created, 0);
        }

        let stale_projection = tempfile::tempdir().unwrap();
        let descriptor =
            write_admission_fixture(stale_projection.path(), Operation::Restore, "running");
        let mut advanced = sample();
        advanced.phase = Phase::RestoreRuntimeApply;
        advanced.patched_policy = Some(Artifact {
            path: Some(POLICY.into()),
            size: 1,
            sha256: "1".repeat(64),
        });
        fs::write(
            stale_projection.path().join(descriptor.journal),
            json(&advanced).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            admit_fixture(stale_projection.path()).unwrap(),
            InitAdmission::Resume(_)
        ));

        let malformed = tempfile::tempdir().unwrap();
        let descriptor = write_admission_fixture(malformed.path(), Operation::Restore, "running");
        fs::write(
            malformed.path().join(descriptor.journal),
            b"not canonical journal\n",
        )
        .unwrap();
        assert!(admit_fixture(malformed.path()).is_err());
    }

    #[test]
    fn explicit_request_remains_creator_after_terminal_cleanup() {
        let mut created = 0;
        let selected = select_existing_or_create(RunMode::Request, None, || {
            created += 1;
            Ok("new restore")
        })
        .unwrap();
        assert_eq!(selected, "new restore");
        assert_eq!(created, 1);

        let selected = select_existing_or_create(RunMode::Request, Some("resumed"), || {
            created += 1;
            Ok("unexpected")
        })
        .unwrap();
        assert_eq!(selected, "resumed");
        assert_eq!(created, 1);
    }
}
