// Signed, no-argument, device-owned install transaction.
#![cfg_attr(not(target_os = "android"), allow(dead_code, unused_imports))]
use voboost_shared::diagnostic_log::{
    self, Level as DiagnosticLevel, Service as DiagnosticService,
};

use voboost_contract::resource_none_helper;
mod acceptance;
mod contract;
use voboost_shared::fixed_process;
use voboost_shared::owned_overlay::Variant;
mod fresh;
use voboost_shared::installed_apk;
mod i18n_resource_admission;
#[path = "../../shared/src/i18n_resource_files.rs"]
mod i18n_resource_files;
mod initial_seeding;
mod inventory;
mod journal;
mod policy;
mod runtime;
mod selinux_backend;
use voboost_contract::{generation as generation_contract, install as install_contract};
use voboost_shared::native_executable_signature;
mod transaction;

use voboost_shared::uninstall_contract;

use voboost_shared::self_executable;

use voboost_shared::mount_policy_transaction;

use voboost_contract::operation as operation_contract;

include!(concat!(env!("OUT_DIR"), "/install_role_keys.rs"));

use contract::{InstallDescriptor, StagingDescriptor, STAGING_DESCRIPTOR_NAME};
use ed25519_dalek::{Signature, VerifyingKey};
use journal::{InstallJournal, InstallPhase};
use operation_contract::{Operation, OperationDescriptor, OperationLease};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(test)]
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const ROOT: &str = "/data/voboost";
const INSTALL_ROOT: &str = "/data/voboost/install";
const SELF_PATH: &str = "/data/voboost/voboost-install";
const ROOT_DOCUMENT: &[u8] = uninstall_contract::ROOT_ZONE_MARKER_BYTES;
const SIGNATURE_MAGIC: &[u8; 8] = b"VOBOOST\0";
const SIGNATURE_TRAILER_BYTES: usize = 80;
const MAX_SELF_BYTES: usize = 16 * 1024 * 1024;
const MAX_INSTALL_JOURNAL_BYTES: usize = 64 * 1024;
const MAX_TERMINAL_INTENT_BYTES: usize = 4096;
// 1024 signed artifacts, the manifest pair, and staging.json.
const MAX_STAGING_ENTRIES: usize = voboost_contract::release::MAX_ARTIFACTS + 3;

struct RetainedDirectory {
    path: PathBuf,
    file: File,
    identity: (u64, u64),
    owner: (u32, u32),
    mode: u32,
}

struct StagingRoot {
    path: PathBuf,
    file: File,
    identity: (u64, u64, u64),
}

impl StagingRoot {
    fn open(path: &Path) -> Result<Self, String> {
        let named = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(path)
            .map_err(|error| format!("open install staging root: {error}"))?;
        let opened = file.metadata().map_err(|error| error.to_string())?;
        if !named.is_dir()
            || named.file_type().is_symlink()
            || !opened.is_dir()
            || opened.nlink() < 2
            || opened.permissions().mode() & 0o7777 != 0o700
            || (named.dev(), named.ino()) != (opened.dev(), opened.ino())
        {
            return Err("install staging root authority is unsafe".to_string());
        }
        #[cfg(target_os = "android")]
        if opened.uid() != 0 || opened.gid() != 0 {
            return Err("install staging root is not root-owned".to_string());
        }
        Ok(Self {
            path: path.to_path_buf(),
            file,
            identity: (opened.dev(), opened.ino(), opened.nlink()),
        })
    }

    fn verify_named_identity(&self) -> Result<(), String> {
        let named = fs::symlink_metadata(&self.path).map_err(|error| error.to_string())?;
        let opened = self.file.metadata().map_err(|error| error.to_string())?;
        if (opened.dev(), opened.ino(), opened.nlink()) != self.identity
            || (named.dev(), named.ino()) != (opened.dev(), opened.ino())
        {
            return Err("install staging root identity changed".to_string());
        }
        Ok(())
    }

    fn entry_names(&self) -> Result<BTreeSet<String>, String> {
        unsafe fn errno_location() -> *mut libc::c_int {
            #[cfg(target_os = "macos")]
            {
                libc::__error()
            }
            #[cfg(target_os = "android")]
            {
                libc::__errno()
            }
            #[cfg(not(any(target_os = "macos", target_os = "android")))]
            {
                libc::__errno_location()
            }
        }
        let duplicate = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
            )
        };
        if duplicate < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let stream = unsafe { libc::fdopendir(duplicate) };
        if stream.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe { libc::close(duplicate) };
            return Err(error.to_string());
        }
        let mut names = BTreeSet::new();
        let result = loop {
            unsafe { *errno_location() = 0 };
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                let errno = unsafe { *errno_location() };
                break if errno == 0 {
                    Ok(names)
                } else {
                    Err(std::io::Error::from_raw_os_error(errno).to_string())
                };
            }
            let bytes = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            if names.len() >= MAX_STAGING_ENTRIES {
                break Err("install staging entry bound exceeded".to_string());
            }
            let name = match std::str::from_utf8(bytes) {
                Ok(name) => name,
                Err(_) => break Err("install staging entry is not UTF-8".to_string()),
            };
            let name = match std::ffi::CString::new(name) {
                Ok(name) => name,
                Err(_) => break Err("install staging entry contains NUL".to_string()),
            };
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::fstatat(
                    self.file.as_raw_fd(),
                    name.as_ptr(),
                    &mut stat,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                break Err(std::io::Error::last_os_error().to_string());
            }
            if stat.st_mode & libc::S_IFMT != libc::S_IFREG
                || stat.st_nlink != 1
                || stat.st_mode & 0o7777 != 0o600
            {
                break Err("install staging entry is not a mode-0600 single-link file".to_string());
            }
            #[cfg(target_os = "android")]
            if stat.st_uid != 0 || stat.st_gid != 0 {
                break Err("install staging entry is not root-owned".to_string());
            }
            if !names.insert(name.to_string_lossy().into_owned()) {
                break Err("install staging entry name is duplicated".to_string());
            }
        };
        unsafe { libc::closedir(stream) };
        result
    }

    fn open_file(&self, name: &str) -> Result<File, String> {
        let name = std::ffi::CString::new(name).map_err(|_| "staging basename contains NUL")?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o7777 != 0o600
        {
            return Err("opened install staging entry identity is unsafe".to_string());
        }
        #[cfg(target_os = "android")]
        if metadata.uid() != 0 || metadata.gid() != 0 {
            return Err("opened install staging entry is not root-owned".to_string());
        }
        Ok(file)
    }

    fn read(&self, name: &str, maximum: usize) -> Result<Vec<u8>, String> {
        let mut file = self.open_file(name)?;
        let before = file.metadata().map_err(|error| error.to_string())?;
        if before.len() > maximum as u64 {
            return Err("install staging entry exceeds byte bound".to_string());
        }
        let mut bytes = Vec::with_capacity(before.len() as usize);
        (&mut file)
            .take(maximum.saturating_add(1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        let after = file.metadata().map_err(|error| error.to_string())?;
        if bytes.len() > maximum
            || bytes.len() as u64 != before.len()
            || file_identity(&before) != file_identity(&after)
        {
            return Err("install staging entry changed while reading".to_string());
        }
        Ok(bytes)
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct PreTransactionFailure<'a> {
    schema_version: u32,
    operation: &'static str,
    failure_type: &'static str,
    error: PreTransactionError<'a>,
}

#[derive(serde::Serialize)]
struct PreTransactionError<'a> {
    code: &'static str,
    message: &'a str,
}

#[cfg(target_os = "android")]
fn android_property(name: &std::ffi::CStr) -> String {
    unsafe extern "C" {
        fn __system_property_get(name: *const libc::c_char, value: *mut libc::c_char) -> i32;
    }
    let mut value = [0 as libc::c_char; 92];
    let length = unsafe { __system_property_get(name.as_ptr(), value.as_mut_ptr()) };
    if length <= 0 || length as usize >= value.len() {
        return String::new();
    }
    unsafe { std::ffi::CStr::from_ptr(value.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

fn monotonic_ms() -> Result<u64, String> {
    let mut time: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return Err("read install monotonic clock".into());
    }
    Ok(time.tv_sec as u64 * 1000 + time.tv_nsec as u64 / 1_000_000)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Invocation {
    Install,
    I18nEarlyCleanup,
    I18nNoneFinalize,
}

fn invocation(args: &[std::ffi::OsString]) -> Result<Invocation, String> {
    match args {
        [] => Ok(Invocation::Install),
        [flag] if flag == "--i18n-early-cleanup" => Ok(Invocation::I18nEarlyCleanup),
        [flag] if flag == "--i18n-none-finalize" => Ok(Invocation::I18nNoneFinalize),
        _ => Err("public arguments are not accepted".into()),
    }
}

fn main() {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if let Ok(kind @ (Invocation::I18nEarlyCleanup | Invocation::I18nNoneFinalize)) =
        invocation(&args)
    {
        if let Err(error) = run_i18n_cleanup(kind) {
            diagnostic_log::stderr(
                DiagnosticService::Install,
                DiagnosticLevel::Error,
                "install.i18n-cleanup",
                &error,
                &[],
            );
            std::process::exit(1);
        }
        return;
    }
    let mut transaction_id = None;
    if let Err(error) = run(&mut transaction_id) {
        diagnostic_log::stderr(
            DiagnosticService::Install,
            DiagnosticLevel::Error,
            "install",
            &error,
            &[],
        );
        report_install_failure_with(
            transaction_id.as_deref(),
            &error,
            publish_install_failure,
            emit_pre_transaction_failure,
        );
        std::process::exit(1);
    }
}

fn report_install_failure_with(
    transaction_id: Option<&str>,
    error: &str,
    publish: impl FnOnce(&str, &str) -> Result<(), String>,
    emit_pre_transaction: impl FnOnce(&str),
) {
    if let Some(transaction_id) = transaction_id {
        let _ = publish(transaction_id, error);
    } else {
        emit_pre_transaction(error);
    }
}

#[cfg_attr(not(target_os = "android"), allow(unused_variables))]
fn run(transaction_id: &mut Option<String>) -> Result<(), String> {
    if invocation(&std::env::args_os().skip(1).collect::<Vec<_>>())? != Invocation::Install {
        return Err("install invocation required".into());
    }
    #[cfg(target_os = "android")]
    {
        verify_device_identity()?;
        run_device_transaction(transaction_id)?;
        Ok(())
    }
    #[cfg(not(target_os = "android"))]
    Err("device install requires Android".to_string())
}

fn cleanup_domain_allowed(uid: u32, parent_pid: u32, context: &[u8]) -> bool {
    uid == 0
        && parent_pid == 1
        && context.strip_suffix(b"\0").unwrap_or(context) == b"u:r:voboost_install:s0"
}

fn run_i18n_cleanup(kind: Invocation) -> Result<(), String> {
    if kind == Invocation::Install {
        return Err("resource cleanup invocation required".into());
    }
    #[cfg(target_os = "android")]
    {
        verify_device_identity()?;
        let context = fs::read("/proc/self/attr/current")
            .map_err(|error| format!("read cleanup domain: {error}"))?;
        if !cleanup_domain_allowed(
            unsafe { libc::geteuid() },
            unsafe { libc::getppid() } as u32,
            &context,
        ) {
            return Err("i18n cleanup requires installer domain".into());
        }
        if kind == Invocation::I18nNoneFinalize {
            i18n_resource_files::finalize_none_verified(&RELEASE_CATALOG_PUBLIC_KEY)
        } else {
            i18n_resource_files::early_cleanup_verified(&RELEASE_CATALOG_PUBLIC_KEY)
        }
        .map_err(|error| format!("verified resource cleanup: {error}"))?;
        Ok(())
    }
    #[cfg(not(target_os = "android"))]
    Err("device resource cleanup requires Android".into())
}

fn reject_cluster_uninstall(root: &Path) -> Result<(), String> {
    voboost_shared::cluster_mailbox::reject_pending_uninstall(
        root,
        &[
            &AGENT_CATALOG_PUBLIC_KEY,
            &RELEASE_CATALOG_PUBLIC_KEY,
            &NATIVE_EXECUTABLE_PUBLIC_KEY,
            &RESTORE_PUBLIC_KEY,
        ],
    )
}

fn begin_install_guard(root: &Path) -> Result<operation_contract::RawOperationLock, String> {
    let guard = operation_contract::RawOperationLock::acquire_in(root)?;
    reject_cluster_uninstall(root)?;
    Ok(guard)
}

#[cfg(target_os = "android")]
fn run_device_transaction(failure_transaction_id: &mut Option<String>) -> Result<bool, String> {
    reconcile_install_projection(Path::new(ROOT))?;
    if recover_terminal_cleanup(Path::new(ROOT))? {
        return Ok(true);
    }
    let operation = begin_install_guard(Path::new(ROOT))?;
    let active = operation_contract::read_active_in(Path::new(ROOT))?;
    let source = if let Some(pointer) = &active {
        if pointer.operation != Operation::Install {
            return Err("another global operation is active".into());
        }
        Path::new(ROOT)
            .join("recovery")
            .join(&pointer.transaction_id)
            .join("frozen")
    } else {
        discover_staging(Path::new(INSTALL_ROOT))?
    };
    let transaction_id = if let Some(pointer) = &active {
        pointer.transaction_id.clone()
    } else {
        source
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|value| contract::lower_hash(value))
            .ok_or_else(|| "install staging transaction is invalid".to_string())?
            .to_string()
    };
    let retained_chain = retain_private_directory_chain(&source)?;
    let staging_root = StagingRoot::open(&source)?;
    let staging_bytes = staging_root.read(
        STAGING_DESCRIPTOR_NAME,
        install_contract::MAX_STAGING_DESCRIPTOR_BYTES,
    )?;
    let staging_descriptor = StagingDescriptor::parse(&staging_bytes)?;
    if staging_descriptor.emulator_acceptance.is_some() {
        acceptance::admit()?;
    }
    if staging_descriptor.transaction_id != transaction_id {
        return Err("staging.json transaction identity differs".to_string());
    }
    let descriptor_bytes = staging_root.read(
        voboost_contract::release::MANIFEST_NAME,
        voboost_contract::release::MAX_MANIFEST_BYTES,
    )?;
    let signature = staging_root.read(voboost_contract::release::MANIFEST_SIGNATURE_NAME, 64)?;
    let descriptor = voboost_contract::release::verify_manifest_signature(
        &descriptor_bytes,
        &signature,
        &RELEASE_CATALOG_PUBLIC_KEY,
    )?;
    if staging_descriptor.release_identity != descriptor.release_identity
        || staging_descriptor.manifest_sha256 != sha256(&descriptor_bytes)
    {
        return Err("staging.json differs from signed product manifest".to_string());
    }
    let captured = verify_inventory_root(&staging_root, &descriptor)?;
    if captured.get(voboost_contract::release::MANIFEST_NAME) != Some(&descriptor_bytes)
        || captured.get(voboost_contract::release::MANIFEST_SIGNATURE_NAME) != Some(&signature)
        || captured.get(STAGING_DESCRIPTOR_NAME) != Some(&staging_bytes)
    {
        return Err("product manifest changed while capturing closure".into());
    }
    staging_root.verify_named_identity()?;
    revalidate_directory_chain(&retained_chain)?;
    let recovery = Path::new(ROOT).join("recovery").join(&transaction_id);
    match active {
        Some(ref pointer)
            if pointer.operation == Operation::Install
                && pointer.transaction_id == transaction_id =>
        {
            fresh::FreshState::parse(&read_bounded(
                &recovery.join("fresh-state.json"),
                4096,
                0o600,
            )?)?;
        }
        Some(_) => return Err("another global operation is active".into()),
        None => {
            let fresh_state = fresh::observe_and_require(&source)?;
            create_private_recovery_transaction(Path::new(ROOT), &transaction_id)?;
            write_atomic(
                &recovery.join("fresh-state.json"),
                &fresh_state.canonical_bytes()?,
                0o600,
            )?;
            freeze_verified_closure(&recovery.join("frozen"), &captured)?;
        }
    }
    let frozen = recovery.join("frozen");
    verify_inventory(&frozen, &descriptor)?;
    let journal_path = recovery.join("install-journal.json");
    let mut journal =
        load_or_create_journal(&journal_path, &transaction_id, &sha256(&descriptor_bytes))?;
    let pointer = OperationDescriptor::new(
        Operation::Install,
        transaction_id.clone(),
        format!("recovery/{transaction_id}/install-journal.json"),
        operation_contract::current_boot_id()?,
    )?;
    let lease = operation.admit(pointer)?;
    lease.verify_owner()?;
    // A correlated failure can be published only after the durable recovery
    // journal and operation descriptor exist under the acquired lease. Earlier
    // authenticated verification failures use the bounded pre-transaction
    // report instead of attempting a silent publication into absent recovery.
    *failure_transaction_id = Some(transaction_id.clone());
    // Bootstrap staging may pre-exist, but ownership of the product root is
    // published only by the verified installer while it holds the global
    // operation lease. A competing install/update can therefore never race
    // root authority ahead of its WAL.
    create_root_document()?;
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| format!("read install startup boot ID: {error}"))?;
    if mount_policy_transaction::consume_startup(
        &recovery.join("mount-policy-journal.json"),
        boot_id.trim(),
    )? {
        fixed_process::request_reboot()?;
        return Ok(false);
    }
    drive_transaction(&lease, &journal_path, &mut journal)?;
    if journal.phase == InstallPhase::InstallCleanup {
        let installed_apk = observe_install_completion(&journal_path)?;
        // The generation is accepted and the APK verified; the consumed
        // root-owned install-window staging must become app-owned before the
        // install is published complete, so OTA staging works from boot on.
        runtime::prepare_agent_incoming()?;
        prepare_terminal_cleanup(&lease, &journal, installed_apk.clone())?;
        let intent =
            transaction::read_terminal_intent(&transaction::terminal_intent_path(Path::new(ROOT)))?;
        transaction::cleanup_payload(
            &Path::new(INSTALL_ROOT).join(&journal.transaction_id),
            &Path::new(ROOT)
                .join("recovery")
                .join(&journal.transaction_id),
            &intent,
        )?;
        journal.phase = InstallPhase::InstallComplete;
        write_atomic(&journal_path, &journal.canonical_bytes()?, 0o600)?;
        emit_result_value(
            &lease,
            &journal.transaction_id,
            journal.phase,
            "complete",
            journal.boot_ids.len(),
            None,
            installed_apk,
        )?;
        transaction::cleanup_control(
            &Path::new(ROOT)
                .join("recovery")
                .join(&journal.transaction_id),
            &intent,
        )?;
        transaction::remove_terminal_intent(Path::new(ROOT), &journal.transaction_id)?;
        lease.finish()?;
    }
    Ok(journal.phase == InstallPhase::InstallComplete)
}

fn require_private_directory(file: &File, mode: u32, what: &str) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("stat {what}: {error}"))?;
    #[cfg(target_os = "android")]
    let owner = (0, 0);
    #[cfg(not(target_os = "android"))]
    let owner = unsafe { (libc::geteuid(), libc::getegid()) };
    if !metadata.is_dir()
        || metadata.uid() != owner.0
        || metadata.gid() != owner.1
        || metadata.permissions().mode() & 0o7777 != mode
    {
        return Err(format!("{what} has a foreign identity"));
    }
    Ok(())
}

fn open_directory_at(parent: &File, name: &std::ffi::CStr) -> Result<File, String> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn mkdir_private_at(
    parent: &File,
    name: &std::ffi::CStr,
    what: &str,
    allow_existing: bool,
) -> Result<(), String> {
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        let error = std::io::Error::last_os_error();
        if !(allow_existing && error.kind() == std::io::ErrorKind::AlreadyExists) {
            return Err(format!("create {what}: {error}"));
        }
        return Ok(());
    }
    parent
        .sync_all()
        .map_err(|error| format!("sync parent after creating {what}: {error}"))
}

fn create_private_recovery_transaction(root: &Path, transaction_id: &str) -> Result<(), String> {
    if !contract::lower_hash(transaction_id) {
        return Err("install recovery transaction identity is invalid".into());
    }
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(root)
        .map_err(|error| format!("open install root for recovery: {error}"))?;
    require_private_directory(&root, 0o755, "install root")?;

    mkdir_private_at(&root, c"recovery", "install recovery root", true)?;
    let recovery = open_directory_at(&root, c"recovery")
        .map_err(|error| format!("open install recovery root: {error}"))?;
    require_private_directory(&recovery, 0o700, "install recovery root")?;

    let transaction = std::ffi::CString::new(transaction_id)
        .map_err(|_| "install recovery transaction contains NUL")?;
    mkdir_private_at(
        &recovery,
        &transaction,
        "install recovery transaction",
        false,
    )?;
    let transaction = open_directory_at(&recovery, &transaction)
        .map_err(|error| format!("open install recovery transaction: {error}"))?;
    require_private_directory(&transaction, 0o700, "install recovery transaction")?;
    Ok(())
}

fn retain_private_directory_chain(path: &Path) -> Result<Vec<RetainedDirectory>, String> {
    retain_private_directory_chain_from(Path::new(ROOT), path)
}

fn retain_private_directory_chain_from(
    ancestor: &Path,
    path: &Path,
) -> Result<Vec<RetainedDirectory>, String> {
    let mut chain = Vec::new();
    let mut current = ancestor.to_path_buf();
    let relative = path
        .strip_prefix(ancestor)
        .map_err(|_| "install authority escaped chain")?;
    for component in std::iter::once(None).chain(relative.components().map(Some)) {
        if let Some(component) = component {
            current.push(component);
        }
        let entry = fs::symlink_metadata(&current).map_err(|error| error.to_string())?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(&current)
            .map_err(|error| format!("open private install directory: {error}"))?;
        let opened = file.metadata().map_err(|error| error.to_string())?;
        let expected_mode = if current == ancestor { 0o755 } else { 0o700 };
        if !entry.is_dir()
            || entry.file_type().is_symlink()
            || !opened.is_dir()
            || opened.nlink() < 2
            || opened.permissions().mode() & 0o7777 != expected_mode
            || (entry.dev(), entry.ino()) != (opened.dev(), opened.ino())
        {
            return Err(format!(
                "unsafe private install directory {}",
                current.display()
            ));
        }
        #[cfg(target_os = "android")]
        if opened.uid() != 0 || opened.gid() != 0 {
            return Err(format!(
                "non-root private install directory {}",
                current.display()
            ));
        }
        chain.push(RetainedDirectory {
            path: current.clone(),
            file,
            identity: (opened.dev(), opened.ino()),
            owner: (opened.uid(), opened.gid()),
            mode: expected_mode,
        });
    }
    Ok(chain)
}

fn revalidate_directory_chain(chain: &[RetainedDirectory]) -> Result<(), String> {
    for retained in chain {
        let opened = retained
            .file
            .metadata()
            .map_err(|error| error.to_string())?;
        let entry = fs::symlink_metadata(&retained.path).map_err(|error| error.to_string())?;
        // Directory link counts track child directories, not directory identity.
        // The daemon may legitimately create run/state while installation observes
        // the shared root. Retain the inode and authority, not its child count.
        if (opened.dev(), opened.ino()) != retained.identity
            || (entry.dev(), entry.ino()) != retained.identity
            || !opened.is_dir()
            || !entry.is_dir()
            || entry.file_type().is_symlink()
            || opened.nlink() < 2
            || (opened.uid(), opened.gid()) != retained.owner
            || (entry.uid(), entry.gid()) != retained.owner
            || opened.permissions().mode() & 0o7777 != retained.mode
            || entry.permissions().mode() & 0o7777 != retained.mode
        {
            return Err(format!(
                "private install directory changed {}",
                retained.path.display()
            ));
        }
    }
    Ok(())
}

fn observed_property_state(value: &str) -> &str {
    if value.is_empty() {
        "unavailable"
    } else {
        value
    }
}

trait InstallActions {
    fn boot_id(&mut self) -> Result<String, String>;
    fn request_reboot(&mut self) -> Result<(), String>;
    fn boot_completed(&mut self) -> Result<bool, String>;
    fn boot_property_state(&self) -> &str {
        "unavailable"
    }
    fn monotonic_ms(&mut self) -> Result<u64, String>;
    fn pause_boot_poll(&mut self);
    fn observer_acceptance(
        &mut self,
        lease: &OperationLease,
        path: &Path,
        journal: &InstallJournal,
        uninstall: &impl Fn() -> bool,
    ) -> Result<(), String>;
    fn generation_acknowledgement(
        &mut self,
        journal_path: &Path,
        journal: &InstallJournal,
    ) -> Result<bool, String>;
    fn execute(
        &mut self,
        phase: InstallPhase,
        journal_path: &Path,
        journal: &InstallJournal,
    ) -> Result<(), String>;
    fn emit(
        &mut self,
        lease: &OperationLease,
        journal_path: &Path,
        transaction_id: &str,
        phase: InstallPhase,
        outcome: &str,
        reboot_count: usize,
    ) -> Result<(), String>;
}

#[cfg(target_os = "android")]
#[derive(Default)]
struct DeviceInstallActions {
    boot_property: String,
}

#[cfg(target_os = "android")]
impl InstallActions for DeviceInstallActions {
    fn boot_id(&mut self) -> Result<String, String> {
        fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map(|value| value.trim().to_string())
            .map_err(|error| format!("read install boot ID: {error}"))
    }

    fn request_reboot(&mut self) -> Result<(), String> {
        diagnostic_log::stderr(
            DiagnosticService::Install,
            DiagnosticLevel::Info,
            "install.reboot",
            "Requesting device restart",
            &[],
        );
        fixed_process::request_reboot()
    }

    fn boot_completed(&mut self) -> Result<bool, String> {
        self.boot_property = android_property(c"sys.boot_completed");
        Ok(self.boot_property == "1")
    }

    fn boot_property_state(&self) -> &str {
        observed_property_state(&self.boot_property)
    }

    fn monotonic_ms(&mut self) -> Result<u64, String> {
        monotonic_ms()
    }

    fn pause_boot_poll(&mut self) {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    fn observer_acceptance(
        &mut self,
        lease: &OperationLease,
        path: &Path,
        journal: &InstallJournal,
        uninstall: &impl Fn() -> bool,
    ) -> Result<(), String> {
        acceptance::wait(lease, path, journal, self, uninstall)?;
        // Evidence is optional and cannot grant installation authority.
        if acceptance::guard().is_ok() {
            if let (Ok(boot), Ok(now)) = (self.boot_id(), self.monotonic_ms()) {
                let _ = initial_seeding::arm(Path::new(ROOT), journal, &boot, now);
            }
        }
        Ok(())
    }

    fn generation_acknowledgement(
        &mut self,
        journal_path: &Path,
        journal: &InstallJournal,
    ) -> Result<bool, String> {
        let path = journal_path.parent().unwrap().join("generation-ack.json");
        if !path.exists() {
            return Ok(false);
        }
        verify_generation_acknowledgement(&path, journal)?;
        Ok(true)
    }

    fn execute(
        &mut self,
        phase: InstallPhase,
        journal_path: &Path,
        journal: &InstallJournal,
    ) -> Result<(), String> {
        execute_phase(phase, journal_path, journal)
    }

    fn emit(
        &mut self,
        lease: &OperationLease,
        _journal_path: &Path,
        transaction_id: &str,
        phase: InstallPhase,
        outcome: &str,
        reboot_count: usize,
    ) -> Result<(), String> {
        emit_result(lease, transaction_id, phase, outcome, reboot_count, None)
    }
}

#[cfg(target_os = "android")]
fn drive_transaction(
    lease: &OperationLease,
    journal_path: &Path,
    journal: &mut InstallJournal,
) -> Result<(), String> {
    drive_transaction_with(
        lease,
        journal_path,
        journal,
        &mut DeviceInstallActions::default(),
    )
}

/// An explicit durable uninstall request has priority over any further
/// install mutation: the worker stops before its next phase and leaves the
/// journal, staging and backups for the uninstall recovery plan. Only the
/// desktop CLI publishes a durable file; the Settings host request lives
/// in the resident daemon, which runs the uninstall itself.
fn uninstall_request_present() -> bool {
    fs::symlink_metadata(voboost_contract::uninstall_request::DESKTOP_REQUEST_PATH).is_ok()
}

fn drive_transaction_with(
    lease: &OperationLease,
    journal_path: &Path,
    journal: &mut InstallJournal,
    actions: &mut impl InstallActions,
) -> Result<(), String> {
    drive_transaction_guarded_with(
        lease,
        journal_path,
        journal,
        actions,
        uninstall_request_present,
    )
}

fn drive_transaction_guarded_with(
    lease: &OperationLease,
    journal_path: &Path,
    journal: &mut InstallJournal,
    actions: &mut impl InstallActions,
    uninstall_fence: impl Fn() -> bool,
) -> Result<(), String> {
    loop {
        lease.verify_owner()?;
        if uninstall_fence() {
            return Err("install superseded by an explicit uninstall request".into());
        }
        if journal.phase.requires_reboot() {
            let boot_id = actions.boot_id()?;
            let reboot_index = match journal.phase {
                InstallPhase::InstallRebootFirst => 0,
                InstallPhase::InstallRebootSecond => 1,
                _ => unreachable!(),
            };
            if journal.boot_ids.len() == reboot_index {
                journal.boot_ids.push(boot_id);
                write_atomic(journal_path, &journal.canonical_bytes()?, 0o600)?;
                actions.emit(
                    lease,
                    journal_path,
                    &journal.transaction_id,
                    journal.phase,
                    "reboot-required",
                    journal.boot_ids.len(),
                )?;
                actions.request_reboot()?;
                return Ok(());
            } else if journal.boot_ids.get(reboot_index) == Some(&boot_id) {
                // OG1: a failed reboot published the terminal `failed`
                // document for this exact phase and WAL (sequence base+3).
                // Re-entering the same boot must not emit the lower
                // `reboot-required` slot (base+2) again — that would require
                // decreasing the sequence and wedge the lease. The failed
                // publication is already the live observer state, so the
                // retry skips the emit and requests the reboot directly.
                if !predecessor_failed_publication(lease, journal_path, journal)? {
                    actions.emit(
                        lease,
                        journal_path,
                        &journal.transaction_id,
                        journal.phase,
                        "reboot-required",
                        journal.boot_ids.len(),
                    )?;
                }
                actions.request_reboot()?;
                return Ok(());
            } else if journal.boot_ids.len() != reboot_index + 1 {
                return Err("install reboot history is not an exact prefix".to_string());
            }
        } else {
            if journal.phase == InstallPhase::InstallAgents
                && !actions.generation_acknowledgement(journal_path, journal)?
            {
                lease.release_for_install_generation()?;
                return Ok(());
            }
            actions.execute(journal.phase, journal_path, journal)?;
        }
        if journal.phase == InstallPhase::InstallCleanup {
            return Ok(());
        }
        let Some(next) = journal.phase.next() else {
            return Ok(());
        };
        if next == InstallPhase::InstallRebootSecond {
            let expected_boot = actions.boot_id()?;
            if journal.boot_ids.len() != 1 || journal.boot_ids[0] == expected_boot {
                return Err("install intermediate boot history differs".into());
            }
            let start = actions.monotonic_ms()?;
            let deadline = start.saturating_add(120_000);
            diagnostic_log::stderr(
                DiagnosticService::Install,
                DiagnosticLevel::Info,
                "install.boot-readiness",
                "Waiting for Android startup",
                &[],
            );
            loop {
                lease.verify_owner()?;
                if uninstall_fence() {
                    return Err("install superseded by an explicit uninstall request".into());
                }
                if actions.boot_id()? != expected_boot {
                    return Err("install boot readiness crossed a boot".into());
                }
                if actions.monotonic_ms()? >= deadline {
                    return Err(format!(
                        "install intermediate boot readiness deadline expired: start_ms={start} deadline_ms={deadline} last_sys.boot_completed={:?}",
                        actions.boot_property_state()
                    ));
                }
                if actions.boot_completed()? {
                    break;
                }
                actions.pause_boot_poll();
            }
            diagnostic_log::stderr(
                DiagnosticService::Install,
                DiagnosticLevel::Info,
                "install.boot-readiness",
                "Android startup completed",
                &[],
            );
            actions.observer_acceptance(lease, journal_path, journal, &uninstall_fence)?;
            lease.verify_owner()?;
            if uninstall_fence()
                || actions.boot_id()? != expected_boot
                || !actions.boot_completed()?
            {
                return Err("install intermediate boot fence changed before reboot2".into());
            }
        }
        if next.requires_reboot() {
            let boot_id = actions.boot_id()?;
            let reboot_index = match next {
                InstallPhase::InstallRebootFirst => 0,
                InstallPhase::InstallRebootSecond => 1,
                _ => unreachable!(),
            };
            if journal.boot_ids.len() != reboot_index {
                return Err("install reboot history is not an exact prefix".to_string());
            }
            journal.phase = next;
            journal.boot_ids.push(boot_id);
            write_atomic(journal_path, &journal.canonical_bytes()?, 0o600)?;
            actions.emit(
                lease,
                journal_path,
                &journal.transaction_id,
                journal.phase,
                "reboot-required",
                journal.boot_ids.len(),
            )?;
            actions.request_reboot()?;
            return Ok(());
        }
        journal.phase = next;
        write_atomic(journal_path, &journal.canonical_bytes()?, 0o600)?;
        actions.emit(
            lease,
            journal_path,
            &journal.transaction_id,
            journal.phase,
            "running",
            journal.boot_ids.len(),
        )?;
    }
}

#[cfg(target_os = "android")]
fn observe_install_completion(journal_path: &Path) -> Result<serde_json::Value, String> {
    let staging = journal_path
        .parent()
        .ok_or("install journal has no recovery parent")?
        .join("frozen");
    let descriptor = InstallDescriptor::parse(&read_bounded(
        &staging.join(voboost_contract::release::MANIFEST_NAME),
        voboost_contract::release::MAX_MANIFEST_BYTES,
        0o600,
    )?)?;
    let apk = descriptor
        .artifacts
        .iter()
        .find(|artifact| artifact.file == "voboost-app.apk")
        .ok_or("product manifest lacks voboost-app.apk")?;
    runtime::observe_installed_apk(
        apk.size,
        &apk.sha256,
        descriptor.apk_version_code()?,
        descriptor.apk_certificate_sha256()?,
    )
}

#[cfg(target_os = "android")]
fn verify_generation_acknowledgement(path: &Path, journal: &InstallJournal) -> Result<(), String> {
    let bytes = read_bounded(path, generation_contract::MAX_GENERATION_ACK_BYTES, 0o600)?;
    let acknowledgement = generation_contract::GenerationAcknowledgement::parse(&bytes)?;
    let descriptor = InstallDescriptor::parse(&read_bounded(
        &path
            .parent()
            .ok_or("generation ack has no recovery parent")?
            .join("frozen/voboost.json"),
        voboost_contract::release::MAX_MANIFEST_BYTES,
        0o600,
    )?)?;
    let apk = descriptor
        .artifacts
        .iter()
        .find(|artifact| artifact.file == "voboost-app.apk")
        .ok_or("product manifest lacks voboost-app.apk")?;
    if acknowledgement.transaction_id != journal.transaction_id
        || acknowledgement.apk_sha256 != apk.sha256
        || acknowledgement.catalog_sha256 != descriptor.agent_catalog_sha256()?
    {
        return Err("install generation acknowledgement correlation differs".to_string());
    }
    let active = read_bounded(
        Path::new(ROOT).join("generations/current").as_path(),
        65,
        0o444,
    )?;
    let active = std::str::from_utf8(&active).map_err(|_| "current generation is not UTF-8")?;
    if active != format!("{}\n", acknowledgement.generation_sha256) {
        return Err("current generation differs from install acknowledgement".to_string());
    }
    Ok(())
}

#[cfg(target_os = "android")]
fn execute_phase(
    phase: InstallPhase,
    journal_path: &Path,
    journal: &InstallJournal,
) -> Result<(), String> {
    let recovery = journal_path
        .parent()
        .ok_or_else(|| "install journal has no recovery directory".to_string())?;
    let staging = recovery.join("frozen");
    let descriptor = InstallDescriptor::parse(&read_bounded(
        &staging.join(voboost_contract::release::MANIFEST_NAME),
        1024 * 1024,
        0o600,
    )?)?;
    verify_inventory(&staging, &descriptor)?;
    if matches!(
        phase,
        InstallPhase::InstallAgents
            | InstallPhase::InstallRuntimeVerify
            | InstallPhase::InstallInventoryCommit
            | InstallPhase::InstallCleanup
            | InstallPhase::InstallComplete
    ) {
        require_enforcing_at(Path::new("/sys/fs/selinux/enforce"))?;
    }
    match phase {
        InstallPhase::InstallPrepare => transaction::prepare(recovery),
        InstallPhase::InstallPolicyBackup => policy::backup(recovery),
        InstallPhase::InstallRuntimeApply => runtime::apply_native(&staging, &descriptor),
        InstallPhase::InstallApp => runtime::apply_app(&staging, &descriptor),
        InstallPhase::InstallPolicyApply => {
            policy::apply(&staging, recovery, &journal.transaction_id, &descriptor)
        }
        InstallPhase::InstallAgents => {
            runtime::verify_committed(&staging, &descriptor)?;
            runtime::verify_native_release(&descriptor)?;
            install_resource_apks(&staging, &journal.transaction_id)
        }
        InstallPhase::InstallRuntimeVerify => {
            runtime::verify_committed(&staging, &descriptor)?;
            runtime::verify_native_release(&descriptor)
        }
        InstallPhase::InstallInventoryCommit => inventory::commit(&staging, recovery, journal),
        InstallPhase::InstallCleanup => {
            inventory::verify_committed()?;
            runtime::verify_native_release(&descriptor)
        }
        InstallPhase::InstallComplete => Ok(()),
        InstallPhase::InstallRebootFirst | InstallPhase::InstallRebootSecond => Ok(()),
    }
}

fn install_resource_apks(staging: &Path, transaction_id: &str) -> Result<(), String> {
    let manifest = read_bounded(
        &staging.join(voboost_contract::release::MANIFEST_NAME),
        voboost_contract::release::MAX_MANIFEST_BYTES,
        0o600,
    )?;
    let signature = read_bounded(
        &staging.join(voboost_contract::release::MANIFEST_SIGNATURE_NAME),
        64,
        0o600,
    )?;
    let directory =
        voboost_shared::secure_fs::Directory::open(staging).map_err(|e| e.to_string())?;
    let resources = i18n_resource_admission::admit_resources(
        &directory,
        &manifest,
        &signature,
        &RELEASE_CATALOG_PUBLIC_KEY,
    )?;
    let resources = resources
        .into_iter()
        .map(|resource| {
            let file = resource_none_helper::VerifiedNoneHelper::module_file_for(&resource)?;
            let bytes = directory
                .read_untrusted(&file, resource_none_helper::MAX_NONE_HELPER_BYTES)
                .map_err(|error| format!("read staged None helper: {error}"))?;
            let helper = resource_none_helper::VerifiedNoneHelper::verify(&resource, &bytes)?;
            Ok((resource, helper))
        })
        .collect::<Result<Vec<_>, String>>()?;
    if resources.is_empty() {
        return Ok(());
    }
    // The owned overlay files all share the single /vendor/overlay mount
    // boundary; one scoped RW window covers the whole variant set and the
    // existing watchdog restores read-only state even on process death.
    let owned_files: Vec<String> = resources
        .iter()
        .map(|(resource, _)| {
            Variant::from_package(&resource.descriptor().overlay_package)
                .map(|variant| format!("/vendor/overlay/{}", variant.file()))
        })
        .collect::<Result<Vec<_>, String>>()?;
    voboost_shared::protected_system_transaction::with_owned_resource_variant_write(
        transaction_id,
        &owned_files[0],
        || {
            for (resource, helper) in &resources {
                i18n_resource_files::install_owned(resource, helper)
                    .map_err(|e| format!("stage authenticated resource: {e}"))?;
            }
            Ok(())
        },
    )
}

fn require_enforcing_at(path: &Path) -> Result<(), String> {
    let file =
        File::open(path).map_err(|error| format!("read post-reboot SELinux state: {error}"))?;
    let mut bytes = Vec::new();
    file.take(3)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if !matches!(bytes.as_slice(), b"1" | b"1\n") {
        return Err(
            "installation continuation requires SELinux Enforcing after first reboot".into(),
        );
    }
    Ok(())
}

#[cfg(target_os = "android")]
fn prepare_terminal_cleanup(
    lease: &OperationLease,
    journal: &InstallJournal,
    installed_apk: serde_json::Value,
) -> Result<(), String> {
    lease.verify_owner()?;
    let intent = transaction::TerminalIntent {
        schema_version: 1,
        transaction_id: journal.transaction_id.clone(),
        manifest_sha256: journal.manifest_sha256.clone(),
        installed_apk,
    };
    let intent_path = transaction::terminal_intent_path(Path::new(ROOT));
    if path_entry_exists(&intent_path)? {
        if read_bounded(&intent_path, MAX_TERMINAL_INTENT_BYTES, 0o600)? != intent.bytes()? {
            return Err("foreign install terminal intent".to_string());
        }
    } else {
        write_atomic(&intent_path, &intent.bytes()?, 0o600)?;
    }
    Ok(())
}

#[cfg(target_os = "android")]
fn recover_terminal_cleanup(root: &Path) -> Result<bool, String> {
    recover_terminal_cleanup_with(
        root,
        inventory::verify_committed_at,
        runtime::prepare_agent_incoming,
        operation_contract::current_boot_id,
    )
}

fn recover_terminal_cleanup_with(
    root: &Path,
    verify_inventory: impl FnOnce(&Path) -> Result<(), String>,
    prepare_agent_incoming: impl FnOnce() -> Result<(), String>,
    boot_id: impl FnOnce() -> Result<String, String>,
) -> Result<bool, String> {
    let pointer = operation_contract::read_current_in(root)?;
    let intent_path = transaction::terminal_intent_path(root);
    if pointer.is_none() && intent_path.exists() {
        return Err("install terminal intent exists without operation authority".to_string());
    }
    let Some(pointer) = pointer else {
        return Ok(false);
    };
    if pointer.operation != Operation::Install {
        return if pointer.outcome == "complete" {
            Ok(false)
        } else {
            Err("another global operation is active".to_string())
        };
    }
    let journal_path = root.join(&pointer.journal);
    if pointer.outcome == "complete" {
        verify_inventory(root)?;
        let journal = if journal_path.exists() {
            let journal: InstallJournal = serde_json::from_slice(&read_bounded(
                &journal_path,
                MAX_INSTALL_JOURNAL_BYTES,
                0o600,
            )?)
            .map_err(|error| format!("parse terminal install journal: {error}"))?;
            if journal.transaction_id != pointer.transaction_id
                || journal.phase != InstallPhase::InstallComplete
                || sha256(&journal.canonical_bytes()?) != pointer.journal_sha256
            {
                return Err("terminal install journal differs from operation authority".to_string());
            }
            Some(journal)
        } else {
            None
        };
        let lease = OperationLease::acquire_in(root, pointer.clone())?;
        if let Some(journal) = journal {
            let expected = transaction::TerminalIntent {
                schema_version: 1,
                transaction_id: journal.transaction_id.clone(),
                manifest_sha256: journal.manifest_sha256.clone(),
                installed_apk: pointer
                    .installed_apk
                    .clone()
                    .ok_or("complete install operation lacks APK identity")?,
            };
            if intent_path.exists() {
                if transaction::read_terminal_intent(&intent_path)? != expected {
                    return Err(
                        "install terminal intent differs from operation authority".to_string()
                    );
                }
            } else {
                write_atomic(&intent_path, &expected.bytes()?, 0o600)?;
            }
            transaction::cleanup_payload(
                &root.join("install").join(&journal.transaction_id),
                &root.join("recovery").join(&journal.transaction_id),
                &expected,
            )?;
            transaction::cleanup_control(
                &root.join("recovery").join(&journal.transaction_id),
                &expected,
            )?;
        } else {
            transaction::require_terminal_transients_absent(root, &pointer.transaction_id)?;
        }
        if intent_path.exists() {
            transaction::remove_terminal_intent(root, &pointer.transaction_id)?;
        }
        lease.finish()?;
        return Ok(true);
    }
    if intent_path.exists() {
        let journal_bytes = read_bounded(&journal_path, MAX_INSTALL_JOURNAL_BYTES, 0o600)?;
        let mut journal: InstallJournal = serde_json::from_slice(&journal_bytes)
            .map_err(|error| format!("parse install cleanup WAL: {error}"))?;
        if journal.transaction_id != pointer.transaction_id
            || journal.phase != InstallPhase::InstallCleanup
            || journal.canonical_bytes()? != journal_bytes
        {
            return Err("install terminal intent is not owned by cleanup phase".to_string());
        }
        let intent = transaction::read_terminal_intent(&intent_path)?;
        if intent.transaction_id != journal.transaction_id
            || intent.manifest_sha256 != journal.manifest_sha256
        {
            return Err("install terminal intent differs from cleanup WAL".to_string());
        }
        verify_inventory(root)?;
        let lease =
            OperationLease::acquire_in_checked(root, pointer, || reject_cluster_uninstall(root))?;
        prepare_agent_incoming()?;
        transaction::cleanup_payload(
            &root.join("install").join(&journal.transaction_id),
            &root.join("recovery").join(&journal.transaction_id),
            &intent,
        )?;
        journal.phase = InstallPhase::InstallComplete;
        write_atomic(&journal_path, &journal.canonical_bytes()?, 0o600)?;
        let terminal = install_operation_document(
            root,
            &journal.transaction_id,
            journal.phase,
            "complete",
            journal.boot_ids.len(),
            None,
            intent.installed_apk.clone(),
            boot_id()?,
        )?;
        lease.publish(&terminal)?;
        transaction::cleanup_control(
            &root.join("recovery").join(&journal.transaction_id),
            &intent,
        )?;
        transaction::remove_terminal_intent(root, &journal.transaction_id)?;
        lease.finish()?;
        return Ok(true);
    }
    if !journal_path.exists() {
        return Err(
            "active install pointer names a missing journal without terminal intent".to_string(),
        );
    }
    Ok(false)
}

/// OG1 helper: true when the live operation document is the failed
/// publication of this exact install phase and WAL, so a same-boot retry
/// must not re-emit the lower reboot-required slot.
fn predecessor_failed_publication(
    lease: &OperationLease,
    journal_path: &Path,
    journal: &InstallJournal,
) -> Result<bool, String> {
    let Some(current) = lease.read_live_projection()? else {
        return Ok(false);
    };
    Ok(current.operation == Operation::Install
        && current.transaction_id == journal.transaction_id
        && current.outcome == "failed"
        && serde_json::to_value(journal.phase)
            .map_err(|error| error.to_string())?
            .as_str()
            .is_some_and(|phase| phase == current.phase)
        && current.journal_sha256
            == sha256(&read_bounded(
                journal_path,
                MAX_INSTALL_JOURNAL_BYTES,
                0o600,
            )?))
}

#[cfg(target_os = "android")]
fn reconcile_install_projection(root: &Path) -> Result<(), String> {
    let Some(pointer) = operation_contract::read_document_in(root)? else {
        return Ok(());
    };
    if pointer.operation != Operation::Install {
        return Ok(());
    }
    let journal_path = root.join(&pointer.journal);
    if !journal_path.exists() {
        return if pointer.outcome == "complete" {
            Ok(())
        } else {
            Err("nonterminal install operation names a missing journal".to_string())
        };
    }
    let bytes = read_bounded(&journal_path, MAX_INSTALL_JOURNAL_BYTES, 0o600)?;
    if sha256(&bytes) == pointer.journal_sha256 {
        return Ok(());
    }
    let journal: InstallJournal = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse install recovery WAL: {error}"))?;
    if journal.transaction_id != pointer.transaction_id || journal.canonical_bytes()? != bytes {
        return Err("install recovery WAL differs from operation authority".to_string());
    }
    let outcome = if journal.phase == InstallPhase::InstallComplete {
        "complete"
    } else {
        "running"
    };
    let installed_apk = if outcome == "complete" {
        let intent_path = transaction::terminal_intent_path(root);
        if intent_path.exists() {
            let intent = transaction::read_terminal_intent(&intent_path)?;
            if intent.transaction_id != journal.transaction_id
                || intent.manifest_sha256 != journal.manifest_sha256
            {
                return Err("install terminal intent differs from recovery WAL".to_string());
            }
            intent.installed_apk
        } else {
            observe_install_completion(&journal_path)?
        }
    } else {
        serde_json::Value::Null
    };
    let recovered = install_operation_document(
        root,
        &journal.transaction_id,
        journal.phase,
        outcome,
        journal.boot_ids.len(),
        None,
        installed_apk,
        operation_contract::current_boot_id()?,
    )?;
    if recovered.operation != pointer.operation
        || recovered.transaction_id != pointer.transaction_id
        || recovered.journal != pointer.journal
    {
        return Err("install recovery projection changed operation authority".to_string());
    }
    let lease = match if outcome == "complete" {
        OperationLease::acquire_in(root, recovered.clone())
    } else {
        OperationLease::acquire_in_checked(root, recovered.clone(), || {
            reject_cluster_uninstall(root)
        })
    } {
        Ok(lease) => lease,
        // R24 terminal WAL→projection cut: the InstallComplete WAL write and
        // the `complete` projection publish are two durable steps. A crash
        // between them leaves the descriptor one publication behind the
        // WAL; the predecessor is derived from the same durable WAL and must
        // be bit-exact the live projection before the terminal document may
        // replace it.
        Err(error)
            if error.contains("operation document and recovery WAL diverged")
                && outcome == "complete" =>
        {
            // The interrupted publication's predecessor is reconstructed
            // from the same durable WAL: the terminal write changed only the
            // journal phase, so the pre-cut projection is derivable bit
            // for bit — including the journal hash it bound (the pre-cut
            // WAL bytes). The contract requires that reconstructed
            // predecessor to equal the live descriptor exactly, to not
            // bind the live (terminal) WAL, and `recovered` to bind the
            // live WAL — the exact terminal-cut proof.
            let mut predecessor = recovered.clone();
            predecessor.phase = "install-cleanup".to_string();
            predecessor.outcome = "running".to_string();
            predecessor.status_sequence =
                operation_status_sequence(InstallPhase::InstallCleanup, "running")?;
            predecessor.installed_apk = None;
            let mut predecessor_journal = journal.clone();
            predecessor_journal.phase = InstallPhase::InstallCleanup;
            predecessor.journal_sha256 = sha256(&predecessor_journal.canonical_bytes()?);
            predecessor.validate()?;
            OperationLease::reconcile_terminal_cut_in(root, &predecessor, &recovered)?
        }
        Err(error) => return Err(error),
    };
    lease.verify_owner()?;
    Ok(())
}

fn emit_result(
    lease: &OperationLease,
    transaction_id: &str,
    phase: InstallPhase,
    outcome: &str,
    reboot_count: usize,
    error: Option<&str>,
) -> Result<(), String> {
    emit_result_value(
        lease,
        transaction_id,
        phase,
        outcome,
        reboot_count,
        error,
        serde_json::Value::Null,
    )
}

fn emit_result_value(
    lease: &OperationLease,
    transaction_id: &str,
    phase: InstallPhase,
    outcome: &str,
    reboot_count: usize,
    error: Option<&str>,
    installed_apk: serde_json::Value,
) -> Result<(), String> {
    let document = install_operation_document(
        Path::new(ROOT),
        transaction_id,
        phase,
        outcome,
        reboot_count,
        error,
        installed_apk,
        operation_contract::current_boot_id()?,
    )?;
    lease.publish(&document)
}

#[allow(clippy::too_many_arguments)] // the terminal document fields are the operation contract
fn install_operation_document(
    root: &Path,
    transaction_id: &str,
    phase: InstallPhase,
    outcome: &str,
    reboot_count: usize,
    error: Option<&str>,
    installed_apk: serde_json::Value,
    boot_id: String,
) -> Result<OperationDescriptor, String> {
    let journal_path = root
        .join("recovery")
        .join(transaction_id)
        .join("install-journal.json");
    let journal_sha256 = sha256(
        &read_bounded(&journal_path, MAX_INSTALL_JOURNAL_BYTES, 0o600)
            .map_err(|error| format!("read install journal for status: {error}"))?,
    );
    let error = error.map(|message| {
        let message = message
            .chars()
            .filter(|character| !character.is_control())
            .take(512)
            .collect::<String>();
        let message = if message.is_empty() {
            "internal install failure".to_string()
        } else {
            message
        };
        serde_json::json!({"code":"install-failed","message":message})
    });
    let status_sequence = operation_status_sequence(phase, outcome)?;
    Ok(OperationDescriptor {
        schema_version: 1,
        operation: Operation::Install,
        transaction_id: transaction_id.to_string(),
        journal: format!("recovery/{transaction_id}/install-journal.json"),
        phase: serde_json::to_value(phase)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string(),
        outcome: outcome.to_string(),
        reboot_count: reboot_count as u32,
        boot_id,
        status_sequence,
        journal_sha256,
        error,
        installed_apk: (!installed_apk.is_null()).then_some(installed_apk),
    })
}

fn operation_status_sequence(phase: InstallPhase, outcome: &str) -> Result<u64, String> {
    let base = (phase.status_sequence() - 1) * 3;
    match outcome {
        "running" => Ok(base + 1),
        "reboot-required" => Ok(base + 2),
        "failed" | "complete" => Ok(base + 3),
        _ => Err("install status outcome is invalid".to_string()),
    }
}

fn publish_install_failure(transaction_id: &str, message: &str) -> Result<(), String> {
    let root = Path::new(ROOT);
    let pointer = operation_contract::read_document_in(root)?
        .ok_or_else(|| "install failure has no operation authority".to_string())?;
    if pointer.operation != Operation::Install
        || pointer.transaction_id != transaction_id
        || pointer.outcome == "complete"
    {
        return Err("install failure operation authority differs".to_string());
    }
    let journal_path = root.join(&pointer.journal);
    let bytes = read_bounded(&journal_path, MAX_INSTALL_JOURNAL_BYTES, 0o600)?;
    let journal: InstallJournal = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse failed install WAL: {error}"))?;
    if journal.transaction_id != transaction_id || journal.canonical_bytes()? != bytes {
        return Err("failed install WAL differs from operation authority".to_string());
    }
    let running = install_operation_document(
        root,
        transaction_id,
        journal.phase,
        "running",
        journal.boot_ids.len(),
        None,
        serde_json::Value::Null,
        operation_contract::current_boot_id()?,
    )?;
    let lease =
        OperationLease::acquire_in_checked(root, running, || reject_cluster_uninstall(root))?;
    let failed = install_operation_document(
        root,
        transaction_id,
        journal.phase,
        "failed",
        journal.boot_ids.len(),
        Some(message),
        serde_json::Value::Null,
        operation_contract::current_boot_id()?,
    )?;
    lease.publish(&failed)
}

#[cfg(test)]
fn failure_report_state(transaction_id: &str) -> Option<(InstallPhase, usize)> {
    let path = Path::new(ROOT)
        .join("recovery")
        .join(transaction_id)
        .join("install-journal.json");
    let bytes = read_bounded(path.as_path(), MAX_INSTALL_JOURNAL_BYTES, 0o600).ok()?;
    parse_failure_report_state(&bytes, transaction_id)
}

#[cfg(test)]
fn parse_failure_report_state(bytes: &[u8], transaction_id: &str) -> Option<(InstallPhase, usize)> {
    let journal: InstallJournal = serde_json::from_slice(bytes).ok()?;
    (journal.transaction_id == transaction_id && journal.canonical_bytes().ok()? == bytes)
        .then_some((journal.phase, journal.boot_ids.len()))
}

fn pre_transaction_failure_bytes(error: &str) -> Option<Vec<u8>> {
    let message = sanitized_failure_message(error);
    let document = PreTransactionFailure {
        schema_version: 1,
        operation: "install",
        failure_type: "pre-transaction",
        error: PreTransactionError {
            code: "install-pre-transaction-failed",
            message: &message,
        },
    };
    let mut bytes = serde_json::to_vec(&document).ok()?;
    bytes.push(b'\n');
    Some(bytes)
}

fn emit_pre_transaction_failure(error: &str) {
    if let Some(bytes) = pre_transaction_failure_bytes(error) {
        let _ = std::io::stdout().write_all(&bytes);
        let _ = std::io::stdout().flush();
    }
}

fn sanitized_failure_message(error: &str) -> String {
    let message = error
        .chars()
        .filter(|character| !character.is_control())
        .take(512)
        .collect::<String>();
    if message.is_empty() {
        "internal install failure".to_string()
    } else {
        message
    }
}

fn discover_staging(root: &Path) -> Result<PathBuf, String> {
    let mut found = None;
    for entry in fs::read_dir(root).map_err(|error| format!("read install staging: {error}"))? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| "install transaction is not UTF-8".to_string())?;
        if !contract::lower_hash(name) || !entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            return Err("foreign install staging entry".to_string());
        }
        if found.replace(entry.path()).is_some() {
            return Err("multiple install transactions are present".to_string());
        }
    }
    found.ok_or_else(|| "install transaction is absent".to_string())
}

fn verify_inventory(
    staging: &Path,
    descriptor: &InstallDescriptor,
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let staging = StagingRoot::open(staging)?;
    verify_inventory_root(&staging, descriptor)
}

fn verify_inventory_root(
    staging: &StagingRoot,
    descriptor: &InstallDescriptor,
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let expected = staging_inventory_names(descriptor);
    if expected.len() > MAX_STAGING_ENTRIES || staging.entry_names()? != expected {
        return Err("install staging inventory is not closed".to_string());
    }
    let captured = capture_verified_inventory(staging, descriptor)?;
    staging.verify_named_identity()?;
    Ok(captured)
}

fn staging_inventory_names(descriptor: &InstallDescriptor) -> BTreeSet<String> {
    let mut expected = descriptor
        .artifacts
        .iter()
        .map(|artifact| artifact.file.clone())
        .collect::<BTreeSet<_>>();
    expected.insert(STAGING_DESCRIPTOR_NAME.to_string());
    expected.insert(voboost_contract::release::MANIFEST_NAME.to_string());
    expected.insert(voboost_contract::release::MANIFEST_SIGNATURE_NAME.to_string());
    expected
}

fn capture_verified_inventory(
    staging: &StagingRoot,
    descriptor: &InstallDescriptor,
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut captured = BTreeMap::new();
    captured.insert(
        STAGING_DESCRIPTOR_NAME.to_string(),
        staging.read(
            STAGING_DESCRIPTOR_NAME,
            install_contract::MAX_STAGING_DESCRIPTOR_BYTES,
        )?,
    );
    captured.insert(
        voboost_contract::release::MANIFEST_NAME.to_string(),
        staging.read(
            voboost_contract::release::MANIFEST_NAME,
            voboost_contract::release::MAX_MANIFEST_BYTES,
        )?,
    );
    captured.insert(
        voboost_contract::release::MANIFEST_SIGNATURE_NAME.to_string(),
        staging.read(voboost_contract::release::MANIFEST_SIGNATURE_NAME, 64)?,
    );
    let verified = voboost_contract::release::verify_manifest_signature(
        captured
            .get(voboost_contract::release::MANIFEST_NAME)
            .ok_or("captured product manifest is absent")?,
        captured
            .get(voboost_contract::release::MANIFEST_SIGNATURE_NAME)
            .ok_or("captured product signature is absent")?,
        &RELEASE_CATALOG_PUBLIC_KEY,
    )?;
    if &verified != descriptor {
        return Err("captured product manifest differs from install authority".to_string());
    }
    let staging_descriptor = StagingDescriptor::parse(
        captured
            .get(STAGING_DESCRIPTOR_NAME)
            .ok_or("captured staging descriptor is absent")?,
    )?;
    let transaction_path =
        if staging.path.file_name().and_then(|name| name.to_str()) == Some("frozen") {
            staging
                .path
                .parent()
                .ok_or("frozen install staging has no transaction parent")?
        } else {
            &staging.path
        };
    let transaction = transaction_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("install staging transaction path is invalid")?;
    if staging_descriptor.transaction_id != transaction
        || staging_descriptor.release_identity != descriptor.release_identity
        || staging_descriptor.manifest_sha256 != descriptor.digest()?
    {
        return Err("staging.json differs from product authority".to_string());
    }
    for artifact in &descriptor.artifacts {
        let maximum = usize::try_from(artifact.size)
            .map_err(|_| format!("install artifact {} size overflows host", artifact.file))?;
        let bytes = staging.read(&artifact.file, maximum)?;
        if bytes.len() as u64 != artifact.size || sha256(&bytes) != artifact.sha256 {
            return Err(format!(
                "install artifact {} differs from product manifest",
                artifact.file
            ));
        }
        let executable_role = match artifact.role {
            voboost_contract::release::ArtifactRole::Daemon => {
                Some(native_executable_signature::NativeExecutableRole::Daemon)
            }
            voboost_contract::release::ArtifactRole::Inject => {
                Some(native_executable_signature::NativeExecutableRole::Inject)
            }
            voboost_contract::release::ArtifactRole::Install => {
                Some(native_executable_signature::NativeExecutableRole::Install)
            }
            voboost_contract::release::ArtifactRole::Restore => {
                Some(native_executable_signature::NativeExecutableRole::Restore)
            }
            voboost_contract::release::ArtifactRole::Uninstall => {
                Some(native_executable_signature::NativeExecutableRole::Uninstall)
            }
            voboost_contract::release::ArtifactRole::Selinux => {
                Some(native_executable_signature::NativeExecutableRole::Selinux)
            }
            _ => None,
        };
        if executable_role.is_some_and(|role| {
            !appended_signature_valid(&bytes, &NATIVE_EXECUTABLE_PUBLIC_KEY, role)
        }) {
            return Err(format!(
                "install artifact {} has an invalid role signature",
                artifact.file
            ));
        }
        if artifact.file == "voboost-app.apk" {
            let apk_file = staging
                .open_file(&artifact.file)
                .map_err(|error| format!("open staged APK identity: {error}"))?;
            let stamp = voboost_contract::apk::FileStamp::read(&apk_file)
                .map_err(|error| format!("stat staged base APK identity: {error:#}"))?;
            let certificate = voboost_contract::apk::signer_sha256_v2_v3(&apk_file, stamp)
                .map_err(|error| format!("parse staged base APK signer: {error:#}"))?;
            if certificate
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
                != descriptor.apk_certificate_sha256()?
            {
                return Err("APK signing certificate differs from product manifest".into());
            }
            if voboost_contract::apk::FileStamp::read(&apk_file)
                .map_err(|error| format!("restat staged base APK identity: {error:#}"))?
                != stamp
            {
                return Err("staged base APK changed during identity verification".into());
            }
        }
        captured.insert(artifact.file.clone(), bytes);
    }
    let catalog = captured.get("agents.json").unwrap();
    let catalog_signature = captured.get("agents.json.sig").unwrap();
    if !detached_signature_valid(catalog, catalog_signature, &AGENT_CATALOG_PUBLIC_KEY) {
        return Err("agent catalog detached signature is invalid".to_string());
    }
    verify_agent_catalog_inventory(descriptor, catalog)?;
    let restore = captured.get("restore.json").unwrap();
    let restore_signature = captured.get("restore.json.sig").unwrap();
    voboost_contract::release::verify_restore_authority(
        descriptor,
        restore,
        restore_signature,
        &RESTORE_PUBLIC_KEY,
    )?;
    Ok(captured)
}

fn freeze_verified_closure(
    frozen: &Path,
    captured: &BTreeMap<String, Vec<u8>>,
) -> Result<(), String> {
    if frozen.exists() {
        return Err("install frozen closure already exists before adoption".into());
    }
    fs::create_dir(frozen).map_err(|error| format!("create frozen closure: {error}"))?;
    fs::set_permissions(frozen, fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    for (relative, bytes) in captured {
        if Path::new(relative).components().count() != 1 {
            return Err("frozen install member is not flat".to_string());
        }
        let target = frozen.join(relative);
        write_atomic(&target, bytes, 0o600)?;
    }
    File::open(frozen)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync frozen closure: {error}"))
}

fn verify_agent_catalog_inventory(
    descriptor: &InstallDescriptor,
    bytes: &[u8],
) -> Result<(), String> {
    let catalog = voboost_contract::agent_catalog::AgentCatalog::parse(bytes)
        .map_err(|error| format!("parse canonical agents.json: {error}"))?;
    let product_core = descriptor.artifact("agent-common.dex")?;
    if catalog.core.file != product_core.file
        || catalog.core.size != product_core.size
        || catalog.core.sha256 != product_core.sha256
    {
        return Err("agents.json core differs from voboost.json".to_string());
    }
    let has_native = catalog
        .agents
        .iter()
        .flat_map(|a| &a.targets)
        .any(|t| !t.is_android());
    if has_native != catalog.cluster_runtime.is_some() {
        return Err("clusterRuntime must match native targets".into());
    }
    if let Some(runtime) = &catalog.cluster_runtime {
        let declared = descriptor.artifact(&runtime.file)?;
        if runtime.file != "libvoboost-runtime-cluster.so"
            || declared.role != voboost_contract::release::ArtifactRole::QnxRuntime
            || declared.size != runtime.size
            || declared.sha256 != runtime.sha256
        {
            return Err("agents.json native runtime differs from product".into());
        }
    }
    if catalog.agents.is_empty() || catalog.agents.len() > 64 {
        return Err("agents.json agent count is invalid".to_string());
    }
    let mut identities = BTreeMap::new();
    let mut filenames = BTreeSet::from([catalog.core.file.to_ascii_lowercase()]);
    let mut agent_ids = BTreeSet::new();
    for agent in &catalog.agents {
        if !agent_ids.insert(agent.id.as_str()) {
            return Err("agents.json agent id is duplicated".into());
        }
        if agent.targets.is_empty() || agent.targets.len() > 64 {
            return Err("agents.json target count is invalid".to_string());
        }
        let mut processes = BTreeSet::new();
        for target in &agent.targets {
            if !processes.insert((target.is_android(), target.process.as_str())) {
                return Err("agents.json target process is duplicated".into());
            }
            use voboost_contract::agent_catalog::{TargetAbi, TargetDomain, TargetPlatform};
            match (target.platform, target.domain, target.entry_abi) {
                (TargetPlatform::Android, TargetDomain::Android, TargetAbi::AndroidJavaV1)
                    if target.file.starts_with("agent-")
                        && target.file.ends_with(".dex")
                        && target.entry_class.is_some()
                        && !target.boot => {}
                (TargetPlatform::Qnx, TargetDomain::Cluster, TargetAbi::VoboostAgent3V1)
                    if target.file == format!("libagent-{}.so", agent.id)
                        && matches!(target.process.as_str(), "gauge" | "point" | "light")
                        && target.entry_class.is_none()
                        && !target.boot => {}
                _ => return Err("agents.json target platform/domain/ABI rejected".into()),
            }
            let identity = (
                agent.id.as_str(),
                target.size,
                target.sha256.as_str(),
                target.entry_class.as_deref(),
            );
            if let Some(previous) = identities.get(target.file.as_str()) {
                if *previous != identity {
                    return Err("agents.json target filename has conflicting identity".into());
                }
            } else {
                if !filenames.insert(target.file.to_ascii_lowercase()) {
                    return Err("agents.json core or case-folded target filename collision".into());
                }
                identities.insert(target.file.as_str(), identity);
            }
        }
    }
    let catalog_files = identities
        .into_iter()
        .map(|(file, (_, size, sha256, _))| (file, (size, sha256)))
        .collect::<BTreeMap<_, _>>();
    let mut product_files = BTreeMap::new();
    for artifact in descriptor.artifacts.iter().filter(|artifact| {
        matches!(
            artifact.role,
            voboost_contract::release::ArtifactRole::AgentModule
                | voboost_contract::release::ArtifactRole::QnxAgentModule
        )
    }) {
        if product_files
            .insert(
                artifact.file.as_str(),
                (artifact.size, artifact.sha256.as_str()),
            )
            .is_some()
        {
            return Err("voboost.json module filename is duplicated".into());
        }
    }
    if catalog_files != product_files {
        return Err("agents.json target closure differs from voboost.json".to_string());
    }
    Ok(())
}

fn load_or_create_journal(
    path: &Path,
    transaction_id: &str,
    manifest_sha256: &str,
) -> Result<InstallJournal, String> {
    if path.exists() {
        let bytes = read_bounded(path, 4096, 0o600)?;
        let journal: InstallJournal =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        if journal.canonical_bytes()? != bytes
            || journal.transaction_id != transaction_id
            || journal.manifest_sha256 != manifest_sha256
        {
            return Err("install journal correlation is invalid".to_string());
        }
        return Ok(journal);
    }
    let journal = InstallJournal {
        schema_version: 1,
        transaction_id: transaction_id.to_string(),
        manifest_sha256: manifest_sha256.to_string(),
        phase: InstallPhase::InstallPrepare,
        boot_ids: Vec::new(),
    };
    write_atomic(path, &journal.canonical_bytes()?, 0o600)?;
    Ok(journal)
}

fn create_root_document() -> Result<(), String> {
    let path = Path::new(ROOT).join("root.json");
    if path_entry_exists(&path)? {
        if read_bounded(&path, ROOT_DOCUMENT.len(), 0o600)? != ROOT_DOCUMENT {
            return Err("foreign root ownership document".to_string());
        }
        Ok(())
    } else {
        write_atomic(&path, ROOT_DOCUMENT, 0o600)
    }
}

fn path_entry_exists(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("lstat {}: {error}", path.display())),
    }
}

#[cfg(target_os = "android")]
fn verify_device_identity() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0
        || std::env::current_exe().map_err(|error| error.to_string())? != Path::new(SELF_PATH)
    {
        return Err("install requires root execution from its fixed path".to_string());
    }
    // The desktop bootstrap publishes this continuation as root:root 0700.
    // apply_native retains that exact private mode for every system program.
    let running =
        self_executable::read_self_executable(Path::new(SELF_PATH), MAX_SELF_BYTES, 0o700, 0, 0)?;
    if !appended_signature_valid(
        &running,
        &NATIVE_EXECUTABLE_PUBLIC_KEY,
        native_executable_signature::NativeExecutableRole::Install,
    ) {
        return Err("install executable identity or role signature is invalid".to_string());
    }
    Ok(())
}

fn read_bounded(path: &Path, maximum: usize, mode: u32) -> Result<Vec<u8>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("open {}: {error}", path.display()))?;
    let before = file.metadata().map_err(|error| error.to_string())?;
    if !before.file_type().is_file()
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > maximum as u64
        || before.permissions().mode() & 0o7777 != mode
    {
        return Err(format!("unsafe file {}", path.display()));
    }
    #[cfg(target_os = "android")]
    if before.uid() != 0 || before.gid() != 0 {
        return Err(format!("non-root file {}", path.display()));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(maximum.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let after = file.metadata().map_err(|error| error.to_string())?;
    if file_identity(&before) != file_identity(&after)
        || bytes.len() as u64 != before.len()
        || bytes.len() > maximum
    {
        return Err(format!("file changed while reading {}", path.display()));
    }
    Ok(bytes)
}

fn file_identity(metadata: &fs::Metadata) -> (u64, u64, u64, i64, i64, u64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.ctime(),
        metadata.ctime_nsec(),
        metadata.nlink(),
    )
}

fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    write_atomic_labeled(path, bytes, mode, None)
}

fn set_file_context(file: &File, context: &str) -> Result<(), String> {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        let value = std::ffi::CString::new(context).map_err(|error| error.to_string())?;
        if unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                b"security.selinux\0".as_ptr().cast(),
                value.as_ptr().cast(),
                value.as_bytes_with_nul().len(),
                0,
            )
        } != 0
        {
            return Err(format!(
                "label inventory descriptor: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = (file, context);
        Err("SELinux labeling requires Android/Linux".into())
    }
}

fn write_atomic_labeled(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    context: Option<&str>,
) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "atomic target has no parent".to_string())?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "non-UTF8 target".to_string())?;
    let temporary = parent.join(format!(".{name}.tmp"));
    let _ = fs::remove_file(&temporary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    if let Some(context) = context {
        set_file_context(&file, context)?;
    }
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())?;
    fs::rename(&temporary, path).map_err(|error| error.to_string())?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn detached_signature_valid(bytes: &[u8], signature: &[u8], key: &[u8; 32]) -> bool {
    VerifyingKey::from_bytes(key)
        .ok()
        .zip(Signature::from_slice(signature).ok())
        .is_some_and(|(key, signature)| key.verify_strict(bytes, &signature).is_ok())
}
fn appended_signature_valid(
    bytes: &[u8],
    key: &[u8; 32],
    role: native_executable_signature::NativeExecutableRole,
) -> bool {
    if bytes.len() < SIGNATURE_TRAILER_BYTES || bytes.len() > MAX_SELF_BYTES {
        return false;
    }
    let prefix = bytes.len() - SIGNATURE_TRAILER_BYTES;
    let trailer = &bytes[prefix..];
    trailer[..8] == *SIGNATURE_MAGIC
        && <[u8; 8]>::try_from(&trailer[8..16])
            .ok()
            .map(u64::from_le_bytes)
            == Some(prefix as u64)
        && native_executable_signature::transcript(role, &bytes[..prefix])
            .is_some_and(|transcript| detached_signature_valid(&transcript, &trailer[16..], key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct ScriptedInstallActions {
        boot_id: String,
        reboot_requests: usize,
        now_ms: u64,
        readiness_after_ms: Option<u64>,
        changed_boot_at_ms: Option<u64>,
        acknowledgement: bool,
        acceptance_platform: Option<acceptance::Platform>,
        acceptance_calls: usize,
        fail_phase: Option<InstallPhase>,
        executed: Vec<InstallPhase>,
        emitted: Vec<(InstallPhase, String, usize)>,
    }

    impl InstallActions for ScriptedInstallActions {
        fn boot_id(&mut self) -> Result<String, String> {
            if self
                .changed_boot_at_ms
                .is_some_and(|change| self.now_ms >= change)
            {
                return Ok("00000000-0000-0000-0000-000000000003".into());
            }
            Ok(self.boot_id.clone())
        }

        fn request_reboot(&mut self) -> Result<(), String> {
            self.reboot_requests += 1;
            Ok(())
        }

        fn boot_completed(&mut self) -> Result<bool, String> {
            Ok(self
                .readiness_after_ms
                .is_none_or(|ready| self.now_ms >= ready))
        }

        fn monotonic_ms(&mut self) -> Result<u64, String> {
            Ok(self.now_ms)
        }

        fn pause_boot_poll(&mut self) {
            self.now_ms += 200;
        }

        fn observer_acceptance(
            &mut self,
            _lease: &OperationLease,
            _path: &Path,
            _journal: &InstallJournal,
            _uninstall: &impl Fn() -> bool,
        ) -> Result<(), String> {
            self.acceptance_calls += 1;
            if let Some(platform) = self.acceptance_platform {
                platform.guard()?;
            }
            Ok(())
        }

        fn generation_acknowledgement(
            &mut self,
            _journal_path: &Path,
            _journal: &InstallJournal,
        ) -> Result<bool, String> {
            Ok(self.acknowledgement)
        }

        fn execute(
            &mut self,
            phase: InstallPhase,
            _journal_path: &Path,
            _journal: &InstallJournal,
        ) -> Result<(), String> {
            self.executed.push(phase);
            if self.fail_phase == Some(phase) {
                return Err(format!("injected {phase:?} failure"));
            }
            Ok(())
        }

        fn emit(
            &mut self,
            lease: &OperationLease,
            journal_path: &Path,
            _transaction_id: &str,
            phase: InstallPhase,
            outcome: &str,
            reboot_count: usize,
        ) -> Result<(), String> {
            self.emitted
                .push((phase, outcome.to_string(), reboot_count));
            let transaction_id = journal_path
                .parent()
                .and_then(Path::file_name)
                .and_then(|value| value.to_str())
                .ok_or_else(|| "test install transaction is invalid".to_string())?;
            let descriptor = OperationDescriptor {
                schema_version: 1,
                operation: Operation::Install,
                transaction_id: transaction_id.to_string(),
                journal: format!("recovery/{transaction_id}/install-journal.json"),
                phase: serde_json::to_value(phase)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string(),
                outcome: outcome.to_string(),
                reboot_count: reboot_count as u32,
                boot_id: self.boot_id.clone(),
                status_sequence: operation_status_sequence(phase, outcome)?,
                journal_sha256: sha256(&read_bounded(
                    journal_path,
                    MAX_INSTALL_JOURNAL_BYTES,
                    0o600,
                )?),
                error: None,
                installed_apk: None,
            };
            lease.publish(&descriptor)?;
            Ok(())
        }
    }

    fn driver_fixture(
        phase: InstallPhase,
        boot_ids: Vec<String>,
    ) -> (tempfile::TempDir, PathBuf, InstallJournal, OperationLease) {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let transaction_id = "11".repeat(32);
        let recovery = root.path().join("recovery").join(&transaction_id);
        fs::create_dir_all(&recovery).unwrap();
        fs::set_permissions(
            root.path().join("recovery"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::set_permissions(&recovery, fs::Permissions::from_mode(0o700)).unwrap();
        let journal_path = recovery.join("install-journal.json");
        let journal = InstallJournal {
            schema_version: 1,
            transaction_id: transaction_id.clone(),
            manifest_sha256: "22".repeat(32),
            phase,
            boot_ids,
        };
        write_atomic(&journal_path, &journal.canonical_bytes().unwrap(), 0o600).unwrap();
        let descriptor = OperationDescriptor::new(
            Operation::Install,
            transaction_id,
            format!("recovery/{}/install-journal.json", "11".repeat(32)),
            "00000000-0000-0000-0000-000000000001".to_string(),
        )
        .unwrap();
        let lease = OperationLease::acquire_in(root.path(), descriptor).unwrap();
        (root, journal_path, journal, lease)
    }

    #[test]
    fn armed_install_crosses_permissive_boot0_to_enforcing_boot1() {
        let boot0 = "00000000-0000-0000-0000-000000000001";
        let boot1 = "00000000-0000-0000-0000-000000000002";
        let platform = acceptance::Platform {
            android: true,
            qemu: true,
            enforcing: false,
            ..Default::default()
        };
        for enforcing in [false, true] {
            let (_root, path, mut journal, lease) =
                driver_fixture(InstallPhase::InstallPrepare, vec![]);
            platform.admit().unwrap();
            let mut actions = ScriptedInstallActions {
                boot_id: boot0.into(),
                acknowledgement: true,
                acceptance_platform: Some(platform),
                ..Default::default()
            };
            drive_transaction_guarded_with(&lease, &path, &mut journal, &mut actions, || false)
                .unwrap();
            assert_eq!(journal.phase, InstallPhase::InstallRebootFirst);
            assert_eq!(journal.boot_ids, [boot0]);
            assert_eq!(actions.reboot_requests, 1);
            assert_eq!(actions.acceptance_calls, 0);
            actions.boot_id = boot1.into();
            actions.acceptance_platform.as_mut().unwrap().enforcing = enforcing;
            let result =
                drive_transaction_guarded_with(&lease, &path, &mut journal, &mut actions, || false);
            assert_eq!(actions.acceptance_calls, 1);
            if enforcing {
                result.unwrap();
                assert_eq!(journal.phase, InstallPhase::InstallRebootSecond);
                assert_eq!(journal.boot_ids, [boot0, boot1]);
                assert_eq!(actions.reboot_requests, 2);
            } else {
                assert!(result.unwrap_err().contains("Enforcing"));
                assert_eq!(journal.phase, InstallPhase::InstallAgents);
                assert_eq!(journal.boot_ids, [boot0]);
                assert_eq!(actions.reboot_requests, 1);
            }
        }
        for denied in [
            acceptance::Platform {
                android: false,
                ..platform
            },
            acceptance::Platform {
                qemu: false,
                ..platform
            },
            acceptance::Platform {
                uid: 2000,
                ..platform
            },
            acceptance::Platform {
                gid: 2000,
                ..platform
            },
        ] {
            assert!(denied.admit().is_err());
            assert!(denied.guard().is_err());
        }
        assert!(acceptance::admit().is_err());
    }

    #[test]
    fn boot_property_diagnostics_preserve_observation() {
        assert_eq!(observed_property_state(""), "unavailable");
        assert_eq!(observed_property_state("0"), "0");
        assert_eq!(observed_property_state("1"), "1");
    }

    #[test]
    fn intermediate_readiness_waits_without_advancing_wal_and_times_out_closed() {
        for readiness in [Some(600), Some(120_000), None] {
            let (_root, path, mut journal, lease) = driver_fixture(
                InstallPhase::InstallAgents,
                vec!["00000000-0000-0000-0000-000000000001".into()],
            );
            let mut actions = ScriptedInstallActions {
                boot_id: "00000000-0000-0000-0000-000000000002".into(),
                acknowledgement: true,
                readiness_after_ms: readiness,
                ..Default::default()
            };
            let result =
                drive_transaction_guarded_with(&lease, &path, &mut journal, &mut actions, || false);
            if readiness == Some(120_000) {
                let error = result.unwrap_err();
                assert!(error.contains("deadline expired"));
                assert!(error.contains("start_ms=0 deadline_ms=120000"));
                assert!(error.contains("last_sys.boot_completed=\"unavailable\""));
                assert_eq!(journal.phase, InstallPhase::InstallAgents);
                assert_eq!(journal.boot_ids.len(), 1);
                assert_eq!(actions.reboot_requests, 0);
                let persisted: InstallJournal =
                    serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
                assert_eq!(persisted.phase, InstallPhase::InstallAgents);
            } else {
                result.unwrap();
                assert_eq!(actions.reboot_requests, 1);
                assert_eq!(journal.phase, InstallPhase::InstallRebootSecond);
                assert_eq!(actions.now_ms, if readiness.is_some() { 600 } else { 0 });
            }
        }
    }

    #[test]
    fn intermediate_readiness_rejects_uuid_drift_and_original_boot() {
        for (boot, change) in [
            ("00000000-0000-0000-0000-000000000002", Some(200)),
            ("00000000-0000-0000-0000-000000000001", None),
        ] {
            let (_root, path, mut journal, lease) = driver_fixture(
                InstallPhase::InstallAgents,
                vec!["00000000-0000-0000-0000-000000000001".into()],
            );
            let mut actions = ScriptedInstallActions {
                boot_id: boot.into(),
                acknowledgement: true,
                readiness_after_ms: Some(600),
                changed_boot_at_ms: change,
                ..Default::default()
            };
            assert!(drive_transaction_guarded_with(
                &lease,
                &path,
                &mut journal,
                &mut actions,
                || false
            )
            .is_err());
            assert_eq!(journal.phase, InstallPhase::InstallAgents);
            assert_eq!(actions.reboot_requests, 0);
        }
    }

    #[test]
    fn intermediate_readiness_honors_uninstall_during_poll() {
        let (_root, path, mut journal, lease) = driver_fixture(
            InstallPhase::InstallAgents,
            vec!["00000000-0000-0000-0000-000000000001".into()],
        );
        let mut actions = ScriptedInstallActions {
            boot_id: "00000000-0000-0000-0000-000000000002".into(),
            acknowledgement: true,
            readiness_after_ms: Some(600),
            ..Default::default()
        };
        let checks = std::cell::Cell::new(0);
        let error =
            drive_transaction_guarded_with(&lease, &path, &mut journal, &mut actions, || {
                checks.set(checks.get() + 1);
                checks.get() == 3
            })
            .unwrap_err();
        assert!(error.contains("uninstall"));
        assert_eq!(journal.phase, InstallPhase::InstallAgents);
        assert_eq!(actions.reboot_requests, 0);
    }

    #[test]
    fn explicit_uninstall_request_stops_the_driver_before_any_mutation() {
        let (_root, journal_path, mut journal, lease) =
            driver_fixture(InstallPhase::InstallPrepare, Vec::new());
        let mut actions = ScriptedInstallActions {
            boot_id: "00000000-0000-0000-0000-000000000001".to_string(),
            acknowledgement: true,
            ..Default::default()
        };
        let fence = tempfile::tempdir().unwrap();
        let request = fence.path().join("desktop-uninstall-request");
        fs::write(&request, b"").unwrap();
        let error = drive_transaction_guarded_with(
            &lease,
            &journal_path,
            &mut journal,
            &mut actions,
            || fs::symlink_metadata(&request).is_ok(),
        )
        .unwrap_err();
        assert_eq!(error, "install superseded by an explicit uninstall request");
        assert!(actions.executed.is_empty());
        assert_eq!(journal.phase, InstallPhase::InstallPrepare);
        // Without the fence the same journal continues normally.
        drop(fence);
        let mut actions = ScriptedInstallActions {
            boot_id: "00000000-0000-0000-0000-000000000001".to_string(),
            acknowledgement: true,
            ..Default::default()
        };
        drive_transaction_with(&lease, &journal_path, &mut journal, &mut actions).unwrap();
        assert_eq!(journal.phase, InstallPhase::InstallRebootFirst);
    }

    #[test]
    fn same_boot_retry_after_a_failed_reboot_does_not_rewind_the_sequence() {
        // OG1: a failed reboot published the terminal `failed` document.
        // Re-entering the same boot must not re-emit the lower
        // reboot-required slot and wedge the lease; the failed publication
        // is already the observer state, so the retry requests the reboot
        // directly and can still converge.
        let boot = "00000000-0000-0000-0000-000000000001".to_string();
        let (_root, journal_path, mut journal, lease) =
            driver_fixture(InstallPhase::InstallRebootFirst, vec![boot.clone()]);
        let mut actions = ScriptedInstallActions {
            boot_id: boot.clone(),
            acknowledgement: true,
            ..Default::default()
        };
        // The failure publisher already published the terminal document.
        let failed = OperationDescriptor {
            schema_version: 1,
            operation: Operation::Install,
            transaction_id: journal.transaction_id.clone(),
            journal: format!("recovery/{}/install-journal.json", journal.transaction_id),
            phase: "install-reboot-first".to_string(),
            outcome: "failed".to_string(),
            reboot_count: 1,
            boot_id: boot,
            status_sequence: operation_status_sequence(InstallPhase::InstallRebootFirst, "failed")
                .unwrap(),
            journal_sha256: sha256(
                &read_bounded(&journal_path, MAX_INSTALL_JOURNAL_BYTES, 0o600).unwrap(),
            ),
            error: Some(serde_json::json!({
                "code": "install-failed",
                "message": "reboot request failed"
            })),
            installed_apk: None,
        };
        lease.publish(&failed).unwrap();
        // The same-boot retry converges: no emit, reboot requested again.
        drive_transaction_with(&lease, &journal_path, &mut journal, &mut actions).unwrap();
        assert_eq!(actions.reboot_requests, 1);
        assert!(actions.emitted.is_empty());
        assert_eq!(journal.phase, InstallPhase::InstallRebootFirst);
        // The live projection is still the terminal failed document.
        let current = lease.read_live_projection().unwrap().unwrap();
        assert_eq!(current.outcome, "failed");
        assert_eq!(
            current.status_sequence,
            operation_status_sequence(InstallPhase::InstallRebootFirst, "failed").unwrap()
        );
    }

    #[test]
    fn production_install_driver_crosses_two_boots_and_executes_every_phase_once() {
        let (_root, journal_path, mut journal, lease) =
            driver_fixture(InstallPhase::InstallPrepare, Vec::new());
        let mut actions = ScriptedInstallActions {
            boot_id: "00000000-0000-0000-0000-000000000001".to_string(),
            acknowledgement: true,
            ..Default::default()
        };
        drive_transaction_with(&lease, &journal_path, &mut journal, &mut actions).unwrap();
        assert_eq!(journal.phase, InstallPhase::InstallRebootFirst);
        assert_eq!(actions.reboot_requests, 1);
        assert_eq!(journal.boot_ids, [actions.boot_id.clone()]);

        drive_transaction_with(&lease, &journal_path, &mut journal, &mut actions).unwrap();
        assert_eq!(journal.phase, InstallPhase::InstallRebootFirst);
        assert_eq!(actions.reboot_requests, 2);

        actions.boot_id = "00000000-0000-0000-0000-000000000002".to_string();
        drive_transaction_with(&lease, &journal_path, &mut journal, &mut actions).unwrap();
        assert_eq!(journal.phase, InstallPhase::InstallRebootSecond);
        assert_eq!(actions.reboot_requests, 3);

        actions.boot_id = "00000000-0000-0000-0000-000000000003".to_string();
        drive_transaction_with(&lease, &journal_path, &mut journal, &mut actions).unwrap();
        assert_eq!(journal.phase, InstallPhase::InstallCleanup);
        assert_eq!(
            actions.executed,
            [
                InstallPhase::InstallPrepare,
                InstallPhase::InstallPolicyBackup,
                InstallPhase::InstallRuntimeApply,
                InstallPhase::InstallApp,
                InstallPhase::InstallPolicyApply,
                InstallPhase::InstallAgents,
                InstallPhase::InstallRuntimeVerify,
                InstallPhase::InstallInventoryCommit,
                InstallPhase::InstallCleanup,
            ]
        );
        let persisted: InstallJournal = serde_json::from_slice(
            &read_bounded(&journal_path, MAX_INSTALL_JOURNAL_BYTES, 0o600).unwrap(),
        )
        .unwrap();
        assert_eq!(persisted, journal);
    }

    #[test]
    fn production_install_driver_restarts_at_every_failed_mutation_phase() {
        for phase in [
            InstallPhase::InstallPrepare,
            InstallPhase::InstallPolicyBackup,
            InstallPhase::InstallRuntimeApply,
            InstallPhase::InstallApp,
            InstallPhase::InstallPolicyApply,
            InstallPhase::InstallAgents,
            InstallPhase::InstallRuntimeVerify,
            InstallPhase::InstallInventoryCommit,
            InstallPhase::InstallCleanup,
        ] {
            let boot_ids = if matches!(
                phase,
                InstallPhase::InstallAgents
                    | InstallPhase::InstallRuntimeVerify
                    | InstallPhase::InstallInventoryCommit
                    | InstallPhase::InstallCleanup
            ) {
                vec!["00000000-0000-0000-0000-000000000001".to_string()]
            } else {
                Vec::new()
            };
            let (_root, journal_path, mut journal, lease) = driver_fixture(phase, boot_ids);
            let before = journal.canonical_bytes().unwrap();
            let mut actions = ScriptedInstallActions {
                boot_id: "00000000-0000-0000-0000-000000000002".to_string(),
                acknowledgement: true,
                fail_phase: Some(phase),
                ..Default::default()
            };
            assert!(
                drive_transaction_with(&lease, &journal_path, &mut journal, &mut actions).is_err()
            );
            assert_eq!(
                read_bounded(&journal_path, MAX_INSTALL_JOURNAL_BYTES, 0o600).unwrap(),
                before,
                "{phase:?} advanced its WAL after a failed mutation"
            );
            actions.fail_phase = None;
            drive_transaction_with(&lease, &journal_path, &mut journal, &mut actions).unwrap();
            assert_ne!(actions.executed.last(), None, "{phase:?}");
        }
    }
    #[test]
    fn phases_are_operation_first_and_have_two_reboots() {
        let mut phase = InstallPhase::InstallPrepare;
        let mut phases = vec![phase];
        while let Some(next) = phase.next() {
            phase = next;
            phases.push(phase);
        }
        assert_eq!(phases.len(), 12);
        assert_eq!(
            phases
                .iter()
                .filter(|phase| phase.requires_reboot())
                .count(),
            2
        );
        assert_eq!(phase, InstallPhase::InstallComplete);
        assert_eq!(
            phases
                .iter()
                .map(|phase| serde_json::to_value(phase)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string())
                .collect::<Vec<_>>(),
            [
                "install-prepare",
                "install-policy-backup",
                "install-runtime-apply",
                "install-app",
                "install-policy-apply",
                "install-reboot-first",
                "install-agents",
                "install-reboot-second",
                "install-runtime-verify",
                "install-inventory-commit",
                "install-cleanup",
                "install-complete"
            ]
        );
    }

    #[test]
    fn status_sequence_reserves_distinct_running_reboot_and_terminal_slots() {
        for (phase, number) in [
            (InstallPhase::InstallPrepare, 1_u64),
            (InstallPhase::InstallApp, 4),
            (InstallPhase::InstallRebootFirst, 6),
            (InstallPhase::InstallComplete, 12),
        ] {
            assert_eq!(
                operation_status_sequence(phase, "running").unwrap(),
                number * 3 - 2
            );
            assert_eq!(
                operation_status_sequence(phase, "reboot-required").unwrap(),
                number * 3 - 1
            );
            for outcome in ["failed", "complete"] {
                assert_eq!(
                    operation_status_sequence(phase, outcome).unwrap(),
                    number * 3
                );
            }
        }
        assert!(operation_status_sequence(InstallPhase::InstallPrepare, "unknown").is_err());
    }

    #[test]
    fn failure_reports_preserve_the_actual_phase_and_closed_preflight_schema() {
        let transaction_id = "11".repeat(32);
        let journal = InstallJournal {
            schema_version: 1,
            transaction_id: transaction_id.clone(),
            manifest_sha256: "22".repeat(32),
            phase: InstallPhase::InstallAgents,
            boot_ids: vec!["00000000-0000-0000-0000-000000000001".to_string()],
        };
        let bytes = journal.canonical_bytes().unwrap();
        assert_eq!(
            parse_failure_report_state(&bytes, &transaction_id),
            Some((InstallPhase::InstallAgents, 1))
        );
        assert!(parse_failure_report_state(&bytes, &"33".repeat(32)).is_none());

        assert_eq!(
            String::from_utf8(pre_transaction_failure_bytes("bad\ninput").unwrap()).unwrap(),
            "{\"schemaVersion\":1,\"operation\":\"install\",\"failureType\":\"pre-transaction\",\"error\":{\"code\":\"install-pre-transaction-failed\",\"message\":\"badinput\"}}\n"
        );
    }

    #[test]
    fn pre_freeze_failure_is_observable_without_fake_durable_transaction_authority() {
        let published = std::cell::Cell::new(false);
        let emitted = std::cell::RefCell::new(Vec::new());
        report_install_failure_with(
            None,
            "authenticated APK signer rejected\nwith detail",
            |_, _| {
                published.set(true);
                Ok(())
            },
            |error| {
                emitted
                    .borrow_mut()
                    .extend(pre_transaction_failure_bytes(error).unwrap())
            },
        );
        assert!(!published.get());
        let bytes = emitted.into_inner();
        assert!(bytes.len() < 1024);
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "{\"schemaVersion\":1,\"operation\":\"install\",\"failureType\":\"pre-transaction\",\"error\":{\"code\":\"install-pre-transaction-failed\",\"message\":\"authenticated APK signer rejectedwith detail\"}}\n"
        );

        let published_id = std::cell::RefCell::new(String::new());
        report_install_failure_with(
            Some(&"ab".repeat(32)),
            "durable failure",
            |transaction_id, _| {
                published_id.borrow_mut().push_str(transaction_id);
                Ok(())
            },
            |_| panic!("durable failure used pre-transaction output"),
        );
        assert_eq!(published_id.into_inner(), "ab".repeat(32));
    }

    #[test]
    fn installer_uses_shared_producer_catalog_order_and_ascii_escaping() {
        let descriptor = contract::tests::descriptor_for_cross_module_tests();
        let bytes = format!(
            concat!(
                r#"{{"schemaVersion":2,"supportedAbis":["arm64-v8a"],"agentEntryAbi":{{"schemaVersion":1,"sha256":"{}"}},"core":{{"file":"agent-common.dex","size":16,"sha256":"{}"}},"agents":[{{"id":"settings","targets":[{{"platform":"android","domain":"android","entryAbi":"android-java-v1","process":"com.qinggan.app.setting","file":"agent-settings.dex","size":17,"sha256":"{}","entryClass":"ru.voboost.agents.settings.SettingsAgent","boot":false}}],"status":"stable","category":"interface","order":0,"activation":{{"type":"config","key":"voboost-startup","value":"interface"}},"disables":[],"options":[],"title":{{"en":"Settings","ru":"\u041d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0438"}},"description":{{"en":"Settings","ru":"\u041d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0438"}},"applicability":{{"chip":["8155"],"vehicle":["free"],"android":[9],"powertrain":["hybrid"],"market":["china"]}}}}]}}"#,
                "\n"
            ),
            "ad4335f5b500b3e82875a26dc6408f7bf2349d55b2f49cd64214565e8b1f7d14",
            "f".repeat(64),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .into_bytes();
        let mut typed: voboost_contract::agent_catalog::AgentCatalog =
            serde_json::from_slice(&bytes).unwrap();
        add_native_test_catalog(&mut typed, &descriptor);
        let bytes = typed.canonical_bytes().unwrap();
        verify_agent_catalog_inventory(&descriptor, &bytes).unwrap();

        let text = String::from_utf8(bytes).unwrap();
        let reordered = text.replacen(
            "{\"schemaVersion\":2,\"supportedAbis\":",
            "{\"supportedAbis\":",
            1,
        );
        let reordered = reordered.replacen(
            "[\"arm64-v8a\"],\"agentEntryAbi\":",
            "[\"arm64-v8a\"],\"schemaVersion\":2,\"agentEntryAbi\":",
            1,
        );
        assert!(verify_agent_catalog_inventory(&descriptor, reordered.as_bytes()).is_err());
    }

    fn add_native_test_catalog(
        catalog: &mut voboost_contract::agent_catalog::AgentCatalog,
        descriptor: &InstallDescriptor,
    ) {
        let runtime = descriptor
            .artifact("libvoboost-runtime-cluster.so")
            .unwrap();
        catalog.cluster_runtime = Some(voboost_contract::agent_catalog::CatalogFile {
            file: runtime.file.clone(),
            size: runtime.size,
            sha256: runtime.sha256.clone(),
        });
        let module = descriptor.artifact("libagent-font-cyrillic.so").unwrap();
        let mut agent = catalog.agents[0].clone();
        agent.id = "font-cyrillic".into();
        agent.targets.truncate(1);
        let target = &mut agent.targets[0];
        target.platform = voboost_contract::agent_catalog::TargetPlatform::Qnx;
        target.domain = voboost_contract::agent_catalog::TargetDomain::Cluster;
        target.entry_abi = voboost_contract::agent_catalog::TargetAbi::VoboostAgent3V1;
        target.entry_class = None;
        target.process = "gauge".into();
        target.file = module.file.clone();
        target.size = module.size;
        target.sha256 = module.sha256.clone();
        catalog.agents.push(agent);
    }

    fn shared_module_catalog() -> voboost_contract::agent_catalog::AgentCatalog {
        let descriptor = contract::tests::descriptor_for_cross_module_tests();
        let core = descriptor.artifact("agent-common.dex").unwrap();
        let module = descriptor.artifact("agent-settings.dex").unwrap();
        let value = serde_json::json!({
            "schemaVersion":2,"supportedAbis":["arm64-v8a"],
            "agentEntryAbi":{"schemaVersion":1,"sha256":"a".repeat(64)},
            "core":{"file":core.file,"size":core.size,"sha256":core.sha256},
            "agents":[{"id":"settings","targets":[{
                "platform":"android","domain":"android","entryAbi":"android-java-v1","process":"com.example.first","file":module.file,"size":module.size,
                "sha256":module.sha256,"entryClass":"ru.voboost.agents.settings.SettingsAgent","boot":false
            }]}]
        });
        let mut catalog: voboost_contract::agent_catalog::AgentCatalog =
            serde_json::from_value(value).unwrap();
        add_native_test_catalog(&mut catalog, &descriptor);
        let mut alias = catalog.agents[0].targets[0].clone();
        alias.process = "com.example.second".into();
        catalog.agents[0].targets.push(alias);
        catalog
    }

    #[test]
    fn installer_shared_module_inventory_accepts_exact_aliases_and_legacy_files() {
        let descriptor = contract::tests::descriptor_for_cross_module_tests();
        let mut catalog = shared_module_catalog();
        verify_agent_catalog_inventory(&descriptor, &catalog.canonical_bytes().unwrap()).unwrap();
        let mut legacy = descriptor.clone();
        let mut artifact = legacy.artifact("agent-settings.dex").unwrap().clone();
        artifact.file = "agent-settings-second.dex".into();
        legacy.artifacts.push(artifact);
        catalog.agents[0].targets[1].file = "agent-settings-second.dex".into();
        verify_agent_catalog_inventory(&legacy, &catalog.canonical_bytes().unwrap()).unwrap();
    }

    #[test]
    fn installer_shared_module_inventory_rejects_conflicts_and_duplicate_product_rows() {
        let descriptor = contract::tests::descriptor_for_cross_module_tests();
        for field in [
            "size", "sha256", "entry", "case", "process", "core", "reserved", "agent",
        ] {
            let mut catalog = shared_module_catalog();
            let mut product = descriptor.clone();
            let target = &mut catalog.agents[0].targets[1];
            match field {
                "size" => target.size += 1,
                "sha256" => target.sha256 = "a".repeat(64),
                "entry" => {
                    target.entry_class = Some("ru.voboost.agents.settings.OtherAgent".into())
                }
                "case" => target.file = "agent-Settings.dex".into(),
                "process" => target.process = "com.example.first".into(),
                "core" => target.file = "agent-common.dex".into(),
                "reserved" => target.file = "agents.json".into(),
                "agent" => {
                    let mut foreign = catalog.agents[0].clone();
                    foreign.id = "other".into();
                    foreign.targets.truncate(1);
                    catalog.agents.push(foreign);
                }
                _ => unreachable!(),
            }
            if matches!(field, "case" | "core" | "reserved") {
                // Match the mutated target closure so rejection proves the
                // collision policy rather than an incidental missing row.
                let target = &catalog.agents[0].targets[1];
                let mut artifact = product.artifact("agent-settings.dex").unwrap().clone();
                artifact.file = target.file.clone();
                artifact.size = target.size;
                artifact.sha256 = target.sha256.clone();
                product.artifacts.push(artifact);
            }
            assert!(
                verify_agent_catalog_inventory(&product, &catalog.canonical_bytes().unwrap())
                    .is_err(),
                "{field}"
            );
        }
        let catalog = shared_module_catalog();
        let mut duplicate = descriptor.clone();
        duplicate
            .artifacts
            .push(duplicate.artifact("agent-settings.dex").unwrap().clone());
        assert!(
            verify_agent_catalog_inventory(&duplicate, &catalog.canonical_bytes().unwrap())
                .is_err()
        );
        let mut missing = descriptor.clone();
        missing
            .artifacts
            .retain(|artifact| artifact.file != "agent-settings.dex");
        assert!(
            verify_agent_catalog_inventory(&missing, &catalog.canonical_bytes().unwrap()).is_err()
        );
    }

    #[test]
    fn recovery_root_is_created_privately_and_hostile_existing_identity_is_never_chmod_adopted() {
        let transaction_id = "ab".repeat(32);
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        create_private_recovery_transaction(root.path(), &transaction_id).unwrap();
        assert_eq!(
            fs::symlink_metadata(root.path().join("recovery"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        assert_eq!(
            fs::symlink_metadata(root.path().join("recovery").join(&transaction_id))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );

        for hostile in ["wrong-mode", "symlink"] {
            let root = tempfile::tempdir().unwrap();
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
            let recovery = root.path().join("recovery");
            if hostile == "wrong-mode" {
                fs::create_dir(&recovery).unwrap();
                fs::set_permissions(&recovery, fs::Permissions::from_mode(0o777)).unwrap();
            } else {
                let outside = tempfile::tempdir().unwrap();
                std::os::unix::fs::symlink(outside.path(), &recovery).unwrap();
                assert!(create_private_recovery_transaction(root.path(), &transaction_id).is_err());
                assert!(!outside.path().join(&transaction_id).exists());
                continue;
            }
            assert!(create_private_recovery_transaction(root.path(), &transaction_id).is_err());
            assert_eq!(
                fs::symlink_metadata(&recovery)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                0o777,
                "hostile recovery root was chmod-adopted"
            );
            assert!(!recovery.join(&transaction_id).exists());
        }
    }

    #[test]
    fn install_admission_rejects_partial_cluster_before_wal() {
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
        assert!(begin_install_guard(root.path()).is_err());
        assert!(!root.path().join("operation.json").exists());
        assert!(!root.path().join("recovery").exists());
        std::fs::remove_file(cluster.join("provision.json")).unwrap();
        let guard = begin_install_guard(root.path()).unwrap();
        let other = root.path().to_path_buf();
        assert!(
            std::thread::spawn(
                move || operation_contract::RawOperationLock::acquire_in(&other).is_err()
            )
            .join()
            .unwrap()
        );
        drop(guard);
    }

    #[test]
    fn root_authority_is_published_only_after_the_verified_lease() {
        let source = include_str!("main.rs");
        let body = source
            .split("fn run_device_transaction")
            .nth(1)
            .unwrap()
            .split("fn drive_transaction")
            .next()
            .unwrap();
        assert!(
            body.find("operation.admit(pointer)").unwrap()
                < body.find("create_root_document()?").unwrap()
        );
        assert!(
            body.find("lease.verify_owner()?").unwrap()
                < body.find("create_root_document()?").unwrap()
        );
    }
    #[test]
    fn installer_consumes_the_host_root_mode_and_keeps_private_descendants() {
        let source = include_str!("main.rs");
        assert!(source.contains("if current == ancestor { 0o755 } else { 0o700 }"));
        let inventory = include_str!("inventory.rs");
        assert!(inventory.contains("\"installer\":artifact(&descriptor,\"voboost-install\")?"));
        let selinux_spec = include_str!("../../openspec/specs/selinux-domain-policy/spec.md");
        assert!(selinux_spec.contains(
            "retained, signed `/data/voboost/voboost-install` SHALL remain root-owned mode `0700`"
        ));
    }
    #[test]
    fn retained_install_chain_allows_children_but_rejects_authority_changes() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let source = root
            .path()
            .join("recovery")
            .join("transaction")
            .join("frozen");
        fs::create_dir_all(&source).unwrap();
        for path in [
            source.parent().unwrap().parent().unwrap(),
            source.parent().unwrap(),
            &source,
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let chain = retain_private_directory_chain_from(root.path(), &source).unwrap();
        let original_links = fs::metadata(root.path()).unwrap().nlink();
        // Actual directory creation changes st_nlink on the guest filesystem.
        // No synthetic metadata is used: exercise the production revalidator.
        fs::create_dir(root.path().join("run")).unwrap();
        fs::create_dir(root.path().join("state")).unwrap();
        assert_ne!(fs::metadata(root.path()).unwrap().nlink(), original_links);
        revalidate_directory_chain(&chain).unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(revalidate_directory_chain(&chain).is_err());
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        revalidate_directory_chain(&chain).unwrap();
        let moved = source.with_file_name("moved");
        fs::rename(&source, &moved).unwrap();
        fs::create_dir(&source).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(revalidate_directory_chain(&chain).is_err());
        fs::remove_dir(&source).unwrap();
        std::os::unix::fs::symlink(&moved, &source).unwrap();
        assert!(revalidate_directory_chain(&chain).is_err());
        fs::remove_file(&source).unwrap();
        fs::rename(&moved, &source).unwrap();
        revalidate_directory_chain(&chain).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(revalidate_directory_chain(&chain).is_err());
    }

    #[test]
    fn staging_discovery_rejects_multiple_transactions() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("11".repeat(32))).unwrap();
        assert!(discover_staging(root.path()).is_ok());
        fs::create_dir(root.path().join("22".repeat(32))).unwrap();
        assert!(discover_staging(root.path()).is_err());
    }

    fn immediate_staging_fixture() -> (tempfile::TempDir, PathBuf, BTreeSet<String>) {
        let root = tempfile::tempdir().unwrap();
        let staging = root.path().join("1".repeat(64));
        fs::create_dir(&staging).unwrap();
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)).unwrap();
        let expected = (0..MAX_STAGING_ENTRIES)
            .map(|index| format!("file-{index:02}"))
            .collect::<BTreeSet<_>>();
        for name in &expected {
            fs::write(staging.join(name), b"").unwrap();
            fs::set_permissions(staging.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
        (root, staging, expected)
    }

    #[test]
    fn staging_root_rejects_empty_deep_wide_link_and_special_entries_before_capture() {
        assert_eq!(MAX_STAGING_ENTRIES, 1024 + 3);
        let (_root, staging, expected) = immediate_staging_fixture();
        let retained = StagingRoot::open(&staging).unwrap();
        assert_eq!(retained.entry_names().unwrap(), expected);
        let last = staging.join("file-69");
        let restore_last = || {
            fs::write(&last, b"").unwrap();
            fs::set_permissions(&last, fs::Permissions::from_mode(0o600)).unwrap();
        };

        fs::remove_file(&last).unwrap();
        let empty_directory = staging.join("empty-directory");
        fs::create_dir(&empty_directory).unwrap();
        assert!(retained.entry_names().is_err());
        fs::remove_dir(&empty_directory).unwrap();
        restore_last();

        fs::remove_file(&last).unwrap();
        let deep = staging.join("deep");
        let mut cursor = deep.clone();
        for _ in 0..128 {
            fs::create_dir(&cursor).unwrap();
            cursor.push("next");
        }
        assert!(retained.entry_names().is_err());
        fs::remove_dir_all(&deep).unwrap();
        restore_last();

        let extra = staging.join("empty-extra");
        fs::write(&extra, b"").unwrap();
        fs::set_permissions(&extra, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(retained.entry_names().is_err());
        fs::remove_file(&extra).unwrap();

        fs::remove_file(&last).unwrap();
        let symlink_path = staging.join("symlink");
        std::os::unix::fs::symlink(staging.join("file-00"), &symlink_path).unwrap();
        assert!(retained.entry_names().is_err());
        fs::remove_file(&symlink_path).unwrap();
        restore_last();

        fs::remove_file(&last).unwrap();
        let hardlink = staging.join("hardlink");
        fs::hard_link(staging.join("file-00"), &hardlink).unwrap();
        assert!(retained.entry_names().is_err());
        fs::remove_file(&hardlink).unwrap();
        restore_last();

        fs::remove_file(&last).unwrap();
        let fifo = staging.join("fifo");
        let fifo_name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        assert!(retained.entry_names().is_err());
        fs::remove_file(&fifo).unwrap();
        restore_last();

        fs::set_permissions(staging.join("file-00"), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(retained.entry_names().is_err());
        fs::set_permissions(staging.join("file-00"), fs::Permissions::from_mode(0o600)).unwrap();

        let displaced = staging.with_extension("retained");
        fs::rename(&staging, &displaced).unwrap();
        std::os::unix::fs::symlink(&displaced, &staging).unwrap();
        assert_eq!(retained.entry_names().unwrap(), expected);
        assert!(retained.verify_named_identity().is_err());
    }

    #[test]
    fn host_staging_is_exact_flat_artifact_closure() {
        let mut manifest = contract::tests::descriptor_for_cross_module_tests();
        let template = manifest
            .artifacts
            .iter()
            .find(|a| a.role == voboost_contract::release::ArtifactRole::AgentModule)
            .unwrap()
            .clone();
        assert_eq!(
            template.role,
            voboost_contract::release::ArtifactRole::AgentModule
        );
        for index in 0..50 {
            let mut artifact = template.clone();
            artifact.file = format!("agent-z{index:02}.dex");
            artifact.size = index + 1;
            artifact.sha256 = format!("{index:064x}");
            manifest.artifacts.push(artifact);
        }
        manifest.artifacts.sort_by_key(|a| (a.role, a.file.clone()));
        manifest.validate().unwrap();
        assert_eq!(manifest.artifacts.len(), 71);
        let signed_closure = manifest
            .artifacts
            .iter()
            .map(|artifact| artifact.file.as_str())
            .chain(["voboost.json", "voboost.json.sig"])
            .collect::<BTreeSet<_>>();
        assert_eq!(signed_closure.len(), 73);
        assert!(signed_closure.contains("voboost-daemon"));
        assert!(signed_closure.contains("voboost-inject"));
        assert!(signed_closure.iter().all(|name| !name.contains('/')));
        assert!(!signed_closure.contains("base.apk"));
        assert!(!signed_closure.contains("install.json"));
        let staging = staging_inventory_names(&manifest);
        assert_eq!(staging.len(), 74);
        assert!(staging.contains("staging.json"));
    }

    #[test]
    fn staging_directory_artifact_and_selinux_substitution_cuts_change_identity() {
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("member");
        let replacement = root.path().join("replacement");
        fs::write(&original, b"verified").unwrap();
        fs::write(&replacement, b"verified").unwrap();
        let opened = File::open(&original).unwrap();
        let before = opened.metadata().unwrap();
        fs::rename(&replacement, &original).unwrap();
        let substituted = fs::metadata(&original).unwrap();
        assert_ne!(file_identity(&before), file_identity(&substituted));
        for cut in ["directory", "artifact", "selinux"] {
            assert_ne!(
                (before.dev(), before.ino()),
                (substituted.dev(), substituted.ino()),
                "{cut} substitution reused authority"
            );
        }
    }

    #[test]
    fn first_enforcing_boot_is_gated_by_trusted_native_relabel() {
        let rc = include_str!("../../config/voboost.rc");
        assert!(rc.contains(
            "on post-fs-data
    start voboost-relabel"
        ));
        assert!(!rc.contains("setenforce"));
        assert!(!rc.contains("/sys/fs/selinux/enforce"));
        assert!(rc.contains("service voboost-relabel /data/voboost/voboost-selinux --relabel"));
        assert!(rc.contains("on property:voboost.relabel.ready=1\n    start voboost-install"));
        assert!(rc.contains("    start voboost-restore\n    start voboost-daemon"));
        assert!(rc.contains("    seclabel u:r:voboost_relabel:s0"));
        let restore = rc
            .split("service voboost-restore ")
            .nth(1)
            .unwrap()
            .split("\n\n")
            .next()
            .unwrap();
        assert!(restore.contains("    seclabel u:r:voboost_restore:s0"));
        let policy = include_str!("../../selinux/voboost.te");
        assert!(policy.contains("type voboost_restore;"));
        assert!(policy.contains("type voboost_relabel;"));
        assert!(!policy.contains("allow init voboost_data_file:file relabelto;"));
        for service in ["voboost-install", "voboost-daemon"] {
            let body = rc
                .split(&format!("service {service} "))
                .nth(1)
                .unwrap()
                .split("\n\n")
                .next()
                .unwrap();
            assert!(body.contains("disabled"));
        }
        let selinux = include_str!("../../selinux/voboost-selinux.c");
        assert!(selinux.contains("publish_relabel_ready() == 0"));
        assert!(selinux.contains("relabel_zone_fd(root_authority.fd, ROOT_ZONE_DIRECTORY) == 0"));
    }

    #[test]
    fn postboot_install_rejects_permissive_and_malformed_kernel_state() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("enforce");
        for (bytes, accepted) in [
            (b"1".as_slice(), true),
            (b"1\n", true),
            (b"0", false),
            (b"0\n", false),
            (b"", false),
            (b"1\nextra", false),
        ] {
            fs::write(&path, bytes).unwrap();
            assert_eq!(require_enforcing_at(&path).is_ok(), accepted);
        }
        fs::remove_file(&path).unwrap();
        assert!(require_enforcing_at(&path).is_err());
    }

    #[test]
    fn completed_install_is_retained_across_every_terminal_cleanup_cut() {
        for cut in [
            "before-intent",
            "before-payload",
            "after-payload",
            "after-control",
        ] {
            let root = tempfile::tempdir().unwrap();
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
            let tx = "11".repeat(32);
            let recovery = root.path().join("recovery").join(&tx);
            let staging = root.path().join("install").join(&tx);
            fs::create_dir_all(&recovery).unwrap();
            fs::create_dir_all(&staging).unwrap();
            fs::set_permissions(
                root.path().join("recovery"),
                fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            fs::set_permissions(
                root.path().join("install"),
                fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            fs::set_permissions(&recovery, fs::Permissions::from_mode(0o700)).unwrap();
            let journal = InstallJournal {
                schema_version: 1,
                transaction_id: tx.clone(),
                manifest_sha256: "22".repeat(32),
                phase: InstallPhase::InstallComplete,
                boot_ids: Vec::new(),
            };
            let journal_bytes = journal.canonical_bytes().unwrap();
            fs::write(recovery.join("install-journal.json"), &journal_bytes).unwrap();
            fs::set_permissions(
                recovery.join("install-journal.json"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            let intent = transaction::TerminalIntent {
                schema_version: 1,
                transaction_id: tx.clone(),
                manifest_sha256: "22".repeat(32),
                installed_apk: serde_json::json!({
                    "packageName": "ru.voboost",
                    "versionCode": 1,
                    "certificateSha256": "33".repeat(32),
                    "path": "/data/app/ru.voboost/base.apk",
                    "size": 1,
                    "sha256": "44".repeat(32)
                }),
            };
            let intent_path = transaction::terminal_intent_path(root.path());
            let descriptor = OperationDescriptor::new(
                Operation::Install,
                tx.clone(),
                format!("recovery/{tx}/install-journal.json"),
                "00000000-0000-0000-0000-000000000001".to_string(),
            )
            .unwrap();
            let lease = OperationLease::acquire_in(root.path(), descriptor).unwrap();
            let terminal = OperationDescriptor {
                schema_version: 1,
                operation: Operation::Install,
                transaction_id: tx.clone(),
                journal: format!("recovery/{tx}/install-journal.json"),
                phase: "install-complete".to_string(),
                outcome: "complete".to_string(),
                reboot_count: 0,
                boot_id: "00000000-0000-0000-0000-000000000001".to_string(),
                status_sequence: 36,
                journal_sha256: sha256(&journal_bytes),
                error: None,
                installed_apk: Some(serde_json::json!({
                    "packageName": "ru.voboost",
                    "versionCode": 1,
                    "certificateSha256": "33".repeat(32),
                    "path": "/data/app/ru.voboost/base.apk",
                    "size": 1,
                    "sha256": "44".repeat(32)
                })),
            };
            write_atomic(
                &root.path().join("operation.json"),
                &terminal.canonical_bytes().unwrap(),
                0o600,
            )
            .unwrap();
            if cut != "before-intent" {
                fs::write(&intent_path, intent.bytes().unwrap()).unwrap();
                fs::set_permissions(&intent_path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            if matches!(cut, "after-payload" | "after-control") {
                transaction::cleanup_payload(&staging, &recovery, &intent).unwrap();
            }
            if cut == "after-control" {
                transaction::cleanup_control(&recovery, &intent).unwrap();
            }
            drop(lease);
            let inventory_checked = std::cell::Cell::new(false);
            let incoming_prepared = std::cell::Cell::new(false);
            recover_terminal_cleanup_with(
                root.path(),
                |_| {
                    inventory_checked.set(true);
                    Ok(())
                },
                || {
                    incoming_prepared.set(true);
                    Ok(())
                },
                || Ok("00000000-0000-0000-0000-000000000001".to_string()),
            )
            .unwrap();
            assert!(inventory_checked.get());
            // The completed terminal is only mirrored here: the driver
            // prepared the incoming staging before it published the install
            // complete, so the recovery of an already complete operation must
            // not run the takeover again.
            assert!(!incoming_prepared.get());
            assert_eq!(
                operation_contract::read_current_in(root.path()).unwrap(),
                Some(terminal)
            );
            assert!(!staging.exists());
            assert!(!recovery.exists());
            assert!(!intent_path.exists());
        }
    }

    #[test]
    fn missed_install_cleanup_prepares_agent_incoming_before_completing() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let tx = "55".repeat(32);
        let recovery = root.path().join("recovery").join(&tx);
        let staging = root.path().join("install").join(&tx);
        fs::create_dir_all(&recovery).unwrap();
        fs::create_dir_all(&staging).unwrap();
        for directory in [
            root.path().join("recovery"),
            root.path().join("install"),
            recovery.clone(),
            staging.clone(),
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let journal = InstallJournal {
            schema_version: 1,
            transaction_id: tx.clone(),
            manifest_sha256: "22".repeat(32),
            phase: InstallPhase::InstallCleanup,
            boot_ids: vec![
                "00000000-0000-0000-0000-000000000002".to_string(),
                "00000000-0000-0000-0000-000000000003".to_string(),
            ],
        };
        let journal_bytes = journal.canonical_bytes().unwrap();
        fs::write(recovery.join("install-journal.json"), &journal_bytes).unwrap();
        fs::set_permissions(
            recovery.join("install-journal.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let installed_apk = serde_json::json!({
            "packageName": "ru.voboost",
            "versionCode": 1,
            "certificateSha256": "33".repeat(32),
            "path": "/data/app/ru.voboost/base.apk",
            "size": 1,
            "sha256": "44".repeat(32)
        });
        let intent = transaction::TerminalIntent {
            schema_version: 1,
            transaction_id: tx.clone(),
            manifest_sha256: "22".repeat(32),
            installed_apk: installed_apk.clone(),
        };
        let intent_path = transaction::terminal_intent_path(root.path());
        fs::write(&intent_path, intent.bytes().unwrap()).unwrap();
        fs::set_permissions(&intent_path, fs::Permissions::from_mode(0o600)).unwrap();
        let pointer = OperationDescriptor {
            schema_version: 1,
            operation: Operation::Install,
            transaction_id: tx.clone(),
            journal: format!("recovery/{tx}/install-journal.json"),
            phase: "install-cleanup".to_string(),
            outcome: "running".to_string(),
            reboot_count: 2,
            boot_id: "00000000-0000-0000-0000-000000000003".to_string(),
            status_sequence: 35,
            journal_sha256: sha256(&journal_bytes),
            error: None,
            installed_apk: None,
        };
        write_atomic(
            &root.path().join("operation.json"),
            &pointer.canonical_bytes().unwrap(),
            0o600,
        )
        .unwrap();
        let completion_order = std::cell::RefCell::new(Vec::new());
        let prepare_failed = std::cell::Cell::new(false);
        recover_terminal_cleanup_with(
            root.path(),
            |_| Ok(()),
            || {
                // The staging takeover must precede the terminal publication:
                // a completed install cannot leave daemon-owned incoming.
                if operation_contract::read_current_in(root.path())
                    .unwrap()
                    .is_some_and(|current| current.outcome == "complete")
                {
                    prepare_failed.set(true);
                }
                completion_order.borrow_mut().push("prepare-incoming");
                Ok(())
            },
            || Ok("00000000-0000-0000-0000-000000000003".to_string()),
        )
        .unwrap();
        assert!(!prepare_failed.get());
        assert_eq!(*completion_order.borrow(), ["prepare-incoming"]);
        let terminal = operation_contract::read_current_in(root.path())
            .unwrap()
            .expect("terminal install operation");
        assert_eq!(terminal.phase, "install-complete");
        assert_eq!(terminal.outcome, "complete");
        assert_eq!(terminal.installed_apk, Some(installed_apk));
        assert!(!staging.exists());
        assert!(!recovery.exists());
        assert!(!intent_path.exists());
    }
}

#[cfg(test)]
mod i18n_invocation_tests {
    use super::*;
    #[test]
    fn typed_cleanup_has_no_arbitrary_arguments() {
        assert_eq!(invocation(&[]).unwrap(), Invocation::Install);
        assert_eq!(
            invocation(&["--i18n-early-cleanup".into()]).unwrap(),
            Invocation::I18nEarlyCleanup
        );
        assert!(invocation(&["--i18n-early-cleanup".into(), "/system/anything".into()]).is_err());
        assert_eq!(
            invocation(&["--i18n-none-finalize".into()]).unwrap(),
            Invocation::I18nNoneFinalize
        );
        assert!(
            invocation(&["--i18n-none-finalize".into(), "/data/untrusted.dex".into()]).is_err()
        );
        assert!(invocation(&["--shell".into()]).is_err());
    }
    #[test]
    fn cleanup_requires_exact_root_installer_domain() {
        assert!(cleanup_domain_allowed(0, 1, b"u:r:voboost_install:s0"));
        assert!(cleanup_domain_allowed(0, 1, b"u:r:voboost_install:s0\0"));
        assert!(!cleanup_domain_allowed(2000, 1, b"u:r:voboost_install:s0"));
        assert!(!cleanup_domain_allowed(0, 1, b"u:r:shell:s0"));
        assert!(!cleanup_domain_allowed(0, 42, b"u:r:voboost_install:s0"));
        assert!(!cleanup_domain_allowed(0, 1, b"u:r:voboost_install:s0:c1"));
    }
}
