//! Init-owned continuation for the signed product protected-system WAL.
//!
//! The command line supplies no transaction, path, digest, or policy input.
//! Every authority is reconstructed from the one active product-update WAL.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use voboost_contract::operation::{read_active_in, Operation, OperationLease};
use voboost_contract::product_update::{
    system_rollback_context, ProductActivationClass, ProductUpdateJournal, ProductUpdatePhase,
};
use voboost_contract::runtime_owner::MAX_NATIVE_EXECUTABLE_BYTES;
use voboost_contract::system_update::{
    PolicyPrepareAck, SystemFailureAck, SystemPostBootAck, SystemRollbackAck, SystemSwitchAck,
    MAX_SYSTEM_ACK_BYTES, POLICY_PREPARE_ACK, SYSTEM_FAILURE_ACK, SYSTEM_POST_BOOT_ACK,
    SYSTEM_ROLLBACK_ACK, SYSTEM_SWITCH_ACK,
};

use super::mount_policy_transaction;
use super::protected_system_transaction::{FileIdentity, PreviousIdentity, Publication};
use super::secure_fs::Directory;

const ROOT: &str = "/data/voboost";
const JOURNAL: &str = "product-proposal.json";
const PREVIOUS: &str = "product-previous";
const INIT: &str = "/system/etc/init/voboost.rc";
const POLICY: &str = "/vendor/etc/selinux/precompiled_sepolicy";
const SELINUX: &str = "/data/voboost/voboost-selinux";
const ROOT_INIT: &str = "/data/voboost/voboost.rc";
const ROOT_INIT_MODE: u32 = 0o644;
const ENFORCE: &str = "/sys/fs/selinux/enforce";
const MAX_DOCUMENT: usize = 1024 * 1024;
const MAX_POLICY: usize = 64 * 1024 * 1024;

struct Authority {
    tx: String,
    recovery: PathBuf,
    previous: PathBuf,
    journal: ProductUpdateJournal,
}

impl Authority {
    fn load() -> Result<(Self, OperationLease), String> {
        let descriptor = read_active_in(Path::new(ROOT))?
            .ok_or("product system helper lacks an active operation")?;
        if descriptor.operation != Operation::Update
            || descriptor.journal
                != format!(
                    "recovery/{}/product-proposal.json",
                    descriptor.transaction_id
                )
            || !descriptor.phase.starts_with("update-product-system-")
        {
            return Err("product system helper operation authority is invalid".into());
        }
        let recovery = Path::new(ROOT)
            .join("recovery")
            .join(&descriptor.transaction_id);
        let recovery_dir = Directory::open(&recovery).map_err(|error| error.to_string())?;
        let bytes = recovery_dir
            .read_trusted(JOURNAL, 1024 * 1024, 0o600)
            .map_err(|error| error.to_string())?;
        let journal = ProductUpdateJournal::parse(&bytes)?;
        if journal.candidate.transaction_id != descriptor.transaction_id
            || !journal.system_plan
            || descriptor.journal_sha256 != sha256(&bytes)
        {
            return Err("product system helper WAL differs from operation authority".into());
        }
        let lease =
            OperationLease::acquire_in_checked(Path::new(ROOT), descriptor.clone(), || {
                crate::reject_cluster_uninstall(Path::new(ROOT))
            })?;
        lease.verify_owner()?;
        if lease.read_live_projection()?.as_ref() != Some(&descriptor) {
            return Err("product system helper authority changed before lease".into());
        }
        Ok((
            Self {
                tx: journal.candidate.transaction_id.clone(),
                previous: recovery.join(PREVIOUS),
                recovery,
                journal,
            },
            lease,
        ))
    }

    fn path(&self, leaf: &str) -> PathBuf {
        self.recovery.join(leaf)
    }

    fn previous_path(&self, leaf: &str) -> PathBuf {
        self.previous.join(leaf)
    }
}

pub fn run() -> Result<(), String> {
    let (authority, lease) = Authority::load()?;
    let phase = authority.journal.phase;
    if phase == ProductUpdatePhase::SystemPostReboot {
        let recovery = Directory::open(&authority.recovery).map_err(|error| error.to_string())?;
        match recovery.read_trusted(SYSTEM_FAILURE_ACK, MAX_SYSTEM_ACK_BYTES, 0o600) {
            Ok(bytes) => {
                let failure = SystemFailureAck::parse(&bytes)?;
                return restore_executables(&authority, &lease, &failure);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    let result = match phase {
        ProductUpdatePhase::SystemPrepared => prepare_policy(&authority, &lease),
        ProductUpdatePhase::SystemHelperRequested => switch_system(&authority, &lease),
        ProductUpdatePhase::SystemPostReboot => verify_post_boot(&authority, &lease),
        ProductUpdatePhase::SystemRollbackPostReboot => verify_rollback(&authority, &lease),
        _ => Err("product system helper was started in a non-helper phase".into()),
    };
    if let Err(error) = result {
        restore_previous_apk(&authority, &lease)?;
        let recover = match phase {
            ProductUpdatePhase::SystemPrepared => rollback_root_members(&authority),
            ProductUpdatePhase::SystemHelperRequested => rollback_system(&authority, false),
            ProductUpdatePhase::SystemPostReboot => rollback_system(&authority, true),
            _ => return Err(error),
        };
        if let Err(recovery_error) = recover {
            return Err(format!(
                "{error}; protected-system rollback failed: {recovery_error}"
            ));
        }
        publish_failure(&authority, phase)?;
        lease.verify_owner()?;
        return Err(error);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ApkRollbackState {
    Previous,
    Candidate,
}

fn rollback_apk_with(
    mut observe: impl FnMut() -> Result<ApkRollbackState, String>,
    install: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    if observe()? == ApkRollbackState::Previous {
        return Ok(());
    }
    let result = install();
    match observe() {
        Ok(ApkRollbackState::Previous) => Ok(()),
        Ok(ApkRollbackState::Candidate) => Err(format!(
            "previous APK is not installed: {}",
            result
                .err()
                .unwrap_or_else(|| "PackageManager returned without confirmed rollback".into())
        )),
        Err(error) => Err(format!("previous APK rollback readback failed: {error}")),
    }
}

fn rollback_manifest(directory: &Directory) -> Result<voboost_contract::release::Manifest, String> {
    let bytes = directory
        .read_trusted(
            "voboost.json",
            voboost_contract::release::MAX_MANIFEST_BYTES,
            0o600,
        )
        .map_err(|e| e.to_string())?;
    let signature = directory
        .read_trusted("voboost.json.sig", 64, 0o600)
        .map_err(|e| e.to_string())?;
    voboost_contract::release::verify_manifest_signature(
        &bytes,
        &signature,
        &super::RELEASE_CATALOG_PUBLIC_KEY,
    )
}

fn rollback_apk_observed(artifact: &voboost_contract::release::Artifact) -> Result<(), String> {
    super::read_installed_apk(artifact)?;
    let dump = super::fixed_process::output(
        "/system/bin/dumpsys",
        &["package", "ru.voboost"],
        Duration::from_secs(2),
        1024 * 1024,
    )?;
    if !dump.status.success()
        || !dump.stderr.is_empty()
        || Some(super::installed_apk::parse_package_version_code(
            &dump.stdout,
        )?) != artifact.version_code
    {
        return Err("PackageManager has not confirmed the rollback APK version".into());
    }
    super::read_installed_apk(artifact)?;
    Ok(())
}

fn restore_previous_apk(authority: &Authority, lease: &OperationLease) -> Result<(), String> {
    if !authority
        .journal
        .activation_classes
        .contains(&ProductActivationClass::PackageInstaller)
    {
        return Ok(());
    }
    let previous = Directory::open(&authority.previous).map_err(|e| e.to_string())?;
    let old = rollback_manifest(&previous)?;
    let complete = Directory::open(
        &Path::new(ROOT)
            .join("install")
            .join(&authority.tx)
            .join("complete-candidate"),
    )
    .map_err(|e| e.to_string())?;
    let candidate = rollback_manifest(&complete)?;
    if candidate.digest()? != authority.journal.candidate.manifest_sha256 {
        return Err("APK rollback candidate differs from the active WAL".into());
    }
    let old_apk = old.artifact("voboost-app.apk")?;
    let new_apk = candidate.artifact("voboost-app.apk")?;
    rollback_apk_with(
        || {
            lease.verify_owner()?;
            if rollback_apk_observed(old_apk).is_ok() {
                return Ok(ApkRollbackState::Previous);
            }
            if rollback_apk_observed(new_apk).is_ok() {
                return Ok(ApkRollbackState::Candidate);
            }
            Err("installed APK matches neither signed rollback authority".into())
        },
        || {
            lease.verify_owner()?;
            let mut input = previous
                .open_trusted_file("voboost-app.apk", old_apk.size, 0o600)
                .map_err(|e| e.to_string())?;
            let mut bytes = Vec::new();
            Read::by_ref(&mut input)
                .take(
                    old_apk
                        .size
                        .checked_add(1)
                        .ok_or("rollback APK size overflow")?,
                )
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            if bytes.len() as u64 != old_apk.size || sha256(&bytes) != old_apk.sha256 {
                return Err("preserved previous APK differs from its signed manifest".into());
            }
            input.rewind().map_err(|e| e.to_string())?;
            lease.verify_owner()?;
            let size = old_apk.size.to_string();
            let result = super::fixed_process::output_with_input(
                "/system/bin/pm",
                &["install", "-r", "-d", "-S", &size],
                Some(input),
                Duration::from_secs(120),
                4096,
            )?;
            if !result.status.success() {
                return Err(format!(
                    "PackageManager rejected previous APK: {}",
                    String::from_utf8_lossy(&result.stderr).trim()
                ));
            }
            Ok(())
        },
    )?;
    lease.verify_owner()
}

fn restore_executables(
    authority: &Authority,
    lease: &OperationLease,
    failure: &SystemFailureAck,
) -> Result<(), String> {
    let boot = current_boot_id()?;
    if failure.transaction_id != authority.tx
        || failure.phase != "system-post-reboot"
        || !failure.reboot_required
        || failure.boot_id != boot
        || authority.journal.post_reboot_boot_id.as_deref() != Some(boot.as_str())
    {
        return Err(
            "system executable rollback receipt differs from the active boot and WAL".into(),
        );
    }
    restore_previous_apk(authority, lease)?;
    // Both snapshots were prepared under this transaction from the signed product closure.
    let root = Directory::open(Path::new(ROOT)).map_err(|error| error.to_string())?;
    let previous = Directory::open(&authority.previous).map_err(|error| error.to_string())?;
    let candidate = root
        .open_child("install")
        .and_then(|install| install.open_child(&authority.tx))
        .and_then(|transaction| transaction.open_child("complete-candidate"))
        .map_err(|error| error.to_string())?;
    for artifact in &authority.journal.candidate.artifacts {
        let Some(context) = system_rollback_context(&artifact.file) else {
            continue;
        };
        lease.verify_owner()?;
        let old = previous
            .read_trusted(&artifact.file, MAX_NATIVE_EXECUTABLE_BYTES, 0o600)
            .map_err(|error| format!("read previous {}: {error}", artifact.file))?;
        let next = candidate
            .read_trusted(&artifact.file, MAX_NATIVE_EXECUTABLE_BYTES, 0o600)
            .map_err(|error| format!("read candidate {}: {error}", artifact.file))?;
        if next.len() as u64 != artifact.size {
            return Err(format!(
                "staged {} size differs from product WAL",
                artifact.file
            ));
        }
        restore_executable(&root, &artifact.file, context, &authority.tx, &old, &next)?;
    }
    lease.verify_owner()
}

fn restore_executable(
    root: &Directory,
    file: &str,
    context: &str,
    transaction: &str,
    old: &[u8],
    candidate: &[u8],
) -> Result<(), String> {
    let read = || {
        root.read_trusted_snapshot(file, MAX_NATIVE_EXECUTABLE_BYTES, 0o700, context)
            .map_err(|error| format!("read installed {file}: {error}"))
    };
    let current = read()?;
    if old.is_empty() || candidate.is_empty() {
        return Err(format!("rollback snapshot for {file} is empty"));
    }
    if current.bytes == old {
        return Ok(());
    }
    if current.bytes != candidate {
        return Err(format!(
            "installed {file} differs from the rollback transaction"
        ));
    }
    let temp = format!(".{file}.rollback-{transaction}.tmp");
    root.prepare_trusted_labeled(&temp, old, 0o700, context)
        .map_err(|error| format!("prepare rollback of {file}: {error}"))?;
    if read()? != current {
        return Err(format!(
            "installed {file} changed before rollback publication"
        ));
    }
    root.rename(&temp, file)
        .and_then(|()| root.sync_all())
        .map_err(|error| format!("publish rollback of {file}: {error}"))?;
    if read()?.bytes != old {
        return Err(format!(
            "installed {file} differs after rollback publication"
        ));
    }
    Ok(())
}

fn prepare_policy(authority: &Authority, lease: &OperationLease) -> Result<(), String> {
    lease.verify_owner()?;
    run_selinux("--install-product-candidate")?;
    lease.verify_owner()?;
    run_selinux("--prepare-product-policy")?;
    let ack = read_policy_ack(authority)?;
    if ack.transaction_id != authority.tx
        || Some(ack.boot_id.as_str()) != authority.journal.pre_reboot_boot_id.as_deref()
        || Some(ack.policy_baseline_sha256.as_str())
            != authority.journal.policy_baseline_sha256.as_deref()
    {
        return Err("policy prepare receipt differs from product WAL".into());
    }
    verify_file(
        &authority.previous_path("policy-candidate"),
        MAX_POLICY,
        0o600,
        &ack.policy_candidate_sha256,
    )?;
    lease.verify_owner()
}

fn switch_system(authority: &Authority, lease: &OperationLease) -> Result<(), String> {
    if authority.path(SYSTEM_SWITCH_ACK).exists() {
        verify_switch_ack(authority)?;
        return lease.verify_owner();
    }
    let boot = current_boot_id()?;
    if Some(boot.as_str()) != authority.journal.pre_reboot_boot_id.as_deref() {
        return Err("system switch crossed an unjournaled boot boundary".into());
    }
    let init_previous = read_exact(
        &authority.previous_path("system-init-previous"),
        MAX_DOCUMENT,
        0o600,
    )?;
    let init_candidate = read_exact(
        &authority.previous_path("system-init-candidate"),
        MAX_DOCUMENT,
        0o600,
    )?;
    let policy_previous = read_exact(
        &authority.previous_path("policy-previous"),
        MAX_POLICY,
        0o600,
    )?;
    let policy_candidate = read_exact(
        &authority.previous_path("policy-candidate"),
        MAX_POLICY,
        0o600,
    )?;
    bind_hashes(
        authority,
        &init_previous,
        &init_candidate,
        &policy_previous,
        &policy_candidate,
    )?;

    let init_wal = authority.path("system-init-remount.json");
    super::protected_system_transaction::recover_pending(
        Path::new(INIT),
        &init_wal,
        &authority.tx,
    )?;
    let publication = Publication {
        target: Path::new(INIT),
        remount_wal: &init_wal,
        transaction_id: &authority.tx,
        temporary_namespace: "product",
        candidate: &init_candidate,
        maximum_bytes: MAX_DOCUMENT as u64,
        identity: FileIdentity {
            uid: 0,
            gid: 0,
            mode: 0o644,
            selinux_context: Some("u:object_r:system_file:s0"),
        },
        previous: PreviousIdentity::Exact(&init_previous),
    };
    super::protected_system_transaction::publish(&publication)?;
    super::protected_system_transaction::verify(&publication)?;
    lease.verify_owner()?;

    let root_init = read_exact(Path::new(ROOT_INIT), MAX_DOCUMENT, ROOT_INIT_MODE)?;
    if sha256(&root_init) != sha256(&init_candidate) {
        super::publish_exact(
            Path::new(ROOT_INIT),
            &init_candidate,
            Path::new(ROOT_INIT),
            &authority.tx,
        )?;
    }
    let policy_wal = authority.path("system-policy-mount.json");
    if policy_wal.exists() {
        let _ = mount_policy_transaction::consume_startup(&policy_wal, &boot)?;
    }
    let watchdog = mount_policy_transaction::begin(
        "update",
        &authority.tx,
        &policy_wal,
        Path::new(POLICY),
        &authority.previous_path("policy-previous"),
        &boot,
    )?;
    mount_policy_transaction::publish_candidate(Path::new(POLICY), &policy_candidate, &policy_wal)?;
    mount_policy_transaction::transfer_to_reboot(&policy_wal, &boot)?;
    watchdog.disarm_for_reboot()?;
    lease.verify_owner()?;

    let ack = SystemSwitchAck {
        schema_version: 1,
        transaction_id: authority.tx.clone(),
        boot_id: boot,
        init_previous_sha256: sha256(&init_previous),
        init_candidate_sha256: sha256(&init_candidate),
        policy_previous_sha256: sha256(&policy_previous),
        policy_baseline_sha256: authority
            .journal
            .policy_baseline_sha256
            .clone()
            .ok_or("system WAL lacks policy baseline hash")?,
        policy_candidate_sha256: sha256(&policy_candidate),
    };
    write_receipt(&authority.path(SYSTEM_SWITCH_ACK), &ack.canonical_bytes()?)?;
    verify_switch_ack(authority)?;
    lease.verify_owner()
}

fn verify_post_boot(authority: &Authority, lease: &OperationLease) -> Result<(), String> {
    if authority.path(SYSTEM_POST_BOOT_ACK).exists() {
        let ack = read_post_ack(authority)?;
        verify_post_ack(authority, &ack)?;
        return lease.verify_owner();
    }
    let boot = current_boot_id()?;
    if Some(boot.as_str()) != authority.journal.post_reboot_boot_id.as_deref()
        || Some(boot.as_str()) == authority.journal.pre_reboot_boot_id.as_deref()
    {
        return Err("post-boot system helper boot ID is not correlated".into());
    }
    let policy_wal = authority.path("system-policy-mount.json");
    if mount_policy_transaction::consume_startup(&policy_wal, &boot)? {
        return Err("policy reboot transfer rolled back before boot confirmation".into());
    }
    let init_previous = read_exact(
        &authority.previous_path("system-init-previous"),
        MAX_DOCUMENT,
        0o600,
    )?;
    let init_candidate = read_exact(
        &authority.previous_path("system-init-candidate"),
        MAX_DOCUMENT,
        0o600,
    )?;
    let init_wal = authority.path("system-init-remount.json");
    let publication = Publication {
        target: Path::new(INIT),
        remount_wal: &init_wal,
        transaction_id: &authority.tx,
        temporary_namespace: "product",
        candidate: &init_candidate,
        maximum_bytes: MAX_DOCUMENT as u64,
        identity: FileIdentity {
            uid: 0,
            gid: 0,
            mode: 0o644,
            selinux_context: Some("u:object_r:system_file:s0"),
        },
        previous: PreviousIdentity::Exact(&init_previous),
    };
    super::protected_system_transaction::verify(&publication)?;
    let policy_hash = authority
        .journal
        .policy_candidate_sha256
        .as_deref()
        .ok_or("system WAL lacks candidate policy hash")?;
    verify_file(Path::new(POLICY), MAX_POLICY, 0o644, policy_hash)?;
    run_selinux("--check-product-policy")?;
    verify_enforcing()?;
    verify_daemon_domain()?;
    lease.verify_owner()?;
    let ack = SystemPostBootAck {
        schema_version: 1,
        transaction_id: authority.tx.clone(),
        boot_id: boot,
        init_candidate_sha256: sha256(&init_candidate),
        policy_candidate_sha256: policy_hash.to_string(),
        enforcing: true,
        daemon_domain: "u:r:voboost:s0".into(),
        loaded_policy_verified: true,
    };
    write_receipt(
        &authority.path(SYSTEM_POST_BOOT_ACK),
        &ack.canonical_bytes()?,
    )?;
    verify_post_ack(authority, &read_post_ack(authority)?)?;
    lease.verify_owner()
}

fn verify_rollback(authority: &Authority, lease: &OperationLease) -> Result<(), String> {
    let boot = current_boot_id()?;
    let rollback_boot = authority
        .journal
        .rollback_boot_id
        .as_deref()
        .ok_or("system rollback lacks its post-rollback boot ID")?;
    if boot != rollback_boot {
        return Err("protected-system rollback boot ID is not correlated".into());
    }
    let init_previous = read_exact(
        &authority.previous_path("system-init-previous"),
        MAX_DOCUMENT,
        0o600,
    )?;
    verify_file(
        Path::new(INIT),
        MAX_DOCUMENT,
        0o644,
        &sha256(&init_previous),
    )?;
    let policy_previous = read_exact(
        &authority.previous_path("policy-previous"),
        MAX_POLICY,
        0o600,
    )?;
    verify_file(
        Path::new(POLICY),
        MAX_POLICY,
        0o644,
        &sha256(&policy_previous),
    )?;
    verify_enforcing()?;
    verify_daemon_domain()?;
    lease.verify_owner()?;
    let ack = SystemRollbackAck {
        schema_version: 1,
        transaction_id: authority.tx.clone(),
        boot_id: boot,
        init_previous_sha256: sha256(&init_previous),
        policy_previous_sha256: sha256(&policy_previous),
        enforcing: true,
        daemon_domain: "u:r:voboost:s0".into(),
    };
    write_receipt(
        &authority.path(SYSTEM_ROLLBACK_ACK),
        &ack.canonical_bytes()?,
    )
}

fn publish_failure(authority: &Authority, phase: ProductUpdatePhase) -> Result<(), String> {
    let phase = match phase {
        ProductUpdatePhase::SystemPrepared => "system-prepared",
        ProductUpdatePhase::SystemHelperRequested => "system-helper-requested",
        ProductUpdatePhase::SystemPostReboot => "system-post-reboot",
        _ => return Err("system failure phase is invalid".into()),
    };
    let ack = SystemFailureAck {
        schema_version: 1,
        transaction_id: authority.tx.clone(),
        boot_id: current_boot_id()?,
        phase: phase.into(),
        reboot_required: phase == "system-post-reboot",
    };
    write_receipt(&authority.path(SYSTEM_FAILURE_ACK), &ack.canonical_bytes()?)
}

fn rollback_system(authority: &Authority, post_boot: bool) -> Result<(), String> {
    let init_previous = read_exact(
        &authority.previous_path("system-init-previous"),
        MAX_DOCUMENT,
        0o600,
    )?;
    let init_candidate = read_exact(
        &authority.previous_path("system-init-candidate"),
        MAX_DOCUMENT,
        0o600,
    )?;
    let init_wal = authority.path("system-init-remount.json");
    super::protected_system_transaction::recover_pending(
        Path::new(INIT),
        &init_wal,
        &authority.tx,
    )?;
    let rollback = Publication {
        target: Path::new(INIT),
        remount_wal: &init_wal,
        transaction_id: &authority.tx,
        temporary_namespace: "product-rollback",
        candidate: &init_previous,
        maximum_bytes: MAX_DOCUMENT as u64,
        identity: FileIdentity {
            uid: 0,
            gid: 0,
            mode: 0o644,
            selinux_context: Some("u:object_r:system_file:s0"),
        },
        previous: PreviousIdentity::Exact(&init_candidate),
    };
    super::protected_system_transaction::rollback(&rollback)?;

    let boot = current_boot_id()?;
    let policy_wal = authority.path("system-policy-mount.json");
    if policy_wal.exists() {
        let _ = mount_policy_transaction::consume_startup(&policy_wal, &boot)?;
    }
    let policy_previous = read_exact(
        &authority.previous_path("policy-previous"),
        MAX_POLICY,
        0o600,
    )?;
    if post_boot {
        let policy_candidate = read_exact(
            &authority.previous_path("policy-candidate"),
            MAX_POLICY,
            0o600,
        )?;
        verify_file(
            Path::new(POLICY),
            MAX_POLICY,
            0o644,
            &sha256(&policy_candidate),
        )?;
        let watchdog = mount_policy_transaction::begin(
            "update",
            &authority.tx,
            &policy_wal,
            Path::new(POLICY),
            &authority.previous_path("policy-candidate"),
            &boot,
        )?;
        mount_policy_transaction::publish_candidate(
            Path::new(POLICY),
            &policy_previous,
            &policy_wal,
        )?;
        mount_policy_transaction::transfer_to_reboot(&policy_wal, &boot)?;
        watchdog.disarm_for_reboot()?;
    } else {
        verify_file(
            Path::new(POLICY),
            MAX_POLICY,
            0o644,
            &sha256(&policy_previous),
        )?;
    }
    rollback_root_members(authority)
}

fn rollback_root_members(authority: &Authority) -> Result<(), String> {
    for (name, maximum, mode) in [
        ("voboost.rc", MAX_DOCUMENT, ROOT_INIT_MODE),
        ("voboost-selinux", MAX_POLICY, 0o700),
    ] {
        let previous = read_exact(&authority.previous_path(name), maximum, 0o600)?;
        let target = Path::new(ROOT).join(name);
        let current = read_exact(&target, maximum, mode)?;
        if current != previous {
            super::publish_exact(&target, &previous, &target, &authority.tx)?;
        }
    }
    Ok(())
}

fn run_selinux(argument: &str) -> Result<(), String> {
    let result = super::fixed_process::output(SELINUX, &[argument], Duration::from_secs(30), 4096)?;
    if result.status.success() {
        Ok(())
    } else {
        Err(format!(
            "fixed SELinux helper {argument} failed: {}; {}",
            result.status,
            super::bounded_restore_error(&String::from_utf8_lossy(&result.stderr))
        ))
    }
}

fn bind_hashes(
    authority: &Authority,
    init_previous: &[u8],
    init_candidate: &[u8],
    policy_previous: &[u8],
    policy_candidate: &[u8],
) -> Result<(), String> {
    let values = [
        (
            authority.journal.system_init_previous_sha256.as_deref(),
            sha256(init_previous),
        ),
        (
            authority.journal.system_init_candidate_sha256.as_deref(),
            sha256(init_candidate),
        ),
        (
            authority.journal.policy_previous_sha256.as_deref(),
            sha256(policy_previous),
        ),
        (
            authority.journal.policy_candidate_sha256.as_deref(),
            sha256(policy_candidate),
        ),
    ];
    if values
        .iter()
        .any(|(expected, actual)| *expected != Some(actual.as_str()))
    {
        Err("protected-system bytes differ from product WAL".into())
    } else {
        Ok(())
    }
}

fn read_policy_ack(authority: &Authority) -> Result<PolicyPrepareAck, String> {
    PolicyPrepareAck::parse(&read_exact(
        &authority.path(POLICY_PREPARE_ACK),
        4096,
        0o600,
    )?)
}

fn verify_switch_ack(authority: &Authority) -> Result<(), String> {
    let ack = SystemSwitchAck::parse(&read_exact(
        &authority.path(SYSTEM_SWITCH_ACK),
        4096,
        0o600,
    )?)?;
    let expected = [
        (
            Some(ack.transaction_id.as_str()),
            Some(authority.tx.as_str()),
        ),
        (
            Some(ack.boot_id.as_str()),
            authority.journal.pre_reboot_boot_id.as_deref(),
        ),
        (
            Some(ack.init_previous_sha256.as_str()),
            authority.journal.system_init_previous_sha256.as_deref(),
        ),
        (
            Some(ack.init_candidate_sha256.as_str()),
            authority.journal.system_init_candidate_sha256.as_deref(),
        ),
        (
            Some(ack.policy_previous_sha256.as_str()),
            authority.journal.policy_previous_sha256.as_deref(),
        ),
        (
            Some(ack.policy_baseline_sha256.as_str()),
            authority.journal.policy_baseline_sha256.as_deref(),
        ),
        (
            Some(ack.policy_candidate_sha256.as_str()),
            authority.journal.policy_candidate_sha256.as_deref(),
        ),
    ];
    if expected.iter().any(|(actual, wanted)| actual != wanted) {
        Err("system switch receipt differs from product WAL".into())
    } else {
        Ok(())
    }
}

fn read_post_ack(authority: &Authority) -> Result<SystemPostBootAck, String> {
    SystemPostBootAck::parse(&read_exact(
        &authority.path(SYSTEM_POST_BOOT_ACK),
        4096,
        0o600,
    )?)
}

fn verify_post_ack(authority: &Authority, ack: &SystemPostBootAck) -> Result<(), String> {
    if ack.transaction_id != authority.tx
        || Some(ack.boot_id.as_str()) != authority.journal.post_reboot_boot_id.as_deref()
        || Some(ack.init_candidate_sha256.as_str())
            != authority.journal.system_init_candidate_sha256.as_deref()
        || Some(ack.policy_candidate_sha256.as_str())
            != authority.journal.policy_candidate_sha256.as_deref()
    {
        Err("system post-boot receipt differs from product WAL".into())
    } else {
        Ok(())
    }
}

fn verify_enforcing() -> Result<(), String> {
    let bytes = read_attribute(Path::new(ENFORCE), 2, 0o644)?;
    (bytes == b"1\n" || bytes == b"1")
        .then_some(())
        .ok_or_else(|| "SELinux is not enforcing".into())
}

fn verify_daemon_domain() -> Result<(), String> {
    let pid = read_exact(
        &Path::new(ROOT)
            .join("run")
            .join(voboost_contract::runtime_owner::OWNER_PID_NAME),
        64,
        0o600,
    )?;
    let pid = std::str::from_utf8(&pid)
        .map_err(|_| "daemon pidfile is not UTF-8")?
        .strip_suffix('\n')
        .ok_or("daemon pidfile lacks newline")?;
    if pid.is_empty() || !pid.bytes().all(|byte| byte.is_ascii_digit()) || pid == "0" {
        return Err("daemon pidfile is invalid".into());
    }
    let context = read_attribute(
        &Path::new("/proc").join(pid).join("attr/current"),
        256,
        0o666,
    )?;
    (context == b"u:r:voboost:s0\0" || context == b"u:r:voboost:s0\n")
        .then_some(())
        .ok_or_else(|| "daemon is not running in voboost".into())
}

fn verify_file(path: &Path, maximum: usize, mode: u32, digest: &str) -> Result<(), String> {
    let bytes = read_exact(path, maximum, mode)?;
    (sha256(&bytes) == digest)
        .then_some(())
        .ok_or_else(|| format!("{} hash differs", path.display()))
}

fn read_exact(path: &Path, maximum: usize, mode: u32) -> Result<Vec<u8>, String> {
    read_verified(path, maximum, mode, true)
}

fn read_attribute(path: &Path, maximum: usize, mode: u32) -> Result<Vec<u8>, String> {
    // procfs and selinuxfs expose these attributes as streams with st_size=0.
    read_verified(path, maximum, mode, false)
}

fn read_verified(
    path: &Path,
    maximum: usize,
    mode: u32,
    exact_length: bool,
) -> Result<Vec<u8>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("open {}: {error}", path.display()))?;
    let before = file.metadata().map_err(|error| error.to_string())?;
    if !before.is_file()
        || before.nlink() != 1
        || before.permissions().mode() & 0o7777 != mode
        || (exact_length && before.len() == 0)
        || before.len() > maximum as u64
        || (cfg!(target_os = "android") && (before.uid() != 0 || before.gid() != 0))
    {
        return Err(format!("{} has a foreign identity", path.display()));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let after = file.metadata().map_err(|error| error.to_string())?;
    if bytes.is_empty()
        || bytes.len() > maximum
        || (exact_length && bytes.len() as u64 != before.len())
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
        return Err(format!("{} changed while reading", path.display()));
    }
    Ok(bytes)
}

fn write_receipt(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let temporary = path.with_file_name(format!(
        ".{}.tmp",
        path.file_name()
            .ok_or("receipt lacks leaf")?
            .to_string_lossy()
    ));
    if path.exists() {
        if read_exact(path, 4096, 0o600)? != bytes {
            return Err("foreign protected-system receipt".into());
        }
        if temporary.exists() {
            if read_exact(&temporary, 4096, 0o600)? != bytes {
                return Err("foreign protected-system receipt temporary".into());
            }
            fs::remove_file(&temporary).map_err(|error| error.to_string())?;
            File::open(path.parent().ok_or("receipt lacks parent")?)
                .and_then(|parent| parent.sync_all())
                .map_err(|error| error.to_string())?;
        }
        return Ok(());
    }
    if temporary.exists() {
        if read_exact(&temporary, 4096, 0o600)? != bytes {
            return Err("foreign protected-system receipt temporary".into());
        }
        fs::rename(&temporary, path).map_err(|error| error.to_string())?;
        return File::open(path.parent().ok_or("receipt lacks parent")?)
            .and_then(|parent| parent.sync_all())
            .map_err(|error| error.to_string());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())?;
    fs::rename(&temporary, path).map_err(|error| error.to_string())?;
    File::open(path.parent().ok_or("receipt lacks parent")?)
        .and_then(|parent| parent.sync_all())
        .map_err(|error| error.to_string())
}

fn current_boot_id() -> Result<String, String> {
    let path = Path::new("/proc/sys/kernel/random/boot_id");
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("open {}: {error}", path.display()))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.permissions().mode() & 0o7777 != 0o444
    {
        return Err("kernel boot ID has a foreign identity".into());
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::fd::AsRawFd;
        let mut status = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // The descriptor is open and statfs initializes the output on success.
        if unsafe { libc::fstatfs(file.as_raw_fd(), status.as_mut_ptr()) } != 0 {
            return Err(format!(
                "inspect boot ID filesystem: {}",
                std::io::Error::last_os_error()
            ));
        }
        let status = unsafe { status.assume_init() };
        if status.f_type as u64 != libc::PROC_SUPER_MAGIC as u64 {
            return Err("kernel boot ID is not on procfs".into());
        }
    }
    read_boot_id(&mut file)
}

fn read_boot_id(reader: &mut impl Read) -> Result<String, String> {
    // Procfs reports zero length; bound the stream instead of trusting st_size.
    let mut bytes = Vec::with_capacity(37);
    reader
        .take(38)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| "boot ID is not UTF-8")?
        .strip_suffix('\n')
        .ok_or("boot ID lacks newline")?;
    if value.len() != 36
        || !value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
            }
        })
    {
        return Err("boot ID is invalid".into());
    }
    Ok(value.into())
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    #[test]
    fn apk_rollback_is_idempotent_and_requires_independent_readback() {
        use super::{rollback_apk_with, ApkRollbackState::*};
        use std::cell::Cell;
        let calls = Cell::new(0);
        assert!(rollback_apk_with(
            || Ok(Previous),
            || {
                calls.set(calls.get() + 1);
                Ok(())
            }
        )
        .is_ok());
        assert_eq!(calls.get(), 0);
        let previous = Cell::new(false);
        assert!(rollback_apk_with(
            || Ok(if previous.get() { Previous } else { Candidate }),
            || {
                calls.set(calls.get() + 1);
                previous.set(true);
                Err("lost PackageManager reply".into())
            }
        )
        .is_ok());
        assert_eq!(calls.get(), 1);
        assert!(rollback_apk_with(
            || Ok(Previous),
            || {
                calls.set(calls.get() + 1);
                Ok(())
            }
        )
        .is_ok());
        assert_eq!(calls.get(), 1);
        assert!(rollback_apk_with(|| Ok(Candidate), || Err("downgrade rejected".into())).is_err());
        assert!(rollback_apk_with(|| Ok(Candidate), || Ok(())).is_err());
        assert!(rollback_apk_with(
            || Err("unknown APK".into()),
            || {
                calls.set(calls.get() + 1);
                Ok(())
            }
        )
        .is_err());
        assert_eq!(calls.get(), 1);
    }

    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn boot_id_stream_is_bounded_and_requires_exact_kernel_format() {
        let valid = b"01234567-89ab-cdef-0123-456789abcdef\n";
        assert_eq!(
            read_boot_id(&mut &valid[..]).unwrap(),
            "01234567-89ab-cdef-0123-456789abcdef"
        );
        for invalid in [
            &valid[..36],
            b"01234567-89AB-cdef-0123-456789abcdef\n",
            b"01234567-89ab-cdef-0123-456789abcdef\n\n",
            b"0123456789ab-cdef-0123-456789abcdef\n",
            b"",
        ] {
            assert!(read_boot_id(&mut &invalid[..]).is_err());
        }
        let mut oversized = std::io::Cursor::new(vec![b'a'; 4096]);
        assert!(read_boot_id(&mut oversized).is_err());
        assert_eq!(oversized.position(), 38);
    }

    #[test]
    fn product_file_reader_still_rejects_empty_regular_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("empty");
        fs::write(&path, []).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        assert!(read_exact(&path, 37, 0o444).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reads_real_zero_size_proc_boot_identity() {
        let path = Path::new("/proc/sys/kernel/random/boot_id");
        assert_eq!(fs::metadata(path).unwrap().len(), 0);
        assert!(read_exact(path, 37, 0o444).is_err());
        assert_eq!(
            current_boot_id().unwrap(),
            fs::read_to_string(path).unwrap().trim_end()
        );
    }

    #[test]
    fn fixed_init_helper_is_pathless_and_reuses_shared_transactions() {
        let init = include_str!("../../config/voboost.rc");
        assert!(init.contains(
            "service voboost-system-update /data/voboost/voboost-restore --product-system-update\n"
        ));
        assert_eq!(init.matches("service voboost-system-update ").count(), 1);
        assert!(!init.contains("service voboost-policy-prepare "));
        assert!(!init.contains("service voboost-policy-check "));
        assert!(super::mount_policy_transaction::valid_operation("update"));
        assert!(!super::mount_policy_transaction::valid_operation(
            "product-update"
        ));
        assert_eq!(INIT, "/system/etc/init/voboost.rc");
        assert_eq!(POLICY, "/vendor/etc/selinux/precompiled_sepolicy");
    }

    #[test]
    fn protected_executable_rollback_preserves_foreign_target_and_recovers_owned_cut() {
        let directory = tempfile::tempdir().unwrap();
        let root = Directory::open(directory.path()).unwrap();
        let file = "voboost-inject";
        let context = system_rollback_context(file).unwrap();
        let transaction = "a".repeat(64);
        let temporary = format!(".{file}.rollback-{transaction}.tmp");
        let old = vec![b'o'; MAX_DOCUMENT + 1];
        let candidate = b"new executable";

        root.write_atomic(file, b"foreign", 0o700).unwrap();
        assert!(restore_executable(&root, file, context, &transaction, &old, candidate).is_err());
        assert_eq!(root.read_trusted(file, 16, 0o700).unwrap(), b"foreign");

        root.write_atomic(file, candidate, 0o700).unwrap();
        std::os::unix::fs::symlink(file, directory.path().join(&temporary)).unwrap();
        assert!(restore_executable(&root, file, context, &transaction, &old, candidate).is_err());
        assert_eq!(root.read_trusted(file, 16, 0o700).unwrap(), candidate);
        root.unlink(&temporary).unwrap();
        root.prepare_trusted(&temporary, b"partial previous executable", 0o600)
            .unwrap();
        restore_executable(&root, file, context, &transaction, &old, candidate).unwrap();
        restore_executable(&root, file, context, &transaction, &old, candidate).unwrap();
        assert_eq!(root.read_trusted(file, old.len(), 0o700).unwrap(), old);
        assert!(!root.entry_exists(&temporary).unwrap());
    }

    #[test]
    fn root_init_readback_uses_the_installed_data_mode() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("voboost.rc");
        fs::write(&path, b"init hook\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            read_exact(&path, MAX_DOCUMENT, ROOT_INIT_MODE).unwrap(),
            b"init hook\n"
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(read_exact(&path, MAX_DOCUMENT, ROOT_INIT_MODE).is_err());
    }

    #[test]
    fn receipt_rename_cuts_adopt_only_exact_durable_bytes() {
        let temporary_root = tempfile::tempdir().unwrap();
        let receipt = temporary_root.path().join("system-switch-ack.json");
        let temporary = temporary_root.path().join(".system-switch-ack.json.tmp");
        let bytes = b"exact receipt\n";
        fs::write(&temporary, bytes).unwrap();
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
        write_receipt(&receipt, bytes).unwrap();
        assert_eq!(fs::read(&receipt).unwrap(), bytes);
        assert!(!temporary.exists());

        fs::write(&temporary, bytes).unwrap();
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
        write_receipt(&receipt, bytes).unwrap();
        assert!(!temporary.exists());

        fs::write(&temporary, b"foreign\n").unwrap();
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(write_receipt(&receipt, bytes).is_err());
        assert_eq!(fs::read(&receipt).unwrap(), bytes);
        assert_eq!(fs::read(&temporary).unwrap(), b"foreign\n");
    }
}
