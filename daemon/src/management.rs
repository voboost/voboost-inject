//! Fixed installed-product management endpoints used by the offline desktop
//! installer. These commands execute before the resident-daemon singleton
//! lock: read-only inspection may coexist with the injection host.

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    config, generation, installed_product, native_binary, operation_contract, plan, uninstall,
};

const STABLE_INJECT: &str = "/data/voboost/voboost-inject";
// Resident status includes bounded per-target accepted endpoint attestations.
const MAX_STATUS_BYTES: usize = crate::status::STATUS_LIMIT;
const MAX_DIAGNOSTIC_CHARS: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Health {
    Healthy,
    Degraded,
    Unknown,
    Unrecoverable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum InjectStatus {
    Running,
    Stopped,
    Unavailable,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum RecoveryStatus {
    Managed,
    Recoverable,
    Unrecoverable,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct LastOperation {
    operation: String,
    outcome: String,
    phase: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct InstalledProbe {
    schema_version: u8,
    installed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    installed_version: Option<String>,
    health: Health,
    startup_mode: plan::Startup,
    daemon_status: InjectStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    active_generation: Option<String>,
    /// Content identity of the installed product: the SHA-256 of the exact
    /// verified active manifest bytes. Absent when the signed manifest could
    /// not be loaded and digested; version equality never implies equality
    /// of this value.
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_operation: Option<LastOperation>,
    recovery_status: RecoveryStatus,
    startup_control_available: bool,
    logs_available: bool,
    upgrade_compatible: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostic: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApplyOfflineReceipt {
    schema_version: u8,
    operation: &'static str,
    admission: String,
}

fn admission_name(admission: crate::product_candidate::Admission) -> &'static str {
    use crate::product_candidate::Admission;
    match admission {
        Admission::Pending => "pending",
        Admission::Accepted => "accepted",
        Admission::InstallApk => "install-apk",
        Admission::RebootRequired => "reboot-required",
        Admission::MetadataOnlyUnavailable => "metadata-only-unavailable",
        Admission::TransactionCollision => "transaction-collision",
        Admission::UnsupportedActivationClass => "unsupported-activation-class",
        Admission::ActivationFailed => "activation-failed",
        Admission::ApkIdentityInvalid => "apk-identity-invalid",
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StatusNativeFailure {
    result: String,
    stage: String,
    restore_part: String,
    operation: String,
    reason: String,
    pstate_expected: Option<u64>,
    pstate_observed: Option<u64>,
    pstate_xor: Option<u64>,
    first_mismatch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    initial_failure: Option<Box<StatusNativeFailure>>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StatusUnsafeNativeFailure {
    process: String,
    target_pid: i32,
    target_starttime: u64,
    generation_id: String,
    catalog_sha256: String,
    document_generation: i64,
    diagnostic: StatusNativeFailure,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StatusDocument {
    schema_version: u32,
    release_identity: String,
    manifest_sha256: String,
    generation_id: String,
    catalog_sha256: String,
    startup_mode: plan::Startup,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    publisher: Option<crate::status::PublisherIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_unsafe_native_failure: Option<StatusUnsafeNativeFailure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    persistent_vehicle_state: Option<crate::agent_state::PersistentVehicleState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    startup_milestones: Option<crate::startup::Milestones>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    process_trace: Option<crate::status::ProcessTrace>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cluster: Option<voboost_contract::cluster::ClusterSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cluster_unavailable: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    i18n_resource_readbacks: Option<crate::status::I18nReadbacks>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    i18n_current_readbacks: Option<crate::status::I18nReadbacks>,
    state: String,
    killed: bool,
    panic: bool,
    injections: Vec<StatusInjection>,
    /// Catalog executors of the active generation (id, processes, surfaces).
    #[serde(default)]
    executors: Vec<StatusExecutor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    log_context: Option<Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusExecutor {
    id: String,
    processes: Vec<String>,
    surfaces: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StatusInjection {
    id: String,
    process: String,
    state: String,
    reason: String,
    details: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    document_generation: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lifecycle_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    current_endpoint: Option<crate::status::EndpointBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ManagementCommand {
    InspectInstalled,
    PrepareOfflineStage(String),
    InspectUninstallAdmission,
    RequestDesktopUninstall,
    ApplyOfflineProduct {
        reapply: bool,
        expected_active_manifest_sha256: String,
        staged_transaction_id: String,
    },
}

pub(crate) fn handle_cli() -> Option<i32> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let management_option = arguments.first().is_some_and(|value| {
        matches!(
            value.as_str(),
            "--inspect-installed"
                | "--inspect-uninstall-admission"
                | "--request-desktop-uninstall"
                | "--apply-offline-product"
                | "--reapply-offline-product"
                | "--prepare-offline-stage"
        )
    });
    let Some(command) = parse_arguments(&arguments) else {
        if management_option {
            crate::log::err("management", "usage: voboost-inject --inspect-installed | \
                 --request-desktop-uninstall | \
                 --apply-offline-product <expected-active-manifest-sha256> <staged-transaction-id> | \
                 --reapply-offline-product <expected-active-manifest-sha256> <stage-hex64> | \
                 --prepare-offline-stage <stage-hex64>");
            return Some(2);
        }
        return None;
    };
    if let Err(error) = authorize_stable_cli() {
        crate::log::err(
            "management",
            &format!("installed management authority rejected: {error}"),
        );
        return Some(126);
    }
    Some(match command {
        ManagementCommand::PrepareOfflineStage(stage) => {
            match crate::product_candidate::prepare_offline_stage(&stage) {
                Ok(()) => write_json_line(
                    &serde_json::json!({"schemaVersion":1,"operation":"prepare-offline-stage","stageTransactionId":stage}),
                ),
                Err(error) => {
                    crate::log::err(
                        "management",
                        &format!("offline stage preparation rejected: {error}"),
                    );
                    5
                }
            }
        }

        ManagementCommand::InspectUninstallAdmission => match authorize_active_product_self()
            .and_then(|()| uninstall::inspect_desktop_result())
        {
            Ok(value) => write_json_line(&value),
            Err(error) => {
                crate::log::err(
                    "management",
                    &format!("uninstall admission result rejected: {error}"),
                );
                5
            }
        },
        ManagementCommand::InspectInstalled => match inspect_installed() {
            Ok(probe) => write_json_line(&probe),
            Err(error) => write_json_line(&unknown_probe(&error)),
        },
        ManagementCommand::ApplyOfflineProduct {
            reapply,
            expected_active_manifest_sha256,
            staged_transaction_id,
        } => {
            match (if reapply {
                crate::product_candidate::reapply_offline_product
            } else {
                crate::product_candidate::apply_offline_product
            })(&expected_active_manifest_sha256, &staged_transaction_id)
            {
                Ok(admission) => write_json_line(&ApplyOfflineReceipt {
                    schema_version: 1,
                    operation: if reapply {
                        "offline-reapply"
                    } else {
                        "offline-update"
                    },
                    admission: admission_name(admission).to_string(),
                }),
                Err(error) => {
                    crate::log::err(
                        "management",
                        &format!("offline product update rejected: {error}"),
                    );
                    5
                }
            }
        }
        // Publishing an untrusted empty request file must not require a
        // healthy installed product: an explicit uninstall has priority over
        // an install that never completed or corrupted itself. The stable
        // root-executed daemon identity checked above is the authority.
        ManagementCommand::RequestDesktopUninstall => {
            match uninstall::publish_desktop_request_with_authority() {
                Ok(publication) => {
                    write_desktop_uninstall_admission(publication, &mut std::io::stdout())
                }
                Err(error) => {
                    crate::log::err(
                        "management",
                        &format!("desktop uninstall request failed: {error}"),
                    );
                    5
                }
            }
        }
    })
}

fn parse_arguments(arguments: &[String]) -> Option<ManagementCommand> {
    match arguments {
        [option, stage] if option == "--prepare-offline-stage" => {
            Some(ManagementCommand::PrepareOfflineStage(stage.clone()))
        }

        [value] if value == "--inspect-uninstall-admission" => {
            Some(ManagementCommand::InspectUninstallAdmission)
        }
        [value] if value == "--inspect-installed" => Some(ManagementCommand::InspectInstalled),
        [value] if value == "--request-desktop-uninstall" => {
            Some(ManagementCommand::RequestDesktopUninstall)
        }
        [option, expected, staged]
            if matches!(
                option.as_str(),
                "--apply-offline-product" | "--reapply-offline-product"
            ) =>
        {
            Some(ManagementCommand::ApplyOfflineProduct {
                reapply: option == "--reapply-offline-product",
                expected_active_manifest_sha256: expected.clone(),
                staged_transaction_id: staged.clone(),
            })
        }
        _ => None,
    }
}

pub(crate) fn authorize_stable_cli() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 || unsafe { libc::getegid() } != 0 {
        return Err("root:root identity is required".into());
    }
    let current = std::env::current_exe().map_err(|error| error.to_string())?;
    if current != Path::new(STABLE_INJECT) {
        return Err("the exact installed stable executable is required".into());
    }
    native_binary::verify_current_role(
        crate::native_executable_signature::NativeExecutableRole::Inject,
    )?;
    Ok(())
}

pub(crate) fn authorize_active_product_self() -> Result<(), String> {
    let manifest = installed_product::load_manifest()?;
    let inject = manifest.artifact("voboost-inject")?;
    let expected_size = usize::try_from(inject.size)
        .map_err(|_| "installed inject size overflows this target".to_string())?;
    native_binary::verify_running(Path::new("/proc/self/exe"), expected_size, &inject.sha256)
}

/// Acquire the shared generation lock for the CLI observation commands.
/// The resident daemon's generation watcher holds this lock for short bounded
/// windows (rejection recovery, activation). Observation is read-only and must
/// survive that transient busy instead of reporting an unknown route; every
/// non-busy reason still surfaces immediately. Mutating commands keep the
/// fail-closed no-retry contract.
pub(crate) fn acquire_generation_guard_observing(
    root: &Path,
) -> Result<operation_contract::GenerationGuard, String> {
    let mut remaining = 20;
    loop {
        match operation_contract::GenerationGuard::acquire_in(root) {
            Ok(guard) => return Ok(guard),
            Err(error) if error == "operation busy" && remaining > 0 => {
                remaining -= 1;
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(error) => return Err(error),
        }
    }
}

fn inspect_installed() -> Result<InstalledProbe, String> {
    let root = Path::new(config::ROOT_ZONE);
    let guard = acquire_generation_guard_observing(root)?;
    let manifest = installed_product::load_manifest()?;
    let manifest_sha256 = manifest.digest()?;
    let generation = generation::GenerationStore::production()
        .active()
        .map_err(|error| error.to_string())?;
    let active_generation = Some(generation.id.clone());
    let current_plan = plan::read_and_validate(&generation);
    let startup = crate::startup_session::effective(current_plan.startup)?;
    let daemon_status = resident_inject_status()?;
    let last_operation = operation_contract::read_current_in(root)?.and_then(|value| {
        matches!(value.outcome.as_str(), "complete" | "failed").then(|| LastOperation {
            operation: value.operation.as_str().to_string(),
            outcome: value.outcome,
            phase: value.phase,
        })
    });

    let mut failures = Vec::new();
    if !current_plan.valid {
        failures.push("canonical agents.json is invalid".to_string());
    }
    if !startup_daemon_admissible(startup, daemon_status) {
        failures.push("resident daemon is not running from the installed executable".to_string());
    }
    if let Err(error) = installed_product::verify_candidate_closure_in(&manifest, true, root) {
        failures.push(format!("installed product closure: {error}"));
    }
    let recovery = match uninstall::verify_committed_installed_authority(&manifest) {
        Ok(()) => true,
        Err(error) => {
            failures.push(format!("installed recovery authority: {error}"));
            false
        }
    };
    if let Err(error) = verify_status(
        &manifest.release_identity,
        &manifest_sha256,
        &generation,
        startup,
    ) {
        failures.push(format!("resident status: {error}"));
    }
    guard.verify_owner()?;

    let health = if failures.is_empty() {
        Health::Healthy
    } else if recovery {
        Health::Degraded
    } else {
        Health::Unrecoverable
    };
    let startup_control_available = current_plan.valid
        && startup_daemon_admissible(startup, daemon_status)
        && health != Health::Unrecoverable;
    Ok(InstalledProbe {
        schema_version: 1,
        installed: true,
        installed_version: Some(manifest.release_identity),
        health,
        startup_mode: current_plan.startup,
        daemon_status,
        active_generation,
        manifest_sha256: Some(manifest_sha256),
        last_operation,
        recovery_status: if recovery {
            if health == Health::Healthy {
                RecoveryStatus::Managed
            } else {
                RecoveryStatus::Recoverable
            }
        } else {
            RecoveryStatus::Unrecoverable
        },
        startup_control_available,
        logs_available: true,
        // Compatibility is independent of agent readiness: explicit reinstall repairs degraded runs.
        upgrade_compatible: recovery && manifest.compatibility.supports_schema_one(),
        diagnostic: diagnostic(&failures),
    })
}

fn unknown_probe(error: &str) -> InstalledProbe {
    InstalledProbe {
        schema_version: 1,
        installed: true,
        installed_version: None,
        health: Health::Unknown,
        startup_mode: plan::Startup::None,
        daemon_status: InjectStatus::Unknown,
        active_generation: None,
        manifest_sha256: None,
        last_operation: None,
        recovery_status: RecoveryStatus::Unknown,
        startup_control_available: false,
        logs_available: true,
        upgrade_compatible: false,
        diagnostic: diagnostic(&[error.to_string()]),
    }
}

fn startup_daemon_admissible(startup: plan::Startup, daemon: InjectStatus) -> bool {
    daemon == InjectStatus::Running
        || (startup == plan::Startup::None && daemon == InjectStatus::Stopped)
}

#[cfg(test)]
#[test]
fn package_execution_stopped_none_preserves_installer_recovery_admission() {
    for startup in [
        plan::Startup::None,
        plan::Startup::Interface,
        plan::Startup::Hidden,
    ] {
        assert!(startup_daemon_admissible(startup, InjectStatus::Running));
        assert_eq!(
            startup_daemon_admissible(startup, InjectStatus::Stopped),
            startup == plan::Startup::None
        );
        assert!(!startup_daemon_admissible(
            startup,
            InjectStatus::Unavailable
        ));
    }
}

fn resident_inject_status() -> Result<InjectStatus, String> {
    let run = crate::secure_fs::Directory::open(Path::new(config::RUN_DIR))
        .map_err(|error| format!("open resident daemon run directory: {error}"))?;
    run.validate_owner_mode(0, 0, config::RUN_DIR_MODE)
        .map_err(|error| format!("validate resident daemon run directory: {error}"))?;
    let pid = run
        .read_trusted(config::PID_NAME, 64, 0o600)
        .map_err(|error| format!("read resident daemon pidfile: {error}"))?;
    let pid = std::str::from_utf8(&pid)
        .ok()
        .and_then(|value| value.strip_suffix('\n'))
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<i32>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| "resident daemon pidfile is invalid".to_string())?;
    if unsafe { libc::kill(pid, 0) } != 0 {
        let error = std::io::Error::last_os_error();
        // A bounded-su management channel gets EACCES from kill(2) even for a
        // live process (the kernel's task hook is denied regardless of the
        // injected allow: proved on the free-09-chinese 6.0.3 emulator).
        // EACCES therefore still implies existence; ESRCH means dead. Confirm
        // existence through the /proc/<pid> directory, whose getattr stays
        // permitted where the task hooks are not.
        if error.raw_os_error() != Some(libc::EACCES)
            || fs::metadata(format!("/proc/{pid}")).is_err()
        {
            return Ok(InjectStatus::Stopped);
        }
    }
    let stable = fs::symlink_metadata(STABLE_INJECT)
        .map_err(|error| format!("stat installed daemon: {error}"))?;
    let resident = fs::metadata(format!("/proc/{pid}/exe"));
    let resident_matches = match resident {
        Ok(resident) => (stable.dev(), stable.ino()) == (resident.dev(), resident.ino()),
        // The exe symlink readlink is denied under the same bounded-su
        // kernel; fall back to the kernel-recorded argv. The resident daemon
        // is exec'd by init from the exact stable path, so argv[0] identifies
        // the executable; the manifest/generation cross-checks in this probe
        // catch the stale-content case the inode comparison would.
        Err(_) => {
            let cmdline = fs::read(format!("/proc/{pid}/cmdline"))
                .map_err(|error| format!("read resident daemon cmdline: {error}"))?;
            cmdline
                .split(|byte| *byte == 0)
                .next()
                .map(|value| value == STABLE_INJECT.as_bytes())
                .unwrap_or(false)
        }
    };
    if !stable.file_type().is_file()
        || stable.nlink() != 1
        || stable.uid() != 0
        || stable.gid() != 0
        || stable.permissions().mode() & 0o7777 != 0o700
    {
        return Ok(InjectStatus::Unavailable);
    }
    Ok(if resident_matches {
        InjectStatus::Running
    } else {
        InjectStatus::Unavailable
    })
}

fn verify_status(
    release_identity: &str,
    manifest_sha256: &str,
    generation: &generation::VerifiedGeneration,
    startup: plan::Startup,
) -> Result<(), String> {
    confirm_status_with_execution(
        || crate::package_execution::verify_receipt(generation, startup),
        || {
            let root = crate::secure_fs::Directory::open(Path::new(config::ROOT_ZONE))
                .map_err(|error| error.to_string())?;
            let bytes = root
                .read_trusted("status.json", MAX_STATUS_BYTES, 0o644)
                .map_err(|error| error.to_string())?;
            verify_status_bytes(
                &bytes,
                release_identity,
                manifest_sha256,
                &generation.id,
                &generation.catalog_sha256,
                startup,
                true,
            )
        },
    )
}

fn confirm_status_with_execution(
    execution: impl FnOnce() -> Result<(), String>,
    status: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    execution()?;
    status()
}

#[cfg(test)]
#[test]
fn package_execution_denial_prevents_management_status_confirmation() {
    let status_probed = std::cell::Cell::new(false);
    let result = confirm_status_with_execution(
        || Err("APK admission pending".into()),
        || {
            status_probed.set(true);
            Ok(())
        },
    );
    assert!(result.is_err());
    assert!(!status_probed.get());
    confirm_status_with_execution(
        || Ok(()),
        || {
            status_probed.set(true);
            Ok(())
        },
    )
    .unwrap();
    assert!(status_probed.get());
}

// Never echo arbitrary status strings, identities, details or capability material.
fn public_status_label<'a>(value: &'a str, allowed: &[&str]) -> &'a str {
    if allowed.contains(&value) {
        value
    } else {
        "unrecognized"
    }
}

pub(crate) fn verify_status_bytes(
    bytes: &[u8],
    release_identity: &str,
    manifest_sha256: &str,
    generation_id: &str,
    catalog_sha256: &str,
    startup: plan::Startup,
    require_healthy_injections: bool,
) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > MAX_STATUS_BYTES {
        return Err("status.json byte envelope is invalid".into());
    }
    let status: StatusDocument =
        serde_json::from_slice(bytes).map_err(|_| "status.json schema is invalid".to_string())?;
    if status
        .process_trace
        .as_ref()
        .is_some_and(|trace| !trace.valid())
    {
        return Err("status.json process trace is invalid".into());
    }
    if status.i18n_resource_readbacks.as_ref().is_some_and(|v| {
        status.publisher.is_none()
            || !v.valid(generation_id, catalog_sha256, "forced-ru-resource-readback")
    }) {
        return Err("status.json i18n readbacks invalid".into());
    }
    if status.i18n_current_readbacks.as_ref().is_some_and(|v| {
        status.publisher.is_none()
            || (![
                "current-owner-resource-readback",
                "current-en-owner-resource-readback",
                "current-zh-owner-resource-readback",
            ]
            .contains(&v.kind.as_str())
                || !v.valid(generation_id, catalog_sha256, &v.kind))
    }) {
        return Err("status.json current i18n readbacks invalid".into());
    }
    if (status.cluster.is_some() || status.cluster_unavailable.is_some())
        && status.publisher.is_none()
    {
        return Err("status.json Cluster publication lacks resident identity".into());
    }
    if status.cluster_unavailable.as_deref().is_some_and(|reason| {
        !matches!(
            reason,
            "snapshot-invalid" | "snapshot-unavailable" | "passive-budget-exceeded"
        )
    }) || (status.cluster.is_some() && status.cluster_unavailable.is_some())
    {
        return Err("status.json Cluster availability is invalid".into());
    }
    if status
        .cluster
        .as_ref()
        .is_some_and(|snapshot| snapshot.validate().is_err())
    {
        return Err("status.json Cluster snapshot is invalid".into());
    }
    let mut canonical = serde_json::to_vec(&status).map_err(|error| error.to_string())?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err("status.json is not canonical daemon output".into());
    }
    for (field, matches) in [
        ("schemaVersion", status.schema_version == 1),
        (
            "releaseIdentity",
            status.release_identity == release_identity,
        ),
        ("manifestSha256", status.manifest_sha256 == manifest_sha256),
        ("generationId", status.generation_id == generation_id),
        ("catalogSha256", status.catalog_sha256 == catalog_sha256),
        ("startupMode", status.startup_mode == startup),
    ] {
        if !matches {
            return Err(format!("status.json authority mismatch: {field}"));
        }
    }
    if status.state != "ready" {
        return Err(format!(
            "status.json daemon is not ready: state={}",
            public_status_label(
                &status.state,
                &["starting", "ready", "degraded", "failed", "stopped"]
            )
        ));
    }
    if status.killed != (startup == plan::Startup::None) {
        return Err(format!(
            "status.json kill switch mismatch: killed={}",
            status.killed
        ));
    }
    if status.panic {
        return Err("status.json daemon panic quarantine is active".into());
    }
    let mut identities = HashSet::new();
    for (index, injection) in status.injections.into_iter().enumerate() {
        let shape_valid = !injection.id.is_empty()
            && !injection.process.is_empty()
            && identities.insert((injection.id, injection.process))
            && injection
                .current_endpoint
                .as_ref()
                .is_none_or(|endpoint| endpoint.valid_for_document(injection.document_generation))
            && injection.details.is_object()
            && injection.reason.chars().count() <= 128
            && !injection.reason.chars().any(char::is_control)
            && matches!(
                injection.state.as_str(),
                "active" | "waiting" | "skipped-coexist" | "failed" | "degraded" | "quarantined"
            );
        let healthy = matches!(
            (injection.state.as_str(), injection.reason.as_str()),
            ("active", _)
                | ("waiting", "target-waiting")
                | ("skipped-coexist", "foreign-footprint")
        );
        if !shape_valid {
            return Err(format!("status.json injection[{index}] shape is invalid"));
        }
        // A committed none plan publishes retained target observations before
        // stopping. They describe prior activity, not required live injections.
        if require_healthy_injections && startup != plan::Startup::None && !healthy {
            return Err(format!(
                "status.json injection[{index}] is unhealthy: state={} reason={}",
                public_status_label(
                    &injection.state,
                    &[
                        "active",
                        "waiting",
                        "skipped-coexist",
                        "failed",
                        "degraded",
                        "quarantined"
                    ]
                ),
                public_status_label(
                    &injection.reason,
                    &[
                        "target-waiting",
                        "foreign-footprint",
                        "inject-failed",
                        "target-degraded",
                        "panic",
                        "agent-readiness-waiting",
                        "initial-sync",
                        "native-init-pending",
                        "native-init-retry-exhausted",
                        "injection-running",
                        "injection-worker-unavailable",
                        "target-died",
                        "target-gone",
                        "invalid-agent-status",
                        "hook-missing"
                    ]
                ),
            ));
        }
    }
    Ok(())
}

fn diagnostic(failures: &[String]) -> Option<String> {
    if failures.is_empty() {
        return None;
    }
    let mut value = failures.join("; ");
    value.retain(|character| !character.is_control());
    Some(value.chars().take(MAX_DIAGNOSTIC_CHARS).collect())
}

pub(crate) fn write_desktop_uninstall_admission(
    publication: uninstall::DesktopRequestPublication,
    writer: &mut impl std::io::Write,
) -> i32 {
    let result = (|| -> Result<(), String> {
        if let Some(authority) = publication.authority.as_ref() {
            serde_json::to_writer(&mut *writer, authority).map_err(|e| e.to_string())?;
            writer.write_all(b"\n").map_err(|e| e.to_string())?;
        }
        writer.flush().map_err(|e| e.to_string())?;
        Ok(())
    })();
    // Keep generation exclusion through BOTH output and flush. Dropping this
    // owner then lets the resident acquire its normal operation lease.
    drop(publication);
    match result {
        Ok(()) => 0,
        Err(e) => {
            crate::log::err(
                "management",
                &format!("desktop uninstall acknowledgement failed: {e}"),
            );
            5
        }
    }
}

fn write_json_line(value: &impl Serialize) -> i32 {
    match serde_json::to_string(value) {
        Ok(value) => {
            println!("{value}");
            0
        }
        Err(error) => {
            crate::log::err(
                "management",
                &format!("installed management output failed: {error}"),
            );
            5
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process_trace_fixture() -> crate::status::ProcessTrace {
        serde_json::from_value(serde_json::json!({
            "identityScope":"direct-child", "dropped":"0", "overwritten":"3", "omitted":0,
            "records":[{"operationId":"9007199254740993", "program":"/system/bin/pm",
                "operation":"path", "parentPid":42, "childPid":222,
                "monotonicNs":"18446744073709551615", "elapsedMs":"0", "outcome":{"exit":0}}]
        }))
        .unwrap()
    }

    #[test]
    fn i18n_readbacks_roundtrip_is_bounded_and_rejects_wrong_scope() {
        let mut document: StatusDocument =
            serde_json::from_slice(&status_fixture("active", "ready")).unwrap();
        document.publisher = Some(serde_json::from_value(serde_json::json!({"bootId":"18cce8ec-6c82-4b6c-b8bd-1b8794ad4174","daemonPid":"42","daemonStarttime":"162","publishedAtBootMs":"20000"})).unwrap());
        document.i18n_resource_readbacks = Some(serde_json::from_value(serde_json::json!({
            "schema":1,"kind":"forced-ru-resource-readback","owners":[{"owner":"com.qinggan.app.setting","profile":"setting-a9","probeRevision":"9","ageMs":1,"binding":{"targetPid":"42","targetStarttime":"162","endpointEpoch":"7","generationId":"11".repeat(32),"catalogSha256":"22".repeat(32),"desiredDocumentGeneration":"3"}}]
        })).unwrap());
        let verify = |document: &StatusDocument| {
            let mut bytes = serde_json::to_vec(document).unwrap();
            bytes.push(b'\n');
            verify_status_bytes(
                &bytes,
                "1.0.0-beta1",
                &"33".repeat(32),
                &"11".repeat(32),
                &"22".repeat(32),
                plan::Startup::Interface,
                true,
            )
        };
        assert!(verify(&document).is_ok());
        let mut current = document.i18n_resource_readbacks.clone().unwrap();
        current.kind = "current-owner-resource-readback".into();
        document.i18n_current_readbacks = Some(current);
        assert!(verify(&document).is_ok());
        document.i18n_current_readbacks.as_mut().unwrap().kind =
            "forced-ru-resource-readback".into();
        assert!(verify(&document).is_err());
        document.i18n_current_readbacks = None;
        document.i18n_resource_readbacks.as_mut().unwrap().owners[0].age_ms = 30001;
        assert!(verify(&document).is_err());
        document.i18n_resource_readbacks.as_mut().unwrap().owners[0].age_ms = 1;
        document.i18n_resource_readbacks.as_mut().unwrap().owners[0]
            .binding
            .endpoint_epoch = "0".into();
        assert!(verify(&document).is_err());
    }

    #[test]
    fn process_trace_strict_management_roundtrip_rejects_unknown_or_unbounded_records() {
        let mut document: StatusDocument =
            serde_json::from_slice(&status_fixture("active", "ready")).unwrap();
        document.process_trace = Some(process_trace_fixture());
        let encode = |document: &StatusDocument| {
            let mut bytes = serde_json::to_vec(document).unwrap();
            bytes.push(b'\n');
            bytes
        };
        let verify = |bytes: &[u8]| {
            verify_status_bytes(
                bytes,
                "1.0.0-beta1",
                &"33".repeat(32),
                &"11".repeat(32),
                &"22".repeat(32),
                plan::Startup::Interface,
                true,
            )
        };
        let bytes = encode(&document);
        verify(&bytes).unwrap();
        let decoded: StatusDocument = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(encode(&decoded), bytes);
        let mut trace = serde_json::to_value(process_trace_fixture()).unwrap();
        trace["records"][0]["argv"] = "must-not-pass".into();
        assert!(serde_json::from_value::<crate::status::ProcessTrace>(trace).is_err());
        let mut trace = serde_json::to_value(process_trace_fixture()).unwrap();
        trace["records"][0]["operation"] = "path.secret".into();
        document.process_trace = Some(serde_json::from_value(trace).unwrap());
        assert_eq!(
            verify(&encode(&document)).unwrap_err(),
            "status.json process trace is invalid"
        );
        let mut trace = serde_json::to_value(process_trace_fixture()).unwrap();
        trace["records"][0]["elapsedMs"] = "9".repeat(8193).into();
        document.process_trace = Some(serde_json::from_value(trace).unwrap());
        assert_eq!(
            verify(&encode(&document)).unwrap_err(),
            "status.json process trace is invalid"
        );
    }

    #[test]
    fn uninstall_admission_inspection_has_no_caller_selected_paths() {
        assert_eq!(
            parse_arguments(&["--inspect-uninstall-admission".into()]),
            Some(ManagementCommand::InspectUninstallAdmission)
        );
        assert!(parse_arguments(&[
            "--inspect-uninstall-admission".into(),
            "/data/foreign".into()
        ])
        .is_none());
    }

    #[test]
    fn resident_status_full_beta1_fixture_roundtrips_current_endpoint_contract() {
        let bytes = include_bytes!("../tests/fixtures/current-endpoint146-beta1-max-status.json");
        let value: Value = serde_json::from_slice(bytes).unwrap();
        let verify = |bytes: &[u8]| {
            verify_status_bytes(
                bytes,
                "1.0.0-beta1",
                value["manifestSha256"].as_str().unwrap(),
                value["generationId"].as_str().unwrap(),
                value["catalogSha256"].as_str().unwrap(),
                plan::Startup::Interface,
                true,
            )
        };
        verify(bytes).unwrap();
        assert_eq!(value["injections"].as_array().unwrap().len(), 52);
        assert!(bytes.len() > 64 * 1024 && bytes.len() < MAX_STATUS_BYTES);
        let document: StatusDocument = serde_json::from_slice(bytes).unwrap();
        let mut roundtrip = serde_json::to_vec(&document).unwrap();
        roundtrip.push(b'\n');
        assert_eq!(roundtrip, bytes);
        for mutation in 0..4 {
            let mut document: StatusDocument = serde_json::from_slice(bytes).unwrap();
            let endpoint = document.injections[0].current_endpoint.as_mut().unwrap();
            match mutation {
                0 => endpoint.target_pid = "02147".into(),
                1 => {
                    endpoint
                        .accepted_status
                        .as_mut()
                        .unwrap()
                        .document_generation = "1".into()
                }
                2 => {
                    endpoint.accepted_status.as_mut().unwrap().receipt.boot_id =
                        "not-a-boot-id".into()
                }
                _ => endpoint.desired_document_generation = "9223372036854775807".into(),
            }
            let mut invalid = serde_json::to_vec(&document).unwrap();
            invalid.push(b'\n');
            assert!(verify(&invalid).is_err());
        }
    }

    #[test]
    fn resident_status_one_mib_boundary_is_inclusive_and_truncation_fails_closed() {
        let mut document: StatusDocument =
            serde_json::from_slice(&status_fixture("active", "ready")).unwrap();
        document.process_trace = Some(process_trace_fixture());
        document.injections[0].details = serde_json::json!({"payload":""});
        let overhead = serde_json::to_vec(&document).unwrap().len() + 1;
        document.injections[0].details["payload"] =
            Value::String("x".repeat(MAX_STATUS_BYTES - overhead));
        let mut bytes = serde_json::to_vec(&document).unwrap();
        bytes.push(b'\n');
        assert_eq!(bytes.len(), MAX_STATUS_BYTES);
        let verify = |bytes: &[u8]| {
            verify_status_bytes(
                bytes,
                "1.0.0-beta1",
                &"33".repeat(32),
                &"11".repeat(32),
                &"22".repeat(32),
                plan::Startup::Interface,
                true,
            )
        };
        verify(&bytes).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let root = crate::secure_fs::Directory::open(directory.path()).unwrap();
        root.write_atomic("status.json", &bytes, 0o644).unwrap();
        assert_eq!(
            root.read_trusted("status.json", MAX_STATUS_BYTES, 0o644)
                .unwrap(),
            bytes
        );
        let mut oversized = bytes.clone();
        oversized.push(b' ');
        assert_eq!(
            verify(&oversized).unwrap_err(),
            "status.json byte envelope is invalid"
        );
        root.write_atomic("status.json", &oversized, 0o644).unwrap();
        assert!(root
            .read_trusted("status.json", MAX_STATUS_BYTES, 0o644)
            .is_err());
        assert!(verify(&bytes[..bytes.len() - 2]).is_err());
        assert!(verify(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn installed_probe_projection_remains_compact_with_large_resident_diagnostic() {
        let probe = unknown_probe(&"x".repeat(MAX_STATUS_BYTES));
        let bytes = serde_json::to_vec(&probe).unwrap();
        assert!(bytes.len() < 64 * 1024);
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(value.get("injections").is_none());
        assert!(value.get("currentEndpoint").is_none());
        assert!(value["diagnostic"].as_str().unwrap().chars().count() <= MAX_DIAGNOSTIC_CHARS);
    }

    #[test]
    fn command_parser_accepts_only_the_closed_installed_management_surface() {
        assert_eq!(
            parse_arguments(&["--inspect-installed".into()]),
            Some(ManagementCommand::InspectInstalled)
        );
        for name in ["interface", "hidden", "none"] {
            assert_eq!(
                parse_arguments(&["--request-startup-mode".into(), name.into()]),
                None
            );
        }
        assert_eq!(
            parse_arguments(&["--request-desktop-uninstall".into()]),
            Some(ManagementCommand::RequestDesktopUninstall)
        );
        assert_eq!(
            parse_arguments(&["--request-startup-mode".into(), "debug".into()]),
            None
        );
        assert_eq!(
            parse_arguments(&["--inspect-installed".into(), "extra".into()]),
            None
        );
        assert_eq!(
            parse_arguments(&[
                "--apply-offline-product".into(),
                "a".repeat(64),
                "staged-1".into(),
            ])
            .unwrap(),
            ManagementCommand::ApplyOfflineProduct {
                reapply: false,
                expected_active_manifest_sha256: "a".repeat(64),
                staged_transaction_id: "staged-1".to_string(),
            }
        );
        assert_eq!(
            parse_arguments(&["--apply-offline-product".into(), "a".repeat(64)]),
            None
        );
    }

    #[test]
    fn unknown_probe_never_invents_an_installed_release_or_mutation_authority() {
        let probe = unknown_probe("operation busy\nwith control");
        assert_eq!(probe.health, Health::Unknown);
        assert_eq!(probe.installed_version, None);
        assert!(!probe.startup_control_available);
        assert!(!probe.upgrade_compatible);
        assert!(probe.logs_available);
        assert!(!probe.diagnostic.unwrap().chars().any(char::is_control));
    }

    #[test]
    fn installed_probe_emitter_matches_the_product_wire_golden_bytes() {
        let healthy = InstalledProbe {
            schema_version: 1,
            installed: true,
            installed_version: Some("1.0.0-beta1".into()),
            health: Health::Healthy,
            startup_mode: plan::Startup::Interface,
            daemon_status: InjectStatus::Running,
            active_generation: Some("77".repeat(32)),
            manifest_sha256: Some("88".repeat(32)),
            last_operation: Some(LastOperation {
                operation: "install".into(),
                outcome: "complete".into(),
                phase: "install-complete".into(),
            }),
            recovery_status: RecoveryStatus::Managed,
            startup_control_available: true,
            logs_available: true,
            upgrade_compatible: true,
            diagnostic: None,
        };
        assert_eq!(
            [serde_json::to_vec(&healthy).unwrap(), b"\n".to_vec()].concat(),
            include_bytes!("../../test/fixtures/wire/installed-healthy.json")
        );

        let unknown = unknown_probe("signed manifest is unavailable");
        assert_eq!(
            [serde_json::to_vec(&unknown).unwrap(), b"\n".to_vec()].concat(),
            include_bytes!("../../test/fixtures/wire/installed-unknown-no-version.json")
        );
    }

    #[test]
    fn management_accepts_typed_cluster_publication_and_rejects_invalid_or_unbound_proof() {
        let mut document: StatusDocument = serde_json::from_slice(include_bytes!(
            "../../test/fixtures/wire/status-interface.json"
        ))
        .unwrap();
        document.publisher = Some(serde_json::from_value(serde_json::json!({"bootId":"18cce8ec-6c82-4b6c-b8bd-1b8794ad4174","daemonPid":"42","daemonStarttime":"162","publishedAtBootMs":"20000"})).unwrap());
        document.cluster = Some(crate::status::cluster_status_fixture(false));
        let verify = |document: &StatusDocument| {
            let mut bytes = serde_json::to_vec(document).unwrap();
            bytes.push(b'\n');
            verify_status_bytes(
                &bytes,
                "1.0.0-beta1",
                &"55".repeat(32),
                &"77".repeat(32),
                &"66".repeat(32),
                plan::Startup::Interface,
                true,
            )
        };
        assert!(verify(&document).is_ok());
        document.cluster.as_mut().unwrap().agents[1].targets.pop();
        let duplicate = document.cluster.as_ref().unwrap().agents[1].targets[0].clone();
        document.cluster.as_mut().unwrap().agents[1]
            .targets
            .push(duplicate);
        assert!(
            verify(&document).is_err(),
            "duplicate target proof must not become a valid status"
        );
        document.cluster = Some(crate::status::cluster_status_fixture(false));
        document.publisher = None;
        assert!(
            verify(&document).is_err(),
            "native proof requires original resident publication binding"
        );
    }

    #[test]
    fn management_consumes_the_product_status_golden_bytes() {
        assert!(verify_status_bytes(
            include_bytes!("../../test/fixtures/wire/status-interface.json"),
            "1.0.0-beta1",
            &"55".repeat(32),
            &"77".repeat(32),
            &"66".repeat(32),
            plan::Startup::Interface,
            true,
        )
        .is_ok());
        assert!(verify_status_bytes(
            include_bytes!("../../test/fixtures/wire/status-none.json"),
            "1.0.0-beta1",
            &"55".repeat(32),
            &"77".repeat(32),
            &"66".repeat(32),
            plan::Startup::None,
            true,
        )
        .is_ok());
    }

    #[test]
    fn persistent_projection_status_preserves_canonical_management_admission() {
        let root = tempfile::tempdir().unwrap();
        let mut status = crate::status::Status::default();
        status.release_identity = "1.0.0-beta1".into();
        status.manifest_sha256 = "33".repeat(32);
        status.generation_id = "11".repeat(32);
        status.catalog_sha256 = "22".repeat(32);
        status.startup_mode = plan::Startup::Interface;
        assert!(status.write_atomic_in(root.path(), "status.json".as_ref()));
        let bytes = fs::read(root.path().join("status.json")).unwrap();
        assert!(serde_json::from_slice::<Value>(&bytes)
            .unwrap()
            .get("persistentVehicleState")
            .is_some());
        verify_status_bytes(
            &bytes,
            "1.0.0-beta1",
            &"33".repeat(32),
            &"11".repeat(32),
            &"22".repeat(32),
            plan::Startup::Interface,
            true,
        )
        .unwrap();
    }

    #[test]
    #[ignore = "composed product gate requires the sibling Node consumer"]
    fn persistent_projection_real_io_to_production_consumer() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let consumer = std::env::var("VOBOOST_PROJECTION_CONSUMER_TEST").unwrap_or_else(|_| {
            format!(
                "{}/../../voboost/tools/emulator/persistent-vehicle-chain.ts",
                env!("CARGO_MANIFEST_DIR")
            )
        });
        for (seconds, nanos, uptime) in [(123, 456_999_999, "123.45"), (129, 260_000_000, "129.26")]
        {
            let root = tempfile::tempdir().unwrap();
            let state = root.path().join("state");
            fs::create_dir(&state).unwrap();
            fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
            for (leaf, value) in [
                (
                    "vehicle-drive-forced-ev_forced-ev-armed.json",
                    b"true\n".as_slice(),
                ),
                (
                    "vehicle-drive-pedestrian-warning_pedestrian-warning-armed.json",
                    b"false\n".as_slice(),
                ),
            ] {
                let path = state.join(leaf);
                fs::write(&path, value).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            let snapshot = crate::agent_state::persistent_vehicle_state_from(&state);
            let mut metadata = serde_json::to_value(snapshot).unwrap();
            // Supply the boot identity, but exercise the actual production clock
            // conversion with deterministic kernel timespec values. The diagnostic
            // uptime is the centisecond output of a subsequent kernel sample.
            metadata["bootId"] = Value::String("11111111-1111-1111-1111-111111111111".into());
            metadata["observedAtBootMs"] = Value::from(
                crate::agent_state::boot_elapsed_ms_with(|_, time| {
                    time.tv_sec = seconds;
                    time.tv_nsec = nanos;
                    0
                })
                .unwrap(),
            );
            let snapshot = serde_json::from_value(metadata).unwrap();
            let mut status = crate::status::Status::default();
            status.release_identity = "1.0.0-beta1".into();
            status.manifest_sha256 = "33".repeat(32);
            status.generation_id = "11".repeat(32);
            status.catalog_sha256 = "22".repeat(32);
            status.startup_mode = plan::Startup::Interface;
            assert!(status.write_atomic_snapshot_in(root.path(), snapshot));
            let root_dir = crate::secure_fs::Directory::open(root.path()).unwrap();
            let bytes = root_dir
                .read_trusted("status.json", MAX_STATUS_BYTES, 0o644)
                .unwrap();
            verify_status_bytes(
                &bytes,
                "1.0.0-beta1",
                &"33".repeat(32),
                &"11".repeat(32),
                &"22".repeat(32),
                plan::Startup::Interface,
                true,
            )
            .unwrap();
            if let Ok(path) = std::env::var("VOBOOST_PROJECTION_TEST_OUTPUT") {
                fs::write(path, &bytes).unwrap();
            }
            let mut child = Command::new("node")
                .arg(&consumer)
                .arg(uptime)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(&bytes).unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "consumer failed: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    fn status_fixture(state: &str, reason: &str) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(&StatusDocument {
            schema_version: 1,
            release_identity: "1.0.0-beta1".into(),
            manifest_sha256: "33".repeat(32),
            generation_id: "11".repeat(32),
            catalog_sha256: "22".repeat(32),
            startup_mode: plan::Startup::Interface,
            log_context: None,
            publisher: None,
            last_unsafe_native_failure: None,
            persistent_vehicle_state: None,
            startup_milestones: None,
            process_trace: None,
            cluster: None,
            cluster_unavailable: None,
            i18n_resource_readbacks: None,
            i18n_current_readbacks: None,
            state: "ready".into(),
            killed: false,
            panic: false,
            executors: Vec::new(),
            injections: vec![StatusInjection {
                id: "settings".into(),
                process: "com.qinggan.app.setting".into(),
                state: state.into(),
                reason: reason.into(),
                details: serde_json::json!({}),
                document_generation: None,
                lifecycle_generation: None,
                current_endpoint: None,
            }],
        })
        .unwrap();
        bytes.push(b'\n');
        bytes
    }

    #[test]
    fn installed_status_accepts_only_ready_correlated_healthy_injections() {
        for (state, reason) in [
            ("active", "started"),
            ("waiting", "target-waiting"),
            ("skipped-coexist", "foreign-footprint"),
        ] {
            assert!(verify_status_bytes(
                &status_fixture(state, reason),
                "1.0.0-beta1",
                &"33".repeat(32),
                &"11".repeat(32),
                &"22".repeat(32),
                plan::Startup::Interface,
                true,
            )
            .is_ok());
        }
        for (state, reason) in [
            ("failed", "inject-failed"),
            ("degraded", "target-degraded"),
            ("quarantined", "panic"),
            ("waiting", "unknown-wait"),
            ("skipped-coexist", "unverified"),
        ] {
            assert!(verify_status_bytes(
                &status_fixture(state, reason),
                "1.0.0-beta1",
                &"33".repeat(32),
                &"11".repeat(32),
                &"22".repeat(32),
                plan::Startup::Interface,
                true,
            )
            .is_err());
        }
        assert!(verify_status_bytes(
            &status_fixture("active", "started"),
            "1.0.0-beta1",
            &"33".repeat(32),
            &"33".repeat(32),
            &"22".repeat(32),
            plan::Startup::Interface,
            true,
        )
        .is_err());

        let mut none: StatusDocument =
            serde_json::from_slice(&status_fixture("active", "started")).unwrap();
        none.startup_mode = plan::Startup::None;
        none.killed = true;
        let mut none = serde_json::to_vec(&none).unwrap();
        none.push(b'\n');
        assert!(verify_status_bytes(
            &none,
            "1.0.0-beta1",
            &"33".repeat(32),
            &"11".repeat(32),
            &"22".repeat(32),
            plan::Startup::None,
            true,
        )
        .is_ok());

        assert!(verify_status_bytes(
            &status_fixture("failed", "inject-failed"),
            "1.0.0-beta1",
            &"33".repeat(32),
            &"11".repeat(32),
            &"22".repeat(32),
            plan::Startup::Interface,
            false,
        )
        .is_ok());
    }

    #[test]
    fn stopped_none_status_accepts_inactive_targets_without_weakening_running_modes() {
        for startup in [
            plan::Startup::None,
            plan::Startup::Interface,
            plan::Startup::Hidden,
        ] {
            for (state, reason) in [
                ("waiting", "initial-sync"),
                ("waiting", "agent-readiness-waiting"),
                ("waiting", "agent-disabled"),
                ("failed", "inject-failed"),
                ("degraded", "target-degraded"),
                ("quarantined", "panic"),
            ] {
                let mut document: StatusDocument =
                    serde_json::from_slice(&status_fixture(state, reason)).unwrap();
                document.startup_mode = startup;
                document.killed = startup == plan::Startup::None;
                let mut bytes = serde_json::to_vec(&document).unwrap();
                bytes.push(b'\n');
                let result = verify_status_bytes(
                    &bytes,
                    "1.0.0-beta1",
                    &"33".repeat(32),
                    &"11".repeat(32),
                    &"22".repeat(32),
                    startup,
                    true,
                );
                assert_eq!(
                    result.is_ok(),
                    startup == plan::Startup::None,
                    "{startup:?}/{reason}: {result:?}"
                );
            }
        }
    }

    #[test]
    fn stopped_none_status_still_requires_trusted_valid_ready_document() {
        let mut document: serde_json::Value =
            serde_json::from_slice(&status_fixture("waiting", "initial-sync")).unwrap();
        document["startupMode"] = serde_json::json!("none");
        document["killed"] = serde_json::json!(true);
        for (field, value) in [
            ("schemaVersion", serde_json::json!(2)),
            ("releaseIdentity", serde_json::json!("wrong")),
            ("manifestSha256", serde_json::json!("wrong")),
            ("generationId", serde_json::json!("wrong")),
            ("catalogSha256", serde_json::json!("wrong")),
            ("startupMode", serde_json::json!("interface")),
            ("state", serde_json::json!("failed")),
            ("killed", serde_json::json!(false)),
            ("panic", serde_json::json!(true)),
            (
                "injections",
                serde_json::json!([{
                    "id":"settings", "process":"com.qinggan.app.setting",
                    "state":"invalid", "reason":"initial-sync", "details":{}
                }]),
            ),
        ] {
            let mut mutated = document.clone();
            mutated[field] = value;
            let mutated: StatusDocument = serde_json::from_value(mutated).unwrap();
            let mut bytes = serde_json::to_vec(&mutated).unwrap();
            bytes.push(b'\n');
            assert!(
                verify_status_bytes(
                    &bytes,
                    "1.0.0-beta1",
                    &"33".repeat(32),
                    &"11".repeat(32),
                    &"22".repeat(32),
                    plan::Startup::None,
                    true,
                )
                .is_err(),
                "{field}"
            );
        }
        let document: StatusDocument = serde_json::from_value(document).unwrap();
        let bytes = serde_json::to_vec_pretty(&document).unwrap();
        assert!(verify_status_bytes(
            &bytes,
            "1.0.0-beta1",
            &"33".repeat(32),
            &"11".repeat(32),
            &"22".repeat(32),
            plan::Startup::None,
            true,
        )
        .is_err());
    }

    #[test]
    fn status_diagnostics_identify_exact_authority_fields_without_values() {
        for (field, value) in [
            ("schemaVersion", serde_json::json!(2)),
            ("releaseIdentity", serde_json::json!("secret-authority")),
            ("manifestSha256", serde_json::json!("secret-authority")),
            ("generationId", serde_json::json!("secret-authority")),
            ("catalogSha256", serde_json::json!("secret-authority")),
            ("startupMode", serde_json::json!("hidden")),
        ] {
            let mut document: StatusDocument =
                serde_json::from_slice(&status_fixture("active", "started")).unwrap();
            let mut value_document = serde_json::to_value(&document).unwrap();
            value_document[field] = value;
            document = serde_json::from_value(value_document).unwrap();
            let mut bytes = serde_json::to_vec(&document).unwrap();
            bytes.push(b'\n');
            assert_eq!(
                verify_status_bytes(
                    &bytes,
                    "1.0.0-beta1",
                    &"33".repeat(32),
                    &"11".repeat(32),
                    &"22".repeat(32),
                    plan::Startup::Interface,
                    true
                )
                .unwrap_err(),
                format!("status.json authority mismatch: {field}")
            );
        }
    }

    #[test]
    fn status_diagnostics_separate_daemon_state_kill_switch_and_panic() {
        for (field, value, expected) in [
            (
                "state",
                serde_json::json!("starting"),
                "status.json daemon is not ready: state=starting",
            ),
            (
                "state",
                serde_json::json!("secret-state"),
                "status.json daemon is not ready: state=unrecognized",
            ),
            (
                "killed",
                serde_json::json!(true),
                "status.json kill switch mismatch: killed=true",
            ),
            (
                "panic",
                serde_json::json!(true),
                "status.json daemon panic quarantine is active",
            ),
        ] {
            let mut document: StatusDocument =
                serde_json::from_slice(&status_fixture("active", "started")).unwrap();
            let mut value_document = serde_json::to_value(&document).unwrap();
            value_document[field] = value;
            document = serde_json::from_value(value_document).unwrap();
            let mut bytes = serde_json::to_vec(&document).unwrap();
            bytes.push(b'\n');
            assert_eq!(
                verify_status_bytes(
                    &bytes,
                    "1.0.0-beta1",
                    &"33".repeat(32),
                    &"11".repeat(32),
                    &"22".repeat(32),
                    plan::Startup::Interface,
                    true
                )
                .unwrap_err(),
                expected
            );
        }
    }

    #[test]
    fn initial_sync_remains_unhealthy_with_precise_diagnostic() {
        let error = verify_status_bytes(
            &status_fixture("waiting", "initial-sync"),
            "1.0.0-beta1",
            &"33".repeat(32),
            &"11".repeat(32),
            &"22".repeat(32),
            plan::Startup::Interface,
            true,
        )
        .unwrap_err();
        assert_eq!(
            error,
            "status.json injection[0] is unhealthy: state=waiting reason=initial-sync"
        );
    }

    #[test]
    fn status_diagnostics_redact_unrecognized_injection_reason() {
        let error = verify_status_bytes(
            &status_fixture("failed", "capability-secret"),
            "1.0.0-beta1",
            &"33".repeat(32),
            &"11".repeat(32),
            &"22".repeat(32),
            plan::Startup::Interface,
            true,
        )
        .unwrap_err();
        assert_eq!(
            error,
            "status.json injection[0] is unhealthy: state=failed reason=unrecognized"
        );
        let error = verify_status_bytes(
            &status_fixture("waiting", "agent-readiness-waiting"),
            "1.0.0-beta1",
            &"33".repeat(32),
            &"11".repeat(32),
            &"22".repeat(32),
            plan::Startup::Interface,
            true,
        )
        .unwrap_err();
        assert_eq!(
            error,
            "status.json injection[0] is unhealthy: state=waiting reason=agent-readiness-waiting"
        );
    }

    #[test]
    fn installed_management_dispatch_precedes_the_resident_singleton_lock() {
        let source = include_str!("main.rs");
        let management = source.find("management::handle_cli()").unwrap();
        let singleton = source
            .find("initialize_daemon_authorities(acquire_single_instance")
            .unwrap();
        assert!(management < singleton);
    }
}
