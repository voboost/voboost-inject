#[cfg_attr(not(target_os = "android"), allow(dead_code))]
mod i18n_resources;
mod icon_quiescence;
pub mod launcher_config;
mod launcher_page;
mod loader_quarantine;
// Injection host entry point.
//
// Verifies agent artifacts and manages generations, target discovery, injection
// and bounded shutdown. The resident daemon owns state, configuration and file logs.

pub mod agent_events;
pub mod agent_log;
pub mod agent_state;
pub mod bootstrap_pipe;
mod bootstrap_worker;
pub mod canonical_log;
pub mod catalog;
pub mod cluster_control;
#[path = "../../uninstall/src/cluster_recovery.rs"]
mod cluster_recovery_snapshot;
pub mod config;
pub mod control_plane;
pub mod downlink;
mod emulator_diagnostic;
mod install_acceptance;
mod log_archive;
mod log_export;
mod native_commands;
mod owned_intent;
mod owner_client;
#[cfg(test)]
#[path = "owner/cluster.rs"]
mod owner_cluster;
#[path = "owner/io.rs"]
mod owner_io;
#[path = "owner/peer.rs"]
#[cfg(not(test))]
mod owner_peer;
pub use voboost_shared::fixed_process;
pub mod generation;
mod generation_layout;
mod injection_jobs;
pub mod injector;
mod installed_product;
mod lifecycle;
pub mod log;
mod management;
pub mod ota_transport;
mod package_execution;
mod transition_log;
pub use voboost_contract::generation as generation_contract;
pub use voboost_contract::operation as operation_contract;
pub use voboost_shared::installed_apk;
mod native_binary;
pub use voboost_shared::native_executable_signature;
#[cfg(test)]
pub mod oem_test_driver;
pub mod pidfile;
pub mod plan;
mod process_restart;
pub mod process_watcher;
mod product_candidate;
pub mod profile;
pub mod reconcile;
mod resident_recovery;
mod runtime;
mod runtime_loop;
pub mod safety;
pub use voboost_shared::secure_fs;
pub mod selection;
mod selinux_backend;
mod startup;
mod startup_preparation;
mod startup_session;
mod state;
pub mod status;
pub mod strict_json;
pub mod target_identity;
pub mod trust;
pub mod uninstall;
pub mod version;

use runtime::{generation_prune_is_safe, retained_process_index, DaemonLoop};

fn uninstall_preempts_new_work(request: bool, prepared: bool) -> bool {
    request || prepared
}

#[derive(Debug, Eq, PartialEq)]
enum PrepareUninstallOutcome {
    Committed,
    PendingOperation,
    PendingCluster,
    Rejected(String),
    RolledBack(String),
}

fn preparation_resolved(result: &Result<PrepareUninstallOutcome, String>) -> bool {
    matches!(
        result,
        Ok(PrepareUninstallOutcome::Committed
            | PrepareUninstallOutcome::RolledBack(_)
            | PrepareUninstallOutcome::Rejected(_))
    )
}

fn preparation_retry_delay(
    result: &Result<PrepareUninstallOutcome, String>,
    published: bool,
) -> Option<std::time::Duration> {
    match result {
        Ok(PrepareUninstallOutcome::PendingCluster) | Err(_) => {
            Some(std::time::Duration::from_secs(1))
        }
        Ok(PrepareUninstallOutcome::RolledBack(_) | PrepareUninstallOutcome::Rejected(_))
            if !published =>
        {
            Some(std::time::Duration::from_secs(1))
        }
        _ => None,
    }
}

fn preparation_error_outcome(error: String) -> PrepareUninstallOutcome {
    if error == uninstall::PREPARATION_OPERATION_BUSY {
        PrepareUninstallOutcome::PendingOperation
    } else if error == cluster_control::UNINSTALL_PENDING {
        PrepareUninstallOutcome::PendingCluster
    } else if let Some(reason) = error.strip_prefix(cluster_control::UNINSTALL_FAILED) {
        PrepareUninstallOutcome::Rejected(reason.into())
    } else {
        PrepareUninstallOutcome::RolledBack(error)
    }
}

#[cfg(test)]
mod pending_cluster_uninstall_tests {
    use super::*;

    #[test]
    fn terminal_cluster_failure_is_definitive_only_after_publication() {
        let outcome = preparation_error_outcome(format!(
            "{}local receipt unavailable",
            cluster_control::UNINSTALL_FAILED
        ));
        assert!(
            matches!(&outcome, PrepareUninstallOutcome::Rejected(reason) if reason == "local receipt unavailable")
        );
        let result = Ok(outcome);
        assert!(preparation_resolved(&result));
        assert!(preparation_retry_delay(&result, false).is_some());
        assert!(preparation_retry_delay(&result, true).is_none());
    }

    #[test]
    fn failed_publication_and_recovery_are_paced_without_consuming_request() {
        let rollback = Ok(PrepareUninstallOutcome::RolledBack("failure".into()));
        assert!(preparation_resolved(&rollback));
        assert!(preparation_retry_delay(&rollback, false).is_some());
        assert!(preparation_retry_delay(&rollback, true).is_none());
        let recovery_failure = Err("recovery failed".into());
        assert!(!preparation_resolved(&recovery_failure));
        assert!(preparation_retry_delay(&recovery_failure, false).is_some());
        assert!(preparation_retry_delay(&Ok(PrepareUninstallOutcome::Committed), true).is_none());
    }

    #[test]
    fn asynchronous_cluster_prepare_retains_request_until_completion() {
        let pending = preparation_error_outcome(cluster_control::UNINSTALL_PENDING.into());
        assert_eq!(pending, PrepareUninstallOutcome::PendingCluster);
        assert!(!preparation_resolved(&Ok(pending)));
        // A signed completion makes the next preparation commit eligible;
        // only that terminal result consumes the original Settings request.
        assert!(preparation_resolved(&Ok(
            PrepareUninstallOutcome::Committed
        )));
        assert!(matches!(
            preparation_error_outcome("invalid signature".into()),
            PrepareUninstallOutcome::RolledBack(_)
        ));
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UninstallPollDisposition {
    RetryCommitted,
    PrepareRequested,
    ContinueNormal,
}

fn uninstall_poll_disposition(
    in_memory_frozen: bool,
    prepared_marker: bool,
    request: bool,
) -> UninstallPollDisposition {
    if in_memory_frozen || prepared_marker {
        UninstallPollDisposition::RetryCommitted
    } else if request {
        UninstallPollDisposition::PrepareRequested
    } else {
        UninstallPollDisposition::ContinueNormal
    }
}

fn consume_completed_uninstall_request() {
    if let Err(error) = uninstall::consume_request() {
        log::err(
            "main",
            &format!("uninstall request consumption failed: {error}"),
        );
    }
}

fn initialize_daemon_authorities(
    acquire: impl FnOnce() -> Result<(), String>,
    initialize_log: impl FnOnce(),
) -> Result<(), String> {
    acquire()?;
    initialize_log();
    Ok(())
}

fn installer_owned_install_handoff_pending(
    operation: Option<&operation_contract::OperationDescriptor>,
) -> bool {
    operation.is_some_and(|operation| {
        let installer_owned_phase = matches!(
            (
                operation.phase.as_str(),
                operation.outcome.as_str(),
                operation.reboot_count
            ),
            ("install-reboot-first", "reboot-required", 1)
                | ("install-reboot-second", "reboot-required", 2)
                | ("install-runtime-verify", "running", 2)
                | ("install-inventory-commit", "running", 2)
                | ("install-cleanup", "running", 2)
        );
        operation.operation == operation_contract::Operation::Install
            && installer_owned_phase
            && operation.error.is_none()
            && operation.installed_apk.is_none()
    })
}

enum InstallerHandoffObservation {
    Running,
    Busy,
    Pending,
    Ready,
}

fn wait_for_installer_owned_handoff_with(
    mut pending: impl FnMut() -> Result<InstallerHandoffObservation, String>,
    mut request_installer: impl FnMut() -> Result<(), String>,
    mut wait: impl FnMut(std::time::Duration),
) -> Result<usize, String> {
    let mut observations = crate::transition_log::Transitions::default();
    let mut attempts = 0_usize;
    let mut starts = 0_usize;
    let mut elapsed = std::time::Duration::ZERO;
    let mut next_start = std::time::Duration::ZERO;
    let mut start_backoff = std::time::Duration::from_secs(1);
    let mut delay = std::time::Duration::from_millis(50);
    loop {
        match pending()? {
            InstallerHandoffObservation::Ready => {
                observations.resolved("installer-handoff");
                return Ok(attempts);
            }
            InstallerHandoffObservation::Pending if starts < 5 && elapsed >= next_start => {
                observations.resolved("installer-handoff");
                request_installer()?;
                starts += 1;
                next_start = elapsed.saturating_add(start_backoff);
                start_backoff = start_backoff.saturating_mul(2);
            }
            // Exhausting the request budget never makes the installation safe.
            // Continue observing until its durable descriptor completes or fails.
            InstallerHandoffObservation::Pending | InstallerHandoffObservation::Running => {
                observations.resolved("installer-handoff");
            }
            InstallerHandoffObservation::Busy => {
                observations.waiting("installer-handoff", "installer", "operation busy")
            }
        }
        wait(delay);
        elapsed = elapsed.saturating_add(delay);
        attempts += 1;
        delay = delay
            .saturating_mul(2)
            .min(std::time::Duration::from_secs(1));
    }
}

fn wait_for_installer_owned_handoff() -> Result<usize, String> {
    wait_for_installer_owned_handoff_with(
        || match operation_contract::observe_current_in(std::path::Path::new(config::ROOT_ZONE))? {
            operation_contract::CurrentOperationObservation::Busy => {
                Ok(InstallerHandoffObservation::Busy)
            }
            operation_contract::CurrentOperationObservation::Snapshot(snapshot) => Ok(
                if installer_owned_install_handoff_pending(snapshot.descriptor()) {
                    use profile::PropSource;
                    match profile::Getprop.prop("init.svc.voboost-install").as_deref() {
                        Some("running" | "restarting") => InstallerHandoffObservation::Running,
                        Some("stopped") => InstallerHandoffObservation::Pending,
                        // Missing or transient init state is not permission to start.
                        _ => InstallerHandoffObservation::Busy,
                    }
                } else {
                    InstallerHandoffObservation::Ready
                },
            ),
        },
        || fixed_process::set_property("ctl.start", "voboost-install"),
        std::thread::sleep,
    )
}

fn main() {
    if let Some(code) = handle_cluster_provision_cli() {
        std::process::exit(code);
    }
    if let Some(code) = launcher_page::handle_cli() {
        std::process::exit(code);
    }
    if let Some(code) = install_acceptance::handle_cli() {
        std::process::exit(code);
    }
    if let Some(code) = emulator_diagnostic::handle_cli() {
        std::process::exit(code);
    }
    if let Some(code) = management::handle_cli() {
        std::process::exit(code);
    }
    if let Some(code) = handle_reboot() {
        std::process::exit(code);
    }
    if let Some(code) = injector::handle_internal_helper_cli() {
        std::process::exit(code);
    }
    if std::env::args_os().len() != 1 {
        log::err("main", "unsupported injection-host command");
        std::process::exit(2);
    }
    #[cfg(not(test))]
    if let Err(error) = owner_client::wait_ready(std::time::Duration::from_secs(5)) {
        log::err("main", &format!("runtime owner is unavailable: {error}"));
        std::process::exit(1);
    }
    // The singleton authority owns creation of /data/voboost/run. Logger
    // initialization may publish a socket there only after the exact root:root
    // mode-0755 directory has been created and retained by the pidfile guard.
    if let Err(error) = initialize_daemon_authorities(acquire_single_instance, log::init) {
        crate::log::err(
            "main",
            &format!("voboost-inject: pidfile authority unavailable: {error}"),
        );
        std::process::exit(1);
    }
    if let Some(code) = handle_generation_cli() {
        std::process::exit(code);
    }
    log::info("main", "voboost-inject starting");

    // A durable prepared uninstall is the irreversible commit boundary. It
    // preempts product and generation recovery, so no queued activation can
    // run after that commit.
    if uninstall::prepared_marker_valid() {
        let generation_store = generation::GenerationStore::production();
        if let Err(error) = uninstall::consume_request() {
            log::err(
                "main",
                &format!("prepared uninstall request consumption failed: {error}"),
            );
        }
        if let Err(error) = uninstall::retry_committed_prepared(&generation_store) {
            log::err(
                "main",
                &format!("prepared uninstall freeze/trigger retry failed: {error}"),
            );
        }
        lifecycle::run_uninstall_frozen_loop();
        return;
    }

    // Product recovery runs before generation validation and any new
    // app-authored work. It is the only native/product update authority.
    let _ = std::fs::create_dir_all(config::ROOT_ZONE);
    let product_recovery =
        product_candidate::ProductCandidateStore::production().recover_product_activation();
    match lifecycle::startup_product_recovery_disposition(&product_recovery) {
        lifecycle::StartupProductRecoveryDisposition::Continue => {
            if matches!(
                product_recovery,
                Ok(Some(product_candidate::Admission::Accepted))
            ) {
                log::ok("main", "recovered product update activation");
            }
        }
        lifecycle::StartupProductRecoveryDisposition::RebootRequired => {
            log::ok("main", "product update requires an init-owned reboot");
            if lifecycle::request_reboot() {
                release_lock();
                std::process::exit(0);
            }
            write_degraded_status();
            lifecycle::run_product_recovery_degraded_loop();
            return;
        }
        lifecycle::StartupProductRecoveryDisposition::ProductDegraded => {
            let error = product_recovery
                .expect_err("product degraded startup disposition requires an error");
            log::err(
                "main",
                &format!("product update activation recovery failed: {error}"),
            );
            write_degraded_status();
            lifecycle::run_product_recovery_degraded_loop();
            return;
        }
    }
    let generation_store = generation::GenerationStore::production();
    match wait_for_installer_owned_handoff() {
        Ok(0) => {}
        Ok(attempts) => log::ok(
            "main",
            &format!("installer-owned handoff completed after {attempts} retries"),
        ),
        Err(error) => {
            log::err(
                "main",
                &format!("install generation handoff failed: {error}"),
            );
            write_degraded_status();
            lifecycle::run_degraded_loop();
            return;
        }
    }
    if !generation_store.activation_kill_switch_active() {
        match generation_store.recover_activation() {
            Ok(Some(recovered)) => log::ok(
                "main",
                &format!(
                    "recovered and verified generation activation: {}",
                    recovered.id
                ),
            ),
            Ok(None) => {}
            Err(error) => {
                log::err(
                    "main",
                    &format!("generation activation recovery failed: {error:#}"),
                );
                write_degraded_status();
                lifecycle::run_degraded_loop();
                return;
            }
        }
    }
    let uninstall_requested = uninstall::request_present();
    if !uninstall_preempts_new_work(uninstall_requested, false) {
        // Read the installed vehicle profile only when normal activation work is
        // allowed. Activation recomputes applicability from root-owned facts.
        if let Err(error) = profile::ensure_vehicle_profile(std::path::Path::new(config::ROOT_ZONE))
        {
            log::err(
                "main",
                &format!("vehicle profile resolution failed: {error}"),
            );
        }
        activate_incoming_if_ready(&generation_store);
    }

    let generation = match generation_store.active() {
        Ok(generation) => generation,
        Err(error) => {
            log::err(
                "main",
                &format!("DEGRADED: active generation invalid: {error}"),
            );
            write_degraded_status();
            lifecycle::run_degraded_loop();
            return;
        }
    };
    let product_identity = match installed_product::load_identity() {
        Ok(identity) => identity,
        Err(error) => {
            log::err(
                "main",
                &format!("DEGRADED: active product identity invalid: {error}"),
            );
            write_degraded_status();
            lifecycle::run_degraded_loop();
            return;
        }
    };
    if uninstall_requested {
        let mut daemon_loop = DaemonLoop::new_with_product_identity(
            generation.clone(),
            true,
            product_identity.clone(),
        );
        match daemon_loop.prepare_uninstall(&generation_store) {
            Ok(PrepareUninstallOutcome::Committed) => {
                consume_completed_uninstall_request();
                lifecycle::run_uninstall_frozen_loop();
            }
            Ok(
                PrepareUninstallOutcome::PendingOperation | PrepareUninstallOutcome::PendingCluster,
            ) => {
                // Retain exact request and authority; the ordinary daemon poll
                // retries with its existing pacing after publisher flush.
                lifecycle::run_daemon(generation, false, product_identity);
            }
            Ok(
                outcome @ (PrepareUninstallOutcome::RolledBack(_)
                | PrepareUninstallOutcome::Rejected(_)),
            ) => {
                let (error, publication) = match outcome {
                    PrepareUninstallOutcome::RolledBack(error) => {
                        let result = uninstall::record_rolled_back_result(&error);
                        (error, result)
                    }
                    PrepareUninstallOutcome::Rejected(error) => {
                        let result = uninstall::record_rejected_result(&error);
                        (error, result)
                    }
                    _ => unreachable!(),
                };
                match publication {
                    Ok(()) => consume_completed_uninstall_request(),
                    Err(reply_error) => log::err(
                        "uninstall",
                        &format!("preparation result unavailable; request retained: {reply_error}"),
                    ),
                }
                uninstall::record_failure(&error);
                log::err("main", &format!("uninstall preparation failed: {error}"));
                lifecycle::run_daemon(generation, false, product_identity);
            }
            Err(error) => {
                // Neither durable commit nor complete rollback was proved. Keep
                // the request for a bounded retry and fence activation work.
                uninstall::record_failure(&error);
                log::err(
                    "main",
                    &format!("uninstall prepare recovery failed: {error}"),
                );
                lifecycle::run_daemon(generation, false, product_identity);
            }
        }
        return;
    }
    log::ok(
        "main",
        &format!(
            "READY generation={} ({} installed agents)",
            generation.id,
            generation.selection.selected_agent_ids.len()
        ),
    );

    // After a daemon restart the in-memory resident registry is empty while
    // OEM processes may still hold DEX from an older immutable generation.
    // Prune only when every live catalog process supplied a verified resident
    // identity; otherwise conservatively retain all generations.
    match generation_store.retained_generations() {
        Ok(retained) => {
            let live_processes = retained_process_index(&retained)
                .into_keys()
                .filter(|process| {
                    retained.iter().any(|generation| {
                        process_watcher::find_pid_in_generation(generation, process).is_some()
                    })
                })
                .collect::<Vec<_>>();
            let resident_generations = live_processes
                .iter()
                .filter_map(|process| control_plane::resident_generation_id(process))
                .collect::<std::collections::BTreeSet<_>>();
            if generation_prune_is_safe(live_processes.len(), resident_generations.len()) {
                match generation_store.prune(&resident_generations) {
                    Ok(removed) if !removed.is_empty() => log::info(
                        "main",
                        &format!("generation GC removed: {}", removed.join(",")),
                    ),
                    Ok(_) => {}
                    Err(error) => log::err("main", &format!("generation GC deferred: {error}")),
                }
            } else {
                log::info(
                    "main",
                    "generation GC deferred: retained-generation resident identity is unavailable after restart",
                );
            }
        }
        Err(error) => log::err(
            "main",
            &format!("generation GC deferred: retained generation verification failed: {error}"),
        ),
    }

    // --- Run the daemon loop ---
    lifecycle::run_daemon(generation, false, product_identity);
}

fn handle_reboot() -> Option<i32> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.as_slice() != ["--reboot"] {
        return None;
    }
    let stable_self = std::env::current_exe()
        .ok()
        .is_some_and(|path| path == std::path::Path::new("/data/voboost/voboost-inject"));
    // Android init is the fixed PID-1 service owner. Avoid accepting a shell
    // or resident-daemon child even when it can execute the same signed ELF.
    let init_parent = unsafe { libc::getppid() } == 1;
    if unsafe { libc::geteuid() } != 0 || !stable_self || !init_parent {
        return Some(126);
    }
    if !matches!(product_candidate::authorize_reboot(), Ok(true)) {
        return Some(125);
    }
    Some(if lifecycle::perform_reboot() { 0 } else { 12 })
}

/// Activation entry shared by startup and the runtime incoming watcher.
///
/// When the `ready` marker is present, run the same activation
/// path as startup activation: verify + import + atomic pointer switch. New
/// processes use the new generation while residents keep their current code;
/// identical re-activation is a logged no-op. A failed validation CONSUMES the staged
/// transaction: the staging tree is quarantined under `rejected/` with the
/// rejection reason so neither this call nor the 500ms watcher retries the
/// same content forever.
fn activate_incoming_if_ready(store: &generation::GenerationStore) {
    activate_incoming_once(store);
}

/// Runtime watcher variant that hands the freshly activated generation back
/// so the live DaemonLoop can cut over to it (new processes must bootstrap
/// the new `current`; residents keep their old generation (docs/developer/updates).
fn activate_incoming_for_loop(
    store: &generation::GenerationStore,
) -> Option<generation::VerifiedGeneration> {
    if !store.incoming_work_present() {
        store.observe_log_resolved("incoming-rejection");
        store.observe_log_resolved("initial-generation");
        return None;
    }
    if store.activation_kill_switch_active() {
        return None;
    }
    let recovery = store.recover_rejection();
    store.observe_log_result("incoming-rejection", &recovery);
    if recovery.is_err() {
        return None;
    }
    match store.prepare_initial_install() {
        Ok(generation::InitialInstallPreparation::Busy) => {
            store.observe_log_wait("initial-generation", "operation busy");
            return None;
        }
        Ok(_) => store.observe_log_resolved("initial-generation"),
        Err(error) => {
            store.observe_log_result::<()>("initial-generation", &Err(error));
            return None;
        }
    }
    let incoming_marker = store.incoming_marker();
    if !incoming_marker.exists() {
        return None;
    }
    match store.activate_incoming() {
        Ok(generation) => {
            log::ok(
                "main",
                &format!("incoming generation activated: {}", generation.id),
            );
            log::info(
                "main",
                "generation switch is passive; resident processes keep their current code until a natural restart",
            );
            Some(generation)
        }
        Err(error) => {
            log::err("main", &format!("incoming generation rejected: {error:#}"));
            if store.activation_kill_switch_active() {
                log::info(
                    "main",
                    "kill-switch blocked generation activation; staging retained",
                );
                return None;
            }
            if store.accepted_activation_pending_cleanup() {
                log::err(
                    "main",
                    "accepted generation cleanup deferred; staging retained for recovery",
                );
                return None;
            }
            // Consume the transaction exactly like the startup path: without
            // the quarantine a bad generation staged after daemon start
            // would be fully re-verified every 500ms forever. If the
            // quarantine itself fails the marker stays, but the next pass
            // retries the quarantine — bounded work per pass, and the reason
            // is logged each time.
            match store.reject_incoming(&error.to_string()) {
                Ok(quarantined) => {
                    log::err(
                        "main",
                        &format!(
                            "rejected staging consumed and quarantined at {}",
                            quarantined.path.display()
                        ),
                    );
                }
                Err(quarantine_error) => log::err(
                    "main",
                    &format!(
                        "quarantining rejected staging failed ({quarantine_error}); \
                         marker left in place"
                    ),
                ),
            }
            None
        }
    }
}

/// One watcher/startup pass over the incoming marker. Returns true when an
/// activation attempt was made; activation is passive and never reboots the
/// multimedia unit or terminates resident OEM processes.
fn activate_incoming_once(store: &generation::GenerationStore) -> bool {
    activate_incoming_once_with_authority(store, store.activation_kill_switch_active())
}

fn activate_incoming_once_with_authority(
    store: &generation::GenerationStore,
    kill_switch_active: bool,
) -> bool {
    if kill_switch_active {
        return false;
    }
    let recovery = store.recover_rejection();
    store.observe_log_result("incoming-rejection", &recovery);
    if recovery.is_err() {
        return false;
    }
    match store.prepare_initial_install() {
        Ok(generation::InitialInstallPreparation::Busy) => {
            store.observe_log_wait("initial-generation", "operation busy");
            return false;
        }
        Ok(_) => store.observe_log_resolved("initial-generation"),
        Err(error) => {
            store.observe_log_result::<()>("initial-generation", &Err(error));
            return false;
        }
    }
    let incoming_marker = store.incoming_marker();
    if !incoming_marker.exists() {
        return false;
    }
    match store.activate_incoming() {
        Ok(generation) => {
            log::ok(
                "main",
                &format!("incoming generation activated: {}", generation.id),
            );
            log::info(
                "main",
                "generation switch is passive; resident processes keep their current code until a natural restart",
            );
        }
        Err(error) => {
            log::err("main", &format!("incoming generation rejected: {error:#}"));
            if store.activation_kill_switch_active() {
                log::info(
                    "main",
                    "kill-switch blocked generation activation; staging retained",
                );
                return false;
            }
            if store.accepted_activation_pending_cleanup() {
                log::err(
                    "main",
                    "accepted generation cleanup deferred; staging retained for recovery",
                );
                return true;
            }
            match store.reject_incoming(&error.to_string()) {
                Ok(quarantined) => {
                    log::err(
                        "main",
                        &format!(
                            "rejected staging consumed and quarantined at {}",
                            quarantined.path.display()
                        ),
                    );
                }
                Err(quarantine_error) => log::err(
                    "main",
                    &format!(
                        "quarantining rejected staging failed ({quarantine_error}); \
                         marker left in place"
                    ),
                ),
            }
        }
    }
    true
}

fn handle_cluster_provision_cli() -> Option<i32> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--uninstall-protocol") {
        if args.len() != 1 {
            return Some(2);
        }
        return Some(
            match management::authorize_stable_cli()
                .and_then(|()| cluster_control::uninstall_bridge::uninstall_provision())
            {
                Ok(Some(provision)) => {
                    println!(
                        "device-owned-v1 cluster {} {} {}",
                        provision.pair_id, provision.authority_epoch, provision.qnx_public_key
                    );
                    0
                }
                Ok(None) => {
                    println!("device-owned-v1 android");
                    0
                }
                Err(error) => {
                    crate::log::err("main", &format!("uninstall protocol observation: {error}"));
                    1
                }
            },
        );
    }
    if args.first().map(String::as_str) == Some("--cluster-uninstall-provisional-export") {
        if args.len() != 1 {
            return Some(2);
        }
        return Some(
            match cluster_control::uninstall_bridge::read_provisional_production() {
                Ok(Some(bytes)) => {
                    use std::io::Write;
                    if std::io::stdout().lock().write_all(&bytes).is_ok() {
                        0
                    } else {
                        1
                    }
                }
                Ok(None) => 0,
                Err(error) => {
                    crate::log::err(
                        "main",
                        &format!("cluster provisional export rejected: {error}"),
                    );
                    1
                }
            },
        );
    }
    if args.first().map(String::as_str) == Some("--cluster-uninstall-provisional") {
        if args.len() != 2 || args[1] != "-" {
            return Some(2);
        }
        use std::io::Read;
        let mut bytes = Vec::new();
        let result = std::io::stdin()
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())
            .and_then(|_| cluster_control::uninstall_bridge::retain_provisional_production(&bytes));
        return Some(match result {
            Ok(()) => {
                println!("{{\"schemaVersion\":1,\"retained\":true}}");
                0
            }
            Err(error) => {
                crate::log::err(
                    "main",
                    &format!("cluster provisional retention rejected: {error}"),
                );
                1
            }
        });
    }
    if args.first().map(String::as_str) == Some("--cluster-uninstall-export") {
        if args.len() != 1 {
            return Some(2);
        }
        return Some(
            match cluster_control::uninstall_bridge::export_production() {
                Ok(bytes) => {
                    use std::io::Write;
                    if std::io::stdout().lock().write_all(&bytes).is_ok() {
                        0
                    } else {
                        1
                    }
                }
                Err(error) => {
                    crate::log::err("main", &format!("cluster uninstall export failed: {error}"));
                    1
                }
            },
        );
    }
    if args.first().map(String::as_str) == Some("--cluster-uninstall-finalize") {
        if args.len() != 2 || (args[1] != "-" && !std::path::Path::new(&args[1]).is_absolute()) {
            return Some(2);
        }
        return Some(
            match cluster_control::uninstall_bridge::import_production(std::path::Path::new(
                &args[1],
            )) {
                Ok(()) => {
                    println!("cluster uninstall completion accepted");
                    0
                }
                Err(error) => {
                    crate::log::err(
                        "main",
                        &format!("cluster uninstall completion rejected: {error}"),
                    );
                    1
                }
            },
        );
    }
    if args.first().map(String::as_str) == Some("--cluster-provision") {
        if args.len() != 2 || !std::path::Path::new(&args[1]).is_absolute() {
            crate::log::err(
                "main",
                "usage: voboost-inject --cluster-provision <protected-absolute-directory>",
            );
            return Some(2);
        }
        return Some(
            match cluster_control::provision_production(std::path::Path::new(&args[1])) {
                Ok(()) => {
                    println!("cluster provisioning accepted");
                    0
                }
                Err(error) if error == "operation busy" => {
                    voboost_contract::cluster_wire::PROVISION_BUSY_EXIT
                }
                Err(error) => {
                    crate::log::err("main", &format!("cluster provisioning failed: {error}"));
                    1
                }
            },
        );
    }
    None
}

fn handle_generation_cli() -> Option<i32> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        return None;
    }
    if args.len() != 1 {
        crate::log::err(
            "main",
            "usage: voboost-inject [--activate-incoming|--describe-active-generation|\
             --rollback-generation|--recompute-profile]",
        );
        return Some(2);
    }
    // The audited operator diagnostic: intentionally rewrite vehicle.json
    // from fresh root probes. Running this command IS the operator
    // confirmation; the recompute is logged to the daemon log.
    if args[0] == "--recompute-profile" {
        let _ = std::fs::create_dir_all(config::ROOT_ZONE);
        return match profile::recompute_vehicle_profile(std::path::Path::new(config::ROOT_ZONE)) {
            Ok(document) => match profile::canonical_bytes(&document.facts) {
                Ok(bytes) => {
                    println!("{}", String::from_utf8_lossy(&bytes));
                    Some(0)
                }
                Err(error) => {
                    crate::log::err(
                        "main",
                        &format!("profile output serialization failed: {error}"),
                    );
                    Some(5)
                }
            },
            Err(error) => {
                crate::log::err("main", &format!("profile recompute failed: {error}"));
                Some(5)
            }
        };
    }
    let store = generation::GenerationStore::production();
    let result = match args[0].as_str() {
        "--activate-incoming" | "--rollback-generation" => {
            // These mutate generation pointers and race the daemon poll loop's
            // prune. Acquire the same pidfile flock as the daemon startup so
            // the CLI operation is serialized against prune. If the daemon
            // holds the lock, refuse rather than corrupting state.
            match acquire_single_instance() {
                Err(error) => {
                    crate::log::err(
                        "main",
                        &format!("pidfile authority unavailable: {error}; retry later"),
                    );
                    return Some(1);
                }
                Ok(()) => match args[0].as_str() {
                    "--activate-incoming" => store.activate_incoming(),
                    "--rollback-generation" => store.rollback(),
                    _ => unreachable!(),
                },
            }
        }
        "--describe-active-generation" => store.active(),
        _ => {
            crate::log::err("main", &format!("unknown option: {}", args[0]));
            return Some(2);
        }
    };
    match result.and_then(|generation| generation.description_json()) {
        Ok(description) => {
            println!("{description}");
            Some(0)
        }
        Err(error) => {
            crate::log::err("main", &format!("generation operation failed: {error}"));
            let text = error.to_string();
            Some(
                if text.contains("missing")
                    || text.contains("invalid")
                    || text.contains("mismatch")
                    || text.contains("rejected")
                {
                    3
                } else if text.contains("current pointer") || text.contains("previous pointer") {
                    6
                } else {
                    5
                },
            )
        }
    }
}

/// Acquire and retain the exact root-owned pidfile authority.
fn acquire_single_instance() -> Result<(), String> {
    pidfile::acquire_process_lock().map_err(|error| error.to_string())
}

fn release_lock() {
    // The typed static guard deliberately releases only at process exit.
}

fn write_degraded_status() {
    let mut status = status::Status::default();
    if let Ok(identity) = installed_product::load_identity() {
        status.release_identity = identity.release_identity;
        status.manifest_sha256 = identity.manifest_sha256;
    }
    status.daemon_state = "degraded".to_string();
    status.write_atomic();
}

#[cfg(test)]
mod tests;
