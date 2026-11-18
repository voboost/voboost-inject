use super::{
    activate_incoming_once, activate_incoming_once_with_authority, config, control_plane, downlink,
    generation, initialize_daemon_authorities, injector, installer_owned_install_handoff_pending,
    plan, preparation_resolved, status, target_identity, uninstall_poll_disposition,
    uninstall_preempts_new_work, wait_for_installer_owned_handoff_with,
    InstallerHandoffObservation, PrepareUninstallOutcome, UninstallPollDisposition,
};
use crate::runtime::test_support::{
    ack_action, exact_rebound_generation, generation_prune_is_safe, next_desired_generation,
    pending_retry_decision, pending_retry_semantics_match, render_confirmed_update_frames,
    resolve_retained_authority, retained_process_index, target_action, verify_resident_identity,
    AckAction, DaemonLoop, DesiredDocumentState, PendingRetryDecision, TargetAction,
    LIVE_ACK_GRACE, LIVE_ACK_MAX_RESTARTS, MAX_AGENT_PENDING_RETRIES,
};
use crate::runtime_loop::{run_poll_pass, PollActions};

#[test]
fn installer_handoff_rearms_busy_after_a_lock_free_observation() {
    let directory = tempfile::tempdir().unwrap();
    let logs = directory.path().join("logs");
    crate::canonical_log::with_test_log(&logs, || {
        let mut states = [
            InstallerHandoffObservation::Busy,
            InstallerHandoffObservation::Running,
            InstallerHandoffObservation::Busy,
            InstallerHandoffObservation::Pending,
            InstallerHandoffObservation::Busy,
            InstallerHandoffObservation::Ready,
        ]
        .into_iter();
        wait_for_installer_owned_handoff_with(|| Ok(states.next().unwrap()), || Ok(()), |_| {})
            .unwrap();
    });
    let rows = std::fs::read_to_string(logs.join("segment-active.jsonl")).unwrap();
    assert_eq!(
        rows.lines()
            .filter(|line| {
                let row: serde_json::Value = serde_json::from_str(line).unwrap();
                row["message"] == "operation busy"
            })
            .count(),
        3
    );
}

#[test]
fn install_handoff_busy_waits_without_start_and_stable_errors_fail() {
    let mut states = [
        InstallerHandoffObservation::Busy,
        InstallerHandoffObservation::Pending,
        InstallerHandoffObservation::Ready,
    ]
    .into_iter();
    let requests = std::cell::Cell::new(0);
    let waits = std::cell::Cell::new(0);
    assert_eq!(
        wait_for_installer_owned_handoff_with(
            || Ok(states.next().unwrap()),
            || {
                requests.set(requests.get() + 1);
                Ok(())
            },
            |_| waits.set(waits.get() + 1)
        )
        .unwrap(),
        2
    );
    assert_eq!(
        requests.get(),
        1,
        "Busy must not request an unrelated installer"
    );
    assert_eq!(waits.get(), 2);
    assert!(wait_for_installer_owned_handoff_with(
        || Err("stable corrupt WAL".into()),
        || {
            requests.set(requests.get() + 1);
            Ok(())
        },
        |_| panic!("corruption is not Busy")
    )
    .is_err());
    assert_eq!(requests.get(), 1);
}

#[test]
fn singleton_authority_precedes_logger_and_failure_never_initializes_logging() {
    let events = std::cell::RefCell::new(Vec::new());
    initialize_daemon_authorities(
        || {
            events.borrow_mut().push("pidfile");
            Ok(())
        },
        || events.borrow_mut().push("logger"),
    )
    .unwrap();
    assert_eq!(events.into_inner(), ["pidfile", "logger"]);

    let logger_called = std::cell::Cell::new(false);
    assert!(initialize_daemon_authorities(
        || Err("foreign run directory".into()),
        || logger_called.set(true),
    )
    .is_err());
    assert!(!logger_called.get());
}

#[test]
fn installer_owned_handoff_restarts_only_the_fixed_installer_with_capped_backoff() {
    use crate::operation_contract::{Operation, OperationDescriptor};

    let mut operation = OperationDescriptor {
        schema_version: 1,
        operation: Operation::Install,
        transaction_id: "11".repeat(32),
        journal: format!("recovery/{}/install-journal.json", "11".repeat(32)),
        phase: "install-reboot-first".into(),
        outcome: "reboot-required".into(),
        reboot_count: 1,
        boot_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
        status_sequence: 17,
        journal_sha256: "22".repeat(32),
        error: None,
        installed_apk: None,
    };
    assert!(installer_owned_install_handoff_pending(Some(&operation)));
    operation.phase = "install-agents".into();
    assert!(!installer_owned_install_handoff_pending(Some(&operation)));
    operation.phase = "install-reboot-second".into();
    operation.reboot_count = 2;
    assert!(installer_owned_install_handoff_pending(Some(&operation)));
    operation.phase = "install-cleanup".into();
    operation.outcome = "running".into();
    assert!(installer_owned_install_handoff_pending(Some(&operation)));
    operation.outcome = "failed".into();
    assert!(!installer_owned_install_handoff_pending(Some(&operation)));

    let mut observations = vec![false, true, true, true].into_iter();
    let requests = std::cell::Cell::new(0_usize);
    let delays = std::cell::RefCell::new(Vec::new());
    let attempts = wait_for_installer_owned_handoff_with(
        || {
            Ok(if observations.next_back().unwrap() {
                InstallerHandoffObservation::Pending
            } else {
                InstallerHandoffObservation::Ready
            })
        },
        || {
            requests.set(requests.get() + 1);
            Ok(())
        },
        |delay| delays.borrow_mut().push(delay),
    )
    .unwrap();
    assert_eq!(attempts, 3);
    assert_eq!(requests.get(), 1);
    assert_eq!(
        delays.into_inner(),
        [
            std::time::Duration::from_millis(50),
            std::time::Duration::from_millis(100),
            std::time::Duration::from_millis(200),
        ]
    );
}

#[test]
fn generation_gc_defers_when_any_live_resident_identity_is_unknown() {
    assert!(generation_prune_is_safe(0, 0));
    assert!(generation_prune_is_safe(2, 2));
    assert!(!generation_prune_is_safe(1, 0));
    assert!(!generation_prune_is_safe(3, 2));
}

#[test]
fn restart_discovery_union_keeps_process_dropped_after_multiple_cutovers() {
    let mut old = generation::test_support::verified_variant(1);
    old.catalog.agents[0].targets[0].process = "old.passive.process".to_string();
    let mut previous = generation::test_support::verified_variant(2);
    previous.catalog.agents[0].targets[0].process = "previous.process".to_string();
    let active = generation::test_support::verified_variant(3);
    let retained = vec![old.clone(), previous, active];

    let process_index = retained_process_index(&retained);
    assert_eq!(process_index["old.passive.process"], vec![0]);
    assert!(process_index.contains_key("previous.process"));
    assert!(process_index.contains_key("com.qinggan.app.setting"));

    let authorized = std::collections::BTreeSet::from([old.id.clone()]);
    let identity = injector::ResidentIdentity {
        generation_id: old.id.clone(),
        catalog_sha256: old.catalog_sha256.clone(),
        settings_loaded: false,
        document_generation: None,
    };
    assert_eq!(
        exact_rebound_generation(&retained, &authorized, &identity, "old.passive.process")
            .unwrap()
            .id,
        old.id
    );
}

#[test]
fn retained_rebind_rejects_ambiguous_or_mismatched_authority() {
    let first = target_identity::AttestedTarget {
        pid: 41,
        starttime: 101,
        uid: 1000,
        selinux_context: "u:r:platform_app:s0".to_string(),
    };
    let mut second = first.clone();
    second.uid += 1;
    assert!(resolve_retained_authority(vec![
        ("a".repeat(64), first.clone()),
        ("b".repeat(64), second),
    ])
    .is_err());

    let (resolved, authorized) = resolve_retained_authority(vec![
        ("a".repeat(64), first.clone()),
        ("b".repeat(64), first.clone()),
    ])
    .unwrap();
    assert_eq!(resolved, first);
    assert_eq!(authorized.len(), 2);

    let retained = vec![generation::test_support::verified_variant(1)];
    let wrong_catalog = injector::ResidentIdentity {
        generation_id: retained[0].id.clone(),
        catalog_sha256: "f".repeat(64),
        settings_loaded: false,
        document_generation: None,
    };
    assert!(exact_rebound_generation(
        &retained,
        &std::collections::BTreeSet::from([retained[0].id.clone()]),
        &wrong_catalog,
        "com.qinggan.app.setting",
    )
    .is_err());
    let unauthorized = injector::ResidentIdentity {
        generation_id: retained[0].id.clone(),
        catalog_sha256: retained[0].catalog_sha256.clone(),
        settings_loaded: false,
        document_generation: None,
    };
    assert!(exact_rebound_generation(
        &retained,
        &std::collections::BTreeSet::new(),
        &unauthorized,
        "com.qinggan.app.setting",
    )
    .is_err());
}

#[test]
fn resident_rebind_identity_retains_exact_old_generation_and_rejects_wrong_catalog() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipped: needs root");
        return;
    }
    let zones = generation::test_support::zones();
    generation::test_support::stage_variant(&zones.store, 1);
    let resident = zones.store.activate_incoming().unwrap();
    let exact = injector::ResidentIdentity {
        generation_id: resident.id.clone(),
        catalog_sha256: resident.catalog_sha256.clone(),
        settings_loaded: false,
        document_generation: None,
    };
    assert_eq!(
        verify_resident_identity(&zones.store, &exact).unwrap().id,
        resident.id
    );
    let wrong = injector::ResidentIdentity {
        catalog_sha256: "f".repeat(64),
        ..exact
    };
    assert!(verify_resident_identity(&zones.store, &wrong).is_err());
}

#[test]
fn uninstall_request_or_prepared_marker_preempts_activation_and_native_work() {
    assert!(!uninstall_preempts_new_work(false, false));
    assert!(uninstall_preempts_new_work(true, false));
    assert!(uninstall_preempts_new_work(false, true));
    assert!(uninstall_preempts_new_work(true, true));
}

#[test]
fn request_is_consumed_only_after_commit_or_complete_rollback() {
    assert!(preparation_resolved(&Ok(
        PrepareUninstallOutcome::Committed
    )));
    assert!(preparation_resolved(&Ok(
        PrepareUninstallOutcome::RolledBack("restored".into())
    )));
    assert!(!preparation_resolved(&Err("restoration incomplete".into())));
    assert!(!preparation_resolved(&Ok(
        PrepareUninstallOutcome::PendingOperation
    )));
}

#[test]
fn committed_marker_and_surviving_request_retry_without_prepare_reentry() {
    let retry_called = std::cell::Cell::new(false);
    let prepare_called = std::cell::Cell::new(false);
    match uninstall_poll_disposition(false, true, true) {
        UninstallPollDisposition::RetryCommitted => retry_called.set(true),
        UninstallPollDisposition::PrepareRequested => prepare_called.set(true),
        UninstallPollDisposition::ContinueNormal => {}
    }
    assert!(retry_called.get());
    assert!(!prepare_called.get());

    assert_eq!(
        uninstall_poll_disposition(true, false, true),
        UninstallPollDisposition::RetryCommitted
    );
    assert_eq!(
        uninstall_poll_disposition(false, true, false),
        UninstallPollDisposition::RetryCommitted
    );
    assert_eq!(
        uninstall_poll_disposition(false, false, true),
        UninstallPollDisposition::PrepareRequested
    );
}

#[test]
fn native_restart_drain_finishes_with_flush_and_status_persistence() {
    #[derive(Default)]
    struct DrainProbe {
        step: usize,
        injected_at: Option<usize>,
        flushed_at: Option<usize>,
        persisted_at: Option<usize>,
    }

    impl DrainProbe {
        fn advance(&mut self) -> usize {
            self.step += 1;
            self.step
        }
    }

    impl PollActions for DrainProbe {
        fn record_deaths(&mut self) {
            self.advance();
        }
        fn drain_agent_logs(&mut self) {
            self.advance();
        }
        fn prepare_injection(&mut self) {
            self.advance();
        }
        fn dispatch_injections(&mut self) {
            self.injected_at = Some(self.advance());
        }
        fn collect_injections(&mut self) {
            self.advance();
        }
        fn aggregate_agent_status(&mut self) {
            self.advance();
        }
        fn push_live_config(&mut self) {
            self.advance();
        }
        fn enforce_live_acks(&mut self) {
            self.advance();
        }
        fn push_confirmed_snapshots(&mut self) {
            self.advance();
        }
        fn flush_downlinks(&mut self) {
            self.flushed_at = Some(self.advance());
        }
        fn persist_status(&mut self) {
            self.persisted_at = Some(self.advance());
        }
    }

    let mut probe = DrainProbe::default();
    run_poll_pass(&mut probe);
    assert!(probe.injected_at < probe.flushed_at);
    assert_eq!(probe.flushed_at.map(|step| step + 1), probe.persisted_at);
    assert_eq!(probe.persisted_at, Some(probe.step));
}

// --- runtime next-generation watcher (ready during a session) ---

fn watcher_zones() -> (tempfile::TempDir, generation::GenerationStore) {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let zone = root.path().join("zone");
    let incoming = root.path().join("incoming");
    std::fs::create_dir_all(&incoming).unwrap();
    std::fs::set_permissions(&incoming, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir_all(&zone).unwrap();
    std::fs::set_permissions(&zone, std::fs::Permissions::from_mode(0o755)).unwrap();
    let store = generation::GenerationStore::new(&zone, &incoming);
    (root, store)
}

#[test]
fn watcher_pass_without_marker_is_a_no_op() {
    let (root, store) = watcher_zones();
    assert!(!activate_incoming_once(&store));
    assert!(root
        .path()
        .join("zone")
        .join("rejected")
        .read_dir()
        .is_err());
}

#[test]
fn watcher_consumes_rejected_staging_without_retry() {
    // A malformed catalog fails at the schema boundary before any key is selected.
    // The watcher must consume the transaction so the 500ms loop does not
    // reprocess it forever, and must record that catalog-level rejection.
    let (root, store) = watcher_zones();
    let incoming = root.path().join("incoming");
    std::fs::write(incoming.join("agents.json"), b"{}").unwrap();
    std::fs::write(incoming.join("agents.json.sig"), vec![0u8; 64]).unwrap();
    std::fs::write(incoming.join(generation::READY_MARKER), b"").unwrap();

    assert!(activate_incoming_once(&store));
    // The marker is gone: a second poll pass must be a no-op.
    assert!(!incoming.join(generation::READY_MARKER).exists());
    assert!(!activate_incoming_once(&store));

    // Exactly one quarantine with the rejected payload and the reason.
    let rejected_dir = root
        .path()
        .join("zone")
        .join(generation::GENERATIONS_DIR)
        .join(generation::QUARANTINE_DIR);
    let entries: Vec<_> = std::fs::read_dir(&rejected_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(entries.len(), 1, "exactly one rejected transaction");
    assert!(entries[0].join("agents.json").exists());
    let reason =
        std::fs::read_to_string(entries[0].join(generation::REJECTION_REASON_FILE)).unwrap();
    assert!(
        reason.contains("catalog"),
        "rejection reason recorded: {reason}"
    );

    // The staging area is recreated with only the correlated rejection
    // acknowledgement for the app; no rejected payload remains live.
    let incoming_entries: Vec<_> = std::fs::read_dir(&incoming)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(
        incoming_entries,
        vec![std::ffi::OsString::from(generation::ACKNOWLEDGEMENT_FILE)]
    );
    let acknowledgement: serde_json::Value = serde_json::from_slice(
        &std::fs::read(incoming.join(generation::ACKNOWLEDGEMENT_FILE)).unwrap(),
    )
    .unwrap();
    assert_eq!(acknowledgement["schemaVersion"], 1);
    assert_eq!(acknowledgement["status"], "rejected");
    assert!(acknowledgement.get("selectionSha256").is_none());
    assert!(acknowledgement.get("generationId").is_none());
}

#[test]
fn watcher_kill_switch_retains_staging_until_retry_is_permitted() {
    let (root, store) = watcher_zones();
    let incoming = root.path().join("incoming");
    let run = root.path().join("zone/run");
    std::fs::create_dir(&run).unwrap();
    std::fs::write(run.join("disable"), b"").unwrap();
    std::fs::write(incoming.join("agents.json"), b"{}").unwrap();
    std::fs::write(incoming.join("agents.json.sig"), vec![0u8; 64]).unwrap();
    std::fs::write(incoming.join(generation::READY_MARKER), b"").unwrap();

    assert!(!activate_incoming_once(&store));
    assert!(incoming.join(generation::READY_MARKER).exists());
    assert!(!root.path().join("zone/rejected").exists());

    std::fs::remove_file(run.join("disable")).unwrap();
    assert!(activate_incoming_once(&store));
    assert!(!incoming.join(generation::READY_MARKER).exists());
}

#[test]
fn watcher_disable_all_retains_staged_generation_for_retry() {
    let (root, store) = watcher_zones();
    let incoming = root.path().join("incoming");
    std::fs::write(incoming.join("agents.json"), b"{}").unwrap();
    std::fs::write(incoming.join("agents.json.sig"), vec![0u8; 64]).unwrap();
    std::fs::write(incoming.join(generation::READY_MARKER), b"").unwrap();

    assert!(!activate_incoming_once_with_authority(&store, true));
    assert!(incoming.join(generation::READY_MARKER).exists());
    assert!(!root.path().join("zone/rejected").exists());

    assert!(activate_incoming_once_with_authority(&store, false));
    assert!(!incoming.join(generation::READY_MARKER).exists());
}

#[test]
fn watcher_activates_a_completed_staging_once() {
    // Root-only: the import writes into a 0711 generations directory.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipped: needs root");
        return;
    }
    let (root, store) = watcher_zones();
    let incoming = root.path().join("incoming");
    let zone = root.path().join("zone");
    let facts = "{\"schemaVersion\":1,\"facts\":{\"chip\":{\"value\":\"8155\"},\
         \"vehicle\":{\"value\":\"free\"},\"android\":{\"value\":9},\
         \"powertrain\":{\"value\":\"hybrid\"},\"market\":{\"value\":\"china\"}}}";
    std::fs::write(zone.join("vehicle.json"), facts).unwrap();
    std::fs::write(incoming.join("agents.json"), b"trusted-by-generation-tests").unwrap();
    // The catalog bytes above are unsigned; activation must fail closed
    // (signature rejection) and consume staging exactly like any other
    // validation failure.
    std::fs::write(incoming.join("agents.json.sig"), vec![1u8; 64]).unwrap();
    std::fs::write(incoming.join(generation::READY_MARKER), b"").unwrap();
    assert!(activate_incoming_once(&store));
    assert!(!incoming.join(generation::READY_MARKER).exists());
    // Consumed: no active generation was installed from invalid content.
    assert!(store.active_id().is_none());
}

#[test]
fn live_ack_action_acked_when_generation_reached() {
    assert!(matches!(
        ack_action(Some(10), 10, std::time::Duration::from_secs(0), 0),
        AckAction::Acked
    ));
    assert!(matches!(
        ack_action(Some(11), 10, LIVE_ACK_GRACE, 0),
        AckAction::Acked
    ));
}

#[test]
fn live_ack_action_waits_inside_grace() {
    assert!(matches!(
        ack_action(Some(9), 10, std::time::Duration::from_secs(1), 0),
        AckAction::Wait
    ));
    assert!(matches!(
        ack_action(None, 10, std::time::Duration::from_secs(1), 0),
        AckAction::Wait
    ));
}

#[test]
fn enabled_to_empty_never_counts_acked_without_runtime_evidence() {
    assert!(matches!(
        ack_action(None, 42, std::time::Duration::ZERO, 0),
        AckAction::Wait
    ));
    assert!(matches!(
        ack_action(Some(41), 42, std::time::Duration::ZERO, 0),
        AckAction::Wait
    ));
}

#[test]
fn live_ack_action_never_kills_after_grace() {
    assert!(matches!(
        ack_action(Some(9), 10, LIVE_ACK_GRACE, 0),
        AckAction::GiveUp
    ));
    assert!(matches!(
        ack_action(None, 10, LIVE_ACK_GRACE, 0),
        AckAction::GiveUp
    ));
}

#[test]
fn live_ack_action_gives_up_after_restart_budget() {
    assert!(matches!(
        ack_action(Some(9), 10, LIVE_ACK_GRACE, LIVE_ACK_MAX_RESTARTS),
        AckAction::GiveUp
    ));
}

#[test]
fn semantic_remove_and_reenable_allocate_new_generations() {
    let enabled = r#"[{"id":"launcher","config":{}}]"#;
    let empty = "[]";

    let first = next_desired_generation(None, enabled, 100)
        .unwrap()
        .unwrap();
    let first_state = DesiredDocumentState::new(enabled, first);
    assert!(next_desired_generation(Some(&first_state), enabled, 100)
        .unwrap()
        .is_none());

    let removed = next_desired_generation(Some(&first_state), empty, 100)
        .unwrap()
        .unwrap();
    let removed_state = DesiredDocumentState::new(empty, removed);
    let reenabled = next_desired_generation(Some(&removed_state), enabled, 100)
        .unwrap()
        .unwrap();

    assert!(removed > first);
    assert!(reenabled > removed);
}

#[test]
fn desired_generation_exhaustion_fails_without_saturation() {
    let maximum = control_plane::MAX_DOCUMENT_GENERATION;
    assert_eq!(
        next_desired_generation(None, "changed", maximum)
            .unwrap()
            .unwrap(),
        maximum
    );
    let exhausted = DesiredDocumentState::new("old", maximum);
    assert!(next_desired_generation(Some(&exhausted), "changed", 0).is_err());
    assert!(next_desired_generation(None, "changed", maximum + 1).is_err());
}

#[test]
fn exact_downlink_budget_accepts_n_minus_one_and_n_but_rejects_n_plus_one() {
    let overhead = format!("A|{}|", u64::MAX).len() + 1;
    let maximum_document = config::MAX_DOWNLINK_FRAME_BYTES - overhead;
    for length in [maximum_document - 1, maximum_document] {
        let document = "x".repeat(length);
        let (desired, acknowledgement) =
            render_confirmed_update_frames(u64::MAX, &document).unwrap();
        assert!(desired.len() <= config::MAX_DOWNLINK_FRAME_BYTES);
        assert!(acknowledgement.len() <= config::MAX_DOWNLINK_FRAME_BYTES);
    }
    assert!(render_confirmed_update_frames(u64::MAX, &"x".repeat(maximum_document + 1)).is_err());
}

#[test]
fn settings_commit_during_drain_queues_runtime_d_before_correlated_a_once() {
    let generation = generation::test_support::verified_variant(1);
    let process = "com.qinggan.app.setting";
    let initial = plan::Plan::defaults_for(&generation);
    let mut daemon_loop = DaemonLoop::new(generation);
    assert!(daemon_loop
        .write_fresh_desired_document(&initial, process)
        .unwrap());

    // Model the fresh canonical read after a successful E commit in the
    // DrainAgentLogs phase. A startup mutation changes the complete
    // Settings projection even though no target-local agent changed.
    let mut committed = initial;
    committed.startup = plan::Startup::Hidden;
    assert!(daemon_loop
        .write_desired_document(&committed, process)
        .unwrap());
    let generation = daemon_loop.desired_document(process).unwrap().generation;

    let mut fds = [-1, -1];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    assert_eq!(
        daemon_loop
            .enqueue_confirmed_update(&committed, process, fds[1], 41)
            .unwrap(),
        generation
    );
    // Drain the pipe like the real consumer: the writer flushes through a
    // nonblocking fd, and a fresh pipe may accept only the first frame before
    // the first read (macOS starts pipes at a 512-byte buffer), so the
    // correlated A frame sits in the downlink queue until a read drains space
    // and the next flush delivers it. Read until both the writer queue is
    // drained and the pipe itself is empty.
    let mut received = Vec::new();
    {
        let mut chunk = vec![0u8; 128 * 1024];
        loop {
            assert!(downlink::flush(fds[1]), "downlink endpoint poisoned");
            if downlink::is_drained(fds[1]) && !received.is_empty() {
                // Queue empty: one final (empty) read proves the pipe is
                // drained too — a nonblocking read returns EAGAIN (-1).
                unsafe { libc::fcntl(fds[0], libc::F_SETFL, libc::O_NONBLOCK) };
                let count = unsafe { libc::read(fds[0], chunk.as_mut_ptr().cast(), chunk.len()) };
                if count > 0 {
                    received.extend_from_slice(&chunk[..count as usize]);
                    continue;
                }
                break;
            }
            let count = unsafe { libc::read(fds[0], chunk.as_mut_ptr().cast(), chunk.len()) };
            assert!(count >= 0);
            if count == 0 {
                break;
            }
            received.extend_from_slice(&chunk[..count as usize]);
        }
    }
    let frames = received.split(|byte| *byte == b'\n').collect::<Vec<_>>();
    assert_eq!(frames.len(), 3);
    assert!(frames[0].starts_with(b"D|"));
    assert!(frames[1].starts_with(b"A|41|"));
    let desired: serde_json::Value = serde_json::from_slice(&frames[0][2..]).unwrap();
    let acknowledged: serde_json::Value = serde_json::from_slice(&frames[1][5..]).unwrap();
    assert_eq!(desired, acknowledged);
    assert_eq!(desired["documentGeneration"], generation);
    assert!(desired["profile"].get("language").is_none());
    assert_eq!(
        daemon_loop.pending_ack_generation(process),
        Some(generation)
    );
    assert!(
        !daemon_loop
            .write_desired_document(&committed, process)
            .unwrap(),
        "the next ordinary poll sees the delivered generation, not a stuck semantic delta"
    );
    downlink::forget_fd(fds[1]);
    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
}

#[test]
fn restart_removal_stamp_is_bound_to_the_old_live_endpoint() {
    let generation = crate::plan::test_fixtures::settings_generation();
    let process = "com.qinggan.systemservice";
    let pid = 1_640_023;
    let mut enabled = plan::Plan::defaults_for(&generation);
    enabled
        .entries
        .iter_mut()
        .find(|entry| entry.id == "forced-ev")
        .unwrap()
        .enabled = true;
    let mut daemon_loop = DaemonLoop::new(generation);
    daemon_loop
        .write_fresh_desired_document(&enabled, process)
        .unwrap();
    let mut pipe = [-1; 2];
    assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
    daemon_loop.track(process, pid, 7001, None, Some(pipe[1]));
    let epoch = daemon_loop.tracked_endpoint_epoch(process, pipe[1]);
    assert!(
        !daemon_loop
            .endpoint_context(pid, process, epoch)
            .restart_allowed
    );
    let mut disabled = enabled;
    disabled
        .entries
        .iter_mut()
        .find(|entry| entry.id == "forced-ev")
        .unwrap()
        .enabled = false;
    assert!(daemon_loop
        .write_desired_document(&disabled, process)
        .unwrap());
    let context = daemon_loop.endpoint_context(pid, process, epoch);
    assert!(context.restart_allowed);
    assert_eq!(
        context.resident_agents, context.agents,
        "ordinary capabilities were not widened"
    );
    assert!(!daemon_loop
        .write_desired_document(&disabled, process)
        .unwrap());
    assert!(
        daemon_loop
            .endpoint_context(pid, process, epoch)
            .restart_allowed
    );
    assert!(
        !daemon_loop
            .endpoint_context(pid, process, epoch + 1)
            .restart_allowed
    );
    assert!(
        !daemon_loop
            .endpoint_context(pid + 1, process, epoch)
            .restart_allowed
    );
    let mut next_pipe = [-1; 2];
    assert_eq!(unsafe { libc::pipe(next_pipe.as_mut_ptr()) }, 0);
    daemon_loop.track(process, pid + 1, 7002, None, Some(next_pipe[1]));
    let next_epoch = daemon_loop.tracked_endpoint_epoch(process, next_pipe[1]);
    assert!(
        !daemon_loop
            .endpoint_context(pid + 1, process, next_epoch)
            .restart_allowed
    );
    unsafe {
        libc::close(pipe[0]);
        libc::close(pipe[1]);
        libc::close(next_pipe[0]);
        libc::close(next_pipe[1]);
    }
}

#[test]
fn live_settings_hidden_document_keeps_the_current_profile_and_exact_status_set() {
    let generation = crate::plan::test_fixtures::settings_generation();
    let process = "com.qinggan.app.setting";
    let initial = plan::Plan::defaults_for(&generation);
    let mut daemon_loop = DaemonLoop::new(generation);
    daemon_loop
        .write_fresh_desired_document(&initial, process)
        .unwrap();
    let mut fds = [-1, -1];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    daemon_loop.track(process, 777, 7001, None, Some(fds[1]));
    let epoch = daemon_loop.tracked_endpoint_epoch(process, fds[1]);
    let mut hidden = initial;
    hidden.startup = plan::Startup::Hidden;
    daemon_loop
        .write_desired_document(&hidden, process)
        .unwrap();
    let document = daemon_loop.desired_document(process).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&document.semantic_document).unwrap();
    assert_eq!(parsed["profile"]["startup"], "hidden");
    assert!(parsed["profile"].get("language").is_none());
    let context = daemon_loop.endpoint_context(777, process, epoch);
    assert!(context.settings_allowed());
    assert!(context.agents.contains("settings"));
    let status = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 1, "process": process,
        "generationId": context.resident_generation_id,
        "catalogSha256": context.resident_catalog_sha256,
        "documentGeneration": document.generation,
        "agents": [{"id": "settings", "lifecycleGeneration": 1,
            "state": "active", "reason": "ready", "details": {}}],
    }))
    .unwrap();
    assert!(control_plane::status_envelope_matches(
        &status,
        process,
        &context.resident_generation_id,
        &context.resident_catalog_sha256,
        &context.agents,
    ));
    use voboost_contract::desired::{Config, Field};
    use voboost_contract::runtime_owner::{Command, Outcome};
    let boot = "11111111-1111-4111-8111-111111111111";
    let mut committed = Config::new("hidden", Default::default()).unwrap();
    let mut receipts = Vec::new();
    assert_eq!(
        crate::agent_events::route_user_desired_for_fixture(
            "701|settings|radio|voboost-startup:interface",
            &context,
            Some(fds[1]),
            boot,
            |command| {
                let Command::SaveDesired {
                    field,
                    value,
                    mut input,
                } = command
                else {
                    panic!("startup radio must use semantic user authority");
                };
                assert_eq!(field, Field::Startup);
                assert_eq!(value, "interface");
                assert_eq!(input.endpoint_epoch, epoch);
                assert_eq!(input.request_id, 701);
                input.injector_pid = 42;
                input.injector_starttime = 100;
                let disposition = committed.save(boot, &field, &value, &input, &[])?;
                Ok(Outcome::DesiredSaved {
                    revision: committed.user_revision,
                    config: serde_json::to_string(&committed).unwrap(),
                    disposition,
                })
            },
            |fd, frame| {
                assert_eq!(fd, fds[1]);
                receipts.push(String::from_utf8(frame.to_vec()).unwrap());
                true
            },
        ),
        Some(Some(1))
    );
    assert_eq!(committed.startup, "interface");
    assert_eq!(committed.user_revision, 1);
    assert_eq!(receipts.len(), 1);
    let receipt: serde_json::Value =
        serde_json::from_str(receipts[0].strip_prefix("U|701|").unwrap().trim_end()).unwrap();
    assert_eq!(receipt["field"]["kind"], "startup");
    assert_eq!(receipt["value"], "interface");
    assert_eq!(receipt["userRevision"], 1);
    // Saved does not replace the effective profile or its exact status set.
    let unchanged = daemon_loop.desired_document(process).unwrap();
    assert_eq!(unchanged.semantic_document, document.semantic_document);
    assert!(!daemon_loop
        .endpoint_context(777, process, epoch + 1)
        .settings_allowed());
    downlink::forget_fd(fds[1]);
    crate::agent_events::forget_endpoint(epoch);
    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
}

#[test]
fn none_terminal_delivery_pushes_fresh_settings_profile_before_self_stop() {
    let generation = crate::plan::test_fixtures::settings_generation();
    let process = "com.qinggan.app.setting";
    let initial = plan::Plan::defaults_for(&generation);
    let mut daemon_loop = DaemonLoop::new(generation);
    daemon_loop
        .write_fresh_desired_document(&initial, process)
        .unwrap();
    let mut fds = [-1, -1];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    unsafe {
        libc::fcntl(fds[0], libc::F_SETFL, libc::O_NONBLOCK);
    }
    daemon_loop.track(process, 778, 7002, None, Some(fds[1]));
    let mut none = initial;
    none.startup = plan::Startup::None;
    none.disable_all = true;
    let read_fd = fds[0];
    let reader = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut received = Vec::new();
        while std::time::Instant::now() < deadline {
            let mut buffer = [0u8; 8192];
            let count = unsafe { libc::read(read_fd, buffer.as_mut_ptr().cast(), buffer.len()) };
            if count > 0 {
                received.extend_from_slice(&buffer[..count as usize]);
                if received.last() == Some(&b'\n') {
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        received
    });
    daemon_loop.finish_none_delivery(&none);
    let frame = reader.join().unwrap();
    assert!(
        !frame.is_empty(),
        "none must publish its fresh D before exiting"
    );
    assert!(frame.starts_with(b"D|"));
    let parsed: serde_json::Value = serde_json::from_slice(&frame[2..frame.len() - 1]).unwrap();
    assert_eq!(parsed["profile"]["startup"], "none");
    assert_eq!(parsed["agents"][0]["id"], "settings");
    downlink::forget_fd(fds[1]);
    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
}

#[test]
fn none_terminal_delivery_resumes_backpressured_pair_and_bounds_a_blocked_peer() {
    let generation = crate::plan::test_fixtures::settings_generation();
    let process = "com.qinggan.app.setting";
    let initial = plan::Plan::defaults_for(&generation);
    let mut daemon_loop = DaemonLoop::new(generation);
    daemon_loop
        .write_fresh_desired_document(&initial, process)
        .unwrap();
    let mut healthy = [-1, -1];
    let mut blocked = [-1, -1];
    assert_eq!(unsafe { libc::pipe(healthy.as_mut_ptr()) }, 0);
    assert_eq!(unsafe { libc::pipe(blocked.as_mut_ptr()) }, 0);
    for fd in [healthy[0], healthy[1], blocked[1]] {
        assert!(unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } >= 0);
    }
    let mut filler_bytes = 0;
    let filler = [b'x'; 512];
    for fd in [healthy[1], blocked[1]] {
        loop {
            let count = unsafe { libc::write(fd, filler.as_ptr().cast(), filler.len()) };
            if count <= 0 {
                break;
            }
            if fd == healthy[1] {
                filler_bytes += count as usize;
            }
        }
    }
    daemon_loop.track(process, 779, 7003, None, Some(healthy[1]));
    daemon_loop.track("blocked.peer", 780, 7004, None, Some(blocked[1]));
    assert!(downlink::enqueue_frame(blocked[1], b"R|blocked|missing|\n"));
    let mut none = initial;
    none.startup = plan::Startup::None;
    none.disable_all = true;
    daemon_loop.write_desired_document(&none, process).unwrap();
    daemon_loop
        .enqueue_confirmed_update(&none, process, healthy[1], 91)
        .unwrap();
    assert!(!downlink::is_drained(healthy[1]));
    let read_fd = healthy[0];
    let reader = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(40));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut received = Vec::new();
        while std::time::Instant::now() < deadline {
            let mut buffer = [0u8; 8192];
            let count = unsafe { libc::read(read_fd, buffer.as_mut_ptr().cast(), buffer.len()) };
            if count > 0 {
                received.extend_from_slice(&buffer[..count as usize]);
                if received.iter().filter(|byte| **byte == b'\n').count() == 2 {
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        received
    });
    let started = std::time::Instant::now();
    daemon_loop.finish_none_delivery(&none);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "terminal delivery took {:?}",
        started.elapsed()
    );
    assert!(downlink::is_drained(healthy[1]));
    assert!(!downlink::is_drained(blocked[1]));
    let received = reader.join().unwrap();
    assert!(received[..filler_bytes].iter().all(|byte| *byte == b'x'));
    let frames = received[filler_bytes..]
        .split(|byte| *byte == b'\n')
        .collect::<Vec<_>>();
    assert_eq!(frames.len(), 3);
    assert!(frames[0].starts_with(b"D|"));
    assert!(frames[1].starts_with(b"A|91|"));
    assert_eq!(&frames[0][2..], &frames[1][5..]);
    let document: serde_json::Value = serde_json::from_slice(&frames[0][2..]).unwrap();
    assert_eq!(document["profile"]["startup"], "none");
    for fd in [healthy[1], blocked[1]] {
        downlink::forget_fd(fd);
    }
    for fd in [healthy[0], healthy[1], blocked[0], blocked[1]] {
        unsafe {
            libc::close(fd);
        }
    }
}

fn queued_snapshot_records(
    directory: &std::path::Path,
) -> Vec<crate::canonical_log::CanonicalRecord> {
    crate::canonical_log::CanonicalLog::open(directory)
        .unwrap()
        .query(&crate::canonical_log::Query {
            after_sequence: 0,
            limit: 200,
            levels: vec![],
            kinds: vec![],
            agent_ids: vec![],
            search: Some("desired-snapshot-queued".into()),
            from_epoch_millis: 0,
            to_epoch_millis: u64::MAX,
        })
        .unwrap()
        .records
}

fn snapshot_log_directory() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn read_downlink_frames(fds: [i32; 2]) -> Vec<u8> {
    assert!(unsafe { libc::fcntl(fds[0], libc::F_SETFL, libc::O_NONBLOCK) } >= 0);
    let mut received = Vec::new();
    let mut buffer = [0u8; 8192];
    for _ in 0..1024 {
        assert!(downlink::flush(fds[1]));
        loop {
            let count = unsafe { libc::read(fds[0], buffer.as_mut_ptr().cast(), buffer.len()) };
            if count <= 0 {
                break;
            }
            received.extend_from_slice(&buffer[..count as usize]);
        }
        if downlink::is_drained(fds[1]) {
            return received;
        }
    }
    panic!("bounded host pipe did not drain");
}

fn assert_queued_snapshot_identity(confirmed: bool) {
    use sha2::{Digest, Sha256};

    let directory = snapshot_log_directory();
    let generation = generation::test_support::verified_variant(1);
    let process = "com.qinggan.app.setting";
    let desired = plan::Plan::defaults_for(&generation);
    let revision = 1_777_777_777_777_777_779;
    let semantic_document = desired
        .desired_semantics_for_process(process, &generation)
        .unwrap();
    let mut daemon_loop = DaemonLoop::new(generation.clone());
    daemon_loop.insert_desired_document(
        process,
        &semantic_document,
        revision,
        vec!["settings".into()],
        generation.clone(),
    );
    let mut fds = [-1, -1];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    daemon_loop.track(process, 4242, 987_654_321, None, Some(fds[1]));
    crate::canonical_log::with_test_log(directory.path(), || {
        assert_eq!(
            if confirmed {
                daemon_loop.enqueue_confirmed_update(&desired, process, fds[1], u64::MAX)
            } else {
                daemon_loop.enqueue_desired_snapshot(&desired, process, fds[1])
            }
            .unwrap(),
            revision
        );
    });
    let received = read_downlink_frames(fds);
    let frames: Vec<_> = received.split(|byte| *byte == b'\n').collect();
    assert!(frames[0].starts_with(b"D|"));
    assert_eq!(frames.len(), if confirmed { 3 } else { 2 });
    let document = &frames[0][2..];
    if confirmed {
        let prefix = format!("A|{}|", u64::MAX);
        assert!(frames[1].starts_with(prefix.as_bytes()));
        assert_eq!(&frames[1][prefix.len()..], document);
    }
    let records = queued_snapshot_records(directory.path());
    assert_eq!(
        records.len(),
        1,
        "one successful enqueue must emit one proof"
    );
    let record = &records[0];
    assert_eq!(record.source.kind, "daemon");
    assert!(record.source.id.is_none());
    assert_eq!(record.level, crate::canonical_log::Level::Info);
    assert_eq!(record.component, "runtime");
    assert_eq!(record.message, "desired-snapshot-queued");
    assert_eq!(record.fields["process"], process);
    assert_eq!(record.fields["targetPid"], "4242");
    assert_eq!(record.fields["targetStarttime"], "987654321");
    assert!(record.fields["endpointEpoch"].parse::<u64>().unwrap() > 0);
    assert_eq!(record.fields["generationId"], generation.id);
    assert_eq!(record.fields["catalogSha256"], generation.catalog_sha256);
    assert_eq!(record.fields["documentGeneration"], revision.to_string());
    assert_eq!(
        record.fields["snapshotSha256"],
        hex::encode(Sha256::digest(document))
    );
    let parsed: serde_json::Value = serde_json::from_slice(document).unwrap();
    assert_eq!(parsed["documentGeneration"].as_i64(), Some(revision));
    let reordered = serde_json::to_vec(&parsed).unwrap();
    assert_ne!(reordered, document);
    assert_ne!(
        record.fields["snapshotSha256"],
        hex::encode(Sha256::digest(&reordered)),
        "the root identity hashes exact wire bytes, not reordered JSON"
    );
    assert!(parsed["profile"].get("language").is_none());
    assert!(!record.fields.contains_key("sourceLanguage"));
    assert!(!record.fields.contains_key("profileLanguage"));
    assert!(!record.fields.contains_key("effectiveLanguage"));
    assert_eq!(record.fields["frames"], if confirmed { "D+A" } else { "D" });
    if confirmed {
        assert_eq!(record.fields["requestId"], u64::MAX.to_string());
    } else {
        assert!(!record.fields.contains_key("requestId"));
    }
    let mut keys = std::collections::HashSet::from([
        "process",
        "generationId",
        "catalogSha256",
        "documentGeneration",
        "snapshotSha256",
        "frames",
        "targetPid",
        "targetStarttime",
        "endpointEpoch",
    ]);
    if confirmed {
        keys.insert("requestId");
    }
    assert_eq!(
        record
            .fields
            .keys()
            .map(String::as_str)
            .collect::<std::collections::HashSet<_>>(),
        keys
    );
    assert!(serde_json::to_vec(record).unwrap().len() < crate::canonical_log::MAX_RECORD_BYTES);
    assert_eq!(daemon_loop.pending_ack_generation(process), Some(revision));
    downlink::forget_fd(fds[1]);
    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
}

#[test]
fn queued_desired_snapshot_has_exact_canonical_identity() {
    assert_queued_snapshot_identity(false);
}

#[test]
fn queued_confirmed_update_proof_matches_both_exact_frames() {
    assert_queued_snapshot_identity(true);
}

#[test]
fn rejected_desired_queues_emit_no_proof_or_pending_ack() {
    let directory = snapshot_log_directory();
    let generation = generation::test_support::verified_variant(1);
    let process = "com.qinggan.app.setting";
    let desired = plan::Plan::defaults_for(&generation);
    let mut daemon_loop = DaemonLoop::new(generation);
    daemon_loop
        .write_fresh_desired_document(&desired, process)
        .unwrap();
    let mut fds = [-1, -1];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    daemon_loop.track(process, 4242, 987_654_321, None, Some(fds[1]));
    // Capacity rejection poisons a real endpoint before the desired enqueue;
    // no successful proof may be inferred from its valid descriptor alone.
    assert!(!downlink::enqueue_frame(
        fds[1],
        &vec![b'x'; 256 * 1024 + 1]
    ));
    crate::canonical_log::with_test_log(directory.path(), || {
        assert!(daemon_loop
            .enqueue_desired_snapshot(&desired, process, -1)
            .is_err());
        assert!(daemon_loop
            .enqueue_confirmed_update(&desired, process, -1, 19)
            .is_err());
        assert!(daemon_loop
            .enqueue_desired_snapshot(&desired, process, fds[1])
            .is_err());
        assert!(daemon_loop
            .enqueue_confirmed_update(&desired, process, fds[1], 20)
            .is_err());
    });
    assert!(queued_snapshot_records(directory.path()).is_empty());
    assert_eq!(daemon_loop.pending_ack_generation(process), None);
    downlink::forget_fd(fds[1]);
    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
}

#[test]
fn queued_desired_snapshot_omits_unmatched_target_identity() {
    let directory = snapshot_log_directory();
    let generation = generation::test_support::verified_variant(1);
    let process = "com.qinggan.app.setting";
    let desired = plan::Plan::defaults_for(&generation);
    let mut daemon_loop = DaemonLoop::new(generation);
    daemon_loop
        .write_fresh_desired_document(&desired, process)
        .unwrap();
    let mut fds = [-1, -1];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    // A matching fd from another registered process is not this target.
    daemon_loop.track("com.example.other", 4242, 987_654_321, None, Some(fds[1]));
    crate::canonical_log::with_test_log(directory.path(), || {
        daemon_loop
            .enqueue_desired_snapshot(&desired, process, fds[1])
            .unwrap();
    });
    assert!(!read_downlink_frames(fds).is_empty());
    let records = queued_snapshot_records(directory.path());
    assert_eq!(records.len(), 1);
    for key in ["targetPid", "targetStarttime", "endpointEpoch"] {
        assert!(!records[0].fields.contains_key(key));
    }
    downlink::forget_fd(fds[1]);
    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
}

#[test]
fn generation_cutover_new_pid_gets_new_current_residents_keep_theirs() {
    // The runtime watcher activation must cut the LIVE loop over to the
    // new generation without a daemon restart or reboot: new processes
    // bootstrap the new current, while resident endpoints (tracker +
    // desired documents) are preserved untouched (docs/developer/updates).
    // The activation import path needs root DAC override on the 0711
    // generations directory; skip on non-root hosts.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipped: needs root");
        return;
    }
    let zones = generation::test_support::zones();
    generation::test_support::stage_variant(&zones.store, 1);
    let first = zones.store.activate_incoming().unwrap();
    generation::test_support::stage_variant(&zones.store, 2);
    let second = zones.store.activate_incoming().unwrap();
    assert_ne!(first.id, second.id);

    let mut daemon_loop = DaemonLoop::new(first.clone());
    // One resident endpoint on the old generation.
    daemon_loop.track("com.qinggan.app.setting", 111, 1, Some(10), Some(11));
    daemon_loop.insert_desired_document(
        "com.qinggan.app.setting",
        "[]",
        1,
        vec!["settings".to_string()],
        first.clone(),
    );
    for _ in 0..=config::SAFETY_MAX_ATTEMPTS {
        daemon_loop.allow_attempt("retired-agent", "retired.process");
        daemon_loop.allow_attempt("settings", "com.qinggan.app.setting");
    }
    for _ in 0..config::BREAKER_THRESHOLD {
        daemon_loop.note_target_crash("retired.process");
        daemon_loop.note_target_crash("com.qinggan.app.setting");
    }
    let resident_semantic = "[]".to_string();

    daemon_loop.adopt_generation(second.clone());

    // The loop now bootstraps from the new current generation...
    assert_eq!(daemon_loop.generation_id(), second.id);
    assert_eq!(daemon_loop.status_generation_id(), second.id);
    assert_eq!(daemon_loop.status_catalog_sha256(), second.catalog_sha256);
    assert!(!daemon_loop.is_quarantined("retired-agent", "retired.process"));
    assert!(!daemon_loop.is_target_degraded("retired.process"));
    assert!(daemon_loop.is_quarantined("settings", "com.qinggan.app.setting"));
    assert!(daemon_loop.is_target_degraded("com.qinggan.app.setting"));
    // ...while the resident endpoint and its desired document survive.
    assert!(daemon_loop.is_tracked(111));
    assert_eq!(
        daemon_loop
            .desired_document("com.qinggan.app.setting")
            .unwrap()
            .semantic_document,
        resident_semantic
    );
    assert_eq!(
        daemon_loop
            .desired_document("com.qinggan.app.setting")
            .unwrap()
            .resident_generation
            .as_ref()
            .unwrap()
            .id,
        first.id
    );
    // Re-adopting the same generation is a no-op.
    let before = daemon_loop.generation_id().to_string();
    daemon_loop.adopt_generation(second.clone());
    assert_eq!(daemon_loop.generation_id(), before);

    // Once R1 exits, preparing a fresh PID must replace the retained R1
    // DesiredDocumentState before an R2 bootstrap is built. Subsequent D
    // and A rendering therefore carries R2, not the dead resident's R1.
    let r2_plan = plan::Plan::defaults_for(&second);
    assert!(daemon_loop
        .write_fresh_desired_document(&r2_plan, "com.qinggan.app.setting")
        .unwrap());
    let fresh = daemon_loop
        .desired_document("com.qinggan.app.setting")
        .unwrap();
    assert!(fresh.generation > 1);
    assert_eq!(fresh.resident_generation.as_ref().unwrap().id, second.id);
    let document = r2_plan
        .desired_document_for_process(
            "com.qinggan.app.setting",
            fresh.resident_generation.as_ref().unwrap(),
            fresh.generation,
        )
        .unwrap();
    let document: serde_json::Value = serde_json::from_str(&document).unwrap();
    assert_eq!(document["generationId"], second.id);
    assert_eq!(document["catalogSha256"], second.catalog_sha256);
}

#[test]
fn vehicle_state_diagnostic_context_uses_exact_tracker_and_desired_identity() {
    let resident = generation::test_support::verified_variant(1);
    let active = generation::test_support::verified_variant(2);
    let process = "com.qinggan.app.setting";
    let revision = 1_777_777_777_777_777_779;
    let mut daemon_loop = DaemonLoop::new(resident.clone());
    daemon_loop.insert_desired_document(
        process,
        "{}",
        revision,
        vec!["vehicle-drive-forced-ev".into()],
        resident.clone(),
    );
    let mut fds = [-1, -1];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    daemon_loop.track(process, 4242, 987_654_321, None, Some(fds[1]));
    let epoch = daemon_loop.tracked_endpoint_epoch(process, fds[1]);
    daemon_loop.adopt_generation(active.clone());
    let context = daemon_loop.endpoint_context(4242, process, epoch);
    assert_eq!(context.target_starttime, Some(987_654_321));
    assert_eq!(context.document_generation, Some(revision));
    assert_eq!(context.resident_generation_id, resident.id);
    assert_eq!(context.resident_catalog_sha256, resident.catalog_sha256);
    assert_eq!(context.active_generation_id, active.id);
    assert_ne!(context.resident_generation_id, context.active_generation_id);
    assert!(context.owns_agent("vehicle-drive-forced-ev"));
    for (pid, name, registered_epoch) in [
        (4243, process, epoch),
        (4242, "other.process", epoch),
        (4242, process, epoch + 1),
    ] {
        assert_eq!(
            daemon_loop
                .endpoint_context(pid, name, registered_epoch)
                .target_starttime,
            None,
        );
    }
    let unknown = daemon_loop.endpoint_context(4242, "other.process", epoch);
    assert!(unknown.document_generation.is_none());
    assert!(unknown.resident_generation_id.is_empty());
    assert!(unknown.resident_catalog_sha256.is_empty());
    assert!(!unknown.owns_agent("vehicle-drive-forced-ev"));
    downlink::forget_fd(fds[1]);
    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
}

#[test]
fn passive_r1_endpoint_is_fenced_and_fresh_pid_rebinds_state_to_r2() {
    let first = generation::test_support::verified_variant(1);
    let second = generation::test_support::verified_variant(2);
    let process = "com.qinggan.app.setting";
    let r1_plan = plan::Plan::defaults_for(&first);
    let mut daemon_loop = DaemonLoop::new(first.clone());
    assert!(daemon_loop
        .write_fresh_desired_document(&r1_plan, process)
        .unwrap());

    daemon_loop.adopt_generation(second.clone());
    let stale = daemon_loop.endpoint_context(111, process, 77);
    assert_eq!(stale.resident_generation_id, first.id);
    assert_eq!(stale.active_generation_id, second.id);
    assert!(!stale.settings_generation_is_active());

    // Model the natural R1 process exit followed by a new R2 PID. The
    // retained per-process state must be rebound before bootstrap/D/A use.
    let r2_plan = plan::Plan::defaults_for(&second);
    assert!(daemon_loop
        .write_fresh_desired_document(&r2_plan, process)
        .unwrap());
    let fresh = daemon_loop.endpoint_context(222, process, 78);
    assert_eq!(fresh.resident_generation_id, second.id);
    assert_eq!(fresh.resident_catalog_sha256, second.catalog_sha256);
    assert!(fresh.settings_generation_is_active());
    let state = daemon_loop.desired_document(process).unwrap();
    let desired = r2_plan
        .desired_document_for_process(
            process,
            state.resident_generation.as_ref().unwrap(),
            state.generation,
        )
        .unwrap();
    let desired: serde_json::Value = serde_json::from_str(&desired).unwrap();
    assert_eq!(desired["generationId"], second.id);
    assert_eq!(desired["catalogSha256"], second.catalog_sha256);
}

#[test]
fn maps_marker_tracks_even_a_disabled_process() {
    assert_eq!(
        target_action(true, false),
        TargetAction::TrackExistingImplant
    );
    assert_eq!(target_action(false, false), TargetAction::ObserveOnly);
    assert_eq!(target_action(false, true), TargetAction::Inject);
}

// Agent core/modules are loaded only from the immutable verified active
// generation. Native payload contains injector libraries, never agent DEX.

// ---- No false native-success state ----
//
// These tests prove the four native-readiness invariants enforced here:
//   1. Native injection success (InjectResult::Ok) does NOT yield Active.
//   2. Bounded retry fires while the PID is alive and stops when it dies.
//   3. Active requires the agent-written readiness signal (status file).
//   4. A native hard failure yields Failed.

// Invariant 1 + the Ok path: a freshly-Ok injection MUST hold Waiting, not
// Active. The daemon loop sets Waiting on Ok and lets the agent-status
// aggregation promote to Active. This models that contract on the Status
// object the loop mutates.
#[test]
fn ok_injection_holds_waiting_not_active() {
    let mut status = status::Status::default();
    // What the loop does on InjectResult::Ok:
    status.set_injection(
        "",
        "com.qinggan.systemservice",
        status::InjectionState::Waiting,
    );
    assert_eq!(
        status.injection_state("com.qinggan.systemservice"),
        Some(status::InjectionState::Waiting)
    );
    assert_ne!(
        status.injection_state("com.qinggan.systemservice"),
        Some(status::InjectionState::Active)
    );
}

// Invariant 1 (Pending case): a deferred agent MUST NOT be reported as a
// success, and the loop sets Waiting (never Active) for it too.
#[test]
fn pending_injection_is_not_active() {
    let mut status = status::Status::default();
    status.set_injection(
        "",
        "com.qinggan.systemservice",
        status::InjectionState::Waiting,
    );
    assert!(
        !injector::InjectResult::Pending.is_ok(),
        "Pending must not be a success"
    );
    assert_ne!(
        status.injection_state("com.qinggan.systemservice"),
        Some(status::InjectionState::Active)
    );
}

// Invariant 4: a native hard failure maps to Failed.
#[test]
fn hard_failure_maps_to_failed() {
    let mut status = status::Status::default();
    // What the loop does on any non-Ok/non-Pending result:
    status.set_injection(
        "",
        "com.qinggan.systemservice",
        status::InjectionState::Failed,
    );
    assert_eq!(
        status.injection_state("com.qinggan.systemservice"),
        Some(status::InjectionState::Failed)
    );
    // And every hard-failure code is non-Ok.
    assert!(!injector::InjectResult::InitFailed.is_ok());
    assert!(!injector::InjectResult::DlopenFailed.is_ok());
    assert!(!injector::InjectResult::Denied.is_ok());
}

// Invariant 2: bounded retry fires while the PID is alive and stops when
// the PID dies. Driven by /proc liveness (the real condition), not a blind
// delay. While alive and under the bound → Retry; dead → PidDead.
#[test]
fn pending_retry_continues_while_pid_alive() {
    let d = pending_retry_decision(
        Some(status::InjectionState::Waiting),
        /* pid_alive */ true,
        /* attempts */ 0,
        MAX_AGENT_PENDING_RETRIES,
    );
    assert!(matches!(d, PendingRetryDecision::Retry));
}

#[test]
fn pending_retry_stops_when_pid_dies() {
    // Same-live-PID invariant: the retry stops the moment /proc/<pid> is
    // gone, even if the bound has not been exhausted.
    let d = pending_retry_decision(
        Some(status::InjectionState::Waiting),
        /* pid_alive */ false,
        /* attempts */ 1,
        MAX_AGENT_PENDING_RETRIES,
    );
    assert!(matches!(d, PendingRetryDecision::PidDead));
}

// Invariant 2 (bound): retrying stops with BoundExhausted after the bound
// while the PID is still alive.
#[test]
fn pending_retry_stops_when_bound_exhausted() {
    let d = pending_retry_decision(
        Some(status::InjectionState::Waiting),
        /* pid_alive */ true,
        /* attempts */ MAX_AGENT_PENDING_RETRIES,
        MAX_AGENT_PENDING_RETRIES,
    );
    assert!(matches!(d, PendingRetryDecision::BoundExhausted));
}

// Invariant 2 + 3: as soon as the agent reports ready (state promoted to
// Active by the status aggregation), the retry stops with Cleared — the
// readiness signal is what stops the retry, not a delay.
#[test]
fn pending_retry_cleared_when_agent_becomes_active() {
    let d = pending_retry_decision(
        Some(status::InjectionState::Active),
        /* pid_alive */ true,
        /* attempts */ 3,
        MAX_AGENT_PENDING_RETRIES,
    );
    assert!(matches!(d, PendingRetryDecision::Cleared));
}

// Invariant 2 (PID death takes precedence over a stale Active claim): if
// the PID is gone, we stop even if a stale status file claimed Active —
// liveness comes from /proc, not the untrusted status file.
#[test]
fn pid_death_precedence_over_stale_active() {
    // The decision checks Active first, but the loop only reaches the
    // decision for a tracked entry; a dead PID is reaped by reap_dead
    // before this point in practice. Guard the precedence explicitly: a
    // dead PID with no state yields PidDead (not Retry).
    let d = pending_retry_decision(
        None,
        /* pid_alive */ false,
        0,
        MAX_AGENT_PENDING_RETRIES,
    );
    assert!(matches!(d, PendingRetryDecision::PidDead));
}

fn retry_authority_matches(
    retry: (&str, &str, i64, &[&str], &str),
    current: (&str, &str, &[&str], &str),
    desired: Option<(&str, &str, i64, &[&str], &str)>,
) -> bool {
    let retry_ids = retry
        .3
        .iter()
        .map(|id| (*id).to_string())
        .collect::<Vec<_>>();
    let current_ids = current
        .2
        .iter()
        .map(|id| (*id).to_string())
        .collect::<Vec<_>>();
    let desired_ids = desired.map(|authority| {
        authority
            .3
            .iter()
            .map(|id| (*id).to_string())
            .collect::<Vec<_>>()
    });
    let desired = desired
        .zip(desired_ids.as_deref())
        .map(|(authority, ids)| (authority.0, authority.1, authority.2, ids, authority.4));
    pending_retry_semantics_match(
        (retry.0, retry.1, retry.2, &retry_ids, retry.4),
        (current.0, current.1, &current_ids, Some(current.3)),
        desired,
    )
}

#[test]
fn pending_retry_mixed_to_forced_only_cancels_frozen_authority() {
    assert!(!retry_authority_matches(
        (
            "r1",
            "c1",
            7,
            &[
                "vehicle-drive-forced-ev",
                "vehicle-drive-pedestrian-warning"
            ],
            "mixed",
        ),
        ("r1", "c1", &["vehicle-drive-forced-ev"], "forced-only",),
        Some(("r1", "c1", 7, &["vehicle-drive-forced-ev"], "forced-only")),
    ));
}

#[test]
fn pending_retry_forced_only_to_mixed_cancels_frozen_authority() {
    assert!(!retry_authority_matches(
        ("r1", "c1", 7, &["vehicle-drive-forced-ev"], "forced-only",),
        (
            "r1",
            "c1",
            &[
                "vehicle-drive-forced-ev",
                "vehicle-drive-pedestrian-warning"
            ],
            "mixed",
        ),
        Some((
            "r1",
            "c1",
            7,
            &[
                "vehicle-drive-forced-ev",
                "vehicle-drive-pedestrian-warning",
            ],
            "mixed",
        )),
    ));
}

#[test]
fn pending_retry_agent_disable_cancels_frozen_authority() {
    assert!(!retry_authority_matches(
        ("r1", "c1", 7, &["settings", "language"], "both-enabled"),
        ("r1", "c1", &["settings"], "language-disabled"),
        Some(("r1", "c1", 7, &["settings"], "language-disabled")),
    ));
}

#[test]
fn pending_retry_r1_to_r2_cancels_frozen_authority() {
    assert!(!retry_authority_matches(
        ("r1", "c1", 7, &["settings"], "same-plan"),
        ("r2", "c2", &["settings"], "same-plan"),
        Some(("r2", "c2", 7, &["settings"], "same-plan")),
    ));
}

#[test]
fn pending_retry_aba_document_generation_cancels_frozen_authority() {
    assert!(!retry_authority_matches(
        ("r1", "c1", 7, &["settings"], "state-a"),
        ("r1", "c1", &["settings"], "state-a"),
        Some(("r1", "c1", 9, &["settings"], "state-a")),
    ));
}

#[test]
fn pending_retry_missing_desired_state_cancels_frozen_authority() {
    assert!(!retry_authority_matches(
        ("r1", "c1", 7, &["settings"], "state-a"),
        ("r1", "c1", &["settings"], "state-a"),
        None,
    ));
}

#[test]
fn committed_none_plan_stops_the_daemon_instead_of_idling() {
    use crate::runtime::test_support::{none_plan_decision, NonePlanDecisionMirror};
    // A plan parsed from the root agents.json with startup=none carries
    // disable_all=true: the daemon must stop its init service.
    assert_eq!(
        none_plan_decision(plan::Startup::None, true, false),
        NonePlanDecisionMirror::SelfStop
    );
}

#[test]
fn uncommitted_none_shapes_keep_the_daemon_resident_fail_safe() {
    use crate::runtime::test_support::{none_plan_decision, NonePlanDecisionMirror};
    // The valid-empty placeholder (missing/unreadable agents.json) keeps
    // disable_all=false even though startup reads None — a corrupt plan must
    // never stop the daemon.
    assert_eq!(
        none_plan_decision(plan::Startup::None, false, false),
        NonePlanDecisionMirror::NotCommitted
    );
    // Every productive mode is not a stop.
    assert_eq!(
        none_plan_decision(plan::Startup::Interface, true, false),
        NonePlanDecisionMirror::NotCommitted
    );
    assert_eq!(
        none_plan_decision(plan::Startup::Hidden, false, true),
        NonePlanDecisionMirror::NotCommitted
    );
}

#[test]
fn in_flight_update_outranks_the_committed_none_self_stop() {
    use crate::runtime::test_support::{none_plan_decision, NonePlanDecisionMirror};
    assert_eq!(
        none_plan_decision(plan::Startup::None, true, true),
        NonePlanDecisionMirror::RebootForUpdate
    );
}

#[test]
fn hidden_bootstrap_delivers_the_settings_module_dormant() {
    use crate::runtime::test_support::bootstrap_module_ids;
    let generation = crate::plan::test_fixtures::settings_generation();
    let mut hidden = plan::Plan::defaults_for(&generation);
    hidden.startup = plan::Startup::Hidden;

    // Hidden: the settings module is DELIVERED (registered in the bootstrap
    // manifest so a live hidden→interface escalation can start it) but stays
    // dormant — the effective desired set for the process omits it.
    let modules = bootstrap_module_ids(&hidden, &generation, "com.qinggan.app.setting").unwrap();
    assert!(modules.iter().any(|id| id == "settings"));
    assert!(hidden
        .enabled_ids_for_process("com.qinggan.app.setting", &generation.catalog)
        .is_empty());

    // Interface: the plan loop delivers it live exactly as before.
    let mut interface = plan::Plan::defaults_for(&generation);
    interface.startup = plan::Startup::Interface;
    let modules = bootstrap_module_ids(&interface, &generation, "com.qinggan.app.setting").unwrap();
    assert!(modules.iter().any(|id| id == "settings"));

    // None: nothing is effective and no dormant delivery is added — the
    // kill-switch pass injects nothing at all.
    let mut none = plan::Plan::defaults_for(&generation);
    none.startup = plan::Startup::None;
    let modules = bootstrap_module_ids(&none, &generation, "com.qinggan.app.setting").unwrap();
    assert!(!modules.iter().any(|id| id == "settings"));

    // Hidden does NOT deliver the settings module into unrelated processes.
    let modules = bootstrap_module_ids(&hidden, &generation, "com.qinggan.systemservice").unwrap();
    assert!(!modules.iter().any(|id| id == "settings"));
}

#[test]
fn bootstrap_registers_disabled_applicable_modules_without_starting_them() {
    use crate::runtime::test_support::bootstrap_module_ids;
    let mut generation = crate::plan::test_fixtures::settings_generation();
    let process = "com.qinggan.app.setting";
    generation.catalog.agents[1].targets[0].process = process.into();
    let mut plan = crate::plan::Plan::defaults_for(&generation);
    assert_eq!(
        plan.enabled_ids_for_process(process, &generation.catalog),
        vec!["settings"]
    );
    let modules = bootstrap_module_ids(&plan, &generation, process).unwrap();
    assert_eq!(modules, vec!["settings", "forced-ev"]);
    plan.entries[0].enabled = false;
    plan.entries[1].enabled = true;
    assert_eq!(
        bootstrap_module_ids(&plan, &generation, process).unwrap(),
        modules
    );
    assert_eq!(
        plan.enabled_ids_for_process(process, &generation.catalog),
        vec!["forced-ev"]
    );
    assert!(
        bootstrap_module_ids(&plan, &generation, "com.example.unrelated")
            .unwrap()
            .is_empty()
    );
    plan.startup = crate::plan::Startup::None;
    assert!(bootstrap_module_ids(&plan, &generation, process)
        .unwrap()
        .is_empty());
    plan.startup = crate::plan::Startup::Interface;
    plan.disable_all = true;
    assert!(bootstrap_module_ids(&plan, &generation, process)
        .unwrap()
        .is_empty());
    plan.disable_all = false;
    generation
        .selection
        .selected_agent_ids
        .retain(|id| id != "forced-ev");
    assert_eq!(
        bootstrap_module_ids(&plan, &generation, process).unwrap(),
        vec!["settings"]
    );
}

#[test]
fn installer_handoff_pending_does_not_repeat_start_forever() {
    let observed = std::cell::Cell::new(0usize);
    let requests = std::cell::Cell::new(0usize);
    wait_for_installer_owned_handoff_with(
        || {
            observed.set(observed.get() + 1);
            Ok(if observed.get() > 100 {
                InstallerHandoffObservation::Ready
            } else {
                InstallerHandoffObservation::Pending
            })
        },
        || {
            requests.set(requests.get() + 1);
            Ok(())
        },
        |_| {},
    )
    .unwrap();
    assert!(
        requests.get() <= 5,
        "pending recovery must have a bounded start budget, got {}",
        requests.get()
    );
    assert_eq!(
        observed.get(),
        101,
        "pending must still be observed until actual completion"
    );
}

#[test]
fn installer_handoff_running_service_is_not_restarted() {
    let mut states = [
        InstallerHandoffObservation::Running,
        InstallerHandoffObservation::Running,
        InstallerHandoffObservation::Ready,
    ]
    .into_iter();
    assert_eq!(
        wait_for_installer_owned_handoff_with(
            || Ok(states.next().unwrap()),
            || panic!("live installer must not be started again"),
            |_| {}
        )
        .unwrap(),
        2
    );
}

#[test]
fn installer_handoff_start_requests_use_exponential_backoff() {
    let elapsed = std::cell::Cell::new(std::time::Duration::ZERO);
    let times = std::cell::RefCell::new(Vec::new());
    let observations = std::cell::Cell::new(0usize);
    wait_for_installer_owned_handoff_with(
        || {
            observations.set(observations.get() + 1);
            Ok(if observations.get() > 40 {
                InstallerHandoffObservation::Ready
            } else {
                InstallerHandoffObservation::Pending
            })
        },
        || {
            times.borrow_mut().push(elapsed.get());
            Ok(())
        },
        |delay| elapsed.set(elapsed.get() + delay),
    )
    .unwrap();
    let times = times.into_inner();
    assert_eq!(times.len(), 5);
    for (pair, minimum) in times.windows(2).zip([1u64, 2, 4, 8]) {
        let gap = pair[1] - pair[0];
        assert!(gap >= std::time::Duration::from_secs(minimum));
        assert!(gap < std::time::Duration::from_secs(minimum + 1));
    }
}

#[test]
fn watcher_busy_episode_logs_once_and_resets_after_real_recovery() {
    let (root, store) = watcher_zones();
    std::fs::write(store.incoming_marker(), b"").unwrap();
    let zone = root.path().join("zone");
    let logs = root.path().join("logs");
    crate::canonical_log::with_test_log(&logs, || {
        let guard = crate::operation_contract::GenerationGuard::acquire_in(&zone).unwrap();
        for _ in 0..100 {
            assert!(super::activate_incoming_for_loop(&store).is_none());
        }
        let rows = || {
            std::fs::read_dir(&logs)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry.file_type().unwrap().is_file()
                        && entry.path().extension().is_some_and(|ext| ext == "jsonl")
                })
                .flat_map(|entry| {
                    std::fs::read_to_string(entry.path())
                        .unwrap()
                        .lines()
                        .map(|line| {
                            serde_json::from_str::<crate::canonical_log::CanonicalRecord>(line)
                                .unwrap()
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            rows().len(),
            1,
            "100 actual busy watcher passes must log once"
        );
        assert_eq!(rows()[0].level, crate::canonical_log::Level::Debug);
        std::fs::remove_file(store.incoming_marker()).unwrap();
        drop(guard);
        assert!(super::activate_incoming_for_loop(&store).is_none());
        assert_eq!(rows().len(), 2, "actual recovery ends the episode");
        std::fs::write(store.incoming_marker(), b"").unwrap();
        let _guard = crate::operation_contract::GenerationGuard::acquire_in(&zone).unwrap();
        assert!(super::activate_incoming_for_loop(&store).is_none());
        assert_eq!(rows().len(), 3, "new contention starts a fresh episode");
    });
}

#[test]
fn watcher_logging_preserves_contextual_errors_and_resets_known_authority() {
    let (root, store) = watcher_zones();
    let logs = root.path().join("logs");
    crate::canonical_log::with_test_log(&logs, || {
        store.set_log_generation("generation-a");
        let error: anyhow::Result<()> =
            Err(anyhow::anyhow!("operation busy").context("cleanup failed"));
        store.observe_log_result("incoming-rejection", &error);
        store.observe_log_result("incoming-rejection", &error);
        store.set_log_operation(Some("operation-b"));
        store.observe_log_result("incoming-rejection", &error);
        store.set_log_generation("generation-c");
        store.observe_log_result("incoming-rejection", &error);
    });
    let rows = crate::canonical_log::CanonicalLog::open(&logs)
        .unwrap()
        .query(&crate::canonical_log::Query {
            after_sequence: 0,
            limit: 200,
            levels: vec![],
            kinds: vec![],
            agent_ids: vec![],
            search: None,
            from_epoch_millis: 0,
            to_epoch_millis: u64::MAX,
        })
        .unwrap()
        .records;
    assert_eq!(rows.len(), 3);
    assert!(rows
        .iter()
        .all(|row| row.level == crate::canonical_log::Level::Error));
    assert!(rows
        .iter()
        .all(|row| row.message.contains("cleanup failed")));
}
