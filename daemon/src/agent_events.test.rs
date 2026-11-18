use super::*;

#[test]
fn electric_click_decoder_is_closed_and_endpoint_bound() {
    let mut ctx = settings_ctx();
    ctx.process = "com.qinggan.app.vehiclesetting".into();
    ctx.target_starttime = Some(123);
    ctx.resident_agents.insert("vehicle-drive-forced-ev".into());
    ctx.agents.insert("vehicle-drive-forced-ev".into());
    let valid = "7|vehicle-drive-forced-ev|electric-click|click";
    assert_eq!(electric_click_request(valid, &ctx, true), Some((7, false)));
    for process in ["com.qinggan.app.launcher", "com.qinggan.app.hiboard"] {
        ctx.process = process.into();
        assert_eq!(electric_click_request(valid, &ctx, true), Some((7, false)));
    }
    ctx.process = "com.android.systemui".into();
    assert_eq!(electric_click_request(valid, &ctx, true), None);
    ctx.process = "com.qinggan.app.vehiclesetting".into();
    for bad in [
        "0|vehicle-drive-forced-ev|electric-click|click",
        "7|vehicle-drive-forced-ev|electric-click|5",
        "7|vehicle-drive-forced-ev|electric-click|click|5",
        "7|vehicle-drive-pedestrian-warning|electric-click|click",
        "7|vehicle-drive-forced-ev|other|click",
    ] {
        assert_eq!(electric_click_request(bad, &ctx, true), None);
    }
    assert_eq!(
        electric_click_request(
            "7|vehicle-drive-forced-ev|electric-click|cancel",
            &ctx,
            true
        ),
        Some((7, true))
    );
    assert_eq!(electric_click_request(valid, &ctx, false), None);
    ctx.active_generation_id = "other".into();
    assert_eq!(electric_click_request(valid, &ctx, true), None);
}

#[test]
fn electric_click_reuses_endpoint_replay_fence() {
    let mut cache = CommittedRequests::default();
    let fingerprint = "vehicle-drive-forced-ev|electric-click";
    assert_eq!(
        cache.classify(11, 10, fingerprint),
        RequestDisposition::Fresh
    );
    cache.remember(11, 10, fingerprint.into());
    assert_eq!(
        cache.classify(11, 10, fingerprint),
        RequestDisposition::Duplicate
    );
    assert_eq!(
        cache.classify(11, 10, "other"),
        RequestDisposition::Conflict
    );
    cache.remember(11, 12, fingerprint.into());
    assert_eq!(
        cache.classify(11, 11, fingerprint),
        RequestDisposition::StaleReplay
    );
    assert_eq!(
        cache.classify(12, 10, fingerprint),
        RequestDisposition::Fresh
    );
    cache.forget(11);
    assert_eq!(
        cache.classify(11, 10, fingerprint),
        RequestDisposition::Fresh
    );
}

#[test]
fn electric_dispatch_lost_reply_retries_as_poll_and_never_resubmits() {
    use voboost_contract::runtime_owner::{Command, ElectricClickStatus, Outcome};
    let mut ctx = settings_ctx();
    ctx.process = "com.qinggan.app.vehiclesetting".into();
    ctx.target_starttime = Some(123);
    ctx.resident_agents.insert("vehicle-drive-forced-ev".into());
    ctx.agents.insert("vehicle-drive-forced-ev".into());
    let mut cache = CommittedRequests::default();
    let line = "7|vehicle-drive-forced-ev|electric-click|click";
    let mut polls = Vec::new();
    let mut frames = Vec::new();
    for attempt in 0..2 {
        assert!(electric_click_route_with(
            line,
            &ctx,
            true,
            &mut cache,
            "11111111-1111-4111-8111-111111111111",
            |command| {
                let Command::ElectricClick {
                    input,
                    poll,
                    cancel,
                } = command
                else {
                    panic!("wrong command")
                };
                assert_eq!(input.endpoint_epoch, ctx.endpoint_epoch);
                assert_eq!(input.request_id, 7);
                assert!(!cancel);
                polls.push(poll);
                if attempt == 0 {
                    Err(std::io::ErrorKind::TimedOut.into())
                } else {
                    Ok(Outcome::ElectricClick {
                        result: ElectricClickStatus::Accepted,
                    })
                }
            },
            |frame| {
                frames.push(String::from_utf8(frame.to_vec()).unwrap());
                true
            }
        ));
    }
    assert_eq!(polls, vec![false, true]);
    assert!(frames[0].contains("unknown"));
    assert!(frames[1].contains("accepted"));
    assert!(!electric_click_route_with(
        "6|vehicle-drive-forced-ev|electric-click|click",
        &ctx,
        true,
        &mut cache,
        "11111111-1111-4111-8111-111111111111",
        |_| panic!("stale action must not reach owner"),
        |_| true
    ));
}

#[test]
fn electric_cancel_first_makes_late_click_a_poll() {
    use voboost_contract::runtime_owner::{Command, ElectricClickStatus, Outcome};
    let mut ctx = settings_ctx();
    ctx.process = "com.qinggan.app.vehiclesetting".into();
    ctx.target_starttime = Some(123);
    ctx.resident_agents.insert("vehicle-drive-forced-ev".into());
    ctx.agents.insert("vehicle-drive-forced-ev".into());
    let mut cache = CommittedRequests::default();
    let mut observed = Vec::new();
    for action in ["cancel", "click"] {
        let line = format!("7|vehicle-drive-forced-ev|electric-click|{action}");
        assert!(electric_click_route_with(
            &line,
            &ctx,
            true,
            &mut cache,
            "11111111-1111-4111-8111-111111111111",
            |command| {
                let Command::ElectricClick { poll, cancel, .. } = command else {
                    panic!("wrong command")
                };
                observed.push((poll, cancel));
                Ok(Outcome::ElectricClick {
                    result: ElectricClickStatus::NotSubmitted,
                })
            },
            |_| true
        ));
    }
    assert_eq!(observed, vec![(false, true), (true, false)]);
}

#[test]
fn electric_endpoint_teardown_retains_pending_identity_for_cancel() {
    use voboost_contract::runtime_owner::{ElectricClickStatus, Outcome};
    let mut ctx = settings_ctx();
    ctx.process = "com.qinggan.app.vehiclesetting".into();
    ctx.target_starttime = Some(123);
    ctx.resident_agents.insert("vehicle-drive-forced-ev".into());
    ctx.agents.insert("vehicle-drive-forced-ev".into());
    let mut cache = CommittedRequests::default();
    let boot = "11111111-1111-4111-8111-111111111111";
    assert!(electric_click_route_with(
        "7|vehicle-drive-forced-ev|electric-click|click",
        &ctx,
        true,
        &mut cache,
        boot,
        |_| Ok(Outcome::ElectricClick {
            result: ElectricClickStatus::Pending
        }),
        |_| true
    ));
    assert!(electric_click_route_with(
        "8|vehicle-drive-forced-ev|electric-click|click",
        &ctx,
        true,
        &mut cache,
        boot,
        |_| panic!("busy action must not reach owner"),
        |_| true
    ));
    assert_eq!(cache.forget(ctx.endpoint_epoch), Some(7));
    assert_eq!(cache.forget(ctx.endpoint_epoch), None);
}

#[test]
fn electric_route_keeps_uncertain_and_draining_work_until_explicit_drained() {
    use voboost_contract::runtime_owner::{ElectricClickStatus as Status, Outcome};
    for pending in [
        Status::Pending,
        Status::Draining,
        Status::Unknown,
        Status::Busy,
    ] {
        let mut ctx = settings_ctx();
        ctx.process = "com.qinggan.app.vehiclesetting".into();
        ctx.target_starttime = Some(123);
        ctx.resident_agents.insert("vehicle-drive-forced-ev".into());
        ctx.agents.insert("vehicle-drive-forced-ev".into());
        let mut cache = CommittedRequests::default();
        let boot = "11111111-1111-4111-8111-111111111111";
        for result in [pending, Status::Drained] {
            assert!(electric_click_route_with(
                "7|vehicle-drive-forced-ev|electric-click|click",
                &ctx,
                true,
                &mut cache,
                boot,
                |_| Ok(Outcome::ElectricClick { result }),
                |_| true
            ));
            assert_eq!(
                cache
                    .by_endpoint
                    .get(&ctx.endpoint_epoch)
                    .unwrap()
                    .electric_active,
                (result != Status::Drained).then_some(7)
            );
        }
    }
}

#[test]
fn mutation_lock_diagnostic_distinguishes_repeated_busy_from_failures() {
    let mut cache = DeferredRequests::default();
    assert_eq!(
        mutation_lock_diagnostic(&mut cache, 1, 7, "operation busy"),
        Some((false, "request 7 deferred: operation lock is busy".into()))
    );
    assert_eq!(
        mutation_lock_diagnostic(&mut cache, 1, 7, "operation busy"),
        None
    );
    for error in [
        "parse operation descriptor: malformed",
        "operation busy: terminal residue",
    ] {
        let expected = Some((true, format!("request 7 mutation lock failed: {error}")));
        assert_eq!(mutation_lock_diagnostic(&mut cache, 1, 7, error), expected);
        assert_eq!(mutation_lock_diagnostic(&mut cache, 1, 7, error), expected);
    }
}

#[test]
fn deferred_log_is_bounded_and_scoped_to_endpoint_request() {
    let mut cache = DeferredRequests::default();
    assert!(cache.first(1, 7));
    for _ in 0..13_002 {
        assert!(!cache.first(1, 7));
    }
    assert!(cache.first(1, 8));
    assert!(cache.first(2, 7));
    cache.forget_endpoint(1);
    assert!(cache.first(1, 7));
    for request in 0..MAX_RECENT_REQUESTS as u64 {
        cache.first(3, request);
    }
    assert!(cache.order.len() <= MAX_RECENT_REQUESTS);
    assert_eq!(cache.order.len(), cache.recent.len());
}

#[test]
fn global_locale_uses_authenticated_observation_without_plan_write_or_ack() {
    let _guard = global_locale::test_guard();
    let mut ctx = settings_ctx();
    ctx.log_generation = Some((
        ctx.resident_generation_id.clone(),
        ctx.resident_catalog_sha256.clone(),
    ));
    ctx.target_starttime = Some(123);
    ctx.document_generation = Some(7);
    ctx.resident_agents.insert("i18n-ru".into());
    ctx.agents.insert("i18n-ru".into());
    ctx.selected_agents.insert("i18n-ru".into());
    let payload = format!(
        r#"1|i18n-ru|global-locale|{{"schema":1,"generation":"{}","documentGeneration":7,"locale":"ru","observedAtBootMs":{}}}"#,
        ctx.resident_generation_id,
        global_locale::boot_ms().unwrap()
    );
    let route = |allowed| {
        route_events_at_with_writer(
            &payload,
            &ctx,
            None,
            std::path::Path::new("unused-observation-plan"),
            allowed,
            |_, _| panic!("observation must not mutate canonical intent"),
        )
    };
    assert_eq!(route(false), None);
    assert_eq!(route(true), Some(1));
    assert_eq!(
        global_locale::latest(&ctx).unwrap().language,
        global_locale::GlobalLanguage::Russian
    );
    assert!(!confirmed_pending()
        .lock()
        .unwrap()
        .values()
        .any(|pending| pending.endpoint_epoch == ctx.endpoint_epoch));
    forget_endpoint(ctx.endpoint_epoch);
}

fn settings_ctx() -> crate::agent_log::EndpointContext {
    // Each test thread owns one endpoint identity across retries. A shared
    // epoch also shared replay floors between unrelated parallel tests.
    thread_local! {
        static EPOCH: u64 = {
            static NEXT: std::sync::atomic::AtomicU64 =
                std::sync::atomic::AtomicU64::new(1_000_000);
            NEXT.fetch_add(1024, std::sync::atomic::Ordering::Relaxed)
        };
    }
    crate::agent_log::EndpointContext {
        owner_started: None,
        pid: 42,
        process: "com.qinggan.app.setting".to_string(),
        endpoint_epoch: EPOCH.with(|epoch| *epoch),
        log_generation: None,
        target_starttime: None,
        document_generation: None,
        restart_allowed: false,
        retiring_state: None,
        resident_agents: std::collections::HashSet::from(["settings".to_string()]),
        agents: std::collections::HashSet::from(["settings".to_string()]),
        selected_agents: std::collections::HashSet::from([
            "settings".to_string(),
            "vehicle-drive-forced-ev".to_string(),
            "vehicle-drive-outing".to_string(),
        ]),
        resident_generation_id: "generation".to_string(),
        resident_catalog_sha256: "catalog".to_string(),
        active_generation_id: "generation".to_string(),
        active_catalog_sha256: "catalog".to_string(),
        known_agents: HashMap::from([
            ("vehicle-drive-forced-ev".to_string(), Vec::new()),
            ("vehicle-drive-outing".to_string(), Vec::new()),
        ]),
        known_options: HashMap::from([(
            "vehicle-drive-outing".to_string(),
            HashMap::from([
                (
                    "exit-target".to_string(),
                    crate::agent_log::KnownOption {
                        option_type: "enum".to_string(),
                        values: std::collections::HashSet::from([
                            "comfort".to_string(),
                            "previous".to_string(),
                        ]),
                    },
                ),
                (
                    "above-speed".to_string(),
                    crate::agent_log::KnownOption {
                        option_type: "enum".to_string(),
                        values: std::collections::HashSet::from([
                            "exit".to_string(),
                            "keep".to_string(),
                        ]),
                    },
                ),
            ]),
        )]),
        startup_escalation_sources: std::collections::HashSet::from(["ui-qinggan".to_string()]),
    }
}

#[test]
fn language_mutations_are_rejected_without_changing_canonical_intent() {
    use std::os::unix::fs::PermissionsExt;
    let mut ctx = settings_ctx();
    ctx.known_agents.insert("settings".to_string(), Vec::new());
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = dir.path().join("agents.json");
    let before = br#"{"schemaVersion":1,"startup":"interface","agents":{"settings":{"enabled":true,"options":{}}}}"#;
    fs::write(&path, before).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    for invalid in [
        "2101001|settings|radio|voboost-language:zh-CN",
        "2101002|other|radio|voboost-language:zh",
    ] {
        assert_eq!(route_events_at(invalid, &ctx, Some(9), &path), None);
        assert_eq!(fs::read(&path).unwrap(), before);
    }
    for locale in ["en", "zh", "ru", "de", "zh-CN"] {
        assert_eq!(
            route_events_at(
                &format!("2101003|settings|radio|voboost-language:{locale}"),
                &ctx,
                Some(9),
                &path
            ),
            None
        );
        assert_eq!(fs::read(&path).unwrap(), before);
    }
}

#[test]
fn restart_wire_requires_bound_removal_before_queuing_correlated_ack() {
    let mut ctx = settings_ctx();
    ctx.pid = ctx.endpoint_epoch as i32;
    ctx.target_starttime = Some(7001);
    ctx.document_generation = Some(12);
    let wire = "1|runtime|restart|process:12";
    assert_eq!(route_events(wire, &ctx, Some(9), false), None);
    ctx.restart_allowed = true;
    assert_eq!(route_events(wire, &ctx, None, false), None);
    assert_eq!(
        route_events("1|runtime|restart|process:11", &ctx, Some(9), false),
        None
    );
    assert_eq!(route_events(wire, &ctx, Some(9), false), Some(1));
    assert_eq!(route_events(wire, &ctx, Some(9), false), Some(1));
    assert_eq!(
        route_events("1|runtime|restart|process:13", &ctx, Some(9), false),
        None
    );
    assert!(crate::process_restart::consume_death(ctx.pid, &ctx.process));
    assert_eq!(route_events(wire, &ctx, Some(9), false), None);
    forget_endpoint(ctx.endpoint_epoch);
}

fn take_target(endpoint_epoch: u64) -> ConfirmedTarget {
    confirmed_pending()
        .lock()
        .unwrap()
        .remove(&(endpoint_epoch, ConfirmationKind::Mutation))
        .unwrap()
}

#[test]
fn restart_confirmation_cannot_replace_the_user_mutation_ack() {
    let ctx = settings_ctx();
    mark_confirmed_pending(&ctx, 31, 41);
    mark_confirmation(&ctx, 31, 42, ConfirmationKind::Restart);
    assert_eq!(take_target(ctx.endpoint_epoch).request_id, 41);
    let restart = confirmed_pending()
        .lock()
        .unwrap()
        .remove(&(ctx.endpoint_epoch, ConfirmationKind::Restart))
        .unwrap();
    assert_eq!(restart.request_id, 42);
    mark_confirmed_pending(&ctx, 31, 43);
    assert!(retry_confirmed_pending(restart));
    assert_eq!(take_target(ctx.endpoint_epoch).request_id, 43);
    assert_eq!(
        confirmed_pending()
            .lock()
            .unwrap()
            .remove(&(ctx.endpoint_epoch, ConfirmationKind::Restart))
            .unwrap()
            .request_id,
        42
    );
    forget_endpoint(ctx.endpoint_epoch);
}

#[test]
fn malformed_and_untrusted_events_fail_closed() {
    assert_eq!(
        route_events(
            "bad|settings|checkbox|x:true",
            &settings_ctx(),
            Some(9),
            true
        ),
        None
    );
    assert_eq!(
        route_events("1|other|checkbox|x:true", &settings_ctx(), Some(9), true),
        None
    );
    assert_eq!(
        route_events(
            "2|settings|checkbox|x:maybe",
            &settings_ctx(),
            Some(9),
            true
        ),
        None
    );
    assert_eq!(
        route_events(
            "3|settings|radio|voboost-language:de",
            &settings_ctx(),
            Some(9),
            true,
        ),
        None
    );
}

#[test]
fn uninstall_start_discards_preexisting_confirmations() {
    let target = ConfirmedTarget {
        endpoint_epoch: 93_002,
        process: "settings".to_string(),
        fd: 62,
        request_id: 45,
        kind: ConfirmationKind::Mutation,
        first_pending_at: Instant::now(),
        failed_attempts: 0,
    };
    let mut pending = HashMap::from([((target.endpoint_epoch, target.kind), target)]);
    assert_eq!(discard_confirmed_map(&mut pending), 1);
    assert!(pending.is_empty());
}

#[test]
fn independent_fixture_threads_do_not_share_replay_floors() {
    let first = std::thread::spawn(|| {
        let epoch = settings_ctx().endpoint_epoch;
        assert_eq!(epoch, settings_ctx().endpoint_epoch);
        epoch
    })
    .join()
    .unwrap();
    let second = std::thread::spawn(|| settings_ctx().endpoint_epoch)
        .join()
        .unwrap();
    let mut cache = CommittedRequests::default();
    cache.remember(first, 100, "checkbox|vehicle-drive-forced-ev:true".into());
    assert_eq!(
        cache.classify(second, 8, "checkbox|vehicle-drive-forced-ev:true"),
        RequestDisposition::Fresh
    );
}

#[test]
fn committed_cache_is_duplicate_only_after_remember() {
    let mut cache = CommittedRequests::default();
    assert_eq!(cache.classify(11, 7, "a"), RequestDisposition::Fresh);
    cache.remember(11, 7, "a".to_string());
    assert_eq!(cache.classify(11, 7, "a"), RequestDisposition::Duplicate);
    assert_eq!(cache.classify(11, 7, "b"), RequestDisposition::Conflict);
    assert_eq!(cache.classify(11, 6, "a"), RequestDisposition::StaleReplay);
    assert_eq!(cache.classify(11, 8, "a"), RequestDisposition::Fresh);
    assert_eq!(cache.classify(12, 7, "a"), RequestDisposition::Fresh);
}

#[test]
fn committed_cache_is_endpoint_scoped_and_cleared_on_teardown() {
    let mut cache = CommittedRequests::default();
    cache.remember(21, 9, "a".to_string());
    cache.remember(22, 4, "b".to_string());
    assert_eq!(cache.classify(21, 8, "a"), RequestDisposition::StaleReplay);
    assert_eq!(cache.classify(22, 5, "b"), RequestDisposition::Fresh);
    cache.forget(21);
    assert_eq!(cache.classify(21, 9, "a"), RequestDisposition::Fresh);
    assert_eq!(cache.classify(22, 4, "b"), RequestDisposition::Duplicate);
}

#[test]
fn evicted_request_ids_remain_rejected_by_high_watermark() {
    let mut cache = CommittedRequests::default();
    for id in 1..=(MAX_RECENT_REQUESTS as u64 + 1) {
        cache.remember(31, id, format!("mutation-{id}"));
    }
    assert_eq!(
        cache.classify(31, 1, "mutation-1"),
        RequestDisposition::StaleReplay
    );
}

#[test]
fn mutation_ack_targets_coalesce_monotonically_per_endpoint() {
    let mut ctx = settings_ctx();
    ctx.endpoint_epoch = 9_001;
    mark_confirmed_pending(&ctx, 31, 10);
    mark_confirmed_pending(&ctx, 31, 12);
    mark_confirmed_pending(&ctx, 31, 11);
    let target = confirmed_pending()
        .lock()
        .unwrap()
        .remove(&(ctx.endpoint_epoch, ConfirmationKind::Mutation))
        .unwrap();
    assert_eq!(target.request_id, 12);
    assert_eq!(target.fd, 31);
}

#[test]
fn failed_ack_delivery_is_retried_then_renders_latest_correlated_frame() {
    let mut ctx = settings_ctx();
    ctx.endpoint_epoch = 9_003;
    mark_confirmed_pending(&ctx, 33, 10);
    mark_confirmed_pending(&ctx, 33, 11);

    let first_attempt = take_target(ctx.endpoint_epoch);
    assert_eq!(first_attempt.request_id, 11);
    assert!(retry_confirmed_pending(first_attempt));

    let successful_attempt = take_target(ctx.endpoint_epoch);
    assert_eq!(successful_attempt.request_id, 11);
    assert_eq!(successful_attempt.failed_attempts, 1);
    assert_eq!(
        crate::runtime::render_mutation_ack_frame(successful_attempt.request_id, "{}"),
        Ok(b"A|11|{}\n".to_vec())
    );
    // A successful enqueue does not requeue the target.
    assert!(!confirmed_pending()
        .lock()
        .unwrap()
        .contains_key(&(ctx.endpoint_epoch, ConfirmationKind::Mutation)));
}

#[test]
fn newer_ack_supersedes_an_older_delivery_being_retried() {
    let mut ctx = settings_ctx();
    ctx.endpoint_epoch = 9_004;
    mark_confirmed_pending(&ctx, 34, 20);
    let older = take_target(ctx.endpoint_epoch);
    mark_confirmed_pending(&ctx, 34, 21);
    assert!(retry_confirmed_pending(older));

    let pending = take_target(ctx.endpoint_epoch);
    assert_eq!(pending.request_id, 21);
    assert_eq!(pending.failed_attempts, 0);
}

#[test]
fn ack_retry_budget_and_lifetime_are_bounded() {
    let mut ctx = settings_ctx();
    ctx.endpoint_epoch = 9_005;
    mark_confirmed_pending(&ctx, 35, 30);
    let mut target = take_target(ctx.endpoint_epoch);
    target.failed_attempts = MAX_CONFIRMATION_RETRY_ATTEMPTS - 1;
    assert!(!retry_confirmed_pending(target));

    mark_confirmed_pending(&ctx, 35, 31);
    let mut expired = take_target(ctx.endpoint_epoch);
    expired.first_pending_at =
        Instant::now() - MAX_CONFIRMATION_RETRY_AGE - Duration::from_millis(1);
    assert!(!retry_confirmed_pending(expired));
    assert!(!confirmed_pending()
        .lock()
        .unwrap()
        .contains_key(&(ctx.endpoint_epoch, ConfirmationKind::Mutation)));
}

#[test]
fn endpoint_teardown_clears_pending_mutation_ack() {
    let mut ctx = settings_ctx();
    ctx.endpoint_epoch = 9_002;
    mark_confirmed_pending(&ctx, 32, 20);
    forget_endpoint(ctx.endpoint_epoch);
    assert!(!confirmed_pending()
        .lock()
        .unwrap()
        .contains_key(&(ctx.endpoint_epoch, ConfirmationKind::Mutation)));
}

#[test]
fn validate_document_rejects_hostile_shapes() {
    let valid: Value = serde_json::json!({
        "schemaVersion": 1,
        "startup": "interface",
        "agents": {
            "vehicle-drive-forced-ev": {"enabled": true, "options": {}}
        }
    });
    assert!(validate_document(&valid).is_some());

    let wrong_schema = serde_json::json!({
        "schemaVersion": 0,
        "startup": "interface",
        "agents": {}
    });
    assert!(validate_document(&wrong_schema).is_none());

    let extra_field = serde_json::json!({
        "schemaVersion": 1,
        "startup": "interface",
        "agents": {},
        "revision": 9
    });
    assert!(validate_document(&extra_field).is_none());

    let bad_startup = serde_json::json!({
        "schemaVersion": 1,
        "startup": "always",
        "agents": {}
    });
    assert!(validate_document(&bad_startup).is_none());

    let bad_entry = serde_json::json!({
        "schemaVersion": 1,
        "startup": "interface",
        "agents": {"a": {"enabled": "yes", "options": {}}}
    });
    assert!(validate_document(&bad_entry).is_none());

    let bad_id = serde_json::json!({
        "schemaVersion": 1,
        "startup": "interface",
        "agents": {"Bad_Id": {"enabled": true, "options": {}}}
    });
    assert!(validate_document(&bad_id).is_none());
}

#[test]
fn enabling_agent_atomically_disables_conflicts() {
    let mut document = serde_json::json!({
        "keyboard-en": {"enabled": false, "options": {}},
        "keyboard-ru": {"enabled": true, "options": {}}
    });
    let agents = document.as_object_mut().unwrap();
    apply_checkbox_mutation(agents, "keyboard-en", true, &["keyboard-ru".to_string()]).unwrap();
    assert_eq!(agents["keyboard-en"]["enabled"], Value::Bool(true));
    assert_eq!(agents["keyboard-ru"]["enabled"], Value::Bool(false));
}

/// The hidden-mode settings-process endpoint: the settings agent is NOT
/// resident (that is the whole point of hidden), only the ui-qinggan
/// executor is injected and therefore carries the escalation authority.
fn hidden_settings_endpoint_ctx() -> crate::agent_log::EndpointContext {
    crate::agent_log::EndpointContext {
        owner_started: None,
        pid: 42,
        process: "com.qinggan.app.setting".to_string(),
        endpoint_epoch: settings_ctx().endpoint_epoch,
        log_generation: None,
        target_starttime: Some(100),
        document_generation: None,
        restart_allowed: false,
        retiring_state: None,
        resident_agents: std::collections::HashSet::new(),
        agents: std::collections::HashSet::new(),
        selected_agents: std::collections::HashSet::from([
            "settings".to_string(),
            "vehicle-drive-forced-ev".to_string(),
        ]),
        resident_generation_id: "generation".to_string(),
        resident_catalog_sha256: "catalog".to_string(),
        active_generation_id: "generation".to_string(),
        active_catalog_sha256: "catalog".to_string(),
        known_agents: HashMap::from([
            ("settings".to_string(), Vec::new()),
            ("vehicle-drive-forced-ev".to_string(), Vec::new()),
        ]),
        known_options: HashMap::new(),
        startup_escalation_sources: std::collections::HashSet::from(["ui-qinggan".to_string()]),
    }
}

fn temp_plan_dir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

#[test]
fn startup_escalation_commits_hidden_to_interface_from_the_gesture_executor() {
    let ctx = hidden_settings_endpoint_ctx();
    let mut config = voboost_contract::desired::Config::new("hidden", Default::default()).unwrap();
    let (result, receipts) = desired_event(
        "31|ui-qinggan|radio|voboost-startup:interface",
        &ctx,
        &mut config,
        true,
    );
    assert_eq!(result, Some(Some(1)));
    assert_eq!(config.startup, "interface");
    assert_eq!(receipts[0]["value"], "interface");
    assert_eq!(receipts[0]["userRevision"], 1);
    assert_eq!(take_target(ctx.endpoint_epoch).request_id, 31);
}

#[test]
fn startup_escalation_fails_closed_for_every_foreign_shape() {
    let ctx = hidden_settings_endpoint_ctx();
    for line in [
        "41|ui-qinggan|radio|voboost-startup:none",
        "42|ui-qinggan|radio|voboost-startup:hidden",
        "43|some-agent|radio|voboost-startup:interface",
        "44|ui-qinggan|radio|foreign:interface",
    ] {
        assert_eq!(
            desired::route_with(
                line,
                &ctx,
                Some(71),
                DESIRED_BOOT,
                |_| panic!("foreign recovery reached owner: {line}"),
                |_, _| panic!("foreign recovery emitted Saved")
            ),
            Some(None)
        );
    }
    let mut foreign = ctx.clone();
    foreign.process = "com.qinggan.media".into();
    foreign.startup_escalation_sources.clear();
    assert_eq!(
        desired::route_with(
            "45|ui-qinggan|radio|voboost-startup:interface",
            &foreign,
            Some(71),
            DESIRED_BOOT,
            |_| panic!("endpoint without recovery authority reached owner"),
            |_, _| panic!("endpoint without recovery authority emitted Saved")
        ),
        Some(None)
    );
    // The owner, rather than the wire adapter, rejects an obsolete recovery endpoint.
    assert_eq!(
        desired::route_with(
            "46|ui-qinggan|radio|voboost-startup:interface",
            &ctx,
            Some(71),
            DESIRED_BOOT,
            |command| {
                assert!(matches!(
                    command,
                    voboost_contract::runtime_owner::Command::SaveStartupRecovery { .. }
                ));
                Err(std::io::Error::other(
                    "current startup none rejects recovery",
                ))
            },
            |_, _| panic!("rejected recovery emitted Saved")
        ),
        Some(None)
    );
    assert!(!confirmed_pending()
        .lock()
        .unwrap()
        .contains_key(&(ctx.endpoint_epoch, ConfirmationKind::Mutation)));
}

#[test]
fn startup_escalation_is_idempotent_when_interface_is_already_committed() {
    let ctx = hidden_settings_endpoint_ctx();
    let mut config = desired_config();
    let wire = "51|ui-qinggan|radio|voboost-startup:interface";
    let (result, first) = desired_event(wire, &ctx, &mut config, true);
    assert_eq!(result, Some(Some(1)));
    let revision = config.user_revision;
    let (result, retry) = desired_event(wire, &ctx, &mut config, true);
    assert_eq!(result, Some(Some(1)));
    assert_eq!(config.startup, "interface");
    assert_eq!(config.user_revision, revision);
    assert_eq!(retry[0]["disposition"], "replayed");
    assert_eq!(retry[0]["requestId"], first[0]["requestId"]);
    assert_eq!(retry[0]["userRevision"], first[0]["userRevision"]);
    assert_eq!(take_target(ctx.endpoint_epoch).request_id, 51);
}

#[test]
fn semantic_commands_require_current_can_service_residency_before_canonical_mutation() {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    let (writer, mut reader) = UnixStream::pair().unwrap();
    let source = "vehicle-drive-forced-ev";
    let mut valid = settings_ctx();
    valid.process = "com.qinggan.canbus.service".into();
    valid.resident_agents = std::collections::HashSet::from([source.into()]);
    let line = format!(
        "7|{source}|vehicle-command|command:{{\"operation\":\"ready\",\"available\":true}}"
    );
    for variant in 0..5 {
        let mut ctx = valid.clone();
        match variant {
            0 => ctx.process = "com.qinggan.systemservice".into(),
            1 => ctx.resident_agents.clear(),
            2 => ctx.known_agents.clear(),
            3 => ctx.active_generation_id = "newer".into(),
            _ => {}
        }
        assert_eq!(
            route_events_at_with_writer(
                &line,
                &ctx,
                Some(writer.as_raw_fd()),
                std::path::Path::new("/data/voboost/agents.json"),
                variant != 4,
                |_, _| panic!("semantic transport must never mutate canonical options")
            ),
            None
        );
    }
    reader.set_nonblocking(true).unwrap();
    let mut byte = [0];
    assert!(
        matches!(reader.read(&mut byte),Err(error) if error.kind()==std::io::ErrorKind::WouldBlock)
    );
    crate::downlink::forget_fd(writer.as_raw_fd());
}

#[test]
fn semantic_command_errors_use_only_the_typed_v_channel() {
    use std::io::BufRead;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    let (writer, reader) = UnixStream::pair().unwrap();
    reader
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut ctx = settings_ctx();
    ctx.process = "com.qinggan.canbus.service".into();
    ctx.resident_agents = std::collections::HashSet::from(["vehicle-drive-forced-ev".into()]);
    assert_eq!(
        route_events_at_with_writer(
            "7|vehicle-drive-forced-ev|vehicle-command|command:invalid",
            &ctx,
            Some(writer.as_raw_fd()),
            std::path::Path::new("/data/voboost/agents.json"),
            true,
            |_, _| panic!("semantic command routing must never write canonical options")
        ),
        Some(1)
    );
    let mut line = String::new();
    std::io::BufReader::new(reader)
        .read_line(&mut line)
        .unwrap();
    assert!(line.starts_with("V|vehicle-drive-forced-ev|7|"));
    let value: Value =
        serde_json::from_str(line.trim_end().splitn(4, '|').nth(3).unwrap()).unwrap();
    assert_eq!(value, serde_json::json!({"status":"unavailable"}));
    assert!(!line.starts_with("A|"));
    crate::downlink::forget_fd(writer.as_raw_fd());
}

const DESIRED_BOOT: &str = "11111111-1111-4111-8111-111111111111";

fn desired_ctx() -> crate::agent_log::EndpointContext {
    let mut ctx = settings_ctx();
    ctx.target_starttime = Some(100);
    ctx
}

fn desired_config() -> voboost_contract::desired::Config {
    voboost_contract::desired::Config::new("interface", Default::default()).unwrap()
}

/// Use the production shared authority engine; this seam proves wire adaptation, not disk I/O.
fn desired_event(
    line: &str,
    ctx: &crate::agent_log::EndpointContext,
    config: &mut voboost_contract::desired::Config,
    deliver: bool,
) -> (Option<Option<usize>>, Vec<Value>) {
    use voboost_contract::desired::Disposition;
    use voboost_contract::runtime_owner::{Command, Outcome};
    let mut receipts: Vec<Value> = Vec::new();
    let mut owned_receipts = 0;
    let result = desired::route_with(
        line,
        ctx,
        Some(71),
        DESIRED_BOOT,
        |command| {
            let disposition = match command {
                Command::SaveDesired {
                    field,
                    value,
                    mut input,
                } => {
                    assert_eq!(input.boot_id, DESIRED_BOOT);
                    assert_eq!(input.endpoint_epoch, ctx.endpoint_epoch);
                    assert_eq!(input.injector_pid, 0);
                    assert_eq!(input.injector_starttime, 0);
                    // The authenticated owner binds these values on the real IPC path.
                    input.injector_pid = 42;
                    input.injector_starttime = 100;
                    config.save(DESIRED_BOOT, &field, &value, &input, &[])?
                }
                Command::SaveStartupRecovery { mut input } => {
                    assert!(line.contains("|ui-qinggan|radio|voboost-startup:interface"));
                    assert!(ctx.startup_escalation_allowed("ui-qinggan"));
                    assert_eq!(input.boot_id, DESIRED_BOOT);
                    assert_eq!(input.endpoint_epoch, ctx.endpoint_epoch);
                    assert_eq!(
                        input.request_id,
                        line.split('|').next().unwrap().parse::<u64>().unwrap()
                    );
                    assert_eq!(input.injector_pid, 0);
                    assert_eq!(input.injector_starttime, 0);
                    input.injector_pid = 42;
                    input.injector_starttime = 100;
                    config.save(
                        DESIRED_BOOT,
                        &voboost_contract::desired::Field::Startup,
                        &"interface".into(),
                        &input,
                        &[],
                    )?
                }
                Command::ReadDesired { .. } => Disposition::Replayed,
                _ => panic!("ordinary user event must use the desired authority lane"),
            };
            Ok(Outcome::DesiredSaved {
                revision: config.user_revision,
                config: serde_json::to_string(config).unwrap(),
                disposition,
            })
        },
        |fd, frame| {
            assert_eq!(fd, 71);
            let frame = std::str::from_utf8(frame).unwrap();
            assert!(frame.ends_with('\n'));
            if frame.starts_with("I|") {
                let wire: Vec<_> = line.splitn(4, '|').collect();
                assert_eq!(wire[2], "owned-intent");
                let (choice, capture) = wire[3].split_once(':').unwrap().1.split_once('@').unwrap();
                assert!(capture.parse::<u64>().unwrap() > 0);
                let receipt = receipts.last().expect("owned receipt must follow Saved U");
                let status = if receipt["disposition"] == "superseded" {
                    "superseded"
                } else {
                    "committed"
                };
                assert_eq!(
                    frame,
                    format!(
                        "I|{}|{}|{}|{}|{}\n",
                        wire[1], wire[0], capture, choice, status
                    )
                );
                owned_receipts += 1;
                return deliver;
            }
            let mut parts = frame.trim_end().splitn(3, '|');
            assert_eq!(parts.next(), Some("U"));
            let request: u64 = parts.next().unwrap().parse().unwrap();
            let receipt: Value = serde_json::from_str(parts.next().unwrap()).unwrap();
            assert_eq!(receipt["requestId"], request);
            receipts.push(receipt);
            deliver
        },
    );
    if result == Some(Some(1)) && line.split('|').nth(2) == Some("owned-intent") {
        assert_eq!(owned_receipts, 1);
    } else {
        assert_eq!(owned_receipts, 0);
    }
    (result, receipts)
}

#[test]
fn ordinary_checkbox_saves_and_reports_the_owner_revision() {
    let ctx = desired_ctx();
    let mut config = desired_config();
    let (result, receipts) = desired_event(
        "8|settings|checkbox|vehicle-drive-forced-ev:false",
        &ctx,
        &mut config,
        true,
    );
    assert_eq!(result, Some(Some(1)));
    assert_eq!(
        receipts,
        vec![serde_json::json!({"requestId":8,"userRevision":1,
            "disposition":"saved","field":{"kind":"enabled","agent":"vehicle-drive-forced-ev"},"value":false})]
    );
    assert!(!config.agents["vehicle-drive-forced-ev"].enabled);
    assert_eq!(take_target(ctx.endpoint_epoch).request_id, 8);
}

#[test]
fn ordinary_desired_event_is_independent_of_product_lock_and_generation() {
    let dir = temp_plan_dir();
    let _guard = mutation_lock_at(dir.path()).unwrap();
    let mut ctx = desired_ctx();
    ctx.active_generation_id = "replacement".into();
    ctx.known_agents.clear();
    ctx.known_options.clear();
    let mut config = desired_config();
    let (result, receipts) = desired_event(
        "7|settings|checkbox|unsupported-agent:false",
        &ctx,
        &mut config,
        true,
    );
    assert_eq!(result, Some(Some(1)));
    assert_eq!(receipts[0]["value"], false);
    assert!(!config.agents["unsupported-agent"].enabled);
    assert_eq!(config.user_revision, 1);
    take_target(ctx.endpoint_epoch);
}

#[test]
fn independent_fields_do_not_share_the_legacy_request_high_watermark() {
    let ctx = desired_ctx();
    committed_requests()
        .lock()
        .unwrap()
        .remember(ctx.endpoint_epoch, 900, "restart".into());
    let mut config = desired_config();
    for line in [
        "900|settings|checkbox|launcher:false",
        "7|settings|checkbox|keyboard-ru:false",
    ] {
        assert_eq!(
            desired_event(line, &ctx, &mut config, true).0,
            Some(Some(1))
        );
    }
    assert_eq!(config.user_revision, 2);
    assert!(!config.agents["launcher"].enabled);
    assert!(!config.agents["keyboard-ru"].enabled);
    forget_endpoint(ctx.endpoint_epoch);
}

#[test]
fn late_same_origin_on_reports_current_off_as_superseded() {
    let ctx = desired_ctx();
    let mut config = desired_config();
    desired_event(
        "8|settings|checkbox|launcher:false",
        &ctx,
        &mut config,
        true,
    );
    let (result, receipts) =
        desired_event("7|settings|checkbox|launcher:true", &ctx, &mut config, true);
    assert_eq!(result, Some(Some(1)));
    assert_eq!(receipts[0]["disposition"], "superseded");
    assert_eq!(receipts[0]["value"], false);
    assert_eq!(receipts[0]["userRevision"], 1);
    assert!(!config.agents["launcher"].enabled);
    take_target(ctx.endpoint_epoch);
}

#[test]
fn lost_saved_receipt_is_recovered_by_read_without_another_mutation() {
    let ctx = desired_ctx();
    let mut config = desired_config();
    assert_eq!(
        desired_event(
            "8|settings|checkbox|launcher:false",
            &ctx,
            &mut config,
            false
        )
        .0,
        Some(None)
    );
    assert!(!confirmed_pending()
        .lock()
        .unwrap()
        .contains_key(&(ctx.endpoint_epoch, ConfirmationKind::Mutation)));
    let (result, receipts) = desired_event(
        "9|settings|desired-read|field:{\"kind\":\"enabled\",\"agent\":\"launcher\"}",
        &ctx,
        &mut config,
        true,
    );
    assert_eq!(result, Some(Some(1)));
    assert_eq!(receipts[0]["userRevision"], 1);
    assert_eq!(receipts[0]["disposition"], "replayed");
    assert_eq!(receipts[0]["value"], false);
    assert_eq!(config.user_revision, 1);
    assert!(!confirmed_pending()
        .lock()
        .unwrap()
        .contains_key(&(ctx.endpoint_epoch, ConfirmationKind::Mutation)));
}

#[test]
fn startup_none_routes_as_saved_without_creating_a_session_fence() {
    let ctx = desired_ctx();
    let mut config = desired_config();
    let (result, receipts) = desired_event(
        "10|settings|radio|voboost-startup:none",
        &ctx,
        &mut config,
        true,
    );
    assert_eq!(result, Some(Some(1)));
    assert_eq!(config.startup, "none");
    assert_eq!(receipts[0]["field"], serde_json::json!({"kind":"startup"}));
    assert_eq!(receipts[0]["value"], "none");
    take_target(ctx.endpoint_epoch);
}

#[test]
fn resident_option_and_owned_intent_use_the_same_saved_lane() {
    for source in [
        "vehicle-drive-forced-ev",
        "vehicle-drive-pedestrian-warning",
    ] {
        let mut ctx = desired_ctx();
        ctx.resident_agents = std::collections::HashSet::from([source.into()]);
        let mut config = desired_config();
        let (result, receipts) = desired_event(
            &format!("20|{source}|owned-intent|{source}/intent:off@123"),
            &ctx,
            &mut config,
            true,
        );
        assert_eq!(result, Some(Some(1)));
        assert_eq!(receipts[0]["value"], "off");
        assert_eq!(config.agents[source].options["intent"], "off");
        let (result, receipts) = desired_event(
            &format!("21|{source}|option|{source}/intent:on"),
            &ctx,
            &mut config,
            true,
        );
        assert_eq!(result, Some(Some(1)));
        assert_eq!(receipts[0]["value"], "on");
        let (result, receipts) = desired_event(
            &format!("19|{source}|owned-intent|{source}/intent:off@122"),
            &ctx,
            &mut config,
            true,
        );
        assert_eq!(result, Some(Some(1)));
        assert_eq!(receipts[0]["disposition"], "superseded");
        assert_eq!(receipts[0]["value"], "on");
        assert_eq!(config.agents[source].options["intent"], "on");
        assert_eq!(
            desired_event(
                &format!("22|{source}|owned-intent|{source}/intent:off@0"),
                &ctx,
                &mut config,
                true,
            )
            .0,
            Some(None)
        );
        assert_eq!(config.user_revision, 2);
        take_target(ctx.endpoint_epoch);
    }
}

#[test]
fn malformed_or_unowned_desired_events_never_reach_the_owner() {
    let ctx = desired_ctx();
    for line in [
        "0|settings|checkbox|launcher:false",
        "8|settings|checkbox|launcher:maybe",
        "8|foreign|option|foreign/theme:dark",
        "8|foreign|owned-intent|foreign/intent:off@1",
        "8|settings|radio|voboost-startup:always",
        "8|settings|option|launcher/key/extra:dark",
        "8|settings|desired-read|field:{\"kind\":\"unknown\"}",
    ] {
        assert_eq!(
            desired::route_with(
                line,
                &ctx,
                Some(71),
                DESIRED_BOOT,
                |_| panic!("invalid input reached owner: {line}"),
                |_, _| panic!("invalid input emitted receipt")
            ),
            Some(None),
            "{line}"
        );
    }
    let mut unbound = ctx.clone();
    unbound.target_starttime = None;
    assert_eq!(
        desired::route_with(
            "8|settings|checkbox|launcher:false",
            &unbound,
            Some(71),
            DESIRED_BOOT,
            |_| panic!("unbound input reached owner"),
            |_, _| panic!("unbound input emitted receipt")
        ),
        Some(None)
    );
}

#[test]
fn desired_owner_failure_never_emits_saved_or_arms_apply_confirmation() {
    let ctx = desired_ctx();
    assert_eq!(
        desired::route_with(
            "8|settings|checkbox|launcher:false",
            &ctx,
            Some(71),
            DESIRED_BOOT,
            |_| Err(std::io::Error::other("owner unavailable")),
            |_, _| panic!("failed save emitted receipt")
        ),
        Some(None)
    );
    assert!(!confirmed_pending()
        .lock()
        .unwrap()
        .contains_key(&(ctx.endpoint_epoch, ConfirmationKind::Mutation)));
}

#[test]
fn unrelated_event_kinds_remain_owned_by_the_existing_routes() {
    let ctx = desired_ctx();
    for line in [
        "7|settings|restart|process:2",
        "8|settings|toggle|launcher:false",
        "9|settings|vehicle-command|command:invalid",
    ] {
        assert_eq!(
            desired::route_with(
                line,
                &ctx,
                Some(71),
                DESIRED_BOOT,
                |_| panic!("unrelated capability reached desired owner"),
                |_, _| panic!("unrelated capability emitted Saved")
            ),
            None
        );
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DesiredRouteCounts {
    result: Option<usize>,
    owner_exchanges: usize,
    saves: usize,
    receipts: usize,
    pending: bool,
}

const DESIRED_WRITE_EVENTS: [&str; 6] = [
    "1|settings|checkbox|launcher:false",
    "2|settings|radio|voboost-startup:hidden",
    "3|settings|option|vehicle-drive-forced-ev/intent:off",
    "4|vehicle-drive-forced-ev|owned-intent|vehicle-drive-forced-ev/intent:off@1",
    "5|ui-qinggan|radio|voboost-startup:interface",
    "6|launcher|launcher-density|density:240",
];

fn counted_desired_route(line: &str, mutations_allowed: bool) -> DesiredRouteCounts {
    use voboost_contract::runtime_owner::{Command, Outcome};
    let mut ctx = desired_ctx();
    ctx.resident_agents
        .extend(["launcher".into(), "vehicle-drive-forced-ev".into()]);
    let mut owner_exchanges = 0;
    let mut saves = 0;
    let mut receipts = 0;
    let result = route_events_at_with_routes(
        line,
        &ctx,
        Some(71),
        std::path::Path::new("unused-desired-plan"),
        mutations_allowed,
        |_, _| panic!("desired policy must not fall back to the legacy writer"),
        || {
            let mut exchange = |command| {
                owner_exchanges += 1;
                let read = matches!(&command, Command::ReadDesired { .. });
                assert!(matches!(
                    command,
                    Command::SaveDesired { .. }
                        | Command::SaveStartupRecovery { .. }
                        | Command::SaveLauncherDesired { .. }
                        | Command::ReadDesired { .. }
                ));
                saves += usize::from(!read);
                Ok(Outcome::DesiredSaved {
                    revision: 1,
                    config: serde_json::json!({
                        "schemaVersion": 2, "startup": "interface",
                        "agents": {
                            "launcher": {"enabled": false, "options": {"densityDpi": 240}},
                            "vehicle-drive-forced-ev": {"enabled": true, "options": {"intent": "off"}}
                        },
                        "userRevision": 0, "fieldRevisions": {}
                    }).to_string(),
                    disposition: voboost_contract::desired::Disposition::Saved,
                })
            };
            let mut send = |fd, frame: &[u8]| {
                assert_eq!(fd, 71);
                assert!(frame.starts_with(b"U|") || frame.starts_with(b"I|"));
                receipts += 1;
                true
            };
            desired::route_with(line, &ctx, Some(71), DESIRED_BOOT, &mut exchange, &mut send)
                .or_else(|| {
                    launcher_desired::route_with(
                        line,
                        &ctx,
                        Some(71),
                        DESIRED_BOOT,
                        &mut exchange,
                        &mut send,
                    )
                })
        },
    );
    let pending = confirmed_pending()
        .lock()
        .unwrap()
        .contains_key(&(ctx.endpoint_epoch, ConfirmationKind::Mutation));
    forget_endpoint(ctx.endpoint_epoch);
    DesiredRouteCounts {
        result,
        owner_exchanges,
        saves,
        receipts,
        pending,
    }
}

#[test]
fn mutation_policy_blocks_desired_saves_receipts_and_pending_before_owner_exchange() {
    let observed: Vec<_> = DESIRED_WRITE_EVENTS
        .iter()
        .map(|line| (*line, counted_desired_route(line, false)))
        .collect();
    let expected: Vec<_> = DESIRED_WRITE_EVENTS
        .iter()
        .map(|line| {
            (
                *line,
                DesiredRouteCounts {
                    result: None,
                    owner_exchanges: 0,
                    saves: 0,
                    receipts: 0,
                    pending: false,
                },
            )
        })
        .collect();
    assert_eq!(observed, expected);
}

#[test]
fn mutation_policy_preserves_enabled_desired_write_routes() {
    for line in DESIRED_WRITE_EVENTS {
        assert_eq!(
            counted_desired_route(line, true),
            DesiredRouteCounts {
                result: Some(1),
                owner_exchanges: 1,
                saves: 1,
                receipts: if line.contains("|owned-intent|") {
                    2
                } else {
                    1
                },
                pending: true,
            },
            "{line}"
        );
    }
}

#[test]
fn mutation_policy_preserves_desired_reads_without_saves_or_pending() {
    let line = r#"7|settings|desired-read|field:{"kind":"enabled","agent":"launcher"}"#;
    for allowed in [false, true] {
        assert_eq!(
            counted_desired_route(line, allowed),
            DesiredRouteCounts {
                result: Some(1),
                owner_exchanges: 1,
                saves: 0,
                receipts: 1,
                pending: false,
            }
        );
    }
}
