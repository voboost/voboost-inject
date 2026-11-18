//! Exact-owner OverlayManager operations. Successful commands are not resource admission.
use crate::agent_events::i18n_resource_events::{
    self as probes, CompatibilityProof, ProbeDescriptor, ProbePhase, ProbeTicket,
};
use crate::fixed_process;
use crate::transition_log::Observation;
use std::path::Path;
use std::time::Duration;
use voboost_contract::resource::OwnedResourceArtifact;
use voboost_shared::secure_fs::Directory;

#[cfg(test)]
use voboost_shared::owned_overlay::OWNER;
use voboost_shared::owned_overlay::{observe_for, OverlayState, Owner, Variant};
const MAX_OUTPUT: usize = 64 * 1024;

/// Owned-byte/system-scan checks are delivery integrity only. Enable additionally requires a current endpoint compatibility proof.
/// The returned state is OMS evidence only, never idmap or per-context Resources readback.
fn set_enabled_after_verified_scan(
    resource: &OwnedResourceArtifact,
    enabled: bool,
    validate: &mut impl FnMut() -> Result<(), String>,
) -> Result<OverlayState, String> {
    let variant = resource_variant(resource)?;
    verify_system_scan(resource)?;
    validate()?;
    let expected = if enabled {
        OverlayState::Enabled
    } else {
        OverlayState::Disabled
    };
    let verb = if enabled { "enable" } else { "disable" };
    let output = fixed_process::output(
        "/system/bin/cmd",
        &["overlay", verb, "--user", "0", variant.package()],
        Duration::from_secs(5),
        MAX_OUTPUT,
    )?;
    if !output.status.success() {
        return Err("overlay change command failed".into());
    }
    verify_system_scan(resource)?;
    let actual = observe_for(variant)?;
    if actual != expected {
        return Err("overlay change was not observed".into());
    }
    Ok(actual)
}

fn verify_system_scan(resource: &OwnedResourceArtifact) -> Result<(), String> {
    let variant = resource_variant(resource)?;
    let descriptor = resource.descriptor();
    if descriptor.owner != variant.owner().agent()
        || descriptor.locale != variant.owner().locale()
        || descriptor.target_package != variant.owner().process()
        || descriptor.overlay_package != variant.package()
    {
        return Err("resource profile unsupported".into());
    }
    let output = fixed_process::output(
        "/system/bin/pm",
        &["path", variant.package()],
        Duration::from_secs(5),
        4096,
    )?;
    if !output.status.success()
        || output.stdout.as_slice()
            != format!("package:/vendor/overlay/{}\n", variant.file()).as_bytes()
    {
        return Err("owned overlay system code path not observed".into());
    }
    let directory = Directory::open(Path::new("/vendor/overlay")).map_err(|e| e.to_string())?;
    directory
        .validate_owner_not_writable(0, 2000)
        .map_err(|e| e.to_string())?;
    directory
        .verify_trusted_digest(
            variant.file(),
            resource.artifact().size,
            &resource.artifact().sha256,
            0o644,
        )
        .map_err(|e| e.to_string())
}
fn enable(
    resource: &OwnedResourceArtifact,
    _compatibility: &CompatibilityProof,
    validate: &mut impl FnMut() -> Result<(), String>,
) -> Result<OverlayState, String> {
    set_enabled_after_verified_scan(resource, true, validate)
}
pub(crate) fn disable(
    resource: &OwnedResourceArtifact,
    endpoint: &crate::agent_log::EndpointContext,
    validate: &mut impl FnMut() -> Result<(), String>,
) -> Result<OverlayState, String> {
    if resource.descriptor().owner == "i18n-en" {
        return set_enabled_after_verified_scan(resource, false, validate);
    }
    let observed = crate::agent_events::global_locale::latest(endpoint)
        .ok_or("actual global locale unavailable before overlay disable")?;
    if observed.language == crate::agent_events::global_locale::GlobalLanguage::Russian {
        return Err("native locale still Russian before overlay disable".into());
    }
    set_enabled_after_verified_scan(resource, false, validate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use voboost_shared::owned_overlay::parse_list;
    use voboost_shared::owned_overlay::PACKAGE;
    const MAX_OUTPUT: usize = 64 * 1024;
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    #[test]
    fn enabled_russian_overlay_rebinds_without_disabling_and_rejects_ambiguity() {
        use OverlayState::{Disabled, Enabled, NotEnabledUnclassified};
        assert_eq!(
            rebind_index(Owner::Setting, &[Enabled, Disabled]),
            Ok(Some(0))
        );
        assert_eq!(
            rebind_index(Owner::Setting, &[Disabled, Enabled]),
            Ok(Some(1))
        );
        assert_eq!(
            rebind_index(Owner::Setting, &[Disabled, NotEnabledUnclassified]),
            Ok(None)
        );
        assert!(rebind_index(Owner::Setting, &[Enabled, Enabled]).is_err());
        // English deltas require their unoverlaid native baseline.
        assert_eq!(rebind_index(Owner::EnSetting, &[Enabled]), Ok(None));
    }
    #[test]
    fn overlay_rebind_requires_fresh_readback_from_the_new_process_epoch() {
        let _guard = TEST_LOCK.lock().unwrap();
        let previous = crate::agent_log::EndpointContext {
            pid: 4242,
            process: Owner::Setting.process().into(),
            endpoint_epoch: 99192,
            target_starttime: Some(120),
            document_generation: Some(7),
            log_generation: Some(("a".repeat(64), "b".repeat(64))),
            resident_generation_id: "a".repeat(64),
            active_generation_id: "a".repeat(64),
            resident_catalog_sha256: "b".repeat(64),
            active_catalog_sha256: "b".repeat(64),
            resident_agents: ["i18n-ru".into()].into(),
            agents: ["i18n-ru".into()].into(),
            selected_agents: ["i18n-ru".into()].into(),
            ..Default::default()
        };
        let mut current = previous.clone();
        current.pid += 1;
        current.target_starttime = Some(121);
        current.endpoint_epoch += 1;
        let descriptor = ProbeDescriptor {
            schema: 1,
            phase: ProbePhase::Readback,
            probe_revision: next_probe_revision().unwrap(),
            profile: "setting-a9".into(),
            target_package: current.process.clone(),
            ledger: serde_json::json!({"compatibility":{"schemaVersion":1,"targetPackage":current.process,"resources":[{"resource":"string/a","type":"string"}]},"expectedReadback":{"a":"Русский"}}),
        };
        let old_ticket = probes::begin_probe(&previous, &descriptor).unwrap();
        probes::forget(previous.endpoint_epoch);
        let ticket = probes::begin_probe(&current, &descriptor).unwrap();
        let event = serde_json::json!({"schema":1,"generation":current.resident_generation_id,"documentGeneration":7,"probeRevision":descriptor.probe_revision,"profile":"setting-a9","targetPackage":current.process,"phase":"readback","checkedResourceCount":1,"contextKinds":["ru"],"outcome":"applied","observedReadback":{"a":"Русский"}});
        assert_eq!(probes::observe(&event.to_string(), &previous), None);
        assert!(probes::take_readback(&old_ticket, &current).is_none());
        assert!(probes::take_readback(&ticket, &current).is_none());
        assert_eq!(probes::observe(&event.to_string(), &current), Some(1));
        let proof = probes::take_readback(&ticket, &current).unwrap();
        assert_eq!(
            proof.binding().endpoint_epoch,
            current.endpoint_epoch.to_string()
        );
        probes::forget(current.endpoint_epoch);
    }
    #[test]
    fn live_current_probe_preserves_admission_waits_for_real_ack_and_revokes() {
        let _guard = TEST_LOCK.lock().unwrap();
        let ctx = crate::agent_log::EndpointContext {
            pid: 4242,
            process: Owner::Setting.process().into(),
            endpoint_epoch: 9992,
            target_starttime: Some(120),
            document_generation: Some(7),
            log_generation: Some(("a".repeat(64), "b".repeat(64))),
            resident_generation_id: "a".repeat(64),
            active_generation_id: "a".repeat(64),
            resident_catalog_sha256: "b".repeat(64),
            active_catalog_sha256: "b".repeat(64),
            resident_agents: ["i18n-ru".into()].into(),
            agents: ["i18n-ru".into()].into(),
            selected_agents: ["i18n-ru".into()].into(),
            ..Default::default()
        };
        probes::forget(ctx.endpoint_epoch);
        let revision = next_probe_revision().unwrap();
        let descriptor = ProbeDescriptor {
            schema: 1,
            phase: ProbePhase::Readback,
            probe_revision: revision,
            profile: "setting-a9".into(),
            target_package: ctx.process.clone(),
            ledger: serde_json::json!({"compatibility":{"schemaVersion":1,"targetPackage":ctx.process,"resources":[{"resource":"string/a","type":"string"}]},"expectedReadback":{"a":"Русский"},"expectedEnglishReadback":{"a":"Language"}}),
        };
        let ticket = probes::begin_probe(&ctx, &descriptor).unwrap();
        let seed = PendingProbe {
            ticket: ticket.clone(),
            tickets: vec![ticket],
            phase: ProbePhase::Readback,
            revision,
            configuration: serde_json::json!({"resourceProbe":{"phase":"readback","probeRevision":revision,"omsEnabled":true}}),
            started: std::time::Instant::now(),
        };
        let mut state = ready_worker(Owner::Setting, &"a".repeat(64), &"b".repeat(64));
        state.current_seed = Some(seed);
        let original = state.admission.clone();
        maintain_current_with_locale(&mut state, None, Some(ProbePhase::Current), true).unwrap();
        assert!(state.current_refresh.is_none());
        maintain_current_with_locale(&mut state, Some(&ctx), Some(ProbePhase::Current), false)
            .unwrap();
        assert!(state.current_refresh.is_none());
        maintain_current_with_locale(&mut state, Some(&ctx), Some(ProbePhase::Current), true)
            .unwrap();
        assert_eq!(state.admission, original);
        let refresh = state.current_refresh.as_ref().unwrap();
        assert!(!refresh.completed);
        let rev = refresh.probe.revision;
        assert_eq!(
            refresh.probe.configuration["resourceProbe"]["phase"],
            "current"
        );
        maintain_current_with_locale(&mut state, Some(&ctx), None, false).unwrap();
        assert_eq!(state.current_refresh.as_ref().unwrap().probe.revision, rev);
        assert!(state.current_locale_confirmed.is_none());
        maintain_current_with_locale(&mut state, Some(&ctx), Some(ProbePhase::Current), true)
            .unwrap();
        assert_eq!(state.current_refresh.as_ref().unwrap().probe.revision, rev);
        let event = serde_json::json!({"schema":1,"generation":ctx.resident_generation_id,"documentGeneration":7,"probeRevision":rev,"profile":"setting-a9","targetPackage":ctx.process,"phase":"current","checkedResourceCount":1,"contextKinds":["current"],"outcome":"applied","observedAtBootMs":crate::agent_state::boot_elapsed_ms().unwrap(),"observedReadback":{"a":"Русский"}});
        assert_eq!(probes::observe(&event.to_string(), &ctx), Some(1));
        maintain_current_with_locale(&mut state, Some(&ctx), Some(ProbePhase::Current), true)
            .unwrap();
        assert!(state.current_refresh.as_ref().unwrap().completed);
        maintain_current_with_locale(&mut state, Some(&ctx), Some(ProbePhase::Current), true)
            .unwrap();
        assert_eq!(state.current_refresh.as_ref().unwrap().probe.revision, rev);
        state.current_refresh.as_mut().unwrap().probe.started =
            std::time::Instant::now() - Duration::from_secs(31);
        maintain_current_with_locale(&mut state, Some(&ctx), None, false).unwrap();
        assert!(state.current_refresh.is_none());
        assert!(probes::current_published(Owner::Setting).is_none());
        maintain_current_with_locale(&mut state, Some(&ctx), Some(ProbePhase::CurrentEn), false)
            .unwrap();
        assert!(state.current_refresh.is_none());
        maintain_current_with_locale(&mut state, Some(&ctx), Some(ProbePhase::CurrentEn), true)
            .unwrap();
        let en = state.current_refresh.as_ref().unwrap().probe.revision;
        let event = serde_json::json!({"schema":1,"generation":ctx.resident_generation_id,"documentGeneration":7,"probeRevision":en,"profile":"setting-a9","targetPackage":ctx.process,"phase":"current-en","checkedResourceCount":1,"contextKinds":["current-en"],"outcome":"applied","observedAtBootMs":crate::agent_state::boot_elapsed_ms().unwrap(),"observedReadback":{"a":"Language"}});
        assert_eq!(probes::observe(&event.to_string(), &ctx), Some(1));
        maintain_current_with_locale(&mut state, Some(&ctx), Some(ProbePhase::CurrentEn), true)
            .unwrap();
        assert!(state.current_refresh.as_ref().unwrap().completed);
        maintain_current_with_locale(&mut state, Some(&ctx), Some(ProbePhase::CurrentZh), true)
            .unwrap();
        let zh = state.current_refresh.as_ref().unwrap().probe.revision;
        assert_ne!(en, zh);
        assert!(probes::current_published(Owner::Setting).is_none());
        let event = serde_json::json!({"schema":1,"generation":ctx.resident_generation_id,"documentGeneration":7,"probeRevision":zh,"profile":"setting-a9","targetPackage":ctx.process,"phase":"current-zh","checkedResourceCount":1,"contextKinds":["current-zh"],"outcome":"applied","observedAtBootMs":crate::agent_state::boot_elapsed_ms().unwrap(),"observedReadback":{"a":"语言"},"referenceReadback":{"a":"语言"}});
        assert_eq!(probes::observe(&event.to_string(), &ctx), Some(1));
        maintain_current_with_locale(&mut state, Some(&ctx), Some(ProbePhase::CurrentZh), true)
            .unwrap();
        assert!(state.current_refresh.as_ref().unwrap().completed);
        probes::forget(ctx.endpoint_epoch);
    }
    #[test]
    fn english_admission_is_independent_of_russian_worker_and_intent() {
        let _guard = TEST_LOCK.lock().unwrap();
        let generation = "7".repeat(64);
        let catalog = "6".repeat(64);
        *worker(Owner::Setting).lock().unwrap() = Worker::default();
        let mut english = ready_worker(Owner::Setting, &generation, &catalog);
        english.admission = Some(
            serde_json::json!({"resourceAdmission":{"profile":"en-setting-a11","expectedReadback":{"a":"English"}}}),
        );
        *worker(Owner::EnSetting).lock().unwrap() = english;
        assert!(
            configuration_for_agent_generation("i18n-ru", &generation, &catalog, OWNER).is_none()
        );
        let en =
            configuration_for_agent_generation("i18n-en", &generation, &catalog, OWNER).unwrap();
        assert_eq!(en["resourceAdmission"]["profile"], "en-setting-a11");
        // Revoking RU cannot clear a separately owned EN admission.
        *worker(Owner::Setting).lock().unwrap() =
            ready_worker(Owner::Setting, &generation, &catalog);
        worker(Owner::Setting).lock().unwrap().admission = None;
        assert_eq!(
            configuration_for_agent_generation("i18n-en", &generation, &catalog, OWNER),
            Some(en)
        );
        *worker(Owner::EnSetting).lock().unwrap() = Worker::default();
        *worker(Owner::Setting).lock().unwrap() = Worker::default();
    }

    #[test]
    fn admission_projection_contains_only_resource_probe_contract() {
        let ledger = serde_json::json!({
            "scope": "complete-ui-owner",
            "expectedReadback": {"language": "Язык"}
        });
        let generation = "a".repeat(64);
        let value = admission_projection(
            &generation,
            "setting-a9",
            "com.qinggan.app.setting",
            "ru.voboost.translation.setting",
            &ledger,
        )
        .unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "schema": 1,
                "generation": generation,
                "observedGeneration": generation,
                "profile": "setting-a9",
                "targetPackage": "com.qinggan.app.setting",
                "overlayPackage": "ru.voboost.translation.setting",
                "scope": "complete-ui-owner",
                "enabled": true,
                "omsEnabled": true,
                "expectedReadback": {"language": "Язык"}
            })
        );
    }
    #[test]
    fn admission_projection_rejects_absent_or_malformed_readback() {
        for readback in [
            serde_json::Value::Null,
            serde_json::json!({}),
            serde_json::json!({"language": true}),
        ] {
            let ledger = serde_json::json!({
                "scope": "complete-ui-owner", "expectedReadback": readback
            });
            assert!(admission_projection(
                &"a".repeat(64),
                "setting-a9",
                "com.qinggan.app.setting",
                "ru.voboost.translation.setting",
                &ledger
            )
            .is_err());
        }
    }
    #[test]
    fn resource_waiting_phases_never_report_terminal_completion() {
        for phase in [
            OwnerPhase::Unobserved,
            OwnerPhase::WaitingProcess,
            OwnerPhase::Preflight,
            OwnerPhase::Readback,
            OwnerPhase::Failed("permission denied".into()),
        ] {
            assert_eq!(phase.completion(), Observation::Pending);
        }
        for phase in [
            OwnerPhase::Ready,
            OwnerPhase::Disabled,
            OwnerPhase::NotApplicable,
            OwnerPhase::Unsupported("ABI".into()),
        ] {
            assert_eq!(phase.completion(), Observation::Complete);
        }
    }
    fn ready_worker(owner: Owner, generation: &str, catalog: &str) -> Worker {
        Worker {
            completed: Some(JobKey {
                generation: generation.into(),
                catalog: catalog.into(),
                enabled: true,
                endpoint: Some(crate::status::EndpointBinding {
                    target_pid: (810
                        + Owner::ALL.iter().position(|value| *value == owner).unwrap())
                    .to_string(),
                    target_starttime: "34".into(),
                    endpoint_epoch: "57".into(),
                    generation_id: generation.into(),
                    catalog_sha256: catalog.into(),
                    desired_document_generation: "1".into(),
                    accepted_status: None,
                }),
                locale_endpoint: None,
            }),
            admission: Some(
                serde_json::json!({"resourceAdmission":{"targetPackage":owner.process()}}),
            ),
            ..Default::default()
        }
    }
    #[test]
    fn settings_admission_survives_other_declared_owner_waiting() {
        let _guard = TEST_LOCK.lock().unwrap();
        let generation = "f".repeat(64);
        let catalog = "e".repeat(64);
        *worker(Owner::Setting).lock().unwrap() =
            ready_worker(Owner::Setting, &generation, &catalog);
        let mut lazy = ready_worker(Owner::Launcher, &generation, &catalog);
        lazy.completed.as_mut().unwrap().endpoint = None;
        lazy.admission = None;
        *worker(Owner::Launcher).lock().unwrap() = lazy;
        assert!(
            configuration_for_generation(&generation, &catalog, Owner::Setting.process()).is_some(),
            "own Setting readback must allow its controls without starting Launcher"
        );
        assert!(
            configuration_for_generation(&generation, &catalog, Owner::Launcher.process())
                .is_none()
        );
        assert!(configuration_for_generation(
            &generation,
            &catalog,
            Owner::VehicleSetting.process()
        )
        .is_none());
        worker(Owner::Setting).lock().unwrap().admission = None;
        assert!(
            configuration_for_generation(&generation, &catalog, Owner::Setting.process()).is_none()
        );
        for owner in Owner::ALL {
            *worker(owner).lock().unwrap() = Worker::default();
        }
    }
    #[test]
    fn closed_capabilities_do_not_expand_signed_declaration() {
        let _guard = TEST_LOCK.lock().unwrap();
        let generation = "5".repeat(64);
        let catalog = "6".repeat(64);
        let declared: std::collections::BTreeSet<_> =
            [Owner::Setting, Owner::Launcher, Owner::VehicleSetting].into();
        let original: Vec<_> = Variant::ALL
            .into_iter()
            .filter(|variant| declared.contains(&variant.owner()))
            .collect();
        assert_eq!(original.len(), 6);
        assert!(validate_inventory(&declared, &original, true).is_ok());
        for owner in Owner::ALL {
            *worker(owner).lock().unwrap() = if declared.contains(&owner) {
                ready_worker(owner, &generation, &catalog)
            } else {
                Worker::default()
            };
        }
        assert!(scope_snapshot(&generation, &catalog, &declared).complete);
        for extra in Variant::ALL
            .into_iter()
            .filter(|variant| !declared.contains(&variant.owner()))
        {
            let mut enlarged = original.clone();
            enlarged.push(extra);
            assert!(validate_inventory(&declared, &enlarged, true).is_err());
            assert!(configuration_for_agent_generation(
                extra.owner().agent(),
                &generation,
                &catalog,
                extra.owner().process()
            )
            .is_none());
        }
        for owner in Owner::ALL {
            *worker(owner).lock().unwrap() = Worker::default();
        }
    }
    #[test]
    fn missing_english_delta_does_not_revoke_other_owners() {
        let declared = [Owner::Setting, Owner::EnSetting, Owner::EnLauncher].into();
        let present = [Variant::SettingA9, Variant::EnLauncherA9];
        assert!(validate_inventory(&declared, &present, true).is_ok());
        assert!(validate_inventory(&declared, &present[1..], true).is_err());
        assert!(validate_inventory(&declared, &[Variant::EnMediaA9], false).is_err());
    }
    #[test]
    fn every_lazy_owner_preserves_setting_without_claiming_complete_scope() {
        let _guard = TEST_LOCK.lock().unwrap();
        let generation = "3".repeat(64);
        let catalog = "4".repeat(64);
        let declared = Owner::ALL.into_iter().collect();
        for lazy in Owner::ALL
            .into_iter()
            .filter(|owner| *owner != Owner::Setting)
        {
            for owner in Owner::ALL {
                *worker(owner).lock().unwrap() = ready_worker(owner, &generation, &catalog);
            }
            let mut waiting = ready_worker(lazy, &generation, &catalog);
            waiting.completed.as_mut().unwrap().endpoint = None;
            waiting.admission = None;
            waiting.observation = Some((
                waiting.completed.as_ref().unwrap().clone(),
                OwnerPhase::WaitingProcess,
            ));
            *worker(lazy).lock().unwrap() = waiting;
            assert!(
                configuration_for_generation(&generation, &catalog, Owner::Setting.process())
                    .is_some()
            );
            assert!(configuration_for_generation(&generation, &catalog, lazy.process()).is_none());
            let scope = scope_snapshot(&generation, &catalog, &declared);
            assert!(!scope.complete);
            assert!(scope
                .owners
                .iter()
                .any(|(owner, phase)| *owner == lazy && *phase == OwnerPhase::WaitingProcess));
        }
        for owner in Owner::ALL {
            *worker(owner).lock().unwrap() = Worker::default();
        }
    }
    #[test]
    fn inventory_failure_revokes_cached_admissions_and_cancelled_results() {
        let _guard = TEST_LOCK.lock().unwrap();
        let generation = "9".repeat(64);
        let catalog = "8".repeat(64);
        let declared = Owner::ALL.into_iter().collect();
        assert!(validate_inventory(
            &declared,
            &Variant::ALL
                .into_iter()
                .filter(|v| v.owner().agent() == "i18n-ru")
                .collect::<Vec<_>>(),
            true
        )
        .is_ok());
        let missing =
            validate_inventory(&declared, &[Variant::SettingA9, Variant::SettingA11], true)
                .unwrap_err();
        assert!(validate_inventory(&[Owner::Setting].into(), &Variant::ALL, true).is_err());
        assert!(validate_inventory(
            &declared,
            &[
                Variant::SettingA9,
                Variant::SettingA11,
                Variant::LauncherA9,
                Variant::LauncherA11
            ],
            true
        )
        .is_err());
        for owner in Owner::ALL {
            *worker(owner).lock().unwrap() = ready_worker(owner, &generation, &catalog);
        }
        let key = worker(Owner::Setting)
            .lock()
            .unwrap()
            .completed
            .clone()
            .unwrap();
        let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let job = Job {
            key: key.clone(),
            cancelled: cancelled.clone(),
            thread: std::thread::spawn(|| Ok(Reconciled::Ready(serde_json::json!({})))),
        };
        assert!(job_result_current(&job, &key));
        worker(Owner::Setting).lock().unwrap().active = Some(job);
        assert!(scope_snapshot(&generation, &catalog, &declared).complete);
        record_inventory_failure(&key, &missing);
        for owner in Owner::ALL {
            assert!(configuration_for_generation(&generation, &catalog, owner.process()).is_none());
        }
        assert!(!scope_snapshot(&generation, &catalog, &declared).complete);
        assert!(cancelled.load(std::sync::atomic::Ordering::Acquire));
        let old_job = worker(Owner::Setting)
            .lock()
            .unwrap()
            .active
            .take()
            .unwrap();
        assert!(!job_result_current(&old_job, &key));
        let _ = old_job.thread.join().unwrap();
        // Repairing the full inventory never resurrects either cached proof.
        assert!(validate_inventory(
            &declared,
            &Variant::ALL
                .into_iter()
                .filter(|v| v.owner().agent() == "i18n-ru")
                .collect::<Vec<_>>(),
            true
        )
        .is_ok());
        clear_inventory_failure(&generation, &catalog);
        for owner in Owner::ALL {
            assert!(configuration_for_generation(&generation, &catalog, owner.process()).is_none());
        }
        *worker(Owner::Setting).lock().unwrap() =
            ready_worker(Owner::Setting, &generation, &catalog);
        assert!(
            configuration_for_generation(&generation, &catalog, Owner::Setting.process()).is_some()
        );
        assert!(!scope_snapshot(&generation, &catalog, &declared).complete);
        for owner in Owner::ALL {
            *worker(owner).lock().unwrap() = Worker::default();
        }
    }
    #[test]
    fn owner_scope_distinguishes_pending_unsupported_and_complete() {
        let _guard = TEST_LOCK.lock().unwrap();
        let generation = "c".repeat(64);
        let catalog = "d".repeat(64);
        let make = |owner: Owner| {
            let binding = crate::status::EndpointBinding {
                target_pid: (800 + Owner::ALL.iter().position(|value| *value == owner).unwrap())
                    .to_string(),
                target_starttime: "34".into(),
                endpoint_epoch: "56".into(),
                generation_id: generation.clone(),
                catalog_sha256: catalog.clone(),
                desired_document_generation: "1".into(),
                accepted_status: None,
            };
            Worker {
                completed: Some(JobKey {
                    generation: generation.clone(),
                    catalog: catalog.clone(),
                    enabled: true,
                    endpoint: Some(binding),
                    locale_endpoint: None,
                }),
                admission: Some(
                    serde_json::json!({"resourceAdmission":{"targetPackage":owner.process()}}),
                ),
                ..Default::default()
            }
        };
        for owner in Owner::ALL {
            *worker(owner).lock().unwrap() = make(owner);
        }
        let mut waiting = make(Owner::Launcher);
        waiting.completed.as_mut().unwrap().endpoint = None;
        waiting.observation = Some((
            waiting.completed.as_ref().unwrap().clone(),
            OwnerPhase::WaitingProcess,
        ));
        waiting.admission = None;
        *worker(Owner::Launcher).lock().unwrap() = waiting;
        // A valid inventory with a nonrunning owner does not block Setting.
        assert!(
            configuration_for_generation(&generation, &catalog, Owner::Setting.process()).is_some()
        );
        assert!(
            configuration_for_generation(&generation, &catalog, Owner::Launcher.process())
                .is_none()
        );
        let declared = Owner::ALL.into_iter().collect();
        let pending = scope_snapshot(&generation, &catalog, &declared);
        assert!(!pending.complete);
        assert_eq!(pending.owners[1].1, OwnerPhase::WaitingProcess);
        let mut previous = None;
        assert!(changed_scope(&mut previous, &pending));
        assert!(!changed_scope(&mut previous, &pending));
        *worker(Owner::Launcher).lock().unwrap() = make(Owner::Launcher);
        let complete = scope_snapshot(&generation, &catalog, &declared);
        assert!(complete.complete);
        worker(Owner::VehicleSetting).lock().unwrap().admission = None;
        assert!(!scope_snapshot(&generation, &catalog, &declared).complete);
        assert!(
            configuration_for_generation(&generation, &catalog, Owner::Setting.process()).is_some()
        );
        *worker(Owner::VehicleSetting).lock().unwrap() = make(Owner::VehicleSetting);
        assert!(changed_scope(&mut previous, &complete));
        for owner in Owner::ALL {
            assert_eq!(
                configuration_for_generation(&generation, &catalog, owner.process()).unwrap()
                    ["resourceAdmission"]["targetPackage"],
                owner.process()
            );
        }
        worker(Owner::Launcher)
            .lock()
            .unwrap()
            .completed
            .as_mut()
            .unwrap()
            .generation = "e".repeat(64);
        assert!(
            configuration_for_generation(&generation, &catalog, Owner::Setting.process()).is_some()
        );
        assert!(!scope_snapshot(&generation, &catalog, &declared).complete);
        *worker(Owner::Launcher).lock().unwrap() = make(Owner::Launcher);
        worker(Owner::Launcher).lock().unwrap().admission =
            Some(serde_json::json!({"resourceProbes":[]}));
        assert!(
            configuration_for_generation(&generation, &catalog, Owner::Setting.process()).is_some()
        );
        for phase in [
            OwnerPhase::Preflight,
            OwnerPhase::Readback,
            OwnerPhase::Unsupported("no actual compatible variant".into()),
            OwnerPhase::Failed("readback failed".into()),
            OwnerPhase::Disabled,
        ] {
            let mut other = make(Owner::Launcher);
            other.observation = Some((other.completed.as_ref().unwrap().clone(), phase.clone()));
            other.admission = None;
            *worker(Owner::Launcher).lock().unwrap() = other;
            let incomplete = scope_snapshot(&generation, &catalog, &declared);
            assert!(!incomplete.complete);
            assert_eq!(incomplete.owners[1].1, phase);
            assert!(
                configuration_for_generation(&generation, &catalog, Owner::Setting.process())
                    .is_some()
            );
            assert!(changed_scope(&mut previous, &incomplete));
            assert!(!changed_scope(&mut previous, &incomplete));
        }
        *worker(Owner::Launcher).lock().unwrap() = make(Owner::Launcher);
        assert!(changed_scope(
            &mut previous,
            &scope_snapshot(&generation, &catalog, &declared)
        ));
        assert!(configuration_for_generation(&generation, &catalog, "com.other").is_none());
        // Existing catalog declaring only Setting does not invent a Launcher payload.
        assert!(scope_snapshot(&generation, &catalog, &[Owner::Setting].into()).complete);
        assert!(
            configuration_for_generation(&generation, &catalog, Owner::Setting.process()).is_some()
        );
        for owner in Owner::ALL {
            *worker(owner).lock().unwrap() = Worker::default();
        }
    }
    #[test]
    fn prepared_resources_survive_only_same_endpoint_document_refresh() {
        let binding = crate::status::EndpointBinding {
            target_pid: "12".into(),
            target_starttime: "34".into(),
            endpoint_epoch: "56".into(),
            generation_id: "a".repeat(64),
            catalog_sha256: "b".repeat(64),
            desired_document_generation: "1".into(),
            accepted_status: None,
        };
        let previous = JobKey {
            generation: "a".repeat(64),
            catalog: "b".repeat(64),
            enabled: true,
            endpoint: Some(binding),
            locale_endpoint: None,
        };
        let mut next = previous.clone();
        next.endpoint.as_mut().unwrap().desired_document_generation = "2".into();
        assert_ne!(previous, next); // Exact active-job cancellation ticket still changes.
        assert!(may_retain_prepared(&previous, &next));
        for field in 0..7 {
            let mut changed = next.clone();
            match field {
                0 => changed.enabled = false,
                1 => changed.generation = "c".repeat(64),
                2 => changed.catalog = "c".repeat(64),
                3 => changed.endpoint = None,
                4 => changed.endpoint.as_mut().unwrap().target_pid = "13".into(),
                5 => changed.endpoint.as_mut().unwrap().target_starttime = "35".into(),
                _ => changed.endpoint.as_mut().unwrap().endpoint_epoch = "57".into(),
            }
            assert!(!may_retain_prepared(&previous, &changed));
        }
    }
    #[test]
    fn actual_owner_markers_are_distinct() {
        for (marker, expected) in [
            ("[x]", OverlayState::Enabled),
            ("[ ]", OverlayState::Disabled),
            ("---", OverlayState::NotEnabledUnclassified),
        ] {
            let list = format!("{OWNER}\n{marker} {PACKAGE}\n");
            assert_eq!(parse_list(list.as_bytes()), Ok(expected));
        }
    }
    #[test]
    fn another_owner_never_admits_overlay() {
        assert!(parse_list(format!("com.other\n[x] {PACKAGE}\n").as_bytes()).is_err());
    }
    #[test]
    fn substring_and_duplicate_are_rejected() {
        assert!(parse_list(format!("{OWNER}\n[x] {PACKAGE}.other\n").as_bytes()).is_err());
        assert!(parse_list(format!("{OWNER}\n[x] {PACKAGE}\n[ ] {PACKAGE}\n").as_bytes()).is_err());
    }
    #[test]
    fn malformed_output_never_means_disabled() {
        assert!(parse_list(b"Error: service unavailable").is_err());
        assert!(parse_list(&[255]).is_err());
        assert!(parse_list(&vec![b'x'; MAX_OUTPUT + 1]).is_err());
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct JobKey {
    generation: String,
    catalog: String,
    enabled: bool,
    endpoint: Option<crate::status::EndpointBinding>,
    locale_endpoint: Option<crate::status::EndpointBinding>,
}
// A desired-document revision does not change the already verified installed APK.
// Keep prepared resource data only for the same live endpoint. Active job tickets
// still compare the entire binding and cancel/revalidate on every revision change.
fn may_retain_prepared(previous: &JobKey, next: &JobKey) -> bool {
    if !previous.enabled
        || !next.enabled
        || previous.generation != next.generation
        || previous.catalog != next.catalog
        || !same_locale_endpoint(&previous.locale_endpoint, &next.locale_endpoint)
    {
        return false;
    }
    match (&previous.endpoint, &next.endpoint) {
        (Some(a), Some(b)) => {
            a.target_pid == b.target_pid
                && a.target_starttime == b.target_starttime
                && a.endpoint_epoch == b.endpoint_epoch
                && a.generation_id == b.generation_id
                && a.catalog_sha256 == b.catalog_sha256
        }
        _ => false,
    }
}

fn same_locale_endpoint(
    a: &Option<crate::status::EndpointBinding>,
    b: &Option<crate::status::EndpointBinding>,
) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => {
            a.target_pid == b.target_pid
                && a.target_starttime == b.target_starttime
                && a.endpoint_epoch == b.endpoint_epoch
                && a.generation_id == b.generation_id
                && a.catalog_sha256 == b.catalog_sha256
        }
        _ => false,
    }
}
struct Job {
    key: JobKey,
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: std::thread::JoinHandle<Result<Reconciled, ReconcileError>>,
}
#[derive(Clone)]
struct PendingProbe {
    ticket: ProbeTicket,
    tickets: Vec<ProbeTicket>,
    phase: ProbePhase,
    revision: u64,
    configuration: serde_json::Value,
    started: std::time::Instant,
}
enum Reconciled {
    Pending(Box<PendingProbe>),
    Ready(serde_json::Value),
    Disabled,
    WaitingProcess,
    NotApplicable,
    Unsupported(String),
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum OwnerPhase {
    Unobserved,
    WaitingProcess,
    Preflight,
    Readback,
    Ready,
    NotApplicable,
    Unsupported(String),
    Failed(String),
    Disabled,
}
impl OwnerPhase {
    fn completion(&self) -> Observation {
        match self {
            Self::Ready | Self::Disabled | Self::NotApplicable | Self::Unsupported(_) => {
                Observation::Complete
            }
            _ => Observation::Pending,
        }
    }
    fn name(&self) -> &'static str {
        match self {
            Self::Unobserved => "unobserved",
            Self::WaitingProcess => "waiting-process",
            Self::Preflight => "preflight",
            Self::Readback => "readback",
            Self::Ready => "ready",
            Self::NotApplicable => "not-applicable",
            Self::Unsupported(_) => "unsupported",
            Self::Failed(_) => "failed",
            Self::Disabled => "disabled",
        }
    }
    fn reason(&self) -> Option<&str> {
        match self {
            Self::Unsupported(reason) | Self::Failed(reason) => Some(reason),
            _ => None,
        }
    }
}
enum ReconcileError {
    Inventory(String),
    Owner(String),
}
impl From<String> for ReconcileError {
    fn from(reason: String) -> Self {
        Self::Owner(reason)
    }
}
#[derive(Clone)]
struct InventoryFault {
    generation: String,
    catalog: String,
    reason: String,
}
fn inventory_fault() -> &'static std::sync::Mutex<Option<InventoryFault>> {
    static FAULT: std::sync::OnceLock<std::sync::Mutex<Option<InventoryFault>>> =
        std::sync::OnceLock::new();
    FAULT.get_or_init(|| std::sync::Mutex::new(None))
}
fn inventory_failure(generation: &str, catalog: &str) -> Option<String> {
    let fault = match inventory_fault().lock() {
        Ok(fault) => fault,
        Err(_) => return Some("resource inventory fault lock poisoned".into()),
    };
    fault
        .as_ref()
        .filter(|fault| fault.generation == generation && fault.catalog == catalog)
        .map(|fault| fault.reason.clone())
}
fn same_generation(key: &JobKey, generation: &str, catalog: &str) -> bool {
    key.generation == generation && key.catalog == catalog
}
fn record_inventory_failure(key: &JobKey, reason: &str) {
    let reason = bounded_reason(reason);
    let changed = if let Ok(mut fault) = inventory_fault().lock() {
        let changed = fault.as_ref().is_none_or(|previous| {
            previous.generation != key.generation
                || previous.catalog != key.catalog
                || previous.reason != reason
        });
        *fault = Some(InventoryFault {
            generation: key.generation.clone(),
            catalog: key.catalog.clone(),
            reason: reason.clone(),
        });
        changed
    } else {
        false
    };
    if changed {
        crate::log::err(
            "i18n-resources",
            &format!(
                "inventory.failed generation={} reason={reason}",
                key.generation
            ),
        );
    }
    // The fault mutex is released before any owner lock. A failed inventory can
    // revoke a completed but uncollected job as well as an already cached proof.
    for owner in Owner::ALL_RESOURCES {
        if let Ok(mut state) = worker(owner).lock() {
            let affected = state
                .completed
                .as_ref()
                .or_else(|| state.observation.as_ref().map(|(key, _)| key))
                .or_else(|| state.active.as_ref().map(|job| &job.key))
                .filter(|candidate| same_generation(candidate, &key.generation, &key.catalog))
                .cloned();
            if let Some(observed) = affected {
                state.admission = None;
                state.probe = None;
                state.completed = None;
                state.observation = Some((observed, OwnerPhase::Failed(reason.clone())));
                state.retry_after = Some(std::time::Instant::now() + Duration::from_secs(2));
                if let Some(job) = &state.active {
                    job.cancelled
                        .store(true, std::sync::atomic::Ordering::Release);
                }
            }
        }
    }
}
fn clear_inventory_failure(generation: &str, catalog: &str) {
    if let Ok(mut fault) = inventory_fault().lock() {
        if fault
            .as_ref()
            .is_some_and(|fault| fault.generation == generation && fault.catalog == catalog)
        {
            *fault = None;
        }
    }
}
fn job_result_current(job: &Job, key: &JobKey) -> bool {
    job.key == *key && !job.cancelled.load(std::sync::atomic::Ordering::Acquire)
}
fn bounded_reason(reason: &str) -> String {
    reason.chars().take(512).collect()
}
#[derive(Default)]
struct Worker {
    active: Option<Job>,
    completed: Option<JobKey>,
    admission: Option<serde_json::Value>,
    probe: Option<PendingProbe>,
    current_seed: Option<PendingProbe>,
    current_refresh: Option<CurrentRefresh>,
    current_locale_confirmed: Option<ProbePhase>,
    retry_after: Option<std::time::Instant>,
    observation: Option<(JobKey, OwnerPhase)>,
}
struct CurrentRefresh {
    probe: PendingProbe,
    completed: bool,
}
fn worker(owner: Owner) -> &'static std::sync::Mutex<Worker> {
    static STATES: std::sync::OnceLock<[std::sync::Mutex<Worker>; Owner::ALL_RESOURCES.len()]> =
        std::sync::OnceLock::new();
    &STATES.get_or_init(|| std::array::from_fn(|_| std::sync::Mutex::new(Worker::default())))
        [owner as usize]
}
static RUNNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
struct Running;
impl Drop for Running {
    fn drop(&mut self) {
        RUNNING.store(false, std::sync::atomic::Ordering::Release);
    }
}
fn enabled_agent(plan: &crate::plan::Plan, agent: &str) -> bool {
    plan.valid
        && !plan.disable_all
        && plan.startup != crate::plan::Startup::None
        && plan
            .entries
            .iter()
            .any(|entry| entry.id == agent && entry.enabled)
}
/// Called before any desired document is built for a newly observed endpoint.
pub(crate) fn invalidate_for(
    owner: Owner,
    generation: &crate::generation::VerifiedGeneration,
    plan: &crate::plan::Plan,
    endpoint: Option<&crate::agent_log::EndpointContext>,
    locale_endpoint: Option<&crate::agent_log::EndpointContext>,
) {
    let key = JobKey {
        generation: generation.id.clone(),
        catalog: generation.catalog_sha256.clone(),
        enabled: enabled_agent(plan, owner.agent()),
        endpoint: endpoint.and_then(crate::control_plane::endpoint_binding),
        locale_endpoint: locale_endpoint.and_then(crate::control_plane::endpoint_binding),
    };
    if let Ok(mut state) = worker(owner).lock() {
        if !state
            .completed
            .as_ref()
            .is_some_and(|previous| previous == &key || may_retain_prepared(previous, &key))
        {
            state.admission = None;
            state.probe = None;
            state.current_seed = None;
            state.current_refresh = None;
            state.current_locale_confirmed = None;
            state.completed = None;
            state.observation = None;
        }
        if let Some(job) = &state.active {
            if job.key != key {
                job.cancelled
                    .store(true, std::sync::atomic::Ordering::Release);
            }
        }
    }
}
/// One finite background job, no queued requests and no blocking process call in the poll loop.
pub(crate) fn observation_identity(
    generation: &crate::generation::VerifiedGeneration,
    plan: &crate::plan::Plan,
    endpoint: Option<&crate::agent_log::EndpointContext>,
    locale_endpoint: Option<&crate::agent_log::EndpointContext>,
) -> String {
    let binding = |context: &crate::agent_log::EndpointContext| {
        (
            context.pid,
            context.target_starttime,
            context.endpoint_epoch,
            context.document_generation,
            context.resident_generation_id.clone(),
            context.resident_catalog_sha256.clone(),
        )
    };
    format!(
        "{:?}",
        (
            &generation.id,
            &generation.catalog_sha256,
            [
                enabled_agent(plan, "i18n-ru"),
                enabled_agent(plan, "i18n-en")
            ],
            endpoint.map(binding),
            locale_endpoint.map(binding)
        )
    )
}

/// Keep the admitted configuration installed while issuing bounded actual-owner readbacks.
fn maintain_current(
    state: &mut Worker,
    endpoint: Option<&crate::agent_log::EndpointContext>,
    locale_endpoint: Option<&crate::agent_log::EndpointContext>,
) -> Result<(), String> {
    let agent = state
        .current_seed
        .as_ref()
        .and_then(|seed| {
            Owner::from_profile_process(
                &seed.ticket.descriptor().profile,
                &seed.ticket.descriptor().target_package,
            )
            .ok()
        })
        .map_or("i18n-ru", Owner::agent);
    let locale = locale_endpoint
        .and_then(crate::agent_events::global_locale::latest)
        .filter(|value| {
            agent != "i18n-en"
                || value.language == crate::agent_events::global_locale::GlobalLanguage::English
        });
    maintain_current_with_locale(
        state,
        endpoint,
        locale.map(|value| match value.language {
            crate::agent_events::global_locale::GlobalLanguage::Russian => ProbePhase::Current,
            crate::agent_events::global_locale::GlobalLanguage::English => ProbePhase::CurrentEn,
            crate::agent_events::global_locale::GlobalLanguage::Chinese => ProbePhase::CurrentZh,
        }),
        endpoint.is_some_and(|ctx| crate::control_plane::agent_ready(ctx, agent)),
    )
}
fn maintain_current_with_locale(
    state: &mut Worker,
    endpoint: Option<&crate::agent_log::EndpointContext>,
    locale: Option<ProbePhase>,
    ready: bool,
) -> Result<(), String> {
    let Some(endpoint) = endpoint else {
        state.current_locale_confirmed = None;
        state.current_refresh = None;
        return Ok(());
    };
    let profile = state
        .current_seed
        .as_ref()
        .map(|seed| seed.ticket.descriptor().profile)
        .unwrap_or_default();
    let owner = Owner::from_profile_process(&profile, &endpoint.process)?;
    state.current_locale_confirmed = locale;
    let Some(locale) = locale else {
        if state
            .current_refresh
            .as_ref()
            .is_some_and(|refresh| refresh.probe.started.elapsed() > Duration::from_secs(30))
        {
            probes::clear_current(owner);
            state.current_refresh = None;
        }
        return Ok(());
    };
    if !locale.is_current() {
        return Err("closed current locale required".into());
    }
    if state
        .current_refresh
        .as_ref()
        .is_some_and(|refresh| refresh.probe.phase != locale)
    {
        probes::clear_current(owner);
        state.current_refresh = None;
    }
    if let Some(refresh) = state.current_refresh.as_mut() {
        if !refresh.completed {
            if probes::take_current(&refresh.probe.ticket, endpoint).is_some() {
                refresh.completed = true;
            } else if refresh.probe.started.elapsed() <= Duration::from_secs(30) {
                return Ok(());
            } else {
                state.current_refresh = None;
            }
        }
    }
    if state
        .current_refresh
        .as_ref()
        .is_some_and(|refresh| refresh.completed)
        && probes::current_published(owner)
            .is_some_and(|proof| proof.age_ms().is_some_and(|age| age < 15000))
    {
        return Ok(());
    }
    if !ready {
        return Ok(());
    }
    let Some(seed) = state.current_seed.as_ref() else {
        return Ok(());
    };
    let mut descriptor = seed.ticket.descriptor();
    descriptor.phase = locale;
    descriptor.probe_revision = next_probe_revision()?;
    let ticket = probes::begin_probe(endpoint, &descriptor)?;
    let mut configuration = seed.configuration.clone();
    let projection = configuration
        .get_mut("resourceProbe")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("current probe seed unavailable")?;
    projection.insert("phase".into(), serde_json::json!(locale.name()));
    projection.insert(
        "probeRevision".into(),
        serde_json::json!(descriptor.probe_revision),
    );
    projection.insert("omsEnabled".into(), serde_json::json!(true));
    state.current_refresh = Some(CurrentRefresh {
        probe: PendingProbe {
            tickets: vec![ticket.clone()],
            ticket,
            phase: locale,
            revision: descriptor.probe_revision,
            configuration,
            started: std::time::Instant::now(),
        },
        completed: false,
    });
    Ok(())
}

/// Observe completion only after the current finite worker produces a terminal owner result.
pub(crate) fn poll(
    owner: Owner,
    generation: &crate::generation::VerifiedGeneration,
    plan: &crate::plan::Plan,
    endpoint: Option<&crate::agent_log::EndpointContext>,
    locale_endpoint: Option<&crate::agent_log::EndpointContext>,
) -> Result<Observation, String> {
    let key = JobKey {
        generation: generation.id.clone(),
        catalog: generation.catalog_sha256.clone(),
        enabled: enabled_agent(plan, owner.agent()),
        endpoint: endpoint.and_then(crate::control_plane::endpoint_binding),
        locale_endpoint: locale_endpoint.and_then(crate::control_plane::endpoint_binding),
    };
    if endpoint.is_some_and(|endpoint| endpoint.process != owner.process()) {
        return Err("resource endpoint belongs to another owner".into());
    }
    let mut state = worker(owner)
        .lock()
        .map_err(|_| "i18n resource worker poisoned")?;
    if !state
        .completed
        .as_ref()
        .is_some_and(|previous| previous == &key || may_retain_prepared(previous, &key))
    {
        state.admission = None;
        state.probe = None;
        state.completed = None;
        state.observation = None;
    }
    if let Some(job) = &state.active {
        if job.key != key {
            job.cancelled
                .store(true, std::sync::atomic::Ordering::Release);
        }
        if !job.thread.is_finished() {
            return Ok(Observation::Pending);
        }
        let job = state.active.take().unwrap();
        let current = job_result_current(&job, &key);
        let result = job
            .thread
            .join()
            .map_err(|_| "i18n resource worker panicked")?;
        if current
            && !job.cancelled.load(std::sync::atomic::Ordering::Acquire)
            && inventory_failure(&key.generation, &key.catalog).is_none()
        {
            match result {
                Ok(result) => {
                    let phase = match &result {
                        Reconciled::Pending(probe) => match probe.phase {
                            ProbePhase::Preflight => OwnerPhase::Preflight,
                            ProbePhase::Readback
                            | ProbePhase::Current
                            | ProbePhase::CurrentEn
                            | ProbePhase::CurrentZh => OwnerPhase::Readback,
                        },
                        Reconciled::Ready(_) => OwnerPhase::Ready,
                        Reconciled::Disabled => OwnerPhase::Disabled,
                        Reconciled::WaitingProcess => OwnerPhase::WaitingProcess,
                        Reconciled::NotApplicable => OwnerPhase::NotApplicable,
                        Reconciled::Unsupported(reason) => {
                            OwnerPhase::Unsupported(bounded_reason(reason))
                        }
                    };
                    let completion = phase.completion();
                    state.observation = Some((key.clone(), phase));
                    state.completed = Some(key);
                    match result {
                        Reconciled::Pending(probe) => {
                            state.admission = Some(probe.configuration.clone());
                            state.probe = Some(*probe);
                            state.retry_after =
                                Some(std::time::Instant::now() + Duration::from_secs(2));
                        }
                        Reconciled::Ready(configuration) => {
                            state.current_seed = state.probe.clone();
                            state.current_refresh = None;
                            state.admission = Some(configuration);
                            state.probe = None;
                        }
                        Reconciled::Disabled
                        | Reconciled::WaitingProcess
                        | Reconciled::NotApplicable
                        | Reconciled::Unsupported(_) => {
                            state.admission = None;
                            state.probe = None;
                        }
                    }
                    return Ok(completion);
                }
                Err(error) => {
                    let reason = match error {
                        ReconcileError::Inventory(reason) | ReconcileError::Owner(reason) => reason,
                    };
                    state.observation = Some((key, OwnerPhase::Failed(bounded_reason(&reason))));
                    state.admission = None;
                    state.probe = None;
                    state.completed = None;
                    state.retry_after = Some(std::time::Instant::now() + Duration::from_secs(2));
                    return Err(reason);
                }
            }
        }
        // A cancelled job may have consumed a phase ACK. Start a fresh probe,
        // never retain a ticket whose one-shot proof could already be spent.
        state.probe = None;
        state.admission = None;
        state.completed = None;
    }
    if state.probe.is_none() && ready_for(&state, &key.generation, &key.catalog) {
        maintain_current(&mut state, endpoint, locale_endpoint)?;
    }
    if state.probe.is_none()
        && state
            .completed
            .as_ref()
            .is_some_and(|previous| previous == &key || may_retain_prepared(previous, &key))
    {
        return Ok(state
            .observation
            .as_ref()
            .map_or(Observation::Pending, |(_, phase)| phase.completion()));
    }
    if state
        .retry_after
        .is_some_and(|deadline| std::time::Instant::now() < deadline)
    {
        return Ok(Observation::Pending);
    }
    let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let child = cancelled.clone();
    let owned = generation.clone();
    let context = endpoint.cloned();
    let locale_context = locale_endpoint.cloned();
    let requested = key.enabled;
    let previous_probe = state.probe.clone();
    let failure_key = key.clone();
    if RUNNING
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
        .is_err()
    {
        return Ok(Observation::Pending);
    }
    let thread = std::thread::Builder::new()
        .name("i18n-resources".into())
        .spawn(move || {
            let _running = Running;
            let result = reconcile(
                owner,
                &owned,
                requested,
                context.as_ref(),
                locale_context.as_ref(),
                previous_probe,
                &child,
            );
            if let Err(ReconcileError::Inventory(reason)) = &result {
                record_inventory_failure(&failure_key, reason);
            }
            result
        })
        .map_err(|e| {
            RUNNING.store(false, std::sync::atomic::Ordering::Release);
            e.to_string()
        })?;
    state.active = Some(Job {
        key,
        cancelled,
        thread,
    });
    Ok(Observation::Pending)
}
/// Derived probe request or completed resource admission, never canonical user intent.
#[cfg(test)]
pub(crate) fn configuration_for_generation(
    generation: &str,
    catalog: &str,
    process: &str,
) -> Option<serde_json::Value> {
    configuration_for_agent_generation("i18n-ru", generation, catalog, process)
}
pub(crate) fn configuration_for_agent_generation(
    agent: &str,
    generation: &str,
    catalog: &str,
    process: &str,
) -> Option<serde_json::Value> {
    if inventory_failure(generation, catalog).is_some() {
        return None;
    }
    let owner = Owner::from_agent_process(agent, process).ok()?;
    let state = worker(owner).lock().ok()?;
    let key = state.completed.as_ref()?;
    if !key.enabled || key.generation != generation || key.catalog != catalog {
        return None;
    }
    let mut configuration = state.admission.clone()?;
    if let Some(refresh) = state.current_refresh.as_ref() {
        let current = refresh.probe.configuration.get("resourceProbe")?.clone();
        configuration
            .as_object_mut()?
            .insert("resourceProbe".into(), current);
    }
    if configuration.get("resourceAdmission").is_some() && !ready_for(&state, generation, catalog) {
        return None;
    }
    drop(state);
    if inventory_failure(generation, catalog).is_some() {
        return None;
    }
    Some(configuration)
}
fn ready_for(state: &Worker, generation: &str, catalog: &str) -> bool {
    state.completed.as_ref().is_some_and(|key| {
        key.enabled
            && key.generation == generation
            && key.catalog == catalog
            && key.endpoint.is_some()
    }) && state
        .admission
        .as_ref()
        .is_some_and(|value| value.get("resourceAdmission").is_some())
}
/// A bounded summary of consumed, root-issued RU overlay probes; this does not
/// describe the current locale of the process or a rendered view.
pub(crate) fn readback_summaries(
    generation: &str,
    catalog: &str,
    current: bool,
) -> crate::status::I18nReadbacks {
    let mut rows = Vec::new();
    let mut current_phase = None;
    for owner in Owner::ALL {
        let proof = if current {
            probes::current_published(owner)
        } else {
            probes::published(owner)
        };
        let Some(proof) = proof else { continue };
        let Ok(state) = worker(owner).lock() else {
            continue;
        };
        if !ready_for(&state, generation, catalog) {
            continue;
        }
        let Some(key) = state.completed.as_ref() else {
            continue;
        };
        let Some(endpoint) = key.endpoint.as_ref() else {
            continue;
        };
        if endpoint.target_pid != proof.binding.target_pid
            || endpoint.target_starttime != proof.binding.target_starttime
            || endpoint.endpoint_epoch != proof.binding.endpoint_epoch
            || endpoint.generation_id != proof.binding.generation_id
            || endpoint.catalog_sha256 != proof.binding.catalog_sha256
        {
            continue;
        }
        if current
            && (state.current_locale_confirmed != Some(proof.phase)
                || !state
                    .current_refresh
                    .as_ref()
                    .is_some_and(|refresh| refresh.completed))
        {
            continue;
        }
        if !current && endpoint != &proof.binding {
            continue;
        }
        if current {
            if current_phase.is_some_and(|phase| phase != proof.phase) {
                continue;
            }
            current_phase = Some(proof.phase);
        }
        let Some(age_ms) = proof.age_ms() else {
            continue;
        };
        rows.push(crate::status::I18nReadback {
            owner: owner.process().into(),
            profile: proof.profile,
            probe_revision: proof.probe_revision.to_string(),
            age_ms,
            binding: proof.binding,
        });
    }
    crate::status::I18nReadbacks {
        schema: 1,
        kind: if current {
            match current_phase {
                Some(ProbePhase::CurrentEn) => "current-en-owner-resource-readback",
                Some(ProbePhase::CurrentZh) => "current-zh-owner-resource-readback",
                _ => "current-owner-resource-readback",
            }
        } else {
            "forced-ru-resource-readback"
        }
        .into(),
        owners: rows,
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct ScopeSnapshot {
    generation: String,
    catalog: String,
    owners: Vec<(Owner, OwnerPhase)>,
    inventory_failure: Option<String>,
    complete: bool,
}
fn scope_snapshot(
    generation: &str,
    catalog: &str,
    declared: &std::collections::BTreeSet<Owner>,
) -> ScopeSnapshot {
    let owners: Vec<_> = declared
        .iter()
        .map(|owner| {
            let phase = worker(*owner)
                .lock()
                .ok()
                .map(|state| {
                    if ready_for(&state, generation, catalog) {
                        return OwnerPhase::Ready;
                    }
                    state
                        .observation
                        .as_ref()
                        .filter(|(key, _)| same_generation(key, generation, catalog))
                        .map(|(_, phase)| {
                            if *phase == OwnerPhase::Ready {
                                OwnerPhase::Unobserved
                            } else {
                                phase.clone()
                            }
                        })
                        .unwrap_or(OwnerPhase::Unobserved)
                })
                .unwrap_or(OwnerPhase::Unobserved);
            (*owner, phase)
        })
        .collect();
    let fault = inventory_failure(generation, catalog);
    let complete = fault.is_none()
        && !owners.is_empty()
        && owners.iter().all(|(_, phase)| *phase == OwnerPhase::Ready);
    ScopeSnapshot {
        generation: generation.into(),
        catalog: catalog.into(),
        owners,
        inventory_failure: fault,
        complete,
    }
}
fn changed_scope(previous: &mut Option<ScopeSnapshot>, next: &ScopeSnapshot) -> bool {
    if previous.as_ref() == Some(next) {
        return false;
    }
    *previous = Some(next.clone());
    true
}
pub(crate) fn report_scope(generation: &crate::generation::VerifiedGeneration) {
    static LAST: std::sync::OnceLock<std::sync::Mutex<Option<ScopeSnapshot>>> =
        std::sync::OnceLock::new();
    let snapshot = match declared_owners(&generation.catalog) {
        Ok(declared) => scope_snapshot(&generation.id, &generation.catalog_sha256, &declared),
        Err(reason) => ScopeSnapshot {
            generation: generation.id.clone(),
            catalog: generation.catalog_sha256.clone(),
            owners: Vec::new(),
            inventory_failure: Some(reason),
            complete: false,
        },
    };
    let publish = LAST
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .ok()
        .is_some_and(|mut previous| changed_scope(&mut previous, &snapshot));
    if publish {
        let owners = snapshot.owners.iter().map(|(owner,phase)|serde_json::json!({"owner":owner.process(),"agent":owner.agent(),"phase":phase.name(),"reason":phase.reason()})).collect::<Vec<_>>();
        crate::log::debug_fields(
            "i18n-resources",
            "resource.scope",
            [
                ("scope".into(), "declared-android-resources".into()),
                ("generation".into(), snapshot.generation),
                ("catalog".into(), snapshot.catalog),
                ("complete".into(), snapshot.complete.to_string()),
                (
                    "owners".into(),
                    serde_json::Value::Array(owners).to_string(),
                ),
                (
                    "reason".into(),
                    snapshot.inventory_failure.unwrap_or_default(),
                ),
            ]
            .into(),
        );
    }
}
pub(crate) fn quiesce() -> bool {
    let mut stopped = true;
    for owner in Owner::ALL_RESOURCES {
        let Ok(mut state) = worker(owner).lock() else {
            return false;
        };
        state.admission = None;
        state.probe = None;
        state.completed = None;
        state.observation = None;
        if let Some(job) = &state.active {
            job.cancelled
                .store(true, std::sync::atomic::Ordering::Release);
            if !job.thread.is_finished() {
                stopped = false;
                continue;
            }
        }
        if let Some(job) = state.active.take() {
            let _ = job.thread.join();
        }
    }
    stopped
}
fn fence(
    owner: Owner,
    generation: &crate::generation::VerifiedGeneration,
    requested: bool,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<(), String> {
    if cancelled.load(std::sync::atomic::Ordering::Acquire)
        || std::path::Path::new(&crate::config::kill_switch_file()).exists()
        || crate::uninstall::request_present()
        || crate::uninstall::prepared_marker_valid()
        || crate::product_candidate::reboot_required()
        || crate::generation::GenerationStore::production()
            .active_id()
            .as_deref()
            != Some(generation.id.as_str())
    {
        return Err("i18n resource ticket cancelled or generation changed".into());
    }
    let current = crate::plan::read_runtime_and_validate(generation);
    if !current.valid || enabled_agent(&current, owner.agent()) != requested {
        return Err("i18n resource desired changed".into());
    }
    Ok(())
}
fn load_resources(
    generation: &crate::generation::VerifiedGeneration,
) -> Result<Vec<OwnedResourceArtifact>, String> {
    let manifest = crate::installed_product::load_manifest()?;
    let artifacts: Vec<_> = manifest
        .artifacts
        .iter()
        .filter(|a| a.role == voboost_contract::release::ArtifactRole::ResourceApk)
        .collect();
    if artifacts.is_empty() {
        return Ok(Vec::new());
    }
    if artifacts.len() > Variant::ALL.len() {
        return Err("resource variant count exceeds bound".into());
    }
    let root = Directory::open(Path::new(crate::config::ROOT_ZONE)).map_err(|e| e.to_string())?;
    let parent = root
        .open_child("i18n-resource-transaction")
        .map_err(|e| e.to_string())?;
    parent
        .validate_owner_mode(0, 0, 0o700)
        .map_err(|e| e.to_string())?;
    let mut variants = std::collections::BTreeSet::new();
    let mut resources = Vec::new();
    for artifact in artifacts {
        let variant = Variant::from_artifact_file(&artifact.file)?;
        if !variants.insert(variant) {
            return Err("duplicate resource variant".into());
        }
        let journal = parent
            .open_child(variant.profile())
            .map_err(|e| e.to_string())?;
        journal
            .validate_owner_mode(0, 0, 0o700)
            .map_err(|e| e.to_string())?;
        let slot = journal
            .open_child(&format!("authority-{}", manifest.digest()?))
            .map_err(|e| e.to_string())?;
        let read = |name, max| {
            slot.read_trusted(name, max, 0o600)
                .map_err(|e| e.to_string())
        };
        let manifest_bytes = read("product-manifest.json", 1024 * 1024)?;
        let signature = read("product-manifest.sig", 64)?;
        let catalog = read("catalog.json", 1024 * 1024)?;
        let apk = read("resource.apk", 16 * 1024 * 1024)?;
        let ledger = read("resource-ledger.json", 1024 * 1024)?;
        let resource =
            OwnedResourceArtifact::verify(voboost_contract::resource::SignedResourceInputs {
                manifest_bytes: &manifest_bytes,
                manifest_signature: &signature,
                product_public_key: &crate::trust::release_catalog_public_key(),
                artifact_file: &artifact.file,
                catalog_bytes: &catalog,
                apk_bytes: &apk,
                ledger_bytes: &ledger,
            })?;
        if resource.manifest_sha256() != manifest.digest()?
            || resource.catalog_sha256() != generation.catalog_sha256
            || resource_variant(&resource)? != variant
        {
            return Err("resource authority differs from active generation".into());
        }
        resources.push(resource);
    }
    Ok(resources)
}
fn reconcile(
    owner: Owner,
    generation: &crate::generation::VerifiedGeneration,
    requested: bool,
    endpoint: Option<&crate::agent_log::EndpointContext>,
    locale_endpoint: Option<&crate::agent_log::EndpointContext>,
    previous_probe: Option<PendingProbe>,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<Reconciled, ReconcileError> {
    fence(owner, generation, requested, cancelled)?;
    let all = load_resources(generation).map_err(ReconcileError::Inventory)?;
    let declared = declared_owners(&generation.catalog).map_err(ReconcileError::Inventory)?;
    let variants = all
        .iter()
        .map(resource_variant)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ReconcileError::Inventory)?;
    let current = crate::plan::read_runtime_and_validate(generation);
    if !current.valid {
        return Err(ReconcileError::Owner("i18n resource plan invalid".into()));
    }
    // Missing EN deltas are owner-local. RU retains complete declared coverage.
    validate_inventory(&declared, &variants, enabled_agent(&current, "i18n-ru"))
        .map_err(ReconcileError::Inventory)?;
    fence(owner, generation, requested, cancelled)?;
    clear_inventory_failure(&generation.id, &generation.catalog_sha256);
    let resources = all
        .into_iter()
        .filter(|resource| resource_variant(resource).is_ok_and(|variant| variant.owner() == owner))
        .collect::<Vec<_>>();
    if requested && owner.agent() == "i18n-en" && resources.is_empty() {
        return Ok(Reconciled::NotApplicable);
    }
    reconcile_owner(
        generation,
        requested,
        endpoint,
        locale_endpoint,
        previous_probe,
        cancelled,
        resources,
    )
    .map_err(ReconcileError::Owner)
}
fn declared_owners(
    catalog: &crate::catalog::AgentCatalog,
) -> Result<std::collections::BTreeSet<Owner>, String> {
    catalog
        .agents
        .iter()
        .filter(|agent| matches!(agent.id.as_str(), "i18n-ru" | "i18n-en"))
        .flat_map(|agent| agent.targets.iter().map(move |target| (agent, target)))
        .filter(|(_, target)| target.platform == crate::catalog::TargetPlatform::Android)
        .map(|(agent, target)| Owner::from_agent_process(&agent.id, &target.process))
        .collect()
}
fn validate_inventory(
    declared: &std::collections::BTreeSet<Owner>,
    variants: &[Variant],
    requested: bool,
) -> Result<(), String> {
    if variants
        .iter()
        .any(|variant| !declared.contains(&variant.owner()))
    {
        return Err("resource owner absent from signed target declaration".into());
    }
    if requested
        && declared.iter().any(|owner| {
            owner.agent() == "i18n-ru" && !variants.iter().any(|variant| variant.owner() == *owner)
        })
    {
        return Err("declared resource owner has no authenticated payload".into());
    }
    Ok(())
}
fn reconcile_owner(
    generation: &crate::generation::VerifiedGeneration,
    requested: bool,
    endpoint: Option<&crate::agent_log::EndpointContext>,
    locale_endpoint: Option<&crate::agent_log::EndpointContext>,
    previous_probe: Option<PendingProbe>,
    cancelled: &std::sync::atomic::AtomicBool,
    resources: Vec<OwnedResourceArtifact>,
) -> Result<Reconciled, String> {
    let Some(first) = resources.first() else {
        return Ok(Reconciled::Disabled);
    };
    let owner = resource_variant(first)?.owner();
    let guard = crate::operation_contract::GenerationGuard::acquire_in(Path::new(
        crate::config::ROOT_ZONE,
    ))?;
    let mut validate = || {
        fence(owner, generation, requested, cancelled)?;
        guard.verify_owner()
    };
    validate()?;
    if !requested {
        deactivate_resources(&resources, None, locale_endpoint, &mut validate)?;
        validate()?;
        return Ok(Reconciled::Disabled);
    }
    let Some(endpoint) = endpoint else {
        return Ok(Reconciled::WaitingProcess);
    };
    let Some(probe) =
        previous_probe.filter(|probe| probe.started.elapsed() <= Duration::from_secs(30))
    else {
        if owner.agent() == "i18n-ru" {
            let states = resources
                .iter()
                .map(|resource| {
                    verify_system_scan(resource)?;
                    observe_for(resource_variant(resource)?)
                })
                .collect::<Result<Vec<_>, String>>()?;
            if let Some(index) = rebind_index(owner, &states)? {
                // An already-enabled signed RU overlay survives its owner process.
                // Re-probe capabilities and Resources in the new endpoint; changing
                // the native language or disabling its overlay is not required.
                validate()?;
                let resource = &resources[index];
                let ledger =
                    serde_json::from_slice(resource.ledger_bytes()).map_err(|e| e.to_string())?;
                return request_probe(
                    generation,
                    resource,
                    endpoint,
                    ledger,
                    ProbePhase::Readback,
                    None,
                );
            }
        }
        // New RU admission and EN deltas require an unoverlaid native baseline.
        deactivate_resources(&resources, None, locale_endpoint, &mut validate)?;
        return request_preflight_batch(generation, &resources, endpoint);
    };
    match probe.phase {
        ProbePhase::Preflight => {
            let Some(result) = probes::take_unique_preflight(&probe.tickets, endpoint) else {
                return Ok(Reconciled::Pending(Box::new(probe)));
            };
            let compatibility = match result {
                Ok(proof) => proof,
                Err(reason) => {
                    deactivate_resources(&resources, None, locale_endpoint, &mut validate)?;
                    if owner.agent() == "i18n-en" && reason == probes::PreflightMismatch::NoMatch {
                        return Ok(Reconciled::NotApplicable);
                    }
                    return Ok(Reconciled::Unsupported(reason.reason().into()));
                }
            };
            if crate::control_plane::endpoint_binding(endpoint).as_ref()
                != Some(compatibility.binding())
            {
                return Err("i18n preflight endpoint changed".into());
            }
            let resource = resources
                .iter()
                .find(|r| resource_profile(r).ok() == Some(compatibility.profile()))
                .ok_or("resource winner is not an admitted candidate")?;
            deactivate_resources(
                &resources,
                Some(compatibility.profile()),
                locale_endpoint,
                &mut validate,
            )?;
            enable(resource, &compatibility, &mut validate)?;
            validate()?;
            write_phase(resource, "oms-enabled-awaiting-owner-readback")?;
            let ledger =
                serde_json::from_slice(resource.ledger_bytes()).map_err(|e| e.to_string())?;
            request_probe(
                generation,
                resource,
                endpoint,
                ledger,
                ProbePhase::Readback,
                Some(probe.revision),
            )
        }
        ProbePhase::Current | ProbePhase::CurrentEn | ProbePhase::CurrentZh => {
            Err("current resource refresh is not wired".into())
        }
        ProbePhase::Readback => {
            let Some(readback) = probes::take_readback(&probe.ticket, endpoint) else {
                return Ok(Reconciled::Pending(Box::new(probe)));
            };
            if crate::control_plane::endpoint_binding(endpoint).as_ref() != Some(readback.binding())
            {
                return Err("i18n readback endpoint changed".into());
            }
            let resource = resources
                .iter()
                .find(|r| resource_profile(r).ok() == Some(readback.profile()))
                .ok_or("resource readback owner is not admitted")?;
            verify_system_scan(resource)?;
            if observe_for(resource_variant(resource)?)? != OverlayState::Enabled {
                return Err("i18n overlay no longer enabled at readback".into());
            }
            for other in &resources {
                if resource_profile(other)? != readback.profile()
                    && observe_for(resource_variant(other)?)? == OverlayState::Enabled
                {
                    return Err("nonselected resource variant became enabled".into());
                }
            }
            validate()?;
            write_phase(resource, "enabled-owner-readback-confirmed")?;
            let ledger =
                serde_json::from_slice(resource.ledger_bytes()).map_err(|e| e.to_string())?;
            Ok(Reconciled::Ready(
                serde_json::json!({"resourceAdmission":resource_projection(generation,resource,&ledger)?}),
            ))
        }
    }
}
fn rebind_index(owner: Owner, states: &[OverlayState]) -> Result<Option<usize>, String> {
    if owner.agent() != "i18n-ru" {
        return Ok(None);
    }
    let mut enabled = states
        .iter()
        .enumerate()
        .filter_map(|(index, state)| (*state == OverlayState::Enabled).then_some(index));
    let result = enabled.next();
    if enabled.next().is_some() {
        return Err("multiple resource variants enabled before owner rebind".into());
    }
    Ok(result)
}
fn deactivate_resources(
    resources: &[OwnedResourceArtifact],
    keep: Option<&str>,
    endpoint: Option<&crate::agent_log::EndpointContext>,
    validate: &mut impl FnMut() -> Result<(), String>,
) -> Result<(), String> {
    for resource in resources {
        if keep == Some(resource_profile(resource)?) {
            continue;
        }
        validate()?;
        verify_system_scan(resource)?;
        let state = observe_for(resource_variant(resource)?)?;
        if state == OverlayState::Enabled {
            if resource.descriptor().owner == "i18n-en" {
                set_enabled_after_verified_scan(resource, false, validate)?;
            } else {
                disable(
                    resource,
                    endpoint.ok_or("native locale cleanup endpoint unavailable")?,
                    validate,
                )?;
            }
            validate()?;
            write_phase(resource, "oms-disabled-awaiting-owner-readback")?;
        } else if state == OverlayState::Disabled {
            write_phase(resource, "oms-disabled-awaiting-owner-readback")?;
        }
        // An inert, nonmatching variant may have no idmap. This is not enabled
        // and is not reported as an OMS-disabled/readback proof.
    }
    Ok(())
}
fn resource_profile(resource: &OwnedResourceArtifact) -> Result<&'static str, String> {
    Ok(Variant::from_artifact_file(&resource.artifact().file)?.profile())
}
fn resource_variant(resource: &OwnedResourceArtifact) -> Result<Variant, String> {
    let variant = Variant::from_profile(resource_profile(resource)?)?;
    let descriptor = resource.descriptor();
    if descriptor.owner != variant.owner().agent()
        || descriptor.locale != variant.owner().locale()
        || descriptor.target_package != variant.owner().process()
        || descriptor.overlay_package != variant.package()
    {
        return Err("owned resource variant tuple differs".into());
    }
    Ok(variant)
}
fn resource_projection(
    generation: &crate::generation::VerifiedGeneration,
    resource: &OwnedResourceArtifact,
    ledger: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let descriptor = resource.descriptor();
    admission_projection(
        &generation.id,
        resource_profile(resource)?,
        &descriptor.target_package,
        &descriptor.overlay_package,
        ledger,
    )
}
fn admission_projection(
    generation: &str,
    profile: &str,
    target_package: &str,
    overlay_package: &str,
    ledger: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let readback = ledger
        .get("expectedReadback")
        .and_then(serde_json::Value::as_object)
        .filter(|map| {
            !map.is_empty() && map.len() <= 64 && map.values().all(serde_json::Value::is_string)
        })
        .ok_or("signed resource expected readback absent")?;
    let scope = ledger
        .get("scope")
        .and_then(serde_json::Value::as_str)
        .ok_or("resource coverage scope absent")?;
    Ok(serde_json::json!({
        "schema": 1,
        "generation": generation,
        "observedGeneration": generation,
        "profile": profile,
        "targetPackage": target_package,
        "overlayPackage": overlay_package,
        "scope": scope,
        "enabled": true,
        "omsEnabled": true,
        "expectedReadback": readback
    }))
}
fn next_probe_revision() -> Result<u64, String> {
    static REVISION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let revision = REVISION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if revision == 0 {
        return Err("i18n probe revision exhausted".into());
    }
    Ok(revision)
}
fn request_probe(
    generation: &crate::generation::VerifiedGeneration,
    resource: &OwnedResourceArtifact,
    endpoint: &crate::agent_log::EndpointContext,
    ledger: serde_json::Value,
    phase: ProbePhase,
    revision: Option<u64>,
) -> Result<Reconciled, String> {
    let revision = match revision {
        Some(value) => value,
        None => next_probe_revision()?,
    };
    if revision == 0 {
        return Err("i18n probe revision exhausted".into());
    }
    let descriptor = ProbeDescriptor {
        schema: 1,
        phase,
        probe_revision: revision,
        profile: resource_profile(resource)?.into(),
        target_package: resource.descriptor().target_package.clone(),
        ledger: ledger.clone(),
    };
    let ticket = probes::begin_probe(endpoint, &descriptor)?;
    let mut projection = resource_projection(generation, resource, &ledger)?;
    let object = projection
        .as_object_mut()
        .ok_or("i18n resource projection invalid")?;
    object.insert(
        "phase".into(),
        serde_json::json!(match phase {
            ProbePhase::Preflight => "preflight",
            ProbePhase::Readback => "readback",
            ProbePhase::Current => "current",
            ProbePhase::CurrentEn => "current-en",
            ProbePhase::CurrentZh => "current-zh",
        }),
    );
    object.insert("probeRevision".into(), serde_json::json!(revision));
    object.insert(
        "profile".into(),
        serde_json::json!(resource_profile(resource)?),
    );
    object.insert(
        "omsEnabled".into(),
        serde_json::json!(phase != ProbePhase::Preflight),
    );
    Ok(Reconciled::Pending(Box::new(PendingProbe {
        tickets: vec![ticket.clone()],
        ticket,
        phase,
        revision,
        configuration: serde_json::json!({"resourceProbe":projection}),
        started: std::time::Instant::now(),
    })))
}
fn request_preflight_batch(
    generation: &crate::generation::VerifiedGeneration,
    resources: &[OwnedResourceArtifact],
    endpoint: &crate::agent_log::EndpointContext,
) -> Result<Reconciled, String> {
    if resources.is_empty() || resources.len() > Owner::CANDIDATE_LIMIT {
        return Err("resource candidate batch shape invalid".into());
    }
    let revision = next_probe_revision()?;
    let mut descriptors = Vec::new();
    let mut projections = Vec::new();
    for resource in resources {
        let ledger: serde_json::Value =
            serde_json::from_slice(resource.ledger_bytes()).map_err(|e| e.to_string())?;
        descriptors.push(ProbeDescriptor {
            schema: 1,
            phase: ProbePhase::Preflight,
            probe_revision: revision,
            profile: resource_profile(resource)?.into(),
            target_package: resource.descriptor().target_package.clone(),
            ledger: ledger.clone(),
        });
        let mut projection = resource_projection(generation, resource, &ledger)?;
        let object = projection
            .as_object_mut()
            .ok_or("resource probe projection invalid")?;
        object.insert("phase".into(), serde_json::json!("preflight"));
        object.insert("probeRevision".into(), serde_json::json!(revision));
        object.insert("omsEnabled".into(), serde_json::json!(false));
        projections.push(projection);
    }
    let tickets = probes::begin_probes(endpoint, &descriptors)?;
    let ticket = tickets
        .first()
        .cloned()
        .ok_or("resource batch ticket absent")?;
    Ok(Reconciled::Pending(Box::new(PendingProbe {
        ticket,
        tickets,
        phase: ProbePhase::Preflight,
        revision,
        configuration: serde_json::json!({"resourceProbes":projections}),
        started: std::time::Instant::now(),
    })))
}
fn write_phase(resource: &OwnedResourceArtifact, phase: &str) -> Result<(), String> {
    let root = Directory::open(Path::new(crate::config::ROOT_ZONE)).map_err(|e| e.to_string())?;
    let journal = root
        .open_child("i18n-resource-transaction")
        .map_err(|e| e.to_string())?;
    let journal = journal
        .open_child(resource_variant(resource)?.profile())
        .map_err(|e| e.to_string())?;
    let _lock = journal
        .lock_transaction(Duration::from_secs(5))
        .map_err(|e| e.to_string())?;
    let bytes = journal
        .read_trusted("resource-transaction.json", 4096, 0o600)
        .map_err(|e| e.to_string())?;
    let mut receipt: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if receipt["generation"].as_str() != Some(resource.manifest_sha256())
        || receipt["overlaySha256"].as_str() != Some(resource.artifact().sha256.as_str())
    {
        return Err("resource journal authority changed".into());
    }
    receipt["phase"] = serde_json::json!(phase);
    journal
        .write_atomic(
            "resource-transaction.json",
            &serde_json::to_vec(&receipt).map_err(|e| e.to_string())?,
            0o600,
        )
        .map_err(|e| e.to_string())
}
