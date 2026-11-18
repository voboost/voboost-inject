use super::*;
use serde_json::json;
use std::collections::BTreeMap;

const BOOT: &str = "11111111-1111-4111-8111-111111111111";
const NEXT_BOOT: &str = "22222222-2222-4222-8222-222222222222";

fn config() -> Config {
    Config::new("interface", BTreeMap::new()).unwrap()
}

fn checkbox(id: &str) -> Field {
    Field::Enabled { agent: id.into() }
}

fn input(epoch: u64, request: u64) -> Input {
    Input {
        boot_id: BOOT.into(),
        endpoint_epoch: epoch,
        request_id: request,
        injector_pid: 42,
        injector_starttime: 100,
    }
}

fn bytes(config: &Config) -> Vec<u8> {
    serde_json::to_vec(config).unwrap()
}

#[test]
fn schema_one_is_rejected_without_migration_or_defaults() {
    assert!(Config::decode(br#"{"schemaVersion":1,"startup":"interface","agents":{}}"#).is_err());
    let original = config();
    assert_eq!(
        bytes(&Config::decode(&bytes(&original)).unwrap()),
        bytes(&original)
    );
}

#[test]
fn owner_revision_is_assigned_atomically_and_values_are_stored_once() {
    let mut config = config();
    assert_eq!(
        config
            .save(
                BOOT,
                &checkbox("launcher"),
                &false.into(),
                &input(1, 8),
                &[]
            )
            .unwrap(),
        Disposition::Saved
    );
    assert_eq!(config.user_revision, 1);
    let document: Value = serde_json::from_slice(&bytes(&config)).unwrap();
    assert_eq!(document["agents"]["launcher"]["enabled"], false);
    let stamp = &document["fieldRevisions"]["agents/launcher/enabled"];
    assert_eq!(stamp["revision"], 1);
    assert!(stamp.get("value").is_none());
}

#[test]
fn field_b_high_request_never_discards_field_a_low_request() {
    let mut config = config();
    config
        .save(
            BOOT,
            &checkbox("keyboard-ru"),
            &false.into(),
            &input(1, 900),
            &[],
        )
        .unwrap();
    assert_eq!(
        config
            .save(
                BOOT,
                &checkbox("launcher"),
                &false.into(),
                &input(1, 7),
                &[]
            )
            .unwrap(),
        Disposition::Saved
    );
    assert_eq!(config.user_revision, 2);
    assert!(!config.agents["launcher"].enabled);
}

#[test]
fn same_origin_late_request_never_rearms_a_newer_off() {
    let mut config = config();
    config
        .save(
            BOOT,
            &checkbox("launcher"),
            &false.into(),
            &input(1, 8),
            &[],
        )
        .unwrap();
    let before = bytes(&config);
    assert_eq!(
        config
            .save(BOOT, &checkbox("launcher"), &true.into(), &input(1, 7), &[])
            .unwrap(),
        Disposition::Superseded
    );
    assert_eq!(bytes(&config), before);
}

#[test]
fn exact_replay_preserves_revision_and_conflicting_payload_never_writes() {
    let mut config = config();
    let identity = input(1, 8);
    config
        .save(BOOT, &checkbox("launcher"), &false.into(), &identity, &[])
        .unwrap();
    let before = bytes(&config);
    assert_eq!(
        config
            .save(BOOT, &checkbox("launcher"), &false.into(), &identity, &[])
            .unwrap(),
        Disposition::Replayed
    );
    assert!(config
        .save(BOOT, &checkbox("launcher"), &true.into(), &identity, &[])
        .is_err());
    assert_eq!(bytes(&config), before);
}

#[test]
fn different_live_origins_linearize_at_owner_admission_without_client_time() {
    let mut config = config();
    config
        .save(
            BOOT,
            &checkbox("launcher"),
            &true.into(),
            &input(1, 900),
            &[],
        )
        .unwrap();
    config
        .save(
            BOOT,
            &checkbox("launcher"),
            &false.into(),
            &input(2, 1),
            &[],
        )
        .unwrap();
    let before = bytes(&config);
    assert_eq!(
        config
            .save(
                BOOT,
                &checkbox("launcher"),
                &true.into(),
                &input(1, 900),
                &[]
            )
            .unwrap(),
        Disposition::Superseded
    );
    assert_eq!(bytes(&config), before);
    assert!(!config.agents["launcher"].enabled);
}

#[test]
fn owner_restart_retains_field_order_and_lost_ack_replay() {
    let mut original = config();
    original
        .save(
            BOOT,
            &checkbox("launcher"),
            &false.into(),
            &input(1, 8),
            &[],
        )
        .unwrap();
    let mut restarted = Config::decode(&bytes(&original)).unwrap();
    assert_eq!(
        restarted
            .save(
                BOOT,
                &checkbox("launcher"),
                &false.into(),
                &input(1, 8),
                &[]
            )
            .unwrap(),
        Disposition::Replayed
    );
    assert_eq!(
        restarted
            .save(BOOT, &checkbox("launcher"), &true.into(), &input(1, 7), &[])
            .unwrap(),
        Disposition::Superseded
    );
    assert_eq!(bytes(&restarted), bytes(&original));
}

#[test]
fn reboot_accepts_new_boot_input_and_rejects_prior_boot_transport() {
    let mut config = config();
    config
        .save(
            BOOT,
            &checkbox("launcher"),
            &true.into(),
            &input(1, 900),
            &[],
        )
        .unwrap();
    let mut next = input(2, 1);
    next.boot_id = NEXT_BOOT.into();
    config
        .save(NEXT_BOOT, &checkbox("launcher"), &false.into(), &next, &[])
        .unwrap();
    let before = bytes(&config);
    assert!(config
        .save(
            NEXT_BOOT,
            &checkbox("launcher"),
            &true.into(),
            &input(1, 901),
            &[]
        )
        .is_err());
    assert_eq!(bytes(&config), before);
}

#[test]
fn trusted_checkbox_dependencies_share_one_revision_and_cannot_partially_apply() {
    let mut config = config();
    config
        .save(
            BOOT,
            &checkbox("keyboard-ru"),
            &true.into(),
            &input(1, 8),
            &[],
        )
        .unwrap();
    config
        .save(
            BOOT,
            &checkbox("keyboard-en"),
            &true.into(),
            &input(1, 9),
            &["keyboard-ru".into()],
        )
        .unwrap();
    assert!(config.agents["keyboard-en"].enabled);
    assert!(!config.agents["keyboard-ru"].enabled);
    assert_eq!(
        config.field_revisions["agents/keyboard-en/enabled"].revision,
        2
    );
    assert_eq!(
        config.field_revisions["agents/keyboard-ru/enabled"].revision,
        2
    );
    let before = bytes(&config);
    assert_eq!(
        config
            .save(
                BOOT,
                &checkbox("keyboard-fr"),
                &true.into(),
                &input(1, 7),
                &["keyboard-en".into()]
            )
            .unwrap(),
        Disposition::Superseded
    );
    assert_eq!(bytes(&config), before);
}

#[test]
fn unsupported_off_and_option_remain_desired_without_catalog_authority() {
    let mut config = config();
    config
        .save(
            BOOT,
            &checkbox("unavailable-agent"),
            &false.into(),
            &input(1, 1),
            &[],
        )
        .unwrap();
    let field = Field::Option {
        agent: "unavailable-agent".into(),
        key: "intent".into(),
    };
    config
        .save(BOOT, &field, &json!("off"), &input(1, 2), &[])
        .unwrap();
    assert!(!config.agents["unavailable-agent"].enabled);
    assert_eq!(config.agents["unavailable-agent"].options["intent"], "off");
}

#[test]
fn failed_validation_never_changes_any_field_or_revision() {
    let mut config = config();
    let before = bytes(&config);
    for (field, value, dependencies) in [
        (Field::Startup, json!("invalid"), vec![]),
        (
            checkbox("launcher"),
            json!(false),
            vec!["keyboard-en".into()],
        ),
        (checkbox("launcher"), json!(true), vec!["launcher".into()]),
        (checkbox("../outside"), json!(false), vec![]),
    ] {
        assert!(config
            .save(BOOT, &field, &value, &input(1, 1), &dependencies)
            .is_err());
        assert_eq!(bytes(&config), before);
    }
}

#[test]
fn revision_metadata_corruption_and_duplicate_json_keys_are_rejected() {
    let mut config = config();
    config
        .save(
            BOOT,
            &checkbox("launcher"),
            &false.into(),
            &input(1, 8),
            &[],
        )
        .unwrap();
    let mut value = serde_json::to_value(&config).unwrap();
    value["fieldRevisions"]["agents/launcher/enabled"]["revision"] = json!(99);
    assert!(Config::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    assert!(Config::decode(br#"{"schemaVersion":2,"schemaVersion":2,"startup":"interface","agents":{},"userRevision":0,"fieldRevisions":{}}"#).is_err());
}

fn store_fixture() -> (tempfile::TempDir, Store) {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::Builder::new()
        .prefix(".desired-owner-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut config = config();
    config
        .save(BOOT, &checkbox("launcher"), &true.into(), &input(1, 1), &[])
        .unwrap();
    Directory::open(root.path())
        .unwrap()
        .write_atomic("agents.json", &bytes(&config), 0o600)
        .unwrap();
    let mut store = Store::new(root.path(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    store.native_boot = Some(BOOT.into());
    store.native_enabled.insert("launcher".into());
    (root, store)
}

#[test]
fn saved_off_is_durable_while_the_product_operation_lock_is_held() {
    let (root, mut store) = store_fixture();
    let _lease = voboost_contract::operation::GenerationGuard::acquire_in(root.path()).unwrap();
    let saved = store
        .save_desired(&checkbox("launcher"), &false.into(), &input(1, 2))
        .unwrap();
    assert!(matches!(
        saved,
        Outcome::DesiredSaved {
            revision: 2,
            disposition: Disposition::Saved,
            ..
        }
    ));
    let durable = Config::decode(&std::fs::read(root.path().join("agents.json")).unwrap()).unwrap();
    assert!(!durable.agents["launcher"].enabled);
    assert_eq!(durable.user_revision, 2);
    // The installation lock cannot delay saving or revoking user OFF.
    assert!(!store.native_enabled.contains("launcher"));
    assert!(store.withdrawing.contains_key("launcher"));
}

#[test]
fn failed_off_write_revokes_before_persistence_and_replay_cannot_restore_on() {
    let (root, mut store) = store_fixture();
    let before = std::fs::read(root.path().join("agents.json")).unwrap();
    assert!(store
        .save_desired_with(
            &checkbox("launcher"),
            &false.into(),
            &input(1, 2),
            |_, _| { Err(io::Error::other("injected file fsync failure")) }
        )
        .is_err());
    assert_eq!(
        std::fs::read(root.path().join("agents.json")).unwrap(),
        before
    );
    assert!(!store.native_enabled.contains("launcher"));
    assert!(store.desired_off_fences.contains("agents/launcher/enabled"));
    let replay = store
        .save_desired(&checkbox("launcher"), &true.into(), &input(1, 1))
        .unwrap();
    assert!(matches!(
        replay,
        Outcome::DesiredSaved {
            disposition: Disposition::Replayed,
            ..
        }
    ));
    assert!(store.desired_off_fences.contains("agents/launcher/enabled"));
    assert!(!store.native_enabled.contains("launcher"));
}

#[test]
fn directory_fsync_uncertainty_never_returns_saved_ack() {
    let (root, mut store) = store_fixture();
    assert!(store
        .save_desired_with(
            &checkbox("launcher"),
            &false.into(),
            &input(1, 2),
            |directory, bytes| {
                directory.write_atomic("agents.json", bytes, 0o600)?;
                Err(io::Error::other(
                    "injected directory fsync uncertainty after rename",
                ))
            }
        )
        .is_err());
    assert!(store.desired_off_fences.contains("agents/launcher/enabled"));
    assert!(!store.native_enabled.contains("launcher"));
    let readable =
        Config::decode(&std::fs::read(root.path().join("agents.json")).unwrap()).unwrap();
    assert!(!readable.agents["launcher"].enabled);
    // Readable bytes after uncertain fsync do not prove power-loss durability.
}

#[test]
fn absent_catalog_does_not_prevent_saving_a_user_on_but_denies_effective_grant() {
    let (root, mut store) = store_fixture();
    let saved = store
        .save_desired(&checkbox("unavailable-agent"), &true.into(), &input(1, 2))
        .unwrap();
    assert!(matches!(
        saved,
        Outcome::DesiredSaved {
            disposition: Disposition::Saved,
            ..
        }
    ));
    let durable = Config::decode(&std::fs::read(root.path().join("agents.json")).unwrap()).unwrap();
    assert!(durable.agents["unavailable-agent"].enabled);
    assert!(store.desired_catalog_fences.contains("unavailable-agent"));
    assert!(!store.native_enabled.contains("unavailable-agent"));
}

#[test]
fn superseded_off_never_revokes_a_more_recent_user_on() {
    let (root, mut store) = store_fixture();
    let result = store.save_desired(&checkbox("launcher"), &false.into(), &input(1, 0));
    assert!(result.is_err());
    assert!(store.desired_off_fences.is_empty());
    assert!(store.native_enabled.contains("launcher"));
    let result = store.save_desired(&checkbox("launcher"), &false.into(), &input(1, 1));
    assert!(result.is_err());
    assert!(store.desired_off_fences.is_empty());
    assert!(store.native_enabled.contains("launcher"));
    let mut latest =
        Config::decode(&std::fs::read(root.path().join("agents.json")).unwrap()).unwrap();
    latest
        .save(BOOT, &checkbox("launcher"), &true.into(), &input(1, 3), &[])
        .unwrap();
    Directory::open(root.path())
        .unwrap()
        .write_atomic("agents.json", &bytes(&latest), 0o600)
        .unwrap();
    let result = store
        .save_desired(&checkbox("launcher"), &false.into(), &input(1, 2))
        .unwrap();
    assert!(matches!(
        result,
        Outcome::DesiredSaved {
            disposition: Disposition::Superseded,
            ..
        }
    ));
    assert!(store.desired_off_fences.is_empty());
    assert!(store.native_enabled.contains("launcher"));
}

#[test]
fn inject_restart_reusing_endpoint_one_does_not_alias_prior_producer() {
    let mut config = config();
    config
        .save(
            BOOT,
            &checkbox("launcher"),
            &false.into(),
            &input(1, 900),
            &[],
        )
        .unwrap();
    let mut new_input = input(1, 1);
    new_input.injector_pid = 43;
    new_input.injector_starttime = 200;
    assert_eq!(
        config
            .save(BOOT, &checkbox("launcher"), &true.into(), &new_input, &[])
            .unwrap(),
        Disposition::Saved
    );
    new_input.request_id = 2;
    config
        .save(BOOT, &checkbox("launcher"), &false.into(), &new_input, &[])
        .unwrap();
    let retained = bytes(&config);
    assert_eq!(
        config
            .save(
                BOOT,
                &checkbox("launcher"),
                &true.into(),
                &input(1, 899),
                &[]
            )
            .unwrap(),
        Disposition::Superseded
    );
    assert_eq!(bytes(&config), retained);
}

#[test]
fn failed_off_fence_survives_refresh_of_the_old_durable_on() {
    let (_root, mut store) = store_fixture();
    assert!(store
        .save_desired_with(
            &checkbox("launcher"),
            &false.into(),
            &input(1, 2),
            |_, _| Err(io::Error::other("fsync failed"))
        )
        .is_err());
    store.refresh_native().unwrap();
    assert!(store.desired_off_fences.contains("agents/launcher/enabled"));
    assert!(!store.native_enabled.contains("launcher"));
    assert!(crate::native::Host::admission(&store, "launcher").is_none());
}

#[test]
fn startup_none_is_saved_for_next_boot_without_stopping_current_running_interface() {
    let (root, mut store) = store_fixture();
    store.initialize_native(BOOT).unwrap();
    assert_eq!(store.running_startup.as_deref(), Some("interface"));
    let saved = store
        .save_desired(&Field::Startup, &"none".into(), &input(1, 2))
        .unwrap();
    assert!(matches!(
        saved,
        Outcome::DesiredSaved {
            disposition: Disposition::Saved,
            ..
        }
    ));
    assert_eq!(store.running_startup.as_deref(), Some("interface"));
    assert!(store.desired_off_fences.is_empty());
    let mut restarted = Store::new(root.path(), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
    restarted.initialize_native(NEXT_BOOT).unwrap();
    assert_eq!(restarted.running_startup.as_deref(), Some("none"));
}

#[test]
fn product_reconciliation_retains_exact_user_metadata_and_rejects_spoofed_stamps() {
    let mut current = config();
    current
        .save(
            BOOT,
            &checkbox("launcher"),
            &false.into(),
            &input(1, 8),
            &[],
        )
        .unwrap();
    let before: Value = serde_json::from_slice(&bytes(&current)).unwrap();
    let mut defaults = config();
    defaults.agents.insert(
        "launcher".into(),
        voboost_contract::desired::Agent {
            enabled: true,
            options: BTreeMap::new(),
        },
    );
    let merged = current.reconcile(&bytes(&defaults)).unwrap();
    let after: Value = serde_json::from_slice(&merged).unwrap();
    assert_eq!(after["fieldRevisions"], before["fieldRevisions"]);
    assert_eq!(after["userRevision"], before["userRevision"]);
    assert_eq!(after["agents"]["launcher"]["enabled"], false);
    assert!(
        current.reconcile(&bytes(&current)).is_err(),
        "a product proposal cannot inject stamps, even valid ones"
    );
    let mut corrupt = after.clone();
    corrupt["fieldRevisions"]["agents/launcher/enabled"]["revision"] = serde_json::json!(999);
    assert!(Config::decode(&serde_json::to_vec(&corrupt).unwrap()).is_err());
}

#[test]
fn reconciliation_conflict_preserves_a_user_save_after_the_observed_snapshot() {
    let (_root, mut store) = store_fixture();
    let defaults = bytes(&Config::new("interface", BTreeMap::new()).unwrap());
    let result = store
        .reconcile_desired_with(&defaults, |store| {
            store.save_desired(&checkbox("launcher"), &false.into(), &input(1, 2))?;
            Ok(())
        })
        .unwrap();
    assert!(matches!(result, Outcome::Conflict {}));
    let current = Config::decode(&store.config().unwrap().unwrap()).unwrap();
    assert!(!current.agents["launcher"].enabled);
    assert_eq!(current.user_revision, 2);
}

#[test]
fn reconciliation_receipt_requires_exact_defaults_and_monotonic_user_authority() {
    let defaults = Config::new("interface", BTreeMap::new()).unwrap();
    let mut published = defaults.clone();
    published
        .save(
            BOOT,
            &checkbox("launcher"),
            &false.into(),
            &input(1, 8),
            &[],
        )
        .unwrap();
    published.verify_defaults(&bytes(&defaults)).unwrap();
    let mut tampered = published.clone();
    tampered.startup = "hidden".into();
    assert!(tampered.verify_defaults(&bytes(&defaults)).is_err());
    tampered = published.clone();
    tampered.agents.get_mut("launcher").unwrap().enabled = true;
    assert!(!tampered.advances_user_authority(&published));
    let mut newer = published.clone();
    newer
        .save(BOOT, &checkbox("launcher"), &true.into(), &input(1, 9), &[])
        .unwrap();
    assert!(newer.advances_user_authority(&published));
    assert!(!published.advances_user_authority(&newer));
}

#[test]
fn fresh_off_denies_old_on_even_when_origin_capacity_or_revision_is_exhausted() {
    for exhaust_revision in [false, true] {
        let (root, mut store) = store_fixture();
        let mut current = Config::decode(&store.config().unwrap().unwrap()).unwrap();
        let stamp = current
            .field_revisions
            .get_mut("agents/launcher/enabled")
            .unwrap();
        if exhaust_revision {
            current.user_revision = i64::MAX as u64;
            stamp.revision = current.user_revision;
        } else {
            for pid in 1000..1127 {
                stamp.origins.insert(format!("{pid}:100:1"), 1);
            }
        }
        Directory::open(root.path())
            .unwrap()
            .write_atomic("agents.json", &bytes(&current), 0o600)
            .unwrap();
        let before = store.config().unwrap().unwrap();
        assert!(store
            .save_desired(&checkbox("launcher"), &false.into(), &input(2, 2))
            .is_err());
        assert_eq!(store.config().unwrap().unwrap(), before);
        assert!(store.desired_off_fences.contains("agents/launcher/enabled"));
        assert!(!store.native_enabled.contains("launcher"));
        store.refresh_native().unwrap();
        assert!(!store.native_enabled.contains("launcher"));
    }
}

#[test]
fn replayed_on_after_uncertain_rename_requires_another_successful_durability_barrier() {
    let (_root, mut store) = store_fixture();
    assert!(store
        .save_desired_with(
            &checkbox("launcher"),
            &true.into(),
            &input(1, 2),
            |directory, bytes| {
                directory.write_atomic("agents.json", bytes, 0o600)?;
                Err(io::Error::other("directory fsync uncertain"))
            }
        )
        .is_err());
    let mut attempted = false;
    let replay =
        store.save_desired_with(&checkbox("launcher"), &true.into(), &input(1, 2), |_, _| {
            attempted = true;
            Err(io::Error::other("durability barrier still unavailable"))
        });
    assert!(attempted);
    assert!(
        replay.is_err(),
        "readable ON bytes must never be acknowledged as saved without a barrier"
    );
    assert!(matches!(
        store
            .save_desired(&checkbox("launcher"), &true.into(), &input(1, 2))
            .unwrap(),
        Outcome::DesiredSaved {
            disposition: Disposition::Replayed,
            ..
        }
    ));
}

#[test]
fn full_config_writer_with_fresh_expected_cannot_change_or_drop_user_stamps() {
    let (_root, mut store) = store_fixture();
    store
        .save_desired(&checkbox("launcher"), &false.into(), &input(1, 2))
        .unwrap();
    let original = store.config().unwrap().unwrap();
    for lose_metadata in [false, true] {
        let mut proposed = Config::decode(&original).unwrap();
        proposed.agents.get_mut("launcher").unwrap().enabled = true;
        if lose_metadata {
            proposed.user_revision = 0;
            proposed.field_revisions.clear();
        }
        let outcome = store
            .command(voboost_contract::runtime_owner::Command::ReplaceConfig {
                expected: Some(String::from_utf8(original.clone()).unwrap()),
                next: String::from_utf8(bytes(&proposed)).unwrap(),
            })
            .unwrap();
        assert!(matches!(outcome, Outcome::Conflict {}));
        assert_eq!(store.config().unwrap().unwrap(), original);
    }
}

#[test]
fn hidden_recovery_is_saved_after_stamped_none_and_old_recovery_cannot_rearm() {
    let (root, mut store) = store_fixture();
    let mut current = Config::decode(&store.config().unwrap().unwrap()).unwrap();
    current.startup = "hidden".into();
    Directory::open(root.path())
        .unwrap()
        .write_atomic("agents.json", &bytes(&current), 0o600)
        .unwrap();
    store.initialize_native(BOOT).unwrap();
    store
        .save_desired(&Field::Startup, &"none".into(), &input(1, 2))
        .unwrap();
    assert_eq!(store.running_startup.as_deref(), Some("hidden"));
    assert!(matches!(
        store.save_startup_recovery(&input(1, 3)).unwrap(),
        Outcome::DesiredSaved {
            disposition: Disposition::Saved,
            ..
        }
    ));
    assert_eq!(store.running_startup.as_deref(), Some("interface"));
    store
        .save_desired(&Field::Startup, &"none".into(), &input(1, 4))
        .unwrap();
    let before = store.config().unwrap();
    let session = store.startup_session().unwrap();
    assert!(matches!(
        store.save_startup_recovery(&input(1, 3)).unwrap(),
        Outcome::DesiredSaved {
            disposition: Disposition::Superseded,
            ..
        }
    ));
    assert_eq!(store.config().unwrap(), before);
    assert_eq!(store.startup_session().unwrap(), session);
    let mut rebooted = Store::new(root.path(), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
    rebooted.initialize_native(NEXT_BOOT).unwrap();
    assert_eq!(rebooted.running_startup.as_deref(), Some("none"));
    assert!(rebooted.save_startup_recovery(&input(1, 3)).is_err());
    assert_eq!(rebooted.config().unwrap(), before);
}

#[test]
fn launcher_leaf_batch_order_sibling_defaults_and_map_bound_are_atomic() {
    let mut current = config();
    let a = Field::LauncherItemVisibility {
        identity: "i.a".into(),
    };
    let b = Field::LauncherItemVisibility {
        identity: "i.b".into(),
    };
    current
        .save_launcher(
            BOOT,
            vec![(a.clone(), false.into()), (b.clone(), false.into())],
            &input(1, 7),
        )
        .unwrap();
    current
        .save_launcher(BOOT, vec![(a.clone(), true.into())], &input(1, 9))
        .unwrap();
    let before = bytes(&current);
    assert_eq!(
        current
            .save_launcher(
                BOOT,
                vec![(a.clone(), false.into()), (b.clone(), false.into())],
                &input(1, 7)
            )
            .unwrap(),
        Disposition::Superseded
    );
    assert_eq!(bytes(&current), before);
    let density = Field::LauncherAppPreference {
        identity: "i.app".into(),
        key: "densityDpi".into(),
    };
    let mode = Field::LauncherAppPreference {
        identity: "i.app".into(),
        key: "displayMode".into(),
    };
    current
        .save_launcher(BOOT, vec![(density.clone(), 210.into())], &input(1, 10))
        .unwrap();
    assert_eq!(current.value_at(&mode.path()), Some("fit".into()));
    assert!(!current.field_revisions.contains_key(&mode.path()));
    current
        .save_launcher(BOOT, vec![(mode, "fullscreen".into())], &input(1, 99))
        .unwrap();
    current
        .save_launcher(BOOT, vec![(density.clone(), 240.into())], &input(1, 12))
        .unwrap();
    assert_eq!(current.value_at(&density.path()), Some(240.into()));
    let changes = (0..254)
        .map(|n| {
            (
                Field::LauncherItemVisibility {
                    identity: format!("i{n:03}"),
                },
                false.into(),
            )
        })
        .collect();
    current
        .save_launcher(BOOT, changes, &input(1, 100))
        .unwrap();
    let before = bytes(&current);
    assert!(current
        .save_launcher(
            BOOT,
            vec![
                (a, false.into()),
                (
                    Field::LauncherItemVisibility {
                        identity: "i.new".into()
                    },
                    false.into()
                )
            ],
            &input(1, 101)
        )
        .is_err());
    assert_eq!(bytes(&current), before);
    let mut malformed = serde_json::to_value(current).unwrap();
    malformed["agents"]["launcher"]["options"]["appPreferences"]["i.app"]["densityDpi"] =
        "invalid".into();
    assert!(Config::decode(&serde_json::to_vec(&malformed).unwrap()).is_err());
}
