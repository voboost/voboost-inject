use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use voboost_contract::domain_core::domain_operation::{
    AbsenceChecks, AbsenceStartup, AuthenticatedReport, DomainOperationReport, InstalledEvidence,
    Operation, Outcome, Phase, ResidentRestore,
};

fn fixture() -> (tempfile::TempDir, Store, Provision) {
    let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let input = tmp.path().join("input");
    let provision = super::super::tests::provision_input(&input);
    let store = Store::at(&tmp.path().join("cluster"));
    store.import_provision(&input).unwrap();
    let generation = super::super::tests::generation();
    store
        .project(
            &super::super::tests::core(&generation),
            &generation.catalog_sha256,
            vec![],
        )
        .unwrap();
    (tmp, store, provision)
}

fn pending(store: &Store, provision: &Provision, kind: RequestKind) -> State {
    let dir = store.directory().unwrap();
    let mut state = store.load(&dir).unwrap().unwrap();
    let file = WireFile {
        role: WireRole::QnxDaemon,
        file: "voboost-cluster-daemon".into(),
        size: 1,
        sha256: "a".repeat(64),
    };
    let generation = kind == RequestKind::Generation;
    let request = Request {
        schema_version: 1,
        kind,
        pair_id: provision.pair_id.clone(),
        domain: Domain::Cluster,
        authority_epoch: provision.authority_epoch.clone(),
        transaction_id: "b".repeat(64),
        catalog_sha256: state.catalog_sha256.clone(),
        closure_sha256: state.closure_sha256.clone(),
        challenge: "c".repeat(64),
        release_manifest_sha256: generation.then(|| "d".repeat(64)),
        files: generation.then_some(vec![file]),
        desired_revision: (!generation).then_some(state.desired_revision),
        desired_sha256: (!generation).then(|| state.desired_sha256.clone()),
        agents: (kind == RequestKind::Desired).then(|| state.agents.clone()),
        global_locale: None,
    };
    state.pending = Some(Pending {
        request,
        files: vec![WireFile {
            role: WireRole::Request,
            file: REQUEST_FILE.into(),
            size: 1,
            sha256: "e".repeat(64),
        }],
        lease: None,
    });
    store.persist(&dir, &state).unwrap();
    state
}

fn desktop(store: &Store) -> Result<Vec<u8>> {
    export_for_actor(store, Some(Actor::Desktop))
}

fn authority_bytes(store: &Store) -> Vec<Vec<u8>> {
    [PROVISION_FILE, SEED_FILE, CREDENTIAL_FILE, STATE_FILE]
        .iter()
        .map(|name| std::fs::read(store.path.join(name)).unwrap())
        .collect()
}

#[test]
fn desktop_not_requested_is_exact_and_read_only_for_active_mailbox_states() {
    for kind in [
        None,
        Some(RequestKind::Generation),
        Some(RequestKind::Desired),
        Some(RequestKind::Observe),
    ] {
        let (_tmp, store, provision) = fixture();
        if let Some(kind) = kind {
            pending(&store, &provision, kind);
        }
        // A new daemon must not normalize or erase the retained pending request.
        let store = Store {
            epoch: Some("9".repeat(64)),
            ..store
        };
        let before = authority_bytes(&store);
        let expected = format!(
            "{{\"schemaVersion\":1,\"state\":\"not-requested\",\"qnxPublicKey\":\"{}\",\"pairId\":\"{}\",\"authorityEpoch\":\"{}\"}}\n",
            provision.qnx_public_key, provision.pair_id, provision.authority_epoch
        );
        assert_eq!(desktop(&store).unwrap(), expected.as_bytes(), "{kind:?}");
        assert!(authority_bytes(&store) == before, "authority was modified");
        assert!(!settings_intent_pending(&store).unwrap());
        assert!(!store.path.join(DELIVERY_OWNER).exists());
        assert!(export_for_actor(&store, Some(Actor::Settings)).is_err());
    }
}

#[test]
fn desktop_not_requested_rejects_foreign_pending_identity_before_epoch_migration() {
    for kind in [
        RequestKind::Generation,
        RequestKind::Desired,
        RequestKind::Observe,
    ] {
        for pair in [true, false] {
            let (_tmp, store, provision) = fixture();
            let mut state = pending(&store, &provision, kind);
            let request = &mut state.pending.as_mut().unwrap().request;
            if pair {
                request.pair_id = "9".repeat(64);
            } else {
                request.authority_epoch = "9".repeat(64);
            }
            if kind == RequestKind::Desired {
                request.global_locale = Some(cluster::GlobalLocale {
                    locale: 1,
                    revision: 1,
                    endpoint_identity: 1,
                    lifecycle_generation: 1,
                    document_generation: 1,
                });
                state.global_locale = request.global_locale.clone();
            }
            store.persist(&store.directory().unwrap(), &state).unwrap();
            let store = Store {
                epoch: Some("9".repeat(64)),
                ..store
            };
            let before = authority_bytes(&store);
            assert!(desktop(&store).is_err(), "{kind:?}, pair={pair}");
            assert!(authority_bytes(&store) == before, "authority was modified");
            assert!(!store.path.join(DELIVERY_OWNER).exists());
        }
    }
}

#[test]
fn desktop_not_requested_rejects_every_uninstall_artifact() {
    for artifact in [
        UNINSTALL_REPORT,
        FINAL_REPORT,
        PROVISIONAL_REPORT,
        DELIVERY_OWNER,
    ] {
        for kind in [
            None,
            Some(RequestKind::Generation),
            Some(RequestKind::Desired),
            Some(RequestKind::Observe),
        ] {
            let (_tmp, store, provision) = fixture();
            if let Some(kind) = kind {
                pending(&store, &provision, kind);
            }
            let dir = store.directory().unwrap();
            dir.write_atomic(artifact, b"foreign artifact", 0o600)
                .unwrap();
            let before = authority_bytes(&store);
            assert!(desktop(&store).is_err(), "{artifact}, {kind:?}");
            assert!(authority_bytes(&store) == before, "authority was modified");
            assert_eq!(
                std::fs::read(store.path.join(artifact)).unwrap(),
                b"foreign artifact"
            );
        }
    }
}

#[test]
fn desktop_not_requested_rejects_partial_authority() {
    for name in [PROVISION_FILE, SEED_FILE, CREDENTIAL_FILE, STATE_FILE] {
        let (_tmp, store, _) = fixture();
        std::fs::remove_file(store.path.join(name)).unwrap();
        assert!(desktop(&store).is_err(), "{name}");
        assert!(!store.path.join(DELIVERY_OWNER).exists());
    }
}

#[test]
fn desktop_not_requested_rejects_unsafe_authority_entries() {
    for name in [PROVISION_FILE, SEED_FILE, CREDENTIAL_FILE, STATE_FILE] {
        for variant in ["mode", "symlink", "hardlink", "directory"] {
            let (tmp, store, _) = fixture();
            let path = store.path.join(name);
            match variant {
                "mode" => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap()
                }
                "symlink" => {
                    let target = tmp.path().join("outside");
                    std::fs::rename(&path, &target).unwrap();
                    symlink(target, &path).unwrap();
                }
                "hardlink" => std::fs::hard_link(&path, tmp.path().join("extra-link")).unwrap(),
                _ => {
                    std::fs::remove_file(&path).unwrap();
                    std::fs::create_dir(&path).unwrap();
                }
            }
            assert!(desktop(&store).is_err(), "{name}, {variant}");
            assert!(!store.path.join(DELIVERY_OWNER).exists());
        }
    }
}

#[test]
fn desktop_not_requested_rejects_malformed_mailbox_and_provision() {
    for name in [PROVISION_FILE, STATE_FILE] {
        for bytes in [
            b"{}\n".as_slice(),
            b"not-json\n",
            b"{\"schemaVersion\":1,\"schemaVersion\":1}\n",
        ] {
            let (_tmp, store, _) = fixture();
            store
                .directory()
                .unwrap()
                .write_atomic(name, bytes, 0o600)
                .unwrap();
            assert!(desktop(&store).is_err(), "{name}");
        }
    }
    let (_tmp, store, _) = fixture();
    store
        .directory()
        .unwrap()
        .write_atomic(SEED_FILE, &[75; 32], 0o600)
        .unwrap();
    assert!(desktop(&store).is_err());
}

#[test]
fn desktop_not_requested_rejects_invalid_pairing_and_truncated_credentials() {
    for field in ["pair", "epoch", "key", "credentials"] {
        let (_tmp, store, mut provision) = fixture();
        let dir = store.directory().unwrap();
        match field {
            "pair" => provision.pair_id = "A".repeat(64),
            "epoch" => provision.authority_epoch = "z".repeat(64),
            "key" => provision.qnx_public_key = provision.android_public_key.clone(),
            _ => dir
                .write_atomic(CREDENTIAL_FILE, b"truncated", 0o600)
                .unwrap(),
        }
        dir.write_atomic(PROVISION_FILE, &encode(&provision).unwrap(), 0o600)
            .unwrap();
        assert!(desktop(&store).is_err(), "{field}");
        assert!(!store.path.join(DELIVERY_OWNER).exists());
    }
}

#[test]
fn desktop_not_requested_rejects_busy_transaction_without_mutation() {
    let (_tmp, store, _) = fixture();
    let dir = store.directory().unwrap();
    let _lock = dir.lock_transaction(Duration::from_millis(20)).unwrap();
    let before = authority_bytes(&store);
    assert!(desktop(&store).is_err());
    assert!(authority_bytes(&store) == before, "authority was modified");
    assert!(!store.path.join(DELIVERY_OWNER).exists());
}

#[test]
fn retained_uninstall_states_preserve_exact_export_contract() {
    let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let empty = Store::at(&tmp.path().join("empty"));
    assert_eq!(
        desktop(&empty).unwrap(),
        b"{\"schemaVersion\":1,\"state\":\"absent\"}\n"
    );

    let (_tmp, store, provision) = fixture();
    desktop(&store).unwrap();
    // Not-requested does not bypass preparation or prove native absence.
    assert!(!store.prepare_uninstall(&"a".repeat(64)).unwrap());
    let dir = store.directory().unwrap();
    let state = store.load(&dir).unwrap().unwrap();
    let request = &state.pending.as_ref().unwrap().request;
    let startup_hash = "c26b4913707a1e96933f48a07d6957857cc52853a7e405eb29b2adab9b84f47a";
    let startup = AbsenceStartup {
        path: "/scripts/startup_cluster.sh".into(),
        original_sha256: startup_hash.into(),
        restored_sha256: startup_hash.into(),
    };
    let mut report = AuthenticatedReport {
        schema_version: 1,
        pair_id: provision.pair_id.clone(),
        authority_epoch: provision.authority_epoch.clone(),
        challenge: request.challenge.clone(),
        report: DomainOperationReport {
            schema_version: 2,
            domain: Domain::Cluster,
            operation: Operation::Uninstall,
            phase: Phase::Uninstall,
            outcome: Outcome::ReloadRequired,
            transaction_id: request.transaction_id.clone(),
            release_manifest_sha256: "a".repeat(64),
            catalog_sha256: request.catalog_sha256.clone(),
            generation_id: None,
            desired_revision: 0,
            desired_sha256: cluster::desired_digest(&[]).unwrap(),
            boot_id: Some("qnx-host-fixture".into()),
            daemon_epoch: Some("b".repeat(64)),
            installed_evidence: Some(InstalledEvidence::QnxRestored {
                startup: startup.clone(),
                restore_fence_sha256: hash(&encode(&request.transaction_id).unwrap()),
                resident_restore: ResidentRestore::Restored,
                reason: "restored; reboot required".into(),
            }),
        },
    };
    let key = SigningKey::from_bytes(&[74; 32]);
    for status in ["pending", "restored", "completed"] {
        match status {
            "restored" => dir
                .write_atomic(UNINSTALL_REPORT, &report.sign(&key).unwrap(), 0o600)
                .unwrap(),
            "completed" => {
                report.report.phase = Phase::Complete;
                report.report.outcome = Outcome::Completed;
                report.report.installed_evidence = Some(InstalledEvidence::QnxAbsence {
                    startup: startup.clone(),
                    checks: AbsenceChecks {
                        daemon_process_absent: true,
                        autostart_removed: true,
                        native_payload_absent: true,
                        persistent_state_absent: true,
                    },
                    proof_sha256: "e".repeat(64),
                });
                import(&store, &report.sign(&key).unwrap()).unwrap();
            }
            _ => {}
        }
        let expected = format!(
            "{{\"schemaVersion\":1,\"state\":\"{status}\",\"request\":{},\"qnxPublicKey\":\"{}\",\"pairId\":\"{}\",\"authorityEpoch\":\"{}\",\"releaseManifestSha256\":\"{}\",\"catalogSha256\":\"{}\",\"androidPublicKey\":\"{}\",\"signedRequestHex\":\"{}\"}}\n",
            serde_json::to_string(request).unwrap(), provision.qnx_public_key,
            provision.pair_id, provision.authority_epoch,
            request.release_manifest_sha256.as_ref().unwrap(), request.catalog_sha256, provision.android_public_key, hex::encode(dir.read_trusted(REQUEST_FILE, 65536, 0o600).unwrap())
        );
        assert_eq!(desktop(&store).unwrap(), expected.as_bytes(), "{status}");
    }
}

#[test]
fn desktop_exports_only_current_verified_signed_uninstall_request() {
    let (_tmp, store, provision) = fixture();
    assert!(!store.prepare_uninstall(&"a".repeat(64)).unwrap());
    let dir = store.directory().unwrap();
    let signed = dir.read_trusted(REQUEST_FILE, 65536, 0o600).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&desktop(&store).unwrap()).unwrap();
    assert_eq!(value["androidPublicKey"], provision.android_public_key);
    assert_eq!(value["signedRequestHex"], hex::encode(&signed));
    assert!(value.get("androidSigningSeed").is_none());

    let mut tampered = signed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    dir.write_atomic(REQUEST_FILE, &tampered, 0o600).unwrap();
    assert!(desktop(&store).is_err());

    let mut state = store.load(&dir).unwrap().unwrap();
    state.pending.as_mut().unwrap().request.challenge = "9".repeat(64);
    store.persist(&dir, &state).unwrap();
    dir.write_atomic(REQUEST_FILE, &signed, 0o600).unwrap();
    assert!(desktop(&store).is_err());

    let mut state = store.load(&dir).unwrap().unwrap();
    let pending = state.pending.as_mut().unwrap();
    let forged = pending
        .request
        .sign(&SigningKey::from_bytes(&[75; 32]))
        .unwrap();
    pending.files[0].size = forged.len() as u64;
    pending.files[0].sha256 = hash(&forged);
    store.persist(&dir, &state).unwrap();
    dir.write_atomic(REQUEST_FILE, &forged, 0o600).unwrap();
    assert!(desktop(&store).is_err());

    let mut state = store.load(&dir).unwrap().unwrap();
    let pending = state.pending.as_mut().unwrap();
    pending.request.pair_id = "8".repeat(64);
    let foreign = pending
        .request
        .sign(&SigningKey::from_bytes(&[73; 32]))
        .unwrap();
    pending.files[0].size = foreign.len() as u64;
    pending.files[0].sha256 = hash(&foreign);
    store.persist(&dir, &state).unwrap();
    dir.write_atomic(REQUEST_FILE, &foreign, 0o600).unwrap();
    assert!(desktop(&store).is_err());
}
