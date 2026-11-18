use voboost_contract_core::{
    catalog::{Domain, FileIdentity},
    domain_operation::{
        AbsenceChecks, AbsenceStartup, DomainOperationReport, InstalledEvidence, Operation,
        Outcome, PersistentRoot, Phase, RestoreProof, RootScope, StartupProof,
    },
};
fn h(c: char) -> String {
    c.to_string().repeat(64)
}
#[test]
fn restored_startup_is_preparation_never_completed_absence() {
    let mut value = report(Domain::Cluster, Operation::Uninstall);
    value.phase = Phase::Uninstall;
    value.outcome = Outcome::ReloadRequired;
    value.installed_evidence = Some(InstalledEvidence::QnxRestored {
        startup: AbsenceStartup {
            path: "/scripts/startup_cluster.sh".into(),
            original_sha256: h('a'),
            restored_sha256: h('a'),
        },
        restore_fence_sha256: h('b'),
        resident_restore: voboost_contract_core::domain_operation::ResidentRestore::ReloadRequired,
        reason: "resident requires reload".into(),
    });
    value.validate().unwrap();
    let mut absent_boot = value.clone();
    absent_boot.boot_id = None;
    assert!(absent_boot.validate().is_err());
    value.phase = Phase::Complete;
    value.outcome = Outcome::Completed;
    assert!(value.validate().is_err());
}
fn native() -> InstalledEvidence {
    InstalledEvidence::QnxNative {
        files: vec![FileIdentity {
            file: "libagent-cluster-vehicle-status-fuel.so".into(),
            size: 23,
            sha256: h('a'),
        }],
        persistent_root: PersistentRoot {
            path: "/protected/voboost".into(),
            scope: RootScope::Persistent,
            device_id: "test-fs".into(),
            owner_uid: 0,
            mode: 448,
        },
        startup: StartupProof {
            path: "/protected/start-gauge.sh".into(),
            original_sha256: h('b'),
            installed_sha256: h('c'),
            restored_sha256: Some(h('b')),
        },
        restore: RestoreProof {
            verified: true,
            proof_sha256: h('d'),
        },
    }
}
fn apk() -> InstalledEvidence {
    InstalledEvidence::AndroidApk {
        certificate_sha256: h('a'),
        package_name: "ru.voboost".into(),
        path: "/data/app/ru.voboost/base.apk".into(),
        sha256: h('b'),
        size: 23,
        version_code: 1,
    }
}
fn report(domain: Domain, operation: Operation) -> DomainOperationReport {
    DomainOperationReport {
        schema_version: 2,
        domain,
        operation,
        phase: Phase::Complete,
        outcome: Outcome::Completed,
        transaction_id: h('1'),
        release_manifest_sha256: h('2'),
        catalog_sha256: h('3'),
        generation_id: Some(h('4')),
        desired_revision: 0,
        desired_sha256: h('5'),
        boot_id: Some("test-boot".into()),
        daemon_epoch: Some(h('6')),
        installed_evidence: Some(if domain == Domain::Cluster {
            native()
        } else {
            apk()
        }),
    }
}
#[test]
fn completed_install_update_restore_require_platform_and_runtime_evidence() {
    for domain in [Domain::Multimedia, Domain::Cluster] {
        for operation in [Operation::Install, Operation::Update, Operation::Restore] {
            let valid = report(domain, operation);
            valid.validate().unwrap();
            for field in 0..4 {
                let mut missing = valid.clone();
                match field {
                    0 => missing.installed_evidence = None,
                    1 => missing.generation_id = None,
                    2 => missing.boot_id = None,
                    _ => missing.daemon_epoch = None,
                }
                assert!(
                    missing.validate().is_err(),
                    "{domain:?} {operation:?} missing {field}"
                );
            }
            let mut wrong = valid.clone();
            wrong.installed_evidence = Some(if domain == Domain::Cluster {
                apk()
            } else {
                native()
            });
            assert!(wrong.validate().is_err());
            if domain == Domain::Cluster {
                let mut volatile = valid.clone();
                if let Some(InstalledEvidence::QnxNative {
                    persistent_root, ..
                }) = &mut volatile.installed_evidence
                {
                    persistent_root.scope = RootScope::Volatile;
                }
                assert!(volatile.validate().is_err());
                let mut wrong_restore = valid.clone();
                if let Some(InstalledEvidence::QnxNative { startup, .. }) =
                    &mut wrong_restore.installed_evidence
                {
                    startup.restored_sha256 = Some(h('e'));
                }
                assert!(wrong_restore.validate().is_err());
            }
        }
    }
}
#[test]
fn completed_uninstall_requires_native_absence_and_null_multimedia_evidence() {
    let mut multimedia = report(Domain::Multimedia, Operation::Uninstall);
    assert!(multimedia.validate().is_err());
    multimedia.installed_evidence = None;
    multimedia.generation_id = None;
    multimedia.validate().unwrap();
    let mut cluster = report(Domain::Cluster, Operation::Uninstall);
    assert!(cluster.validate().is_err());
    cluster.installed_evidence = None;
    assert!(cluster.validate().is_err());
    cluster.installed_evidence = Some(InstalledEvidence::QnxAbsence {
        startup: AbsenceStartup {
            path: "/protected/start-gauge.sh".into(),
            original_sha256: h('b'),
            restored_sha256: h('b'),
        },
        checks: AbsenceChecks {
            daemon_process_absent: true,
            autostart_removed: true,
            native_payload_absent: true,
            persistent_state_absent: true,
        },
        proof_sha256: h('d'),
    });
    cluster.generation_id = None;
    cluster.validate().unwrap();
    let mut one_shot = cluster.clone();
    one_shot.boot_id = None;
    one_shot.daemon_epoch = None;
    one_shot.validate().unwrap();
    one_shot.outcome = Outcome::ReloadRequired;
    assert!(one_shot.validate().is_err());
    one_shot.outcome = Outcome::Completed;
    one_shot.phase = Phase::Uninstall;
    assert!(one_shot.validate().is_err());
    for field in 0..2 {
        let mut missing = cluster.clone();
        if field == 0 {
            missing.boot_id = None;
        } else {
            missing.daemon_epoch = None;
        }
        assert!(missing.validate().is_err());
    }
    for field in 0..5 {
        let mut wrong = cluster.clone();
        if let Some(InstalledEvidence::QnxAbsence {
            startup, checks, ..
        }) = &mut wrong.installed_evidence
        {
            match field {
                0 => startup.restored_sha256 = h('e'),
                1 => checks.daemon_process_absent = false,
                2 => checks.autostart_removed = false,
                3 => checks.native_payload_absent = false,
                _ => checks.persistent_state_absent = false,
            }
        }
        assert!(wrong.validate().is_err());
    }
}
#[test]
fn pending_bootstrap_preserves_unknown_runtime_and_volatile_scope() {
    for outcome in [
        Outcome::Pending,
        Outcome::SetupRequired,
        Outcome::ReloadRequired,
    ] {
        let mut pending = report(Domain::Cluster, Operation::Install);
        pending.phase = Phase::Install;
        pending.outcome = outcome;
        pending.generation_id = None;
        pending.boot_id = None;
        pending.daemon_epoch = None;
        pending.installed_evidence = None;
        pending.validate().unwrap();
        pending.installed_evidence = Some(native());
        if let Some(InstalledEvidence::QnxNative {
            persistent_root,
            startup,
            restore,
            ..
        }) = &mut pending.installed_evidence
        {
            persistent_root.scope = RootScope::Volatile;
            startup.restored_sha256 = None;
            restore.verified = false;
        }
        pending.validate().unwrap();
    }
}
