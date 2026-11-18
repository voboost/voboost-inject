use super::*;

#[test]
fn removal_preserves_the_executable_mode_of_both_installed_cluster_layouts() {
    for name in [
        "voboost-cluster",
        "libvoboost-cluster-implant.so",
        "voboost-cluster-daemon",
        "libvoboost-cluster-inject.so",
    ] {
        assert_eq!(installed_artifact_mode(name), 0o700, "{name}");
    }
    assert_eq!(installed_artifact_mode("voboost.json"), 0o600);
}

#[test]
fn recovery_uses_the_implant_role_from_the_actual_installed_manifest() {
    let mut manifest = Manifest::parse(include_bytes!(
        "../../test/fixtures/product-release/voboost/valid/minimal.json"
    )).unwrap();
    assert_eq!(installed_implant(&manifest).unwrap(), "libvoboost-cluster-inject.so");
    manifest.artifacts.iter_mut()
        .find(|artifact| artifact.role == ArtifactRole::QnxImplant).unwrap()
        .file = "libvoboost-cluster-implant.so".into();
    assert_eq!(installed_implant(&manifest).unwrap(), "libvoboost-cluster-implant.so");
    manifest.artifacts.retain(|artifact| artifact.role != ArtifactRole::QnxImplant);
    assert!(installed_implant(&manifest).is_err());
}

#[test]
fn process_absence_reenumerates_after_a_process_disappears_without_hiding_a_live_owner() {
    let mut attempts = 0;
    let mut waits = 0;
    let found = observe_processes(|| {
        attempts += 1;
        if attempts == 1 {
            Err("native uninstall process identity unavailable; retry".into())
        } else {
            Ok(true)
        }
    }, || waits += 1).unwrap();
    assert!(found);
    assert_eq!((attempts, waits), (2, 1));
}

#[test]
fn process_absence_does_not_turn_persistent_unreadable_processes_into_success() {
    let mut attempts = 0;
    let mut waits = 0;
    assert!(observe_processes(|| {
        attempts += 1;
        Err("native uninstall process identity unavailable; retry".into())
    }, || waits += 1).is_err());
    assert_eq!((attempts, waits), (3, 2));
    assert!(observe_processes(|| Err("native process pathname invalid".into()),
        || panic!("invalid data must not be retried")).is_err());
}

#[test]
fn offline_restore_input_bounds_hex_and_preserves_observation_limit() {
    let input = RecoveryObservationInput {
        schema_version: 1,
        transaction_id: "a".repeat(64),
        challenge: "b".repeat(64),
        pair_id: "c".repeat(64),
        authority_epoch: "d".repeat(64),
        qnx_public_key: "e".repeat(64),
        release_manifest_sha256: "f".repeat(64),
        catalog_sha256: "0".repeat(64),
    };
    let mut wrapper = OfflineRestoreInput {
        observation: input,
        request: "ab".repeat(OFFLINE_REQUEST_MAX),
    };
    let bytes = ascii_json(&wrapper).unwrap();
    assert!(bytes.len() > RECOVERY_INPUT_MAX);
    assert_eq!(
        parse_offline_restore_input(&bytes).unwrap().1.len(),
        OFFLINE_REQUEST_MAX
    );
    wrapper.request.push_str("ab");
    assert!(parse_offline_restore_input(&ascii_json(&wrapper).unwrap()).is_err());
    wrapper.request = "a".into();
    assert!(parse_offline_restore_input(&ascii_json(&wrapper).unwrap()).is_err());
    wrapper.request = "zz".into();
    assert!(parse_offline_restore_input(&ascii_json(&wrapper).unwrap()).is_err());
    assert!(parse_offline_restore_input(&vec![b' '; OFFLINE_INPUT_MAX + 1]).is_err());
}

#[test]
fn supervisor_parent_admits_oem_public_directory_and_preserves_protected_member() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let base =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build/cluster-test-tmp");
    std::fs::create_dir_all(&base).unwrap();
    let temp = tempfile::tempdir_in(base).unwrap();
    let path = std::fs::canonicalize(temp.path()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let config = path.join("boot_cfg.xml");
    let original = b"<boot/>\n";
    std::fs::write(&config, original).unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644)).unwrap();
    let owner = crate::fs::uid().unwrap();
    assert!(Dir::open(path.to_str().unwrap(), owner).is_err());
    let parent = supervisor_parent(config.to_str().unwrap(), owner).unwrap();
    assert_eq!(parent.read("boot_cfg.xml", 1024, 0o644).unwrap(), original);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o755
    );
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(parent.read("boot_cfg.xml", 1024, 0o644).is_err());
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(parent.read("boot_cfg.xml", 1024, 0o644).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::remove_file(&config).unwrap();
    symlink("missing", &config).unwrap();
    assert!(parent.read("boot_cfg.xml", 1024, 0o644).is_err());
}

#[test]
fn supervisor_parent_rejects_writable_foreign_or_symlinked_directory() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let base =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build/cluster-test-tmp");
    std::fs::create_dir_all(&base).unwrap();
    let temp = tempfile::tempdir_in(base).unwrap();
    let path = std::fs::canonicalize(temp.path()).unwrap();
    let config = path.join("boot_cfg.xml");
    let owner = crate::fs::uid().unwrap();
    for mode in [0o775, 0o757, 0o777] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(supervisor_parent(config.to_str().unwrap(), owner).is_err());
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(supervisor_parent(config.to_str().unwrap(), owner.wrapping_add(1)).is_err());
    let link = path.join("linked-parent");
    symlink(&path, &link).unwrap();
    assert!(supervisor_parent(link.join("boot_cfg.xml").to_str().unwrap(), owner).is_err());
    assert!(supervisor_parent(path.join("other.xml").to_str().unwrap(), owner).is_err());
}

#[test]
fn supervisor_installation_validates_exact_protected_receipt_and_live_files() {
    let (_temp, config, _, _, _, _) = crate::engine::tests::fixture();
    let owner = crate::fs::uid().unwrap();
    let root = Dir::open(&config.root, owner).unwrap();
    let bin = root.child("bin").unwrap();
    let implant = b"test implant bytes; not an execution or delivery proof";
    bin.write("libvoboost-cluster-inject.so", implant, 0o700)
        .unwrap();
    root.write("boot.json", &ascii_json(&config).unwrap(), 0o600)
        .unwrap();
    let original = b"#!/bin/sh\nclusterboot &\n";
    let installed = b"#!/bin/sh\n# managed test integration\nclusterboot &\n";
    root.write("startup.original", original, 0o600).unwrap();
    root.write("startup.test", installed, 0o700).unwrap();
    let mut proof = Installation {
        schema_version: 1,
        bootfile: format!("{}/boot.json", config.root),
        startup_file: format!("{}/startup.test", config.root),
        original_sha256: hash(original),
        installed_sha256: hash(installed),
        startup_mode: 0o700,
        release_manifest_sha256: "a".repeat(64),
        catalog_sha256: "b".repeat(64),
        files: vec![FileIdentity {
            file: "libvoboost-cluster-inject.so".into(),
            size: implant.len() as u64,
            sha256: hash(implant),
        }],
        supervisor_config: None,
    };
    let publish = |proof: &Installation| {
        root.write("installation.json", &ascii_json(proof).unwrap(), 0o600)
            .unwrap()
    };
    publish(&proof);
    let admitted = supervisor_installation(&config).unwrap();
    assert_eq!(admitted.bootfile(), proof.bootfile);
    assert_eq!(
        admitted.implant_path(),
        format!("{}/bin/libvoboost-cluster-inject.so", config.root)
    );
    assert_eq!(admitted.identity(), hash(&ascii_json(&proof).unwrap()));
    proof.files.push(proof.files[0].clone());
    publish(&proof);
    assert!(supervisor_installation(&config).is_err());
    proof.files.pop();
    publish(&proof);
    bin.write("libvoboost-cluster-inject.so", b"foreign", 0o700)
        .unwrap();
    assert!(supervisor_installation(&config).is_err());
    bin.write("libvoboost-cluster-inject.so", implant, 0o700)
        .unwrap();
    root.write("startup.test", original, 0o700).unwrap();
    assert!(supervisor_installation(&config).is_err());
    root.write("startup.test", installed, 0o700).unwrap();
    root.write("startup.original", b"changed backup", 0o600)
        .unwrap();
    assert!(supervisor_installation(&config).is_err());
}

#[test]
fn recovery_input_uses_oem_parent_and_preserves_file_protection() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let base =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build/cluster-test-tmp");
    std::fs::create_dir_all(&base).unwrap();
    let temp = tempfile::tempdir_in(base).unwrap();
    let path = std::fs::canonicalize(temp.path()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let owner = crate::fs::uid().unwrap();
    assert!(
        Dir::open(path.to_str().unwrap(), owner).is_err(),
        "old private-parent route must reject755"
    );
    let parent = Dir::parent(path.to_str().unwrap(), owner).unwrap();
    let name = format!("voboost-observe-{}.json", "a".repeat(64));
    let input = path.join(&name);
    std::fs::write(&input, b"protected fixture").unwrap();
    std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        read_recovery_observation_input(&parent, &name).unwrap(),
        b"protected fixture"
    );
    std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_recovery_observation_input(&parent, &name).is_err());
    std::fs::remove_file(&input).unwrap();
    symlink("missing", &input).unwrap();
    assert!(read_recovery_observation_input(&parent, &name).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(Dir::parent(path.to_str().unwrap(), owner).is_err());
}

#[test]
fn recovery_input_rejects_other_parents_prefixes_and_unsafe_names() {
    let nonce = "a".repeat(64);
    assert!(recovery_observation_input_name(&format!("/var/voboost-observe-{nonce}.json")).is_ok());
    for path in [
        format!("/tmp/voboost-observe-{nonce}.json"),
        format!("/var/other-{nonce}.json"),
        "/var/voboost-observe-../escape.json".into(),
        format!("/var/voboost-observe-{}.json", "A".repeat(64)),
        format!("/var//voboost-observe-{nonce}.json"),
    ] {
        assert!(recovery_observation_input_name(&path).is_err());
    }
}

#[test]
fn uninstall_disarms_startup_before_resident_reload_and_retains_error() {
    use voboost_contract_core::domain_operation::ResidentRestore;
    let disarmed = core::cell::Cell::new(false);
    let (state, reason) = prepare_restoration(
        || {
            disarmed.set(true);
            Ok(())
        },
        || {
            assert!(disarmed.get());
            Err("UI restore requires process reload".into())
        },
    )
    .unwrap();
    assert_eq!(state, ResidentRestore::ReloadRequired);
    assert_eq!(reason, "UI restore requires process reload");
    let (state, _) = prepare_restoration(|| Ok(()), || Ok(true)).unwrap();
    assert_eq!(state, ResidentRestore::Restored);
}

#[test]
fn uninstall_startup_failure_never_produces_preparation_or_stops_resident() {
    let called = core::cell::Cell::new(false);
    let result = prepare_restoration(
        || Err("startup readback differs".into()),
        || {
            called.set(true);
            Ok(true)
        },
    );
    assert!(result.unwrap_err().contains("startup readback differs"));
    assert!(!called.get());
}

#[test]
fn report_signer_requires_exact_paired_seed() {
    let (_temp, config, _, _, _, _) = crate::engine::tests::fixture();
    let root = Dir::open(&config.root, crate::fs::uid().unwrap()).unwrap();
    assert!(signing_key(&config).is_ok());
    root.write("qnx-signing.seed", &[17; 32], 0o600).unwrap();
    assert!(signing_key(&config).is_err());
    root.write("qnx-signing.seed", &[15; 31], 0o600).unwrap();
    assert!(signing_key(&config).is_err());
}

#[test]
fn integration_input_rejects_missing_authority() {
    assert!(Integration::parse(b"{}").is_err());
}

#[test]
fn startup_prepares_boot_synchronously_and_stops_on_prepare_failure() {
    use std::os::unix::fs::PermissionsExt;
    let base =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build/cluster-test-tmp");
    std::fs::create_dir_all(&base).unwrap();
    let temp = tempfile::tempdir_in(base).unwrap();
    let root = temp.path();
    std::fs::create_dir(root.join("bin")).unwrap();
    let program = root.join("bin/voboost-cluster-daemon");
    std::fs::write(&program, b"#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"$TRACE\"\nif [ \"$1\" = prepare-boot ] && [ \"$FAIL_PREPARE\" = 1 ]; then exit 1; fi\n").unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
    let boot = root.join("boot.json");
    std::fs::write(&boot, b"protected input fixture").unwrap();
    let startup = std::env::var_os("VOBOOST_STARTUP_SCRIPT_SAMPLE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../service/startup.sh")
        });
    for (failed, expected) in [(false, "prepare-boot\ndaemon\n"), (true, "prepare-boot\n")] {
        let trace = root.join(if failed {
            "failed.trace"
        } else {
            "success.trace"
        });
        let result = std::process::Command::new("/bin/sh")
            .args([
                "-c",
                ". \"$1\" \"$2\" \"$3\"; result=$?; wait; exit \"$result\"",
                "startup-test",
            ])
            .arg(&startup)
            .arg(root)
            .arg(&boot)
            .env("TRACE", &trace)
            .env("FAIL_PREPARE", if failed { "1" } else { "0" })
            .status()
            .unwrap();
        assert_eq!(result.success(), !failed);
        assert_eq!(std::fs::read_to_string(trace).unwrap(), expected);
        assert!(!root.join("service.log").exists());
    }
}

#[test]
fn provisioning_is_immutable_and_checks_all_collisions_before_writing() {
    let (_temp, mut config, _, _, _, _) = crate::engine::tests::fixture();
    let owner = crate::fs::uid().unwrap();
    let root = Dir::open(&config.root, owner).unwrap();
    let source = root.child("provision-input").unwrap();
    source.write("qnx-signing.seed", &[15; 32], 0o600).unwrap();
    for name in ["server.pem", "key.pem", "ca.pem"] {
        source.write(name, b"protected TLS input", 0o600).unwrap();
    }
    config.tls.server_certificate = format!("{}/server.pem", config.root);
    config.tls.server_private_key = format!("{}/key.pem", config.root);
    config.tls.client_ca = format!("{}/ca.pem", config.root);
    root.write("server.pem", b"prior authority", 0o600).unwrap();
    assert!(provision(&config, &source.path, owner).is_err());
    assert!(!root.exists("key.pem").unwrap());
    assert!(!root.exists("ca.pem").unwrap());
    assert_eq!(
        root.read("server.pem", 64, 0o600).unwrap(),
        b"prior authority"
    );
    source
        .write("server.pem", b"prior authority", 0o600)
        .unwrap();
    provision(&config, &source.path, owner).unwrap();
    let before = std::fs::metadata(format!("{}/qnx-signing.seed", config.root)).unwrap();
    provision(&config, &source.path, owner).unwrap();
    use std::os::unix::fs::MetadataExt;
    assert_eq!(
        before.ino(),
        std::fs::metadata(format!("{}/qnx-signing.seed", config.root))
            .unwrap()
            .ino()
    );
    source.write("qnx-signing.seed", &[17; 32], 0o600).unwrap();
    assert!(provision(&config, &source.path, owner).is_err());
    assert_eq!(root.read("qnx-signing.seed", 32, 0o600).unwrap(), [15; 32]);
    config.tls.client_ca = "/elsewhere/ca.pem".into();
    assert!(provision(&config, &source.path, owner).is_err());
}

fn integration_for(original: &[u8], anchor: &str) -> Integration {
    Integration {
        schema_version: 1,
        bootfile: "/protected/boot.json".into(),
        source_directory: "/protected/source".into(),
        provision_directory: None,
        startup_file: "/scripts/startup_cluster.sh".into(),
        original_sha256: hash(original),
        anchor: anchor.into(),
        startup_profile: None,
        scope: RootScope::Volatile,
        root_device_id: "1".into(),
        transaction_id: "1".repeat(64),
        challenge: "2".repeat(64),
        receipt_file: "/protected/receipt.json".into(),
    }
}

#[test]
fn startup_anchor_requires_complete_unique_line() {
    let (_temp, config, _, _, _, _) = crate::engine::tests::fixture();
    let original = b"#!/bin/sh\nexec /usr/bin/gauge -config=/oem.cfg\n";
    let input = integration_for(original, "exec /usr/bin/gauge -config=/oem.cfg");
    assert_eq!(startup_position(&input, &config, original).unwrap(), 10);
    let prefix = integration_for(original, "exec /usr/bin/gauge");
    assert!(startup_position(&prefix, &config, original).is_err());
    let duplicate = b"exec /usr/bin/gauge\nexec /usr/bin/gauge\n";
    assert!(startup_position(
        &integration_for(duplicate, "exec /usr/bin/gauge"),
        &config,
        duplicate
    )
    .is_err());
}

#[test]
fn clusterboot_structural_probe_accepts_distinct_firmware_and_shell_whitespace() {
    let (_temp, config, _, _, _, _) = crate::engine::tests::fixture();
    for original in [
        b"#!/bin/sh\nclusterboot &\n".as_slice(),
        "#!/bin/sh\n# 中文注释\n\t clusterboot  \t & \r\n".as_bytes(),
    ] {
        let mut input = integration_for(original, "clusterboot &");
        assert!(startup_position(&input, &config, original).is_err());
        input.startup_profile = Some(StartupProfile::Clusterboot);
        assert!(startup_position(&input, &config, original).is_ok());
        input.original_sha256 = "0".repeat(64);
        assert!(startup_position(&input, &config, original).is_err());
    }
    for bad in [
        b"clusterboot &\nclusterboot &\n".as_slice(),
        b"prefix clusterboot &\n",
        b"clusterboot & suffix\n",
        b"LD_PRELOAD=bad clusterboot &\n",
        b"clusterboot &\0",
        b"# clusterboot &\n",
    ] {
        assert!(probe_clusterboot_startup(bad).is_err());
    }
}

#[test]
fn recovery_observation_rejects_malformed_authority_before_native_reads() {
    let mut input = RecoveryObservationInput {
        schema_version: 1,
        transaction_id: "1".repeat(64),
        challenge: "2".repeat(64),
        pair_id: "3".repeat(64),
        authority_epoch: "4".repeat(64),
        qnx_public_key: "5".repeat(64),
        release_manifest_sha256: "6".repeat(64),
        catalog_sha256: "7".repeat(64),
    };
    validate_recovery_observation_input(&input).unwrap();
    input.challenge = "not-a-challenge".into();
    assert!(validate_recovery_observation_input(&input).is_err());
    input.challenge = "2".repeat(64);
    input.schema_version = 2;
    assert!(validate_recovery_observation_input(&input).is_err());
}

#[test]
fn recovery_installation_rejects_foreign_product_and_modified_startup() {
    let original = b"#!/bin/sh\n# different firmware fixture\nclusterboot &\n".to_vec();
    let installed = [original.as_slice(), b"\n# managed fixture\n"].concat();
    let input = RecoveryObservationInput {
        schema_version: 1,
        transaction_id: "1".repeat(64),
        challenge: "2".repeat(64),
        pair_id: "3".repeat(64),
        authority_epoch: "4".repeat(64),
        qnx_public_key: "5".repeat(64),
        release_manifest_sha256: "6".repeat(64),
        catalog_sha256: "7".repeat(64),
    };
    let mut proof = Installation {
        schema_version: 1,
        bootfile: "/var/voboost/boot.json".into(),
        startup_file: "/scripts/startup_cluster.sh".into(),
        original_sha256: hash(&original),
        installed_sha256: hash(&installed),
        startup_mode: 0o755,
        release_manifest_sha256: input.release_manifest_sha256.clone(),
        catalog_sha256: input.catalog_sha256.clone(),
        files: vec![],
        supervisor_config: None,
    };
    validate_recovery_installation(&input, &proof, &original, &installed, 0o755).unwrap();
    validate_recovery_installation(&input, &proof, &original, &original, 0o755).unwrap();
    assert!(validate_recovery_installation(&input, &proof, &original, b"foreign", 0o755).is_err());
    assert!(validate_recovery_installation(&input, &proof, &original, &installed, 0o777).is_err());
    proof.catalog_sha256 = "8".repeat(64);
    assert!(validate_recovery_installation(&input, &proof, &original, &installed, 0o755).is_err());
}

#[test]
fn installed_shared_implant_requires_executable_permission() {
    assert_eq!(
        installed_artifact_mode("libvoboost-cluster-inject.so"),
        0o700
    );
    assert_eq!(installed_artifact_mode("voboost-cluster-daemon"), 0o700);
    assert_eq!(installed_artifact_mode("boot.json"), 0o600);
}

#[test]
fn implant_mode_repair_is_exact_content_bound_and_idempotent() {
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    let base =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build/cluster-test-tmp");
    std::fs::create_dir_all(&base).unwrap();
    let temp = tempfile::tempdir_in(base).unwrap();
    let path = std::fs::canonicalize(temp.path()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let dir = Dir::open(path.to_str().unwrap(), crate::fs::uid().unwrap()).unwrap();
    let file = path.join("libvoboost-cluster-inject.so");
    std::fs::write(&file, b"exact signed fixture").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let before = std::fs::metadata(&file).unwrap();
    assert!(dir.repair_implant_executable(b"foreign").is_err());
    assert_eq!(std::fs::metadata(&file).unwrap().mode() & 0o7777, 0o600);
    dir.repair_implant_executable(b"exact signed fixture")
        .unwrap();
    dir.repair_implant_executable(b"exact signed fixture")
        .unwrap();
    let after = std::fs::metadata(&file).unwrap();
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert_eq!(after.mode() & 0o7777, 0o700);
    for mode in [0o644, 0o755, 0o4700] {
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(dir
            .repair_implant_executable(b"exact signed fixture")
            .is_err());
    }
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::hard_link(&file, path.join("alias")).unwrap();
    assert!(dir
        .repair_implant_executable(b"exact signed fixture")
        .is_err());
    std::fs::remove_file(path.join("alias")).unwrap();
    std::fs::rename(&file, path.join("original")).unwrap();
    symlink("original", &file).unwrap();
    assert!(dir
        .repair_implant_executable(b"exact signed fixture")
        .is_err());
    assert_eq!(
        std::fs::metadata(path.join("original")).unwrap().mode() & 0o7777,
        0o600
    );
}

#[test]
fn offline_restore_requires_the_original_authenticated_uninstall_request() {
    use voboost_contract_core::cluster::{Request, RequestKind};
    let mut input = RecoveryObservationInput {
        schema_version: 1,
        transaction_id: "1".repeat(64),
        challenge: "2".repeat(64),
        pair_id: "3".repeat(64),
        authority_epoch: "4".repeat(64),
        qnx_public_key: "5".repeat(64),
        release_manifest_sha256: "6".repeat(64),
        catalog_sha256: "7".repeat(64),
    };
    let request = Request {
        global_locale: None,
        schema_version: 1,
        kind: RequestKind::Uninstall,
        domain: Domain::Cluster,
        pair_id: input.pair_id.clone(),
        authority_epoch: input.authority_epoch.clone(),
        transaction_id: input.transaction_id.clone(),
        catalog_sha256: input.catalog_sha256.clone(),
        closure_sha256: "0".repeat(64),
        challenge: input.challenge.clone(),
        release_manifest_sha256: Some(input.release_manifest_sha256.clone()),
        files: None,
        desired_revision: Some(0),
        desired_sha256: Some(voboost_contract_core::cluster::desired_digest(&[]).unwrap()),
        agents: None,
    };
    let key = SigningKey::from_bytes(&[42; 32]);
    let envelope = request.sign(&key).unwrap();
    let verified = Request::verify(&envelope, &key.verifying_key()).unwrap();
    validate_offline_restore_request(&input, &verified).unwrap();
    let (_temp, mut config, _, _, _, _) = crate::engine::tests::fixture();
    let root = Dir::open(&config.root, crate::fs::uid().unwrap()).unwrap();
    config.root = "/var/voboost".into();
    config.pair_id = input.pair_id.clone();
    config.authority_epoch = input.authority_epoch.clone();
    config.qnx_public_key = input.qnx_public_key.clone();
    config.android_public_key = hex::encode(key.verifying_key().as_bytes());
    let mut service = crate::service::ServiceRecord {
        schema_version: 1,
        pid: 42,
        boot_id: "current-boot".into(),
        daemon_epoch: "9".repeat(64),
        generation_id: None,
        desired_revision: 0,
        desired_sha256: "a".repeat(64),
        running: true,
    };
    let shutdown = offline_shutdown(&config, &input, &verified, &envelope, &service).unwrap();
    assert_eq!(shutdown.daemon_epoch, service.daemon_epoch);
    assert_eq!(shutdown.transaction_id, verified.transaction_id);
    root.write("service.json", &ascii_json(&service).unwrap(), 0o600)
        .unwrap();
    publish_offline_shutdown(&root, &config, &service, &shutdown).unwrap();
    service.daemon_epoch = "a".repeat(64);
    let retry = offline_shutdown(&config, &input, &verified, &envelope, &service).unwrap();
    assert!(publish_offline_shutdown(&root, &config, &service, &retry).is_err());
    root.write("service.json", &ascii_json(&service).unwrap(), 0o600)
        .unwrap();
    publish_offline_shutdown(&root, &config, &service, &retry).unwrap();
    assert_eq!(
        root.read("shutdown.request", crate::service::SHUTDOWN_MAX, 0o600)
            .unwrap(),
        ascii_json(&retry).unwrap()
    );
    let mut changed = request.clone();
    changed.challenge = "b".repeat(64);
    input.challenge = changed.challenge.clone();
    let changed_envelope = changed.sign(&key).unwrap();
    let foreign = offline_shutdown(&config, &input, &changed, &changed_envelope, &service).unwrap();
    assert!(publish_offline_shutdown(&root, &config, &service, &foreign).is_err());
    assert_eq!(
        root.read("shutdown.request", crate::service::SHUTDOWN_MAX, 0o600)
            .unwrap(),
        ascii_json(&retry).unwrap()
    );
    input.challenge = verified.challenge.clone();
    let mut forged = envelope.clone();
    *forged.last_mut().unwrap() ^= 1;
    assert!(offline_shutdown(&config, &input, &verified, &forged, &service).is_err());
    input.schema_version = 2;
    assert!(offline_shutdown(&config, &input, &verified, &envelope, &service).is_err());
    assert!(recovery_preflight(&input, crate::fs::uid().unwrap(), false, Some(&envelope)).is_err());
    input.schema_version = 1;
    service.daemon_epoch = "invalid".into();
    assert!(offline_shutdown(&config, &input, &verified, &envelope, &service).is_err());
    assert!(Request::verify(
        &envelope,
        &SigningKey::from_bytes(&[43; 32]).verifying_key()
    )
    .is_err());
    input.challenge = "8".repeat(64);
    assert!(validate_offline_restore_request(&input, &verified).is_err());
    input.challenge = request.challenge.clone();
    input.catalog_sha256 = "9".repeat(64);
    assert!(validate_offline_restore_request(&input, &verified).is_err());
}

#[test]
fn offline_handoff_requires_exact_stopped_service_even_when_the_tick_lock_is_free() {
    let (_temp, config, _, _, _, _) = crate::engine::tests::fixture();
    let root = Dir::open(&config.root, crate::fs::uid().unwrap()).unwrap();
    drop(crate::operation::Lock::initialize(&root).unwrap());
    let mut service = crate::service::ServiceRecord {
        schema_version: 1,
        pid: 42,
        boot_id: "current-boot".into(),
        daemon_epoch: "a".repeat(64),
        generation_id: None,
        desired_revision: 0,
        desired_sha256: "b".repeat(64),
        running: true,
    };
    root.write("service.json", &ascii_json(&service).unwrap(), 0o600)
        .unwrap();
    let deadline = || crate::engine::monotonic_ms().unwrap() + 30;
    assert!(
        wait_offline_handoff(&root, Some(&service), deadline()).is_err(),
        "an unlocked tick is not proof that the resident stopped"
    );
    service.running = false;
    root.write("service.json", &ascii_json(&service).unwrap(), 0o600)
        .unwrap();
    drop(wait_offline_handoff(&root, Some(&service), deadline()).unwrap());
    service.daemon_epoch = "c".repeat(64);
    assert!(wait_offline_handoff(&root, Some(&service), deadline()).is_err());
    assert!(wait_offline_handoff(&root, None, deadline()).is_err());
    std::fs::remove_file(format!("{}/service.json", config.root)).unwrap();
    assert!(wait_offline_handoff(&root, Some(&service), deadline()).is_err());
    drop(wait_offline_handoff(&root, None, deadline()).unwrap());
}

#[test]
fn clusterboot_probe_rejects_inert_or_additional_shell_launches() {
    for misleading in [
        "cat <<EOF\nclusterboot &\nEOF\n",
        "echo '\nclusterboot &\n'\n",
        "echo \"\nclusterboot &\n\"\n",
        "echo `\nclusterboot &\n`\n",
        "echo prefix \\\nclusterboot &\n",
        "LD_PRELOAD=x clusterboot &\n",
        "env X=y /usr/bin/clusterboot &\n",
        "echo '# not a comment'; clusterboot &\n",
        "clu\\sterboot &\n",
        "clu\"ster\"boot &\n",
        "clusterboot() { true; }\n",
    ] {
        let candidate = format!("#!/bin/sh\nclusterboot &\n{misleading}");
        assert!(
            probe_clusterboot_startup(candidate.as_bytes()).is_err(),
            "{misleading}"
        );
    }
    assert!(probe_clusterboot_startup(
        b"#!/bin/sh\n# clusterboot & ignored comment\nclusterboot &\n"
    )
    .is_ok());
    assert!(probe_clusterboot_startup(b"#!/bin/sh\necho \"unterminated\nclusterboot &\n").is_err());
}

#[test]
fn clusterboot_probe_rejects_non_top_level_launch() {
    for source in [
        "if false; then\nclusterboot &\nfi\n",
        "(\nclusterboot &\n)\n",
        "f() {\nclusterboot &\n}\n",
        "for n in 1; do\nclusterboot &\ndone\n",
        "case x in\nx)\nclusterboot &\nesac\n",
    ] {
        assert!(
            probe_clusterboot_startup(source.as_bytes()).is_err(),
            "{source}"
        );
    }
}

#[test]
fn clusterboot_probe_accepts_observed_startup_sample_when_supplied() {
    let Ok(path) = std::env::var("VOBOOST_STARTUP_PROBE_SAMPLE") else {
        return;
    };
    let bytes = std::fs::read(path).unwrap();
    probe_clusterboot_startup(&bytes).unwrap();
}

#[test]
fn clusterboot_probe_rejects_multiline_conditional_and_pipeline_context() {
    for prefix in [
        "false &&",
        "true ||",
        "echo text |",
        "false && # conditional comment",
    ] {
        let source = format!("#!/bin/sh\n{prefix}\nclusterboot &\n");
        assert!(
            probe_clusterboot_startup(source.as_bytes()).is_err(),
            "{source}"
        );
    }
}
