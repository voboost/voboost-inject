use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

fn fixture() -> (tempfile::TempDir, Dir) {
    let base =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build/cluster-test-tmp");
    std::fs::create_dir_all(&base).unwrap();
    let temp = tempfile::tempdir_in(base).unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = std::fs::canonicalize(temp.path()).unwrap();
    let parent = Dir::parent(path.to_str().unwrap(), crate::fs::uid().unwrap()).unwrap();
    (temp, parent)
}

#[test]
fn stage_paths_and_device_identity_come_from_protected_created_directories() {
    let (_temp, parent) = fixture();
    let tx = "a".repeat(64);
    let report = observed_stage(&parent, &tx).unwrap();
    let root = Dir::open(&report.root, parent.owner).unwrap();
    assert_eq!(
        report.root_device_id,
        format!("{}", crate::fs::stat(root.fd.0).unwrap().st_dev)
    );
    assert_eq!(report.root_mode, 0o700);
    assert_eq!(report.root_uid, parent.owner);
    assert!(!report.existing_bootfile);
    assert!(!report.existing_installation);
    assert!(report
        .source_directory
        .ends_with(&format!("voboost-stage-{tx}/source")));
    assert!(report
        .provision_directory
        .ends_with(&format!("voboost-stage-{tx}/provision")));
    assert!(report.bootfile.ends_with("/voboost/boot.json"));
    assert!(report
        .prepare_report_file
        .ends_with(&format!("voboost-stage-{tx}/prepare.json")));
    assert!(ascii_json(&report).unwrap().len() < 16384);
    assert!(observed_stage(&parent, &tx).is_err());
    root.write("boot.json", b"preserved", 0o600).unwrap();
    root.write("installation.json", b"preserved", 0o600)
        .unwrap();
    // A distinct transaction may reuse only the same protected persistent root.
    let second = observed_stage(&parent, &"b".repeat(64)).unwrap();
    assert_eq!(second.root, report.root);
    assert!(second.existing_bootfile);
    assert!(second.existing_installation);
    let mut expected = serde_json::to_vec(&second).unwrap();
    expected.push(b'\n');
    assert_eq!(ascii_json(&second).unwrap(), expected);
    assert!(core::str::from_utf8(&expected).unwrap().contains(
        "\"rootMode\":448,\"existingBootfile\":true,\"existingInstallation\":true,\"startupFile\":"
    ));
}

#[test]
fn invalid_transaction_and_untrusted_existing_roots_are_not_taken_over() {
    let (_temp, parent) = fixture();
    for tx in ["", "../escape", "A", &"A".repeat(64)] {
        assert!(observed_stage(&parent, tx).is_err());
    }
    assert!(!parent.exists("voboost").unwrap());
    let root_path = std::path::Path::new(&parent.path).join("voboost");
    std::fs::create_dir(&root_path).unwrap();
    std::fs::set_permissions(&root_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(observed_stage(&parent, &"a".repeat(64)).is_err());
    assert!(!parent
        .exists(&format!("voboost-stage-{}", "a".repeat(64)))
        .unwrap());
    std::fs::remove_dir(&root_path).unwrap();
    symlink("missing", &root_path).unwrap();
    assert!(observed_stage(&parent, &"a".repeat(64)).is_err());
}

#[test]
fn public_entry_rejects_path_input_before_touching_profile_or_directories() {
    assert!(prepare_stage("/var/arbitrary", "/var/arbitrary").is_err());
}

#[test]
fn stock_report_is_canonical_challenge_bound_and_has_closed_states() {
    for invalid in ["", "/var/arbitrary", &"A".repeat(64)] {
        assert!(stock_observation(invalid, || panic!("invalid challenge observed")).is_err());
    }
    let challenge = "a".repeat(64);
    for (observation, state, object) in [
        (Ok(None), "absent", "known-surfaces"),
        (Ok(Some("startup")), "present", "startup"),
        (Err("supervisor-config"), "unknown", "supervisor-config"),
    ] {
        let expected = format!(
            "{{\"schemaVersion\":1,\"kind\":\"bootstrap-stock-observation\",\"challenge\":\"{challenge}\",\"state\":\"{state}\",\"object\":\"{object}\"}}\n"
        );
        assert_eq!(
            stock_observation(&challenge, || observation).unwrap(),
            expected.as_bytes()
        );
    }
}

#[test]
fn stock_observer_distinguishes_known_stage_names_and_emitted_markers() {
    let nonce = "a".repeat(64);
    for name in [
        format!("voboost-stage-{nonce}"),
        format!("voboost-finalize-{nonce}"),
        format!("voboost-observe-{nonce}"),
        format!("voboost-observe-{nonce}.json"),
    ] {
        assert!(stock_stage_name(&name));
    }
    assert!(!stock_stage_name("voboost-stage-unrelated"));
    assert!(!stock_stage_name(&format!(
        "voboost-observe-{nonce}.json.bak"
    )));
    assert!(!has_marker(b"clusterboot &\n", STARTUP_MARKERS));
    assert!(has_marker(
        b". /var/voboost/bin/voboost-cluster-startup.sh /var/voboost/boot.json nonce\n",
        STARTUP_MARKERS,
    ));
    let other = "b".repeat(64);
    let own = format!("voboost-stock-{nonce}");
    assert!(!stock_helper_name(&format!("voboost-{nonce}"), &own));
    assert!(stock_helper_name(&format!("voboost-stock-{other}"), &own));
    assert!(stock_helper_name(
        &format!("voboost-bootstrap-{nonce}"),
        &own
    ));
    assert!(!stock_helper_name(&own, &own));
    assert!(!stock_helper_name("voboost-stock-unrelated", &own));
}

#[test]
fn native_helper_is_bound_to_the_role_and_transaction_under_var() {
    let tx = "c".repeat(64);
    let name = format!("voboost-bootstrap-{tx}");
    assert_eq!(
        helper_name(&format!("/var/{name}"), "bootstrap", &tx).unwrap(),
        name
    );
    for path in [
        format!("/tmp/{name}"),
        format!("/var/{name}/x"),
        format!("/var/voboost-stock-{tx}"),
    ] {
        assert!(helper_name(&path, "bootstrap", &tx).is_err());
    }
    assert!(install(&format!("/var/{name}"), "/var/voboost/integration.json").is_err());
}

#[test]
fn stock_process_detects_managed_and_transaction_executables_after_disk_cleanup() {
    let tx = "a".repeat(64);
    for path in [
        "/var/voboost/bin/voboost-cluster-daemon".into(),
        format!("/var/voboost-finalize-{tx}/helper"),
        format!("/var/voboost-bootstrap-{tx}"),
        format!("/var/voboost-stock-{tx}"),
        format!("/log/tmp/voboost-{tx}"),
    ] {
        assert!(stock_process(path.as_bytes()), "{path}");
    }
    for path in [
        "/usr/bin/gauge",
        "/var/voboost-stock-unrelated",
        "/tmp/voboost-custom",
    ] {
        assert!(!stock_process(path.as_bytes()), "{path}");
    }
}

fn gauge_fixture(identity: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; 320];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&183u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x400100u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&5u32.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&320u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&320u64.to_le_bytes());
    bytes[112..120].copy_from_slice(&4096u64.to_le_bytes());
    bytes[120..124].copy_from_slice(&4u32.to_le_bytes());
    bytes[128..136].copy_from_slice(&272u64.to_le_bytes());
    bytes[136..144].copy_from_slice(&0x400110u64.to_le_bytes());
    let note_size = 16 + identity.len() as u64;
    bytes[152..160].copy_from_slice(&note_size.to_le_bytes());
    bytes[160..168].copy_from_slice(&note_size.to_le_bytes());
    bytes[168..176].copy_from_slice(&4u64.to_le_bytes());
    bytes[256..260].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    bytes[272..276].copy_from_slice(&4u32.to_le_bytes());
    bytes[276..280].copy_from_slice(&(identity.len() as u32).to_le_bytes());
    bytes[280..284].copy_from_slice(&3u32.to_le_bytes());
    bytes[284..288].copy_from_slice(b"GNU\0");
    bytes[288..288 + identity.len()].copy_from_slice(identity);
    bytes
}

fn observed_stage(parent: &Dir, transaction: &str) -> Result<Stage> {
    directories(
        parent,
        transaction,
        b"#!/bin/sh\nclusterboot &\n",
        &gauge_fixture(&[1, 2, 3, 4]),
    )
}

#[test]
fn stage_records_actual_input_identity_without_known_firmware_pins() {
    let (_temp, parent) = fixture();
    let startup = b"#!/bin/sh\n# compatible changed startup\nclusterboot &\n";
    crate::install::probe_clusterboot_startup(startup).unwrap();
    let gauge = gauge_fixture(&[4, 3, 2, 1]);
    let stage = directories(&parent, &"c".repeat(64), startup, &gauge).unwrap();
    assert_eq!(stage.startup_bytes, startup.len() as u64);
    assert_eq!(stage.original_sha256, hash(startup));
    assert_eq!(stage.expected_executable_bytes, gauge.len() as u64);
    assert_eq!(stage.expected_executable_sha256, hash(&gauge));
    assert_eq!(stage.expected_build_ids[0].build_id, "04030201");
}

#[test]
fn protected_bootstrap_inputs_reject_symlinks_empty_and_writable_files() {
    let (_temp, parent) = fixture();
    let file = std::path::Path::new(&parent.path).join("input");
    std::fs::write(&file, b"input").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(protected_file(file.to_str().unwrap(), 64).is_err());
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&file, b"").unwrap();
    assert!(protected_file(file.to_str().unwrap(), 64).is_err());
    let link = std::path::Path::new(&parent.path).join("symlink");
    symlink(&file, &link).unwrap();
    assert!(protected_file(link.to_str().unwrap(), 64).is_err());
}

#[test]
fn executable_probe_rejects_malformed_architecture_and_notes() {
    let valid = gauge_fixture(&[1, 2, 3, 4]);
    assert_eq!(crate::elf::build_id(&valid).unwrap(), "01020304");
    bootstrap_elf::probe(&valid, true, &[]).unwrap();
    let mut wrong_arch = valid.clone();
    wrong_arch[18..20].copy_from_slice(&62u16.to_le_bytes());
    assert!(crate::elf::build_id(&wrong_arch).is_err());
    assert!(crate::elf::build_id(&valid[..287]).is_err());
    let mut missing_note = valid;
    missing_note[120..124].copy_from_slice(&1u32.to_le_bytes());
    assert!(crate::elf::build_id(&missing_note).is_err());
}
