//! Host filesystem admission and exact-byte supervisor transaction tests.
//! Filesystem tests exercise the production parent-identity and member reader.
//! Transaction tests drive lock/WAL/recovery through a deterministic mock Writer.
//! These tests do not establish QNX F_SETLK or remount ABI.
use super::*;
use alloc::{format, string::ToString, vec::Vec};
use std::os::unix::fs::PermissionsExt;

fn config_parent() -> (tempfile::TempDir, Dir, libc::stat) {
    let base =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build/cluster-test-tmp");
    std::fs::create_dir_all(&base).unwrap();
    let temp = tempfile::tempdir_in(base).unwrap();
    let path = std::fs::canonicalize(temp.path()).unwrap().join("clsboot");
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let parent = Dir::parent(path.to_str().unwrap(), crate::fs::uid().unwrap()).unwrap();
    let expected = crate::fs::stat(parent.fd.0).unwrap();
    (temp, parent, expected)
}

#[test]
fn protected_config_read_observes_original_absence() {
    let (_temp, parent, expected) = config_parent();
    assert!(parent_identity(&parent, &expected).is_ok());
    assert!(read_config(&parent, &expected).unwrap().is_none());
}

#[test]
fn protected_config_parent_rejects_path_replacement_and_symlink() {
    use std::os::unix::fs::symlink;
    let (_temp, parent, expected) = config_parent();
    let original = std::path::Path::new(&parent.path);
    let retained = original.with_extension("retained");
    std::fs::write(original.join(CONFIG_NAME), b"retained original").unwrap();
    assert!(parent_identity(&parent, &expected).is_ok());
    std::fs::rename(original, &retained).unwrap();
    std::fs::create_dir(original).unwrap();
    std::fs::set_permissions(original, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(original.join(CONFIG_NAME), b"replacement").unwrap();
    assert!(parent_identity(&parent, &expected).is_err());
    assert!(read_config(&parent, &expected).is_err());
    std::fs::remove_file(original.join(CONFIG_NAME)).unwrap();
    std::fs::remove_dir(original).unwrap();
    symlink(&retained, original).unwrap();
    assert!(parent_identity(&parent, &expected).is_err());
    assert!(read_config(&parent, &expected).is_err());
    std::fs::remove_file(original).unwrap();
    std::fs::rename(retained, original).unwrap();
}

#[test]
fn protected_config_read_rejects_symlink_member() {
    use std::os::unix::fs::symlink;
    let (_temp, parent, expected) = config_parent();
    symlink(
        "missing",
        std::path::Path::new(&parent.path).join(CONFIG_NAME),
    )
    .unwrap();
    assert!(parent_identity(&parent, &expected).is_ok());
    assert!(read_config(&parent, &expected).is_err());
}

#[test]
fn protected_config_read_never_treats_access_denial_as_absence() {
    if crate::fs::uid().unwrap() == 0 {
        return;
    }
    let (_temp, parent, _) = config_parent();
    std::fs::set_permissions(&parent.path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let expected = crate::fs::stat(parent.fd.0).unwrap();
    let result = read_config(&parent, &expected);
    std::fs::set_permissions(&parent.path, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(result.is_err());
}

/// Deterministic in-memory mock of the fixed-path mount writer.
#[derive(Default)]
struct Mock {
    live: Option<(Vec<u8>, u32)>, // None = absent
    readonly: bool,
    calls: Vec<&'static str>,
    failures: Vec<&'static str>,
}
impl Mock {
    fn with(live: Option<(Vec<u8>, u32)>) -> Self {
        Self {
            live,
            readonly: true,
            ..Mock::default()
        }
    }
    fn call(&mut self, name: &'static str) -> Result<()> {
        self.calls.push(name);
        if let Some(at) = self.failures.iter().position(|v| *v == name) {
            self.failures.remove(at);
            return Err(format!("injected {name} failure"));
        }
        Ok(())
    }
    fn installed(&self) -> Vec<u8> {
        self.live
            .as_ref()
            .map(|(b, _)| b.clone())
            .unwrap_or_default()
    }
}
impl Writer for Mock {
    fn observe(&mut self) -> Result<LiveConfig> {
        self.call("observe")?;
        Ok(match &self.live {
            Some((bytes, mode)) => LiveConfig {
                present: true,
                bytes: bytes.clone(),
                mode: *mode,
            },
            None => LiveConfig {
                present: false,
                bytes: Vec::new(),
                mode: 0,
            },
        })
    }
    fn writable(&mut self) -> Result<()> {
        self.call("rw")?;
        self.readonly = false;
        Ok(())
    }
    fn verify_writable(&mut self) -> Result<()> {
        self.call("verify-rw")?;
        if self.readonly {
            return Err("mock not writable".into());
        }
        Ok(())
    }
    fn publish(&mut self, bytes: &[u8], mode: u32) -> Result<()> {
        self.call("write")?;
        // Atomic publish + exact readback semantics.
        self.live = Some((bytes.to_vec(), mode));
        Ok(())
    }
    fn publish_absence(&mut self) -> Result<()> {
        self.call("unlink")?;
        self.live = None;
        Ok(())
    }
    fn readonly(&mut self) -> Result<()> {
        self.call("ro")?;
        self.readonly = true;
        Ok(())
    }
    fn verify_readonly(&mut self, _expect_installed: bool) -> Result<()> {
        self.call("verify-ro")?;
        if !self.readonly {
            return Err("mock not readonly".into());
        }
        Ok(())
    }
}

fn store() -> (tempfile::TempDir, crate::fs::Dir) {
    let base =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build/cluster-test-tmp");
    std::fs::create_dir_all(&base).unwrap();
    let temp = tempfile::tempdir_in(&base).unwrap();
    let path = std::fs::canonicalize(temp.path()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let owner = crate::fs::uid().unwrap();
    (
        temp,
        crate::fs::Dir::open(path.to_str().unwrap(), owner).unwrap(),
    )
}

fn nonce(seed: char) -> String {
    seed.to_string().repeat(64)
}

/// Production restore transaction ids are digest-shaped hex (the WAL validates
/// its own record with the same shape check); use a hex seed for ids passed to
/// restore_standard.
fn txid(seed: char) -> String {
    assert!(seed.is_ascii_hexdigit());
    seed.to_string().repeat(64)
}

fn candidate(implant: &str, bootfile: &str, stamp: &str) -> Vec<u8> {
    // Structurally complete three-target candidate, byte-shape of the
    // proved emitter output; the transaction never re-serializes it.
    let mut xml = String::from("<?xml version=\"1.0\"?><clsboot_root><action_execs>");
    for owner in ["gauge", "point", "light"] {
        xml.push_str(
            &format!(
                "<action_exec><m_args nums=\"1\"><arg>/usr/bin/{owner}</arg></m_args><m_envs nums=\"3\">"
            ),
        );
        xml.push_str(&format!("<env>LD_PRELOAD={implant}</env>"));
        xml.push_str(&format!("<env>VOBOOST_CLUSTER_BOOTFILE={bootfile}</env>"));
        xml.push_str(&format!("<env>VOBOOST_CLUSTER_SUPERVISOR={stamp}</env>"));
        xml.push_str("</m_envs></action_exec>");
    }
    xml.push_str("</action_execs></clsboot_root>");
    xml.into_bytes()
}

fn operation(seed: char, defaults: Option<Vec<u8>>) -> Operation {
    Operation {
        transaction_id: nonce(seed),
        implant: "/var/voboost/bin/libvoboost-cluster-inject.so".into(),
        bootfile: "/var/voboost/boot.json".into(),
        nonce: nonce(seed),
        default_candidate: defaults,
        failpoints: Failpoints::new(),
        restore: false,
    }
}

/// Minimal enclosing Installation record so the typed subrecord is exercised
/// through the real parse/persist functions in install.rs. Field order and
/// compact spacing match the canonical serialization contract exactly.
fn seed_installation(root: &crate::fs::Dir) {
    let text = format!(
        "{{\"schemaVersion\":1,\"bootfile\":\"/var/voboost/boot.json\",\
         \"startupFile\":\"/scripts/startup_cluster.sh\",\
         \"originalSha256\":\"{}\",\"installedSha256\":\"{}\",\
         \"startupMode\":448,\"releaseManifestSha256\":\"{}\",\
         \"catalogSha256\":\"{}\",\"files\":[]}}\n",
        nonce('o'),
        nonce('i'),
        nonce('e'),
        nonce('c')
    );
    root.write("installation.json", text.as_bytes(), 0o600)
        .unwrap();
}

fn install_op(seed: char) -> Operation {
    operation(seed, None)
}

// 1. absent/present/empty original + first install success
#[test]
fn first_install_present_captures_first_original_and_publishes() {
    let (_t, root) = store();
    seed_installation(&root);
    let original = b"<?xml version=\"1.0\"?><clsboot_root/>".to_vec();
    let mut mock = Mock::with(Some((original.clone(), 0o600)));
    let op = install_op('a');
    let bytes = candidate(&op.implant, &op.bootfile, &nonce('a'));
    let lock = OperationLock::acquire(&root).unwrap();
    execute(&root, &mut mock, &op, &bytes, None, 0o600, true).unwrap();
    drop(lock);
    assert_eq!(mock.live.as_ref().unwrap().0, bytes);
    assert_eq!(root.read(ORIGINAL_NAME, 4096, 0o600).unwrap(), original);
    let record = permit_ready(&root).unwrap().unwrap();
    assert!(!record.original_absent);
    assert_eq!(record.delivery_nonce, nonce('a'));
}

fn legacy_uninstall_fixture(root: &Dir) -> (Mock, Vec<u8>, Vec<u8>) {
    seed_installation(root);
    let original = b"<?xml version=\"1.0\"?><clsboot_root/>".to_vec();
    let mut writer = Mock::with(Some((original.clone(), 0o644)));
    let op = install_op('a');
    let installed = candidate(&op.implant, &op.bootfile, &nonce('a'));
    run_standard(root, &mut writer, &op, &installed, None, 0o600, true).unwrap();
    (writer, original, installed)
}

#[test]
fn legacy_uninstall_restores_exact_original_and_blocks_same_boot_after_lost_ack() {
    let (_t, root) = store();
    let (mut writer, original, _) = legacy_uninstall_fixture(&root);
    let transaction = txid('b');
    let reboot = require_uninstall_restored(&root, &mut writer, &transaction, 12).unwrap_err();
    assert_eq!(
        reboot,
        "native uninstall requires independent new kernel boot after legacy supervisor restoration"
    );
    assert_eq!(writer.live, Some((original, 0o644)));
    assert!(restored_without_receipt(&root, &mut writer).unwrap());
    writer.calls.clear();
    assert_eq!(
        require_uninstall_restored(&root, &mut writer, &transaction, 12).unwrap_err(),
        reboot
    );
    assert!(!writer.calls.contains(&"rw"));
    assert!(require_uninstall_restored(&root, &mut writer, &txid('c'), 13).is_err());
    require_uninstall_restored(&root, &mut writer, &transaction, 13).unwrap();
}

#[test]
fn legacy_uninstall_does_not_write_foreign_bytes_mode_or_presence() {
    let (_t, root) = store();
    let (mut writer, original, installed) = legacy_uninstall_fixture(&root);
    let transaction = txid('b');
    for foreign in [
        Some((original, 0o644)),
        Some((b"foreign".to_vec(), 0o600)),
        Some((installed, 0o640)),
        None,
    ] {
        writer.live = foreign.clone();
        writer.calls.clear();
        assert!(require_uninstall_restored(&root, &mut writer, &transaction, 12).is_err());
        assert_eq!(writer.live, foreign);
        assert!(!writer.calls.contains(&"rw"));
        assert!(permit_ready(&root).unwrap().is_some());
        assert!(!root.exists("supervisor-uninstall-reboot.json").unwrap());
    }
}

#[test]
fn legacy_uninstall_recovers_prepared_restore_under_the_original_fence() {
    let (_t, root) = store();
    let (mut writer, original, _) = legacy_uninstall_fixture(&root);
    let transaction = txid('b');
    writer.failures.push("ro"); // publication succeeds; the WAL remains Prepared
    assert!(require_uninstall_restored(&root, &mut writer, &transaction, 12).is_err());
    assert_eq!(writer.live, Some((original, 0o644)));
    assert!(root.exists("supervisor-uninstall-reboot.json").unwrap());
    assert!(!restored_without_receipt(&root, &mut writer).unwrap());
    assert!(require_uninstall_restored(&root, &mut writer, &txid('c'), 12).is_err());
    let reboot = require_uninstall_restored(&root, &mut writer, &transaction, 12).unwrap_err();
    assert!(reboot.contains("new kernel boot after legacy supervisor restoration"));
    assert!(restored_without_receipt(&root, &mut writer).unwrap());
    require_uninstall_restored(&root, &mut writer, &transaction, 13).unwrap();
}

#[test]
fn first_install_absent_keeps_absence_and_uses_staged_default() {
    let (_t, root) = store();
    seed_installation(&root);
    let mut mock = Mock::with(None);
    let op = install_op('a');
    let bytes = candidate(&op.implant, &op.bootfile, &nonce('a'));

    let lock = OperationLock::acquire(&root).unwrap();
    execute(&root, &mut mock, &op, &bytes, None, 0o600, true).unwrap();
    drop(lock);
    assert_eq!(mock.live.as_ref().unwrap().0, bytes);
    assert_eq!(root.read(ORIGINAL_NAME, 64, 0o600).unwrap(), ABSENT_MARKER);
    assert!(permit_ready(&root).unwrap().unwrap().original_absent);
}

#[test]
fn first_install_empty_present_original_is_not_confused_with_absent() {
    let (_t, root) = store();
    seed_installation(&root);
    let mut mock = Mock::with(Some((Vec::new(), 0o600)));
    let mut op = install_op('a');
    let bytes = candidate(&op.implant, &op.bootfile, &nonce('a'));
    op.default_candidate = Some(bytes.clone());
    let lock = OperationLock::acquire(&root).unwrap();
    execute(&root, &mut mock, &op, &bytes, None, 0o600, true).unwrap();
    drop(lock);
    // Empty-but-present original: original sidecar is the empty payload, not
    // the absence marker; receipt records original as PRESENT.
    assert_eq!(root.read(ORIGINAL_NAME, 64, 0o600).unwrap(), b"");
    assert!(!permit_ready(&root).unwrap().unwrap().original_absent);
}

// 2. update preserves FIRST original and rotates only the nonce
#[test]
fn update_keeps_first_original_and_requires_new_nonce() {
    let (_t, root) = store();
    seed_installation(&root);
    let original = b"<clsboot_root>".to_vec();
    let mut mock = Mock::with(Some((original.clone(), 0o600)));
    let first = install_op('a');
    let bytes = candidate(&first.implant, &first.bootfile, &nonce('a'));
    let lock = OperationLock::acquire(&root).unwrap();
    execute(&root, &mut mock, &first, &bytes, None, 0o600, true).unwrap();
    drop(lock);
    let second = install_op('b');
    let next = candidate(&second.implant, &second.bootfile, &nonce('b'));
    let lock = OperationLock::acquire(&root).unwrap();
    execute(&root, &mut mock, &second, &next, None, 0o600, true).unwrap();
    drop(lock);
    assert_eq!(root.read(ORIGINAL_NAME, 4096, 0o600).unwrap(), original);
    assert_eq!(
        permit_ready(&root).unwrap().unwrap().delivery_nonce,
        nonce('b')
    );
    let same_nonce = Operation {
        nonce: nonce('b'),
        ..install_op('c')
    };
    let lock = OperationLock::acquire(&root).unwrap();
    let err = execute(&root, &mut mock, &same_nonce, &next, None, 0o600, true);
    drop(lock);
    assert!(err.unwrap_err().contains("nonce must differ"));
}

#[test]
fn update_rejects_live_xml_not_equal_to_retained_candidate() {
    let (_t, root) = store();
    seed_installation(&root);
    let mut mock = Mock::with(Some((b"<clsboot_root>".to_vec(), 0o600)));
    let first = install_op('a');
    let bytes = candidate(&first.implant, &first.bootfile, &nonce('a'));
    let lock = OperationLock::acquire(&root).unwrap();
    execute(&root, &mut mock, &first, &bytes, None, 0o600, true).unwrap();
    drop(lock);
    // foreign mutation between runs
    mock.live = Some((b"<clsboot_root><foreign/></clsboot_root>".to_vec(), 0o600));
    let second = install_op('b');
    let next = candidate(&second.implant, &second.bootfile, &nonce('b'));
    let lock = OperationLock::acquire(&root).unwrap();
    let err = execute(&root, &mut mock, &second, &next, None, 0o600, true);
    drop(lock);
    assert!(err.unwrap_err().contains("differs from retained candidate"));
    // foreign bytes preserved, payload/authority intact
    assert!(permit_ready(&root).is_ok());
    assert!(root.exists(ORIGINAL_NAME).unwrap());
}

#[test]
fn first_install_rejects_orphan_original_sidecar() {
    let (_t, root) = store();
    seed_installation(&root);
    root.write(ORIGINAL_NAME, b"orphan", 0o600).unwrap();
    let mut mock = Mock::with(None);
    let op = install_op('a');
    let bytes = candidate(&op.implant, &op.bootfile, &nonce('a'));
    let lock = OperationLock::acquire(&root).unwrap();
    let err = execute(&root, &mut mock, &op, &bytes, None, 0o600, true);
    drop(lock);
    assert!(err.unwrap_err().contains("orphan original sidecar"));
}

// 3. two writers cannot both proceed
fn run_lock_helper(temp: &std::path::Path) -> bool {
    std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("supervisor_config::tests::lock_helper_child")
        .arg("--nocapture")
        .env(
            "VOBOOST_LOCK_HELPER_ROOT",
            std::fs::canonicalize(temp).unwrap(),
        )
        .status()
        .unwrap()
        .success()
}
#[test]
fn lock_helper_child() {
    // Spawned by lock_is_exclusive_for_concurrent_writers as a real second
    // process; without the env it is an inert pass in ordinary runs.
    let Some(path) = std::env::var_os("VOBOOST_LOCK_HELPER_ROOT") else {
        return;
    };
    let owner = crate::fs::uid().unwrap();
    let root = crate::fs::Dir::open(path.to_str().unwrap(), owner).unwrap();
    let held = OperationLock::acquire(&root);
    if let Ok(held) = held {
        drop(held);
    } else if let Err(reason) = held {
        panic!("child lock acquisition failed: {reason}");
    }
}
#[test]
fn lock_is_exclusive_for_concurrent_writers() {
    // Advisory POSIX locks are held per process: a second writer must be a
    // real concurrent process, not a second FD in this same process.
    let (temp, root) = store();
    let held = OperationLock::acquire(&root).unwrap();
    assert!(
        !run_lock_helper(temp.path()),
        "a second process must not acquire while held"
    );
    drop(held);
    assert!(run_lock_helper(temp.path()));
    assert!(OperationLock::acquire(&root).is_ok());
}

#[test]
fn lock_inode_is_stable_and_never_rewritten() {
    let (_t, root) = store();
    seed_installation(&root);
    let a = OperationLock::acquire(&root).unwrap();
    drop(a);
    let b = OperationLock::acquire(&root).unwrap();
    drop(b);
    assert_eq!(
        root.read("supervisor.lock", 64, 0o600).unwrap(),
        LOCK_MARKER
    );
}

// 4. interruption matrix: before/after each durable step
#[test]
fn interruption_at_each_durable_step_leaves_recoverable_or_untouched_state() {
    let points = [
        Failpoint::WalPreparingPersisted,
        Failpoint::SidecarsPersisted,
        Failpoint::WalPrepared,
        Failpoint::FenceWritten,
        Failpoint::RemountWritable,
        Failpoint::BeforeRecheck,
        Failpoint::Published,
        Failpoint::ReadonlyRestored,
        Failpoint::InstalledSidecarPersisted,
        Failpoint::ReceiptPersisted,
        Failpoint::FinalReadback,
    ];
    for point in points {
        let (_t, root) = store();
        let original = b"<clsboot_root>".to_vec();
        seed_installation(&root);
        let mut mock = Mock::with(Some((original.clone(), 0o600)));
        let mut op = install_op('a');
        op.failpoints.insert(point);
        let bytes = candidate(&op.implant, &op.bootfile, &nonce('a'));
        let lock = OperationLock::acquire(&root).unwrap();
        let result = execute(&root, &mut mock, &op, &bytes, None, 0o600, true);
        drop(lock);
        assert!(result.is_err(), "{point:?} must not report success");
        // Live state is always exactly original or the complete candidate —
        // never a half state.
        let live = mock.installed();
        assert!(
            live == original || live == bytes,
            "{point:?} must leave original or complete candidate"
        );
        if matches!(permit_ready(&root), Ok(Some(_)),) {
            // A permit can only exist when everything, including the
            // terminal marker and receipt, is durably complete.
            assert_eq!(mock.installed(), bytes, "{point:?} incomplete but admitted");
        }
        // A permit is NEVER granted while the WAL is pending: verify the
        // deny for each pre-ReceiptPersisted failpoint.
        if !matches!(point, Failpoint::FinalReadback) {
            assert!(matches!(permit_ready(&root), Ok(None)), "{point:?}");
        }
    }
}

// 5. crash recovery: exact before/after only
#[test]
fn crash_at_publish_yields_original_or_complete_candidate_only() {
    for published in [false, true] {
        let (_t, root) = store();
        seed_installation(&root);
        let original = b"<clsboot_root-orig>".to_vec();
        let mut mock = Mock::with(Some((original.clone(), 0o600)));
        let op = install_op('a');
        let bytes = candidate(&op.implant, &op.bootfile, &nonce('a'));
        let lock = OperationLock::acquire(&root).unwrap();
        let mut prepared_fail = Failpoints::new();
        if published {
            prepared_fail.insert(Failpoint::ReadonlyRestored);
        } else {
            prepared_fail.insert(Failpoint::Published);
        }
        let result = {
            let mut failing = Operation {
                transaction_id: op.transaction_id.clone(),
                implant: op.implant.clone(),
                bootfile: op.bootfile.clone(),
                nonce: op.nonce.clone(),
                default_candidate: op.default_candidate.clone(),
                failpoints: prepared_fail,
                restore: false,
            };
            failing.failpoints.insert(if published {
                Failpoint::ReadonlyRestored
            } else {
                Failpoint::Published
            });
            execute(&root, &mut mock, &failing, &bytes, None, 0o600, true)
        };
        drop(lock);
        assert!(result.is_err());
        // Live state after the simulated crash is exactly before or after.
        let live_bytes = mock.installed();
        assert!(
            live_bytes == original || live_bytes == bytes,
            "crash must yield original or complete candidate"
        );
        // Recovery recognizes both, never anything else.
        let lock = OperationLock::acquire(&root).unwrap();
        let recovered = recover_existing(&root, &mut mock);
        drop(lock);
        assert!(recovered.is_err() || mock.installed() == original);
    }
}

// 6. missing/corrupt sidecars in Preparing/Prepared deny everything
#[test]
fn preparing_wal_without_sidecars_denies_permit_and_preserves_journal() {
    let (_t, root) = store();
    seed_installation(&root);
    let wal = Wal {
        schema_version: 1,
        transaction_id: nonce('a'),
        config_path: CONFIG_PATH.into(),
        delivery_nonce: nonce('a'),
        state: WalState::Preparing,
        restoring: false,
        first_original: Presence::of(true, 0o600).unwrap(),
        before: Presence::of(true, 0o600).unwrap(),
        after: Presence::of(true, 0o600).unwrap(),
    };
    root.write("supervisor-config.wal", &wal.bytes().unwrap(), 0o600)
        .unwrap();
    let mut mock = Mock::default();
    let lock = OperationLock::acquire(&root).unwrap();
    let err = recover_existing(&root, &mut mock);
    drop(lock);
    assert!(err.unwrap_err().contains("Preparing"));
    // Journal preserved, not overwritten.
    assert!(root.exists("supervisor-config.wal").unwrap());
    assert!(matches!(permit_ready(&root), Ok(None)));
}

#[test]
fn malformed_wal_is_preserved_and_reported_never_treated_absent() {
    let (_t, root) = store();
    seed_installation(&root);
    root.write("supervisor-config.wal", b"VBCSUPABSENT\n", 0o600)
        .unwrap();
    let mut mock = Mock::default();
    let lock = OperationLock::acquire(&root).unwrap();
    let err = recover_existing(&root, &mut mock);
    drop(lock);
    assert!(err.unwrap_err().contains("malformed"));
    assert_eq!(
        root.read("supervisor-config.wal", 64, 0o600).unwrap(),
        b"VBCSUPABSENT\n"
    );
    assert!(matches!(permit_ready(&root), Ok(None)));
}

// 7. reboot (simulated new boot id) cannot turn incomplete into ready
#[test]
fn simulated_reboot_does_not_complete_an_incomplete_wal() {
    let (_t, root) = store();
    seed_installation(&root);
    let wal = Wal {
        schema_version: 1,
        transaction_id: nonce('a'),
        config_path: CONFIG_PATH.into(),
        delivery_nonce: nonce('a'),
        state: WalState::Prepared,
        restoring: false,
        first_original: Presence::of(true, 0o600).unwrap(),
        before: Presence::of(true, 0o600).unwrap(),
        after: Presence::of(true, 0o600).unwrap(),
    };
    root.write("supervisor-config.wal", &wal.bytes().unwrap(), 0o600)
        .unwrap();
    // Several simulated boots later the answer is identical.
    for _boot in 0..3 {
        assert!(matches!(permit_ready(&root), Ok(None)));
    }
}

// 8. foreign bytes/mode/presence preserved on restore
#[test]
fn restore_refuses_foreign_live_state_and_keeps_all_retained_state() {
    let (_t, root) = store();
    seed_installation(&root);
    let original = b"<clsboot_root>".to_vec();
    let mut mock = Mock::with(Some((original.clone(), 0o600)));
    let first = install_op('a');
    let bytes = candidate(&first.implant, &first.bootfile, &nonce('a'));
    let lock = OperationLock::acquire(&root).unwrap();
    execute(&root, &mut mock, &first, &bytes, None, 0o600, true).unwrap();
    drop(lock);
    // Foreign content, mode, and presence each refuse restore.
    let op = Operation { ..install_op('a') };
    for foreign in [
        Some((b"<foreign/>".to_vec(), 0o600)),
        Some((bytes.clone(), 0o644)),
        None,
    ] {
        mock.live = foreign;
        let lock = OperationLock::acquire(&root).unwrap();
        let err = restore(&root, &mut mock, &op);
        drop(lock);
        assert!(err.is_err());
        // Failed restoration never deletes payload/authority/WAL.
        assert!(root.exists(ORIGINAL_NAME).unwrap());
        assert!(root.exists(INSTALLED_NAME).unwrap());
        assert!(root.exists("supervisor-config.wal").unwrap());
    }
}

#[test]
fn restore_returns_exact_first_original_or_absence() {
    for original in [Some(b"<clsboot_root>".to_vec()), None] {
        let (_t, root) = store();
        seed_installation(&root);
        let mut mock = Mock::with(original.clone().map(|b| (b, 0o600)));
        let op = install_op('a');
        let bytes = candidate(&op.implant, &op.bootfile, &nonce('a'));
        let lock = OperationLock::acquire(&root).unwrap();
        execute(&root, &mut mock, &op, &bytes, None, 0o600, true).unwrap();
        drop(lock);
        let restore_op = install_op('a');
        let lock = OperationLock::acquire(&root).unwrap();
        restore(&root, &mut mock, &restore_op).unwrap();
        drop(lock);
        match original {
            Some(bytes) => {
                assert_eq!(mock.live.as_ref().unwrap().0, bytes);
                assert_eq!(mock.live.as_ref().unwrap().1, 0o600);
            }
            None => assert!(mock.live.is_none()),
        }
    }
}

// 9. missing/corrupt sidecars in Prepared are diagnosed, never overwritten
#[test]
fn prepared_wal_with_missing_sidecars_is_preserved_for_diagnosis() {
    let (_t, root) = store();
    seed_installation(&root);
    root.write(
        "supervisor-config.wal",
        &{
            let wal = Wal {
                schema_version: 1,
                transaction_id: nonce('a'),
                config_path: CONFIG_PATH.into(),
                delivery_nonce: nonce('a'),
                state: WalState::Prepared,
                restoring: false,
                first_original: Presence::of(true, 0o600).unwrap(),
                before: Presence::of(true, 0o600).unwrap(),
                after: Presence::of(true, 0o600).unwrap(),
            };
            wal.bytes().unwrap()
        },
        0o600,
    )
    .unwrap();
    let mut mock = Mock::default();
    let lock = OperationLock::acquire(&root).unwrap();
    let err = recover_existing(&root, &mut mock);
    drop(lock);
    assert!(err.unwrap_err().contains("sidecar missing"));
    assert!(root.exists("supervisor-config.wal").unwrap());
}

// 10. revoke/publish/readback/RO restore failures never claim success
#[test]
fn writer_failures_never_provide_a_permit_and_keep_recovery_bytes() {
    for failure in ["rw", "verify-rw", "write", "ro", "verify-ro", "observe"] {
        let (_t, root) = store();
        seed_installation(&root);
        let original = b"<clsboot_root>".to_vec();
        let mut mock = Mock {
            live: Some((original.clone(), 0o600)),
            readonly: true,
            failures: alloc::vec![failure],
            calls: Vec::new(),
        };
        let op = install_op('a');
        let bytes = candidate(&op.implant, &op.bootfile, &nonce('a'));
        let lock = OperationLock::acquire(&root).unwrap();
        let err = execute(&root, &mut mock, &op, &bytes, None, 0o600, true);
        drop(lock);
        assert!(err.is_err(), "{failure} must fail the transaction");
        assert!(matches!(permit_ready(&root), Ok(None)), "{failure}");
        if failure == "observe" {
            // The very first observation failed: nothing was persisted yet.
            assert!(!root.exists("supervisor-config.wal").unwrap());
            continue;
        }
        // WAL pending + sidecars retained: recovery data survives.
        assert!(root.exists("supervisor-config.wal").unwrap());
        assert!(root.exists("supervisor-config.pending-before").unwrap());
        assert!(root.exists("supervisor-config.pending-after").unwrap());
        // Live bytes are exactly the original or the complete candidate;
        // post-publish remount failures leave the finished publish in place.
        let live = mock.installed();
        assert!(live == original || live == bytes, "{failure}");
    }
}

// 11. first install rejects target spans already carrying our tokens
#[test]
fn first_install_rejects_preexisting_delivery_tokens() {
    let (_t, root) = store();
    seed_installation(&root);
    let implant = "/var/voboost/bin/libvoboost-cluster-inject.so";
    for token in [
        "VOBOOST_CLUSTER_BOOTFILE=/var/voboost/boot.json".to_string(),
        format!("VOBOOST_CLUSTER_SUPERVISOR={}", nonce('z')),
        format!("LD_PRELOAD={implant}"),
    ] {
        let xml = format!(
            "<?xml version=\"1.0\"?><clsboot_root><action_execs><action_exec>\
             <m_args nums=\"1\"><arg>/usr/bin/gauge</arg></m_args>\
             <m_envs nums=\"1\"><env>{token}</env></m_envs></action_exec>\
             </action_execs></clsboot_root>"
        );
        let mut mock = Mock::with(Some((xml.into_bytes(), 0o600)));
        let op = install_op('a');
        let bytes = candidate(&op.implant, &op.bootfile, &nonce('a'));
        let lock = OperationLock::acquire(&root).unwrap();
        let result = execute(&root, &mut mock, &op, &bytes, None, 0o600, true);
        drop(lock);
        assert!(
            result
                .map_err(|e| e.to_string())
                .unwrap_err()
                .contains("unowned"),
            "preexisting {token} must reject"
        );
    }
}

// F1 regression: a candidate composed from a pre-lock observation must fail
// when the live config changed before the transaction lock reobserves it.
#[test]
fn stale_composed_source_fails_before_any_durable_state() {
    let (_t, root) = store();
    seed_installation(&root);
    let mut mock = Mock::with(Some((b"<clsboot_root-stale/>".to_vec(), 0o600)));
    let op = install_op('a');
    let bytes = candidate(&op.implant, &op.bootfile, &nonce('a'));
    mock.live = Some((b"<clsboot_root-foreign/>".to_vec(), 0o600));
    let lock = OperationLock::acquire(&root).unwrap();
    let err = execute(
        &root,
        &mut mock,
        &op,
        &bytes,
        Some(&LiveConfig {
            present: true,
            bytes: b"<clsboot_root-stale/>".to_vec(),
            mode: 0o600,
        }),
        0o600,
        true,
    );
    drop(lock);
    assert!(err
        .map_err(|e| e.to_string())
        .unwrap_err()
        .contains("changed before transaction lock"));
    assert!(!root.exists(WAL_NAME).unwrap(), "no WAL may be written");
}

// F3 regression: an interrupted restore keeps the exact FIRST-original target
// (not synthetic absence) as its recovery after-state.
#[test]
fn interrupted_restore_targets_first_original_in_wal() {
    let (_t, root) = store();
    seed_installation(&root);
    let original = b"<clsboot_root-orig>".to_vec();
    let mut mock = Mock::with(Some((original.clone(), 0o600)));
    let first = install_op('a');
    let bytes = candidate(&first.implant, &first.bootfile, &nonce('a'));
    let lock = OperationLock::acquire(&root).unwrap();
    execute(&root, &mut mock, &first, &bytes, None, 0o600, true).unwrap();
    drop(lock);
    // A failing restore (publish step injects) must leave after == original presence.
    let mut failing = Operation {
        failpoints: Failpoints::new(),
        ..install_op('a')
    };
    failing.failpoints.insert(Failpoint::Published);
    let lock = OperationLock::acquire(&root).unwrap();
    let err = restore(&root, &mut mock, &failing);
    drop(lock);
    assert!(err.is_err());
    let wal_bytes = root.read(WAL_NAME, RECORD_MAX, 0o600).unwrap();
    let wal = Wal::parse(&wal_bytes).unwrap();
    assert!(
        wal.after.present,
        "restore after must be the present original"
    );
    assert_eq!(wal.after.mode, 0o600);
    let after = root.read(AFTER_NAME, 4096, 0o600).unwrap();
    assert_ne!(
        after, b"VBCSUPABSENT\n",
        "after sidecar must hold original bytes"
    );
    assert_eq!(root.read(ORIGINAL_NAME, 4096, 0o600).unwrap(), original);
}

// F4 regression: a mode-only foreign change on the live config refuses update.
#[test]
fn update_rejects_mode_only_foreign_change() {
    let (_t, root) = store();
    seed_installation(&root);
    let original = b"<clsboot_root>".to_vec();
    let mut mock = Mock::with(Some((original.clone(), 0o600)));
    let first = install_op('a');
    let bytes = candidate(&first.implant, &first.bootfile, &nonce('a'));
    let lock = OperationLock::acquire(&root).unwrap();
    execute(&root, &mut mock, &first, &bytes, None, 0o600, true).unwrap();
    drop(lock);
    // Same bytes, foreign mode.
    mock.live = Some((bytes.clone(), 0o644));
    let second = install_op('b');
    let next = candidate(&second.implant, &second.bootfile, &nonce('b'));
    let lock = OperationLock::acquire(&root).unwrap();
    let err = execute(&root, &mut mock, &second, &next, None, 0o600, true);
    drop(lock);
    assert!(err
        .map_err(|e| e.to_string())
        .unwrap_err()
        .contains("differs from retained candidate"));
}

// F5 regression: a crash between the enclosing installation.json write and the
// config-receipt persist previously wedged both commands — install refused
// "already exists" and restore refused "no validated supervisor config
// receipt" — with the live config already rolled back and nothing left to do.
// The completed recovery-to-before with no receipt must terminate restore
// successfully, and every neighboring state must keep the hard refusal.
#[test]
fn receiptless_completed_rollback_terminates_restore_but_neighbors_refuse() {
    // Build the crash-window leftover the way a real run leaves it: an
    // interrupted install publish (crash at ReadonlyRestored), then the
    // bounded recovery rolling the config back to the FIRST original and
    // marking the WAL Applied — with the durable receipt never printed.
    let setup_crash_window = |seed_original: Option<Vec<u8>>| {
        let (_t, root) = store();
        seed_installation(&root);
        let mut mock = Mock::with(seed_original.clone().map(|b| (b, 0o600)));
        let op = install_op('a');
        let bytes = candidate(&op.implant, &op.bootfile, &nonce('a'));
        let mut failing = operation('a', None);
        failing.failpoints.insert(Failpoint::ReadonlyRestored);
        let lock = OperationLock::acquire(&root).unwrap();
        let err = execute(&root, &mut mock, &failing, &bytes, None, 0o600, true);
        drop(lock);
        assert!(err.is_err(), "the tail crashes before the receipt");
        let lock = OperationLock::acquire(&root).unwrap();
        recover_existing(&root, &mut mock).unwrap();
        drop(lock);
        (_t, root, mock, bytes)
    };

    // 1. Present FIRST original: the waived tail admits restore to success.
    {
        let original = b"<clsboot_root-orig>".to_vec();
        let (_t, root, mut mock, bytes) = setup_crash_window(Some(original.clone()));
        let lock = OperationLock::acquire(&root).unwrap();
        assert_eq!(mock.live.as_ref().unwrap().0, original);
        // The recovery marked the WAL Applied and the live state rolled back.
        assert!(matches!(
            Wal::parse(&root.read(WAL_NAME, RECORD_MAX, 0o600).unwrap())
                .unwrap()
                .state,
            WalState::Applied
        ));
        assert!(
            restored_without_receipt(&root, &mut mock).unwrap(),
            "completed receipt-less rollback must be a waiver"
        );
        let result = restore(&root, &mut mock, &install_op('a'));
        drop(lock);
        result.expect("receipt-less completed rollback must terminate restore");
        assert_eq!(mock.live.as_ref().unwrap().0, original);
        // Nothing was written or removed by the waiver: the journal and every
        // retained sidecar stay intact for diagnosis.
        assert!(root.exists(WAL_NAME).unwrap());
        assert!(root.exists(ORIGINAL_NAME).unwrap());
        assert!(root.exists(BEFORE_NAME).unwrap());
        assert!(root.exists(AFTER_NAME).unwrap());
        let _ = bytes;
    }

    // 2. Recorded original absence: the waived tail equally terminates the
    // restore of an originally-absent config.
    {
        let (_t, root, mut mock, _bytes) = setup_crash_window(None);
        let lock = OperationLock::acquire(&root).unwrap();
        assert!(mock.live.is_none());
        assert!(restored_without_receipt(&root, &mut mock).unwrap());
        let result = restore(&root, &mut mock, &install_op('a'));
        drop(lock);
        result.unwrap();
        assert!(mock.live.is_none());
    }

    // 3. Negative: a still-installed candidate (crash after publish, before
    // the rollback recovery) is NOT a waiver; restore keeps failing closed.
    {
        let (_t, root) = store();
        seed_installation(&root);
        let original = b"<clsboot_root-orig>".to_vec();
        let mut mock = Mock::with(Some((original.clone(), 0o600)));
        let op = install_op('a');
        let bytes = candidate(&op.implant, &op.bootfile, &nonce('a'));
        let mut failing = operation('a', None);
        // Crash early enough that no rollback happened yet; the WAL stays
        // Prepared with the candidate retained in the after sidecar.
        failing.failpoints.insert(Failpoint::Published);
        let lock = OperationLock::acquire(&root).unwrap();
        assert!(execute(&root, &mut mock, &failing, &bytes, None, 0o600, true).is_err());
        assert!(
            !restored_without_receipt(&root, &mut mock).unwrap(),
            "an unrecovered WAL may not be a waiver"
        );
        let result = restore(&root, &mut mock, &install_op('a'));
        drop(lock);
        assert!(result.is_err(), "not-yet-recovered state must refuse");
    }

    // 4. Negative: a foreign post-rollback change to the original config
    // invalidates the waiver; restore keeps the fail-closed refusal.
    {
        let original = b"<clsboot_root-orig>".to_vec();
        let (_t, root, mut mock, _bytes) = setup_crash_window(Some(original.clone()));
        mock.live = Some((b"<clsboot_root-foreign/>".to_vec(), 0o600));
        let lock = OperationLock::acquire(&root).unwrap();
        assert!(!restored_without_receipt(&root, &mut mock).unwrap());
        let result = restore(&root, &mut mock, &install_op('a'));
        drop(lock);
        assert!(result.is_err(), "a foreign live config may not restore");
    }
}

// F5 standard-chain regression: the production restore_config command is a
// thin wrapper over restore_standard — lock, recover_existing, restore. The
// waived crash window and every neighboring state must resolve identically
// when driven through that same orchestration, not by calling the underlying
// restore() helper directly.
#[test]
fn receiptless_crash_window_resolves_through_standard_restore_orchestration() {
    let crash_window = |seed_original: Option<Vec<u8>>| {
        let (_t, root) = store();
        seed_installation(&root);
        let mut mock = Mock::with(seed_original.clone().map(|b| (b, 0o600)));
        let op = install_op('a');
        let bytes = candidate(&op.implant, &op.bootfile, &nonce('a'));
        let mut failing = operation('a', None);
        failing.failpoints.insert(Failpoint::ReadonlyRestored);
        let lock = OperationLock::acquire(&root).unwrap();
        assert!(execute(&root, &mut mock, &failing, &bytes, None, 0o600, true).is_err());
        drop(lock);
        (_t, root, mock)
    };

    // Waived tail: the standard chain terminates successfully, live state and
    // the diagnostic journal are untouched.
    for original in [Some(b"<clsboot_root-orig>".to_vec()), None] {
        let (_t, root, mut mock) = crash_window(original.clone());
        restore_standard(&root, &mut mock, &txid('e'))
            .expect("the standard production chain must complete the waived rollback");
        assert_eq!(mock.live.clone().map(|(b, _)| b), original);
        assert!(root.exists(WAL_NAME).unwrap());
        assert!(root.exists(ORIGINAL_NAME).unwrap());
    }

    // Neighboring negative states keep the hard refusal through the same
    // standard chain and nothing is cleaned up.
    // (a) still-Prepared WAL: the old code failed here with the early
    // receipt refusal; the standard chain must fail through bounded recovery.
    {
        let (_t, root) = store();
        seed_installation(&root);
        let mut mock = Mock::with(Some((b"<clsboot_root-orig>".to_vec(), 0o600)));
        let op = install_op('a');
        let bytes = candidate(&op.implant, &op.bootfile, &nonce('a'));
        let mut failing = operation('a', None);
        failing.failpoints.insert(Failpoint::Published);
        let lock = OperationLock::acquire(&root).unwrap();
        assert!(execute(&root, &mut mock, &failing, &bytes, None, 0o600, true).is_err());
        drop(lock);
        // The WAL is still Prepared with the candidate live. The standard
        // chain first runs the bounded recovery — which rolls the config back
        // to the exact FIRST original and marks the WAL Applied — and then the
        // receipt-less waived branch terminates the command: the same
        // completed-recovery state a real crash window leaves. This is the
        // owner-criterion case where the OLD chain (early permit_ready refusal
        // before recovery) could never finish.
        restore_standard(&root, &mut mock, &txid('e'))
            .expect("recovered Prepared rollback must terminate through the standard chain");
        assert_eq!(
            mock.live.as_ref().map(|(b, _)| b.clone()),
            Some(b"<clsboot_root-orig>".to_vec()),
            "the candidate is rolled back to the FIRST original"
        );
        assert!(root.exists(WAL_NAME).unwrap(), "journal preserved");
    }
    // (b) a still-Preparing WAL (crash before any system mutation, sidecars
    // absent) demands bounded recovery and is never a waiver: hard refusal
    // through the standard chain with the journal preserved.
    {
        let (_t, root) = store();
        seed_installation(&root);
        let wal = Wal {
            schema_version: 1,
            transaction_id: nonce('a'),
            config_path: CONFIG_PATH.into(),
            delivery_nonce: nonce('a'),
            state: WalState::Preparing,
            restoring: false,
            first_original: Presence::of(true, 0o600).unwrap(),
            before: Presence::of(true, 0o600).unwrap(),
            after: Presence::of(true, 0o600).unwrap(),
        };
        root.write(WAL_NAME, &wal.bytes().unwrap(), 0o600).unwrap();
        let mut mock = Mock::default();
        let err = restore_standard(&root, &mut mock, &txid('e'))
            .map_err(|e| e.to_string())
            .unwrap_err();
        assert!(
            err.contains("Preparing"),
            "still-Preparing WAL must refuse through the standard chain, got: {err}"
        );
        assert!(root.exists(WAL_NAME).unwrap());
    }
    // (c) foreign post-rollback content invalidates the waiver even through
    // the standard chain.
    {
        let (_t, root, mut mock) = crash_window(Some(b"<clsboot_root-orig>".to_vec()));
        mock.live = Some((b"<clsboot_root-foreign/>".to_vec(), 0o600));
        let err = restore_standard(&root, &mut mock, &txid('e'))
            .map_err(|e| e.to_string())
            .unwrap_err();
        // Either refusal is correct: the foreign live config already stops the
        // bounded recovery (fail-closed before the receipt question), or the
        // receipt-less waiver check refuses it. Never a silent success, and
        // nothing is cleaned up either way.
        assert!(
            err.contains("no validated supervisor config receipt") || err.contains("foreign"),
            "got: {err}"
        );
        assert!(root.exists(WAL_NAME).unwrap());
    }
    // (d) untouched tree without any WAL: plain receipt-less refusal.
    {
        let (_t, root) = store();
        seed_installation(&root);
        let mut mock = Mock::with(Some((b"<clsboot_root>".to_vec(), 0o600)));
        let err = restore_standard(&root, &mut mock, &txid('e'))
            .map_err(|e| e.to_string())
            .unwrap_err();
        assert!(err.contains("no validated supervisor config receipt"));
    }
    // Sanity: a normal receipt-backed restore still succeeds through the
    // standard chain (the orchestration must not have broken it).
    {
        let (_t, root) = store();
        seed_installation(&root);
        let original = b"<clsboot_root-orig>".to_vec();
        let mut mock = Mock::with(Some((original.clone(), 0o600)));
        let op = install_op('a');
        let bytes = candidate(&op.implant, &op.bootfile, &nonce('a'));
        let lock = OperationLock::acquire(&root).unwrap();
        execute(&root, &mut mock, &op, &bytes, None, 0o600, true).unwrap();
        drop(lock);
        restore_standard(&root, &mut mock, &txid('e')).unwrap();
        assert_eq!(mock.live.as_ref().unwrap().0, original);
    }
}

#[test]
fn restore_crash_retry_converges_through_standard_chain() {
    let points = [
        Failpoint::WalPrepared,
        Failpoint::FenceWritten,
        Failpoint::RemountWritable,
        Failpoint::BeforeRecheck,
        Failpoint::Published,
        Failpoint::ReadonlyRestored,
        Failpoint::InstalledSidecarPersisted,
        Failpoint::ReceiptPersisted,
        Failpoint::FinalReadback,
    ];
    for original in [Some(b"<clsboot_root-orig>".to_vec()), None] {
        for point in points {
            let (_t, root) = store();
            seed_installation(&root);
            let mut mock = Mock::with(original.clone().map(|b| (b, 0o600)));
            let install = install_op('a');
            let bytes = candidate(&install.implant, &install.bootfile, &nonce('a'));
            {
                let _lock = OperationLock::acquire(&root).unwrap();
                execute(&root, &mut mock, &install, &bytes, None, 0o600, true).unwrap();
            }
            let mut failing = install_op('a');
            failing.failpoints.insert(point);
            {
                let _lock = OperationLock::acquire(&root).unwrap();
                assert!(restore(&root, &mut mock, &failing).is_err(), "{point:?}");
            }
            restore_standard(&root, &mut mock, &txid('e'))
                .unwrap_or_else(|e| panic!("original={} point={point:?}: {e}", original.is_some()));
            assert_eq!(
                mock.live.as_ref().map(|(b, _)| b.clone()),
                original,
                "{point:?}"
            );
            assert!(crate::install::supervisor_config_receipt(&root)
                .unwrap()
                .is_none());
            assert_eq!(
                root.read(INSTALLED_NAME, MAX_CONFIG + 16, 0o600).unwrap(),
                ABSENT_MARKER
            );
            assert_eq!(
                Wal::parse(&root.read(WAL_NAME, RECORD_MAX, 0o600).unwrap())
                    .unwrap()
                    .state,
                WalState::Applied
            );
            assert!(mock.readonly);
            restore_standard(&root, &mut mock, &txid('e')).unwrap();
        }
    }
}

#[test]
fn prepared_recovery_refuses_foreign_after_mode_without_writing() {
    let (_t, root) = store();
    seed_installation(&root);
    let mut mock = Mock::with(Some((b"<original/>".to_vec(), 0o600)));
    let mut op = install_op('a');
    op.failpoints.insert(Failpoint::Published);
    let bytes = candidate(&op.implant, &op.bootfile, &nonce('a'));
    {
        let _lock = OperationLock::acquire(&root).unwrap();
        assert!(execute(&root, &mut mock, &op, &bytes, None, 0o600, true).is_err());
    }
    mock.live.as_mut().unwrap().1 = 0o644;
    mock.calls.clear();
    assert!(restore_standard(&root, &mut mock, &txid('e')).is_err());
    assert_eq!(mock.live.as_ref().unwrap().0, bytes);
    assert_eq!(mock.live.as_ref().unwrap().1, 0o644);
    assert!(!mock.calls.contains(&"write"));
    assert!(!mock.calls.contains(&"unlink"));
}

#[test]
fn restore_recovery_rejects_foreign_authority_without_publishing_or_retiring() {
    for scenario in [
        "before-mode",
        "after-mode",
        "target",
        "missing-installed",
        "absent-installed-before",
        "nonce",
        "readonly",
    ] {
        let (_t, root) = store();
        seed_installation(&root);
        let original = b"<original/>".to_vec();
        let mut mock = Mock::with(Some((original.clone(), 0o600)));
        let install = install_op('a');
        let bytes = candidate(&install.implant, &install.bootfile, &nonce('a'));
        {
            let _lock = OperationLock::acquire(&root).unwrap();
            execute(&root, &mut mock, &install, &bytes, None, 0o600, true).unwrap();
        }
        let mut failing = install_op('a');
        failing.failpoints.insert(
            if scenario == "before-mode" || scenario == "absent-installed-before" {
                Failpoint::WalPrepared
            } else {
                Failpoint::ReadonlyRestored
            },
        );
        {
            let _lock = OperationLock::acquire(&root).unwrap();
            assert!(restore(&root, &mut mock, &failing).is_err());
        }
        match scenario {
            "before-mode" | "after-mode" => mock.live.as_mut().unwrap().1 = 0o644,
            "target" => root.write(AFTER_NAME, b"<foreign/>", 0o600).unwrap(),
            "missing-installed" => {
                std::fs::remove_file(format!("{}/{}", root.path, INSTALLED_NAME)).unwrap()
            }
            "absent-installed-before" => root.write(INSTALLED_NAME, ABSENT_MARKER, 0o600).unwrap(),
            "nonce" => {
                let mut receipt = crate::install::supervisor_config_receipt(&root)
                    .unwrap()
                    .unwrap();
                receipt.delivery_nonce = nonce('b');
                crate::install::persist_supervisor_config_receipt(&root, &receipt).unwrap();
            }
            "readonly" => mock.failures.push("verify-ro"),
            _ => unreachable!(),
        }
        let before_receipt = crate::install_layout::read_state(&root).unwrap();
        let live = mock.live.clone();
        mock.calls.clear();
        assert!(
            restore_standard(&root, &mut mock, &txid('e')).is_err(),
            "{scenario}"
        );
        assert_eq!(mock.live, live, "{scenario}");
        assert_eq!(
            crate::install_layout::read_state(&root).unwrap(),
            before_receipt,
            "{scenario}"
        );
        assert!(!mock.calls.contains(&"write"), "{scenario}");
        assert!(!mock.calls.contains(&"unlink"), "{scenario}");
        assert_ne!(
            Wal::parse(&root.read(WAL_NAME, RECORD_MAX, 0o600).unwrap())
                .unwrap()
                .state,
            WalState::Applied
        );
    }
}

#[test]
fn install_wal_without_direction_retains_exact_canonical_format() {
    let (_t, root) = store();
    seed_installation(&root);
    let mut mock = Mock::with(Some((b"<original/>".to_vec(), 0o600)));
    let op = install_op('a');
    let bytes = candidate(&op.implant, &op.bootfile, &nonce('a'));
    {
        let _lock = OperationLock::acquire(&root).unwrap();
        execute(&root, &mut mock, &op, &bytes, None, 0o600, true).unwrap();
    }
    let retained = root.read(WAL_NAME, RECORD_MAX, 0o600).unwrap();
    let mut wal = Wal::parse(&retained).unwrap();
    assert!(!String::from_utf8(retained.clone())
        .unwrap()
        .contains("restoring"));
    assert!(!wal.restoring);
    assert_eq!(wal.bytes().unwrap(), retained);
    wal.restoring = true;
    assert!(Wal::parse(&wal.bytes().unwrap()).unwrap().restoring);
}

#[test]
fn production_install_observation_accepts_absence_and_rejects_concurrent_changes() {
    for initial in [Some((b"<original/>".to_vec(), 0o600)), None] {
        let (_t, root) = store();
        seed_installation(&root);
        let mut mock = Mock::with(initial.clone());
        let source = mock.observe().unwrap();
        let op = install_op('a');
        let bytes = candidate(&op.implant, &op.bootfile, &nonce('a'));
        run_standard(
            &root,
            &mut mock,
            &op,
            &bytes,
            Some(&source),
            source.mode.max(0o600),
            true,
        )
        .unwrap_or_else(|e| panic!("production observed present={}: {e}", source.present));
        assert_eq!(mock.live.as_ref().unwrap().0, bytes);
        restore_standard(&root, &mut mock, &txid('e')).unwrap();
        assert_eq!(mock.live, initial);
    }
}

#[test]
fn production_install_observation_preserves_foreign_presence_mode_and_bytes() {
    let before = Some((b"<original/>".to_vec(), 0o600));
    for (initial, changed) in [
        (before.clone(), None),
        (None, before.clone()),
        (before.clone(), Some((b"<original/>".to_vec(), 0o644))),
        (before.clone(), Some((b"<foreign/>".to_vec(), 0o600))),
    ] {
        let (_t, root) = store();
        seed_installation(&root);
        let mut mock = Mock::with(initial);
        let source = mock.observe().unwrap();
        mock.live = changed.clone();
        mock.calls.clear();
        let op = install_op('a');
        let bytes = candidate(&op.implant, &op.bootfile, &nonce('a'));
        let err = run_standard(
            &root,
            &mut mock,
            &op,
            &bytes,
            Some(&source),
            source.mode.max(0o600),
            true,
        )
        .unwrap_err();
        assert!(err.contains("changed before transaction lock"));
        assert_eq!(mock.live, changed);
        assert!(!root.exists(WAL_NAME).unwrap());
        assert!(!mock.calls.contains(&"write"));
        assert!(!mock.calls.contains(&"unlink"));
    }
}
