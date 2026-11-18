use super::*;
use crate::secure_fs::Directory;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use voboost_contract::desired::{Config, Disposition, Field, Input};
const SOURCE: &str = "vehicle-drive-forced-ev";
const BOOT: &str = "11111111-1111-4111-8111-111111111111";
const NEXT_BOOT: &str = "22222222-2222-4222-8222-222222222222";
fn fixture() -> (tempfile::TempDir, std::path::PathBuf, Config) {
    let root = tempfile::Builder::new()
        .prefix(".owned-intent-test-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let path = root.path().join("agents.json");
    let config = Config::new("interface", BTreeMap::new()).unwrap();
    publish(&path, &config);
    (root, path, config)
}
fn publish(path: &Path, config: &Config) -> Vec<u8> {
    let bytes = serde_json::to_vec(config).unwrap();
    crate::secure_fs::write_atomic_private(path, &bytes, 0o600).unwrap();
    bytes
}
fn save(
    config: &mut Config,
    source: &str,
    choice: &str,
    boot: &str,
    pid: i32,
    request: u64,
) -> Disposition {
    config
        .save(
            boot,
            &Field::Option {
                agent: source.into(),
                key: KEY.into(),
            },
            &json!(choice),
            &Input {
                boot_id: boot.into(),
                endpoint_epoch: 1,
                request_id: request,
                injector_pid: pid,
                injector_starttime: 100,
            },
            &[],
        )
        .unwrap()
}
fn wal(root: &Path, source: &str, bytes: &[u8]) {
    let path = root.join("state");
    if !path.exists() {
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    Directory::open(&path)
        .unwrap()
        .write_atomic(&journal_name(source), bytes, 0o600)
        .unwrap();
}
fn pending(boot: &str, choice: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"schemaVersion":1,"bootId":boot,"captureNs":50,
        "pid":42,"requestId":1,"choice":choice,"pending":true}))
    .unwrap()
}
#[test]
fn receipt_binds_source_and_rejects_ambiguous_fields() {
    for source in SOURCES {
        let frame = receipt_frame(source, u64::MAX, u64::MAX, "off", "superseded").unwrap();
        assert_eq!(
            frame,
            format!("I|{source}|{}|{}|off|superseded\n", u64::MAX, u64::MAX)
        );
        assert!(frame.len() <= 192);
    }
    for source in ["", "settings", "vehicle-drive-forced-ev|other"] {
        assert!(!supports(source));
        assert!(receipt_frame(source, 1, 1, "on", "committed").is_none());
    }
    assert!(receipt_frame(SOURCE, 0, 1, "on", "committed").is_none());
    assert!(receipt_frame(SOURCE, 1, 0, "on", "committed").is_none());
    assert!(receipt_frame(SOURCE, 1, 1, "observe", "committed").is_none());
    assert!(receipt_frame(SOURCE, 1, 1, "on", "applied").is_none());
}
#[test]
fn sources_keep_independent_owner_stamps_without_wal_ordering() {
    let (root, path, mut config) = fixture();
    assert_eq!(
        save(&mut config, SOURCE, "off", BOOT, 42, 900),
        Disposition::Saved
    );
    assert_eq!(
        save(&mut config, SOURCES[1], "on", BOOT, 42, 1),
        Disposition::Saved
    );
    assert_eq!(
        save(&mut config, SOURCE, "on", BOOT, 42, 899),
        Disposition::Superseded
    );
    let saved = publish(&path, &config);
    recover(&path).unwrap();
    assert_eq!(fs::read(&path).unwrap(), saved);
    assert_eq!(config.user_revision, 2);
    assert_eq!(config.agents[SOURCE].options[KEY], "off");
    assert_eq!(config.agents[SOURCES[1]].options[KEY], "on");
    assert!(!root.path().join("state").exists());
}
#[test]
fn owner_order_survives_cache_loss_and_rejects_old_same_origin_on() {
    let (_root, path, mut config) = fixture();
    save(&mut config, SOURCE, "on", BOOT, 42, 1);
    save(&mut config, SOURCE, "off", BOOT, 42, 2);
    let saved = publish(&path, &config);
    let mut restarted = Config::decode(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        save(&mut restarted, SOURCE, "on", BOOT, 42, 1),
        Disposition::Superseded
    );
    assert_eq!(serde_json::to_vec(&restarted).unwrap(), saved);
    recover(&path).unwrap();
    assert_eq!(fs::read(&path).unwrap(), saved);
}
#[test]
fn previous_boot_pending_input_never_creates_current_boot_user_authority() {
    for boot in [BOOT, NEXT_BOOT] {
        let (root, path, mut config) = fixture();
        let old = pending(boot, "on");
        wal(root.path(), SOURCE, &old);
        let original = fs::read(&path).unwrap();
        for _ in 0..2 {
            assert!(recover(&path).is_err());
            assert_eq!(fs::read(&path).unwrap(), original);
        }
        assert_eq!(
            save(&mut config, SOURCE, "off", NEXT_BOOT, 43, 1),
            Disposition::Saved
        );
        let saved = publish(&path, &config);
        recover(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), saved);
        assert_eq!(
            fs::read(root.path().join("state").join(journal_name(SOURCE))).unwrap(),
            old
        );
    }
}
#[test]
fn malformed_auxiliary_wal_cannot_replace_or_override_saved_authority() {
    for bytes in [b"{invalid".as_slice(), b"null", b"{}"] {
        let (root, path, mut config) = fixture();
        wal(root.path(), SOURCE, bytes);
        let original = fs::read(&path).unwrap();
        assert!(recover(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        save(&mut config, SOURCE, "off", BOOT, 42, 1);
        let saved = publish(&path, &config);
        recover(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), saved);
        assert_eq!(
            fs::read(root.path().join("state").join(journal_name(SOURCE))).unwrap(),
            bytes
        );
    }
}
#[test]
fn crash_recovery_does_not_replay_before_or_after_saved_publication() {
    let (root, path, mut config) = fixture();
    let old = pending(BOOT, "on");
    wal(root.path(), SOURCE, &old);
    let original = fs::read(&path).unwrap();
    let guard = crate::operation_contract::GenerationGuard::acquire_in(root.path()).unwrap();
    assert!(recover(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    drop(guard);
    assert!(recover(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    save(&mut config, SOURCE, "off", BOOT, 42, 2);
    let saved = publish(&path, &config);
    for _ in 0..2 {
        recover(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), saved);
    }
    assert_eq!(Config::decode(&saved).unwrap().user_revision, 1);
    assert_eq!(
        fs::read(root.path().join("state").join(journal_name(SOURCE))).unwrap(),
        old
    );
}
