//! Bounded desktop admission relay. Recovery mutations belong to init only.
use super::*;
use secure_fs::Directory;
#[cfg(target_os = "android")]
use std::time::Instant;

const REQUEST: &str = "restore-request.json";
const REPLY: &str = "restore-reply.json";
const TEMP: &str = ".restore-reply.tmp";
#[cfg(target_os = "android")]
const REPLY_CONTEXT: &str = "u:object_r:voboost_recovery_file:s0";
const MAX_REQUEST_BYTES: usize = 2048;
#[cfg(any(target_os = "android", test))]
const MAX_REPLY_BYTES: usize = 4096;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Request {
    schema_version: u32,
    nonce: String,
    boot_id: String,
    manifest_sha256: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Reply {
    request: Request,
    #[serde(skip_serializing_if = "Option::is_none")]
    transaction_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure: Option<serde_json::Value>,
}
#[cfg(any(target_os = "android", test))]
pub(super) enum Admission {
    Accepted,
    Rejected(Vec<u8>),
}
/// Tracks delivery independently of durable operation admission. A consumed
/// request is never replayed merely because its reply could not be delivered.
#[derive(Default)]
pub(super) struct ReplyTracking {
    published: bool,
}
impl ReplyTracking {
    pub(super) fn publish_with(
        &mut self,
        transaction: Option<&str>,
        error: Option<&str>,
        publish: impl FnOnce(Option<&str>, Option<&str>) -> Result<(), String>,
    ) -> Result<(), String> {
        publish(transaction, error)?;
        self.published = true;
        Ok(())
    }
    pub(super) fn finish_failure_with(
        &mut self,
        transaction: Option<&str>,
        error: &str,
        verify_admission: impl FnOnce(&str) -> Result<(), String>,
        publish: impl FnOnce(Option<&str>, Option<&str>) -> Result<(), String>,
    ) -> Result<(), String> {
        if self.published {
            return Ok(());
        }
        if let Some(transaction) = transaction {
            // Admission may have succeeded before a subsequent persist/sync
            // failed. Never turn that cut into a pre-transaction rejection.
            verify_admission(transaction)?;
            self.publish_with(Some(transaction), None, publish)
        } else {
            self.publish_with(None, Some(error), publish)
        }
    }
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn parse_request(bytes: &[u8], boot: &str, manifest: &str) -> Result<Request, String> {
    let request: Request =
        serde_json::from_slice(bytes).map_err(|e| format!("parse restore request: {e}"))?;
    if json(&request)? != bytes
        || request.schema_version != 1
        || !hash(&request.nonce)
        || request.boot_id != boot
        || request.manifest_sha256 != manifest
        || !hash(&request.manifest_sha256)
    {
        return Err(
            "restore request differs from the canonical current boot/catalog contract".into(),
        );
    }
    Ok(request)
}
fn directory(root: &Path, leaf: &str, mode: u32) -> Result<Directory, String> {
    let root = Directory::open(root).map_err(|e| format!("open restore relay root: {e}"))?;
    let dir = root
        .open_child(leaf)
        .map_err(|e| format!("open restore relay {leaf}: {e}"))?;
    dir.validate_owner_mode(unsafe { libc::geteuid() }, unsafe { libc::getegid() }, mode)
        .map_err(|e| format!("verify restore relay {leaf}: {e}"))?;
    Ok(dir)
}
fn reply_directory(root: &Path) -> Result<Directory, String> {
    directory(root, "run", 0o755)
}
fn manifest_digest() -> Result<String, String> {
    let (_, _, authority) = fixed_product_authority()?;
    Ok(digest(&authority[0]))
}
#[cfg(any(target_os = "android", test))]
fn read_reply(recovery: &Directory) -> std::io::Result<Vec<u8>> {
    #[cfg(target_os = "android")]
    {
        recovery
            .read_trusted_snapshot(REPLY, MAX_REPLY_BYTES, 0o600, REPLY_CONTEXT)
            .map(|s| s.bytes)
    }
    #[cfg(not(target_os = "android"))]
    recovery.read_trusted(REPLY, MAX_REPLY_BYTES, 0o600)
}
#[cfg(any(target_os = "android", test))]
fn decode_reply(
    bytes: &[u8],
    expected: &Request,
) -> Result<Option<(Admission, Option<String>)>, String> {
    let reply: Reply =
        serde_json::from_slice(bytes).map_err(|e| format!("parse restore admission reply: {e}"))?;
    if json(&reply)? != bytes {
        return Err("restore admission reply is not canonical".into());
    }
    if &reply.request != expected {
        return Ok(None);
    }
    match (reply.transaction_id, reply.failure) {
        (Some(transaction), None) if hash(&transaction) => {
            Ok(Some((Admission::Accepted, Some(transaction))))
        }
        (None, Some(failure)) => {
            let message = failure
                .get("error")
                .and_then(|v| v.get("message"))
                .and_then(serde_json::Value::as_str)
                .ok_or("restore reply lacks failure cause")?;
            let canonical = restore_pre_transaction_failure_bytes(message);
            let expected: serde_json::Value =
                serde_json::from_slice(&canonical).map_err(|e| e.to_string())?;
            if failure != expected {
                return Err("restore reply failure is outside admission contract".into());
            }
            Ok(Some((Admission::Rejected(canonical), None)))
        }
        _ => Err("restore reply must contain exactly one admission outcome".into()),
    }
}
#[cfg(target_os = "android")]
pub(super) fn relay() -> Result<Admission, String> {
    let run = directory(Path::new(PRODUCT_ROOT), "run", 0o755)?;
    // Producers serialize; the init service does not take this lock. It is
    // released as soon as admission is published, before any reboot.
    let _owner = run
        .lock_transaction(Duration::from_secs(3))
        .map_err(|e| format!("restore request producer is busy: {e}"))?;
    let boot = boot_id()?;
    let manifest = manifest_digest()?;
    let mut entropy = [0u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut entropy))
        .map_err(|e| format!("create restore request identity: {e}"))?;
    let request = Request {
        schema_version: 1,
        nonce: hex::encode(entropy),
        boot_id: boot,
        manifest_sha256: manifest,
    };
    run.write_atomic(REQUEST, &json(&request)?, 0o600)
        .and_then(|_| run.sync_all())
        .map_err(|e| format!("publish restore request: {e}"))?;
    fixed_process::set_property("ctl.start", "voboost-restore")?;
    // Admission replies are control-plane messages, not recovery transactions.
    // Keep their protected file label while leaving recovery strictly journal-only.
    let recovery = reply_directory(Path::new(PRODUCT_ROOT))?;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(30) {
        if boot_id()? != request.boot_id {
            return Err(
                "restore admission outcome unknown: boot changed before correlated reply".into(),
            );
        }
        match read_reply(&recovery) {
            Ok(bytes) => {
                if let Some((admission, transaction)) = decode_reply(&bytes, &request)? {
                    if let Some(transaction) = transaction {
                        let document =
                            operation_contract::read_document_in(Path::new(PRODUCT_ROOT))?
                                .ok_or("restore admission lost its operation authority")?;
                        if document.operation != Operation::Restore
                            || document.transaction_id != transaction
                        {
                            return Err(
                                "restore admission differs from the real operation authority"
                                    .into(),
                            );
                        }
                    }
                    return Ok(admission);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("read protected restore admission reply: {e}")),
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err("restore admission outcome unknown: correlated init reply deadline expired".into())
}
/// Invalid or unreadable requests cannot fall through into WAL continuation.
/// Only an absent request permits the separate noncreating continuation path.
pub(super) fn take() -> Result<Option<Request>, String> {
    take_in(Path::new(PRODUCT_ROOT), &boot_id()?, &manifest_digest()?)
}

fn take_in(root: &Path, boot: &str, manifest: &str) -> Result<Option<Request>, String> {
    let run = directory(root, "run", 0o755)?;
    let bytes = match run.read_trusted(REQUEST, MAX_REQUEST_BYTES, 0o600) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read restore request: {e}")),
    };
    let request = parse_request(&bytes, boot, manifest)?;
    // Consume before mutation; a restarted service cannot replay this request.
    run.unlink(REQUEST)
        .and_then(|_| run.sync_all())
        .map_err(|e| format!("consume restore request: {e}"))?;
    Ok(Some(request))
}
pub(super) fn publish(
    request: &Request,
    transaction: Option<&str>,
    error: Option<&str>,
) -> Result<(), String> {
    let reply = match (transaction, error) {
        (Some(transaction), None) if hash(transaction) => Reply {
            request: request.clone(),
            transaction_id: Some(transaction.into()),
            failure: None,
        },
        (None, Some(error)) => Reply {
            request: request.clone(),
            transaction_id: None,
            failure: Some(
                serde_json::from_slice(&restore_pre_transaction_failure_bytes(error))
                    .map_err(|e| e.to_string())?,
            ),
        },
        _ => return Err("invalid restore admission publication".into()),
    };
    // Admission replies are control-plane messages, not recovery transactions.
    // Keep their protected file label while leaving recovery strictly journal-only.
    let recovery = reply_directory(Path::new(PRODUCT_ROOT))?;
    write_reply(&recovery, &json(&reply)?)
}
fn write_reply(recovery: &Directory, bytes: &[u8]) -> Result<(), String> {
    #[cfg(target_os = "android")]
    let prepared = recovery.prepare_trusted_labeled(TEMP, bytes, 0o600, REPLY_CONTEXT);
    #[cfg(not(target_os = "android"))]
    let prepared = recovery.prepare_trusted(TEMP, bytes, 0o600);
    prepared
        .and_then(|_| recovery.replace(TEMP, REPLY))
        .and_then(|_| recovery.sync_all())
        .map_err(|e| format!("publish protected restore admission reply: {e}"))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Request {
        Request {
            schema_version: 1,
            nonce: "a".repeat(64),
            boot_id: "00000000-0000-0000-0000-000000000001".into(),
            manifest_sha256: "b".repeat(64),
        }
    }
    #[test]
    fn persist_failure_after_admission_publishes_exact_acceptance() {
        let mut reply = ReplyTracking::default();
        let tx = "c".repeat(64);
        reply
            .finish_failure_with(
                Some(&tx),
                "persist denied",
                |actual| {
                    assert_eq!(actual, tx);
                    Ok(())
                },
                |actual, error| {
                    assert_eq!(actual, Some(tx.as_str()));
                    assert_eq!(error, None);
                    Ok(())
                },
            )
            .unwrap();
        assert!(reply.published);
    }
    #[test]
    fn admitted_reply_failure_never_becomes_rejection_or_replays_mutation() {
        let mut reply = ReplyTracking::default();
        assert!(reply
            .publish_with(Some("tx"), None, |_, _| Err("write denied".into()))
            .is_err());
        assert!(!reply.published);
        assert_eq!(
            reply.finish_failure_with(
                Some("tx"),
                "write denied",
                |_| Ok(()),
                |tx, error| {
                    assert_eq!(tx, Some("tx"));
                    assert_eq!(error, None);
                    Err("still denied".into())
                }
            ),
            Err("still denied".into())
        );
        assert!(!reply.published);
        assert!(reply
            .finish_failure_with(
                Some("tx"),
                "failure",
                |_| Err("authority unavailable".into()),
                |_, _| panic!("no false reply")
            )
            .is_err());
    }
    #[test]
    fn pretransaction_reply_failure_is_explicit_and_does_not_mark_published() {
        let mut reply = ReplyTracking::default();
        assert_eq!(
            reply.finish_failure_with(
                None,
                "prepare denied",
                |_| panic!("not admitted"),
                |tx, error| {
                    assert_eq!(tx, None);
                    assert_eq!(error, Some("prepare denied"));
                    Err("reply denied".into())
                }
            ),
            Err("reply denied".into())
        );
        assert!(!reply.published);
        reply
            .finish_failure_with(
                None,
                "prepare denied",
                |_| panic!("not admitted"),
                |_, _| Ok(()),
            )
            .unwrap();
        reply
            .finish_failure_with(
                None,
                "later failure",
                |_| panic!("already delivered"),
                |_, _| panic!("no duplicate"),
            )
            .unwrap();
    }
    #[test]
    fn request_binds_boot_catalog_and_canonical_identity() {
        let r = request();
        assert!(parse_request(&json(&r).unwrap(), &r.boot_id, &r.manifest_sha256).is_ok());
        assert!(parse_request(&json(&r).unwrap(), "other-boot", &r.manifest_sha256).is_err());
        assert!(parse_request(&json(&r).unwrap(), &r.boot_id, &"c".repeat(64)).is_err());
        let mut invalid = r.clone();
        invalid.nonce = "caller-path".into();
        assert!(parse_request(&json(&invalid).unwrap(), &r.boot_id, &r.manifest_sha256).is_err());
        let mut bytes = json(&r).unwrap();
        bytes.push(b' ');
        assert!(parse_request(&bytes, &r.boot_id, &r.manifest_sha256).is_err());
    }
    #[test]
    fn reply_cannot_borrow_another_request_or_fabricate_failure_transaction() {
        let r = request();
        let mut reply = Reply {
            request: r.clone(),
            transaction_id: Some("c".repeat(64)),
            failure: None,
        };
        assert!(matches!(
            decode_reply(&json(&reply).unwrap(), &r).unwrap(),
            Some((Admission::Accepted, _))
        ));
        reply.request.nonce = "d".repeat(64);
        assert!(decode_reply(&json(&reply).unwrap(), &r).unwrap().is_none());
        reply.request = r.clone();
        reply.failure = Some(
            serde_json::from_slice(&restore_pre_transaction_failure_bytes(
                "exact stage path: denied",
            ))
            .unwrap(),
        );
        assert!(decode_reply(&json(&reply).unwrap(), &r).is_err());
        reply.transaction_id = None;
        let Some((Admission::Rejected(bytes), None)) =
            decode_reply(&json(&reply).unwrap(), &r).unwrap()
        else {
            panic!("failure required")
        };
        assert_eq!(
            bytes,
            restore_pre_transaction_failure_bytes("exact stage path: denied")
        );
    }
    #[test]
    fn reply_bound_accepts_full_unicode_failure_and_rejects_oversize() {
        let r = request();
        let message = "🚙".repeat(512);
        let reply = Reply {
            request: r.clone(),
            transaction_id: None,
            failure: Some(
                serde_json::from_slice(&restore_pre_transaction_failure_bytes(&message)).unwrap(),
            ),
        };
        let bytes = json(&reply).unwrap();
        let failure = reply.failure.as_ref().unwrap();
        let retained = failure["error"]["message"].as_str().unwrap();
        assert_eq!(retained.len(), 512);
        assert_eq!(retained.chars().count(), 128);
        assert!(bytes.len() <= MAX_REPLY_BYTES);
        let Some((Admission::Rejected(failure), None)) = decode_reply(&bytes, &r).unwrap() else {
            panic!("failure required")
        };
        assert_eq!(failure, restore_pre_transaction_failure_bytes(&message));
        assert!(decode_reply(&vec![b' '; MAX_REPLY_BYTES + 1], &r).is_err());
        assert!(parse_request(
            &vec![b' '; MAX_REQUEST_BYTES + 1],
            &r.boot_id,
            &r.manifest_sha256
        )
        .is_err());
    }
    #[test]
    fn producer_contract_uses_public_run_mode_and_serializes_callers() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir(root.path().join("run")).unwrap();
        fs::set_permissions(root.path().join("run"), fs::Permissions::from_mode(0o755)).unwrap();
        let first = directory(root.path(), "run", 0o755).unwrap();
        let owner = first.lock_transaction(Duration::ZERO).unwrap();
        let second = directory(root.path(), "run", 0o755).unwrap();
        assert!(second.lock_transaction(Duration::ZERO).is_err());
        drop(owner);
        assert!(second.lock_transaction(Duration::ZERO).is_ok());
        assert!(directory(root.path(), "run", 0o700).is_err());
    }
    #[test]
    fn consumer_is_single_use_and_stale_input_does_not_mutate_authority() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir(root.path().join("run")).unwrap();
        fs::set_permissions(root.path().join("run"), fs::Permissions::from_mode(0o755)).unwrap();
        let run = directory(root.path(), "run", 0o755).unwrap();
        let r = request();
        assert!(take_in(root.path(), &r.boot_id, &r.manifest_sha256)
            .unwrap()
            .is_none());
        run.write_atomic(REQUEST, &json(&r).unwrap(), 0o600)
            .unwrap();
        assert!(take_in(root.path(), "other-boot", &r.manifest_sha256).is_err());
        assert!(run.entry_exists(REQUEST).unwrap());
        assert!(!root.path().join("operation.json").exists());
        assert_eq!(
            take_in(root.path(), &r.boot_id, &r.manifest_sha256).unwrap(),
            Some(r.clone())
        );
        assert!(take_in(root.path(), &r.boot_id, &r.manifest_sha256)
            .unwrap()
            .is_none());
        assert!(!root.path().join("operation.json").exists());
    }
    #[test]
    fn request_input_rejects_link_and_relaxed_mode() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir(root.path().join("run")).unwrap();
        fs::set_permissions(root.path().join("run"), fs::Permissions::from_mode(0o755)).unwrap();
        let run = directory(root.path(), "run", 0o755).unwrap();
        let r = request();
        run.write_atomic(REQUEST, &json(&r).unwrap(), 0o644)
            .unwrap();
        assert!(take_in(root.path(), &r.boot_id, &r.manifest_sha256).is_err());
        fs::remove_file(root.path().join("run").join(REQUEST)).unwrap();
        std::os::unix::fs::symlink("outside", root.path().join("run").join(REQUEST)).unwrap();
        assert!(take_in(root.path(), &r.boot_id, &r.manifest_sha256).is_err());
    }
    #[test]
    fn protected_reply_never_occupies_recovery_transaction_namespace() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir(root.path().join("run")).unwrap();
        fs::set_permissions(root.path().join("run"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir(root.path().join("recovery")).unwrap();
        fs::set_permissions(
            root.path().join("recovery"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let reply = Reply {
            request: request(),
            transaction_id: None,
            failure: Some(serde_json::json!({"code": "rejected"})),
        };
        let bytes = json(&reply).unwrap();
        let run = reply_directory(root.path()).unwrap();
        write_reply(&run, &bytes).unwrap();
        assert_eq!(read_reply(&run).unwrap(), bytes);
        assert_eq!(
            fs::read_dir(root.path().join("recovery")).unwrap().count(),
            0
        );
        assert_eq!(
            fs::metadata(root.path().join("run").join(REPLY))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        fs::set_permissions(root.path().join("run"), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(reply_directory(root.path()).is_err());
    }
    #[test]
    fn protected_reply_preserves_file_boundary() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let recovery = Directory::open(root.path()).unwrap();
        let bytes = json(&Reply {
            request: request(),
            transaction_id: Some("e".repeat(64)),
            failure: None,
        })
        .unwrap();
        write_reply(&recovery, &bytes).unwrap();
        assert_eq!(read_reply(&recovery).unwrap(), bytes);
        fs::remove_file(root.path().join(REPLY)).unwrap();
        std::os::unix::fs::symlink("outside", root.path().join(REPLY)).unwrap();
        assert!(read_reply(&recovery).is_err());
    }
}
