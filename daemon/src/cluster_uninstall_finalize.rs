//! Android-root delivery of the already authorized native uninstall transaction.
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;
use std::time::Duration;
use voboost_contract::cluster::{Request, RequestKind};
use voboost_contract::domain_catalog::Domain;
use voboost_contract::domain_core::domain_operation::{
    AuthenticatedReport, InstalledEvidence, Operation, Outcome, Phase,
};

#[path = "cluster_uninstall_transport.rs"]
mod transport;
type Result<T> = std::result::Result<T, String>;
const STARTUP: &str = "c26b4913707a1e96933f48a07d6957857cc52853a7e405eb29b2adab9b84f47a";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Authority {
    schema_version: u32,
    state: String,
    request: Request,
    qnx_public_key: String,
    pair_id: String,
    authority_epoch: String,
    release_manifest_sha256: String,
    catalog_sha256: String,
    android_public_key: String,
    signed_request_hex: String,
}
impl Authority {
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 65536 {
            return Err("Cluster removal authority exceeds bound".into());
        }
        let value: Self =
            serde_json::from_slice(bytes).map_err(|e| format!("Cluster removal authority: {e}"))?;
        value.request.validate()?;
        if value.schema_version != 1
            || value.state != "restored"
            || value.request.kind != RequestKind::Uninstall
            || value.request.pair_id != value.pair_id
            || value.request.authority_epoch != value.authority_epoch
            || value.request.catalog_sha256 != value.catalog_sha256
            || value.request.release_manifest_sha256.as_deref()
                != Some(&value.release_manifest_sha256)
        {
            return Err("Cluster removal lacks correlated restored authority".into());
        }
        let android_key = Self::decode_key(&value.android_public_key)?;
        let signed = hex::decode(&value.signed_request_hex)
            .map_err(|_| "Cluster removal signed request encoding")?;
        let request = Request::verify(&signed, &android_key)?;
        if voboost_contract::domain_core::ascii_json(&request)?
            != voboost_contract::domain_core::ascii_json(&value.request)?
        {
            return Err("Cluster removal signed request differs".into());
        }
        value.key()?;
        Ok(value)
    }
    fn key(&self) -> Result<ed25519_dalek::VerifyingKey> {
        Self::decode_key(&self.qnx_public_key)
    }
    fn decode_key(encoded: &str) -> Result<ed25519_dalek::VerifyingKey> {
        let key: [u8; 32] = hex::decode(encoded)
            .map_err(|_| "Cluster removal key encoding")?
            .try_into()
            .map_err(|_| "Cluster removal key length")?;
        ed25519_dalek::VerifyingKey::from_bytes(&key)
            .map_err(|_| "Cluster removal key invalid".into())
    }
    fn verify(&self, bytes: &[u8]) -> Result<()> {
        let receipt = AuthenticatedReport::verify(
            bytes,
            &self.key()?,
            &self.pair_id,
            &self.authority_epoch,
            &self.request.challenge,
            &self.request.transaction_id,
            &self.release_manifest_sha256,
        )?;
        let report = receipt.report;
        if report.domain != Domain::Cluster
            || report.operation != Operation::Uninstall
            || report.phase != Phase::Complete
            || report.outcome != Outcome::Completed
            || report.catalog_sha256 != self.catalog_sha256
        {
            return Err("Cluster finalizer signed report is unrelated".into());
        }
        match report.installed_evidence {
            Some(InstalledEvidence::QnxAbsence { startup, .. })
                if startup.path == "/scripts/startup_cluster.sh"
                    && startup.original_sha256 == STARTUP
                    && startup.restored_sha256 == STARTUP =>
            {
                Ok(())
            }
            _ => Err("Cluster finalizer lacks exact signed absence".into()),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Input<'a> {
    schema_version: u32,
    bootfile: &'a str,
    transaction_id: &'a str,
    challenge: &'a str,
    receipt_file: &'a str,
}

fn verified_helper(product_sha256: &str) -> Result<Vec<u8>> {
    let manifest = crate::installed_product::load_manifest()?;
    if manifest.digest()? != product_sha256 {
        return Err("Cluster finalizer product changed".into());
    }
    let artifact = manifest.artifact("voboost-cluster-daemon")?;
    if artifact.role != voboost_contract::release::ArtifactRole::QnxDaemon
        || artifact.size == 0
        || artifact.size > crate::config::MAX_NATIVE_EXECUTABLE_BYTES as u64
    {
        return Err("Cluster finalizer role/size differs".into());
    }
    let root = crate::secure_fs::Directory::open(Path::new(crate::config::ROOT_ZONE))
        .map_err(|e| e.to_string())?;
    let mut descriptor = root
        .open_trusted_file(&artifact.file, artifact.size, 0o700)
        .map_err(|e| e.to_string())?;
    let mut bytes = Vec::with_capacity(artifact.size as usize);
    descriptor
        .by_ref()
        .take(artifact.size + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    verify_helper(&bytes, artifact.size, &artifact.sha256)?;
    Ok(bytes)
}
fn verify_helper(bytes: &[u8], size: u64, digest: &str) -> Result<()> {
    if bytes.len() as u64 != size
        || crate::trust::sha256_bytes(bytes) != digest
        || !crate::native_binary::verify_appended_signature(
            crate::native_executable_signature::NativeExecutableRole::Daemon,
            bytes,
        )
    {
        return Err("Cluster finalizer installed helper identity/signature differs".into());
    }
    Ok(())
}

trait Remote {
    fn absent(&self, path: &str) -> Result<bool>;
    fn read(&self, path: &str, maximum: usize) -> Result<Vec<u8>>;
    fn upload(&self, path: &str, bytes: &[u8], mode: u32) -> Result<()>;
    fn rename(&self, from: &str, to: &str) -> Result<()>;
    fn receipt(&self, executable: &str, argv: &[&str]) -> Result<Vec<u8>>;
    fn reboot(&self) -> Result<()>;
    fn wait(&self) -> Result<()>;
}
impl Remote for transport::Transport {
    fn absent(&self, path: &str) -> Result<bool> {
        self.absent(path)
    }
    fn read(&self, path: &str, maximum: usize) -> Result<Vec<u8>> {
        self.read(path, maximum)
    }
    fn upload(&self, path: &str, bytes: &[u8], mode: u32) -> Result<()> {
        self.upload(path, bytes, mode)
    }
    fn rename(&self, from: &str, to: &str) -> Result<()> {
        self.rename(from, to)
    }
    fn receipt(&self, executable: &str, argv: &[&str]) -> Result<Vec<u8>> {
        self.receipt(executable, argv)
    }
    fn reboot(&self) -> Result<()> {
        self.reboot()
    }
    fn wait(&self) -> Result<()> {
        std::thread::sleep(self.remaining()?.min(Duration::from_millis(200)));
        self.remaining().map(|_| ())
    }
}

fn publish_atomic(remote: &impl Remote, path: &str, bytes: &[u8], mode: u32) -> Result<()> {
    // The single transaction worker owns this private stage. Never reuse an
    // interrupted attempt or overwrite different canonical bytes.
    match remote.read(path, bytes.len()) {
        Ok(existing) if existing == bytes => return Ok(()),
        Ok(_) => return Err("Cluster finalizer canonical stage differs".into()),
        Err(_) if remote.absent(path)? => (),
        Err(_) => return Err("Cluster finalizer canonical path exists but cannot be read".into()),
    }
    let mut nonce = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut nonce))
        .map_err(|e| format!("Cluster finalizer stage entropy: {e}"))?;
    let temporary = format!("{path}.attempt-{}", hex::encode(nonce));
    remote.upload(&temporary, bytes, mode)?;
    let observed = remote.read(&temporary, bytes.len())?;
    if observed.len() != bytes.len()
        || crate::trust::sha256_bytes(&observed) != crate::trust::sha256_bytes(bytes)
        || observed != bytes
    {
        return Err("Cluster finalizer attempt readback differs".into());
    }
    match remote.read(path, bytes.len()) {
        Ok(existing) if existing == bytes => return Ok(()),
        Ok(_) => return Err("Cluster finalizer canonical stage changed".into()),
        Err(_) if remote.absent(path)? => (),
        Err(_) => return Err("Cluster finalizer canonical path became unreadable".into()),
    }
    remote.rename(&temporary, path)?;
    if remote.read(path, bytes.len())? != bytes {
        return Err("Cluster finalizer published readback differs".into());
    }
    Ok(())
}

fn exact_json(bytes: &[u8], expected: serde_json::Value) -> Result<()> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| "Cluster finalizer acknowledgement invalid")?;
    if value != expected {
        return Err("Cluster finalizer acknowledgement differs".into());
    }
    Ok(())
}

fn deliver_with_journal(
    remote: &impl Remote,
    authority: &Authority,
    helper_bytes: &[u8],
    progress: impl Fn(&str),
    retained: Option<&[u8]>,
    retain: impl Fn(&[u8]) -> Result<()>,
) -> Result<Vec<u8>> {
    let tx = &authority.request.transaction_id;
    let directory = format!("/var/voboost-finalize-{tx}");
    let helper = format!("{directory}/helper");
    let input = format!("{directory}/input.json");
    let receipt = format!("{directory}/receipt.bin");
    if let Some(bytes) = retained {
        authority.verify(bytes)?;
        // A prior verified receipt does not prove stage cleanup. Both exact
        // roots must independently return remote ENOENT, never generic error.
        if remote.absent("/var/voboost")? && remote.absent(&directory)? {
            progress("cluster-remove-cleanup-observed");
            return Ok(bytes.to_vec());
        }
    }
    let input_bytes = voboost_contract::domain_core::ascii_json(&Input {
        schema_version: 1,
        bootfile: "/var/voboost/boot.json",
        transaction_id: tx,
        challenge: &authority.request.challenge,
        receipt_file: &receipt,
    })?;
    // Existing exact stage is authoritative on retry, including after managed root purge.
    // Never overwrite a different stage or infer completion from missing files.
    let resumed = match remote.read(&input, input_bytes.len()) {
        Ok(bytes) if bytes == input_bytes => true,
        Ok(_) => return Err("Cluster finalizer retained input differs".into()),
        Err(_) => {
            progress("cluster-remove-stage");
            let executable = "/var/voboost/bin/voboost-cluster-daemon";
            exact_json(
                &remote.receipt(executable, &[executable, "prepare-remove", tx])?,
                serde_json::json!({"schemaVersion":1,"directory":directory}),
            )?;
            // Helper first: a partial stage cannot be mistaken for a complete retry.
            match remote.read(&helper, helper_bytes.len()) {
                Ok(bytes) if bytes == helper_bytes => (),
                Ok(_) => return Err("Cluster finalizer retained helper differs".into()),
                Err(_) => publish_atomic(remote, &helper, helper_bytes, 0o700)?,
            }
            publish_atomic(remote, &input, &input_bytes, 0o600)?;
            false
        }
    };
    if remote.read(&helper, helper_bytes.len())? != helper_bytes {
        return Err("Cluster finalizer staged helper changed".into());
    }
    // On a resumed new boot this can finish immediately without another reboot.
    let first = if resumed {
        Some(remote.receipt(&helper, &[&helper, "uninstall", &input])?)
    } else {
        None
    };
    let bytes = match first {
        Some(bytes) if !native_not_ready(&bytes) => {
            authority.verify(&bytes)?;
            bytes
        }
        _ => {
            progress("cluster-remove-reboot");
            remote.reboot()?;
            progress("cluster-remove-new-boot");
            loop {
                remote.wait()?;
                if let Ok(bytes) = remote.receipt(&helper, &[&helper, "uninstall", &input]) {
                    if !native_not_ready(&bytes) {
                        authority.verify(&bytes)?;
                        break bytes;
                    }
                }
            }
        }
    };
    authority.verify(&bytes)?;
    retain(&bytes)?;
    progress("cluster-remove-final-cleanup");
    let acknowledged = remote
        .receipt(&helper, &[&helper, "finish-remove", tx])
        .and_then(|ack| {
            exact_json(
                &ack,
                serde_json::json!({"schemaVersion":1,"transactionId":tx,"stageAbsent":true}),
            )
        });
    if let Err(error) = acknowledged {
        // The verified receipt was durably retained before cleanup. A lost
        // reply can be resolved by a new independent observation, not by
        // treating EOF or arbitrary remote errors as an acknowledgement.
        if !(remote.absent("/var/voboost")? && remote.absent(&directory)?) {
            return Err(error);
        }
        progress("cluster-remove-cleanup-observed");
    }
    Ok(bytes)
}

fn native_not_ready(bytes: &[u8]) -> bool {
    // qconn EOF does not carry a POSIX exit status. These bytes are never evidence.
    const CLEAN: &str =
        "native uninstall requires independent new kernel boot and absent old RAM identity";
    const SUPERVISOR: &str =
        "native uninstall requires independent new kernel boot after legacy supervisor restoration";
    if let Some(reason) =
        bytes.strip_prefix(b"Voboost native operation failed; no completion claimed: ")
    {
        return std::str::from_utf8(reason).is_ok_and(|reason| {
            matches!(reason.trim_end_matches(['\r', '\n']), CLEAN | SUPERVISOR)
        });
    }
    if bytes.len() > 4096 {
        return false;
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return false;
    };
    value["schemaVersion"] == 1
        && value["sequence"]
            .as_u64()
            .is_some_and(|sequence| sequence > 0)
        && value["timestamp"]
            .as_str()
            .is_some_and(|timestamp| !timestamp.is_empty())
        && value["source"]["kind"] == "qnx"
        && value["source"]["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("native:"))
        && value["component"] == "native-entry"
        && value["level"] == "error"
        && value["fields"]
            .as_object()
            .is_some_and(|fields| fields.is_empty())
        && matches!(value["message"].as_str(), Some(CLEAN | SUPERVISOR))
}

pub(crate) fn run(export: &[u8], progress: impl Fn(&str)) -> Result<Vec<u8>> {
    let authority = Authority::parse(export)?;
    let helper = verified_helper(&authority.release_manifest_sha256)?;
    let remote = transport::Transport::new(Duration::from_secs(180));
    loop {
        let retained = retry_local_receipt(
            super::uninstall_bridge::read_provisional_production,
            std::thread::sleep,
        )?;
        match deliver_with_journal(
            &remote,
            &authority,
            &helper,
            &progress,
            retained.as_deref(),
            |bytes| {
                retry_local_receipt(
                    || super::uninstall_bridge::retain_provisional_production(bytes),
                    std::thread::sleep,
                )
            },
        ) {
            Err(error) if error.starts_with("Cluster qconn connect:") => remote.wait()?,
            result => return result,
        }
    }
}

// Retry only contention on our local receipt journal. Remote operations and
// signature/ownership failures are never replayed by this policy.
fn retry_local_receipt<T>(
    mut operation: impl FnMut() -> Result<T>,
    mut pause: impl FnMut(Duration),
) -> Result<T> {
    for delay in [50, 100, 200, 400, 800, 800, 800, 800] {
        match operation() {
            Err(error) if error == "directory transaction lock deadline" => {
                pause(Duration::from_millis(delay));
            }
            result => return result,
        }
    }
    operation()
}

#[cfg(test)]
fn deliver(
    remote: &impl Remote,
    authority: &Authority,
    helper: &[u8],
    progress: impl Fn(&str),
) -> Result<Vec<u8>> {
    deliver_with_journal(remote, authority, helper, progress, None, |_| Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::{BTreeMap, VecDeque};

    #[test]
    fn local_receipt_contention_recovers_without_replaying_remote_work() {
        let mut attempts = 0;
        let mut waits = Vec::new();
        let receipt = retry_local_receipt(
            || {
                attempts += 1;
                if attempts < 3 {
                    Err("directory transaction lock deadline".into())
                } else {
                    Ok(b"retained authenticated receipt".to_vec())
                }
            },
            |delay| waits.push(delay),
        )
        .unwrap();
        assert_eq!(attempts, 3);
        assert_eq!(receipt, b"retained authenticated receipt");
        assert_eq!(
            waits,
            [Duration::from_millis(50), Duration::from_millis(100)]
        );
    }

    #[test]
    fn local_receipt_retry_is_bounded_and_rejects_authority_failures_immediately() {
        for reason in [
            "directory transaction lock deadline",
            "provisional receipt lost pairing",
        ] {
            let mut attempts = 0;
            let mut waits = 0;
            let result: Result<()> = retry_local_receipt(
                || {
                    attempts += 1;
                    Err(reason.into())
                },
                |_| waits += 1,
            );
            assert_eq!(result.unwrap_err(), reason);
            assert_eq!(
                (attempts, waits),
                if reason == "directory transaction lock deadline" {
                    (9, 8)
                } else {
                    (1, 0)
                }
            );
        }
    }

    fn fixture() -> (Authority, Vec<u8>) {
        use voboost_contract::domain_core::domain_operation::{
            AbsenceChecks, AbsenceStartup, DomainOperationReport,
        };
        let key = ed25519_dalek::SigningKey::from_bytes(&[74; 32]);
        let d = "a".repeat(64);
        let request: Request = serde_json::from_value(serde_json::json!({
            "schemaVersion":1,"kind":"uninstall","domain":"cluster","pairId":d,
            "authorityEpoch":d,"transactionId":d,"challenge":d,"catalogSha256":d,
            "closureSha256":d,"releaseManifestSha256":d,"desiredRevision":0,"desiredSha256":d
        }))
        .unwrap();
        let signed_request_hex = hex::encode(request.sign(&key).unwrap());
        let authority = Authority {
            schema_version: 1,
            state: "restored".into(),
            request,
            qnx_public_key: hex::encode(key.verifying_key().as_bytes()),
            pair_id: d.clone(),
            authority_epoch: d.clone(),
            release_manifest_sha256: d.clone(),
            catalog_sha256: d.clone(),
            android_public_key: hex::encode(key.verifying_key().as_bytes()),
            signed_request_hex,
        };
        let report = AuthenticatedReport {
            schema_version: 1,
            pair_id: d.clone(),
            authority_epoch: d.clone(),
            challenge: d.clone(),
            report: DomainOperationReport {
                schema_version: 2,
                domain: Domain::Cluster,
                operation: Operation::Uninstall,
                phase: Phase::Complete,
                outcome: Outcome::Completed,
                transaction_id: d.clone(),
                release_manifest_sha256: d.clone(),
                catalog_sha256: d.clone(),
                generation_id: None,
                desired_revision: 0,
                desired_sha256: d.clone(),
                boot_id: Some("new-kernel".into()),
                daemon_epoch: Some(d.clone()),
                installed_evidence: Some(InstalledEvidence::QnxAbsence {
                    startup: AbsenceStartup {
                        path: "/scripts/startup_cluster.sh".into(),
                        original_sha256: STARTUP.into(),
                        restored_sha256: STARTUP.into(),
                    },
                    checks: AbsenceChecks {
                        daemon_process_absent: true,
                        autostart_removed: true,
                        native_payload_absent: true,
                        persistent_state_absent: true,
                    },
                    proof_sha256: d,
                }),
            },
        };
        (authority, report.sign(&key).unwrap())
    }
    struct Fake {
        files: RefCell<BTreeMap<String, Vec<u8>>>,
        replies: RefCell<VecDeque<Result<Vec<u8>>>>,
        calls: RefCell<Vec<String>>,
        expired: bool,
        fail_write: std::cell::Cell<bool>,
        fail_absence: std::cell::Cell<bool>,
        fail_read: std::cell::Cell<bool>,
    }
    impl Remote for Fake {
        fn absent(&self, path: &str) -> Result<bool> {
            if self.fail_absence.get() {
                return Err("qconn EOF is not ENOENT".into());
            }
            Ok(!self
                .files
                .borrow()
                .keys()
                .any(|name| name == path || name.starts_with(&format!("{path}/"))))
        }
        fn read(&self, path: &str, _maximum: usize) -> Result<Vec<u8>> {
            if self.fail_read.get() {
                return Err("invalid mode or oversized file".into());
            }
            self.files
                .borrow()
                .get(path)
                .cloned()
                .ok_or("absent".into())
        }
        fn upload(&self, path: &str, bytes: &[u8], _mode: u32) -> Result<()> {
            if self.fail_write.replace(false) {
                self.files
                    .borrow_mut()
                    .insert(path.into(), bytes[..bytes.len() / 2].to_vec());
                return Err("network interrupted mid-write".into());
            }
            self.files.borrow_mut().insert(path.into(), bytes.into());
            Ok(())
        }
        fn rename(&self, from: &str, to: &str) -> Result<()> {
            let mut files = self.files.borrow_mut();
            let bytes = files.remove(from).ok_or("temporary missing")?;
            files.insert(to.into(), bytes);
            Ok(())
        }
        fn receipt(&self, _executable: &str, argv: &[&str]) -> Result<Vec<u8>> {
            self.calls.borrow_mut().push(argv[1].into());
            self.replies
                .borrow_mut()
                .pop_front()
                .unwrap_or(Err("EOF".into()))
        }
        fn reboot(&self) -> Result<()> {
            self.calls.borrow_mut().push("reboot".into());
            Ok(())
        }
        fn wait(&self) -> Result<()> {
            if self.expired {
                Err("deadline".into())
            } else {
                Ok(())
            }
        }
    }
    fn staged(authority: &Authority, replies: Vec<Result<Vec<u8>>>) -> Fake {
        let directory = format!("/var/voboost-finalize-{}", authority.request.transaction_id);
        let receipt = format!("{directory}/receipt.bin");
        let input = voboost_contract::domain_core::ascii_json(&Input {
            schema_version: 1,
            bootfile: "/var/voboost/boot.json",
            transaction_id: &authority.request.transaction_id,
            challenge: &authority.request.challenge,
            receipt_file: &receipt,
        })
        .unwrap();
        Fake {
            files: RefCell::new(BTreeMap::from([
                (format!("{directory}/input.json"), input),
                (format!("{directory}/helper"), b"helper".to_vec()),
            ])),
            replies: RefCell::new(replies.into()),
            calls: RefCell::new(Vec::new()),
            expired: false,
            fail_write: std::cell::Cell::new(false),
            fail_absence: std::cell::Cell::new(false),
            fail_read: std::cell::Cell::new(false),
        }
    }
    #[test]
    fn interrupted_publish_leaves_only_temporary_and_retry_publishes_complete() {
        let (authority, _) = fixture();
        for (path, mode) in [
            ("/var/voboost-finalize-test/helper", 0o700),
            ("/var/voboost-finalize-test/input.json", 0o600),
        ] {
            let remote = staged(&authority, vec![]);
            remote.fail_write.set(true);
            assert!(publish_atomic(&remote, path, b"complete bytes", mode).is_err());
            assert!(!remote.files.borrow().contains_key(path));
            let first_attempt = remote
                .files
                .borrow()
                .keys()
                .find(|name| name.starts_with(&format!("{path}.attempt-")))
                .unwrap()
                .clone();
            publish_atomic(&remote, path, b"complete bytes", mode).unwrap();
            assert_eq!(remote.files.borrow().get(path).unwrap(), b"complete bytes");
            assert!(remote.files.borrow().contains_key(&first_attempt));
        }
    }
    #[test]
    fn atomic_publish_never_overwrites_different_canonical_file() {
        let (authority, _) = fixture();
        let remote = staged(&authority, vec![]);
        let path = "/var/voboost-finalize-test/helper";
        remote
            .files
            .borrow_mut()
            .insert(path.into(), b"foreign valid file".to_vec());
        assert!(publish_atomic(&remote, path, b"complete bytes", 0o700).is_err());
        assert_eq!(
            remote.files.borrow().get(path).unwrap(),
            b"foreign valid file"
        );
    }
    #[test]
    fn unreadable_canonical_is_never_treated_as_absent_or_overwritten() {
        let (authority, _) = fixture();
        let remote = staged(&authority, vec![]);
        let path = "/var/voboost-finalize-test/helper";
        remote
            .files
            .borrow_mut()
            .insert(path.into(), b"foreign oversized bytes".to_vec());
        remote.fail_read.set(true);
        assert!(publish_atomic(&remote, path, b"new", 0o700).is_err());
        assert_eq!(
            remote.files.borrow().get(path).unwrap(),
            b"foreign oversized bytes"
        );
        remote.fail_absence.set(true);
        assert!(publish_atomic(&remote, path, b"new", 0o700).is_err());
        assert_eq!(
            remote.files.borrow().get(path).unwrap(),
            b"foreign oversized bytes"
        );
    }
    #[test]
    fn malformed_authority_and_modified_helper_are_rejected() {
        assert!(Authority::parse(b"{}").is_err());
        assert!(verify_helper(b"modified", 8, &crate::trust::sha256_bytes(b"modified")).is_err());
        assert!(verify_helper(b"modified", 9, &crate::trust::sha256_bytes(b"modified")).is_err());
    }
    #[test]
    fn finalizer_admits_only_the_exact_signed_android_request() {
        let (authority, _) = fixture();
        let mut export = serde_json::json!({
            "schemaVersion":1,"state":"restored","request":authority.request,
            "qnxPublicKey":authority.qnx_public_key,"pairId":authority.pair_id,
            "authorityEpoch":authority.authority_epoch,
            "releaseManifestSha256":authority.release_manifest_sha256,
            "catalogSha256":authority.catalog_sha256,
            "androidPublicKey":authority.android_public_key,
            "signedRequestHex":authority.signed_request_hex
        });
        assert!(Authority::parse(&serde_json::to_vec(&export).unwrap()).is_ok());
        export["request"]["challenge"] = serde_json::json!("b".repeat(64));
        assert!(Authority::parse(&serde_json::to_vec(&export).unwrap()).is_err());
    }
    #[test]
    fn stage_ack_must_be_exact_and_complete() {
        let expected =
            serde_json::json!({"schemaVersion":1,"transactionId":"a","stageAbsent":true});
        assert!(exact_json(
            br#"{"schemaVersion":1,"transactionId":"a","stageAbsent":false}"#,
            expected.clone()
        )
        .is_err());
        assert!(exact_json(b"", expected.clone()).is_err());
        assert!(exact_json(
            br#"{"schemaVersion":1,"transactionId":"a","stageAbsent":true,"extra":1}"#,
            expected.clone()
        )
        .is_err());
        assert!(exact_json(
            br#"{"schemaVersion":1,"transactionId":"a","stageAbsent":true}"#,
            expected
        )
        .is_ok());
    }
    #[test]
    fn retained_stage_resumes_after_managed_root_is_gone_without_reboot() {
        let (authority, receipt) = fixture();
        let ack=serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"transactionId":authority.request.transaction_id,"stageAbsent":true})).unwrap();
        let remote = staged(&authority, vec![Ok(receipt.clone()), Ok(ack)]);
        assert_eq!(
            deliver(&remote, &authority, b"helper", |_| {}).unwrap(),
            receipt
        );
        assert_eq!(*remote.calls.borrow(), vec!["uninstall", "finish-remove"]);
    }
    #[test]
    fn receipt_alone_never_completes_when_finish_ack_is_lost() {
        let (authority, receipt) = fixture();
        let remote = staged(&authority, vec![Ok(receipt), Err("EOF before ACK".into())]);
        assert!(deliver(&remote, &authority, b"helper", |_| {}).is_err());
    }
    #[test]
    fn durable_receipt_resumes_after_lost_ack_only_when_both_roots_absent() {
        let (authority, receipt) = fixture();
        let remote = staged(&authority, vec![]);
        remote.files.borrow_mut().clear();
        assert_eq!(
            deliver_with_journal(
                &remote,
                &authority,
                b"helper",
                |_| {},
                Some(&receipt),
                |_| panic!("already retained")
            )
            .unwrap(),
            receipt
        );
        assert!(remote.calls.borrow().is_empty());
        remote
            .files
            .borrow_mut()
            .insert("/var/voboost/remnant".into(), vec![]);
        assert!(deliver_with_journal(
            &remote,
            &authority,
            b"helper",
            |_| {},
            Some(&receipt),
            |_| Ok(())
        )
        .is_err());
    }
    #[test]
    fn provisional_write_failure_prevents_destructive_stage_cleanup() {
        let (authority, receipt) = fixture();
        let remote = staged(&authority, vec![Ok(receipt)]);
        assert!(deliver_with_journal(
            &remote,
            &authority,
            b"helper",
            |_| {},
            None,
            |_| Err("disk full".into())
        )
        .is_err());
        assert_eq!(*remote.calls.borrow(), vec!["uninstall"]);
    }
    #[test]
    fn forged_retained_receipt_cannot_infer_absence() {
        let (authority, mut receipt) = fixture();
        *receipt.last_mut().unwrap() ^= 1;
        let remote = staged(&authority, vec![]);
        remote.files.borrow_mut().clear();
        assert!(deliver_with_journal(
            &remote,
            &authority,
            b"helper",
            |_| {},
            Some(&receipt),
            |_| Ok(())
        )
        .is_err());
        assert!(remote.calls.borrow().is_empty());
    }
    #[test]
    fn retained_receipt_never_turns_absence_transport_error_into_completion() {
        let (authority, receipt) = fixture();
        let remote = staged(&authority, vec![]);
        remote.files.borrow_mut().clear();
        remote.fail_absence.set(true);
        assert!(deliver_with_journal(
            &remote,
            &authority,
            b"helper",
            |_| {},
            Some(&receipt),
            |_| Ok(())
        )
        .is_err());
        assert!(remote.calls.borrow().is_empty());
    }
    #[test]
    fn forged_receipt_never_reaches_finish_and_changed_helper_never_executes() {
        let (authority, mut receipt) = fixture();
        *receipt.last_mut().unwrap() ^= 1;
        let remote = staged(&authority, vec![Ok(receipt)]);
        assert!(deliver(&remote, &authority, b"helper", |_| {}).is_err());
        assert_eq!(*remote.calls.borrow(), vec!["uninstall"]);
        let remote = staged(&authority, vec![]);
        assert!(deliver(&remote, &authority, b"changed", |_| {}).is_err());
        assert!(remote.calls.borrow().is_empty());
    }
    #[test]
    fn native_old_kernel_failure_is_not_receipt_and_deadline_is_terminal() {
        let (authority, _) = fixture();
        let diagnostic = serde_json::json!({
            "schemaVersion":1,"sequence":1,"timestamp":"2026-11-10T12:00:00Z",
            "source":{"kind":"qnx","id":"native:14"},"component":"native-entry","level":"error",
            "message":"native uninstall requires independent new kernel boot and absent old RAM identity",
            "fields":{}
        });
        let mut remote = staged(
            &authority,
            vec![Ok(serde_json::to_vec(&diagnostic).unwrap())],
        );
        remote.expired = true;
        assert!(deliver(&remote, &authority, b"helper", |_| {})
            .unwrap_err()
            .contains("deadline"));
        assert_eq!(*remote.calls.borrow(), vec!["uninstall", "reboot"]);
    }

    #[test]
    fn unrelated_native_error_does_not_reboot_cluster() {
        let (authority, _) = fixture();
        let diagnostic = serde_json::json!({
            "schemaVersion":1,"sequence":1,"timestamp":"2026-11-10T12:00:00Z",
            "source":{"kind":"qnx","id":"native:14"},"component":"native-entry","level":"error",
            "message":"native uninstall authority differs","fields":{}
        });
        let remote = staged(
            &authority,
            vec![Ok(serde_json::to_vec(&diagnostic).unwrap())],
        );
        assert!(deliver(&remote, &authority, b"helper", |_| {}).is_err());
        assert_eq!(*remote.calls.borrow(), vec!["uninstall"]);
    }

    #[test]
    fn connection_loss_while_observing_a_retained_stage_does_not_authorize_reboot() {
        let (authority, _) = fixture();
        let remote = staged(
            &authority,
            vec![Err("Cluster qconn connect: timed out".into())],
        );
        assert!(deliver(&remote, &authority, b"helper", |_| {}).is_err());
        assert_eq!(*remote.calls.borrow(), vec!["uninstall"]);
    }

    #[test]
    fn empty_retained_stage_output_does_not_authorize_reboot_or_cleanup() {
        let (authority, _) = fixture();
        let mut remote = staged(&authority, vec![Ok(vec![])]);
        remote.expired = true;
        assert!(deliver(&remote, &authority, b"helper", |_| {}).is_err());
        assert_eq!(*remote.calls.borrow(), vec!["uninstall"]);
        assert!(!native_not_ready(b""));
    }
}
