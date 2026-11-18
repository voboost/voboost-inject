//! Exact successful-bootstrap retirement. The public root journal survives a
//! partial stage purge and a lost acknowledgement; it contains no credentials.
use super::*;
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Retirement {
    schema_version: u32,
    transaction_id: String,
    installation_sha256: String,
    stage_device: u64,
    stage_inode: u64,
    files: BTreeMap<String, FileIdentity>,
}

fn inventory(stage: &Dir) -> Result<BTreeMap<String, FileIdentity>> {
    let mut files = BTreeMap::new();
    for name in crate::fs::directory_names(&stage.path)? {
        if name == "source" || name == "provision" {
            let dir = Dir::open(&format!("{}/{name}", stage.path), crate::fs::uid()?)?;
            for child in crate::fs::directory_names(&dir.path)? {
                let mut bytes = dir.read(&child, 64 * 1024 * 1024, 0o600)?;
                let file = format!("{name}/{child}");
                files.insert(
                    file.clone(),
                    FileIdentity {
                        file,
                        size: bytes.len() as u64,
                        sha256: hash(&bytes),
                    },
                );
                if name == "provision" {
                    bytes.fill(0);
                }
            }
        } else {
            if !["prepare.json", "integration.json", "receipt.json"].contains(&name.as_str()) {
                return Err("bootstrap retirement foreign stage member".into());
            }
            let bytes = stage.read(&name, 65536, 0o600)?;
            files.insert(
                name.clone(),
                FileIdentity {
                    file: name,
                    size: bytes.len() as u64,
                    sha256: hash(&bytes),
                },
            );
        }
    }
    Ok(files)
}

fn remaining_matches(
    expected: &BTreeMap<String, FileIdentity>,
    remaining: &BTreeMap<String, FileIdentity>,
) -> Result<()> {
    for (path, actual) in remaining {
        let wanted = expected
            .get(path)
            .ok_or("bootstrap retirement foreign member")?;
        if wanted.size != actual.size || wanted.sha256 != actual.sha256 {
            return Err("bootstrap retirement retained member changed".into());
        }
    }
    Ok(())
}

pub(super) fn finish(transaction: &str) -> Result<()> {
    if !digest(transaction) || crate::fs::uid()? != 0 {
        return Err("bootstrap retirement authority rejected".into());
    }
    crate::fs::write_all(
        1,
        &finish_at(
            transaction,
            "/var/voboost",
            format!("/var/voboost-stage-{transaction}"),
            0,
        )?,
    )
}

// Paths/owner are supplied only by the fixed production entry above. Host tests
// exercise the identical protected journal, installed-authority and purge path.
fn finish_at(transaction: &str, root_path: &str, path: String, owner: u32) -> Result<Vec<u8>> {
    if !digest(transaction) {
        return Err("bootstrap retirement transaction invalid".into());
    }
    let root = Dir::open(root_path, owner)?;
    let config = Config::parse(&root.read("boot.json", 16384, 0o600)?)?;
    let proof_bytes = crate::install_layout::read_state(&root)?;
    let proof: Installation = parse_canonical(&proof_bytes, 65536)?;
    if config.root != root.path
        || proof.schema_version != 1
        || proof.bootfile != format!("{root_path}/boot.json")
    {
        return Err("bootstrap retirement installed authority differs".into());
    }
    signing_key(&config)?;
    let (_, _, current, mode) = startup(&proof.startup_file, owner)?;
    if hash(&current) != proof.installed_sha256 || mode != proof.startup_mode {
        return Err("bootstrap retirement startup differs".into());
    }
    let journal = if let Some(bytes) = crate::install_layout::read_retirement(&root, transaction)? {
        let journal: Retirement = parse_canonical(&bytes, 131072)?;
        if journal.schema_version != 1
            || journal.transaction_id != transaction
            || journal.installation_sha256 != hash(&proof_bytes)
        {
            return Err("bootstrap retirement journal authority differs".into());
        }
        crate::install_layout::write_retirement(&root, transaction, &bytes)?;
        journal
    } else {
        let stage = Dir::open(&path, owner)?;
        let integration = Integration::parse(&stage.read("integration.json", 16384, 0o600)?)?;
        let preparation: serde_json::Value =
            serde_json::from_slice(&stage.read("prepare.json", 16384, 0o600)?)
                .map_err(|_| "bootstrap retirement preparation invalid")?;
        if preparation.get("transactionId").and_then(|v| v.as_str()) != Some(transaction)
            || preparation.get("stageDirectory").and_then(|v| v.as_str()) != Some(path.as_str())
            || preparation.get("root").and_then(|v| v.as_str()) != Some(root.path.as_str())
        {
            return Err("bootstrap retirement preparation differs".into());
        }
        if integration.transaction_id != transaction
            || integration.bootfile != proof.bootfile
            || integration.source_directory != format!("{path}/source")
            || integration.provision_directory.as_deref()
                != Some(format!("{path}/provision").as_str())
            || integration.receipt_file != format!("{path}/receipt.json")
            || integration.startup_file != proof.startup_file
            || integration.original_sha256 != proof.original_sha256
            || !matches!(integration.scope, RootScope::Persistent)
            || integration.root_device_id != format!("{}", crate::fs::stat(root.fd.0)?.st_dev)
        {
            return Err("bootstrap retirement integration differs".into());
        }
        let public = ed25519_dalek::VerifyingKey::from_bytes(&crate::key(&config.qnx_public_key)?)
            .map_err(|_| "bootstrap retirement key")?;
        let receipt = AuthenticatedReport::verify(
            &stage.read("receipt.json", 65536, 0o600)?,
            &public,
            &config.pair_id,
            &config.authority_epoch,
            &integration.challenge,
            transaction,
            &proof.release_manifest_sha256,
        )?;
        if receipt.report.operation != Operation::Install
            || receipt.report.phase != Phase::Install
            || receipt.report.outcome != Outcome::Pending
            || receipt.report.catalog_sha256 != proof.catalog_sha256
        {
            return Err("bootstrap retirement receipt differs".into());
        }
        let source = Dir::open(&integration.source_directory, owner)?;
        let (_, _, payload) = bundle(&source, &ProductRoots::default(), false)?;
        let files = inventory(&stage)?;
        let source_count = files
            .keys()
            .filter(|name| name.starts_with("source/"))
            .count();
        if source_count != payload.len() {
            return Err("bootstrap retirement foreign source".into());
        }
        for (name, bytes) in payload {
            let expected = proof
                .files
                .iter()
                .find(|file| file.file == name)
                .ok_or("bootstrap retirement source not installed")?;
            if expected.size != bytes.len() as u64 || expected.sha256 != hash(&bytes) {
                return Err("bootstrap retirement source differs".into());
            }
        }
        let provision = Dir::open(
            integration
                .provision_directory
                .as_deref()
                .ok_or("bootstrap provision absent")?,
            owner,
        )?;
        let names = [
            "qnx-signing.seed",
            config
                .tls
                .server_certificate
                .rsplit('/')
                .next()
                .ok_or("certificate name")?,
            config
                .tls
                .server_private_key
                .rsplit('/')
                .next()
                .ok_or("key name")?,
            config.tls.client_ca.rsplit('/').next().ok_or("CA name")?,
        ];
        if crate::fs::directory_names(&provision.path)?.len() != names.len() {
            return Err("bootstrap retirement foreign provision".into());
        }
        for name in names {
            let mut staged = provision.read(name, 65536, 0o600)?;
            let mut installed = root.read(name, 65536, 0o600)?;
            let same = staged == installed;
            staged.fill(0);
            installed.fill(0);
            if !same {
                return Err("bootstrap retirement provision differs".into());
            }
        }
        let stat = crate::fs::stat(stage.fd.0)?;
        let journal = Retirement {
            schema_version: 1,
            transaction_id: transaction.into(),
            installation_sha256: hash(&proof_bytes),
            stage_device: stat.st_dev as u64,
            stage_inode: stat.st_ino as u64,
            files,
        };
        let bytes = ascii_json(&journal)?;
        crate::install_layout::write_retirement(&root, transaction, &bytes)?;
        if crate::install_layout::read_retirement(&root, transaction)?.as_deref()
            != Some(bytes.as_slice())
        {
            return Err("bootstrap retirement journal readback differs".into());
        }
        journal
    };
    if !crate::fs::path_absent(&path)? {
        let stage = Dir::open(&path, owner)?;
        let stat = crate::fs::stat(stage.fd.0)?;
        if stat.st_dev as u64 != journal.stage_device || stat.st_ino as u64 != journal.stage_inode {
            return Err("bootstrap retirement stage identity changed".into());
        }
        remaining_matches(&journal.files, &inventory(&stage)?)?;
        crate::fs::purge_private_tree(&stage)?;
    }
    if !crate::fs::path_absent(&path)? {
        return Err("bootstrap retirement stage remains".into());
    }
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Finished<'a> {
        schema_version: u32,
        transaction_id: &'a str,
        stage_absent: bool,
    }
    ascii_json(&Finished {
        schema_version: 1,
        transaction_id: transaction,
        stage_absent: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn authorized_journal_fixture() -> (tempfile::TempDir, Dir, String, String) {
        let (temp, config, _, _, _, _) = crate::engine::tests::fixture();
        let root = Dir::open(&config.root, crate::fs::uid().unwrap()).unwrap();
        root.write("boot.json", &ascii_json(&config).unwrap(), 0o600)
            .unwrap();
        root.write("startup-test", b"installed startup", 0o600)
            .unwrap();
        let proof = Installation {
            schema_version: 1,
            bootfile: format!("{}/boot.json", root.path),
            startup_file: format!("{}/startup-test", root.path),
            original_sha256: hash(b"original startup"),
            installed_sha256: hash(b"installed startup"),
            startup_mode: 0o600,
            release_manifest_sha256: "a".repeat(64),
            catalog_sha256: "b".repeat(64),
            files: Vec::new(),
            supervisor_config: None,
        };
        let proof_bytes = ascii_json(&proof).unwrap();
        root.write("installation.json", &proof_bytes, 0o600)
            .unwrap();
        let stage = root.child("retirement-stage").unwrap();
        let provision = stage.child("provision").unwrap();
        provision
            .write("qnx-signing.seed", &[15; 32], 0o600)
            .unwrap();
        provision
            .write("key.pem", b"private fixture", 0o600)
            .unwrap();
        stage
            .write("integration.json", b"previously verified input", 0o600)
            .unwrap();
        let stat = crate::fs::stat(stage.fd.0).unwrap();
        let tx = "c".repeat(64);
        let journal = Retirement {
            schema_version: 1,
            transaction_id: tx.clone(),
            installation_sha256: hash(&proof_bytes),
            stage_device: stat.st_dev as u64,
            stage_inode: stat.st_ino as u64,
            files: inventory(&stage).unwrap(),
        };
        root.write(
            &format!("bootstrap-retired-{tx}.json"),
            &ascii_json(&journal).unwrap(),
            0o600,
        )
        .unwrap();
        (temp, root, stage.path, tx)
    }
    #[test]
    fn full_journal_transaction_removes_secrets_and_lost_ack_retry_is_identical() {
        let (_temp, root, path, tx) = authorized_journal_fixture();
        let ack = finish_at(&tx, &root.path, path.clone(), crate::fs::uid().unwrap()).unwrap();
        assert!(crate::fs::path_absent(&path).unwrap());
        assert_eq!(root.read("qnx-signing.seed", 32, 0o600).unwrap(), [15; 32]);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&ack).unwrap(),
            serde_json::json!({"schemaVersion":1,"transactionId":tx,"stageAbsent":true})
        );
        assert_eq!(
            finish_at(&tx, &root.path, path, crate::fs::uid().unwrap()).unwrap(),
            ack
        );
    }
    #[test]
    fn full_journal_transaction_resumes_after_actual_partial_purge() {
        let (_temp, root, path, tx) = authorized_journal_fixture();
        std::fs::remove_file(format!("{path}/integration.json")).unwrap();
        std::fs::remove_file(format!("{path}/provision/qnx-signing.seed")).unwrap();
        assert!(finish_at(&tx, &root.path, path.clone(), crate::fs::uid().unwrap()).is_ok());
        assert!(crate::fs::path_absent(&path).unwrap());
    }
    #[test]
    fn full_journal_transaction_preserves_foreign_member_and_credentials() {
        let (_temp, root, path, tx) = authorized_journal_fixture();
        let provision = Dir::open(&format!("{path}/provision"), crate::fs::uid().unwrap()).unwrap();
        provision.write("foreign", b"preserve", 0o600).unwrap();
        assert!(finish_at(&tx, &root.path, path.clone(), crate::fs::uid().unwrap()).is_err());
        assert_eq!(provision.read("foreign", 32, 0o600).unwrap(), b"preserve");
        assert_eq!(
            provision.read("qnx-signing.seed", 32, 0o600).unwrap(),
            [15; 32]
        );
    }
    #[test]
    fn full_journal_transaction_rejects_changed_installed_authority_before_purge() {
        let (_temp, root, path, tx) = authorized_journal_fixture();
        let mut proof: Installation = parse_canonical(
            &root.read("installation.json", 65536, 0o600).unwrap(),
            65536,
        )
        .unwrap();
        proof.release_manifest_sha256 = "d".repeat(64);
        root.write("installation.json", &ascii_json(&proof).unwrap(), 0o600)
            .unwrap();
        assert!(finish_at(&tx, &root.path, path.clone(), crate::fs::uid().unwrap()).is_err());
        assert!(std::path::Path::new(&format!("{path}/provision/qnx-signing.seed")).exists());
    }
    fn identity(name: &str, bytes: &[u8]) -> FileIdentity {
        FileIdentity {
            file: name.into(),
            size: bytes.len() as u64,
            sha256: hash(bytes),
        }
    }
    #[test]
    fn interrupted_cleanup_allows_only_unchanged_remaining_members() {
        let expected = BTreeMap::from([
            ("provision/key".into(), identity("provision/key", b"secret")),
            (
                "integration.json".into(),
                identity("integration.json", b"input"),
            ),
        ]);
        assert!(remaining_matches(&expected, &BTreeMap::new()).is_ok());
        assert!(remaining_matches(
            &expected,
            &BTreeMap::from([("provision/key".into(), identity("provision/key", b"secret"))])
        )
        .is_ok());
        assert!(remaining_matches(
            &expected,
            &BTreeMap::from([(
                "provision/key".into(),
                identity("provision/key", b"changed")
            )])
        )
        .is_err());
        assert!(remaining_matches(
            &expected,
            &BTreeMap::from([("foreign".into(), identity("foreign", b"secret"))])
        )
        .is_err());
    }
    #[test]
    fn rejects_arbitrary_stage_names_before_access() {
        assert!(finish("../foreign").is_err());
    }
    #[test]
    fn inventory_rejects_unknown_and_symlinked_members_without_removing_credentials() {
        let (_temp, config, _, _, _, _) = crate::engine::tests::fixture();
        let root = Dir::open(&config.root, crate::fs::uid().unwrap()).unwrap();
        let stage = root.child("retirement-test").unwrap();
        let provision = stage.child("provision").unwrap();
        provision.write("key", b"retained secret", 0o600).unwrap();
        stage.write("foreign", b"do not delete", 0o600).unwrap();
        assert!(inventory(&stage).is_err());
        assert_eq!(
            provision.read("key", 64, 0o600).unwrap(),
            b"retained secret"
        );
        std::fs::remove_file(format!("{}/foreign", stage.path)).unwrap();
        std::os::unix::fs::symlink("key", format!("{}/link", provision.path)).unwrap();
        assert!(inventory(&stage).is_err());
        assert_eq!(
            provision.read("key", 64, 0o600).unwrap(),
            b"retained secret"
        );
    }
}
