//! Fixed QNX delivery documents persisted by the runtime owner.
use crate::secure_fs::Directory;
use ed25519_dalek::VerifyingKey;
use std::io;
use voboost_contract::{cluster, runtime_owner::ClusterArtifact};
use voboost_shared::cluster_mailbox::{Provision, State};

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn key(text: &str) -> io::Result<VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(text)
        .map_err(invalid)?
        .try_into()
        .map_err(|_| invalid("invalid cluster public key"))?;
    VerifyingKey::from_bytes(&bytes).map_err(invalid)
}

pub(super) fn import(
    directory: &Directory,
    material: &voboost_contract::runtime_owner::ClusterPairing,
) -> io::Result<()> {
    use sha2::{Digest, Sha256};
    let provision: Provision =
        voboost_contract::domain_core::parse_canonical(&material.provision, 16 * 1024)
            .map_err(invalid)?;
    provision.validate().map_err(invalid)?;
    let seed: [u8; 32] = material
        .seed
        .as_slice()
        .try_into()
        .map_err(|_| invalid("invalid cluster signing seed size"))?;
    if ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key()
        != key(&provision.android_public_key)?
    {
        return Err(invalid(
            "cluster signing seed differs from paired authority",
        ));
    }
    if material.credentials.len() as u64 != provision.transport.credentials.size
        || hex::encode(Sha256::digest(&material.credentials))
            != provision.transport.credentials.sha256
    {
        return Err(invalid(
            "cluster credentials differ from provisioned identity",
        ));
    }
    let mut complete = true;
    for (name, bytes) in [
        ("device-signing.seed", material.seed.as_slice()),
        ("transport.p12", material.credentials.as_slice()),
        ("provision.json", material.provision.as_slice()),
    ] {
        match directory.read_trusted(name, bytes.len(), 0o600) {
            Ok(existing) if existing == bytes => (),
            Ok(_) => return Err(invalid("cluster pairing is immutable")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => complete = false,
            Err(error) => return Err(error),
        }
    }
    let provisioned = directory.entry_exists("provision.json")?;
    let mailbox = match directory.read_trusted(
        "mailbox.json",
        voboost_contract::runtime_owner::MAX_CLUSTER_MAILBOX_BYTES,
        0o600,
    ) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    if provisioned && mailbox.is_none() {
        return Err(invalid(
            "provisioned cluster mailbox missing; authority retained",
        ));
    }
    if let Some(bytes) = &mailbox {
        if bytes != voboost_shared::cluster_mailbox::INITIAL_MAILBOX {
            let state: State = voboost_contract::domain_core::parse_canonical(
                bytes,
                voboost_contract::runtime_owner::MAX_CLUSTER_MAILBOX_BYTES,
            )
            .map_err(invalid)?;
            state.validate().map_err(invalid)?;
        }
    }
    if complete {
        return Ok(());
    }
    // Publication of provision.json commits the already durable private inputs.
    directory.write_atomic("device-signing.seed", &material.seed, 0o600)?;
    directory.write_atomic("transport.p12", &material.credentials, 0o600)?;
    if mailbox.is_none() {
        directory.write_atomic(
            "mailbox.json",
            voboost_shared::cluster_mailbox::INITIAL_MAILBOX,
            0o600,
        )?;
    }
    directory.write_atomic("provision.json", &material.provision, 0o600)
}

pub(super) fn write(
    directory: &Directory,
    artifact: ClusterArtifact,
    bytes: &[u8],
) -> io::Result<()> {
    match directory.read_trusted(artifact.file(), 65536, 0o600) {
        Ok(_) => (),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    let provision: Provision =
        serde_json::from_slice(&directory.read_trusted("provision.json", 65536, 0o600)?)
            .map_err(invalid)?;
    provision.validate().map_err(invalid)?;
    match artifact {
        ClusterArtifact::Request => {
            let request = cluster::Request::verify(bytes, &key(&provision.android_public_key)?)
                .map_err(invalid)?;
            if request.pair_id != provision.pair_id
                || request.authority_epoch != provision.authority_epoch
            {
                return Err(invalid("cluster request differs from pairing"));
            }
        }
        ClusterArtifact::Receipt | ClusterArtifact::UninstallReport => {
            let state: State = serde_json::from_slice(&directory.read_trusted(
                "mailbox.json",
                voboost_contract::runtime_owner::MAX_CLUSTER_MAILBOX_BYTES,
                0o600,
            )?)
            .map_err(invalid)?;
            state.validate().map_err(invalid)?;
            let pending = state
                .pending
                .as_ref()
                .ok_or_else(|| invalid("cluster request absent"))?;
            if pending.request.pair_id != provision.pair_id
                || pending.request.authority_epoch != provision.authority_epoch
            {
                return Err(invalid("cluster pending request differs from pairing"));
            }
            let authority = key(&provision.qnx_public_key)?;
            match artifact {
                ClusterArtifact::Receipt => {
                    let receipt = cluster::Receipt::verify(bytes, &authority).map_err(invalid)?;
                    receipt
                        .correlate(
                            &pending.request,
                            state
                                .generation
                                .as_ref()
                                .map(|generation| generation.generation_id.as_str()),
                        )
                        .map_err(invalid)?;
                    state.validate_receipt_targets(&receipt).map_err(invalid)?;
                }
                ClusterArtifact::UninstallReport => {
                    voboost_contract::domain_core::domain_operation::verify_qnx_restoration(
                        bytes,
                        &authority,
                        &pending.request,
                    )
                    .map_err(invalid)?;
                }
                ClusterArtifact::Request => unreachable!(),
            }
        }
    }
    directory.write_atomic(artifact.file(), bytes, 0o600)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    fn pairing() -> voboost_contract::runtime_owner::ClusterPairing {
        use sha2::{Digest, Sha256};
        let android = SigningKey::from_bytes(&[73; 32]);
        let qnx = SigningKey::from_bytes(&[74; 32]);
        let credentials = vec![42; 32];
        let provision: Provision = serde_json::from_value(json!({
            "schemaVersion": 1, "pairId": "1".repeat(64), "authorityEpoch": "2".repeat(64),
            "androidPublicKey": hex::encode(android.verifying_key().to_bytes()),
            "qnxPublicKey": hex::encode(qnx.verifying_key().to_bytes()),
            "transport": {
                "host": "192.0.2.1", "port": 9443,
                "serverCertificateSha256": "3".repeat(64),
                "clientCertificateSha256": "4".repeat(64),
                "credentials": { "size": 32, "sha256": hex::encode(Sha256::digest(&credentials)) }
            }
        }))
        .unwrap();
        voboost_contract::runtime_owner::ClusterPairing {
            provision: voboost_contract::domain_core::ascii_json(&provision).unwrap(),
            seed: vec![73; 32],
            credentials,
        }
    }

    #[test]
    fn pairing_import_is_retryable_but_never_rotates_existing_authority() {
        let root = tempfile::tempdir().unwrap();
        let directory = Directory::open(root.path()).unwrap();
        let mut material = pairing();
        material.seed[0] ^= 1;
        assert!(import(&directory, &material).is_err());
        assert!(!directory.entry_exists("provision.json").unwrap());
        material.seed[0] ^= 1;
        // Resume an interrupted import whose seed was already committed.
        directory
            .write_atomic("device-signing.seed", &material.seed, 0o600)
            .unwrap();
        import(&directory, &material).unwrap();
        import(&directory, &material).unwrap();
        let mut changed: Provision =
            voboost_contract::domain_core::parse_canonical(&material.provision, 16384).unwrap();
        changed.authority_epoch = "f".repeat(64);
        let conflicting = voboost_contract::runtime_owner::ClusterPairing {
            provision: voboost_contract::domain_core::ascii_json(&changed).unwrap(),
            seed: material.seed.clone(),
            credentials: material.credentials.clone(),
        };
        assert!(import(&directory, &conflicting).is_err());
        assert_eq!(
            directory.read_trusted("mailbox.json", 4096, 0o600).unwrap(),
            voboost_shared::cluster_mailbox::INITIAL_MAILBOX
        );
        material.credentials[0] ^= 1;
        assert!(import(&directory, &material).is_err());
        assert_eq!(
            directory
                .read_trusted("provision.json", 16384, 0o600)
                .unwrap(),
            material.provision
        );
        directory.unlink("mailbox.json").unwrap();
        material.credentials[0] ^= 1;
        assert!(import(&directory, &material).is_err());
        assert!(!directory.entry_exists("mailbox.json").unwrap());
    }

    #[test]
    fn signed_request_commit_rejects_foreign_key_pairing_and_document_role() {
        let root = tempfile::tempdir().unwrap();
        let directory = Directory::open(root.path()).unwrap();
        let material = pairing();
        import(&directory, &material).unwrap();
        let android = SigningKey::from_bytes(&[73; 32]);
        let qnx = SigningKey::from_bytes(&[74; 32]);
        let mut request: cluster::Request = serde_json::from_value(json!({
            "schemaVersion": 1, "kind": "observe", "domain": "cluster",
            "pairId": "1".repeat(64), "authorityEpoch": "2".repeat(64),
            "transactionId": "6".repeat(64), "catalogSha256": "7".repeat(64),
            "closureSha256": "8".repeat(64), "challenge": "9".repeat(64),
            "desiredRevision": 1, "desiredSha256": "a".repeat(64)
        }))
        .unwrap();
        let bytes = request.sign(&android).unwrap();
        write(&directory, ClusterArtifact::Request, &bytes).unwrap();
        assert_eq!(
            directory.read_trusted("request.vbc", 65536, 0o600).unwrap(),
            bytes
        );
        let foreign = request.sign(&qnx).unwrap();
        assert!(write(&directory, ClusterArtifact::Request, &foreign).is_err());
        request.pair_id = "f".repeat(64);
        assert!(write(
            &directory,
            ClusterArtifact::Request,
            &request.sign(&android).unwrap()
        )
        .is_err());
        assert!(write(&directory, ClusterArtifact::Receipt, &bytes).is_err());
        assert!(write(&directory, ClusterArtifact::UninstallReport, &bytes).is_err());
        assert_eq!(
            directory.read_trusted("request.vbc", 65536, 0o600).unwrap(),
            bytes
        );
        assert!(!directory.entry_exists("receipt.vbc").unwrap());
        assert!(!directory.entry_exists("uninstall-report.vbc").unwrap());
        directory.unlink("request.vbc").unwrap();
        let outside = root.path().join("outside");
        std::fs::write(&outside, b"untouched").unwrap();
        std::os::unix::fs::symlink(&outside, root.path().join("request.vbc")).unwrap();
        assert!(write(&directory, ClusterArtifact::Request, &bytes).is_err());
        assert_eq!(std::fs::read(&outside).unwrap(), b"untouched");
        assert!(std::fs::symlink_metadata(root.path().join("request.vbc"))
            .unwrap()
            .file_type()
            .is_symlink());
    }
}
