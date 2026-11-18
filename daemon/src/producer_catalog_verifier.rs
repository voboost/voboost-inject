use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

mod config {
    pub const MAX_PLAN_BYTES: usize = 1024 * 1024;
}

mod trust {
    #![allow(dead_code)]
    #[derive(Clone, Copy)]
    pub enum SignatureRole {
        AgentCatalog,
    }

    pub fn verify_signature(_role: SignatureRole, _data: &[u8], _signature: &[u8]) -> bool {
        false
    }
}

#[path = "catalog.rs"]
#[allow(dead_code)]
mod catalog;
#[path = "../../build_support/strict_ed25519_spki.rs"]
mod strict_ed25519_spki;

fn read_exact_file(path: &Path, maximum: usize, label: &str) -> Result<Vec<u8>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("open {label}: {error}"))?;
    let before = file
        .metadata()
        .map_err(|error| format!("stat {label}: {error}"))?;
    if !before.is_file()
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > maximum as u64
    {
        return Err(format!("{label} file identity or size is unsafe"));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(maximum.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {label}: {error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("restat {label}: {error}"))?;
    let stamp = |metadata: &std::fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.ctime(),
            metadata.ctime_nsec(),
            metadata.nlink(),
        )
    };
    if stamp(&before) != stamp(&after) || bytes.len() as u64 != before.len() {
        return Err(format!("{label} changed while reading"));
    }
    Ok(bytes)
}

fn verify(catalog_path: &Path, signature_path: &Path, key_path: &Path) -> Result<(), String> {
    let exact_bytes =
        read_exact_file(catalog_path, catalog::MAX_CATALOG_BYTES, "producer catalog")?;
    let signature = read_exact_file(
        signature_path,
        catalog::SIGNATURE_BYTES,
        "producer signature",
    )?;
    if signature.len() != catalog::SIGNATURE_BYTES {
        return Err("producer signature is not exactly 64 bytes".to_string());
    }
    let key_pem = read_exact_file(key_path, 256, "producer public key")?;
    let key = strict_ed25519_spki::extract_ed25519_pubkey_from_pem(&key_pem)?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_| "producer public key is invalid")?;
    let signature =
        Signature::from_slice(&signature).map_err(|_| "producer signature is invalid")?;
    key.verify(&exact_bytes, &signature)
        .map_err(|_| "producer signature does not authenticate exact catalog bytes")?;
    let parsed = catalog::AgentCatalog::parse(&exact_bytes)
        .map_err(|error| format!("producer catalog schema is invalid: {error}"))?;
    let stable = parsed
        .agents
        .iter()
        .filter(|agent| agent.status == Some(catalog::AgentStatus::Stable))
        .map(|agent| agent.id.as_str())
        .collect::<HashSet<_>>();
    let expected = catalog::STABLE_AGENT_IDS
        .into_iter()
        .collect::<HashSet<_>>();
    if stable != expected {
        return Err("producer stable agent set differs".to_string());
    }
    Ok(())
}

fn main() {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 3 {
        voboost_shared::diagnostic_log::stderr(voboost_shared::diagnostic_log::Service::CatalogVerifier, voboost_shared::diagnostic_log::Level::Error, "catalog-verifier", "usage: voboost-producer-catalog-verifier <agents.json> <agents.json.sig> <agent-catalog-public.pem>", &[]);
        std::process::exit(2);
    }
    if let Err(error) = verify(
        Path::new(&arguments[0]),
        Path::new(&arguments[1]),
        Path::new(&arguments[2]),
    ) {
        voboost_shared::diagnostic_log::stderr(
            voboost_shared::diagnostic_log::Service::CatalogVerifier,
            voboost_shared::diagnostic_log::Level::Error,
            "catalog-verifier",
            &format!("producer catalog verification failed: {error}"),
            &[],
        );
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use ed25519_dalek::{Signer, SigningKey};
    use std::fs::File;
    use std::io::Write;
    use std::os::unix::fs::symlink;

    fn catalog_bytes() -> Vec<u8> {
        let sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let agents = catalog::STABLE_AGENT_IDS
            .iter()
            .enumerate()
            .map(|(index, id)| {
                let activation = if *id == "settings" {
                    serde_json::json!({
                        "type": "config",
                        "key": "voboost-startup",
                        "value": "interface"
                    })
                } else {
                    serde_json::json!({"type": "checkbox", "default": false})
                };
                serde_json::json!({
                    "id": id,
                    "targets": [{
                        "platform":"android","domain":"android","entryAbi":"android-java-v1",
                        "process": format!("com.example.target{index}"),
                        "file": format!("agent-{id}.dex"),
                        "size": 3,
                        "sha256": sha,
                        "entryClass": format!("ru.voboost.agents.Test{index}Agent"),
                        "boot": false
                    }],
                    "status": "stable",
                    "category": "interface",
                    "order": index as i32 + 1,
                    "activation": activation,
                    "disables": [],
                    "options": [],
                    "title": {"en": id, "ru": id},
                    "description": {"en": id, "ru": id},
                    "applicability": {
                        "chip": ["8155"], "vehicle": ["free"], "android": [9],
                        "powertrain": ["hybrid"], "market": ["china"]
                    }
                })
            })
            .collect::<Vec<_>>();
        let value = serde_json::json!({
            "schemaVersion": 2,
            "supportedAbis": ["arm64-v8a", "armeabi-v7a"],
            "agentEntryAbi": {"schemaVersion": 1, "sha256": catalog::AGENT_ENTRY_ABI_SHA256},
            "core": {"file": "agent-common.dex", "size": 3, "sha256": sha},
            "agents": agents
        });
        let parsed: catalog::AgentCatalog = serde_json::from_value(value).unwrap();
        let mut bytes = serde_json::to_vec(&parsed).unwrap();
        bytes.push(b'\n');
        catalog::AgentCatalog::parse(&bytes).unwrap();
        bytes
    }

    fn fixture() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        let root = tempfile::tempdir().unwrap();
        let catalog = root.path().join("agents.json");
        let signature = root.path().join("agents.json.sig");
        let key = root.path().join("agent-catalog-public.pem");
        let bytes = catalog_bytes();
        let signing = SigningKey::from_bytes(&[0x33; 32]);
        File::create(&catalog).unwrap().write_all(&bytes).unwrap();
        File::create(&signature)
            .unwrap()
            .write_all(&signing.sign(&bytes).to_bytes())
            .unwrap();
        File::create(&key)
            .unwrap()
            .write_all(
                signing
                    .verifying_key()
                    .to_public_key_pem(LineEnding::LF)
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap();
        (root, catalog, signature, key)
    }

    #[test]
    fn exact_external_inputs_verify_and_each_substitution_fails() {
        let (_root, catalog, signature, key) = fixture();
        verify(&catalog, &signature, &key).unwrap();
        let original = std::fs::read(&catalog).unwrap();
        std::fs::write(&catalog, [original.as_slice(), b" "].concat()).unwrap();
        assert!(verify(&catalog, &signature, &key).is_err());
        std::fs::write(&catalog, original).unwrap();
        std::fs::write(&signature, [0_u8; 64]).unwrap();
        assert!(verify(&catalog, &signature, &key).is_err());
    }

    #[test]
    fn missing_linked_and_noncanonical_key_inputs_fail_closed() {
        let (root, catalog, signature, key) = fixture();
        let linked = root.path().join("linked.json");
        symlink(&catalog, &linked).unwrap();
        assert!(verify(&linked, &signature, &key).is_err());
        std::fs::write(&key, b"not a public key\n").unwrap();
        assert!(verify(&catalog, &signature, &key).is_err());
        assert!(verify(&root.path().join("missing"), &signature, &key).is_err());
    }
}
