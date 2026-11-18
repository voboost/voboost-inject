//! Strict, side-effect-free native release authentication shared by recovery consumers.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseIdentity {
    pub channel: String,
    pub base_version: String,
    pub beta: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileEntry {
    path: String,
    channel: String,
    sha256: String,
    size: i64,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    abi: Option<String>,
    role: String,
    activation: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    version: String,
    channel: String,
    release_identity: ReleaseIdentity,
    files: Vec<FileEntry>,
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn verify_exact_native_release(
    manifest_bytes: &[u8],
    signature: &[u8],
    native_key: &[u8; 32],
    expected_identity: &ReleaseIdentity,
    mut member: impl FnMut(&str, u32) -> Result<Vec<u8>, String>,
) -> Result<String, String> {
    VerifyingKey::from_bytes(native_key)
        .map_err(|e| e.to_string())?
        .verify(
            manifest_bytes,
            &Signature::from_slice(signature).map_err(|e| e.to_string())?,
        )
        .map_err(|_| "native manifest signature is invalid".to_string())?;
    let value: Manifest = serde_json::from_slice(manifest_bytes).map_err(|e| e.to_string())?;
    let mut canonical = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
    canonical.push(b'\n');
    if canonical != manifest_bytes {
        return Err("native manifest is not canonical".into());
    }
    if value.schema_version != 1
        || value.channel != "inject"
        || value.version != value.release_identity.base_version
        || &value.release_identity != expected_identity
    {
        return Err("native manifest target identity mismatch".into());
    }
    let mut expected = BTreeSet::new();
    expected.insert(("voboost-daemon".to_string(), None, "daemon", "update"));
    expected.insert(("voboost-inject".to_string(), None, "inject", "update"));
    expected.insert((
        "voboost-install".to_string(),
        None,
        "install",
        "install-only",
    ));
    expected.insert((
        "voboost-uninstall".to_string(),
        None,
        "uninstall",
        "install-only",
    ));
    for abi in ["arm64-v8a", "armeabi-v7a"] {
        expected.insert((
            format!("payload/{abi}/libimplant.so"),
            Some(abi.to_string()),
            "runtime",
            "update",
        ));
    }
    expected.insert((
        "restore/arm64-v8a/voboost-restore".to_string(),
        Some("arm64-v8a".to_string()),
        "restore",
        "update",
    ));
    expected.insert((
        "selinux/arm64-v8a/voboost-selinux".to_string(),
        Some("arm64-v8a".to_string()),
        "selinux",
        "install-only",
    ));
    expected.insert(("voboost.rc".into(), None, "init", "install-only"));
    expected.insert(("restore.json".into(), None, "restore-manifest", "update"));
    expected.insert((
        "restore.json.sig".into(),
        None,
        "restore-manifest-signature",
        "update",
    ));
    let mut seen = BTreeSet::new();
    for file in &value.files {
        let identity = (
            file.path.clone(),
            file.abi.clone(),
            file.role.as_str(),
            file.activation.as_str(),
        );
        if file.channel != "inject"
            || file.version != value.version
            || !expected.contains(&identity)
            || file.size <= 0
            || file.size > 64 * 1024 * 1024
            || !canonical_sha256(&file.sha256)
            || !seen.insert(identity)
        {
            return Err(format!("invalid native member {}", file.path));
        }
        if file.activation == "update" || file.path == "voboost.rc" {
            let bytes = member(&file.path, file.size as u32)?;
            if bytes.len() as i64 != file.size || sha(&bytes) != file.sha256 {
                return Err(format!("native member corruption: {}", file.path));
            }
        }
    }
    if seen != expected {
        return Err("native bundle is incomplete".into());
    }
    Ok(sha(manifest_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;

    struct Fixture {
        key: SigningKey,
        identity: ReleaseIdentity,
        manifest: Vec<u8>,
        signature: Vec<u8>,
        members: BTreeMap<String, Vec<u8>>,
    }

    fn fixture() -> Fixture {
        let key = SigningKey::from_bytes(&[9; 32]);
        let identity = ReleaseIdentity {
            channel: "dev-vithar".into(),
            base_version: "1.2.3".into(),
            beta: Some(7),
        };
        let mut members: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for path in [
            "voboost-daemon",
            "voboost-inject",
            "voboost-install",
            "voboost-uninstall",
            "payload/arm64-v8a/libimplant.so",
            "payload/armeabi-v7a/libimplant.so",
            "restore/arm64-v8a/voboost-restore",
            "voboost.rc",
            "restore.json",
            "restore.json.sig",
            "restore/arm64-v8a/voboost-restore",
            "selinux/arm64-v8a/voboost-selinux",
        ] {
            members.insert(path.into(), format!("bytes:{path}").into_bytes());
        }
        let files = members
            .iter()
            .map(|(path, bytes)| {
                let abi = if path.contains("arm64-v8a") {
                    Some("arm64-v8a")
                } else if path.contains("armeabi-v7a") {
                    Some("armeabi-v7a")
                } else {
                    None
                };
                let (role, activation) = if path == "voboost-daemon" {
                    ("daemon", "update")
                } else if path == "voboost-inject" {
                    ("inject", "update")
                } else if path == "voboost-install" {
                    ("install", "install-only")
                } else if path == "voboost-uninstall" {
                    ("uninstall", "install-only")
                } else if path.starts_with("payload/") {
                    ("runtime", "update")
                } else if path.starts_with("restore/") {
                    ("restore", "update")
                } else if path.starts_with("selinux/") {
                    ("selinux", "install-only")
                } else if path == "voboost.rc" {
                    ("init", "install-only")
                } else if path == "restore.json" {
                    ("restore-manifest", "update")
                } else if path == "restore.json.sig" {
                    ("restore-manifest-signature", "update")
                } else {
                    unreachable!("closed native fixture path")
                };
                FileEntry {
                    path: path.clone(),
                    channel: "inject".into(),
                    sha256: sha(bytes),
                    size: bytes.len() as i64,
                    version: "1.2.3".into(),
                    abi: abi.map(str::to_string),
                    role: role.into(),
                    activation: activation.into(),
                }
            })
            .collect();
        let manifest = Manifest {
            schema_version: 1,
            version: "1.2.3".into(),
            channel: "inject".into(),
            release_identity: identity.clone(),
            files,
        };
        let mut bytes = serde_json::to_vec(&manifest).unwrap();
        bytes.push(b'\n');
        let signature = key.sign(&bytes).to_bytes().to_vec();
        Fixture {
            key,
            identity,
            manifest: bytes,
            signature,
            members,
        }
    }

    #[test]
    fn target_mismatch_and_every_applied_member_corruption_fail_closed() {
        let Fixture {
            key,
            identity,
            manifest,
            signature,
            members,
        } = fixture();
        let verify = |identity: &ReleaseIdentity, corpus: &BTreeMap<String, Vec<u8>>| {
            verify_exact_native_release(
                &manifest,
                &signature,
                key.verifying_key().as_bytes(),
                identity,
                |path, _| corpus.get(path).cloned().ok_or_else(|| "missing".into()),
            )
        };
        assert!(verify(&identity, &members).is_ok());
        let mut wrong = identity.clone();
        wrong.beta = Some(8);
        assert!(verify(&wrong, &members).is_err());
        for path in [
            "voboost-daemon",
            "voboost-inject",
            "payload/arm64-v8a/libimplant.so",
            "payload/armeabi-v7a/libimplant.so",
            "voboost.rc",
            "restore.json",
            "restore.json.sig",
        ] {
            let mut corrupted = members.clone();
            corrupted.get_mut(path).unwrap().push(0);
            assert!(
                verify(&identity, &corrupted).is_err(),
                "accepted corruption of {path}"
            );
        }
        let mut missing_inject = members.clone();
        missing_inject.remove("voboost-inject");
        assert!(verify(&identity, &missing_inject).is_err());
    }
}
