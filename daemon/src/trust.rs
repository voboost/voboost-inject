// trust.rs — role-separated embedded trust anchors + ed25519 verify + sha256.
//
// No key is ever read from disk at runtime. Verification is always on; there
// is no skip-verify path and callers must select the artifact role explicitly.

use ed25519_dalek::{Signature, VerifyingKey, SIGNATURE_LENGTH};
use sha2::{Digest, Sha256};

include!(concat!(env!("OUT_DIR"), "/embedded_pubkey.rs"));

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureRole {
    AgentCatalog,
    ReleaseCatalog,
    NativeExecutable,
}

fn public_key(role: SignatureRole) -> &'static [u8; 32] {
    match role {
        SignatureRole::AgentCatalog => &AGENT_CATALOG_PUBKEY,
        SignatureRole::ReleaseCatalog => &RELEASE_CATALOG_PUBKEY,
        SignatureRole::NativeExecutable => &NATIVE_EXECUTABLE_PUBKEY,
    }
}

pub fn agent_catalog_public_key() -> [u8; 32] {
    AGENT_CATALOG_PUBKEY
}

pub fn release_catalog_public_key() -> [u8; 32] {
    RELEASE_CATALOG_PUBKEY
}

pub fn verify_product_restore_authority(
    manifest: &voboost_contract::release::Manifest,
    data: &[u8],
    signature: &[u8],
) -> Result<voboost_contract::release::RestoreDocument, String> {
    voboost_contract::release::verify_restore_authority(
        manifest,
        data,
        signature,
        &RESTORE_PUBLIC_KEY,
    )
}

pub fn verify_with_raw_key(data: &[u8], signature: &[u8], public_key: &[u8; 32]) -> bool {
    if signature.len() != SIGNATURE_LENGTH {
        return false;
    }
    let Ok(vk) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };
    vk.verify_strict(data, &sig).is_ok()
}

pub fn agent_catalog_key_sha256() -> String {
    // Keep a machine-readable build identity in the final ELF and fail closed
    // if generated source ever stops describing the exact verifier bytes.
    const PREFIX: &str = "\0VOBOOST_AGENT_CATALOG_RAW32=";
    // black_box prevents release/LTO constant folding from erasing the
    // machine-readable identity bytes that product authoring must attest.
    let build_identity = std::hint::black_box(AGENT_CATALOG_BUILD_IDENTITY);
    let Some(raw_hex) = build_identity
        .strip_prefix(PREFIX)
        .and_then(|value| value.strip_suffix('\0'))
    else {
        return String::new();
    };
    if raw_hex != hex::encode(public_key(SignatureRole::AgentCatalog)) {
        return String::new();
    }
    sha256_bytes(public_key(SignatureRole::AgentCatalog))
}

pub fn restore_key_sha256() -> String {
    sha256_bytes(&RESTORE_PUBLIC_KEY)
}

/// Verify a detached Ed25519 signature against exactly one artifact role.
pub fn verify_signature(role: SignatureRole, data: &[u8], signature: &[u8]) -> bool {
    verify_with_raw_key(data, signature, public_key(role))
}

/// Compute the sha256 hex digest of already-opened/read bytes.
pub fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Verify bytes read from one descriptor against an expected sha256.
pub fn verify_payload_bytes(data: &[u8], expected_sha256: &str) -> bool {
    sha256_bytes(data).eq_ignore_ascii_case(expected_sha256)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const AGENT_CATALOG_TEST_SEED: [u8; 32] =
        hex_literal("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5");
    const NATIVE_EXECUTABLE_TEST_SEED: [u8; 32] =
        hex_literal("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");

    const fn hex_literal(value: &str) -> [u8; 32] {
        let bytes = value.as_bytes();
        let mut output = [0u8; 32];
        let mut index = 0;
        while index < 32 {
            output[index] = (nibble(bytes[index * 2]) << 4) | nibble(bytes[index * 2 + 1]);
            index += 1;
        }
        output
    }

    const fn nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid fixture hex"),
        }
    }

    #[test]
    fn verify_signature_rejects_wrong_length() {
        assert!(!verify_signature(
            SignatureRole::NativeExecutable,
            b"data",
            b"too short"
        ));
        let zero_sig = [0u8; 64];
        assert!(!verify_signature(
            SignatureRole::NativeExecutable,
            b"data",
            &zero_sig
        ));
    }

    #[test]
    fn role_keys_are_distinct_and_not_interchangeable() {
        assert_ne!(AGENT_CATALOG_PUBKEY, NATIVE_EXECUTABLE_PUBKEY);
        let signing_key = SigningKey::from_bytes(&AGENT_CATALOG_TEST_SEED);
        let signature = signing_key.sign(b"fixture").to_bytes();
        assert!(verify_signature(
            SignatureRole::AgentCatalog,
            b"fixture",
            &signature
        ));
        assert!(!verify_signature(
            SignatureRole::NativeExecutable,
            b"fixture",
            &signature
        ));
    }

    #[test]
    fn release_catalog_signature_is_not_accepted_by_any_other_role() {
        let bytes = b"voboost.json\n";
        let cases = [
            (
                hex_literal("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5"),
                Some(SignatureRole::AgentCatalog),
            ),
            ([12_u8; 32], Some(SignatureRole::ReleaseCatalog)),
            (
                NATIVE_EXECUTABLE_TEST_SEED,
                Some(SignatureRole::NativeExecutable),
            ),
            (
                hex_literal("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"),
                None,
            ),
        ];
        for (seed, role) in cases {
            let signature = SigningKey::from_bytes(&seed).sign(bytes).to_bytes();
            assert_eq!(
                verify_signature(SignatureRole::ReleaseCatalog, bytes, &signature),
                role == Some(SignatureRole::ReleaseCatalog)
            );
            for verifier in [SignatureRole::AgentCatalog, SignatureRole::NativeExecutable] {
                assert_eq!(
                    verify_signature(verifier, bytes, &signature),
                    role == Some(verifier)
                );
            }
            assert_eq!(
                verify_with_raw_key(bytes, &signature, &RESTORE_PUBLIC_KEY),
                role.is_none()
            );
        }
    }

    #[test]
    fn embedded_roots_ignore_device_key_files() {
        let directory = tempfile::tempdir().unwrap();
        let alternate = SigningKey::from_bytes(&[8_u8; 32]);
        for name in ["native-executable.pub", "next.pub", "trust.json"] {
            std::fs::write(
                directory.path().join(name),
                alternate.verifying_key().as_bytes(),
            )
            .unwrap();
        }

        let bytes = b"fixture";
        let alternate_signature = alternate.sign(bytes).to_bytes();
        assert!(!verify_signature(
            SignatureRole::NativeExecutable,
            bytes,
            &alternate_signature,
        ));
        let embedded = SigningKey::from_bytes(&NATIVE_EXECUTABLE_TEST_SEED);
        assert!(verify_signature(
            SignatureRole::NativeExecutable,
            bytes,
            &embedded.sign(bytes).to_bytes(),
        ));
    }

    #[test]
    fn sha256_bytes_matches_known_content() {
        assert_eq!(
            sha256_bytes(b"hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn catalog_fingerprint_hashes_the_raw_ed25519_key() {
        assert_eq!(
            AGENT_CATALOG_BUILD_IDENTITY,
            format!(
                "\0VOBOOST_AGENT_CATALOG_RAW32={}\0",
                hex::encode(AGENT_CATALOG_PUBKEY)
            )
        );
        assert_eq!(
            agent_catalog_key_sha256(),
            sha256_bytes(&AGENT_CATALOG_PUBKEY)
        );
    }

    #[test]
    fn restore_fingerprint_hashes_the_embedded_raw_key() {
        assert_eq!(restore_key_sha256(), sha256_bytes(&RESTORE_PUBLIC_KEY));
        assert_ne!(RESTORE_PUBLIC_KEY, AGENT_CATALOG_PUBKEY);
        assert_ne!(RESTORE_PUBLIC_KEY, NATIVE_EXECUTABLE_PUBKEY);
        assert_ne!(RESTORE_PUBLIC_KEY, RELEASE_CATALOG_PUBKEY);
        assert_ne!(RELEASE_CATALOG_PUBKEY, AGENT_CATALOG_PUBKEY);
        assert_ne!(RELEASE_CATALOG_PUBKEY, NATIVE_EXECUTABLE_PUBKEY);
    }
}
