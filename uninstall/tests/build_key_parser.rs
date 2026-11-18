#[path = "../../build_support/strict_ed25519_spki.rs"]
mod build_key;
#[path = "../../build_support/strict_hex32.rs"]
mod strict_hex32;

const PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

#[test]
fn build_cache_tracks_the_embedded_android_certificate_authority() {
    let source = include_str!("../build.rs");
    assert!(source.contains("cargo:rerun-if-env-changed=VOBOOST_ANDROID_CERT_SHA256"));
}

fn encode_base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();
    for chunk in input.chunks(3) {
        let value = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | chunk.get(2).copied().unwrap_or(0) as u32;
        output.push(TABLE[((value >> 18) & 0x3f) as usize] as char);
        output.push(TABLE[((value >> 12) & 0x3f) as usize] as char);
        output.push(if chunk.len() > 1 {
            TABLE[((value >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            TABLE[(value & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    output
}

fn pem(der: &[u8]) -> Vec<u8> {
    format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        encode_base64(der)
    )
    .into_bytes()
}

#[test]
fn accepts_only_canonical_ed25519_spki() {
    let key = [0x5au8; 32];
    let mut der = PREFIX.to_vec();
    der.extend_from_slice(&key);
    assert_eq!(
        build_key::extract_ed25519_pubkey_from_pem(&pem(&der)),
        Ok(key)
    );
}

#[test]
fn rejects_noncanonical_spki_prefix_and_length() {
    let mut wrong_prefix = PREFIX.to_vec();
    wrong_prefix[8] ^= 1;
    wrong_prefix.extend_from_slice(&[0x5a; 32]);
    assert!(build_key::extract_ed25519_pubkey_from_pem(&pem(&wrong_prefix)).is_err());

    let mut oversized = PREFIX.to_vec();
    oversized.extend_from_slice(&[0x5a; 33]);
    assert!(build_key::extract_ed25519_pubkey_from_pem(&pem(&oversized)).is_err());
}

#[test]
fn rejects_malformed_or_foreign_pem_envelopes() {
    let mut der = PREFIX.to_vec();
    der.extend_from_slice(&[0x5a; 32]);
    let encoded = encode_base64(&der);
    for malformed in [
        format!("{encoded}\n"),
        format!("-----BEGIN PRIVATE KEY-----\n{encoded}\n-----END PRIVATE KEY-----\n"),
        format!(
            "-----BEGIN PUBLIC KEY-----\n{encoded}\n-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n"
        ),
        "-----BEGIN PUBLIC KEY-----\n!\n-----END PUBLIC KEY-----\n".to_string(),
    ] {
        assert!(build_key::extract_ed25519_pubkey_from_pem(malformed.as_bytes()).is_err());
    }
}

#[test]
fn rejects_noncanonical_base64_and_pem_spelling() {
    let mut der = PREFIX.to_vec();
    der.extend_from_slice(&[0x5a; 32]);
    let encoded = encode_base64(&der);
    let mut nonzero_tail_bits = encoded.clone();
    nonzero_tail_bits.replace_range(encoded.len() - 2..encoded.len() - 1, "p");
    for malformed in [
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            encoded.trim_end_matches('=')
        ),
        format!("-----BEGIN PUBLIC KEY-----\n={encoded}\n-----END PUBLIC KEY-----\n"),
        format!("-----BEGIN PUBLIC KEY-----\n{encoded}=\n-----END PUBLIC KEY-----\n"),
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n{}\n-----END PUBLIC KEY-----\n",
            &encoded[..32],
            &encoded[32..]
        ),
        format!("-----BEGIN PUBLIC KEY-----\n{nonzero_tail_bits}\n-----END PUBLIC KEY-----\n"),
        format!("-----BEGIN PUBLIC KEY-----\r\n{encoded}\r\n-----END PUBLIC KEY-----\r\n"),
        format!("-----BEGIN PUBLIC KEY-----\n{encoded}\n-----END PUBLIC KEY-----"),
        format!("-----BEGIN PUBLIC KEY-----\n{encoded}\n-----END PUBLIC KEY-----\n\n"),
        format!("-----BEGIN PUBLIC KEY-----\n{encoded}\n-----END PUBLIC KEY-----\ntrailing"),
    ] {
        assert!(build_key::extract_ed25519_pubkey_from_pem(malformed.as_bytes()).is_err());
    }
}

#[test]
fn android_certificate_identity_requires_canonical_lowercase_hex() {
    assert!(strict_hex32::parse_lower_hex32(&"ab".repeat(32)).is_ok());
    assert!(strict_hex32::parse_lower_hex32(&"AB".repeat(32)).is_err());
    assert!(strict_hex32::parse_lower_hex32(&"ab".repeat(31)).is_err());
    assert!(strict_hex32::parse_lower_hex32(&format!("{}g0", "ab".repeat(31))).is_err());
}
