const BEGIN: &str = "-----BEGIN PUBLIC KEY-----";
const END: &str = "-----END PUBLIC KEY-----";
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn extract_ed25519_pubkey_from_pem(pem: &[u8]) -> Result<[u8; 32], String> {
    let pem = std::str::from_utf8(pem).map_err(|error| format!("PEM not utf8: {error}"))?;
    let pem = pem
        .strip_suffix('\n')
        .ok_or_else(|| "canonical PEM must end with exactly one LF".to_string())?;
    let mut lines = pem.split('\n');
    let begin = lines.next();
    let encoded = lines.next();
    let end = lines.next();
    if begin != Some(BEGIN) || end != Some(END) || lines.next().is_some() {
        return Err("expected one canonical three-line PUBLIC KEY PEM envelope".to_string());
    }
    let encoded = encoded.expect("three-line envelope has a payload");
    if encoded.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err("base64 payload contains whitespace".to_string());
    }
    let der = decode_canonical_base64(encoded)?;
    if der.len() != ED25519_SPKI_PREFIX.len() + 32 || !der.starts_with(&ED25519_SPKI_PREFIX) {
        return Err(format!(
            "expected canonical 44-byte Ed25519 SubjectPublicKeyInfo, got {} bytes",
            der.len()
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&der[ED25519_SPKI_PREFIX.len()..]);
    Ok(key)
}

fn decode_canonical_base64(input: &str) -> Result<Vec<u8>, String> {
    let bytes = input.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return Err("base64 length is not a nonzero multiple of four".to_string());
    }
    let padding = bytes.iter().rev().take_while(|byte| **byte == b'=').count();
    if padding > 2 || bytes[..bytes.len() - padding].contains(&b'=') {
        return Err("base64 padding is misplaced or excessive".to_string());
    }

    let mut output = Vec::with_capacity(bytes.len() / 4 * 3 - padding);
    for (index, chunk) in bytes.as_chunks::<4>().0.iter().enumerate() {
        let last = index + 1 == bytes.len() / 4;
        let expected_padding = if last { padding } else { 0 };
        let a = decode_base64_byte(chunk[0])?;
        let b = decode_base64_byte(chunk[1])?;
        let c = if expected_padding == 2 {
            0
        } else {
            decode_base64_byte(chunk[2])?
        };
        let d = if expected_padding >= 1 {
            0
        } else {
            decode_base64_byte(chunk[3])?
        };
        if (expected_padding == 2 && b & 0x0f != 0) || (expected_padding == 1 && c & 0x03 != 0) {
            return Err("base64 has nonzero unused tail bits".to_string());
        }
        output.push((a << 2) | (b >> 4));
        if expected_padding < 2 {
            output.push((b << 4) | (c >> 2));
        }
        if expected_padding == 0 {
            output.push((c << 6) | d);
        }
    }
    if encode_base64(&output) != input {
        return Err("base64 payload is not canonical".to_string());
    }
    Ok(output)
}

fn decode_base64_byte(byte: u8) -> Result<u8, String> {
    BASE64
        .iter()
        .position(|candidate| *candidate == byte)
        .map(|value| value as u8)
        .ok_or_else(|| format!("invalid base64 byte 0x{byte:02x}"))
}

fn encode_base64(input: &[u8]) -> String {
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let value = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | chunk.get(2).copied().unwrap_or(0) as u32;
        output.push(BASE64[((value >> 18) & 0x3f) as usize] as char);
        output.push(BASE64[((value >> 12) & 0x3f) as usize] as char);
        output.push(if chunk.len() > 1 {
            BASE64[((value >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            BASE64[(value & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    output
}
