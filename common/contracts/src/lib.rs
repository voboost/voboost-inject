#![no_std]
//! One authenticated semantic core for Android and QNX. No filesystem or transport.
extern crate alloc;
#[cfg(test)]
extern crate std;
pub mod agent_catalog;
pub mod apk_signer;
pub mod catalog;
pub mod cluster;
pub mod cluster_log;
pub mod domain_operation;
pub mod generation;
pub mod install_layout;
pub mod lookups;
pub mod pw_live;
pub mod release;
pub mod resource_apk;
pub mod resource_compatibility;
pub mod resource_pack;
pub mod wire;

use alloc::{format, string::String, vec::Vec};
use core::fmt::Write;
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
pub type Result<T> = core::result::Result<T, String>;
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
pub const MAX_DOCUMENT_BYTES: usize = 65_536;
pub const MAX_FILE_BYTES: u64 = 67_108_864;
pub const MAX_CLOSURE_BYTES: u64 = 268_435_456;
pub fn hash(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        write!(out, "{byte:02x}").expect("String write");
    }
    out
}
pub fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
pub fn printable(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.bytes().all(|b| (0x20..=0x7e).contains(&b))
}
pub fn safe_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= 512
        && value != "/"
        && value.split('/').skip(1).all(|s| {
            identifier(s, 128)
                || (!s.is_empty()
                    && s != "."
                    && s != ".."
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)))
        })
}
pub fn basename(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
pub fn ascii_json<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    let encoded = serde_json::to_string(value).map_err(|e| format!("encode JSON: {e}"))?;
    let mut out = String::with_capacity(encoded.len() + 1);
    for c in encoded.chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            let mut words = [0u16; 2];
            for word in c.encode_utf16(&mut words) {
                write!(out, "\\u{word:04x}").expect("String write");
            }
        }
    }
    out.push('\n');
    Ok(out.into_bytes())
}
pub fn parse_canonical<T: Serialize + DeserializeOwned>(bytes: &[u8], max: usize) -> Result<T> {
    if bytes.is_empty() || bytes.len() > max || !bytes.is_ascii() || bytes.last() != Some(&b'\n') {
        return Err("document byte envelope is invalid".into());
    }
    let value: T = serde_json::from_slice(bytes).map_err(|e| format!("parse JSON: {e}"))?;
    if ascii_json(&value)? != bytes {
        return Err("document is not canonical ordered JSON".into());
    }
    Ok(value)
}
/// Remove only insignificant JSON whitespace. Strings and escapes remain exact.
/// Used for signed producer catalog2 whose indentation is not authority.
pub fn compact_catalog(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.is_empty()
        || bytes.len() > 1024 * 1024
        || !bytes.is_ascii()
        || bytes.last() != Some(&b'\n')
    {
        return Err("catalog byte envelope is invalid".into());
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut quoted = false;
    let mut escaped = false;
    for &b in bytes {
        if quoted {
            out.push(b);
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                quoted = false;
            }
        } else if b == b'"' {
            quoted = true;
            out.push(b);
        } else if !b.is_ascii_whitespace() {
            out.push(b);
        }
    }
    if quoted {
        return Err("unterminated catalog string".into());
    }
    out.push(b'\n');
    Ok(out)
}
