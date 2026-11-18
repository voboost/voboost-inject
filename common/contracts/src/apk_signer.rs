//! Bounded APK v2/v3 certificate identity parsing shared by host and resident code.
//! This extracts signer identity; it does not verify APK cryptographic signatures.
use alloc::{
    collections::BTreeSet,
    string::{String, ToString},
};
use sha2::{Digest, Sha256};
type Result<T> = core::result::Result<T, String>;
const APK_MAGIC: &[u8; 16] = b"APK Sig Block 42";
const V2_ID: u32 = 0x7109_871a;
const V3_ID: u32 = 0xf053_68c0;
const MAX_SIGNING_BLOCK: usize = 16 * 1024 * 1024;
macro_rules! ensure {
    ($condition:expr, $message:literal $(,)?) => {
        if !$condition {
            return Err($message.to_string());
        }
    };
}
fn le16(bytes: &[u8]) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes.try_into().map_err(|_| "truncated u16".to_string())?,
    ))
}

fn le32(bytes: &[u8]) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes.try_into().map_err(|_| "truncated u32".to_string())?,
    ))
}

fn le64(bytes: &[u8]) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes.try_into().map_err(|_| "truncated u64".to_string())?,
    ))
}

fn length_prefixed<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8]> {
    ensure!(bytes.len() >= 4, "signing field is truncated");
    let size = le32(&bytes[..4])? as usize;
    ensure!(size <= bytes.len() - 4, "signing field exceeds container");
    let value = &bytes[4..4 + size];
    *bytes = &bytes[4 + size..];
    Ok(value)
}

fn fixed32(bytes: &mut &[u8]) -> Result<u32> {
    ensure!(bytes.len() >= 4, "SDK field truncated");
    let value = le32(&bytes[..4])?;
    *bytes = &bytes[4..];
    Ok(value)
}

fn certificate<'a>(
    value: &'a [u8],
    v3: bool,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<&'a [u8]> {
    check()?;
    // The scheme value is a length-prefixed sequence containing one or more
    // length-prefixed signer records. Voboost admits exactly one signer.
    let mut container = value;
    let mut signers = length_prefixed(&mut container)?;
    ensure!(container.is_empty(), "signer container has trailing data");
    let mut signer = length_prefixed(&mut signers)?;
    ensure!(signers.is_empty(), "multi-signer APK is rejected");
    let mut signed = length_prefixed(&mut signer)?;
    let _digests = length_prefixed(&mut signed)?;
    let mut certificates = length_prefixed(&mut signed)?;
    let certificate = length_prefixed(&mut certificates)?;
    ensure!(!certificate.is_empty(), "signer certificate is empty");
    while !certificates.is_empty() {
        check()?;
        ensure!(
            !length_prefixed(&mut certificates)?.is_empty(),
            "certificate chain contains an empty certificate"
        );
    }
    if v3 {
        let min = fixed32(&mut signed)?;
        let max = fixed32(&mut signed)?;
        let _attributes = length_prefixed(&mut signed)?;
        ensure!(
            min <= max && min == fixed32(&mut signer)? && max == fixed32(&mut signer)?,
            "v3 SDK bounds disagree"
        );
    } else {
        let _attributes = length_prefixed(&mut signed)?;
    }
    // Current AOSP apksig emits one additional empty length-prefixed element
    // after the v2 additional-attributes sequence. Android's v2 verifier
    // tolerates it. Accept only that exact four-byte empty extension; never
    // accept arbitrary signer trailing data.
    if !v3 && signed == [0, 0, 0, 0] {
        signed = &[];
    }
    let _signatures = length_prefixed(&mut signer)?;
    let public_key = length_prefixed(&mut signer)?;
    ensure!(
        !public_key.is_empty() && signed.is_empty() && signer.is_empty(),
        "signer structure has trailing data"
    );
    Ok(certificate)
}

pub fn signer_sha256_from_block(block: &[u8]) -> Result<[u8; 32]> {
    signer_sha256_from_block_checked(block, &mut || Ok(()))
}

pub fn signer_sha256_from_block_checked(
    block: &[u8],
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<[u8; 32]> {
    check()?;
    ensure!(
        block.len() >= 32
            && block.len() <= MAX_SIGNING_BLOCK
            && &block[block.len() - 16..] == APK_MAGIC,
        "APK signing magic invalid"
    );
    let declared =
        usize::try_from(le64(&block[..8])?).map_err(|_| "signing size overflow".to_string())?;
    ensure!(
        declared.checked_add(8) == Some(block.len())
            && le64(&block[block.len() - 24..block.len() - 16])? == declared as u64,
        "signing sizes disagree"
    );
    let mut pairs = &block[8..block.len() - 24];
    let mut accepted: Option<&[u8]> = None;
    let mut seen = BTreeSet::new();
    while !pairs.is_empty() {
        check()?;
        ensure!(pairs.len() >= 12, "signing pair truncated");
        let size =
            usize::try_from(le64(&pairs[..8])?).map_err(|_| "pair size overflow".to_string())?;
        ensure!(size >= 4 && size <= pairs.len() - 8, "signing pair invalid");
        let id = le32(&pairs[8..12])?;
        if id == V2_ID || id == V3_ID {
            ensure!(seen.insert(id), "duplicate signing scheme");
            let current = certificate(&pairs[12..8 + size], id == V3_ID, check)?;
            if let Some(previous) = accepted {
                ensure!(previous == current, "v2/v3 certificates disagree");
            }
            accepted = Some(current);
        }
        pairs = &pairs[8 + size..];
    }
    let certificate = accepted.ok_or_else(|| "no APK v2/v3 signer".to_string())?;
    let mut digest = Sha256::new();
    for chunk in certificate.chunks(64 * 1024) {
        check()?;
        digest.update(chunk);
    }
    check()?;
    Ok(digest.finalize().into())
}

/// Inspect exact product-authenticated bytes without an OS filesystem dependency.
pub fn signer_sha256_v2_v3_bytes(apk: &[u8]) -> Result<[u8; 32]> {
    ensure!(
        (22..=1024 * 1024 * 1024).contains(&apk.len()),
        "APK bytes exceed bound"
    );
    let tail_start = apk.len().saturating_sub(65_557);
    let tail = &apk[tail_start..];
    let eocd = tail
        .windows(4)
        .rposition(|w| w == b"PK\x05\x06")
        .ok_or_else(|| "ZIP EOCD missing".to_string())?;
    ensure!(eocd + 22 <= tail.len(), "truncated EOCD");
    ensure!(
        eocd + 22 + le16(&tail[eocd + 20..eocd + 22])? as usize == tail.len(),
        "non-canonical EOCD"
    );
    ensure!(
        le16(&tail[eocd + 4..eocd + 6])? == 0 && le16(&tail[eocd + 6..eocd + 8])? == 0,
        "multi-disk APK rejected"
    );
    let central = le32(&tail[eocd + 16..eocd + 20])? as usize;
    ensure!(
        central >= 24 && central <= tail_start + eocd,
        "APK signing directory bounds"
    );
    let footer = &apk[central - 24..central];
    ensure!(&footer[8..] == APK_MAGIC, "signing footer magic invalid");
    let declared =
        usize::try_from(le64(&footer[..8])?).map_err(|_| "signing size overflow".to_string())?;
    let total = declared
        .checked_add(8)
        .ok_or_else(|| "signing size overflow".to_string())?;
    ensure!(
        total <= MAX_SIGNING_BLOCK && total <= central,
        "signing block exceeds bound"
    );
    signer_sha256_from_block(&apk[central - total..central])
}

#[cfg(test)]
mod tests {
    use super::signer_sha256_from_block as signing_digest;
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn checked_parser_stops_inside_a_long_valid_pair_sequence() {
        let unknown = signing_block(b"ignored", 0x1234_5678);
        let known = signing_block(b"certificate", V2_ID);
        let mut pairs = unknown[8..unknown.len() - 24].repeat(100);
        pairs.extend_from_slice(&known[8..known.len() - 24]);
        let size = (pairs.len() + 24) as u64;
        let mut block = size.to_le_bytes().to_vec();
        block.extend_from_slice(&pairs);
        block.extend_from_slice(&size.to_le_bytes());
        block.extend_from_slice(APK_MAGIC);
        assert!(signer_sha256_from_block(&block).is_ok());
        let mut checkpoints = 0;
        let error = signer_sha256_from_block_checked(&block, &mut || {
            checkpoints += 1;
            if checkpoints >= 20 {
                Err("deadline".to_string())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(error, "deadline");
        assert_eq!(checkpoints, 20);
    }

    fn lp(value: &[u8]) -> Vec<u8> {
        let mut encoded = (value.len() as u32).to_le_bytes().to_vec();
        encoded.extend_from_slice(value);
        encoded
    }

    fn signing_block_with_v2_extension(
        certificate: &[u8],
        id: u32,
        v2_extension: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut signed_data = lp(b"digests");
        signed_data.extend_from_slice(&lp(&lp(certificate)));
        if id == V3_ID {
            signed_data.extend_from_slice(&28_u32.to_le_bytes());
            signed_data.extend_from_slice(&35_u32.to_le_bytes());
        }
        signed_data.extend_from_slice(&lp(b"attributes"));
        if id == V2_ID {
            if let Some(extension) = v2_extension {
                signed_data.extend_from_slice(&lp(extension));
            }
        }
        let mut signer = lp(&signed_data);
        if id == V3_ID {
            signer.extend_from_slice(&28_u32.to_le_bytes());
            signer.extend_from_slice(&35_u32.to_le_bytes());
        }
        signer.extend_from_slice(&lp(b"signatures"));
        signer.extend_from_slice(&lp(b"public-key"));
        let mut pair = id.to_le_bytes().to_vec();
        pair.extend_from_slice(&lp(&lp(&signer)));
        let mut pairs = (pair.len() as u64).to_le_bytes().to_vec();
        pairs.extend_from_slice(&pair);
        let size = (pairs.len() + 24) as u64;
        let mut block = size.to_le_bytes().to_vec();
        block.append(&mut pairs);
        block.extend_from_slice(&size.to_le_bytes());
        block.extend_from_slice(APK_MAGIC);
        block
    }

    fn signing_block(certificate: &[u8], id: u32) -> Vec<u8> {
        signing_block_with_v2_extension(certificate, id, Some(b""))
    }

    fn apk(schemes: &[(u32, &[u8])]) -> Vec<u8> {
        let mut pairs = Vec::new();
        for (id, signer_certificate) in schemes {
            let block = signing_block(signer_certificate, *id);
            pairs.extend_from_slice(&block[8..block.len() - 24]);
        }
        let size = (pairs.len() + 24) as u64;
        let mut signing = size.to_le_bytes().to_vec();
        signing.extend_from_slice(&pairs);
        signing.extend_from_slice(&size.to_le_bytes());
        signing.extend_from_slice(APK_MAGIC);

        let mut value = b"PK\x03\x04deterministic-voboost-apk".to_vec();
        value.extend_from_slice(&signing);
        let central_directory = value.len() as u32;
        value.extend_from_slice(b"PK\x05\x06");
        value.extend_from_slice(&[0; 12]);
        value.extend_from_slice(&central_directory.to_le_bytes());
        value.extend_from_slice(&0_u16.to_le_bytes());
        assert_eq!(value.len(), central_directory as usize + 22);
        value
    }

    #[test]
    fn apk_signer_binding_accepts_one_v2_or_v3_certificate_and_rejects_substitution() {
        let certificate = b"bounded DER certificate fixture";
        let expected: [u8; 32] = Sha256::digest(certificate).into();
        assert_eq!(
            signing_digest(&signing_block(certificate, V2_ID)).unwrap(),
            expected
        );
        assert_eq!(
            signing_digest(&signing_block(certificate, V3_ID)).unwrap(),
            expected
        );
        assert_ne!(
            signing_digest(&signing_block(b"different certificate", V3_ID)).unwrap(),
            expected
        );
        assert!(signing_digest(&signing_block(certificate, 0x1234_5678)).is_err());
    }

    #[test]
    fn rejects_malformed_authority_inputs() {
        assert!(signing_digest(b"").is_err());
        let mut truncated = signing_block(b"certificate", V2_ID);
        truncated.pop();
        assert!(signing_digest(&truncated).is_err());
        let mut inconsistent = signing_block(b"certificate", V2_ID);
        inconsistent[0] ^= 1;
        assert!(signing_digest(&inconsistent).is_err());
    }

    #[test]
    fn whole_apk_v2_signer_matches_certificate_and_unknown_pairs_are_ignored() {
        let certificate = b"real-layout DER certificate";
        let bytes = apk(&[(0x1234_5678, b"ignored"), (V2_ID, certificate)]);
        let expected: [u8; 32] = Sha256::digest(certificate).into();
        assert_eq!(signer_sha256_v2_v3_bytes(&bytes).unwrap(), expected);
    }

    #[test]
    fn one_signer_and_scheme_lengths_are_strict() {
        let certificate = b"certificate";
        let mut duplicate_signer = signing_block(certificate, V2_ID);
        let signer_pair = duplicate_signer[24..duplicate_signer.len() - 24].to_vec();
        let signers_size = le32(&duplicate_signer[20..24]).unwrap() + signer_pair.len() as u32;
        duplicate_signer[20..24].copy_from_slice(&signers_size.to_le_bytes());
        let pair_size = le64(&duplicate_signer[8..16]).unwrap() + signer_pair.len() as u64;
        duplicate_signer[8..16].copy_from_slice(&pair_size.to_le_bytes());
        let insertion = duplicate_signer.len() - 24;
        duplicate_signer.splice(insertion..insertion, signer_pair);
        let declared = (duplicate_signer.len() - 8) as u64;
        duplicate_signer[..8].copy_from_slice(&declared.to_le_bytes());
        let footer = duplicate_signer.len() - 24;
        duplicate_signer[footer..footer + 8].copy_from_slice(&declared.to_le_bytes());
        assert!(signing_digest(&duplicate_signer).is_err());

        let mut duplicate_scheme = signing_block(certificate, V2_ID);
        let pair = duplicate_scheme[8..duplicate_scheme.len() - 24].to_vec();
        let insertion = duplicate_scheme.len() - 24;
        duplicate_scheme.splice(insertion..insertion, pair);
        let declared = (duplicate_scheme.len() - 8) as u64;
        duplicate_scheme[..8].copy_from_slice(&declared.to_le_bytes());
        let footer = duplicate_scheme.len() - 24;
        duplicate_scheme[footer..footer + 8].copy_from_slice(&declared.to_le_bytes());
        assert!(signing_digest(&duplicate_scheme).is_err());

        let mut malformed_pair = signing_block(certificate, V2_ID);
        malformed_pair[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(signing_digest(&malformed_pair).is_err());
        assert!(signing_digest(&signing_block(certificate, 0x1234_5678)).is_err());
    }

    #[test]
    fn v2_accepts_documented_and_apksig_empty_forms_but_rejects_other_trailing_data() {
        let certificate = b"certificate";
        let expected: [u8; 32] = Sha256::digest(certificate).into();
        assert_eq!(
            signing_digest(&signing_block_with_v2_extension(certificate, V2_ID, None)).unwrap(),
            expected
        );
        assert_eq!(
            signing_digest(&signing_block_with_v2_extension(
                certificate,
                V2_ID,
                Some(b"")
            ))
            .unwrap(),
            expected
        );
        assert!(signing_digest(&signing_block_with_v2_extension(
            certificate,
            V2_ID,
            Some(b"unexpected")
        ))
        .is_err());
    }

    #[test]
    fn v2_v3_must_bind_the_same_single_certificate() {
        let matching = apk(&[(V2_ID, b"same"), (V3_ID, b"same")]);
        let mismatching = apk(&[(V2_ID, b"v2"), (V3_ID, b"v3")]);
        for (bytes, accepted) in [(matching, true), (mismatching, false)] {
            assert_eq!(signer_sha256_v2_v3_bytes(&bytes).is_ok(), accepted);
        }
    }
    #[test]
    fn rejects_footer_size_with_nonzero_high_word() {
        let mut b = signing_block(b"certificate", V2_ID);
        let offset = b.len() - 24;
        let declared = le64(&b[offset..offset + 8]).unwrap() | (1u64 << 32);
        b[offset..offset + 8].copy_from_slice(&declared.to_le_bytes());
        assert!(signer_sha256_from_block(&b).is_err());
    }
    #[test]
    fn bounds_public_block_api() {
        assert!(signer_sha256_from_block(&alloc::vec![0;MAX_SIGNING_BLOCK+1]).is_err());
    }
}
