//! Bounded APK Signing Block v2/v3 certificate identity for Voboost-owned APKs.

use std::fs::File;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::time::{Duration, Instant};

use anyhow::{ensure, Context, Result};
#[cfg(test)]
use sha2::{Digest, Sha256};

const APK_MAGIC: &[u8; 16] = b"APK Sig Block 42";
#[cfg(test)]
const V2_ID: u32 = 0x7109_871a;
#[cfg(test)]
const V3_ID: u32 = 0xf053_68c0;
const MAX_APK_SIZE: u64 = 1024 * 1024 * 1024;
const MAX_SIGNING_BLOCK: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileStamp {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub ctime: i64,
    pub ctime_nsec: i64,
}

impl FileStamp {
    pub fn read(file: &File) -> Result<Self> {
        let metadata = file.metadata().context("stat Voboost APK descriptor")?;
        ensure!(metadata.is_file(), "Voboost APK is not a regular file");
        ensure!(
            metadata.nlink() == 1,
            "Voboost APK has an ambiguous hard-link authority"
        );
        ensure!(
            metadata.len() > 0 && metadata.len() <= MAX_APK_SIZE,
            "Voboost APK size is unsafe"
        );
        Ok(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: metadata.len(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        })
    }
}

fn check_deadline(deadline: Instant) -> Result<()> {
    ensure!(Instant::now() < deadline, "APK signer observation deadline");
    Ok(())
}

fn read_exact_at(file: &File, offset: u64, size: usize, deadline: Instant) -> Result<Vec<u8>> {
    check_deadline(deadline)?;
    ensure!(size <= MAX_SIGNING_BLOCK, "APK signing read exceeds bound");
    let mut bytes = vec![0; size];
    for (index, chunk) in bytes.chunks_mut(64 * 1024).enumerate() {
        check_deadline(deadline)?;
        let offset = offset
            .checked_add(index as u64 * 64 * 1024)
            .context("APK read offset overflow")?;
        file.read_exact_at(chunk, offset)
            .context("pread Voboost APK")?;
        check_deadline(deadline)?;
    }
    Ok(bytes)
}

#[cfg(test)]
use voboost_contract_core::apk_signer::signer_sha256_from_block as signing_digest;
fn le32(bytes: &[u8]) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes.try_into().context("truncated u32")?,
    ))
}
fn le16(bytes: &[u8]) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes.try_into().context("truncated u16")?,
    ))
}
fn le64(bytes: &[u8]) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes.try_into().context("truncated u64")?,
    ))
}

fn signing_block_offset(file: &File, size: u64, deadline: Instant) -> Result<u64> {
    let tail_size = size.min(65_557) as usize;
    let tail_offset = size - tail_size as u64;
    let tail = read_exact_at(file, tail_offset, tail_size, deadline)?;
    let eocd = tail
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .context("ZIP EOCD missing")?;
    check_deadline(deadline)?;
    ensure!(
        eocd + 22 <= tail.len()
            && eocd + 22 + le16(&tail[eocd + 20..eocd + 22])? as usize == tail.len(),
        "non-canonical EOCD"
    );
    ensure!(
        le16(&tail[eocd + 4..eocd + 6])? == 0 && le16(&tail[eocd + 6..eocd + 8])? == 0,
        "multi-disk APK rejected"
    );
    Ok(le32(&tail[eocd + 16..eocd + 20])? as u64)
}

pub fn signer_sha256_v2_v3(file: &File, stamp: FileStamp) -> Result<[u8; 32]> {
    signer_sha256_v2_v3_until(file, stamp, Instant::now() + Duration::from_secs(15))
}

pub fn signer_sha256_v2_v3_until(
    file: &File,
    stamp: FileStamp,
    deadline: Instant,
) -> Result<[u8; 32]> {
    check_deadline(deadline)?;
    let central_directory = signing_block_offset(file, stamp.size, deadline)?;
    ensure!(central_directory >= 24, "signing footer missing");
    let footer = read_exact_at(file, central_directory - 24, 24, deadline)?;
    ensure!(&footer[8..] == APK_MAGIC, "signing footer magic invalid");
    let declared = usize::try_from(le64(&footer[..8])?).context("signing size overflow")?;
    let total = declared.checked_add(8).context("signing size overflow")?;
    ensure!(
        total <= MAX_SIGNING_BLOCK && total as u64 <= central_directory,
        "signing block exceeds bound"
    );
    let bytes = read_exact_at(file, central_directory - total as u64, total, deadline)?;
    voboost_contract_core::apk_signer::signer_sha256_from_block_checked(&bytes, &mut || {
        check_deadline(deadline).map_err(|error| error.to_string())
    })
    .map_err(anyhow::Error::msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_signer_checks_the_shared_deadline_before_io() {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new_in(std::env::current_dir().unwrap()).unwrap();
        file.write_all(&apk(&[(V2_ID, b"certificate")])).unwrap();
        let stamp = FileStamp::read(file.as_file()).unwrap();
        assert!(
            signer_sha256_v2_v3_until(file.as_file(), stamp, Instant::now())
                .unwrap_err()
                .to_string()
                .contains("deadline")
        );
        assert!(signer_sha256_v2_v3_until(
            file.as_file(),
            stamp,
            Instant::now() + Duration::from_secs(1)
        )
        .is_ok());
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
        use std::io::Write;

        let certificate = b"real-layout DER certificate";
        let bytes = apk(&[(0x1234_5678, b"ignored"), (V2_ID, certificate)]);
        let mut fixture = tempfile::NamedTempFile::new().unwrap();
        fixture.write_all(&bytes).unwrap();
        let file = fixture.as_file();
        let stamp = FileStamp::read(file).unwrap();
        let expected: [u8; 32] = Sha256::digest(certificate).into();
        assert_eq!(signer_sha256_v2_v3(file, stamp).unwrap(), expected);
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
            use std::io::Write;
            let mut fixture = tempfile::NamedTempFile::new().unwrap();
            fixture.write_all(&bytes).unwrap();
            let file = fixture.as_file();
            let stamp = FileStamp::read(file).unwrap();
            assert_eq!(signer_sha256_v2_v3(file, stamp).is_ok(), accepted);
        }
    }
}
