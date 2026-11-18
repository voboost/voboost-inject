const DOMAIN: &[u8] = b"voboost-native-executable-v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub enum NativeExecutableRole {
    Daemon,
    Inject,
    Install,
    Restore,
    Uninstall,
    Selinux,
}

impl NativeExecutableRole {
    fn bytes(self) -> &'static [u8] {
        match self {
            Self::Daemon => b"daemon",
            Self::Inject => b"inject",
            Self::Install => b"install",
            Self::Restore => b"restore",
            Self::Uninstall => b"uninstall",
            Self::Selinux => b"selinux",
        }
    }
}

pub fn transcript(role: NativeExecutableRole, elf: &[u8]) -> Option<Vec<u8>> {
    let length = u64::try_from(elf.len()).ok()?;
    let capacity = DOMAIN
        .len()
        .checked_add(role.bytes().len())?
        .checked_add(9)?
        .checked_add(elf.len())?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(role.bytes());
    bytes.push(0);
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(elf);
    Some(bytes)
}

/// Verify the role-bound trailer of the exact supplied executable bytes.
pub fn verify(key: &[u8; 32], role: NativeExecutableRole, bytes: &[u8]) -> bool {
    const TRAILER: usize = 80;
    if bytes.len() <= TRAILER {
        return false;
    }
    let end = bytes.len() - TRAILER;
    if &bytes[end..end + 8] != b"VOBOOST\0" {
        return false;
    }
    let Ok(length) = <[u8; 8]>::try_from(&bytes[end + 8..end + 16]) else {
        return false;
    };
    if u64::from_le_bytes(length) != end as u64 {
        return false;
    }
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(key) else {
        return false;
    };
    let Ok(signature) = ed25519_dalek::Signature::from_slice(&bytes[end + 16..]) else {
        return false;
    };
    transcript(role, &bytes[..end])
        .is_some_and(|input| key.verify_strict(&input, &signature).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn appended_bytes_reject_role_key_content_and_trailer_changes() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let prefix = b"\x7fELFfixture";
        let mut signed = prefix.to_vec();
        signed.extend_from_slice(b"VOBOOST\0");
        signed.extend_from_slice(&(prefix.len() as u64).to_le_bytes());
        signed.extend_from_slice(
            &key.sign(&transcript(NativeExecutableRole::Inject, prefix).unwrap())
                .to_bytes(),
        );
        let public = key.verifying_key().to_bytes();
        assert!(verify(&public, NativeExecutableRole::Inject, &signed));
        assert!(!verify(&public, NativeExecutableRole::Daemon, &signed));
        assert!(!verify(
            &SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
            NativeExecutableRole::Inject,
            &signed
        ));
        for index in [0, prefix.len(), prefix.len() + 8, signed.len() - 1] {
            let mut changed = signed.clone();
            changed[index] ^= 1;
            assert!(!verify(&public, NativeExecutableRole::Inject, &changed));
        }
        for end in [0, 80, signed.len() - 1] {
            assert!(!verify(
                &public,
                NativeExecutableRole::Inject,
                &signed[..end]
            ));
        }
    }

    #[test]
    fn role_signatures_are_not_interchangeable() {
        let elf = b"\x7fELFfixture";
        let roles = [
            NativeExecutableRole::Daemon,
            NativeExecutableRole::Inject,
            NativeExecutableRole::Install,
            NativeExecutableRole::Restore,
            NativeExecutableRole::Uninstall,
            NativeExecutableRole::Selinux,
        ];
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let signatures: Vec<_> = roles
            .iter()
            .map(|role| signing_key.sign(&transcript(*role, elf).unwrap()))
            .collect();
        for (expected_index, expected) in roles.iter().enumerate() {
            let expected_transcript = transcript(*expected, elf).unwrap();
            for (actual_index, signature) in signatures.iter().enumerate() {
                assert_eq!(
                    verifying_key
                        .verify_strict(&expected_transcript, signature)
                        .is_ok(),
                    expected_index == actual_index,
                );
            }
        }
        let daemon = transcript(NativeExecutableRole::Daemon, elf).unwrap();
        assert!(daemon.ends_with(elf));
        assert!(daemon
            .windows(8)
            .any(|bytes| bytes == (elf.len() as u64).to_le_bytes()));
    }
}
