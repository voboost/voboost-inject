//! Process-local verification of pinned executable identities.
use super::{invalid, stamp, File, Metadata, NativeExecutableRole, Stamp};
use std::io::{self, Read};

#[cfg(any(target_os = "android", target_os = "linux"))]
pub(super) fn authenticate(
    role: NativeExecutableRole,
    file: File,
    current: impl FnMut() -> io::Result<Metadata>,
    verify: impl FnOnce(NativeExecutableRole, &[u8]) -> bool,
) -> io::Result<()> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<Cache>> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| invalid())?
        .verify(role, file, current, verify)
}

struct Entry {
    identity: Stamp,
    file: File,
}

#[derive(Default)]
struct Cache {
    entries: [Option<Entry>; 2],
}
impl Cache {
    fn verify(
        &mut self,
        role: NativeExecutableRole,
        mut file: File,
        mut current: impl FnMut() -> io::Result<Metadata>,
        verify: impl FnOnce(NativeExecutableRole, &[u8]) -> bool,
    ) -> io::Result<()> {
        let slot = match role {
            NativeExecutableRole::Daemon => 0,
            NativeExecutableRole::Inject => 1,
            _ => return Err(invalid()),
        };
        let before = stamp(&file.metadata()?);
        if before != stamp(&current()?) {
            return Err(invalid());
        }
        if let Some(entry) = &self.entries[slot] {
            if entry.identity == before
                && stamp(&entry.file.metadata()?) == before
                && stamp(&file.metadata()?) == before
                && stamp(&current()?) == before
            {
                return Ok(());
            }
        }
        self.entries[slot] = None;
        let mut bytes = Vec::new();
        (&mut file)
            .take(crate::config::MAX_NATIVE_EXECUTABLE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != before.size
            || !verify(role, &bytes)
            || stamp(&file.metadata()?) != before
            || stamp(&current()?) != before
        {
            return Err(invalid());
        }
        self.entries[slot] = Some(Entry {
            identity: before,
            file,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::Seek;
    use std::os::unix::fs::MetadataExt;

    fn fixture() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix(".peer-test-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap()
    }

    #[test]
    fn unchanged_executable_is_verified_once_and_not_read_again() {
        let dir = fixture();
        let path = dir.path().join("executable");
        std::fs::write(&path, b"signed executable").unwrap();
        let calls = Cell::new(0);
        let mut cache = Cache::default();
        for _ in 0..2 {
            let file = File::open(&path).unwrap();
            let mut probe = file.try_clone().unwrap();
            let prior = calls.get();
            cache
                .verify(
                    NativeExecutableRole::Inject,
                    file,
                    || std::fs::metadata(&path),
                    |role, bytes| {
                        assert_eq!(role, NativeExecutableRole::Inject);
                        calls.set(calls.get() + 1);
                        bytes == b"signed executable"
                    },
                )
                .unwrap();
            if prior > 0 {
                assert_eq!(probe.stream_position().unwrap(), 0);
            }
        }
        assert_eq!(calls.get(), 1);
    }

    fn verify(cache: &mut Cache, path: &std::path::Path, calls: &Cell<usize>) -> io::Result<()> {
        cache.verify(
            NativeExecutableRole::Inject,
            File::open(path)?,
            || std::fs::metadata(path),
            |_, bytes| {
                calls.set(calls.get() + 1);
                bytes == b"signed executable"
            },
        )
    }

    #[test]
    fn replaced_inode_with_identical_bytes_is_verified_again() {
        let dir = fixture();
        let path = dir.path().join("executable");
        let replacement = dir.path().join("replacement");
        std::fs::write(&path, b"signed executable").unwrap();
        let calls = Cell::new(0);
        let mut cache = Cache::default();
        verify(&mut cache, &path, &calls).unwrap();
        let old_inode = cache.entries[1]
            .as_ref()
            .unwrap()
            .file
            .metadata()
            .unwrap()
            .ino();
        std::fs::write(&replacement, b"signed executable").unwrap();
        std::fs::rename(replacement, &path).unwrap();
        assert_ne!(std::fs::metadata(&path).unwrap().ino(), old_inode);
        verify(&mut cache, &path, &calls).unwrap();
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn changed_content_or_metadata_cannot_reuse_verification() {
        use std::os::unix::fs::PermissionsExt;
        let dir = fixture();
        let path = dir.path().join("executable");
        std::fs::write(&path, b"signed executable").unwrap();
        let calls = Cell::new(0);
        let mut cache = Cache::default();
        verify(&mut cache, &path, &calls).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        verify(&mut cache, &path, &calls).unwrap();
        assert_eq!(calls.get(), 2);
        std::fs::write(&path, b"unsigned executable").unwrap();
        assert!(verify(&mut cache, &path, &calls).is_err());
        assert!(cache.entries[1].is_none());
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn role_verifications_are_independent_and_failed_signatures_are_not_cached() {
        let dir = fixture();
        let path = dir.path().join("executable");
        std::fs::write(&path, b"signed executable").unwrap();
        let calls = Cell::new(0);
        let mut cache = Cache::default();
        verify(&mut cache, &path, &calls).unwrap();
        for _ in 0..2 {
            assert!(cache
                .verify(
                    NativeExecutableRole::Daemon,
                    File::open(&path).unwrap(),
                    || std::fs::metadata(&path),
                    |role, _| {
                        assert_eq!(role, NativeExecutableRole::Daemon);
                        calls.set(calls.get() + 1);
                        false
                    }
                )
                .is_err());
        }
        assert_eq!(calls.get(), 3);
        verify(&mut cache, &path, &calls).unwrap();
        assert_eq!(calls.get(), 3);
        assert!(cache.entries[0].is_none());
        assert!(cache.entries[1].is_some());
        assert!(cache
            .verify(
                NativeExecutableRole::Install,
                File::open(&path).unwrap(),
                || std::fs::metadata(&path),
                |_, _| panic!("unsupported role")
            )
            .is_err());
    }

    #[test]
    fn changed_proc_target_is_rejected_even_with_a_warm_cache() {
        let dir = fixture();
        let path = dir.path().join("executable");
        let other = dir.path().join("other");
        std::fs::write(&path, b"signed executable").unwrap();
        std::fs::write(&other, b"signed executable").unwrap();
        let calls = Cell::new(0);
        let mut cache = Cache::default();
        verify(&mut cache, &path, &calls).unwrap();
        assert!(cache
            .verify(
                NativeExecutableRole::Inject,
                File::open(&path).unwrap(),
                || std::fs::metadata(&other),
                |_, _| panic!("different executable must be rejected")
            )
            .is_err());
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn metadata_failure_never_becomes_a_cache_hit() {
        let dir = fixture();
        let path = dir.path().join("executable");
        std::fs::write(&path, b"signed executable").unwrap();
        let calls = Cell::new(0);
        let mut cache = Cache::default();
        verify(&mut cache, &path, &calls).unwrap();
        assert!(cache
            .verify(
                NativeExecutableRole::Inject,
                File::open(&path).unwrap(),
                || Err(io::Error::from(io::ErrorKind::NotFound)),
                |_, _| panic!("missing executable must be rejected")
            )
            .is_err());
    }

    #[test]
    fn mutation_during_signature_check_is_rejected_and_not_cached() {
        let dir = fixture();
        let path = dir.path().join("executable");
        std::fs::write(&path, b"signed executable").unwrap();
        let mut cache = Cache::default();
        assert!(cache
            .verify(
                NativeExecutableRole::Inject,
                File::open(&path).unwrap(),
                || std::fs::metadata(&path),
                |_, bytes| {
                    assert_eq!(bytes, b"signed executable");
                    std::fs::write(&path, b"changed executable").unwrap();
                    true
                }
            )
            .is_err());
        assert!(cache.entries[1].is_none());
    }
    #[test]
    fn real_role_bound_signature_is_preserved_across_hits_and_replacements() {
        use ed25519_dalek::{Signer, SigningKey};
        let dir = fixture();
        let path = dir.path().join("executable");
        let key = SigningKey::from_bytes(&[7; 32]);
        let public = key.verifying_key().to_bytes();
        let role = NativeExecutableRole::Inject;
        let prefix = b"\x7fELFpeer-fixture";
        let mut signed = prefix.to_vec();
        signed.extend_from_slice(b"VOBOOST\0");
        signed.extend_from_slice(&(prefix.len() as u64).to_le_bytes());
        signed.extend_from_slice(
            &key.sign(&crate::native_executable_signature::transcript(role, prefix).unwrap())
                .to_bytes(),
        );
        std::fs::write(&path, &signed).unwrap();
        let calls = Cell::new(0);
        let check = |role, bytes: &[u8]| {
            calls.set(calls.get() + 1);
            crate::native_executable_signature::verify(&public, role, bytes)
        };
        let mut cache = Cache::default();
        for _ in 0..2 {
            cache
                .verify(
                    role,
                    File::open(&path).unwrap(),
                    || std::fs::metadata(&path),
                    check,
                )
                .unwrap();
        }
        assert_eq!(calls.get(), 1);
        assert!(cache
            .verify(
                NativeExecutableRole::Daemon,
                File::open(&path).unwrap(),
                || std::fs::metadata(&path),
                check
            )
            .is_err());
        assert_eq!(calls.get(), 2);
        let replacement = dir.path().join("modified");
        signed[4] ^= 1;
        std::fs::write(&replacement, signed).unwrap();
        std::fs::rename(replacement, &path).unwrap();
        assert!(cache
            .verify(
                role,
                File::open(&path).unwrap(),
                || std::fs::metadata(&path),
                check
            )
            .is_err());
        assert_eq!(calls.get(), 3);
        assert!(cache.entries[1].is_none());
    }
}
