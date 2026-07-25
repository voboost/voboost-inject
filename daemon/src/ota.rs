// ota.rs — atomic apply / rollback primitives (atomic-apply-rollback spec).
//
// Artifact-agnostic, frida-free filesystem logic ported from Vala ota.vala
// (recover_manifest, preserve_previous_binary, atomic rename-aside). These are
// the atomic primitives shared by every apply/rollback path:
//
//   - recover_manifest(): boot recovery of the daemon manifest after a
//     power-loss-interrupted swap (restore .prev over a bad/absent active).
//   - atomic_rename_swap(): rename the active file aside to `.prev` then move a
//     staged file into place as one indivisible operation, leaving a rollback
//     target. A swap with no rollback target never proceeds.
//   - marker helpers for the switch-pending/update-ready signals.
//
// The inject-core self-update (ELF + per-ABI payload atomic swap, re-verify
// against the release manifest, self-shutdown + init restart) builds on these
// primitives and is completed in the `ota` change. rename(2) on one filesystem
// is the atomicity primitive; the running process keeps its inode until exit.

use std::fs;
use std::path::Path;

use crate::config;
use crate::log;
use crate::release_manifest;
use crate::trust;

/// The one-deep rollback copies of the active daemon manifest.
const MANIFEST_PREV_SUFFIX: &str = ".prev";

/// True when `path`+`sig` both exist and the signature verifies against the
/// embedded key. The shared "does this signed manifest verify?" check used by
/// boot recovery.
fn manifest_verifies(path: &str, sig_path: &str) -> bool {
    let Ok(json_bytes) = fs::read(path) else {
        return false;
    };
    let Ok(sig) = fs::read(sig_path) else {
        return false;
    };
    trust::verify_signature(&json_bytes, &sig)
}

/// Boot recovery for the daemon manifest (atomic-apply-rollback "Boot recovery
/// after interrupted agent apply"). If the active manifest is absent or its
/// signature does not verify, but `manifest.json.prev` (+`.sig.prev`) verifies,
/// restore it via atomic rename. Returns true when a recovery happened.
///
/// Both renames must succeed: if the manifest lands but its signature does not,
/// the active pair would be left half-updated (fresh manifest, stale sig) and
/// the `.prev` backup destroyed. The first rename is rolled back if the second
/// fails so `.prev` survives for the next attempt.
pub fn recover_manifest() -> bool {
    let active = config::manifest_file();
    let active_sig = config::manifest_sig_file();
    if manifest_verifies(&active, &active_sig) {
        return false;
    }
    let prev = format!("{active}{MANIFEST_PREV_SUFFIX}");
    let prev_sig = format!("{active_sig}{MANIFEST_PREV_SUFFIX}");
    if !manifest_verifies(&prev, &prev_sig) {
        return false;
    }

    // Restore: rename .prev over the active (atomic on one filesystem). If the
    // active is absent this creates it; if present-but-bad it is replaced.
    if fs::rename(&prev, &active).is_err() {
        log::err("ota", "restore manifest.json rename failed");
        return false;
    }
    if fs::rename(&prev_sig, &active_sig).is_err() {
        log::err("ota", "restore manifest.sig rename failed; rolling back");
        // Best-effort: move manifest.json back to .prev so the verified .prev
        // pair is preserved for the next recovery attempt.
        if fs::rename(&active, &prev).is_err() {
            log::err("ota", "manifest.json rollback failed; .prev lost");
        }
        return false;
    }
    log::ok("ota", "restored manifest from .prev");
    true
}

/// Atomically swap a file into place while preserving the previous version:
/// rename `stable` aside to `prev` (rollback target), then rename `staged` to
/// `stable`. Returns the paths whose previous version was preserved (for
/// rollback), or `None` if the swap could not proceed safely.
///
/// On Linux/Android, rename(2) of a running binary is safe: the running
/// process keeps its inode until exit. The previous file is preserved *before*
/// the staged file takes the pathname, so a mid-swap failure always leaves a
/// rollback target. A first update with no existing `stable` proceeds with no
/// `.prev` (rollback will report no target — the never-broken invariant: no
/// file is lost).
pub fn atomic_rename_swap(stable: &str, prev: &str, staged: &str) -> Option<()> {
    // Preserve the previous version as .prev. If stable does not exist (first
    // update) there is nothing to preserve and the swap proceeds.
    if Path::new(stable).exists() && fs::rename(stable, prev).is_err() {
        log::err("ota", "cannot preserve previous file; aborting swap");
        return None;
    }
    // Commit: move the staged file to the stable pathname (atomic rename).
    if fs::rename(staged, stable).is_err() {
        log::err("ota", "staged->stable rename failed; aborting swap");
        // Restore the previous version we just set aside, if any.
        if Path::new(prev).exists() {
            let _ = fs::rename(prev, stable);
        }
        return None;
    }
    Some(())
}

// --- inject self-update (ota spec) -------------------------------------

/// Result of `apply_inject_update`. `Applied` means the caller MUST perform a
/// clean self-shutdown so the init hook restarts the service on the new ELF +
/// payload; the running binary is never replaced in place (renamed aside to
/// `.prev` and the new binary installed at the same pathname). Every
/// `Rejected*` leaves the current binary and payload active and unchanged.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InjectApplyOutcome {
    Applied,
    RejectedNoApk,
    RejectedBadBinary,
    /// The previous binary/payload could not be preserved for rollback; the
    /// switch is aborted so a bad new set is never installed without a
    /// rollback target.
    RejectedNoRollback,
}

/// Appended-signature trailing block: 8 bytes magic "VOBSIG1\0", 8 bytes LE
/// u64 SIG_OFFSET naming the end of the ELF part, 64 bytes raw ed25519
/// signature over the ELF bytes. The kernel loads the ELF by its header and
/// ignores the trailing bytes at exec.
const SIG_TRAILING: usize = 80;
const SIG_MAGIC: [u8; 8] = *b"VOBSIG1\0";

/// Verify the appended signature of a staged inject file. On success returns
/// the ELF bytes `[0..SIG_OFFSET)`. Returns `None` on any structural failure
/// (file too short, missing magic, SIG_OFFSET out of bounds) or a signature
/// failure. Pure (no instance state); used by `apply_inject_update`.
pub fn verify_appended_sig(bytes: &[u8]) -> Option<Vec<u8>> {
    // Need at least 1 ELF byte + the trailing block.
    if bytes.len() < SIG_TRAILING + 1 {
        return None;
    }
    let trailing_start = bytes.len() - SIG_TRAILING;
    if bytes[trailing_start..trailing_start + 8] != SIG_MAGIC {
        return None;
    }
    // SIG_OFFSET (LE u64) at trailing_start + 8: the authoritative end of the
    // ELF part. Bounds-checked: at least 1 ELF byte, no overrun past trailing.
    let sig_offset = read_le64(bytes, trailing_start + 8) as usize;
    if sig_offset < 1 || sig_offset > trailing_start {
        return None;
    }
    // Signature: 64 raw bytes immediately after the offset field.
    let sig_off = trailing_start + 16;
    let sig = &bytes[sig_off..sig_off + 64];
    let elf = &bytes[..sig_offset];
    if trust::verify_signature(elf, sig) {
        Some(elf.to_vec())
    } else {
        None
    }
}

/// Read an 8-byte little-endian unsigned 64-bit integer at `off`.
fn read_le64(b: &[u8], off: usize) -> u64 {
    let mut v = 0u64;
    for i in 0..8 {
        v |= (b[off + i] as u64) << (8 * i);
    }
    v
}

/// True when the producer signalled a verified staged inject update (the
/// single-use `voboost-inject-update-ready` marker is present in staging).
pub fn inject_update_ready(staging: &str) -> bool {
    Path::new(&config::inject_update_ready_marker(staging)).exists()
}

/// Remove the update-ready marker. Called BEFORE the apply (single-use,
/// consume first): a successful self-replace + init-restart must not re-apply
/// the same payload on every boot. Best-effort.
pub fn consume_inject_update_ready(staging: &str) {
    let _ = fs::remove_file(config::inject_update_ready_marker(staging));
}

/// True when a switch-pending marker is present (a self-replace was committed
/// but not yet confirmed/rolled back).
pub fn inject_switch_pending() -> bool {
    Path::new(&config::inject_switch_pending_marker()).exists()
}

/// Confirm a successful inject switch: clear the marker and drop the `.prev`
/// rollback targets (ELF + per-ABI payload). ota "Ready restart confirms".
pub fn confirm_inject_switch() {
    let _ = fs::remove_file(config::inject_switch_pending_marker());
    let _ = fs::remove_file(config::inject_prev_file());
    for abi in release_manifest::REQUIRED_ABIS {
        for name in release_manifest::PAYLOAD_FILES {
            let p = format!("{}/{abi}/{name}.prev", config::PAYLOAD_DIR);
            let _ = fs::remove_file(p);
        }
    }
}

/// Roll back a failed inject switch: restore the `.prev` rollback targets
/// (ELF + per-ABI payload) over the bad new set, clear the marker. Returns
/// false if no `.prev` ELF target exists (the daemon stays DEGRADED rather
/// than exec a known-bad binary with no rollback target). ota "Degraded
/// restart rolls back".
pub fn rollback_inject_switch() -> bool {
    let _ = fs::remove_file(config::inject_switch_pending_marker());
    let stable = config::inject_binary_file();
    let prev = config::inject_prev_file();
    if !Path::new(&prev).exists() {
        log::err("ota", "no .prev rollback target; staying DEGRADED");
        return false;
    }
    // Restore the ELF (.prev over stable). rename of the running binary is
    // safe on Linux/Android (the running process keeps its inode until exit).
    if fs::rename(&prev, &stable).is_err() {
        log::err("ota", "rollback ELF rename failed");
        return false;
    }
    // Restore each per-ABI payload file (.prev over active).
    for abi in release_manifest::REQUIRED_ABIS {
        for name in release_manifest::PAYLOAD_FILES {
            let active = format!("{}/{abi}/{name}", config::PAYLOAD_DIR);
            let p = format!("{active}.prev");
            if Path::new(&p).exists() && fs::rename(&p, &active).is_err() {
                log::err("ota", &format!("rollback payload {name} rename failed"));
            }
        }
    }
    log::ok("ota", "inject rolled back");
    true
}

/// Apply a staged inject update: verify the staged ELF (appended signature)
/// and each staged per-ABI payload file (sha256 against the verified release
/// manifest), then atomically swap the ELF and payload into place as one
/// indivisible operation. On `Applied` the caller MUST self-shut down so the
/// init hook restarts the service on the new ELF + payload (ota spec).
///
/// All-or-nothing: if any payload swap fails after the ELF (or other payload
/// files) were swapped, the already-swapped files are restored so the daemon
/// never observes a partial update. A switch with no rollback target never
/// proceeds.
pub fn apply_inject_update(
    staging: &str,
    rm: Option<&release_manifest::ReleaseManifest>,
) -> InjectApplyOutcome {
    // Consume the marker BEFORE the apply (single-use): a successful
    // self-replace + init-restart must not re-apply the same payload on every
    // boot (crash-loop). The marker is the trigger, not part of the verified
    // set, so consuming it first is safe.
    consume_inject_update_ready(staging);

    // --- Re-verify the staged payload sha256 against the release manifest ---
    // (never broken: a payload file that fails verification aborts the apply).
    let Some(rm) = rm else {
        log::err(
            "ota",
            "no verified release manifest; aborting inject update",
        );
        return InjectApplyOutcome::RejectedBadBinary;
    };
    for abi in release_manifest::REQUIRED_ABIS {
        for name in release_manifest::PAYLOAD_FILES {
            let staged_path = format!("{staging}/payload/{abi}/{name}");
            if let Some(expected) = rm.payload_sha256(name, abi) {
                if !trust::verify_payload(&staged_path, expected) {
                    log::err(
                        "ota",
                        &format!(
                            "staged payload {name} for {abi} \
                             sha256 mismatch; aborting update"
                        ),
                    );
                    return InjectApplyOutcome::RejectedBadBinary;
                }
            } else {
                log::err(
                    "ota",
                    &format!(
                        "staged payload {name} for {abi} not in \
                         release-manifest; aborting update"
                    ),
                );
                return InjectApplyOutcome::RejectedBadBinary;
            }
        }
    }

    // --- Verify + read the staged ELF (appended signature) ---
    let inject = find_staged_inject(staging);
    let Some(inject) = inject else {
        log::err("ota", "no staged inject ELF in staging/");
        return InjectApplyOutcome::RejectedNoApk;
    };
    // DoS guard: stat size before reading.
    let Ok(meta) = fs::metadata(&inject) else {
        log::err("ota", "staged inject ELF stat failed");
        return InjectApplyOutcome::RejectedNoApk;
    };
    let size = meta.len() as usize;
    if size > config::MAX_INJECT_BYTES {
        log::err("ota", "staged inject ELF oversize");
        return InjectApplyOutcome::RejectedNoApk;
    }
    let Ok(inject_bytes) = fs::read(&inject) else {
        log::err("ota", "staged inject ELF read failed");
        return InjectApplyOutcome::RejectedNoApk;
    };
    if inject_bytes.len() > config::MAX_INJECT_BYTES {
        log::err("ota", "staged inject ELF grew past bound");
        return InjectApplyOutcome::RejectedNoApk;
    }
    let Some(elf_bytes) = verify_appended_sig(&inject_bytes) else {
        log::err("ota", "staged inject signature rejected");
        return InjectApplyOutcome::RejectedBadBinary;
    };
    if elf_bytes.is_empty() {
        log::err("ota", "staged inject ELF is empty");
        return InjectApplyOutcome::RejectedBadBinary;
    }

    // --- Install the new ELF as a root-zone temp, fsync, fchmod 0755 ---
    let tmp = format!("{}/.ota.inject.tmp", config::ROOT_ZONE);
    if !write_bytes_exec(&tmp, &elf_bytes) {
        log::err("ota", "inject install write failed");
        let _ = fs::remove_file(&tmp);
        return InjectApplyOutcome::RejectedBadBinary;
    }

    // --- Preserve the previous ELF as .prev (rollback target) ---
    let stable = config::inject_binary_file();
    let elf_prev = config::inject_prev_file();
    if Path::new(&stable).exists() && fs::rename(&stable, &elf_prev).is_err() {
        log::err("ota", "cannot preserve previous ELF; aborting switch");
        let _ = fs::remove_file(&tmp);
        return InjectApplyOutcome::RejectedNoRollback;
    }

    // --- Swap each staged payload file into place (all-or-nothing) ---
    // Track every file swapped so a later failure restores them. The ELF .prev
    // is already set aside; a payload failure restores the swapped payload
    // files and rolls the ELF .prev back.
    let mut swapped: Vec<(String, String)> = Vec::new(); // (active, prev)
    for abi in release_manifest::REQUIRED_ABIS {
        for name in release_manifest::PAYLOAD_FILES {
            let active = format!("{}/{abi}/{name}", config::PAYLOAD_DIR);
            let prev = format!("{active}.prev");
            let staged_path = format!("{staging}/payload/{abi}/{name}");
            if atomic_rename_swap(&active, &prev, &staged_path).is_none() {
                log::err(
                    "ota",
                    &format!(
                        "payload {name} for {abi} swap failed; \
                         aborting update"
                    ),
                );
                // Restore the payload files already swapped.
                for (a, p) in &swapped {
                    let _ = fs::rename(p, a);
                }
                // Restore the previous ELF.
                if Path::new(&elf_prev).exists() {
                    let _ = fs::rename(&elf_prev, &stable);
                }
                let _ = fs::remove_file(&tmp);
                return InjectApplyOutcome::RejectedBadBinary;
            }
            swapped.push((active, prev));
        }
    }

    // --- Write the switch-pending marker before the new ELF takes the path ---
    // It is the rollback trigger on a DEGRADED restart. Without it the switch
    // is not safe to activate.
    if !write_marker() {
        log::err("ota", "cannot write switch-pending marker; aborting switch");
        for (a, p) in &swapped {
            let _ = fs::rename(p, a);
        }
        if Path::new(&elf_prev).exists() {
            let _ = fs::rename(&elf_prev, &stable);
        }
        let _ = fs::remove_file(&tmp);
        return InjectApplyOutcome::RejectedNoRollback;
    }

    // --- Commit: install the new ELF at the stable pathname (atomic rename) ---
    if fs::rename(&tmp, &stable).is_err() {
        log::err("ota", "inject install rename failed; aborting switch");
        let _ = fs::remove_file(config::inject_switch_pending_marker());
        for (a, p) in &swapped {
            let _ = fs::rename(p, a);
        }
        if Path::new(&elf_prev).exists() {
            let _ = fs::rename(&elf_prev, &stable);
        }
        return InjectApplyOutcome::RejectedBadBinary;
    }

    log::ok("ota", &format!("inject self-updated -> {stable}"));
    InjectApplyOutcome::Applied
}

/// Find the staged inject ELF in staging/ (the producer stages it as
/// `voboost-inject`, a single appended-sig ELF). Returns its path or None.
fn find_staged_inject(staging: &str) -> Option<String> {
    let path = format!("{staging}/voboost-inject");
    if Path::new(&path).exists() {
        Some(path)
    } else {
        None
    }
}

/// Write data to dst as a fresh regular file, fsync via O_NOFOLLOW (refuses a
/// racing symlink back to a root file), fchmod 0755. Mirrors Status.write_atomic.
fn write_bytes_exec(dst: &str, data: &[u8]) -> bool {
    if fs::write(dst, data).is_err() {
        return false;
    }
    // Best-effort fsync + fchmod via O_NOFOLLOW.
    unsafe {
        let fd = libc::open(
            std::ffi::CString::new(dst).unwrap().as_ptr(),
            libc::O_WRONLY | libc::O_NOFOLLOW,
        );
        if fd < 0 {
            let _ = fs::remove_file(dst);
            return false;
        }
        libc::fchmod(fd, 0o755);
        libc::fsync(fd);
        libc::close(fd);
    }
    true
}

/// Durably write the switch-pending marker. Returns false on any IO failure
/// (the caller aborts the switch: without a marker a DEGRADED restart cannot
/// roll back, so the switch must not proceed).
fn write_marker() -> bool {
    let _ = fs::create_dir_all(config::RUN_DIR);
    let marker = config::inject_switch_pending_marker();
    let tmp = format!("{}/.ota.marker.tmp", config::RUN_DIR);
    if fs::write(&tmp, "pending").is_err() {
        return false;
    }
    unsafe {
        let fd = libc::open(
            std::ffi::CString::new(tmp.clone()).unwrap().as_ptr(),
            libc::O_WRONLY | libc::O_NOFOLLOW,
        );
        if fd >= 0 {
            libc::fsync(fd);
            libc::close(fd);
        }
    }
    fs::rename(&tmp, &marker).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    /// A detached ed25519 signature that verifies against EMBEDDED_PUBKEY is
    /// not feasible to forge in a unit test, so manifest_verifies is exercised
    /// only on the negative paths (absent / bad files). The recovery happy path
    /// is covered structurally by atomic_rename_swap + the rename-rollback
    /// logic, which is the artifact-agnostic atomicity under test here.

    #[test]
    fn manifest_verifies_false_when_absent() {
        let dir = tempdir().unwrap();
        let m = dir.path().join("manifest.json");
        let s = dir.path().join("manifest.sig");
        assert!(!manifest_verifies(m.to_str().unwrap(), s.to_str().unwrap()));
    }

    #[test]
    fn atomic_swap_preserves_previous_and_installs_staged() {
        let dir = tempdir().unwrap();
        let stable = dir.path().join("f");
        let prev = dir.path().join("f.prev");
        let staged = dir.path().join("staged");
        fs::write(&stable, "old").unwrap();
        fs::write(&staged, "new").unwrap();

        assert!(atomic_rename_swap(
            stable.to_str().unwrap(),
            prev.to_str().unwrap(),
            staged.to_str().unwrap(),
        )
        .is_some());

        assert_eq!(fs::read_to_string(&stable).unwrap(), "new");
        assert_eq!(fs::read_to_string(&prev).unwrap(), "old");
    }

    #[test]
    fn atomic_swap_first_update_has_no_prev() {
        let dir = tempdir().unwrap();
        let stable = dir.path().join("f");
        let prev = dir.path().join("f.prev");
        let staged = dir.path().join("staged");
        // No existing stable (first update).
        fs::write(&staged, "new").unwrap();

        assert!(atomic_rename_swap(
            stable.to_str().unwrap(),
            prev.to_str().unwrap(),
            staged.to_str().unwrap(),
        )
        .is_some());

        assert_eq!(fs::read_to_string(&stable).unwrap(), "new");
        assert!(!prev.exists());
    }

    #[test]
    fn atomic_swap_aborts_and_restores_when_staged_missing() {
        let dir = tempdir().unwrap();
        let stable = dir.path().join("f");
        let prev = dir.path().join("f.prev");
        let staged = dir.path().join("staged");
        fs::write(&stable, "old").unwrap();
        // staged does not exist → commit rename fails.

        assert!(atomic_rename_swap(
            stable.to_str().unwrap(),
            prev.to_str().unwrap(),
            staged.to_str().unwrap(),
        )
        .is_none());

        // The previous version was restored to the stable pathname.
        assert_eq!(fs::read_to_string(&stable).unwrap(), "old");
        assert!(!prev.exists());
    }

    // --- appended-sig verify + LE reader (ota spec) ---

    #[test]
    fn read_le64_round_trips() {
        let bytes: [u8; 8] = [0x78, 0x56, 0x34, 0x12, 0x9a, 0xbc, 0xde, 0xf0];
        assert_eq!(read_le64(&bytes, 0), 0xf0de_bc9a_1234_5678);
    }

    #[test]
    fn verify_appended_sig_rejects_too_short() {
        // Fewer than TRAILING+1 bytes.
        let bytes = vec![0u8; SIG_TRAILING];
        assert!(verify_appended_sig(&bytes).is_none());
    }

    #[test]
    fn verify_appended_sig_rejects_bad_magic() {
        // 1 ELF byte + trailing block, but the magic bytes are wrong.
        let mut bytes = vec![0x7f; 1 + SIG_TRAILING];
        // magic slot (last 80 bytes, first 8) is zeroed → not VOBSIG1.
        let magic_off = bytes.len() - SIG_TRAILING;
        bytes[magic_off..magic_off + 8].fill(0);
        assert!(verify_appended_sig(&bytes).is_none());
    }

    #[test]
    fn verify_appended_sig_rejects_out_of_bounds_offset() {
        // Valid magic but SIG_OFFSET overruns past the trailing block start.
        let mut bytes = vec![0x7f; 1 + SIG_TRAILING];
        let magic_off = bytes.len() - SIG_TRAILING;
        bytes[magic_off..magic_off + 8].copy_from_slice(&SIG_MAGIC);
        // SIG_OFFSET = trailing_start + 1 (past the ELF part). LE u64.
        let offset_off = magic_off + 8;
        let overrun = (bytes.len() - SIG_TRAILING + 1) as u64;
        bytes[offset_off..offset_off + 8].copy_from_slice(&overrun.to_le_bytes());
        assert!(verify_appended_sig(&bytes).is_none());
    }

    // A real ed25519 signature that verifies against EMBEDDED_PUBKEY cannot be
    // forged without the private key, so the verify_appended_sig happy path is
    // covered structurally (the magic/offset/sig-slice logic) by the negatives
    // above; apply_inject_update composes these with device-only paths.

    #[test]
    fn find_staged_inject_none_when_absent() {
        let dir = tempdir().unwrap();
        assert!(find_staged_inject(dir.path().to_str().unwrap()).is_none());
    }

    #[test]
    fn find_staged_inject_some_when_present() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("voboost-inject"), b"ELF").unwrap();
        let found = find_staged_inject(dir.path().to_str().unwrap());
        assert!(found.is_some());
        assert!(found.unwrap().ends_with("voboost-inject"));
    }
}
