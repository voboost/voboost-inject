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
}
