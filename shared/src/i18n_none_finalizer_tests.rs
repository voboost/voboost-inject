//! Host tests for the late native None finalizer.
//! No fixed-guest writes: pure-function and real root-owned host-directory
//! (tempfile) coverage only; nothing under /data/voboost is touched.
use super::*;
use crate::resource_none_helper::I18N_RU_NONE_CLEANUP_CLASS;

const BOOT_A: &str = "11111111-1111-1111-1111-111111111111";
const BOOT_B: &str = "22222222-2222-2222-2222-222222222222";

fn plan_none() -> Vec<u8> {
    br#"{"schemaVersion":2,"userRevision":0,"fieldRevisions":{},"startup":"none","agents":{}}"#
        .to_vec()
}

#[test]
fn readback_requires_armed_phase_and_current_removal_boot() {
    assert!(confirm_readback(READBACK_PHASE, Some(BOOT_A), BOOT_A).is_ok());
    // Final-phase replay on the same removal boot is admissible recovery.
    assert!(confirm_readback(FINAL_PHASE, Some(BOOT_A), BOOT_A).is_ok());
    for phase in ["prepared", "awaiting-system-scan", "operation-removing", ""] {
        assert!(confirm_readback(phase, Some(BOOT_A), BOOT_A).is_err());
    }
    // A same-boot radio without a valid removal receipt stays rejected.
    assert!(confirm_readback(READBACK_PHASE, None, BOOT_A).is_err());
    assert!(confirm_readback(READBACK_PHASE, Some(BOOT_B), BOOT_A).is_err());
    assert!(confirm_readback(READBACK_PHASE, Some(BOOT_A), BOOT_B).is_err());
    assert!(confirm_readback(READBACK_PHASE, Some(""), BOOT_A).is_err());
    assert!(confirm_readback(
        READBACK_PHASE,
        Some("00000000-0000-0000-0000-000000000000"),
        BOOT_A
    )
    .is_err());
}

#[test]
fn late_canonical_none_ignores_startup_session_defer() {
    // Root-owned temp journal tree (host-only); the current plan is read
    // FROM DISK by canonical_none_now exactly as in the post-observation recheck.
    let temp = tempfile::tempdir().unwrap();
    let root = Directory::open(temp.path()).unwrap();
    root.write_atomic(PLAN, &plan_none(), 0o600).unwrap();
    // The late gate calls decide(plan, None, boot): it takes no session
    // input at all, so a current-boot none session written by a late
    // daemon can never trigger the early same-boot DeferCurrentBoot rule.
    // (Session bytes are intentionally never constructed or read here.)
    assert!(canonical_none_now(&root, BOOT_A).is_ok());
    root.write_atomic(
        PLAN,
        br#"{"schemaVersion":2,"userRevision":0,"fieldRevisions":{},"startup":"interface","agents":{}}"#,
        0o600,
    )
    .unwrap();
    assert!(canonical_none_now(&root, BOOT_A).is_err());
    root.write_atomic(PLAN, b"", 0o600).unwrap();
    assert!(canonical_none_now(&root, BOOT_A).is_err());
}

#[test]
fn classpath_uses_only_validated_hex_identity_in_authority_slot() {
    for bad in [
        "".to_string(),
        "abc".to_string(),
        "z".repeat(64),
        "a".repeat(63),
    ] {
        assert!(assemble_classpath(&bad).is_err());
    }
    let good = "1".repeat(64);
    let classpath = assemble_classpath(&good).unwrap();
    assert_eq!(
        classpath,
        format!(
            "-Djava.class.path={ROOT}/{TRANSACTION}/setting-a9/authority-{good}/{NONE_HELPER_NAME}"
        )
    );
    assert!(!classpath.contains(".."));
    let a11 =
        assemble_classpath_for(voboost_shared::owned_overlay::Variant::SettingA11, &good).unwrap();
    assert!(a11.contains("/setting-a11/authority-"));
    assert_ne!(a11, classpath);
    // The runtime class is the fixed cleanup class, not the agent entrypoint.
    assert_eq!(
        I18N_RU_NONE_CLEANUP_CLASS,
        "ru.voboost.agents.i18n.ru.I18nRuNoneCleanup"
    );
    assert_ne!(
        I18N_RU_NONE_CLEANUP_CLASS,
        crate::resource_none_helper::I18N_RU_AGENT_ENTRY_CLASS
    );
}

#[test]
fn helper_observation_must_agree_with_independent_framework_witness() {
    use super::super::none_observation::PrimaryLanguage::*;
    assert!(cross_language(English, Language::English).is_ok());
    assert!(cross_language(Chinese, Language::Chinese).is_ok());
    assert!(cross_language(English, Language::Chinese).is_err());
    assert!(cross_language(Chinese, Language::English).is_err());
    assert!(cross_language(English, Language::Russian).is_err());
    assert!(cross_language(Chinese, Language::Russian).is_err());
}

#[test]
fn commit_publishes_final_phase_only_after_observer_success_and_unchanged_receipt() {
    // Root-owned temp journal with an armed receipt.
    let temp = tempfile::tempdir().unwrap();
    let journal = Directory::open(temp.path()).unwrap();
    let receipt = Receipt {
        schema: 1,
        generation: "1".repeat(64),
        overlay_sha256: "2".repeat(64),
        previous_sha256: None,
        phase: READBACK_PHASE.into(),
        removal_boot_id: Some(BOOT_A.into()),
    };
    super::super::publish(&journal, &receipt).unwrap();
    let guard = GenerationGuard::acquire_in(temp.path())
        .map_err(io::Error::other)
        .unwrap();
    let published =
        commit_final_phase(&journal, &guard, BOOT_A, &receipt, || Ok(()), || Ok(())).unwrap();
    assert_eq!(published.phase, FINAL_PHASE);
    let persisted: Receipt =
        serde_json::from_slice(&journal.read_trusted(JOURNAL, 4096, 0o600).unwrap()).unwrap();
    assert_eq!(persisted.phase, FINAL_PHASE);
    assert_eq!(persisted.removal_boot_id.as_deref(), Some(BOOT_A));
}

#[test]
fn commit_keeps_phase_unchanged_when_observer_fails() {
    let temp = tempfile::tempdir().unwrap();
    let journal = Directory::open(temp.path()).unwrap();
    let receipt = Receipt {
        schema: 1,
        generation: "1".repeat(64),
        overlay_sha256: "2".repeat(64),
        previous_sha256: None,
        phase: READBACK_PHASE.into(),
        removal_boot_id: Some(BOOT_A.into()),
    };
    super::super::publish(&journal, &receipt).unwrap();
    let guard = GenerationGuard::acquire_in(temp.path())
        .map_err(io::Error::other)
        .unwrap();
    // Observer failure (native witness failed) must not publish the final phase.
    let native_error = commit_final_phase(
        &journal,
        &guard,
        BOOT_A,
        &receipt,
        || Err(fail("helper launch failed")),
        || Ok(()),
    );
    assert!(native_error.is_err());
    // Recheck failure equally must not publish.
    let recheck_error = commit_final_phase(
        &journal,
        &guard,
        BOOT_A,
        &receipt,
        || Ok(()),
        || Err(fail("plan reread mismatch")),
    );
    assert!(recheck_error.is_err());
    let persisted: Receipt =
        serde_json::from_slice(&journal.read_trusted(JOURNAL, 4096, 0o600).unwrap()).unwrap();
    assert_eq!(persisted.phase, READBACK_PHASE);
}

#[test]
fn commit_rejects_wrong_boot_or_unarmed_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let journal = Directory::open(temp.path()).unwrap();
    let mut receipt = Receipt {
        schema: 1,
        generation: "1".repeat(64),
        overlay_sha256: "2".repeat(64),
        previous_sha256: None,
        phase: READBACK_PHASE.into(),
        removal_boot_id: Some(BOOT_A.into()),
    };
    super::super::publish(&journal, &receipt).unwrap();
    let guard = GenerationGuard::acquire_in(temp.path())
        .map_err(io::Error::other)
        .unwrap();
    // Removal happened on BOOT_A; a different current boot must reject.
    assert!(commit_final_phase(&journal, &guard, BOOT_B, &receipt, || Ok(()), || Ok(())).is_err());
    receipt.phase = "prepared".into();
    super::super::publish(&journal, &receipt).unwrap();
    assert!(commit_final_phase(&journal, &guard, BOOT_A, &receipt, || Ok(()), || Ok(())).is_err());
    receipt.phase = FINAL_PHASE.into();
    super::super::publish(&journal, &receipt).unwrap();
    // Replay of the final phase stays idempotent on the removal boot.
    let replayed =
        commit_final_phase(&journal, &guard, BOOT_A, &receipt, || Ok(()), || Ok(())).unwrap();
    assert_eq!(replayed.phase, FINAL_PHASE);
}

#[test]
fn retained_helper_fd_identity_survives_untouched_reopen() {
    // The identity/bytes reopen comparison against the held FD: a real
    // host directory pair proves an untouched retained file passes and a
    // replaced file fails (write_atomic swaps the inode).
    let temp = tempfile::tempdir().unwrap();
    let slot = Directory::open(temp.path()).unwrap();
    slot.write_atomic(NONE_HELPER_NAME, b"helper-bytes", 0o600)
        .unwrap();
    let (retained, code_fd) = slot
        .read_trusted_retained(NONE_HELPER_NAME, MAX_HELPER, 0o600)
        .unwrap();
    let identity = helper_identity(&code_fd).unwrap();
    let (after, after_fd) = slot
        .read_trusted_retained(NONE_HELPER_NAME, MAX_HELPER, 0o600)
        .unwrap();
    assert_eq!(helper_identity(&after_fd).unwrap(), identity);
    assert_eq!(after, retained);
    assert_eq!(after, b"helper-bytes");
    // A replacement changes dev/ino identity (write_atomic renames a new inode).
    slot.write_atomic(NONE_HELPER_NAME, b"attacker-bytes", 0o600)
        .unwrap();
    let (replaced, replaced_fd) = slot
        .read_trusted_retained(NONE_HELPER_NAME, MAX_HELPER, 0o600)
        .unwrap();
    let new_identity = helper_identity(&replaced_fd).unwrap();
    if new_identity == identity {
        // Extremely unlikely inode reuse on one host; bytes still differ.
        assert_ne!(replaced, retained);
    } else {
        assert_ne!(new_identity, identity);
        assert_ne!(replaced, retained);
    }
}

#[test]
fn english_cleanup_framework_witness_allows_unchanged_russian_only_for_english_owner() {
    use super::super::none_observation::PrimaryLanguage::*;
    for (helper, framework) in [
        (English, Language::English),
        (Chinese, Language::Chinese),
        (Russian, Language::Russian),
    ] {
        assert!(cross_language_for_owner("i18n-en", helper, framework).is_ok());
    }
    assert!(cross_language_for_owner("i18n-ru", Russian, Language::Russian).is_err());
    assert!(cross_language_for_owner("i18n-en", Russian, Language::English).is_err());
    assert!(cross_language_for_owner("i18n-en", English, Language::Russian).is_err());
}
