//! Retained signed helper and late native locale readback for resource removal.
//! Init activation remains separate from these authenticated lifecycle operations.
use std::io;
use std::os::unix::fs::MetadataExt;
use std::time::Duration;
use voboost_contract::operation::GenerationGuard;
use voboost_contract::resource::OwnedResourceArtifact;

use super::none_observation::PrimaryLanguage;
use super::{valid_resource_boot_id, Receipt, JOURNAL};
use crate::resource_none_helper::VerifiedNoneHelper;
use voboost_shared::early_none_gate::{self, Decision};
use voboost_shared::observed_locale::Language;
use voboost_shared::secure_fs::Directory;

const ROOT: &str = "/data/voboost";
const PLAN: &str = "agents.json";
const TRANSACTION: &str = "i18n-resource-transaction";
pub(super) const NONE_HELPER_NAME: &str = "none-helper.dex";
const MAX_HELPER: usize = 64 * 1024 * 1024;
const HELPER_TIMEOUT: Duration = Duration::from_secs(20);
const HELPER_OUTPUT_MAX: usize = 8 * 1024;
const PM_TIMEOUT: Duration = Duration::from_secs(5);
const PM_OUTPUT_MAX: usize = 64 * 1024;
const READBACK_PHASE: &str = "early-none-awaiting-native-readback";
const FINAL_PHASE: &str = "early-none-restored-confirmed";

fn fail(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(super) fn confirm_readback(
    receipt_phase: &str,
    removal_boot_id: Option<&str>,
    current_boot: &str,
) -> io::Result<()> {
    if !matches!(receipt_phase, READBACK_PHASE | FINAL_PHASE) {
        return Err(fail("late None finalizer phase not armed"));
    }
    let removal = removal_boot_id.ok_or_else(|| fail("removal boot id missing"))?;
    if !valid_resource_boot_id(removal) || !valid_resource_boot_id(current_boot) {
        return Err(fail("late None finalizer boot ids invalid"));
    }
    if removal != current_boot {
        return Err(fail("late None readback requires the removal boot"));
    }
    Ok(())
}

/// Late canonical-None check with NO session input: the same-boot defer is
/// an early-cleanup-only rule (a late daemon may legitimately have written
/// the current none session); radios without removal receipts are already
/// rejected by `confirm_readback`.
pub(super) fn canonical_none_now(root: &Directory, current_boot: &str) -> io::Result<()> {
    let plan = root.read_trusted(PLAN, 1024 * 1024, 0o600)?;
    match early_none_gate::decide(&plan, None, current_boot).map_err(io::Error::other)? {
        Decision::Cleanup => Ok(()),
        _ => Err(fail("canonical plan is not None")),
    }
}

/// Install-executor retention called BEFORE `install_owned` side effects.
/// Reuses the immutable authority slot; creates no separate helper dirs.
pub(crate) fn retain_none_helper(
    journal: &Directory,
    resource: &OwnedResourceArtifact,
    module_bytes: &[u8],
) -> io::Result<()> {
    let helper = VerifiedNoneHelper::verify(resource, module_bytes).map_err(io::Error::other)?;
    let slot = journal
        .open_or_create_private_child(&format!("authority-{}", resource.manifest_sha256()))?;
    slot.write_atomic(NONE_HELPER_NAME, helper.bytes(), 0o600)
}

pub(super) fn assemble_classpath(manifest_sha256: &str) -> io::Result<String> {
    assemble_classpath_for(
        voboost_shared::owned_overlay::Variant::SettingA9,
        manifest_sha256,
    )
}
pub(super) fn assemble_classpath_for(
    variant: voboost_shared::owned_overlay::Variant,
    manifest_sha256: &str,
) -> io::Result<String> {
    if manifest_sha256.len() != 64
        || !manifest_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(fail("helper slot identity invalid"));
    }
    Ok(format!(
        "-Djava.class.path={ROOT}/{TRANSACTION}/{}/authority-{manifest_sha256}/{NONE_HELPER_NAME}",
        variant.profile()
    ))
}

pub(super) fn helper_identity(file: &std::fs::File) -> io::Result<(u64, u64, u64)> {
    let meta = file.metadata()?;
    Ok((meta.dev(), meta.ino(), meta.len()))
}

/// Exact retained helper through the EXISTING authority slot, opened
/// read-only (`super::authority_slot` never creates a directory).
pub(super) fn retained_helper(
    journal: &Directory,
    resource: &OwnedResourceArtifact,
) -> io::Result<Vec<u8>> {
    let slot = super::authority_slot(journal, resource.manifest_sha256())?;
    let bytes = slot.read_trusted(NONE_HELPER_NAME, MAX_HELPER, 0o600)?;
    VerifiedNoneHelper::verify(resource, &bytes).map_err(io::Error::other)?;
    Ok(bytes)
}

pub(super) fn cross_language(helper: PrimaryLanguage, framework: Language) -> io::Result<()> {
    match (helper, framework) {
        (PrimaryLanguage::English, Language::English)
        | (PrimaryLanguage::Chinese, Language::Chinese) => Ok(()),
        _ => Err(fail("native locale observation disagrees with helper")),
    }
}

pub(super) fn cross_language_for_owner(
    owner: &str,
    helper: PrimaryLanguage,
    framework: Language,
) -> io::Result<()> {
    if owner == "i18n-en" && helper == PrimaryLanguage::Russian && framework == Language::Russian {
        return Ok(());
    }
    cross_language(helper, framework)
}

/// Finite host-injectable final commit: the receipt is read under the
/// transaction lock, the `native` and post-observation `recheck`
/// closures run (see `late_finalize_verified` for their exact witnesses),
/// and the guard owner is THEN reverified before
/// the final phase is published; on any failure the phase is untouched.
pub(super) fn commit_final_phase<F, G>(
    journal: &Directory,
    guard: &GenerationGuard,
    current_boot: &str,
    expected: &Receipt,
    native: F,
    recheck: G,
) -> io::Result<Receipt>
where
    F: FnOnce() -> io::Result<()>,
    G: FnOnce() -> io::Result<()>,
{
    let _lock = journal.lock_transaction(Duration::from_secs(5))?;
    let mut receipt: Receipt = serde_json::from_slice(&journal.read_trusted(JOURNAL, 4096, 0o600)?)
        .map_err(io::Error::other)?;
    if receipt.schema != 1 {
        return Err(fail("None receipt schema invalid"));
    }
    if &receipt != expected {
        return Err(fail("None receipt changed before locked readback"));
    }
    confirm_readback(
        &receipt.phase,
        receipt.removal_boot_id.as_deref(),
        current_boot,
    )?;
    native()?;
    recheck()?;
    guard.verify_owner().map_err(io::Error::other)?;
    if receipt.phase != FINAL_PHASE {
        receipt.phase = FINAL_PHASE.into();
        super::publish(journal, &receipt)?;
    }
    Ok(receipt)
}

/// Late native None finalizer (production entry). The caller must be the
/// init-owned late service enforcing PPID 1/executable identity.
#[allow(dead_code)]
pub(super) fn late_finalize_verified(product_key: &[u8; 32]) -> io::Result<Option<Receipt>> {
    super::none_driver::late_none_verified(product_key)
}

#[cfg(test)]
#[path = "i18n_none_finalizer_tests.rs"]
mod tests;
