//! Signed resource lifecycle shared by the install, restore and uninstall one-shots.
// Each binary uses only its own lifecycle entry points; release LTO removes the others.
#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io, path::Path, time::Duration};
use voboost_contract::resource::{OwnedResourceArtifact, SignedResourceInputs};
use voboost_shared::owned_overlay::Variant;
use voboost_shared::secure_fs::Directory;
const OWNED: &str = "voboost-setting-ru.apk";
const STAGED: &str = ".voboost-setting-ru.apk.staged";
const BACKUP: &str = "previous.apk";
const JOURNAL: &str = "resource-transaction.json";
const MAX_APK: usize = 16 * 1024 * 1024;
const LABEL: &str = "u:object_r:voboost_resource_overlay_file:s0";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Receipt {
    pub schema: u8,
    pub generation: String,
    pub overlay_sha256: String,
    pub previous_sha256: Option<String>,
    pub phase: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removal_boot_id: Option<String>,
}
fn fail(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn publish(journal: &Directory, receipt: &Receipt) -> io::Result<()> {
    journal.write_atomic(
        JOURNAL,
        &serde_json::to_vec(receipt).map_err(io::Error::other)?,
        0o600,
    )
}
/// The authenticated resource role must authorize these exact bytes and generation.
/// This executor does not accept paths from user configuration or authenticate a catalog itself.
pub fn install_owned(
    resource: &OwnedResourceArtifact,
    helper: &crate::resource_none_helper::VerifiedNoneHelper,
) -> io::Result<Receipt> {
    let variant = variant_for(resource)?;
    let descriptor = resource.descriptor();
    if descriptor.owner != variant.owner().agent()
        || descriptor.locale != variant.owner().locale()
        || descriptor.target_package != variant.owner().process()
        || descriptor.overlay_package != variant.package()
    {
        return Err(fail("resource profile unsupported"));
    }
    // Inert delivery authenticates only our bytes. Actual target resource/method
    // compatibility is probed in the resident endpoint before OMS enable.
    let (overlays, journal) = open_production_for(variant)?;
    if helper.manifest_sha256() != resource.manifest_sha256() {
        return Err(fail("None helper belongs to another signed release"));
    }

    none_finalizer::retain_none_helper(&journal, resource, helper.bytes())?;
    install_with_authority(
        &overlays,
        &journal,
        (
            resource.manifest_sha256(),
            &resource.artifact().sha256,
            variant,
        ),
        resource.apk_bytes(),
        None,
        Some(LABEL),
        Some(resource),
    )
}
fn variant_for(resource: &OwnedResourceArtifact) -> io::Result<Variant> {
    let variant = Variant::from_artifact_file(&resource.artifact().file).map_err(|e| fail(&e))?;
    let descriptor = resource.descriptor();
    if descriptor.owner != variant.owner().agent()
        || descriptor.locale != variant.owner().locale()
        || descriptor.target_package != variant.owner().process()
        || descriptor.overlay_package != variant.package()
    {
        return Err(fail("owned resource tuple differs"));
    }
    Ok(variant)
}
fn authority_slot(journal: &Directory, generation: &str) -> io::Result<Directory> {
    if !hash(generation) {
        return Err(fail("resource authority slot invalid"));
    }
    journal.open_child(&format!("authority-{generation}"))
}
fn retain_authority(journal: &Directory, resource: &OwnedResourceArtifact) -> io::Result<()> {
    let slot = journal
        .open_or_create_private_child(&format!("authority-{}", resource.manifest_sha256()))?;
    for (name, bytes) in [
        ("product-manifest.json", resource.manifest_bytes()),
        ("product-manifest.sig", resource.manifest_signature()),
        ("catalog.json", resource.catalog_bytes()),
        ("resource-ledger.json", resource.ledger_bytes()),
        ("resource.apk", resource.apk_bytes()),
    ] {
        slot.write_atomic(name, bytes, 0o600)?;
    }
    slot.write_atomic("artifact-name", resource.artifact().file.as_bytes(), 0o600)?;
    Ok(())
}

fn verify_retained_authority(
    journal: &Directory,
    resource: &OwnedResourceArtifact,
) -> io::Result<()> {
    let slot = authority_slot(journal, resource.manifest_sha256())?;
    for (name, expected) in [
        ("product-manifest.json", resource.manifest_bytes()),
        ("product-manifest.sig", resource.manifest_signature()),
        ("catalog.json", resource.catalog_bytes()),
        ("resource-ledger.json", resource.ledger_bytes()),
        ("resource.apk", resource.apk_bytes()),
        ("artifact-name", resource.artifact().file.as_bytes()),
    ] {
        if slot.read_trusted(name, expected.len(), 0o600)? != expected {
            return Err(fail("retained resource authority differs"));
        }
    }
    Ok(())
}

fn install(
    overlay_dir: &Directory,
    journal: &Directory,
    generation: &str,
    expected_sha256: &str,
    apk: &[u8],
    expected_previous: Option<&str>,
    label: Option<&str>,
) -> io::Result<Receipt> {
    install_with_authority(
        overlay_dir,
        journal,
        (generation, expected_sha256, Variant::SettingA9),
        apk,
        expected_previous,
        label,
        None,
    )
}
fn stable_predecessor_phase(phase: &str) -> bool {
    matches!(
        phase,
        "awaiting-system-scan"
            | "oms-enabled-awaiting-owner-readback"
            | "oms-disabled-awaiting-owner-readback"
            | "enabled-owner-readback-confirmed"
            | "disabled-owner-readback-confirmed"
            | "early-none-awaiting-native-readback"
            | "early-none-restored-confirmed"
            | "late-none-final"
    )
}
fn install_with_authority(
    overlay_dir: &Directory,
    journal: &Directory,
    identity: (&str, &str, Variant),
    apk: &[u8],
    expected_previous: Option<&str>,
    label: Option<&str>,
    authority: Option<&OwnedResourceArtifact>,
) -> io::Result<Receipt> {
    let variant = identity.2;
    if authority
        .map(variant_for)
        .transpose()?
        .is_some_and(|owned| owned != variant)
    {
        return Err(fail("resource capability belongs to another variant"));
    }
    let owned = variant.file();
    let staged = variant.staged();
    let (generation, expected_sha256, _) = identity;
    if !hash(generation)
        || !hash(expected_sha256)
        || apk.is_empty()
        || apk.len() > MAX_APK
        || digest(apk) != expected_sha256
        || expected_previous.is_some_and(|s| !hash(s))
    {
        return Err(fail("resource artifact identity invalid"));
    }
    let _lock = journal.lock_transaction(Duration::from_secs(5))?;
    let mut predecessor = expected_previous.map(str::to_owned);
    // Replay only the same authenticated closure; never adopt a foreign or stale journal.
    match journal.read_trusted(JOURNAL, 4096, 0o600) {
        Ok(bytes) => {
            let existing: Receipt = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            let Some(resource) = authority else {
                return Err(fail("resource recovery pending"));
            };
            if existing.generation != generation || existing.overlay_sha256 != expected_sha256 {
                let old = read_owned_authority_for(
                    journal,
                    &existing.generation,
                    resource.verification_key(),
                    variant,
                )?;
                if existing.schema != 1
                    || existing.generation != old.manifest_sha256()
                    || existing.overlay_sha256 != old.artifact().sha256
                    || !stable_predecessor_phase(&existing.phase)
                {
                    return Err(fail("resource predecessor phase/identity invalid"));
                }
                let previous = match overlay_dir.read_trusted(owned, MAX_APK, 0o644) {
                    Ok(bytes) => {
                        if digest(&bytes) != old.artifact().sha256 {
                            return Err(fail("resource predecessor changed"));
                        }
                        Some(old.artifact().sha256.clone())
                    }
                    Err(error)
                        if error.kind() == io::ErrorKind::NotFound
                            && matches!(
                                existing.phase.as_str(),
                                "early-none-awaiting-native-readback"
                                    | "early-none-restored-confirmed"
                                    | "late-none-final"
                            ) =>
                    {
                        None
                    }
                    Err(error) => return Err(error),
                };
                journal.write_atomic("previous-resource-transaction.json", &bytes, 0o600)?;
                predecessor = previous;
            } else {
                verify_retained_authority(journal, resource)?;
                if existing.schema != 1
                    || existing
                        .previous_sha256
                        .as_deref()
                        .is_some_and(|hash_value| !hash(hash_value))
                {
                    return Err(fail("resource recovery identity differs"));
                }
                predecessor = existing.previous_sha256.clone();
                match existing.phase.as_str() {
                    "awaiting-system-scan"
                    | "oms-enabled-awaiting-owner-readback"
                    | "oms-disabled-awaiting-owner-readback"
                    | "enabled-owner-readback-confirmed"
                    | "disabled-owner-readback-confirmed" => {
                        overlay_dir.verify_trusted_digest(
                            owned,
                            apk.len() as u64,
                            expected_sha256,
                            0o644,
                        )?;
                        return Ok(existing);
                    }
                    "early-none-awaiting-native-readback"
                    | "early-none-restored-confirmed"
                    | "late-none-final" => {
                        // Reinstalling the same signed build is the authorized way out of None.
                        // Require the exact retained authority above and actual owned-file absence.
                        match overlay_dir.read_trusted(owned, MAX_APK, 0o644) {
                            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                                predecessor = None;
                            }
                            Ok(_) => {
                                return Err(fail(
                                    "None cleanup owned overlay unexpectedly present",
                                ));
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    "prepared" => match overlay_dir.read_trusted(owned, MAX_APK, 0o644) {
                        Ok(bytes) if digest(&bytes) == expected_sha256 => {
                            let mut recovered = existing;
                            recovered.phase = "awaiting-system-scan".into();
                            publish(journal, &recovered)?;
                            return Ok(recovered);
                        }
                        Ok(bytes)
                            if existing.previous_sha256.as_deref()
                                == Some(digest(&bytes).as_str()) => {}
                        Ok(_) => return Err(fail("prepared owned overlay differs")),
                        Err(error)
                            if error.kind() == io::ErrorKind::NotFound && predecessor.is_none() => {
                        }
                        Err(error) => return Err(error),
                    },
                    _ => return Err(fail("resource recovery phase requires explicit recovery")),
                }
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    let expected_previous = predecessor.as_deref();
    let previous = match overlay_dir.read_trusted(owned, MAX_APK, 0o644) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    let actual_previous = previous.as_deref().map(digest);
    if actual_previous.as_deref() != expected_previous {
        // A journal-free reinstall may find a byte-exact leftover of the SAME
        // authenticated artifact (an emergency removal retains the original
        // policy and cannot take the resource-uninstall transaction, so its
        // previously committed owned overlay files survive without journals).
        // Only the exact expected signed bytes are adopted — the file is
        // already the committed payload, so the publication below is a no-op
        // rename of identical content; anything else is a foreign file and
        // stays a hard failure.
        let byte_exact_orphan = predecessor.is_none()
            && previous
                .as_deref()
                .is_some_and(|bytes| digest(bytes) == expected_sha256);
        if !byte_exact_orphan {
            return Err(fail(&format!(
                "/vendor/overlay/{owned}: owned overlay changed"
            )));
        }
    }
    if let Some(resource) = authority {
        retain_authority(journal, resource)?;
    }
    if let Some(bytes) = previous {
        journal.write_atomic(BACKUP, &bytes, 0o600)?;
    }
    let mut receipt = Receipt {
        schema: 1,
        generation: generation.into(),
        overlay_sha256: expected_sha256.into(),
        previous_sha256: actual_previous,
        phase: "prepared".into(),
        removal_boot_id: None,
    };
    publish(journal, &receipt)?;
    if let Some(label) = label {
        overlay_dir.prepare_trusted_labeled(staged, apk, 0o644, label)?;
    } else {
        overlay_dir.prepare_trusted(staged, apk, 0o644)?;
    }
    overlay_dir.verify_trusted_digest(staged, apk.len() as u64, expected_sha256, 0o644)?;
    overlay_dir.rename(staged, owned)?;
    overlay_dir.sync_all()?;
    overlay_dir.verify_trusted_digest(owned, apk.len() as u64, expected_sha256, 0o644)?;
    receipt.phase = "awaiting-system-scan".into();
    publish(journal, &receipt)?;
    Ok(receipt)
}
/// Physical removal is only a transaction step; package absence after reboot is a separate gate.
pub fn remove_verified(
    overlay_dir: &Directory,
    journal: &Directory,
    generation: &str,
    expected_sha256: &str,
) -> io::Result<Receipt> {
    remove_verified_for(
        overlay_dir,
        journal,
        generation,
        expected_sha256,
        Variant::SettingA9,
    )
}
pub fn remove_verified_for(
    overlay_dir: &Directory,
    journal: &Directory,
    generation: &str,
    expected_sha256: &str,
    variant: Variant,
) -> io::Result<Receipt> {
    let owned = variant.file();
    if !hash(generation) || !hash(expected_sha256) {
        return Err(fail("resource identity invalid"));
    }
    let _lock = journal.lock_transaction(Duration::from_secs(5))?;
    let existing = journal.read_trusted(JOURNAL, 4096, 0o600)?;
    let mut receipt: Receipt = serde_json::from_slice(&existing).map_err(io::Error::other)?;
    if receipt.schema != 1
        || receipt.generation != generation
        || receipt.overlay_sha256 != expected_sha256
        || receipt.phase != "disabled-owner-readback-confirmed"
    {
        return Err(fail("disable readback transaction required"));
    }
    let bytes = overlay_dir.read_trusted(owned, MAX_APK, 0o644)?;
    if digest(&bytes) != expected_sha256 {
        return Err(fail("owned overlay changed"));
    }
    journal.write_atomic(BACKUP, &bytes, 0o600)?;
    receipt.phase = "removing".into();
    publish(journal, &receipt)?;
    overlay_dir.unlink(owned)?;
    overlay_dir.sync_all()?;
    receipt.phase = "awaiting-package-absence".into();
    publish(journal, &receipt)?;
    Ok(receipt)
}
/// Restore only the retained exact owned predecessor; keep the journal for reboot readback.
pub fn restore_verified(overlay_dir: &Directory, journal: &Directory) -> io::Result<Receipt> {
    restore(overlay_dir, journal, Some(LABEL))
}
pub fn restore_verified_for(
    overlay_dir: &Directory,
    journal: &Directory,
    variant: Variant,
) -> io::Result<Receipt> {
    restore_for_variant(overlay_dir, journal, Some(LABEL), variant)
}
fn restore(
    overlay_dir: &Directory,
    journal: &Directory,
    label: Option<&str>,
) -> io::Result<Receipt> {
    restore_for_variant(overlay_dir, journal, label, Variant::SettingA9)
}
fn restore_for_variant(
    overlay_dir: &Directory,
    journal: &Directory,
    label: Option<&str>,
    variant: Variant,
) -> io::Result<Receipt> {
    let owned = variant.file();
    let staged = variant.staged();
    let _lock = journal.lock_transaction(Duration::from_secs(5))?;
    let bytes = journal.read_trusted(JOURNAL, 4096, 0o600)?;
    let mut receipt: Receipt = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if receipt.schema != 1 || !hash(&receipt.generation) || !hash(&receipt.overlay_sha256) {
        return Err(fail("recovery identity invalid"));
    }
    let current = match overlay_dir.read_trusted(owned, MAX_APK, 0o644) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    if let Some(bytes) = &current {
        let current_hash = digest(bytes);
        if current_hash != receipt.overlay_sha256
            && Some(&current_hash) != receipt.previous_sha256.as_ref()
        {
            return Err(fail("recovery owned artifact changed"));
        }
    }
    let previous = if let Some(expected) = &receipt.previous_sha256 {
        if !hash(expected) {
            return Err(fail("recovery predecessor invalid"));
        }
        let bytes = journal.read_trusted(BACKUP, MAX_APK, 0o600)?;
        if digest(&bytes) != *expected {
            return Err(fail("recovery predecessor changed"));
        }
        Some(bytes)
    } else {
        None
    };
    receipt.phase = "restoring".into();
    publish(journal, &receipt)?;
    if let Some(bytes) = previous {
        if let Some(label) = label {
            overlay_dir.prepare_trusted_labeled(staged, &bytes, 0o644, label)?;
        } else {
            overlay_dir.prepare_trusted(staged, &bytes, 0o644)?;
        }
        overlay_dir.rename(staged, owned)?;
    } else if current.is_some() {
        overlay_dir.unlink(owned)?;
    }
    overlay_dir.sync_all()?;
    receipt.phase = "awaiting-restored-package-scan".into();
    publish(journal, &receipt)?;
    Ok(receipt)
}
fn none_requested(bytes: &[u8]) -> io::Result<bool> {
    if bytes.len() > 1024 * 1024 {
        return Err(fail("early boot plan exceeds bound"));
    }
    let plan = voboost_contract::desired::Config::decode(bytes)?;
    if plan.agents.len() > 64 {
        return Err(fail("early resource boot plan invalid"));
    }
    Ok(plan.startup == "none")
}
/// Invoked synchronously by the signed install binary under init before zygote.
/// Reads configured next-boot intent, not the old resident startup session.
pub fn early_cleanup_verified(product_key: &[u8; 32]) -> io::Result<Option<Receipt>> {
    let root = Directory::open(Path::new("/data/voboost"))?;
    root.validate_owner_not_writable(0, 0)?;
    let bytes = match root.read_trusted("agents.json", 1024 * 1024, 0o600) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let current_boot = voboost_contract::operation::current_boot_id().map_err(io::Error::other)?;
    let session = match root.open_child("run") {
        Ok(run) => {
            run.validate_owner_mode(0, 0, 0o755)?;
            match run.read_trusted("startup-session.json", 512, 0o600) {
                Ok(bytes) => Some(bytes),
                Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                Err(error) => return Err(error),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    match voboost_shared::early_none_gate::decide(&bytes, session.as_deref(), &current_boot)
        .map_err(io::Error::other)?
    {
        voboost_shared::early_none_gate::Decision::Cleanup => (),
        voboost_shared::early_none_gate::Decision::Skip
        | voboost_shared::early_none_gate::Decision::DeferCurrentBoot => return Ok(None),
    }
    let journal = match root.open_child("i18n-resource-transaction") {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    journal.validate_owner_mode(0, 0, 0o700)?;
    cleanup_for_none(product_key)
}
/// Invoked only by the authenticated init-only None decision. Ownership verification
/// remains valid after an OEM update; this function accepts no caller path.
/// This proves owned APK removal only. Native EN and post-scan absence remain separate.
pub fn cleanup_for_none(product_key: &[u8; 32]) -> io::Result<Option<Receipt>> {
    let profiles = open_existing_variants()?;
    if profiles.is_empty() {
        return Ok(None);
    }
    let _batch = none_batch::Lease::open()?;
    let mut profile_locks = Vec::new();
    for (_, _, journal) in &profiles {
        profile_locks.push(journal.lock_transaction(Duration::from_secs(5))?);
    }
    preflight_profiles(&profiles, product_key, RemovalMode::None)?;
    for (_, _, journal) in &profiles {
        let receipt: Receipt = serde_json::from_slice(&journal.read_trusted(JOURNAL, 4096, 0o600)?)
            .map_err(io::Error::other)?;
        if receipt.phase.starts_with("operation-") {
            return Err(fail("None cannot adopt an operation receipt"));
        }
    }
    let mut result = None;
    for (variant, overlays, journal) in &profiles {
        let value = cleanup_for_none_profile(product_key, *variant, overlays, journal)?;
        if result.is_none() {
            result = value;
        }
    }
    Ok(result)
}
#[derive(Clone, Copy)]
enum RemovalMode {
    None,
    Operation,
    Absence,
    Resume,
}
fn validate_removal_member(receipt: &Receipt, present: bool, mode: RemovalMode) -> io::Result<()> {
    let phase = receipt.phase.as_str();
    match mode {
        RemovalMode::None => {
            if phase.starts_with("operation-")
                || (present
                    && matches!(
                        phase,
                        "late-none-final"
                            | "early-none-awaiting-native-readback"
                            | "early-none-restored-confirmed"
                            | "late-none-awaiting-package-absence"
                            | "late-none-request-attempted"
                    ))
            {
                return Err(fail("None phase/presence inconsistent"));
            }
        }
        RemovalMode::Operation => {
            if !present
                && !matches!(
                    phase,
                    "operation-removing"
                        | "operation-awaiting-package-absence"
                        | "operation-reboot-attempted"
                        | "operation-package-absence-confirmed"
                        | "late-none-final"
                )
                && !(phase == "prepared" && receipt.previous_sha256.is_none())
            {
                return Err(fail("operation cannot adopt missing resource"));
            }
        }
        RemovalMode::Absence | RemovalMode::Resume => {
            if present
                || !matches!(
                    phase,
                    "operation-awaiting-package-absence"
                        | "operation-reboot-attempted"
                        | "operation-package-absence-confirmed"
                )
            {
                return Err(fail("operation absence phase/presence inconsistent"));
            }
        }
    }
    Ok(())
}
fn preflight_profiles(
    profiles: &[(Variant, Directory, Directory)],
    key: &[u8; 32],
    mode: RemovalMode,
) -> io::Result<()> {
    let mut registered_owners = Vec::new();
    for (variant, overlays, journal) in profiles {
        let receipt = if matches!(mode, RemovalMode::Operation) {
            operation_ownership::receipt(journal, overlays, *variant, key)?
        } else {
            serde_json::from_slice(&journal.read_trusted(JOURNAL, 4096, 0o600)?)
                .map_err(io::Error::other)?
        };
        let resource = read_owned_authority_for(journal, &receipt.generation, key, *variant)?;
        if receipt.schema != 1
            || receipt.generation != resource.manifest_sha256()
            || receipt.overlay_sha256 != resource.artifact().sha256
        {
            return Err(fail("plural resource authority differs"));
        }
        if !matches!(
            receipt.phase.as_str(),
            "prepared"
                | "awaiting-system-scan"
                | "enabled-owner-readback-confirmed"
                | "oms-enabled-awaiting-owner-readback"
                | "oms-disabled-awaiting-owner-readback"
                | "disabled-owner-readback-confirmed"
                | "early-none-removing"
                | "early-none-awaiting-native-readback"
                | "early-none-restored-confirmed"
                | "late-none-removing"
                | "late-none-awaiting-package-absence"
                | "late-none-request-attempted"
                | "late-none-final"
                | "operation-removing"
                | "operation-awaiting-package-absence"
                | "operation-reboot-attempted"
                | "operation-package-absence-confirmed"
        ) {
            return Err(fail("plural resource phase invalid"));
        }
        if (receipt.phase.starts_with("early-none-")
            || receipt.phase.starts_with("late-none-")
            || receipt.phase.starts_with("operation-"))
            && receipt
                .removal_boot_id
                .as_deref()
                .is_none_or(|boot| !valid_resource_boot_id(boot))
        {
            return Err(fail("plural removal boot invalid"));
        }
        let present = if matches!(mode, RemovalMode::Operation) {
            let (owned, staged) =
                operation_ownership::files(overlays, journal, *variant, key, &receipt, &resource)?;
            if owned.is_some() {
                registered_owners.push(*variant);
            }
            owned.is_some() || staged.is_some()
        } else {
            if matches!(mode, RemovalMode::Absence | RemovalMode::Resume)
                && overlays.entry_exists(variant.staged())?
            {
                return Err(fail(&format!(
                    "/vendor/overlay/{} remains",
                    variant.staged()
                )));
            }
            match overlays.read_trusted(variant.file(), MAX_APK, 0o644) {
                Ok(bytes) if bytes == resource.apk_bytes() => true,
                Ok(_) => {
                    return Err(fail(&format!(
                        "/vendor/overlay/{}: resource file replaced",
                        variant.file()
                    )))
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                Err(error) => return Err(error),
            }
        };
        if !present
            && !matches!(mode, RemovalMode::Operation)
            && !receipt.phase.starts_with("early-none-")
            && !receipt.phase.starts_with("late-none-")
            && !receipt.phase.starts_with("operation-")
        {
            return Err(fail("armed resource missing"));
        }
        if matches!(mode, RemovalMode::Operation | RemovalMode::Resume)
            && matches!(
                receipt.phase.as_str(),
                "operation-removing"
                    | "operation-awaiting-package-absence"
                    | "operation-reboot-attempted"
            )
            && !registered_owners.contains(variant)
        {
            // During replay the managers can retain our already unlinked fixed path.
            registered_owners.push(*variant);
        }
        validate_removal_member(&receipt, present, mode)?;
        if matches!(mode, RemovalMode::Absence) {
            validate_absence_boot(
                &receipt,
                &voboost_contract::operation::current_boot_id().map_err(io::Error::other)?,
            )?;
        }
        none_finalizer::retained_helper(journal, &resource)?;
    }
    if matches!(mode, RemovalMode::Operation | RemovalMode::Resume) {
        operation_registrations::preflight(&registered_owners)?;
    }
    Ok(())
}

fn cleanup_for_none_profile(
    product_key: &[u8; 32],
    variant: Variant,
    overlays: &Directory,
    journal: &Directory,
) -> io::Result<Option<Receipt>> {
    let bytes = match journal.read_trusted(JOURNAL, 4096, 0o600) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let receipt: Receipt = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if receipt.schema != 1
        || !matches!(
            receipt.phase.as_str(),
            "prepared"
                | "awaiting-system-scan"
                | "enabled-owner-readback-confirmed"
                | "oms-enabled-awaiting-owner-readback"
                | "oms-disabled-awaiting-owner-readback"
                | "disabled-owner-readback-confirmed"
                | "early-none-removing"
                | "early-none-awaiting-native-readback"
                | "early-none-restored-confirmed"
                | "late-none-final"
                | "late-none-removing"
                | "late-none-awaiting-package-absence"
                | "late-none-request-attempted"
        )
    {
        return Err(fail("resource None recovery phase invalid"));
    }
    let resource = read_owned_authority_for(journal, &receipt.generation, product_key, variant)?;
    if receipt.generation != resource.manifest_sha256()
        || receipt.overlay_sha256 != resource.artifact().sha256
    {
        return Err(fail("retained resource receipt identity differs"));
    }
    none_finalizer::retained_helper(journal, &resource)?;
    if receipt.phase == "late-none-final" {
        match overlays.read_trusted(variant.file(), MAX_APK, 0o644) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Some(receipt)),
            Ok(_) => return Err(fail("final None resource reappeared")),
            Err(error) => return Err(error),
        }
    }
    let mut receipt = receipt;
    receipt.removal_boot_id =
        Some(voboost_contract::operation::current_boot_id().map_err(io::Error::other)?);
    finish_none_removal(overlays, journal, receipt, &resource, || {
        voboost_shared::protected_system_transaction::recover_owned_resource_write(
            resource.manifest_sha256(),
        )
        .map_err(io::Error::other)
    })
    .map(Some)
}
fn finish_none_removal(
    overlays: &Directory,
    journal: &Directory,
    mut receipt: Receipt,
    resource: &OwnedResourceArtifact,
    recover: impl FnOnce() -> io::Result<()>,
) -> io::Result<Receipt> {
    if receipt.generation != resource.manifest_sha256()
        || receipt.overlay_sha256 != resource.artifact().sha256
    {
        return Err(fail("None cleanup owned authority differs"));
    }
    let variant = variant_for(resource)?;
    // Recover a pending writable mount before *either* presence or absence can
    // advance the receipt; crash-after-unlink must never silently skip the WAL.
    recover()?;
    match overlays.read_trusted(variant.file(), MAX_APK, 0o644) {
        Ok(current) => {
            if digest(&current) != resource.artifact().sha256 {
                return Err(fail("owned resource changed before None cleanup"));
            }
            receipt.phase = "early-none-removing".into();
            publish(journal, &receipt)?;
            voboost_shared::protected_system_transaction::with_owned_resource_write(
                resource.manifest_sha256(),
                || {
                    overlays
                        .unlink(variant.file())
                        .map_err(|error| error.to_string())?;
                    overlays.sync_all().map_err(|error| error.to_string())
                },
            )
            .map_err(io::Error::other)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    receipt.phase = "early-none-awaiting-native-readback".into();
    publish(journal, &receipt)?;
    Ok(receipt)
}
/// Called only from an already-admitted restore/uninstall WAL while its lease is held.
/// Removal uses ownership, not target compatibility, so an OEM update cannot strand our APK.
pub fn cleanup_for_operation(
    product_key: &[u8; 32],
    lease: &voboost_contract::operation::OperationLease,
    expected: voboost_contract::operation::Operation,
) -> io::Result<Option<Receipt>> {
    lease.verify_owner().map_err(io::Error::other)?;
    use voboost_contract::operation::{self, Operation};
    let active = operation::read_active_in(Path::new("/data/voboost")).map_err(io::Error::other)?;
    if !matches!(expected, Operation::Restore | Operation::Uninstall)
        || active
            .as_ref()
            .is_none_or(|current| current.operation != expected)
    {
        return Err(fail("resource removal operation differs"));
    }
    let profiles = open_operation_variants()?;
    if profiles.is_empty() {
        return Ok(None);
    }
    let _batch = none_batch::Lease::open()?;
    let mut profile_locks = Vec::new();
    for (_, _, journal) in &profiles {
        profile_locks.push(journal.lock_transaction(Duration::from_secs(5))?);
    }
    preflight_profiles(&profiles, product_key, RemovalMode::Operation)?;
    let first = &profiles[0];
    let r = operation_ownership::receipt(&first.2, &first.1, first.0, product_key)?;
    let authority = read_owned_authority_for(&first.2, &r.generation, product_key, first.0)?;
    none_driver::restore_native(&first.2, &authority)?;
    let mut result = None;
    for (variant, overlays, journal) in &profiles {
        let value = cleanup_for_operation_profile(product_key, *variant, overlays, journal, lease)?;
        if result.is_none() {
            result = value;
        }
    }
    Ok(result)
}
fn cleanup_for_operation_profile(
    product_key: &[u8; 32],
    variant: Variant,
    overlays: &Directory,
    journal: &Directory,
    lease: &voboost_contract::operation::OperationLease,
) -> io::Result<Option<Receipt>> {
    use voboost_contract::operation;
    lease.verify_owner().map_err(io::Error::other)?;
    let mut receipt = operation_ownership::receipt(journal, overlays, variant, product_key)?;
    let resource = read_owned_authority_for(journal, &receipt.generation, product_key, variant)?;
    if receipt.schema != 1
        || receipt.generation != resource.manifest_sha256()
        || receipt.overlay_sha256 != resource.artifact().sha256
    {
        return Err(fail("resource removal receipt differs"));
    }
    voboost_shared::protected_system_transaction::recover_owned_resource_write(
        resource.manifest_sha256(),
    )
    .map_err(io::Error::other)?;
    let files =
        operation_ownership::files(overlays, journal, variant, product_key, &receipt, &resource)?;
    if files.0.is_none() && files.1.is_none() && receipt.phase != "prepared" {
        validate_removal_member(&receipt, false, RemovalMode::Operation)?;
        recover_absent_removal(journal, overlays, &mut receipt)?;
        if receipt.phase == "late-none-final" {
            verify_package_absence_for(variant)?;
            receipt.phase = "operation-awaiting-package-absence".into();
            publish(journal, &receipt)?;
        }
        return Ok(Some(receipt));
    }
    if variant.owner().agent() == "i18n-ru"
        && voboost_shared::observed_locale::observe().map_err(io::Error::other)?
            == voboost_shared::observed_locale::Language::Russian
    {
        return Err(fail(
            "native locale remains Russian before resource removal",
        ));
    }
    lease.verify_owner().map_err(io::Error::other)?;
    use voboost_shared::owned_overlay::OverlayState;
    if files.0.is_some() {
        match observe_overlay_for_removal(variant)? {
            Some(OverlayState::Disabled) | None => (),
            Some(OverlayState::Enabled) => {
                verify_registered_overlay_path(variant)?;
                operation_registrations::verify_overlay_path(variant)?;
                let output = voboost_shared::fixed_process::output(
                    "/system/bin/cmd",
                    &["overlay", "disable", "--user", "0", variant.package()],
                    Duration::from_secs(5),
                    64 * 1024,
                )
                .map_err(io::Error::other)?;
                if !output.status.success()
                    || observe_overlay_for_removal(variant)? == Some(OverlayState::Enabled)
                {
                    return Err(fail("resource disable not observed before removal"));
                }
            }
            // Removal-only: signed ownership and global native EN were proved above.
            // An unclassified non-enabled state is not a Disabled or Ready claim.
            Some(OverlayState::NotEnabledUnclassified) => (),
        }
    }
    if variant.owner().agent() == "i18n-ru"
        && voboost_shared::observed_locale::observe().map_err(io::Error::other)?
            == voboost_shared::observed_locale::Language::Russian
    {
        return Err(fail("native locale changed back to Russian before removal"));
    }
    lease.verify_owner().map_err(io::Error::other)?;
    receipt.removal_boot_id = Some(operation::current_boot_id().map_err(io::Error::other)?);
    receipt.phase = "operation-removing".into();
    publish(journal, &receipt)?;
    if files.0.is_some() || files.1.is_some() {
        voboost_shared::protected_system_transaction::with_owned_resource_variant_write(
            resource.manifest_sha256(),
            &format!("/vendor/overlay/{}", variant.file()),
            || {
                if operation_ownership::files(
                    overlays,
                    journal,
                    variant,
                    product_key,
                    &receipt,
                    &resource,
                )
                .map_err(|error| error.to_string())?
                    != files
                {
                    return Err(format!(
                        "/vendor/overlay/{} changed before unlink",
                        variant.file()
                    ));
                }
                if files.1.is_some() {
                    overlays
                        .unlink(variant.staged())
                        .map_err(|error| error.to_string())?;
                }
                if files.0.is_some() {
                    overlays
                        .unlink(variant.file())
                        .map_err(|error| error.to_string())?;
                }
                overlays.sync_all().map_err(|error| error.to_string())
            },
        )
        .map_err(io::Error::other)?;
    }
    receipt.phase = "operation-awaiting-package-absence".into();
    publish(journal, &receipt)?;
    Ok(Some(receipt))
}
fn recover_absent_removal(
    journal: &Directory,
    overlays: &Directory,
    receipt: &mut Receipt,
) -> io::Result<()> {
    if receipt
        .removal_boot_id
        .as_deref()
        .is_none_or(|value| !valid_resource_boot_id(value))
    {
        return Err(fail("resource removal boot missing during replay"));
    }
    if receipt.phase == "operation-removing" {
        overlays.sync_all()?;
        receipt.phase = "operation-awaiting-package-absence".into();
        publish(journal, receipt)?;
    }
    Ok(())
}
/// Close only after a different boot and a real PackageManager absence observation.
/// Retained signed authority remains available until the caller's terminal cleanup.
pub fn verify_operation_absence(
    product_key: &[u8; 32],
    lease: &voboost_contract::operation::OperationLease,
    expected: voboost_contract::operation::Operation,
) -> io::Result<Option<Receipt>> {
    lease.verify_owner().map_err(io::Error::other)?;
    let profiles = open_operation_variants()?;
    if profiles.is_empty() {
        if expected == voboost_contract::operation::Operation::Uninstall {
            verify_resource_absence(&profiles)?;
        }
        return Ok(None);
    }
    let _batch = none_batch::Lease::open()?;
    let mut profile_locks = Vec::new();
    for (_, _, journal) in &profiles {
        profile_locks.push(journal.lock_transaction(Duration::from_secs(5))?);
    }
    preflight_profiles(&profiles, product_key, RemovalMode::Absence)?;
    let first = &profiles[0];
    let r: Receipt = serde_json::from_slice(&first.2.read_trusted(JOURNAL, 4096, 0o600)?)
        .map_err(io::Error::other)?;
    let authority = read_owned_authority_for(&first.2, &r.generation, product_key, first.0)?;
    verify_resource_absence(&profiles)?;
    none_driver::restore_native(&first.2, &authority)?;
    let observed_boot = voboost_contract::operation::current_boot_id().map_err(io::Error::other)?;
    let verified = collect_absence_before_commit(
        profiles.len(),
        |index| {
            let (variant, overlays, journal) = &profiles[index];
            verify_operation_absence_profile(
                product_key,
                *variant,
                overlays,
                journal,
                lease,
                expected,
            )?
            .ok_or_else(|| fail("authenticated profile lost its receipt"))
        },
        || {
            lease.verify_owner().map_err(io::Error::other)?;
            if voboost_contract::operation::current_boot_id().map_err(io::Error::other)?
                != observed_boot
            {
                return Err(fail("boot changed during all-owned absence proof"));
            }
            preflight_profiles(&profiles, product_key, RemovalMode::Absence)?;
            verify_resource_absence(&profiles)
        },
        |index, receipt| publish(&profiles[index].2, receipt),
    )?;
    let result = verified.into_iter().next();
    let boot = voboost_contract::operation::current_boot_id().map_err(io::Error::other)?;
    let mut members = Vec::new();
    for (variant, _, journal) in &profiles {
        let receipt: Receipt = serde_json::from_slice(&journal.read_trusted(JOURNAL, 4096, 0o600)?)
            .map_err(io::Error::other)?;
        members.push((*variant, receipt));
    }
    _batch.finish(&members, &boot)?;
    Ok(result)
}
fn verify_operation_absence_profile(
    product_key: &[u8; 32],
    variant: Variant,
    overlays: &Directory,
    journal: &Directory,
    lease: &voboost_contract::operation::OperationLease,
    expected: voboost_contract::operation::Operation,
) -> io::Result<Option<Receipt>> {
    use voboost_contract::operation::{self, Operation};
    if !matches!(expected, Operation::Restore | Operation::Uninstall) {
        return Err(fail("resource absence operation invalid"));
    }
    lease.verify_owner().map_err(io::Error::other)?;
    let active = operation::read_active_in(Path::new("/data/voboost")).map_err(io::Error::other)?;
    if active
        .as_ref()
        .is_none_or(|value| value.operation != expected)
    {
        return Err(fail("resource absence operation differs"));
    }
    let mut receipt: Receipt = serde_json::from_slice(&journal.read_trusted(JOURNAL, 4096, 0o600)?)
        .map_err(io::Error::other)?;
    let owned = read_owned_authority_for(journal, &receipt.generation, product_key, variant)?;
    if receipt.schema != 1
        || receipt.generation != owned.manifest_sha256()
        || receipt.overlay_sha256 != owned.artifact().sha256
    {
        return Err(fail("resource absence authority differs"));
    }
    validate_absence_boot(
        &receipt,
        &operation::current_boot_id().map_err(io::Error::other)?,
    )?;
    match overlays.read_trusted(variant.file(), MAX_APK, 0o644) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Ok(_) => return Err(fail("owned resource still exists after reboot")),
        Err(error) => return Err(error),
    }
    verify_package_absence_for(variant)?;
    if variant.owner().agent() == "i18n-ru"
        && voboost_shared::observed_locale::observe().map_err(io::Error::other)?
            == voboost_shared::observed_locale::Language::Russian
    {
        return Err(fail("native locale remains Russian after resource removal"));
    }
    lease.verify_owner().map_err(io::Error::other)?;
    receipt.phase = "operation-package-absence-confirmed".into();
    // The collection coordinator publishes only after every profile proof.
    Ok(Some(receipt))
}
fn collect_absence_before_commit(
    count: usize,
    mut observe: impl FnMut(usize) -> io::Result<Receipt>,
    fence: impl FnOnce() -> io::Result<()>,
    mut commit: impl FnMut(usize, &Receipt) -> io::Result<()>,
) -> io::Result<Vec<Receipt>> {
    if count > Variant::ALL.len() {
        return Err(fail("absence collection exceeds owned profiles"));
    }
    let mut receipts = Vec::with_capacity(count);
    for index in 0..count {
        receipts.push(observe(index)?);
    }
    fence()?;
    for (index, receipt) in receipts.iter().enumerate() {
        commit(index, receipt)?;
    }
    Ok(receipts)
}
fn verify_package_absence_for(variant: Variant) -> io::Result<()> {
    let output = voboost_shared::fixed_process::output(
        "/system/bin/cmd",
        &["package", "list", "packages", "-u", variant.package()],
        Duration::from_secs(5),
        64 * 1024,
    )
    .map_err(io::Error::other)?;
    validate_package_absence(output.status.success(), &output.stdout, &output.stderr)
        .map_err(|error| fail(&format!("PackageManager {}: {error}", variant.package())))
}

fn verify_resource_absence(profiles: &[(Variant, Directory, Directory)]) -> io::Result<()> {
    let output = voboost_shared::fixed_process::output(
        "/system/bin/cmd",
        &[
            "package",
            "list",
            "packages",
            "-u",
            "ru.voboost.translation",
        ],
        Duration::from_secs(5),
        64 * 1024,
    )
    .map_err(io::Error::other)?;
    validate_package_absence(output.status.success(), &output.stdout, &output.stderr)?;

    let output = overlay_list()?;
    validate_overlay_absence(&output)?;
    // Reobserve known paths after PM/OMS to fence a replacement during the probe.
    let observed = open_operation_variants()?;
    if !observed
        .iter()
        .map(|(variant, _, _)| variant)
        .eq(profiles.iter().map(|(variant, _, _)| variant))
    {
        return Err(fail(
            "resource profiles changed during absence verification",
        ));
    }
    for (variant, overlays, _) in observed {
        for name in [variant.file(), variant.staged()] {
            if overlays.entry_exists(name)? {
                return Err(fail(&format!(
                    "/vendor/overlay/{name}: resource remains after reboot"
                )));
            }
        }
    }
    Ok(())
}

fn overlay_list() -> io::Result<Vec<u8>> {
    let output = voboost_shared::fixed_process::output(
        "/system/bin/cmd",
        &["overlay", "list", "--user", "0"],
        Duration::from_secs(5),
        64 * 1024,
    )
    .map_err(io::Error::other)?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(fail("OverlayManager list query failed"));
    }
    Ok(output.stdout)
}

fn overlay_list_records(stdout: &[u8]) -> io::Result<Vec<&str>> {
    let text =
        std::str::from_utf8(stdout).map_err(|_| fail("OverlayManager output is not UTF-8"))?;
    if !text.is_empty() && !text.ends_with('\n') {
        return Err(fail("OverlayManager output has incomplete final record"));
    }
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let package = line
                .strip_prefix("[x] ")
                .or_else(|| line.strip_prefix("[ ] "))
                .or_else(|| line.strip_prefix("--- "))
                .unwrap_or(line);
            // Fabricated overlays can append an overlay name to their package.
            if package.is_empty()
                || !package
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':'))
            {
                return Err(fail("OverlayManager record malformed"));
            }
            Ok(package)
        })
        .collect()
}

fn verify_registered_overlay_path(variant: Variant) -> io::Result<()> {
    let output = voboost_shared::fixed_process::output(
        "/system/bin/pm",
        &["path", variant.package()],
        Duration::from_secs(5),
        4096,
    )
    .map_err(io::Error::other)?;
    let expected = format!("package:/vendor/overlay/{}\n", variant.file());
    if !output.status.success() || !output.stderr.is_empty() || output.stdout != expected.as_bytes()
    {
        return Err(fail(&format!(
            "PackageManager {}: expected code path /vendor/overlay/{}",
            variant.package(),
            variant.file()
        )));
    }
    Ok(())
}

fn observe_overlay_for_removal(
    variant: Variant,
) -> io::Result<Option<voboost_shared::owned_overlay::OverlayState>> {
    let output = overlay_list()?;
    if !overlay_list_records(&output)?.contains(&variant.package()) {
        return Ok(None);
    }
    voboost_shared::owned_overlay::parse_list_for(&output, variant)
        .map(Some)
        .map_err(|error| fail(&format!("OverlayManager {}: {error}", variant.package())))
}

fn validate_overlay_absence(stdout: &[u8]) -> io::Result<()> {
    for package in overlay_list_records(stdout)? {
        if Variant::from_package(package).is_ok() {
            return Err(fail(&format!(
                "OverlayManager {package}: resource remains registered"
            )));
        }
    }
    Ok(())
}

fn validate_package_absence(success: bool, stdout: &[u8], stderr: &[u8]) -> io::Result<()> {
    if !success || !stderr.is_empty() || stdout.len() > 64 * 1024 {
        return Err(fail(
            "PackageManager absence query failed or exceeded bound",
        ));
    }
    let text =
        std::str::from_utf8(stdout).map_err(|_| fail("PackageManager output is not UTF-8"))?;
    if !text.is_empty() && !text.ends_with('\n') {
        return Err(fail("PackageManager output has incomplete final record"));
    }
    for line in text.lines() {
        let package = line
            .strip_prefix("package:")
            .ok_or_else(|| fail("PackageManager record malformed"))?;
        if package.is_empty()
            || !package
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_'))
        {
            return Err(fail("PackageManager package name malformed"));
        }
        if Variant::ALL
            .iter()
            .any(|variant| package == variant.package())
        {
            return Err(fail(&format!(
                "PackageManager {package}: resource remains registered"
            )));
        }
    }
    Ok(())
}
fn valid_resource_boot_id(value: &str) -> bool {
    value.len() == 36
        && value != "00000000-0000-0000-0000-000000000000"
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
            }
        })
}
fn validate_absence_boot(receipt: &Receipt, current: &str) -> io::Result<()> {
    match operation_boot::decide(receipt, current)? {
        operation_boot::Action::VerifyAbsence => Ok(()),
        _ => Err(fail("resource absence requires a different boot")),
    }
}
#[cfg(test)]
mod removal_mode_tests {
    use super::*;
    fn receipt(phase: &str) -> Receipt {
        Receipt {
            schema: 1,
            generation: "a".repeat(64),
            overlay_sha256: "b".repeat(64),
            previous_sha256: None,
            phase: phase.into(),
            removal_boot_id: Some("11111111-1111-4111-8111-111111111111".into()),
        }
    }
    #[test]
    fn resource_absence_requires_complete_clean_manager_readbacks() {
        let package = Variant::SettingA9.package();
        assert!(validate_package_absence(true, b"", b"").is_ok());
        assert!(
            validate_package_absence(true, format!("package:{package}\n").as_bytes(), b"")
                .unwrap_err()
                .to_string()
                .contains(package)
        );
        assert!(validate_overlay_absence(b"android\n[x] com.example:accent\n").is_ok());
        for marker in ["[x]", "[ ]", "---"] {
            let output = format!("com.qinggan.app.setting\n{marker} {package}\n");
            assert!(validate_overlay_absence(output.as_bytes())
                .unwrap_err()
                .to_string()
                .contains(package));
        }
        assert!(validate_overlay_absence(b"android\n[!] malformed\n").is_err());
        assert!(validate_overlay_absence(b"android").is_err());
    }
    #[test]
    fn second_package_presence_blocks_every_final_publication() {
        let commits = std::cell::Cell::new(0);
        assert!(collect_absence_before_commit(
            2,
            |index| {
                if index == 1 {
                    Err(fail("A11 package still registered"))
                } else {
                    Ok(receipt("operation-package-absence-confirmed"))
                }
            },
            || Ok(()),
            |_, _| {
                commits.set(commits.get() + 1);
                Ok(())
            },
        )
        .is_err());
        assert_eq!(commits.get(), 0);
    }
    #[test]
    fn all_absence_observers_and_fence_precede_first_commit() {
        let observed = std::cell::Cell::new(0);
        let fenced = std::cell::Cell::new(false);
        let receipts = collect_absence_before_commit(
            2,
            |_| {
                observed.set(observed.get() + 1);
                Ok(receipt("operation-package-absence-confirmed"))
            },
            || {
                fenced.set(true);
                Ok(())
            },
            |_, _| {
                assert_eq!(observed.get(), 2);
                assert!(fenced.get());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(receipts.len(), 2);
    }
    #[test]
    fn final_reappearance_fails_none_collection_preflight() {
        assert!(
            validate_removal_member(&receipt("late-none-final"), true, RemovalMode::None).is_err()
        );
    }
    #[test]
    fn operation_cannot_adopt_missing_early_none_member() {
        assert!(validate_removal_member(
            &receipt("early-none-awaiting-native-readback"),
            false,
            RemovalMode::Operation
        )
        .is_err());
        assert!(validate_removal_member(
            &receipt("operation-removing"),
            false,
            RemovalMode::Operation
        )
        .is_ok());
    }
}

fn read_owned_authority(
    journal: &Directory,
    generation: &str,
    product_key: &[u8; 32],
) -> io::Result<OwnedResourceArtifact> {
    let slot = authority_slot(journal, generation)?;
    let manifest = slot.read_trusted("product-manifest.json", 1024 * 1024, 0o600)?;
    let signature = slot.read_trusted("product-manifest.sig", 64, 0o600)?;
    let catalog = slot.read_trusted("catalog.json", 1024 * 1024, 0o600)?;
    let ledger = slot.read_trusted("resource-ledger.json", 1024 * 1024, 0o600)?;
    let apk = slot.read_trusted("resource.apk", MAX_APK, 0o600)?;
    let name = slot.read_trusted("artifact-name", 128, 0o600)?;
    let name = std::str::from_utf8(&name).map_err(|_| fail("retained artifact name invalid"))?;
    let resource = OwnedResourceArtifact::verify(SignedResourceInputs {
        manifest_bytes: &manifest,
        manifest_signature: &signature,
        product_public_key: product_key,
        artifact_file: name,
        catalog_bytes: &catalog,
        apk_bytes: &apk,
        ledger_bytes: &ledger,
    })
    .map_err(io::Error::other)?;
    let descriptor = resource.descriptor();
    if descriptor.owner != variant_for(&resource)?.owner().agent()
        || descriptor.locale != variant_for(&resource)?.owner().locale()
        || descriptor.overlay_package != variant_for(&resource)?.package()
        || descriptor.target_package != variant_for(&resource)?.owner().process()
    {
        return Err(fail("retained owned resource profile differs"));
    }
    Ok(resource)
}
fn read_owned_authority_for(
    journal: &Directory,
    generation: &str,
    key: &[u8; 32],
    variant: Variant,
) -> io::Result<OwnedResourceArtifact> {
    let resource = read_owned_authority(journal, generation, key)?;
    if variant_for(&resource)? != variant {
        return Err(fail("retained resource belongs to another profile"));
    }
    Ok(resource)
}
pub fn open_production_for(variant: Variant) -> io::Result<(Directory, Directory)> {
    let (overlays, root) = open_production()?;
    let journal = root.open_or_create_private_child(variant.profile())?;
    Ok((overlays, journal))
}
pub fn open_existing_variants() -> io::Result<Vec<(Variant, Directory, Directory)>> {
    let root = Directory::open(Path::new("/data/voboost"))?;
    root.validate_owner_not_writable(0, 0)?;
    let parent = match root.open_child("i18n-resource-transaction") {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    parent.validate_owner_mode(0, 0, 0o700)?;
    for name in parent.entry_names_bounded(Variant::ALL.len() + 2)? {
        if !Variant::ALL.iter().any(|variant| variant.profile() == name)
            && !matches!(name.as_str(), "none-batch-reboot.json" | "remount.json")
        {
            return Err(fail("unexpected owned resource journal member"));
        }
    }
    let mut entries = Vec::new();
    for variant in Variant::ALL {
        let journal = match parent.open_child(variant.profile()) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        journal.validate_owner_mode(0, 0, 0o700)?;
        let overlays = Directory::open(Path::new("/vendor/overlay"))?;
        overlays.validate_owner_not_writable(0, 2000)?;
        entries.push((variant, overlays, journal));
    }
    Ok(entries)
}
fn open_operation_variants() -> io::Result<Vec<(Variant, Directory, Directory)>> {
    let profiles = open_existing_variants()?;
    let overlays = match Directory::open(Path::new("/vendor/overlay")) {
        Ok(overlays) => overlays,
        Err(error) if error.kind() == io::ErrorKind::NotFound && profiles.is_empty() => {
            return Ok(profiles)
        }
        Err(error) => return Err(error),
    };
    overlays.validate_owner_not_writable(0, 2000)?;
    for variant in Variant::ALL {
        if profiles.iter().any(|(profile, _, _)| *profile == variant) {
            continue;
        }
        for name in [variant.file(), variant.staged()] {
            if overlays.entry_exists(name)? {
                return Err(fail(&format!(
                    "/vendor/overlay/{name}: no retained resource profile ownership"
                )));
            }
        }
    }
    Ok(profiles)
}
/// Open only fixed production paths. Tests use retained directory descriptors directly.
pub fn open_production() -> io::Result<(Directory, Directory)> {
    let overlays = Directory::open(Path::new("/vendor/overlay"))?;
    overlays.validate_owner_not_writable(0, 2000)?;
    let root = Directory::open(Path::new("/data/voboost"))?;
    root.validate_owner_not_writable(0, 0)?;
    let journal = root.open_or_create_private_child("i18n-resource-transaction")?;
    Ok((overlays, journal))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn six_profile_file_transactions_and_restore_are_isolated() {
        // Tests fixed filesystem paths, not signed APK admission or PM scanning.
        let (_temp, overlays, parent) = dirs();
        let generation = "2".repeat(64);
        for variant in Variant::ALL {
            let journal = parent
                .open_or_create_private_child(variant.profile())
                .unwrap();
            let bytes = variant.profile().as_bytes();
            install_with_authority(
                &overlays,
                &journal,
                (&generation, &digest(bytes), variant),
                bytes,
                None,
                None,
                None,
            )
            .unwrap();
        }
        for variant in Variant::ALL {
            assert_eq!(
                overlays
                    .read_trusted(variant.file(), MAX_APK, 0o644)
                    .unwrap(),
                variant.profile().as_bytes()
            );
        }
        for (index, variant) in Variant::ALL.into_iter().enumerate() {
            let journal = parent.open_child(variant.profile()).unwrap();
            restore_for_variant(&overlays, &journal, None, variant).unwrap();
            for (other_index, other) in Variant::ALL.into_iter().enumerate() {
                let live = overlays.read_trusted(other.file(), MAX_APK, 0o644);
                if other_index <= index {
                    assert_eq!(live.unwrap_err().kind(), io::ErrorKind::NotFound);
                } else {
                    assert_eq!(live.unwrap(), other.profile().as_bytes());
                }
            }
        }
    }
    #[test]
    fn core_a11_file_transaction_and_restore_never_touch_a9_overlay() {
        // Filesystem executor regression only: arbitrary fixture bytes are not
        // claimed to pass signed APK admission or PackageManager scanning.
        let (_temp, overlays, journal) = dirs();
        overlays
            .prepare_trusted(Variant::SettingA9.file(), b"other owned variant", 0o644)
            .unwrap();
        let bytes = b"a11 filesystem transaction fixture";
        let generation = "1".repeat(64);
        let artifact = digest(bytes);
        install_with_authority(
            &overlays,
            &journal,
            (&generation, &artifact, Variant::SettingA11),
            bytes,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            overlays
                .read_trusted(Variant::SettingA11.file(), MAX_APK, 0o644)
                .unwrap(),
            bytes
        );
        assert_eq!(
            overlays
                .read_trusted(Variant::SettingA9.file(), MAX_APK, 0o644)
                .unwrap(),
            b"other owned variant"
        );
        restore_for_variant(&overlays, &journal, None, Variant::SettingA11).unwrap();
        assert!(overlays
            .read_trusted(Variant::SettingA11.file(), MAX_APK, 0o644)
            .is_err());
        assert_eq!(
            overlays
                .read_trusted(Variant::SettingA9.file(), MAX_APK, 0o644)
                .unwrap(),
            b"other owned variant"
        );
    }
    fn dirs() -> (tempfile::TempDir, Directory, Directory) {
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir(t.path().join("overlay")).unwrap();
        std::fs::create_dir(t.path().join("journal")).unwrap();
        let a = Directory::open(&t.path().join("overlay")).unwrap();
        let b = Directory::open(&t.path().join("journal")).unwrap();
        (t, a, b)
    }
    #[test]
    fn journal_free_reinstall_adopts_only_byte_exact_orphan_overlay() {
        // Emergency removal restores the original policy first and cannot
        // take the resource-uninstall transaction, so its committed owned
        // overlay files survive with no journals. Reinstalling the same
        // signed build must converge onto the byte-exact orphan (the
        // free-09-chinese emulator reproduced this as the hard failure
        // "owned overlay changed" blocking every retry).
        let (_t, overlays, journal) = dirs();
        let generation = "2".repeat(64);
        let bytes = b"owned-payload".as_slice();
        let expected = digest(bytes);
        overlays
            .prepare_trusted(Variant::SettingA9.file(), bytes, 0o644)
            .unwrap();
        let receipt = install_with_authority(
            &overlays,
            &journal,
            (&generation, &expected, Variant::SettingA9),
            bytes,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(receipt.phase, "awaiting-system-scan");
        // A foreign file with different bytes still fails closed: the second
        // journal-free install expects the same bytes but finds a stranger.
        overlays
            .prepare_trusted(Variant::SettingA9.file(), b"foreign-bytes", 0o644)
            .unwrap();
        assert!(install_with_authority(
            &overlays,
            &journal,
            (&generation, &expected, Variant::SettingA9),
            bytes,
            None,
            None,
            None,
        )
        .is_err());
    }
    #[test]
    fn replay_after_unlink_durably_arms_absence_without_changing_boot() {
        let (_t, overlays, journal) = dirs();
        let mut receipt = Receipt {
            schema: 1,
            generation: "1".repeat(64),
            overlay_sha256: "2".repeat(64),
            previous_sha256: None,
            phase: "operation-removing".into(),
            removal_boot_id: Some("11111111-1111-1111-1111-111111111111".into()),
        };
        publish(&journal, &receipt).unwrap();
        recover_absent_removal(&journal, &overlays, &mut receipt).unwrap();
        let persisted: Receipt =
            serde_json::from_slice(&journal.read_trusted(JOURNAL, 4096, 0o600).unwrap()).unwrap();
        assert_eq!(persisted.phase, "operation-awaiting-package-absence");
        assert_eq!(
            persisted.removal_boot_id.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert!(validate_absence_boot(&persisted, "11111111-1111-1111-1111-111111111111").is_err());
        assert!(validate_absence_boot(&persisted, "22222222-2222-2222-2222-222222222222").is_ok());
    }
    #[test]
    fn package_absence_requires_complete_successful_native_records() {
        assert!(validate_package_absence(true, b"", b"").is_ok());
        assert!(validate_package_absence(
            true,
            b"package:ru.voboost.translation.setting.other\n",
            b""
        )
        .is_ok());
        for bytes in [
            b"package:ru.voboost.translation.setting\n".as_slice(),
            b"package:foreign",
            b"Error: service unavailable\n",
            &[0xff],
        ] {
            assert!(validate_package_absence(true, bytes, b"").is_err());
        }
        assert!(validate_package_absence(false, b"", b"").is_err());
        assert!(validate_package_absence(true, b"", b"error").is_err());
        assert!(validate_package_absence(true, &vec![b'x'; 65537], b"").is_err());
    }
    #[test]
    fn absence_requires_armed_receipt_and_different_boot() {
        let mut receipt = Receipt {
            schema: 1,
            generation: "1".repeat(64),
            overlay_sha256: "2".repeat(64),
            previous_sha256: None,
            phase: "operation-awaiting-package-absence".into(),
            removal_boot_id: Some("11111111-1111-1111-1111-111111111111".into()),
        };
        assert!(validate_absence_boot(&receipt, "11111111-1111-1111-1111-111111111111").is_err());
        assert!(validate_absence_boot(&receipt, "22222222-2222-2222-2222-222222222222").is_ok());
        receipt.removal_boot_id = None;
        assert!(validate_absence_boot(&receipt, "22222222-2222-2222-2222-222222222222").is_err());
        receipt.removal_boot_id = Some("11111111-1111-1111-1111-111111111111".into());
        receipt.phase = "prepared".into();
        assert!(validate_absence_boot(&receipt, "22222222-2222-2222-2222-222222222222").is_err());
    }
    #[test]
    fn exact_atomic_install_retains_receipt() {
        let (_t, a, b) = dirs();
        let bytes = b"signed APK fixture";
        let r = install(&a, &b, &"1".repeat(64), &digest(bytes), bytes, None, None).unwrap();
        assert_eq!(r.phase, "awaiting-system-scan");
        assert_eq!(a.read_trusted(OWNED, MAX_APK, 0o644).unwrap(), bytes);
        assert!(install(
            &a,
            &b,
            &"1".repeat(64),
            &digest(bytes),
            bytes,
            Some(&digest(bytes)),
            None
        )
        .is_err());
    }
    #[test]
    fn only_next_boot_none_removes_preinstalled_resource() {
        for startup in ["hidden", "interface"] {
            let bytes = format!(
                r#"{{"schemaVersion":2,"userRevision":0,"fieldRevisions":{{}},"startup":"{startup}","agents":{{"i18n-ru":{{"enabled":false,"options":{{}}}}}}}}"#
            );
            assert!(!none_requested(bytes.as_bytes()).unwrap());
        }
        assert!(none_requested(br#"{"schemaVersion":2,"userRevision":0,"fieldRevisions":{},"startup":"none","agents":{}}"#).unwrap());
    }
    #[test]
    fn invalid_boot_plan_cannot_request_cleanup() {
        for bytes in [
            br#"{"schemaVersion":2,"userRevision":0,"fieldRevisions":{},"startup":"none","startup":"interface","agents":{}}"#.as_slice(),
            br#"{"schemaVersion":2,"startup":"none","agents":{}}"#,
            br#"{"schemaVersion":2,"userRevision":0,"fieldRevisions":{},"startup":"unknown","agents":{}}"#,
            br#"{"schemaVersion":2,"userRevision":0,"fieldRevisions":{},"startup":"none","agents":{},"force":true}"#,
        ] {
            assert!(none_requested(bytes).is_err());
        }
    }
    #[test]
    fn wrong_digest_writes_nothing() {
        let (_t, a, b) = dirs();
        assert!(install(&a, &b, &"1".repeat(64), &"2".repeat(64), b"bad", None, None).is_err());
        assert!(a.read_trusted(OWNED, MAX_APK, 0o644).is_err());
        assert!(b.read_trusted(JOURNAL, 4096, 0o600).is_err());
    }
    #[test]
    fn unexpected_existing_file_is_not_replaced() {
        let (_t, a, b) = dirs();
        a.prepare_trusted(OWNED, b"foreign", 0o644).unwrap();
        assert!(install(&a, &b, &"1".repeat(64), &digest(b"new"), b"new", None, None).is_err());
        assert_eq!(a.read_trusted(OWNED, MAX_APK, 0o644).unwrap(), b"foreign");
    }
    #[test]
    fn update_preserves_old_bytes_before_publish() {
        let (_t, a, b) = dirs();
        a.prepare_trusted(OWNED, b"old", 0o644).unwrap();
        install(
            &a,
            &b,
            &"1".repeat(64),
            &digest(b"new"),
            b"new",
            Some(&digest(b"old")),
            None,
        )
        .unwrap();
        assert_eq!(b.read_trusted(BACKUP, MAX_APK, 0o600).unwrap(), b"old");
    }
    #[test]
    fn rollback_restores_predecessor_and_keeps_recovery() {
        let (_t, a, b) = dirs();
        a.prepare_trusted(OWNED, b"old", 0o644).unwrap();
        install(
            &a,
            &b,
            &"1".repeat(64),
            &digest(b"new"),
            b"new",
            Some(&digest(b"old")),
            None,
        )
        .unwrap();
        let r = restore(&a, &b, None).unwrap();
        assert_eq!(r.phase, "awaiting-restored-package-scan");
        assert_eq!(a.read_trusted(OWNED, MAX_APK, 0o644).unwrap(), b"old");
        assert!(b.read_trusted(JOURNAL, 4096, 0o600).is_ok());
    }
    #[test]
    fn rollback_rejects_modified_owned_apk() {
        let (_t, a, b) = dirs();
        install(&a, &b, &"1".repeat(64), &digest(b"new"), b"new", None, None).unwrap();
        a.prepare_trusted(OWNED, b"other", 0o644).unwrap();
        assert!(restore(&a, &b, None).is_err());
        assert_eq!(a.read_trusted(OWNED, MAX_APK, 0o644).unwrap(), b"other");
    }
    #[test]
    fn symlink_is_rejected_without_touching_target() {
        let (t, a, b) = dirs();
        let victim = t.path().join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        std::os::unix::fs::symlink(&victim, t.path().join("overlay").join(OWNED)).unwrap();
        assert!(install(&a, &b, &"1".repeat(64), &digest(b"new"), b"new", None, None).is_err());
        assert_eq!(std::fs::read(victim).unwrap(), b"keep");
    }
}

#[cfg(test)]
#[path = "i18n_resource_files_signed_tests.rs"]
mod signed_tests;

#[path = "i18n_none_finalizer.rs"]
mod none_finalizer;

#[path = "i18n_none_observation.rs"]
mod none_observation;

pub fn finalize_none_verified(key: &[u8; 32]) -> io::Result<Option<Receipt>> {
    none_driver::late_none_verified(key)
}

#[path = "i18n_none_state.rs"]
mod none_state;

#[path = "i18n_none_batch.rs"]
mod none_batch;

#[path = "i18n_none_driver.rs"]
mod none_driver;

#[path = "i18n_operation_boot.rs"]
mod operation_boot;

#[path = "i18n_operation_ownership.rs"]
mod operation_ownership;

#[path = "i18n_operation_registrations.rs"]
mod operation_registrations;

#[path = "i18n_operation_resume.rs"]
mod operation_resume;

pub use operation_resume::Continuation as OperationContinuation;
pub fn prepare_operation_before_runtime_remove(
    key: &[u8; 32],
    lease: &voboost_contract::operation::OperationLease,
) -> io::Result<OperationContinuation> {
    operation_resume::prepare_before_runtime_remove(key, lease)
}

pub fn require_operation_resume_service(key: &[u8; 32]) -> io::Result<()> {
    operation_resume::require_resume_service(key)
}
