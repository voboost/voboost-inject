//! Product ownership witnesses for interrupted overlay publication and uninstall.
use super::*;
use voboost_shared::secure_fs::TrustedSnapshot;

const PREVIOUS: &str = "previous-resource-transaction.json";

pub(super) fn snapshot(overlays: &Directory, name: &str) -> io::Result<Option<TrustedSnapshot>> {
    match overlays.read_trusted_snapshot(name, MAX_APK, 0o644, LABEL) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(fail(&format!("/vendor/overlay/{name}: {error}"))),
    }
}

fn trusted_receipt(journal: &Directory, name: &str) -> io::Result<Receipt> {
    serde_json::from_slice(&journal.read_trusted(name, 4096, 0o600)?).map_err(io::Error::other)
}

pub(super) fn receipt(
    journal: &Directory,
    overlays: &Directory,
    variant: Variant,
    key: &[u8; 32],
) -> io::Result<Receipt> {
    match trusted_receipt(journal, JOURNAL) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        result => return result,
    }
    let owned = snapshot(overlays, variant.file())?;
    let staged = snapshot(overlays, variant.staged())?;
    if owned.is_none() && staged.is_none() {
        return Err(fail(&format!(
            "{}: resource transaction missing without an overlay ownership witness",
            variant.profile()
        )));
    }
    let mut candidate: Option<Receipt> = None;
    for name in journal.entry_names_bounded(128)? {
        let Some(generation) = name.strip_prefix("authority-").filter(|value| hash(value)) else {
            continue;
        };
        // Unrelated or partially written slots carry no ownership authority.
        let Ok(authority) = read_owned_authority_for(journal, generation, key, variant) else {
            continue;
        };
        if authority.manifest_sha256() != generation
            || [owned.as_ref(), staged.as_ref()]
                .into_iter()
                .flatten()
                .any(|file| file.bytes != authority.apk_bytes())
        {
            continue;
        }
        if candidate.is_some() {
            return Err(fail(&format!(
                "/vendor/overlay/{}: ambiguous retained resource authority",
                variant.file()
            )));
        }
        candidate = Some(Receipt {
            schema: 1,
            generation: generation.into(),
            overlay_sha256: authority.artifact().sha256.clone(),
            previous_sha256: None,
            phase: "prepared".into(),
            removal_boot_id: None,
        });
    }
    candidate.ok_or_else(|| {
        fail(&format!(
            "/vendor/overlay/{}: resource transaction missing and no authenticated retained bytes match",
            if owned.is_some() { variant.file() } else { variant.staged() }
        ))
    })
}

pub(super) fn files(
    overlays: &Directory,
    journal: &Directory,
    variant: Variant,
    key: &[u8; 32],
    receipt: &Receipt,
    authority: &OwnedResourceArtifact,
) -> io::Result<(Option<TrustedSnapshot>, Option<TrustedSnapshot>)> {
    let owned = snapshot(overlays, variant.file())?;
    let staged = snapshot(overlays, variant.staged())?;
    let interrupted = matches!(receipt.phase.as_str(), "prepared" | "operation-removing");
    if let Some(file) = &owned {
        if file.bytes != authority.apk_bytes()
            && !(interrupted && matches_predecessor(journal, variant, key, receipt, &file.bytes)?)
        {
            return Err(fail(&format!(
                "/vendor/overlay/{}: file differs from authenticated resource ownership",
                variant.file()
            )));
        }
    }
    if let Some(file) = &staged {
        if !interrupted || file.bytes != authority.apk_bytes() {
            return Err(fail(&format!(
                "/vendor/overlay/{}: staged file differs from the interrupted publication",
                variant.staged()
            )));
        }
    }
    Ok((owned, staged))
}

fn matches_predecessor(
    journal: &Directory,
    variant: Variant,
    key: &[u8; 32],
    receipt: &Receipt,
    bytes: &[u8],
) -> io::Result<bool> {
    let Some(expected) = receipt.previous_sha256.as_deref() else {
        return Ok(false);
    };
    let previous = trusted_receipt(journal, PREVIOUS)?;
    let authority = read_owned_authority_for(journal, &previous.generation, key, variant)?;
    Ok(previous.schema == 1
        && stable_predecessor_phase(&previous.phase)
        && previous.generation == authority.manifest_sha256()
        && previous.overlay_sha256 == expected
        && authority.artifact().sha256 == expected
        && authority.apk_bytes() == bytes)
}
