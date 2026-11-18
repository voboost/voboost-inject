//! Resource admission within the existing verified install transaction.
//! Inert staging verifies only our signed payload; real Resources probes authorize later use.
use voboost_contract::{
    release::{self, ArtifactRole},
    resource::{OwnedResourceArtifact, SignedResourceInputs},
};
use voboost_shared::secure_fs::Directory;

pub fn admit_resources(
    staging: &Directory,
    manifest_bytes: &[u8],
    manifest_signature: &[u8],
    product_public_key: &[u8; 32],
) -> Result<Vec<OwnedResourceArtifact>, String> {
    if manifest_bytes.len() > release::MAX_MANIFEST_BYTES {
        return Err("resource manifest byte bound".into());
    }
    let manifest =
        release::verify_manifest_signature(manifest_bytes, manifest_signature, product_public_key)?;
    let artifacts = manifest
        .artifacts
        .iter()
        .filter(|a| a.role == ArtifactRole::ResourceApk)
        .collect::<Vec<_>>();
    if artifacts.is_empty() {
        return Ok(Vec::new());
    }
    let catalog = staging
        .read_untrusted("agents.json", 1024 * 1024)
        .map_err(|_| "read staged resource owner catalog")?;
    let mut retained_bytes = 0u64;
    for artifact in &artifacts {
        let descriptor = artifact
            .resource
            .as_ref()
            .ok_or("resource descriptor absent")?;
        for bytes in [
            artifact.size,
            descriptor.coverage_ledger.size,
            manifest_bytes.len() as u64,
            manifest_signature.len() as u64,
            catalog.len() as u64,
        ] {
            retained_bytes = retained_bytes
                .checked_add(bytes)
                .ok_or("resource retained byte overflow")?;
        }
    }
    if retained_bytes > voboost_contract::domain_core::MAX_CLOSURE_BYTES {
        return Err("resource retained closure exceeds byte bound".into());
    }
    let mut admitted = Vec::with_capacity(artifacts.len());
    for artifact in artifacts {
        let descriptor = artifact
            .resource
            .as_ref()
            .ok_or("resource descriptor absent")?;
        let apk = staging
            .read_untrusted(&artifact.file, 16 * 1024 * 1024)
            .map_err(|_| "read staged resource APK")?;
        let ledger = staging
            .read_untrusted(&descriptor.coverage_ledger.file, 1024 * 1024)
            .map_err(|_| "read staged resource ledger")?;
        admitted.push(OwnedResourceArtifact::verify(SignedResourceInputs {
            manifest_bytes,
            manifest_signature,
            product_public_key,
            artifact_file: &artifact.file,
            catalog_bytes: &catalog,
            apk_bytes: &apk,
            ledger_bytes: &ledger,
        })?);
    }
    // No filesystem mutation occurs until the caller admits the complete resource set.
    Ok(admitted)
}

#[cfg(test)]
#[path = "i18n_resource_admission_tests.rs"]
mod tests;
