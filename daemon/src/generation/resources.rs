//! Resource-bearing generations retain their product authority, not a second config.
use super::*;
use voboost_contract::release::{ArtifactRole, Manifest, MANIFEST_NAME, MANIFEST_SIGNATURE_NAME};
pub(super) struct ResourceProduct {
    manifest: Manifest,
    bytes: Vec<u8>,
    signature: Vec<u8>,
}
impl ResourceProduct {
    pub(super) fn verified(
        manifest: Manifest,
        bytes: Vec<u8>,
        signature: Vec<u8>,
        catalog: &AgentCatalog,
        catalog_bytes: &[u8],
        catalog_signature: &[u8],
    ) -> Result<Option<Self>> {
        if !manifest.artifacts.iter().any(|a| {
            matches!(
                a.role,
                ArtifactRole::ResourceApk | ArtifactRole::QnxResourcePack
            )
        }) {
            return Ok(None);
        }
        for (name, data) in [
            (CATALOG_FILE, catalog_bytes),
            (CATALOG_SIGNATURE_FILE, catalog_signature),
        ] {
            let artifact = manifest.artifact(name).map_err(anyhow::Error::msg)?;
            ensure!(
                artifact.size == data.len() as u64 && artifact.sha256 == digest(data),
                "resource product catalog binding differs"
            );
        }
        correlate_product_generation(&manifest, catalog)?;
        for artifact in manifest
            .artifacts
            .iter()
            .filter(|a| a.role == ArtifactRole::ResourceApk)
        {
            let metadata = artifact
                .resource
                .as_ref()
                .context("resource metadata absent")?;
            ensure!(
                catalog
                    .agents
                    .iter()
                    .filter(|a| a.id == metadata.owner && a.kind.is_none())
                    .count()
                    == 1,
                "resource owner missing or ambiguous in signed catalog"
            );
        }
        Ok(Some(Self {
            manifest,
            bytes,
            signature,
        }))
    }
    pub(super) fn load(
        dir: &Directory,
        mode: Option<u32>,
        catalog: &AgentCatalog,
        catalog_bytes: &[u8],
        catalog_signature: &[u8],
    ) -> Result<Option<Self>> {
        let read = |name: &str, max: usize| match mode {
            Some(m) => dir.read_trusted(name, max, m),
            None => dir.read_untrusted(name, max),
        };
        let bytes = match read(MANIFEST_NAME, voboost_contract::release::MAX_MANIFEST_BYTES) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                ensure!(
                    matches!(read(MANIFEST_SIGNATURE_NAME,64),Err(e) if e.kind()==std::io::ErrorKind::NotFound),
                    "resource product signature without manifest"
                );
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        };
        let signature = read(MANIFEST_SIGNATURE_NAME, 64)?;
        let manifest = voboost_contract::release::verify_manifest_signature(
            &bytes,
            &signature,
            &crate::trust::release_catalog_public_key(),
        )
        .map_err(anyhow::Error::msg)?;
        let result = Self::verified(
            manifest,
            bytes,
            signature,
            catalog,
            catalog_bytes,
            catalog_signature,
        )?;
        ensure!(
            result.is_some(),
            "non-resource product authority in generation"
        );
        Ok(result)
    }
    pub(super) fn extend(&self, files: &mut BTreeMap<String, GenerationFile>) -> Result<()> {
        for (name, data) in [
            (MANIFEST_NAME, self.bytes.as_slice()),
            (MANIFEST_SIGNATURE_NAME, self.signature.as_slice()),
        ] {
            insert_expected(
                files,
                GenerationFile {
                    file: name.into(),
                    size: data.len() as u64,
                    sha256: digest(data),
                },
            )?;
        }
        for a in self.manifest.artifacts.iter().filter(|a| {
            matches!(
                a.role,
                ArtifactRole::ResourceApk
                    | ArtifactRole::ResourceLedger
                    | ArtifactRole::QnxResourcePack
                    | ArtifactRole::QnxResourceLedger
            )
        }) {
            insert_expected(
                files,
                GenerationFile {
                    file: a.file.clone(),
                    size: a.size,
                    sha256: a.sha256.clone(),
                },
            )?;
        }
        let total = files.values().try_fold(0u64, |sum, f| {
            sum.checked_add(f.size)
                .context("resource generation size overflow")
        })?;
        ensure!(
            total <= catalog::MAX_RELEASE_BYTES,
            "resource generation exceeds release byte bound"
        );
        Ok(())
    }
    pub(super) fn generation_id(&self, catalog: &str, selection: &str) -> Result<String> {
        ensure!(
            catalog::is_sha256(catalog) && catalog::is_sha256(selection),
            "resource generation input hash invalid"
        );
        Ok(digest(
            format!(
                "voboost-resource-generation-v1\n{catalog}\n{selection}\n{}\n",
                digest(&self.bytes)
            )
            .as_bytes(),
        ))
    }
}
pub(super) fn generation_identity(
    resource: Option<&ResourceProduct>,
    catalog: &str,
    selection: &str,
) -> Result<String> {
    match resource {
        Some(r) => r.generation_id(catalog, selection),
        None => generation_id(catalog, selection),
    }
}

pub(crate) struct ResourceBootstrapArtifact {
    pub(crate) id: String,
    pub(crate) file: String,
    pub(crate) size: u64,
}
impl VerifiedGeneration {
    /// Only signed, immutable generation members can enter native artifact FDs.
    pub(crate) fn resource_bootstrap_artifacts(
        &self,
        process: &str,
    ) -> Result<Vec<ResourceBootstrapArtifact>> {
        let installed = self.installed_agent_ids();
        if !["i18n-ru", "i18n-en"]
            .into_iter()
            .any(|agent| installed.contains(agent) && self.catalog.has_target(agent, process))
        {
            return Ok(Vec::new());
        }
        if !self.files.iter().any(|f| f.file == MANIFEST_NAME) {
            return Ok(Vec::new());
        }
        let bytes = self.read_file_exact(MANIFEST_NAME)?;
        let signature = self.read_file_exact(MANIFEST_SIGNATURE_NAME)?;
        let manifest = voboost_contract::release::verify_manifest_signature(
            &bytes,
            &signature,
            &crate::trust::release_catalog_public_key(),
        )
        .map_err(anyhow::Error::msg)?;
        let catalog_bytes = self.read_file_exact(CATALOG_FILE)?;
        let catalog_signature = self.read_file_exact(CATALOG_SIGNATURE_FILE)?;
        let resource = ResourceProduct::verified(
            manifest,
            bytes,
            signature,
            &self.catalog,
            &catalog_bytes,
            &catalog_signature,
        )?
        .context("resource bootstrap binding absent")?;
        ensure!(
            resource.generation_id(&self.catalog_sha256, &self.selection_sha256)? == self.id,
            "resource bootstrap generation binding differs"
        );
        let mut out = Vec::new();
        for a in resource
            .manifest
            .artifacts
            .iter()
            .filter(|a| a.role == ArtifactRole::ResourceApk)
        {
            let m = a.resource.as_ref().context("resource metadata absent")?;
            if !installed.contains(m.owner.as_str())
                || !self.catalog.has_target(&m.owner, process)
                || m.target_package != process
            {
                continue;
            }
            let variant = voboost_shared::owned_overlay::Variant::from_artifact_file(&a.file)
                .map_err(anyhow::Error::msg)?;
            let profile = variant.profile();
            for (id, file, size) in [
                (format!("{}:{profile}-apk", m.owner), a.file.clone(), a.size),
                (
                    format!("{}:{profile}-ledger", m.owner),
                    m.coverage_ledger.file.clone(),
                    m.coverage_ledger.size,
                ),
            ] {
                ensure!(
                    self.files.iter().any(|f| f.file == file && f.size == size),
                    "resource bootstrap file missing from immutable inventory"
                );
                out.push(ResourceBootstrapArtifact { id, file, size });
            }
        }
        Ok(out)
    }
}
