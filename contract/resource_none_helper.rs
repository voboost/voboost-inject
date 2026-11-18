//! Signed admission of the owner-bound Java helper used by the next-boot None cleanup.
//!
//! The catalog entrypoint remains `ru.voboost.agents.i18n.ru.I18nRuAgent`.
//! The separate fixed `I18nRuNoneCleanup` class is an execution target only.
//!
//! The product signature verified by `OwnedResourceArtifact::verify`
//! authenticates the release closure. This module verifies that the delivered
//! helper bytes are the agent-module artifact bound by that signed catalog to
//! `com.qinggan.app.setting`; it does not establish firmware compatibility.

use crate::agent_catalog::{AgentCatalog, TargetAbi, TargetPlatform};
use crate::release::{self, Activation, ArtifactRole, Manifest};
use crate::resource::OwnedResourceArtifact;
use sha2::{Digest, Sha256};

/// Fixed resource owner profile (must equal `ResourceMetadata::owner`).
pub const I18N_RU_OWNER: &str = "i18n-ru";
/// Fixed Android target process for the i18n-ru helper.
pub const I18N_RU_TARGET_PROCESS: &str = "com.qinggan.app.setting";
/// ACTUAL catalog entryClass of the i18n-ru agent (see I18nRuAgent.json).
pub const I18N_RU_AGENT_ENTRY_CLASS: &str = "ru.voboost.agents.i18n.ru.I18nRuAgent";
/// Fixed helper EXECUTION class (argument-free nextboot None cleanup). This is
/// a downstream runtime constant ONLY: the catalog entrypoint is NOT changed.
pub const I18N_RU_NONE_CLEANUP_CLASS: &str = "ru.voboost.agents.i18n.ru.I18nRuNoneCleanup";
/// English resource owner and its fixed agent/helper classes.
pub const I18N_EN_OWNER: &str = "i18n-en";
pub const I18N_EN_AGENT_ENTRY_CLASS: &str = "ru.voboost.agents.i18n.en.I18nEnAgent";
pub const I18N_EN_NONE_CLEANUP_CLASS: &str = "ru.voboost.agents.i18n.en.I18nEnNoneCleanup";
fn entry_class(owner: &str) -> Result<&'static str, String> {
    match owner {
        I18N_RU_OWNER => Ok(I18N_RU_AGENT_ENTRY_CLASS),
        I18N_EN_OWNER => Ok(I18N_EN_AGENT_ENTRY_CLASS),
        _ => Err("none helper resource owner unsupported".into()),
    }
}
/// Upper byte bound for one module DEX (`release::maximum_size(AgentModule)`).
pub const MAX_NONE_HELPER_BYTES: usize = 64 * 1024 * 1024;

fn hex_sha256(bytes: &[u8]) -> String {
    // Same digest-iteration hex format as the existing contract resource code
    // path; deliberately no new `hex` dependency for this module.
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Sealed verified admission of OUR delivered helper module bytes only.
#[derive(Debug)]
pub struct VerifiedNoneHelper {
    module_file: String,
    bytes: Vec<u8>,
    release_identity: String,
    manifest_sha256: String,
}

impl VerifiedNoneHelper {
    /// Signed catalog selector for bounded staging reads, not compatibility admission.
    /// The bound agent target is the one whose Android process equals the
    /// resource target package; each translation agent binds its own module.
    pub fn module_file_for(resource: &OwnedResourceArtifact) -> Result<String, String> {
        let expected_class = entry_class(&resource.descriptor().owner)?;
        let catalog = AgentCatalog::parse(resource.catalog_bytes())?;
        let selected = catalog
            .agents
            .iter()
            .filter(|a| a.id == resource.descriptor().owner)
            .flat_map(|a| &a.targets)
            .filter(|t| {
                t.process == resource.descriptor().target_package
                    && t.platform == TargetPlatform::Android
                    && t.entry_abi == TargetAbi::AndroidJavaV1
            })
            .collect::<Vec<_>>();
        if selected.len() != 1 {
            return Err("none helper target absent or ambiguous".into());
        }
        let target = selected[0];
        if target.entry_class.as_deref() != Some(expected_class)
            || !matches!(
                release::classify(&target.file),
                Ok((ArtifactRole::AgentModule, Activation::AgentGeneration, None))
            )
        {
            return Err("none helper catalog binding invalid".into());
        }
        Ok(target.file.clone())
    }
    /// Verifies, against the already product-signed `resource`:
    /// 1. the canonical catalog carrying exactly one descriptor owner whose
    //     Android target for the resource target package binds
    ///    `file`/`size`/`sha256` and the ACTUAL agent `entryClass` above;
    /// 2. the signed manifest intersects that binding on an exact
    ///    `ArtifactRole::AgentModule` + `Activation::AgentGeneration` artifact
    ///    with identical size and digest;
    /// 3. `module_bytes` are exactly those authenticated bytes.
    pub fn verify(resource: &OwnedResourceArtifact, module_bytes: &[u8]) -> Result<Self, String> {
        if module_bytes.is_empty() || module_bytes.len() > MAX_NONE_HELPER_BYTES {
            return Err("none helper module byte bound".into());
        }
        let descriptor = resource.descriptor();
        let expected_class = entry_class(&descriptor.owner)?;
        let catalog = AgentCatalog::parse(resource.catalog_bytes())?;
        let owner_agents = catalog
            .agents
            .iter()
            .filter(|agent| agent.id == descriptor.owner)
            .collect::<Vec<_>>();
        if owner_agents.len() != 1 {
            return Err("none helper owner absent or ambiguous".into());
        }
        let targets = owner_agents[0]
            .targets
            .iter()
            .filter(|target| {
                target.process == descriptor.target_package
                    && target.platform == TargetPlatform::Android
                    && target.entry_abi == TargetAbi::AndroidJavaV1
            })
            .collect::<Vec<_>>();
        if targets.len() != 1 {
            return Err("none helper target absent or ambiguous".into());
        }
        let target = targets[0];
        // entry_class is nullable in the contract (Option<String>) but the
        // catalog producer requires a present, voboost-namespace executor
        // class; we accept only the exact actual agent entrypoint.
        if target.entry_class.as_deref() != Some(expected_class) {
            return Err("none helper entry class differs".into());
        }
        if !matches!(
            release::classify(&target.file),
            Ok((ArtifactRole::AgentModule, Activation::AgentGeneration, None))
        ) {
            return Err("none helper target file is not a catalog agent module".into());
        }
        if target.size == 0 || target.size != module_bytes.len() as u64 {
            return Err("none helper module size differs from catalog binding".into());
        }
        let manifest = Manifest::parse(resource.manifest_bytes())?;
        let artifact = manifest
            .artifact(&target.file)
            .map_err(|_| "none helper module absent from signed manifest".to_string())?;
        if artifact.role != ArtifactRole::AgentModule
            || artifact.activation != Activation::AgentGeneration
        {
            return Err("none helper module role mismatch in signed manifest".into());
        }
        if artifact.size != target.size || artifact.sha256 != target.sha256 {
            return Err("none helper manifest-catalog integrity binding differs".into());
        }
        let digest = hex_sha256(module_bytes);
        if artifact.size != module_bytes.len() as u64 || artifact.sha256 != digest {
            return Err("none helper module bytes differ".into());
        }
        Ok(Self {
            module_file: target.file.clone(),
            bytes: module_bytes.to_vec(),
            release_identity: manifest.release_identity.clone(),
            manifest_sha256: resource.manifest_sha256().to_string(),
        })
    }

    /// Catalog file basename of the verified module (never a path).
    pub fn module_file(&self) -> &str {
        &self.module_file
    }
    /// Exact authenticated module bytes for the helper runtime.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Release identity of the signed manifest that authenticated these bytes.
    pub fn release_identity(&self) -> &str {
        &self.release_identity
    }
    /// Digest of the signed manifest binding (provenance only; callers must
    /// not treat it as authority to load other bytes).
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }
}

#[cfg(test)]
#[path = "resource_none_helper_tests.rs"]
mod tests;
