//! Current signed generation bytes prepared off the OEM UI thread.
use super::*;
use voboost_contract_core::resource_pack::{Inputs, OwnedPack};
/// Byte ownership only. The native host must independently fence its live
/// process/storage lease and prove the actual selected dictionary contents.
#[derive(Debug)]
pub struct OwnedPackLeaseInputs {
    pub storage_id: String,
    pub packs: Vec<OwnedPack>,
}
impl Authority {
    pub fn owned_resource_packs(&self) -> Result<OwnedPackLeaseInputs> {
        self.read_resource_packs(|| Ok(()))
    }
    fn read_resource_packs(
        &self,
        before_final: impl FnOnce() -> Result<()>,
    ) -> Result<OwnedPackLeaseInputs> {
        let generation = self
            .generation
            .as_ref()
            .ok_or("resource lease generation absent")?;
        let before = crate::install_layout::read_current(&self.root)?
            .ok_or("resource lease current authority absent")?;
        let pointer: Durable = parse_canonical(&before, 65536)?;
        if pointer.schema_version != 1
            || pointer.pair_id != self.config.pair_id
            || pointer.authority_epoch != self.config.authority_epoch
            || pointer.generation.as_deref() != Some(generation.storage_id.as_str())
        {
            return Err("resource lease current authority differs".into());
        }
        let mut packs = Vec::new();
        if generation
            .files
            .iter()
            .any(|f| f.role == WireRole::QnxResourcePack)
        {
            let directory = self
                .root
                .child("generations")?
                .child(&generation.storage_id)?;
            let read = |name: &str| -> Result<Vec<u8>> {
                let file = generation
                    .files
                    .iter()
                    .find(|f| f.file == name)
                    .ok_or("resource lease file absent from signed request")?;
                let bytes = directory.read(
                    name,
                    usize::try_from(file.size).map_err(|_| "resource lease size")?,
                    0o600,
                )?;
                if bytes.len() as u64 != file.size || hash(&bytes) != file.sha256 {
                    return Err("resource lease retained bytes differ".into());
                }
                Ok(bytes)
            };
            let manifest_bytes = read("voboost.json")?;
            let signature = read("voboost.json.sig")?;
            if hash(&manifest_bytes) != generation.release_sha256 {
                return Err("resource lease release identity differs".into());
            }
            let manifest =
                verify_manifest_signature(&manifest_bytes, &signature, &self.roots.release)?;
            let catalog = read("agents.json")?;
            for artifact in manifest
                .artifacts
                .iter()
                .filter(|a| a.role == ArtifactRole::QnxResourcePack)
            {
                let ledger_file = format!(
                    "{}.json",
                    artifact
                        .file
                        .strip_suffix(".kzb")
                        .ok_or("resource lease filename")?
                );
                packs.push(OwnedPack::verify(Inputs {
                    manifest: &manifest_bytes,
                    signature: &signature,
                    public_key: &self.roots.release,
                    catalog: &catalog,
                    artifact_file: &artifact.file,
                    pack: &read(&artifact.file)?,
                    ledger: &read(&ledger_file)?,
                })?);
            }
        }
        before_final()?;
        if crate::install_layout::read_current(&self.root)?
            .ok_or("resource lease current authority absent")?
            != before
        {
            return Err("resource lease authority changed during preparation".into());
        }
        Ok(OwnedPackLeaseInputs {
            storage_id: generation.storage_id.clone(),
            packs,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn imported() -> (tempfile::TempDir, Authority) {
        let (temp, config, roots, bytes, request, android) = crate::engine::tests::fixture();
        let mut a = Authority::open(config, unsafe { libc::geteuid() }, roots).unwrap();
        let envelope = request.sign(&android).unwrap();
        let mut files = vec![WireFile {
            role: WireRole::Request,
            file: "request.vbc".into(),
            size: envelope.len() as u64,
            sha256: hash(&envelope),
        }];
        files.extend(request.files.clone().unwrap());
        a.import(
            &envelope,
            &NetworkHeader {
                protocol_version: 1,
                files,
            },
            &bytes,
        )
        .unwrap();
        (temp, a)
    }
    #[test]
    fn no_pack_current_generation_has_empty_inert_lease() {
        let (_t, a) = imported();
        let lease = a.owned_resource_packs().unwrap();
        assert_eq!(lease.storage_id, a.generation.as_ref().unwrap().storage_id);
        assert!(lease.packs.is_empty());
    }
    #[test]
    fn stale_durable_generation_is_rejected() {
        let (_t, a) = imported();
        let mut p = a.state.clone();
        p.generation = Some("a".repeat(64));
        crate::install_layout::write_current(&a.root, &ascii_json(&p).unwrap()).unwrap();
        assert!(a
            .owned_resource_packs()
            .unwrap_err()
            .contains("current authority"));
    }
    #[test]
    fn concurrent_authority_change_discards_prepared_lease() {
        let (_t, a) = imported();
        assert!(a
            .read_resource_packs(|| {
                let mut p = a.state.clone();
                p.observation_revision += 1;
                crate::install_layout::write_current(&a.root, &ascii_json(&p)?)
            })
            .unwrap_err()
            .contains("changed during preparation"));
    }
}
