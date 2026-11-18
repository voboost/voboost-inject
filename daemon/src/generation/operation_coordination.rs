use super::*;
use crate::operation_contract::{GenerationGuard, Operation, OperationDescriptor};
use voboost_contract::release::Manifest;

fn lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Debug)]
pub(super) struct InstallGenerationContext {
    pub transaction_id: String,
    pub apk_size: u64,
    pub apk_sha256: String,
    pub catalog_sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InstallJournalAuthority {
    schema_version: u32,
    transaction_id: String,
    manifest_sha256: String,
    phase: String,
    boot_ids: Vec<String>,
}

fn parse_install_generation_context(
    pointer: &OperationDescriptor,
    journal: &[u8],
    descriptor: &[u8],
) -> Result<InstallGenerationContext> {
    ensure!(
        digest(journal) == pointer.journal_sha256,
        "install WAL digest differs from operation authority"
    );
    let journal_value: InstallJournalAuthority = serde_json::from_slice(journal)?;
    ensure!(
        serde_json::to_vec(&journal_value).map(|mut value| {
            value.push(b'\n');
            value
        })? == journal,
        "install WAL is not canonical"
    );
    ensure!(
        journal_value.schema_version == 1
            && journal_value.transaction_id == pointer.transaction_id
            && lower_sha256(&journal_value.manifest_sha256)
            && journal_value.phase == "install-agents"
            && journal_value.boot_ids.len() == 1,
        "install WAL does not authorize generation activation"
    );
    ensure!(
        digest(descriptor) == journal_value.manifest_sha256,
        "install descriptor differs from WAL authority"
    );
    let descriptor = Manifest::parse(descriptor).map_err(anyhow::Error::msg)?;
    let apk = descriptor.app_artifact().map_err(anyhow::Error::msg)?;
    let catalog = descriptor
        .artifact("agents.json")
        .map_err(anyhow::Error::msg)?;
    Ok(InstallGenerationContext {
        transaction_id: pointer.transaction_id.clone(),
        apk_size: apk.size,
        apk_sha256: apk.sha256.clone(),
        catalog_sha256: catalog.sha256.clone(),
    })
}

impl GenerationStore {
    pub(super) fn install_generation_context(&self) -> Result<Option<InstallGenerationContext>> {
        let root = Directory::open(&self.root)?;
        let bytes = match root.read_trusted("operation.json", 4096, ROOT_FILE_MODE) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.set_log_operation(None);
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        let pointer = OperationDescriptor::parse(&bytes).map_err(anyhow::Error::msg)?;
        if pointer.outcome == "complete" {
            self.set_log_operation(None);
            return Ok(None);
        }
        ensure!(
            pointer.operation == Operation::Install,
            "generation activation is fenced by a foreign operation"
        );
        let recovery = Directory::open(&self.root.join("recovery").join(&pointer.transaction_id))?;
        let journal = recovery.read_trusted("install-journal.json", 4096, ROOT_FILE_MODE)?;
        let frozen = Directory::open(
            &self
                .root
                .join("recovery")
                .join(&pointer.transaction_id)
                .join("frozen"),
        )?;
        let descriptor = frozen.read_trusted(
            voboost_contract::release::MANIFEST_NAME,
            voboost_contract::release::MAX_MANIFEST_BYTES,
            ROOT_FILE_MODE,
        )?;
        let context = parse_install_generation_context(&pointer, &journal, &descriptor)?;
        self.set_log_operation(Some(&context.transaction_id));
        Ok(Some(context))
    }

    pub(super) fn ensure_no_active_global_operation(&self) -> Result<()> {
        self.install_generation_context().map(|_| ())
    }

    pub(crate) fn install_generation_waiting(&self) -> bool {
        matches!(self.install_generation_context(), Ok(Some(_)))
    }

    pub(super) fn acquire_generation_guard(&self) -> Result<GenerationGuard> {
        match GenerationGuard::acquire_in(&self.root) {
            Ok(guard) => Ok(guard),
            Err(error) if error.starts_with("operation busy") => {
                let guard = GenerationGuard::acquire_install_generation_in(&self.root)
                    .map_err(anyhow::Error::msg)?;
                self.install_generation_context()?
                    .context("install generation context absent")?;
                Ok(guard)
            }
            Err(error) => Err(anyhow::Error::msg(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical(value: &impl Serialize) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn descriptor(extra_transaction: bool) -> Vec<u8> {
        let mut descriptor = Manifest::parse(include_bytes!(
            "../../../test/fixtures/product-release/voboost/valid/minimal.json"
        ))
        .unwrap();
        let apk = descriptor
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.file == "voboost-app.apk")
            .unwrap();
        apk.size = 123;
        apk.sha256 = "55".repeat(32);
        descriptor
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.file == "agents.json")
            .unwrap()
            .sha256 = "22".repeat(32);
        if extra_transaction {
            let mut value = serde_json::to_value(descriptor).unwrap();
            value.as_object_mut().unwrap().insert(
                "transactionId".to_string(),
                serde_json::json!("66".repeat(32)),
            );
            canonical(&value)
        } else {
            canonical(&descriptor)
        }
    }

    fn authority(descriptor: &[u8]) -> (OperationDescriptor, Vec<u8>) {
        let transaction_id = "66".repeat(32);
        let journal = canonical(&InstallJournalAuthority {
            schema_version: 1,
            transaction_id: transaction_id.clone(),
            manifest_sha256: digest(descriptor),
            phase: "install-agents".to_string(),
            boot_ids: vec!["01234567-89ab-cdef-0123-456789abcdef".to_string()],
        });
        let pointer = OperationDescriptor {
            schema_version: 1,
            operation: Operation::Install,
            transaction_id: transaction_id.clone(),
            journal: format!("recovery/{transaction_id}/install-journal.json"),
            phase: "install-agents".to_string(),
            outcome: "running".to_string(),
            reboot_count: 1,
            boot_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
            status_sequence: 11,
            journal_sha256: digest(&journal),
            error: None,
            installed_apk: None,
        };
        (pointer, journal)
    }

    #[test]
    fn install_generation_uses_the_separate_transaction_and_descriptor_authorities() {
        let descriptor = descriptor(false);
        let (pointer, journal) = authority(&descriptor);
        let context = parse_install_generation_context(&pointer, &journal, &descriptor).unwrap();
        assert_eq!(context.transaction_id, "66".repeat(32));
        assert_eq!(context.apk_size, 123);
        assert_eq!(context.apk_sha256, "55".repeat(32));
        assert_eq!(context.catalog_sha256, "22".repeat(32));
    }

    #[test]
    fn install_generation_rejects_a_legacy_descriptor_transaction_field() {
        let descriptor = descriptor(true);
        let (pointer, journal) = authority(&descriptor);
        assert!(parse_install_generation_context(&pointer, &journal, &descriptor).is_err());
    }

    #[test]
    fn install_generation_requires_both_authority_digests() {
        let descriptor = descriptor(false);
        let (pointer, mut journal) = authority(&descriptor);
        journal[20] ^= 1;
        assert!(parse_install_generation_context(&pointer, &journal, &descriptor).is_err());

        let (pointer, journal) = authority(&descriptor);
        let mut changed_descriptor = descriptor;
        changed_descriptor[30] ^= 1;
        assert!(parse_install_generation_context(&pointer, &journal, &changed_descriptor).is_err());
    }

    #[test]
    fn completed_install_is_not_generation_activation_authority() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let transaction_id = "77".repeat(32);
        let pointer = OperationDescriptor {
            schema_version: 1,
            operation: Operation::Install,
            transaction_id: transaction_id.clone(),
            journal: format!("recovery/{transaction_id}/install-journal.json"),
            phase: "install-complete".into(),
            outcome: "complete".into(),
            reboot_count: 2,
            boot_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
            status_sequence: 36,
            journal_sha256: "88".repeat(32),
            error: None,
            installed_apk: Some(serde_json::json!({
                "packageName": "ru.voboost",
                "versionCode": 1,
                "certificateSha256": "99".repeat(32),
                "path": "/data/app/ru.voboost/base.apk",
                "size": 1,
                "sha256": "aa".repeat(32)
            })),
        };
        std::fs::write(
            root.path().join("operation.json"),
            pointer.canonical_bytes().unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(
            root.path().join("operation.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let store = GenerationStore::new(root.path(), root.path().join("incoming"));
        assert!(store.install_generation_context().unwrap().is_none());
    }
}
