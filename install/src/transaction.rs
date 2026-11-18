use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

const TERMINAL_INTENT: &str = "install-terminal.json";

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalIntent {
    pub schema_version: u32,
    pub transaction_id: String,
    pub manifest_sha256: String,
    pub installed_apk: serde_json::Value,
}

impl TerminalIntent {
    pub fn bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

pub fn prepare(recovery: &Path) -> Result<(), String> {
    fs::create_dir_all(recovery).map_err(|error| format!("create install recovery: {error}"))?;
    fs::set_permissions(recovery, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("mode install recovery: {error}"))?;
    File::open(recovery)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync install recovery: {error}"))
}

pub fn terminal_intent_path(root: &Path) -> PathBuf {
    root.join("recovery").join(TERMINAL_INTENT)
}

pub fn read_terminal_intent(intent_path: &Path) -> Result<TerminalIntent, String> {
    let bytes = crate::read_bounded(intent_path, 4096, 0o600)
        .map_err(|error| format!("read install terminal intent: {error}"))?;
    let actual: TerminalIntent = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse install terminal intent: {error}"))?;
    if actual.bytes()? != bytes {
        return Err("install terminal intent correlation is invalid".to_string());
    }
    Ok(actual)
}

pub fn cleanup_payload(
    staging: &Path,
    recovery: &Path,
    expected: &TerminalIntent,
) -> Result<(), String> {
    let actual = read_terminal_intent(&terminal_intent_path(
        recovery
            .parent()
            .ok_or("install recovery has no parent")?
            .parent()
            .ok_or("install recovery root has no parent")?,
    ))?;
    if actual != *expected {
        return Err("install terminal intent correlation is invalid".to_string());
    }
    let allowed_files = BTreeSet::from([
        "install-journal.json",
        "fresh-state.json",
        "generation-ack.json",
        "install-acceptance.json",
        "initial-seeding-arm.json",
        "mount-policy-journal.json",
        "policy.meta.json",
        "policy-sidecars.json",
        "precompiled_sepolicy.orig",
        "precompiled_sepolicy.patched",
    ]);
    let entries = if recovery.exists() {
        fs::read_dir(recovery)
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
    } else {
        Vec::new()
    };
    for entry in &entries {
        let name = entry.file_name();
        let name = name.to_str().ok_or("non-UTF8 install recovery member")?;
        let file_type = entry.file_type().map_err(|error| error.to_string())?;
        if name == "frozen" {
            if !file_type.is_dir() {
                return Err("foreign install recovery member".to_string());
            }
            validate_frozen(&entry.path())?;
        } else if !allowed_files.contains(name) || !file_type.is_file() {
            return Err("foreign install recovery member".to_string());
        }
        if name == "install-acceptance.json" {
            crate::acceptance::validate_cleanup(
                &entry.path(),
                &expected.transaction_id,
                &expected.manifest_sha256,
            )?;
        }
    }
    if staging.exists() {
        fs::remove_dir_all(staging).map_err(|error| format!("remove install staging: {error}"))?;
    }
    for entry in entries {
        if entry.file_name() == "frozen" {
            fs::remove_dir_all(entry.path()).map_err(|error| error.to_string())?;
        } else if entry.file_name() != "install-journal.json" {
            fs::remove_file(entry.path()).map_err(|error| error.to_string())?;
        }
    }
    if recovery.exists() {
        File::open(recovery)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("sync install cleanup: {error}"))?;
    }
    Ok(())
}

fn validate_frozen(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    #[cfg(target_os = "android")]
    let owner = (0, 0);
    #[cfg(not(target_os = "android"))]
    let owner = unsafe { (libc::geteuid(), libc::getegid()) };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner.0
        || metadata.gid() != owner.1
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err("frozen install closure has a foreign identity".into());
    }
    let entries = fs::read_dir(path)
        .map_err(|error| error.to_string())?
        .take(crate::MAX_STAGING_ENTRIES + 1)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    if entries.len() > crate::MAX_STAGING_ENTRIES {
        return Err("frozen install closure has a foreign inventory".into());
    }
    for entry in entries {
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| error.to_string())?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.nlink() != 1
            || metadata.uid() != owner.0
            || metadata.gid() != owner.1
            || metadata.permissions().mode() & 0o7777 != 0o600
        {
            return Err("frozen install member has a foreign identity".into());
        }
    }
    Ok(())
}

pub fn cleanup_control(recovery: &Path, expected: &TerminalIntent) -> Result<(), String> {
    let actual = read_terminal_intent(&terminal_intent_path(
        recovery
            .parent()
            .ok_or("install recovery has no parent")?
            .parent()
            .ok_or("install recovery root has no parent")?,
    ))?;
    if actual != *expected {
        return Err("install terminal intent correlation is invalid".to_string());
    }
    if recovery.exists() {
        let entries = fs::read_dir(recovery)
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        for entry in entries {
            if entry.file_name() != "install-journal.json"
                || !entry
                    .file_type()
                    .map_err(|error| error.to_string())?
                    .is_file()
            {
                return Err("foreign install control member".to_string());
            }
            fs::remove_file(entry.path()).map_err(|error| error.to_string())?;
        }
        File::open(recovery)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("sync install control cleanup: {error}"))?;
        fs::remove_dir(recovery).map_err(|error| format!("remove install recovery: {error}"))?;
    }
    File::open(recovery.parent().ok_or("install recovery has no parent")?)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync recovery root: {error}"))?;
    Ok(())
}

pub fn require_terminal_transients_absent(root: &Path, transaction_id: &str) -> Result<(), String> {
    if root.join("install").join(transaction_id).exists()
        || root.join("recovery").join(transaction_id).exists()
    {
        return Err("terminal install transients remain without operation pointer".into());
    }
    Ok(())
}

pub fn remove_terminal_intent(root: &Path, transaction_id: &str) -> Result<(), String> {
    let path = terminal_intent_path(root);
    let actual = read_terminal_intent(&path)?;
    if actual.transaction_id != transaction_id {
        return Err("foreign install terminal intent".into());
    }
    fs::remove_file(&path).map_err(|error| format!("remove install terminal intent: {error}"))?;
    File::open(path.parent().ok_or("terminal intent has no parent")?)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync terminal intent parent: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_cleanup_is_exact_and_foreign_residue_is_non_mutating() {
        let root = tempfile::tempdir().unwrap();
        let recovery_root = root.path().join("recovery");
        let recovery = recovery_root.join("11".repeat(32));
        let staging = root.path().join("install").join("11".repeat(32));
        fs::create_dir_all(&recovery).unwrap();
        fs::create_dir_all(&staging).unwrap();
        let frozen = recovery.join("frozen");
        fs::create_dir(&frozen).unwrap();
        fs::set_permissions(&frozen, fs::Permissions::from_mode(0o700)).unwrap();
        for index in 0..crate::MAX_STAGING_ENTRIES {
            let path = frozen.join(format!("member-{index:02}"));
            fs::write(&path, b"owned").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::write(staging.join("voboost-app.apk"), b"apk").unwrap();
        fs::write(recovery.join("install-journal.json"), b"journal").unwrap();
        fs::write(recovery.join("generation-ack.json"), b"ack").unwrap();
        fs::write(recovery.join("initial-seeding-arm.json"), b"arm").unwrap();
        fs::write(recovery.join("foreign"), b"foreign").unwrap();
        let intent = TerminalIntent {
            schema_version: 1,
            transaction_id: "11".repeat(32),
            manifest_sha256: "22".repeat(32),
            installed_apk: serde_json::json!({"test": true}),
        };
        let intent_path = terminal_intent_path(root.path());
        fs::write(&intent_path, intent.bytes().unwrap()).unwrap();
        fs::set_permissions(&intent_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(cleanup_payload(&staging, &recovery, &intent).is_err());
        assert!(staging.join("voboost-app.apk").exists());
        fs::remove_file(recovery.join("foreign")).unwrap();
        cleanup_payload(&staging, &recovery, &intent).unwrap();
        assert!(!staging.exists());
        assert!(!frozen.exists());
        assert!(!recovery.join("generation-ack.json").exists());
        assert!(!recovery.join("initial-seeding-arm.json").exists());
        assert!(recovery.join("install-journal.json").exists());
        cleanup_control(&recovery, &intent).unwrap();
        assert!(!recovery.exists());
        assert!(intent_path.exists());
        remove_terminal_intent(root.path(), &intent.transaction_id).unwrap();
        assert!(!intent_path.exists());
    }

    #[test]
    fn emulator_only_persisted_names_are_always_foreign_recovery_residue() {
        let root = tempfile::tempdir().unwrap();
        let transaction_id = "33".repeat(32);
        let recovery = root.path().join("recovery").join(&transaction_id);
        let staging = root.path().join("install").join(&transaction_id);
        fs::create_dir_all(&recovery).unwrap();
        fs::create_dir_all(&staging).unwrap();
        fs::write(staging.join("artifact"), b"artifact").unwrap();
        fs::write(recovery.join("install-journal.json"), b"journal").unwrap();
        fs::write(
            recovery.join("emulator-selinux-skipped.json"),
            b"emulator-only",
        )
        .unwrap();
        let intent = TerminalIntent {
            schema_version: 1,
            transaction_id,
            manifest_sha256: "44".repeat(32),
            installed_apk: serde_json::json!({"test": true}),
        };
        let intent_path = terminal_intent_path(root.path());
        fs::write(&intent_path, intent.bytes().unwrap()).unwrap();
        fs::set_permissions(&intent_path, fs::Permissions::from_mode(0o600)).unwrap();

        let result = cleanup_payload(&staging, &recovery, &intent);
        assert_eq!(result.unwrap_err(), "foreign install recovery member");
        assert!(staging.join("artifact").exists());
        assert!(recovery.join("emulator-selinux-skipped.json").exists());
    }
}
