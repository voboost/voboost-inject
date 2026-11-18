//! Inert, private recovery inputs retained before Android teardown.
use std::io;
use std::path::Path;
use voboost_shared::secure_fs::Directory;

const ROOT_FILES: &[&str] = &["voboost.json", "voboost.json.sig", "voboost-cluster-daemon"];
const CLUSTER_FILES: &[&str] = &[
    "provision.json",
    "device-signing.seed",
    "transport.p12",
    "mailbox.json",
    "request.vbc",
    "uninstall-authority.json",
    "uninstall-report.vbc",
    "uninstall-final-report.vbc",
    "uninstall-provisional-report.vbc",
    "uninstall-delivery-owner.json",
];

fn copy_member(
    source: &Directory,
    target: &Directory,
    name: &str,
    maximum: usize,
    required: bool,
) -> Result<(), String> {
    let bytes = match source.read_trusted_bounded(name, maximum) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound && !required => return Ok(()),
        Err(error) => return Err(format!("read recovery member {name}: {error}")),
    };
    if target
        .entry_exists(name)
        .map_err(|error| error.to_string())?
    {
        let retained = target
            .read_trusted(name, maximum, 0o600)
            .map_err(|error| error.to_string())?;
        if retained != bytes {
            return Err(format!("retained recovery member differs: {name}"));
        }
        return Ok(());
    }
    target
        .write_atomic(name, &bytes, 0o600)
        .map_err(|error| format!("retain recovery member {name}: {error}"))
}

pub(crate) fn preserve_if_pending(root: &Path, transaction: &str) -> Result<bool, String> {
    if pending(root, transaction)? {
        return Ok(true);
    }
    let directory = Directory::open(root).map_err(|error| error.to_string())?;
    let cluster = match directory.open_child("cluster") {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.to_string()),
    };
    if !cluster
        .entry_exists("provision.json")
        .map_err(|error| error.to_string())?
    {
        return if cluster
            .entry_exists("device-signing.seed")
            .map_err(|error| error.to_string())?
        {
            preserve(root, transaction)
        } else {
            Ok(false)
        };
    }
    let bytes = cluster
        .read_trusted("uninstall-authority.json", 65536, 0o600)
        .map_err(|error| format!("read QNX removal recovery authority: {error}"))?;
    let authority: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    match authority.get("state").and_then(serde_json::Value::as_str) {
        Some("completed") => Ok(false),
        Some("pending" | "restored") => preserve(root, transaction),
        _ => Err("QNX removal authority has an unknown state; recovery inputs retained".into()),
    }
}

pub(crate) fn pending(root: &Path, transaction: &str) -> Result<bool, String> {
    if transaction.len() != 64
        || !transaction
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid recovery transaction".into());
    }
    let source = Directory::open(root).map_err(|error| error.to_string())?;
    let recovery = match source
        .open_child("recovery")
        .and_then(|dir| dir.open_child(transaction))
    {
        Ok(dir) => dir,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.to_string()),
    };
    recovery
        .validate_owner_mode(
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o700,
        )
        .map_err(|error| error.to_string())?;
    let bytes = match recovery.read_trusted("recovery.json", 4096, 0o600) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.to_string()),
    };
    let marker: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if marker
        != serde_json::json!({"schemaVersion":1,"transactionId":transaction,"domain":"cluster","state":"pending"})
    {
        return Err("retained recovery marker differs from transaction".into());
    }
    let cluster = recovery
        .open_child("cluster")
        .map_err(|error| error.to_string())?;
    cluster
        .validate_owner_mode(
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o700,
        )
        .map_err(|error| error.to_string())?;
    for name in ROOT_FILES {
        if recovery
            .read_trusted(name, 16 * 1024 * 1024, 0o600)
            .map_err(|error| error.to_string())?
            .is_empty()
        {
            return Err(format!("empty retained recovery member: {name}"));
        }
    }
    for name in [
        "provision.json",
        "device-signing.seed",
        "transport.p12",
        "request.vbc",
        "uninstall-authority.json",
    ] {
        if cluster
            .read_trusted(name, 1024 * 1024, 0o600)
            .map_err(|error| error.to_string())?
            .is_empty()
        {
            return Err(format!("empty retained recovery member: {name}"));
        }
    }
    Ok(true)
}

pub(crate) fn preserve(root: &Path, transaction: &str) -> Result<bool, String> {
    if pending(root, transaction)? {
        return Ok(true);
    }
    let source = Directory::open(root).map_err(|error| error.to_string())?;
    let cluster = match source.open_child("cluster") {
        Ok(dir) => dir,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.to_string()),
    };
    cluster
        .validate_owner_mode(
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o700,
        )
        .map_err(|error| error.to_string())?;
    if !cluster
        .entry_exists("provision.json")
        .map_err(|error| error.to_string())?
        && !cluster
            .entry_exists("device-signing.seed")
            .map_err(|error| error.to_string())?
    {
        return Ok(false);
    }
    let recovery = source
        .open_or_create_private_child("recovery")
        .map_err(|error| error.to_string())?;
    let target = recovery
        .open_or_create_private_child(transaction)
        .map_err(|error| error.to_string())?;
    let cluster_target = target
        .open_or_create_private_child("cluster")
        .map_err(|error| error.to_string())?;
    let mut errors = Vec::new();
    for name in ROOT_FILES {
        if let Err(error) = copy_member(&source, &target, name, 16 * 1024 * 1024, true) {
            errors.push(error);
        }
    }
    for name in CLUSTER_FILES {
        if let Err(error) = copy_member(
            &cluster,
            &cluster_target,
            name,
            1024 * 1024,
            matches!(
                *name,
                "provision.json"
                    | "device-signing.seed"
                    | "transport.p12"
                    | "request.vbc"
                    | "uninstall-authority.json"
            ),
        ) {
            errors.push(error);
        }
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    cluster_target
        .sync_all()
        .map_err(|error| error.to_string())?;
    target
        .write_atomic(
            "recovery.json",
            &serde_json::to_vec(&serde_json::json!({
                "schemaVersion":1,"transactionId":transaction,"domain":"cluster","state":"pending"
            }))
            .map_err(|error| error.to_string())?,
            0o600,
        )
        .map_err(|error| error.to_string())?;
    target.sync_all().map_err(|error| error.to_string())?;
    recovery.sync_all().map_err(|error| error.to_string())?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn recovery_lookup_rejects_noncanonical_transactions_before_filesystem_access() {
        for transaction in ["", "..", "../cluster", &"A".repeat(64), &"a".repeat(63)] {
            assert_eq!(
                preserve_if_pending(Path::new("missing-recovery-root"), transaction).unwrap_err(),
                "invalid recovery transaction"
            );
        }
    }

    #[test]
    fn completed_cluster_removal_does_not_create_a_pending_snapshot() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let root = tmp.path().join("voboost");
        std::fs::create_dir(&root).unwrap();
        let cluster = Directory::open(&root)
            .unwrap()
            .open_or_create_private_child("cluster")
            .unwrap();
        cluster
            .write_atomic("provision.json", b"provision", 0o600)
            .unwrap();
        cluster
            .write_atomic(
                "uninstall-authority.json",
                br#"{"state":"completed"}"#,
                0o600,
            )
            .unwrap();
        assert!(!preserve_if_pending(&root, &"a".repeat(64)).unwrap());
        assert!(!root.join("recovery").exists());
        cluster
            .write_atomic("uninstall-authority.json", br#"{"state":"unknown"}"#, 0o600)
            .unwrap();
        assert!(preserve_if_pending(&root, &"a".repeat(64)).is_err());
    }

    #[test]
    fn retained_inputs_survive_ordinary_cleanup_and_are_private() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let root = tmp.path().join("voboost");
        std::fs::create_dir(&root).unwrap();
        let dir = Directory::open(&root).unwrap();
        let cluster = dir.open_or_create_private_child("cluster").unwrap();
        cluster
            .write_atomic("provision.json", b"provision", 0o600)
            .unwrap();
        cluster
            .write_atomic("device-signing.seed", &[7; 32], 0o600)
            .unwrap();
        dir.write_atomic("voboost-cluster-daemon", b"helper", 0o700)
            .unwrap();
        for name in ["voboost.json", "voboost.json.sig"] {
            dir.write_atomic(name, b"fixture", 0o600).unwrap();
        }
        for name in ["transport.p12", "request.vbc", "uninstall-authority.json"] {
            cluster.write_atomic(name, b"fixture", 0o600).unwrap();
        }
        let tx = "a".repeat(64);
        assert!(preserve(&root, &tx).unwrap());
        assert!(preserve(&root, &tx).unwrap());
        for entry in std::fs::read_dir(&root).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name() == "recovery" {
                continue;
            }
            if entry.file_type().unwrap().is_dir() {
                std::fs::remove_dir_all(entry.path()).unwrap();
            } else {
                std::fs::remove_file(entry.path()).unwrap();
            }
        }
        assert!(!root.join("cluster").exists());
        assert!(!root.join("voboost-cluster-daemon").exists());
        assert!(pending(&root, &tx).unwrap());
        assert!(preserve_if_pending(&root, &tx).unwrap());
        assert!(preserve(&root, &tx).unwrap());
        let retained = root.join("recovery").join(tx);
        assert_eq!(
            std::fs::read(retained.join("cluster/device-signing.seed")).unwrap(),
            [7; 32]
        );
        assert_eq!(
            std::fs::metadata(retained.join("voboost-cluster-daemon"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&retained).unwrap().permissions().mode() & 0o777,
            0o700
        );
        std::fs::remove_file(retained.join("cluster/transport.p12")).unwrap();
        assert!(pending(&root, &"a".repeat(64)).is_err());
        assert!(preserve_if_pending(&root, &"a".repeat(64)).is_err());
    }
    #[test]
    fn missing_required_members_preserve_available_data_without_ready_marker() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let root = tmp.path().join("voboost");
        std::fs::create_dir(&root).unwrap();
        let dir = Directory::open(&root).unwrap();
        let cluster = dir.open_or_create_private_child("cluster").unwrap();
        cluster
            .write_atomic("device-signing.seed", &[9; 32], 0o600)
            .unwrap();
        let tx = "c".repeat(64);
        let error = preserve(&root, &tx).unwrap_err();
        assert!(error.contains("voboost.json"));
        assert!(error.contains("transport.p12"));
        let target = root.join("recovery").join(tx);
        assert_eq!(
            std::fs::read(target.join("cluster/device-signing.seed")).unwrap(),
            [9; 32]
        );
        assert!(!target.join("recovery.json").exists());
        assert_eq!(
            std::fs::read(root.join("cluster/device-signing.seed")).unwrap(),
            [9; 32]
        );
    }

    #[test]
    fn redirected_recovery_root_is_rejected_without_touching_target() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let root = tmp.path().join("voboost");
        std::fs::create_dir(&root).unwrap();
        let cluster = Directory::open(&root)
            .unwrap()
            .open_or_create_private_child("cluster")
            .unwrap();
        cluster
            .write_atomic("provision.json", b"provision", 0o600)
            .unwrap();
        let victim = tmp.path().join("victim");
        std::fs::create_dir(&victim).unwrap();
        symlink(&victim, root.join("recovery")).unwrap();
        assert!(preserve(&root, &"b".repeat(64)).is_err());
        assert_eq!(std::fs::read_dir(victim).unwrap().count(), 0);
    }
}
