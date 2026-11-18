//! On-demand archive export. The resident startup path never calls this reader.
use crate::secure_fs::Directory;
use serde_json::Value;
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;
use voboost_contract::runtime_owner::{Command, Outcome};

const MAX_DIAGNOSTIC_BYTES: usize = 64 * 1024;
const MAX_CONTEXT_BYTES: usize = 128 * 1024;
const MAX_RECOVERY_ENTRIES: usize = 256;
const MAX_RECOVERY_DIAGNOSTICS: usize = 4;

pub(super) fn write(root: &Path, output: &mut impl Write) -> io::Result<()> {
    output.write_all(&export(root)?)
}

fn export(root: &Path) -> io::Result<Vec<u8>> {
    let before = current_session(root).ok();
    let directory = Directory::open(root)?;
    directory.validate_owner_mode(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        0o755,
    )?;
    let mut context = retained_context(&directory).unwrap_or_else(|error| {
        serde_json::json!({"schemaVersion":1,"logSource":"root-owned-segments",
            "appPrivateBatchesRead":false,"uninstallDiagnostics":{},
            "retainedContext":{"availability":"unavailable","reason":format!("{:?}",error.kind())}})
    });
    context["configuration"] = serde_json::json!({
        "consistency": "independent-owner-reads-not-atomic",
        "desired": owner_projection(super::client::call(root, Command::ReadConfig {}), false),
        "running": owner_projection(super::client::call(root, Command::ReadStartupSession {}), true)
    });
    let records = match directory.open_child("logs") {
        Ok(logs) => {
            logs.validate_owner_mode(
                unsafe { libc::geteuid() },
                unsafe { libc::getegid() },
                0o700,
            )?;
            let _guard = logs.lock_transaction(Duration::from_secs(2))?;
            if let Some(value) = diagnostic(&logs, "remount-dbg.log") {
                context["uninstallDiagnostics"]["logs/remount-dbg.log"] = value;
            }
            let mut snapshot = crate::log_archive::Snapshot::owner(&logs)?;
            drop(_guard);
            snapshot.qnx(&logs)?;
            snapshot.into_bytes()
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error),
    };
    if let Err(error) = attach_recovery(&directory, &mut context) {
        context["uninstallDiagnostics"]["recovery"] =
            format!("<unavailable: {:?}>", error.kind()).into();
    }
    context["currentLogSession"] = session_context(before, current_session(root).ok());
    let context = serde_json::to_vec(&context).map_err(io::Error::other)?;
    crate::log_export::encode(&records, &context)
}

fn owner_projection(outcome: io::Result<Outcome>, running: bool) -> Value {
    let bytes = match (outcome, running) {
        (Ok(Outcome::Config { bytes }), false) => bytes,
        (Ok(Outcome::StartupSession { bytes }), true) => bytes,
        _ => return serde_json::json!({"availability":"unavailable","reason":"owner-read-failed"}),
    };
    let Some(bytes) = bytes else {
        return serde_json::json!({"availability":"unavailable","reason":"owner-value-missing"});
    };
    let limit = if running {
        512
    } else {
        voboost_contract::runtime_owner::MAX_CONFIG_BYTES
    };
    if bytes.len() > limit
        || serde_json::from_str::<crate::strict_json::StrictValue>(&bytes).is_err()
    {
        return serde_json::json!({"availability":"unavailable","reason":"owner-value-invalid"});
    }
    let mut value: Value = match serde_json::from_str(&bytes) {
        Ok(value @ Value::Object(_)) => value,
        _ => {
            return serde_json::json!({"availability":"unavailable","reason":"owner-value-invalid"})
        }
    };
    redact_projection(&mut value);
    serde_json::json!({"availability":"available","value":value})
}

fn redact_projection(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                let key = key.to_ascii_lowercase();
                if [
                    "seed",
                    "privatekey",
                    "private_key",
                    "password",
                    "credential",
                    "token",
                    "secret",
                ]
                .iter()
                .any(|part| key.contains(part))
                {
                    *value = Value::String("[REDACTED]".into());
                } else {
                    redact_projection(value);
                }
            }
        }
        Value::Array(values) => values.iter_mut().for_each(redact_projection),
        Value::String(value) => *value = voboost_contract::runtime_log::redact(value),
        _ => {}
    }
}

fn current_session(root: &Path) -> io::Result<Value> {
    let outcome = super::client::call(root, Command::ReadLogSession {})?;
    match outcome {
        Outcome::LogSession {
            boot_id,
            writer_id,
            sequence,
        } => Ok(
            serde_json::json!({"availability":"available","bootId":boot_id,"writerId":writer_id,"sequence":sequence}),
        ),
        _ => Err(invalid("log owner session unavailable")),
    }
}

fn session_context(before: Option<Value>, after: Option<Value>) -> Value {
    match (before, after) {
        (Some(before), Some(after))
            if before["bootId"] == after["bootId"]
                && before["writerId"] == after["writerId"]
                && before["sequence"].as_u64() <= after["sequence"].as_u64() =>
        {
            after
        }
        _ => {
            serde_json::json!({"availability":"unavailable","reason":"owner-unavailable-or-changed"})
        }
    }
}

fn retained_context(root: &Directory) -> io::Result<Value> {
    let missing = || serde_json::json!({"schemaVersion":1,"logSource":"root-owned-segments","appPrivateBatchesRead":false,"vehicleDiagnostics":{"availability":"unavailable","reason":"retained-status-unavailable"},"uninstallDiagnostics":{}});
    let bytes = match root.read_trusted(
        "status.json",
        voboost_contract::runtime_owner::MAX_STATUS_BYTES,
        0o644,
    ) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(missing()),
        Err(error) => return Err(error),
    };
    serde_json::from_slice::<crate::strict_json::StrictValue>(&bytes).map_err(io::Error::other)?;
    let publication: Value = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    let Some(mut context) = publication.get("logContext").cloned() else {
        return Ok(missing());
    };
    let object = context
        .as_object()
        .ok_or_else(|| invalid("status log context is not an object"))?;
    if publication.get("schemaVersion").and_then(Value::as_u64) != Some(1)
        || object.get("schemaVersion").and_then(Value::as_u64) != Some(1)
        || object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "schemaVersion"
                    | "releaseIdentity"
                    | "manifestSha256"
                    | "logSource"
                    | "appPrivateBatchesRead"
                    | "vehicleDiagnostics"
                    | "processTrace"
            )
        })
        || serde_json::to_vec(&context)
            .map_err(io::Error::other)?
            .len()
            > MAX_CONTEXT_BYTES
    {
        return Err(invalid("status log context is invalid"));
    }
    context["uninstallDiagnostics"] = serde_json::json!({});
    Ok(context)
}

fn diagnostic(directory: &Directory, name: &str) -> Option<Value> {
    match directory.read_untrusted(name, MAX_DIAGNOSTIC_BYTES) {
        Ok(bytes) => {
            Some(voboost_contract::runtime_log::redact(&String::from_utf8_lossy(&bytes)).into())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => Some(format!("<unavailable: {:?}>", error.kind()).into()),
    }
}

fn attach_recovery(root: &Directory, context: &mut Value) -> io::Result<()> {
    let recovery = match root.open_child("recovery") {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    recovery.validate_owner_mode(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        0o700,
    )?;
    let mut names = recovery.entry_names_bounded(MAX_RECOVERY_ENTRIES)?;
    names.sort();
    for name in names.into_iter().take(MAX_RECOVERY_DIAGNOSTICS) {
        let transaction = recovery.open_child(&name)?;
        transaction.validate_owner_mode(
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o700,
        )?;
        if let Some(value) = diagnostic(&transaction, "diag.log") {
            context["uninstallDiagnostics"][format!("recovery/{name}/diag.log")] = value;
        }
    }
    Ok(())
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    fn current_session_cannot_be_inferred_from_archive_order_or_changed_owner() {
        let head = serde_json::json!({"bootId":"boot","writerId":"writer","sequence":4});
        let mut next = head.clone();
        next["sequence"] = 5.into();
        assert_eq!(
            session_context(Some(head.clone()), Some(next.clone())),
            next
        );
        for field in ["writerId", "bootId"] {
            let mut changed = next.clone();
            changed[field] = "other".into();
            assert_eq!(
                session_context(Some(head.clone()), Some(changed))["availability"],
                "unavailable"
            );
        }
        assert_eq!(
            session_context(Some(next), Some(head))["availability"],
            "unavailable"
        );
        assert_eq!(session_context(None, None)["availability"], "unavailable");
    }

    #[test]
    fn export_without_inject_or_status_produces_valid_empty_archive() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let bytes = export(root.path()).unwrap();
        assert_eq!(&bytes[..10], b"VBOOSTLOG1");
        let header = u32::from_be_bytes(bytes[11..15].try_into().unwrap()) as usize;
        let metadata: Value = serde_json::from_slice(&bytes[55..55 + header]).unwrap();
        assert_eq!(metadata["recordsLength"], 0);
        let context: Value = serde_json::from_slice(&bytes[55 + header..]).unwrap();
        assert_eq!(context["vehicleDiagnostics"]["availability"], "unavailable");
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[test]
    fn optional_redirected_status_and_unknown_context_fields_are_unavailable() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let status = root.path().join("status.json");
        fs::write(
            &status,
            b"{\"schemaVersion\":1,\"logContext\":{\"schemaVersion\":1,\"secret\":\"no\"}}",
        )
        .unwrap();
        fs::set_permissions(&status, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(export(root.path()).is_ok());
        fs::remove_file(&status).unwrap();
        std::os::unix::fs::symlink("missing", &status).unwrap();
        assert!(export(root.path()).is_ok());
    }

    #[test]
    fn unavailable_optional_recovery_does_not_block_primary_logs() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink("missing", root.path().join("recovery")).unwrap();
        let bytes = export(root.path()).unwrap();
        let header = u32::from_be_bytes(bytes[11..15].try_into().unwrap()) as usize;
        let context: Value = serde_json::from_slice(&bytes[55 + header..]).unwrap();
        assert!(context["uninstallDiagnostics"]["recovery"]
            .as_str()
            .unwrap()
            .starts_with("<unavailable:"));
    }

    #[test]
    fn export_keeps_committed_records_context_and_redacted_recovery_diagnostics() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let directory = Directory::open(root.path()).unwrap();
        let logs = directory.create_private_child("logs").unwrap();
        let session = logs
            .create_private_child("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();
        let mut event = serde_json::to_vec(&serde_json::json!({"schemaVersion":2,"bootId":"11111111-1111-4111-8111-111111111111","writerId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sequence":1,"timestamp":"2026-10-29T08:00:00.000Z","level":"info","source":{"kind":"daemon"},"component":"test","message":"saved","fields":{}})).unwrap();
        event.push(b'\n');
        session
            .write_atomic("info-00000000000000000000.jsonl", &event, 0o600)
            .unwrap();
        let publication = serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"logContext":{"schemaVersion":1,"releaseIdentity":"1.0.0-beta1","vehicleDiagnostics":{"availability":"retained-publication"},"processTrace":{"proof":"retained-publication"}}})).unwrap();
        directory
            .write_atomic("status.json", &publication, 0o644)
            .unwrap();
        let recovery = directory.create_private_child("recovery").unwrap();
        let transaction = recovery.create_private_child("transaction").unwrap();
        transaction
            .write_atomic("diag.log", b"failure token=private-value\n", 0o600)
            .unwrap();
        let bytes = export(root.path()).unwrap();
        let header_size = u32::from_be_bytes(bytes[11..15].try_into().unwrap()) as usize;
        let metadata: Value = serde_json::from_slice(&bytes[55..55 + header_size]).unwrap();
        let records_size = metadata["recordsLength"].as_u64().unwrap() as usize;
        assert_eq!(
            &bytes[55 + header_size..55 + header_size + records_size],
            event
        );
        let context: Value =
            serde_json::from_slice(&bytes[55 + header_size + records_size..]).unwrap();
        assert_eq!(context["processTrace"]["proof"], "retained-publication");
        assert_eq!(
            context["uninstallDiagnostics"]["recovery/transaction/diag.log"],
            "failure token=[REDACTED]\n"
        );
        assert_eq!(
            directory.read_trusted("status.json", 4096, 0o644).unwrap(),
            publication
        );
        assert_eq!(
            transaction.read_trusted("diag.log", 4096, 0o600).unwrap(),
            b"failure token=private-value\n"
        );
        directory
            .write_atomic("status.json", b"malformed optional status", 0o644)
            .unwrap();
        let degraded = export(root.path()).unwrap();
        let header = u32::from_be_bytes(degraded[11..15].try_into().unwrap()) as usize;
        assert_eq!(&degraded[55 + header..55 + header + event.len()], event);
        let context: Value =
            serde_json::from_slice(&degraded[55 + header + event.len()..]).unwrap();
        assert_eq!(context["retainedContext"]["availability"], "unavailable");
    }
    #[test]
    fn owner_projections_are_bounded_independent_and_redacted() {
        let desired = owner_projection(
            Ok(Outcome::Config {
                bytes: Some(r#"{"startup":"hidden","password":"private"}"#.into()),
            }),
            false,
        );
        assert_eq!(desired["availability"], "available");
        assert_eq!(desired["value"]["startup"], "hidden");
        assert_eq!(desired["value"]["password"], "[REDACTED]");
        for bytes in ["{".to_string(), "x".repeat(513)] {
            assert_eq!(
                owner_projection(Ok(Outcome::StartupSession { bytes: Some(bytes) }), true)
                    ["availability"],
                "unavailable"
            );
        }
        assert_eq!(
            owner_projection(Ok(Outcome::Config { bytes: None }), false)["reason"],
            "owner-value-missing"
        );
        assert_eq!(
            owner_projection(Err(io::ErrorKind::ConnectionRefused.into()), true)["reason"],
            "owner-read-failed"
        );
    }
}
