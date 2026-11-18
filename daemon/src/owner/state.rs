//! Daemon-owned scalar state files. Its runtime owner serializes all writes.
//! Endpoint authorization and wire routing remain with the caller.

use crate::secure_fs::Directory;
use serde_json::Value;
use std::fs;
use std::io;
use std::path::Path;

pub(crate) const MAX_BYTES: usize = 4096;
pub(crate) const MAX_KEY_BYTES: usize = 96;
pub(crate) const MAX_SOURCE_BYTES: usize = voboost_contract::runtime_owner::MAX_SOURCE_BYTES;
pub(crate) const MAX_STORAGE_KEY_BYTES: usize = MAX_SOURCE_BYTES + 1 + MAX_KEY_BYTES;
pub(crate) const MAX_FILENAME_BYTES: usize = MAX_STORAGE_KEY_BYTES + 5;

#[derive(Debug, PartialEq)]
pub(crate) enum ReadOutcome {
    Value(Value),
    Missing,
    Error,
}

pub(crate) fn render_value(json: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(json).unwrap_or_else(|_| b"null".to_vec());
    bytes.push(b'\n');
    bytes
}

pub(crate) fn sanitize_key(key: &str) -> Option<String> {
    if key.is_empty() || key.len() > MAX_KEY_BYTES {
        return None;
    }
    if !key
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return None;
    }
    Some(key.to_string())
}

pub(crate) fn sanitize_source(source: &str) -> Option<String> {
    voboost_contract::runtime_owner::valid_source(source).then(|| source.to_string())
}

pub(crate) fn storage_key(source: &str, key: &str) -> Option<String> {
    let source = sanitize_source(source)?;
    let key = sanitize_key(key)?;
    let storage = format!("{source}_{key}");
    (storage.len() <= MAX_STORAGE_KEY_BYTES && storage.len() + ".json".len() <= MAX_FILENAME_BYTES)
        .then_some(storage)
}

pub(crate) fn valid_storage_key(value: &str) -> bool {
    let Some((source, key)) = value.split_once('_') else {
        return false;
    };
    storage_key(source, key).as_deref() == Some(value)
}

pub(crate) fn read(root_path: &Path, source: &str, safe_key: &str) -> ReadOutcome {
    super::initial_seeding::read(root_path, source, safe_key, false, || {
        read_unobserved(root_path, source, safe_key)
    })
}

pub(crate) fn read_controller(root_path: &Path, source: &str, safe_key: &str) -> ReadOutcome {
    super::initial_seeding::read(root_path, source, safe_key, true, || {
        read_unobserved(root_path, source, safe_key)
    })
}

pub(super) fn read_unobserved(root_path: &Path, source: &str, safe_key: &str) -> ReadOutcome {
    let Some(storage_key) = storage_key(source, safe_key) else {
        return ReadOutcome::Error;
    };
    let dir = match open_directory(root_path, false) {
        Ok(dir) => dir,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return ReadOutcome::Missing,
        Err(_) => return ReadOutcome::Error,
    };
    let active = format!("{storage_key}.json");
    let bytes = match dir.read_trusted(&active, MAX_BYTES, 0o600) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return ReadOutcome::Missing,
        Err(_) => return ReadOutcome::Error,
    };
    if validate_scalar_bytes(&bytes).is_err() {
        return ReadOutcome::Error;
    }
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(value @ (Value::String(_) | Value::Number(_) | Value::Bool(_))) => {
            ReadOutcome::Value(value)
        }
        _ => ReadOutcome::Error,
    }
}

pub(crate) fn write(path: &Path, safe_key: &str, bytes: &[u8]) -> Result<(), String> {
    super::initial_seeding::write(path, safe_key, bytes, false, || {
        write_unobserved(path, safe_key, bytes)
    })
}

pub(crate) fn write_controller(path: &Path, safe_key: &str, bytes: &[u8]) -> Result<(), String> {
    super::initial_seeding::write(path, safe_key, bytes, true, || {
        write_unobserved(path, safe_key, bytes)
    })
}

/// Called inside the single owner command handler, serialized with every state write.
pub(crate) fn clear_controller_if(
    path: &Path,
    source: &str,
    key: &str,
    expected: &str,
) -> Result<bool, String> {
    if source != "media-apps"
        || key != "media-selected-package"
        || expected.is_empty()
        || expected.len() > 255
        || !expected
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
    {
        return Err("invalid conditional media clear".into());
    }
    match read_controller(path, source, key) {
        ReadOutcome::Value(Value::String(value)) if value == expected => {
            let storage = storage_key(source, key).ok_or("invalid state owner")?;
            write_controller(path, &storage, &render_value(&Value::String(String::new())))?;
            Ok(true)
        }
        ReadOutcome::Error => Err("conditional media state unavailable".into()),
        _ => Ok(false),
    }
}

fn write_unobserved(path: &Path, safe_key: &str, bytes: &[u8]) -> Result<(), String> {
    if !valid_storage_key(safe_key) {
        return Err("unsafe state storage key".to_string());
    }
    validate_scalar_bytes(bytes)?;

    let dir = open_directory(path, true).map_err(|error| error.to_string())?;
    write_state_bytes_in(&dir, safe_key, bytes)
}

fn write_state_bytes_in(dir: &Directory, safe_key: &str, bytes: &[u8]) -> Result<(), String> {
    let active = format!("{safe_key}.json");
    let temp = format!(".{active}.tmp");

    dir.prepare_trusted(&temp, bytes, 0o600)
        .map_err(|error| format!("prepare temp: {error}"))?;
    if let Err(error) = dir.rename(&temp, &active) {
        let _ = dir.unlink(&temp);
        return Err(format!("rename: {error}"));
    }
    dir.sync_all()
        .map_err(|error| format!("directory fsync: {error}"))
}

pub(crate) fn open_directory(path: &Path, create: bool) -> io::Result<Directory> {
    let mut created = false;
    if create {
        match fs::create_dir(path) {
            Ok(()) => created = true,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }

    let dir = Directory::open(path)?;
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    let mode = 0o700;
    if created {
        // fs::create_dir yields mode 0777 & ~umask, which the strict checks
        // below would reject for a zero umask. A directory we just created is
        // trusted: normalize its mode before validating.
        dir.set_mode(mode)?;
        dir.validate_owner_mode(uid, gid, mode)?;
        return Ok(dir);
    }
    dir.validate_owner_not_writable(uid, gid)?;
    dir.set_mode(mode)?;
    dir.validate_owner_mode(uid, gid, mode)?;
    Ok(dir)
}

fn validate_scalar_bytes(bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err("state scalar exceeds size bound".to_string());
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if !(value.is_number() || value.is_boolean() || value.is_string()) {
        return Err("state file must contain one JSON number, boolean, or string".to_string());
    }
    Ok(())
}
