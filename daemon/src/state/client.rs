use serde_json::Value;
use std::path::Path;
use voboost_contract::runtime_owner::{self, Command, Outcome};
pub(crate) const MAX_BYTES: usize = runtime_owner::MAX_STATE_BYTES;
pub(crate) const MAX_KEY_BYTES: usize = runtime_owner::MAX_KEY_BYTES;
pub(crate) const MAX_SOURCE_BYTES: usize = runtime_owner::MAX_SOURCE_BYTES;
pub(crate) const MAX_STORAGE_KEY_BYTES: usize = MAX_SOURCE_BYTES + 1 + MAX_KEY_BYTES;
pub(crate) const MAX_FILENAME_BYTES: usize = MAX_STORAGE_KEY_BYTES + 5;
#[derive(Debug, PartialEq)]
pub(crate) enum ReadOutcome {
    Value(Value),
    Missing,
    Error,
}
pub(crate) fn render_value(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).expect("JSON value is serializable");
    bytes.push(b'\n');
    bytes
}
pub(crate) fn sanitize_key(key: &str) -> Option<String> {
    runtime_owner::valid_key(key).then(|| key.into())
}
pub(crate) fn sanitize_source(source: &str) -> Option<String> {
    runtime_owner::valid_source(source).then(|| source.into())
}
pub(crate) fn storage_key(source: &str, key: &str) -> Option<String> {
    Some(format!(
        "{}_{}",
        sanitize_source(source)?,
        sanitize_key(key)?
    ))
}
pub(crate) fn read(path: &Path, source: &str, key: &str) -> ReadOutcome {
    read_impl(path, source, key, false)
}
pub(crate) fn read_controller(path: &Path, source: &str, key: &str) -> ReadOutcome {
    read_impl(path, source, key, true)
}
fn read_impl(path: &Path, source: &str, key: &str, controller: bool) -> ReadOutcome {
    if path != Path::new(crate::config::STATE_DIR) {
        return ReadOutcome::Error;
    }
    let command = if controller {
        Command::ReadControllerState {
            source: source.into(),
            key: key.into(),
        }
    } else {
        Command::ReadState {
            source: source.into(),
            key: key.into(),
        }
    };
    match crate::owner_client::call(command) {
        Ok(Outcome::State { value: Some(value) }) => ReadOutcome::Value(value),
        Ok(Outcome::State { value: None }) => ReadOutcome::Missing,
        _ => ReadOutcome::Error,
    }
}
pub(crate) fn write_controller(path: &Path, key: &str, bytes: &[u8]) -> Result<(), String> {
    if path != Path::new(crate::config::STATE_DIR) {
        return Err("state target rejected".into());
    }
    let (source, key) = key.split_once('_').ok_or("invalid storage key")?;
    let value = serde_json::from_slice(bytes).map_err(|e| format!("invalid state value: {e}"))?;
    let command = Command::WriteControllerState {
        source: source.into(),
        key: key.into(),
        value,
    };
    match crate::owner_client::call(command).map_err(|e| e.to_string())? {
        Outcome::Written {} => Ok(()),
        _ => Err("runtime owner did not confirm state commit".into()),
    }
}

pub(crate) fn clear_controller_if(
    path: &Path,
    source: &str,
    key: &str,
    expected: &str,
) -> Result<bool, String> {
    if path != Path::new(crate::config::STATE_DIR) {
        return Err("state target rejected".into());
    }
    match crate::owner_client::call(Command::ClearControllerState {
        source: source.into(),
        key: key.into(),
        expected: expected.into(),
    })
    .map_err(|error| error.to_string())?
    {
        Outcome::StateCleared { cleared } => Ok(cleared),
        _ => Err("runtime owner did not confirm conditional clear".into()),
    }
}

#[cfg(test)]
pub(crate) fn write(path: &Path, key: &str, bytes: &[u8]) -> Result<(), String> {
    if path != Path::new(crate::config::STATE_DIR) {
        return Err("state target rejected".into());
    }
    let (source, key) = key.split_once('_').ok_or("invalid storage key")?;
    let value = serde_json::from_slice(bytes).map_err(|e| format!("invalid state value: {e}"))?;
    match crate::owner_client::call(Command::WriteState {
        source: source.into(),
        key: key.into(),
        value,
    })
    .map_err(|e| e.to_string())?
    {
        Outcome::Written {} => Ok(()),
        _ => Err("runtime owner did not confirm state commit".into()),
    }
}
