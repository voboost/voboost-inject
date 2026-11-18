//! Captured OEM actions use SaveDesired; auxiliary journals never replay a user choice.
use std::path::Path;
const SOURCES: &[&str] = &[
    "vehicle-drive-forced-ev",
    "vehicle-drive-pedestrian-warning",
];
const KEY: &str = "intent";
pub(crate) fn supports(source: &str) -> bool {
    SOURCES.contains(&source)
}

#[cfg(not(test))]
pub(crate) fn recover(path: &Path) -> Result<(), String> {
    if path != Path::new(&crate::config::plan_file()) {
        return Err("intent recovery root rejected".into());
    }
    for source in SOURCES {
        crate::owner_client::recover_intent(source, KEY).map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn recover(path: &Path) -> Result<(), String> {
    for source in SOURCES {
        recover_source(path, source)?;
    }
    Ok(())
}

#[cfg(test)]
fn journal_name(source: &str) -> String {
    format!(".{source}_{KEY}.journal.json")
}

#[cfg(test)]
fn recover_source(path: &Path, source: &str) -> Result<(), String> {
    use crate::secure_fs::Directory;
    use std::io;
    use voboost_contract::desired::{Config, Field};
    use voboost_contract::runtime_owner::CapturedIntent;
    let current = match crate::plan::read_canonical_bounded(path) {
        Ok(bytes) => Some(Config::decode(&bytes).map_err(|error| error.to_string())?),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.to_string()),
    };
    let field = Field::Option {
        agent: source.into(),
        key: KEY.into(),
    };
    if current
        .as_ref()
        .is_some_and(|config| config.field_revisions.contains_key(&field.path()))
    {
        return Ok(());
    }
    let root = Directory::open(path.parent().ok_or("plan has no parent")?)
        .map_err(|error| error.to_string())?;
    let state = match root.open_child("state") {
        Ok(state) => state,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    state
        .validate_owner_mode(
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o700,
        )
        .map_err(|error| error.to_string())?;
    let bytes = match state.read_trusted(
        &journal_name(source),
        voboost_contract::runtime_owner::MAX_STATE_BYTES,
        0o600,
    ) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    let record = CapturedIntent::decode(&bytes).map_err(str::to_string)?;
    if record.pending {
        return Err("pending auxiliary capture has no saved user authority".into());
    }
    Ok(())
}

pub(crate) fn receipt_frame(
    source: &str,
    request: u64,
    capture: u64,
    choice: &str,
    status: &str,
) -> Option<String> {
    if !supports(source)
        || request == 0
        || capture == 0
        || !matches!(choice, "on" | "off")
        || !matches!(status, "committed" | "superseded")
    {
        return None;
    }
    let frame = format!("I|{source}|{request}|{capture}|{choice}|{status}\n");
    (frame.len() <= 192).then_some(frame)
}

#[cfg(test)]
#[path = "owned_intent.test.rs"]
mod tests;
