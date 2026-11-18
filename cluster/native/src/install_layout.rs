use crate::{fs::Dir, Result};
use alloc::{format, vec::Vec};
use voboost_contract_core::install_layout::{
    CURRENT, GENERATIONS, INSTALL, PREVIOUS, STATE, TRANSACTIONS,
};

const LEGACY_STATE: &str = "installation.json";
const LEGACY_CURRENT: &str = "authority.json";
const RETIREMENT: &str = "bootstrap-retirement.json";

fn existing_child(parent: &Dir, child: &str) -> Result<Option<Dir>> {
    if parent.exists(child)? {
        return Ok(Some(Dir::open(
            &format!("{}/{child}", parent.path),
            parent.owner,
        )?));
    }
    Ok(None)
}

fn read_record(
    root: &Dir,
    parent: Option<Dir>,
    file: &str,
    legacy: &str,
    max: usize,
) -> Result<Option<Vec<u8>>> {
    if let Some(parent) = parent {
        if parent.exists(file)? {
            if root.exists(legacy)? {
                return Err("multiple native install state records".into());
            }
            return parent.read(file, max, 0o600).map(Some);
        }
    }
    if root.exists(legacy)? {
        return root.read(legacy, max, 0o600).map(Some);
    }
    Ok(None)
}

pub(crate) fn state_exists(root: &Dir) -> Result<bool> {
    Ok(read_state_optional(root)?.is_some())
}

fn read_state_optional(root: &Dir) -> Result<Option<Vec<u8>>> {
    read_record(
        root,
        existing_child(root, INSTALL)?,
        STATE,
        LEGACY_STATE,
        65536,
    )
}

pub(crate) fn read_state(root: &Dir) -> Result<Vec<u8>> {
    read_state_optional(root)?.ok_or_else(|| "native installation state absent".into())
}

pub(crate) fn write_state(root: &Dir, bytes: &[u8]) -> Result<()> {
    let install = root.child(INSTALL)?;
    migrate_record(root, &install, STATE, LEGACY_STATE)?;
    install.write(STATE, bytes, 0o600)
}

/// The caller holds the same native installation lock that guards the bytes.
/// Rename publishes one name atomically, so old and new can never both be active.
fn migrate_record(root: &Dir, parent: &Dir, file: &str, legacy: &str) -> Result<()> {
    if root.exists(legacy)? {
        root.rename_file_to(legacy, parent, file)?;
    }
    Ok(())
}

fn existing_transaction(root: &Dir, id: &str) -> Result<Option<Dir>> {
    if !voboost_contract_core::digest(id) {
        return Err("invalid native installation transaction".into());
    }
    let Some(install) = existing_child(root, INSTALL)? else {
        return Ok(None);
    };
    let Some(transactions) = existing_child(&install, TRANSACTIONS)? else {
        return Ok(None);
    };
    existing_child(&transactions, id)
}

pub(crate) fn read_retirement(root: &Dir, id: &str) -> Result<Option<Vec<u8>>> {
    read_record(
        root,
        existing_transaction(root, id)?,
        RETIREMENT,
        &format!("bootstrap-retired-{id}.json"),
        131072,
    )
}

pub(crate) fn write_retirement(root: &Dir, id: &str, bytes: &[u8]) -> Result<()> {
    if !voboost_contract_core::digest(id) {
        return Err("invalid native installation transaction".into());
    }
    let directory = root.child(INSTALL)?.child(TRANSACTIONS)?.child(id)?;
    migrate_record(
        root,
        &directory,
        RETIREMENT,
        &format!("bootstrap-retired-{id}.json"),
    )?;
    if directory.exists(RETIREMENT)? && directory.read(RETIREMENT, 131072, 0o600)? == bytes {
        return Ok(());
    }
    directory.write(RETIREMENT, bytes, 0o600)
}

/// The active generation and its desired/revision state form one atomic record.
pub(crate) fn read_current(root: &Dir) -> Result<Option<Vec<u8>>> {
    read_record(
        root,
        existing_child(root, GENERATIONS)?,
        CURRENT,
        LEGACY_CURRENT,
        65536,
    )
}

pub(crate) fn write_current(root: &Dir, bytes: &[u8]) -> Result<()> {
    let generations = root.child(GENERATIONS)?;
    migrate_record(root, &generations, CURRENT, LEGACY_CURRENT)?;
    generations.write(CURRENT, bytes, 0o600)
}

const ACTIVATION: &str = ".activation.json";

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Activation {
    before: Option<alloc::string::String>,
    after: alloc::string::String,
}

fn read_activation(generations: &Dir) -> Result<Option<Activation>> {
    if !generations.exists(ACTIVATION)? {
        return Ok(None);
    }
    let transition: Option<Activation> =
        voboost_contract_core::parse_canonical(&generations.read(ACTIVATION, 1024, 0o600)?, 1024)?;
    if transition.as_ref().is_some_and(|step| {
        !voboost_contract_core::digest(&step.after)
            || step.before.as_deref().is_some_and(|before| {
                !voboost_contract_core::digest(before) || before == step.after
            })
    }) {
        return Err("invalid native generation activation journal".into());
    }
    Ok(transition)
}

fn read_previous(generations: &Dir) -> Result<Option<alloc::string::String>> {
    if !generations.exists(PREVIOUS)? {
        return Ok(None);
    }
    let previous: Option<alloc::string::String> =
        voboost_contract_core::parse_canonical(&generations.read(PREVIOUS, 256, 0o600)?, 256)?;
    if previous
        .as_deref()
        .is_some_and(|id| !voboost_contract_core::digest(id))
    {
        return Err("invalid previous native generation".into());
    }
    Ok(previous)
}

/// The current record is the commit point. A pending journal can only refer
/// to the observed current generation on one side of that commit.
pub(crate) fn recover_activation(root: &Dir, current: Option<&str>) -> Result<()> {
    let generations = root.child(GENERATIONS)?;
    let Some(step) = read_activation(&generations)? else {
        return Ok(());
    };
    if current == Some(step.after.as_str()) {
        if read_previous(&generations)? != step.before {
            generations.write(
                PREVIOUS,
                &voboost_contract_core::ascii_json(&step.before)?,
                0o600,
            )?;
        }
    } else if current != step.before.as_deref() {
        return Err("current native generation differs from activation journal".into());
    }
    generations.write(ACTIVATION, b"null\n", 0o600)
}

pub(crate) fn begin_activation(root: &Dir, before: Option<&str>, after: &str) -> Result<()> {
    if !voboost_contract_core::digest(after)
        || before.is_some_and(|id| !voboost_contract_core::digest(id) || id == after)
    {
        return Err("invalid native generation transition".into());
    }
    recover_activation(root, before)?;
    let generations = root.child(GENERATIONS)?;
    let step = Activation {
        before: before.map(Into::into),
        after: after.into(),
    };
    generations.write(
        ACTIVATION,
        &voboost_contract_core::ascii_json(&step)?,
        0o600,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn activation_recovery_keeps_previous_only_for_committed_current() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = Dir::open(tmp.path().to_str().unwrap(), crate::fs::uid().unwrap()).unwrap();
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        begin_activation(&root, None, &a).unwrap();
        write_current(&root, b"generation A").unwrap();
        recover_activation(&root, Some(&a)).unwrap();
        let generations = root.child(GENERATIONS).unwrap();
        assert!(read_previous(&generations).unwrap().is_none());
        begin_activation(&root, Some(&a), &b).unwrap();
        recover_activation(&root, Some(&a)).unwrap();
        assert!(read_previous(&generations).unwrap().is_none());
        begin_activation(&root, Some(&a), &b).unwrap();
        write_current(&root, b"generation B").unwrap();
        assert!(recover_activation(&root, Some(&"c".repeat(64))).is_err());
        recover_activation(&root, Some(&b)).unwrap();
        assert_eq!(
            read_previous(&generations).unwrap().as_deref(),
            Some(a.as_str())
        );
        begin_activation(&root, Some(&b), &a).unwrap();
        write_current(&root, b"generation A").unwrap();
        recover_activation(&root, Some(&a)).unwrap();
        assert_eq!(
            read_previous(&generations).unwrap().as_deref(),
            Some(b.as_str())
        );
    }

    #[test]
    fn legacy_state_migrates_without_dual_authority_and_conflict_fails_closed() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = Dir::open(tmp.path().to_str().unwrap(), crate::fs::uid().unwrap()).unwrap();
        root.write(LEGACY_STATE, b"old receipt", 0o600).unwrap();
        assert_eq!(read_state(&root).unwrap(), b"old receipt");
        write_state(&root, b"new receipt").unwrap();
        assert!(!root.exists(LEGACY_STATE).unwrap());
        assert_eq!(read_state(&root).unwrap(), b"new receipt");
        root.write(LEGACY_STATE, b"foreign legacy receipt", 0o600)
            .unwrap();
        assert!(read_state(&root).is_err());
        assert!(write_state(&root, b"another").is_err());
    }

    #[test]
    fn retirement_migrates_with_the_original_transaction_and_retry_reads_same_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = Dir::open(tmp.path().to_str().unwrap(), crate::fs::uid().unwrap()).unwrap();
        let id = "a".repeat(64);
        let legacy = format!("bootstrap-retired-{id}.json");
        root.write(&legacy, b"verified receipt", 0o600).unwrap();
        let first = read_retirement(&root, &id).unwrap().unwrap();
        write_retirement(&root, &id, &first).unwrap();
        assert!(!root.exists(&legacy).unwrap());
        assert_eq!(read_retirement(&root, &id).unwrap().unwrap(), first);
        assert!(read_retirement(&root, &"b".repeat(64)).unwrap().is_none());
        assert!(read_retirement(&root, "../wrong").is_err());
    }
}
