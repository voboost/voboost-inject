//! Installed inventory authority. The operation projection and WAL stay independent.
use crate::secure_fs::Directory;
use std::{
    io,
    path::{Path, PathBuf},
};
use voboost_contract::domain_core::install_layout::{INSTALL, STATE};

pub const LEGACY_DIRECTORY: &str = "uninstall";
pub const LEGACY_FILE: &str = "install-inventory.json";

fn child(root: &Directory, name: &str) -> io::Result<Option<Directory>> {
    match root.open_child(name) {
        Ok(directory) => Ok(Some(directory)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn member(root: &Directory, directory: &str, file: &str) -> io::Result<Option<Directory>> {
    let Some(parent) = child(root, directory)? else {
        return Ok(None);
    };
    if parent.entry_exists(file)? {
        Ok(Some(parent))
    } else {
        Ok(None)
    }
}

pub fn location(root: &Directory) -> io::Result<(Directory, &'static str)> {
    let current = member(root, INSTALL, STATE)?;
    let legacy = member(root, LEGACY_DIRECTORY, LEGACY_FILE)?;
    match (current, legacy) {
        (Some(_), Some(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "multiple installed state records",
        )),
        (Some(directory), None) => Ok((directory, STATE)),
        (None, Some(directory)) => Ok((directory, LEGACY_FILE)),
        (None, None) => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "installed state absent",
        )),
    }
}

pub fn path(root: &Path) -> io::Result<PathBuf> {
    let (_, file) = location(&Directory::open(root)?)?;
    Ok(root
        .join(if file == STATE {
            INSTALL
        } else {
            LEGACY_DIRECTORY
        })
        .join(file))
}

pub fn read(root: &Directory, max: usize) -> io::Result<Vec<u8>> {
    let (directory, file) = location(root)?;
    directory.read_trusted(file, max, 0o600)
}

/// Publish at the path recorded in the transaction snapshot. A missing
/// destination is recoverable from that snapshot; a different authority is not.
pub fn replace(root: &Directory, file: &str, bytes: &[u8]) -> io::Result<()> {
    match location(root) {
        Ok((_, current)) if current == file => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "installed state path changed during transaction",
            ));
        }
    }
    let directory = match file {
        STATE => root.open_child(INSTALL)?,
        LEGACY_FILE => root.open_child(LEGACY_DIRECTORY)?,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid installed state name",
            ));
        }
    };
    directory.write_atomic(file, bytes, 0o600)
}

/// Fresh installation is the only caller that changes the installed-state
/// pathname. Existing product OTA/WAL execution keeps its selected pathname.
pub fn prepare_canonical(root: &Directory) -> io::Result<Directory> {
    let install = root.open_or_create_private_child(INSTALL)?;
    match location(root) {
        Ok((legacy, LEGACY_FILE)) => {
            legacy.read_trusted(LEGACY_FILE, 1024 * 1024, 0o600)?;
            if install.entry_exists(STATE)? {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "installed state destination exists",
                ));
            }
            legacy.rename_to(LEGACY_FILE, &install, STATE)?;
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(install)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_migration_is_atomic_and_a_second_authority_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let root = Directory::open(temp.path()).unwrap();
        let legacy = root.open_or_create_private_child(LEGACY_DIRECTORY).unwrap();
        legacy
            .write_atomic(LEGACY_FILE, b"retained bytes", 0o600)
            .unwrap();
        assert_eq!(read(&root, 100).unwrap(), b"retained bytes");
        let install = prepare_canonical(&root).unwrap();
        assert_eq!(
            path(temp.path()).unwrap(),
            temp.path().join("install/state.json")
        );
        assert_eq!(
            install.read_trusted(STATE, 100, 0o600).unwrap(),
            b"retained bytes"
        );
        assert!(!legacy.entry_exists(LEGACY_FILE).unwrap());
        legacy
            .write_atomic(LEGACY_FILE, b"foreign duplicate", 0o600)
            .unwrap();
        assert!(location(&root).is_err());
    }
}
