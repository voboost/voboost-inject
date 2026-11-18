//! A Settings radio changes next-boot intent, never the running session.
#[cfg(test)]
use crate::secure_fs::Directory;
use crate::{config, plan::Startup};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::io;
use std::path::Path;
#[cfg(test)]
const NAME: &str = "startup-session.json";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Session {
    schema_version: u32,
    boot_id: String,
    startup: Startup,
}
#[cfg(test)]
fn directory(root: &Path) -> Result<Directory, String> {
    directory_with_create(root, false)
}
#[cfg(test)]
fn directory_with_create(root: &Path, create: bool) -> Result<Directory, String> {
    let root = Directory::open(root).map_err(|e| e.to_string())?;
    root.validate_owner_not_writable(unsafe { libc::geteuid() }, unsafe { libc::getegid() })
        .map_err(|e| e.to_string())?;
    let run = if create {
        root.open_or_create_child_with_mode("run", config::RUN_DIR_MODE)
    } else {
        root.open_child("run")
    }
    .map_err(|e| e.to_string())?;
    run.validate_owner_mode(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        config::RUN_DIR_MODE,
    )
    .map_err(|e| e.to_string())?;
    Ok(run)
}
fn boot() -> Result<String, String> {
    // Host-only unit fixtures cannot read Android procfs. Production builds
    // always use the kernel's canonical boot identity without a fallback.
    #[cfg(all(test, not(target_os = "android")))]
    {
        Ok("11111111-1111-4111-8111-111111111111".into())
    }
    #[cfg(not(all(test, not(target_os = "android"))))]
    {
        voboost_contract::operation::current_boot_id()
    }
}
#[cfg(test)]
fn read(dir: &Directory) -> Result<Option<Vec<u8>>, String> {
    match dir.read_trusted(NAME, 512, 0o600) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}
pub(crate) fn canonical_boot_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}
fn select(bytes: Option<&[u8]>, boot_id: &str, desired: Startup) -> Result<Startup, String> {
    let Some(bytes) = bytes else {
        return Ok(desired);
    };
    let session: Session = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if session.schema_version != 1 || !canonical_boot_id(&session.boot_id) {
        return Err("invalid startup session identity".into());
    }
    Ok(if session.boot_id == boot_id {
        session.startup
    } else {
        desired
    })
}
pub(crate) fn effective(desired: Startup) -> Result<Startup, String> {
    effective_at(Path::new(config::ROOT_ZONE), desired, &boot()?)
}
pub(crate) fn effective_at_for_event(root: &Path, desired: Startup) -> Result<Startup, String> {
    effective_at(root, desired, &boot()?)
}
#[cfg(test)]
fn optional_directory(root: &Path) -> Result<Option<Directory>, String> {
    let pinned = Directory::open(root).map_err(|e| e.to_string())?;
    pinned
        .validate_owner_not_writable(unsafe { libc::geteuid() }, unsafe { libc::getegid() })
        .map_err(|e| e.to_string())?;
    let dir = match pinned.open_child("run") {
        Ok(dir) => dir,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    dir.validate_owner_mode(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        config::RUN_DIR_MODE,
    )
    .map_err(|e| e.to_string())?;
    Ok(Some(dir))
}
fn effective_at(root: &Path, desired: Startup, boot_id: &str) -> Result<Startup, String> {
    let bytes = read_at(root)?;
    select(bytes.as_deref(), boot_id, desired)
}
fn read_at(root: &Path) -> Result<Option<Vec<u8>>, String> {
    #[cfg(not(test))]
    {
        require_root(root)?;
        crate::owner_client::read_startup_session().map_err(|e| e.to_string())
    }
    #[cfg(test)]
    {
        let Some(dir) = optional_directory(root)? else {
            return Ok(None);
        };
        read(&dir)
    }
}
#[cfg(not(test))]
fn require_root(root: &Path) -> Result<(), String> {
    if root != Path::new(config::ROOT_ZONE) {
        return Err("startup session root rejected".into());
    }
    Ok(())
}
fn replace_at(root: &Path, expected: Option<Vec<u8>>, next: Option<Vec<u8>>) -> Result<(), String> {
    #[cfg(not(test))]
    {
        require_root(root)?;
        crate::owner_client::replace_startup_session(expected, next).map_err(|e| e.to_string())
    }
    #[cfg(test)]
    {
        if read_at(root)? != expected {
            return Err("startup session changed".into());
        }
        if expected.is_none() && next.is_none() {
            return Ok(());
        }
        let dir = directory_with_create(root, true)?;
        match next {
            Some(bytes) => dir.write_atomic(NAME, &bytes, 0o600),
            None => dir.unlink(NAME).and_then(|()| dir.sync_all()),
        }
        .map_err(|e| e.to_string())
    }
}
/// Retain old bytes so a failed canonical publication can restore the fence.
pub(crate) struct Deferred {
    root: std::path::PathBuf,
    previous: Option<Vec<u8>>,
    published: Vec<u8>,
}
impl Deferred {
    pub(crate) fn rollback(self) -> Result<(), String> {
        replace_at(&self.root, Some(self.published), self.previous)
    }
}
pub(crate) fn defer_at(root: &Path, desired: Startup) -> Result<Deferred, String> {
    defer_for_boot(root, desired, &boot()?)
}
fn defer_for_boot(root: &Path, desired: Startup, boot_id: &str) -> Result<Deferred, String> {
    let previous = read_at(root)?;
    let startup = select(previous.as_deref(), boot_id, desired)?;
    let bytes = serde_json::to_vec(&Session {
        schema_version: 1,
        boot_id: boot_id.into(),
        startup,
    })
    .map_err(|e| e.to_string())?;
    replace_at(root, previous.clone(), Some(bytes.clone()))?;
    Ok(Deferred {
        root: root.into(),
        previous,
        published: bytes,
    })
}
pub(crate) fn clear_at(root: &Path) -> Result<(), String> {
    let previous = read_at(root)?;
    replace_at(root, previous, None)
}
#[cfg(test)]
mod tests {
    use super::*;
    const A: &str = "11111111-1111-4111-8111-111111111111";
    const B: &str = "22222222-2222-4222-8222-222222222222";
    #[test]
    fn early_resource_cleanup_obeys_the_actual_radio_boot_fence() {
        let root = tempfile::tempdir().unwrap();
        defer_for_boot(root.path(), Startup::Interface, A).unwrap();
        assert_eq!(
            effective_at(root.path(), Startup::None, A).unwrap(),
            Startup::Interface
        );
        let session = std::fs::read(root.path().join("run/startup-session.json")).unwrap();
        let canonical = br#"{"schemaVersion":2,"userRevision":0,"fieldRevisions":{},"startup":"none","agents":{}}"#;
        assert_eq!(
            voboost_shared::early_none_gate::decide(canonical, Some(&session), A).unwrap(),
            voboost_shared::early_none_gate::Decision::DeferCurrentBoot
        );
        assert_eq!(
            voboost_shared::early_none_gate::decide(canonical, Some(&session), B).unwrap(),
            voboost_shared::early_none_gate::Decision::Cleanup
        );
    }
    #[test]
    fn radio_changes_only_next_boot_including_daemon_recreation() {
        let root = tempfile::tempdir().unwrap();
        defer_for_boot(root.path(), Startup::Interface, A).unwrap();
        // This rereads disk each time, exactly like a replacement daemon.
        for desired in [
            Startup::None,
            Startup::Hidden,
            Startup::Interface,
            Startup::None,
        ] {
            defer_for_boot(root.path(), desired, A).unwrap();
            assert_eq!(
                effective_at(root.path(), desired, A).unwrap(),
                Startup::Interface
            );
            assert_eq!(effective_at(root.path(), desired, B).unwrap(), desired);
        }
    }
    #[test]
    fn explicit_management_override_is_live_and_next_radio_defers() {
        let root = tempfile::tempdir().unwrap();
        defer_for_boot(root.path(), Startup::Hidden, A).unwrap();
        clear_at(root.path()).unwrap();
        assert_eq!(
            effective_at(root.path(), Startup::Interface, A).unwrap(),
            Startup::Interface
        );
        defer_for_boot(root.path(), Startup::Interface, A).unwrap();
        assert_eq!(
            effective_at(root.path(), Startup::None, A).unwrap(),
            Startup::Interface
        );
    }
    #[test]
    fn failed_config_commit_restores_old_fence_or_absence() {
        let root = tempfile::tempdir().unwrap();
        defer_for_boot(root.path(), Startup::Interface, A)
            .unwrap()
            .rollback()
            .unwrap();
        assert_eq!(
            effective_at(root.path(), Startup::Hidden, A).unwrap(),
            Startup::Hidden
        );
        defer_for_boot(root.path(), Startup::Hidden, A).unwrap();
        let old = read(&directory(root.path()).unwrap()).unwrap();
        defer_for_boot(root.path(), Startup::None, B)
            .unwrap()
            .rollback()
            .unwrap();
        assert_eq!(read(&directory(root.path()).unwrap()).unwrap(), old);
    }
    #[test]
    fn malformed_duplicate_unknown_schema_and_symlink_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let dir = directory_with_create(root.path(), true).unwrap();
        for bytes in [b"{}".as_slice(), br#"{"schemaVersion":2,"bootId":"11111111-1111-4111-8111-111111111111","startup":"interface"}"#, br#"{"schemaVersion":1,"bootId":"11111111-1111-4111-8111-111111111111","startup":"interface","startup":"none"}"#] {
            dir.write_atomic(NAME, bytes, 0o600).unwrap();
            assert!(effective_at(root.path(), Startup::None, A).is_err());
            assert!(defer_for_boot(root.path(), Startup::None, A).is_err());
        }
        dir.unlink(NAME).unwrap();
        std::os::unix::fs::symlink(
            root.path().join("agents.json"),
            root.path().join("run").join(NAME),
        )
        .unwrap();
        assert!(effective_at(root.path(), Startup::None, A).is_err());
    }
}
