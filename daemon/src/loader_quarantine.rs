// Root-owned write-ahead safety markers, independent of diagnostic status.
use crate::secure_fs::Directory;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::path::Path;

const PREFIX: &str = ".loader-call-";
const STAGE_PREFIX: &str = ".loader-stage-";
static ADMISSION: std::sync::Mutex<()> = std::sync::Mutex::new(());
const MAX_MARKERS: usize = 128;
const MAX_BYTES: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Marker {
    schema_version: u32,
    boot_id: String,
    pid: i32,
    starttime: u64,
    process: String,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn valid_boot(boot: &str) -> bool {
    boot.len() == 36
        && boot.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
            }
        })
}
impl Marker {
    fn new(boot: &str, pid: i32, starttime: u64, process: &str) -> io::Result<Self> {
        if !valid_boot(boot)
            || pid <= 0
            || starttime == 0
            || process.is_empty()
            || process.len() > 256
            || !process
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:".contains(&b))
        {
            return Err(invalid("invalid loader lifetime identity"));
        }
        Ok(Self {
            schema_version: 1,
            boot_id: boot.into(),
            pid,
            starttime,
            process: process.into(),
        })
    }
    fn name(&self) -> String {
        format!(
            "{PREFIX}{}-{}-{}.json",
            self.boot_id, self.pid, self.starttime
        )
    }
    fn validate(&self, name: &str) -> io::Result<()> {
        if self.schema_version != 1
            || Self::new(&self.boot_id, self.pid, self.starttime, &self.process)? != *self
            || self.name() != name
        {
            return Err(invalid("foreign loader marker identity"));
        }
        Ok(())
    }
}

pub(crate) struct Call {
    dir: Directory,
    marker: Marker,
}
impl Call {
    pub(crate) fn begin(
        root: &Path,
        boot: &str,
        pid: i32,
        starttime: u64,
        process: &str,
    ) -> io::Result<Self> {
        // Serialize only bounded filesystem admission, never the remote call.
        let _admission = ADMISSION
            .lock()
            .map_err(|_| invalid("loader admission poisoned"))?;
        let marker = Marker::new(boot, pid, starttime, process)?;
        let dir = Directory::open(root)?;
        let (uid, gid) = dir.owner()?;
        #[cfg(target_os = "android")]
        if uid != 0 || gid != 0 {
            return Err(invalid("loader marker root must be root owned"));
        }
        dir.validate_owner_mode(uid, gid, 0o755)?;
        // Validate the exact lifetime before admission. Other current-boot
        // targets may concurrently complete/unlink; their markers are not this
        // target's authority and must not serialize independent injection.
        let mut count = 0;
        let current_prefix = format!("{PREFIX}{boot}-");
        for name in dir.entry_names_bounded(4096)? {
            if let Some(suffix) = name.strip_prefix(STAGE_PREFIX) {
                let stage_boot = suffix
                    .get(..36)
                    .filter(|b| valid_boot(b))
                    .ok_or_else(|| invalid("foreign loader stage namespace"))?;
                // Staging precedes any remote call. A different boot can
                // remove it after strict inode ownership/mode validation.
                dir.metadata_trusted(&name, 0o600)?;
                if stage_boot != boot {
                    dir.unlink(&name)?;
                    dir.sync_all()?;
                } else {
                    count += 1;
                }
                continue;
            }
            if !name.starts_with(PREFIX) {
                continue;
            }
            if name.starts_with(&current_prefix) {
                count += 1;
                if name == marker.name() {
                    let bytes = dir.read_trusted(&name, MAX_BYTES, 0o600)?;
                    let existing: Marker = serde_json::from_slice(&bytes)
                        .map_err(|_| invalid("corrupt loader safety marker"))?;
                    existing.validate(&name)?;
                    return Err(invalid("loader lifetime quarantined or call unresolved"));
                }
                continue;
            }
            let bytes = match dir.read_trusted(&name, MAX_BYTES, 0o600) {
                Ok(bytes) => bytes,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            let existing: Marker = serde_json::from_slice(&bytes)
                .map_err(|_| invalid("corrupt old-boot loader safety marker"))?;
            existing.validate(&name)?;
            if existing.boot_id == boot {
                return Err(invalid("loader marker boot namespace mismatch"));
            }
            // Different kernel boot proves the old target cannot exist.
            match dir.unlink(&name) {
                Ok(()) => dir.sync_all()?,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        if count >= MAX_MARKERS {
            return Err(invalid("loader marker retention bound exceeded"));
        }
        // Per-key exclusive staging owns publication. Other targets never see
        // partial JSON under the published marker namespace.
        let stage = format!("{STAGE_PREFIX}{}-{}-{}.json", boot, pid, starttime);
        let mut file = dir.create_new(stage.as_ref(), 0o600)?;
        let bytes = serde_json::to_vec(&marker).map_err(|_| invalid("encode loader marker"))?;
        // Any failed write/fsync retains a marker (possibly invalid); no remote
        // call is admitted, and restart cannot convert that uncertainty to OK.
        file.write_all(&bytes)?;
        file.sync_all()?;
        // The exclusive per-lifetime stage prevents a competing writer from
        // reaching publication; final entry was checked above.
        if dir.entry_exists(&marker.name())? {
            return Err(invalid("loader marker appeared before publication"));
        }
        dir.rename(&stage, &marker.name())?;
        dir.sync_all()?;
        Ok(Self { dir, marker })
    }

    pub(crate) fn complete(self, unresolved: bool) -> io::Result<()> {
        if unresolved {
            return Ok(());
        }
        let name = self.marker.name();
        let bytes = self.dir.read_trusted(&name, MAX_BYTES, 0o600)?;
        let current: Marker =
            serde_json::from_slice(&bytes).map_err(|_| invalid("corrupt completion marker"))?;
        if current != self.marker {
            return Err(invalid("loader completion identity changed"));
        }
        self.dir.unlink(&name)?;
        self.dir.sync_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    const BOOT: &str = "47089009-3923-4088-80e7-1fa327c24ca7";
    const NEXT: &str = "57089009-3923-4088-80e7-1fa327c24ca7";
    fn root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        root
    }
    fn begin(p: &Path) -> io::Result<Call> {
        Call::begin(p, BOOT, 2802, 1048, "com.pateonavi.naviapp")
    }
    #[test]
    fn restart_without_completion_cannot_reenter_same_lifetime() {
        let r = root();
        drop(begin(r.path()).unwrap()); // daemon dies before receiving result
        assert!(begin(r.path()).is_err());
    }
    #[test]
    fn timeout_and_stop_do_not_clear_marker_but_completed_call_does() {
        let r = root();
        begin(r.path()).unwrap().complete(true).unwrap();
        assert!(begin(r.path()).is_err());
        let r = root();
        begin(r.path()).unwrap().complete(false).unwrap();
        assert!(begin(r.path()).is_ok());
    }
    #[test]
    fn new_starttime_and_new_boot_are_independent() {
        let r = root();
        drop(begin(r.path()).unwrap());
        Call::begin(r.path(), BOOT, 2802, 1049, "com.pateonavi.naviapp").unwrap();
        Call::begin(r.path(), NEXT, 2802, 1048, "com.pateonavi.naviapp").unwrap();
        assert_eq!(fs::read_dir(r.path()).unwrap().count(), 1);
    }
    #[test]
    fn interrupted_stage_blocks_same_lifetime_and_old_boot_cleans_it() {
        let r = root();
        let name = format!("{STAGE_PREFIX}{BOOT}-2802-1048.json");
        let p = r.path().join(&name);
        fs::write(&p, b"").unwrap(); // crash before publication, no remote call
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(begin(r.path()).is_err());
        Call::begin(r.path(), NEXT, 2802, 1048, "com.pateonavi.naviapp").unwrap();
        assert!(!p.exists());
    }
    #[test]
    fn persistence_admission_failure_never_returns_a_call_token() {
        let r = root();
        fs::set_permissions(r.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(begin(r.path()).is_err());
        assert_eq!(fs::read_dir(r.path()).unwrap().count(), 0);
    }
    #[test]
    fn different_targets_do_not_share_a_busy_marker() {
        let r = root();
        let _a = begin(r.path()).unwrap();
        let _b = Call::begin(r.path(), BOOT, 2493, 845, "com.qinggan.systemservice").unwrap();
    }
    #[test]
    fn corrupt_foreign_mode_symlink_and_hardlink_fail_closed() {
        for fault in 0..5 {
            let r = root();
            let m = Marker::new(BOOT, 2802, 1048, "com.pateonavi.naviapp").unwrap();
            let p = r.path().join(m.name());
            let mut bytes = serde_json::to_vec(&m).unwrap();
            if fault == 0 {
                bytes = b"broken".to_vec();
            }
            if fault == 1 {
                bytes = String::from_utf8(bytes)
                    .unwrap()
                    .replace("2802", "2803")
                    .into_bytes();
            }
            fs::write(&p, bytes).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
            if fault == 2 {
                fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
            }
            if fault == 3 {
                fs::rename(&p, r.path().join("other")).unwrap();
                symlink("other", &p).unwrap();
            }
            if fault == 4 {
                fs::hard_link(&p, r.path().join("other")).unwrap();
            }
            assert!(begin(r.path()).is_err(), "fault {fault}");
            assert!(fs::symlink_metadata(&p).is_ok());
        }
    }
}
