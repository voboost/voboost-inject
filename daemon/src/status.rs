// status.rs — atomic write of inject-status.json (app-readable).
//
// Ported from Vala status.vala. Reports daemon/manifest versions, kill-switch
// and panic-quarantine state, and every per-injection state. Written via
// temp+rename+fsync+dir-fsync (atomic, symlink-safe, durable).

use serde::Serialize;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::config;
use crate::log;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InjectionState {
    Active,
    Failed,
    SkippedCoexist,
    Waiting,
    Quarantined,
    Degraded,
}

impl InjectionState {
    fn label(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Failed => "failed",
            Self::SkippedCoexist => "skipped-coexist",
            Self::Quarantined => "quarantined",
            Self::Degraded => "degraded",
            Self::Waiting => "waiting",
        }
    }
}

#[derive(Debug, Clone)]
pub struct InjectionStatus {
    pub id: String,
    pub process: String,
    pub state: InjectionState,
}

#[derive(Debug, Serialize)]
struct StatusJson<'a> {
    daemon: &'a str,
    manifest: i64,
    state: &'a str,
    killed: bool,
    panic: bool,
    injections: Vec<InjectionJson<'a>>,
}

#[derive(Debug, Serialize)]
struct InjectionJson<'a> {
    id: &'a str,
    process: &'a str,
    state: &'a str,
}

pub struct Status {
    pub daemon_version: String,
    pub daemon_state: String,
    pub manifest_version: i64,
    pub kill_switch: bool,
    pub panic_quarantine: bool,
    injections: Vec<InjectionStatus>,
}

impl Default for Status {
    fn default() -> Self {
        Self {
            daemon_version: String::new(),
            daemon_state: "ready".to_string(),
            manifest_version: 0,
            kill_switch: false,
            panic_quarantine: false,
            injections: Vec::new(),
        }
    }
}

impl Status {
    pub fn set_injection(&mut self, id: &str, process: &str, state: InjectionState) {
        if let Some(slot) = self
            .injections
            .iter_mut()
            .find(|i| i.id == id && i.process == process)
        {
            slot.state = state;
        } else {
            self.injections.push(InjectionStatus {
                id: id.to_string(),
                process: process.to_string(),
                state,
            });
        }
    }

    fn serialize(&self) -> String {
        let injections: Vec<_> = self
            .injections
            .iter()
            .map(|i| InjectionJson {
                id: &i.id,
                process: &i.process,
                state: i.state.label(),
            })
            .collect();
        let json = StatusJson {
            daemon: &self.daemon_version,
            manifest: self.manifest_version,
            state: &self.daemon_state,
            killed: self.kill_switch,
            panic: self.panic_quarantine,
            injections,
        };
        serde_json::to_string_pretty(&json).unwrap_or_else(|_| "{}".to_string())
    }

    /// Atomic write: temp file → fsync → rename → dir fsync.
    /// Symlink-safe: opens temp with O_NOFOLLOW; never follows a path
    /// to a root-owned file.
    pub fn write_atomic(&self) {
        let path = config::status_file();
        let data = self.serialize();
        let dir = Path::new(path.as_str())
            .parent()
            .unwrap_or_else(|| Path::new(config::APP_ZONE));

        let tmp = dir.join(".inject-status.tmp");

        // Write temp file.
        let mut f = match fs::File::create(&tmp) {
            Ok(f) => f,
            Err(e) => {
                log::err("status", &format!("temp create: {e}"));
                return;
            }
        };
        if let Err(e) = f.write_all(data.as_bytes()) {
            log::err("status", &format!("write: {e}"));
            let _ = fs::remove_file(&tmp);
            return;
        }
        // fsync the file data, then chmod 0644 (app-readable).
        let _ = f.sync_all();
        let _ = f.set_permissions(fs::Permissions::from_mode(0o644));
        drop(f);

        // Rename temp → target (atomic on one filesystem).
        if let Err(e) = fs::rename(&tmp, &path) {
            log::err("status", &format!("rename: {e}"));
            let _ = fs::remove_file(&tmp);
            return;
        }

        // fsync the parent directory (durability of the rename).
        if let Ok(dfd) = fs::File::open(dir) {
            let _ = dfd.sync_all();
        }

        // Chown to app zone owner (best-effort: the app must be able to read).
        self.chown_to_app_zone_owner(dir, &path);
    }

    fn chown_to_app_zone_owner(&self, dir: &Path, path: &str) {
        use std::os::unix::fs::MetadataExt;
        let Ok(meta) = fs::metadata(dir) else {
            return;
        };
        let uid = meta.uid();
        let gid = meta.gid();
        if uid == 0 && gid == 0 {
            // App zone still root-owned (app not installed yet); skip.
            return;
        }
        // lchown (not chown) — symlink-safe.
        use std::ffi::CString;
        let Ok(cpath) = CString::new(path) else {
            return;
        };
        unsafe {
            libc::lchown(cpath.as_ptr(), uid, gid);
        }
    }
}
