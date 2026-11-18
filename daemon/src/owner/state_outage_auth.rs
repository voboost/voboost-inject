//! Fixed emulator marker authority for the native controller diagnostic.
use crate::secure_fs::Directory;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const MARKER: &str = "emulator-diagnostic.json";
const LIMIT: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Window {
    schema_version: u8,
    kind: String,
    token: String,
    boot_id: String,
    release_identity: String,
    manifest_sha256: String,
    generation_id: String,
    catalog_sha256: String,
    owner_writer_id: String,
    owner_pid: i32,
    owner_starttime: String,
    daemon_pid: i32,
    daemon_starttime: String,
    target_pid: i32,
    target_starttime: String,
    started_monotonic_ms: String,
    expires_monotonic_ms: String,
}

pub(super) struct Authority {
    marker: Window,
    bytes: Vec<u8>,
    inode: u64,
    root: std::path::PathBuf,
    #[cfg(test)]
    test_clock: Option<u64>,
}

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "native outage authority unavailable",
    )
}
fn decimal(value: &str) -> Option<u64> {
    let n = value.parse::<u64>().ok()?;
    (n > 0 && n.to_string() == value).then_some(n)
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn read_bounded(path: &str, limit: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(denied());
    }
    Ok(bytes)
}
fn current_start(pid: i32) -> io::Result<u64> {
    if pid <= 1 {
        return Err(denied());
    }
    let stat = read_bounded(&format!("/proc/{pid}/stat"), 4096)?;
    let stat = std::str::from_utf8(&stat).map_err(|_| denied())?;
    let (_, rest) = stat.rsplit_once(')').ok_or_else(denied)?;
    rest.split_whitespace()
        .nth(19)
        .and_then(decimal)
        .ok_or_else(denied)
}
fn argv0(pid: i32) -> io::Result<String> {
    let bytes = read_bounded(&format!("/proc/{pid}/cmdline"), 4096)?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(denied)?;
    if end == 0 || end > 255 {
        return Err(denied());
    }
    let first = &bytes[..end];
    std::str::from_utf8(first)
        .map(str::to_owned)
        .map_err(|_| denied())
}
fn catalog_authority(root: &Directory, generation: &str) -> io::Result<()> {
    use crate::generation_layout::{
        ACTIVE_POINTER, CATALOG_FILE, CATALOG_SIGNATURE_FILE, GENERATIONS_DIR, GENERATION_FILE_MODE,
    };
    let generations = root.open_child(GENERATIONS_DIR)?;
    generations.validate_owner_mode(0, 0, 0o711)?;
    let active = generations.read_trusted(ACTIVE_POINTER, 65, GENERATION_FILE_MODE)?;
    if active != format!("{generation}\n").as_bytes() {
        return Err(denied());
    }
    let dir = generations.open_child(generation)?;
    dir.validate_owner_mode(0, 0, crate::generation_layout::GENERATION_DIR_MODE)?;
    let bytes = dir.read_trusted(
        CATALOG_FILE,
        voboost_contract::agent_catalog::MAX_CATALOG_BYTES,
        GENERATION_FILE_MODE,
    )?;
    let signature = dir.read_trusted(CATALOG_SIGNATURE_FILE, 64, GENERATION_FILE_MODE)?;
    let signature = Signature::from_slice(&signature).map_err(|_| denied())?;
    VerifyingKey::from_bytes(&crate::native_binary::AGENT_CATALOG_PUBKEY)
        .map_err(|_| denied())?
        .verify_strict(&bytes, &signature)
        .map_err(|_| denied())?;
    let catalog =
        voboost_contract::agent_catalog::AgentCatalog::parse(&bytes).map_err(|_| denied())?;
    for id in [
        "vehicle-drive-forced-ev",
        "vehicle-drive-pedestrian-warning",
    ] {
        let agents: Vec<_> = catalog
            .agents
            .iter()
            .filter(|agent| agent.id == id)
            .collect();
        if agents.len() != 1
            || agents[0]
                .targets
                .iter()
                .filter(|target| {
                    target.process == "com.qinggan.canbus.service"
                        && target.platform
                            == voboost_contract::agent_catalog::TargetPlatform::Android
                })
                .count()
                != 1
        {
            return Err(denied());
        }
    }
    Ok(())
}

fn target_security(pid: i32) -> io::Result<(u32, Vec<u8>)> {
    let status = read_bounded(&format!("/proc/{pid}/status"), 8192)?;
    let status = std::str::from_utf8(&status).map_err(|_| denied())?;
    let mut uids = status.lines().filter_map(|line| line.strip_prefix("Uid:"));
    let uid = uids.next().ok_or_else(denied)?;
    if uids.next().is_some() {
        return Err(denied());
    }
    let values: Vec<u32> = uid
        .split_whitespace()
        .map(str::parse)
        .collect::<Result<_, _>>()
        .map_err(|_| denied())?;
    if values.len() != 4 || values.iter().any(|value| *value != values[0]) {
        return Err(denied());
    }
    let context = read_bounded(&format!("/proc/{pid}/attr/current"), 256)?;
    let context = if matches!(context.last(), Some(b'\n' | 0)) {
        &context[..context.len() - 1]
    } else {
        &context
    };
    if context.is_empty()
        || context.len() > 256
        || context.iter().any(|b| *b == 0 || b.is_ascii_whitespace())
    {
        return Err(denied());
    }
    std::str::from_utf8(context).map_err(|_| denied())?;
    Ok((values[0], context.to_vec()))
}

fn monotonic_ms() -> io::Result<u64> {
    let mut time: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(time.tv_sec)
        .ok()
        .and_then(|s| s.checked_mul(1000))
        .and_then(|s| s.checked_add(time.tv_nsec as u64 / 1_000_000))
        .ok_or_else(denied)
}
fn emulator() -> bool {
    #[cfg(target_os = "android")]
    {
        unsafe extern "C" {
            fn __system_property_get(name: *const libc::c_char, value: *mut libc::c_char) -> i32;
        }
        let mut value = [0 as libc::c_char; 92];
        (unsafe { __system_property_get(c"ro.kernel.qemu".as_ptr(), value.as_mut_ptr()) }) == 1
            && value[0] == b'1' as libc::c_char
            && matches!(
                std::fs::read("/sys/fs/selinux/enforce").as_deref(),
                Ok(b"1" | b"1\n")
            )
            && unsafe { libc::geteuid() == 0 && libc::getegid() == 0 }
    }
    #[cfg(not(target_os = "android"))]
    {
        false
    }
}
#[cfg(any(target_os = "linux", target_os = "android"))]
fn lease_held(root: &Directory) -> io::Result<bool> {
    use std::os::fd::AsRawFd;
    let (_, file) = root.read_trusted_retained("operation.lock", 0, 0o600)?;
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = libc::F_RDLCK as _;
    lock.l_whence = libc::SEEK_SET as _;
    lock.l_len = 1;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_OFD_GETLK, &mut lock) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(lock.l_type == libc::F_WRLCK as libc::c_short
        && lock.l_pid == -1
        && lock.l_start == 0
        && lock.l_len == 1)
}
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn lease_held(_: &Directory) -> io::Result<bool> {
    Err(io::ErrorKind::Unsupported.into())
}

fn window_matches(
    marker: &Window,
    boot: &str,
    session: &str,
    token: &str,
    producer: (i32, u64),
) -> bool {
    let (Some(start), Some(end), Some(owner_start), Some(_daemon_start), Some(_target_start)) = (
        decimal(&marker.started_monotonic_ms),
        decimal(&marker.expires_monotonic_ms),
        decimal(&marker.owner_starttime),
        decimal(&marker.daemon_starttime),
        decimal(&marker.target_starttime),
    ) else {
        return false;
    };
    marker.schema_version == 1
        && matches!(
            marker.kind.as_str(),
            "native-state-read-unavailable" | "native-state-write-unavailable"
        )
        && marker.token == token
        && hash(token)
        && marker.boot_id == boot
        && marker.owner_writer_id == session
        && hash(&marker.manifest_sha256)
        && hash(&marker.generation_id)
        && hash(&marker.catalog_sha256)
        && !marker.release_identity.is_empty()
        && marker.release_identity.len() <= 128
        && producer == (marker.owner_pid, owner_start)
        && marker.owner_pid > 1
        && marker.daemon_pid > 1
        && marker.target_pid > 1
        && start.checked_add(90_000) == Some(end)
}

impl Authority {
    pub(super) fn begin(
        root: &Path,
        boot: &str,
        session: &str,
        token: &str,
        producer: (i32, u64),
    ) -> io::Result<(Self, super::state_outage::Scope)> {
        if !emulator() {
            return Err(denied());
        }
        let root_dir = Directory::open(root)?;
        root_dir.validate_owner_mode(0, 0, 0o755)?;
        let run = root_dir.open_child("run")?;
        run.validate_owner_mode(0, 0, crate::config::RUN_DIR_MODE)?;
        let (bytes, fd) = run.read_trusted_retained(MARKER, LIMIT, 0o600)?;
        let inode = fd.metadata()?.ino();
        let marker: Window = serde_json::from_slice(&bytes).map_err(|_| denied())?;
        let mut canonical = serde_json::to_vec(&marker).map_err(|_| denied())?;
        canonical.push(b'\n');
        let end = decimal(&marker.expires_monotonic_ms).ok_or_else(denied)?;
        if canonical != bytes || !window_matches(&marker, boot, session, token, producer) {
            return Err(denied());
        }
        let scope = super::state_outage::Scope {
            kind: match marker.kind.as_str() {
                "native-state-read-unavailable" => super::state_outage::FaultKind::Read,
                "native-state-write-unavailable" => super::state_outage::FaultKind::Write,
                _ => return Err(denied()),
            },
            token: token.into(),
            boot: boot.into(),
            generation: marker.generation_id.clone(),
            catalog: marker.catalog_sha256.clone(),
            owner_session: session.into(),
            target_pid: marker.target_pid,
            target_start: decimal(&marker.target_starttime).ok_or_else(denied)?,
            deadline_ms: end,
        };
        let authority = Self {
            marker,
            bytes,
            inode,
            root: root.into(),
            #[cfg(test)]
            test_clock: None,
        };
        authority.require_live()?;
        Ok((authority, scope))
    }
    pub(super) fn require_live(&self) -> io::Result<u64> {
        #[cfg(test)]
        if let Some(now) = self.test_clock {
            return Ok(now);
        }
        if !emulator() {
            return Err(denied());
        }
        let root = Directory::open(&self.root)?;
        root.validate_owner_mode(0, 0, 0o755)?;
        let run = root.open_child("run")?;
        run.validate_owner_mode(0, 0, crate::config::RUN_DIR_MODE)?;
        let (bytes, fd) = run.read_trusted_retained(MARKER, LIMIT, 0o600)?;
        let now = monotonic_ms()?;
        if voboost_contract::operation::current_boot_id().map_err(|_| denied())?
            != self.marker.boot_id
        {
            return Err(denied());
        }
        catalog_authority(&root, &self.marker.generation_id)?;
        let security = target_security(self.marker.target_pid)?;
        if argv0(self.marker.owner_pid)? != "/data/voboost/voboost-inject"
            || argv0(self.marker.daemon_pid)? != "/data/voboost/voboost-inject"
        {
            return Err(denied());
        }
        if bytes != self.bytes
            || fd.metadata()?.ino() != self.inode
            || !lease_held(&root)?
            || now < decimal(&self.marker.started_monotonic_ms).ok_or_else(denied)?
            || now >= decimal(&self.marker.expires_monotonic_ms).ok_or_else(denied)?
            || current_start(self.marker.owner_pid)?
                != decimal(&self.marker.owner_starttime).ok_or_else(denied)?
            || current_start(self.marker.daemon_pid)?
                != decimal(&self.marker.daemon_starttime).ok_or_else(denied)?
            || current_start(self.marker.target_pid)?
                != decimal(&self.marker.target_starttime).ok_or_else(denied)?
            || argv0(self.marker.target_pid)? != "com.qinggan.canbus.service"
        {
            return Err(denied());
        }
        let (after, after_fd) = run.read_trusted_retained(MARKER, LIMIT, 0o600)?;
        if after != self.bytes
            || target_security(self.marker.target_pid)? != security
            || after_fd.metadata()?.ino() != self.inode
            || !lease_held(&root)?
            || current_start(self.marker.target_pid)?
                != decimal(&self.marker.target_starttime).ok_or_else(denied)?
            || current_start(self.marker.owner_pid)?
                != decimal(&self.marker.owner_starttime).ok_or_else(denied)?
            || current_start(self.marker.daemon_pid)?
                != decimal(&self.marker.daemon_starttime).ok_or_else(denied)?
        {
            return Err(denied());
        }
        catalog_authority(&root, &self.marker.generation_id)?;
        let final_now = monotonic_ms()?;
        if final_now < now
            || final_now >= decimal(&self.marker.expires_monotonic_ms).ok_or_else(denied)?
        {
            return Err(denied());
        }
        Ok(final_now)
    }
}

/// One in-memory owner session. An invalidated authority can never recover coverage.
pub(super) struct Session {
    authority: Authority,
    scope: super::state_outage::Scope,
    observer: super::state_outage::Observer,
    invalid: bool,
}
impl Session {
    #[cfg(test)]
    pub(super) fn fixture() -> Self {
        let scope = super::state_outage::Scope {
            kind: super::state_outage::FaultKind::Read,
            token: "a".repeat(64),
            boot: "11111111-1111-1111-1111-111111111111".into(),
            generation: "b".repeat(64),
            catalog: "c".repeat(64),
            owner_session: "d".repeat(32),
            target_pid: 41,
            target_start: 514,
            deadline_ms: 90001,
        };
        let marker = Window {
            schema_version: 1,
            kind: "native-state-read-unavailable".into(),
            token: scope.token.clone(),
            boot_id: scope.boot.clone(),
            release_identity: "candidate".into(),
            manifest_sha256: "f".repeat(64),
            generation_id: scope.generation.clone(),
            catalog_sha256: scope.catalog.clone(),
            owner_writer_id: scope.owner_session.clone(),
            owner_pid: 42,
            owner_starttime: "100".into(),
            daemon_pid: 43,
            daemon_starttime: "101".into(),
            target_pid: 41,
            target_starttime: "514".into(),
            started_monotonic_ms: "1".into(),
            expires_monotonic_ms: "90001".into(),
        };
        let observer = super::state_outage::Observer::begin(scope.clone(), 1).unwrap();
        Self {
            authority: Authority {
                marker,
                bytes: Vec::new(),
                inode: 1,
                root: Path::new("/").into(),
                test_clock: Some(1000),
            },
            scope,
            observer,
            invalid: false,
        }
    }
    pub(super) fn begin(
        root: &Path,
        boot: &str,
        writer: &str,
        token: &str,
        producer: (i32, u64),
    ) -> io::Result<Self> {
        let (authority, scope) = Authority::begin(root, boot, writer, token, producer)?;
        let now = authority.require_live()?;
        let observer =
            super::state_outage::Observer::begin(scope.clone(), now).map_err(|_| denied())?;
        Ok(Self {
            authority,
            scope,
            observer,
            invalid: false,
        })
    }
    fn current(&mut self) -> io::Result<u64> {
        if self.invalid {
            return Err(denied());
        }
        match self.authority.require_live() {
            Ok(now) => Ok(now),
            Err(error) => {
                self.invalid = true;
                self.observer.invalidate();
                Err(error)
            }
        }
    }
    pub(super) fn stale(&mut self) -> bool {
        self.current().is_err()
    }
    fn control(&mut self, token: &str, producer: (i32, u64)) -> io::Result<u64> {
        if token != self.scope.token
            || producer
                != (
                    self.authority.marker.owner_pid,
                    decimal(&self.authority.marker.owner_starttime).ok_or_else(denied)?,
                )
        {
            return Err(denied());
        }
        self.current()
    }
    pub(super) fn stale_operation(&mut self, source: &str) {
        if source == super::state_outage::PW {
            self.invalid = true;
            self.observer.invalidate();
        }
    }
    pub(super) fn read(&mut self, source: &str, revision: u64, key: &str) -> bool {
        if source != super::state_outage::PW {
            return false;
        }
        let Ok(now) = self.current() else {
            return false;
        };
        self.observer.read(&self.scope, now, revision, source, key)
    }
    pub(super) fn read_complete(
        &mut self,
        source: &str,
        revision: u64,
        key: &str,
        result: &crate::native_api::Read<bool>,
    ) {
        if source != super::state_outage::PW || !self.observer.released() {
            return;
        }
        let Ok(now) = self.current() else {
            return;
        };
        let value = match result {
            crate::native_api::Read::Value(value) => Some(*value),
            _ => None,
        };
        let _ = self
            .observer
            .read_value(&self.scope, now, revision, source, key, value);
    }
    pub(super) fn write(&mut self, source: &str, revision: u64, key: &str) -> bool {
        if source != super::state_outage::PW {
            return false;
        }
        let Ok(now) = self.current() else {
            return false;
        };
        self.observer
            .write(&self.scope, now, revision, source, key)
            .unwrap_or(false)
    }
    pub(super) fn stopped_write(&mut self, source: &str, key: &str) {
        if source != super::state_outage::PW {
            return;
        }
        let Ok(now) = self.current() else {
            return;
        };
        let _ = self.observer.stopped_write(&self.scope, now, source, key);
    }
    pub(super) fn progress(
        &mut self,
        source: &str,
        revision: u64,
        result: Result<crate::native_api::Progress, crate::native_api::Failure>,
    ) {
        if source != super::state_outage::PW {
            return;
        }
        let Ok(now) = self.current() else {
            return;
        };
        if result
            == Ok(crate::native_api::Progress::Waiting(
                crate::native_api::Wait::State,
            ))
        {
            let _ = self.observer.wait_state(&self.scope, now, revision, source);
        } else {
            let _ = self
                .observer
                .check_progress(&self.scope, now, revision, source);
        }
    }
    pub(super) fn stopped(&mut self, source: &str) {
        if source != super::state_outage::PW {
            return;
        }
        let Ok(now) = self.current() else {
            return;
        };
        let _ = self.observer.stopped(&self.scope, now, source);
    }
    pub(super) fn receipt(
        &mut self,
        token: &str,
        producer: (i32, u64),
        action: &str,
    ) -> io::Result<voboost_contract::runtime_owner::NativeStateOutageReceipt> {
        let now = self.control(token, producer)?;
        let observed = match action {
            "snapshot" => self.observer.snapshot(&self.scope, now),
            "release" => self
                .observer
                .release(&self.scope, now)
                .and_then(|()| self.observer.snapshot(&self.scope, now)),
            "close" if self.observer.released() => self.observer.close(&self.scope, now),
            _ => return Err(denied()),
        }
        .map_err(|_| denied())?;
        let owner_pid = i32::try_from(std::process::id()).map_err(|_| denied())?;
        #[cfg(test)]
        let owner_starttime = if self.authority.test_clock.is_some() {
            123
        } else {
            current_start(owner_pid)?
        };
        #[cfg(not(test))]
        let owner_starttime = current_start(owner_pid)?;
        Ok(voboost_contract::runtime_owner::NativeStateOutageReceipt {
            kind: match self.scope.kind {
                super::state_outage::FaultKind::Read => "native-state-read-unavailable",
                super::state_outage::FaultKind::Write => "native-state-write-unavailable",
            }
            .into(),
            token: self.scope.token.clone(),
            boot_id: self.scope.boot.clone(),
            generation_id: self.scope.generation.clone(),
            catalog_sha256: self.scope.catalog.clone(),
            owner_writer_id: self.scope.owner_session.clone(),
            owner_pid,
            owner_starttime,
            target_pid: self.scope.target_pid,
            target_starttime: self.scope.target_start,
            deadline_monotonic_ms: self.scope.deadline_ms,
            observed_monotonic_ms: now,
            reads: observed.reads,
            dropped_reads: observed.dropped,
            writes: observed.writes,
            failed_writes: observed.failed_writes,
            wait_state_steps: observed.waits,
            recovered_values: observed.recovered_values,
            recovered_value: observed.recovered_value,
            lease_revision: self.observer.lease_revision(),
            stopped: observed.stopped,
            released: observed.released,
            closed: observed.closed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn window() -> Window {
        Window {
            schema_version: 1,
            kind: "native-state-read-unavailable".into(),
            token: "a".repeat(64),
            boot_id: "11111111-1111-1111-1111-111111111111".into(),
            release_identity: "candidate".into(),
            manifest_sha256: "b".repeat(64),
            generation_id: "c".repeat(64),
            catalog_sha256: "d".repeat(64),
            owner_writer_id: "e".repeat(32),
            owner_pid: 41,
            owner_starttime: "101".into(),
            daemon_pid: 42,
            daemon_starttime: "102".into(),
            target_pid: 43,
            target_starttime: "103".into(),
            started_monotonic_ms: "1".into(),
            expires_monotonic_ms: "90001".into(),
        }
    }
    #[test]
    fn stopped_old_worker_nonwaiting_progress_invalidates_coverage() {
        use crate::native_api::{Failure, Progress};
        for result in [
            Ok(Progress::Idle),
            Ok(Progress::Applied),
            Err(Failure::StateUnavailable),
        ] {
            let mut session = Session::fixture();
            assert!(session.read(
                super::super::state_outage::PW,
                7,
                super::super::state_outage::DISARM
            ));
            session.stopped(super::super::state_outage::PW);
            session.progress(super::super::state_outage::PW, 7, result);
            assert!(
                session
                    .receipt(&"a".repeat(64), (42, 100), "snapshot")
                    .is_err(),
                "old nonwaiting progress must poison coverage"
            );
        }
    }

    #[test]
    fn stale_source_read_permanently_revokes_owner_coverage() {
        let mut session = Session::fixture();
        assert!(session.read(
            super::super::state_outage::PW,
            7,
            super::super::state_outage::DISARM
        ));
        session.stopped(super::super::state_outage::PW);
        session.stale_operation(super::super::state_outage::PW);
        assert!(session
            .receipt(&"a".repeat(64), (42, 100), "snapshot")
            .is_err());
        assert!(!session.read(
            super::super::state_outage::PW,
            8,
            super::super::state_outage::DISARM
        ));
        assert!(session
            .receipt(&"a".repeat(64), (42, 100), "snapshot")
            .is_err());
    }

    #[test]
    fn window_rejects_foreign_writer_owner_replay_and_invalid_deadline() {
        let w = window();
        let valid = |x: &Window, session: &str, producer| {
            window_matches(x, &w.boot_id, session, &w.token, producer)
        };
        assert!(valid(&w, &w.owner_writer_id, (41, 101)));
        assert!(!valid(&w, &"f".repeat(32), (41, 101)));
        assert!(!valid(&w, &w.owner_writer_id, (41, 102)));
        for mutate in 0..5 {
            let mut bad = w.clone();
            match mutate {
                0 => bad.kind = "vehicle-state-reply-loss".into(),
                1 => bad.target_pid = 0,
                2 => bad.expires_monotonic_ms = "90002".into(),
                3 => bad.generation_id = "foreign".into(),
                _ => bad.target_starttime = "01".into(),
            }
            assert!(!valid(&bad, &w.owner_writer_id, (41, 101)));
        }
        assert!(
            !emulator(),
            "host tests cannot authorize an emulator diagnostic"
        );
    }
}
