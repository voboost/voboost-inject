// Inject and agent diagnostics routed to the resident owner.
// The owner assigns UTC timestamps, sequence and bound source; producer event
// time remains context. Independent128 MiB tiers retain debug+info+error,
// info+error, and error. Endpoint ownership binds agent identity before records
// reach this facade; unregistered native diagnostics keep their declared source
// as context and use daemon identity.
#![allow(dead_code)]

use std::ffi::{CStr, CString, OsStr};
use std::fs::{File, Metadata};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config;

static DEBUG_ENABLED: AtomicBool = AtomicBool::new(true);
static LOGGER: OnceLock<Mutex<LogAuthority>> = OnceLock::new();
static FALLBACK_REPORTED: AtomicBool = AtomicBool::new(false);
const MAX_LOG_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_LOG_RECORD_BYTES: usize = 64 * 1024;
const RETENTION_DAYS: u64 = 7;

static LAST_CLEANUP: AtomicU64 = AtomicU64::new(0);
const CLEANUP_INTERVAL_SECS: u64 = 24 * 60 * 60;

/// Initialize the logger with the log directory.
pub fn init() {
    if crate::canonical_log::init_global(config::LOG_DIR).is_err() {
        report_unavailable();
    } else {
        crate::fixed_process::enable_observations();
    }
}

/// Run the retention sweep at most once per 24 h, not once per process:
/// a daemon living for months must still drop expired log pairs.
pub fn maybe_cleanup() {
    let now = now_secs();
    let last = LAST_CLEANUP.load(Ordering::Relaxed);
    if now > last
        && now - last >= CLEANUP_INTERVAL_SECS
        && LAST_CLEANUP.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            == Ok(last)
    {
        if let Some(logger) = LOGGER.get() {
            match logger.lock() {
                Ok(mut authority) => authority.cleanup(SystemTime::now()),
                Err(_) => report_unavailable(),
            }
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Toggle debug verbosity at runtime (plan log_level "debug" => on).
pub fn set_debug(enabled: bool) {
    DEBUG_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_debug() -> bool {
    DEBUG_ENABLED.load(Ordering::Relaxed)
}

fn tag_symbol(tag: LogTag) -> &'static str {
    match tag {
        LogTag::Minus => "-",
        LogTag::Plus => "+",
        LogTag::Star => "*",
    }
}

#[derive(Clone, Copy)]
pub enum LogTag {
    Minus,
    Plus,
    Star,
}

/// Agent log levels (unified across daemon/agents/app). Higher = more verbose.
pub const LEVEL_NONE: i32 = 0;
pub const LEVEL_ERROR: i32 = 1;
pub const LEVEL_INFO: i32 = 2;
pub const LEVEL_DEBUG: i32 = 3;

pub fn info(src: &str, msg: &str) {
    write_log(LogTag::Plus, src, msg);
}

pub fn info_fields(src: &str, msg: &str, fields: std::collections::HashMap<String, String>) {
    write_log_fields(LogTag::Plus, src, msg, fields);
}

pub fn debug_fields(src: &str, msg: &str, fields: std::collections::HashMap<String, String>) {
    if is_debug() {
        write_log_fields(LogTag::Star, src, msg, fields);
    }
}

pub fn ok(src: &str, msg: &str) {
    write_log(LogTag::Plus, src, msg);
}

pub fn err(src: &str, msg: &str) {
    write_log(LogTag::Minus, src, msg);
}

pub fn debug(src: &str, msg: &str) {
    if !is_debug() {
        return;
    }
    write_log(LogTag::Star, src, msg);
}

/// Write an agent-originated log line.
///
/// `ts_ms` is the event timestamp (Unix milliseconds), stamped by the agent at
/// call time — preserved as producerTimestampMs/producerClock fields. Canonical
/// timestamp/sequence describe sink receipt order, never a fabricated event order. `level` is the unified
/// int level (1=ERROR, 2=INFO, 3=DEBUG); `source` is an endpoint-owned agent ID,
/// or None for unregistered native diagnostics. The `log_level` threshold (`info`/`debug`) filters agent
/// lines here, at the single filter point.
pub fn agent(
    ts_ms: u64,
    source: Option<&str>,
    level: i32,
    msg: &str,
    mut fields: std::collections::HashMap<String, String>,
) {
    let tag = match level {
        LEVEL_ERROR => LogTag::Minus,
        LEVEL_INFO => LogTag::Plus,
        LEVEL_DEBUG => LogTag::Star,
        _ => return,
    };
    // Filter: debug-level agent lines are dropped unless debug is enabled
    // (same threshold as the daemon's own debug lines).
    if level == LEVEL_DEBUG && !is_debug() {
        return;
    }
    fields.insert("producerTimestampMs".into(), ts_ms.to_string());
    fields.insert("producerClock".into(), "unix".into());
    let canonical_level = match tag {
        LogTag::Minus => crate::canonical_log::Level::Error,
        LogTag::Plus => crate::canonical_log::Level::Info,
        LogTag::Star => crate::canonical_log::Level::Debug,
    };
    let fallback_fields = fields.clone();
    if crate::canonical_log::append_global(
        crate::canonical_log::Source {
            kind: if source.is_some() { "agent" } else { "daemon" }.into(),
            id: source.map(str::to_string),
        },
        crate::canonical_log::ProducerRecord {
            level: canonical_level,
            component: if source.is_some() { "agent" } else { "implant" }.into(),
            message: msg.to_string(),
            fields,
        },
    )
    .is_err()
    {
        fallback(tag, "agent", msg, &fallback_fields);
    }
}

/// Private helper producer frame, canonicalized once by its owning parent.
#[cfg(target_os = "android")]
pub fn helper_record(level: crate::canonical_log::Level, component: &str, message: &str) {
    use std::io::Write;
    if level == crate::canonical_log::Level::Debug && !is_debug() {
        return;
    }
    let record = crate::canonical_log::ProducerRecord {
        level,
        component: component.into(),
        message: message.chars().take(1024).collect(),
        fields: Default::default(),
    };
    if let Ok(mut bytes) = serde_json::to_vec(&record) {
        bytes.push(b'\n');
        let _ = std::io::stderr().lock().write_all(&bytes);
    }
}
pub fn producer(record: crate::canonical_log::ProducerRecord) {
    let tag = match record.level {
        crate::canonical_log::Level::Debug => {
            if !is_debug() {
                return;
            }
            LogTag::Star
        }
        crate::canonical_log::Level::Info => LogTag::Plus,
        crate::canonical_log::Level::Error => LogTag::Minus,
    };
    write_log_fields(tag, &record.component, &record.message, record.fields);
}

fn write_log(tag: LogTag, src: &str, msg: &str) {
    write_log_fields(tag, src, msg, std::collections::HashMap::new());
}

fn write_log_fields(
    tag: LogTag,
    src: &str,
    msg: &str,
    fields: std::collections::HashMap<String, String>,
) {
    let record = crate::canonical_log::ProducerRecord {
        level: canonical_level(tag),
        component: src.into(),
        message: msg.into(),
        fields,
    };
    if crate::canonical_log::append_global(
        crate::canonical_log::Source {
            kind: "daemon".into(),
            id: None,
        },
        record.clone(),
    )
    .is_err()
    {
        fallback(tag, &record.component, &record.message, &record.fields);
    }
}

fn fallback(
    tag: LogTag,
    component: &str,
    message: &str,
    fields: &std::collections::HashMap<String, String>,
) {
    use voboost_shared::diagnostic_log::{self, Level, Service};
    let level = match tag {
        LogTag::Minus => Level::Error,
        LogTag::Plus => Level::Info,
        LogTag::Star => Level::Debug,
    };
    let context = fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect::<Vec<_>>();
    diagnostic_log::stderr(Service::Inject, level, component, message, &context);
}

fn canonical_level(tag: LogTag) -> crate::canonical_log::Level {
    match tag {
        LogTag::Minus => crate::canonical_log::Level::Error,
        LogTag::Plus => crate::canonical_log::Level::Info,
        LogTag::Star => crate::canonical_log::Level::Debug,
    }
}

/// Format an agent line from an explicit event timestamp (Unix ms), using the
/// daemon's wall-clock `now` only to pick the log file (same-day date).
fn format_agent_line(ts_ms: u64, tag: LogTag, src: &str, msg: &str) -> String {
    let secs = ts_ms / 1000;
    let millis = ts_ms % 1000;
    let (year, month, day, hour, min, sec) = decompose_unix(secs);
    format!(
        "{{\"timestamp\":\"{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{millis:03}Z\",\"level\":\"{level}\",\"service\":\"voboost-daemon\",\"source\":\"{src}\",\"event\":\"log.agent\",\"outcome\":\"{outcome}\",\"fields\":{{\"message\":\"{msg}\"}}}}
",
        level = level_name(tag),
        outcome = tag_outcome(tag)
    )
}

/// Write an already-formatted line to today's log file (now only picks the file).
fn write_line(now: SystemTime, line: String) {
    let result = LOGGER
        .get()
        .ok_or_else(|| invalid_data("logger is not initialized"))
        .and_then(|logger| {
            logger
                .lock()
                .map_err(|_| invalid_data("logger lock is poisoned"))?
                .append(now, line.as_bytes())
        });
    if result.is_err() {
        report_unavailable();
    }
}

pub(crate) fn report_unavailable() {
    if !FALLBACK_REPORTED.swap(true, Ordering::Relaxed) {
        fallback(
            LogTag::Minus,
            "logger",
            "secure file logger unavailable",
            &Default::default(),
        );
    }
}

struct LogAuthority {
    dir: File,
    directory_stamp: DirectoryStamp,
    uid: u32,
    gid: u32,
    max_file_bytes: u64,
    poisoned: bool,
}

impl LogAuthority {
    fn open_or_create(path: &Path, uid: u32, gid: u32) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(invalid_data("log directory path is not absolute"));
        }
        let parent = path
            .parent()
            .ok_or_else(|| invalid_data("log directory has no parent"))?;
        let name = path
            .file_name()
            .ok_or_else(|| invalid_data("log directory has no name"))?;
        let parent = open_directory_tree(parent)?;
        validate_parent(&parent, uid, gid)?;
        let name = c_name(name)?;
        let (dir, created) = match openat_directory(&parent, &name) {
            Ok(dir) => (dir, false),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let result = unsafe {
                    libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700 as libc::mode_t)
                };
                if result == 0 {
                    (openat_directory(&parent, &name)?, true)
                } else if io::Error::last_os_error().kind() == io::ErrorKind::AlreadyExists {
                    (openat_directory(&parent, &name)?, false)
                } else {
                    return Err(io::Error::last_os_error());
                }
            }
            Err(error) => return Err(error),
        };
        if created {
            if unsafe { libc::fchown(dir.as_raw_fd(), uid, gid) } != 0
                || unsafe { libc::fchmod(dir.as_raw_fd(), 0o700 as libc::mode_t) } != 0
            {
                return Err(io::Error::last_os_error());
            }
            dir.sync_all()?;
            parent.sync_all()?;
        }
        Self::from_directory(dir, uid, gid, MAX_LOG_FILE_BYTES)
    }

    #[cfg(test)]
    fn open_existing(path: &Path, uid: u32, gid: u32, max_file_bytes: u64) -> io::Result<Self> {
        let path = c_path(path)?;
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Self::from_directory(unsafe { File::from_raw_fd(fd) }, uid, gid, max_file_bytes)
    }

    fn from_directory(dir: File, uid: u32, gid: u32, max_file_bytes: u64) -> io::Result<Self> {
        let meta = dir.metadata()?;
        validate_directory(&meta, uid, gid)?;
        Ok(Self {
            dir,
            directory_stamp: DirectoryStamp::from(&meta),
            uid,
            gid,
            max_file_bytes,
            poisoned: false,
        })
    }

    fn append(&mut self, now: SystemTime, line: &[u8]) -> io::Result<()> {
        self.append_with_io(now, line, write_all_fd, truncate_fd)
    }

    fn append_with_io<W, T>(
        &mut self,
        now: SystemTime,
        line: &[u8],
        mut write: W,
        mut truncate: T,
    ) -> io::Result<()>
    where
        W: FnMut(&File, &[u8]) -> Result<(), WriteFailure>,
        T: FnMut(&File, u64) -> io::Result<()>,
    {
        validate_record(line)?;
        if line.len() as u64 > self.max_file_bytes {
            return Err(invalid_data("log record exceeds file size bound"));
        }
        self.validate_authority()?;
        let daily = daily_name(now);
        let mut file = self.open_log(&daily, true)?;
        let before = file.metadata()?;
        if before.len().saturating_add(line.len() as u64) > self.max_file_bytes {
            drop(file);
            self.rotate(&daily)?;
            file = self.open_log(&daily, true)?;
        }

        let before = file.metadata()?;
        validate_log(&before, self.uid, self.gid, self.max_file_bytes)?;
        let before = LogStamp::from(&before);
        if let Err(failure) = write(&file, line) {
            if self
                .restore_failed_append(&daily, &file, &before, failure.bytes_written, &mut truncate)
                .is_err()
            {
                self.poisoned = true;
            }
            return Err(failure.error);
        }
        let expected_len = before
            .size
            .checked_add(line.len() as u64)
            .ok_or_else(|| invalid_data("log size overflow after appending"))?;
        if let Err(error) = self.confirm_open_log(&daily, &file, &before.identity, expected_len) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    fn restore_failed_append<T>(
        &self,
        daily: &str,
        file: &File,
        before: &LogStamp,
        bytes_written: usize,
        truncate: &mut T,
    ) -> io::Result<()>
    where
        T: FnMut(&File, u64) -> io::Result<()>,
    {
        let partial_len = before
            .size
            .checked_add(bytes_written as u64)
            .ok_or_else(|| invalid_data("log size overflow during failed append"))?;
        self.confirm_open_log(daily, file, &before.identity, partial_len)?;
        if bytes_written != 0 {
            truncate(file, before.size)?;
        }
        self.confirm_open_log(daily, file, &before.identity, before.size)
    }

    fn confirm_open_log(
        &self,
        name: &str,
        file: &File,
        expected_identity: &FileIdentity,
        expected_len: u64,
    ) -> io::Result<()> {
        self.validate_authority()?;
        let meta = file.metadata()?;
        validate_log(&meta, self.uid, self.gid, self.max_file_bytes)?;
        if &FileIdentity::from(&meta) != expected_identity || meta.len() != expected_len {
            return Err(invalid_data("log inode changed while appending"));
        }
        if entry_stat(&self.dir, name)? != LogStamp::from(&meta) {
            return Err(invalid_data("open log differs from directory entry"));
        }
        Ok(())
    }

    fn rotate(&mut self, daily: &str) -> io::Result<()> {
        self.validate_authority()?;
        if !is_daily_log_name(daily) || daily.ends_with(".1") {
            return Err(invalid_data("invalid daily log name"));
        }
        let source = self.open_log(daily, false)?;
        let source_stamp = LogStamp::from(&source.metadata()?);
        let rotated = format!("{daily}.1");
        match self.open_log(&rotated, false) {
            Ok(existing) => {
                let stamp = LogStamp::from(&existing.metadata()?);
                drop(existing);
                self.unlink_exact(&rotated, &stamp)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        self.require_entry_stamp(daily, &source_stamp)?;
        let old = c_name(OsStr::new(daily))?;
        let new = c_name(OsStr::new(&rotated))?;
        if unsafe {
            libc::renameat(
                self.dir.as_raw_fd(),
                old.as_ptr(),
                self.dir.as_raw_fd(),
                new.as_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        self.dir.sync_all()
    }

    fn cleanup(&mut self, now: SystemTime) {
        if self.validate_authority().is_err() {
            report_unavailable();
            return;
        }
        let cutoff = now
            .checked_sub(std::time::Duration::from_secs(RETENTION_DAYS * 86_400))
            .unwrap_or(UNIX_EPOCH);
        let Ok(names) = directory_names(&self.dir) else {
            report_unavailable();
            return;
        };
        for name in names {
            if !is_daily_log_name(&name) {
                continue;
            }
            let Ok(file) = self.open_log(&name, false) else {
                continue;
            };
            let Ok(meta) = file.metadata() else {
                continue;
            };
            if meta.modified().map(|time| time < cutoff).unwrap_or(false) {
                let stamp = LogStamp::from(&meta);
                drop(file);
                let _ = self.unlink_exact(&name, &stamp);
            }
        }
    }

    fn validate_authority(&self) -> io::Result<()> {
        if self.poisoned {
            return Err(invalid_data("log authority is permanently poisoned"));
        }
        let meta = self.dir.metadata()?;
        validate_directory(&meta, self.uid, self.gid)?;
        if DirectoryStamp::from(&meta) != self.directory_stamp {
            return Err(invalid_data("log directory authority changed"));
        }
        Ok(())
    }

    fn open_log(&self, name: &str, create: bool) -> io::Result<File> {
        if !is_daily_log_name(name) {
            return Err(invalid_data("invalid log file name"));
        }
        let name_c = c_name(OsStr::new(name))?;
        let mut flags = libc::O_WRONLY | libc::O_APPEND | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        if create {
            flags |= libc::O_CREAT;
        }
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                name_c.as_ptr(),
                flags,
                0o600 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let meta = file.metadata()?;
        validate_log(&meta, self.uid, self.gid, self.max_file_bytes)?;
        let entry = entry_stat(&self.dir, name)?;
        if LogStamp::from(&meta) != entry {
            return Err(invalid_data("opened log differs from directory entry"));
        }
        Ok(file)
    }

    fn require_entry_stamp(&self, name: &str, expected: &LogStamp) -> io::Result<()> {
        if &entry_stat(&self.dir, name)? != expected {
            return Err(invalid_data("log directory entry was substituted"));
        }
        Ok(())
    }

    fn unlink_exact(&self, name: &str, expected: &LogStamp) -> io::Result<()> {
        self.require_entry_stamp(name, expected)?;
        let name = c_name(OsStr::new(name))?;
        if unsafe { libc::unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn format_line(now: SystemTime, tag: LogTag, src: &str, msg: &str) -> String {
    let (secs, millis) = elapsed(now);
    let (year, month, day, hour, min, sec) = decompose_unix(secs);
    format!(
        "{{\"timestamp\":\"{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{millis:03}Z\",\"level\":\"{level}\",\"service\":\"voboost-daemon\",\"source\":\"{src}\",\"event\":\"log.line\",\"outcome\":\"{outcome}\",\"fields\":{{\"message\":\"{msg}\",\"tag\":\"{tag}\"}}}}\n",
        level = level_name(tag),
        outcome = tag_outcome(tag),
        tag = tag_symbol(tag)
    )
}

fn level_name(tag: LogTag) -> &'static str {
    match tag {
        LogTag::Minus => "error",
        LogTag::Plus | LogTag::Star => "info",
    }
}

fn tag_outcome(tag: LogTag) -> &'static str {
    match tag {
        LogTag::Minus => "failure",
        LogTag::Plus => "success",
        LogTag::Star => "info",
    }
}

/// Escape a string for embedding in a JSON string literal.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn elapsed(now: SystemTime) -> (u64, u64) {
    let dur = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    (dur.as_secs(), dur.subsec_millis() as u64)
}

/// Decompose a Unix timestamp into (year, month, day, hour, min, sec) in UTC.
/// Uses a simple civil-from-days algorithm (no chrono dependency).
fn decompose_unix(unix: u64) -> (u32, u32, u32, u32, u32, u32) {
    let days = (unix / 86400) as i64;
    let rem = (unix % 86400) as u32;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;

    // Days since epoch (1970-01-01) → civil date (Howard Hinnant's algorithm).
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y } as u32;

    (year, m, d, hour, min, sec)
}

fn daily_name(now: SystemTime) -> String {
    let (secs, _) = elapsed(now);
    let (year, month, day, _, _, _) = decompose_unix(secs);
    format!("{year:04}-{month:02}-{day:02}.jsonl")
}

fn is_daily_log_name(name: &str) -> bool {
    let base = name.strip_suffix(".1").unwrap_or(name);
    let Some(date) = base.strip_suffix(".jsonl") else {
        return false;
    };
    let bytes = date.as_bytes();
    if !(bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit()))
    {
        return false;
    }
    let month = date[5..7].parse::<u8>().unwrap_or(0);
    let day = date[8..10].parse::<u8>().unwrap_or(0);
    (1..=12).contains(&month) && (1..=31).contains(&day)
}

fn validate_record(line: &[u8]) -> io::Result<()> {
    if line.is_empty()
        || line.len() > MAX_LOG_RECORD_BYTES
        || line.last() != Some(&b'\n')
        || line[..line.len() - 1].contains(&b'\n')
        || serde_json::from_slice::<serde_json::Value>(&line[..line.len() - 1])
            .map(|value| !value.is_object())
            .unwrap_or(true)
    {
        return Err(invalid_data("log record is not one bounded JSON line"));
    }
    Ok(())
}

fn validate_parent(parent: &File, uid: u32, gid: u32) -> io::Result<()> {
    let meta = parent.metadata()?;
    if !meta.file_type().is_dir()
        || meta.uid() != uid
        || meta.gid() != gid
        || meta.mode() & 0o022 != 0
    {
        return Err(invalid_data("log parent is not a trusted root directory"));
    }
    Ok(())
}

fn validate_directory(meta: &Metadata, uid: u32, gid: u32) -> io::Result<()> {
    if !meta.file_type().is_dir()
        || meta.uid() != uid
        || meta.gid() != gid
        || meta.mode() & 0o7777 != 0o700
        || !directory_links_are_exact(meta.nlink())
    {
        return Err(invalid_data(
            "log directory must be an exact private directory authority",
        ));
    }
    Ok(())
}

fn directory_links_are_exact(nlink: u64) -> bool {
    if cfg!(any(target_os = "android", target_os = "linux")) {
        nlink == 2
    } else {
        // APFS reports directory link counts differently as regular entries
        // are added; it must still retain the mandatory self/parent links.
        nlink >= 2
    }
}

fn validate_log(meta: &Metadata, uid: u32, gid: u32, max_bytes: u64) -> io::Result<()> {
    if !meta.file_type().is_file()
        || meta.uid() != uid
        || meta.gid() != gid
        || meta.mode() & 0o7777 != 0o600
        || meta.nlink() != 1
        || meta.len() > max_bytes
    {
        return Err(invalid_data(
            "log entry is not an exact bounded private regular file",
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct WriteFailure {
    error: io::Error,
    bytes_written: usize,
}

fn write_all_fd(file: &File, bytes: &[u8]) -> Result<(), WriteFailure> {
    write_all_with(bytes, |remaining| write_fd_once(file, remaining))
}

fn write_fd_once(file: &File, bytes: &[u8]) -> io::Result<usize> {
    let written = unsafe {
        libc::write(
            file.as_raw_fd(),
            bytes.as_ptr().cast(),
            bytes.len() as libc::size_t,
        )
    };
    if written < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(written as usize)
    }
}

fn truncate_fd(file: &File, len: u64) -> io::Result<()> {
    let len = libc::off_t::try_from(len).map_err(|_| invalid_data("log truncate size overflow"))?;
    loop {
        if unsafe { libc::ftruncate(file.as_raw_fd(), len) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn write_all_with<F>(mut bytes: &[u8], mut write: F) -> Result<(), WriteFailure>
where
    F: FnMut(&[u8]) -> io::Result<usize>,
{
    let mut bytes_written = 0;
    while !bytes.is_empty() {
        match write(bytes) {
            Ok(0) => {
                return Err(WriteFailure {
                    error: io::Error::new(io::ErrorKind::WriteZero, "zero-length log write"),
                    bytes_written,
                });
            }
            Ok(written) if written <= bytes.len() => {
                bytes_written += written;
                bytes = &bytes[written..];
            }
            Ok(_) => {
                return Err(WriteFailure {
                    error: invalid_data("log write returned an invalid length"),
                    bytes_written,
                });
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(WriteFailure {
                    error,
                    bytes_written,
                });
            }
        }
    }
    Ok(())
}

fn open_directory_tree(path: &Path) -> io::Result<File> {
    let root = CString::new("/").expect("literal has no NUL");
    let fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut current = unsafe { File::from_raw_fd(fd) };
    for component in path.components() {
        use std::path::Component;
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                current = openat_directory(&current, &c_name(name)?)?;
            }
            _ => return Err(invalid_data("log path is not canonical absolute path")),
        }
    }
    Ok(current)
}

fn openat_directory(parent: &File, name: &CStr) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn entry_stat(dir: &File, name: &str) -> io::Result<LogStamp> {
    let name = c_name(OsStr::new(name))?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(LogStamp::from(unsafe { &stat.assume_init() }))
}

fn directory_names(dir: &File) -> io::Result<Vec<String>> {
    // `dup` would share the directory stream offset and make later retention
    // passes start at EOF. Reopen `.` relative to the retained authority so
    // every sweep receives an independent cursor without resolving a path.
    let dot = CString::new(".").expect("literal has no NUL");
    let cursor = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if cursor < 0 {
        return Err(io::Error::last_os_error());
    }
    let stream = unsafe { libc::fdopendir(cursor) };
    if stream.is_null() {
        unsafe { libc::close(cursor) };
        return Err(io::Error::last_os_error());
    }
    let mut names = Vec::new();
    loop {
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if let Ok(name) = name.to_str() {
            if name != "." && name != ".." {
                names.push(name.to_owned());
            }
        }
    }
    if unsafe { libc::closedir(stream) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(names)
}

#[cfg(test)]
fn c_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

fn c_name(name: &OsStr) -> io::Result<CString> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "entry name must be one path component",
        ));
    }
    CString::new(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "entry name contains NUL"))
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DirectoryStamp {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

impl From<&Metadata> for DirectoryStamp {
    fn from(meta: &Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.mode(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
}

impl From<&Metadata> for FileIdentity {
    fn from(meta: &Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.mode(),
            nlink: meta.nlink(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LogStamp {
    identity: FileIdentity,
    size: u64,
}

impl From<&Metadata> for LogStamp {
    fn from(meta: &Metadata) -> Self {
        Self {
            identity: FileIdentity::from(meta),
            size: meta.len(),
        }
    }
}

impl From<&libc::stat> for LogStamp {
    fn from(stat: &libc::stat) -> Self {
        Self {
            identity: FileIdentity {
                dev: stat.st_dev as u64,
                ino: stat.st_ino,
                uid: stat.st_uid,
                gid: stat.st_gid,
                mode: stat.st_mode as u32,
                nlink: stat.st_nlink as u64,
            },
            size: stat.st_size as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    fn fixture(max_file_bytes: u64) -> (TempDir, std::path::PathBuf, LogAuthority) {
        let root = tempfile::tempdir().unwrap();
        let logs = root.path().join("logs");
        fs::create_dir(&logs).unwrap();
        fs::set_permissions(&logs, fs::Permissions::from_mode(0o700)).unwrap();
        let authority = LogAuthority::open_existing(
            &logs,
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            max_file_bytes,
        )
        .unwrap();
        (root, logs, authority)
    }

    #[test]
    fn level_mapping_never_relabels_info_as_debug() {
        assert_eq!(
            canonical_level(LogTag::Minus),
            crate::canonical_log::Level::Error
        );
        assert_eq!(
            canonical_level(LogTag::Plus),
            crate::canonical_log::Level::Info
        );
        assert_eq!(
            canonical_level(LogTag::Star),
            crate::canonical_log::Level::Debug
        );
    }

    fn private_file(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn test_line(id: usize) -> Vec<u8> {
        format!("{{\"id\":{id},\"message\":\"safe\"}}\n").into_bytes()
    }

    fn partial_then_error(
        error_kind: io::ErrorKind,
    ) -> impl FnMut(&File, &[u8]) -> Result<(), WriteFailure> {
        move |file, bytes| {
            let mut calls = 0;
            write_all_with(bytes, |remaining| {
                calls += 1;
                if calls == 1 {
                    write_fd_once(file, &remaining[..remaining.len().min(5)])
                } else {
                    Err(io::Error::new(error_kind, "injected hard write error"))
                }
            })
        }
    }

    #[test]
    fn exact_directory_is_created_privately_and_symlink_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let canonical_root = fs::canonicalize(root.path()).unwrap();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let logs = canonical_root.join("logs");
        let authority = LogAuthority::open_or_create(&logs, uid, gid).unwrap();
        let meta = authority.dir.metadata().unwrap();
        assert_eq!(meta.mode() & 0o777, 0o700);
        assert_eq!((meta.uid(), meta.gid()), (uid, gid));
        drop(authority);

        fs::remove_dir(&logs).unwrap();
        let target = canonical_root.join("target");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&target, &logs).unwrap();
        assert!(LogAuthority::open_or_create(&logs, uid, gid).is_err());
    }

    #[test]
    fn names_are_an_exact_daily_or_rotated_allowlist() {
        assert!(is_daily_log_name("2026-08-24.jsonl"));
        assert!(is_daily_log_name("2026-08-24.jsonl.1"));
        for invalid in [
            "2026-00-24.jsonl",
            "2026-13-24.jsonl",
            "2026-08-00.jsonl",
            "2026-08-24.jsonl.2",
            "../2026-08-24.jsonl",
            "2026-08-24.jsonl.tmp",
        ] {
            assert!(!is_daily_log_name(invalid), "accepted {invalid}");
        }
    }

    #[test]
    fn append_rejects_symlink_hardlink_and_foreign_metadata() {
        let (_root, logs, mut authority) = fixture(4096);
        let date = daily_name(UNIX_EPOCH);
        let victim = logs.parent().unwrap().join("victim");
        private_file(&victim, b"victim");
        symlink(&victim, logs.join(&date)).unwrap();
        assert!(authority.append(UNIX_EPOCH, &test_line(1)).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"victim");

        fs::remove_file(logs.join(&date)).unwrap();
        let hard_target = logs.parent().unwrap().join("hard-target");
        private_file(&hard_target, b"hard");
        fs::hard_link(&hard_target, logs.join(&date)).unwrap();
        assert!(authority.append(UNIX_EPOCH, &test_line(2)).is_err());
        assert_eq!(fs::read(&hard_target).unwrap(), b"hard");

        fs::remove_file(logs.join(&date)).unwrap();
        private_file(&logs.join(&date), b"foreign");
        fs::set_permissions(logs.join(&date), fs::Permissions::from_mode(0o640)).unwrap();
        assert!(authority.append(UNIX_EPOCH, &test_line(3)).is_err());
        assert_eq!(fs::read(logs.join(&date)).unwrap(), b"foreign");
    }

    #[test]
    fn rotation_refuses_a_substituted_destination() {
        let (_root, logs, mut authority) = fixture(64);
        let date = daily_name(UNIX_EPOCH);
        let seed = vec![b'x'; 60];
        private_file(&logs.join(&date), &seed);
        let victim = logs.parent().unwrap().join("rotation-victim");
        private_file(&victim, b"victim");
        symlink(&victim, logs.join(format!("{date}.1"))).unwrap();

        assert!(authority.append(UNIX_EPOCH, &test_line(1)).is_err());
        assert_eq!(fs::read(logs.join(&date)).unwrap(), seed);
        assert_eq!(fs::read(victim).unwrap(), b"victim");
    }

    #[test]
    fn short_writes_and_eintr_are_retried() {
        let mut output = Vec::new();
        let mut calls = 0;
        write_all_with(b"complete", |remaining| {
            calls += 1;
            if calls == 1 {
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            let written = remaining.len().min(2);
            output.extend_from_slice(&remaining[..written]);
            Ok(written)
        })
        .unwrap();
        assert_eq!(output, b"complete");
        assert!(calls > 2);
    }

    #[test]
    fn partial_hard_error_rolls_back_the_same_open_inode() {
        let (_root, logs, mut authority) = fixture(4096);
        let date = daily_name(UNIX_EPOCH);
        let seed = test_line(1);
        private_file(&logs.join(&date), &seed);
        let identity = FileIdentity::from(&fs::metadata(logs.join(&date)).unwrap());

        let error = authority
            .append_with_io(
                UNIX_EPOCH,
                &test_line(2),
                partial_then_error(io::ErrorKind::PermissionDenied),
                truncate_fd,
            )
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(fs::read(logs.join(&date)).unwrap(), seed);
        assert_eq!(
            FileIdentity::from(&fs::metadata(logs.join(date)).unwrap()),
            identity
        );
        assert!(!authority.poisoned);
    }

    #[test]
    fn recoverable_partial_error_allows_a_later_valid_jsonl_append() {
        let (_root, logs, mut authority) = fixture(4096);
        let date = daily_name(UNIX_EPOCH);
        authority.append(UNIX_EPOCH, &test_line(1)).unwrap();
        authority
            .append_with_io(
                UNIX_EPOCH,
                &test_line(2),
                partial_then_error(io::ErrorKind::BrokenPipe),
                truncate_fd,
            )
            .unwrap_err();
        authority.append(UNIX_EPOCH, &test_line(3)).unwrap();

        let bytes = fs::read(logs.join(date)).unwrap();
        let lines: Vec<_> = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(lines[0]).unwrap()["id"],
            1
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(lines[1]).unwrap()["id"],
            3
        );
    }

    #[test]
    fn rollback_failure_permanently_poisons_the_authority() {
        let (_root, logs, mut authority) = fixture(4096);
        let date = daily_name(UNIX_EPOCH);
        authority.append(UNIX_EPOCH, &test_line(1)).unwrap();

        let error = authority
            .append_with_io(
                UNIX_EPOCH,
                &test_line(2),
                partial_then_error(io::ErrorKind::PermissionDenied),
                |_file, _len| {
                    Err(io::Error::new(
                        io::ErrorKind::ReadOnlyFilesystem,
                        "injected",
                    ))
                },
            )
            .unwrap_err();
        let partial = fs::read(logs.join(&date)).unwrap();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(authority.poisoned);
        assert!(authority.append(UNIX_EPOCH, &test_line(3)).is_err());
        assert_eq!(fs::read(logs.join(&date)).unwrap(), partial);
        assert!(authority.rotate(&date).is_err());
        assert!(!logs.join(format!("{date}.1")).exists());

        let expired = "2000-01-01.jsonl";
        private_file(&logs.join(expired), b"{}\n");
        authority.cleanup(SystemTime::now() + Duration::from_secs(8 * 86_400));
        assert!(logs.join(expired).exists());
    }

    #[test]
    fn retained_directory_does_not_follow_a_path_swap() {
        let (root, logs, mut authority) = fixture(4096);
        let retained = root.path().join("retained-logs");
        fs::rename(&logs, &retained).unwrap();
        fs::create_dir(&logs).unwrap();
        fs::set_permissions(&logs, fs::Permissions::from_mode(0o700)).unwrap();
        let victim = root.path().join("victim");
        private_file(&victim, b"untouched");
        let date = daily_name(UNIX_EPOCH);
        symlink(&victim, logs.join(&date)).unwrap();

        authority.append(UNIX_EPOCH, &test_line(7)).unwrap();

        assert_eq!(fs::read(&victim).unwrap(), b"untouched");
        assert_eq!(fs::read(retained.join(date)).unwrap(), test_line(7));
    }

    #[test]
    fn concurrent_records_remain_complete_json_physical_lines() {
        let (_root, logs, authority) = fixture(64 * 1024);
        let authority = Arc::new(Mutex::new(authority));
        let barrier = Arc::new(Barrier::new(33));
        let mut threads = Vec::new();
        for id in 0..32 {
            let authority = Arc::clone(&authority);
            let barrier = Arc::clone(&barrier);
            threads.push(thread::spawn(move || {
                barrier.wait();
                authority
                    .lock()
                    .unwrap()
                    .append(UNIX_EPOCH, &test_line(id))
                    .unwrap();
            }));
        }
        barrier.wait();
        for handle in threads {
            handle.join().unwrap();
        }

        let bytes = fs::read(logs.join(daily_name(UNIX_EPOCH))).unwrap();
        assert!(bytes.ends_with(b"\n"));
        let lines: Vec<_> = bytes.split(|byte| *byte == b'\n').collect();
        assert_eq!(lines.len(), 33);
        assert!(lines.last().unwrap().is_empty());
        for line in &lines[..32] {
            assert!(serde_json::from_slice::<serde_json::Value>(line)
                .unwrap()
                .is_object());
        }
    }

    #[test]
    fn rotation_is_serialized_with_concurrent_appends() {
        let seed = vec![b'x'; 700];
        let (_root, logs, authority) = fixture(710);
        let date = daily_name(UNIX_EPOCH);
        private_file(&logs.join(&date), &seed);
        let authority = Arc::new(Mutex::new(authority));
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for id in 0..2 {
            let authority = Arc::clone(&authority);
            let barrier = Arc::clone(&barrier);
            threads.push(thread::spawn(move || {
                barrier.wait();
                authority
                    .lock()
                    .unwrap()
                    .append(UNIX_EPOCH, &test_line(id))
                    .unwrap();
            }));
        }
        barrier.wait();
        for handle in threads {
            handle.join().unwrap();
        }

        assert_eq!(fs::read(logs.join(format!("{date}.1"))).unwrap(), seed);
        let current = fs::read(logs.join(date)).unwrap();
        assert_eq!(current.split(|byte| *byte == b'\n').count(), 3);
        for line in current
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            serde_json::from_slice::<serde_json::Value>(line).unwrap();
        }
    }

    #[test]
    fn oversize_inode_and_record_fail_closed() {
        let (_root, logs, mut authority) = fixture(128);
        let date = daily_name(UNIX_EPOCH);
        let oversized = vec![b'x'; 129];
        private_file(&logs.join(&date), &oversized);
        assert!(authority.append(UNIX_EPOCH, &test_line(1)).is_err());
        assert_eq!(fs::read(logs.join(&date)).unwrap(), oversized);
        assert!(!logs.join(format!("{date}.1")).exists());

        fs::remove_file(logs.join(&date)).unwrap();
        let record = format!("{{\"message\":\"{}\"}}\n", "x".repeat(MAX_LOG_RECORD_BYTES));
        assert!(authority.append(UNIX_EPOCH, record.as_bytes()).is_err());
        assert!(!logs.join(date).exists());
    }

    #[test]
    fn retention_removes_only_exact_owned_daily_files() {
        let (_root, logs, mut authority) = fixture(4096);
        authority.cleanup(SystemTime::now());
        let daily = "2026-08-01.jsonl";
        let rotated = "2026-08-01.jsonl.1";
        private_file(&logs.join(daily), b"{}\n");
        private_file(&logs.join(rotated), b"{}\n");
        private_file(&logs.join("keep.txt"), b"keep");
        let victim = logs.parent().unwrap().join("victim");
        private_file(&victim, b"victim");
        symlink(&victim, logs.join("2026-08-02.jsonl")).unwrap();
        let hard_target = logs.parent().unwrap().join("hard-target");
        private_file(&hard_target, b"hard");
        fs::hard_link(&hard_target, logs.join("2026-08-03.jsonl")).unwrap();

        authority.cleanup(SystemTime::now() + Duration::from_secs(8 * 86_400));

        assert!(!logs.join(daily).exists());
        assert!(!logs.join(rotated).exists());
        assert_eq!(fs::read(logs.join("keep.txt")).unwrap(), b"keep");
        assert_eq!(fs::read(&victim).unwrap(), b"victim");
        assert_eq!(fs::read(&hard_target).unwrap(), b"hard");
        assert!(fs::symlink_metadata(logs.join("2026-08-02.jsonl"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(logs.join("2026-08-03.jsonl").exists());
    }
}
