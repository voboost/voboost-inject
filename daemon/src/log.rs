// log.rs — shared log format with the app.
//
// Ported from Vala log.vala: "yyyy-MM-dd HH:mm:ss.SSS [tag] src: msg".
// Root-only file /data/voboost-inject/logs/inject-YYYY-MM-DD.log (600),
// 7-day retention. Retention runs at most once per 24 hours.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config;

static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);
static LOG_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Initialize the logger with the log directory.
pub fn init() {
    let dir = PathBuf::from(config::LOG_DIR);
    let _ = fs::create_dir_all(&dir);
    let _ = set_permissions(&dir, 0o700);
    LOG_DIR.set(dir).ok();
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
        LogTag::Debug => "#",
    }
}

#[derive(Clone, Copy)]
pub enum LogTag {
    Minus,
    Plus,
    Star,
    Debug,
}

pub fn info(src: &str, msg: &str) {
    write_log(LogTag::Star, src, msg);
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
    write_log(LogTag::Debug, src, msg);
}

fn write_log(tag: LogTag, src: &str, msg: &str) {
    let now = SystemTime::now();
    let line = format_line(now, tag, src, msg);

    if let Some(dir) = LOG_DIR.get() {
        let path = today_path(dir, now);
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
            let _ = f.write_all(line.as_bytes());
            let _ = set_permissions(&path, 0o600);
        }
    } else {
        eprint!("{line}");
    }
}

fn format_line(now: SystemTime, tag: LogTag, src: &str, msg: &str) -> String {
    let (secs, millis) = elapsed(now);
    let (year, month, day, hour, min, sec) = decompose_unix(secs);
    format!(
        "{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02}.{millis:03} [{tag}] {src}: {msg}\n",
        tag = tag_symbol(tag)
    )
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

fn today_path(dir: &Path, now: SystemTime) -> PathBuf {
    let (secs, _) = elapsed(now);
    let (year, month, day, _, _, _) = decompose_unix(secs);
    dir.join(format!("inject-{year:04}-{month:02}-{day:02}.log"))
}

fn set_permissions(path: &PathBuf, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}
