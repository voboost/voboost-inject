//! Canonical best-effort diagnostics. Never writes protocol stdout.
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
static SEQUENCE: AtomicU64 = AtomicU64::new(1);
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Debug,
    Info,
    Error,
}
#[derive(Clone, Copy)]
pub enum Service {
    Daemon,
    Inject,
    CatalogVerifier,
    Install,
    Restore,
    Uninstall,
}
impl Service {
    fn name(self) -> &'static str {
        match self {
            Self::Daemon => "voboost-daemon",
            Self::Inject => "voboost-inject",
            Self::CatalogVerifier => "voboost-producer-catalog-verifier",
            Self::Install => "voboost-install",
            Self::Restore => "voboost-restore",
            Self::Uninstall => "voboost-uninstall",
        }
    }
}
#[derive(Serialize)]
struct Source {
    kind: &'static str,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    schema_version: u8,
    sequence: u64,
    timestamp: String,
    source: Source,
    level: Level,
    component: String,
    message: String,
    fields: BTreeMap<String, String>,
}
fn bounded(value: &str) -> String {
    let mut text: String = value
        .chars()
        .filter(|c| !c.is_control())
        .take(2048)
        .collect();
    for key in ["token=", "password=", "secret="] {
        if let Some(start) = text.to_ascii_lowercase().find(key) {
            let end = text[start..]
                .find(char::is_whitespace)
                .map_or(text.len(), |n| start + n);
            text.replace_range(start + key.len()..end, "[redacted]");
        }
    }
    text
}
pub fn timestamp() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let seconds = (millis / 1000) as libc::time_t;
    let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
    if unsafe { libc::gmtime_r(&seconds, tm.as_mut_ptr()) }.is_null() {
        return "1970-01-01T00:00:00.000Z".into();
    }
    let tm = unsafe { tm.assume_init() };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        millis % 1000
    )
}
pub fn encode(
    service: Service,
    level: Level,
    component: &str,
    message: &str,
    fields: &[(&str, &str)],
) -> Vec<u8> {
    let mut context = BTreeMap::new();
    for (key, value) in fields.iter().take(16) {
        context.insert(bounded(key), bounded(value));
    }
    context.insert("producerService".into(), service.name().into());
    context.insert("producerPid".into(), std::process::id().to_string());
    let record = Record {
        schema_version: 1,
        sequence: SEQUENCE.fetch_add(1, Ordering::Relaxed),
        timestamp: timestamp(),
        source: Source { kind: "daemon" },
        level,
        component: bounded(component),
        message: bounded(message),
        fields: context,
    };
    let mut bytes = serde_json::to_vec(&record).unwrap_or_default();
    if !bytes.is_empty() {
        bytes.push(b'\n');
    }
    bytes
}
pub fn stderr(
    service: Service,
    level: Level,
    component: &str,
    message: &str,
    fields: &[(&str, &str)],
) {
    write_best_effort(
        &mut io::stderr().lock(),
        &encode(service, level, component, message, fields),
    );
}
pub fn write_best_effort(writer: &mut impl Write, bytes: &[u8]) {
    let _ = writer.write_all(bytes);
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_schema_bound_source_escaping_and_sequence() {
        let first: serde_json::Value = serde_json::from_slice(&encode(
            Service::Install,
            Level::Error,
            "install",
            "quote\"\nline",
            &[("producerService", "foreign"), ("path", "x\\y")],
        ))
        .unwrap();
        let second: serde_json::Value =
            serde_json::from_slice(&encode(Service::Restore, Level::Info, "restore", "ok", &[]))
                .unwrap();
        assert_eq!(first.as_object().unwrap().len(), 8);
        assert_eq!(first["schemaVersion"], 1);
        assert_eq!(first["source"], serde_json::json!({"kind":"daemon"}));
        assert_eq!(first["level"], "error");
        assert_eq!(first["message"], "quote\"line");
        assert_eq!(first["fields"]["producerService"], "voboost-install");
        assert!(first["fields"]
            .as_object()
            .unwrap()
            .values()
            .all(|v| v.is_string()));
        let ts = first["timestamp"].as_str().unwrap();
        assert_eq!(ts.len(), 24);
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[19..20], ".");
        assert!(second["sequence"].as_u64() > first["sequence"].as_u64());
    }
    #[test]
    fn bounded_sanitized_and_redacted() {
        assert_eq!(bounded("password=abc tail\n"), "password=[redacted] tail");
        assert_eq!(bounded(&"界".repeat(3000)).chars().count(), 2048);
    }
    #[test]
    fn broken_sink_never_propagates() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        write_best_effort(
            &mut Broken,
            &encode(Service::Uninstall, Level::Debug, "uninstall", "phase", &[]),
        );
    }
}
