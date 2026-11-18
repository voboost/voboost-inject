//! Local diagnostics; authenticated replies and stdout protocols are separate.
use alloc::{collections::BTreeMap, format, string::String, vec::Vec};
use core::sync::atomic::{AtomicU32, Ordering};
use serde::Serialize;
static SEQUENCE: AtomicU32 = AtomicU32::new(0);
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Record<'a> {
    schema_version: u8,
    sequence: u32,
    timestamp: String,
    source: Source,
    level: &'a str,
    component: &'a str,
    message: &'a str,
    fields: BTreeMap<&'a str, &'a str>,
}
#[derive(Serialize)]
struct Source {
    kind: &'static str,
    id: String,
}
pub(crate) fn timestamp(seconds: i64, millis: i64) -> String {
    let z = seconds.div_euclid(86400) + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let sod = seconds.rem_euclid(86400);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        sod / 3600,
        sod / 60 % 60,
        sod % 60
    )
}
pub(crate) fn record(
    level: &str,
    component: &str,
    message: &str,
    fields: &[(&str, &str)],
) -> Vec<u8> {
    let (sec, ms) = realtime();
    let record = Record {
        schema_version: 1,
        sequence: SEQUENCE.fetch_add(1, Ordering::Relaxed).wrapping_add(1),
        timestamp: timestamp(sec, ms),
        source: Source {
            kind: "qnx",
            id: format!("native:{}", unsafe { libc::getpid() }),
        },
        level,
        component,
        message,
        fields: fields.iter().copied().collect(),
    };
    serde_json::to_vec(&record).unwrap_or_default()
}
pub(crate) fn realtime() -> (i64, i64) {
    let mut time: libc::timespec = unsafe { core::mem::zeroed() };
    let valid =
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut time) } == 0 && time.tv_sec >= 0;
    if valid {
        (time.tv_sec as i64, time.tv_nsec as i64 / 1_000_000)
    } else {
        (0, 0)
    }
}

pub(crate) fn emit(level: &str, component: &str, message: &str, fields: &[(&str, &str)]) {
    crate::diagnostic_ram::emit(false, level, component, message.as_bytes(), fields);
}
/// # Safety
/// A non-null message must address at least min(length, 512) readable bytes.
#[no_mangle]
pub unsafe extern "C" fn vbc_preload_diagnostic(error: u32, message: *const u8, length: usize) {
    if !message.is_null() {
        let bytes = core::slice::from_raw_parts(
            message,
            length.min(voboost_contract_core::cluster_log::MAX_MESSAGE_BYTES),
        );
        crate::diagnostic_ram::emit(
            true,
            if error == 0 { "debug" } else { "error" },
            "preload",
            bytes,
            &[],
        );
    }
}
#[derive(Default)]
pub(crate) struct Transition {
    last: Option<(String, String)>,
}
impl Transition {
    pub(crate) const fn new() -> Self {
        Self { last: None }
    }
    fn update(&mut self, identity: &str, error: Option<&str>) -> Option<(bool, String)> {
        if let Some(error) = error {
            if identity.len() > 1024 || error.len() > 4096 {
                // Never collapse distinct long failures on a shared prefix.
                self.last = None;
                return Some((false, error.chars().take(4096).collect()));
            }
        }
        let next = error.map(|s| (identity.into(), s.into()));
        if next == self.last {
            return None;
        }
        let message = next
            .as_ref()
            .map(|v| v.1.clone())
            .unwrap_or_else(|| "operation recovered".into());
        let recovering = next.is_none();
        self.last = next;
        Some((recovering, message))
    }
    pub(crate) fn observe_optional<T>(
        &mut self,
        component: &str,
        identity: &str,
        result: &crate::Result<Option<T>>,
    ) {
        if matches!(result, Ok(None)) {
            self.pending(component, identity, "controller observation pending");
        } else {
            self.observe(component, identity, result);
        }
    }
    pub(crate) fn pending(&mut self, component: &str, identity: &str, message: &str) {
        if self.update(identity, Some(message)).is_some() {
            emit("debug", component, message, &[("identity", identity)]);
        }
    }
    pub(crate) fn observe<T>(
        &mut self,
        component: &str,
        identity: &str,
        result: &crate::Result<T>,
    ) {
        if let Some((recovering, message)) =
            self.update(identity, result.as_ref().err().map(String::as_str))
        {
            emit(
                if recovering { "debug" } else { "error" },
                component,
                &message,
                &[("identity", identity)],
            );
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_schema_and_escaping() {
        let bytes = record("error", "controller", "quoted \" \n", &[("reason", "a\nb")]);
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["schemaVersion"], 1);
        assert_eq!(v["fields"]["reason"], "a\nb");
        assert!(v["timestamp"].as_str().unwrap().ends_with('Z'));
        assert_eq!(v.as_object().unwrap().len(), 8);
    }
    #[test]
    fn calendar() {
        assert_eq!(timestamp(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(timestamp(1709251200, 123), "2024-03-01T00:00:00.123Z");
    }

    #[test]
    fn failures_with_same_long_prefix_remain_distinct() {
        let mut t = Transition::default();
        let a = format!("{}first", "x".repeat(600));
        let b = format!("{}second", "x".repeat(600));
        assert!(t.update("owner", Some(&a)).is_some());
        assert!(t.update("owner", Some(&b)).is_some());
        assert!(t.update("owner", Some(&b)).is_none());
    }

    #[test]
    fn changes_only() {
        let mut t = Transition::default();
        assert!(t.update("a", None).is_none());
        assert!(t.update("a", Some("failed")).is_some());
        for _ in 0..100 {
            assert!(t.update("a", Some("failed")).is_none());
        }
        assert!(t.update("b", Some("failed")).is_some());
        assert_eq!(
            t.update("b", None),
            Some((true, "operation recovered".into()))
        );
        assert!(t.update("b", None).is_none());
    }
}
