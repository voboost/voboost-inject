// agent_state.rs — agent state-pipe route (typed `W|` records).
//
// The daemon is the only state writer. Every accepted value is written to the
// trusted root store and can be read only by the source-owning agent over the
// bounded request/reply pipe. The app has no state mirror.

use std::collections::HashMap;
#[cfg(test)]
use std::fs;
use std::path::Path;

use serde_json::Value;

use crate::config;
use crate::log;
#[cfg(test)]
pub(crate) use crate::state::open_directory as open_state_directory;
#[cfg(test)]
use crate::state::valid_storage_key;
#[cfg(test)]
use crate::state::write as write_state_bytes;
use crate::state::{
    read as read_owned_state, read_controller as read_controller_state, render_value, sanitize_key,
    sanitize_source, storage_key, write_controller as write_controller_state, ReadOutcome,
};

/// Route one `W|<ts_ms>|<source>|<key>|<value>` record.
///
/// A record counts as routed only after its root store write succeeds.
pub fn route_state(rest: &str, ctx: &crate::agent_log::EndpointContext) -> Option<usize> {
    route_state_from(Path::new(config::STATE_DIR), rest, ctx)
}

fn route_state_from(
    root: &Path,
    rest: &str,
    ctx: &crate::agent_log::EndpointContext,
) -> Option<usize> {
    let mut parts = rest.splitn(4, '|');
    let _ts_ms: u64 = parts.next()?.parse().ok()?;
    let source = sanitize_source(parts.next()?)?;
    // Capability check: the endpoint may only persist state under an agent
    // id resident on it (docs/developer/agents-runtime); spoofed sources fail closed.
    let key = sanitize_key(parts.next()?)?;
    let value = parts.next().unwrap_or("");
    if source == "launcher" && crate::launcher_config::reserved(&key) {
        return crate::launcher_config::publish(&key, value, ctx).then_some(1);
    }
    let scalar = coerce_json_value(value);
    if !ctx.owns_state(&source, &key, Some(&scalar)) {
        log::debug(
            "agent-state",
            &format!(
                "write rejected source={source} pid={} reason=endpoint-ownership",
                ctx.pid
            ),
        );
        return None;
    }
    let bytes = render_value(&scalar);
    if bytes.len() > config::MAX_AGENT_STATE_BYTES {
        return None;
    }

    let storage_key = storage_key(&source, &key)?;
    let outcome = write_controller_state(root, &storage_key, &bytes);
    match outcome {
        Ok(()) => {
            log::info(
                "agent-state",
                &format!(
                    "root store committed source={source} key={key} bytes={}",
                    bytes.len()
                ),
            );
            observe_write_readback(root, &source, &key, &scalar, ctx);
            if scalar.is_boolean() || scalar.is_number() {
                log::debug(
                    "agent-state",
                    &format!("confirmed source={source} key={key} value={scalar}"),
                );
            }
            Some(1)
        }
        Err(error) => {
            observe_vehicle_state(
                &source,
                &key,
                "write-readback",
                StateObservation::Unavailable,
                None,
                ctx,
            );
            log::err(
                "agent-state",
                &format!("root store write {key}.json failed: {error}"),
            );
            None
        }
    }
}

/// Route one `R|<request_id>|<source>|<key>` read request and write exactly
/// one bounded reply to the daemon-owned reply pipe. Every failure is encoded
/// without including the stored value, so callers fail closed.
pub fn route_read(
    rest: &str,
    reply_fd: i32,
    ctx: &crate::agent_log::EndpointContext,
) -> Option<usize> {
    route_read_from(Path::new(config::STATE_DIR), rest, reply_fd, ctx)
}

/// Narrow conditional clear; comparison and commit execute as one owner command.
pub fn route_clear(
    rest: &str,
    reply_fd: i32,
    ctx: &crate::agent_log::EndpointContext,
) -> Option<usize> {
    route_clear_from(Path::new(config::STATE_DIR), rest, reply_fd, ctx)
}

fn route_clear_from(
    root: &Path,
    rest: &str,
    reply_fd: i32,
    ctx: &crate::agent_log::EndpointContext,
) -> Option<usize> {
    let mut parts = rest.splitn(4, '|');
    let request_id: u64 = parts.next()?.parse().ok()?;
    let source = parts.next()?;
    let key = parts.next()?;
    let expected = parts.next()?;
    if source != "media-apps"
        || key != "media-selected-package"
        || expected.is_empty()
        || expected.len() > 255
        || !expected
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
        || !ctx.owns_state(source, key, Some(&Value::String(String::new())))
    {
        return None;
    }
    let outcome = crate::state::clear_controller_if(root, source, key, expected);
    let response = match outcome {
        Ok(cleared) => format!("R|{request_id}|ok|{cleared}\n"),
        Err(_) => format!("R|{request_id}|error|\n"),
    };
    crate::downlink::enqueue_frame(reply_fd, response.as_bytes()).then_some(1)
}

fn route_read_from(
    root_path: &Path,
    rest: &str,
    reply_fd: i32,
    ctx: &crate::agent_log::EndpointContext,
) -> Option<usize> {
    let mut parts = rest.splitn(3, '|');
    let request_id: u64 = parts.next()?.parse().ok()?;
    let source = sanitize_source(parts.next()?)?;
    // Capability check: an endpoint may only read state owned by its own
    // resident agents (docs/developer/agents-runtime).
    let key = sanitize_key(parts.next()?)?;
    if !ctx.owns_state(&source, &key, None) {
        log::debug(
            "agent-state",
            &format!("read rejected request={request_id} source={source} pid={} reason=endpoint-ownership", ctx.pid),
        );
        return None;
    }
    if crate::emulator_diagnostic::drop_state_reply(&source, &key, ctx, request_id) {
        return Some(1);
    }

    let outcome = if source == "launcher" && crate::launcher_config::reserved(&key) {
        crate::launcher_config::read(&key, ctx)
            .map(ReadOutcome::Value)
            .unwrap_or(ReadOutcome::Missing)
    } else {
        read_controller_state(root_path, &source, &key)
    };
    observe_vehicle_state(
        &source,
        &key,
        "read",
        state_observation(&outcome),
        Some(request_id),
        ctx,
    );
    let status = match &outcome {
        ReadOutcome::Value(_) => "value",
        ReadOutcome::Missing => "missing",
        ReadOutcome::Error => "error",
    };
    log::debug(
        "agent-state",
        &format!(
            "read request={request_id} source={source} key={key} pid={} outcome={status}",
            ctx.pid
        ),
    );
    let reply = render_read_response(request_id, outcome);
    if reply.len() > config::MAX_AGENT_STATE_RESPONSE_BYTES {
        return None;
    }
    // Rides the same serialized downlink writer as D frames so replies are
    // never interleaved mid-frame and short writes are resumed.
    if !crate::downlink::enqueue_frame(reply_fd, &reply) {
        log::err(
            "agent-state",
            &format!("state read reply write failed request={request_id}"),
        );
        return None;
    }
    Some(1)
}

#[cfg(test)]
pub(crate) fn route_read_fixture(
    root: &Path,
    rest: &str,
    reply_fd: i32,
    ctx: &crate::agent_log::EndpointContext,
) -> Option<usize> {
    route_read_from(root, rest, reply_fd, ctx)
}

fn coerce_json_value(raw: &str) -> Value {
    if let Ok(n) = raw.parse::<i64>() {
        return Value::from(n);
    }
    if let Ok(f) = raw.parse::<f64>() {
        if f.is_finite() {
            return Value::from(f);
        }
    }
    match raw {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        _ => Value::String(raw.to_string()),
    }
}

fn render_read_response(request_id: u64, outcome: ReadOutcome) -> Vec<u8> {
    let (status, value) = match outcome {
        ReadOutcome::Value(Value::String(value)) => ("ok", value),
        ReadOutcome::Value(value) => ("ok", value.to_string()),
        ReadOutcome::Missing => ("missing", String::new()),
        ReadOutcome::Error => ("error", String::new()),
    };
    format!("R|{request_id}|{status}|{value}\n").into_bytes()
}

/// Closed diagnostic projection of secure persistent reads, independent of agent reports.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "outcome", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum PersistentFlag {
    Value { value: bool },
    Missing,
    Unavailable,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PersistentVehicleState {
    boot_id: Option<String>,
    observed_at_boot_ms: Option<u64>,
    forced_ev: PersistentFlag,
    pedestrian_warning: PersistentFlag,
}

pub(crate) fn persistent_vehicle_state() -> PersistentVehicleState {
    persistent_vehicle_state_from(Path::new(config::STATE_DIR))
}

pub(crate) fn persistent_vehicle_state_from(root: &Path) -> PersistentVehicleState {
    let observe = |source, key| match read_owned_state(root, source, key) {
        ReadOutcome::Value(Value::Bool(value)) => PersistentFlag::Value { value },
        ReadOutcome::Missing => PersistentFlag::Missing,
        _ => PersistentFlag::Unavailable,
    };
    let forced_ev = observe("vehicle-drive-forced-ev", "forced-ev-armed");
    let pedestrian_warning = observe(
        "vehicle-drive-pedestrian-warning",
        "pedestrian-warning-armed",
    );
    PersistentVehicleState {
        boot_id: crate::operation_contract::current_boot_id().ok(),
        observed_at_boot_ms: boot_elapsed_ms(),
        forced_ev,
        pedestrian_warning,
    }
}

// Linux /proc/uptime floors boot time to centiseconds. Publish the same
// precision so a subsequent diagnostic sample cannot look earlier merely
// because it has lower precision. Freshness consumers must allow for the
// current sample's unknown trailing 0..9 integer milliseconds.
// Linux /proc/uptime includes suspended time, as does CLOCK_BOOTTIME.
// Read the kernel clock directly: the daemon's SELinux domain need not be able
// to open proc uptime. Do not substitute MONOTONIC on Android (it excludes suspend).
#[cfg(any(target_os = "linux", target_os = "android"))]
const BOOT_CLOCK: libc::clockid_t = libc::CLOCK_BOOTTIME;
// Host-only portability for macOS checks; this is never compiled for Android.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const BOOT_CLOCK: libc::clockid_t = libc::CLOCK_MONOTONIC;

pub(crate) fn boot_elapsed_ms() -> Option<u64> {
    boot_elapsed_ms_with(|clock, time| unsafe { libc::clock_gettime(clock, time) })
}

pub(crate) fn boot_elapsed_ms_with(
    read_clock: impl FnOnce(libc::clockid_t, &mut libc::timespec) -> i32,
) -> Option<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if read_clock(BOOT_CLOCK, &mut time) != 0
        || time.tv_sec < 0
        || !(0..1_000_000_000).contains(&time.tv_nsec)
    {
        return None;
    }
    u64::try_from(time.tv_sec)
        .ok()?
        .checked_mul(1000)?
        .checked_add(u64::try_from(time.tv_nsec).ok()? / 10_000_000 * 10)
}

#[derive(Clone, Copy)]
enum StateObservation {
    Value(bool),
    Missing,
    Unavailable,
}

fn state_observation(outcome: &ReadOutcome) -> StateObservation {
    match outcome {
        ReadOutcome::Value(Value::Bool(value)) => StateObservation::Value(*value),
        ReadOutcome::Missing => StateObservation::Missing,
        _ => StateObservation::Unavailable,
    }
}

fn vehicle_state_pair(source: &str, key: &str) -> bool {
    matches!(
        (source, key),
        ("vehicle-drive-forced-ev", "forced-ev-armed")
            | (
                "vehicle-drive-pedestrian-warning",
                "pedestrian-warning-armed"
            )
    )
}

fn observe_write_readback(
    root: &Path,
    source: &str,
    key: &str,
    requested: &Value,
    ctx: &crate::agent_log::EndpointContext,
) {
    if !vehicle_state_pair(source, key) {
        return;
    }
    let observation = match requested {
        Value::Bool(expected) => match read_owned_state(root, source, key) {
            ReadOutcome::Value(Value::Bool(actual)) if actual == *expected => {
                StateObservation::Value(actual)
            }
            ReadOutcome::Missing => StateObservation::Missing,
            _ => StateObservation::Unavailable,
        },
        _ => StateObservation::Unavailable,
    };
    observe_vehicle_state(source, key, "write-readback", observation, None, ctx);
}

fn observe_vehicle_state(
    source: &str,
    key: &str,
    operation: &str,
    observation: StateObservation,
    request_id: Option<u64>,
    ctx: &crate::agent_log::EndpointContext,
) {
    if !vehicle_state_pair(source, key) {
        return;
    }
    let outcome = match observation {
        StateObservation::Value(_) => "value",
        StateObservation::Missing => "missing",
        StateObservation::Unavailable => "unavailable",
    };
    let mut fields = HashMap::from([
        ("agentId".into(), source.to_string()),
        ("key".into(), key.to_string()),
        ("operation".into(), operation.to_string()),
        ("outcome".into(), outcome.to_string()),
        ("process".into(), ctx.process.clone()),
        ("targetPid".into(), ctx.pid.to_string()),
        ("endpointEpoch".into(), ctx.endpoint_epoch.to_string()),
    ]);
    if let StateObservation::Value(value) = observation {
        fields.insert("value".into(), value.to_string());
    }
    if !ctx.resident_generation_id.is_empty() && !ctx.resident_catalog_sha256.is_empty() {
        fields.insert("generationId".into(), ctx.resident_generation_id.clone());
        fields.insert("catalogSha256".into(), ctx.resident_catalog_sha256.clone());
    }
    if let Some(starttime) = ctx.target_starttime {
        fields.insert("targetStarttime".into(), starttime.to_string());
    }
    if let Some(generation) = ctx.document_generation {
        fields.insert("documentGeneration".into(), generation.to_string());
    }
    if let Ok(boot_id) = crate::operation_contract::current_boot_id() {
        fields.insert("bootId".into(), boot_id);
    }
    if let Some(request_id) = request_id {
        fields.insert("requestId".into(), request_id.to_string());
    }
    log::info_fields("agent-state", "vehicle-state-observed", fields);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use tempfile::tempdir;

    #[test]
    fn projection_clock_uses_kernel_boot_domain_and_centisecond_floor() {
        assert_eq!(
            boot_elapsed_ms_with(|clock, time| {
                assert_eq!(clock, BOOT_CLOCK);
                #[cfg(any(target_os = "linux", target_os = "android"))]
                assert_eq!(clock, libc::CLOCK_BOOTTIME);
                time.tv_sec = 123;
                time.tv_nsec = 456_999_999;
                0
            }),
            Some(123450)
        );
        assert_eq!(boot_elapsed_ms_with(|_, _| -1), None);
        assert_eq!(
            boot_elapsed_ms_with(|_, time| {
                time.tv_sec = -1;
                0
            }),
            None
        );
        assert_eq!(
            boot_elapsed_ms_with(|_, time| {
                time.tv_nsec = 1_000_000_000;
                0
            }),
            None
        );
    }

    #[test]
    fn projection_uses_real_kernel_clock_without_proc_uptime_dependency() {
        // Exercise the actual production syscall, not a prefilled timestamp.
        let before = boot_elapsed_ms().expect("kernel boot clock");
        let root = tempdir().unwrap();
        let projection = persistent_vehicle_state_from(root.path());
        let after = boot_elapsed_ms().expect("kernel boot clock");
        let observed = projection
            .observed_at_boot_ms
            .expect("projection timestamp");
        assert!(before <= observed && observed <= after);
        // Proc access is deliberately absent from this production path.
        let source = include_str!("agent_state.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        assert!(!production.contains("read_to_string(\"/proc/uptime\")"));
    }

    fn make_dir(path: &Path) {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn persistent_projection_reads_fixed_booleans_and_preserves_missing_unavailable() {
        let root = tempdir().unwrap();
        let state = root.path().join("state");
        write_state_bytes(&state, "vehicle-drive-forced-ev_forced-ev-armed", b"true\n").unwrap();
        write_state_bytes(
            &state,
            "vehicle-drive-pedestrian-warning_pedestrian-warning-armed",
            b"false\n",
        )
        .unwrap();
        let value = serde_json::to_value(persistent_vehicle_state_from(&state)).unwrap();
        assert_eq!(
            value["forcedEv"],
            serde_json::json!({"outcome":"value","value":true})
        );
        assert_eq!(
            value["pedestrianWarning"],
            serde_json::json!({"outcome":"value","value":false})
        );
        fs::remove_file(state.join("vehicle-drive-forced-ev_forced-ev-armed.json")).unwrap();
        fs::write(
            state.join("vehicle-drive-pedestrian-warning_pedestrian-warning-armed.json"),
            b"\"true\"\n",
        )
        .unwrap();
        let value = serde_json::to_value(persistent_vehicle_state_from(&state)).unwrap();
        assert_eq!(value["forcedEv"], serde_json::json!({"outcome":"missing"}));
        assert_eq!(
            value["pedestrianWarning"],
            serde_json::json!({"outcome":"unavailable"})
        );
        let pw = state.join("vehicle-drive-pedestrian-warning_pedestrian-warning-armed.json");
        for invalid in [b"{broken".as_slice(), b"null\n", b"[]\n"] {
            fs::write(&pw, invalid).unwrap();
            let value = serde_json::to_value(persistent_vehicle_state_from(&state)).unwrap();
            assert_eq!(
                value["pedestrianWarning"],
                serde_json::json!({"outcome":"unavailable"})
            );
        }
        fs::write(&pw, b"false\n").unwrap();
        fs::set_permissions(&pw, fs::Permissions::from_mode(0o644)).unwrap();
        let value = serde_json::to_value(persistent_vehicle_state_from(&state)).unwrap();
        assert_eq!(
            value["pedestrianWarning"],
            serde_json::json!({"outcome":"unavailable"})
        );
        let target = root.path().join("target");
        fs::write(&target, b"true\n").unwrap();
        symlink(
            &target,
            state.join("vehicle-drive-forced-ev_forced-ev-armed.json"),
        )
        .unwrap();
        let value = serde_json::to_value(persistent_vehicle_state_from(&state)).unwrap();
        assert_eq!(
            value["forcedEv"],
            serde_json::json!({"outcome":"unavailable"})
        );
    }

    #[test]
    fn coerce_int_float_bool_string() {
        assert_eq!(coerce_json_value("5"), Value::from(5i64));
        assert_eq!(coerce_json_value("-3"), Value::from(-3i64));
        assert_eq!(coerce_json_value("1.5"), Value::from(1.5));
        assert_eq!(coerce_json_value("true"), Value::Bool(true));
        assert_eq!(coerce_json_value("false"), Value::Bool(false));
        assert_eq!(coerce_json_value("on"), Value::String("on".into()));
        assert_eq!(coerce_json_value(""), Value::String("".into()));
    }

    #[test]
    fn coerce_rejects_non_finite_float() {
        assert_eq!(coerce_json_value("inf"), Value::String("inf".into()));
        assert_eq!(coerce_json_value("NaN"), Value::String("NaN".into()));
    }

    #[test]
    fn sanitize_rejects_unsafe_or_oversized_keys() {
        assert_eq!(
            sanitize_key("ivi-soc-modeset").as_deref(),
            Some("ivi-soc-modeset")
        );
        assert!(sanitize_key("../etc/passwd").is_none());
        assert!(sanitize_key("a/b").is_none());
        assert!(sanitize_key("").is_none());
        assert!(sanitize_key(&"a".repeat(config::MAX_AGENT_STATE_KEY_BYTES + 1)).is_none());
    }

    #[test]
    fn sanitize_rejects_unsafe_or_oversized_sources() {
        assert_eq!(sanitize_source("media-apps").as_deref(), Some("media-apps"));
        assert!(sanitize_source("media/apps").is_none());
        assert!(sanitize_source("").is_none());
        assert!(sanitize_source(&"a".repeat(config::MAX_AGENT_STATE_SOURCE_BYTES + 1)).is_none());
    }

    #[test]
    fn catalog_source_and_key_maxima_fit_one_unambiguous_storage_filename() {
        let source = format!("a{}", "b".repeat(config::MAX_AGENT_STATE_SOURCE_BYTES - 1));
        let key = "k".repeat(config::MAX_AGENT_STATE_KEY_BYTES);
        let storage = storage_key(&source, &key).unwrap();
        assert_eq!(storage.len(), config::MAX_AGENT_STATE_STORAGE_KEY_BYTES);
        assert_eq!(
            format!("{storage}.json").len(),
            config::MAX_AGENT_STATE_FILENAME_BYTES
        );
        assert!(valid_storage_key(&storage));
        assert_ne!(storage_key("a-b", "c_d"), storage_key("a", "b_c_d"));
        assert!(storage_key(&format!("a{source}"), &key).is_none());
        assert!(storage_key(&source, &format!("k{key}")).is_none());
    }

    fn endpoint_ctx() -> crate::agent_log::EndpointContext {
        crate::agent_log::EndpointContext {
            pid: 42,
            process: "com.qinggan.app.setting".to_string(),
            endpoint_epoch: 1,
            resident_agents: std::collections::HashSet::from([
                "forced-ev".to_string(),
                "media-apps".to_string(),
            ]),
            agents: std::collections::HashSet::from([
                "forced-ev".to_string(),
                "media-apps".to_string(),
            ]),
            ..Default::default()
        }
    }

    #[test]
    fn conditional_clear_rejects_malformed_and_unowned_records_without_writes() {
        let root = tempfile::Builder::new()
            .prefix(".media-clear-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap();
        let store = root.path().join("state");
        for record in [
            "bad|media-apps|media-selected-package|old.app",
            "1|other|media-selected-package|old.app",
            "1|media-apps|wrong-key|old.app",
            "1|media-apps|media-selected-package|",
            "1|media-apps|media-selected-package|old.app|extra",
            "1|media-apps|media-selected-package|old app",
        ] {
            assert_eq!(route_clear_from(&store, record, -1, &endpoint_ctx()), None);
            assert!(!store.exists());
        }
        let context = crate::agent_log::EndpointContext::default();
        assert_eq!(
            route_clear_from(
                &store,
                "1|media-apps|media-selected-package|old.app",
                -1,
                &context
            ),
            None
        );
        assert!(!store.exists());
    }

    #[test]
    fn conditional_clear_replies_with_exact_commit_status_and_preserves_newer_selection() {
        let root = tempfile::Builder::new()
            .prefix(".media-clear-reply-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap();
        let store = root.path().join("state");
        let reply = |request: &str| {
            let mut fds = [-1, -1];
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            assert_eq!(
                route_clear_from(&store, request, fds[1], &endpoint_ctx()),
                Some(1)
            );
            assert!(crate::downlink::flush(fds[1]));
            crate::downlink::forget_fd(fds[1]);
            close_fd(fds[1]);
            let mut bytes = vec![0; 256];
            let count = unsafe { libc::read(fds[0], bytes.as_mut_ptr().cast(), bytes.len()) };
            close_fd(fds[0]);
            assert!(count > 0);
            bytes.truncate(count as usize);
            bytes
        };
        assert_eq!(
            reply("81|media-apps|media-selected-package|old.app"),
            b"R|81|ok|false\n"
        );
        write_state_bytes(
            &store,
            "media-apps_media-selected-package",
            b"\"old.app\"\n",
        )
        .unwrap();
        assert_eq!(
            reply("82|media-apps|media-selected-package|old.app"),
            b"R|82|ok|true\n"
        );
        assert_eq!(
            read_controller_state(&store, "media-apps", "media-selected-package"),
            ReadOutcome::Value(Value::String(String::new()))
        );
        write_state_bytes(
            &store,
            "media-apps_media-selected-package",
            b"\"new.app\"\n",
        )
        .unwrap();
        assert_eq!(
            reply("83|media-apps|media-selected-package|old.app"),
            b"R|83|ok|false\n"
        );
        assert_eq!(
            read_controller_state(&store, "media-apps", "media-selected-package"),
            ReadOutcome::Value(Value::String("new.app".into()))
        );
    }

    fn vehicle_pairs() -> [(&'static str, &'static str); 2] {
        [
            ("vehicle-drive-forced-ev", "forced-ev-armed"),
            (
                "vehicle-drive-pedestrian-warning",
                "pedestrian-warning-armed",
            ),
        ]
    }

    fn vehicle_context() -> crate::agent_log::EndpointContext {
        crate::agent_log::EndpointContext {
            pid: 4242,
            process: "com.qinggan.canbus.service".into(),
            endpoint_epoch: 77,
            log_generation: None,
            target_starttime: Some(987_654_321),
            document_generation: Some(1_777_777_777_777_777_779),
            resident_agents: vehicle_pairs().map(|(source, _)| source.to_string()).into(),
            resident_generation_id: "resident-generation".into(),
            resident_catalog_sha256: "resident-catalog".into(),
            active_generation_id: "other-active-generation".into(),
            active_catalog_sha256: "other-active-catalog".into(),
            ..Default::default()
        }
    }

    fn vehicle_records(path: &Path) -> Vec<crate::canonical_log::CanonicalRecord> {
        crate::canonical_log::CanonicalLog::open(path)
            .unwrap()
            .query(&crate::canonical_log::Query {
                after_sequence: 0,
                limit: 200,
                levels: vec![],
                kinds: vec![],
                agent_ids: vec![],
                search: Some("vehicle-state-observed".into()),
                from_epoch_millis: 0,
                to_epoch_millis: u64::MAX,
            })
            .unwrap()
            .records
    }

    fn read_vehicle_reply(root: &Path, source: &str, key: &str, request_id: u64) -> Vec<u8> {
        let mut fds = [-1, -1];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        assert_eq!(
            route_read_from(
                root,
                &format!("{request_id}|{source}|{key}"),
                fds[1],
                &vehicle_context(),
            ),
            Some(1)
        );
        assert!(crate::downlink::flush(fds[1]));
        crate::downlink::forget_fd(fds[1]);
        close_fd(fds[1]);
        let mut reply = vec![0; 256];
        let count = unsafe { libc::read(fds[0], reply.as_mut_ptr().cast(), reply.len()) };
        close_fd(fds[0]);
        assert!(count > 0);
        reply.truncate(count as usize);
        reply
    }

    #[test]
    fn vehicle_state_read_logs_strict_booleans_and_missing() {
        let root = tempdir().unwrap();
        let store = root.path().join("state");
        let logs = root.path().join("logs");
        crate::canonical_log::with_test_log(&logs, || {
            for (source, key) in vehicle_pairs() {
                assert_eq!(
                    read_vehicle_reply(&store, source, key, u64::MAX),
                    format!("R|{}|missing|\n", u64::MAX).as_bytes()
                );
                for value in [true, false] {
                    write_state_bytes(
                        &store,
                        &storage_key(source, key).unwrap(),
                        &render_value(&Value::Bool(value)),
                    )
                    .unwrap();
                    assert_eq!(
                        read_vehicle_reply(&store, source, key, u64::MAX),
                        format!("R|{}|ok|{value}\n", u64::MAX).as_bytes()
                    );
                }
            }
            let (source, key) = vehicle_pairs()[0];
            let mut context = vehicle_context();
            context.target_starttime = None;
            context.document_generation = None;
            context.resident_generation_id.clear();
            // A failed response delivery must not change the actual root-read
            // observation, and active identity must not fill a resident gap.
            assert_eq!(
                route_read_from(&store, &format!("9|{source}|{key}"), -1, &context),
                None
            );
            context.resident_generation_id = "resident-generation".into();
            context.resident_catalog_sha256.clear();
            assert_eq!(
                route_read_from(&store, &format!("10|{source}|{key}"), -1, &context),
                None
            );
        });
        let records = vehicle_records(&logs);
        assert_eq!(records.len(), 8, "every actual read needs root-owned proof");
        for ((source, key), group) in vehicle_pairs()
            .into_iter()
            .zip(records[..6].as_chunks::<3>().0)
        {
            for (record, outcome) in group.iter().zip(["missing", "value", "value"]) {
                assert_eq!(record.source.kind, "daemon");
                assert!(record.source.id.is_none());
                assert_eq!(record.level, crate::canonical_log::Level::Info);
                assert_eq!(record.component, "agent-state");
                assert_eq!(record.message, "vehicle-state-observed");
                assert_eq!(record.fields["agentId"], source);
                assert_eq!(record.fields["key"], key);
                assert_eq!(record.fields["operation"], "read");
                assert_eq!(record.fields["outcome"], outcome);
                assert_eq!(record.fields["requestId"], u64::MAX.to_string());
                assert_eq!(record.fields["targetPid"], "4242");
                assert_eq!(record.fields["endpointEpoch"], "77");
                assert_eq!(record.fields["process"], "com.qinggan.canbus.service");
                assert_eq!(record.fields["targetStarttime"], "987654321");
                assert_eq!(record.fields["documentGeneration"], "1777777777777777779");
                assert_eq!(record.fields["generationId"], "resident-generation");
                assert_eq!(record.fields["catalogSha256"], "resident-catalog");
                let mut expected = std::collections::HashSet::from([
                    "agentId",
                    "key",
                    "operation",
                    "outcome",
                    "requestId",
                    "process",
                    "targetPid",
                    "endpointEpoch",
                    "generationId",
                    "catalogSha256",
                    "targetStarttime",
                    "documentGeneration",
                ]);
                if outcome == "value" {
                    expected.insert("value");
                }
                if let Ok(boot_id) = crate::operation_contract::current_boot_id() {
                    expected.insert("bootId");
                    assert_eq!(record.fields["bootId"], boot_id);
                }
                assert_eq!(
                    record
                        .fields
                        .keys()
                        .map(String::as_str)
                        .collect::<std::collections::HashSet<_>>(),
                    expected
                );
                assert!(
                    serde_json::to_vec(record).unwrap().len()
                        < crate::canonical_log::MAX_RECORD_BYTES
                );
            }
            assert!(!group[0].fields.contains_key("value"));
            assert_eq!(group[1].fields["value"], "true");
            assert_eq!(group[2].fields["value"], "false");
        }
        for record in &records[6..] {
            assert_vehicle_outcome(
                record,
                vehicle_pairs()[0].0,
                vehicle_pairs()[0].1,
                "read",
                "value",
                Some("false"),
            );
            for name in [
                "generationId",
                "catalogSha256",
                "targetStarttime",
                "documentGeneration",
            ] {
                assert!(!record.fields.contains_key(name));
            }
        }
    }

    fn set_private_file(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn assert_vehicle_outcome(
        record: &crate::canonical_log::CanonicalRecord,
        source: &str,
        key: &str,
        operation: &str,
        outcome: &str,
        value: Option<&str>,
    ) {
        assert_eq!(record.source.kind, "daemon");
        assert!(record.source.id.is_none());
        assert_eq!(record.level, crate::canonical_log::Level::Info);
        assert_eq!(record.component, "agent-state");
        assert_eq!(record.message, "vehicle-state-observed");
        assert_eq!(record.fields["agentId"], source);
        assert_eq!(record.fields["key"], key);
        assert_eq!(record.fields["operation"], operation);
        assert_eq!(record.fields["outcome"], outcome);
        assert_eq!(record.fields.get("value").map(String::as_str), value);
        assert!(!record.fields.contains_key("path"));
        if operation == "write-readback" {
            assert!(!record.fields.contains_key("requestId"));
        }
    }

    #[test]
    fn vehicle_state_read_rejects_nonboolean_and_untrusted_store() {
        let root = tempdir().unwrap();
        let logs = root.path().join("logs");
        let cases: [(&[u8], &str); 10] = [
            (b"\"true\"\n", "ok|true"),
            (b"42\n", "ok|42"),
            (b"null\n", "error|"),
            (b"{}\n", "error|"),
            (b"[true]\n", "error|"),
            (b"true trailing\n", "error|"),
            (b"true\n", "error|"),
            (b"true\n", "error|"),
            (b"true\n", "error|"),
            (b"true\n", "error|"),
        ];
        crate::canonical_log::with_test_log(&logs, || {
            for (pair_index, (source, key)) in vehicle_pairs().into_iter().enumerate() {
                for (case_index, (bytes, response)) in cases.iter().enumerate() {
                    let store = root.path().join(format!("state-{pair_index}-{case_index}"));
                    fs::create_dir(&store).unwrap();
                    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
                    let leaf = store.join(format!("{}.json", storage_key(source, key).unwrap()));
                    match case_index {
                        6 => {
                            let target = root.path().join(format!("symlink-{pair_index}"));
                            set_private_file(&target, bytes);
                            symlink(&target, &leaf).unwrap();
                        }
                        7 => {
                            let target = root.path().join(format!("hardlink-{pair_index}"));
                            set_private_file(&target, bytes);
                            fs::hard_link(&target, &leaf).unwrap();
                        }
                        8 => {
                            set_private_file(&leaf, bytes);
                            fs::set_permissions(&leaf, fs::Permissions::from_mode(0o644)).unwrap();
                        }
                        9 => {
                            set_private_file(&leaf, bytes);
                            fs::set_permissions(&store, fs::Permissions::from_mode(0o777)).unwrap();
                        }
                        _ => set_private_file(&leaf, bytes),
                    }
                    let request_id = (pair_index * cases.len() + case_index) as u64;
                    assert_eq!(
                        read_vehicle_reply(&store, source, key, request_id),
                        format!("R|{request_id}|{response}\n").as_bytes(),
                        "pair={pair_index} case={case_index}",
                    );
                }
            }
        });
        let records = vehicle_records(&logs);
        assert_eq!(records.len(), 2 * cases.len());
        for ((source, key), group) in vehicle_pairs()
            .into_iter()
            .zip(records.chunks_exact(cases.len()))
        {
            for record in group {
                assert_vehicle_outcome(record, source, key, "read", "unavailable", None);
            }
        }
    }

    #[test]
    fn vehicle_state_write_logs_only_durable_matching_readback() {
        let root = tempdir().unwrap();
        let store = root.path().join("state");
        let logs = root.path().join("logs");
        let context = vehicle_context();
        crate::canonical_log::with_test_log(&logs, || {
            for (source, key) in vehicle_pairs() {
                for value in [true, false] {
                    assert_eq!(
                        route_state_from(&store, &format!("1|{source}|{key}|{value}"), &context),
                        Some(1),
                    );
                    assert_eq!(
                        read_owned_state(&store, source, key),
                        ReadOutcome::Value(Value::Bool(value)),
                    );
                    let leaf = store.join(format!("{}.json", storage_key(source, key).unwrap()));
                    assert_eq!(fs::read(&leaf).unwrap(), format!("{value}\n").as_bytes());
                    assert_eq!(
                        fs::metadata(&leaf).unwrap().permissions().mode() & 0o777,
                        0o600
                    );
                    assert!(!store
                        .join(format!(".{}.json.tmp", storage_key(source, key).unwrap()))
                        .exists());
                }
                // The same production readback helper must observe current disk bytes,
                // rather than the earlier requested value or a routing cache.
                let leaf = store.join(format!("{}.json", storage_key(source, key).unwrap()));
                set_private_file(&leaf, b"false\n");
                observe_write_readback(&store, source, key, &Value::Bool(true), &context);
                set_private_file(&leaf, b"\"true\"\n");
                observe_write_readback(&store, source, key, &Value::Bool(true), &context);
                fs::remove_file(&leaf).unwrap();
                observe_write_readback(&store, source, key, &Value::Bool(true), &context);
                set_private_file(&leaf, b"true\n");
                fs::set_permissions(&leaf, fs::Permissions::from_mode(0o644)).unwrap();
                observe_write_readback(&store, source, key, &Value::Bool(true), &context);
            }
        });
        assert_eq!(
            fs::metadata(&store).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let records = vehicle_records(&logs);
        assert_eq!(records.len(), 12);
        for ((source, key), group) in vehicle_pairs().into_iter().zip(records.as_chunks::<6>().0) {
            for (record, (outcome, value)) in group.iter().zip([
                ("value", Some("true")),
                ("value", Some("false")),
                ("unavailable", None),
                ("unavailable", None),
                ("missing", None),
                ("unavailable", None),
            ]) {
                assert_vehicle_outcome(record, source, key, "write-readback", outcome, value);
            }
        }
    }

    #[test]
    fn vehicle_state_write_failure_and_other_keys_emit_no_success() {
        let root = tempdir().unwrap();
        let logs = root.path().join("logs");
        let store = root.path().join("state");
        let unsafe_store = root.path().join("unsafe-state");
        fs::create_dir(&unsafe_store).unwrap();
        fs::set_permissions(&unsafe_store, fs::Permissions::from_mode(0o777)).unwrap();
        let mut context = vehicle_context();
        context.resident_agents.insert("media-apps".into());
        crate::canonical_log::with_test_log(&logs, || {
            for (source, key) in vehicle_pairs() {
                assert_eq!(
                    route_state_from(&unsafe_store, &format!("1|{source}|{key}|true"), &context),
                    None
                );
                let prepare_store = root.path().join(format!("prepare-{source}"));
                fs::create_dir(&prepare_store).unwrap();
                fs::set_permissions(&prepare_store, fs::Permissions::from_mode(0o700)).unwrap();
                let victim = root.path().join(format!("victim-{source}"));
                set_private_file(&victim, b"unchanged");
                symlink(
                    &victim,
                    prepare_store.join(format!(".{}.json.tmp", storage_key(source, key).unwrap())),
                )
                .unwrap();
                assert_eq!(
                    route_state_from(&prepare_store, &format!("1|{source}|{key}|true"), &context),
                    None
                );
                assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
                let rename_store = root.path().join(format!("rename-{source}"));
                fs::create_dir(&rename_store).unwrap();
                fs::set_permissions(&rename_store, fs::Permissions::from_mode(0o700)).unwrap();
                fs::create_dir(
                    rename_store.join(format!("{}.json", storage_key(source, key).unwrap())),
                )
                .unwrap();
                assert_eq!(
                    route_state_from(&rename_store, &format!("1|{source}|{key}|true"), &context),
                    None
                );
                assert!(!rename_store
                    .join(format!(".{}.json.tmp", storage_key(source, key).unwrap()))
                    .exists());
                assert_eq!(
                    route_state_from(
                        &store,
                        &format!("2|{source}|{key}|true"),
                        &Default::default()
                    ),
                    None
                );
                assert_eq!(
                    route_read_from(
                        &store,
                        &format!("3|{source}|{key}"),
                        -1,
                        &Default::default()
                    ),
                    None
                );
                assert_eq!(
                    route_state_from(&store, &format!("4|{source}|{key}|on"), &context),
                    Some(1)
                );
                assert_eq!(
                    read_owned_state(&store, source, key),
                    ReadOutcome::Value(Value::String("on".into()))
                );
            }
            for record in [
                "5|vehicle-drive-forced-ev|pedestrian-warning-armed|true",
                "6|vehicle-drive-pedestrian-warning|forced-ev-armed|true",
                "7|vehicle-drive-forced-ev|other-key|true",
                "8|media-apps|forced-ev-armed|true",
            ] {
                assert_eq!(route_state_from(&store, record, &context), Some(1));
            }
            assert_eq!(
                route_read_from(&store, "9|vehicle-drive-forced-ev|other-key", -1, &context),
                None
            );
        });
        let records = vehicle_records(&logs);
        assert_eq!(
            records.len(),
            8,
            "only failed writes and nonboolean writes are diagnosed"
        );
        for ((source, key), group) in vehicle_pairs().into_iter().zip(records.as_chunks::<4>().0) {
            for record in group {
                assert_vehicle_outcome(record, source, key, "write-readback", "unavailable", None);
            }
        }
    }

    #[test]
    fn route_state_rejects_missing_key_bad_timestamp_and_unsafe_key() {
        assert_eq!(
            route_state("1723392000456|forced-ev||5", &endpoint_ctx()),
            None
        );
        assert_eq!(route_state("notatime|forced-ev|k|v", &endpoint_ctx()), None);
        assert_eq!(
            route_state("1723392000456|forced-ev|../key|5", &endpoint_ctx()),
            None
        );
    }

    #[test]
    fn route_state_rejects_oversized_rendered_scalar() {
        let value = "x".repeat(config::MAX_AGENT_STATE_BYTES);
        let record = format!("1723392000456|forced-ev|key|{value}");

        assert_eq!(route_state(&record, &endpoint_ctx()), None);
    }

    #[test]
    fn route_state_value_absorbs_pipes() {
        assert_eq!(
            route_state("1723392000456|forced-ev|charging|sport|42", &endpoint_ctx()),
            None
        );
    }

    #[test]
    fn render_value_emits_compact_with_newline() {
        assert_eq!(render_value(&Value::from(5)), b"5\n");
        assert_eq!(render_value(&Value::Bool(true)), b"true\n");
        assert_eq!(render_value(&Value::String("on".into())), b"\"on\"\n");
    }

    #[test]
    fn root_write_uses_source_prefixed_name_without_owner_file() {
        let root = tempdir().unwrap();
        let root_state = root.path().join("root-state");

        let result = write_state_bytes(&root_state, "forced-ev_ivi-soc-modeset", b"5\n");

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(
            fs::metadata(&root_state).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::read(root_state.join("forced-ev_ivi-soc-modeset.json")).unwrap(),
            b"5\n"
        );
        assert_eq!(
            fs::metadata(root_state.join("forced-ev_ivi-soc-modeset.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(!root_state.join("ivi-soc-modeset.owner").exists());
    }

    #[test]
    fn owner_is_stable_and_unauthorized_read_does_not_disclose_value() {
        let root = tempdir().unwrap();
        let root_state = root.path().join("root-state");
        let first = write_state_bytes(
            &root_state,
            "media-apps_media-selected-package",
            b"\"com.example.player\"\n",
        );
        assert!(first.is_ok());

        assert_eq!(
            read_owned_state(&root_state, "media-apps", "media-selected-package"),
            ReadOutcome::Value(Value::String("com.example.player".to_string()))
        );
        assert_eq!(
            read_owned_state(&root_state, "other-agent", "media-selected-package"),
            ReadOutcome::Missing
        );

        let takeover = write_state_bytes(
            &root_state,
            "other-agent_media-selected-package",
            b"\"com.attacker\"\n",
        );
        assert!(takeover.is_ok());
        assert_eq!(
            fs::read(root_state.join("media-apps_media-selected-package.json")).unwrap(),
            b"\"com.example.player\"\n"
        );
    }

    #[test]
    fn typed_read_reply_is_bounded_and_contains_only_owned_value() {
        let root = tempdir().unwrap();
        let root_state = root.path().join("root-state");
        let outcome = write_state_bytes(
            &root_state,
            "media-apps_media-selected-package",
            b"\"com.example.player\"\n",
        );
        assert!(outcome.is_ok());

        let response = render_read_response(
            17,
            read_owned_state(&root_state, "media-apps", "media-selected-package"),
        );
        assert_eq!(response, b"R|17|ok|com.example.player\n");
        assert!(response.len() <= config::MAX_AGENT_STATE_RESPONSE_BYTES);

        let denied = render_read_response(
            18,
            read_owned_state(&root_state, "other-agent", "media-selected-package"),
        );
        assert_eq!(denied, b"R|18|missing|\n");
        assert!(!String::from_utf8(denied)
            .unwrap()
            .contains("com.example.player"));
    }

    #[test]
    fn typed_read_route_writes_owned_response_to_reply_pipe() {
        let root = tempdir().unwrap();
        let root_state = root.path().join("root-state");
        let outcome = write_state_bytes(
            &root_state,
            "media-apps_media-selected-package",
            b"\"com.example.player\"\n",
        );
        assert!(outcome.is_ok());
        let mut fds = [-1, -1];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);

        let routed = route_read_from(
            &root_state,
            "41|media-apps|media-selected-package",
            fds[1],
            &endpoint_ctx(),
        );
        close_fd(fds[1]);
        let mut response = [0u8; 64];
        let count = unsafe { libc::read(fds[0], response.as_mut_ptr() as *mut _, response.len()) };
        close_fd(fds[0]);

        assert_eq!(routed, Some(1));
        assert_eq!(&response[..count as usize], b"R|41|ok|com.example.player\n");
    }

    fn close_fd(fd: i32) {
        unsafe {
            libc::close(fd);
        }
    }

    #[test]
    fn temp_symlink_does_not_redirect_write() {
        let root = tempdir().unwrap();
        let state = root.path().join("state");
        let victim = root.path().join("victim");
        make_dir(&state);
        fs::write(&victim, b"unchanged").unwrap();
        symlink(&victim, state.join(".key.json.tmp")).unwrap();

        let result = write_state_bytes(&state, "key", b"5\n");

        assert!(result.is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
        assert!(!state.join("key.json").exists());
    }

    #[test]
    fn policy_does_not_expose_agent_state_to_app() {
        let policy = include_str!("../../selinux/voboost.te");
        let contexts = include_str!("../../selinux/file_contexts");

        assert!(policy.contains("typeattribute voboost mlstrustedsubject;"));
        assert!(policy.contains("type voboost_agent_state_file;"));
        assert!(policy.contains("allow voboost voboost_agent_state_file:file"));
        assert!(!policy.contains("allow untrusted_app voboost_agent_state_file:file"));
        assert!(!contexts.contains("ru\\.voboost/state(/.*)?"));
    }

    #[test]
    fn implant_contract_log_native_class_matches_agents_facade() {
        // Regression guard: the Java logging facade is
        // ru.voboost.agents.AgentLog (renamed from ru.voboost.reflect.Log).
        // A stale class name makes every injection throw
        // "No implementation found for ... AgentLog.log".
        let implant = include_str!("../../implant/implant.cpp");
        assert!(implant
            .contains("static const char *LOG_NATIVE_CLASS    = \"ru/voboost/agents/AgentLog\";"));
        assert!(!implant.contains("ru/voboost/reflect/Log"));
        assert!(implant.contains(
            "{\"log\", \"(JILjava/lang/String;Ljava/lang/String;)V\", (void *)native_log_impl}"
        ));
        assert!(
            implant.contains("register_natives_on(env, loader, LOG_NATIVE_CLASS, log_methods, 1)")
        );
    }

    #[test]
    fn implant_read_contract_has_bounded_timeout_and_matching_request_gate() {
        let implant = include_str!("../../implant/implant.cpp");
        let decode = include_str!("../../implant/state_reply_decode.h");

        // The bounded-timeout read loop stays in implant.cpp; the matching
        // request-id gate and the "ok" status slice moved into the pure,
        // host-testable state_reply_decode.h conversion (review-0901 F4
        // extraction) — the contract pins BOTH sites.
        assert!(implant.contains("STATE_READ_TIMEOUT_MS = 500"));
        assert!(implant.contains("poll(&poll_fd, 1, remaining_ms)"));
        assert!(implant.contains("return nullptr"));
        assert!(decode.contains("parsed_id != awaited_request_id"));
        assert!(decode.contains("status_end - id_end - 1"));
    }

    #[test]
    fn implant_contract_registers_all_agent_events_natives() {
        // Source contract only; native routing behavior has separate host gates.
        fn valid_events_registration(implant: &str) -> bool {
            let entries = [
                r#"{"emit", "(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V", (void *)native_events_emit_impl},"#,
                r#"{"takeMutationAck", "(J)Ljava/lang/String;", (void *)native_events_take_mutation_ack_impl},"#,
                r#"{"takeSavedNative", "(J)Ljava/lang/String;", (void *)native_events_take_saved_impl},"#,
                r#"{"takeVehicleCommandNative", "(Ljava/lang/String;)Ljava/lang/String;", (void *)native_take_vehicle_command},"#,
                r#"{"peekVehicleCommandNative", "(Ljava/lang/String;)Ljava/lang/String;", (void *)native_peek_vehicle_command},"#,
                r#"{"vehicleCommandTransportEpochNative", "()J", (void *)native_vehicle_transport_epoch},"#,
                r#"{"submitOwnedIntent", "(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z", (void *)native_events_submit_owned_intent_impl},"#,
            ];
            let Some((_, table)) = implant.split_once("JNINativeMethod events_methods[] = {")
            else {
                return false;
            };
            let Some((table, _)) = table.split_once("\n    };") else {
                return false;
            };
            let compact = |value: &str| value.split_whitespace().collect::<String>();
            let call_prefix =
                "register_natives_on(env, loader, EVENTS_NATIVE_CLASS, events_methods,";
            let call = format!("{call_prefix} sizeof(events_methods) / sizeof(events_methods[0]))");
            compact(table) == compact(&entries.join(""))
                && implant.matches(call_prefix).count() == 1
                && compact(implant).matches(&compact(&call)).count() == 1
                && !implant.contains("takeConfirmedDesired")
        }
        let implant = include_str!("../../implant/implant.cpp");
        assert!(valid_events_registration(implant));
        for (original, replacement) in [
            (
                r#""takeMutationAck", "(J)Ljava/lang/String;""#,
                r#""takeMutationAck", "(I)Ljava/lang/String;""#,
            ),
            (
                r#""takeVehicleCommandNative", "(Ljava/lang/String;)Ljava/lang/String;""#,
                r#""takeVehicleCommandNative", "(J)Ljava/lang/String;""#,
            ),
            (
                r#""peekVehicleCommandNative", "(Ljava/lang/String;)Ljava/lang/String;""#,
                r#""peekVehicleCommandNative", "(J)Ljava/lang/String;""#,
            ),
            (
                r#""vehicleCommandTransportEpochNative", "()J""#,
                r#""vehicleCommandTransportEpochNative", "()I""#,
            ),
            ("native_events_take_saved_impl},", "other_impl},"),
            ("native_events_submit_owned_intent_impl},", "other_impl},"),
            ("native_take_vehicle_command},", "other_impl},"),
            ("native_peek_vehicle_command},", "other_impl},"),
            ("native_vehicle_transport_epoch},", "other_impl},"),
        ] {
            let invalid = implant.replace(original, replacement);
            assert_ne!(invalid, implant, "mutation must match: {original}");
            assert!(
                !valid_events_registration(&invalid),
                "accepted: {replacement}"
            );
        }
        for count in [0, 3, 5, 6, 7, 8] {
            let invalid = implant.replace(
                "sizeof(events_methods) / sizeof(events_methods[0])",
                &count.to_string(),
            );
            assert_ne!(invalid, implant, "count mutation must match");
            assert!(
                !valid_events_registration(&invalid),
                "accepted count: {count}"
            );
        }
    }

    #[test]
    fn implant_contract_deferred_retry_resets_envelope_and_memfds() {
        // Regression guard: the Deferred branch
        // must clear the stored pipe-bootstrap envelope, its ready flag and
        // every staged memfd, so the retry re-reads a fresh envelope instead
        // of reusing stale payload while the daemon writer blocks. Resident
        // artifact descriptors belong to the active generation and remain
        // valid until a replacement is published.
        let implant = include_str!("../../implant/implant.cpp");
        assert!(implant.contains("g_bootstrap_fds.discard_staged();"));
        assert!(implant.contains("g_pipe_bootstrap = PipeBootstrapEnvelope{};"));
        assert!(implant.contains("g_pipe_bootstrap_ready = false;"));
    }

    #[test]
    fn implant_contract_hard_native_failures_release_bootstrap_storage() {
        let implant = include_str!("../../implant/implant.cpp");
        assert!(implant.contains("static int fail_bootstrap_attempt(int result)"));
        for failure in [
            "pipe bootstrap read failed",
            "JNI_GetCreatedJavaVMs resolution failed",
            "no JavaVM found",
            "AttachCurrentThread failed",
            "GetEnv failed",
            "LSPlant init failed",
        ] {
            let start = implant
                .find(failure)
                .expect("hard failure branch must exist");
            let tail = &implant[start..];
            let return_at = tail.find("return ").expect("hard failure must return");
            assert!(tail[..return_at + 120].contains("fail_bootstrap_attempt("));
        }
    }

    #[test]
    fn policy_is_pipe_only_no_target_readable_bootstrap_or_shared() {
        let policy = include_str!("../../selinux/voboost.te");
        let contexts = include_str!("../../selinux/file_contexts");
        let implant = include_str!("../../implant/implant.cpp");

        assert!(policy.contains("type voboost_generation_file;"));
        // Pipe-only bootstrap: targets never read generation/bootstrap files.
        assert!(!contexts.contains("process-load-descriptors"));
        assert!(!policy.contains("voboost_bootstrap_file"));
        assert!(!policy.contains("allow untrusted_app voboost_generation_file"));
        assert!(!policy.contains("allow platform_app voboost_generation_file"));
        assert!(!contexts.contains("/data/voboost/shared"));
        assert!(!policy.contains("media_rw_data_file"));
        // No descriptor-file fallback remains in the implant.
        assert!(!implant.contains("read_bootstrap"));
        assert!(implant.contains("registerModule"));
        assert!(implant.contains("AGENT_ENTRY_REGISTER_METHOD_SIG"));
        assert!(implant.contains("moduleProcesses"));
        let seam = include_str!("../../implant/include/agent_entry_seam.h");
        assert!(seam.contains("[Ljava/lang/String;Ljava/lang/ClassLoader;)V"));
    }
    #[test]
    fn retiring_state_terminal_stop_write_commits_and_readback_confirms() {
        let root = tempdir().unwrap();
        let store = root.path().join("state");
        let mut ctx = vehicle_context();
        ctx.process = "test.retiring.write".into();
        ctx.resident_agents.clear();
        ctx.agents.clear();
        ctx.resident_generation_id = "a".repeat(64);
        ctx.resident_catalog_sha256 = "b".repeat(64);
        ctx.log_generation = Some((
            ctx.resident_generation_id.clone(),
            ctx.resident_catalog_sha256.clone(),
        ));
        ctx.retiring_state = Some(crate::agent_log::RetiringState {
            process: ctx.process.clone(),
            binding: crate::control_plane::endpoint_binding(&ctx).unwrap(),
            sources: std::collections::HashSet::from(["vehicle-drive-forced-ev".into()]),
            expires: std::time::Instant::now() + std::time::Duration::from_secs(30),
            revoked: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        });
        assert_eq!(
            route_state_from(
                &store,
                "1|vehicle-drive-forced-ev|forced-ev-lifecycle-active|false",
                &ctx
            ),
            Some(1)
        );
        assert_eq!(
            read_owned_state(
                &store,
                "vehicle-drive-forced-ev",
                "forced-ev-lifecycle-active"
            ),
            ReadOutcome::Value(serde_json::json!(false))
        );
        assert_eq!(
            route_state_from(
                &store,
                "1|vehicle-drive-forced-ev|forced-ev-lifecycle-active|true",
                &ctx
            ),
            None
        );
        let mut fds = [-1, -1];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        assert_eq!(
            route_read_from(
                &store,
                "77|vehicle-drive-forced-ev|forced-ev-lifecycle-active",
                fds[1],
                &ctx
            ),
            Some(1)
        );
        assert!(crate::downlink::flush(fds[1]));
        crate::downlink::forget_fd(fds[1]);
        close_fd(fds[1]);
        let mut reply = [0u8; 128];
        let count = unsafe { libc::read(fds[0], reply.as_mut_ptr().cast(), reply.len()) };
        close_fd(fds[0]);
        assert!(count > 0);
        assert_eq!(&reply[..count as usize], b"R|77|ok|false\n");
    }

    #[test]
    fn failed_write_does_not_replace_prior_confirmed_value_into_missing_read() {
        // Boot-capture boundary: a failed root-store write must never leave
        // the previous confirmed value silently absent — the agent would read
        // `missing` after a confirmed store and delete durable state after the
        // next re-arm.
        let root = tempdir().unwrap();
        let store = root.path().join("state");
        let context = vehicle_context();
        let (source, key) = vehicle_pairs()[0];
        assert_eq!(
            route_state_from(&store, &format!("1|{source}|{key}|true"), &context),
            Some(1)
        );
        // Pre-create a directory at the temp-file path: prepare_trusted
        // fails, the rename never runs, the daemon reports a refused write.
        fs::create_dir(&store).ok();
        fs::create_dir(store.join(format!(".{}.json.tmp", storage_key(source, key).unwrap())))
            .unwrap();
        assert_eq!(
            route_state_from(&store, &format!("2|{source}|{key}|false"), &context),
            None
        );
        fs::remove_dir(store.join(format!(".{}.json.tmp", storage_key(source, key).unwrap())))
            .unwrap();
        // The refused write leaves the earlier confirmed value intact.
        assert_eq!(
            read_owned_state(&store, source, key),
            ReadOutcome::Value(Value::Bool(true))
        );
    }

    #[test]
    fn the_same_reply_fd_serves_many_repeated_replays_in_order() {
        // The reply pipe is reused by repeated requests (FEV attempt 8 and PW
        // attempt 9 were observed in the same boot window). Repeated and
        // distinct sequential replays of the same request over one reply fd
        // must each produce a fresh, ordered, non-interleaved frame. This is
        // a sequential single-thread replay — it does not exercise cross-
        // thread contention, short-write resume or backpressure.
        let root = tempdir().unwrap();
        let store = root.path().join("state");
        write_state_bytes(
            &store,
            &storage_key(vehicle_pairs()[0].0, vehicle_pairs()[0].1).unwrap(),
            b"true\n",
        )
        .unwrap();
        let mut fds = [-1, -1];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (source, key) = vehicle_pairs()[0];
        for rewrite in [true, false, true] {
            let mut context = vehicle_context();
            context.endpoint_epoch = rewrite as u64 + 81;
            for request in [7u64, 7u64, 8u64, u64::MAX] {
                assert_eq!(
                    route_read_from(
                        &store,
                        &format!("{request}|{source}|{key}"),
                        fds[1],
                        &context,
                    ),
                    Some(1)
                );
            }
            assert!(crate::downlink::flush(fds[1]));
        }
        crate::downlink::forget_fd(fds[1]);
        close_fd(fds[1]);
        let mut replies = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let count = unsafe { libc::read(fds[0], buffer.as_mut_ptr().cast(), buffer.len()) };
            if count <= 0 {
                break;
            }
            replies.extend_from_slice(&buffer[..count as usize]);
        }
        close_fd(fds[0]);
        let mut expected = "R|7|ok|true\n".repeat(2);
        expected.push_str("R|8|ok|true\n");
        expected.push_str(&format!("R|{}|ok|true\n", u64::MAX));
        expected = expected.repeat(3);
        assert_eq!(String::from_utf8(replies).unwrap(), expected);
    }

    #[test]
    fn spoofing_outsider_cannot_read_full_store_across_epoch_and_source_confusion() {
        // Cross-referenced endpoints claim only their own residents: defense against
        // spoofing from another endpoint (epoch confusion) and confusion of
        // foreign agent prefixes. Failed/successful spoofing writes and reads
        // do not change the owner's data.
        let root = tempdir().unwrap();
        let store = root.path().join("state");
        let owner = vehicle_context();
        let mut outsider = endpoint_ctx();
        outsider.endpoint_epoch = owner.endpoint_epoch + 1; // claim a different, later epoch — never a right of access
        outsider.resident_agents = ["forced-ev".to_string(), "media-apps".to_string()].into();
        outsider.log_generation = None;
        write_state_bytes(
            &store,
            &storage_key(vehicle_pairs()[0].0, vehicle_pairs()[0].1).unwrap(),
            b"true\n",
        )
        .unwrap();
        let (source, key) = vehicle_pairs()[0];
        let mut fds = [-1, -1];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);

        // Outsider cannot read the owner's state despite claiming a later
        // epoch (irrelevant: owns_state never reads endpoint_epoch) and cannot
        // write over it.
        assert_eq!(
            route_read_from(&store, &format!("5|{source}|{key}"), fds[1], &outsider),
            None
        );
        assert_eq!(
            route_state_from(&store, &format!("6|{source}|{key}|false"), &outsider),
            None
        );
        crate::downlink::forget_fd(fds[1]);
        close_fd(fds[1]);
        close_fd(fds[0]);
        assert_eq!(
            read_owned_state(&store, source, key),
            ReadOutcome::Value(Value::Bool(true))
        );
        // Source-confusion: distinct lengths never alias into one file.
        let s1 = "x".repeat(config::MAX_AGENT_STATE_SOURCE_BYTES);
        let s2 = "x".repeat(config::MAX_AGENT_STATE_SOURCE_BYTES - 1);
        let alias = storage_key("ab", "c_d").unwrap();
        assert_ne!(alias, storage_key("a", "b_c_d").unwrap());
        let mut spoof = outsider.clone();
        spoof.resident_agents = [s1.clone()].into();
        assert!(spoof.owns_state(&s1, "k", None));
        assert_eq!(
            route_state_from(&store, &format!("7|{s1}|k|9"), &spoof),
            Some(1)
        );
        assert!(!store
            .join(format!("{}.json", storage_key(&s2, "k").unwrap()))
            .exists());
        let (source, key) = vehicle_pairs()[0];
        assert_eq!(
            read_owned_state(&store, source, key),
            ReadOutcome::Value(Value::Bool(true))
        );
    }
}
