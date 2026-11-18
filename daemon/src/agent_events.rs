//! Direct strict SettingsAgent mutation route; no app/events.json round-trip.
//!
//! Runtime-state contract: a request id counts as processed only after the
//! mutated full snapshot has been committed atomically. A duplicate request
//! id returns the same accepted outcome without a second mutation; a request
//! that was rejected (invalid or failed to commit) may be retried. Checkbox
//! and enum-option mutations are catalog-aware: the endpoint must be resident
//! on the active generation and the exact id/key/value must exist in that
//! generation's signed, applicable catalog surface.
//!
//! The read/validate/write window runs under the shared short kernel
//! mutation lock (`operation.lock`, the same one generation/product/CLI
//! startup writers hold), so a concurrent full-document RMW by another writer
//! cannot interleave and lose an unrelated committed field. The lock is
//! never held across a status wait; a busy lock fails this event without an
//! ACK so the endpoint retries the same request id later.

mod desired;
#[cfg(test)]
pub(crate) use desired::route_with as route_fixture_desired;
#[cfg(test)]
pub(crate) use desired::route_with as route_user_desired_for_fixture;
#[path = "global_locale.rs"]
pub mod global_locale;
#[path = "i18n_resource_events.rs"]
pub mod i18n_resource_events;
mod launcher_desired;

use crate::{config, log};
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
#[cfg(test)]
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Default)]
struct DeferredRequests {
    recent: HashMap<(u64, u64), ()>,
    order: VecDeque<(u64, u64)>,
}

impl DeferredRequests {
    fn first(&mut self, endpoint: u64, request: u64) -> bool {
        let key = (endpoint, request);
        if self.recent.contains_key(&key) {
            return false;
        }
        self.recent.insert(key, ());
        self.order.push_back(key);
        while self.order.len() > MAX_RECENT_REQUESTS {
            if let Some(expired) = self.order.pop_front() {
                self.recent.remove(&expired);
            }
        }
        true
    }

    fn forget_endpoint(&mut self, endpoint: u64) {
        self.recent.retain(|(epoch, _), _| *epoch != endpoint);
        self.order.retain(|(epoch, _)| *epoch != endpoint);
    }
}

fn deferred_requests() -> &'static Mutex<DeferredRequests> {
    static CACHE: OnceLock<Mutex<DeferredRequests>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(DeferredRequests::default()))
}

fn mutation_lock_diagnostic(
    cache: &mut DeferredRequests,
    endpoint: u64,
    request: u64,
    error: &str,
) -> Option<(bool, String)> {
    if error == "operation busy" {
        cache.first(endpoint, request).then(|| {
            (
                false,
                format!("request {request} deferred: operation lock is busy"),
            )
        })
    } else {
        Some((
            true,
            format!("request {request} mutation lock failed: {error}"),
        ))
    }
}

/// Decode only an authenticated vehicle-control Electric click; no target value is accepted.
fn electric_click_request(
    rest: &str,
    ctx: &crate::agent_log::EndpointContext,
    mutations_allowed: bool,
) -> Option<(u64, bool)> {
    if !mutations_allowed
        || !matches!(
            ctx.process.as_str(),
            "com.qinggan.app.vehiclesetting"
                | "com.qinggan.app.launcher"
                | "com.qinggan.app.hiboard"
        )
        || ctx.pid <= 1
        || ctx.target_starttime.is_none()
        || ctx.endpoint_epoch == 0
        || !ctx.settings_generation_is_active()
        || !ctx.owns_agent("vehicle-drive-forced-ev")
        || !ctx.agents.contains("vehicle-drive-forced-ev")
        || !ctx.known_agents.contains_key("vehicle-drive-forced-ev")
    {
        return None;
    }
    let mut parts = rest.split('|');
    let id = parts.next()?.parse::<u64>().ok()?;
    if id == 0
        || id > voboost_contract::runtime_owner::MAX_NATIVE_ID
        || parts.next()? != "vehicle-drive-forced-ev"
        || parts.next()? != "electric-click"
    {
        return None;
    }
    let cancel = match parts.next()? {
        "click" => false,
        "cancel" => true,
        _ => return None,
    };
    if parts.next().is_some() {
        return None;
    }
    Some((id, cancel))
}

fn electric_click_route_with(
    rest: &str,
    ctx: &crate::agent_log::EndpointContext,
    allowed: bool,
    cache: &mut CommittedRequests,
    boot: &str,
    mut exchange: impl FnMut(
        voboost_contract::runtime_owner::Command,
    ) -> std::io::Result<voboost_contract::runtime_owner::Outcome>,
    mut send: impl FnMut(&[u8]) -> bool,
) -> bool {
    use voboost_contract::runtime_owner::ElectricClickStatus;
    use voboost_contract::runtime_owner::{Command, Outcome};
    let Some((id, cancel)) = electric_click_request(rest, ctx, allowed) else {
        return false;
    };
    let fingerprint = "vehicle-drive-forced-ev|electric-click";
    let poll = match cache.classify(ctx.endpoint_epoch, id, fingerprint) {
        RequestDisposition::Fresh => {
            let occupied = cache
                .by_endpoint
                .get(&ctx.endpoint_epoch)
                .and_then(|endpoint| endpoint.electric_active)
                .is_some_and(|active| active != id);
            // An ambiguous owner reply is never retried as a fresh transmission.
            cache.remember(ctx.endpoint_epoch, id, fingerprint.into());
            if occupied {
                let document =
                    serde_json::json!({"electricClick":ElectricClickStatus::Busy}).to_string();
                return crate::runtime::render_mutation_ack_frame(id, &document)
                    .is_ok_and(|frame| send(&frame));
            }
            cache
                .by_endpoint
                .get_mut(&ctx.endpoint_epoch)
                .expect("remembered endpoint")
                .electric_active = Some(id);
            false
        }
        RequestDisposition::Duplicate => true,
        RequestDisposition::Conflict | RequestDisposition::StaleReplay => return false,
    };
    let input = voboost_contract::desired::Input {
        boot_id: boot.into(),
        endpoint_epoch: ctx.endpoint_epoch,
        request_id: id,
        injector_pid: 0,
        injector_starttime: 0,
    };
    let (result, terminal) = match exchange(Command::ElectricClick {
        input,
        poll,
        cancel,
    }) {
        Ok(Outcome::ElectricClick { result }) => (
            result,
            matches!(
                result,
                ElectricClickStatus::NotSubmitted
                    | ElectricClickStatus::Accepted
                    | ElectricClickStatus::Drained
            ),
        ),
        _ => (ElectricClickStatus::Unknown, false),
    };
    if terminal {
        if let Some(endpoint) = cache.by_endpoint.get_mut(&ctx.endpoint_epoch) {
            if endpoint.electric_active == Some(id) {
                endpoint.electric_active = None;
            }
        }
    }
    let document = serde_json::json!({"electricClick":result}).to_string();
    crate::runtime::render_mutation_ack_frame(id, &document).is_ok_and(|frame| send(&frame))
}

fn committed_requests() -> &'static Mutex<CommittedRequests> {
    static CACHE: OnceLock<Mutex<CommittedRequests>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(CommittedRequests::default()))
}

#[derive(Default)]
struct CommittedRequests {
    by_endpoint: HashMap<u64, EndpointRequests>,
}

const MAX_RECENT_REQUESTS: usize = 4096;

#[derive(Default)]
struct EndpointRequests {
    highest: u64,
    electric_active: Option<u64>,
    recent: HashMap<u64, String>,
    order: VecDeque<u64>,
}

#[derive(Debug, PartialEq, Eq)]
enum RequestDisposition {
    Fresh,
    Duplicate,
    Conflict,
    StaleReplay,
}

impl CommittedRequests {
    fn classify(&self, endpoint_epoch: u64, id: u64, fingerprint: &str) -> RequestDisposition {
        let Some(endpoint) = self.by_endpoint.get(&endpoint_epoch) else {
            return RequestDisposition::Fresh;
        };
        if let Some(committed) = endpoint.recent.get(&id) {
            return if committed == fingerprint {
                RequestDisposition::Duplicate
            } else {
                RequestDisposition::Conflict
            };
        }
        if id <= endpoint.highest {
            RequestDisposition::StaleReplay
        } else {
            RequestDisposition::Fresh
        }
    }

    fn remember(&mut self, endpoint_epoch: u64, id: u64, fingerprint: String) {
        let endpoint = self.by_endpoint.entry(endpoint_epoch).or_default();
        endpoint.highest = endpoint.highest.max(id);
        endpoint.recent.insert(id, fingerprint);
        endpoint.order.push_back(id);
        while endpoint.order.len() > MAX_RECENT_REQUESTS {
            if let Some(expired) = endpoint.order.pop_front() {
                endpoint.recent.remove(&expired);
            }
        }
    }

    fn forget(&mut self, endpoint_epoch: u64) -> Option<u64> {
        self.by_endpoint
            .remove(&endpoint_epoch)
            .and_then(|entry| entry.electric_active)
    }
}

pub fn forget_endpoint(endpoint_epoch: u64) {
    if let Ok(mut deferred) = deferred_requests().lock() {
        deferred.forget_endpoint(endpoint_epoch);
    }
    global_locale::forget(endpoint_epoch);
    i18n_resource_events::forget(endpoint_epoch);
    crate::launcher_config::forget_endpoint(endpoint_epoch);
    let pending_electric = if let Ok(mut cache) = committed_requests().lock() {
        cache.forget(endpoint_epoch)
    } else {
        None
    };
    if let (Some(request_id), Ok(boot_id)) = (
        pending_electric,
        crate::operation_contract::current_boot_id(),
    ) {
        let input = voboost_contract::desired::Input {
            boot_id,
            endpoint_epoch,
            request_id,
            injector_pid: 0,
            injector_starttime: 0,
        };
        let _ =
            crate::owner_client::call(voboost_contract::runtime_owner::Command::ElectricClick {
                input,
                poll: true,
                cancel: true,
            });
    }
    if let Ok(mut pending) = confirmed_pending().lock() {
        pending.retain(|(epoch, _), _| *epoch != endpoint_epoch);
    }
}

/// Set after every successful commit so the daemon's poll loop pushes a
/// confirmed `A` snapshot to the submitting endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmedTarget {
    pub endpoint_epoch: u64,
    pub process: String,
    pub fd: i32,
    pub request_id: u64,
    kind: ConfirmationKind,
    first_pending_at: Instant,
    failed_attempts: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ConfirmationKind {
    Mutation,
    Restart,
}

type Confirmations = HashMap<(u64, ConfirmationKind), ConfirmedTarget>;

const MAX_CONFIRMATION_RETRY_ATTEMPTS: u8 = 20;
const MAX_CONFIRMATION_RETRY_AGE: Duration = Duration::from_secs(15);

fn confirmed_pending() -> &'static Mutex<Confirmations> {
    static PENDING: OnceLock<Mutex<Confirmations>> = OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(HashMap::new()))
}

fn mark_confirmed_pending(ctx: &crate::agent_log::EndpointContext, fd: i32, request_id: u64) {
    mark_confirmation(ctx, fd, request_id, ConfirmationKind::Mutation);
}

fn mark_confirmation(
    ctx: &crate::agent_log::EndpointContext,
    fd: i32,
    request_id: u64,
    kind: ConfirmationKind,
) {
    if let Ok(mut pending) = confirmed_pending().lock() {
        let key = (ctx.endpoint_epoch, kind);
        let should_replace = pending
            .get(&key)
            .is_none_or(|current| request_id > current.request_id);
        if should_replace {
            pending.insert(
                key,
                ConfirmedTarget {
                    endpoint_epoch: ctx.endpoint_epoch,
                    process: ctx.process.clone(),
                    fd,
                    request_id,
                    kind,
                    first_pending_at: Instant::now(),
                    failed_attempts: 0,
                },
            );
        }
    }
}

/// Consume each coalesced target exactly once. A slow or dead Settings
/// endpoint cannot amplify delivery to unrelated residents on later polls.
pub fn take_confirmed_pending() -> Vec<ConfirmedTarget> {
    confirmed_pending()
        .lock()
        .map(|mut pending| std::mem::take(&mut *pending).into_values().collect())
        .unwrap_or_default()
}

/// Drop acknowledgements for mutations committed before uninstall preparation.
/// Once cleanup starts, no canonical mutation acknowledgement may be delivered
/// into the ephemeral disable/frozen path.
pub fn discard_confirmed_pending() -> usize {
    confirmed_pending()
        .lock()
        .map(|mut pending| discard_confirmed_map(&mut pending))
        .unwrap_or_default()
}

fn discard_confirmed_map(pending: &mut Confirmations) -> usize {
    let count = pending.len();
    pending.clear();
    count
}

/// Retain a transiently undeliverable ACK for a bounded number of daemon poll
/// passes and a bounded wall-clock lifetime. A newer request already pending
/// for the same endpoint always wins over the failed older delivery.
pub fn retry_confirmed_pending(mut target: ConfirmedTarget) -> bool {
    target.failed_attempts = target.failed_attempts.saturating_add(1);
    if target.failed_attempts >= MAX_CONFIRMATION_RETRY_ATTEMPTS
        || target.first_pending_at.elapsed() >= MAX_CONFIRMATION_RETRY_AGE
    {
        return false;
    }
    let Ok(mut pending) = confirmed_pending().lock() else {
        return false;
    };
    let key = (target.endpoint_epoch, target.kind);
    match pending.get(&key) {
        Some(current) if current.request_id > target.request_id => true,
        _ => {
            pending.insert(key, target);
            true
        }
    }
}

pub fn has_confirmed_pending() -> bool {
    confirmed_pending()
        .lock()
        .map(|mut pending| {
            pending.retain(|_, target| {
                target.first_pending_at.elapsed() < MAX_CONFIRMATION_RETRY_AGE
                    && target.failed_attempts < MAX_CONFIRMATION_RETRY_ATTEMPTS
            });
            !pending.is_empty()
        })
        .unwrap_or(false)
}

/// E|<request-id>|settings|<checkbox|radio|option>|<key>:<value>
///
/// Typed agent option payloads are exactly `<agent-id>/<option-key>:<value>`.
pub fn route_events(
    rest: &str,
    ctx: &crate::agent_log::EndpointContext,
    reply_fd: Option<i32>,
    mutations_allowed: bool,
) -> Option<usize> {
    route_events_at_with_policy(
        rest,
        ctx,
        reply_fd,
        &PathBuf::from(config::plan_file()),
        mutations_allowed,
    )
}

/// OEM offline test driver entry: the production event parser and guards
/// against a fixture-owned plan path (the host driver has no
/// /data/voboost). Same cfg(test) seam the unit tests use; the runtime
/// keeps its own canonical path.
#[cfg(test)]
pub fn route_events_at_fixture_plan(
    rest: &str,
    ctx: &crate::agent_log::EndpointContext,
    reply_fd: Option<i32>,
    path: &std::path::Path,
) -> Option<usize> {
    route_events_at_with_policy(rest, ctx, reply_fd, path, true)
}

#[cfg(test)]
fn route_events_at(
    rest: &str,
    ctx: &crate::agent_log::EndpointContext,
    reply_fd: Option<i32>,
    path: &std::path::Path,
) -> Option<usize> {
    route_events_at_with_policy(rest, ctx, reply_fd, path, true)
}

fn route_events_at_with_policy(
    rest: &str,
    ctx: &crate::agent_log::EndpointContext,
    reply_fd: Option<i32>,
    path: &std::path::Path,
    mutations_allowed: bool,
) -> Option<usize> {
    route_events_at_with_writer(rest, ctx, reply_fd, path, mutations_allowed, write_atomic)
}

fn route_events_at_with_writer(
    rest: &str,
    ctx: &crate::agent_log::EndpointContext,
    reply_fd: Option<i32>,
    path: &std::path::Path,
    mutations_allowed: bool,
    writer: impl FnOnce(&std::path::Path, &Value) -> Result<(), String>,
) -> Option<usize> {
    route_events_at_with_routes(rest, ctx, reply_fd, path, mutations_allowed, writer, || {
        desired::route(rest, ctx, reply_fd).or_else(|| launcher_desired::route(rest, ctx, reply_fd))
    })
}

fn route_events_at_with_routes(
    rest: &str,
    ctx: &crate::agent_log::EndpointContext,
    reply_fd: Option<i32>,
    path: &std::path::Path,
    mutations_allowed: bool,
    writer: impl FnOnce(&std::path::Path, &Value) -> Result<(), String>,
    routes: impl FnOnce() -> Option<Option<usize>>,
) -> Option<usize> {
    if mutations_allowed || rest.split('|').nth(2) == Some("desired-read") {
        if let Some(result) = routes() {
            return result;
        }
    }
    if electric_click_request(rest, ctx, mutations_allowed).is_some() {
        let fd = reply_fd?;
        let boot = crate::operation_contract::current_boot_id().ok()?;
        let mut cache = committed_requests().lock().ok()?;
        return electric_click_route_with(
            rest,
            ctx,
            mutations_allowed,
            &mut cache,
            &boot,
            crate::owner_client::call,
            |frame| crate::downlink::enqueue_frame(fd, frame),
        )
        .then_some(1);
    }
    // Read-only observations never mutate canonical intent or emit config ACKs.
    let mut observation = rest.splitn(4, '|');
    if let (
        Some(request),
        Some(source @ ("i18n-ru" | "i18n-en")),
        Some(kind @ ("global-locale" | "resource-probe")),
        Some(payload),
    ) = (
        observation.next(),
        observation.next(),
        observation.next(),
        observation.next(),
    ) {
        if !mutations_allowed || request.parse::<u64>().ok().filter(|id| *id > 0).is_none() {
            return None;
        }
        return match kind {
            "global-locale" => global_locale::observe_from(source, payload, ctx),
            _ => i18n_resource_events::observe_from(source, payload, ctx),
        };
    }
    let mut commands = rest.splitn(4, '|');
    if let (Some(request), Some(source), Some("vehicle-command"), Some(payload)) = (
        commands.next(),
        commands.next(),
        commands.next(),
        commands.next(),
    ) {
        let request = request.parse::<u64>().ok().filter(|request| {
            *request > 0 && *request <= voboost_contract::runtime_owner::MAX_NATIVE_ID
        })?;
        let payload = payload.strip_prefix("command:")?;
        if !crate::native_commands::route_allowed(
            ctx,
            source,
            payload.as_bytes(),
            mutations_allowed,
        ) || reply_fd.is_none() && !crate::native_commands::is_terminal(payload.as_bytes())
        {
            return None;
        }
        let response = crate::native_commands::handle(source, request, payload.as_bytes(), ctx);
        if let Some(fd) = reply_fd {
            let frame = crate::native_commands::frame(source, request, &response)?;
            return crate::downlink::enqueue_frame(fd, frame.as_bytes()).then_some(1);
        }
        return matches!(
            response,
            Ok(voboost_contract::runtime_owner::Outcome::NativeCommandReported { .. })
        )
        .then_some(1);
    }
    if let Some((request, revision)) = restart_request(rest) {
        let fd = reply_fd?;
        let fingerprint = format!("restart|process:{revision}");
        let mut cache = committed_requests().lock().ok()?;
        let disposition = cache.classify(ctx.endpoint_epoch, request, &fingerprint);
        let allowed = match disposition {
            RequestDisposition::Fresh => crate::process_restart::authorize(ctx, request, revision),
            RequestDisposition::Duplicate => {
                crate::process_restart::pending(ctx, request, revision)
            }
            RequestDisposition::Conflict | RequestDisposition::StaleReplay => false,
        };
        if allowed {
            if disposition == RequestDisposition::Fresh {
                cache.remember(ctx.endpoint_epoch, request, fingerprint);
                log::debug("process-restart", &format!(
                    "permission granted process={} pid={} starttime={:?} epoch={} revision={} request={request}",
                    ctx.process, ctx.pid, ctx.target_starttime, ctx.endpoint_epoch, revision));
            }
            mark_confirmation(ctx, fd, request, ConfirmationKind::Restart);
            return Some(1);
        }
        log::debug("process-restart", &format!(
            "permission rejected process={} pid={} epoch={} requested={} expected={:?} removal={} active={}",
            ctx.process, ctx.pid, ctx.endpoint_epoch, revision, ctx.document_generation,
            ctx.restart_allowed, ctx.settings_generation_is_active()));
        return None;
    }
    if !mutations_allowed {
        log::debug(
            "agent-events",
            "Settings mutation rejected during uninstall preparation",
        );
        return None;
    }
    // Capability and generation fence: canonical intent is active-catalog
    // state. An older passive resident may keep receiving resident-catalog D
    // snapshots, but it cannot mutate canonical agents.json or receive a
    // false A acknowledgement for an active-generation document.
    // Stage 013 authority: canonical E mutations belong to an endpoint that
    // OWNS the emitting source. The Settings endpoint (settings resident)
    // keeps its exclusive panel authority: source "settings" may submit
    // option/checkbox/radio lines for any selected agent exactly as before.
    // A non-settings endpoint may submit ONLY its own resident agent's
    // option line (source == resident agent == option agent id): the
    // editor endpoint (vehicle-drive-outing resident in the vehiclesetting
    // process) can never borrow Settings authority, and Settings can never
    // emit through the editor endpoint.
    if !ctx.settings_generation_is_active() {
        log::err(
            "agent-events",
            &format!(
                "rejected stale Settings endpoint epoch={} resident={}/{} active={}/{}",
                ctx.endpoint_epoch,
                ctx.resident_generation_id,
                ctx.resident_catalog_sha256,
                ctx.active_generation_id,
                ctx.active_catalog_sha256,
            ),
        );
        return None;
    }
    let reply_fd = reply_fd?;
    let mut parts = rest.splitn(4, '|');
    let request_id: u64 = parts.next()?.parse().ok()?;
    let source = parts.next()?;
    let event_type = parts.next()?;
    let (key, raw) = parts.next()?.split_once(':')?;
    let launcher_input = source == "launcher"
        && matches!(
            (event_type, key),
            ("launcher-item-visibility", "item")
                | ("launcher-section-visibility", "section")
                | ("launcher-density", "density")
                | ("launcher-app-preference", "preference")
        );
    // Captured OEM inputs belong exclusively to the semantic Saved lane above.
    if event_type == "owned-intent" {
        return None;
    }
    // Stage 013 authority split: the exclusive settings-source panel wire
    // (option/checkbox/radio for any selected agent) stays byte-identical.
    // A resident-owner source different from "settings" is authorized ONLY
    // for its OWN typed option line: the option path agent id must equal
    // the source, and the option key must belong to that agent's signed
    // enum surface (the known_options check below). Every other shape
    // (checkbox/radio, someone else's options, settings wire on a
    // non-settings endpoint) fails closed.
    let settings_wire = source == "settings";
    // Startup-escalation wire: the ONE non-settings line a settings-host
    // executor may submit — the T-Box version gesture's recovery transition
    // hidden→interface. It is authorized only by the daemon-computed executor
    // residency on the settings-host process (never by the settings panel
    // authority) and further constrained inside the mutation arm below.
    let startup_escalation_wire =
        !settings_wire && event_type == "radio" && key == "voboost-startup" && raw == "interface";
    if settings_wire && !ctx.settings_allowed() {
        return None;
    }
    if !settings_wire {
        if launcher_input {
            if ctx.process != "com.qinggan.app.setting" || !ctx.owns_agent("launcher") {
                return None;
            }
        } else if startup_escalation_wire {
            // Narrow gesture authority: a catalog executor the daemon
            // actually injects into the settings-host process.
            if !ctx.startup_escalation_allowed(source) {
                return None;
            }
        } else {
            // Stage 014 ownership guard: a non-settings line must come from an
            // agent RESIDENT on this endpoint (daemon-trusted resident set).
            // Knowing the agent's signed option surface (known_options) only
            // validates the payload shape — residency is the authority; a
            // known-but-non-resident agent can never emit through this
            // endpoint. Runs before the idempotence cache and the mutation
            // lock so a rejected spoof has no side effects at all.
            if !ctx.owns_agent(source) {
                return None;
            }
            if event_type != "option" || !key.starts_with(&format!("{source}/")) {
                return None;
            }
        }
    }
    if key.is_empty()
        || key.len() > 192
        || raw.is_empty()
        || raw.len() > if launcher_input { 1024 } else { 128 }
    {
        return None;
    }

    let fingerprint = format!("{event_type}|{key}:{raw}");
    // Idempotence is scoped to the daemon-owned endpoint epoch and the exact
    // mutation identity. Reusing an id for another mutation, or replaying an
    // evicted old id below the monotonic floor, fails closed.
    {
        if let Ok(cache) = committed_requests().lock() {
            match cache.classify(ctx.endpoint_epoch, request_id, &fingerprint) {
                RequestDisposition::Duplicate => {
                    mark_confirmed_pending(ctx, reply_fd, request_id);
                    return Some(1);
                }
                RequestDisposition::Conflict | RequestDisposition::StaleReplay => return None,
                RequestDisposition::Fresh => {}
            }
        }
    }

    // Hold the shared short mutation lock across the whole read/modify/write
    // window so a concurrent CLI startup RMW or a generation/product writer
    // cannot interleave with this committed snapshot. A busy lock rejects the
    // event without an ACK; the endpoint retries the same request id.
    let lock_root = path
        .parent()
        .ok_or_else(|| "agents.json has no parent".to_string())
        .map_err(|error| {
            log::err(
                "agent-events",
                &format!("agents.json mutation lock: {error}"),
            );
        })
        .ok()?;
    let _guard = match mutation_lock_at(lock_root) {
        Ok(guard) => guard,
        Err(error) => {
            crate::emulator_diagnostic::observe_startup_rejection(ctx, request_id, event_type, key);
            let diagnostic = deferred_requests()
                .lock()
                .map(|mut cache| {
                    mutation_lock_diagnostic(&mut cache, ctx.endpoint_epoch, request_id, &error)
                })
                .unwrap_or_else(|_| {
                    Some((
                        true,
                        format!("request {request_id} mutation lock failed: {error}"),
                    ))
                });
            if let Some((failed, message)) = diagnostic {
                if failed {
                    log::err("agent-events", &message);
                } else {
                    log::debug("agent-events", &message);
                }
            }
            return None;
        }
    };
    let bytes = crate::plan::read_canonical_bounded(path).ok()?;
    let mut root: Value = serde_json::from_slice(&bytes).ok()?;
    let object = root.as_object_mut()?;
    match (event_type, key) {
        ("launcher-item-visibility", "item") if launcher_input => {
            let options = object
                .get_mut("agents")?
                .get_mut("launcher")?
                .get_mut("options")?;
            crate::launcher_config::mutate(options, raw, ctx)?;
        }
        ("launcher-section-visibility", "section") if launcher_input => {
            let options = object
                .get_mut("agents")?
                .get_mut("launcher")?
                .get_mut("options")?;
            crate::launcher_config::mutate_section(options, raw, ctx)?;
        }
        ("launcher-app-preference", "preference") if launcher_input => {
            let options = object
                .get_mut("agents")?
                .get_mut("launcher")?
                .get_mut("options")?;
            crate::launcher_config::mutate_preference(options, raw, ctx)?;
        }
        ("launcher-density", "density") if launcher_input => {
            if !matches!(raw, "160" | "210" | "240" | "300") {
                return None;
            }
            let options = object
                .get_mut("agents")?
                .get_mut("launcher")?
                .get_mut("options")?;
            if !crate::launcher_config::valid_options(options) {
                return None;
            }
            options
                .as_object_mut()?
                .insert("densityDpi".into(), raw.parse::<u64>().ok()?.into());
        }
        ("radio", "voboost-startup") if matches!(raw, "none" | "hidden" | "interface") => {
            // Escalation-wire constraint: the recovery gesture may only
            // complete hidden→interface (an idempotent re-tap while already
            // interface re-commits the same value); every other shape from a
            // non-settings source fails closed. The settings panel wire keeps
            // its full none/hidden/interface authority.
            if !settings_wire {
                let configured = serde_json::from_value(object.get("startup")?.clone()).ok()?;
                let effective =
                    crate::startup_session::effective_at_for_event(path.parent()?, configured)
                        .ok()?;
                let permitted = matches!(
                    effective,
                    crate::plan::Startup::Hidden | crate::plan::Startup::Interface
                ) && raw == "interface";
                if !permitted {
                    log::err(
                        "agent-events",
                        &format!(
                            "request {request_id} startup escalation rejected for source {source}"
                        ),
                    );
                    return None;
                }
            }
            object.insert("startup".into(), Value::String(raw.into()));
        }
        ("checkbox", agent_id)
            if agent_id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') =>
        {
            let enabled = match raw {
                "true" => true,
                "false" => false,
                _ => return None,
            };
            // Catalog-aware: unknown agent ids are rejected before any write.
            let disables = ctx.known_agents.get(agent_id).cloned();
            let Some(disables) = disables else {
                log::err(
                    "agent-events",
                    &format!("request {request_id} referenced unknown agent {agent_id}"),
                );
                return None;
            };
            let agents = object.get_mut("agents")?.as_object_mut()?;
            apply_checkbox_mutation(agents, agent_id, enabled, &disables)?;
        }
        ("option", option_path) => {
            let (agent_id, option_key) = option_path.split_once('/')?;
            if agent_id.is_empty()
                || option_key.is_empty()
                || option_key.contains('/')
                || !agent_id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                || !option_key
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return None;
            }
            let option = ctx.known_options.get(agent_id)?.get(option_key)?;
            if option.option_type != "enum" || !option.values.contains(raw) {
                log::err(
                    "agent-events",
                    &format!(
                        "request {request_id} referenced unknown enum value {agent_id}/{option_key}"
                    ),
                );
                return None;
            }
            let agents = object.get_mut("agents")?.as_object_mut()?;
            let options = agents
                .get_mut(agent_id)?
                .as_object_mut()?
                .get_mut("options")?
                .as_object_mut()?;
            // Only this signed enum key changes. Checkbox conflict relations
            // are intentionally unaffected by an option selection.
            options.insert(option_key.to_string(), Value::String(raw.to_string()));
        }
        _ => return None,
    }
    validate_document_for_context(&root, ctx)?;
    // Publish the session fence before canonical intent. A poll between the
    // two publications must still retain the currently active startup mode.
    let session = if event_type == "radio" && key == "voboost-startup" && settings_wire {
        let previous: Value = serde_json::from_slice(&bytes).ok()?;
        let previous = serde_json::from_value(previous.get("startup")?.clone()).ok()?;
        Some(crate::startup_session::defer_at(path.parent()?, previous).ok()?)
    } else {
        None
    };
    if let Err(error) = writer(path, &root) {
        if let Some(session) = session {
            // Atomic rename may have succeeded before directory fsync failed.
            // Only a proven unchanged canonical document permits rollback.
            // New or unreadable bytes retain the fence and never apply none
            // mid-session. The same generation guard is still held here.
            if crate::plan::read_canonical_bounded(path).is_ok_and(|current| current == bytes) {
                if let Err(rollback) = session.rollback() {
                    log::err(
                        "agent-events",
                        &format!("startup session rollback failed: {rollback}"),
                    );
                }
            }
        }
        log::err(
            "agent-events",
            &format!("agents.json mutation failed: {error}"),
        );
        return None;
    }
    if startup_escalation_wire {
        if let Err(error) = crate::startup_session::clear_at(path.parent()?) {
            log::err("agent-events", &format!("startup recovery fence: {error}"));
            return None;
        }
    }
    drop(_guard);
    // The request counts as processed only after the successful commit.
    {
        if let Ok(mut cache) = committed_requests().lock() {
            cache.remember(ctx.endpoint_epoch, request_id, fingerprint);
        }
    }
    mark_confirmed_pending(ctx, reply_fd, request_id);
    log::debug(
        "agent-events",
        &format!("accepted request {request_id} for {key}"),
    );
    Some(1)
}

fn restart_request(rest: &str) -> Option<(u64, i64)> {
    let mut parts = rest.splitn(4, '|');
    let request = parts.next()?.parse().ok()?;
    if parts.next()? != "runtime" || parts.next()? != "restart" {
        return None;
    }
    let revision = parts.next()?.strip_prefix("process:")?.parse().ok()?;
    Some((request, revision))
}

fn apply_checkbox_mutation(
    agents: &mut serde_json::Map<String, Value>,
    agent_id: &str,
    enabled: bool,
    disables: &[String],
) -> Option<()> {
    let agent = agents.get_mut(agent_id)?.as_object_mut()?;
    agent.insert("enabled".into(), Value::Bool(enabled));
    if enabled {
        for disabled in disables {
            if let Some(conflict) = agents.get_mut(disabled) {
                conflict
                    .as_object_mut()?
                    .insert("enabled".into(), Value::Bool(false));
            }
        }
    }
    Some(())
}

/// Strict structural validation of the mutated full snapshot before commit:
/// supported schemaVersion, known enums, agent entries shaped
/// `{enabled: bool, options: object}` with bounded size. Mirrors the strict
/// schema in plan.rs; unknown/duplicate JSON keys are impossible here because
/// the document was produced by serde from the previously validated file.
fn validate_document(root: &Value) -> Option<()> {
    let object = root.as_object()?;
    if object.len() != 3 {
        return None;
    }
    if object.get("schemaVersion") != Some(&Value::from(1u64)) {
        return None;
    }
    match object.get("startup")?.as_str()? {
        "none" | "hidden" | "interface" => {}
        _ => return None,
    }
    let agents = object.get("agents")?.as_object()?;
    if agents.len() > 1024 {
        return None;
    }
    for (id, entry) in agents {
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return None;
        }
        let entry = entry.as_object()?;
        if entry.len() != 2
            || !entry.get("enabled")?.is_boolean()
            || !entry.get("options")?.is_object()
        {
            return None;
        }
    }
    if serde_json::to_vec(root).ok()?.len() > config::MAX_PLAN_BYTES {
        return None;
    }
    Some(())
}

/// Validate every present canonical agent and option against the same signed,
/// selected catalog surface that authorized the endpoint. This keeps a
/// Settings mutation from republishing an unrelated malformed option already
/// present in the complete document.
fn validate_document_for_context(
    root: &Value,
    ctx: &crate::agent_log::EndpointContext,
) -> Option<()> {
    validate_document(root)?;
    let agents = root.get("agents")?.as_object()?;
    for (agent_id, entry) in agents {
        if !ctx.known_agents.contains_key(agent_id) {
            return None;
        }
        let options = entry.get("options")?.as_object()?;
        if agent_id == "launcher" {
            crate::launcher_config::valid_options(entry.get("options")?).then_some(())?;
            continue;
        }
        let known = ctx.known_options.get(agent_id);
        if options.len() != known.map_or(0, HashMap::len) {
            return None;
        }
        for (key, value) in options {
            let option = known?.get(key)?;
            if option.option_type != "enum" || !option.values.contains(value.as_str()?) {
                return None;
            }
        }
    }
    Some(())
}

fn write_atomic(path: &std::path::Path, value: &Value) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    let expected = crate::plan::read_canonical_bounded(path).map_err(|e| e.to_string())?;
    crate::plan::replace_canonical(path, Some(expected), &bytes)
}

/// Take the shared short kernel mutation lock for one canonical plan RMW.
/// The lock is the same `operation.lock` every generation, product and CLI
/// startup writer takes, so cooperating writers cannot lose each other's
/// committed fields. An in-flight install/update/uninstall or another
/// writer reports busy; the caller rejects the event without an ACK.
fn mutation_lock_at(
    root: &std::path::Path,
) -> Result<crate::operation_contract::GenerationGuard, String> {
    crate::operation_contract::GenerationGuard::acquire_in(root)
}

#[cfg(test)]
#[path = "agent_events.test.rs"]
mod tests;
