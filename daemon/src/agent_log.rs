// agent_log.rs — unified typed agent-pipe drain (L/W/R/E/S records).
//
// The implant creates a single pipe inside the target process and writes
// typed, `\n`-terminated records into it. The root injector duplicates the
// read-end through /proc/<pid>/fd and keeps that daemon-owned duplicate in the
// ProcessTracker keyed by pid. The poll loop drains it here and routes each
// record by its one-letter type prefix (persistence-design §6):
//
//   "L|<ts_ms>|<source>|<level>|<message>\n"   → route_log    → canonical severity tiers
//   "W|<ts_ms>|<source>|<key>|<value>\n"        → route_state  → state/<key>.json
//   "R|<request_id>|<source>|<key>\n"           → route_read   → reply pipe
//   "E|<request_id>|<source>|<eventType>|<payload>\n" → canonical mutation route
//   "S|<ts_ms>|<process>|snapshot|<json>\n"      → runtime status registry
//   "Q|<operation>|<request_id>|<json>\n"         → capability-scoped logs RPC
//
// `drain` is format-independent pipe-buffer management: it reads bytes,
// accumulates them into the per-process buffer, splits on '\n', and hands each
// complete line to `parse_and_route`, which splits off the type prefix on the
// first '|' and dispatches. The type-specific payload is parsed inside each
// route_* handler (splitn 4, so the last field absorbs any embedded '|').
//
// Embedded '\n' are rewritten to '\r' by the implant so the daemon's split on
// '\n' yields exactly one record per line; route_log restores '\r' → '\n' in
// the message. The read-end is non-blocking: the daemon drains everything
// available within a fixed batch, yielding even when producers keep writing. See agent-logging /
// persistence-design specs.

use crate::agent_events;
use crate::agent_state;
use crate::log;
use std::collections::{HashMap, HashSet};

/// Immutable capability context of one pipe endpoint, built by the daemon
/// from the tracker (PID/process) and the resident desired document (selected
/// agent ids). Every record type is authorized against this context BEFORE
/// any storage or control-plane action: an agent-controlled `source` or
/// `process` string in the frame can never widen the endpoint's rights
/// (docs/developer/logs and docs/developer/contracts).
#[derive(Clone, Debug, Default)]
pub struct EndpointContext {
    pub owner_started: Option<std::time::Instant>,
    pub pid: i32,
    pub process: String,
    pub endpoint_epoch: u64,
    /// Verified native load identity frozen on this exact endpoint registration.
    pub log_generation: Option<(String, String)>,
    /// Attested starttime only for the exact PID/process/epoch registration.
    pub target_starttime: Option<u64>,
    /// Daemon desired-context revision; this does not assert agent application.
    pub document_generation: Option<i64>,
    /// Current desired revision removed an agent on this exact old endpoint.
    pub restart_allowed: bool,
    /// State-only authority retained while an admitted removed agent cleans up.
    pub retiring_state: Option<RetiringState>,
    /// Agents actually resident on this endpoint and therefore allowed to emit
    /// capability-scoped L/W/R records. During uninstall cleanup this remains
    /// the pre-disable resident set while `agents` below becomes the empty
    /// desired set required by the cleanup status acknowledgement.
    pub resident_agents: HashSet<String>,
    /// Agents expected in the latest desired/status document.
    pub agents: HashSet<String>,
    /// Complete selected set from the authenticated active catalog. The Logs
    /// capability uses this only to validate cross-process agent-ID filters.
    pub selected_agents: HashSet<String>,
    /// Exact immutable identity loaded by this resident runtime.
    pub resident_generation_id: String,
    pub resident_catalog_sha256: String,
    /// Exact active identity against which canonical `agents.json` is
    /// validated. Settings mutations fail closed unless both identities match.
    pub active_generation_id: String,
    pub active_catalog_sha256: String,
    /// Signed active-catalog checkbox relations. This is endpoint-scoped so a
    /// passive generation cutover cannot silently replace the validation view
    /// underneath an old resident endpoint.
    pub known_agents: HashMap<String, Vec<String>>,
    /// Signed active-catalog enum options for selected (supported or explicit
    /// unknown) agents. Settings option events are authorized only by this
    /// exact endpoint-scoped surface.
    pub known_options: HashMap<String, HashMap<String, KnownOption>>,
    /// Daemon-computed authority sources for the one-line startup escalation
    /// (radio voboost-startup:interface from hidden): the catalog executors
    /// injected into the settings-host process. Empty for every other
    /// process, and never widened by any agent-controlled frame field.
    pub startup_escalation_sources: HashSet<String>,
}

/// Exact endpoint-scoped, bounded cleanup authority; never used for L/S/E/restart.
#[derive(Clone, Debug)]
pub struct RetiringState {
    pub process: String,
    pub binding: crate::status::EndpointBinding,
    pub sources: HashSet<String>,
    pub expires: std::time::Instant,
    pub revoked: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl RetiringState {
    pub(crate) fn permits_retirement(&self, ctx: &EndpointContext, source: &str) -> bool {
        use std::sync::atomic::Ordering;
        if self.revoked.load(Ordering::Acquire)
            || self.expires <= std::time::Instant::now()
            || self.process != ctx.process
            || !self.sources.contains(source)
            || crate::control_plane::endpoint_binding(ctx).as_ref() != Some(&self.binding)
        {
            return false;
        }
        let ids: Vec<String> = ctx.agents.iter().cloned().collect();
        if crate::control_plane::recovery_ready(
            &ctx.process,
            &self.binding,
            ctx.document_generation.unwrap_or(-1),
            &ctx.resident_generation_id,
            &ctx.resident_catalog_sha256,
            &ids,
        ) {
            self.revoked.store(true, Ordering::Release);
            return false;
        }
        true
    }
}

#[derive(Clone, Debug, Default)]
pub struct KnownOption {
    pub option_type: String,
    pub values: HashSet<String>,
}

impl EndpointContext {
    /// True when the settings agent is resident on this endpoint: the only
    /// source allowed to submit Settings `E` mutations.
    pub fn settings_allowed(&self) -> bool {
        self.resident_agents.contains("settings")
    }

    pub fn settings_generation_is_active(&self) -> bool {
        !self.resident_generation_id.is_empty()
            && !self.resident_catalog_sha256.is_empty()
            && self.resident_generation_id == self.active_generation_id
            && self.resident_catalog_sha256 == self.active_catalog_sha256
    }

    /// Narrow startup-escalation authority: only an executor the daemon
    /// actually injects into the settings-host process (in hidden mode that is
    /// the gesture host ui-qinggan) may submit the startup escalation line.
    pub fn startup_escalation_allowed(&self, source: &str) -> bool {
        self.startup_escalation_sources.contains(source)
    }

    pub fn owns_agent(&self, source: &str) -> bool {
        self.resident_agents.contains(source)
    }

    pub fn owns_state(&self, source: &str, key: &str, value: Option<&serde_json::Value>) -> bool {
        if self.owns_agent(source) {
            return true;
        }
        // Cross-agent shared-state endorsement: the steering media agents run
        // in the keymanager host and coordinate with media-apps through the
        // ONE durable media-selected-package pair (the media-apps owner stays
        // the value's identity; steering is a co-signer, never a new owner).
        // The endorsement is granted only where a steering media agent is
        // actually resident (their only target process), so a plain endpoint
        // without steering keeps the strict resident-only rule.
        if source == "media-apps"
            && key == "media-selected-package"
            && (self.resident_agents.contains("steering-media-app-switcher")
                || self.resident_agents.contains("steering-media-session"))
        {
            return true;
        }
        let terminal = matches!(
            (source, key, value),
            (
                "vehicle-drive-forced-ev",
                "forced-ev-lifecycle-active" | "forced-ev-armed",
                None | Some(serde_json::Value::Bool(false))
            ) | (
                "vehicle-drive-forced-ev",
                "forced-ev-disarm-pending",
                None | Some(serde_json::Value::Bool(_))
            ) | (
                "vehicle-drive-pedestrian-warning",
                "pedestrian-warning-clean-stop-pending-reconcile",
                None | Some(serde_json::Value::Bool(true))
            )
        );
        terminal
            && self
                .retiring_state
                .as_ref()
                .is_some_and(|token| token.permits_retirement(self, source))
    }

    pub fn matches_process(&self, process: &str) -> bool {
        !self.process.is_empty() && self.process == process
    }
}

/// Drain one bounded batch from a read-end fd, accumulate into the
/// per-process buffer, split on '\n', and route each complete typed record via
/// `parse_and_route`. Incomplete trailing bytes stay in the buffer for next
/// pass. Returns the number of complete records routed.
pub fn drain(
    read_fd: i32,
    reply_fd: Option<i32>,
    state: &mut DrainState,
    context: &EndpointContext,
) -> usize {
    drain_with_policy(read_fd, reply_fd, state, context, true)
}

/// A native worker may preserve failure diagnostics, but cannot route state,
/// status, receipts, mutations or replies before the synchronous owner adopts it.
pub(crate) fn drain_diagnostics(read_fd: i32, state: &mut DrainState) -> usize {
    let context = EndpointContext::default();
    drain_bytes(
        |chunk| {
            let n = unsafe { libc::read(read_fd, chunk.as_mut_ptr().cast(), chunk.len()) };
            let error = std::io::Error::last_os_error().raw_os_error();
            if n == 0 || (n < 0 && !matches!(error, Some(libc::EAGAIN) | Some(libc::EINTR))) {
                crate::control_plane::forget_agent_status(&context.process);
                crate::launcher_config::forget_endpoint(context.endpoint_epoch);
            }
            n
        },
        state,
        |line| {
            std::str::from_utf8(line)
                .ok()
                .and_then(|line| line.strip_prefix("L|"))
                .and_then(|record| route_log(record, &context))
                .unwrap_or(0)
        },
    )
}

/// Drain diagnostics/state/status during uninstall preparation while rejecting
/// every Settings mutation before canonical/cache/pending-ACK side effects.
pub fn drain_uninstall_preparing(
    read_fd: i32,
    reply_fd: Option<i32>,
    state: &mut DrainState,
    context: &EndpointContext,
) -> usize {
    drain_with_policy(read_fd, reply_fd, state, context, false)
}

fn drain_with_policy(
    read_fd: i32,
    reply_fd: Option<i32>,
    state: &mut DrainState,
    context: &EndpointContext,
    mutations_allowed: bool,
) -> usize {
    let _logs = crate::canonical_log::begin_uplink_batch();
    drain_bytes(
        |chunk| {
            let n = unsafe { libc::read(read_fd, chunk.as_mut_ptr().cast(), chunk.len()) };
            let error = std::io::Error::last_os_error().raw_os_error();
            if n == 0 || (n < 0 && !matches!(error, Some(libc::EAGAIN) | Some(libc::EINTR))) {
                crate::control_plane::forget_agent_status(&context.process);
                crate::launcher_config::forget_endpoint(context.endpoint_epoch);
            }
            n
        },
        state,
        |line| parse_and_route_with_policy(line, reply_fd, context, mutations_allowed).unwrap_or(0),
    )
}

const MAX_DRAIN_READS: usize = 8;

fn drain_bytes(
    mut read: impl FnMut(&mut [u8]) -> isize,
    state: &mut DrainState,
    mut route: impl FnMut(&[u8]) -> usize,
) -> usize {
    let mut chunk = [0u8; 8192];
    let mut records = 0usize;

    for _ in 0..MAX_DRAIN_READS {
        let n = read(&mut chunk);
        if n <= 0 {
            break; // EAGAIN (non-blocking) or EOF/error — done for this pass
        }
        state.feed(&chunk[..n as usize], |line| {
            records += route(line);
        });
    }

    records
}

const MAX_DRAIN_RECORD_BYTES: usize = 256 * 1024;

#[derive(Default)]
pub struct DrainState {
    pending: Vec<u8>,
    discarding_oversize: bool,
}

impl DrainState {
    fn feed<F>(&mut self, bytes: &[u8], mut consume: F)
    where
        F: FnMut(&[u8]),
    {
        for &byte in bytes {
            if self.discarding_oversize {
                if byte == b'\n' {
                    self.discarding_oversize = false;
                }
                continue;
            }
            if byte == b'\n' {
                consume(&self.pending);
                self.pending.clear();
                continue;
            }
            if self.pending.len() == MAX_DRAIN_RECORD_BYTES {
                self.pending.clear();
                self.discarding_oversize = true;
                continue;
            }
            self.pending.push(byte);
        }
    }
}

/// Parse one strict UTF-8 typed record: split off the leading `<type>|` and
/// dispatch the rest to the matching route. Returns what the route returns
/// (typically `Some(1)` when the record was parsed and routed), or `None` for
/// an unknown type / malformed prefix.
#[cfg(test)]
fn parse_and_route(line: &[u8], reply_fd: Option<i32>, ctx: &EndpointContext) -> Option<usize> {
    parse_and_route_with_policy(line, reply_fd, ctx, true)
}

fn parse_and_route_with_policy(
    line: &[u8],
    reply_fd: Option<i32>,
    ctx: &EndpointContext,
    mutations_allowed: bool,
) -> Option<usize> {
    let s = std::str::from_utf8(line).ok()?;
    let (typ, rest) = s.split_once('|')?;
    match typ {
        "B" => crate::bootstrap_worker::observe(rest, ctx.pid, ctx.endpoint_epoch).then_some(1),
        "C" => crate::icon_quiescence::observe(rest, ctx),
        "P" => crate::launcher_page::observe(rest, ctx),
        "L" => route_log(rest, ctx),
        "W" => agent_state::route_state(rest, ctx),
        "R" => agent_state::route_read(rest, reply_fd?, ctx),
        "X" => agent_state::route_clear(rest, reply_fd?, ctx),
        "E" => agent_events::route_events(rest, ctx, reply_fd, mutations_allowed),
        "S" if crate::bootstrap_worker::ready_allowed(ctx.pid, ctx.endpoint_epoch) => {
            route_status(rest, ctx)
        }
        "Q" => route_logs(rest, reply_fd?, ctx),
        other => {
            log::debug(
                "agent-pipe",
                &format!("skipping unknown record type {other:?}"),
            );
            None
        }
    }
}

fn route_logs(rest: &str, reply_fd: i32, ctx: &EndpointContext) -> Option<usize> {
    let mut parts = rest.splitn(3, '|');
    let operation = parts.next()?;
    let request_id = parts.next()?;
    let request_json = parts.next()?;
    let response = crate::canonical_log::dispatch_agent_rpc(
        operation,
        request_id,
        request_json,
        &ctx.resident_agents,
        &ctx.selected_agents,
    )
    .ok()?;
    let frame = format!("Q|{request_id}|ok|{response}\n");
    if frame.len() > crate::config::MAX_DOWNLINK_FRAME_BYTES
        || !crate::downlink::enqueue_frame(reply_fd, frame.as_bytes())
    {
        return None;
    }
    Some(1)
}

fn route_status(rest: &str, ctx: &EndpointContext) -> Option<usize> {
    let mut parts = rest.splitn(4, '|');
    let _ts_ms: u64 = parts.next()?.parse().ok()?;
    let process = parts.next()?;
    // Capability check: a snapshot is only accepted for the process that
    // owns this endpoint; frames naming another process fail closed.
    if !ctx.matches_process(process) {
        return None;
    }
    if process.is_empty()
        || process.len() > 255
        || !process
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
    {
        return None;
    }
    if parts.next()? != "snapshot" {
        return None;
    }
    let document = parts.next()?;
    if document.len() > crate::config::MAX_AGENT_STATUS_BYTES {
        return None;
    }
    let _: serde_json::Value = serde_json::from_str(document).ok()?;
    if !crate::control_plane::status_envelope_matches(
        document.as_bytes(),
        process,
        &ctx.resident_generation_id,
        &ctx.resident_catalog_sha256,
        &ctx.agents,
    ) {
        return None;
    }
    // Keep the snapshot in the daemon's in-memory registry; the aggregate
    // root status.json is the only persisted surface (docs/developer/logs).
    crate::control_plane::accept_agent_status(ctx, document.as_bytes()).then_some(1)
}

/// Route one `L` (log) record's payload: `<ts_ms>|<source>|<level>|<message>`
/// (splitn 4 — the message absorbs any embedded '|'). '\r' in the message is
/// restored to '\n'. Returns `Some(1)` if forwarded, `None` if the shape was
/// bad (unparseable ts/level).
fn route_log(rest: &str, ctx: &EndpointContext) -> Option<usize> {
    let mut parts = rest.splitn(4, '|');
    let ts_ms: u64 = parts.next()?.parse().ok()?;
    let source = parts.next()?;
    if source.is_empty() {
        return None;
    }
    let level: i32 = parts.next()?.parse().ok()?;
    let mut message = parts.next().unwrap_or("").to_string();
    // Restore embedded newlines the implant rewrote to '\r'.
    if message.contains('\r') {
        message = message.replace('\r', "\n");
    }
    if message
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
    {
        return None;
    }
    // Frame content cannot contribute authority fields. Unknown loader sources
    // and pre-registration diagnostics remain deliberately unattributed.
    let mut fields = root_log_fields(source, ctx, crate::control_plane::daemon_identity());
    let owned_source = ctx.owns_agent(source).then_some(source);
    if owned_source.is_none() {
        fields.insert("declaredSource".into(), source.to_string());
    }
    log::agent(ts_ms, owned_source, level, &message, fields);
    Some(1)
}

fn root_log_fields(
    source: &str,
    ctx: &EndpointContext,
    identity: Option<crate::control_plane::DaemonIdentity>,
) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    if ctx.owns_agent(source) && ctx.pid > 0 && ctx.endpoint_epoch > 0 {
        if let Some(starttime) = ctx.target_starttime {
            fields.insert("process".into(), ctx.process.clone());
            fields.insert("targetPid".into(), ctx.pid.to_string());
            fields.insert("targetStarttime".into(), starttime.to_string());
            fields.insert("endpointEpoch".into(), ctx.endpoint_epoch.to_string());
            if let Some(revision) = ctx.document_generation {
                // This is the current daemon desired context, never an applied ACK.
                fields.insert("desiredDocumentGeneration".into(), revision.to_string());
            }
            if let Some(identity) = identity {
                fields.insert("daemonPid".into(), identity.daemon_pid);
                fields.insert("daemonStarttime".into(), identity.daemon_starttime);
                fields.insert("bootId".into(), identity.boot_id);
            }
            if let Some((generation, catalog)) = &ctx.log_generation {
                fields.insert("generationId".into(), generation.clone());
                fields.insert("catalogSha256".into(), catalog.clone());
            }
        }
    }
    fields
}

/// Close a read-end fd (called by ProcessTracker on process death / clear).
pub fn close_fd(fd: i32) {
    unsafe {
        libc::close(fd);
    }
}

/// Per-pid accumulation buffers for the drain pass (incomplete tail bytes).
/// Keyed by read-end fd so a reused pid with a new pipe does not mix buffers.
#[derive(Default)]
pub struct DrainBuffers {
    bufs: HashMap<i32, DrainState>,
}

impl DrainBuffers {
    pub fn get_or_insert(&mut self, fd: i32) -> &mut DrainState {
        self.bufs.entry(fd).or_default()
    }

    /// Drop buffers whose fds are no longer tracked. This prevents an
    /// incomplete record from being attached to a later pipe that reuses the
    /// same numeric fd.
    pub fn retain_active(&mut self, active: &std::collections::HashSet<i32>) {
        self.bufs.retain(|fd, _| active.contains(fd));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_authority_binds_same_daemon_incarnation_and_desired_context_without_claiming_ack() {
        let fixtures: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/current-endpoint146.json"))
                .unwrap();
        let expected = &fixtures["routedLogMeta"];
        let text = |key: &str| expected[key].as_str().unwrap().to_string();
        let mut ctx = ctx_settings();
        ctx.pid = expected["targetPid"].as_str().unwrap().parse().unwrap();
        ctx.process = text("process");
        ctx.endpoint_epoch = expected["endpointEpoch"].as_str().unwrap().parse().unwrap();
        ctx.target_starttime = Some(
            expected["targetStarttime"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
        );
        ctx.document_generation = Some(
            expected["desiredDocumentGeneration"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
        );
        ctx.log_generation = Some((text("generationId"), text("catalogSha256")));
        let identity = crate::control_plane::DaemonIdentity {
            daemon_pid: text("daemonPid"),
            daemon_starttime: text("daemonStarttime"),
            boot_id: text("bootId"),
        };
        let fields = root_log_fields("settings", &ctx, Some(identity.clone()));
        assert_eq!(serde_json::to_value(&fields).unwrap(), *expected);
        assert!(!fields.contains_key("documentGeneration"));
        assert!(!fields.contains_key("acceptedDocumentGeneration"));
        assert!(root_log_fields("unowned", &ctx, Some(identity)).is_empty());
        let unavailable = root_log_fields("settings", &ctx, None);
        assert!(!unavailable.contains_key("daemonPid"));
        assert!(!unavailable.contains_key("bootId"));
    }

    #[test]
    fn uplink_eof_revokes_current_status_but_would_block_keeps_it() {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        let mut ctx = ctx_settings();
        ctx.process = "com.example.endpoint146-disconnect".into();
        ctx.agents.clear();
        ctx.log_generation = Some(("generation".into(), "catalog".into()));
        ctx.target_starttime = Some(888);
        ctx.document_generation = Some(17);
        let document = serde_json::json!({"schemaVersion":1,"process":ctx.process,"generationId":"generation","catalogSha256":"catalog","documentGeneration":17,"agents":[]});
        let (reader, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        writeln!(writer, "S|1|{}|snapshot|{}", ctx.process, document).unwrap();
        let mut state = DrainState::default();
        assert_eq!(drain(reader.as_raw_fd(), None, &mut state, &ctx), 1);
        assert_eq!(
            crate::control_plane::observed_document_generation(
                &ctx.process,
                "generation",
                "catalog",
                &[]
            ),
            Some(17)
        );
        writer.shutdown(std::net::Shutdown::Write).unwrap();
        drain(reader.as_raw_fd(), None, &mut state, &ctx);
        assert_eq!(
            crate::control_plane::observed_document_generation(
                &ctx.process,
                "generation",
                "catalog",
                &[]
            ),
            None
        );
    }

    #[test]
    fn current_status_requires_registered_birth_generation_and_actual_desired_ack() {
        let mut ctx = ctx_settings();
        ctx.process = "com.example.endpoint146-route".into();
        ctx.log_generation = Some(("generation".into(), "catalog".into()));
        ctx.target_starttime = Some(888);
        ctx.document_generation = Some(17);
        ctx.agents = HashSet::from(["forced-ev".into()]);
        let document = serde_json::json!({"schemaVersion":1,"process":ctx.process,"generationId":"generation","catalogSha256":"catalog","documentGeneration":17,"agents":[{"id":"forced-ev","lifecycleGeneration":1,"state":"active","reason":"ready","details":{}}]});
        let line = format!("1|{}|snapshot|{}", ctx.process, document);
        assert_eq!(route_status(&line, &ctx), Some(1));
        ctx.document_generation = Some(18);
        assert_eq!(route_status(&line, &ctx), None);
        ctx.document_generation = Some(17);
        ctx.target_starttime = None;
        assert_eq!(route_status(&line, &ctx), None);
        ctx.target_starttime = Some(888);
        ctx.log_generation = Some(("other".into(), "catalog".into()));
        assert_eq!(route_status(&line, &ctx), None);
        crate::control_plane::forget_agent_status(&ctx.process);
    }

    #[test]
    fn continuously_readable_uplink_yields_and_retains_partial_record() {
        let mut state = DrainState::default();
        let mut reads = 0;
        let mut delivered = Vec::new();
        let count = drain_bytes(
            |buffer| {
                reads += 1;
                if reads > MAX_DRAIN_READS + 1 {
                    return 0;
                }
                let bytes = if reads == 1 {
                    &b"first\npar"[..]
                } else {
                    &b"t"[..]
                };
                buffer[..bytes.len()].copy_from_slice(bytes);
                bytes.len() as isize
            },
            &mut state,
            |line| {
                delivered.push(line.to_vec());
                1
            },
        );
        assert_eq!(reads, MAX_DRAIN_READS);
        assert_eq!(count, 1);
        assert_eq!(delivered, [b"first".to_vec()]);
        let mut chunks = [b"ial\nnext\n".as_slice()].into_iter();
        assert_eq!(
            drain_bytes(
                |buffer| match chunks.next() {
                    Some(bytes) => {
                        buffer[..bytes.len()].copy_from_slice(bytes);
                        bytes.len() as isize
                    }
                    None => 0,
                },
                &mut state,
                |line| {
                    delivered.push(line.to_vec());
                    1
                },
            ),
            2
        );
        let mut continued = b"par".to_vec();
        continued.extend(std::iter::repeat_n(b't', MAX_DRAIN_READS - 1));
        continued.extend_from_slice(b"ial");
        assert_eq!(delivered, [b"first".to_vec(), continued, b"next".to_vec()]);
        assert!(state.pending.is_empty());
    }

    fn ctx_settings() -> EndpointContext {
        EndpointContext {
            owner_started: None,
            pid: 42,
            process: "com.qinggan.app.setting".to_string(),
            endpoint_epoch: 1,
            log_generation: None,
            target_starttime: None,
            document_generation: None,
            restart_allowed: false,
            retiring_state: None,
            resident_agents: HashSet::from([
                "settings".to_string(),
                "vehicle-drive-forced-ev".to_string(),
            ]),
            agents: HashSet::from([
                "settings".to_string(),
                "vehicle-drive-forced-ev".to_string(),
            ]),
            selected_agents: HashSet::from([
                "settings".to_string(),
                "vehicle-drive-forced-ev".to_string(),
            ]),
            resident_generation_id: "generation".to_string(),
            resident_catalog_sha256: "catalog".to_string(),
            active_generation_id: "generation".to_string(),
            active_catalog_sha256: "catalog".to_string(),
            known_agents: HashMap::from([("vehicle-drive-forced-ev".to_string(), Vec::new())]),
            known_options: HashMap::new(),
            startup_escalation_sources: HashSet::from(["ui-qinggan".to_string()]),
        }
    }

    fn ctx_other_process() -> EndpointContext {
        EndpointContext {
            owner_started: None,
            pid: 7,
            process: "com.qinggan.media".to_string(),
            endpoint_epoch: 2,
            log_generation: None,
            target_starttime: None,
            document_generation: None,
            restart_allowed: false,
            retiring_state: None,
            resident_agents: HashSet::from(["media-apps".to_string()]),
            agents: HashSet::from(["media-apps".to_string()]),
            selected_agents: HashSet::from(["media-apps".to_string()]),
            resident_generation_id: "generation".to_string(),
            resident_catalog_sha256: "catalog".to_string(),
            active_generation_id: "generation".to_string(),
            active_catalog_sha256: "catalog".to_string(),
            known_agents: HashMap::new(),
            known_options: HashMap::new(),
            startup_escalation_sources: HashSet::new(),
        }
    }

    #[test]
    fn pipe_logs_keep_endpoint_authority_outside_forged_message() {
        let directory = tempfile::tempdir().unwrap();
        let logs = directory.path().join("logs");
        let mut ctx = ctx_settings();
        ctx.target_starttime = Some(1234);
        ctx.log_generation = Some(("native-generation".into(), "native-catalog".into()));
        let message = r#"{"targetPid":999,"generationId":"forged","snapshotSha256":"forged"}"#;
        crate::canonical_log::with_test_log(&logs, || {
            for epoch in [1, 2] {
                ctx.endpoint_epoch = epoch;
                let mut fds = [-1; 2];
                assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
                let frame = format!("L|1|settings|2|{message}\n");
                assert_eq!(
                    unsafe { libc::write(fds[1], frame.as_ptr().cast(), frame.len()) },
                    frame.len() as isize
                );
                close_fd(fds[1]);
                assert_eq!(drain(fds[0], None, &mut DrainState::default(), &ctx), 1);
                close_fd(fds[0]);
            }
            assert_eq!(
                parse_and_route(b"L|1|implant|2|raw", None, &EndpointContext::default()),
                Some(1)
            );
        });
        let records = crate::canonical_log::CanonicalLog::open(&logs)
            .unwrap()
            .query(&crate::canonical_log::Query {
                after_sequence: 0,
                limit: 200,
                levels: vec![],
                kinds: vec![],
                agent_ids: vec![],
                search: None,
                from_epoch_millis: 0,
                to_epoch_millis: u64::MAX,
            })
            .unwrap()
            .records;
        assert_eq!(records.len(), 3);
        for (record, epoch) in records[..2].iter().zip(["1", "2"]) {
            assert_eq!(record.fields["targetPid"], "42");
            assert_eq!(record.fields["process"], ctx.process);
            assert_eq!(record.fields["targetStarttime"], "1234");
            assert_eq!(record.fields["endpointEpoch"], epoch);
            assert_eq!(record.fields["generationId"], "native-generation");
            assert_eq!(record.fields["catalogSha256"], "native-catalog");
            assert_eq!(record.fields.len(), 8);
            assert_eq!(record.fields["producerTimestampMs"], "1");
            assert_eq!(record.fields["producerClock"], "unix");
            assert_eq!(record.message, message);
            assert!(!record.fields.contains_key("documentGeneration"));
            assert!(!record.fields.contains_key("snapshotSha256"));
        }
        assert_eq!(records[2].fields.len(), 3);
        assert_eq!(records[2].fields["declaredSource"], "implant");
        assert_eq!(records[2].fields["producerTimestampMs"], "1");
        assert_eq!(records[2].fields["producerClock"], "unix");
        assert!(!records[2].fields.contains_key("targetPid"));
    }

    #[test]
    fn pipe_logs_bind_only_owned_sources_and_preserve_multiline_errors() {
        let directory = tempfile::tempdir().unwrap();
        let logs = directory.path().join("logs");
        let mut ctx = ctx_settings();
        ctx.resident_agents.remove("vehicle-drive-forced-ev");
        ctx.agents.remove("vehicle-drive-forced-ev");
        crate::canonical_log::with_test_log(&logs, || {
            let mut fds = [-1; 2];
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            let frames = b"L|1|vehicle-drive-forced-ev|1|foreign diagnostic\nL|2|settings|1|first\rsecond\tcolumn\nL|3|settings|1|invalid\x01control\n";
            assert_eq!(
                unsafe { libc::write(fds[1], frames.as_ptr().cast(), frames.len()) },
                frames.len() as isize
            );
            close_fd(fds[1]);
            drain(fds[0], None, &mut DrainState::default(), &ctx);
            close_fd(fds[0]);
        });
        let logger = crate::canonical_log::CanonicalLog::open(&logs).unwrap();
        let mut query = crate::canonical_log::Query {
            after_sequence: 0,
            limit: 200,
            levels: vec![crate::canonical_log::Level::Error],
            kinds: vec![],
            agent_ids: vec![],
            search: None,
            from_epoch_millis: 0,
            to_epoch_millis: u64::MAX,
        };
        let rows = logger.query(&query).unwrap().records;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].source.kind, "daemon");
        assert_eq!(rows[0].source.id, None);
        assert_eq!(rows[0].fields["declaredSource"], "vehicle-drive-forced-ev");
        assert_eq!(rows[1].source.id.as_deref(), Some("settings"));
        assert_eq!(rows[1].message, "first\nsecond\tcolumn");
        query.agent_ids = vec!["vehicle-drive-forced-ev".into()];
        assert!(logger.query(&query).unwrap().records.is_empty());
        let errors = std::fs::read_to_string(logs.join("error/segment-active.jsonl")).unwrap();
        assert_eq!(errors.lines().count(), 2);
        assert!(!errors.contains("invalid"));
    }

    #[test]
    fn capability_gates_block_cross_endpoint_impersonation() {
        let ctx = ctx_other_process();
        // W under a foreign agent id (not resident on this endpoint).
        assert_eq!(
            parse_and_route(b"W|1723392000456|forced-ev|ivi-soc-modeset|5", None, &ctx),
            None
        );
        // R for a foreign agent's state.
        assert_eq!(
            parse_and_route(b"R|41|forced-ev|ivi-soc-modeset", None, &ctx),
            None
        );
        // E from an endpoint without the settings agent.
        assert_eq!(
            parse_and_route(b"E|5|settings|checkbox|forced-ev:true", None, &ctx),
            None
        );
        // S naming a different process.
        assert_eq!(
            parse_and_route(
                b"S|1723392000456|com.qinggan.app.setting|snapshot|{}",
                None,
                &ctx
            ),
            None
        );
        // The same W record from the owning endpoint is authorized (the
        // store write itself is host-dependent, so an unavailable host store
        // propagates failure). The positive E path
        // additionally requires the root agents.json and is exercised in the
        // agent_events suite.
        let settings = ctx_settings();
        assert_eq!(
            parse_and_route(
                b"W|1723392000456|forced-ev|ivi-soc-modeset|5",
                None,
                &settings
            ),
            None
        );
    }

    #[test]
    fn steering_endorses_the_shared_media_selected_package_pair_only() {
        // keymanager endpoint with the steering media agents resident: the
        // cross-agent endorsement allows the ONE shared pair, nothing wider.
        fn ctx_keymanager(switcher: bool, session: bool) -> EndpointContext {
            let mut residents = HashSet::new();
            if switcher {
                residents.insert("steering-media-app-switcher".to_string());
            }
            if session {
                residents.insert("steering-media-session".to_string());
            }
            EndpointContext {
                process: "com.qinggan.keymanager.service".to_string(),
                resident_agents: residents,
                ..ctx_other_process()
            }
        }
        let endorsed = ctx_keymanager(true, false);
        assert!(endorsed.owns_state("media-apps", "media-selected-package", None));
        let endorsed_session = ctx_keymanager(false, true);
        assert!(endorsed_session.owns_state("media-apps", "media-selected-package", None));
        // No steering resident: strict resident-only rule returns.
        let plain = ctx_keymanager(false, false);
        assert!(!plain.owns_state("media-apps", "media-selected-package", None));
        // The endorsement never widens to other keys or other sources.
        let narrow = ctx_keymanager(true, true);
        assert!(!narrow.owns_state("media-apps", "media-apps", None));
        assert!(!narrow.owns_state("launcher", "media-selected-package", None));
        // An endpoint WITHOUT steering keeps strict ownership even in the
        // media host process (media-apps resident there reads its own state
        // through the regular resident path, not through the endorsement).
        let media_host = ctx_other_process();
        assert!(!media_host.owns_state("launcher", "anything", None));
    }

    #[test]
    fn routes_log_record() {
        // L|<ts>|<source>|<level>|<message>. log::agent writes a file (not
        // observable here), but the route should parse and return Some(1).
        let line = b"L|1722600000123|forced-ev|2|hooked onCreate";
        assert_eq!(parse_and_route(line, None, &ctx_settings()), Some(1));
    }

    #[test]
    fn routes_state_record() {
        // S|<ts>|<source>|<key>|<value>. route_state writes to /data/... which
        // is absent on the dev machine, so the write failure propagates.
        let line = b"W|1723392000456|forced-ev|ivi-soc-modeset|5";
        assert_eq!(parse_and_route(line, None, &ctx_settings()), None);
    }

    #[test]
    fn routes_events_record() {
        // E|<request-id>|<source>|<eventType>|<payload=configKey:value>.
        // This endpoint is authorized for Settings but the source/id is not,
        // so the direct canonical mutation route rejects it.
        let line = b"E|1723392001000|untrusted|checkbox|forced-ev:true";
        assert_eq!(parse_and_route(line, None, &ctx_settings()), None);
    }

    #[test]
    fn uninstall_policy_keeps_resident_capabilities_and_routes_cleanup_status() {
        let mut ctx = ctx_settings();
        ctx.agents.clear();
        ctx.log_generation = Some(("generation".into(), "catalog".into()));
        ctx.target_starttime = Some(888);
        ctx.document_generation = Some(17);
        assert!(ctx.settings_allowed());
        assert!(ctx.owns_agent("settings"));
        let line = br#"S|1723392000456|com.qinggan.app.setting|snapshot|{"schemaVersion":1,"generationId":"generation","catalogSha256":"catalog","process":"com.qinggan.app.setting","documentGeneration":17,"agents":[]}"#;
        assert_eq!(
            parse_and_route_with_policy(line, None, &ctx, false),
            Some(1)
        );
    }

    #[test]
    fn unknown_type_is_skipped() {
        // An unknown type prefix must not panic; it returns None (dropped).
        assert_eq!(
            parse_and_route(b"X|123|src|stuff", None, &ctx_settings()),
            None
        );
        assert_eq!(parse_and_route(b"hello world", None, &ctx_settings()), None);
    }

    #[test]
    fn log_record_bad_shape_is_skipped() {
        // L with an unparseable level → None (malformed).
        assert_eq!(
            parse_and_route(b"L|1722600000123|src|notalevel|msg", None, &ctx_settings()),
            None
        );
        // L with an unparseable ts → None.
        assert_eq!(
            parse_and_route(b"L|notatime|src|2|msg", None, &ctx_settings()),
            None
        );
    }

    #[test]
    fn log_record_message_absorbs_pipes() {
        // splitn(4) — a message with '|' is kept whole.
        let line = b"L|1722600000123|forced-ev|2|a|b|c";
        assert_eq!(parse_and_route(line, None, &ctx_settings()), Some(1));
    }

    #[test]
    fn log_record_restores_embedded_newlines() {
        // '\r' → '\n' restoration happens inside route_log; verify it parses
        // without panic.
        let line = b"L|1722600000123|forced-ev|1|line1\rline2";
        assert_eq!(parse_and_route(line, None, &ctx_settings()), Some(1));
    }

    #[test]
    fn drops_buffers_for_closed_fds() {
        let mut buffers = DrainBuffers::default();
        buffers
            .get_or_insert(7)
            .feed(b"partial", |_| panic!("partial record routed"));
        buffers
            .get_or_insert(8)
            .feed(b"kept", |_| panic!("partial record routed"));
        buffers.retain_active(&std::collections::HashSet::from([8]));
        assert!(!buffers.bufs.contains_key(&7));
        assert_eq!(buffers.bufs.get(&8).unwrap().pending, b"kept");
    }

    #[test]
    fn per_fd_oversize_discards_exact_tail_through_newline() {
        let mut state = DrainState::default();
        let mut lines = Vec::new();
        state.feed(&vec![b'x'; MAX_DRAIN_RECORD_BYTES], |line| {
            lines.push(line.to_vec())
        });
        state.feed(b"y\xfftail", |line| lines.push(line.to_vec()));
        assert!(state.discarding_oversize);
        assert!(lines.is_empty());
        state.feed(b"-still-hostile\nL|1|settings|1|ok\n", |line| {
            lines.push(line.to_vec())
        });
        assert!(!state.discarding_oversize);
        assert_eq!(lines, vec![b"L|1|settings|1|ok".to_vec()]);
    }

    #[test]
    fn exact_record_bound_is_accepted_and_n_plus_one_is_discarded() {
        let mut exact = DrainState::default();
        let mut exact_lines = Vec::new();
        let mut bytes = vec![b'x'; MAX_DRAIN_RECORD_BYTES];
        bytes.push(b'\n');
        exact.feed(&bytes, |line| exact_lines.push(line.len()));
        assert_eq!(exact_lines, vec![MAX_DRAIN_RECORD_BYTES]);

        let mut over = DrainState::default();
        let mut over_lines = Vec::new();
        let mut bytes = vec![b'x'; MAX_DRAIN_RECORD_BYTES + 1];
        bytes.extend_from_slice(b"\nX|next\n");
        over.feed(&bytes, |line| over_lines.push(line.to_vec()));
        assert_eq!(over_lines, vec![b"X|next".to_vec()]);
    }

    #[test]
    fn invalid_utf8_record_is_rejected_without_affecting_next_record() {
        assert_eq!(
            parse_and_route(b"L|1|settings|1|bad\xff", None, &ctx_settings()),
            None
        );
        assert_eq!(
            parse_and_route(b"L|1|settings|1|good", None, &ctx_settings()),
            Some(1)
        );
    }
    fn retiring_context(name: &str) -> EndpointContext {
        let mut ctx = ctx_settings();
        ctx.process = format!("test.retiring.{name}");
        ctx.resident_generation_id = "a".repeat(64);
        ctx.resident_catalog_sha256 = "b".repeat(64);
        ctx.log_generation = Some((
            ctx.resident_generation_id.clone(),
            ctx.resident_catalog_sha256.clone(),
        ));
        ctx.target_starttime = Some(100);
        ctx.document_generation = Some(12);
        ctx.resident_agents.clear();
        ctx.agents.clear();
        ctx.retiring_state = Some(RetiringState {
            process: ctx.process.clone(),
            binding: crate::control_plane::endpoint_binding(&ctx).unwrap(),
            sources: HashSet::from(["vehicle-drive-forced-ev".into()]),
            expires: std::time::Instant::now() + std::time::Duration::from_secs(30),
            revoked: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        });
        ctx
    }

    #[test]
    fn retiring_state_is_terminal_only_and_not_other_capabilities() {
        let ctx = retiring_context("terminal");
        let source = "vehicle-drive-forced-ev";
        assert!(ctx.owns_state(
            source,
            "forced-ev-lifecycle-active",
            Some(&serde_json::json!(false))
        ));
        assert!(ctx.owns_state(source, "forced-ev-lifecycle-active", None));
        assert!(!ctx.owns_state(
            source,
            "forced-ev-lifecycle-active",
            Some(&serde_json::json!(true))
        ));
        assert!(!ctx.owns_state(source, "forced-ev-armed", Some(&serde_json::json!(true))));
        assert!(!ctx.owns_state(source, "new-key", Some(&serde_json::json!(false))));
        assert!(!ctx.owns_state("spoof", "forced-ev-lifecycle-active", None));
        assert!(!ctx.owns_agent(source));
        assert!(!ctx.settings_allowed());
        assert!(!ctx.startup_escalation_allowed(source));
        assert!(!ctx.restart_allowed);
    }

    #[test]
    fn retiring_state_fences_every_endpoint_identity_component_and_expiry() {
        let ctx = retiring_context("fences");
        for index in 0..6 {
            let mut stale = ctx.clone();
            match index {
                0 => stale.pid += 1,
                1 => stale.target_starttime = Some(101),
                2 => stale.endpoint_epoch += 1,
                3 => stale.document_generation = Some(13),
                4 => stale.resident_generation_id = "other".into(),
                _ => stale.resident_catalog_sha256 = "other".into(),
            }
            assert!(!stale.owns_state(
                "vehicle-drive-forced-ev",
                "forced-ev-lifecycle-active",
                None
            ));
        }
        let mut expired = ctx.clone();
        expired.retiring_state.as_mut().unwrap().expires = std::time::Instant::now();
        assert!(!expired.owns_state(
            "vehicle-drive-forced-ev",
            "forced-ev-lifecycle-active",
            None
        ));
    }

    #[test]
    fn retiring_state_current_ack_revokes_shared_batch_context_permanently() {
        let ctx = retiring_context("ack");
        let batch = ctx.clone();
        let source = "vehicle-drive-forced-ev";
        assert!(ctx.owns_state(source, "forced-ev-lifecycle-active", None));
        let binding = crate::control_plane::endpoint_binding(&ctx).unwrap();
        let receipt = crate::status::AcceptanceReceipt {
            sequence: "1".into(),
            daemon_pid: "100".into(),
            daemon_starttime: "1".into(),
            boot_id: "11111111-1111-1111-1111-111111111111".into(),
        };
        let document = serde_json::to_vec(&serde_json::json!({
            "schemaVersion":1, "process":ctx.process, "generationId":ctx.resident_generation_id,
            "catalogSha256":ctx.resident_catalog_sha256, "documentGeneration":12, "agents":[]
        }))
        .unwrap();
        assert!(crate::control_plane::accept_agent_status_with_receipt(
            &ctx.process,
            &document,
            binding,
            Some(receipt)
        ));
        assert!(!ctx.owns_state(source, "forced-ev-lifecycle-active", None));
        crate::control_plane::forget_agent_status(&ctx.process);
        assert!(!batch.owns_state(source, "forced-ev-lifecycle-active", None));
    }
}
