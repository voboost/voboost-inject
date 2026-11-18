// control_plane.rs — daemon-side handling of agent runtime status reports.
//
// All configuration and bootstrap delivery rides the per-process pipe (see
// bootstrap_pipe.rs and agent_events.rs). Runtime `S` snapshots arrive on the
// same pipe, are validated at drain time and kept in this in-memory registry
// keyed by process name; `aggregate_agent_status` folds them into the
// root-owned status.json. There is no shared status/config file and no
// process-load-descriptor writer anymore, and nothing in /data/voboost
// is readable by the target processes.

use std::collections::HashMap;
use std::fs;
use std::sync::{Mutex, OnceLock};

use serde::Deserialize;
use serde_json::Value;

use crate::config;
#[path = "pw_live.rs"]
pub mod pw_live;
#[path = "pw_transport.rs"]
pub mod pw_transport;
use crate::status::{AcceptanceReceipt, AcceptedStatus, EndpointBinding, InjectionState, Status};

pub const MAX_DOCUMENT_GENERATION: i64 = i64::MAX - 2;

/// In-memory registry of the latest validated `S` snapshot per process.
/// Daemon-lifetime state only: after a daemon restart the map is empty until
/// each resident endpoint sends its next snapshot (docs/developer/contracts).
#[derive(Clone)]
struct Snapshot {
    startup_receipt_times: HashMap<String, (Value, u64)>,
    document: Vec<u8>,
    binding: Option<EndpointBinding>,
}

fn status_snapshots() -> &'static Mutex<HashMap<String, Snapshot>> {
    static SNAPSHOTS: OnceLock<Mutex<HashMap<String, Snapshot>>> = OnceLock::new();
    SNAPSHOTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Unbound fixture snapshots never authorize aggregate active status.
#[cfg(test)]
pub fn store_agent_status(process: &str, document: &[u8]) {
    if let Ok(mut snapshots) = status_snapshots().lock() {
        snapshots.insert(
            process.to_string(),
            Snapshot {
                startup_receipt_times: HashMap::new(),
                document: document.to_vec(),
                binding: None,
            },
        );
    }
}

/// Drop the stored snapshot for a dead/re-injected process.
pub fn forget_agent_status(process: &str) {
    if let Ok(mut snapshots) = status_snapshots().lock() {
        snapshots.remove(process);
    }
}

/// Read the latest stored snapshot for `process`, if any.
fn read_agent_status(process: &str) -> Option<Vec<u8>> {
    status_snapshots().lock().ok().and_then(|snapshots| {
        snapshots
            .get(process)
            .map(|snapshot| snapshot.document.clone())
    })
}

/// Actual daemon incarnation shared by accepted S receipts and routed L metadata.
#[derive(Clone)]
pub(crate) struct DaemonIdentity {
    pub daemon_pid: String,
    pub daemon_starttime: String,
    pub boot_id: String,
}

pub(crate) fn daemon_identity() -> Option<DaemonIdentity> {
    let pid = std::process::id() as i32;
    let starttime = crate::target_identity::read_starttime(pid).ok()?;
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let boot_id = boot_id.trim();
    if boot_id.is_empty() {
        return None;
    }
    Some(DaemonIdentity {
        daemon_pid: pid.to_string(),
        daemon_starttime: starttime.to_string(),
        boot_id: boot_id.to_string(),
    })
}

/// Root receipt is independent of agent timestamps and retained log queues.
fn acceptance_receipt() -> Option<AcceptanceReceipt> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQUENCE: AtomicU64 = AtomicU64::new(1);
    let identity = daemon_identity()?;
    let sequence = SEQUENCE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .ok()?;
    Some(AcceptanceReceipt {
        sequence: sequence.to_string(),
        daemon_pid: identity.daemon_pid,
        daemon_starttime: identity.daemon_starttime,
        boot_id: identity.boot_id,
    })
}

pub fn endpoint_binding(ctx: &crate::agent_log::EndpointContext) -> Option<EndpointBinding> {
    let (generation, catalog) = ctx.log_generation.as_ref()?;
    if ctx.pid <= 1
        || ctx.endpoint_epoch == 0
        || ctx.target_starttime == Some(0)
        || generation.is_empty()
        || catalog.is_empty()
        || generation != &ctx.resident_generation_id
        || catalog != &ctx.resident_catalog_sha256
    {
        return None;
    }
    Some(EndpointBinding {
        target_pid: ctx.pid.to_string(),
        target_starttime: ctx.target_starttime?.to_string(),
        endpoint_epoch: ctx.endpoint_epoch.to_string(),
        generation_id: generation.clone(),
        catalog_sha256: catalog.clone(),
        desired_document_generation: ctx.document_generation?.to_string(),
        accepted_status: None,
    })
}

pub fn accept_agent_status(ctx: &crate::agent_log::EndpointContext, document: &[u8]) -> bool {
    if serde_json::from_slice::<crate::strict_json::StrictValue>(document).is_err() {
        return false;
    }
    let Some(binding) = endpoint_binding(ctx) else {
        return false;
    };
    let ids = ctx.agents.iter().cloned().collect::<Vec<_>>();
    if parse_agent_status_bound(
        document,
        &ctx.process,
        ctx.document_generation.unwrap(),
        &ctx.resident_generation_id,
        &ctx.resident_catalog_sha256,
        &ids,
    )
    .is_err()
    {
        return false;
    }
    let receipt = acceptance_receipt();
    let accepted_owner_ms = ctx
        .owner_started
        .map(|start| start.elapsed().as_millis() as u64);
    accept_agent_status_with_clock(&ctx.process, document, binding, receipt, accepted_owner_ms)
}

#[cfg(test)]
pub(crate) fn accept_agent_status_with_receipt(
    process: &str,
    document: &[u8],
    binding: EndpointBinding,
    receipt: Option<AcceptanceReceipt>,
) -> bool {
    accept_agent_status_with_clock(process, document, binding, receipt, None)
}

fn accept_agent_status_with_clock(
    process: &str,
    document: &[u8],
    mut binding: EndpointBinding,
    receipt: Option<AcceptanceReceipt>,
    accepted_owner_ms: Option<u64>,
) -> bool {
    let Ok(parsed) = serde_json::from_slice::<AgentStatusDocumentJson>(document) else {
        return false;
    };
    // Desired revision is only a comparison operand. The acknowledged value
    // always comes from the actual received S document.
    if parsed.document_generation.to_string() != binding.desired_document_generation {
        return false;
    }
    binding.accepted_status = receipt.map(|receipt| AcceptedStatus {
        document_generation: parsed.document_generation.to_string(),
        receipt,
    });
    if let Ok(mut snapshots) = status_snapshots().lock() {
        let previous = snapshots.get(process).filter(|prior| {
            let mut prior_binding = prior.binding.clone();
            if let Some(value) = prior_binding.as_mut() {
                value.accepted_status = None;
            }
            let mut current = binding.clone();
            current.accepted_status = None;
            prior_binding.as_ref() == Some(&current)
        });
        let mut startup_receipt_times = HashMap::new();
        if let Some(clock) = accepted_owner_ms {
            for agent in &parsed.agents {
                if let Some((value, first)) =
                    previous.and_then(|prior| prior.startup_receipt_times.get(&agent.id))
                {
                    let retained = serde_json::json!({"startupApplication":value});
                    if crate::startup::parse_application(
                        &retained,
                        parsed.document_generation,
                        agent.lifecycle_generation,
                        *first,
                    )
                    .is_some()
                    {
                        startup_receipt_times.insert(agent.id.clone(), (value.clone(), *first));
                        continue;
                    }
                }
                if crate::startup::parse_application(
                    &agent.details,
                    parsed.document_generation,
                    agent.lifecycle_generation,
                    clock,
                )
                .is_none()
                {
                    continue;
                }
                let value = agent.details.get("startupApplication").unwrap().clone();
                startup_receipt_times.insert(agent.id.clone(), (value, clock));
            }
        }
        snapshots.insert(
            process.to_string(),
            Snapshot {
                startup_receipt_times,
                document: document.to_vec(),
                binding: Some(binding),
            },
        );
        true
    } else {
        false
    }
}

fn current_snapshot(process: &str, current: &EndpointBinding) -> Option<Snapshot> {
    let mut snapshots = status_snapshots().lock().ok()?;
    let snapshot = snapshots.get(process)?;
    let mut accepted = snapshot.binding.clone()?;
    accepted.accepted_status = None;
    if &accepted != current {
        snapshots.remove(process);
        return None;
    }
    Some(snapshot.clone())
}

/// A live diagnostic may start only after this exact agent acknowledged the current endpoint.
pub(crate) fn agent_ready(ctx: &crate::agent_log::EndpointContext, id: &str) -> bool {
    let Some(binding) = endpoint_binding(ctx) else {
        return false;
    };
    let Some(snapshot) = current_snapshot(&ctx.process, &binding) else {
        return false;
    };
    let Some(accepted) = snapshot.binding.as_ref() else {
        return false;
    };
    let Some(revision) = ctx.document_generation else {
        return false;
    };
    if accepted.accepted_status.is_none() || !accepted.valid_for_document(Some(revision)) {
        return false;
    }
    let ids: Vec<_> = ctx.agents.iter().cloned().collect();
    parse_agent_status_bound(
        &snapshot.document,
        &ctx.process,
        revision,
        &ctx.resident_generation_id,
        &ctx.resident_catalog_sha256,
        &ids,
    )
    .is_ok_and(|rows| {
        rows.iter().any(|entry| {
            entry.id == id && entry.state == InjectionState::Active && entry.reason == "ready"
        })
    })
}

/// Only a registry-owned, accepted current S receipt can complete transport recovery.
pub(crate) fn recovery_ready(
    process: &str,
    current: &EndpointBinding,
    revision: i64,
    generation: &str,
    catalog: &str,
    ids: &[String],
) -> bool {
    if current.generation_id != generation
        || current.catalog_sha256 != catalog
        || current.desired_document_generation != revision.to_string()
    {
        return false;
    }
    let Some(snapshot) = current_snapshot(process, current) else {
        return false;
    };
    let Some(accepted) = snapshot.binding.as_ref() else {
        return false;
    };
    if accepted.accepted_status.is_none() || !accepted.valid_for_document(Some(revision)) {
        return false;
    }
    parse_agent_status_bound(
        &snapshot.document,
        process,
        revision,
        generation,
        catalog,
        ids,
    )
    .is_ok_and(|entries| {
        entries.len() == ids.len()
            && entries
                .iter()
                .all(|entry| entry.state == InjectionState::Active && entry.reason == "ready")
    })
}

/// Check if a target process is alive via /proc/<pid>.
pub fn is_process_alive(pid: i32) -> bool {
    fs::metadata(format!("/proc/{pid}")).is_ok()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AgentStatusDocumentJson {
    schema_version: i64,
    process: String,
    generation_id: String,
    catalog_sha256: String,
    document_generation: i64,
    agents: Vec<AgentStatusEntryJson>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AgentStatusEntryJson {
    id: String,
    lifecycle_generation: i64,
    state: String,
    reason: String,
    details: Value,
}

pub fn status_envelope_matches(
    bytes: &[u8],
    process: &str,
    generation_id: &str,
    catalog_sha256: &str,
    expected_ids: &std::collections::HashSet<String>,
) -> bool {
    let Ok(document) = serde_json::from_slice::<AgentStatusDocumentJson>(bytes) else {
        return false;
    };
    let actual = document
        .agents
        .iter()
        .map(|entry| entry.id.clone())
        .collect::<std::collections::HashSet<_>>();
    document.schema_version == 1
        && document.process == process
        && document.generation_id == generation_id
        && document.catalog_sha256 == catalog_sha256
        && document.document_generation >= 0
        && document.document_generation <= MAX_DOCUMENT_GENERATION
        && actual.len() == document.agents.len()
        && &actual == expected_ids
}

#[derive(Debug)]
struct ParsedAgentStatus {
    id: String,
    lifecycle_generation: i64,
    state: InjectionState,
    reason: String,
    details: Value,
}

fn parse_agent_status_bound(
    bytes: &[u8],
    expected_process: &str,
    expected_generation: i64,
    expected_generation_id: &str,
    expected_catalog_sha256: &str,
    expected_ids: &[String],
) -> Result<Vec<ParsedAgentStatus>, ()> {
    if bytes.len() > config::MAX_AGENT_STATUS_BYTES {
        return Err(());
    }
    let document: AgentStatusDocumentJson = serde_json::from_slice(bytes).map_err(|_| ())?;
    if document.schema_version != 1
        || document.process != expected_process
        || document.generation_id != expected_generation_id
        || document.catalog_sha256 != expected_catalog_sha256
        || document.document_generation != expected_generation
        || document.document_generation < 0
    {
        return Err(());
    }

    let expected: std::collections::HashSet<_> = expected_ids.iter().map(String::as_str).collect();
    let mut seen = std::collections::HashSet::new();
    let mut parsed = Vec::with_capacity(document.agents.len());
    for entry in document.agents {
        if entry.id.is_empty()
            || !expected.contains(entry.id.as_str())
            || !seen.insert(entry.id.clone())
            || entry.lifecycle_generation < 0
            || entry.reason.len() > 128
            || !entry.details.is_object()
            || serde_json::to_vec(&entry.details).map_err(|_| ())?.len() > 8 * 1024
        {
            return Err(());
        }
        let state = match entry.state.as_str() {
            "waiting" => InjectionState::Waiting,
            "active" => InjectionState::Active,
            "failed" => InjectionState::Failed,
            _ => return Err(()),
        };
        parsed.push(ParsedAgentStatus {
            id: entry.id,
            lifecycle_generation: entry.lifecycle_generation,
            state,
            reason: entry.reason,
            details: entry.details,
        });
    }
    Ok(parsed)
}

/// Use an existing resident runtime's generation only as a lower bound for the
/// daemon's first post-restart semantic write.
pub fn observed_document_generation(
    process: &str,
    generation_id: &str,
    catalog_sha256: &str,
    expected_ids: &[String],
) -> Option<i64> {
    let bytes = read_agent_status(process)?;
    let document: AgentStatusDocumentJson = serde_json::from_slice(&bytes).ok()?;
    let expected: std::collections::HashSet<_> = expected_ids.iter().map(String::as_str).collect();
    let actual: std::collections::HashSet<_> = document
        .agents
        .iter()
        .map(|entry| entry.id.as_str())
        .collect();
    if document.schema_version != 1
        || document.process != process
        || document.generation_id != generation_id
        || document.catalog_sha256 != catalog_sha256
        || actual != expected
        || document.document_generation < 0
        || document.document_generation > MAX_DOCUMENT_GENERATION
    {
        return None;
    }
    Some(document.document_generation)
}

/// Generation identity reported by a resident process. Used only as a
/// conservative GC retention reference; it never authorizes code loading.
pub fn resident_generation_id(process: &str) -> Option<String> {
    let bytes = read_agent_status(process)?;
    let document: AgentStatusDocumentJson = serde_json::from_slice(&bytes).ok()?;
    (document.schema_version == 1 && document.process == process).then_some(document.generation_id)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResidentGeneration {
    Matching,
    Mismatched,
    Unknown,
}

fn classify_resident_generation(
    document: &AgentStatusDocumentJson,
    process: &str,
    expected_generation_id: &str,
    expected_catalog_sha256: &str,
) -> ResidentGeneration {
    if document.schema_version != 1 || document.process != process {
        return ResidentGeneration::Unknown;
    }
    if document.generation_id == expected_generation_id
        && document.catalog_sha256 == expected_catalog_sha256
    {
        ResidentGeneration::Matching
    } else {
        ResidentGeneration::Mismatched
    }
}

pub fn resident_generation(
    process: &str,
    expected_generation_id: &str,
    expected_catalog_sha256: &str,
) -> ResidentGeneration {
    let Some(bytes) = read_agent_status(process) else {
        return ResidentGeneration::Unknown;
    };
    let Ok(document) = serde_json::from_slice::<AgentStatusDocumentJson>(&bytes) else {
        return ResidentGeneration::Unknown;
    };
    classify_resident_generation(
        &document,
        process,
        expected_generation_id,
        expected_catalog_sha256,
    )
}

/// Strictly aggregate one live process's current-generation status.
pub fn aggregate_agent_status(
    status: &mut Status,
    process: &str,
    document_generation: i64,
    generation_id: &str,
    catalog_sha256: &str,
    expected_ids: &[String],
    current: Option<EndpointBinding>,
) {
    for id in expected_ids {
        status.set_injection_event(
            id,
            process,
            InjectionState::Waiting,
            "status-pending",
            Value::Object(Default::default()),
            Some(document_generation),
            None,
        );
    }

    let Some(current) = current else {
        forget_agent_status(process);
        return;
    };
    if !current
        .target_pid
        .parse::<i32>()
        .is_ok_and(is_process_alive)
    {
        forget_agent_status(process);
        return;
    }
    status.set_current_endpoint(process, current.clone());
    let Some(snapshot) = current_snapshot(process, &current) else {
        return;
    };
    let accepted_binding = snapshot.binding.clone().unwrap();
    let startup_receipt_times = snapshot.startup_receipt_times.clone();
    let parsed = match Some(snapshot.document) {
        Some(bytes) => parse_agent_status_bound(
            &bytes,
            process,
            document_generation,
            generation_id,
            catalog_sha256,
            expected_ids,
        ),
        None => return,
    };
    match parsed {
        Ok(entries) => {
            for entry in entries {
                let first = startup_receipt_times.get(&entry.id);
                let retained_details =
                    first.map(|(value, _)| serde_json::json!({"startupApplication":value}));
                status.accept_startup_application(
                    &entry.id,
                    process,
                    document_generation,
                    entry.lifecycle_generation,
                    retained_details.as_ref().unwrap_or(&entry.details),
                    &accepted_binding,
                    first.map(|(_, time)| *time),
                );
                status.set_injection_event(
                    &entry.id,
                    process,
                    entry.state,
                    &entry.reason,
                    entry.details,
                    Some(document_generation),
                    Some(entry.lifecycle_generation),
                );
            }
            status.set_current_endpoint(process, accepted_binding);
        }
        Err(()) => {
            for id in expected_ids {
                status.set_injection_event(
                    id,
                    process,
                    InjectionState::Failed,
                    "invalid-agent-status",
                    Value::Object(Default::default()),
                    Some(document_generation),
                    None,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::InjectionState;

    fn parse_agent_status(
        bytes: &[u8],
        process: &str,
        generation: i64,
        ids: &[String],
    ) -> Result<Vec<ParsedAgentStatus>, ()> {
        parse_agent_status_bound(bytes, process, generation, "generation", "catalog", ids)
    }

    fn binding(epoch: &str) -> EndpointBinding {
        EndpointBinding {
            target_pid: "2493".into(),
            target_starttime: "888".into(),
            endpoint_epoch: epoch.into(),
            generation_id: "g".into(),
            catalog_sha256: "c".into(),
            desired_document_generation: "17".into(),
            accepted_status: None,
        }
    }

    fn receipt() -> AcceptanceReceipt {
        AcceptanceReceipt {
            sequence: "1".into(),
            daemon_pid: "100".into(),
            daemon_starttime: "700".into(),
            boot_id: "22a77f16-368f-4a32-96f3-6b773aa8ce15".into(),
        }
    }

    fn ack(process: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"generationId":"g","catalogSha256":"c","process":process,"documentGeneration":17,"agents":[{"id":"forced-ev","lifecycleGeneration":1,"state":"active","reason":"ready","details":{}}]})).unwrap()
    }

    #[test]
    fn i18n_current_probe_requires_accepted_live_agent_not_only_admission() {
        let process = "com.example.i18n-live-gate";
        let mut ctx = crate::agent_log::EndpointContext {
            pid: 2493,
            process: process.into(),
            endpoint_epoch: 6,
            target_starttime: Some(888),
            document_generation: Some(17),
            log_generation: Some(("a".repeat(64), "b".repeat(64))),
            resident_generation_id: "a".repeat(64),
            resident_catalog_sha256: "b".repeat(64),
            agents: ["i18n-ru".into()].into(),
            ..Default::default()
        };
        let mut value = serde_json::json!({"schemaVersion":1,"generationId":"a".repeat(64),"catalogSha256":"b".repeat(64),"process":process,"documentGeneration":17,"agents":[{"id":"i18n-ru","lifecycleGeneration":1,"state":"active","reason":"ready","details":{}}]});
        forget_agent_status(process);
        assert!(!agent_ready(&ctx, "i18n-ru"));
        let actual = endpoint_binding(&ctx).unwrap();
        assert!(accept_agent_status_with_receipt(
            process,
            &serde_json::to_vec(&value).unwrap(),
            actual.clone(),
            Some(receipt())
        ));
        assert!(agent_ready(&ctx, "i18n-ru"));
        ctx.endpoint_epoch += 1;
        assert!(!agent_ready(&ctx, "i18n-ru"));
        ctx.endpoint_epoch -= 1;
        value["agents"][0]["state"] = "waiting".into();
        assert!(accept_agent_status_with_receipt(
            process,
            &serde_json::to_vec(&value).unwrap(),
            actual,
            Some(receipt())
        ));
        assert!(!agent_ready(&ctx, "i18n-ru"));
        forget_agent_status(process);
    }

    #[test]
    fn same_pid_new_epoch_cannot_reuse_cached_active_s() {
        let process = "com.example.endpoint146-active-red";
        let mut tracker = crate::process_watcher::ProcessTracker::default();
        tracker.track(process, 146, 900, None, None).unwrap();
        let raw = serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"generationId":"g","catalogSha256":"c","process":process,"documentGeneration":17,"agents":[{"id":"forced-ev","lifecycleGeneration":1,"state":"active","reason":"ready","details":{}}]})).unwrap();
        store_agent_status(process, &raw);
        let cached_active = || {
            read_agent_status(process)
                .and_then(|bytes| {
                    parse_agent_status_bound(&bytes, process, 17, "g", "c", &["forced-ev".into()])
                        .ok()
                })
                .is_some_and(|entries| entries[0].state == InjectionState::Active)
        };
        assert!(cached_active());
        tracker.track(process, 146, 900, None, None).unwrap();
        assert!(
            !cached_active(),
            "new same-PID epoch must not inherit old active S"
        );
    }

    #[test]
    fn exact_endpoint_requires_new_ack_after_rebind_and_retains_receipt_without_logs() {
        let process = "com.example.endpoint146-ack";
        let bytes = ack(process);
        assert!(accept_agent_status_with_receipt(
            process,
            &bytes,
            binding("6"),
            Some(receipt())
        ));
        let snapshot = current_snapshot(process, &binding("6")).unwrap();
        assert_eq!(
            parse_agent_status_bound(
                &snapshot.document,
                process,
                17,
                "g",
                "c",
                &["forced-ev".into()]
            )
            .unwrap()[0]
                .state,
            InjectionState::Active
        );
        // No queue/log record is consulted: receipt belongs to retained current S.
        assert_eq!(
            snapshot
                .binding
                .unwrap()
                .accepted_status
                .unwrap()
                .receipt
                .sequence,
            "1"
        );
        assert!(current_snapshot(process, &binding("7")).is_none());
        assert!(accept_agent_status_with_receipt(
            process,
            &bytes,
            binding("7"),
            Some(receipt())
        ));
        assert!(current_snapshot(process, &binding("7")).is_some());
        forget_agent_status(process);
        assert!(current_snapshot(process, &binding("7")).is_none());
    }

    #[test]
    fn pid_starttime_catalog_generation_and_desired_revision_changes_invalidate_ack() {
        let process = "com.example.endpoint146-mismatch";
        let bytes = ack(process);
        for field in 0..5 {
            assert!(accept_agent_status_with_receipt(
                process,
                &bytes,
                binding("6"),
                Some(receipt())
            ));
            let mut changed = binding("6");
            match field {
                0 => changed.target_pid = "2494".into(),
                1 => changed.target_starttime = "889".into(),
                2 => changed.catalog_sha256 = "other".into(),
                3 => changed.generation_id = "other".into(),
                _ => changed.desired_document_generation = "18".into(),
            }
            assert!(current_snapshot(process, &changed).is_none());
            assert!(read_agent_status(process).is_none());
        }
        let mut changed = binding("6");
        changed.desired_document_generation = "18".into();
        assert!(!accept_agent_status_with_receipt(
            process,
            &bytes,
            changed,
            Some(receipt())
        ));
    }

    #[test]
    fn unavailable_root_receipt_keeps_current_functional_ack_without_attestation() {
        let process = "com.example.endpoint146-unavailable";
        assert!(accept_agent_status_with_receipt(
            process,
            &ack(process),
            binding("6"),
            None
        ));
        let snapshot = current_snapshot(process, &binding("6")).unwrap();
        assert!(snapshot.binding.unwrap().accepted_status.is_none());
        assert!(current_snapshot(process, &binding("7")).is_none());
    }

    #[test]
    fn snapshot_registry_is_per_process_and_forgotten_on_death() {
        // Store uses a unique process name to avoid cross-test interference
        // with the shared global registry.
        let process = format!("com.example.dead-{}", line!());
        store_agent_status(
            &process,
            br#"{"schemaVersion":1,"generationId":"g","catalogSha256":"c","process":"p","documentGeneration":1,"agents":[]}"#,
        );
        assert!(read_agent_status(&process).is_some());
        // A different process must not observe it.
        assert!(read_agent_status("com.example.other").is_none());
        // Death drops it: a reincarnated PID stays status-pending until its
        // own first S frame arrives.
        forget_agent_status(&process);
        assert!(read_agent_status(&process).is_none());
    }

    #[test]
    fn schema_one_status_preserves_divergent_co_resident_entries() {
        let raw = br#"{
            "schemaVersion":1,"generationId":"generation","catalogSha256":"catalog",
            "process":"system_server",
            "documentGeneration":17,
            "agents":[
                {"id":"forced-ev","lifecycleGeneration":3,"state":"active",
                 "reason":"ready","details":{"source":"vehicle"}},
                {"id":"settings-menu","lifecycleGeneration":4,"state":"failed",
                 "reason":"hook-missing","details":{"member":"setTabs"}}
            ]
        }"#;
        let expected = vec!["forced-ev".to_string(), "settings-menu".to_string()];

        let parsed = parse_agent_status(raw, "system_server", 17, &expected).unwrap();

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].id, "forced-ev");
        assert_eq!(parsed[0].state, InjectionState::Active);
        assert_eq!(parsed[0].reason, "ready");
        assert_eq!(parsed[0].details["source"], "vehicle");
        assert_eq!(parsed[1].id, "settings-menu");
        assert_eq!(parsed[1].state, InjectionState::Failed);
        assert_eq!(parsed[1].reason, "hook-missing");
    }

    #[test]
    fn resident_generation_matches_or_defers_mismatch_and_unknown_identity() {
        let matching: AgentStatusDocumentJson = serde_json::from_str(
            r#"{"schemaVersion":1,"process":"p","generationId":"g","catalogSha256":"c","documentGeneration":1,"agents":[]}"#,
        )
        .unwrap();
        let old: AgentStatusDocumentJson = serde_json::from_str(
            r#"{"schemaVersion":1,"process":"p","generationId":"old","catalogSha256":"c","documentGeneration":1,"agents":[]}"#,
        )
        .unwrap();
        assert_eq!(
            classify_resident_generation(&matching, "p", "g", "c"),
            ResidentGeneration::Matching
        );
        assert_eq!(
            classify_resident_generation(&old, "p", "g", "c"),
            ResidentGeneration::Mismatched
        );
        assert_eq!(
            classify_resident_generation(&matching, "other", "g", "c"),
            ResidentGeneration::Unknown
        );
    }

    #[test]
    fn media_runtime_failed_status_maps_to_daemon_failed_vocabulary() {
        let raw = br#"{
            "schemaVersion":1,"generationId":"generation","catalogSha256":"catalog",
            "process":"com.qinggan.media",
            "documentGeneration":23,
            "agents":[{"id":"media-window","lifecycleGeneration":7,
            "state":"failed","reason":"media-hook-breaker-open","details":{}}]
        }"#;
        let expected = vec!["media-window".to_string()];

        let parsed = parse_agent_status(raw, "com.qinggan.media", 23, &expected).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id, "media-window");
        assert_eq!(parsed[0].state, InjectionState::Failed);
    }

    #[test]
    fn stale_unknown_and_duplicate_status_fail_closed() {
        let expected = vec!["launcher-apps".to_string()];
        let stale = br#"{"schemaVersion":1,"generationId":"generation","catalogSha256":"catalog","process":"launcher",
            "documentGeneration":16,"agents":[]}"#;
        let unknown_state = br#"{"schemaVersion":1,"generationId":"generation","catalogSha256":"catalog","process":"launcher",
            "documentGeneration":17,"agents":[{"id":"launcher-apps",
            "lifecycleGeneration":1,"state":"mystery","reason":"ready","details":{}}]}"#;
        let duplicate = br#"{"schemaVersion":1,"generationId":"generation","catalogSha256":"catalog","process":"launcher",
            "documentGeneration":17,"agents":[
            {"id":"launcher-apps","lifecycleGeneration":1,"state":"active",
             "reason":"ready","details":{}},
            {"id":"launcher-apps","lifecycleGeneration":2,"state":"failed",
             "reason":"duplicate","details":{}}]}"#;

        assert!(parse_agent_status(stale, "launcher", 17, &expected).is_err());
        assert!(parse_agent_status(unknown_state, "launcher", 17, &expected).is_err());
        assert!(parse_agent_status(duplicate, "launcher", 17, &expected).is_err());
    }

    #[test]
    fn malformed_wrong_process_unknown_id_and_unknown_field_fail_closed() {
        let expected = vec!["launcher-apps".to_string()];
        let malformed = br#"{"schemaVersion":1,"#;
        let wrong_process = br#"{"schemaVersion":1,"generationId":"generation","catalogSha256":"catalog","process":"other",
            "documentGeneration":17,"agents":[]}"#;
        let unknown_id = br#"{"schemaVersion":1,"generationId":"generation","catalogSha256":"catalog","process":"launcher",
            "documentGeneration":17,"agents":[{"id":"retired-agent",
            "lifecycleGeneration":1,"state":"active","reason":"ready","details":{}}]}"#;
        let unknown_field = br#"{"schemaVersion":1,"generationId":"generation","catalogSha256":"catalog","process":"launcher",
            "documentGeneration":17,"unexpected":true,"agents":[]}"#;

        assert!(parse_agent_status(malformed, "launcher", 17, &expected).is_err());
        assert!(parse_agent_status(wrong_process, "launcher", 17, &expected).is_err());
        assert!(parse_agent_status(unknown_id, "launcher", 17, &expected).is_err());
        assert!(parse_agent_status(unknown_field, "launcher", 17, &expected).is_err());
    }

    #[test]
    fn valid_status_may_omit_a_requested_entry() {
        let raw = br#"{"schemaVersion":1,"generationId":"generation","catalogSha256":"catalog","process":"system_server",
            "documentGeneration":17,"agents":[
            {"id":"forced-ev","lifecycleGeneration":3,"state":"active",
             "reason":"ready","details":{}}]}"#;
        let expected = vec!["forced-ev".to_string(), "settings-menu".to_string()];

        let parsed = parse_agent_status(raw, "system_server", 17, &expected).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id, "forced-ev");
    }
    #[test]
    fn startup_first_owner_receipt_survives_repeated_status_and_resets_identity() {
        let process = "com.example.startup155-first";
        let mut value: Value = serde_json::from_slice(&ack(process)).unwrap();
        value["agents"][0]["details"] = serde_json::json!({"startupApplication":{
            "authority":"backend","documentGeneration":"17","lifecycleGeneration":"1",
            "clockDomain":"android.elapsedRealtime","contract":"selected","intent":"armed",
            "outcome":"matchedNoop","observedAtBootMs":55,
            "semantics":[{"name":"desired","desired":true,"actual":true}]}});
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(accept_agent_status_with_clock(
            process,
            &bytes,
            binding("6"),
            Some(receipt()),
            Some(10)
        ));
        assert!(accept_agent_status_with_clock(
            process,
            &bytes,
            binding("6"),
            Some(receipt()),
            Some(20)
        ));
        assert_eq!(
            current_snapshot(process, &binding("6"))
                .unwrap()
                .startup_receipt_times["forced-ev"]
                .1,
            10
        );
        assert!(accept_agent_status_with_clock(
            process,
            &ack(process),
            binding("6"),
            Some(receipt()),
            Some(25)
        ));
        assert_eq!(
            current_snapshot(process, &binding("6"))
                .unwrap()
                .startup_receipt_times["forced-ev"]
                .1,
            10
        );
        assert!(accept_agent_status_with_clock(
            process,
            &bytes,
            binding("7"),
            Some(receipt()),
            Some(30)
        ));
        assert_eq!(
            current_snapshot(process, &binding("7"))
                .unwrap()
                .startup_receipt_times["forced-ev"]
                .1,
            30
        );
        value["agents"][0]["details"]["startupApplication"]["documentGeneration"] = "16".into();
        let stale = serde_json::to_vec(&value).unwrap();
        assert!(accept_agent_status_with_clock(
            process,
            &stale,
            binding("7"),
            Some(receipt()),
            Some(40)
        ));
        assert_eq!(
            current_snapshot(process, &binding("7"))
                .unwrap()
                .startup_receipt_times["forced-ev"]
                .1,
            30
        );
        let mut changed_binding = binding("7");
        changed_binding.desired_document_generation = "18".into();
        value["documentGeneration"] = 18.into();
        let changed = serde_json::to_vec(&value).unwrap();
        assert!(accept_agent_status_with_clock(
            process,
            &changed,
            changed_binding.clone(),
            Some(receipt()),
            Some(50)
        ));
        assert!(current_snapshot(process, &changed_binding)
            .unwrap()
            .startup_receipt_times
            .is_empty());
    }
    #[test]
    fn duplicate_application_json_is_rejected_before_value_decoding() {
        let process = "com.example.startup155-duplicate";
        let ctx = crate::agent_log::EndpointContext {
            pid: 2493,
            process: process.into(),
            endpoint_epoch: 6,
            log_generation: Some(("g".into(), "c".into())),
            target_starttime: Some(888),
            document_generation: Some(17),
            resident_generation_id: "g".into(),
            resident_catalog_sha256: "c".into(),
            agents: ["forced-ev".into()].into_iter().collect(),
            ..Default::default()
        };
        let raw = ack(process);
        assert!(accept_agent_status(&ctx, &raw));
        let raw = String::from_utf8(raw).unwrap().replace(
            "\"details\":{}",
            "\"details\":{\"startupApplication\":{\"intent\":\"armed\",\"intent\":\"idle\"}}",
        );
        assert!(!accept_agent_status(&ctx, raw.as_bytes()));
    }
}
