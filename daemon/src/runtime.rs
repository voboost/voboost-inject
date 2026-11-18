//! Resident daemon runtime loop and retained-generation authority.

use super::*;
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};

pub(crate) fn generation_prune_is_safe(live_processes: usize, identified_residents: usize) -> bool {
    live_processes == identified_residents
}

pub(crate) fn retained_process_index(
    retained: &[generation::VerifiedGeneration],
) -> std::collections::BTreeMap<String, Vec<usize>> {
    let mut index = std::collections::BTreeMap::<String, Vec<usize>>::new();
    for (generation_index, generation) in retained.iter().enumerate() {
        for process in generation.catalog.processes() {
            index.entry(process).or_default().push(generation_index);
        }
    }
    index
}

struct RetainedGenerationAuthority<'a> {
    store: &'a generation::GenerationStore,
    generations: &'a [generation::VerifiedGeneration],
}

fn resolve_retained_authority(
    successes: Vec<(String, target_identity::AttestedTarget)>,
) -> Result<
    (
        target_identity::AttestedTarget,
        std::collections::BTreeSet<String>,
    ),
    String,
> {
    let mut successes = successes.into_iter();
    let Some((first_id, first_authority)) = successes.next() else {
        return Err("no retained signed catalog authorized the resident target".to_string());
    };
    let mut authorized = std::collections::BTreeSet::new();
    authorized.insert(first_id);
    for (id, authority) in successes {
        if authority != first_authority {
            return Err("retained catalogs produced ambiguous target authorities".to_string());
        }
        authorized.insert(id);
    }
    Ok((first_authority, authorized))
}

fn attest_retained_catalogs(
    retained: &[generation::VerifiedGeneration],
    pid: i32,
    process: &str,
    maps_starttime: u64,
) -> Result<
    (
        target_identity::AttestedTarget,
        std::collections::BTreeSet<String>,
    ),
    String,
> {
    attest_retained_catalogs_with(retained, process, |generation, agent_ids| {
        target_identity::attest_catalog_target_for_agents(
            &generation.catalog,
            pid,
            process,
            maps_starttime,
            agent_ids,
        )
        .ok()
    })
}

fn attest_retained_catalogs_with<F>(
    retained: &[generation::VerifiedGeneration],
    process: &str,
    mut attest: F,
) -> Result<
    (
        target_identity::AttestedTarget,
        std::collections::BTreeSet<String>,
    ),
    String,
>
where
    F: FnMut(&generation::VerifiedGeneration, &[&str]) -> Option<target_identity::AttestedTarget>,
{
    let successes = retained
        .iter()
        .filter(|generation| {
            generation
                .catalog
                .processes()
                .iter()
                .any(|value| value == process)
        })
        .filter_map(|generation| {
            let agent_ids = retained_agent_ids(generation, process);
            attest(generation, &agent_ids).map(|authority| (generation.id.clone(), authority))
        })
        .collect::<Vec<_>>();
    resolve_retained_authority(successes)
}

fn retained_agent_ids<'a>(
    generation: &'a generation::VerifiedGeneration,
    process: &str,
) -> Vec<&'a str> {
    generation
        .installed_agent_ids()
        .into_iter()
        .filter(|id| generation.catalog.has_target(id, process))
        .collect()
}

fn exact_rebound_generation<'a>(
    retained: &'a [generation::VerifiedGeneration],
    authorized_generation_ids: &std::collections::BTreeSet<String>,
    identity: &injector::ResidentIdentity,
    process: &str,
) -> Result<&'a generation::VerifiedGeneration, String> {
    let resident = retained
        .iter()
        .find(|generation| generation.id == identity.generation_id)
        .ok_or_else(|| "resident returned a generation outside retained authority".to_string())?;
    if resident.catalog_sha256 != identity.catalog_sha256
        || !authorized_generation_ids.contains(&resident.id)
        || !resident
            .catalog
            .processes()
            .iter()
            .any(|value| value == process)
    {
        return Err("resident generation/catalog/target authority mismatch".to_string());
    }
    Ok(resident)
}

fn verify_resident_identity(
    store: &generation::GenerationStore,
    identity: &injector::ResidentIdentity,
) -> Result<generation::VerifiedGeneration, String> {
    let resident = store
        .resident(&identity.generation_id)
        .map_err(|error| format!("resident generation rejected: {error}"))?;
    if resident.catalog_sha256 != identity.catalog_sha256 {
        return Err("resident rebind catalog identity mismatch".to_string());
    }
    Ok(resident)
}

/// Catalog authority is separate from the disabled feature execution set.
fn bootstrap_authority_ids(
    generation: &generation::VerifiedGeneration,
    process: &str,
    enabled: &[String],
) -> Vec<String> {
    if !enabled.is_empty() {
        return enabled.to_vec();
    }
    if process == crate::launcher_page::PROCESS {
        return retained_agent_ids(generation, process)
            .into_iter()
            .map(str::to_owned)
            .collect();
    }
    Vec::new()
}

/// Verify the native payload for `abi` against the release manifest before
/// injecting it into `process` (trust-verification). Returns true when the
/// payload is verified and injection may proceed; false (fail-closed) when the
/// manifest is absent, a required payload file is missing, or a hash mismatches.
fn verify_payload_before_inject(
    release_manifest: &Option<voboost_contract::release::Manifest>,
    abi: &str,
    process: &str,
) -> bool {
    let Some(rm) = release_manifest else {
        log::err(
            "main",
            "product manifest absent: payload unverified, skip inject",
        );
        return false;
    };
    match installed_product::verify_runtime_for_abi(rm, abi) {
        Ok(()) => true,
        Err(error) => {
            log::err(
                "main",
                &format!("product runtime payload rejected for {abi}: {error}; skip {process}"),
            );
            false
        }
    }
}

/// Native early-boot deferrals get twenty fast retries, then one attempt every
/// thirty seconds. Each retains the exact original envelope/authority. A hard
/// failure, cancellation, identity change or unsafe cleanup never enters this
/// slow path; process death and authenticated readiness stop it immediately.
const MAX_AGENT_PENDING_RETRIES: u32 = 20;

fn pending_retry_delay(attempts: u32) -> std::time::Duration {
    std::time::Duration::from_millis(if attempts >= MAX_AGENT_PENDING_RETRIES {
        30_000
    } else {
        500
    })
}

/// Per-process early-boot retry state. `attempts` counts completed re-injection
/// attempts for this process name (one per poll pass while the PID is alive).
#[derive(Clone)]
struct PendingRetry {
    pid: i32,
    starttime: u64,
    attempts: u32,
    next_retry_at: std::time::Duration,
    /// Exact immutable generation/catalog authority used to attest the target
    /// and build the retained envelope. A later active-generation cutover
    /// must never authorize these bytes through the replacement catalog.
    generation: generation::VerifiedGeneration,
    /// Complete ordered process agent-ID set and semantic control surface
    /// carried by the retained envelope. Either changing cancels the retry;
    /// the live process may bootstrap the replacement state after a natural
    /// restart.
    agent_ids: Vec<String>,
    desired_semantics: String,
    document_generation: i64,
    /// Verified native payload authority from the original attempt. Retrying
    /// against a newly loaded manifest could authorize different on-disk
    /// bytes than the retained agent envelope was paired with.
    release_manifest: Option<voboost_contract::release::Manifest>,
    /// The verified pipe-bootstrap envelope for this process. Every retry
    /// must run a full two-phase `inject_pipe_bootstrap`: the adopted pipes
    /// from the first attempt were closed when that attempt returned
    /// Pending, so a load-only retry would create new pipes whose
    /// descriptors never reach the daemon.
    bootstrap: std::sync::Arc<Vec<u8>>,
}

struct InjectionContext {
    process: String,
    authority: target_identity::AttestedTarget,
    retry: PendingRetry,
    agent_id: String,
    started: std::time::Instant,
}

struct RebindContext {
    recovery_identity: Option<crate::resident_recovery::Identity>,
    process: String,
    authority: target_identity::AttestedTarget,
    generations: Vec<generation::VerifiedGeneration>,
    authorized_generations: std::collections::BTreeSet<String>,
    started: std::time::Instant,
}

struct RebindOutcome {
    result: injector::InjectResult,
    record: Option<OwnedFd>,
    downlink: Option<OwnedFd>,
    identity: Option<injector::ResidentIdentity>,
}

fn pending_retry_semantics_match(
    retry: (&str, &str, i64, &[String], &str),
    current: (&str, &str, &[String], Option<&str>),
    desired: Option<(&str, &str, i64, &[String], &str)>,
) -> bool {
    let Some(desired) = desired else {
        return false;
    };
    retry.0 == current.0
        && retry.1 == current.1
        && retry.3 == current.2
        && current.3 == Some(retry.4)
        && desired.0 == retry.0
        && desired.1 == retry.1
        && desired.2 == retry.2
        && desired.3 == retry.3
        && desired.4 == retry.4
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TargetAction {
    TrackExistingImplant,
    ObserveOnly,
    Inject,
}

fn target_action(already_injected: bool, has_desired_agents: bool) -> TargetAction {
    if already_injected {
        TargetAction::TrackExistingImplant
    } else if has_desired_agents {
        TargetAction::Inject
    } else {
        TargetAction::ObserveOnly
    }
}

struct DesiredDocumentState {
    semantic_document: String,
    generation: i64,
    ids: Vec<String>,
    admitted_endpoint: Option<(i32, u64, u64)>,
    restart_endpoint: Option<(i32, u64, u64)>,
    restart_removed: Vec<String>,
    retiring_state: Option<agent_log::RetiringState>,
    /// Generation actually resident in this process. It survives a passive
    /// current-generation cutover and is used for D frames/status checks.
    resident_generation: Option<generation::VerifiedGeneration>,
}

fn admitted_ids_for_endpoint<'a>(
    state: Option<&'a DesiredDocumentState>,
    endpoint: Option<(i32, u64, u64)>,
    native_identity: Option<(String, String)>,
    resident: &generation::VerifiedGeneration,
) -> &'a [String] {
    let Some(state) = state else {
        return &[];
    };
    let Some(endpoint) = endpoint else {
        return &[];
    };
    if state.admitted_endpoint != Some(endpoint)
        || native_identity.as_ref() != Some(&(resident.id.clone(), resident.catalog_sha256.clone()))
        || state
            .resident_generation
            .as_ref()
            .map(|value| (&value.id, &value.catalog_sha256))
            != Some((&resident.id, &resident.catalog_sha256))
    {
        return &[];
    }
    &state.ids
}

fn restart_removed_agents(
    previous: Option<&DesiredDocumentState>,
    ids: &[String],
    endpoint: Option<(i32, u64, u64)>,
) -> Vec<String> {
    let Some(previous) = previous.filter(|_| endpoint.is_some()) else {
        return Vec::new();
    };
    let mut removed = if previous.restart_endpoint == endpoint {
        previous.restart_removed.clone()
    } else {
        Vec::new()
    };
    removed.extend(previous.ids.iter().filter(|id| !ids.contains(id)).cloned());
    removed.retain(|id| !ids.contains(id));
    removed.sort();
    removed.dedup();
    removed
}

pub(crate) fn render_mutation_ack_frame(
    request_id: u64,
    document: &str,
) -> Result<Vec<u8>, String> {
    let prefix = format!("A|{request_id}|");
    if prefix.len() + document.len() + 1 > config::MAX_DOWNLINK_FRAME_BYTES
        || document.contains('\n')
    {
        return Err("mutation ACK exceeds frame budget".to_string());
    }
    let mut frame = Vec::with_capacity(prefix.len() + document.len() + 1);
    frame.extend_from_slice(prefix.as_bytes());
    frame.extend_from_slice(document.as_bytes());
    frame.push(b'\n');
    Ok(frame)
}

fn render_desired_frame(document: &str) -> Result<Vec<u8>, String> {
    if document.len() + 3 > config::MAX_DOWNLINK_FRAME_BYTES || document.contains('\n') {
        return Err("desired snapshot exceeds frame budget".to_string());
    }
    let mut frame = Vec::with_capacity(document.len() + 3);
    frame.extend_from_slice(b"D|");
    frame.extend_from_slice(document.as_bytes());
    frame.push(b'\n');
    Ok(frame)
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct DesiredSnapshotLogIdentity {
    generation_id: String,
    catalog_sha256: String,
    document_generation: i64,
}

fn render_confirmed_update_frames(
    request_id: u64,
    document: &str,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    Ok((
        render_desired_frame(document)?,
        render_mutation_ack_frame(request_id, document)?,
    ))
}

struct BootstrapPayloadDescriptor {
    wire_name: String,
    source_name: String,
    size: u64,
    context: String,
}

fn bootstrap_metadata(
    plan: &plan::Plan,
    generation: &generation::VerifiedGeneration,
    process: &str,
    document_generation: i64,
) -> Result<(Vec<u8>, Vec<BootstrapPayloadDescriptor>), String> {
    let desired_json = plan
        .desired_document_for_process(process, generation, document_generation)
        .map_err(|error| format!("{error} for {process}"))?;
    let mut identities = Vec::new();
    let mut executor_identities = Vec::new();
    let mut payloads = vec![BootstrapPayloadDescriptor {
        wire_name: "agents.dex".to_string(),
        source_name: generation.catalog.core.file.clone(),
        size: generation.catalog.core.size,
        context: "verified core dex".to_string(),
    }];
    let mut push_module = |id: &str, executor: bool| -> Result<(), String> {
        let agent = generation
            .catalog
            .find(id)
            .ok_or_else(|| format!("bootstrap module missing: {id}"))?;
        let target = generation
            .catalog
            .target(id, process)
            .ok_or_else(|| format!("bootstrap target missing: {id}/{process}"))?;
        let index = payloads.len();
        payloads.push(BootstrapPayloadDescriptor {
            wire_name: target.file.clone(),
            source_name: target.file.clone(),
            size: target.size,
            context: format!("verified module {id}"),
        });
        let processes: Vec<&str> = agent
            .targets
            .iter()
            .map(|target| target.process.as_str())
            .collect();
        let identity = serde_json::json!({
            "id":id,
            "entryClass":target.entry_class,
            "processes":processes,
            "fileIndex":index
        });
        if executor {
            executor_identities.push(identity);
        } else {
            identities.push(identity);
        }
        Ok(())
    };
    // Executors first: the resident runtime starts them before the first
    // desired-snapshot reconcile.
    for agent in &generation.catalog.agents {
        if agent.is_executor() && generation.catalog.has_target(&agent.id, process) {
            push_module(&agent.id, true)?;
        }
    }
    // Register every applicable module for this process, including disabled
    // agents. Later desired documents can enable them without reinjection;
    // registration does not start an agent omitted from the desired set.
    if plan.startup != plan::Startup::None && !plan.disable_all {
        let installed = generation.installed_agent_ids();
        for agent in &generation.catalog.agents {
            if !agent.is_executor()
                && installed.contains(agent.id.as_str())
                && generation.catalog.has_target(&agent.id, process)
            {
                push_module(&agent.id, false)?;
            }
        }
    }
    let mut artifact_identities = Vec::new();
    if plan.startup != plan::Startup::None && !plan.disable_all {
        for artifact in generation
            .resource_bootstrap_artifacts(process)
            .map_err(|e| e.to_string())?
        {
            let index = payloads.len();
            payloads.push(BootstrapPayloadDescriptor {
                wire_name: artifact.file.clone(),
                source_name: artifact.file,
                size: artifact.size,
                context: format!("verified resource artifact {}", artifact.id),
            });
            artifact_identities.push(serde_json::json!({"id":artifact.id,"fileIndex":index}));
        }
    }
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion":2,
        "generationId":generation.id,
        "catalogSha256":generation.catalog_sha256,
        "desiredJson":desired_json,
        "coreFileIndex":0,
        "modules":identities,
        "executors":executor_identities,
        "artifacts":artifact_identities,
    }))
    .map_err(|error| error.to_string())?;
    Ok((manifest, payloads))
}

pub(crate) fn validate_generation_representability(
    generation: &generation::VerifiedGeneration,
    canonical_plan: &plan::Plan,
) -> Result<(), String> {
    let mut maximum_plan = canonical_plan.clone();
    // Capacity validation considers a future repaired/enabled configuration;
    // this local validation copy is never an execution authority.
    maximum_plan.runtime_fences.clear();
    maximum_plan.startup = plan::Startup::Interface;
    for entry in &mut maximum_plan.entries {
        entry.enabled = true;
        if let Some(agent) = generation.catalog.find(&entry.id) {
            let mut options = serde_json::Map::new();
            for option in agent.options.as_deref().unwrap_or(&[]) {
                let longest = option
                    .values
                    .iter()
                    .max_by_key(|value| value.value.len())
                    .ok_or_else(|| format!("agent {} has no option values", agent.id))?;
                options.insert(
                    option.key.clone(),
                    serde_json::Value::String(longest.value.clone()),
                );
            }
            entry.config = serde_json::Value::Object(options);
        }
    }
    for process in generation.catalog.processes() {
        let desired = maximum_plan.desired_document_for_process(
            &process,
            generation,
            control_plane::MAX_DOCUMENT_GENERATION,
        )?;
        render_confirmed_update_frames(u64::MAX, &desired)
            .map_err(|error| format!("unrepresentable desired document for {process}: {error}"))?;
        let (manifest, payloads) = bootstrap_metadata(
            &maximum_plan,
            generation,
            &process,
            control_plane::MAX_DOCUMENT_GENERATION,
        )?;
        let files = payloads
            .iter()
            .map(|payload| bootstrap_pipe::File {
                name: &payload.wire_name,
                size: payload.size,
            })
            .collect::<Vec<_>>();
        bootstrap_pipe::validate_layout(&manifest, &files)
            .map_err(|error| format!("unrepresentable bootstrap for {process}: {error}"))?;
    }
    Ok(())
}

impl DesiredDocumentState {
    #[cfg(test)]
    fn new(semantic_document: &str, generation: i64) -> Self {
        Self {
            semantic_document: semantic_document.to_string(),
            generation,
            ids: Vec::new(),
            admitted_endpoint: None,
            restart_endpoint: None,
            restart_removed: Vec::new(),
            retiring_state: None,
            resident_generation: None,
        }
    }

    fn with_ids(
        semantic_document: String,
        generation: i64,
        ids: Vec<String>,
        resident_generation: generation::VerifiedGeneration,
    ) -> Self {
        Self {
            semantic_document,
            generation,
            ids,
            admitted_endpoint: None,
            restart_endpoint: None,
            restart_removed: Vec::new(),
            retiring_state: None,
            resident_generation: Some(resident_generation),
        }
    }
}

fn next_desired_generation(
    previous: Option<&DesiredDocumentState>,
    semantic_document: &str,
    floor: i64,
) -> Result<Option<i64>, String> {
    if previous.is_some_and(|state| state.semantic_document == semantic_document) {
        return Ok(None);
    }
    if !(0..=control_plane::MAX_DOCUMENT_GENERATION).contains(&floor) {
        return Err("desired document generation floor is outside the supported range".to_string());
    }
    let previous_floor = match previous {
        Some(state) => state
            .generation
            .checked_add(1)
            .filter(|value| *value <= control_plane::MAX_DOCUMENT_GENERATION)
            .ok_or_else(|| "desired document generation is exhausted".to_string())?,
        None => 0,
    };
    Ok(Some(previous_floor.max(floor)))
}

fn correlated_observed_generation(process: &str, state: &DesiredDocumentState) -> Option<i64> {
    let resident = state.resident_generation.as_ref()?;
    control_plane::observed_document_generation(
        process,
        &resident.id,
        &resident.catalog_sha256,
        &state.ids,
    )
}

fn desired_generation_floor(
    process: &str,
    resident_generation: &generation::VerifiedGeneration,
    ids: &[String],
) -> Result<i64, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let now = i64::try_from(now)
        .ok()
        .filter(|value| *value <= control_plane::MAX_DOCUMENT_GENERATION)
        .ok_or_else(|| "wall-clock generation floor is outside the supported range".to_string())?;
    let observed = control_plane::observed_document_generation(
        process,
        &resident_generation.id,
        &resident_generation.catalog_sha256,
        ids,
    )
    .map(|generation| {
        generation
            .checked_add(1)
            .filter(|value| *value <= control_plane::MAX_DOCUMENT_GENERATION)
            .ok_or_else(|| "resident document generation is exhausted".to_string())
    })
    .transpose()?
    .unwrap_or(0);
    Ok(now.max(observed))
}

fn set_status_for_ids(
    status: &mut status::Status,
    ids: &[String],
    process: &str,
    state: status::InjectionState,
    reason: &str,
    document_generation: Option<i64>,
) {
    for id in ids {
        status.set_injection_event(
            id,
            process,
            state,
            reason,
            serde_json::Value::Object(Default::default()),
            document_generation,
            None,
        );
    }
}

/// The pure decision for one pending-retry entry on a poll pass, evaluated
/// BEFORE re-injecting. Extracted so the early-boot retry invariants are
/// unit-testable without a live /proc or daemon loop.
enum PendingRetryDecision {
    /// The agent has since reported ready (status aggregation promoted it to
    /// Active). Stop retrying; drop the entry.
    Cleared,
    /// The PID died while the agent was still pending. Stop retrying; mark
    /// Failed. This is the "same-live-PID" invariant: the retry stops as soon
    /// as the PID is gone.
    PidDead,
    /// The fast retry budget ended while the PID stayed alive. Use slow cadence.
    BoundExhausted,
    /// Retry the injection on the same live PID.
    Retry,
}

/// Decide what to do for a pending early-boot agent-init retry. Pure function
/// of (current injection state, PID liveness, attempts so far, max attempts).
fn pending_retry_decision(
    state: Option<status::InjectionState>,
    pid_alive: bool,
    attempts: u32,
    max_attempts: u32,
) -> PendingRetryDecision {
    // Agent reached readiness via the status aggregation → nothing to retry.
    if matches!(state, Some(status::InjectionState::Active)) {
        return PendingRetryDecision::Cleared;
    }
    // Same-live-PID invariant: stop the moment the PID disappears.
    if !pid_alive {
        return PendingRetryDecision::PidDead;
    }
    // The fast budget changes cadence; it must not strand a transient deferral.
    if attempts >= max_attempts {
        return PendingRetryDecision::BoundExhausted;
    }
    PendingRetryDecision::Retry
}

use runtime_loop::{run_poll_pass_with_startup_confirmation, PollActions};

/// Persistent state owned by the READY daemon poll loop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DaemonPollDisposition {
    Continue,
    RebootForUpdate,
    /// Committed `startup: none`: publish the final status and hand the init
    /// service back so nothing of voboost stays resident (the service is not
    /// oneshot — crash recovery keeps init-owned restarts; the planned stop
    /// goes through init's `ctl.stop`).
    SelfStopForNone,
}

/// The pure per-pass decision for the committed `startup: none` gate. Only a
/// plan PARSED from the root agents.json with `startup: none` carries
/// `disable_all == true`; the valid-empty placeholder (missing/unreadable
/// plan) and every other mode keep it false, so the fail-safe daemon stays
/// resident and the operator kill-switch file path below keeps its emergency
/// idle semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NonePlanDecision {
    /// Not a committed none plan: ordinary kill-switch/idle handling applies.
    NotCommitted,
    /// An in-flight update outranks the stop: the reboot path owns the exit.
    RebootForUpdate,
    /// Publish the final status and stop the init-owned service.
    SelfStop,
}

fn none_plan_decision(
    startup: plan::Startup,
    disable_all: bool,
    activation_frozen: bool,
) -> NonePlanDecision {
    if startup != plan::Startup::None || !disable_all {
        NonePlanDecision::NotCommitted
    } else if activation_frozen {
        NonePlanDecision::RebootForUpdate
    } else {
        NonePlanDecision::SelfStop
    }
}

pub(crate) struct DaemonLoop {
    observations: crate::transition_log::Transitions,
    generation: generation::VerifiedGeneration,
    safety: safety::Safety,
    watcher: process_watcher::ProcessWatcher,
    status: status::Status,
    pending_retries: std::collections::HashMap<String, PendingRetry>,
    injection_jobs: crate::injection_jobs::Jobs<InjectionContext, injector::BootstrapOutcome>,
    rebind_jobs: crate::injection_jobs::Jobs<RebindContext, RebindOutcome>,
    resident_recovery: std::collections::HashMap<String, crate::resident_recovery::Recovery>,
    drain_buffers: agent_log::DrainBuffers,
    desired_documents: std::collections::HashMap<String, DesiredDocumentState>,
    uninstall_cache_context: Option<agent_log::EndpointContext>,
    /// Live config pushes still awaiting the target's status-file ack.
    pending_acks: std::collections::HashMap<String, PendingAck>,
    /// Sources whose saved removal was already reported to the owner as
    /// applied. Cleared when a source is enabled again, so a later removal is
    /// confirmed on its own evidence rather than on the earlier report.
    confirmed_withdrawals: std::collections::BTreeSet<String>,
    last_plan: plan::Plan,
    startup_confirmed: bool,
    root_plan_unavailable: bool,
    #[cfg(target_os = "android")]
    package_execution: crate::package_execution::Worker,
    activation_frozen: bool,
    uninstall_frozen: bool,
    uninstall_retry_at: Option<std::time::Instant>,
    injection_unsafe: bool,
    startup_clock_anchor: Option<crate::startup::ClockAnchor>,
    preparation: crate::startup_preparation::Preparation,
    started: std::time::Instant,
}

struct ProductivePollPass<'a> {
    daemon: &'a mut DaemonLoop,
    plan: &'a plan::Plan,
    appeared: &'a [(String, i32)],
    died: &'a [(i32, String)],
    release_manifest: Option<voboost_contract::release::Manifest>,
    tracked: Vec<(i32, String)>,
}

impl PollActions for ProductivePollPass<'_> {
    fn record_deaths(&mut self) {
        self.daemon.record_deaths(self.died, self.plan);
    }

    fn drain_agent_logs(&mut self) {
        self.daemon.drain_agent_logs();
    }

    fn prepare_injection(&mut self) {
        if !self.daemon.activation_frozen {
            self.release_manifest = installed_product::load_manifest().ok();
        }
    }

    fn dispatch_injections(&mut self) {
        self.daemon.collect_injections(self.plan);
        if self.daemon.activation_frozen {
            self.daemon.stop_injections();
            self.daemon.pending_retries.clear();
        } else {
            self.daemon
                .dispatch_injections(self.appeared, self.plan, &self.release_manifest);
        }
    }

    fn collect_injections(&mut self) {
        self.daemon.collect_injections(self.plan);
    }

    fn aggregate_agent_status(&mut self) {
        self.tracked = self.daemon.aggregate_agent_statuses(self.plan);
    }

    fn push_live_config(&mut self) {
        self.daemon.push_live_config(self.plan, &self.tracked);
    }

    fn enforce_live_acks(&mut self) {
        self.daemon.enforce_live_acks();
    }

    fn push_confirmed_snapshots(&mut self) {
        self.daemon.push_confirmed_snapshots();
    }

    fn flush_downlinks(&mut self) {
        self.daemon.service_launcher_observation();
        self.daemon.flush_downlinks();
    }

    fn persist_status(&mut self) {
        self.daemon.status.write_atomic();
    }
}

/// One pushed desired document awaiting acknowledgement by the target runtime.
struct PendingAck {
    generation: i64,
    pushed_at: std::time::Instant,
    restarts: u32,
}

/// Live-update acknowledgement decision (pure, unit-tested).
enum AckAction {
    /// Target status file already reports this generation.
    Acked,
    /// Still inside the grace window.
    Wait,
    /// Restart budget exhausted; drop the pending ack.
    GiveUp,
}

const LIVE_ACK_GRACE: std::time::Duration = std::time::Duration::from_secs(10);
const LIVE_ACK_MAX_RESTARTS: u32 = 3;

fn ack_action(
    observed: Option<i64>,
    pushed_generation: i64,
    elapsed: std::time::Duration,
    restarts: u32,
) -> AckAction {
    if observed.is_some_and(|generation| generation >= pushed_generation) {
        return AckAction::Acked;
    }
    if restarts >= LIVE_ACK_MAX_RESTARTS {
        return AckAction::GiveUp;
    }
    if elapsed >= LIVE_ACK_GRACE {
        return AckAction::GiveUp;
    }
    AckAction::Wait
}

/// Live-update removal decision for one target process (pure, unit-tested).
enum RemovalAction {
    /// The process cannot still be running the hook that captured the input.
    Applied,
    /// The process may still hold the hook; the owner keeps the admission.
    Pending,
}

/// The inject may only report a saved removal as applied on positive evidence:
/// the process is gone, or it reports having applied the pushed document that
/// no longer enables the source. Anything unknown stays pending, so the owner
/// keeps the admission and the bound remains the only fail-open path.
fn removal_action(
    live: bool,
    document: Option<&DesiredDocumentState>,
    source: &str,
    observed: Option<i64>,
) -> RemovalAction {
    if !live {
        return RemovalAction::Applied;
    }
    let Some(document) = document else {
        return RemovalAction::Pending;
    };
    if document.ids.iter().any(|id| id == source) {
        return RemovalAction::Pending;
    }
    if observed.is_some_and(|generation| generation >= document.generation) {
        RemovalAction::Applied
    } else {
        RemovalAction::Pending
    }
}

impl DaemonLoop {
    #[cfg(test)]
    fn new(generation: generation::VerifiedGeneration) -> Self {
        Self::new_with_product_identity(
            generation,
            false,
            installed_product::ProductIdentity {
                release_identity: "1.0.0-test".into(),
                manifest_sha256: "00".repeat(32),
            },
        )
    }

    pub(crate) fn new_with_product_identity(
        generation: generation::VerifiedGeneration,
        activation_frozen: bool,
        product_identity: installed_product::ProductIdentity,
    ) -> Self {
        let started = std::time::Instant::now();
        let startup_clock_anchor = crate::startup::ClockAnchor::sample_owner_start(started);
        let mut status = status::Status::default();
        status.release_identity = product_identity.release_identity;
        status.manifest_sha256 = product_identity.manifest_sha256;
        status.daemon_state = "ready".to_string();
        status.generation_id = generation.id.clone();
        status.catalog_sha256 = generation.catalog_sha256.clone();
        status.executors = generation
            .catalog
            .agents
            .iter()
            .filter(|agent| agent.is_executor())
            .map(|agent| status::StatusExecutor {
                id: agent.id.clone(),
                processes: agent
                    .targets
                    .iter()
                    .map(|target| target.process.clone())
                    .collect(),
                surfaces: agent.surfaces.clone(),
            })
            .collect();
        let last_plan = plan::Plan::valid_empty_for(&generation);
        Self {
            observations: Default::default(),
            generation,
            safety: safety::Safety::new(),
            watcher: process_watcher::ProcessWatcher::new(),
            status,
            pending_retries: std::collections::HashMap::new(),
            injection_jobs: crate::injection_jobs::Jobs::default(),
            rebind_jobs: crate::injection_jobs::Jobs::default(),
            resident_recovery: std::collections::HashMap::new(),
            pending_acks: std::collections::HashMap::new(),
            confirmed_withdrawals: std::collections::BTreeSet::new(),
            drain_buffers: agent_log::DrainBuffers::default(),
            desired_documents: std::collections::HashMap::new(),
            uninstall_cache_context: None,
            last_plan,
            startup_confirmed: false,
            root_plan_unavailable: false,
            #[cfg(target_os = "android")]
            package_execution: Default::default(),
            activation_frozen,
            uninstall_frozen: false,
            uninstall_retry_at: None,
            injection_unsafe: false,
            startup_clock_anchor,
            preparation: Default::default(),
            started,
        }
    }

    pub(crate) fn set_uninstall_frozen(&mut self, frozen: bool) {
        self.uninstall_frozen = frozen;
        if frozen {
            self.stop_injections();
        }
    }

    pub(crate) fn set_product_identity(&mut self, identity: installed_product::ProductIdentity) {
        self.status.release_identity = identity.release_identity;
        self.status.manifest_sha256 = identity.manifest_sha256;
    }

    pub(crate) fn uninstall_frozen(&self) -> bool {
        self.uninstall_frozen
    }

    /// Cut the live loop over to a newly activated generation (runtime
    /// watcher path). New processes bootstrap from this generation; resident
    /// endpoints keep their old generation identity (passive switch,
    /// docs/developer/updates). Endpoint-scoped Settings validation remains bound to
    /// each resident generation; old residents fail closed for mutations.
    pub(crate) fn adopt_generation(&mut self, fresh: generation::VerifiedGeneration) {
        if fresh.id == self.generation.id {
            return;
        }
        log::ok(
            "main",
            &format!(
                "daemon loop cut over to generation {} (residents keep theirs)",
                fresh.id
            ),
        );
        self.observations.clear();
        self.status.generation_id = fresh.id.clone();
        self.status.catalog_sha256 = fresh.catalog_sha256.clone();
        self.generation = fresh;
        self.prune_safety_authority();
    }

    fn pid_owned(&self, pid: i32) -> bool {
        self.injection_jobs.contains(pid) || self.rebind_jobs.contains(pid)
    }

    pub(crate) fn injection_jobs_active(&self) -> bool {
        #[cfg(target_os = "android")]
        if self.package_execution.is_active() {
            return true;
        }
        !self.injection_jobs.is_empty() || !self.rebind_jobs.is_empty()
    }

    pub(crate) fn generation_id(&self) -> &str {
        &self.generation.id
    }

    fn prune_safety_authority(&mut self) {
        let mut authorities = std::collections::BTreeSet::new();
        let mut add_catalog = |catalog: &catalog::AgentCatalog| {
            for agent in &catalog.agents {
                for target in &agent.targets {
                    authorities.insert((agent.id.clone(), target.process.clone()));
                }
            }
        };
        add_catalog(&self.generation.catalog);
        for desired in self.desired_documents.values() {
            if let Some(resident) = &desired.resident_generation {
                add_catalog(&resident.catalog);
            }
        }
        for pending in self.pending_retries.values() {
            add_catalog(&pending.generation.catalog);
        }
        for job in self.injection_jobs.contexts() {
            add_catalog(&job.retry.generation.catalog);
        }
        for job in self.rebind_jobs.contexts() {
            for generation in &job.generations {
                add_catalog(&generation.catalog);
            }
        }
        self.safety.retain_authorities(
            authorities
                .iter()
                .map(|(agent, process)| (agent.as_str(), process.as_str())),
        );
    }

    /// Close the old daemon's write endpoints after its final nonblocking
    /// flush. Resident implants interpret EOF as loss of daemon ownership and
    /// keep their hooks loaded until the init successor performs the explicit
    /// rebind handshake.
    pub(crate) fn fence_native_restart_endpoints(&mut self) {
        self.stop_injections();
        let downlinks = self
            .watcher
            .tracker()
            .downlinks()
            .into_iter()
            .map(|(_, _, _, fd)| fd)
            .collect::<Vec<_>>();
        for fd in downlinks {
            self.watcher.tracker_mut().disable_downlink(fd);
        }
        self.pending_acks.clear();
    }

    fn quiesce_i18n_resources(&self) -> bool {
        if let Err(error) = crate::cluster_control::project_global_locale(&self.generation, None) {
            log::err("i18n-global-locale", &error);
            return false;
        }
        let stopped = crate::i18n_resources::quiesce();
        crate::i18n_resources::report_scope(&self.generation);
        stopped
    }

    /// Execute one poll pass. Every manifest process remains observable so a
    /// resident implant can receive valid empty state and later re-enable.
    pub(crate) fn poll_once(&mut self) -> DaemonPollDisposition {
        self.poll_with_plan(plan::read_runtime_and_validate)
    }

    fn poll_with_plan(
        &mut self,
        read_plan: impl FnOnce(&generation::VerifiedGeneration) -> plan::Plan,
    ) -> DaemonPollDisposition {
        if crate::product_candidate::reboot_required()
            || self.activation_frozen
            || self.uninstall_frozen
            || crate::uninstall::request_present()
            || crate::uninstall::prepared_marker_valid()
            || self.safety.kill_switch_active()
        {
            crate::control_plane::pw_transport::cancel();
        }
        // Stop resource side effects before every emergency or teardown handoff.
        if (crate::product_candidate::reboot_required()
            || self.activation_frozen
            || self.uninstall_frozen
            || crate::uninstall::request_present()
            || crate::uninstall::prepared_marker_valid()
            || self.safety.kill_switch_active())
            && !self.quiesce_i18n_resources()
        {
            self.drain_agent_logs_with_policy(false);
            self.flush_downlinks();
            return DaemonPollDisposition::Continue;
        }
        if crate::product_candidate::reboot_required() {
            self.stop_injections();
            self.status.write_atomic();
            #[cfg(target_os = "android")]
            if !self.package_execution.quiesce() {
                return DaemonPollDisposition::Continue;
            }
            return DaemonPollDisposition::RebootForUpdate;
        }
        let request_present = crate::uninstall::request_present();
        let prepared_marker = crate::uninstall::prepared_marker_valid();
        let disposition =
            uninstall_poll_disposition(self.uninstall_frozen, prepared_marker, request_present);
        if disposition != UninstallPollDisposition::ContinueNormal {
            let plan = self.last_plan.clone();
            self.collect_injections(&plan);
            self.drain_agent_logs_with_policy(false);
            self.flush_downlinks();
        }
        #[cfg(target_os = "android")]
        if disposition != UninstallPollDisposition::ContinueNormal
            && !self.package_execution.quiesce()
        {
            self.drain_agent_logs_with_policy(false);
            self.flush_downlinks();
            return DaemonPollDisposition::Continue;
        }
        if disposition == UninstallPollDisposition::ContinueNormal {
            self.observations.resolved("uninstall-result");
            self.observations.resolved("uninstall-prepare");
        }
        if disposition == UninstallPollDisposition::RetryCommitted {
            self.uninstall_frozen = true;
            self.stop_injections();
            self.pending_retries.clear();
            if request_present {
                consume_completed_uninstall_request();
            }
            let store = generation::GenerationStore::production();
            if let Err(error) = crate::uninstall::retry_committed_prepared(&store) {
                crate::uninstall::record_failure(&format!(
                    "committed uninstall freeze/trigger retry failed: {error}"
                ));
                log::err(
                    "main",
                    &format!("committed uninstall retry failed: {error}"),
                );
            }
            self.status.write_atomic();
            return DaemonPollDisposition::Continue;
        }
        if disposition == UninstallPollDisposition::PrepareRequested {
            if self
                .uninstall_retry_at
                .is_some_and(|at| std::time::Instant::now() < at)
            {
                self.drain_agent_logs_with_policy(false);
                self.flush_downlinks();
                return DaemonPollDisposition::Continue;
            }
            if !self.observations.contains("uninstall-prepare") {
                log::info("uninstall", "Preparing removal");
            }
            let store = generation::GenerationStore::production();
            let prepared = self.prepare_uninstall(&store);
            let rollback_result_published = match &prepared {
                Ok(
                    PrepareUninstallOutcome::RolledBack(error)
                    | PrepareUninstallOutcome::Rejected(error),
                ) => {
                    let publication =
                        if matches!(&prepared, Ok(PrepareUninstallOutcome::Rejected(_))) {
                            crate::uninstall::record_rejected_result(error)
                        } else {
                            crate::uninstall::record_rolled_back_result(error)
                        };
                    match publication {
                        Ok(()) => {
                            self.observations.resolved("uninstall-result");
                            true
                        }
                        Err(reply_error) => {
                            let reason: String = format!(
                                "preparation result unavailable; request retained: {reply_error}"
                            )
                            .chars()
                            .take(1024)
                            .collect();
                            self.observations.failed(
                                "uninstall-result",
                                &self.generation.id,
                                &reason,
                            );
                            false
                        }
                    }
                }
                _ => true,
            };
            self.uninstall_retry_at = preparation_retry_delay(&prepared, rollback_result_published)
                .map(|delay| std::time::Instant::now() + delay);
            if preparation_resolved(&prepared) && rollback_result_published {
                consume_completed_uninstall_request();
            }
            match prepared {
                Ok(PrepareUninstallOutcome::Committed)
                    if crate::uninstall::prepared_marker_valid() =>
                {
                    self.observations.resolved("uninstall-prepare");
                    self.observations.resolved("uninstall-result");
                    self.uninstall_frozen = true;
                }
                Ok(PrepareUninstallOutcome::Committed) => {
                    let error = "uninstall preparation returned without durable authority";
                    crate::uninstall::record_failure(error);
                    log::err("main", error);
                    self.uninstall_frozen = true;
                }
                Ok(PrepareUninstallOutcome::PendingOperation) => {
                    self.observations.waiting(
                        "uninstall-prepare",
                        &self.generation.id,
                        "operation busy",
                    );
                    self.uninstall_frozen = false;
                }
                Ok(PrepareUninstallOutcome::PendingCluster) => {
                    self.uninstall_frozen = false;
                    self.observations.waiting(
                        "uninstall-prepare",
                        &self.generation.id,
                        "waiting for signed Cluster absence",
                    );
                }
                Ok(
                    PrepareUninstallOutcome::RolledBack(error)
                    | PrepareUninstallOutcome::Rejected(error),
                ) => {
                    let reason: String = format!("uninstall preparation failed: {error}")
                        .chars()
                        .take(1024)
                        .collect();
                    if self.observations.failed_changed(
                        "uninstall-prepare",
                        &self.generation.id,
                        &reason,
                    ) {
                        crate::uninstall::record_failure(&error);
                    }
                    self.uninstall_frozen = false;
                }
                Err(error) => {
                    let reason: String = format!("uninstall prepare recovery failed: {error}")
                        .chars()
                        .take(1024)
                        .collect();
                    if self.observations.failed_changed(
                        "uninstall-prepare",
                        &self.generation.id,
                        &reason,
                    ) {
                        crate::uninstall::record_failure(&error);
                    }
                    self.uninstall_frozen = false;
                }
            }
            self.status.write_atomic();
            return DaemonPollDisposition::Continue;
        }
        let candidate = read_plan(&self.generation);
        let startup_changed = candidate.valid
            && (!self.startup_confirmed || candidate.startup != self.status.startup_mode);
        if !candidate.valid {
            // Unknown authority is not a committed None command. Do not run a
            // productive pass or permanently close injection admission for it.
            self.root_plan_unavailable = true;
            self.last_plan = candidate;
            self.observations.failed(
                "root-plan",
                &self.generation.id,
                "invalid root agents.json; effective application fenced",
            );
            self.status.daemon_state = "degraded".into();
            crate::control_plane::pw_transport::cancel();
            self.reconcile_status_entries(&self.last_plan.clone());
            self.quiesce_plan_workers();
            // An independent operator/emergency fence still owns normal teardown.
            if self.kill_switch_blocks_pass() {
                self.stop_injections();
            }
            self.status.write_atomic();
            return DaemonPollDisposition::Continue;
        }
        if self.root_plan_unavailable {
            self.last_plan = candidate.clone();
            // A bounded worker may have finished while authority was unavailable.
            // Consume UnsafeCleanup/panic before any ready publication or new work.
            self.collect_injections(&candidate);
            let workers_stopped = self.quiesce_plan_workers();
            if !self.injection_jobs.is_empty() || !self.rebind_jobs.is_empty() || !workers_stopped {
                // Fresh authority permits the existing terminal-drain pipe policy;
                // new dispatch/config pushes remain behind this recovery barrier.
                self.drain_agent_logs_with_policy(false);
                self.flush_downlinks();
                self.status.write_atomic();
                return DaemonPollDisposition::Continue;
            }
            self.root_plan_unavailable = false;
            if !self.injection_unsafe
                && self.injection_jobs.admissions_open()
                && self.rebind_jobs.admissions_open()
                && !self.safety.kill_switch_active()
            {
                self.status.daemon_state = "ready".into();
            }
        }
        self.startup_confirmed = true;
        self.observations.resolved("root-plan");
        self.last_plan = candidate;
        let plan = self.last_plan.clone();
        self.status.startup_mode = plan.startup;
        log::set_debug(plan.log_level.is_debug());
        self.safety.set_plan_disable_all(plan.disable_all);
        if !plan.valid || plan.disable_all {
            crate::control_plane::pw_transport::cancel();
        }
        self.reconcile_status_entries(&plan);

        // Committed `startup: none` is a product state, not an emergency: the
        // daemon publishes its final status and stops its own init service so
        // nothing of voboost stays resident. Unknown root authority returned
        // above without changing the effective mode or closing admission.
        // The uninstall phases also returned before this point.
        match none_plan_decision(plan.startup, plan.disable_all, self.activation_frozen) {
            NonePlanDecision::NotCommitted => {}
            NonePlanDecision::RebootForUpdate => {
                if !self.quiesce_i18n_resources() {
                    return DaemonPollDisposition::Continue;
                }
                self.stop_injections();
                // An in-flight update outranks the stop: the reboot path owns
                // the process exit.
                self.flush_downlinks();
                self.status.write_atomic();
                #[cfg(target_os = "android")]
                if !self.package_execution.quiesce() {
                    return DaemonPollDisposition::Continue;
                }
                return DaemonPollDisposition::RebootForUpdate;
            }
            NonePlanDecision::SelfStop => {
                if !self.quiesce_i18n_resources() {
                    return DaemonPollDisposition::Continue;
                }
                if !self.status.kill_switch {
                    self.status.kill_switch = true;
                    log::info(
                        "main",
                        "startup=none committed; publishing final status and stopping the service",
                    );
                }
                self.stop_injections();
                #[cfg(target_os = "android")]
                let admission = self.package_execution.poll(&self.generation, plan.startup);
                #[cfg(not(target_os = "android"))]
                let admission = Ok(true);
                return self.complete_none_after_package_admission(&plan, admission);
            }
        }

        if self.kill_switch_blocks_pass() {
            if !self.quiesce_i18n_resources() {
                return DaemonPollDisposition::Continue;
            }
            self.stop_injections();
            if self.activation_frozen {
                self.flush_downlinks();
                self.status.write_atomic();
                #[cfg(target_os = "android")]
                if !self.package_execution.quiesce() {
                    return DaemonPollDisposition::Continue;
                }
                return DaemonPollDisposition::RebootForUpdate;
            }
            return DaemonPollDisposition::Continue;
        }

        let observed_processes = self.generation.catalog.processes();
        let scan_begin = self.started.elapsed().as_millis() as u64;
        let (appeared, died) = self
            .watcher
            .poll_pass_generation(&self.generation, &observed_processes);
        let scan_end = self.started.elapsed().as_millis() as u64;
        self.preparation.observe(
            self.watcher.observed_targets(),
            &observed_processes,
            scan_begin,
            scan_end,
        );
        // The scheduler owns the one-pass action order; this composition root
        // supplies the actions and their pass-local data.
        let locale_endpoint = self.resource_endpoint(voboost_shared::owned_overlay::Owner::Setting);
        for owner in voboost_shared::owned_overlay::Owner::ALL_RESOURCES {
            let resource_endpoint = self
                .watcher
                .tracker()
                .tracked_targets()
                .into_iter()
                .find(|(_, process)| process == owner.process())
                .and_then(|(pid, process)| {
                    self.watcher
                        .tracker()
                        .status_epoch(pid, &process)
                        .map(|epoch| self.endpoint_context(pid, &process, epoch))
                });
            crate::i18n_resources::invalidate_for(
                owner,
                &self.generation,
                &plan,
                resource_endpoint.as_ref(),
                locale_endpoint.as_ref(),
            );
        }

        run_poll_pass_with_startup_confirmation(
            &mut ProductivePollPass {
                daemon: self,
                plan: &plan,
                appeared: &appeared,
                died: &died,
                release_manifest: None,
                tracked: Vec::new(),
            },
            startup_changed,
        );
        // Resource discovery/hash and native OMS commands run in one bounded worker.
        // Vehicle injection and pipe draining above never wait on those process calls.
        #[cfg(target_os = "android")]
        if !self.activation_frozen {
            let locale_endpoint =
                self.resource_endpoint(voboost_shared::owned_overlay::Owner::Setting);
            for owner in voboost_shared::owned_overlay::Owner::ALL_RESOURCES {
                let endpoint = self
                    .watcher
                    .tracker()
                    .tracked_targets()
                    .into_iter()
                    .find(|(_, process)| process == owner.process())
                    .and_then(|(pid, process)| {
                        self.watcher
                            .tracker()
                            .status_epoch(pid, &process)
                            .map(|epoch| self.endpoint_context(pid, &process, epoch))
                    });
                if owner == voboost_shared::owned_overlay::Owner::Setting {
                    let result = crate::cluster_control::project_global_locale(
                        &self.generation,
                        endpoint.as_ref(),
                    );
                    let identity = format!(
                        "{}:{}:{}",
                        self.generation.id,
                        endpoint.as_ref().map_or(0, |ctx| ctx.pid),
                        endpoint.as_ref().map_or(0, |ctx| ctx.endpoint_epoch)
                    );
                    self.observations.result(
                        "i18n-global-locale",
                        &identity,
                        result.as_ref().map(|_| ()).map_err(|error| error.as_str()),
                    );
                }
                let result = crate::i18n_resources::poll(
                    owner,
                    &self.generation,
                    &plan,
                    endpoint.as_ref(),
                    locale_endpoint.as_ref(),
                );
                let identity = crate::i18n_resources::observation_identity(
                    &self.generation,
                    &plan,
                    endpoint.as_ref(),
                    locale_endpoint.as_ref(),
                );
                self.observations.completion(
                    &format!("{}:{}", owner.agent(), owner.process()),
                    &identity,
                    result.as_ref().copied().map_err(|error| error.as_str()),
                );
            }
            crate::i18n_resources::report_scope(&self.generation);
        }
        // Canonical mode is already validated above. Reconcile after a process
        // restart too, covering interruption after commit and before enable.
        #[cfg(target_os = "android")]
        if !self.activation_frozen {
            let result = self.package_execution.poll(&self.generation, plan.startup);
            self.observations.completion(
                "apk-execution",
                &format!("{}:{:?}", self.generation.id, plan.startup),
                result
                    .as_ref()
                    .map(|complete| (*complete).into())
                    .map_err(|error| error.as_str()),
            );
            if result.is_err() {
                return DaemonPollDisposition::Continue;
            }
        }

        if self.activation_frozen {
            if !self.quiesce_i18n_resources() {
                return DaemonPollDisposition::Continue;
            }
            #[cfg(target_os = "android")]
            if !self.package_execution.quiesce() {
                return DaemonPollDisposition::Continue;
            }
            DaemonPollDisposition::RebootForUpdate
        } else {
            DaemonPollDisposition::Continue
        }
    }

    fn complete_none_after_package_admission(
        &mut self,
        plan: &plan::Plan,
        admission: Result<bool, String>,
    ) -> DaemonPollDisposition {
        self.observations.completion(
            "startup-none",
            &format!("{}:{:?}", self.generation.id, plan.startup),
            admission
                .as_ref()
                .map(|complete| (*complete).into())
                .map_err(|error| error.as_str()),
        );
        match admission {
            Ok(true) => {
                self.finish_none_delivery(plan);
                self.status.write_atomic();
                DaemonPollDisposition::SelfStopForNone
            }
            Ok(false) => {
                self.drain_agent_logs_with_policy(false);
                self.flush_downlinks();
                DaemonPollDisposition::Continue
            }
            Err(error) => {
                self.drain_agent_logs_with_policy(false);
                self.flush_downlinks();
                let _ = error; // Failure already observed once above; retries remain productive.
                DaemonPollDisposition::Continue
            }
        }
    }

    fn reconcile_status_entries(&mut self, plan: &plan::Plan) {
        let desired: std::collections::HashSet<_> = plan
            .entries
            .iter()
            .filter(|entry| entry.enabled)
            .flat_map(|entry| {
                self.generation
                    .catalog
                    .find(&entry.id)
                    .into_iter()
                    .flat_map(|agent| agent.targets.iter())
                    .map(|target| (entry.id.clone(), target.process.clone()))
            })
            .collect();
        self.status.retain_injections(&desired);
        for (id, process) in desired {
            let generation = self
                .desired_documents
                .get(&process)
                .map(|state| state.generation);
            self.status.ensure_injection(&id, &process, generation);
            if let Some(error) = plan.runtime_fences.get(&id) {
                self.status.set_injection_event(
                    &id,
                    &process,
                    status::InjectionState::Quarantined,
                    "owned-input-recovery-failed",
                    serde_json::json!({
                        "authority":"fenced", "pendingIntent":"uncertain", "error":error
                    }),
                    generation,
                    None,
                );
            } else {
                self.status
                    .clear_owned_input_fence(&id, &process, generation);
            }
        }
    }

    // Cancel only already-owned resource/package jobs; never project a None
    // startup choice or launch a new operation while root authority is unknown.
    fn quiesce_plan_workers(&mut self) -> bool {
        let stopped = crate::i18n_resources::quiesce();
        #[cfg(target_os = "android")]
        let stopped = self.package_execution.quiesce() && stopped;
        stopped
    }

    fn kill_switch_blocks_pass(&mut self) -> bool {
        if self.safety.kill_switch_active() {
            if !self.status.kill_switch {
                log::info("main", "kill-switch active; idling");
                self.status.kill_switch = true;
                self.status.write_atomic();
            }
            return true;
        }
        if self.status.kill_switch {
            self.status.kill_switch = false;
            log::info("main", "kill-switch cleared but restart required to resume");
            self.status.write_atomic();
            return true;
        }
        false
    }

    fn record_deaths(&mut self, died: &[(i32, String)], plan: &plan::Plan) {
        for (pid, process) in died {
            if crate::process_restart::consume_death(*pid, process) {
                log::info(
                    "main",
                    &format!("authorized removal exit observed for {process} pid={pid}"),
                );
            } else {
                self.safety.note_target_death();
                self.safety.note_target_crash(process);
            }
            // Drop the dead endpoint's stored S snapshot immediately so a
            // reincarnated PID with matching generation identity cannot be
            // promoted from the previous process's snapshot (docs/developer/contracts).
            control_plane::forget_agent_status(process);
            self.set_process_event(
                plan,
                process,
                status::InjectionState::Waiting,
                "target-waiting",
            );
        }
        if self.safety.panic_quarantined() && !self.status.panic_quarantine {
            self.status.panic_quarantine = true;
            log::err("main", "panic-quarantine active");
        }
    }

    fn set_process_event(
        &mut self,
        plan: &plan::Plan,
        process: &str,
        state: status::InjectionState,
        reason: &str,
    ) {
        let ids = plan.enabled_ids_for_process(process, &self.generation.catalog);
        let generation = self
            .desired_documents
            .get(process)
            .map(|document| document.generation);
        for id in ids {
            self.status.set_injection_event(
                &id,
                process,
                state,
                reason,
                serde_json::Value::Object(Default::default()),
                generation,
                None,
            );
        }
    }

    fn track_endpoint(
        &mut self,
        process: &str,
        pid: i32,
        starttime: u64,
        record_fd: Option<i32>,
        downlink_fd: Option<i32>,
    ) -> Result<(), String> {
        let result =
            self.watcher
                .tracker_mut()
                .track(process, pid, starttime, record_fd, downlink_fd);
        result.map_err(|error| {
            self.injection_unsafe = true;
            self.status.daemon_state = "degraded".to_owned();
            self.injection_jobs.close();
            self.rebind_jobs.close();
            let message = format!(
                "endpoint registration failed for {process} pid={pid}: {error}; injection admission closed"
            );
            log::err("injector", &message);
            message
        })
    }

    fn write_desired_document(&mut self, plan: &plan::Plan, process: &str) -> Result<bool, String> {
        let resident_generation = self
            .desired_documents
            .get(process)
            .and_then(|state| state.resident_generation.clone())
            .unwrap_or_else(|| self.generation.clone());
        let settings_loaded = self.settings_loaded_for(process, &resident_generation);
        self.write_desired_document_for(
            plan,
            process,
            resident_generation.clone(),
            settings_loaded,
            self.admitted_ids_for(process, &resident_generation, None),
        )
    }

    fn write_fresh_desired_document(
        &mut self,
        plan: &plan::Plan,
        process: &str,
    ) -> Result<bool, String> {
        self.write_desired_document_for(plan, process, self.generation.clone(), false, Vec::new())
    }

    fn write_desired_document_for(
        &mut self,
        plan: &plan::Plan,
        process: &str,
        resident_generation: generation::VerifiedGeneration,
        settings_loaded: bool,
        admitted_ids: Vec<String>,
    ) -> Result<bool, String> {
        let semantic_document = plan.desired_semantics_for_admitted(
            process,
            &resident_generation,
            settings_loaded,
            &admitted_ids,
        )?;
        let ids = plan.enabled_ids_for_admitted(
            process,
            &resident_generation.catalog,
            settings_loaded,
            &admitted_ids,
        );
        let live_endpoint = self
            .watcher
            .tracker()
            .downlinks()
            .into_iter()
            .find(|(_, name, _, _)| name == process)
            .and_then(|(pid, name, epoch, _)| {
                self.watcher
                    .tracker()
                    .endpoint_starttime(pid, &name, epoch)
                    .map(|starttime| (pid, epoch, starttime))
            });
        let retiring_sources = live_endpoint.map(|(pid, epoch, _)| {
            let context = self.endpoint_context(pid, process, epoch);
            let old_ids: Vec<String> = context.agents.iter().cloned().collect();
            let accepted = control_plane::endpoint_binding(&context).is_some_and(|binding| {
                control_plane::recovery_ready(
                    process,
                    &binding,
                    context.document_generation.unwrap_or(-1),
                    &context.resident_generation_id,
                    &context.resident_catalog_sha256,
                    &old_ids,
                )
            });
            let mut sources = std::collections::HashSet::new();
            if accepted {
                sources.extend(old_ids.into_iter().filter(|id| !ids.contains(id)));
            }
            if let Some(token) = &context.retiring_state {
                sources.extend(
                    token
                        .sources
                        .iter()
                        .filter(|id| !ids.contains(id) && token.permits_retirement(&context, id))
                        .cloned(),
                );
            }
            (
                sources,
                context.retiring_state.as_ref().map(|token| token.expires),
            )
        });
        let previous = self.desired_documents.get(process);
        let Some(generation) = next_desired_generation(
            previous,
            &semantic_document,
            desired_generation_floor(process, &resident_generation, &ids)?,
        )?
        else {
            if let Some(state) = self.desired_documents.get_mut(process) {
                state.admitted_endpoint = live_endpoint;
            }
            return Ok(false);
        };
        if let Some(token) = previous.and_then(|value| value.retiring_state.as_ref()) {
            token
                .revoked
                .store(true, std::sync::atomic::Ordering::Release);
        }
        let restart_removed = restart_removed_agents(previous, &ids, live_endpoint);
        let restart_endpoint = live_endpoint.filter(|_| !restart_removed.is_empty());
        let mut next = DesiredDocumentState::with_ids(
            semantic_document,
            generation,
            ids.clone(),
            resident_generation,
        );
        next.admitted_endpoint = live_endpoint;
        next.restart_endpoint = restart_endpoint;
        next.restart_removed = restart_removed;
        self.desired_documents.insert(process.to_string(), next);
        if let (Some((pid, epoch, _)), Some((sources, old_expiry))) =
            (live_endpoint, retiring_sources)
        {
            if !sources.is_empty() {
                let context = self.endpoint_context(pid, process, epoch);
                if let Some(binding) = control_plane::endpoint_binding(&context) {
                    self.desired_documents
                        .get_mut(process)
                        .unwrap()
                        .retiring_state = Some(agent_log::RetiringState {
                        process: process.to_owned(),
                        binding,
                        sources,
                        expires: old_expiry.unwrap_or_else(|| {
                            std::time::Instant::now() + std::time::Duration::from_secs(30)
                        }),
                        revoked: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                    });
                }
            }
        }
        control_plane::forget_agent_status(process);
        for id in ids {
            self.status.set_injection_event(
                &id,
                process,
                status::InjectionState::Waiting,
                "desired-state-updated",
                serde_json::Value::Object(Default::default()),
                Some(generation),
                None,
            );
        }
        Ok(true)
    }

    fn admitted_ids_for(
        &self,
        process: &str,
        resident: &generation::VerifiedGeneration,
        required_fd: Option<i32>,
    ) -> Vec<String> {
        let current = self
            .watcher
            .tracker()
            .downlinks()
            .into_iter()
            .find(|(_, target, _, fd)| {
                target == process && required_fd.is_none_or(|want| want == *fd)
            });
        let Some((pid, _, epoch, fd)) = current else {
            return Vec::new();
        };
        let endpoint = self
            .watcher
            .tracker()
            .downlink_identity(process, fd)
            .filter(|(target_pid, starttime, target_epoch)| {
                *target_pid == pid
                    && *target_epoch == epoch
                    && self
                        .watcher
                        .tracker()
                        .endpoint_starttime(pid, process, epoch)
                        == Some(*starttime)
            })
            .map(|(pid, starttime, epoch)| (pid, epoch, starttime));
        admitted_ids_for_endpoint(
            self.desired_documents.get(process),
            endpoint,
            self.watcher.tracker().log_generation(pid, process, epoch),
            resident,
        )
        .to_vec()
    }

    fn settings_loaded_for(
        &self,
        process: &str,
        resident: &generation::VerifiedGeneration,
    ) -> bool {
        self.watcher
            .tracker()
            .downlinks()
            .iter()
            .any(|(pid, target, epoch, _)| {
                target == process
                    && self.watcher.tracker().settings_loaded(
                        *pid,
                        process,
                        *epoch,
                        &resident.id,
                        &resident.catalog_sha256,
                    )
            })
    }

    fn bind_loaded_settings(&mut self, process: &str, pid: i32, loaded: bool) {
        let resident = self
            .desired_documents
            .get(process)
            .and_then(|document| document.resident_generation.as_ref())
            .unwrap_or(&self.generation);
        let eligible = loaded && resident.catalog.has_target("settings", process);
        self.watcher.tracker_mut().bind_settings(
            pid,
            &resident.id,
            &resident.catalog_sha256,
            eligible,
        );
    }

    fn bind_settings_delivery(&mut self, plan: &plan::Plan, process: &str, fd: i32) {
        if let Some((pid, _, _)) = self.watcher.tracker().downlink_identity(process, fd) {
            if plan.uninstall_cleanup {
                self.bind_loaded_settings(process, pid, false);
            } else if plan.startup == plan::Startup::Interface
                && self
                    .desired_documents
                    .get(process)
                    .is_some_and(|document| document.ids.iter().any(|id| id == "settings"))
            {
                self.bind_loaded_settings(process, pid, true);
            }
        }
    }

    fn resident_identity(
        &self,
        plan: &plan::Plan,
        process: &str,
        pid: i32,
        starttime: u64,
    ) -> Result<crate::resident_recovery::Identity, String> {
        Ok(crate::resident_recovery::Identity {
            pid,
            starttime,
            generation: self.generation.id.clone(),
            catalog: self.generation.catalog_sha256.clone(),
            semantics: plan.desired_semantics_for_process(process, &self.generation)?,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn rebind_existing_resident(
        &mut self,
        plan: &plan::Plan,
        retained: RetainedGenerationAuthority<'_>,
        process: &str,
        pid: i32,
        maps: &reconcile::ProcMapsSnapshot,
        maps_starttime: u64,
        mut preparation: Option<crate::startup_preparation::Attempt>,
    ) -> Result<(), String> {
        crate::startup_preparation::Attempt::stage(
            &mut preparation,
            crate::startup_preparation::Stage::Rebind,
        );
        if self.pid_owned(pid) {
            return Err("target PID already owns an injection or rebind job".into());
        }
        let abi = reconcile::detect_bitness(pid, maps)
            .ok_or_else(|| format!("resident bitness unavailable: {process} pid={pid}"))?;
        let (initial, initial_generations) =
            attest_retained_catalogs(retained.generations, pid, process, maps_starttime)
                .map_err(|error| format!("retained target identity rejected: {error}"))?;
        let fresh_starttime = target_identity::read_starttime(pid)
            .map_err(|error| format!("resident starttime reread failed: {error}"))?;
        let (authority, authorized_generations) =
            attest_retained_catalogs(retained.generations, pid, process, fresh_starttime)
                .map_err(|error| format!("retained target re-attestation rejected: {error}"))?;
        if authority != initial || authorized_generations != initial_generations {
            return Err("retained target authority changed before rebind".to_string());
        }
        let worker_authority = authority.clone();
        let worker_process = process.to_string();
        let abi = abi.to_string();
        let context = RebindContext {
            recovery_identity: self
                .resident_recovery
                .get(process)
                .map(|recovery| recovery.identity().clone()),
            process: process.to_string(),
            authority,
            generations: retained.generations.to_vec(),
            authorized_generations,
            started: std::time::Instant::now(),
        };
        crate::startup_preparation::Attempt::bind(&mut preparation, initial.starttime);
        crate::startup_preparation::Attempt::ready(
            &mut preparation,
            self.started.elapsed().as_millis() as u64,
        );
        let startup_sample = self.startup_ready(process, pid, initial.starttime, plan);
        self.rebind_jobs
            .dispatch(pid, context, move || {
                let (result, record, downlink, identity) =
                    injector::rebind_resident(pid, &abi, &worker_process, &worker_authority);
                RebindOutcome {
                    result,
                    record: record.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }),
                    downlink: downlink.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }),
                    identity,
                }
            })
            .map_err(|(_, error)| error)?;
        self.startup_dispatched(startup_sample);
        crate::startup_preparation::Attempt::accepted(
            &mut preparation,
            true,
            startup_sample.map(|(_, before)| before),
            self.started.elapsed().as_millis() as u64,
        );
        log::info(
            "injector",
            &format!(
                "rebind job dispatched process={process} pid={pid} starttime={} ownerElapsedMs={}",
                initial.starttime,
                self.started.elapsed().as_millis()
            ),
        );
        self.set_process_event(
            plan,
            process,
            status::InjectionState::Waiting,
            "resident-rebind-running",
        );
        Ok(())
    }

    fn adopt_rebind(
        &mut self,
        plan: &plan::Plan,
        context: RebindContext,
        outcome: RebindOutcome,
        cache_only: bool,
    ) -> Result<(), String> {
        let process = context.process.as_str();
        let pid = context.authority.pid;
        let authority = context.authority;
        let authorized_generations = context.authorized_generations;
        let store = generation::GenerationStore::production();
        let retained = RetainedGenerationAuthority {
            store: &store,
            generations: &context.generations,
        };
        let RebindOutcome {
            result,
            record,
            downlink,
            identity,
        } = outcome;
        if result != injector::InjectResult::Rebound {
            return Err(format!("resident rebind returned {}", result.label()));
        }
        let record = record.ok_or_else(|| "resident rebind lacks log endpoint".to_string())?;
        let downlink =
            downlink.ok_or_else(|| "resident rebind lacks downlink endpoint".to_string())?;
        let record_fd = record.into_raw_fd();
        let downlink_fd = downlink.into_raw_fd();
        let Some(identity) = identity else {
            agent_log::close_fd(record_fd);
            agent_log::close_fd(downlink_fd);
            return Err("resident rebind lacks exact identity".to_string());
        };
        let expected_resident = match exact_rebound_generation(
            retained.generations,
            &authorized_generations,
            &identity,
            process,
        ) {
            Ok(resident) => resident,
            Err(error) => {
                agent_log::close_fd(record_fd);
                agent_log::close_fd(downlink_fd);
                return Err(error);
            }
        };
        let resident = match verify_resident_identity(retained.store, &identity) {
            Ok(resident) => resident,
            Err(error) => {
                agent_log::close_fd(record_fd);
                agent_log::close_fd(downlink_fd);
                return Err(error);
            }
        };
        if resident.id != expected_resident.id
            || resident.catalog_sha256 != expected_resident.catalog_sha256
        {
            agent_log::close_fd(record_fd);
            agent_log::close_fd(downlink_fd);
            return Err("resident generation changed after retained verification".to_string());
        }
        let post_starttime = target_identity::read_starttime(pid).map_err(|error| {
            agent_log::close_fd(record_fd);
            agent_log::close_fd(downlink_fd);
            format!("resident post-transport starttime read failed: {error}")
        })?;
        let resident_agent_ids = retained_agent_ids(&resident, process);
        let post_authority = target_identity::attest_catalog_target_for_agents(
            &resident.catalog,
            pid,
            process,
            post_starttime,
            &resident_agent_ids,
        )
        .map_err(|error| {
            agent_log::close_fd(record_fd);
            agent_log::close_fd(downlink_fd);
            format!("resident exact-generation target re-attestation rejected: {error}")
        })?;
        if post_authority != authority {
            agent_log::close_fd(record_fd);
            agent_log::close_fd(downlink_fd);
            return Err("resident target authority changed after transport identity".to_string());
        }
        let cache_revision = if cache_only {
            Some(
                identity
                    .document_generation
                    .filter(|revision| {
                        *revision >= 0 && *revision <= control_plane::MAX_DOCUMENT_GENERATION
                    })
                    .ok_or_else(|| {
                        agent_log::close_fd(record_fd);
                        agent_log::close_fd(downlink_fd);
                        "resident lacks accepted desired revision for cache maintenance"
                    })?,
            )
        } else {
            None
        };
        self.track_endpoint(
            process,
            pid,
            authority.starttime,
            Some(record_fd),
            Some(downlink_fd),
        )?;
        self.startup_adopted(process, pid, authority.starttime);
        self.watcher
            .tracker_mut()
            .bind_log_generation(pid, &resident.id, &resident.catalog_sha256);
        self.watcher.tracker_mut().bind_settings(
            pid,
            &resident.id,
            &resident.catalog_sha256,
            identity.settings_loaded && resident.catalog.has_target("settings", process),
        );
        if cache_only {
            let revision =
                cache_revision.expect("cache maintenance revision validated before adoption");
            let (_, _, epoch, _) = self
                .watcher
                .tracker()
                .downlinks()
                .into_iter()
                .find(|(target_pid, name, _, _)| *target_pid == pid && name == process)
                .ok_or("cache maintenance endpoint disappeared")?;
            self.uninstall_cache_context = Some(agent_log::EndpointContext {
                pid,
                process: process.to_owned(),
                endpoint_epoch: epoch,
                target_starttime: Some(authority.starttime),
                document_generation: Some(revision),
                resident_generation_id: resident.id.clone(),
                resident_catalog_sha256: resident.catalog_sha256.clone(),
                log_generation: Some((resident.id.clone(), resident.catalog_sha256.clone())),
                retiring_state: None,
                resident_agents: resident_agent_ids.into_iter().map(str::to_owned).collect(),
                ..Default::default()
            });
            return Ok(());
        }
        let settings_loaded = self.settings_loaded_for(process, &resident);
        if let Err(error) = self.write_desired_document_for(
            plan,
            process,
            resident.clone(),
            settings_loaded,
            self.admitted_ids_for(process, &resident, None),
        ) {
            self.watcher.tracker_mut().clear(pid);
            return Err(error);
        }
        if let Err(error) = self.enqueue_desired_snapshot(plan, process, downlink_fd) {
            self.watcher.tracker_mut().clear(pid);
            return Err(error);
        }
        log::ok(
            "main",
            &format!(
                "resident rebound without agent reload: {process} pid={pid} generation={}",
                identity.generation_id
            ),
        );
        Ok(())
    }

    fn enqueue_desired_snapshot(
        &mut self,
        plan: &plan::Plan,
        process: &str,
        fd: i32,
    ) -> Result<i64, String> {
        let state = self
            .desired_documents
            .get(process)
            .ok_or_else(|| format!("desired state missing for {process}"))?;
        let resident_generation = state
            .resident_generation
            .as_ref()
            .unwrap_or(&self.generation);
        let document = plan
            .desired_document_for_admitted(
                process,
                resident_generation,
                state.generation,
                self.settings_loaded_for(process, resident_generation),
                &self.admitted_ids_for(process, resident_generation, Some(fd)),
            )
            .map_err(|error| format!("{error} for {process}"))?;
        let frame =
            render_desired_frame(&document).map_err(|error| format!("{error} for {process}"))?;
        if !downlink::enqueue_frame(fd, &frame) {
            return Err(format!("desired snapshot queue rejected for {process}"));
        }
        let generation = state.generation;
        self.pending_acks.insert(
            process.to_string(),
            PendingAck {
                generation,
                pushed_at: std::time::Instant::now(),
                restarts: 0,
            },
        );
        self.log_queued_desired_snapshot(process, fd, &document, None);
        self.bind_settings_delivery(plan, process, fd);
        Ok(generation)
    }

    /// Atomically queue the runtime desired snapshot before the correlated UI
    /// acknowledgement. Advancing `desired_documents` without this `D` would
    /// make the ordinary live-config pass see no semantic change and strand
    /// the resident runtime on the previous generation forever.
    fn enqueue_confirmed_update(
        &mut self,
        plan: &plan::Plan,
        process: &str,
        fd: i32,
        request_id: u64,
    ) -> Result<i64, String> {
        let state = self
            .desired_documents
            .get(process)
            .ok_or_else(|| format!("desired state missing for {process}"))?;
        let resident_generation = state
            .resident_generation
            .as_ref()
            .unwrap_or(&self.generation);
        let document = plan
            .desired_document_for_admitted(
                process,
                resident_generation,
                state.generation,
                self.settings_loaded_for(process, resident_generation),
                &self.admitted_ids_for(process, resident_generation, Some(fd)),
            )
            .map_err(|error| format!("{error} for {process}"))?;
        let (desired, acknowledgement) = render_confirmed_update_frames(request_id, &document)
            .map_err(|error| format!("{error} for {process}"))?;
        if !downlink::enqueue_frames(fd, &[&desired, &acknowledgement]) {
            return Err(format!(
                "confirmed desired snapshot and mutation ACK queue rejected for {process}"
            ));
        }
        let generation = state.generation;
        self.pending_acks.insert(
            process.to_string(),
            PendingAck {
                generation,
                pushed_at: std::time::Instant::now(),
                restarts: 0,
            },
        );
        self.log_queued_desired_snapshot(process, fd, &document, Some(request_id));
        self.bind_settings_delivery(plan, process, fd);
        Ok(generation)
    }

    fn log_queued_desired_snapshot(
        &self,
        process: &str,
        fd: i32,
        document: &str,
        request_id: Option<u64>,
    ) {
        use sha2::{Digest, Sha256};

        let Ok(identity) = serde_json::from_str::<DesiredSnapshotLogIdentity>(document) else {
            log::err("runtime", "queued desired snapshot metadata is invalid");
            return;
        };
        let mut fields = std::collections::HashMap::from([
            ("process".into(), process.to_string()),
            ("generationId".into(), identity.generation_id),
            ("catalogSha256".into(), identity.catalog_sha256),
            (
                "documentGeneration".into(),
                identity.document_generation.to_string(),
            ),
            (
                "snapshotSha256".into(),
                hex::encode(Sha256::digest(document.as_bytes())),
            ),
            (
                "frames".into(),
                if request_id.is_some() { "D+A" } else { "D" }.into(),
            ),
        ]);
        if let Some((pid, starttime, epoch)) = self.watcher.tracker().downlink_identity(process, fd)
        {
            fields.insert("targetPid".into(), pid.to_string());
            fields.insert("targetStarttime".into(), starttime.to_string());
            fields.insert("endpointEpoch".into(), epoch.to_string());
        }
        if let Some(request_id) = request_id {
            fields.insert("requestId".into(), request_id.to_string());
        }
        log::info_fields("runtime", "desired-snapshot-queued", fields);
    }

    pub(crate) fn prepare_uninstall(
        &mut self,
        store: &generation::GenerationStore,
    ) -> Result<PrepareUninstallOutcome, String> {
        let canonical_path = std::path::PathBuf::from(config::plan_file());
        let previous_canonical = plan::read_canonical_bounded(&canonical_path)
            .map_err(|error| format!("snapshot canonical agents.json: {error}"))?;
        let previous_plan = plan::validate(&self.generation, &previous_canonical);
        if !previous_plan.valid {
            return Err("canonical agents.json snapshot is invalid".to_string());
        }
        // Pending Cluster removal still owns the normal courier endpoints.
        // Collect dispatched jobs even when this pass returns before normal polling.
        self.collect_injections(&previous_plan);
        let discarded_confirmations = agent_events::discard_confirmed_pending();
        if discarded_confirmations > 0 {
            log::info(
                "uninstall",
                &format!(
                    "discarded {discarded_confirmations} pending Settings mutation confirmation(s)"
                ),
            );
        }
        // No general in-process agent teardown: the terminal reboot removes
        // every injected agent physically. The cache-only writer drain below
        // does not disable hooks or deinitialize the implant.
        let result = self.prepare_uninstall_inner(store);
        self.finish_uninstall_preparation(result)
    }

    fn finish_uninstall_preparation(
        &mut self,
        result: Result<(), String>,
    ) -> Result<PrepareUninstallOutcome, String> {
        match result {
            Ok(()) => {
                self.finish_uninstall_cache_maintenance(false);
                Ok(PrepareUninstallOutcome::Committed)
            }
            Err(primary) => {
                let outcome = crate::preparation_error_outcome(primary);
                if matches!(
                    outcome,
                    PrepareUninstallOutcome::PendingOperation
                        | PrepareUninstallOutcome::PendingCluster
                ) {
                    return Ok(outcome);
                }
                self.finish_uninstall_cache_maintenance(true);
                self.activation_frozen = false;
                if !self.injection_unsafe {
                    self.injection_jobs.reopen();
                    self.rebind_jobs.reopen();
                }
                Ok(outcome)
            }
        }
    }

    fn prepare_uninstall_inner(
        &mut self,
        store: &generation::GenerationStore,
    ) -> Result<(), String> {
        let inventory = crate::uninstall::CommittedInventoryProof::load()?;
        // An unavailable Cluster may outlive Android only with retained recovery inputs.
        crate::cluster_control::prepare_android_uninstall(None)?;
        if inventory.context_degraded() {
            log::info(
                "uninstall",
                "committed inventory admitted with a degraded SELinux context; the installed product no longer carries its compile-time labels",
            );
        }
        self.activation_frozen = true;
        self.stop_injections();
        self.pending_retries.clear();

        inventory.revalidate()?;
        let cache_preparation = [
            (
                "recover launcher endpoint",
                self.recover_uninstall_cache_endpoint(store),
            ),
            (
                "quiesce launcher cache",
                self.quiesce_launcher_cache(inventory.transaction_id()),
            ),
        ];
        let uninstall_lease = continue_after_cache_preparation(
            cache_preparation,
            |error| log::err("uninstall", error),
            || crate::uninstall::publish_prepared(crate::uninstall::cleanup_proved(), &inventory),
        )?;
        uninstall_lease.verify_owner()?;
        if let Err(error) =
            crate::uninstall::retry_committed_prepared_with_lease(store, &uninstall_lease)
        {
            crate::uninstall::record_failure(&format!(
                "prepared uninstall freeze/trigger pending retry: {error}"
            ));
            log::err(
                "uninstall",
                &format!("prepared uninstall remains frozen for retry: {error}"),
            );
        }
        Ok(())
    }

    fn finish_uninstall_cache_maintenance(&mut self, rolled_back: bool) {
        if let Some(context) = self.uninstall_cache_context.take() {
            if rolled_back {
                // A maintenance endpoint has no ordinary desired-state document.
                // Close it so normal polling must authenticate and adopt afresh.
                self.watcher.tracker_mut().clear(context.pid);
            }
        }
    }

    fn recover_uninstall_cache_endpoint(
        &mut self,
        store: &generation::GenerationStore,
    ) -> Result<(), String> {
        let process = crate::icon_quiescence::PROCESS;
        if self
            .watcher
            .tracker()
            .downlinks()
            .iter()
            .any(|(_, name, _, _)| name == process)
        {
            return Ok(());
        }
        let Some(pid) = process_watcher::find_pid(process) else {
            return Ok(());
        };
        let (maps, starttime) = target_identity::read_bound_maps(pid)
            .map_err(|error| format!("cache maintenance maps: {error}"))?;
        if !maps.is_injected() {
            return Ok(());
        }
        let retained = store
            .retained_generations()
            .map_err(|error| error.to_string())?;
        let canonical =
            plan::read_canonical_bounded(&std::path::PathBuf::from(config::plan_file()))
                .map_err(|error| error.to_string())?;
        let plan = plan::validate(&self.generation, &canonical);
        if !plan.valid {
            return Err("cache maintenance canonical plan invalid".into());
        }
        self.rebind_jobs.reopen();
        let dispatched = self.rebind_existing_resident(
            &plan,
            RetainedGenerationAuthority {
                store,
                generations: &retained,
            },
            process,
            pid,
            &maps,
            starttime,
            None,
        );
        self.rebind_jobs.close();
        dispatched?;
        // The existing bounded helper owns its deadline and ptrace cleanup.
        // Never detach an in-flight worker or run normal injection adoption here.
        loop {
            self.drain_agent_logs_with_policy(false);
            self.flush_downlinks();
            if let Some((context, result, _timing)) = self.rebind_jobs.collect().into_iter().next()
            {
                let outcome = result?;
                if outcome.result == injector::InjectResult::UnsafeCleanup {
                    self.injection_unsafe = true;
                }
                return self.adopt_rebind(&plan, context, outcome, true);
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    fn service_launcher_observation(&mut self) {
        let endpoints = self
            .watcher
            .tracker()
            .downlinks()
            .into_iter()
            .filter(|(_, process, _, _)| process == crate::launcher_page::PROCESS)
            .collect::<Vec<_>>();
        if let [(pid, process, epoch, fd)] = endpoints.as_slice() {
            crate::launcher_page::dispatch(&self.endpoint_context(*pid, process, *epoch), *fd);
        }
    }

    fn quiesce_launcher_cache(&mut self, transaction_id: &str) -> Result<(), String> {
        use std::io::Read;
        let endpoints = self
            .watcher
            .tracker()
            .downlinks()
            .into_iter()
            .filter(|(_, process, _, _)| process == crate::icon_quiescence::PROCESS)
            .collect::<Vec<_>>();
        crate::icon_quiescence::reset();
        if endpoints.is_empty() {
            let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .map_err(|e| e.to_string())?;
            let receipt = crate::icon_quiescence::no_endpoint_receipt(transaction_id, boot.trim())?;
            crate::icon_quiescence::persist_receipt(&receipt)?;
            log::info(
                "uninstall",
                "no launcher endpoint; uninstaller must prove no live cache writer before purge",
            );
            return Ok(());
        }
        if endpoints.len() != 1 {
            return Err("launcher cache endpoint is absent or ambiguous".to_string());
        }
        let (pid, process, epoch, fd) = &endpoints[0];
        let context = self.endpoint_context(*pid, process, *epoch);
        let mut nonce = [0u8; 32];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut nonce))
            .map_err(|e| e.to_string())?;
        let command = crate::icon_quiescence::begin(&context, hex::encode(nonce))?;
        log::info("uninstall", &format!("launcher cache drain requested pid={pid} starttime={} epoch={epoch} documentGeneration={}", context.target_starttime.unwrap_or(0), context.document_generation.unwrap_or(0)));
        if !crate::downlink::enqueue_frame(*fd, &command) {
            crate::icon_quiescence::reset();
            return Err("launcher cache request could not be delivered".to_string());
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let outcome = (|| loop {
            self.flush_downlinks();
            self.drain_agent_logs_with_policy(false);
            if crate::target_identity::read_starttime(*pid).ok() != context.target_starttime {
                break Err("launcher cache endpoint process changed".to_string());
            }
            if crate::icon_quiescence::acknowledged(&context) {
                let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                    .map_err(|e| e.to_string())?;
                let receipt =
                    crate::icon_quiescence::receipt(&context, transaction_id, boot.trim())?;
                crate::icon_quiescence::persist_receipt(&receipt)?;
                log::info(
                    "uninstall",
                    "launcher cache writer drained; correlated root receipt durable",
                );
                break Ok(());
            }
            if std::time::Instant::now() >= deadline {
                break Err("launcher cache quiescence acknowledgment expired".to_string());
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        })();
        crate::icon_quiescence::reset();
        outcome
    }

    fn build_pipe_bootstrap(&self, plan: &plan::Plan, process: &str) -> Result<Vec<u8>, String> {
        let document_generation = self
            .desired_documents
            .get(process)
            .map(|state| state.generation)
            .ok_or_else(|| format!("desired document generation missing: {process}"))?;
        let (manifest, payloads) =
            bootstrap_metadata(plan, &self.generation, process, document_generation)?;
        let files = payloads
            .iter()
            .map(|payload| bootstrap_pipe::File {
                name: &payload.wire_name,
                size: payload.size,
            })
            .collect::<Vec<_>>();
        bootstrap_pipe::build(&manifest, &files, |index| {
            let payload = &payloads[index];
            self.generation
                .read_file_exact(&payload.source_name)
                .map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("read {}: {error}", payload.context),
                    )
                })
        })
        .map_err(|error| error.to_string())
    }

    /// Drain every active agent log pipe and discard buffers for reaped
    /// targets. Process polling closes dead targets' read ends first.
    fn resource_endpoint(
        &self,
        owner: voboost_shared::owned_overlay::Owner,
    ) -> Option<crate::agent_log::EndpointContext> {
        self.watcher
            .tracker()
            .tracked_targets()
            .into_iter()
            .find(|(_, process)| process == owner.process())
            .and_then(|(pid, process)| {
                self.watcher
                    .tracker()
                    .status_epoch(pid, &process)
                    .map(|epoch| self.endpoint_context(pid, &process, epoch))
            })
    }
    fn endpoint_context(
        &self,
        pid: i32,
        process: &str,
        endpoint_epoch: u64,
    ) -> agent_log::EndpointContext {
        if let Some(context) = &self.uninstall_cache_context {
            if self.activation_frozen
                && context.pid == pid
                && context.process == process
                && context.endpoint_epoch == endpoint_epoch
            {
                return context.clone();
            }
        }
        let document = self.desired_documents.get(process);
        let agents: std::collections::HashSet<String> = document
            .map(|document| document.ids.iter().cloned().collect())
            .unwrap_or_default();
        let resident_generation =
            document.and_then(|document| document.resident_generation.as_ref());
        let mut resident_agents = agents.clone();
        let settings_loaded = resident_generation.is_some_and(|resident| {
            self.watcher.tracker().settings_loaded(
                pid,
                process,
                endpoint_epoch,
                &resident.id,
                &resident.catalog_sha256,
            )
        });
        if !settings_loaded {
            resident_agents.remove("settings");
        }
        let selected = self.generation.installed_agent_ids();
        // Startup-escalation authority is computed from the catalog, never
        // from frame fields: the executors injected into the settings-host
        // process are the only allowed sources of the escalation line.
        let settings_host_process = self
            .generation
            .catalog
            .agents
            .iter()
            .filter(|agent| plan::is_settings_host(&agent.id))
            .any(|agent| self.generation.catalog.has_target(&agent.id, process));
        let startup_escalation_sources = if settings_host_process {
            self.generation
                .catalog
                .agents
                .iter()
                .filter(|agent| {
                    agent.is_executor() && self.generation.catalog.has_target(&agent.id, process)
                })
                .map(|agent| agent.id.clone())
                .collect()
        } else {
            std::collections::HashSet::new()
        };
        agent_log::EndpointContext {
            owner_started: Some(self.started),
            retiring_state: document.and_then(|value| value.retiring_state.clone()),
            pid,
            process: process.to_string(),
            endpoint_epoch,
            log_generation: self
                .watcher
                .tracker()
                .log_generation(pid, process, endpoint_epoch),
            target_starttime: self.watcher.tracker().endpoint_starttime(
                pid,
                process,
                endpoint_epoch,
            ),
            document_generation: document.map(|document| document.generation),
            restart_allowed: process != "system_server"
                && document.is_some_and(|document| {
                    document
                        .restart_endpoint
                        .is_some_and(|(old_pid, old_epoch, old_starttime)| {
                            old_pid == pid
                                && old_epoch == endpoint_epoch
                                && self.watcher.tracker().endpoint_starttime(
                                    pid,
                                    process,
                                    endpoint_epoch,
                                ) == Some(old_starttime)
                        })
                }),
            resident_agents,
            agents,
            selected_agents: selected.iter().map(|id| (*id).to_string()).collect(),
            startup_escalation_sources,
            resident_generation_id: resident_generation
                .map(|generation| generation.id.clone())
                .unwrap_or_default(),
            resident_catalog_sha256: resident_generation
                .map(|generation| generation.catalog_sha256.clone())
                .unwrap_or_default(),
            active_generation_id: self.generation.id.clone(),
            active_catalog_sha256: self.generation.catalog_sha256.clone(),
            known_agents: self
                .generation
                .catalog
                .agents
                .iter()
                .filter(|agent| selected.contains(agent.id.as_str()))
                .map(|agent| (agent.id.clone(), agent.disables.clone().unwrap_or_default()))
                .collect(),
            known_options: self
                .generation
                .catalog
                .agents
                .iter()
                .filter(|agent| selected.contains(agent.id.as_str()))
                .filter(|agent| !agent.options.as_deref().unwrap_or(&[]).is_empty())
                .map(|agent| {
                    (
                        agent.id.clone(),
                        agent
                            .options
                            .as_deref()
                            .unwrap_or(&[])
                            .iter()
                            .map(|option| {
                                (
                                    option.key.clone(),
                                    agent_log::KnownOption {
                                        option_type: option.option_type.clone(),
                                        values: option
                                            .values
                                            .iter()
                                            .map(|value| value.value.clone())
                                            .collect(),
                                    },
                                )
                            })
                            .collect(),
                    )
                })
                .collect(),
        }
    }

    fn drain_agent_logs(&mut self) {
        self.drain_agent_logs_with_policy(true);
    }

    fn drain_agent_logs_with_policy(&mut self, mutations_allowed: bool) {
        let log_pipes = self.watcher.tracker().log_pipes();
        let active_log_fds = log_pipes
            .iter()
            .map(|(_, _, _, fd, _)| *fd)
            .collect::<std::collections::HashSet<_>>();
        crate::native_commands::retain_endpoints(
            &log_pipes
                .iter()
                .map(|(pid, _, epoch, _, _)| (*pid, *epoch))
                .collect::<Vec<_>>(),
        );
        self.drain_buffers.retain_active(&active_log_fds);
        for (pid, process, endpoint_epoch, read_fd, reply_fd) in log_pipes {
            // Capability-scoped routing: the endpoint context comes from the
            // daemon's tracker + resident desired document, never from the
            // frame itself (docs/developer/contracts).
            let context = self.endpoint_context(pid, &process, endpoint_epoch);
            crate::native_commands::pump(&context, reply_fd, mutations_allowed);
            let buffer = self.drain_buffers.get_or_insert(read_fd);
            if mutations_allowed {
                agent_log::drain(read_fd, reply_fd, buffer, &context);
            } else {
                agent_log::drain_uninstall_preparing(read_fd, reply_fd, buffer, &context);
            }
        }
    }

    fn prepare_startup_milestones(&mut self, plan: &plan::Plan) {
        let processes = self
            .generation
            .catalog
            .agents
            .iter()
            .flat_map(|a| a.targets.iter().map(|t| t.process.clone()))
            .collect::<std::collections::HashSet<_>>();
        let mut members = std::collections::HashSet::new();
        for process in &processes {
            let enabled = plan.enabled_ids_for_process(process, &self.generation.catalog);
            for agent in &self.generation.catalog.agents {
                if agent.startup_priority == Some(crate::catalog::StartupPriority::Vehicle)
                    && enabled.contains(&agent.id)
                    && self.generation.catalog.has_target(&agent.id, process)
                {
                    members.insert((agent.id.clone(), process.clone()));
                }
            }
        }
        self.status.startup_vehicle_members = members;
        let reset = self.status.startup_milestones.as_ref().is_none_or(|t| {
            t.identity.generation_id != self.generation.id
                || t.identity.catalog_sha256 != self.generation.catalog_sha256
                || t.identity.manifest_sha256 != self.status.manifest_sha256
        });
        if reset {
            if let Some(identity) = control_plane::daemon_identity() {
                if let (Ok(pid), Ok(starttime)) = (
                    identity.daemon_pid.parse(),
                    identity.daemon_starttime.parse(),
                ) {
                    self.status.startup_milestones = Some(crate::startup::Milestones::new(
                        crate::startup::Identity {
                            boot_id: identity.boot_id,
                            daemon_pid: pid,
                            daemon_starttime: starttime,
                            manifest_sha256: self.status.manifest_sha256.clone(),
                            generation_id: self.generation.id.clone(),
                            catalog_sha256: self.generation.catalog_sha256.clone(),
                        },
                        processes.len(),
                        self.status.startup_vehicle_members.len(),
                    ));
                }
            }
        }
        if let Some(tracker) = self.status.startup_milestones.as_mut() {
            tracker.clock_anchor = self.startup_clock_anchor.clone();
            tracker.expected_target_count = processes.len();
            tracker.expected_member_count = self.status.startup_vehicle_members.len();
            tracker.members.retain(|m| {
                tracker.targets.get(m.target).is_some_and(|t| {
                    self.status
                        .startup_vehicle_members
                        .contains(&(m.id.clone(), t.process.clone()))
                })
            });
        }
    }

    fn begin_preparation(
        &mut self,
        process: &str,
        pid: i32,
    ) -> Option<crate::startup_preparation::Attempt> {
        let identity = self.status.startup_milestones.as_ref()?.identity.clone();
        self.preparation.begin(
            identity,
            process,
            pid,
            self.started.elapsed().as_millis() as u64,
            self.started,
        )
    }

    fn startup_ready(
        &mut self,
        process: &str,
        pid: i32,
        starttime: u64,
        plan: &plan::Plan,
    ) -> Option<(usize, u64)> {
        let now = self.started.elapsed().as_millis() as u64;
        let tracker = self.status.startup_milestones.as_mut()?;
        let index = tracker.ready(crate::startup::Target {
            process: process.to_string(),
            pid,
            starttime,
            ready_ms: now,
            batch: tracker.batch_counter,
            priority: plan.startup_priority(process, &self.generation.catalog),
            dispatch_ms: None,
            dispatch_rank: None,
            endpoint_epoch: None,
            adopted_ms: None,
        })?;
        Some((index, now))
    }

    fn startup_dispatched(&mut self, sample: Option<(usize, u64)>) {
        if let (Some((index, before)), Some(tracker)) =
            (sample, self.status.startup_milestones.as_mut())
        {
            let rank = tracker.next_rank();
            tracker.dispatched(index, before, rank);
        }
    }

    fn startup_adopted(&mut self, process: &str, pid: i32, starttime: u64) {
        let Some(epoch) = self.watcher.tracker().status_epoch(pid, process) else {
            return;
        };
        if let Some(tracker) = self.status.startup_milestones.as_mut() {
            if let Some(index) = tracker.target_index(process) {
                tracker.adopted(
                    index,
                    pid,
                    starttime,
                    epoch,
                    self.started.elapsed().as_millis() as u64,
                );
            }
        }
    }

    fn dispatch_injections(
        &mut self,
        appeared: &[(String, i32)],
        plan: &plan::Plan,
        release_manifest: &Option<voboost_contract::release::Manifest>,
    ) {
        self.prepare_startup_milestones(plan);
        if let Some(tracker) = self.status.startup_milestones.as_mut() {
            tracker.begin_batch();
        }
        if !self.injection_jobs.admissions_open() || !self.rebind_jobs.admissions_open() {
            return;
        }
        let mut appeared = appeared.to_vec();
        for (pid, process) in self.watcher.tracker().tracked_targets() {
            if !self.watcher.tracker().is_tracked_with_pipes(pid)
                && !self.pending_retries.contains_key(&process)
                && self
                    .resident_recovery
                    .get(&process)
                    .is_some_and(|recovery| {
                        recovery.admit(self.started.elapsed())
                            == crate::resident_recovery::Admission::Ready
                    })
                && !appeared.iter().any(|(_, existing)| *existing == pid)
            {
                appeared.push((process, pid));
            }
        }
        let mut retries = self
            .pending_retries
            .iter()
            .map(|(process, retry)| (process.clone(), retry.pid))
            .collect::<Vec<_>>();
        retries.sort_by(|left, right| left.0.cmp(&right.0));
        let priorities = appeared
            .iter()
            .chain(&retries)
            .map(|(process, _)| {
                (
                    process.clone(),
                    plan.startup_priority(process, &self.generation.catalog),
                )
            })
            .collect::<std::collections::HashMap<_, _>>();
        runtime_loop::run_mixed_startup_batch(
            &appeared,
            &retries,
            |(process, _)| priorities[process],
            |retry, step| match step {
                runtime_loop::TargetBatchStep::ServiceTrackedPipes => {
                    self.drain_agent_logs();
                    self.flush_downlinks();
                }
                runtime_loop::TargetBatchStep::Inject((process, pid)) => {
                    if retry {
                        self.retry_pending(std::slice::from_ref(process), plan);
                    } else {
                        self.inject_new_targets(
                            &[(process.clone(), *pid)],
                            plan,
                            release_manifest,
                            true,
                        );
                    }
                }
            },
        );
    }

    fn inject_new_targets(
        &mut self,
        appeared: &[(String, i32)],
        plan: &plan::Plan,
        release_manifest: &Option<voboost_contract::release::Manifest>,
        attempt_rebind: bool,
    ) {
        let priorities: std::collections::HashMap<_, _> = appeared
            .iter()
            .map(|(process, _)| {
                let priority = plan.startup_priority(process, &self.generation.catalog);
                (process.clone(), priority)
            })
            .collect();
        runtime_loop::run_startup_batch(
            appeared,
            |(process, _)| priorities[process],
            |step| {
                let runtime_loop::TargetBatchStep::Inject((process, pid)) = step else {
                    self.drain_agent_logs();
                    self.flush_downlinks();
                    return;
                };
                // `appeared` predates completion collection in this pass.
                // A newly adopted endpoint already owns this live process.
                if self.pid_owned(*pid)
                    || self.watcher.tracker().is_tracked_with_pipes(*pid)
                    || self.pending_retries.contains_key(process)
                {
                    return;
                }
                let agent_ids = plan.enabled_ids_for_process(process, &self.generation.catalog);
                // Executors are not plan-gated: a process with an executor target
                // injects even when no plan agent is enabled for it.
                let has_executor = self.generation.catalog.agents.iter().any(|agent| {
                    agent.is_executor() && self.generation.catalog.has_target(&agent.id, process)
                });
                let agent_id = agent_ids.first().cloned().unwrap_or_else(|| {
                    self.generation
                        .catalog
                        .agents
                        .iter()
                        .find(|agent| {
                            agent.is_executor()
                                && self.generation.catalog.has_target(&agent.id, process)
                        })
                        .map(|agent| agent.id.clone())
                        .unwrap_or_default()
                });
                let _ = has_executor;
                if self.safety.is_target_degraded(process)
                    || self.safety.is_quarantined(&agent_id, process)
                    || agent_ids
                        .iter()
                        .any(|id| self.safety.is_quarantined(id, process))
                {
                    return;
                }
                let authority_ids = bootstrap_authority_ids(&self.generation, process, &agent_ids);
                let module_wanted = !authority_ids.is_empty() || has_executor;
                let mut preparation = self.begin_preparation(process, *pid);
                let (maps, maps_starttime) = match target_identity::read_bound_maps(*pid) {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        log::err(
                            "main",
                            &format!("bounded maps snapshot failed: {process} pid={pid}: {error}"),
                        );
                        self.set_process_event(
                            plan,
                            process,
                            status::InjectionState::Failed,
                            "maps-classification-failed",
                        );
                        return;
                    }
                };
                crate::startup_preparation::Attempt::bind(&mut preparation, maps_starttime);
                let already_injected = maps.is_injected();
                let action = target_action(already_injected, module_wanted);
                if action != TargetAction::TrackExistingImplant {
                    // A newly unmapped process ends the old resident lifecycle.
                    // Mapped disabled modules still need their control transport.
                    self.resident_recovery.remove(process);
                }
                if action == TargetAction::ObserveOnly {
                    crate::startup_preparation::Attempt::cancel(&mut preparation);
                    return;
                }
                if action == TargetAction::TrackExistingImplant && attempt_rebind {
                    let identity = match self.resident_identity(plan, process, *pid, maps_starttime)
                    {
                        Ok(identity) => identity,
                        Err(_) => {
                            self.set_process_event(
                                plan,
                                process,
                                status::InjectionState::Failed,
                                "resident-recovery-identity-unavailable",
                            );
                            return;
                        }
                    };
                    let recovery = self
                        .resident_recovery
                        .entry(process.clone())
                        .or_insert_with(|| {
                            crate::resident_recovery::Recovery::new(identity.clone())
                        });
                    recovery.bind(identity);
                    match recovery.admit(self.started.elapsed()) {
                        crate::resident_recovery::Admission::Ready => {
                            log::debug("main", &format!("resident transport recovery admitted process={process} pid={pid}"));
                            recovery.attempted();
                        }
                        crate::resident_recovery::Admission::Backoff => {
                            self.set_process_event(
                                plan,
                                process,
                                status::InjectionState::Waiting,
                                "resident-rebind-backoff",
                            );
                            return;
                        }
                        crate::resident_recovery::Admission::Exhausted => {
                            self.set_process_event(
                                plan,
                                process,
                                status::InjectionState::Failed,
                                "resident-rebind-exhausted",
                            );
                            return;
                        }
                    }
                }
                match action {
                    TargetAction::TrackExistingImplant if attempt_rebind => {
                        let store = generation::GenerationStore::production();
                        let retained = match store.retained_generations() {
                            Ok(retained) => retained,
                            Err(error) => {
                                self.set_process_event(
                                    plan,
                                    process,
                                    status::InjectionState::Waiting,
                                    "resident-generation-verification-failed",
                                );
                                if self
                                    .track_endpoint(process, *pid, maps_starttime, None, None)
                                    .is_err()
                                {
                                    return;
                                }
                                log::err(
                                "main",
                                &format!(
                                    "retained generation verification failed for resident {process} pid={pid}: {error}"
                                ),
                            );
                                return;
                            }
                        };
                        if let Err(error) = self.rebind_existing_resident(
                            plan,
                            RetainedGenerationAuthority {
                                store: &store,
                                generations: &retained,
                            },
                            process,
                            *pid,
                            &maps,
                            maps_starttime,
                            preparation,
                        ) {
                            self.set_process_event(
                                plan,
                                process,
                                status::InjectionState::Waiting,
                                "resident-rebind-failed",
                            );
                            if self
                                .track_endpoint(process, *pid, maps_starttime, None, None)
                                .is_err()
                            {
                                return;
                            }
                            log::err(
                            "main",
                            &format!("resident rebind failed for {process} pid={pid}: {error}; resident bootstrap replay forbidden"),
                        );
                            // Predispatch authority/ABI/generation errors are terminal
                            // for this identity. Only a completed native transient
                            // outcome may arm transport recovery.
                        }
                        // A failed resident rebind does not authorize another bootstrap.
                        return;
                    }
                    TargetAction::ObserveOnly => unreachable!(),
                    TargetAction::Inject | TargetAction::TrackExistingImplant => {}
                }

                crate::startup_preparation::Attempt::stage(
                    &mut preparation,
                    crate::startup_preparation::Stage::Authority,
                );
                let initial_authority = match target_identity::attest_catalog_target_for_agents(
                    &self.generation.catalog,
                    *pid,
                    process,
                    maps_starttime,
                    &authority_ids,
                ) {
                    Ok(authority) => authority,
                    Err(error) => {
                        log::err(
                            "main",
                            &format!("target identity rejected: {process} pid={pid}: {error:#}"),
                        );
                        self.set_process_event(
                            plan,
                            process,
                            status::InjectionState::Failed,
                            "target-identity-rejected",
                        );
                        return;
                    }
                };

                if self.safety.is_target_degraded(process) {
                    self.set_process_event(
                        plan,
                        process,
                        status::InjectionState::Degraded,
                        "target-degraded",
                    );
                    return;
                }

                if maps.has_foreign_footprint() {
                    log::info("main", &format!("coexistence skip: {process} pid={pid}"));
                    self.set_process_event(
                        plan,
                        process,
                        status::InjectionState::SkippedCoexist,
                        "foreign-footprint",
                    );
                    return;
                }

                let Some(abi) = reconcile::detect_bitness(*pid, &maps) else {
                    log::err(
                        "main",
                        &format!("bitness detection failed: {process} pid={pid}"),
                    );
                    self.set_process_event(
                        plan,
                        process,
                        status::InjectionState::Failed,
                        "bitness-detection-failed",
                    );
                    return;
                };

                // A fresh injection always binds state to the current generation.
                // A dead R1 endpoint may have left DesiredDocumentState behind
                // after a passive R2 cutover; never reuse that resident identity
                // for an R2 bootstrap.
                crate::startup_preparation::Attempt::stage(
                    &mut preparation,
                    crate::startup_preparation::Stage::Desired,
                );
                if let Err(error) = self.write_fresh_desired_document(plan, process) {
                    log::err(
                        "main",
                        &format!("desired document write failed for {process}: {error}"),
                    );
                    self.set_process_event(
                        plan,
                        process,
                        status::InjectionState::Failed,
                        "desired-document-write-failed",
                    );
                    return;
                }
                crate::startup_preparation::Attempt::stage(
                    &mut preparation,
                    crate::startup_preparation::Stage::Bootstrap,
                );
                let pipe_bootstrap = match self.build_pipe_bootstrap(plan, process) {
                    Ok(envelope) => envelope,
                    Err(error) => {
                        log::err(
                            "main",
                            &format!("pipe bootstrap build failed for {process}: {error}"),
                        );
                        self.set_process_event(
                            plan,
                            process,
                            status::InjectionState::Failed,
                            "pipe-bootstrap-build-failed",
                        );
                        return;
                    }
                };

                crate::startup_preparation::Attempt::stage(
                    &mut preparation,
                    crate::startup_preparation::Stage::Payload,
                );
                if !verify_payload_before_inject(release_manifest, abi, process) {
                    self.safety.note_failure(&agent_id, process);
                    self.set_process_event(
                        plan,
                        process,
                        status::InjectionState::Failed,
                        "payload-verification-failed",
                    );
                    return;
                }

                crate::startup_preparation::Attempt::stage(
                    &mut preparation,
                    crate::startup_preparation::Stage::FinalAttestation,
                );
                let final_starttime = match target_identity::read_starttime(*pid) {
                    Ok(starttime) => starttime,
                    Err(error) => {
                        log::err(
                            "main",
                            &format!("target identity starttime reread failed: {error}"),
                        );
                        self.set_process_event(
                            plan,
                            process,
                            status::InjectionState::Failed,
                            "target-identity-stale",
                        );
                        return;
                    }
                };
                let authority = match target_identity::attest_catalog_target_for_agents(
                    &self.generation.catalog,
                    *pid,
                    process,
                    final_starttime,
                    &authority_ids,
                ) {
                    Ok(authority) if authority.starttime == initial_authority.starttime => {
                        authority
                    }
                    Ok(_) => {
                        self.set_process_event(
                            plan,
                            process,
                            status::InjectionState::Failed,
                            "target-identity-pid-reused",
                        );
                        return;
                    }
                    Err(error) => {
                        log::err(
                            "main",
                            &format!("target identity re-attestation rejected: {error}"),
                        );
                        self.set_process_event(
                            plan,
                            process,
                            status::InjectionState::Failed,
                            "target-identity-stale",
                        );
                        return;
                    }
                };

                crate::startup_preparation::Attempt::bind(&mut preparation, authority.starttime);
                crate::startup_preparation::Attempt::ready(
                    &mut preparation,
                    self.started.elapsed().as_millis() as u64,
                );
                let desired = &self.desired_documents[process];
                let retry = PendingRetry {
                    pid: *pid,
                    starttime: authority.starttime,
                    attempts: 0,
                    next_retry_at: std::time::Duration::ZERO,
                    generation: self.generation.clone(),
                    agent_ids,
                    desired_semantics: desired.semantic_document.clone(),
                    document_generation: desired.generation,
                    release_manifest: release_manifest.clone(),
                    bootstrap: std::sync::Arc::new(pipe_bootstrap),
                };
                self.dispatch_bootstrap(
                    process,
                    retry,
                    authority,
                    abi,
                    agent_id,
                    plan,
                    preparation,
                );
            },
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn dispatch_bootstrap(
        &mut self,
        process: &str,
        retry: PendingRetry,
        authority: target_identity::AttestedTarget,
        abi: &str,
        agent_id: String,
        plan: &plan::Plan,
        mut preparation: Option<crate::startup_preparation::Attempt>,
    ) {
        let pid = retry.pid;
        if self.pid_owned(pid) {
            return;
        }
        let starttime = retry.starttime;
        let generation_id = retry.generation.id.clone();
        let envelope = retry.bootstrap.clone();
        let worker_authority = authority.clone();
        let worker_process = process.to_string();
        let abi = abi.to_string();
        let context = InjectionContext {
            process: process.to_string(),
            authority,
            retry,
            agent_id,
            started: std::time::Instant::now(),
        };
        let startup_sample = self.startup_ready(process, pid, starttime, plan);
        match self.injection_jobs.dispatch(pid, context, move || {
            injector::inject_pipe_bootstrap(
                pid,
                &abi,
                &envelope,
                &worker_process,
                &worker_authority,
            )
        }) {
            Ok(()) => {
                self.startup_dispatched(startup_sample);
                crate::startup_preparation::Attempt::accepted(
                    &mut preparation,
                    false,
                    startup_sample.map(|(_, before)| before),
                    self.started.elapsed().as_millis() as u64,
                );
                log::info("injector", &format!("bootstrap job dispatched process={process} pid={pid} starttime={starttime} generation={generation_id} ownerElapsedMs={}", self.started.elapsed().as_millis()));
                self.set_process_event(
                    plan,
                    process,
                    status::InjectionState::Waiting,
                    "injection-running",
                );
            }
            Err((_, error)) => {
                log::err("main", &format!("{process} pid={pid} {error}"));
                self.set_process_event(
                    plan,
                    process,
                    status::InjectionState::Failed,
                    "injection-worker-unavailable",
                );
            }
        }
    }

    fn rebind_recovery_current(
        &self,
        plan: &plan::Plan,
        context: &RebindContext,
        observed_starttime: Option<u64>,
    ) -> bool {
        let Some(captured) = context.recovery_identity.as_ref() else {
            return false;
        };
        observed_starttime == Some(context.authority.starttime)
            && self
                .resident_identity(
                    plan,
                    &context.process,
                    context.authority.pid,
                    context.authority.starttime,
                )
                .ok()
                .as_ref()
                == Some(captured)
            && self
                .resident_recovery
                .get(&context.process)
                .is_some_and(|recovery| recovery.identity() == captured)
    }

    fn collect_rebind_outcome(
        &mut self,
        plan: &plan::Plan,
        context: RebindContext,
        outcome: RebindOutcome,
        observed_starttime: Option<u64>,
    ) {
        let process = context.process.clone();
        let pid = context.authority.pid;

        if outcome.result == injector::InjectResult::UnsafeCleanup {
            self.injection_unsafe = true;
            self.status.daemon_state = "degraded".into();
            self.injection_jobs.close();
            self.rebind_jobs.close();
        }
        if !self.rebind_recovery_current(plan, &context, observed_starttime) {
            // Drop owned descriptors without adopting stale authority or
            // changing a newer recovery budget, desired document or status.
            log::info(
                "injector",
                &format!("stale resident recovery completion rejected process={process} pid={pid}"),
            );
            return;
        }
        let retryable = matches!(
            outcome.result,
            injector::InjectResult::InitFailed
                | injector::InjectResult::Pending
                | injector::InjectResult::RegisterDeferred
        );
        if let Err(error) = self.adopt_rebind(plan, context, outcome, false) {
            log::err(
                "injector",
                &format!("resident rebind failed: {process} pid={pid}: {error}"),
            );
            // A mapped implant may own an incomplete Java bootstrap or an
            // uncertain pipe handoff. Never replay a full bootstrap here.
            if let Some(recovery) = self.resident_recovery.get_mut(&process) {
                if retryable {
                    recovery.failed(self.started.elapsed());
                }
                self.set_process_event(
                    plan,
                    &process,
                    status::InjectionState::Failed,
                    "resident-rebind-failed",
                );
            }
        } else if let Some(recovery) = self.resident_recovery.get_mut(&process) {
            // Keep a completion-based cooldown if this valid endpoint closes
            // before the accepted ready receipt can clear the recovery budget.
            recovery.failed(self.started.elapsed());
        }
    }

    fn collect_injections(&mut self, plan: &plan::Plan) {
        for (context, result, timing) in self.rebind_jobs.collect() {
            log::info("injector", &format!("rebind job completed process={} pid={} starttime={} elapsedMs={} ownerElapsedMs={}", context.process, context.authority.pid, context.authority.starttime, context.started.elapsed().as_millis(), self.started.elapsed().as_millis()));
            log::info(
                "injector",
                &format!(
                    "rebind worker timing process={} workerElapsedMs={:?} collectionDelayMs={:?}",
                    context.process,
                    timing.worker_elapsed.map(|value| value.as_millis()),
                    timing.collection_delay.map(|value| value.as_millis())
                ),
            );
            let observed_starttime = target_identity::read_starttime(context.authority.pid).ok();
            match result {
                Ok(outcome) => {
                    self.collect_rebind_outcome(plan, context, outcome, observed_starttime)
                }
                Err(error) => {
                    self.injection_unsafe = true;
                    self.status.daemon_state = "degraded".into();
                    self.injection_jobs.close();
                    self.rebind_jobs.close();
                    log::err("injector", &error);
                }
            }
        }
        for (context, result, timing) in self.injection_jobs.collect() {
            log::info(
                "injector",
                &format!(
                    "worker timing process={} workerElapsedMs={:?} collectionDelayMs={:?}",
                    context.process,
                    timing.worker_elapsed.map(|value| value.as_millis()),
                    timing.collection_delay.map(|value| value.as_millis())
                ),
            );
            log::info(
                "injector",
                &format!(
                    "job completed process={} pid={} starttime={} generation={} elapsedMs={} ownerElapsedMs={}",
                    context.process,
                    context.retry.pid,
                    context.retry.starttime,
                    context.retry.generation.id,
                    context.started.elapsed().as_millis(),
                    self.started.elapsed().as_millis()
                ),
            );
            let outcome = match result {
                Ok(outcome) => outcome,
                Err(error) => {
                    // A panic cannot supply native cleanup proof. Close admissions;
                    // retained workers still complete before the daemon relinquishes ownership.
                    self.injection_unsafe = true;
                    self.status.daemon_state = "degraded".into();
                    self.injection_jobs.close();
                    self.rebind_jobs.close();
                    log::err("injector", &error);
                    continue;
                }
            };
            let identity_matches = target_identity::read_starttime(context.retry.pid)
                .ok()
                .and_then(|starttime| {
                    target_identity::attest_catalog_target_for_agents(
                        &context.retry.generation.catalog,
                        context.retry.pid,
                        &context.process,
                        starttime,
                        &bootstrap_authority_ids(
                            &context.retry.generation,
                            &context.process,
                            &context.retry.agent_ids,
                        ),
                    )
                    .ok()
                })
                .is_some_and(|authority| authority == context.authority);
            self.adopt_injection(context, outcome, plan, identity_matches);
        }
    }

    fn adopt_injection(
        &mut self,
        context: InjectionContext,
        outcome: injector::BootstrapOutcome,
        plan: &plan::Plan,
        identity_matches: bool,
    ) {
        let InjectionContext {
            process,
            mut retry,
            agent_id,
            ..
        } = context;
        if outcome.result == injector::InjectResult::UnsafeCleanup {
            // This completion fences the whole daemon even when its original
            // target or desired document has changed. Keep that cause before
            // rejecting stale per-agent state below.
            self.status.last_unsafe_native_failure = Some(status::UnsafeNativeFailure {
                process: process.clone(),
                target_pid: retry.pid,
                target_starttime: retry.starttime,
                generation_id: retry.generation.id.clone(),
                catalog_sha256: retry.generation.catalog_sha256.clone(),
                document_generation: retry.document_generation,
                diagnostic: outcome
                    .failure
                    .clone()
                    .unwrap_or_else(|| injector::NativeFailure::classify(outcome.result, "")),
            });
            self.injection_unsafe = true;
            self.status.daemon_state = "degraded".into();
            self.injection_jobs.close();
            self.rebind_jobs.close();
            log::err(
                "injector",
                "native cleanup unproved; injection admissions fenced",
            );
        }
        if !identity_matches {
            // Owned descriptors close here. Never clear a newer PID registration.
            log::info(
                "injector",
                &format!(
                    "stale target completion rejected: {process} pid={} starttime={}",
                    retry.pid, retry.starttime
                ),
            );
            return;
        }
        let current = self.generation.id == retry.generation.id
            && self.generation.catalog_sha256 == retry.generation.catalog_sha256
            && plan.enabled_ids_for_process(&process, &self.generation.catalog) == retry.agent_ids
            && plan
                .desired_semantics_for_process(&process, &self.generation)
                .ok()
                .as_deref()
                == Some(&retry.desired_semantics)
            && self
                .desired_documents
                .get(&process)
                .is_some_and(|document| document.generation == retry.document_generation);
        let result = outcome.result;
        if matches!(
            result,
            injector::InjectResult::Ok | injector::InjectResult::Staged
        ) {
            let injector::BootstrapOutcome {
                record,
                downlink,
                binding,
                ..
            } = outcome;
            if (result == injector::InjectResult::Staged) != binding.is_some() {
                log::err(
                    "injector",
                    "completed bootstrap has inconsistent staged ownership",
                );
                return;
            }
            let (Some(record), Some(downlink)) = (record, downlink) else {
                log::err("injector", "completed bootstrap lacks owned endpoints");
                return;
            };
            if let Some(binding) = binding {
                crate::bootstrap_worker::register(binding);
            }
            let downlink = downlink.into_raw_fd();
            if self
                .track_endpoint(
                    &process,
                    retry.pid,
                    retry.starttime,
                    Some(record.into_raw_fd()),
                    Some(downlink),
                )
                .is_err()
            {
                crate::bootstrap_worker::forget(retry.pid);
                self.set_process_event(
                    plan,
                    &process,
                    status::InjectionState::Failed,
                    "endpoint-registration-failed",
                );
                return;
            }
            self.startup_adopted(&process, retry.pid, retry.starttime);
            self.watcher.tracker_mut().bind_log_generation(
                retry.pid,
                &retry.generation.id,
                &retry.generation.catalog_sha256,
            );
            let settings_loaded = result == injector::InjectResult::Ok
                && retry.agent_ids.iter().any(|id| id == "settings");
            self.watcher.tracker_mut().bind_settings(
                retry.pid,
                &retry.generation.id,
                &retry.generation.catalog_sha256,
                settings_loaded,
            );
            // Even a generation/document cutover retains control of code already
            // loaded under the old signed authority. Never relabel it as current.
            // Reconcile the latest plan through its resident projection, which also
            // delivers removals/empty state and denies old-generation mutations.
            if let Err(error) = self
                .write_desired_document_for(
                    plan,
                    &process,
                    retry.generation.clone(),
                    settings_loaded,
                    self.admitted_ids_for(&process, &retry.generation, None),
                )
                .and_then(|_| {
                    self.enqueue_desired_snapshot(plan, &process, downlink)
                        .map(|_| ())
                })
            {
                log::err(
                    "injector",
                    &format!("completed resident desired delivery failed: {error}"),
                );
            }
            if current {
                self.set_process_event(
                    plan,
                    &process,
                    status::InjectionState::Waiting,
                    if result == injector::InjectResult::Staged {
                        "owned-worker-waiting"
                    } else {
                        "agent-readiness-waiting"
                    },
                );
            } else {
                log::info("injector", &format!("completed old authority retained as controlled resident: {process} pid={} generation={}", retry.pid, retry.generation.id));
            }
            if result == injector::InjectResult::Staged {
                self.pending_retries.insert(process, retry);
            } else {
                self.safety.note_success(&agent_id, &process);
            }
        } else if matches!(
            result,
            injector::InjectResult::Pending | injector::InjectResult::RegisterDeferred
        ) && current
        {
            if self
                .track_endpoint(&process, retry.pid, retry.starttime, None, None)
                .is_err()
            {
                self.set_process_event(
                    plan,
                    &process,
                    status::InjectionState::Failed,
                    "endpoint-registration-failed",
                );
                return;
            }
            self.set_process_event(
                plan,
                &process,
                status::InjectionState::Waiting,
                if result == injector::InjectResult::RegisterDeferred {
                    "register-baseline-deferred"
                } else {
                    "native-init-pending"
                },
            );
            retry.next_retry_at = self
                .started
                .elapsed()
                .saturating_add(pending_retry_delay(retry.attempts));
            self.pending_retries.insert(process, retry);
        } else if current {
            self.safety.note_failure(&agent_id, &process);
            self.safety.note_target_crash(&process);
            self.set_process_event(
                plan,
                &process,
                status::InjectionState::Failed,
                "native-injection-failed",
            );
            let details = serde_json::json!({"nativeFailure": outcome.failure, "targetPid": retry.pid, "targetStarttime": retry.starttime});
            for id in plan.enabled_ids_for_process(&process, &self.generation.catalog) {
                self.status.set_injection_event(
                    &id,
                    &process,
                    status::InjectionState::Failed,
                    "native-injection-failed",
                    details.clone(),
                    Some(retry.document_generation),
                    None,
                );
            }
        }
    }

    /// Stop admissions and allow every native helper to finish its bounded
    /// cleanup. Do not abandon an attached helper or release the singleton early.
    pub(crate) fn stop_package_execution(&mut self) {
        #[cfg(target_os = "android")]
        while !self.package_execution.quiesce() {
            self.drain_agent_logs_with_policy(false);
            self.flush_downlinks();
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    pub(crate) fn stop_injections(&mut self) {
        self.injection_jobs.close();
        self.rebind_jobs.close();
        let plan = self.last_plan.clone();
        while !self.injection_jobs.is_empty() || !self.rebind_jobs.is_empty() {
            self.collect_injections(&plan);
            self.drain_agent_logs_with_policy(false);
            self.flush_downlinks();
            if !self.injection_jobs.is_empty() || !self.rebind_jobs.is_empty() {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
    }

    /// Retry deferred agents with the same between-target service boundary as fresh injection.
    fn retry_pending(&mut self, processes: &[String], plan: &plan::Plan) {
        let priorities: std::collections::HashMap<_, _> = processes
            .iter()
            .map(|process| {
                (
                    process.clone(),
                    plan.startup_priority(process, &self.generation.catalog),
                )
            })
            .collect();
        runtime_loop::run_startup_batch(
            processes,
            |process| priorities[process],
            |step| {
                let runtime_loop::TargetBatchStep::Inject(process) = step else {
                    self.drain_agent_logs();
                    self.flush_downlinks();
                    return;
                };
                if self.pending_retries.get(process).is_some_and(|retry| {
                    self.injection_jobs.contains(retry.pid) || self.rebind_jobs.contains(retry.pid)
                }) {
                    return;
                }
                // Release the map-entry borrow before the callback can service newly tracked pipes.
                let Some(mut retry) = self.pending_retries.remove(process) else {
                    return;
                };
                if self.retry_pending_target(process, &mut retry, plan) {
                    self.pending_retries.insert(process.clone(), retry);
                }
            },
        );
    }

    fn retry_pending_target(
        &mut self,
        process: &str,
        retry: &mut PendingRetry,
        plan: &plan::Plan,
    ) -> bool {
        let current_generation = &self.generation;
        let status = &mut self.status;
        let watcher = &mut self.watcher;
        let safety = &mut self.safety;

        let agent_ids = &retry.agent_ids;
        let agent_id = agent_ids.first().cloned().unwrap_or_default();
        let document_generation = Some(retry.document_generation);
        // A staged worker owns live pipes until an authenticated terminal
        // outcome. Polling it is not a completed re-injection attempt.
        if watcher.tracker().is_tracked_with_pipes(retry.pid) {
            if !crate::bootstrap_worker::has_binding(retry.pid, retry.starttime) {
                // An independently rebound resident already owns the pipes.
                return false;
            }
            match crate::bootstrap_worker::take_outcome(retry.pid, retry.starttime) {
                None => return true,
                Some(crate::bootstrap_worker::Outcome::Ready) => {
                    watcher.tracker_mut().bind_log_generation(
                        retry.pid,
                        &retry.generation.id,
                        &retry.generation.catalog_sha256,
                    );
                    watcher.tracker_mut().bind_settings(
                        retry.pid,
                        &retry.generation.id,
                        &retry.generation.catalog_sha256,
                        agent_ids.iter().any(|id| id == "settings"),
                    );
                    safety.note_success(&agent_id, process);
                    return false;
                }
                Some(crate::bootstrap_worker::Outcome::Deferred) => {
                    watcher.tracker_mut().clear(retry.pid);
                }
                Some(crate::bootstrap_worker::Outcome::Failed) => {
                    watcher.tracker_mut().clear(retry.pid);
                    safety.note_failure(&agent_id, process);
                    set_status_for_ids(
                        status,
                        agent_ids,
                        process,
                        status::InjectionState::Failed,
                        "owned-worker-failed",
                        document_generation,
                    );
                    return false;
                }
            }
        }
        let current_agent_ids = plan.enabled_ids_for_process(process, &current_generation.catalog);
        let current_semantics = plan
            .desired_semantics_for_process(process, current_generation)
            .ok();
        let desired_authority = self.desired_documents.get(process).and_then(|desired| {
            desired.resident_generation.as_ref().map(|resident| {
                (
                    resident.id.as_str(),
                    resident.catalog_sha256.as_str(),
                    desired.generation,
                    desired.ids.as_slice(),
                    desired.semantic_document.as_str(),
                )
            })
        });
        if !pending_retry_semantics_match(
            (
                &retry.generation.id,
                &retry.generation.catalog_sha256,
                retry.document_generation,
                &retry.agent_ids,
                &retry.desired_semantics,
            ),
            (
                &current_generation.id,
                &current_generation.catalog_sha256,
                &current_agent_ids,
                current_semantics.as_deref(),
            ),
            desired_authority,
        ) {
            watcher.tracker_mut().clear(retry.pid);
            log::info(
                "main",
                &format!(
                    "{process} pid={} pending retry authority changed; cancelled until restart",
                    retry.pid
                ),
            );
            return false;
        }
        if agent_ids
            .iter()
            .any(|id| safety.is_quarantined(id, process))
            || safety.is_target_degraded(process)
        {
            return false;
        }
        if self.started.elapsed() < retry.next_retry_at {
            return true;
        }
        let decision = pending_retry_decision(
            status.injection_state(process),
            target_identity::read_starttime(retry.pid)
                .is_ok_and(|starttime| starttime == retry.starttime),
            retry.attempts,
            MAX_AGENT_PENDING_RETRIES,
        );
        match decision {
            PendingRetryDecision::Cleared => {
                log::ok(
                    "main",
                    &format!(
                        "{process} pid={} agent ready — pending retry cleared",
                        retry.pid
                    ),
                );
                return false;
            }
            PendingRetryDecision::PidDead => {
                log::info(
                    "main",
                    &format!(
                        "{process} pid={} died while agent pending — stopped retry",
                        retry.pid
                    ),
                );
                set_status_for_ids(
                    status,
                    agent_ids,
                    process,
                    status::InjectionState::Failed,
                    "target-died",
                    document_generation,
                );
                return false;
            }
            PendingRetryDecision::BoundExhausted => {
                log::info(
                    "main",
                    &format!("{process} pid={} native init slow retry rearmed attempts={} interval_ms=30000", retry.pid, retry.attempts),
                );
            }
            PendingRetryDecision::Retry => {}
        }

        retry.attempts = retry.attempts.saturating_add(1);
        retry.next_retry_at = self
            .started
            .elapsed()
            .saturating_add(pending_retry_delay(retry.attempts));
        let mut preparation = status.startup_milestones.as_ref().and_then(|milestones| {
            self.preparation.begin(
                milestones.identity.clone(),
                process,
                retry.pid,
                self.started.elapsed().as_millis() as u64,
                self.started,
            )
        });
        let (maps, maps_starttime) = match target_identity::read_bound_maps(retry.pid) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                log::err(
                    "main",
                    &format!(
                        "{process} pid={} bounded maps snapshot failed on retry: {error}",
                        retry.pid
                    ),
                );
                set_status_for_ids(
                    status,
                    agent_ids,
                    process,
                    status::InjectionState::Failed,
                    "maps-classification-failed",
                    document_generation,
                );
                return false;
            }
        };
        crate::startup_preparation::Attempt::bind(&mut preparation, maps_starttime);
        crate::startup_preparation::Attempt::stage(
            &mut preparation,
            crate::startup_preparation::Stage::Authority,
        );
        let abi = match reconcile::detect_bitness(retry.pid, &maps) {
            Some(abi) => abi,
            None => {
                log::err(
                    "main",
                    &format!(
                        "{process} pid={} bitness detection failed on retry",
                        retry.pid
                    ),
                );
                set_status_for_ids(
                    status,
                    agent_ids,
                    process,
                    status::InjectionState::Failed,
                    "bitness-detection-failed",
                    document_generation,
                );
                return false;
            }
        };
        let authority = match target_identity::attest_catalog_target_for_agents(
            &retry.generation.catalog,
            retry.pid,
            process,
            maps_starttime,
            &bootstrap_authority_ids(&retry.generation, process, agent_ids),
        ) {
            Ok(authority) if authority.starttime == retry.starttime => authority,
            Ok(_) => {
                set_status_for_ids(
                    status,
                    agent_ids,
                    process,
                    status::InjectionState::Failed,
                    "target-identity-pid-reused",
                    document_generation,
                );
                return false;
            }
            Err(error) => {
                log::err(
                    "main",
                    &format!("retry target identity rejected: {error:#}"),
                );
                set_status_for_ids(
                    status,
                    agent_ids,
                    process,
                    status::InjectionState::Failed,
                    "target-identity-rejected",
                    document_generation,
                );
                return false;
            }
        };
        crate::startup_preparation::Attempt::stage(
            &mut preparation,
            crate::startup_preparation::Stage::Payload,
        );
        if !verify_payload_before_inject(&retry.release_manifest, abi, process) {
            set_status_for_ids(
                status,
                agent_ids,
                process,
                status::InjectionState::Failed,
                "payload-verification-failed",
                document_generation,
            );
            return false;
        }

        log::debug(
            "main",
            &format!(
                "{process} pid={} retry {}/{} (agent pending)",
                retry.pid, retry.attempts, MAX_AGENT_PENDING_RETRIES
            ),
        );
        // Skip injection if a live track with pipes already exists for this
        // pid — another flow (install-agents) already completed phase-1 and
        // is awaiting readiness. Re-injecting would hit the idempotent
        // re-entry path which returns Ok WITHOUT pipes (IMPLANT_INIT_PIPE_OK),
        // causing "agent log-pipe unavailable" and a spurious init-failed.
        if watcher.tracker().is_tracked_with_pipes(retry.pid) {
            set_status_for_ids(
                status,
                agent_ids,
                process,
                status::InjectionState::Waiting,
                "agent-readiness-waiting",
                document_generation,
            );
            log::debug(
                "main",
                &format!(
                    "{process} pid={} retry {} skipped (already tracked, awaiting readiness)",
                    retry.pid, retry.attempts
                ),
            );
            return false;
        }
        crate::startup_preparation::Attempt::bind(&mut preparation, authority.starttime);
        crate::startup_preparation::Attempt::ready(
            &mut preparation,
            self.started.elapsed().as_millis() as u64,
        );
        let retry = retry.clone();
        let agent_id = agent_id.clone();
        self.dispatch_bootstrap(process, retry, authority, abi, agent_id, plan, preparation);
        false
    }

    fn clear_ready_recovery(
        &mut self,
        plan: &plan::Plan,
        process: &str,
        pid: i32,
        observed_starttime: Option<u64>,
    ) {
        let Some(recovery) = self.resident_recovery.get(process) else {
            return;
        };
        let identity = recovery.identity();
        if identity.pid != pid
            || observed_starttime != Some(identity.starttime)
            || self
                .resident_identity(plan, process, pid, identity.starttime)
                .ok()
                .as_ref()
                != Some(identity)
        {
            return;
        }
        let Some(document) = self.desired_documents.get(process) else {
            return;
        };
        let resident = document
            .resident_generation
            .as_ref()
            .unwrap_or(&self.generation);
        // The budget fences current requested authority. A verified retained
        // resident may intentionally belong to an older immutable generation.
        // endpoint_binding below requires its exact document/native-log identity.
        if plan
            .desired_semantics_for_admitted(
                process,
                resident,
                self.settings_loaded_for(process, resident),
                &self.admitted_ids_for(process, resident, None),
            )
            .ok()
            .as_ref()
            != Some(&document.semantic_document)
        {
            return;
        }
        let Some(binding) = self
            .watcher
            .tracker()
            .status_epoch(pid, process)
            .and_then(|epoch| {
                control_plane::endpoint_binding(&self.endpoint_context(pid, process, epoch))
            })
        else {
            return;
        };
        if binding.target_starttime != identity.starttime.to_string() {
            return;
        }
        if control_plane::recovery_ready(
            process,
            &binding,
            document.generation,
            &resident.id,
            &resident.catalog_sha256,
            &document.ids,
        ) {
            self.resident_recovery.remove(process);
        }
    }

    fn aggregate_agent_statuses(&mut self, plan: &plan::Plan) -> Vec<(i32, String)> {
        self.prepare_startup_milestones(plan);
        let tracked = self.watcher.tracker().tracked_targets();
        for (pid, process) in &tracked {
            self.clear_ready_recovery(
                plan,
                process,
                *pid,
                target_identity::read_starttime(*pid).ok(),
            );
            let Some(document) = self.desired_documents.get(process) else {
                continue;
            };
            let resident_generation = document
                .resident_generation
                .as_ref()
                .unwrap_or(&self.generation);
            let current_semantic = match plan.desired_semantics_for_admitted(
                process,
                resident_generation,
                self.settings_loaded_for(process, resident_generation),
                &self.admitted_ids_for(process, resident_generation, None),
            ) {
                Ok(document) => document,
                Err(error) => {
                    log::err(
                        "main",
                        &format!("desired semantics serialization failed for {process}: {error}"),
                    );
                    continue;
                }
            };
            if document.semantic_document != current_semantic {
                continue;
            }
            if document.ids.is_empty() {
                continue;
            }
            let binding = self
                .watcher
                .tracker()
                .status_epoch(*pid, process)
                .and_then(|epoch| {
                    control_plane::endpoint_binding(&self.endpoint_context(*pid, process, epoch))
                });
            control_plane::aggregate_agent_status(
                &mut self.status,
                process,
                document.generation,
                &resident_generation.id,
                &resident_generation.catalog_sha256,
                &document.ids,
                binding,
            );
        }
        tracked
    }

    /// Verify that pushed live configs were applied by their target runtimes.
    ///
    /// A target acknowledges a pushed desired document by republishing its
    /// per-process agent-status file with the new document generation. Some
    /// OEM 32-bit targets stop delivering FileObserver events to the injected
    /// ConfigWatcher a while after injection, so the runtime silently never
    /// applies the update (agents stay stopped, the status keeps the stale
    /// generation — surfaced as `invalid-agent-status`). The daemon NEVER
    /// restarts an OEM process (system invariant): when the grace window
    /// lapses it logs the missed ack and gives up; the update is applied at
    /// the target's next natural restart. LIVE_ACK_MAX_RESTARTS bounds the
    /// reserved-but-unused restart budget at 0 effective restarts.
    /// Push an ordinary runtime `D` followed by the correlated
    /// `A|request|<desired document>` to the Settings endpoint that submitted
    /// the committed mutation. Pending targets are coalesced per endpoint
    /// epoch and consumed once, so a blocked resident cannot amplify fanout or
    /// duplicate delivery to healthy endpoints.
    fn push_confirmed_snapshots(&mut self) {
        if !agent_events::has_confirmed_pending() {
            return;
        }
        // The `plan` captured at the start of this poll pass predates any
        // E mutation committed by DrainAgentLogs in the same pass. Build the
        // confirmed snapshot from a FRESH read of agents.json so both pushed
        // frames carry exactly the committed document. Keep the pending flag until a
        // valid fresh plan is available (an invalid file never clears it).
        let fresh_plan = plan::read_runtime_and_validate(&self.generation);
        if !fresh_plan.valid {
            log::err(
                "main",
                "confirmed snapshot deferred: agents.json unreadable after commit",
            );
            return;
        }
        let plan = &fresh_plan;
        let pending = agent_events::take_confirmed_pending();
        let active = self
            .watcher
            .tracker()
            .downlinks()
            .into_iter()
            .map(|(pid, process, epoch, fd)| (epoch, (pid, process, fd)))
            .collect::<std::collections::HashMap<_, _>>();
        for target in pending {
            let Some((pid, process, fd)) = active.get(&target.endpoint_epoch) else {
                let request_id = target.request_id;
                if !agent_events::retry_confirmed_pending(target) {
                    log::err(
                        "main",
                        &format!(
                            "mutation ACK request={request_id} expired before endpoint became writable"
                        ),
                    );
                }
                continue;
            };
            if *fd != target.fd || *process != target.process {
                let request_id = target.request_id;
                if !agent_events::retry_confirmed_pending(target) {
                    log::err(
                        "main",
                        &format!(
                            "mutation ACK request={request_id} expired after endpoint identity mismatch"
                        ),
                    );
                }
                continue;
            }
            if let Err(error) = self.write_desired_document(plan, process) {
                log::err("main", &format!("confirmed desired update failed: {error}"));
                let request_id = target.request_id;
                if !agent_events::retry_confirmed_pending(target) {
                    log::err(
                        "main",
                        &format!("mutation ACK request={request_id} retry budget exhausted"),
                    );
                }
                continue;
            }
            if let Ok(generation) =
                self.enqueue_confirmed_update(plan, process, *fd, target.request_id)
            {
                log::info(
                    "main",
                    &format!(
                        "pushed desired generation={generation} and mutation ACK request={} to {process} pid={pid}",
                        target.request_id,
                    ),
                );
            } else {
                log::err(
                    "main",
                    &format!(
                        "confirmed snapshot push to {process} pid={pid} deferred (delivery incomplete)"
                    ),
                );
                let request_id = target.request_id;
                if !agent_events::retry_confirmed_pending(target) {
                    log::err(
                        "main",
                        &format!("mutation ACK request={request_id} retry budget exhausted"),
                    );
                }
            }
        }
    }

    fn flush_downlinks(&mut self) {
        let mut poisoned = Vec::new();
        for (pid, process, _, fd) in self.watcher.tracker().downlinks() {
            if !downlink::flush(fd) {
                log::err(
                    "main",
                    &format!("closing poisoned downlink for {process} pid={pid}"),
                );
                poisoned.push(fd);
            }
        }
        for fd in poisoned {
            self.watcher.tracker_mut().disable_downlink(fd);
        }
    }

    fn finish_none_delivery(&mut self, plan: &plan::Plan) {
        let tracked = self.watcher.tracker().tracked_targets();
        self.push_live_config(plan, &tracked);
        self.push_confirmed_snapshots();
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(750);
        loop {
            self.flush_downlinks();
            let mut waiting = self
                .watcher
                .tracker()
                .downlinks()
                .into_iter()
                .filter(|(_, _, _, fd)| !downlink::is_drained(*fd))
                .map(|(_, _, _, fd)| libc::pollfd {
                    fd,
                    events: libc::POLLOUT,
                    revents: 0,
                })
                .collect::<Vec<_>>();
            if waiting.is_empty() {
                break;
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                log::err(
                    "runtime",
                    "startup=none final downlink delivery deadline expired",
                );
                break;
            }
            let timeout = remaining.as_millis().min(25) as i32;
            unsafe {
                libc::poll(waiting.as_mut_ptr(), waiting.len() as libc::nfds_t, timeout);
            }
        }
    }

    fn enforce_live_acks(&mut self) {
        let processes: Vec<String> = self.pending_acks.keys().cloned().collect();
        for process in processes {
            if !self.desired_documents.contains_key(&process) {
                self.pending_acks.remove(&process);
                continue;
            }
            let Some(pending) = self.pending_acks.get(&process) else {
                // The entry may have been removed by a concurrent path (or by
                // the empty/missing-desired branches above on a prior loop
                // iteration). Fail-soft: skip this process this tick rather
                // than panicking the daemon.
                continue;
            };
            let observed = self
                .desired_documents
                .get(&process)
                .and_then(|state| correlated_observed_generation(&process, state));
            let action = ack_action(
                observed,
                pending.generation,
                pending.pushed_at.elapsed(),
                pending.restarts,
            );
            match action {
                AckAction::Acked => {
                    self.pending_acks.remove(&process);
                }
                AckAction::Wait => {}
                AckAction::GiveUp => {
                    log::err(
                        "main",
                        &format!(
                            "live update for {process} unacked after grace window; giving up (no OEM restart)"
                        ),
                    );
                    self.pending_acks.remove(&process);
                }
            }
        }
        self.confirm_withdrawals();
    }

    /// Report completed UI teardown separately from the durable OFF, which
    /// already revoked native automation without waiting for target processes.
    fn confirm_withdrawals(&mut self) {
        let plan = self.last_plan.clone();
        if !plan.valid {
            return;
        }
        let enabled: std::collections::HashSet<&str> = plan
            .entries
            .iter()
            .filter(|entry| entry.enabled)
            .map(|entry| entry.id.as_str())
            .collect();
        // An enabled source cannot be withdrawing; forgetting the report here
        // lets a later removal be confirmed on its own evidence.
        self.confirmed_withdrawals
            .retain(|source| !enabled.contains(source.as_str()));
        let withdrawn: Vec<String> = plan
            .entries
            .iter()
            .filter(|entry| !entry.enabled)
            .map(|entry| entry.id.clone())
            .filter(|source| !self.confirmed_withdrawals.contains(source))
            .filter(|source| self.removal_applied(source))
            .collect();
        for source in withdrawn {
            match crate::owner_client::confirm_agent_withdrawn(&source) {
                Ok(()) => {
                    self.confirmed_withdrawals.insert(source);
                }
                Err(error) => log::debug(
                    "main",
                    &format!("withdrawal confirmation for {source} not delivered: {error}"),
                ),
            }
        }
    }

    /// True when no target process of `source` can still be running the hook
    /// that captures its input: every target either is not present, or reports
    /// an applied document generation at or beyond the pushed document that no
    /// longer enables the source.
    fn removal_applied(&self, source: &str) -> bool {
        let Some(agent) = self.generation.catalog.find(source) else {
            return true;
        };
        agent
            .targets
            .iter()
            .filter(|target| target.is_android())
            .all(|target| self.process_applied_removal(&target.process, source))
    }

    fn process_applied_removal(&self, process: &str, source: &str) -> bool {
        let live = self
            .watcher
            .tracker()
            .downlinks()
            .into_iter()
            .any(|(_, name, _, _)| name == process);
        let state = self.desired_documents.get(process);
        let observed = state.and_then(|state| correlated_observed_generation(process, state));
        matches!(
            removal_action(live, state, source, observed),
            RemovalAction::Applied
        )
    }

    fn push_live_config(&mut self, plan: &plan::Plan, tracked: &[(i32, String)]) {
        match crate::cluster_control::reconcile_snapshot(&self.generation, plan) {
            Ok(Some(snapshot)) => {
                for (_, process, epoch, fd) in self.watcher.tracker().downlinks() {
                    if self.generation.catalog.has_target("settings", &process) {
                        if let Err(error) =
                            crate::cluster_control::push_snapshot(&snapshot, epoch, fd)
                        {
                            log::debug(
                                "cluster",
                                &format!("snapshot downlink unavailable: {error}"),
                            );
                        }
                    }
                }
            }
            Ok(None) => {}
            Err(error) => log::debug("cluster", &format!("snapshot unavailable: {error}")),
        }

        let downlinks = self
            .watcher
            .tracker()
            .downlinks()
            .into_iter()
            .map(|(pid, process, _epoch, fd)| ((pid, process), fd))
            .collect::<std::collections::HashMap<_, _>>();
        for (pid, process) in tracked {
            if !self.desired_documents.contains_key(process) {
                continue;
            }
            match self.write_desired_document(plan, process) {
                Err(error) => {
                    log::debug(
                        "main",
                        &format!("live config re-push failed for {process}: {error}"),
                    );
                }
                Ok(true) => {
                    let Some(fd) = downlinks.get(&(*pid, process.clone())) else {
                        log::err(
                            "main",
                            &format!("live config for {process} has no resident downlink"),
                        );
                        continue;
                    };
                    match self.enqueue_desired_snapshot(plan, process, *fd) {
                        Ok(generation) => log::debug(
                            "main",
                            &format!("live config pushed for {process} generation={generation}"),
                        ),
                        Err(error) => log::err("main", &error),
                    }
                }
                Ok(false) => {}
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    #[test]
    fn pending_removal_survives_other_changes_but_not_reenable_or_a_new_endpoint() {
        let endpoint = Some((123, 7, 99));
        let mut previous = super::DesiredDocumentState::new("old", 1);
        previous.ids = vec!["settings".into()];
        previous.restart_endpoint = endpoint;
        previous.restart_removed = vec!["font-cyrillic".into()];
        let ids = vec!["settings".into()];
        assert_eq!(
            super::restart_removed_agents(Some(&previous), &ids, endpoint),
            vec!["font-cyrillic"]
        );
        assert!(super::restart_removed_agents(
            Some(&previous),
            &["settings".into(), "font-cyrillic".into()],
            endpoint
        )
        .is_empty());
        assert!(
            super::restart_removed_agents(Some(&previous), &ids, Some((124, 8, 100))).is_empty()
        );
        assert!(super::restart_removed_agents(Some(&previous), &ids, None).is_empty());
    }

    pub(crate) const LIVE_ACK_GRACE: std::time::Duration = super::LIVE_ACK_GRACE;
    pub(crate) const LIVE_ACK_MAX_RESTARTS: u32 = super::LIVE_ACK_MAX_RESTARTS;
    pub(crate) const MAX_AGENT_PENDING_RETRIES: u32 = super::MAX_AGENT_PENDING_RETRIES;

    #[derive(Debug, PartialEq, Eq)]
    pub(crate) enum AckAction {
        Acked,
        Wait,
        GiveUp,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub(crate) enum TargetAction {
        TrackExistingImplant,
        ObserveOnly,
        Inject,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub(crate) enum RemovalAction {
        Applied,
        Pending,
    }

    #[test]
    fn a_removal_is_reported_applied_only_on_positive_evidence() {
        use self::RemovalAction::{Applied, Pending};
        let removing = Some((Vec::new(), 17));
        // No live endpoint can still be running the hook.
        assert_eq!(
            removal_action(false, removing.clone(), "font-cyrillic", None),
            Applied
        );
        // A live endpoint whose applied document still enables the source.
        assert_eq!(
            removal_action(
                true,
                Some((vec!["font-cyrillic".into()], 17)),
                "font-cyrillic",
                Some(17)
            ),
            Pending
        );
        // A live endpoint that has not reported the pushed document yet.
        for observed in [None, Some(16)] {
            assert_eq!(
                removal_action(true, removing.clone(), "font-cyrillic", observed),
                Pending
            );
        }
        // Only a reported applied generation at or beyond the pushed one counts.
        for observed in [Some(17), Some(18)] {
            assert_eq!(
                removal_action(true, removing.clone(), "font-cyrillic", observed),
                Applied
            );
        }
        // A live endpoint with no pushed document is unknown, never applied.
        assert_eq!(
            removal_action(true, None, "font-cyrillic", Some(17)),
            Pending
        );
    }

    #[derive(Debug, PartialEq, Eq)]
    pub(crate) enum PendingRetryDecision {
        Cleared,
        PidDead,
        BoundExhausted,
        Retry,
    }

    /// Mirror of the private per-pass none-plan decision for integration
    /// tests (same shape as the AckAction mirrors above).
    #[derive(Debug, PartialEq, Eq)]
    pub(crate) enum NonePlanDecisionMirror {
        NotCommitted,
        RebootForUpdate,
        SelfStop,
    }

    pub(crate) fn none_plan_decision(
        startup: plan::Startup,
        disable_all: bool,
        activation_frozen: bool,
    ) -> NonePlanDecisionMirror {
        match super::none_plan_decision(startup, disable_all, activation_frozen) {
            super::NonePlanDecision::NotCommitted => NonePlanDecisionMirror::NotCommitted,
            super::NonePlanDecision::RebootForUpdate => NonePlanDecisionMirror::RebootForUpdate,
            super::NonePlanDecision::SelfStop => NonePlanDecisionMirror::SelfStop,
        }
    }

    pub(crate) fn ack_action(
        observed: Option<i64>,
        pushed_generation: i64,
        elapsed: std::time::Duration,
        restarts: u32,
    ) -> AckAction {
        match super::ack_action(observed, pushed_generation, elapsed, restarts) {
            super::AckAction::Acked => AckAction::Acked,
            super::AckAction::Wait => AckAction::Wait,
            super::AckAction::GiveUp => AckAction::GiveUp,
        }
    }

    pub(crate) fn removal_action(
        live: bool,
        document: Option<(Vec<String>, i64)>,
        source: &str,
        observed: Option<i64>,
    ) -> RemovalAction {
        let document = document.map(|(ids, generation)| {
            let mut state = super::DesiredDocumentState::new("", generation);
            state.ids = ids;
            state
        });
        match super::removal_action(live, document.as_ref(), source, observed) {
            super::RemovalAction::Applied => RemovalAction::Applied,
            super::RemovalAction::Pending => RemovalAction::Pending,
        }
    }

    pub(crate) fn target_action(already_injected: bool, has_desired_agents: bool) -> TargetAction {
        match super::target_action(already_injected, has_desired_agents) {
            super::TargetAction::TrackExistingImplant => TargetAction::TrackExistingImplant,
            super::TargetAction::ObserveOnly => TargetAction::ObserveOnly,
            super::TargetAction::Inject => TargetAction::Inject,
        }
    }

    pub(crate) fn pending_retry_decision(
        state: Option<status::InjectionState>,
        pid_alive: bool,
        attempts: u32,
        max_attempts: u32,
    ) -> PendingRetryDecision {
        match super::pending_retry_decision(state, pid_alive, attempts, max_attempts) {
            super::PendingRetryDecision::Cleared => PendingRetryDecision::Cleared,
            super::PendingRetryDecision::PidDead => PendingRetryDecision::PidDead,
            super::PendingRetryDecision::BoundExhausted => PendingRetryDecision::BoundExhausted,
            super::PendingRetryDecision::Retry => PendingRetryDecision::Retry,
        }
    }

    pub(crate) fn generation_prune_is_safe(
        live_processes: usize,
        identified_residents: usize,
    ) -> bool {
        super::generation_prune_is_safe(live_processes, identified_residents)
    }

    pub(crate) fn bootstrap_bytes(
        plan: &plan::Plan,
        generation: &generation::VerifiedGeneration,
        process: &str,
    ) -> Result<Vec<u8>, String> {
        let mut daemon = super::DaemonLoop::new(generation.clone());
        daemon.write_fresh_desired_document(plan, process)?;
        daemon.build_pipe_bootstrap(plan, process)
    }

    /// Non-executor module ids the bootstrap manifest would deliver for one
    /// process under the given plan (mirrors the wire "modules" list).
    pub(crate) fn bootstrap_module_ids(
        plan: &plan::Plan,
        generation: &generation::VerifiedGeneration,
        process: &str,
    ) -> Result<Vec<String>, String> {
        let (manifest, _payloads) = super::bootstrap_metadata(plan, generation, process, 0)?;
        let value: serde_json::Value =
            serde_json::from_slice(&manifest).map_err(|error| error.to_string())?;
        Ok(value["modules"]
            .as_array()
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| entry["id"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }

    pub(crate) fn retained_process_index(
        retained: &[generation::VerifiedGeneration],
    ) -> std::collections::BTreeMap<String, Vec<usize>> {
        super::retained_process_index(retained)
    }

    pub(crate) fn resolve_retained_authority(
        successes: Vec<(String, target_identity::AttestedTarget)>,
    ) -> Result<
        (
            target_identity::AttestedTarget,
            std::collections::BTreeSet<String>,
        ),
        String,
    > {
        super::resolve_retained_authority(successes)
    }

    pub(crate) fn exact_rebound_generation<'a>(
        retained: &'a [generation::VerifiedGeneration],
        authorized_generation_ids: &std::collections::BTreeSet<String>,
        identity: &injector::ResidentIdentity,
        process: &str,
    ) -> Result<&'a generation::VerifiedGeneration, String> {
        super::exact_rebound_generation(retained, authorized_generation_ids, identity, process)
    }

    pub(crate) fn verify_resident_identity(
        store: &generation::GenerationStore,
        identity: &injector::ResidentIdentity,
    ) -> Result<generation::VerifiedGeneration, String> {
        super::verify_resident_identity(store, identity)
    }

    pub(crate) fn pending_retry_semantics_match(
        retry: (&str, &str, i64, &[String], &str),
        current: (&str, &str, &[String], Option<&str>),
        desired: Option<(&str, &str, i64, &[String], &str)>,
    ) -> bool {
        super::pending_retry_semantics_match(retry, current, desired)
    }

    pub(crate) fn render_confirmed_update_frames(
        request_id: u64,
        document: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        super::render_confirmed_update_frames(request_id, document)
    }

    pub(crate) struct DesiredDocumentState(super::DesiredDocumentState);

    impl DesiredDocumentState {
        pub(crate) fn new(semantic_document: &str, generation: i64) -> Self {
            Self(super::DesiredDocumentState::new(
                semantic_document,
                generation,
            ))
        }
    }

    pub(crate) fn next_desired_generation(
        previous: Option<&DesiredDocumentState>,
        semantic_document: &str,
        floor: i64,
    ) -> Result<Option<i64>, String> {
        super::next_desired_generation(previous.map(|state| &state.0), semantic_document, floor)
    }

    pub(crate) struct DesiredDocumentView {
        pub(crate) semantic_document: String,
        pub(crate) generation: i64,
        pub(crate) resident_generation: Option<generation::VerifiedGeneration>,
    }

    pub(crate) struct DaemonLoop(super::DaemonLoop);

    impl DaemonLoop {
        pub(crate) fn new(generation: generation::VerifiedGeneration) -> Self {
            Self(super::DaemonLoop::new(generation))
        }

        pub(crate) fn write_fresh_desired_document(
            &mut self,
            plan: &plan::Plan,
            process: &str,
        ) -> Result<bool, String> {
            self.0.write_fresh_desired_document(plan, process)
        }

        pub(crate) fn write_desired_document(
            &mut self,
            plan: &plan::Plan,
            process: &str,
        ) -> Result<bool, String> {
            self.0.write_desired_document(plan, process)
        }

        pub(crate) fn enqueue_confirmed_update(
            &mut self,
            plan: &plan::Plan,
            process: &str,
            fd: i32,
            request_id: u64,
        ) -> Result<i64, String> {
            self.0
                .enqueue_confirmed_update(plan, process, fd, request_id)
        }

        pub(crate) fn enqueue_desired_snapshot(
            &mut self,
            plan: &plan::Plan,
            process: &str,
            fd: i32,
        ) -> Result<i64, String> {
            self.0.enqueue_desired_snapshot(plan, process, fd)
        }

        pub(crate) fn finish_none_delivery(&mut self, plan: &plan::Plan) {
            self.0.finish_none_delivery(plan);
        }

        pub(crate) fn adopt_generation(&mut self, generation: generation::VerifiedGeneration) {
            self.0.adopt_generation(generation);
        }

        pub(crate) fn endpoint_context(
            &self,
            pid: i32,
            process: &str,
            endpoint_epoch: u64,
        ) -> agent_log::EndpointContext {
            self.0.endpoint_context(pid, process, endpoint_epoch)
        }

        pub(crate) fn track(
            &mut self,
            process: &str,
            pid: i32,
            starttime: u64,
            record_fd: Option<i32>,
            downlink_fd: Option<i32>,
        ) {
            self.0
                .watcher
                .tracker_mut()
                .track(process, pid, starttime, record_fd, downlink_fd)
                .unwrap();
            let loaded = self
                .0
                .desired_documents
                .get(process)
                .is_some_and(|document| document.ids.iter().any(|id| id == "settings"));
            self.0.bind_loaded_settings(process, pid, loaded);
        }

        pub(crate) fn tracked_endpoint_epoch(&self, process: &str, fd: i32) -> u64 {
            self.0
                .watcher
                .tracker()
                .downlink_identity(process, fd)
                .unwrap()
                .2
        }

        pub(crate) fn insert_desired_document(
            &mut self,
            process: &str,
            semantic_document: &str,
            generation: i64,
            ids: Vec<String>,
            resident_generation: generation::VerifiedGeneration,
        ) {
            self.0.desired_documents.insert(
                process.to_string(),
                super::DesiredDocumentState::with_ids(
                    semantic_document.to_string(),
                    generation,
                    ids,
                    resident_generation,
                ),
            );
        }

        pub(crate) fn allow_attempt(&mut self, agent: &str, process: &str) {
            self.0.safety.allow_attempt(agent, process);
        }

        pub(crate) fn note_target_crash(&mut self, process: &str) {
            self.0.safety.note_target_crash(process);
        }

        pub(crate) fn generation_id(&self) -> &str {
            &self.0.generation.id
        }

        pub(crate) fn status_generation_id(&self) -> &str {
            &self.0.status.generation_id
        }

        pub(crate) fn status_catalog_sha256(&self) -> &str {
            &self.0.status.catalog_sha256
        }

        pub(crate) fn is_quarantined(&self, agent: &str, process: &str) -> bool {
            self.0.safety.is_quarantined(agent, process)
        }

        pub(crate) fn is_target_degraded(&self, process: &str) -> bool {
            self.0.safety.is_target_degraded(process)
        }

        pub(crate) fn is_tracked(&self, pid: i32) -> bool {
            self.0.watcher.tracker().is_tracked(pid)
        }

        pub(crate) fn desired_document(&self, process: &str) -> Option<DesiredDocumentView> {
            self.0
                .desired_documents
                .get(process)
                .map(|state| DesiredDocumentView {
                    semantic_document: state.semantic_document.clone(),
                    generation: state.generation,
                    resident_generation: state.resident_generation.clone(),
                })
        }

        pub(crate) fn pending_ack_generation(&self, process: &str) -> Option<i64> {
            self.0.pending_acks.get(process).map(|ack| ack.generation)
        }
    }
}

fn continue_after_cache_preparation<T>(
    attempts: [(&str, Result<(), String>); 2],
    mut report: impl FnMut(&str),
    next: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    for (step, result) in attempts {
        if let Err(error) = result {
            report(&format!(
                "Nonfatal launcher cache preparation: {step}: {error}"
            ));
        }
    }
    next()
}

#[cfg(test)]
mod parallel_tests {
    #[test]
    fn cache_preparation_failures_never_cancel_uninstall_admission() {
        for mask in 0u8..4 {
            let attempts = [
                (
                    "recover",
                    if mask & 1 == 0 {
                        Ok(())
                    } else {
                        Err("endpoint unavailable".into())
                    },
                ),
                (
                    "quiesce",
                    if mask & 2 == 0 {
                        Ok(())
                    } else {
                        Err("drain unavailable".into())
                    },
                ),
            ];
            let mut warnings = Vec::new();
            let mut continued = false;
            let result = super::continue_after_cache_preparation(
                attempts,
                |warning| warnings.push(warning.to_string()),
                || {
                    continued = true;
                    Ok(42)
                },
            );
            assert_eq!(result.unwrap(), 42);
            assert!(continued);
            assert_eq!(warnings.len(), mask.count_ones() as usize);
            assert_eq!(
                warnings.iter().any(|s| s.contains("endpoint unavailable")),
                mask & 1 != 0
            );
            assert_eq!(
                warnings.iter().any(|s| s.contains("drain unavailable")),
                mask & 2 != 0
            );
        }
        let result = super::continue_after_cache_preparation::<()>(
            [("recover", Ok(())), ("quiesce", Err("offline".into()))],
            |_| (),
            || Err("invalid removal authority".into()),
        );
        assert_eq!(result.unwrap_err(), "invalid removal authority");
    }

    #[test]
    fn fresh_root_recovery_services_state_reply_needed_by_the_held_worker() {
        const PROCESS: &str = "com.qinggan.app.setting.test_root_recovery_read_reply";
        let (mut daemon, valid, context) = fixture(PROCESS);
        let (record, mut client_log) = std::os::unix::net::UnixStream::pair().unwrap();
        let (reply, mut client_reply) = std::os::unix::net::UnixStream::pair().unwrap();
        record.set_nonblocking(true).unwrap();
        reply.set_nonblocking(true).unwrap();
        client_reply
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        daemon
            .watcher
            .tracker_mut()
            .track(
                PROCESS,
                193003,
                789,
                Some(record.into_raw_fd()),
                Some(reply.into_raw_fd()),
            )
            .unwrap();
        daemon.watcher.tracker_mut().bind_settings(
            193003,
            &daemon.generation.id,
            &daemon.generation.catalog_sha256,
            true,
        );
        daemon.write_desired_document(&valid, PROCESS).unwrap();
        let (release, wait) = mpsc::channel();
        daemon
            .injection_jobs
            .dispatch(context.retry.pid, context, move || {
                wait.recv_timeout(Duration::from_secs(2)).unwrap();
                injector::BootstrapOutcome {
                    result: injector::InjectResult::Pending,
                    record: None,
                    downlink: None,
                    binding: None,
                    failure: None,
                }
            })
            .unwrap_or_else(|_| panic!("initial worker admission failed"));
        let unavailable = crate::plan::test_fixtures::startup_session_unavailable(valid.clone());
        assert_eq!(
            daemon.poll_with_plan(|_| unavailable),
            DaemonPollDisposition::Continue
        );
        let client = std::thread::spawn(move || {
            client_log
                .write_all(b"R|1|settings|root-recovery-missing\n")
                .unwrap();
            let mut response = [0; 128];
            let received = client_reply
                .read(&mut response)
                .ok()
                .is_some_and(|count| &response[..count] == b"R|1|missing|\n");
            release.send(()).unwrap();
            received
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while daemon.root_plan_unavailable && std::time::Instant::now() < deadline {
            assert_eq!(
                daemon.poll_with_plan(|_| valid.clone()),
                DaemonPollDisposition::Continue
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(!daemon.root_plan_unavailable);
        assert!(daemon.injection_jobs.is_empty());
        assert!(daemon.injection_jobs.admissions_open());
        assert_eq!(daemon.status.daemon_state, "ready");
        assert!(
            client.join().unwrap(),
            "existing state read needs a reply while held worker drains"
        );
        daemon.watcher.tracker_mut().clear(193003);
    }

    #[test]
    fn root_timeout_keeps_one_bounded_worker_owned_until_fresh_authority_and_safe_completion() {
        let (mut daemon, valid, context) = fixture("com.example.held_safe_root");
        let pid = context.retry.pid;
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let worker_calls = calls.clone();
        let (release, wait) = std::sync::mpsc::channel();
        daemon
            .injection_jobs
            .dispatch(pid, context, move || {
                worker_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                wait.recv().unwrap();
                injector::BootstrapOutcome {
                    result: injector::InjectResult::Ok,
                    record: None,
                    downlink: None,
                    binding: None,
                    failure: None,
                }
            })
            .unwrap_or_else(|_| panic!("initial owned worker admission failed"));
        let unavailable = crate::plan::test_fixtures::startup_session_unavailable(valid.clone());
        assert_eq!(
            daemon.poll_with_plan(|_| unavailable),
            DaemonPollDisposition::Continue
        );
        assert!(daemon.injection_jobs.contains(pid));
        assert!(!daemon.last_plan.valid);
        assert_eq!(
            daemon.poll_with_plan(|_| valid.clone()),
            DaemonPollDisposition::Continue
        );
        assert!(daemon.injection_jobs.contains(pid));
        assert_eq!(daemon.status.daemon_state, "degraded");
        release.send(()).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while daemon.root_plan_unavailable && std::time::Instant::now() < deadline {
            assert_eq!(
                daemon.poll_with_plan(|_| valid.clone()),
                DaemonPollDisposition::Continue
            );
            std::thread::yield_now();
        }
        assert!(!daemon.root_plan_unavailable);
        assert!(daemon.injection_jobs.is_empty());
        assert!(daemon.injection_jobs.admissions_open());
        assert!(daemon.rebind_jobs.admissions_open());
        assert!(!daemon.injection_unsafe);
        assert_eq!(daemon.status.daemon_state, "ready");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn held_unsafe_or_panicked_worker_is_fenced_before_root_recovery_can_publish_ready() {
        for panics in [false, true] {
            let process = if panics {
                "com.example.held_panic"
            } else {
                "com.example.held_unsafe"
            };
            let (mut daemon, valid, context) = fixture(process);
            daemon.last_plan = valid.clone();
            daemon.status.startup_mode = plan::Startup::Interface;
            let pid = context.retry.pid;
            let (release, wait) = std::sync::mpsc::channel();
            daemon
                .injection_jobs
                .dispatch(pid, context, move || {
                    wait.recv().unwrap();
                    if panics {
                        panic!("held native worker panic");
                    }
                    injector::BootstrapOutcome {
                        result: injector::InjectResult::UnsafeCleanup,
                        record: None,
                        downlink: None,
                        binding: None,
                        failure: None,
                    }
                })
                .unwrap_or_else(|_| panic!("initial owned worker admission failed"));
            let unavailable =
                crate::plan::test_fixtures::startup_session_unavailable(valid.clone());
            assert_eq!(
                daemon.poll_with_plan(|_| unavailable),
                DaemonPollDisposition::Continue
            );
            assert!(!daemon.injection_unsafe);
            assert_eq!(daemon.status.daemon_state, "degraded");
            release.send(()).unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while !daemon.injection_unsafe && std::time::Instant::now() < deadline {
                assert_eq!(
                    daemon.poll_with_plan(|_| valid.clone()),
                    DaemonPollDisposition::Continue
                );
                assert_eq!(daemon.status.daemon_state, "degraded");
                std::thread::yield_now();
            }
            assert!(daemon.injection_unsafe);
            assert!(!daemon.injection_jobs.admissions_open());
            assert!(!daemon.rebind_jobs.admissions_open());
        }
    }

    #[test]
    fn fresh_root_authority_never_reopens_independently_closed_injection_admission() {
        let generation = crate::plan::test_fixtures::settings_generation();
        let valid = plan::Plan::defaults_for(&generation);
        let mut daemon = DaemonLoop::new(generation);
        daemon.last_plan = valid.clone();
        daemon.stop_injections();
        let unavailable = crate::plan::test_fixtures::startup_session_unavailable(valid.clone());
        assert_eq!(
            daemon.poll_with_plan(|_| unavailable),
            DaemonPollDisposition::Continue
        );
        assert_eq!(
            daemon.poll_with_plan(|_| valid),
            DaemonPollDisposition::Continue
        );
        assert!(!daemon.injection_jobs.admissions_open());
        assert!(!daemon.rebind_jobs.admissions_open());
        assert_eq!(daemon.status.daemon_state, "degraded");
    }

    #[test]
    fn an_authoritative_none_plan_still_stops_the_actual_poll() {
        let generation = crate::plan::test_fixtures::settings_generation();
        let mut none = plan::Plan::defaults_for(&generation);
        none.startup = plan::Startup::None;
        none.disable_all = true;
        assert!(none.valid);
        let mut daemon = DaemonLoop::new(generation);
        assert_eq!(
            daemon.poll_with_plan(|_| none),
            DaemonPollDisposition::SelfStopForNone
        );
        assert!(!daemon.injection_jobs.admissions_open());
        assert!(!daemon.rebind_jobs.admissions_open());
    }

    #[test]
    fn owner_timeout_never_commits_none_or_permanently_closes_late_target_admission() {
        let generation = crate::plan::test_fixtures::settings_generation();
        let valid = plan::Plan::defaults_for(&generation);
        assert_eq!(valid.startup, plan::Startup::Interface);
        let mut daemon = DaemonLoop::new(generation);
        daemon.last_plan = valid.clone();
        daemon.status.startup_mode = plan::Startup::Interface;
        daemon.startup_confirmed = true;
        let unavailable = crate::plan::test_fixtures::startup_session_unavailable(valid.clone());
        assert!(!unavailable.valid);
        assert!(unavailable.disable_all);
        assert_eq!(
            daemon.poll_with_plan(|_| unavailable),
            DaemonPollDisposition::Continue
        );
        assert!(daemon.injection_jobs.admissions_open());
        assert!(daemon.rebind_jobs.admissions_open());
        assert_eq!(daemon.status.startup_mode, plan::Startup::Interface);
        assert!(daemon.startup_confirmed);
        assert_eq!(daemon.status.daemon_state, "degraded");
        assert!(!daemon.last_plan.valid);
        assert_eq!(
            daemon.poll_with_plan(|_| valid),
            DaemonPollDisposition::Continue
        );
        assert!(daemon.injection_jobs.admissions_open());
        assert!(daemon.rebind_jobs.admissions_open());
        assert!(!daemon.status.kill_switch);
        assert_eq!(daemon.status.daemon_state, "ready");
    }

    use super::*;

    #[test]
    fn fev_recovery_fence_publishes_live_removal_and_scoped_quarantine_without_restart() {
        use std::io::BufRead;
        let generation = crate::plan::test_fixtures::vehicle_fault_generation();
        let mut plan = plan::Plan::defaults_for(&generation);
        plan.entries
            .iter_mut()
            .for_each(|entry| entry.enabled = true);
        let canonical_before = format!("{:?}", plan.entries);
        let mut daemon = DaemonLoop::new(generation.clone());
        let process = "com.qinggan.systemservice";
        daemon.write_fresh_desired_document(&plan, process).unwrap();
        let before = daemon.desired_documents[process].generation;
        for agent in &generation.catalog.agents {
            for target in &agent.targets {
                daemon.status.set_injection(
                    &agent.id,
                    &target.process,
                    status::InjectionState::Active,
                );
            }
        }
        let (downlink, target) = std::os::unix::net::UnixStream::pair().unwrap();
        target
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let fd = downlink.into_raw_fd();
        downlink::forget_fd(fd);
        daemon
            .watcher
            .tracker_mut()
            .track(process, 193555, 100, None, Some(fd))
            .unwrap();
        plan.runtime_fences
            .insert("vehicle-drive-forced-ev".into(), "invalid FEV WAL".into());
        daemon.reconcile_status_entries(&plan);
        daemon.push_live_config(&plan, &[(193555, process.into())]);
        let mut line = String::new();
        std::io::BufReader::new(target)
            .read_line(&mut line)
            .unwrap();
        assert!(line.starts_with("D|"));
        let desired: serde_json::Value = serde_json::from_str(line[2..].trim()).unwrap();
        assert_eq!(desired["agents"].as_array().unwrap().len(), 6);
        assert!(desired["agents"]
            .as_array()
            .unwrap()
            .iter()
            .all(|agent| agent["id"] != "vehicle-drive-forced-ev"));
        assert!(daemon.desired_documents[process].generation > before);
        assert_eq!(canonical_before, format!("{:?}", plan.entries));
        assert!(daemon.watcher.tracker().is_tracked(193555)); // No restart/kill.
        let status: serde_json::Value = serde_json::from_str(&daemon.status.serialize()).unwrap();
        let rows = status["injections"].as_array().unwrap();
        for row in rows {
            if row["id"] == "vehicle-drive-forced-ev" {
                assert_eq!(row["state"], "quarantined");
                assert_eq!(row["reason"], "owned-input-recovery-failed");
            } else {
                // Existing live-update acknowledgement may mark same-process
                // peers waiting; none is failed/quarantined or omitted.
                assert!(row["state"] == "active" || row["state"] == "waiting");
                assert_ne!(row["reason"], "owned-input-recovery-failed");
                if row["id"] == "settings" {
                    assert_eq!(row["state"], "active");
                }
            }
        }
        let (manifest, _) = bootstrap_metadata(&plan, &generation, process, 100).unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
        let initial: serde_json::Value =
            serde_json::from_str(manifest["desiredJson"].as_str().unwrap()).unwrap();
        assert!(initial["agents"]
            .as_array()
            .unwrap()
            .iter()
            .all(|agent| agent["id"] != "vehicle-drive-forced-ev"));
        // Module registration remains available for repair/re-enable without
        // reinjection; registration alone never executes a disabled agent.
        assert!(manifest["modules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|agent| agent["id"] == "vehicle-drive-forced-ev"));
        plan.runtime_fences.clear();
        daemon.reconcile_status_entries(&plan);
        let recovered: serde_json::Value =
            serde_json::from_str(&daemon.status.serialize()).unwrap();
        for row in recovered["injections"].as_array().unwrap() {
            if row["id"] == "vehicle-drive-forced-ev" {
                assert_eq!(row["state"], "waiting");
                assert_eq!(row["reason"], "target-waiting");
                assert!(row.get("currentEndpoint").is_none());
            }
        }
        downlink::forget_fd(fd);
    }

    #[test]
    fn launcher_observer_authority_keeps_all_features_disabled() {
        let mut generation = crate::plan::test_fixtures::settings_generation();
        generation.catalog.agents[1].targets[0].process = crate::launcher_page::PROCESS.into();
        let plan = plan::Plan::defaults_for(&generation);
        let before = format!("{plan:?}");
        let enabled =
            plan.enabled_ids_for_process(crate::launcher_page::PROCESS, &generation.catalog);
        assert!(enabled.is_empty());
        let authority =
            bootstrap_authority_ids(&generation, crate::launcher_page::PROCESS, &enabled);
        assert!(!authority.is_empty());
        assert!(bootstrap_authority_ids(&generation, "other.process", &enabled).is_empty());
        let (manifest, _) =
            bootstrap_metadata(&plan, &generation, crate::launcher_page::PROCESS, 1).unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
        let desired: serde_json::Value =
            serde_json::from_str(manifest["desiredJson"].as_str().unwrap()).unwrap();
        assert!(desired["agents"]
            .as_array()
            .unwrap()
            .iter()
            .all(|agent| agent["enabled"] == false));
        assert_eq!(before, format!("{plan:?}"));
    }

    #[test]
    fn cache_maintenance_context_does_not_activate_agents_and_rollback_closes_it() {
        const PROCESS: &str = "com.qinggan.app.setting.test_cache_maintenance_context_does_not_activate_agents_and_rollback_closes_it";
        let (mut daemon, _, _) = fixture(PROCESS);
        daemon.desired_documents.clear();
        daemon.activation_frozen = true;
        let process = crate::icon_quiescence::PROCESS;
        let (record, _target_log) = std::os::unix::net::UnixStream::pair().unwrap();
        let (downlink, _target_state) = std::os::unix::net::UnixStream::pair().unwrap();
        daemon
            .watcher
            .tracker_mut()
            .track(
                process,
                123,
                456,
                Some(record.into_raw_fd()),
                Some(downlink.into_raw_fd()),
            )
            .unwrap();
        let (_, _, epoch, _) = daemon.watcher.tracker().downlinks()[0].clone();
        let context = agent_log::EndpointContext {
            pid: 123,
            process: process.into(),
            endpoint_epoch: epoch,
            target_starttime: Some(456),
            document_generation: Some(999),
            resident_generation_id: "a".repeat(64),
            resident_catalog_sha256: "b".repeat(64),
            ..Default::default()
        };
        daemon.uninstall_cache_context = Some(context.clone());
        let maintenance = daemon.endpoint_context(123, process, epoch);
        assert_eq!(maintenance.document_generation, Some(999));
        assert!(maintenance.agents.is_empty());
        assert!(daemon.desired_documents.is_empty());
        assert!(!maintenance.restart_allowed);
        let frame = crate::icon_quiescence::begin(&maintenance, "c".repeat(64)).unwrap();
        let json = std::str::from_utf8(&frame[2..frame.len() - 1]).unwrap();
        assert!(!crate::icon_quiescence::acknowledged(&maintenance));
        let wrong_revision = agent_log::EndpointContext {
            document_generation: Some(1000),
            ..maintenance.clone()
        };
        assert_eq!(crate::icon_quiescence::observe(json, &wrong_revision), None);
        assert_eq!(crate::icon_quiescence::observe(json, &maintenance), Some(1));
        assert!(crate::icon_quiescence::acknowledged(&maintenance));
        let receipt = crate::icon_quiescence::receipt(
            &maintenance,
            &"d".repeat(64),
            "11111111-1111-1111-1111-111111111111",
        )
        .unwrap();
        let receipt: voboost_contract::icon_cache_quiescence::Receipt =
            serde_json::from_slice(&receipt).unwrap();
        assert!(receipt.matches(&"d".repeat(64), "11111111-1111-1111-1111-111111111111"));
        crate::icon_quiescence::reset();
        assert_ne!(
            daemon
                .endpoint_context(124, process, epoch)
                .document_generation,
            Some(999)
        );
        assert_ne!(
            daemon
                .endpoint_context(123, process, epoch + 1)
                .document_generation,
            Some(999)
        );
        daemon.activation_frozen = false;
        assert_ne!(
            daemon
                .endpoint_context(123, process, epoch)
                .document_generation,
            Some(999)
        );
        daemon.finish_uninstall_cache_maintenance(true);
        assert!(daemon.uninstall_cache_context.is_none());
        assert!(daemon.watcher.tracker().downlinks().is_empty());
        assert!(daemon.desired_documents.is_empty());
    }

    #[test]
    fn none_admitted_ids_require_exact_endpoint_and_native_generation() {
        let resident = crate::plan::test_fixtures::settings_generation();
        let mut state = DesiredDocumentState::with_ids(
            "semantic".into(),
            1,
            vec!["settings".into(), "font-cyrillic".into()],
            resident.clone(),
        );
        let endpoint = (42, 7, 99);
        state.admitted_endpoint = Some(endpoint);
        let native = (resident.id.clone(), resident.catalog_sha256.clone());
        assert_eq!(
            admitted_ids_for_endpoint(
                Some(&state),
                Some(endpoint),
                Some(native.clone()),
                &resident
            ),
            state.ids
        );
        for stale in [(43, 7, 99), (42, 8, 99), (42, 7, 100)] {
            assert!(admitted_ids_for_endpoint(
                Some(&state),
                Some(stale),
                Some(native.clone()),
                &resident
            )
            .is_empty());
        }
        for stale in [
            ("wrong-generation".into(), native.1.clone()),
            (native.0.clone(), "wrong-catalog".into()),
        ] {
            assert!(admitted_ids_for_endpoint(
                Some(&state),
                Some(endpoint),
                Some(stale),
                &resident
            )
            .is_empty());
        }
        assert!(
            admitted_ids_for_endpoint(Some(&state), None, Some(native.clone()), &resident)
                .is_empty()
        );
        assert!(
            admitted_ids_for_endpoint(Some(&state), Some(endpoint), None, &resident).is_empty()
        );
        state.admitted_endpoint = None;
        assert!(
            admitted_ids_for_endpoint(Some(&state), Some(endpoint), Some(native), &resident)
                .is_empty()
        );
    }

    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, IntoRawFd};
    use std::sync::mpsc;
    use std::time::Duration;

    const PROCESS: &str = "com.qinggan.app.setting";

    fn fixture(process: &str) -> (DaemonLoop, plan::Plan, InjectionContext) {
        static NEXT_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(193010);
        let pid = NEXT_PID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut generation = generation::test_support::verified_variant(1);
        for agent in &mut generation.catalog.agents {
            for target in &mut agent.targets {
                if target.process == PROCESS {
                    target.process = process.into();
                }
            }
        }
        let plan = plan::Plan::defaults_for(&generation);
        let mut daemon = DaemonLoop::new(generation.clone());
        daemon.last_plan = plan.clone();
        daemon.write_fresh_desired_document(&plan, process).unwrap();
        let desired = &daemon.desired_documents[process];
        let context = InjectionContext {
            process: process.into(),
            authority: target_identity::AttestedTarget {
                pid,
                starttime: 123,
                uid: 1000,
                selinux_context: "u:r:platform_app:s0".into(),
            },
            retry: PendingRetry {
                pid,
                starttime: 123,
                attempts: 0,
                next_retry_at: std::time::Duration::ZERO,
                generation,
                agent_ids: desired.ids.clone(),
                desired_semantics: desired.semantic_document.clone(),
                document_generation: desired.generation,
                release_manifest: None,
                bootstrap: std::sync::Arc::new(Vec::new()),
            },
            agent_id: "settings".into(),
            started: std::time::Instant::now(),
        };
        (daemon, plan, context)
    }

    #[test]
    fn pending_cluster_preserves_live_bootstrap_and_admission_state() {
        let (mut daemon, plan, context) = fixture("com.qinggan.app.setting.pending_cluster");
        let pid = context.retry.pid;
        let (release, wait) = mpsc::channel();
        daemon
            .injection_jobs
            .dispatch(pid, context, move || {
                wait.recv().unwrap();
                injector::BootstrapOutcome {
                    result: injector::InjectResult::Pending,
                    record: None,
                    downlink: None,
                    binding: None,
                    failure: None,
                }
            })
            .unwrap_or_else(|_| panic!("worker admission failed"));
        // A pending result must not perform a rollback even if an earlier
        // fence closed the queue while the worker was still draining.
        daemon.injection_jobs.close();
        assert!(matches!(
            daemon.finish_uninstall_preparation(Err(
                crate::cluster_control::UNINSTALL_PENDING.into()
            )),
            Ok(PrepareUninstallOutcome::PendingCluster)
        ));
        assert!(daemon.injection_jobs.contains(pid));
        assert!(!daemon.injection_jobs.admissions_open());
        release.send(()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !daemon.injection_jobs.is_empty() {
            assert!(std::time::Instant::now() < deadline);
            daemon.collect_injections(&plan);
            std::thread::yield_now();
        }
    }

    fn pipes(
        result: injector::InjectResult,
    ) -> (
        injector::BootstrapOutcome,
        std::os::unix::net::UnixStream,
        std::os::unix::net::UnixStream,
    ) {
        let (record, target_log) = std::os::unix::net::UnixStream::pair().unwrap();
        let (downlink, target_state) = std::os::unix::net::UnixStream::pair().unwrap();
        record.set_nonblocking(true).unwrap();
        downlink.set_nonblocking(true).unwrap();
        (
            injector::BootstrapOutcome {
                result,
                record: Some(record.into()),
                downlink: Some(downlink.into()),
                binding: None,
                failure: None,
            },
            target_log,
            target_state,
        )
    }

    #[test]
    fn endpoint_clock_failure_after_completed_bootstrap_fences_injection() {
        const PROCESS: &str = "com.qinggan.app.setting.test_endpoint_clock_failure";
        let (mut daemon, plan, context) = fixture(PROCESS);
        let pid = context.retry.pid;
        daemon
            .watcher
            .tracker_mut()
            .fail_next_epoch_allocation(std::io::ErrorKind::PermissionDenied);
        let (outcome, mut target_log, mut target_state) = pipes(injector::InjectResult::Ok);
        daemon.adopt_injection(context, outcome, &plan, true);
        assert!(daemon.injection_unsafe);
        assert!(!daemon.injection_jobs.admissions_open());
        assert!(!daemon.rebind_jobs.admissions_open());
        assert!(!daemon.watcher.tracker_mut().is_tracked(pid));
        let mut byte = [0];
        assert_eq!(target_log.read(&mut byte).unwrap(), 0);
        assert_eq!(target_state.read(&mut byte).unwrap(), 0);
        assert!(daemon
            .status
            .serialize()
            .contains("endpoint-registration-failed"));
    }

    #[test]
    fn native_pending_completion_retains_authority_and_enters_slow_retry() {
        const PROCESS: &str = "com.qinggan.app.setting.test_native_pending_completion_retains_authority_and_enters_slow_retry";
        let (mut daemon, plan, mut context) = fixture(PROCESS);
        context.retry.attempts = MAX_AGENT_PENDING_RETRIES;
        let pid = context.retry.pid;
        let authority = context.retry.generation.id.clone();
        daemon.adopt_injection(
            context,
            injector::BootstrapOutcome {
                result: injector::InjectResult::Pending,
                record: None,
                downlink: None,
                binding: None,
                failure: None,
            },
            &plan,
            true,
        );
        let retry = &daemon.pending_retries[PROCESS];
        assert_eq!(retry.generation.id, authority);
        assert_eq!(retry.attempts, MAX_AGENT_PENDING_RETRIES);
        assert!(retry.next_retry_at >= Duration::from_secs(30));
        assert!(daemon.watcher.tracker().is_tracked(pid));
        assert!(!daemon.watcher.tracker().is_tracked_with_pipes(pid));
        assert_eq!(pending_retry_delay(0), Duration::from_millis(500));
        assert_eq!(pending_retry_delay(19), Duration::from_millis(500));
        assert_eq!(pending_retry_delay(20), Duration::from_secs(30));
        assert_eq!(pending_retry_delay(u32::MAX), Duration::from_secs(30));
        daemon.watcher.tracker_mut().clear(pid);
    }

    #[test]
    fn permanent_rebind_rejection_never_rearms_transport_or_bootstrap() {
        const PROCESS: &str = "com.qinggan.app.setting.test_permanent_rebind_rejection_never_rearms_transport_or_bootstrap";
        for result in [
            injector::InjectResult::Denied,
            injector::InjectResult::IdentityMismatch,
            injector::InjectResult::BitnessFailed,
            injector::InjectResult::LoaderUnresolved,
        ] {
            let (mut daemon, plan, context) = fixture(PROCESS);
            let pid = context.retry.pid;
            let identity = daemon.resident_identity(&plan, PROCESS, pid, 123).unwrap();
            let mut recovery = crate::resident_recovery::Recovery::new(identity.clone());
            recovery.attempted();
            daemon.resident_recovery.insert(PROCESS.into(), recovery);
            daemon.collect_rebind_outcome(
                &plan,
                RebindContext {
                    process: PROCESS.into(),
                    authority: context.authority,
                    recovery_identity: Some(identity),
                    generations: vec![context.retry.generation],
                    authorized_generations: Default::default(),
                    started: std::time::Instant::now(),
                },
                RebindOutcome {
                    result,
                    record: None,
                    downlink: None,
                    identity: None,
                },
                Some(123),
            );
            assert_ne!(
                daemon.resident_recovery[PROCESS].admit(Duration::from_secs(3600)),
                crate::resident_recovery::Admission::Ready
            );
            assert!(daemon.injection_jobs.is_empty());
        }
    }

    #[test]
    fn package_execution_pending_and_denied_never_complete_none_or_stop_service() {
        const PROCESS: &str = "com.qinggan.app.setting.test_package_execution_pending_and_denied_never_complete_none_or_stop_service";
        let (mut daemon, plan, _context) = fixture(PROCESS);
        let status = daemon.status.serialize();
        for admission in [Ok(false), Err("package service denied".into())] {
            assert_eq!(
                daemon.complete_none_after_package_admission(&plan, admission),
                DaemonPollDisposition::Continue
            );
            assert_eq!(daemon.status.serialize(), status);
        }
    }

    #[test]
    fn package_execution_pending_never_recovers_a_failed_observation() {
        const PROCESS: &str = "com.qinggan.app.setting.test_package_execution_pending_never_recovers_a_failed_observation";
        let (mut daemon, plan, _context) = fixture(PROCESS);
        let directory = tempfile::tempdir().unwrap();
        let logs = directory.path().join("logs");
        crate::canonical_log::with_test_log(&logs, || {
            for admission in [
                Err("package service denied".into()),
                Ok(false),
                Ok(false),
                Err("package service denied".into()),
            ] {
                daemon.complete_none_after_package_admission(&plan, admission);
            }
        });
        let rows = std::fs::read_to_string(logs.join("segment-active.jsonl")).unwrap();
        assert_eq!(
            rows.lines().count(),
            1,
            "pending must preserve the failed episode: {rows}"
        );
        assert!(!rows.contains("recovered"));
    }

    #[test]
    fn native_failure_survives_atomic_status_publish_and_log_retention() {
        const PROCESS: &str = "com.qinggan.app.setting.test_native_failure_survives_atomic_status_publish_and_log_retention";
        let (mut daemon, plan, context) = fixture(PROCESS);
        let failure = injector::NativeFailure::classify(injector::InjectResult::UnsafeCleanup,
            "remote-call-restore restore=gpr/compare reason=mismatch pstate-valid=1 expected=0x60000000 observed=0x60000400 changed=0x400 first=265 attemptToken=DO_NOT_PERSIST");
        let (mut outcome, _log, _state) = pipes(injector::InjectResult::UnsafeCleanup);
        outcome.failure = Some(failure);
        daemon.adopt_injection(context, outcome, &plan, true);
        let directory = tempfile::tempdir().unwrap();
        assert!(daemon
            .status
            .write_atomic_in(directory.path(), std::ffi::OsStr::new("status.json")));
        let before = std::fs::read(directory.path().join("status.json")).unwrap();
        let document: serde_json::Value = serde_json::from_slice(&before).unwrap();
        let entry = document["injections"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["reason"] == "native-injection-failed")
            .unwrap();
        assert_eq!(
            entry["details"]["nativeFailure"]["stage"],
            "register-restore"
        );
        assert_eq!(entry["details"]["nativeFailure"]["pstate_xor"], 1024);
        assert!(!String::from_utf8_lossy(&before).contains("DO_NOT_PERSIST"));
        daemon.set_process_event(
            &plan,
            PROCESS,
            status::InjectionState::Waiting,
            "native-init-pending",
        );
        let waiting: serde_json::Value = serde_json::from_str(&daemon.status.serialize()).unwrap();
        assert!(waiting["injections"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["details"]["nativeFailure"]["stage"] == "register-restore"));
        crate::canonical_log::test_rotate_away_initial_record();
        assert_eq!(
            std::fs::read(directory.path().join("status.json")).unwrap(),
            before
        );
        assert!(daemon
            .status
            .write_atomic_in(directory.path(), std::ffi::OsStr::new("status.json")));
        let published: serde_json::Value =
            serde_json::from_slice(&std::fs::read(directory.path().join("status.json")).unwrap())
                .unwrap();
        assert!(published["injections"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["details"]["nativeFailure"]["stage"] == "register-restore"));
        daemon.set_process_event(
            &plan,
            PROCESS,
            status::InjectionState::Active,
            "agent-ready",
        );
        let active: serde_json::Value = serde_json::from_str(&daemon.status.serialize()).unwrap();
        assert!(active["injections"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["details"].get("nativeFailure").is_none()));
        assert_eq!(
            active["lastUnsafeNativeFailure"]["diagnostic"]["stage"],
            "register-restore"
        );
    }

    #[test]
    fn stale_unsafe_completion_retains_global_cause_without_changing_agent_slots() {
        const PROCESS: &str = "com.qinggan.app.setting.test_stale_unsafe_completion_retains_global_cause_without_changing_agent_slots";
        let mut published = Vec::new();
        let mut directories = Vec::new();
        for identity_matches in [false, true] {
            let (mut daemon, plan, mut context) = fixture(PROCESS);
            let initial = daemon.status.serialize();
            let generation = context.retry.generation.id.clone();
            let original_document = context.retry.document_generation;
            if identity_matches {
                context.retry.document_generation -= 1;
            }
            let (mut outcome, _log, _state) = pipes(injector::InjectResult::UnsafeCleanup);
            outcome.failure = Some(injector::NativeFailure::classify(injector::InjectResult::UnsafeCleanup,
                "restore=gpr/compare reason=mismatch pstate-valid=1 expected=0x60000000 observed=0x60000400 first=265"));
            daemon.adopt_injection(context, outcome, &plan, identity_matches);
            assert!(daemon.injection_unsafe);
            let value: serde_json::Value =
                serde_json::from_str(&daemon.status.serialize()).unwrap();
            let previous: serde_json::Value = serde_json::from_str(&initial).unwrap();
            assert_eq!(value["injections"], previous["injections"]);
            assert_eq!(value["lastUnsafeNativeFailure"]["generationId"], generation);
            assert_eq!(
                value["lastUnsafeNativeFailure"]["documentGeneration"],
                original_document - i64::from(identity_matches)
            );
            daemon.set_process_event(
                &plan,
                PROCESS,
                status::InjectionState::Active,
                "unrelated-agent-ready",
            );
            assert!(daemon.status.last_unsafe_native_failure.is_some());
            let directory = tempfile::tempdir().unwrap();
            assert!(daemon
                .status
                .write_atomic_in(directory.path(), std::ffi::OsStr::new("status.json")));
            let bytes = std::fs::read(directory.path().join("status.json")).unwrap();
            let result = crate::management::verify_status_bytes(
                &bytes,
                &daemon.status.release_identity,
                &daemon.status.manifest_sha256,
                &daemon.status.generation_id,
                &daemon.status.catalog_sha256,
                daemon.status.startup_mode,
                false,
            );
            assert_eq!(
                result.unwrap_err(),
                "status.json daemon is not ready: state=degraded"
            );
            published.push(bytes);
            directories.push(directory);
        }
        crate::canonical_log::test_rotate_away_initial_record();
        for (directory, bytes) in directories.iter().zip(published) {
            assert_eq!(
                std::fs::read(directory.path().join("status.json")).unwrap(),
                bytes
            );
        }
    }

    #[test]
    fn stale_completion_closes_endpoints_without_tracking_or_replacement_status() {
        const PROCESS: &str = "com.qinggan.app.setting.test_stale_completion_closes_endpoints_without_tracking_or_replacement_status";
        for change in 0..4 {
            let (mut daemon, mut plan, mut context) = fixture(PROCESS);
            match change {
                0 => {
                    // A reused target must not overwrite the newer registration.
                    daemon
                        .watcher
                        .tracker_mut()
                        .track(PROCESS, context.retry.pid, 456, None, None)
                        .unwrap();
                }
                1 => {
                    let next = generation::test_support::verified_variant(2);
                    plan = plan::Plan::defaults_for(&next);
                    daemon.adopt_generation(next);
                }
                2 => {
                    daemon.generation.catalog_sha256 = "f".repeat(64);
                }
                3 => {
                    context.retry.document_generation -= 1;
                }
                _ => unreachable!(),
            }
            let state_before = daemon.status.serialize();
            let (outcome, _log, _state) = pipes(if change == 0 {
                injector::InjectResult::Ok
            } else {
                injector::InjectResult::Denied
            });
            let record = outcome.record.as_ref().unwrap().as_raw_fd();
            let downlink = outcome.downlink.as_ref().unwrap().as_raw_fd();
            let pid = context.retry.pid;
            daemon.adopt_injection(context, outcome, &plan, change != 0);
            assert_eq!(unsafe { libc::fcntl(record, libc::F_GETFD) }, -1);
            assert_eq!(unsafe { libc::fcntl(downlink, libc::F_GETFD) }, -1);
            assert_eq!(daemon.status.serialize(), state_before);
            assert_eq!(daemon.watcher.tracker().is_tracked(pid), change == 0);
        }
    }

    #[test]
    fn register_deferral_retries_without_fencing_admissions() {
        const PROCESS: &str =
            "com.qinggan.app.setting.test_register_deferral_retries_without_fencing_admissions";
        let (mut daemon, plan, context) = fixture(PROCESS);
        let pid = context.retry.pid;
        daemon.adopt_injection(
            context,
            injector::BootstrapOutcome {
                result: injector::InjectResult::RegisterDeferred,
                record: None,
                downlink: None,
                binding: None,
                failure: None,
            },
            &plan,
            true,
        );
        assert!(daemon.pending_retries.contains_key(PROCESS));
        assert!(daemon.watcher.tracker().is_tracked(pid));
        assert!(!daemon.watcher.tracker().is_tracked_with_pipes(pid));
        assert!(!daemon.injection_unsafe);
        assert!(daemon.injection_jobs.admissions_open());
        assert!(daemon
            .status
            .serialize()
            .contains("register-baseline-deferred"));
    }

    #[test]
    fn missing_preparation_observation_does_not_block_bootstrap_dispatch() {
        const PROCESS: &str = "com.qinggan.app.setting.test_missing_preparation_observation";
        let (mut daemon, plan, context) = fixture(PROCESS);
        let pid = context.retry.pid;
        assert!(daemon.begin_preparation(PROCESS, pid).is_none());
        daemon.dispatch_bootstrap(
            PROCESS,
            context.retry,
            context.authority,
            "arm64-v8a",
            context.agent_id,
            &plan,
            None,
        );
        assert!(daemon.injection_jobs.contains(pid));
        daemon.stop_injections();
    }

    #[test]
    fn bootstrap_and_rebind_admission_share_one_pid_owner() {
        const PROCESS: &str =
            "com.qinggan.app.setting.test_bootstrap_and_rebind_admission_share_one_pid_owner";
        let (mut daemon, plan, context) = fixture(PROCESS);
        let pid = context.retry.pid;
        let retry = context.retry.clone();
        let authority = context.authority.clone();
        let (release_tx, release_rx) = mpsc::channel();
        daemon
            .injection_jobs
            .dispatch(pid, context, move || {
                release_rx.recv().unwrap();
                injector::BootstrapOutcome {
                    result: injector::InjectResult::Pending,
                    record: None,
                    downlink: None,
                    binding: None,
                    failure: None,
                }
            })
            .ok()
            .unwrap();
        daemon.dispatch_bootstrap(
            PROCESS,
            retry.clone(),
            authority.clone(),
            "arm64-v8a",
            "settings".into(),
            &plan,
            None,
        );
        assert_eq!(daemon.injection_jobs.contexts().count(), 1);
        assert!(daemon.rebind_jobs.is_empty());
        release_tx.send(()).unwrap();
        while !daemon.injection_jobs.is_empty() {
            daemon.injection_jobs.collect();
            std::thread::yield_now();
        }
        let rebind = RebindContext {
            recovery_identity: None,
            process: PROCESS.into(),
            authority: authority.clone(),
            generations: vec![retry.generation.clone()],
            authorized_generations: Default::default(),
            started: std::time::Instant::now(),
        };
        let (release_tx, release_rx) = mpsc::channel();
        daemon
            .rebind_jobs
            .dispatch(pid, rebind, move || {
                release_rx.recv().unwrap();
                RebindOutcome {
                    result: injector::InjectResult::Pending,
                    record: None,
                    downlink: None,
                    identity: None,
                }
            })
            .ok()
            .unwrap();
        daemon.dispatch_bootstrap(
            PROCESS,
            retry,
            authority,
            "arm64-v8a",
            "settings".into(),
            &plan,
            None,
        );
        assert!(daemon.injection_jobs.is_empty());
        assert_eq!(daemon.rebind_jobs.contexts().count(), 1);
        release_tx.send(()).unwrap();
        daemon.stop_injections();
        assert!(!daemon.injection_jobs_active());
    }

    #[test]
    fn collected_completion_suppresses_stale_appearance_without_rebinding() {
        const PROCESS: &str = "com.qinggan.app.setting.test_collected_completion_suppresses_stale_appearance_without_rebinding";
        let (mut daemon, plan, context) = fixture(PROCESS);
        let pid = context.retry.pid;
        let (outcome, _log, _state) = pipes(injector::InjectResult::Ok);
        daemon.adopt_injection(context, outcome, &plan, true);
        let before = daemon.status.serialize();
        daemon.inject_new_targets(&[(PROCESS.into(), pid)], &plan, &None, true);
        assert_eq!(daemon.status.serialize(), before);
        assert!(daemon.watcher.tracker().is_tracked_with_pipes(pid));
        assert!(!daemon.injection_jobs_active());
        daemon.watcher.tracker_mut().clear(pid);
    }

    fn assert_peer_closed(peer: &mut std::os::unix::net::UnixStream) {
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.read(&mut [0u8; 1]).unwrap(),
            0,
            "original socket peer must observe EOF"
        );
    }

    #[test]
    fn peer_closure_assertion_survives_fd_number_reuse() {
        const CHILD: &str = "VOBOOST_ENDPOINT146_FD_REUSE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "runtime::parallel_tests::peer_closure_assertion_survives_fd_number_reuse",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        use std::os::fd::{FromRawFd, OwnedFd};
        let (record, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        // A private child file table permits deterministic high-number reuse
        // without replacing another test's descriptor.
        let number = unsafe { libc::fcntl(record.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 512) };
        assert!(number >= 512);
        let duplicate = unsafe { OwnedFd::from_raw_fd(number) };
        drop(record);
        drop(duplicate);
        let unrelated = std::fs::File::open("/dev/null").unwrap();
        let reused = unsafe { libc::fcntl(unrelated.as_raw_fd(), libc::F_DUPFD_CLOEXEC, number) };
        assert_eq!(reused, number);
        let _reused = unsafe { OwnedFd::from_raw_fd(reused) };
        assert_ne!(unsafe { libc::fcntl(number, libc::F_GETFD) }, -1);
        assert_peer_closed(&mut peer);
    }

    #[test]
    fn unsafe_cleanup_fences_admission_even_when_target_identity_is_stale() {
        const PROCESS: &str = "com.qinggan.app.setting.test_unsafe_cleanup_fences_admission_even_when_target_identity_is_stale";
        let (mut daemon, plan, context) = fixture(PROCESS);
        let (outcome, mut log, _state) = pipes(injector::InjectResult::UnsafeCleanup);
        daemon.adopt_injection(context, outcome, &plan, false);
        assert!(daemon.injection_unsafe);
        assert!(!daemon.injection_jobs.admissions_open());
        assert!(!daemon.rebind_jobs.admissions_open());
        assert_eq!(daemon.status.daemon_state, "degraded");
        assert_peer_closed(&mut log);
    }

    #[test]
    fn changed_generation_completion_keeps_old_resident_control_and_delivers_empty_desired() {
        const PROCESS: &str = "com.qinggan.app.setting.test_changed_generation_completion_keeps_old_resident_control_and_delivers_empty_desired";
        let (mut daemon, _plan, context) = fixture(PROCESS);
        let old_id = context.retry.generation.id.clone();
        let next = generation::test_support::verified_variant(2);
        let mut plan = plan::Plan::defaults_for(&next);
        plan = plan.disabled_for_uninstall();
        daemon.adopt_generation(next.clone());
        let pid = context.retry.pid;
        let (outcome, _log, mut target) = pipes(injector::InjectResult::Ok);
        target
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let fd = outcome.downlink.as_ref().unwrap().as_raw_fd();
        daemon.adopt_injection(context, outcome, &plan, true);
        assert!(daemon.watcher.tracker().is_tracked_with_pipes(pid));
        let epoch = daemon
            .watcher
            .tracker()
            .downlink_identity(PROCESS, fd)
            .unwrap()
            .2;
        let endpoint = daemon.endpoint_context(pid, PROCESS, epoch);
        assert_eq!(endpoint.resident_generation_id, old_id);
        assert_eq!(endpoint.active_generation_id, next.id);
        assert!(endpoint.agents.is_empty());
        assert_eq!(daemon.status.generation_id, next.id);
        daemon.flush_downlinks();
        let mut bytes = [0; 8192];
        let count = target.read(&mut bytes).unwrap();
        let frame = std::str::from_utf8(&bytes[..count]).unwrap();
        assert!(frame.starts_with("D|"), "{frame}");
        let value: serde_json::Value =
            serde_json::from_str(frame.trim().strip_prefix("D|").unwrap()).unwrap();
        assert_eq!(value["generationId"], old_id);
        assert_eq!(value["agents"], serde_json::json!([]));
        daemon.watcher.tracker_mut().clear(pid);
    }

    #[test]
    fn staged_old_generation_remains_controlled_until_terminal_outcome() {
        const PROCESS: &str = "com.qinggan.app.setting.test_staged_old_generation_remains_controlled_until_terminal_outcome";
        let (mut daemon, _plan, mut context) = fixture(PROCESS);
        let old = context.retry.generation.clone();
        let manifest = serde_json::to_vec(&serde_json::json!({"generationId": old.id,
            "catalogSha256": old.catalog_sha256}))
        .unwrap();
        let files = [bootstrap_pipe::File {
            name: "core.dex",
            size: 1,
        }];
        let envelope = bootstrap_pipe::build(&manifest, &files, |_| Ok(vec![1])).unwrap();
        let binding = crate::bootstrap_worker::new_binding(
            context.retry.pid,
            context.retry.starttime,
            &envelope,
        )
        .unwrap();
        context.retry.bootstrap = std::sync::Arc::new(envelope);
        let next = generation::test_support::verified_variant(2);
        let mut plan = plan::Plan::defaults_for(&next);
        plan = plan.disabled_for_uninstall();
        daemon.adopt_generation(next);
        let pid = context.retry.pid;
        let starttime = context.retry.starttime;
        let (mut outcome, _log, _state) = pipes(injector::InjectResult::Staged);
        outcome.binding = Some(binding.clone());
        let fd = outcome.downlink.as_ref().unwrap().as_raw_fd();
        daemon.adopt_injection(context, outcome, &plan, true);
        let mut retry = daemon.pending_retries.remove(PROCESS).unwrap();
        assert!(daemon.retry_pending_target(PROCESS, &mut retry, &plan));
        assert!(daemon.watcher.tracker().is_tracked_with_pipes(pid));
        let epoch = daemon
            .watcher
            .tracker()
            .downlink_identity(PROCESS, fd)
            .unwrap()
            .2;
        let record = format!(
            "{}|{pid}|{starttime}|{}|{}|ready",
            hex::encode(binding.nonce),
            old.id,
            old.catalog_sha256
        );
        assert!(crate::bootstrap_worker::observe(&record, pid, epoch));
        assert!(!daemon.retry_pending_target(PROCESS, &mut retry, &plan));
        assert!(daemon.watcher.tracker().is_tracked_with_pipes(pid));
        daemon.watcher.tracker_mut().clear(pid);
    }

    #[test]
    fn uninstall_freeze_joins_active_jobs_before_returning() {
        const PROCESS: &str =
            "com.qinggan.app.setting.test_uninstall_freeze_joins_active_jobs_before_returning";
        let (mut daemon, _plan, context) = fixture(PROCESS);
        let (release_tx, release_rx) = mpsc::channel();
        daemon
            .injection_jobs
            .dispatch(context.retry.pid, context, move || {
                release_rx.recv().unwrap();
                injector::BootstrapOutcome {
                    result: injector::InjectResult::Pending,
                    record: None,
                    downlink: None,
                    binding: None,
                    failure: None,
                }
            })
            .ok()
            .unwrap();
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            release_tx.send(()).unwrap();
        });
        daemon.set_uninstall_frozen(true);
        assert!(daemon.uninstall_frozen());
        assert!(!daemon.injection_jobs_active());
        assert!(!daemon.injection_jobs.admissions_open());
        release.join().unwrap();
    }

    #[test]
    fn terminal_drain_services_real_state_reply_before_joining_blocked_job() {
        const PROCESS: &str = "com.qinggan.app.setting.test_terminal_drain_services_real_state_reply_before_joining_blocked_job";
        let (mut daemon, plan, context) = fixture(PROCESS);
        let (record, mut client_log) = std::os::unix::net::UnixStream::pair().unwrap();
        let (reply, mut client_reply) = std::os::unix::net::UnixStream::pair().unwrap();
        record.set_nonblocking(true).unwrap();
        reply.set_nonblocking(true).unwrap();
        client_reply
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        daemon
            .watcher
            .tracker_mut()
            .track(
                PROCESS,
                193002,
                789,
                Some(record.into_raw_fd()),
                Some(reply.into_raw_fd()),
            )
            .unwrap();
        daemon.watcher.tracker_mut().bind_settings(
            193002,
            &daemon.generation.id,
            &daemon.generation.catalog_sha256,
            true,
        );
        daemon.write_desired_document(&plan, PROCESS).unwrap();
        let (release_tx, release_rx) = mpsc::channel();
        daemon
            .injection_jobs
            .dispatch(context.retry.pid, context, move || {
                release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
                injector::BootstrapOutcome {
                    result: injector::InjectResult::Pending,
                    record: None,
                    downlink: None,
                    binding: None,
                    failure: None,
                }
            })
            .ok()
            .unwrap();
        let client = std::thread::spawn(move || {
            client_log
                .write_all(b"R|1|settings|parallel-job-missing\n")
                .unwrap();
            let mut reply = [0; 128];
            let count = client_reply.read(&mut reply).unwrap();
            assert_eq!(&reply[..count], b"R|1|missing|\n");
            release_tx.send(()).unwrap();
        });
        daemon.stop_injections();
        assert!(!daemon.injection_jobs_active());
        assert!(!daemon.injection_jobs.admissions_open());
        client.join().unwrap();
        daemon.watcher.tracker_mut().clear(193002);
    }
    #[test]
    fn failed_rebind_completion_never_dispatches_full_bootstrap() {
        const PROCESS: &str =
            "com.qinggan.app.setting.test_failed_rebind_completion_never_dispatches_full_bootstrap";
        let (mut daemon, plan, context) = fixture(PROCESS);
        let pid = context.retry.pid;
        let identity = daemon
            .resident_identity(&plan, PROCESS, pid, context.authority.starttime)
            .unwrap();
        let mut recovery = crate::resident_recovery::Recovery::new(identity.clone());
        recovery.attempted();
        daemon.resident_recovery.insert(PROCESS.into(), recovery);
        let rebind = RebindContext {
            recovery_identity: Some(identity),
            process: PROCESS.into(),
            authority: context.authority,
            generations: vec![context.retry.generation],
            authorized_generations: Default::default(),
            started: std::time::Instant::now(),
        };
        daemon.collect_rebind_outcome(
            &plan,
            rebind,
            RebindOutcome {
                result: injector::InjectResult::InitFailed,
                record: None,
                downlink: None,
                identity: None,
            },
            Some(123),
        );
        assert!(
            daemon.injection_jobs.is_empty(),
            "uncertain resident must not replay Java bootstrap"
        );
        assert_eq!(
            daemon.resident_recovery[PROCESS].admit(daemon.started.elapsed()),
            crate::resident_recovery::Admission::Backoff
        );
        assert!(!daemon.watcher.tracker().is_tracked_with_pipes(pid));
    }
    #[test]
    fn stale_rebind_completion_cannot_change_newer_recovery_budget_or_status() {
        const PROCESS: &str = "com.qinggan.app.setting.test_stale_rebind_completion_cannot_change_newer_recovery_budget_or_status";
        let (mut daemon, plan, context) = fixture(PROCESS);
        let pid = context.retry.pid;
        let old = daemon
            .resident_identity(&plan, PROCESS, pid, context.authority.starttime)
            .unwrap();
        let mut newer = old.clone();
        newer.starttime += 1;
        let mut recovery = crate::resident_recovery::Recovery::new(newer);
        for _ in 0..3 {
            recovery.attempted();
        }
        daemon.resident_recovery.insert(PROCESS.into(), recovery);
        let before = daemon.status.serialize();
        let rebind = RebindContext {
            recovery_identity: Some(old),
            process: PROCESS.into(),
            authority: context.authority,
            generations: vec![context.retry.generation],
            authorized_generations: Default::default(),
            started: std::time::Instant::now(),
        };
        daemon.collect_rebind_outcome(
            &plan,
            rebind,
            RebindOutcome {
                result: injector::InjectResult::InitFailed,
                record: None,
                downlink: None,
                identity: None,
            },
            Some(123),
        );
        assert_eq!(daemon.status.serialize(), before);
        assert_eq!(
            daemon.resident_recovery[PROCESS].admit(std::time::Duration::from_secs(100)),
            crate::resident_recovery::Admission::Exhausted
        );
        assert!(daemon.injection_jobs.is_empty());
    }
    #[test]
    fn stale_successful_rebind_closes_endpoints_without_adopting_or_resetting_budget() {
        const PROCESS: &str = "com.qinggan.app.setting.test_stale_successful_rebind_closes_endpoints_without_adopting_or_resetting_budget";
        let (mut daemon, plan, context) = fixture(PROCESS);
        let pid = context.retry.pid;
        let old = daemon
            .resident_identity(&plan, PROCESS, pid, context.authority.starttime)
            .unwrap();
        let mut newer = old.clone();
        newer.starttime += 1;
        let mut recovery = crate::resident_recovery::Recovery::new(newer);
        for _ in 0..3 {
            recovery.attempted();
        }
        daemon.resident_recovery.insert(PROCESS.into(), recovery);
        let before = daemon.status.serialize();
        let before_desired = daemon.desired_documents[PROCESS].semantic_document.clone();
        let before_revision = daemon.desired_documents[PROCESS].generation;
        let (transport, mut log_peer, mut downlink_peer) = pipes(injector::InjectResult::Ok);
        let rebind = RebindContext {
            recovery_identity: Some(old),
            process: PROCESS.into(),
            authority: context.authority,
            generations: vec![context.retry.generation],
            authorized_generations: Default::default(),
            started: std::time::Instant::now(),
        };
        daemon.collect_rebind_outcome(
            &plan,
            rebind,
            RebindOutcome {
                result: injector::InjectResult::Rebound,
                record: transport.record,
                downlink: transport.downlink,
                identity: Some(injector::ResidentIdentity {
                    generation_id: "a".repeat(64),
                    catalog_sha256: "b".repeat(64),
                    settings_loaded: false,
                    document_generation: Some(1),
                }),
            },
            Some(123),
        );
        assert_eq!(daemon.status.serialize(), before);
        assert_eq!(
            daemon.resident_recovery[PROCESS].admit(std::time::Duration::from_secs(100)),
            crate::resident_recovery::Admission::Exhausted
        );
        assert!(daemon.injection_jobs.is_empty());
        assert!(!daemon.watcher.tracker().is_tracked_with_pipes(pid));
        assert_eq!(
            daemon.desired_documents[PROCESS].semantic_document,
            before_desired
        );
        assert_eq!(
            daemon.desired_documents[PROCESS].generation,
            before_revision
        );
        assert_peer_closed(&mut log_peer);
        assert_peer_closed(&mut downlink_peer);
    }
    #[test]
    fn recovery_reset_requires_current_accepted_ready_receipt_and_preserves_stale_or_waiting() {
        const PROCESS: &str = "com.qinggan.app.setting.test_recovery_reset_requires_current_accepted_ready_receipt_and_preserves_stale_or_waiting";
        let (mut daemon, plan, context) = fixture(PROCESS);
        let pid = context.retry.pid;
        let starttime = context.authority.starttime;
        let (outcome, _log_peer, _state_peer) = pipes(injector::InjectResult::Ok);
        daemon.adopt_injection(context, outcome, &plan, true);
        let identity = daemon
            .resident_identity(&plan, PROCESS, pid, starttime)
            .unwrap();
        let mut recovery = crate::resident_recovery::Recovery::new(identity.clone());
        for _ in 0..3 {
            recovery.attempted();
        }
        daemon.resident_recovery.insert(PROCESS.into(), recovery);
        daemon.clear_ready_recovery(&plan, PROCESS, pid, Some(starttime));
        assert!(
            daemon.resident_recovery.contains_key(PROCESS),
            "pipe adoption alone is not readiness"
        );
        let document = &daemon.desired_documents[PROCESS];
        let revision = document.generation;
        let ids = document.ids.clone();
        let resident = document
            .resident_generation
            .as_ref()
            .unwrap_or(&daemon.generation)
            .clone();
        let epoch = daemon.watcher.tracker().status_epoch(pid, PROCESS).unwrap();
        let binding =
            control_plane::endpoint_binding(&daemon.endpoint_context(pid, PROCESS, epoch)).unwrap();
        let receipt = status::AcceptanceReceipt {
            sequence: "1".into(),
            daemon_pid: "9000".into(),
            daemon_starttime: "100".into(),
            boot_id: "11111111-1111-1111-1111-111111111111".into(),
        };
        let status_bytes = |state: &str, rev: i64| {
            serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"process":PROCESS,"generationId":resident.id,"catalogSha256":resident.catalog_sha256,"documentGeneration":rev,"agents":ids.iter().map(|id| serde_json::json!({"id":id,"lifecycleGeneration":1,"state":state,"reason":if state == "active" {"ready"} else {"pending"},"details":{}})).collect::<Vec<_>>() })).unwrap()
        };
        let waiting = status_bytes("waiting", revision);
        assert!(control_plane::accept_agent_status_with_receipt(
            PROCESS,
            &waiting,
            binding.clone(),
            Some(receipt.clone())
        ));
        daemon.clear_ready_recovery(&plan, PROCESS, pid, Some(starttime));
        assert!(daemon.resident_recovery.contains_key(PROCESS));
        let ready = status_bytes("active", revision);
        assert!(control_plane::accept_agent_status_with_receipt(
            PROCESS,
            &ready,
            binding.clone(),
            None
        ));
        daemon.clear_ready_recovery(&plan, PROCESS, pid, Some(starttime));
        assert!(
            daemon.resident_recovery.contains_key(PROCESS),
            "unreceipted status cannot reset budget"
        );
        let mut wrong_epoch = binding.clone();
        wrong_epoch.endpoint_epoch = (epoch + 1).to_string();
        assert!(control_plane::accept_agent_status_with_receipt(
            PROCESS,
            &ready,
            wrong_epoch,
            Some(receipt.clone())
        ));
        daemon.clear_ready_recovery(&plan, PROCESS, pid, Some(starttime));
        assert!(
            daemon.resident_recovery.contains_key(PROCESS),
            "stale endpoint cannot reset budget"
        );
        assert!(control_plane::accept_agent_status_with_receipt(
            PROCESS,
            &ready,
            binding.clone(),
            Some(receipt.clone())
        ));
        daemon.clear_ready_recovery(&plan, PROCESS, pid, Some(starttime + 1));
        assert!(
            daemon.resident_recovery.contains_key(PROCESS),
            "reused PID cannot reset budget"
        );
        daemon.clear_ready_recovery(&plan, PROCESS, pid, Some(starttime));
        assert!(
            !daemon.resident_recovery.contains_key(PROCESS),
            "current accepted ready receipt resets budget"
        );
        // Healthy process can recover repeatedly; three successful recovery cycles do not exhaust it.
        for _ in 0..4 {
            let mut recovery = crate::resident_recovery::Recovery::new(identity.clone());
            recovery.attempted();
            daemon.resident_recovery.insert(PROCESS.into(), recovery);
            daemon.clear_ready_recovery(&plan, PROCESS, pid, Some(starttime));
            assert!(!daemon.resident_recovery.contains_key(PROCESS));
        }
        control_plane::forget_agent_status(PROCESS);
        daemon.watcher.tracker_mut().clear(pid);
    }
    #[test]
    fn retiring_state_requires_prior_ack_and_reenable_revokes_old_tuple() {
        const PROCESS: &str = "com.qinggan.app.setting.test_retiring_state_requires_prior_ack_and_reenable_revokes_old_tuple";
        let (mut daemon, mut plan, mut context) = fixture(PROCESS);
        let pid = context.retry.pid;
        let source = "vehicle-drive-forced-ev";
        let old = daemon.generation.catalog.agents[0].id.clone();
        daemon.generation.catalog.agents[0].id = source.into();
        daemon.generation.catalog.agents[0].kind = Some("executor".into());
        for entry in &mut plan.entries {
            if entry.id == old {
                entry.id = source.into();
                entry.enabled = true;
            }
        }
        daemon.write_fresh_desired_document(&plan, PROCESS).unwrap();
        let document = &daemon.desired_documents[PROCESS];
        context.retry.generation = daemon.generation.clone();
        context.retry.agent_ids = document.ids.clone();
        context.retry.desired_semantics = document.semantic_document.clone();
        context.retry.document_generation = document.generation;
        let (outcome, _log_peer, _state_peer) = pipes(injector::InjectResult::Ok);
        daemon.adopt_injection(context, outcome, &plan, true);
        let epoch = daemon.watcher.tracker().status_epoch(pid, PROCESS).unwrap();
        let ctx = daemon.endpoint_context(pid, PROCESS, epoch);
        let binding = control_plane::endpoint_binding(&ctx).unwrap();
        let document = serde_json::to_vec(&serde_json::json!({
            "schemaVersion":1,"process":PROCESS,"generationId":ctx.resident_generation_id,
            "catalogSha256":ctx.resident_catalog_sha256,"documentGeneration":ctx.document_generation.unwrap(),
            "agents":[{"id":source,"lifecycleGeneration":1,"state":"active","reason":"ready","details":{}}]
        })).unwrap();
        assert!(control_plane::accept_agent_status_with_receipt(
            PROCESS,
            &document,
            binding,
            Some(status::AcceptanceReceipt {
                sequence: "1".into(),
                daemon_pid: "9000".into(),
                daemon_starttime: "100".into(),
                boot_id: "11111111-1111-1111-1111-111111111111".into()
            })
        ));
        for entry in &mut plan.entries {
            entry.enabled = false;
        }
        daemon
            .write_desired_document_for(&plan, PROCESS, daemon.generation.clone(), false, vec![])
            .unwrap();
        let retiring = daemon.endpoint_context(pid, PROCESS, epoch);
        assert!(!retiring.owns_agent(source));
        assert!(retiring.owns_state(
            source,
            "forced-ev-lifecycle-active",
            Some(&serde_json::json!(false))
        ));
        assert!(!retiring.owns_state(source, "forced-ev-armed", Some(&serde_json::json!(true))));
        assert!(
            !daemon.endpoint_context(pid, PROCESS, epoch + 1).owns_state(
                source,
                "forced-ev-lifecycle-active",
                None
            )
        );
        for entry in &mut plan.entries {
            entry.enabled = true;
        }
        daemon
            .write_desired_document_for(&plan, PROCESS, daemon.generation.clone(), false, vec![])
            .unwrap();
        assert!(!retiring.owns_state(source, "forced-ev-lifecycle-active", None));
        assert!(daemon.desired_documents[PROCESS].retiring_state.is_none());
        // Re-disable before any acknowledgement of the new lifecycle: no grant.
        for entry in &mut plan.entries {
            entry.enabled = false;
        }
        daemon
            .write_desired_document_for(&plan, PROCESS, daemon.generation.clone(), false, vec![])
            .unwrap();
        assert!(daemon.desired_documents[PROCESS].retiring_state.is_none());
        control_plane::forget_agent_status(PROCESS);
    }

    #[test]
    fn disabled_mapped_target_preserves_pending_cleanup_and_ends_only_after_current_empty_ack() {
        const PROCESS: &str = "com.qinggan.app.setting.test_disabled_mapped_target_preserves_pending_cleanup_and_ends_only_after_current_empty_ack";
        for executor in [false, true] {
            let (mut daemon, mut plan, mut context) = fixture(PROCESS);
            let pid = context.retry.pid;
            let starttime = context.authority.starttime;
            // Host lifecycle fixture: ordinary hook vs executor share the same transport path.
            let old = daemon.generation.catalog.agents[0].id.clone();
            daemon.generation.catalog.agents[0].id = "font-cyrillic".into();
            daemon.generation.catalog.agents[0].kind = executor.then(|| "executor".into());
            for entry in &mut plan.entries {
                if entry.id == old {
                    entry.id = "font-cyrillic".into();
                    entry.enabled = true;
                }
            }
            daemon.write_fresh_desired_document(&plan, PROCESS).unwrap();
            let document = &daemon.desired_documents[PROCESS];
            context.retry.generation = daemon.generation.clone();
            context.retry.agent_ids = document.ids.clone();
            context.retry.desired_semantics = document.semantic_document.clone();
            context.retry.document_generation = document.generation;
            let (outcome, _log_peer, _state_peer) = pipes(injector::InjectResult::Ok);
            daemon.adopt_injection(context, outcome, &plan, true);
            for entry in &mut plan.entries {
                entry.enabled = false;
            }
            daemon
                .write_desired_document_for(
                    &plan,
                    PROCESS,
                    daemon.generation.clone(),
                    false,
                    vec![],
                )
                .unwrap();
            assert!(daemon.desired_documents[PROCESS].ids.is_empty());
            let identity = daemon
                .resident_identity(&plan, PROCESS, pid, starttime)
                .unwrap();
            let mut recovery = crate::resident_recovery::Recovery::new(identity);
            recovery.attempted();
            daemon.resident_recovery.insert(PROCESS.into(), recovery);
            daemon.clear_ready_recovery(&plan, PROCESS, pid, Some(starttime));
            assert!(
                daemon.resident_recovery.contains_key(PROCESS),
                "possible prior hooks need bounded cleanup even when disabled"
            );
            assert_eq!(
                target_action(true, false),
                TargetAction::TrackExistingImplant
            );
            let revision = daemon.desired_documents[PROCESS].generation;
            let epoch = daemon.watcher.tracker().status_epoch(pid, PROCESS).unwrap();
            let binding =
                control_plane::endpoint_binding(&daemon.endpoint_context(pid, PROCESS, epoch))
                    .unwrap();
            let receipt = status::AcceptanceReceipt {
                sequence: "1".into(),
                daemon_pid: "9000".into(),
                daemon_starttime: "100".into(),
                boot_id: "11111111-1111-1111-1111-111111111111".into(),
            };
            let empty = |revision: i64| {
                serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"process":PROCESS,"generationId":daemon.generation.id,"catalogSha256":daemon.generation.catalog_sha256,"documentGeneration":revision,"agents":[]})).unwrap()
            };
            let mut stale = binding.clone();
            stale.desired_document_generation = (revision - 1).to_string();
            assert!(control_plane::accept_agent_status_with_receipt(
                PROCESS,
                &empty(revision - 1),
                stale,
                Some(receipt.clone())
            ));
            daemon.clear_ready_recovery(&plan, PROCESS, pid, Some(starttime));
            assert!(
                daemon.resident_recovery.contains_key(PROCESS),
                "stale empty ack must not release cleanup"
            );
            let current = serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"process":PROCESS,"generationId":daemon.generation.id,"catalogSha256":daemon.generation.catalog_sha256,"documentGeneration":revision,"agents":[]})).unwrap();
            assert!(control_plane::accept_agent_status_with_receipt(
                PROCESS,
                &current,
                binding,
                Some(receipt)
            ));
            daemon.clear_ready_recovery(&plan, PROCESS, pid, Some(starttime));
            assert!(
                !daemon.resident_recovery.contains_key(PROCESS),
                "verified empty desired receipt ends recovery"
            );
            daemon.inject_new_targets(&[(PROCESS.into(), pid)], &plan, &None, true);
            assert!(
                !daemon.resident_recovery.contains_key(PROCESS),
                "mapped quiescent target must not create a new budget"
            );
            assert!(daemon.injection_jobs.is_empty());
            assert!(daemon.rebind_jobs.is_empty());
            control_plane::forget_agent_status(PROCESS);
            daemon.watcher.tracker_mut().clear(pid);
        }
    }
    #[test]
    fn retained_old_resident_ready_resets_only_current_global_budget_with_owned_endpoint_proof() {
        const PROCESS: &str = "com.qinggan.app.setting.test_retained_old_resident_ready_resets_only_current_global_budget_with_owned_endpoint_proof";
        let (mut daemon, plan, context) = fixture(PROCESS);
        let pid = context.retry.pid;
        let starttime = context.authority.starttime;
        let old = daemon.generation.clone();
        let (outcome, _log_peer, _state_peer) = pipes(injector::InjectResult::Ok);
        daemon.adopt_injection(context, outcome, &plan, true);
        let revision = daemon.desired_documents[PROCESS].generation;
        let ids = daemon.desired_documents[PROCESS].ids.clone();
        let epoch = daemon.watcher.tracker().status_epoch(pid, PROCESS).unwrap();
        let owned =
            control_plane::endpoint_binding(&daemon.endpoint_context(pid, PROCESS, epoch)).unwrap();
        let receipt = status::AcceptanceReceipt {
            sequence: "1".into(),
            daemon_pid: "9000".into(),
            daemon_starttime: "100".into(),
            boot_id: "11111111-1111-1111-1111-111111111111".into(),
        };
        let ready = serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"process":PROCESS,"generationId":old.id,"catalogSha256":old.catalog_sha256,"documentGeneration":revision,"agents":ids.iter().map(|id|serde_json::json!({"id":id,"lifecycleGeneration":1,"state":"active","reason":"ready","details":{}})).collect::<Vec<_>>() })).unwrap();
        let old_budget = daemon
            .resident_identity(&plan, PROCESS, pid, starttime)
            .unwrap();
        daemon.generation = generation::test_support::verified_variant(2);
        assert_ne!(old.id, daemon.generation.id);
        let current_budget = daemon
            .resident_identity(&plan, PROCESS, pid, starttime)
            .unwrap();
        let mut budget = crate::resident_recovery::Recovery::new(old_budget);
        for _ in 0..3 {
            budget.attempted();
        }
        daemon.resident_recovery.insert(PROCESS.into(), budget);
        assert!(control_plane::accept_agent_status_with_receipt(
            PROCESS,
            &ready,
            owned.clone(),
            Some(receipt.clone())
        ));
        daemon.clear_ready_recovery(&plan, PROCESS, pid, Some(starttime));
        assert!(
            daemon.resident_recovery.contains_key(PROCESS),
            "changed global authority cannot reset an old request budget"
        );
        let mut budget = crate::resident_recovery::Recovery::new(current_budget.clone());
        for _ in 0..3 {
            budget.attempted();
        }
        daemon.resident_recovery.insert(PROCESS.into(), budget);
        let mut forged = owned.clone();
        forged.generation_id = "c".repeat(64);
        forged.catalog_sha256 = "d".repeat(64);
        let mut forged_document: serde_json::Value = serde_json::from_slice(&ready).unwrap();
        forged_document["generationId"] = forged.generation_id.clone().into();
        forged_document["catalogSha256"] = forged.catalog_sha256.clone().into();
        assert!(control_plane::accept_agent_status_with_receipt(
            PROCESS,
            &serde_json::to_vec(&forged_document).unwrap(),
            forged,
            Some(receipt.clone())
        ));
        daemon.clear_ready_recovery(&plan, PROCESS, pid, Some(starttime));
        assert!(
            daemon.resident_recovery.contains_key(PROCESS),
            "untrusted old generation cannot replace owned endpoint provenance"
        );
        assert!(control_plane::accept_agent_status_with_receipt(
            PROCESS,
            &serde_json::to_vec(&forged_document).unwrap(),
            owned.clone(),
            Some(receipt.clone())
        ));
        assert!(
            !control_plane::recovery_ready(
                PROCESS,
                &owned,
                revision,
                &"c".repeat(64),
                &"d".repeat(64),
                &ids
            ),
            "body generation cannot override trusted endpoint generation"
        );
        let mut stale = owned.clone();
        stale.desired_document_generation = (revision - 1).to_string();
        let mut stale_document: serde_json::Value = serde_json::from_slice(&ready).unwrap();
        stale_document["documentGeneration"] = (revision - 1).into();
        assert!(control_plane::accept_agent_status_with_receipt(
            PROCESS,
            &serde_json::to_vec(&stale_document).unwrap(),
            stale,
            Some(receipt.clone())
        ));
        daemon.clear_ready_recovery(&plan, PROCESS, pid, Some(starttime));
        assert!(
            daemon.resident_recovery.contains_key(PROCESS),
            "stale old-generation revision cannot reset current recovery"
        );
        assert!(control_plane::accept_agent_status_with_receipt(
            PROCESS,
            &ready,
            owned,
            Some(receipt)
        ));
        daemon.clear_ready_recovery(&plan, PROCESS, pid, Some(starttime));
        assert!(
            !daemon.resident_recovery.contains_key(PROCESS),
            "verified owned retained generation may complete current transport recovery"
        );
        control_plane::forget_agent_status(PROCESS);
        daemon.watcher.tracker_mut().clear(pid);
    }
}
