//! Injection observations serialized for publication by the resident owner.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
#[cfg(test)]
use std::fs;
#[cfg(test)]
use std::io::Write;
#[cfg(test)]
use std::os::unix::fs::MetadataExt;
#[cfg(test)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::config;
use crate::log;
#[cfg(test)]
use crate::secure_fs::set_owner;
#[cfg(test)]
use crate::secure_fs::Directory;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InjectionState {
    Active,
    Failed,
    SkippedCoexist,
    Waiting,
    Quarantined,
    Degraded,
}

impl InjectionState {
    fn label(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Failed => "failed",
            Self::SkippedCoexist => "skipped-coexist",
            Self::Quarantined => "quarantined",
            Self::Degraded => "degraded",
            Self::Waiting => "waiting",
        }
    }
}

#[derive(Debug, Clone)]
pub struct InjectionStatus {
    pub id: String,
    pub process: String,
    pub state: InjectionState,
    pub reason: String,
    pub details: Value,
    pub document_generation: Option<i64>,
    pub lifecycle_generation: Option<i64>,
    pub current_endpoint: Option<EndpointBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointBinding {
    pub target_pid: String,
    pub target_starttime: String,
    pub endpoint_epoch: String,
    pub generation_id: String,
    pub catalog_sha256: String,
    pub desired_document_generation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_status: Option<AcceptedStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptedStatus {
    pub document_generation: String,
    pub receipt: AcceptanceReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptanceReceipt {
    pub sequence: String,
    pub daemon_pid: String,
    pub daemon_starttime: String,
    pub boot_id: String,
}

impl EndpointBinding {
    pub(crate) fn valid_for_document(&self, document_generation: Option<i64>) -> bool {
        fn decimal(value: &str, min: u64, max: u64) -> bool {
            value
                .parse::<u64>()
                .is_ok_and(|number| number >= min && number <= max && number.to_string() == value)
        }
        let digest = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if !decimal(&self.target_pid, 2, i32::MAX as u64)
            || !decimal(&self.target_starttime, 1, u64::MAX)
            || !decimal(&self.endpoint_epoch, 1, u64::MAX)
            || !digest(&self.generation_id)
            || !digest(&self.catalog_sha256)
            || !decimal(
                &self.desired_document_generation,
                0,
                crate::control_plane::MAX_DOCUMENT_GENERATION as u64,
            )
            || document_generation
                .map(|value| value.to_string())
                .as_deref()
                != Some(self.desired_document_generation.as_str())
        {
            return false;
        }
        self.accepted_status.as_ref().is_none_or(|accepted| {
            let receipt = &accepted.receipt;
            accepted.document_generation == self.desired_document_generation
                && decimal(&receipt.sequence, 1, u64::MAX)
                && decimal(&receipt.daemon_pid, 2, i32::MAX as u64)
                && decimal(&receipt.daemon_starttime, 1, u64::MAX)
                && receipt.boot_id.len() == 36
                && receipt.boot_id.bytes().enumerate().all(|(index, byte)| {
                    if [8, 13, 18, 23].contains(&index) {
                        byte == b'-'
                    } else {
                        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                    }
                })
        })
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UnsafeNativeFailure {
    pub process: String,
    pub target_pid: i32,
    pub target_starttime: u64,
    pub generation_id: String,
    pub catalog_sha256: String,
    pub document_generation: i64,
    pub diagnostic: crate::injector::NativeFailure,
}

pub(crate) const STATUS_LIMIT: usize = voboost_contract::runtime_owner::MAX_STATUS_BYTES;
const PASSIVE_STATUS_LIMIT: usize = 32 * 1024;
pub(crate) const PROCESS_TRACE_LIMIT: usize = 8192;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProcessTrace {
    identity_scope: ChildScope,
    dropped: String,
    overwritten: String,
    omitted: usize,
    records: Vec<ProcessRecord>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
enum ChildScope {
    #[serde(rename = "direct-child")]
    DirectChild,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProcessRecord {
    operation_id: String,
    program: String,
    operation: String,
    parent_pid: u32,
    child_pid: u32,
    monotonic_ns: Option<String>,
    elapsed_ms: String,
    outcome: ProcessOutcome,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum ProcessOutcome {
    Started,
    Exit(i32),
    Signal(i32),
    Timeout,
    Error,
}

fn decimal(value: &str) -> bool {
    value.parse::<u64>().is_ok_and(|n| n.to_string() == value)
}

impl ProcessTrace {
    fn from_snapshot(snapshot: crate::fixed_process::ObservationSnapshot) -> Self {
        use crate::fixed_process::Outcome;
        Self {
            identity_scope: ChildScope::DirectChild,
            dropped: snapshot.dropped.to_string(),
            overwritten: snapshot.overwritten.to_string(),
            omitted: 0,
            records: snapshot
                .records
                .into_iter()
                .flatten()
                .map(|record| ProcessRecord {
                    operation_id: record.operation_id.to_string(),
                    program: record.operation.program().into(),
                    operation: record.operation.name().into(),
                    parent_pid: record.parent_pid,
                    child_pid: record.child_pid,
                    monotonic_ns: record.monotonic_ns.map(|n| n.to_string()),
                    elapsed_ms: record.elapsed_ms.to_string(),
                    outcome: match record.outcome {
                        Outcome::Started => ProcessOutcome::Started,
                        Outcome::Exit(n) => ProcessOutcome::Exit(n),
                        Outcome::Signal(n) => ProcessOutcome::Signal(n),
                        Outcome::Timeout => ProcessOutcome::Timeout,
                        Outcome::Error => ProcessOutcome::Error,
                    },
                })
                .collect(),
        }
    }

    fn fit(mut self, budget: usize) -> Option<Self> {
        if budget == 0 {
            return None;
        }
        let mut records = std::mem::take(&mut self.records);
        let lengths = records
            .iter()
            .map(|record| serde_json::to_vec(record).ok().map(|v| v.len()))
            .collect::<Option<Vec<_>>>()?;
        let metadata = serde_json::to_vec(&self).ok()?.len();
        let digits = |n: usize| {
            if n < 10 {
                1
            } else if n < 100 {
                2
            } else {
                3
            }
        };
        let mut bytes: usize = lengths.iter().sum();
        let mut skip = 0;
        loop {
            let remaining = records.len() - skip;
            let size = metadata + digits(self.omitted + skip) - digits(self.omitted)
                + bytes
                + remaining.saturating_sub(1);
            if size <= budget {
                records.drain(..skip);
                self.records = records;
                self.omitted += skip;
                return Some(self);
            }
            bytes = bytes.checked_sub(*lengths.get(skip)?)?;
            skip += 1;
        }
    }

    pub(crate) fn valid(&self) -> bool {
        decimal(&self.dropped)
            && decimal(&self.overwritten)
            && self.omitted <= 128
            && self.records.len() + self.omitted <= 128
            && serde_json::to_vec(self).is_ok_and(|bytes| bytes.len() <= PROCESS_TRACE_LIMIT)
            && self.records.iter().all(|record| {
                crate::fixed_process::known_operation(&record.program, &record.operation)
                    && decimal(&record.operation_id)
                    && record.operation_id != "0"
                    && record.parent_pid > 0
                    && record.child_pid > 1
                    && record.monotonic_ns.as_deref().is_none_or(decimal)
                    && record
                        .elapsed_ms
                        .parse::<u128>()
                        .is_ok_and(|n| n.to_string() == record.elapsed_ms)
                    && match record.outcome {
                        ProcessOutcome::Exit(n) => (0..=255).contains(&n),
                        ProcessOutcome::Signal(n) => (1..=128).contains(&n),
                        _ => true,
                    }
            })
    }
}

/// Historical status provenance is exported without claiming current-boot freshness.
/// Read a bounded diagnostic projection of the resident's retained publication.
/// This exporter is a separate process: it never samples or rewrites agent state.
fn project_vehicle_diagnostics(status: &Value) -> Value {
    const LIMIT: usize = 24 * 1024;
    fn unavailable(reason: &str) -> Value {
        serde_json::json!({"availability": "unavailable", "reason": reason})
    }
    fn token(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c))
    }
    fn closed_values(value: &Value) -> bool {
        match value {
            Value::Null | Value::Bool(_) | Value::Number(_) => true,
            Value::String(text) => token(text),
            Value::Array(values) => values.len() <= 128 && values.iter().all(closed_values),
            Value::Object(values) => values.values().all(closed_values),
        }
    }
    let mut result = serde_json::json!({
        "availability": "retained-publication",
        "persistentVehicleState": unavailable("missing-or-invalid"),
        "startupMilestones": unavailable("missing-or-invalid"),
        "injections": unavailable("missing-or-invalid")
    });
    let publisher = status
        .get("publisher")
        .cloned()
        .and_then(|value| serde_json::from_value::<PublisherIdentity>(value).ok());
    let Some(publisher) = publisher.filter(|publisher| {
        publisher.boot_id.len() == 36
            && publisher.boot_id.bytes().enumerate().all(|(i, c)| {
                if [8, 13, 18, 23].contains(&i) {
                    c == b'-'
                } else {
                    c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
                }
            })
            && decimal(&publisher.daemon_pid)
            && publisher.daemon_pid != "0"
            && decimal(&publisher.daemon_starttime)
            && publisher.daemon_starttime != "0"
            && decimal(&publisher.published_at_boot_ms)
    }) else {
        return unavailable("publisher-unavailable");
    };
    result["publisher"] = serde_json::to_value(publisher).unwrap_or(Value::Null);
    if let Some(value) = status.get("persistentVehicleState") {
        if let Ok(flags) =
            serde_json::from_value::<crate::agent_state::PersistentVehicleState>(value.clone())
        {
            let value = serde_json::to_value(flags).unwrap_or(Value::Null);
            if closed_values(&value) {
                result["persistentVehicleState"] = value;
            }
        }
    }
    if let Some(value) = status.get("startupMilestones") {
        if let Ok(milestones) = serde_json::from_value::<crate::startup::Milestones>(value.clone())
        {
            let mut value = serde_json::to_value(milestones).unwrap_or(Value::Null);
            // The arbitrary free-form diagnostic reason is not an export field.
            if let Some(object) = value.as_object_mut() {
                object.remove("reason");
            }
            if closed_values(&value) {
                result["startupMilestones"] = value;
            }
        }
    }
    #[derive(Deserialize, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Injection {
        id: String,
        process: String,
        state: String,
        #[serde(default)]
        reason: String,
        document_generation: Option<i64>,
        lifecycle_generation: Option<i64>,
    }
    if let Some(value) = status.get("injections") {
        if let Ok(injections) = serde_json::from_value::<Vec<Injection>>(value.clone()) {
            if injections.len() <= 128
                && injections.iter().all(|item| {
                    token(&item.id)
                        && token(&item.process)
                        && matches!(
                            item.state.as_str(),
                            "active"
                                | "failed"
                                | "skipped-coexist"
                                | "waiting"
                                | "quarantined"
                                | "degraded"
                        )
                })
            {
                let projections: Vec<_> = injections
                    .into_iter()
                    .map(|mut item| {
                        if !token(&item.reason) {
                            item.reason = "unavailable".into();
                        }
                        item
                    })
                    .collect();
                result["injections"] = serde_json::to_value(projections).unwrap_or(Value::Null);
            }
        }
    }
    if serde_json::to_vec(&result).is_ok_and(|bytes| bytes.len() <= LIMIT) {
        result
    } else {
        unavailable("projection-exceeds-bound")
    }
}

fn project_process_trace(status: &Value) -> Option<Value> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Publication {
        publisher: PublisherIdentity,
        manifest_sha256: String,
        process_trace: ProcessTrace,
    }
    let publication: Publication = serde_json::from_value(status.clone()).ok()?;
    let publisher = &publication.publisher;
    let hex = |value: &str| {
        value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    };
    if !publication.process_trace.valid()
        || publication.manifest_sha256.len() != 64
        || !hex(&publication.manifest_sha256)
        || publisher.boot_id.len() != 36
        || publisher.boot_id.bytes().enumerate().any(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c != b'-'
            } else {
                !c.is_ascii_digit() && !(b'a'..=b'f').contains(&c)
            }
        })
        || !decimal(&publisher.daemon_pid)
        || publisher.daemon_pid == "0"
        || !decimal(&publisher.daemon_starttime)
        || publisher.daemon_starttime == "0"
        || !decimal(&publisher.published_at_boot_ms)
        || publication
            .process_trace
            .records
            .iter()
            .any(|record| record.parent_pid.to_string() != publisher.daemon_pid)
    {
        return None;
    }
    Some(serde_json::json!({
        "proof": "retained-publication",
        "publisher": publication.publisher,
        "manifestSha256": publication.manifest_sha256,
        "trace": publication.process_trace,
    }))
}

#[cfg(test)]
fn retained_status(root: &Path) -> Option<Value> {
    let directory = Directory::open(root).ok()?;
    directory
        .validate_owner_mode(
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o755,
        )
        .ok()?;
    let bytes = directory
        .read_trusted("status.json", STATUS_LIMIT, 0o644)
        .ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    (value.get("schemaVersion")?.as_u64()? == 1).then_some(value)
}
#[cfg(test)]
pub(crate) fn vehicle_diagnostics_export(root: &Path) -> Value {
    retained_status(root).map(|value| project_vehicle_diagnostics(&value)).unwrap_or_else(|| serde_json::json!({"availability":"unavailable","reason":"retained-status-unavailable"}))
}
#[cfg(test)]
pub(crate) fn process_trace_export(root: &Path) -> Option<Value> {
    project_process_trace(&retained_status(root)?)
}
/// Attach the retained log context without pushing the publication past the
/// passive observer's 32 KiB read envelope. The base status is budgeted by
/// `serialize_with_trace_and_cluster`, but the context is composed afterwards,
/// so this is the only place that can enforce the combined bound. Dropping the
/// context is never silent: the identity fields stay, and the projected
/// diagnostics degrade to an explicit unavailable reason — the same pattern the
/// cluster envelope already uses for `passive-budget-exceeded`.
fn attach_log_context(prefix: &str, context: &Value) -> String {
    let render = |context: &Value| format!("{prefix},\"logContext\":{context}}}\n");
    let full = render(context);
    if full.len() <= PASSIVE_STATUS_LIMIT {
        return full;
    }
    let mut degraded = context.clone();
    if let Some(object) = degraded.as_object_mut() {
        object.insert(
            "vehicleDiagnostics".into(),
            serde_json::json!({
                "availability": "unavailable",
                "reason": "passive-budget-exceeded",
            }),
        );
    }
    let degraded = render(&degraded);
    if degraded.len() <= PASSIVE_STATUS_LIMIT {
        return degraded;
    }
    // Even the identity-only context cannot fit: publish the base status
    // alone. The retained log reader already treats a missing context as
    // unavailable rather than an error.
    format!("{prefix}}}\n")
}

fn diagnostic_context(status: &Value) -> Value {
    let mut context = serde_json::json!({"schemaVersion":1,"releaseIdentity":status.get("releaseIdentity"),"manifestSha256":status.get("manifestSha256"),"logSource":"root-owned-segments","appPrivateBatchesRead":false,"vehicleDiagnostics":project_vehicle_diagnostics(status)});
    if let Some(trace) = project_process_trace(status) {
        context["processTrace"] = trace;
    }
    context
}

/// Production publisher incarnation. Optional only for legacy wire decoding.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PublisherIdentity {
    boot_id: String,
    daemon_pid: String,
    daemon_starttime: String,
    published_at_boot_ms: String,
}
impl PublisherIdentity {
    fn current() -> Option<Self> {
        let pid = std::process::id();
        Some(Self {
            boot_id: crate::operation_contract::current_boot_id().ok()?,
            daemon_pid: pid.to_string(),
            daemon_starttime: crate::target_identity::read_starttime(pid as i32)
                .ok()?
                .to_string(),
            published_at_boot_ms: crate::agent_state::boot_elapsed_ms()?.to_string(),
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct I18nReadback {
    pub owner: String,
    pub profile: String,
    pub probe_revision: String,
    pub age_ms: u64,
    pub binding: EndpointBinding,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct I18nReadbacks {
    pub schema: u32,
    pub kind: String,
    pub owners: Vec<I18nReadback>,
}
impl I18nReadbacks {
    pub(crate) fn valid(&self, generation: &str, catalog: &str, kind: &str) -> bool {
        use voboost_shared::owned_overlay::{Owner, Variant};
        let mut owners = std::collections::HashSet::new();
        self.schema == 1
            && self.kind == kind
            && self.owners.len() <= Owner::ALL.len()
            && self.owners.iter().all(|row| {
                let owner = Owner::from_process(&row.owner).ok();
                let variant = Variant::from_profile(&row.profile).ok();
                owner.is_some()
                    && variant.map(|v| v.owner()) == owner
                    && owners.insert(&row.owner)
                    && row
                        .probe_revision
                        .parse::<u64>()
                        .is_ok_and(|v| v > 0 && v.to_string() == row.probe_revision)
                    && row.age_ms <= 30000
                    && row.binding.generation_id == generation
                    && row.binding.catalog_sha256 == catalog
                    && row
                        .binding
                        .desired_document_generation
                        .parse::<i64>()
                        .ok()
                        .is_some_and(|doc| row.binding.valid_for_document(Some(doc)))
            })
    }
}

#[derive(Debug, Serialize)]
struct StatusJson<'a> {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    #[serde(rename = "releaseIdentity")]
    release_identity: &'a str,
    #[serde(rename = "manifestSha256")]
    manifest_sha256: &'a str,
    #[serde(rename = "generationId")]
    generation_id: &'a str,
    #[serde(rename = "catalogSha256")]
    catalog_sha256: &'a str,
    #[serde(rename = "startupMode")]
    startup_mode: crate::plan::Startup,
    #[serde(skip_serializing_if = "Option::is_none")]
    publisher: Option<PublisherIdentity>,
    #[serde(
        rename = "lastUnsafeNativeFailure",
        skip_serializing_if = "Option::is_none"
    )]
    last_unsafe_native_failure: &'a Option<UnsafeNativeFailure>,
    #[serde(
        rename = "persistentVehicleState",
        skip_serializing_if = "Option::is_none"
    )]
    persistent_vehicle_state: Option<crate::agent_state::PersistentVehicleState>,
    #[serde(rename = "startupMilestones", skip_serializing_if = "Option::is_none")]
    startup_milestones: Option<crate::startup::Milestones>,
    #[serde(rename = "processTrace", skip_serializing_if = "Option::is_none")]
    process_trace: Option<ProcessTrace>,
    /// Original current native receipt projection, published only by the resident daemon.
    #[serde(skip_serializing_if = "Option::is_none")]
    cluster: Option<voboost_contract::cluster::ClusterSnapshot>,
    #[serde(rename = "clusterUnavailable", skip_serializing_if = "Option::is_none")]
    cluster_unavailable: Option<&'static str>,
    #[serde(
        rename = "i18nResourceReadbacks",
        skip_serializing_if = "Option::is_none"
    )]
    i18n_resource_readbacks: Option<I18nReadbacks>,
    #[serde(
        rename = "i18nCurrentReadbacks",
        skip_serializing_if = "Option::is_none"
    )]
    i18n_current_readbacks: Option<I18nReadbacks>,
    state: &'a str,
    killed: bool,
    panic: bool,
    injections: Vec<InjectionJson<'a>>,
    /// Catalog executors active in this generation: {id, processes, surfaces}.
    executors: Vec<StatusExecutor>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusExecutor {
    pub id: String,
    pub processes: Vec<String>,
    pub surfaces: Vec<String>,
}

#[derive(Debug, Serialize)]
struct InjectionJson<'a> {
    id: &'a str,
    process: &'a str,
    state: &'a str,
    reason: &'a str,
    details: &'a Value,
    #[serde(rename = "documentGeneration", skip_serializing_if = "Option::is_none")]
    document_generation: Option<i64>,
    #[serde(
        rename = "lifecycleGeneration",
        skip_serializing_if = "Option::is_none"
    )]
    lifecycle_generation: Option<i64>,
    #[serde(rename = "currentEndpoint", skip_serializing_if = "Option::is_none")]
    current_endpoint: &'a Option<EndpointBinding>,
}

#[derive(Default)]
struct Publication {
    input: String,
    checked: Option<std::time::Instant>,
    published: Option<String>,
}

impl Publication {
    fn observe(&mut self, input: &str, now: std::time::Instant) -> bool {
        if self.input == input
            && self.checked.is_some_and(|checked| {
                now.saturating_duration_since(checked) < std::time::Duration::from_secs(1)
            })
        {
            return false;
        }
        self.input = input.to_owned();
        self.checked = Some(now);
        true
    }
}

#[cfg(test)]
mod publication_tests {
    use super::*;
    #[test]
    fn unchanged_input_does_not_poll_owner_on_the_fast_loop() {
        let now = std::time::Instant::now();
        let mut publication = Publication::default();
        assert!(publication.observe("ready", now));
        for step in 1..20 {
            assert!(
                !publication.observe("ready", now + std::time::Duration::from_millis(step * 50))
            );
        }
        assert!(publication.observe("ready", now + std::time::Duration::from_secs(1)));
        assert!(publication.observe("removed", now + std::time::Duration::from_millis(1001)));
    }
}

pub struct Status {
    publication: std::cell::RefCell<Publication>,
    pub(crate) startup_milestones: Option<crate::startup::Milestones>,
    pub(crate) startup_vehicle_members: HashSet<(String, String)>,
    pub release_identity: String,
    pub manifest_sha256: String,
    pub daemon_state: String,
    pub(crate) last_unsafe_native_failure: Option<UnsafeNativeFailure>,
    pub generation_id: String,
    pub catalog_sha256: String,
    pub startup_mode: crate::plan::Startup,
    pub kill_switch: bool,
    pub panic_quarantine: bool,
    injections: Vec<InjectionStatus>,
    /// Catalog executors of the active generation (id, processes, surfaces).
    pub executors: Vec<StatusExecutor>,
}

impl Default for Status {
    fn default() -> Self {
        Self {
            publication: Default::default(),
            startup_milestones: None,
            startup_vehicle_members: HashSet::new(),
            release_identity: String::new(),
            manifest_sha256: String::new(),
            daemon_state: "ready".to_string(),
            last_unsafe_native_failure: None,
            generation_id: String::new(),
            catalog_sha256: String::new(),
            startup_mode: crate::plan::Startup::None,
            kill_switch: false,
            panic_quarantine: false,
            injections: Vec::new(),
            executors: Vec::new(),
        }
    }
}

impl Status {
    pub fn set_injection(&mut self, id: &str, process: &str, state: InjectionState) {
        self.set_injection_event(
            id,
            process,
            state,
            "",
            Value::Object(Default::default()),
            None,
            None,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn set_injection_event(
        &mut self,
        id: &str,
        process: &str,
        state: InjectionState,
        reason: &str,
        details: Value,
        document_generation: Option<i64>,
        lifecycle_generation: Option<i64>,
    ) {
        if let Some(slot) = self
            .injections
            .iter_mut()
            .find(|i| i.id == id && i.process == process)
        {
            slot.state = state;
            slot.reason = reason.to_string();
            // Generic waiting/quarantine events must not erase the bounded
            // native failure before an operator can collect diagnostics. A
            // successful current activation explicitly clears the old failure.
            let mut details = details;
            if state != InjectionState::Active {
                if let (Some(previous), Some(next)) =
                    (slot.details.as_object(), details.as_object_mut())
                {
                    if !next.contains_key("nativeFailure") && previous.contains_key("nativeFailure")
                    {
                        for key in ["nativeFailure", "targetPid", "targetStarttime"] {
                            if let Some(value) = previous.get(key) {
                                next.insert(key.into(), value.clone());
                            }
                        }
                    }
                }
            }
            slot.details = details;
            slot.document_generation = document_generation;
            slot.lifecycle_generation = lifecycle_generation;
            slot.current_endpoint = None;
        } else {
            self.injections.push(InjectionStatus {
                id: id.to_string(),
                process: process.to_string(),
                state,
                reason: reason.to_string(),
                details,
                document_generation,
                lifecycle_generation,
                current_endpoint: None,
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn accept_startup_application(
        &mut self,
        id: &str,
        process: &str,
        document: i64,
        lifecycle: i64,
        details: &Value,
        binding: &EndpointBinding,
        received_ms: Option<u64>,
    ) {
        if !self
            .startup_vehicle_members
            .contains(&(id.to_string(), process.to_string()))
        {
            return;
        }
        let Some(tracker) = self.startup_milestones.as_mut() else {
            return;
        };
        if binding.generation_id != tracker.identity.generation_id
            || binding.catalog_sha256 != tracker.identity.catalog_sha256
            || binding.desired_document_generation != document.to_string()
            || binding.accepted_status.is_none()
        {
            return;
        }
        let receipt = &binding.accepted_status.as_ref().unwrap().receipt;
        if receipt.daemon_pid != tracker.identity.daemon_pid.to_string()
            || receipt.daemon_starttime != tracker.identity.daemon_starttime.to_string()
            || receipt.boot_id != tracker.identity.boot_id
        {
            return;
        }
        let Some(index) = tracker.target_index(process) else {
            return;
        };
        let target = &tracker.targets[index];
        if binding.target_pid != target.pid.to_string()
            || binding.target_starttime != target.starttime.to_string()
        {
            return;
        }
        let Some(epoch) = binding.endpoint_epoch.parse::<u64>().ok() else {
            return;
        };
        let member = crate::startup::Member {
            id: id.to_string(),
            target: index,
            document_generation: document,
            lifecycle_generation: lifecycle,
            application: None,
        };
        if !tracker.admit_member(member.clone()) {
            return;
        }
        let Some(clock) = received_ms else {
            return;
        };
        if let Some(application) =
            crate::startup::parse_application(details, document, lifecycle, clock)
        {
            tracker.confirm(&member, epoch, application);
        }
    }

    pub fn set_current_endpoint(&mut self, process: &str, binding: EndpointBinding) {
        for entry in self
            .injections
            .iter_mut()
            .filter(|entry| entry.process == process)
        {
            // A process endpoint only authorizes rows in its current desired document.
            entry.current_endpoint = (entry
                .document_generation
                .map(|value| value.to_string())
                .as_deref()
                == Some(binding.desired_document_generation.as_str()))
            .then(|| binding.clone());
        }
    }

    pub fn ensure_injection(&mut self, id: &str, process: &str, document_generation: Option<i64>) {
        if self
            .injections
            .iter()
            .any(|entry| entry.id == id && entry.process == process)
        {
            return;
        }
        self.set_injection_event(
            id,
            process,
            InjectionState::Waiting,
            "target-waiting",
            Value::Object(Default::default()),
            document_generation,
            None,
        );
    }

    /// A recovered input fence permits waiting for activation, never claims activation itself.
    pub fn clear_owned_input_fence(&mut self, id: &str, process: &str, generation: Option<i64>) {
        if self.injections.iter().any(|entry| {
            entry.id == id
                && entry.process == process
                && entry.state == InjectionState::Quarantined
                && entry.reason == "owned-input-recovery-failed"
        }) {
            self.set_injection_event(
                id,
                process,
                InjectionState::Waiting,
                "target-waiting",
                Value::Object(Default::default()),
                generation,
                None,
            );
        }
    }

    pub fn retain_injections(&mut self, desired: &HashSet<(String, String)>) {
        self.injections
            .retain(|entry| desired.contains(&(entry.id.clone(), entry.process.clone())));
    }

    /// The current injection state recorded for a process (ignoring agent id),
    /// or None if no entry exists. Used by the early-boot retry loop to detect
    /// that a pending target has since been promoted to Active by the
    /// agent-status aggregation, so its retry can stop.
    pub fn injection_state(&self, process: &str) -> Option<InjectionState> {
        let states: Vec<_> = self
            .injections
            .iter()
            .filter(|entry| entry.process == process)
            .map(|entry| entry.state)
            .collect();
        if states.is_empty() {
            return None;
        }
        if states.contains(&InjectionState::Failed) {
            return Some(InjectionState::Failed);
        }
        if states.contains(&InjectionState::Degraded) {
            return Some(InjectionState::Degraded);
        }
        if states.contains(&InjectionState::Quarantined) {
            return Some(InjectionState::Quarantined);
        }
        if states.contains(&InjectionState::SkippedCoexist) {
            return Some(InjectionState::SkippedCoexist);
        }
        if states.iter().all(|state| *state == InjectionState::Active) {
            return Some(InjectionState::Active);
        }
        Some(InjectionState::Waiting)
    }

    #[cfg(test)]
    pub(crate) fn serialize(&self) -> String {
        self.serialize_with_vehicle_state(None)
    }

    #[cfg(test)]
    fn serialize_with_vehicle_state(
        &self,
        persistent_vehicle_state: Option<crate::agent_state::PersistentVehicleState>,
    ) -> String {
        self.serialize_with_provenance(persistent_vehicle_state, None)
    }

    #[cfg(test)]
    fn serialize_with_provenance(
        &self,
        persistent_vehicle_state: Option<crate::agent_state::PersistentVehicleState>,
        publisher: Option<PublisherIdentity>,
    ) -> String {
        let snapshot = publisher
            .as_ref()
            .and_then(|_| crate::fixed_process::snapshot_observations());
        self.serialize_with_trace(
            persistent_vehicle_state,
            publisher,
            snapshot.map(ProcessTrace::from_snapshot),
        )
    }

    #[cfg(test)]
    fn serialize_with_trace(
        &self,
        persistent_vehicle_state: Option<crate::agent_state::PersistentVehicleState>,
        publisher: Option<PublisherIdentity>,
        trace: Option<ProcessTrace>,
    ) -> String {
        self.serialize_with_trace_and_cluster(persistent_vehicle_state, publisher, trace, None)
    }

    fn serialize_with_trace_and_cluster(
        &self,
        persistent_vehicle_state: Option<crate::agent_state::PersistentVehicleState>,
        publisher: Option<PublisherIdentity>,
        trace: Option<ProcessTrace>,
        cluster: Option<voboost_contract::cluster::ClusterSnapshot>,
    ) -> String {
        let injections: Vec<_> = self
            .injections
            .iter()
            .map(|i| InjectionJson {
                id: &i.id,
                process: &i.process,
                state: i.state.label(),
                reason: &i.reason,
                details: &i.details,
                document_generation: i.document_generation,
                lifecycle_generation: i.lifecycle_generation,
                current_endpoint: &i.current_endpoint,
            })
            .collect();
        let mut json = StatusJson {
            schema_version: 1,
            startup_milestones: self.startup_milestones.clone(),
            process_trace: None,
            release_identity: &self.release_identity,
            manifest_sha256: &self.manifest_sha256,
            generation_id: &self.generation_id,
            catalog_sha256: &self.catalog_sha256,
            startup_mode: self.startup_mode,
            persistent_vehicle_state,
            publisher,
            cluster: None,
            cluster_unavailable: None,
            i18n_resource_readbacks: None,
            i18n_current_readbacks: None,
            state: &self.daemon_state,
            last_unsafe_native_failure: &self.last_unsafe_native_failure,
            killed: self.kill_switch,
            panic: self.panic_quarantine,
            injections,
            executors: self.executors.clone(),
        };
        let mut encoded = serde_json::to_string(&json).unwrap_or_else(|_| "{}".to_string());
        // Preserve the full typed native envelope or publish an explicit unavailable
        // reason. Never truncate targets or stretch the passive observer's 32 KiB cap.
        if json.publisher.is_some() {
            match cluster {
                Some(snapshot) if snapshot.validate().is_ok() => json.cluster = Some(snapshot),
                Some(_) => json.cluster_unavailable = Some("snapshot-invalid"),
                None => json.cluster_unavailable = Some("snapshot-unavailable"),
            }
            let candidate = serde_json::to_string(&json).unwrap_or_default();
            if candidate.is_empty() || candidate.len() + 1 > PASSIVE_STATUS_LIMIT {
                json.cluster = None;
                json.cluster_unavailable = Some("passive-budget-exceeded");
                let unavailable = serde_json::to_string(&json).unwrap_or_default();
                if !unavailable.is_empty() && unavailable.len() < PASSIVE_STATUS_LIMIT {
                    encoded = unavailable;
                } else {
                    // A base status already at the envelope limit remains unchanged.
                    // Absence of cluster evidence is unavailable, never a ready receipt.
                    json.cluster_unavailable = None;
                }
            } else {
                encoded = candidate;
            }
        }
        if json.publisher.is_some() {
            let summary = crate::i18n_resources::readback_summaries(
                &self.generation_id,
                &self.catalog_sha256,
                false,
            );
            if summary.valid(
                &self.generation_id,
                &self.catalog_sha256,
                "forced-ru-resource-readback",
            ) {
                json.i18n_resource_readbacks = Some(summary);
                let candidate = serde_json::to_string(&json).unwrap_or_default();
                if candidate.is_empty() || candidate.len() + 1 > PASSIVE_STATUS_LIMIT {
                    json.i18n_resource_readbacks = None;
                } else {
                    encoded = candidate;
                }
            }
        }
        if json.publisher.is_some() {
            let summary = crate::i18n_resources::readback_summaries(
                &self.generation_id,
                &self.catalog_sha256,
                true,
            );
            if [
                "current-owner-resource-readback",
                "current-en-owner-resource-readback",
                "current-zh-owner-resource-readback",
            ]
            .contains(&summary.kind.as_str())
                && summary.valid(&self.generation_id, &self.catalog_sha256, &summary.kind)
            {
                json.i18n_current_readbacks = Some(summary);
                let candidate = serde_json::to_string(&json).unwrap_or_default();
                if candidate.is_empty() || candidate.len() + 1 > PASSIVE_STATUS_LIMIT {
                    json.i18n_current_readbacks = None;
                } else {
                    encoded = candidate;
                }
            }
        }
        // Never push a previously passive-readable publication beyond its existing 32 KiB cap.
        let trace_envelope = if encoded.len() < PASSIVE_STATUS_LIMIT {
            PASSIVE_STATUS_LIMIT
        } else {
            STATUS_LIMIT
        };
        let trace_budget = trace_envelope
            .saturating_sub(encoded.len() + 1 + ",\"processTrace\":".len())
            .min(PROCESS_TRACE_LIMIT);
        json.process_trace = trace.and_then(|trace| trace.fit(trace_budget));
        if json.process_trace.is_some() {
            encoded = serde_json::to_string(&json).unwrap_or_else(|_| "{}".to_string());
        }
        if encoded.len() + 1 > STATUS_LIMIT && json.startup_milestones.is_some() {
            if let Some(startup) = json.startup_milestones.as_mut() {
                startup.complete = false;
                startup.reason = Some("budget-exceeded".to_string());
                startup.targets.clear();
                startup.members.clear();
            }
            encoded = serde_json::to_string(&json).unwrap_or_else(|_| "{}".to_string());
            if encoded.len() + 1 > STATUS_LIMIT {
                // Preserve canonical base output rather than allowing optional diagnostics to break commands.
                json.startup_milestones = None;
                encoded = serde_json::to_string(&json).unwrap_or_else(|_| "{}".to_string());
            }
        }
        encoded.push('\n');
        encoded
    }

    /// Atomic write: temp file → fsync → rename → dir fsync.
    /// Symlink-safe: opens temp with O_NOFOLLOW; never follows a path
    /// to a root-owned file.
    pub fn write_atomic(&self) {
        let input = self.serialize_with_trace_and_cluster(None, None, None, None);
        let now = std::time::Instant::now();
        if !self.publication.borrow_mut().observe(&input, now) {
            return;
        }
        let path = config::status_file();
        let dir = Path::new(path.as_str())
            .parent()
            .unwrap_or_else(|| Path::new(config::ROOT_ZONE));
        let Some(name) = Path::new(path.as_str()).file_name() else {
            log::err("status", "status path has no file name");
            return;
        };
        let _ = self.write_atomic_in(dir, name);
    }

    pub(crate) fn write_atomic_in(&self, dir: &Path, name: &std::ffi::OsStr) -> bool {
        let publisher = PublisherIdentity::current();
        // Store::snapshot binds native observations to this resident daemon epoch.
        // Never move this call into a foreign management/installer read process.
        let cluster = publisher.as_ref().and_then(|_| {
            crate::cluster_control::Store::production()
                .snapshot()
                .ok()
                .flatten()
        });
        let trace = publisher
            .as_ref()
            .and_then(|_| crate::fixed_process::snapshot_observations())
            .map(ProcessTrace::from_snapshot);
        let data = self.serialize_with_trace_and_cluster(
            Some(crate::agent_state::persistent_vehicle_state()),
            publisher,
            trace,
            cluster,
        );
        if self.publication.borrow().published.as_deref() == Some(data.as_str()) {
            return true;
        }
        let written = self.write_atomic_data_in(dir, name, &data);
        if written {
            self.publication.borrow_mut().published = Some(data);
        }
        written
    }

    #[cfg(test)]
    pub(crate) fn write_atomic_snapshot_in(
        &self,
        dir: &Path,
        snapshot: crate::agent_state::PersistentVehicleState,
    ) -> bool {
        let data = self.serialize_with_vehicle_state(Some(snapshot));
        self.write_atomic_data_in(dir, "status.json".as_ref(), &data)
    }

    fn write_atomic_data_in(&self, dir: &Path, name: &std::ffi::OsStr, data: &str) -> bool {
        let Ok(publication) = serde_json::from_str::<Value>(data) else {
            return false;
        };
        let context = diagnostic_context(&publication);
        // Keep the typed status field order; sorting through Value would no
        // longer match the independent canonical management decoder.
        let Some(prefix) = data.trim_end_matches('\n').strip_suffix('}') else {
            return false;
        };
        let data = attach_log_context(prefix, &context);
        #[cfg(not(test))]
        {
            if dir != Path::new(config::ROOT_ZONE) || name != std::ffi::OsStr::new("status.json") {
                log::err("status", "status publication target rejected");
                return false;
            }
            match crate::owner_client::publish_injection_status(&data) {
                Ok(()) => true,
                Err(error) => {
                    log::err(
                        "status",
                        &format!("status publication unavailable: {error}"),
                    );
                    false
                }
            }
        }
        #[cfg(test)]
        {
            let Some(name) = name.to_str() else {
                log::err("status", "status file name is not UTF-8");
                return false;
            };
            let dir = match Directory::open(dir) {
                Ok(dir) => dir,
                Err(e) => {
                    log::err("status", &format!("open root status directory: {e}"));
                    return false;
                }
            };
            let (uid, gid) = match dir.owner() {
                Ok(owner) => owner,
                Err(e) => {
                    log::err("status", &format!("stat root status directory: {e}"));
                    return false;
                }
            };

            let temp_name = ".status.tmp";
            let mut f = match dir.create_new(temp_name.as_ref(), 0o600) {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    /* A stale REGULAR tempfile from an interrupted write is
                     * removed and the create retried once. Any other pre-existing
                     * entry (symlink, directory, ...) fails closed: replacing it
                     * could redirect the write through state we do not own. */
                    match dir.entry_is_regular(temp_name) {
                        Ok(true) => {}
                        Ok(false) => {
                            log::err("status", "temp path exists and is not a regular file");
                            return false;
                        }
                        Err(e) => {
                            log::err("status", &format!("stat temp path: {e}"));
                            return false;
                        }
                    }
                    if let Err(e) = dir.unlink(temp_name) {
                        log::err("status", &format!("stale temp unlink: {e}"));
                        return false;
                    }
                    match dir.create_new(temp_name.as_ref(), 0o600) {
                        Ok(f) => f,
                        Err(e) => {
                            log::err("status", &format!("temp create: {e}"));
                            return false;
                        }
                    }
                }
                Err(e) => {
                    log::err("status", &format!("temp create: {e}"));
                    return false;
                }
            };
            if let Err(e) = f.write_all(data.as_bytes()) {
                log::err("status", &format!("write: {e}"));
                let _ = dir.unlink(temp_name);
                return false;
            }
            if let Err(e) = f.sync_all() {
                log::err("status", &format!("fsync: {e}"));
                let _ = dir.unlink(temp_name);
                return false;
            }
            if let Err(e) = f.set_permissions(fs::Permissions::from_mode(0o644)) {
                log::err("status", &format!("chmod: {e}"));
                let _ = dir.unlink(temp_name);
                return false;
            }

            // Rename while the inode is still daemon-owned. The app can read mode
            // 0644 but cannot race a write before ownership transfer on this fd.
            if let Err(e) = dir.replace(temp_name, name) {
                log::err("status", &format!("rename: {e}"));
                let _ = dir.unlink(temp_name);
                return false;
            }
            if let Err(e) = set_owner(&f, uid, gid) {
                log::err("status", &format!("chown: {e}"));
                return false;
            }
            if let Err(e) = f.sync_all() {
                log::err("status", &format!("metadata fsync: {e}"));
                return false;
            }
            let Ok(meta) = f.metadata() else {
                return false;
            };
            meta.file_type().is_file()
                && meta.nlink() == 1
                && meta.uid() == uid
                && meta.gid() == gid
                && meta.permissions().mode() & 0o777 == 0o644
        }
    }
}

#[cfg(test)]
pub(crate) fn cluster_status_fixture(
    stress_six_targets: bool,
) -> voboost_contract::cluster::ClusterSnapshot {
    use voboost_contract::cluster::*;
    let ids = ["font-cyrillic", "i18n-ru"];
    let desired: Vec<DesiredAgent> = ids
        .iter()
        .map(|id| DesiredAgent {
            id: (*id).into(),
            enabled: true,
            options: Default::default(),
        })
        .collect();
    let agents = ids.iter().map(|id| {
        let processes: &[&str] = if *id == "i18n-ru" || stress_six_targets { &["gauge", "light", "point"] } else { &["gauge"] };
        let targets: Vec<ObservedAgent> = processes.iter().enumerate().map(|(index, process)| ObservedAgent {
            id: (*id).into(), target_process: (*process).into(), state: ObservedState::Applied,
            reason: "confirmed locale and full private Russian dictionary".into(),
            process: Some(serde_json::from_value(serde_json::json!({"pid":42+index,"birthIdentity":"8".repeat(64),"executableSha256":"9".repeat(64),"endpointEpoch":"a".repeat(64),"lifecycleGeneration":1})).unwrap()),
        }).collect();
        ClusterAgentState { id: (*id).into(), enabled: true, options: Default::default(), state: ObservedState::Applied,
            reason: "all-selected-targets-applied".into(), process: if targets.len() == 1 { targets[0].process.clone() } else { None }, targets }
    }).collect();
    let snapshot = ClusterSnapshot {
        schema_version: 1,
        domain: voboost_contract::domain_catalog::Domain::Cluster,
        snapshot_revision: 7,
        catalog_sha256: "b".repeat(64),
        generation_id: Some("c".repeat(64)),
        desired_revision: 3,
        desired_sha256: desired_digest(&desired).unwrap(),
        observation_revision: 5,
        boot_id: Some("actual-qnx-boot".into()),
        daemon_epoch: Some("d".repeat(64)),
        delivery_state: DeliveryState::Idle,
        agents,
    };
    snapshot.validate().unwrap();
    snapshot
}

#[cfg(test)]
pub(crate) fn beta1_max_status_fixture() -> String {
    use sha2::{Digest, Sha256};
    let catalog_bytes = include_bytes!("../tests/fixtures/current-endpoint146-beta1-catalog.json");
    let catalog_digest = hex::encode(Sha256::digest(catalog_bytes));
    assert_eq!(
        catalog_digest,
        "ce32deede8a99156cc98fe8a03fcc7ea93b9f7b6418dc2c610df6c9d7a2531bc"
    );
    let catalog = crate::catalog::AgentCatalog::parse(catalog_bytes).unwrap();
    assert_eq!(
        catalog
            .agents
            .iter()
            .filter(|agent| !agent.is_executor())
            .count(),
        7
    );
    assert_eq!(
        catalog
            .agents
            .iter()
            .filter(|agent| agent.is_executor())
            .count(),
        1
    );
    beta1_max_status_for_catalog(catalog_bytes, &catalog)
}

#[cfg(test)]
fn beta1_max_status_for_catalog(bytes: &[u8], reviewed: &crate::catalog::AgentCatalog) -> String {
    beta1_max_status_for_catalog_options(bytes, reviewed, false, 52)
}

#[cfg(test)]
fn beta1_max_status_for_catalog_options(
    bytes: &[u8],
    reviewed: &crate::catalog::AgentCatalog,
    startup: bool,
    reviewed_rows: usize,
) -> String {
    let status = beta1_status_for_catalog_options(bytes, reviewed, startup, reviewed_rows);
    let serialized = status.serialize();
    assert!(serialized.len() > 64 * 1024);
    assert!(
        serialized.len() <= STATUS_LIMIT,
        "resident read cap must cover the full signed inventory"
    );
    serialized
}

#[cfg(test)]
fn beta1_status_for_catalog_options(
    bytes: &[u8],
    reviewed: &crate::catalog::AgentCatalog,
    startup: bool,
    reviewed_rows: usize,
) -> Status {
    use sha2::{Digest, Sha256};
    let catalog = crate::catalog::AgentCatalog::parse(bytes)
        .expect("actual beta1 catalog must parse strictly");
    let inventory = |catalog: &crate::catalog::AgentCatalog| {
        let mut ids = HashSet::new();
        let mut pairs = HashSet::new();
        for agent in &catalog.agents {
            assert!(
                ids.insert((agent.id.clone(), agent.is_executor())),
                "duplicate agent"
            );
            if !agent.is_executor() {
                assert_eq!(agent.status, Some(crate::catalog::AgentStatus::Stable));
            }
            for target in &agent.targets {
                assert!(
                    !target.process.contains('*'),
                    "beta1 targets must be finite"
                );
                assert!(
                    pairs.insert((agent.id.clone(), target.process.clone())),
                    "duplicate target"
                );
            }
        }
        (ids, pairs)
    };
    assert_eq!(
        inventory(&catalog),
        inventory(reviewed),
        "actual beta1 agent/target inventory changed; review the budget"
    );
    let catalog_digest = hex::encode(Sha256::digest(bytes));
    let mut pairs = HashSet::new();
    let mut status = Status {
        release_identity: "1.0.0-beta1".into(),
        manifest_sha256: "3".repeat(64),
        generation_id: "1".repeat(64),
        catalog_sha256: catalog_digest.clone(),
        startup_mode: crate::plan::Startup::Interface,
        ..Status::default()
    };
    let revision = crate::control_plane::MAX_DOCUMENT_GENERATION;
    let mut details = serde_json::json!({"payload":""});
    let overhead = serde_json::to_vec(&details).unwrap().len();
    details["payload"] = Value::String("x".repeat(8192 - overhead));
    assert_eq!(serde_json::to_vec(&details).unwrap().len(), 8192);
    for agent in &catalog.agents {
        for target in &agent.targets {
            assert!(!target.process.contains('*'));
            assert!(pairs.insert((agent.id.clone(), target.process.clone())));
            status.set_injection_event(
                &agent.id,
                &target.process,
                InjectionState::Active,
                &"\"".repeat(128),
                details.clone(),
                Some(revision),
                Some(i64::MAX),
            );
            status.set_current_endpoint(
                &target.process,
                EndpointBinding {
                    target_pid: i32::MAX.to_string(),
                    target_starttime: u64::MAX.to_string(),
                    endpoint_epoch: u64::MAX.to_string(),
                    generation_id: status.generation_id.clone(),
                    catalog_sha256: catalog_digest.clone(),
                    desired_document_generation: revision.to_string(),
                    accepted_status: Some(AcceptedStatus {
                        document_generation: revision.to_string(),
                        receipt: AcceptanceReceipt {
                            sequence: u64::MAX.to_string(),
                            daemon_pid: i32::MAX.to_string(),
                            daemon_starttime: u64::MAX.to_string(),
                            boot_id: "ffffffff-ffff-ffff-ffff-ffffffffffff".into(),
                        },
                    }),
                },
            );
        }
        if agent.is_executor() {
            status.executors.push(StatusExecutor {
                id: agent.id.clone(),
                processes: agent
                    .targets
                    .iter()
                    .map(|target| target.process.clone())
                    .collect(),
                surfaces: agent.surfaces.clone(),
            });
        }
    }
    assert_eq!(
        pairs.len(),
        reviewed_rows,
        "signed beta1 inventory growth requires budget review"
    );
    if startup {
        let processes = catalog
            .agents
            .iter()
            .flat_map(|a| {
                a.targets
                    .iter()
                    .filter(|t| t.is_android())
                    .map(|t| t.process.clone())
            })
            .collect::<HashSet<_>>();
        let pair_count = catalog
            .agents
            .iter()
            .filter(|a| a.startup_priority == Some(crate::catalog::StartupPriority::Vehicle))
            .map(|a| a.targets.iter().filter(|t| t.is_android()).count())
            .sum();
        let mut tracker = crate::startup::Milestones::new(
            crate::startup::Identity {
                boot_id: "ffffffff-ffff-ffff-ffff-ffffffffffff".into(),
                daemon_pid: i32::MAX,
                daemon_starttime: u64::MAX,
                manifest_sha256: status.manifest_sha256.clone(),
                generation_id: status.generation_id.clone(),
                catalog_sha256: status.catalog_sha256.clone(),
            },
            processes.len(),
            pair_count,
        );
        tracker.clock_anchor = crate::startup::ClockAnchor::from_sample(Some(900), 0, 0);
        tracker.begin_batch();
        let mut ordered = processes
            .into_iter()
            .map(|process| {
                let priority = catalog
                    .agents
                    .iter()
                    .filter(|a| catalog.has_target(&a.id, &process))
                    .map(|a| {
                        a.startup_priority
                            .unwrap_or(crate::catalog::StartupPriority::Applications)
                            as u8
                    })
                    .min()
                    .unwrap();
                (priority, process)
            })
            .collect::<Vec<_>>();
        ordered.sort();
        for (rank, (priority, process)) in ordered.into_iter().enumerate() {
            let index = tracker
                .ready(crate::startup::Target {
                    process: process.clone(),
                    pid: i32::MAX,
                    starttime: u64::MAX,
                    ready_ms: 1,
                    batch: 1,
                    priority,
                    dispatch_ms: None,
                    dispatch_rank: None,
                    endpoint_epoch: None,
                    adopted_ms: None,
                })
                .unwrap();
            tracker.dispatched(index, 2 + rank as u64, rank as u32);
            tracker.adopted(index, i32::MAX, u64::MAX, u64::MAX, 100 + rank as u64);
            for agent in catalog.agents.iter().filter(|a| {
                a.startup_priority == Some(crate::catalog::StartupPriority::Vehicle)
                    && catalog.has_target(&a.id, &process)
            }) {
                let member = crate::startup::Member {
                    id: agent.id.clone(),
                    target: index,
                    document_generation: revision,
                    lifecycle_generation: i64::MAX,
                    application: None,
                };
                tracker.admit_member(member.clone());
                // Fixture authority is a serializer boundary only, never runtime CAN evidence.
                tracker.confirm(
                    &member,
                    u64::MAX,
                    crate::startup::Application {
                        contract: "selected-fixture-contract".into(),
                        intent: "armed".into(),
                        semantics: vec![crate::startup::Semantic {
                            name: "selected-fixture-semantic".into(),
                            desired: true,
                            actual: true,
                        }],
                        outcome: crate::startup::Outcome::MatchedNoop,
                        android_observed_at_boot_ms: 1000,
                        received_ms: 200 + rank as u64,
                    },
                );
            }
        }
        assert!(tracker.complete);
        status.startup_milestones = Some(tracker);
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;

    fn sample_trace() -> ProcessTrace {
        ProcessTrace::from_snapshot(crate::fixed_process::ObservationSnapshot {
            records: std::array::from_fn(|index| {
                Some(crate::fixed_process::Observation {
                    operation_id: 9_007_199_254_740_993 + index as u64,
                    operation: crate::fixed_process::Operation::Cmd("package.list"),
                    parent_pid: 42,
                    child_pid: 222,
                    monotonic_ns: Some(u64::MAX),
                    elapsed_ms: u128::MAX,
                    outcome: crate::fixed_process::Outcome::Signal(11),
                })
            }),
            dropped: u64::MAX,
            overwritten: 19,
        })
    }

    fn publisher() -> PublisherIdentity {
        PublisherIdentity {
            boot_id: "18cce8ec-6c82-4b6c-b8bd-1b8794ad4174".into(),
            daemon_pid: "42".into(),
            daemon_starttime: "162".into(),
            published_at_boot_ms: "9007199254740993".into(),
        }
    }

    #[test]
    fn cluster_publication_preserves_all_targets_and_original_native_authority() {
        let snapshot = cluster_status_fixture(false);
        let status = Status::default();
        let output = status.serialize_with_trace_and_cluster(
            None,
            Some(publisher()),
            None,
            Some(snapshot.clone()),
        );
        let value: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(value["cluster"], serde_json::to_value(snapshot).unwrap());
        assert_eq!(
            value["cluster"]["agents"][1]["targets"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        assert_ne!(value["publisher"]["bootId"], value["cluster"]["bootId"]);
        assert!(output.len() <= PASSIVE_STATUS_LIMIT);
        let foreign = status.serialize_with_trace_and_cluster(
            None,
            None,
            None,
            Some(cluster_status_fixture(false)),
        );
        assert!(serde_json::from_str::<Value>(&foreign)
            .unwrap()
            .get("cluster")
            .is_none());
    }

    #[test]
    fn retained_log_context_never_pushes_the_publication_past_the_passive_envelope() {
        let prefix = r#"{"schemaVersion":1,"releaseIdentity":"1.0.0-beta1""#;
        let small = serde_json::json!({"schemaVersion":1,"releaseIdentity":"1.0.0-beta1"});
        let retained = attach_log_context(prefix, &small);
        let value: Value = serde_json::from_str(&retained).unwrap();
        assert_eq!(value["logContext"]["schemaVersion"], 1);
        assert!(retained.len() <= PASSIVE_STATUS_LIMIT);

        // A real retained context (57 targets) is larger than the whole passive
        // envelope on its own. The publication must degrade to an explicit
        // unavailable reason rather than become unreadable to the observer.
        let mut oversized = small.clone();
        oversized["vehicleDiagnostics"] = Value::String("x".repeat(PASSIVE_STATUS_LIMIT));
        let retained = attach_log_context(prefix, &oversized);
        let value: Value = serde_json::from_str(&retained).unwrap();
        assert_eq!(
            value["logContext"]["vehicleDiagnostics"]["reason"],
            "passive-budget-exceeded"
        );
        assert_eq!(value["logContext"]["releaseIdentity"], "1.0.0-beta1");
        assert!(retained.len() <= PASSIVE_STATUS_LIMIT);

        // Identity alone can still overflow a base that is already at the
        // limit; the base publication survives and the context is omitted.
        let full_prefix = format!(r#"{{"padding":"{}""#, "y".repeat(PASSIVE_STATUS_LIMIT));
        let retained = attach_log_context(&full_prefix, &small);
        assert_eq!(retained, format!("{full_prefix}}}\n"));
    }

    #[test]
    fn six_native_target_stress_fits_retained_beta1_passive_status_and_budget_failure_is_explicit()
    {
        let mut status = Status::default();
        for (id, process) in [
            ("launcher", "com.qinggan.app.launcher"),
            ("settings", "com.qinggan.app.setting"),
            ("font-cyrillic", "com.qinggan.app.video"),
        ] {
            status.set_injection_event(
                id,
                process,
                InjectionState::Active,
                "ready",
                serde_json::json!({"padding":""}),
                None,
                None,
            );
        }
        let overhead = status.serialize().len();
        for row in &mut status.injections {
            row.details["padding"] = Value::String("x".repeat((17100 - overhead) / 3));
        }
        let output = status.serialize_with_trace_and_cluster(
            None,
            Some(publisher()),
            Some(sample_trace()),
            Some(cluster_status_fixture(true)),
        );
        let value: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(
            value["cluster"]["agents"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a["targets"].as_array().unwrap().len())
                .sum::<usize>(),
            6
        );
        assert!(value.get("clusterUnavailable").is_none());
        assert!(output.len() <= PASSIVE_STATUS_LIMIT);
        status.set_injection_event(
            "phone",
            "com.qinggan.app.bluetooth",
            InjectionState::Active,
            "ready",
            serde_json::json!({"padding":""}),
            None,
            None,
        );
        for row in &mut status.injections {
            row.details["padding"] = Value::String("x".repeat((PASSIVE_STATUS_LIMIT - 2000) / 4));
        }
        let oversized = status.serialize_with_trace_and_cluster(
            None,
            Some(publisher()),
            None,
            Some(cluster_status_fixture(true)),
        );
        let value: Value = serde_json::from_str(&oversized).unwrap();
        assert!(value.get("cluster").is_none());
        assert_eq!(value["clusterUnavailable"], "passive-budget-exceeded");
        assert!(oversized.len() <= PASSIVE_STATUS_LIMIT);
    }

    #[test]
    fn process_trace_exists_for_real234_four_pair_input_and_no_restore_shape() {
        // Retained234 action181: two FEV input targets, one absent; both backends ready(false).
        let mut status = Status {
            release_identity: "1.0.0-beta1".into(),
            manifest_sha256: "1".repeat(64),
            generation_id: "2".repeat(64),
            catalog_sha256: "3".repeat(64),
            startup_mode: crate::plan::Startup::Interface,
            ..Status::default()
        };
        let pairs = [
            ("vehicle-drive-forced-ev", "com.qinggan.app.launcher", true),
            ("vehicle-drive-forced-ev", "com.qinggan.systemservice", true),
            (
                "vehicle-drive-forced-ev",
                "com.qinggan.app.vehiclesetting",
                false,
            ),
            (
                "vehicle-drive-pedestrian-warning",
                "com.qinggan.systemservice",
                true,
            ),
        ];
        let mut tracker = crate::startup::Milestones::new(
            crate::startup::Identity {
                boot_id: publisher().boot_id,
                daemon_pid: 42,
                daemon_starttime: 162,
                manifest_sha256: status.manifest_sha256.clone(),
                generation_id: status.generation_id.clone(),
                catalog_sha256: status.catalog_sha256.clone(),
            },
            43,
            4,
        );
        for (id, process, ready) in pairs {
            status
                .startup_vehicle_members
                .insert((id.into(), process.into()));
            status.set_injection_event(
                id,
                process,
                if ready {
                    InjectionState::Active
                } else {
                    InjectionState::Waiting
                },
                if ready { "ready" } else { "target-waiting" },
                if ready {
                    serde_json::json!({"armed":false})
                } else {
                    serde_json::json!({})
                },
                ready.then_some(1),
                ready.then_some(1),
            );
            if ready {
                let target = tracker.targets.len();
                tracker.targets.push(crate::startup::Target {
                    process: process.into(),
                    pid: 4470 + target as i32,
                    starttime: 2037,
                    ready_ms: 13085,
                    batch: 190,
                    priority: 0,
                    dispatch_ms: Some(13085),
                    dispatch_rank: Some(0),
                    endpoint_epoch: Some(1),
                    adopted_ms: Some(13493),
                });
                tracker.members.push(crate::startup::Member {
                    id: id.into(),
                    target,
                    document_generation: 1,
                    lifecycle_generation: 1,
                    application: None,
                });
            }
        }
        status.startup_milestones = Some(tracker);
        // Actual retained status was 17100 bytes; keep its compact envelope in this regression.
        status.injections[0].details["padding"] = Value::String("".into());
        let size = status
            .serialize_with_trace(None, Some(publisher()), None)
            .len();
        status.injections[0].details["padding"] = Value::String("x".repeat(17100 - size));
        let output = status.serialize_with_trace(None, Some(publisher()), Some(sample_trace()));
        let value: Value = serde_json::from_str(&output).unwrap();
        assert!(output.len() <= PASSIVE_STATUS_LIMIT);
        assert_eq!(value["startupMilestones"]["expectedMemberCount"], 4);
        assert_eq!(
            value["startupMilestones"]["members"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        assert!(value["startupMilestones"]["members"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["application"].is_null()));
        let trace = &value["processTrace"];
        assert!(serde_json::to_vec(trace).unwrap().len() <= PROCESS_TRACE_LIMIT);
        assert!(trace["omitted"].as_u64().unwrap() > 0);
        assert!(trace["records"].as_array().unwrap().len() > 1);
        assert_eq!(trace["records"][0]["monotonicNs"], u64::MAX.to_string());
        assert!(trace["records"][0]["operationId"].is_string());
        crate::management::verify_status_bytes(
            output.as_bytes(),
            "1.0.0-beta1",
            &status.manifest_sha256,
            &status.generation_id,
            &status.catalog_sha256,
            crate::plan::Startup::Interface,
            true,
        )
        .unwrap();
    }

    #[test]
    fn process_trace_prunes_first_at_passive_and_status_bounds() {
        for baseline in [25000, 32300, 32760, STATUS_LIMIT - 16] {
            let mut status = Status::default();
            status.set_injection_event(
                "agent",
                "process",
                InjectionState::Waiting,
                "ready",
                serde_json::json!({"payload":""}),
                None,
                None,
            );
            let size = status.serialize().len();
            status.injections[0].details["payload"] = Value::String("x".repeat(baseline - size));
            let base = status.serialize();
            assert_eq!(base.len(), baseline);
            let output = status.serialize_with_trace(None, None, Some(sample_trace()));
            assert!(
                output.len()
                    <= if baseline <= PASSIVE_STATUS_LIMIT {
                        PASSIVE_STATUS_LIMIT
                    } else {
                        STATUS_LIMIT
                    }
            );
            let mut value: Value = serde_json::from_str(&output).unwrap();
            if let Some(trace) = value.as_object_mut().unwrap().remove("processTrace") {
                assert!(serde_json::to_vec(&trace).unwrap().len() <= PROCESS_TRACE_LIMIT);
                let trace: ProcessTrace = serde_json::from_value(trace).unwrap();
                assert!(trace.valid());
                if baseline == 25000 {
                    assert!(!trace.records.is_empty());
                }
            } else {
                assert_eq!(output, base);
            }
            assert_eq!(value, serde_json::from_str::<Value>(&base).unwrap());
        }
        // Exercise the same serializer with the actual retained52-row maximum fixture.
        let bytes = include_bytes!("../tests/fixtures/current-endpoint146-beta1-catalog.json");
        let catalog = crate::catalog::AgentCatalog::parse(bytes).unwrap();
        let status = beta1_status_for_catalog_options(bytes, &catalog, true, 52);
        let base = status.serialize();
        assert_eq!(
            base,
            include_str!("../tests/fixtures/startup-milestones-beta1-max-status.json")
        );
        let output = status.serialize_with_trace(None, None, Some(sample_trace()));
        assert!(output.len() > base.len() && output.len() <= base.len() + PROCESS_TRACE_LIMIT + 16);
        let mut value: Value = serde_json::from_str(&output).unwrap();
        assert!(value
            .as_object_mut()
            .unwrap()
            .remove("processTrace")
            .is_some());
        assert_eq!(value, serde_json::from_str::<Value>(&base).unwrap());
        crate::management::verify_status_bytes(
            output.as_bytes(),
            "1.0.0-beta1",
            &status.manifest_sha256,
            &status.generation_id,
            &status.catalog_sha256,
            crate::plan::Startup::Interface,
            true,
        )
        .unwrap();
    }

    #[test]
    fn vehicle_diagnostics_export_is_closed_bounded_read_only_and_explicit() {
        let root = tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            vehicle_diagnostics_export(root.path())["availability"],
            "unavailable"
        );
        let path = root.path().join("status.json");
        let mut status = Status::default();
        status.set_injection_event(
            "vehicle-drive-forced-ev",
            "com.qinggan.systemservice",
            InjectionState::Failed,
            "endpoint-unavailable",
            serde_json::json!({"secret": "never-export"}),
            None,
            None,
        );
        let encoded = status.serialize_with_trace(
            Some(crate::agent_state::persistent_vehicle_state_from(
                &root.path().join("state"),
            )),
            Some(publisher()),
            None,
        );
        let mut value: Value = serde_json::from_str(&encoded).unwrap();
        value["startupMilestones"] = serde_json::to_value(crate::startup::Milestones::new(
            crate::startup::Identity {
                boot_id: publisher().boot_id,
                daemon_pid: 123,
                daemon_starttime: 162,
                manifest_sha256: "a".repeat(64),
                generation_id: "b".repeat(64),
                catalog_sha256: "c".repeat(64),
            },
            0,
            0,
        ))
        .unwrap();
        value["persistentVehicleState"]["forcedEv"] =
            serde_json::json!({"outcome": "value", "value": true});
        value["persistentVehicleState"]["pedestrianWarning"] =
            serde_json::json!({"outcome": "value", "value": false});
        value["secret"] = "never-export".into();
        let bytes = serde_json::to_vec(&value).unwrap();
        fs::write(&path, &bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let context = vehicle_diagnostics_export(root.path());
        assert_eq!(context["availability"], "retained-publication");
        assert_eq!(context["persistentVehicleState"]["forcedEv"]["value"], true);
        assert_eq!(
            context["persistentVehicleState"]["pedestrianWarning"]["value"],
            false
        );
        assert_eq!(context["startupMilestones"]["complete"], true);
        assert_eq!(context["injections"][0]["state"], "failed");
        assert_eq!(context["injections"][0]["reason"], "endpoint-unavailable");
        assert!(!context.to_string().contains("never-export"));
        assert_eq!(
            fs::read(&path).unwrap(),
            bytes,
            "export must not mutate retained state"
        );
        for field in ["persistentVehicleState", "startupMilestones", "injections"] {
            let mut changed = value.clone();
            changed[field] = serde_json::json!({"unexpected": "never-export"});
            fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
            assert_eq!(
                vehicle_diagnostics_export(root.path())[field]["availability"],
                "unavailable"
            );
        }
        let mut invalid_publisher = value.clone();
        invalid_publisher["publisher"]["bootId"] = "not-a-boot".into();
        fs::write(&path, serde_json::to_vec(&invalid_publisher).unwrap()).unwrap();
        assert_eq!(
            vehicle_diagnostics_export(root.path())["reason"],
            "publisher-unavailable"
        );
        let mut oversized = value.clone();
        let mut injection = oversized["injections"][0].clone();
        injection["id"] = "a".repeat(128).into();
        injection["process"] = "b".repeat(128).into();
        oversized["injections"] = vec![injection; 128].into();
        fs::write(&path, serde_json::to_vec(&oversized).unwrap()).unwrap();
        assert_eq!(
            vehicle_diagnostics_export(root.path())["reason"],
            "projection-exceeds-bound"
        );
        value["injections"][0]["reason"] = "private path /secret".into();
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            vehicle_diagnostics_export(root.path())["injections"][0]["reason"],
            "unavailable"
        );
        for bytes in [
            b"not-json".to_vec(),
            vec![b' '; STATUS_LIMIT + 1],
            b"{\"schemaVersion\":2}".to_vec(),
        ] {
            fs::write(&path, bytes).unwrap();
            assert_eq!(
                vehicle_diagnostics_export(root.path())["availability"],
                "unavailable"
            );
        }
        fs::write(&path, &encoded).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            vehicle_diagnostics_export(root.path())["availability"],
            "unavailable"
        );
        fs::remove_file(&path).unwrap();
        let other = root.path().join("other-status");
        fs::write(&other, encoded).unwrap();
        fs::set_permissions(&other, fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&other, &path).unwrap();
        assert_eq!(
            vehicle_diagnostics_export(root.path())["availability"],
            "unavailable"
        );
    }

    #[test]
    fn process_trace_export_is_trusted_bounded_historical_and_closed() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let status = Status {
            manifest_sha256: "a".repeat(64),
            ..Status::default()
        };
        let encoded = status.serialize_with_trace(None, Some(publisher()), Some(sample_trace()));
        let path = root.path().join("status.json");
        assert!(process_trace_export(root.path()).is_none());
        fs::write(&path, &encoded).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let context = process_trace_export(root.path()).unwrap();
        assert_eq!(context["proof"], "retained-publication");
        assert_eq!(context["publisher"]["bootId"], publisher().boot_id);
        assert_eq!(context["publisher"]["daemonStarttime"], "162");
        assert_eq!(context["manifestSha256"], "a".repeat(64));
        assert!(context.get("current").is_none());
        let mut value: Value = serde_json::from_str(&encoded).unwrap();
        value["secret"] = "never-export".into();
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(!process_trace_export(root.path())
            .unwrap()
            .to_string()
            .contains("never-export"));
        for mutation in ["argument", "operation", "parent", "oversize"] {
            let mut changed = value.clone();
            match mutation {
                "argument" => changed["processTrace"]["records"][0]["argv"] = "secret".into(),
                "operation" => {
                    changed["processTrace"]["records"][0]["operation"] =
                        "package.list.secret".into()
                }
                "parent" => changed["processTrace"]["records"][0]["parentPid"] = 77.into(),
                _ => changed["processTrace"]["records"][0]["elapsedMs"] = "9".repeat(8193).into(),
            }
            fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
            assert!(process_trace_export(root.path()).is_none(), "{mutation}");
        }
        fs::write(&path, &encoded).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(process_trace_export(root.path()).is_none());
        fs::remove_file(&path).unwrap();
        let other = root.path().join("other");
        fs::write(&other, encoded).unwrap();
        fs::set_permissions(&other, fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&other, &path).unwrap();
        assert!(process_trace_export(root.path()).is_none());
    }

    #[test]
    fn publication_identity_survives_absent_optional_startup_diagnostics() {
        let status = Status {
            release_identity: "1.0.0-beta1".into(),
            manifest_sha256: "1".repeat(64),
            generation_id: "2".repeat(64),
            catalog_sha256: "3".repeat(64),
            startup_mode: crate::plan::Startup::Interface,
            ..Status::default()
        };
        let publisher = PublisherIdentity {
            boot_id: "11111111-1111-1111-1111-111111111111".into(),
            daemon_pid: "42".into(),
            daemon_starttime: "123".into(),
            published_at_boot_ms: "9007199254740993".into(),
        };
        let encoded = status.serialize_with_provenance(None, Some(publisher));
        let value: Value = serde_json::from_str(&encoded).unwrap();
        assert!(value.get("startupMilestones").is_none());
        assert_eq!(value["publisher"]["daemonPid"], "42");
        assert_eq!(value["publisher"]["publishedAtBootMs"], "9007199254740993");
        assert!(crate::management::verify_status_bytes(
            encoded.as_bytes(),
            "1.0.0-beta1",
            &"1".repeat(64),
            &"2".repeat(64),
            &"3".repeat(64),
            crate::plan::Startup::Interface,
            true
        )
        .is_ok());
    }

    #[test]
    fn actual_serializer_startup_catalog_fixture_roundtrips_management_and_host() {
        use sha2::Digest;
        let bytes = include_bytes!("../tests/fixtures/current-endpoint146-beta1-catalog.json");
        let catalog = crate::catalog::AgentCatalog::parse(bytes).unwrap();
        let output = beta1_max_status_for_catalog_options(bytes, &catalog, true, 52);
        if let Some(path) = std::env::var_os("VOBOOST_STARTUP155_FIXTURE_OUTPUT") {
            std::fs::write(path, &output).unwrap();
        }
        assert_eq!(
            output,
            include_str!("../tests/fixtures/startup-milestones-beta1-max-status.json")
        );
        assert!(crate::management::verify_status_bytes(
            output.as_bytes(),
            "1.0.0-beta1",
            &"3".repeat(64),
            &"1".repeat(64),
            &hex::encode(sha2::Sha256::digest(bytes)),
            crate::plan::Startup::Interface,
            true
        )
        .is_ok());
        let value: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(value["startupMilestones"]["complete"], true);
        assert!(
            value["startupMilestones"]["targets"]
                .as_array()
                .unwrap()
                .len()
                > 1
        );
        let decoded: crate::startup::Milestones =
            serde_json::from_value(value["startupMilestones"].clone()).unwrap();
        assert_eq!(decoded.expected_member_count, 3);
        println!(
            "actual52row status with retained startup diagnostics: {} bytes",
            output.len()
        );
    }

    #[test]
    fn current_beta1_status_plus_full_diagnostic_budget_fits_existing_wire_limit() {
        let base = beta1_max_status_fixture();
        let mut value: Value = serde_json::from_str(&base).unwrap();
        value["startupMilestones"] =
            serde_json::json!({"payload":"x".repeat(crate::startup::MAX_BYTES)});
        let conservative = serde_json::to_vec(&value).unwrap().len() + 1;
        assert!(conservative < 1024 * 1024);
        println!(
            "current beta1 maximum base={} plus64KiB diagnostics conservative={} bytes",
            base.len(),
            conservative
        );
    }

    #[test]
    fn optional_diagnostics_never_break_existing_near_limit_status() {
        let mut status = Status::default();
        status.set_injection_event(
            "agent",
            "process",
            InjectionState::Waiting,
            "ready",
            serde_json::json!({"payload":""}),
            None,
            None,
        );
        let overhead = status.serialize().len();
        status.injections[0].details["payload"] =
            Value::String("x".repeat(1024 * 1024 - overhead - 16));
        let base = status.serialize();
        assert_eq!(base.len(), 1024 * 1024 - 16);
        status.startup_milestones = Some(crate::startup::Milestones::new(
            crate::startup::Identity {
                boot_id: "b".into(),
                daemon_pid: 2,
                daemon_starttime: 1,
                manifest_sha256: "m".into(),
                generation_id: "g".into(),
                catalog_sha256: "c".into(),
            },
            52,
            3,
        ));
        let output = status.serialize_with_trace(None, None, Some(sample_trace()));
        assert_eq!(
            output, base,
            "optional overflow must preserve exact canonical base bytes"
        );
    }

    #[test]
    fn startup_fixture_excludes_qnx_from_android_milestones_and_retains_resident_row() {
        let bytes = include_bytes!("../tests/fixtures/current-endpoint197-beta1-catalog.json");
        let source: Value = serde_json::from_slice(bytes).unwrap();
        assert!(source["agents"].as_array().unwrap().iter().any(|agent| {
            agent["id"] == "font-cyrillic"
                && agent["targets"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|target| target["process"] == "gauge" && target["platform"] == "qnx")
        }));
        // Exercise both normal font priority and a vehicle-priority native owner:
        // Android milestone member counts must never include the QNX member.
        for vehicle_priority in [false, true] {
            let mut candidate = source.clone();
            if vehicle_priority {
                candidate["agents"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|agent| agent["id"] == "font-cyrillic")
                    .unwrap()["startupPriority"] = "vehicle".into();
            }
            let shared: voboost_contract::agent_catalog::AgentCatalog =
                serde_json::from_value(candidate).unwrap();
            let bytes = shared.canonical_bytes().unwrap();
            let catalog = crate::catalog::AgentCatalog::parse(&bytes).unwrap();
            let rows = catalog.agents.iter().map(|agent| agent.targets.len()).sum();
            let output = beta1_max_status_for_catalog_options(&bytes, &catalog, true, rows);
            let value: Value = serde_json::from_str(&output).unwrap();
            assert_eq!(value["injections"].as_array().unwrap().len(), rows);
            assert!(value["injections"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["id"] == "font-cyrillic" && row["process"] == "gauge"));
            let milestones: crate::startup::Milestones =
                serde_json::from_value(value["startupMilestones"].clone()).unwrap();
            let android_processes = catalog
                .agents
                .iter()
                .flat_map(|agent| &agent.targets)
                .filter(|target| target.is_android())
                .map(|target| &target.process)
                .collect::<HashSet<_>>();
            let vehicle_pairs: usize = catalog
                .agents
                .iter()
                .filter(|agent| {
                    agent.startup_priority == Some(crate::catalog::StartupPriority::Vehicle)
                })
                .map(|agent| {
                    agent
                        .targets
                        .iter()
                        .filter(|target| target.is_android())
                        .count()
                })
                .sum();
            assert_eq!(milestones.targets.len(), android_processes.len());
            assert!(milestones
                .targets
                .iter()
                .all(|target| target.process != "gauge"));
            assert_eq!(milestones.expected_member_count, vehicle_pairs);
            assert!(milestones.complete);
            assert!(output.len() <= STATUS_LIMIT);
        }
    }

    #[test]
    fn current_signed_beta1_inventory_fits_resident_budget() {
        use sha2::Digest;
        let bytes = include_bytes!("../tests/fixtures/current-endpoint197-beta1-catalog.json");
        let budget: Value = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/current-endpoint197-beta1-budget.json"
        ))
        .unwrap();
        let rows = budget["catalogTargetRows"].as_u64().unwrap() as usize;
        let reviewed = crate::catalog::AgentCatalog::parse(bytes).unwrap();
        assert_eq!(
            reviewed
                .agents
                .iter()
                .filter(|agent| !agent.is_executor())
                .count(),
            budget["stableAgents"].as_u64().unwrap() as usize
        );
        assert_eq!(
            reviewed
                .agents
                .iter()
                .filter(|agent| agent.is_executor())
                .count(),
            budget["executors"].as_u64().unwrap() as usize
        );
        assert_eq!(
            reviewed
                .agents
                .iter()
                .map(|agent| agent.targets.len())
                .sum::<usize>(),
            rows
        );
        let output = beta1_max_status_for_catalog_options(bytes, &reviewed, false, rows);
        if let Some(path) = std::env::var_os("VOBOOST_ENDPOINT197_SCALE_OUTPUT") {
            std::fs::write(path, &output).unwrap();
        }
        assert_eq!(
            output,
            include_str!("../tests/fixtures/current-endpoint197-beta1-max-status.json")
        );
        assert!(output.len() < 1024 * 1024);
        assert!(crate::management::verify_status_bytes(
            output.as_bytes(),
            "1.0.0-beta1",
            &"3".repeat(64),
            &"1".repeat(64),
            &hex::encode(sha2::Sha256::digest(bytes)),
            crate::plan::Startup::Interface,
            true
        )
        .is_ok());
        let with_startup = beta1_max_status_for_catalog_options(bytes, &reviewed, true, rows);
        assert!(with_startup.len() < 1024 * 1024);
        assert!(crate::management::verify_status_bytes(
            with_startup.as_bytes(),
            "1.0.0-beta1",
            &"3".repeat(64),
            &"1".repeat(64),
            &hex::encode(sha2::Sha256::digest(bytes)),
            crate::plan::Startup::Interface,
            true
        )
        .is_ok());
        let value: Value = serde_json::from_str(&with_startup).unwrap();
        let milestones: crate::startup::Milestones =
            serde_json::from_value(value["startupMilestones"].clone()).unwrap();
        assert_eq!(
            milestones.expected_member_count,
            budget["startupVehicleTargetRows"].as_u64().unwrap() as usize
        );
        assert!(milestones.complete);
        println!(
            "current finite-target status with startup diagnostics: {} bytes",
            with_startup.len()
        );
        if let Some(path) = std::env::var_os("VOBOOST_ENDPOINT197_CATALOG_PATH") {
            let actual = beta1_max_status_for_catalog_options(
                &std::fs::read(path).unwrap(),
                &reviewed,
                false,
                rows,
            );
            assert!(actual.len() < 1024 * 1024);
        }
        let mut rebuilt = reviewed.clone();
        for agent in &mut rebuilt.agents {
            for target in &mut agent.targets {
                target.sha256 = "a".repeat(64);
                target.size += 4;
            }
        }
        let raw = serde_json::to_vec(&rebuilt).unwrap();
        let shared: voboost_contract::agent_catalog::AgentCatalog =
            serde_json::from_slice(&raw).unwrap();
        let rebuilt_bytes = shared.canonical_bytes().unwrap();
        let rebuilt_status =
            beta1_max_status_for_catalog_options(&rebuilt_bytes, &reviewed, false, rows);
        let rebuilt_value: Value = serde_json::from_str(&rebuilt_status).unwrap();
        assert_eq!(
            rebuilt_value["catalogSha256"],
            hex::encode(sha2::Sha256::digest(&rebuilt_bytes))
        );
        assert!(rebuilt_status.len() < 1024 * 1024);
        let mut changed = reviewed.clone();
        changed.agents[0].targets[0].process = "com.example.unreviewed".into();
        let raw = serde_json::to_vec(&changed).unwrap();
        let shared: voboost_contract::agent_catalog::AgentCatalog =
            serde_json::from_slice(&raw).unwrap();
        let encoded = shared.canonical_bytes().unwrap();
        let failure = std::panic::catch_unwind(|| {
            beta1_max_status_for_catalog_options(&encoded, &reviewed, false, rows)
        })
        .expect_err("unreviewed inventory must fail");
        let message = failure.downcast_ref::<String>().unwrap();
        assert!(message.contains("actual beta1 agent/target inventory changed"));
        println!(
            "current finite-target maximum status: {} bytes",
            output.len()
        );
    }

    #[test]
    fn signed_beta1_inventory_max_details_and_endpoint_identity_fit_resident_budget() {
        let fixture = beta1_max_status_fixture();
        assert_eq!(
            fixture,
            include_str!("../tests/fixtures/current-endpoint146-beta1-max-status.json")
        );
        let actual = if let Some(path) = std::env::var_os("VOBOOST_ENDPOINT146_CATALOG_PATH") {
            let reviewed = crate::catalog::AgentCatalog::parse(include_bytes!(
                "../tests/fixtures/current-endpoint146-beta1-catalog.json"
            ))
            .unwrap();
            beta1_max_status_for_catalog(&std::fs::read(path).unwrap(), &reviewed)
        } else {
            fixture
        };
        if let Some(path) = std::env::var_os("VOBOOST_ENDPOINT146_SCALE_OUTPUT") {
            std::fs::write(path, &actual).unwrap();
        }
        println!("beta1 maximum status: {} bytes, 52 rows", actual.len());
    }

    #[test]
    fn beta1_budget_allows_new_payload_but_rejects_inventory_changes() {
        let reviewed = crate::catalog::AgentCatalog::parse(include_bytes!(
            "../tests/fixtures/current-endpoint146-beta1-catalog.json"
        ))
        .unwrap();
        let mut changed = reviewed.clone();
        for agent in &mut changed.agents {
            for target in &mut agent.targets {
                target.sha256 = "a".repeat(64);
                target.size += 4;
            }
        }
        let encode = |catalog: &crate::catalog::AgentCatalog| {
            let raw = serde_json::to_vec(catalog).unwrap();
            let shared: voboost_contract::agent_catalog::AgentCatalog =
                serde_json::from_slice(&raw).unwrap();
            shared.canonical_bytes().unwrap()
        };
        let bytes = encode(&changed);
        let status = beta1_max_status_for_catalog(&bytes, &reviewed);
        let value: Value = serde_json::from_str(&status).unwrap();
        use sha2::{Digest, Sha256};
        assert_eq!(value["catalogSha256"], hex::encode(Sha256::digest(&bytes)));
        for variant in 0..4 {
            let mut invalid = changed.clone();
            match variant {
                0 => invalid.agents[0].targets[0].process = "com.example.new".into(),
                1 => {
                    let target = invalid.agents[0].targets[0].clone();
                    invalid.agents[0].targets.push(target);
                }
                2 => {
                    invalid.agents[0].targets.pop();
                }
                _ => invalid.agents[0].id = "unknown-beta1-agent".into(),
            }
            assert!(std::panic::catch_unwind(|| beta1_max_status_for_catalog(
                &encode(&invalid),
                &reviewed
            ))
            .is_err());
        }
    }

    #[test]
    fn current_endpoint_serializes_exact_producer_fixture_and_clears_with_generic_events() {
        let fixtures: Value =
            serde_json::from_str(include_str!("../tests/fixtures/current-endpoint146.json"))
                .unwrap();
        let endpoint = &fixtures["accepted"];
        let receipt = &endpoint["acceptedStatus"]["receipt"];
        let text = |value: &Value| value.as_str().unwrap().to_string();
        let binding = EndpointBinding {
            target_pid: text(&endpoint["targetPid"]),
            target_starttime: text(&endpoint["targetStarttime"]),
            endpoint_epoch: text(&endpoint["endpointEpoch"]),
            generation_id: text(&endpoint["generationId"]),
            catalog_sha256: text(&endpoint["catalogSha256"]),
            desired_document_generation: text(&endpoint["desiredDocumentGeneration"]),
            accepted_status: Some(AcceptedStatus {
                document_generation: text(&endpoint["acceptedStatus"]["documentGeneration"]),
                receipt: AcceptanceReceipt {
                    sequence: text(&receipt["sequence"]),
                    daemon_pid: text(&receipt["daemonPid"]),
                    daemon_starttime: text(&receipt["daemonStarttime"]),
                    boot_id: text(&receipt["bootId"]),
                },
            }),
        };
        let mut status = Status::default();
        let revision = binding.desired_document_generation.parse::<i64>().unwrap();
        status.set_injection_event(
            "forced-ev",
            "p",
            InjectionState::Active,
            "ready",
            serde_json::json!({}),
            Some(revision),
            Some(revision),
        );
        status.set_injection("settings-menu", "p", InjectionState::Waiting);
        status.set_injection_event(
            "stale",
            "p",
            InjectionState::Waiting,
            "target-waiting",
            serde_json::json!({}),
            Some(revision + 1),
            None,
        );
        // Simulate an endpoint retained before a row leaves the current document.
        status.injections[2].current_endpoint = Some(binding.clone());
        status.set_injection_event(
            "other-process",
            "q",
            InjectionState::Active,
            "ready",
            serde_json::json!({}),
            Some(revision),
            Some(revision),
        );
        status.set_current_endpoint("p", binding.clone());
        assert!(status.injections[0]
            .current_endpoint
            .as_ref()
            .unwrap()
            .valid_for_document(status.injections[0].document_generation));
        assert!(status.injections[1].current_endpoint.is_none());
        assert!(status.injections[2].current_endpoint.is_none());
        assert!(status.injections[3].current_endpoint.is_none());
        let raw: Value = serde_json::from_str(&status.serialize()).unwrap();
        assert_eq!(&raw["injections"][0]["currentEndpoint"], endpoint);
        let mut pending = binding;
        pending.accepted_status = None;
        status.set_current_endpoint("p", pending);
        let raw: Value = serde_json::from_str(&status.serialize()).unwrap();
        assert!(raw["injections"][0]["currentEndpoint"]
            .get("acceptedStatus")
            .is_none());
        status.set_injection("forced-ev", "p", InjectionState::Waiting);
        let raw: Value = serde_json::from_str(&status.serialize()).unwrap();
        assert!(raw["injections"][0].get("currentEndpoint").is_none());
    }

    #[test]
    fn set_injection_creates_new_entry() {
        let mut s = Status::default();
        s.set_injection(
            "forced-ev",
            "com.qinggan.systemservice",
            InjectionState::Waiting,
        );
        assert_eq!(
            s.injection_state("com.qinggan.systemservice"),
            Some(InjectionState::Waiting)
        );
    }

    #[test]
    fn set_injection_updates_existing_entry() {
        let mut s = Status::default();
        s.set_injection("forced-ev", "p", InjectionState::Waiting);
        s.set_injection("forced-ev", "p", InjectionState::Active);
        assert_eq!(s.injection_state("p"), Some(InjectionState::Active));
    }

    #[test]
    fn injection_state_none_for_unknown_process() {
        let s = Status::default();
        assert!(s.injection_state("unknown").is_none());
    }

    #[test]
    fn set_injection_dedupes_by_id_and_process() {
        let mut s = Status::default();
        s.set_injection("a", "p", InjectionState::Waiting);
        s.set_injection("a", "p", InjectionState::Failed);
        assert_eq!(s.injections.len(), 1);
        assert_eq!(s.injection_state("p"), Some(InjectionState::Failed));
    }

    #[test]
    fn co_resident_state_is_failed_when_one_agent_fails() {
        let mut s = Status::default();
        s.set_injection("a", "p", InjectionState::Active);
        s.set_injection("b", "p", InjectionState::Failed);
        assert_eq!(s.injection_state("p"), Some(InjectionState::Failed));
    }

    #[test]
    fn retain_injections_removes_disabled_status() {
        let mut s = Status::default();
        s.set_injection("enabled", "p", InjectionState::Active);
        s.set_injection("disabled", "p", InjectionState::Active);
        let desired = HashSet::from([("enabled".to_string(), "p".to_string())]);

        s.retain_injections(&desired);

        assert_eq!(s.injections.len(), 1);
        assert_eq!(s.injections[0].id, "enabled");
    }

    #[test]
    fn serialization_preserves_agent_metadata() {
        let mut s = Status {
            release_identity: "1.0.0-beta1".into(),
            manifest_sha256: "11".repeat(32),
            startup_mode: crate::plan::Startup::Hidden,
            ..Status::default()
        };
        s.set_injection_event(
            "launcher",
            "launcher",
            InjectionState::Failed,
            "hook-missing",
            serde_json::json!({"member":"loadData"}),
            Some(17),
            Some(4),
        );

        let value: Value = serde_json::from_str(&s.serialize()).unwrap();
        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["startupMode"], "hidden");
        let entry = &value["injections"][0];
        assert_eq!(entry["reason"], "hook-missing");
        assert_eq!(entry["details"]["member"], "loadData");
        assert_eq!(entry["documentGeneration"], 17);
        assert_eq!(entry["lifecycleGeneration"], 4);
        assert_eq!(value["releaseIdentity"], "1.0.0-beta1");
        assert_eq!(value["manifestSha256"], "11".repeat(32));
        assert!(value.get("daemon").is_none());
        assert!(value.get("manifest").is_none());
        assert!(s.serialize().starts_with(
            "{\"schemaVersion\":1,\"releaseIdentity\":\"1.0.0-beta1\",\"manifestSha256\":"
        ));
        assert!(s.serialize().ends_with("}\n"));
    }

    #[test]
    fn status_emitter_matches_the_product_wire_golden_bytes() {
        let mut status = Status {
            release_identity: "1.0.0-beta1".into(),
            manifest_sha256: "55".repeat(32),
            generation_id: "77".repeat(32),
            catalog_sha256: "66".repeat(32),
            startup_mode: crate::plan::Startup::Interface,
            ..Status::default()
        };
        status.set_injection_event(
            "settings-menu",
            "com.qinggan.app.setting",
            InjectionState::Active,
            "ready",
            serde_json::json!({}),
            Some(17),
            Some(17),
        );
        assert_eq!(
            status.serialize().as_bytes(),
            include_bytes!("../../test/fixtures/wire/status-interface.json")
        );

        status.startup_mode = crate::plan::Startup::None;
        status.kill_switch = true;
        assert_eq!(
            status.serialize().as_bytes(),
            include_bytes!("../../test/fixtures/wire/status-none.json")
        );
    }

    #[test]
    fn status_temp_symlink_does_not_modify_target() {
        let dir = tempdir().unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, b"unchanged").unwrap();
        symlink(&victim, dir.path().join(".status.tmp")).unwrap();

        let wrote = Status::default().write_atomic_in(dir.path(), "status.json".as_ref());

        assert!(!wrote);
        assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
        assert!(!dir.path().join("status.json").exists());
    }

    #[test]
    fn status_final_symlink_is_replaced_without_following_target() {
        let dir = tempdir().unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, b"unchanged").unwrap();
        symlink(&victim, dir.path().join("status.json")).unwrap();

        let wrote = Status::default().write_atomic_in(dir.path(), "status.json".as_ref());

        assert!(wrote);
        assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
        let meta = fs::symlink_metadata(dir.path().join("status.json")).unwrap();
        let dir_meta = fs::metadata(dir.path()).unwrap();
        assert!(meta.file_type().is_file());
        assert_eq!((meta.uid(), meta.gid()), (dir_meta.uid(), dir_meta.gid()));
        assert_eq!(meta.permissions().mode() & 0o777, 0o644);
    }
}
