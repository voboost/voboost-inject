//! Semantic-command delivery for current authenticated CanBusService endpoints.
use crate::agent_log::EndpointContext;
use crate::owner_client;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use voboost_contract::runtime_owner::{self, NativeCommandIdentity, NativeCommandStatus, Outcome};

const MAX_EVENT_BYTES: usize = 4096;
const MAX_SOURCES: usize = 16;
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const CAN_SERVICE: &str = "com.qinggan.canbus.service";

#[derive(Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
enum Event {
    Ready {
        available: bool,
    },
    Poll {},
    Observe {
        observation: runtime_owner::NativeVehicleObservation,
    },
    Claim {
        identity: NativeCommandIdentity,
    },
    Accepted {
        identity: NativeCommandIdentity,
    },
    Cancelled {
        identity: NativeCommandIdentity,
    },
    Failed {
        identity: NativeCommandIdentity,
    },
    Unknown {
        identity: NativeCommandIdentity,
    },
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid native command event")
}

fn parse(source: &str, boot: &str, request_id: u64, bytes: &[u8]) -> io::Result<Event> {
    if !runtime_owner::valid_source(source)
        || request_id == 0
        || request_id > runtime_owner::MAX_NATIVE_ID
        || bytes.is_empty()
        || bytes.len() > MAX_EVENT_BYTES
    {
        return Err(invalid());
    }
    let event: Event = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if matches!(&event, Event::Observe { observation } if !observation.valid()) {
        return Err(invalid());
    }
    let identity = match &event {
        Event::Ready { .. } | Event::Poll {} | Event::Observe { .. } => None,
        Event::Claim { identity }
        | Event::Accepted { identity }
        | Event::Cancelled { identity }
        | Event::Failed { identity }
        | Event::Unknown { identity } => Some(identity),
    };
    if identity.is_some_and(|identity| {
        !identity.valid() || identity.source != source || identity.boot_id != boot
    }) {
        return Err(invalid());
    }
    Ok(event)
}

pub(crate) fn allowed(ctx: &EndpointContext, source: &str, mutations_allowed: bool) -> bool {
    mutations_allowed
        && ctx.settings_generation_is_active()
        && ctx.process == CAN_SERVICE
        && ctx.owns_agent(source)
        && ctx.known_agents.contains_key(source)
}

/// The caller supplies a current tracker context; event payloads cannot choose a process.
pub(crate) fn handle(
    source: &str,
    request_id: u64,
    bytes: &[u8],
    ctx: &EndpointContext,
) -> io::Result<Outcome> {
    let boot = crate::operation_contract::current_boot_id().map_err(io::Error::other)?;
    let event = parse(source, &boot, request_id, bytes)?;
    let response = match event {
        Event::Ready { available } => {
            owner_client::register_native_transport(source, ctx.pid, ctx.endpoint_epoch, available)
        }
        Event::Poll {} => owner_client::poll_native_command(source, ctx.pid, ctx.endpoint_epoch),
        Event::Observe { observation } => {
            owner_client::observe_native_vehicle(source, ctx.pid, ctx.endpoint_epoch, observation)
        }
        Event::Claim { identity } => owner_client::report_native_command(
            identity,
            ctx.pid,
            ctx.endpoint_epoch,
            NativeCommandStatus::Claim,
        ),
        Event::Accepted { identity } => owner_client::report_native_command(
            identity,
            ctx.pid,
            ctx.endpoint_epoch,
            NativeCommandStatus::Accepted,
        ),
        Event::Cancelled { identity } => owner_client::report_native_command(
            identity,
            ctx.pid,
            ctx.endpoint_epoch,
            NativeCommandStatus::Cancelled,
        ),
        Event::Failed { identity } => owner_client::report_native_command(
            identity,
            ctx.pid,
            ctx.endpoint_epoch,
            NativeCommandStatus::Failed,
        ),
        Event::Unknown { identity } => owner_client::report_native_command(
            identity,
            ctx.pid,
            ctx.endpoint_epoch,
            NativeCommandStatus::Unknown,
        ),
    }?;
    if !matches_boot(&response, &boot) {
        return Err(invalid());
    }
    pin_execution(ctx, &response)?;
    if let Outcome::NativeCommandReported { identity, result } = &response {
        if let Ok(mut executions) = executions().lock() {
            if let Some(execution) = executions
                .get_mut(source)
                .filter(|entry| entry.identity == *identity)
            {
                execution.terminal = Some(*result);
            }
        }
    }
    if let Outcome::NativeTransportRegistered { receipt } = &response {
        register(source, ctx, receipt.available)?;
    }
    Ok(response)
}

fn matches_boot(outcome: &Outcome, boot: &str) -> bool {
    match outcome {
        Outcome::NativeTransportRegistered { receipt } => receipt.boot_id == boot,
        Outcome::NativeVehicleObserved { boot_id, .. } => boot_id == boot,
        Outcome::NativeCommand {
            command: Some(command),
            ..
        } => command.identity.boot_id == boot,
        Outcome::NativeCommand { command: None, .. } => true,
        Outcome::NativeCommandReported { identity, .. } => identity.boot_id == boot,
        _ => false,
    }
}

/// A typed V response is never a Settings A acknowledgement.
pub(crate) fn frame(
    source: &str,
    request_id: u64,
    response: &io::Result<Outcome>,
) -> Option<String> {
    if !runtime_owner::valid_source(source) || request_id > runtime_owner::MAX_NATIVE_ID {
        return None;
    }
    let unavailable = Outcome::Unavailable {};
    let outcome = response.as_ref().unwrap_or(&unavailable);
    let valid = match outcome {
        Outcome::NativeTransportRegistered { receipt } => {
            receipt.valid() && receipt.source == source
        }
        Outcome::NativeCommand {
            source: returned,
            command,
        } => {
            returned == source
                && command
                    .as_ref()
                    .is_none_or(|command| command.valid() && command.identity.source == source)
        }
        Outcome::NativeCommandReported { identity, result } => {
            identity.valid() && identity.source == source && *result != NativeCommandStatus::Claim
        }
        Outcome::NativeVehicleObserved {
            source: observed,
            boot_id,
        } => observed == source && voboost_contract::operation::canonical_boot_id(boot_id),
        Outcome::Unavailable {} => true,
        _ => false,
    };
    if !valid {
        return None;
    }
    let payload = serde_json::to_string(outcome).ok()?;
    let frame = format!("V|{source}|{request_id}|{payload}\n");
    (frame.len() <= MAX_EVENT_BYTES).then_some(frame)
}

struct Execution {
    identity: NativeCommandIdentity,
    pid: i32,
    epoch: u64,
    starttime: Option<u64>,
    terminal: Option<NativeCommandStatus>,
}
static EXECUTIONS: OnceLock<Mutex<BTreeMap<String, Execution>>> = OnceLock::new();
fn executions() -> &'static Mutex<BTreeMap<String, Execution>> {
    EXECUTIONS.get_or_init(Default::default)
}
fn terminal(event: &Event) -> Option<(&NativeCommandIdentity, NativeCommandStatus)> {
    match event {
        Event::Accepted { identity } => Some((identity, NativeCommandStatus::Accepted)),
        Event::Cancelled { identity } => Some((identity, NativeCommandStatus::Cancelled)),
        Event::Failed { identity } => Some((identity, NativeCommandStatus::Failed)),
        Event::Unknown { identity } => Some((identity, NativeCommandStatus::Unknown)),
        _ => None,
    }
}

pub(crate) fn is_terminal(bytes: &[u8]) -> bool {
    bytes.len() <= MAX_EVENT_BYTES
        && serde_json::from_slice::<Event>(bytes)
            .ok()
            .is_some_and(|event| terminal(&event).is_some())
}

pub(crate) fn route_allowed(
    ctx: &EndpointContext,
    source: &str,
    bytes: &[u8],
    mutations_allowed: bool,
) -> bool {
    if allowed(ctx, source, mutations_allowed) {
        return true;
    }
    if ctx.process != CAN_SERVICE || bytes.is_empty() || bytes.len() > MAX_EVENT_BYTES {
        return false;
    }
    let Ok(event) = serde_json::from_slice::<Event>(bytes) else {
        return false;
    };
    let Some((identity, status)) = terminal(&event) else {
        return false;
    };
    identity.valid()
        && identity.source == source
        && executions().lock().is_ok_and(|executions| {
            executions.get(source).is_some_and(|entry| {
                entry.identity == *identity
                    && entry.pid == ctx.pid
                    && entry.epoch == ctx.endpoint_epoch
                    && entry.starttime == ctx.target_starttime
                    && entry.terminal.is_none_or(|previous| previous == status)
            })
        })
}

fn pin_execution(ctx: &EndpointContext, outcome: &Outcome) -> io::Result<()> {
    let Outcome::NativeCommand {
        command: Some(command),
        ..
    } = outcome
    else {
        return Ok(());
    };
    if !command.valid() {
        return Err(invalid());
    }
    if command.phase != runtime_owner::NativeCommandPhase::Execute {
        return Ok(());
    }
    let mut executions = executions().lock().map_err(|_| invalid())?;
    if !executions.contains_key(&command.identity.source) && executions.len() >= MAX_SOURCES {
        return Err(invalid());
    }
    if let Some(entry) = executions
        .get(&command.identity.source)
        .filter(|entry| entry.identity == command.identity)
    {
        if entry.pid != ctx.pid
            || entry.epoch != ctx.endpoint_epoch
            || entry.starttime != ctx.target_starttime
        {
            return Err(invalid());
        }
        return Ok(());
    }
    executions.insert(
        command.identity.source.clone(),
        Execution {
            identity: command.identity.clone(),
            pid: ctx.pid,
            epoch: ctx.endpoint_epoch,
            starttime: ctx.target_starttime,
            terminal: None,
        },
    );
    Ok(())
}

/// Remove only endpoint registrations absent from the current tracker inventory.
pub(crate) fn retain_endpoints(active: &[(i32, u64)]) {
    let removed: Vec<_> = {
        let Ok(mut endpoints) = endpoints().lock() else {
            return;
        };
        let removed = endpoints
            .iter()
            .filter(|(_, endpoint)| !active.contains(&(endpoint.pid, endpoint.epoch)))
            .map(|(source, endpoint)| (source.clone(), endpoint.pid, endpoint.epoch))
            .collect::<Vec<_>>();
        endpoints.retain(|_, endpoint| active.contains(&(endpoint.pid, endpoint.epoch)));
        removed
    };
    for (source, pid, epoch) in removed {
        let _ = owner_client::register_native_transport(&source, pid, epoch, false);
    }
    if let Ok(mut executions) = executions().lock() {
        executions.retain(|_, execution| active.contains(&(execution.pid, execution.epoch)));
    }
}

struct Endpoint {
    pid: i32,
    epoch: u64,
    last_poll: Option<Instant>,
    last_delivery: Vec<u8>,
    delivered_at: Option<Instant>,
}
static ENDPOINTS: OnceLock<Mutex<BTreeMap<String, Endpoint>>> = OnceLock::new();
static LAST_PUMP: OnceLock<Mutex<Option<Instant>>> = OnceLock::new();
fn endpoints() -> &'static Mutex<BTreeMap<String, Endpoint>> {
    ENDPOINTS.get_or_init(Default::default)
}
fn register(source: &str, ctx: &EndpointContext, available: bool) -> io::Result<()> {
    let mut endpoints = endpoints().lock().map_err(|_| invalid())?;
    if !available {
        endpoints.remove(source);
    } else if let Some(current) = endpoints.get(source) {
        if current.pid != ctx.pid || current.epoch != ctx.endpoint_epoch {
            endpoints.insert(
                source.into(),
                Endpoint {
                    pid: ctx.pid,
                    epoch: ctx.endpoint_epoch,
                    last_poll: None,
                    last_delivery: Vec::new(),
                    delivered_at: None,
                },
            );
        }
    } else if endpoints.len() < MAX_SOURCES {
        endpoints.insert(
            source.into(),
            Endpoint {
                pid: ctx.pid,
                epoch: ctx.endpoint_epoch,
                last_poll: None,
                last_delivery: Vec::new(),
                delivered_at: None,
            },
        );
    } else {
        return Err(invalid());
    }
    Ok(())
}

/// Called only with the current endpoint context, never a retained catalog snapshot.
pub(crate) fn pump(ctx: &EndpointContext, fd: Option<i32>, mutations_allowed: bool) {
    let Some(fd) = fd else {
        return;
    };
    if ctx.process != CAN_SERVICE {
        return;
    }
    let now = Instant::now();
    {
        let Ok(mut last) = LAST_PUMP.get_or_init(Default::default).lock() else {
            return;
        };
        if last.is_some_and(|last| now.saturating_duration_since(last) < POLL_INTERVAL) {
            return;
        }
        *last = Some(now);
    }
    let selected = {
        let Ok(mut endpoints) = endpoints().lock() else {
            return;
        };
        let next = endpoints
            .iter()
            .filter(|(_, endpoint)| endpoint.pid == ctx.pid && endpoint.epoch == ctx.endpoint_epoch)
            .min_by_key(|(_, endpoint)| endpoint.last_poll)
            .map(|(source, _)| source.clone());
        if let Some(source) = &next {
            if let Some(endpoint) = endpoints.get_mut(source) {
                endpoint.last_poll = Some(now);
            }
        }
        next
    };
    if let Some(source) = selected {
        if !allowed(ctx, &source, mutations_allowed) {
            let _ = owner_client::register_native_transport(
                &source,
                ctx.pid,
                ctx.endpoint_epoch,
                false,
            );
            if let Ok(mut endpoints) = endpoints().lock() {
                endpoints.remove(&source);
            }
            return;
        }
        let response = owner_client::poll_native_command(&source, ctx.pid, ctx.endpoint_epoch)
            .and_then(|outcome| {
                if matches!(&outcome, Outcome::NativeCommand { command: None, .. }) {
                    return Ok(outcome);
                }
                let boot =
                    crate::operation_contract::current_boot_id().map_err(io::Error::other)?;
                if matches_boot(&outcome, &boot) {
                    Ok(outcome)
                } else {
                    Err(invalid())
                }
            });
        if response
            .as_ref()
            .is_ok_and(|outcome| pin_execution(ctx, outcome).is_err())
        {
            return;
        }
        let Some(frame) = frame(&source, 0, &response) else {
            return;
        };
        let active = matches!(&response, Ok(Outcome::NativeCommand { command: Some(command), .. }) if command.phase != runtime_owner::NativeCommandPhase::Cancelled);
        let changed = endpoints().lock().is_ok_and(|endpoints| {
            endpoints.get(&source).is_some_and(|endpoint| {
                endpoint.pid == ctx.pid
                    && endpoint.epoch == ctx.endpoint_epoch
                    && (endpoint.last_delivery != frame.as_bytes()
                        || active
                            && endpoint
                                .delivered_at
                                .is_none_or(|last| last.elapsed() >= Duration::from_millis(250)))
            })
        });
        if changed && crate::downlink::enqueue_frame(fd, frame.as_bytes()) {
            if let Ok(mut endpoints) = endpoints().lock() {
                if let Some(endpoint) = endpoints.get_mut(&source) {
                    endpoint.last_delivery = frame.into_bytes();
                    endpoint.delivered_at = Some(Instant::now());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use voboost_contract::runtime_owner::{NativeCommandEnvelope, NativeCommandPhase, SCHEMA};
    const SOURCE: &str = "vehicle-drive-forced-ev";
    const BOOT: &str = "11111111-1111-4111-8111-111111111111";
    fn identity() -> NativeCommandIdentity {
        NativeCommandIdentity {
            owner_session: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            boot_id: BOOT.into(),
            source: SOURCE.into(),
            command_id: 7,
            revision: 2,
            state: "IVI_SOC_MODESET".into(),
            value: 5,
        }
    }
    fn context() -> EndpointContext {
        EndpointContext {
            pid: 20,
            process: CAN_SERVICE.into(),
            endpoint_epoch: 30,
            resident_agents: std::collections::HashSet::from([SOURCE.into()]),
            known_agents: std::collections::HashMap::from([(SOURCE.into(), Vec::new())]),
            resident_generation_id: "generation".into(),
            active_generation_id: "generation".into(),
            resident_catalog_sha256: "catalog".into(),
            active_catalog_sha256: "catalog".into(),
            ..Default::default()
        }
    }
    #[test]
    fn event_identity_never_supplies_endpoint_capabilities() {
        for operation in ["claim", "accepted", "cancelled", "failed", "unknown"] {
            let valid = serde_json::json!({"operation":operation,"identity":identity()});
            assert!(parse(SOURCE, BOOT, 99, valid.to_string().as_bytes()).is_ok());
            for (key, value) in [
                ("pid", serde_json::json!(999)),
                ("endpointEpoch", serde_json::json!(99)),
                ("source", serde_json::json!("other")),
            ] {
                let mut invalid = valid.clone();
                invalid[key] = value;
                assert!(parse(SOURCE, BOOT, 99, invalid.to_string().as_bytes()).is_err());
            }
            assert!(parse("other", BOOT, 99, valid.to_string().as_bytes()).is_err());
            assert!(parse(SOURCE, "other", 99, valid.to_string().as_bytes()).is_err());
        }
        assert!(parse(
            SOURCE,
            BOOT,
            1,
            br#"{"operation":"ready","available":true}"#
        )
        .is_ok());
        assert!(parse(SOURCE, BOOT, 1, br#"{"operation":"poll"}"#).is_ok());
        assert!(parse(SOURCE, BOOT, 0, br#"{"operation":"poll"}"#).is_err());
        assert!(parse(
            SOURCE,
            BOOT,
            1,
            br#"{"operation":"ready","available":"true"}"#
        )
        .is_err());
    }
    #[test]
    fn command_channel_retains_source_and_does_not_emit_settings_acknowledgements() {
        let outcome = Outcome::NativeCommand {
            source: SOURCE.into(),
            command: Some(NativeCommandEnvelope {
                schema_version: SCHEMA,
                identity: identity(),
                phase: NativeCommandPhase::Offered,
            }),
        };
        let value = frame(SOURCE, 0, &Ok(outcome)).unwrap();
        assert!(value.starts_with(&format!("V|{SOURCE}|0|")));
        let json: serde_json::Value =
            serde_json::from_str(value.trim_end().splitn(4, '|').nth(3).unwrap()).unwrap();
        assert_eq!(json["status"], "native-command");
        assert_eq!(json["command"]["identity"]["commandId"], 7);
        assert!(json["command"].get("ownerSession").is_none());
        assert!(!value.starts_with("A|"));
        let unavailable = frame(SOURCE, 99, &Err(io::ErrorKind::NotConnected.into())).unwrap();
        assert!(unavailable.contains("\"status\":\"unavailable\""));
        assert!(!unavailable.contains("execute"));
        assert!(frame(
            "other",
            1,
            &Ok(Outcome::NativeCommandReported {
                identity: identity(),
                result: NativeCommandStatus::Accepted
            })
        )
        .is_none());
    }
    #[test]
    fn retired_endpoints_can_report_only_the_exact_previously_granted_execution() {
        let source = "native-test-retired";
        let mut ctx = context();
        ctx.target_starttime = Some(40);
        let mut command = identity();
        command.source = source.into();
        let delivery = Outcome::NativeCommand {
            source: source.into(),
            command: Some(NativeCommandEnvelope {
                schema_version: SCHEMA,
                identity: command.clone(),
                phase: NativeCommandPhase::Execute,
            }),
        };
        pin_execution(&ctx, &delivery).unwrap();
        ctx.resident_agents.clear();
        ctx.known_agents.clear();
        ctx.active_generation_id = "newer".into();
        let accepted = serde_json::json!({"operation":"accepted","identity":command}).to_string();
        assert!(route_allowed(&ctx, source, accepted.as_bytes(), false));
        for operation in ["ready", "poll", "claim"] {
            let payload = match operation {
                "ready" => serde_json::json!({"operation":"ready","available":true}),
                "poll" => serde_json::json!({"operation":"poll"}),
                _ => serde_json::json!({"operation":"claim","identity":command}),
            }
            .to_string();
            assert!(!route_allowed(&ctx, source, payload.as_bytes(), false));
        }
        for variant in 0..3 {
            let mut changed = ctx.clone();
            match variant {
                0 => changed.pid += 1,
                1 => changed.endpoint_epoch += 1,
                _ => changed.target_starttime = Some(41),
            }
            assert!(!route_allowed(&changed, source, accepted.as_bytes(), false));
        }
        let mut changed = command.clone();
        changed.value = 2;
        let wrong = serde_json::json!({"operation":"accepted","identity":changed}).to_string();
        assert!(!route_allowed(&ctx, source, wrong.as_bytes(), false));
        executions()
            .lock()
            .unwrap()
            .get_mut(source)
            .unwrap()
            .terminal = Some(NativeCommandStatus::Accepted);
        let conflict = serde_json::json!({"operation":"failed","identity":command}).to_string();
        assert!(!route_allowed(&ctx, source, conflict.as_bytes(), false));
        executions().lock().unwrap().remove(source);
    }

    #[test]
    fn offered_commands_never_grant_retired_endpoint_reporting_authority() {
        let source = "native-test-offered";
        let mut ctx = context();
        let mut command = identity();
        command.source = source.into();
        pin_execution(
            &ctx,
            &Outcome::NativeCommand {
                source: source.into(),
                command: Some(NativeCommandEnvelope {
                    schema_version: SCHEMA,
                    identity: command.clone(),
                    phase: NativeCommandPhase::Offered,
                }),
            },
        )
        .unwrap();
        ctx.resident_agents.clear();
        ctx.known_agents.clear();
        let payload = serde_json::json!({"operation":"accepted","identity":command}).to_string();
        assert!(!route_allowed(&ctx, source, payload.as_bytes(), false));
        assert!(!executions().lock().unwrap().contains_key(source));
    }

    #[test]
    fn only_current_can_service_residents_may_use_the_command_lane() {
        let valid = context();
        assert!(allowed(&valid, SOURCE, true));
        for variant in 0..5 {
            let mut ctx = valid.clone();
            match variant {
                0 => ctx.process = "com.qinggan.systemservice".into(),
                1 => ctx.resident_agents.clear(),
                2 => ctx.known_agents.clear(),
                3 => ctx.active_generation_id = "newer".into(),
                _ => {}
            }
            assert!(!allowed(&ctx, SOURCE, variant != 4));
        }
    }
}
