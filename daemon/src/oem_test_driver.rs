//! OEM offline test driver (DEV-PLAN 2026-09-22-22-51-oem-tests, step 2).
//!
//! One ignored Rust test `tests::serve` that binds a loopback TCP socket on
//! an ephemeral port and speaks bounded JSON-lines `{id, op, payload}` →
//! `{id, ok, payload}` (version 1, 1 MiB frame cap, 10 s io deadlines,
//! harness-side shutdown deadline 5 s). The Java harness (agents repo)
//! starts this executable with `--exact oem_test_driver::tests::serve
//! --ignored --nocapture --test-threads=1` and drives the production daemon
//! paths through it: Settings mutations through
//! `agent_events::route_events` (production event parser + guards), the
//! canonical plan bytes/hash, canonical producer records and logs RPC
//! through `canonical_log`. The driver never synthesizes an acceptance.
//!
//! This is a transport test harness only — a cfg(test) module of the
//! daemon binary, wired through the existing fixture seam; the production
//! entrypoints keep every guard (EndpointContext gates, catalog awareness,
//! idempotence, frame budgets).

use crate::agent_log::EndpointContext;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

const VERSION: u32 = 1;
const MAX_FRAME_BYTES: usize = 1024 * 1024;
const IO_DEADLINE: Duration = Duration::from_secs(10);

/// Unique temp dir for the handshake (atomic write of port + version).
const HANDSHAKE_ENV: &str = "OEM_DRIVER_HANDSHAKE";

#[derive(serde::Deserialize)]
struct Request {
    id: u64,
    op: String,
    #[serde(default)]
    payload: Value,
}

struct DriverState {
    ctx: EndpointContext,
    plan_path: std::path::PathBuf,
    log_dir: std::path::PathBuf,
    /// Verified generation identity the committed fixture plan is validated
    /// against (the same release-catalog identity the daemon-loop tests use).
    generation: crate::generation::VerifiedGeneration,
    /// Mirrors the production per-process desired-document generation
    /// counter: each newly published desired snapshot (bind-time bootstrap
    /// and every later confirmed ack) renders with the next generation, or
    /// the runtime consumer's same-generation equivocation guard
    /// fail-closes the transport (stale-document-generation).
    document_generation: i64,
    /// Fixture-owned bootstrap/D admission, never supplied by a request or S.
    settings_loaded: bool,
    reply_write: std::fs::File,
    /// Read end of the same pipe: the harness reads the actual produced
    /// frame bytes back from it (`read-reply` op).
    reply_read: std::fs::File,
}

#[cfg(test)]
fn fixture_settings_ctx() -> EndpointContext {
    // Fixture trusted facts for the Settings endpoint: the same catalog and
    // generation identities the existing daemon unit tests use
    // (agent_events settings_ctx), so production guards accept the fixture
    // endpoint exactly like the resident runtime's.
    crate::agent_log::EndpointContext {
        owner_started: None,
        pid: 42,
        process: "com.qinggan.app.setting".to_string(),
        endpoint_epoch: 1,
        log_generation: None,
        target_starttime: Some(100),
        document_generation: None,
        restart_allowed: false,
        retiring_state: None,
        resident_agents: std::collections::HashSet::from([
            "settings".to_string(),
            "logs".to_string(),
        ]),
        agents: std::collections::HashSet::from(["settings".to_string()]),
        selected_agents: std::collections::HashSet::from([
            "settings".to_string(),
            "vehicle-drive-forced-ev".to_string(),
            "vehicle-drive-outing".to_string(),
            "logs".to_string(),
        ]),
        resident_generation_id: "generation".to_string(),
        resident_catalog_sha256: "catalog".to_string(),
        active_generation_id: "generation".to_string(),
        active_catalog_sha256: "catalog".to_string(),
        known_agents: std::collections::HashMap::from([
            // The Settings host itself is a resident catalog agent: the
            // committed chain fixture plan carries its enabled entry, and
            // validate_document_for_context accepts exactly the known set.
            // Stage 011: production catalog identities —
            // vehicle-drive-forced-ev / vehicle-drive-outing.
            ("settings".to_string(), Vec::new()),
            ("vehicle-drive-forced-ev".to_string(), Vec::new()),
            ("vehicle-drive-outing".to_string(), Vec::new()),
        ]),
        known_options: std::collections::HashMap::from([(
            "vehicle-drive-outing".to_string(),
            std::collections::HashMap::from([
                (
                    "exit-target".to_string(),
                    crate::agent_log::KnownOption {
                        option_type: "enum".to_string(),
                        values: std::collections::HashSet::from([
                            "comfort".to_string(),
                            "previous".to_string(),
                        ]),
                    },
                ),
                (
                    "above-speed".to_string(),
                    crate::agent_log::KnownOption {
                        option_type: "enum".to_string(),
                        values: std::collections::HashSet::from([
                            "exit".to_string(),
                            "keep".to_string(),
                        ]),
                    },
                ),
            ]),
        )]),
        startup_escalation_sources: std::collections::HashSet::new(),
    }
}

/// Stage 013: the REAL Outing editor endpoint — process
/// com.qinggan.app.vehiclesetting with vehicle-drive-outing resident and NO
/// settings resident (production ownership: the settings agent targets only
/// com.qinggan.app.setting, so it can never be resident here). The E-line
/// the stage-012 submitter emits (source "settings") must be rejected on
/// this endpoint.
#[cfg(test)]
fn fixture_vehiclesetting_ctx() -> EndpointContext {
    let base = fixture_settings_ctx();
    EndpointContext {
        pid: 43,
        process: "com.qinggan.app.vehiclesetting".to_string(),
        resident_agents: std::collections::HashSet::from(["vehicle-drive-outing".to_string()]),
        agents: std::collections::HashSet::from(["vehicle-drive-outing".to_string()]),
        // Same catalog surface: the endpoint-scoped known_options map is
        // derived from the shared active catalog, not from residentship.
        known_agents: base.known_agents.clone(),
        known_options: base.known_options.clone(),
        selected_agents: base.selected_agents.clone(),
        endpoint_epoch: 2,
        ..base
    }
}

#[cfg(test)]
impl DriverState {
    fn new(plan_path: std::path::PathBuf, log_dir: std::path::PathBuf) -> Self {
        // Mirror the real single-fd reply channel with an os pipe: production
        // handlers store the write fd, and the harness reads the actual
        // produced frame bytes back from the read end.
        let (reply_read, reply_write) = os_pipe().expect("driver reply pipe");
        DriverState {
            ctx: fixture_settings_ctx(),
            plan_path,
            log_dir,
            generation: crate::generation::test_support::verified_oem_chain(),
            document_generation: 0,
            settings_loaded: false,
            reply_write,
            reply_read,
        }
    }

    fn exchange_desired(
        &self,
        boot: &str,
        command: voboost_contract::runtime_owner::Command,
    ) -> std::io::Result<voboost_contract::runtime_owner::Outcome> {
        use voboost_contract::desired::{Config, Disposition, Field};
        use voboost_contract::runtime_owner::{Command, Outcome};

        let mut config = Config::decode(&std::fs::read(&self.plan_path)?)?;
        let disposition = match command {
            Command::SaveDesired {
                field,
                value,
                mut input,
            } => {
                let dependencies = match &field {
                    Field::Enabled { agent } => {
                        let declared = self.ctx.known_agents.get(agent).ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "unknown fixture agent",
                            )
                        })?;
                        if value == true {
                            declared.as_slice()
                        } else {
                            &[]
                        }
                    }
                    _ => &[],
                };
                input.injector_pid = self.ctx.pid;
                input.injector_starttime = self.ctx.target_starttime.unwrap_or_default();
                let disposition = config.save(boot, &field, &value, &input, dependencies)?;
                let bytes = serde_json::to_vec(&config)?;
                if !crate::plan::validate(&self.generation, &bytes).valid {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid fixture desired configuration",
                    ));
                }
                crate::secure_fs::write_atomic_private(&self.plan_path, &bytes, 0o600)?;
                disposition
            }
            Command::ReadDesired { .. } => Disposition::Replayed,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "unsupported fixture desired command",
                ))
            }
        };
        Ok(Outcome::DesiredSaved {
            revision: config.user_revision,
            config: serde_json::to_string(&config)?,
            disposition,
        })
    }

    fn reply_fd(&self) -> i32 {
        use std::os::fd::AsRawFd;
        self.reply_write.as_raw_fd()
    }
}

#[cfg(test)]
fn os_pipe() -> std::io::Result<(std::fs::File, std::fs::File)> {
    // Pipes through raw libc, wrapped in Files so the fds close at drop.
    unsafe {
        let mut fds = [0i32; 2];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        use std::os::fd::FromRawFd;
        Ok((
            std::fs::File::from_raw_fd(fds[0]),
            std::fs::File::from_raw_fd(fds[1]),
        ))
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
fn handle(state: &mut DriverState, request: &Request) -> Value {
    match request.op.as_str() {
        "initialize" => {
            if let Some(plan_parent) = state.plan_path.parent() {
                std::fs::create_dir_all(plan_parent).ok();
            }
            // The canonical log authority is created by CanonicalLog::open
            // itself (private 0700 child); pre-creating it with a different
            // mode fails the production validate_owner_mode gate.
            if let Err(e) = crate::canonical_log::init_global_without_app_listener(
                state.log_dir.to_str().unwrap(),
            ) {
                return json!({"ok": false, "id": request.id, "error": e.to_string()});
            }
            json!({
                "ok": true, "id": request.id,
                "payload": {
                    "version": VERSION,
                    "planPath": state.plan_path.to_str().unwrap(),
                }
            })
        }
        // The confirmed process document rendered by the production
        // constructors over the committed fixture plan, without any pending
        // mutation (the chain test bootstraps the runtime consumer with the
        // pre-click confirmed state the real daemon would have delivered at
        // endpoint bind time).
        "render-document" => {
            let confirmed = match crate::plan::read_canonical_bounded(&state.plan_path) {
                Ok(bytes) => crate::plan::validate(&state.generation, &bytes),
                Err(error) => {
                    return json!({"ok": false, "id": request.id,
                        "error": format!("confirmed snapshot read failed: {error}")});
                }
            };
            if !confirmed.valid {
                return json!({"ok": false, "id": request.id,
                    "error": "committed agents.json is not valid for the generation"});
            }
            // The bind-time bootstrap snapshot consumes the NEXT document
            // generation exactly like a production publish would.
            let next = state.document_generation + 1;
            match confirmed.desired_document_for_resident(
                &state.ctx.process,
                &state.generation,
                next,
                state.settings_loaded,
            ) {
                Ok(document) => {
                    state.document_generation = next;
                    state.settings_loaded = confirmed.startup == crate::plan::Startup::Interface
                        && confirmed
                            .enabled_ids_for_process(&state.ctx.process, &state.generation.catalog)
                            .iter()
                            .any(|id| id == "settings")
                        || state.settings_loaded && !confirmed.uninstall_cleanup;
                    json!({"ok": true, "id": request.id,
                        "payload": {"document": document}})
                }
                Err(error) => json!({"ok": false, "id": request.id, "error": error}),
            }
        }
        // Generation identity the committed fixture plan is validated
        // against: the chain test registers the same identity into the
        // runtime jar (AgentEntry.registerGeneration) so the rendered
        // A-frame document is accepted by the production consumer.
        "generation-info" => {
            json!({
                "ok": true, "id": request.id,
                "payload": {
                    "generationId": state.generation.id,
                    "catalogSha256": state.generation.catalog_sha256,
                }
            })
        }
        // The fixture plan the case runs against (harness-stored bytes are
        // the case input, never mutated by the driver itself).
        "store" => {
            let bytes = request
                .payload
                .get("contents")
                .and_then(Value::as_str)
                .unwrap_or("")
                .as_bytes()
                .to_vec();
            // The plan is written through the production atomic writer so
            // the file lands with exactly the mode read_canonical_bounded
            // trusts (0600 root-style private in the fixture directory).
            crate::secure_fs::write_atomic_private(&state.plan_path, &bytes, 0o600)
                .expect("store fixture plan");
            json!({
                "ok": true, "id": request.id,
                "payload": {"storedBytes": bytes.len()}
            })
        }
        "read" => {
            let bytes = match std::fs::read(&state.plan_path) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return json!({"ok": false, "id": request.id, "error": e.to_string()});
                }
            };
            json!({
                "ok": true, "id": request.id,
                "payload": {
                    "contents": String::from_utf8_lossy(&bytes),
                    "sha256": sha256_hex(&bytes),
                }
            })
        }
        // Submit real producer event bytes: production parser, production
        // guards; on accept the canonical plan changes atomically and a
        // confirmed ACK target is created for this endpoint.
        // Stage 013: switch the driver endpoint to another fixture context
        // (settings = the Settings process with settings resident;
        // vehiclesetting = the real Outing editor process with only
        // vehicle-drive-outing resident). Guard behavior is entirely the
        // production routes'; only the trusted ctx facts change.
        "use-context" => {
            let name = request
                .payload
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("");
            match name {
                "settings" => state.ctx = fixture_settings_ctx(),
                "vehiclesetting" => state.ctx = fixture_vehiclesetting_ctx(),
                _ => {
                    return json!({"ok": false, "id": request.id,
                        "error": "unknown fixture context"});
                }
            }
            // Confirmed-pending acks are epoch-scoped to the OLD endpoint;
            // a context restart keeps them undeliverable exactly like a
            // new bind would (production acks never cross endpoints).
            json!({"ok": true, "id": request.id,
                "payload": {"process": state.ctx.process}})
        }
        "mutate" => {
            let payload = request
                .payload
                .get("event")
                .and_then(Value::as_str)
                .unwrap_or("");
            if payload.len() > MAX_FRAME_BYTES {
                return json!({
                    "ok": false, "id": request.id,
                    "error": "frame exceeds 1 MiB budget"
                });
            }
            const FIXTURE_BOOT: &str = "11111111-1111-4111-8111-111111111111";
            let mut saved_frames = Vec::new();
            let routed = match crate::agent_events::route_fixture_desired(
                payload,
                &state.ctx,
                Some(state.reply_fd()),
                FIXTURE_BOOT,
                |command| state.exchange_desired(FIXTURE_BOOT, command),
                |_, frame| {
                    saved_frames.push(String::from_utf8_lossy(frame).into_owned());
                    true
                },
            ) {
                Some(result) => result,
                None => crate::agent_events::route_events_at_fixture_plan(
                    payload,
                    &state.ctx,
                    Some(state.reply_fd()),
                    &state.plan_path,
                ),
            }
            .is_some();
            json!({
                "ok": true, "id": request.id,
                "payload": {"routed": routed, "savedFrames": saved_frames, "canonicalPath":
                    state.plan_path.to_str().unwrap()}
            })
        }
        // Render and deliver the actual A-frame bytes: the production
        // daemon poll pass re-reads the committed canonical plan, validates
        // it against the verified generation, renders the confirmed process
        // document with the production constructors, and writes the frame on
        // the stored fd. read-reply mirrors that exact poll-pass sequence for
        // this driver's reply endpoint and reads the produced bytes back so
        // the chain test asserts the real E-line -> A-frame correlation. A
        // delivered ack leaves pending (production consumption); the next
        // call yields pending=false.
        "read-reply" => {
            use std::io::Read;
            let targets = crate::agent_events::take_confirmed_pending();
            let target = targets
                .iter()
                .find(|t| t.endpoint_epoch == state.ctx.endpoint_epoch)
                .cloned();
            let Some(target) = target else {
                return json!({"ok": true, "id": request.id,
                    "payload": {"pending": false, "frame": ""}});
            };
            if target.fd != state.reply_fd() || target.process != state.ctx.process {
                // Identically to the production poll pass: retry later.
                crate::agent_events::retry_confirmed_pending(target);
                return json!({"ok": true, "id": request.id,
                    "payload": {"pending": false, "error": "endpoint identity mismatch"}});
            }
            // The committed canonical plan, re-read through the production
            // bounded reader and validated against the verified generation.
            let confirmed = match crate::plan::read_canonical_bounded(&state.plan_path) {
                Ok(bytes) => crate::plan::validate(&state.generation, &bytes),
                Err(error) => {
                    crate::agent_events::retry_confirmed_pending(target);
                    return json!({"ok": false, "id": request.id,
                        "error": format!("confirmed snapshot read failed: {error}")});
                }
            };
            if !confirmed.valid {
                crate::agent_events::retry_confirmed_pending(target);
                return json!({"ok": false, "id": request.id,
                    "error": "confirmed snapshot deferred: agents.json unreadable after commit"});
            }
            let started_enabled = confirmed.startup != crate::plan::Startup::None;
            // The confirmed ack consumes the NEXT document generation, same
            // as the production poll pass publishing a new desired snapshot.
            let next = state.document_generation + 1;
            let document = match confirmed.desired_document_for_resident(
                &state.ctx.process,
                &state.generation,
                next,
                state.settings_loaded,
            ) {
                Ok(document) => document,
                Err(error) => {
                    crate::agent_events::retry_confirmed_pending(target);
                    return json!({"ok": false, "id": request.id,
                        "error": format!("confirmed document render failed: {error}")});
                }
            };
            let frame =
                match crate::runtime::render_mutation_ack_frame(target.request_id, &document) {
                    Ok(frame) => frame,
                    Err(error) => {
                        crate::agent_events::retry_confirmed_pending(target);
                        return json!({"ok": false, "id": request.id, "error": error});
                    }
                };
            if let Err(error) = state.reply_write.write_all(&frame) {
                crate::agent_events::retry_confirmed_pending(target);
                return json!({"ok": false, "id": request.id,
                    "error": format!("ack frame write failed: {error}")});
            }
            // Delivery completed: the new document is now the resident
            // generation for this endpoint.
            state.document_generation = next;
            let mut buffer = Vec::new();
            let mut take = (&state.reply_read).take(frame.len() as u64);
            let _ = take.read_to_end(&mut buffer);
            json!({"ok": true, "id": request.id,
                "payload": {"pending": true,
                    "requestId": target.request_id,
                    "enabled": started_enabled,
                    "frame": String::from_utf8_lossy(&buffer)}})
        }
        "check" => {
            // The production delivery path: the pending ACK target that the
            // accepted mutation created, rendered with the actual production
            // frame constructor, written on the actual fd the production
            // handler stored. returns the requestId it correlates.
            let targets = crate::agent_events::take_confirmed_pending();
            let target = targets
                .iter()
                .find(|t| t.endpoint_epoch == state.ctx.endpoint_epoch);
            match target {
                None => json!({
                    "ok": true, "id": request.id,
                    "payload": {"pending": false}
                }),
                Some(target) => {
                    json!({
                        "ok": true, "id": request.id,
                        "payload": {
                            "pending": true,
                            "requestId": target.request_id,
                            "process": target.process,
                        }
                    })
                }
            }
        }
        "select" => {
            // The production market gate (review F5): selection::evaluate
            // over the caller-supplied applicability + facts. The offline
            // RU suite proves China-only agents cannot evaluate Supported on
            // the RU (global) profile through the REAL production function,
            // not through a mirrored condition.
            let applicability = crate::catalog::Applicability {
                chip: request
                    .payload
                    .get("chip")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default(),
                vehicle: request
                    .payload
                    .get("vehicle")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default(),
                android: request
                    .payload
                    .get("android")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_u64())
                            .map(|v| v as u8)
                            .collect()
                    })
                    .unwrap_or_default(),
                powertrain: request
                    .payload
                    .get("powertrain")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default(),
                market: request
                    .payload
                    .get("market")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default(),
            };
            let facts = crate::selection::VehicleProfile {
                chip: crate::selection::Fact::Known(crate::selection::Known {
                    value: match request
                        .payload
                        .pointer("/facts/chip")
                        .and_then(Value::as_str)
                    {
                        Some("nxp") => crate::selection::Chip::Nxp,
                        _ => crate::selection::Chip::Qualcomm8155,
                    },
                }),
                vehicle: crate::selection::Fact::Known(crate::selection::Known {
                    value: match request
                        .payload
                        .pointer("/facts/vehicle")
                        .and_then(Value::as_str)
                    {
                        Some("dreamer") => crate::selection::Vehicle::Dreamer,
                        _ => crate::selection::Vehicle::Free,
                    },
                }),
                android: crate::selection::Fact::Known(crate::selection::Known {
                    value: match request
                        .payload
                        .pointer("/facts/android")
                        .and_then(|v| v.as_u64())
                    {
                        Some(11) => crate::selection::AndroidVersion::Eleven,
                        _ => crate::selection::AndroidVersion::Nine,
                    },
                }),
                powertrain: crate::selection::Fact::Known(crate::selection::Known {
                    value: match request
                        .payload
                        .pointer("/facts/powertrain")
                        .and_then(Value::as_str)
                    {
                        Some("ev") => crate::selection::Powertrain::Ev,
                        _ => crate::selection::Powertrain::Hybrid,
                    },
                }),
                market: crate::selection::Fact::Known(crate::selection::Known {
                    value: match request
                        .payload
                        .pointer("/facts/market")
                        .and_then(Value::as_str)
                    {
                        Some("global") => crate::selection::Market::Global,
                        _ => crate::selection::Market::China,
                    },
                }),
            };
            let outcome = crate::selection::evaluate(&applicability, &facts);
            json!({
                "ok": true, "id": request.id,
                "payload": {"result": format!("{:?}", outcome).to_lowercase()}
            })
        }
        "append-record" => {
            let kind = request
                .payload
                .get("sourceKind")
                .and_then(Value::as_str)
                .unwrap_or("agent");
            let agent = request
                .payload
                .get("sourceId")
                .and_then(Value::as_str)
                .map(str::to_string);
            let component = request
                .payload
                .get("component")
                .and_then(Value::as_str)
                .unwrap_or("settings");
            let level = request
                .payload
                .get("level")
                .and_then(Value::as_str)
                .unwrap_or("info");
            let message = request
                .payload
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("");
            let record = crate::canonical_log::ProducerRecord {
                level: parse_level(level),
                component: component.to_string(),
                message: message.to_string(),
                fields: std::collections::HashMap::new(),
            };
            let source = crate::canonical_log::Source {
                kind: kind.to_string(),
                id: agent.clone(),
            };
            match crate::canonical_log::append_global(source, record) {
                Ok(seq) => json!({
                    "ok": true, "id": request.id,
                    "payload": {"sequence": seq}
                }),
                Err(e) => json!({"ok": false, "id": request.id, "error": e.to_string()}),
            }
        }
        "logs-query" | "logs-follow" | "logs-stop" => {
            let request_id = request
                .payload
                .get("requestId")
                .and_then(Value::as_str)
                .unwrap_or("");
            let query = request.payload.get("query").cloned().unwrap_or(json!({}));
            match crate::canonical_log::dispatch_agent_rpc(
                &request.op,
                request_id,
                &query.to_string(),
                &state.ctx.resident_agents,
                &state.ctx.selected_agents,
            ) {
                Ok(response) => json!({
                    "ok": true, "id": request.id,
                    "payload": {"response": response}
                }),
                Err(e) => json!({"ok": false, "id": request.id, "error": e.to_string()}),
            }
        }
        "close" => json!({"ok": true, "id": request.id, "payload": {"closed": true}}),
        other => json!({
            "ok": false, "id": request.id,
            "error": format!("unknown-op:{other}")
        }),
    }
}

#[cfg(test)]
fn parse_level(level: &str) -> crate::canonical_log::Level {
    match level {
        "debug" => crate::canonical_log::Level::Debug,
        "error" => crate::canonical_log::Level::Error,
        _ => crate::canonical_log::Level::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The driver entrypoint. Binds loopback, writes the handshake (port +
    /// version) into the unique temp dir named by OEM_DRIVER_HANDSHAKE, then
    /// serves one JSON-lines connection until `close` or an io deadline.
    #[test]
    #[ignore]
    fn serve() {
        let handshake_dir =
            std::env::var(HANDSHAKE_ENV).expect("OEM_DRIVER_HANDSHAKE must name a unique tmp dir");
        std::fs::create_dir_all(&handshake_dir).unwrap();
        let root = std::env::temp_dir().join(format!("oem-driver-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let plan_path = root.join("agents.json");
        let log_dir = root.join("canonical-logs");

        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback bind");
        let port = listener.local_addr().unwrap().port();
        let handshake = std::path::Path::new(&handshake_dir).join("handshake.json");
        let tmp = handshake.with_extension("tmp");
        let handshake_bytes =
            serde_json::to_vec(&json!({"version": VERSION, "port": port})).unwrap();
        std::fs::write(&tmp, &handshake_bytes).unwrap();
        std::fs::rename(&tmp, &handshake).unwrap();

        // One driver state across connections: a client that drops its
        // socket (e.g. an offline suite whose bounded ack-wait exceeds the
        // per-frame io deadline) reconnects and resumes the same confirmed
        // plan, pending ack targets and document-generation counter, exactly
        // like an endpoint reconnecting to the resident daemon.
        let mut state = DriverState::new(plan_path.clone(), log_dir.clone());
        loop {
            let (stream, _) = listener
                .accept()
                .expect("driver accept (harness deadline 10 s)");
            let closed = serve_connection(stream, &mut state);
            if closed {
                break;
            }
        }

        // Shutdown completion marker for the harness reap check.
        std::fs::write(
            std::path::Path::new(&handshake_dir).join("shutdown.complete"),
            b"ok",
        )
        .unwrap();
    }

    /// Serves one JSON-lines connection; true when the client asked to
    /// close, false when the connection dropped (io deadline or EOF).
    fn serve_connection(stream: TcpStream, state: &mut DriverState) -> bool {
        stream.set_read_timeout(Some(IO_DEADLINE)).unwrap();
        stream.set_write_timeout(Some(IO_DEADLINE)).unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut writer = stream;
        loop {
            let mut frame = String::new();
            match reader.read_line(&mut frame) {
                Ok(0) | Err(_) => return false,
                Ok(_) => {}
            }
            if frame.len() > MAX_FRAME_BYTES || frame.trim().is_empty() {
                return false;
            }
            let Ok(request) = serde_json::from_str::<Request>(&frame) else {
                let _ = writeln!(writer, "{{\"id\":0,\"ok\":false,\"error\":\"bad-frame\"}}");
                writer.flush().ok();
                return false;
            };
            let response = handle(state, &request);
            let mut line = serde_json::to_string(&response).unwrap();
            line.push('\n');
            if writer.write_all(line.as_bytes()).is_err() {
                return false;
            }
            writer.flush().ok();
            if request.op == "close" {
                return true;
            }
        }
    }
}
