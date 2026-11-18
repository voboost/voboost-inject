//! User settings have a semantic owner lane, independent of product transactions and apply ACKs.
use crate::agent_log::EndpointContext;
use serde_json::Value;
use voboost_contract::desired::{Field, Input};
use voboost_contract::runtime_owner::{Command, Outcome};

pub(super) fn route(
    rest: &str,
    context: &EndpointContext,
    reply_fd: Option<i32>,
) -> Option<Option<usize>> {
    let mut header = rest.splitn(4, '|');
    header.next()?;
    header.next()?;
    let kind = header.next()?;
    if !matches!(
        kind,
        "checkbox" | "radio" | "option" | "owned-intent" | "desired-read"
    ) {
        return None;
    }
    let boot = match voboost_contract::operation::current_boot_id() {
        Ok(boot) => boot,
        Err(_) => return Some(None),
    };
    route_with(
        rest,
        context,
        reply_fd,
        &boot,
        |command| match command {
            Command::SaveDesired {
                field,
                value,
                input,
            } => crate::owner_client::save_desired(field, value, input),
            Command::ReadDesired { field } => crate::owner_client::read_desired(field),
            command => crate::owner_client::call(command),
        },
        crate::downlink::enqueue_frame,
    )
}

/// Outer None means another capability owns the event. Recognized invalid input never falls back.
pub(crate) fn route_with(
    rest: &str,
    context: &EndpointContext,
    reply_fd: Option<i32>,
    boot: &str,
    mut exchange: impl FnMut(Command) -> std::io::Result<Outcome>,
    mut send: impl FnMut(i32, &[u8]) -> bool,
) -> Option<Option<usize>> {
    let mut parts = rest.splitn(4, '|');
    let request = parts.next()?;
    let source = parts.next()?;
    let kind = parts.next()?;
    if !matches!(
        kind,
        "checkbox" | "radio" | "option" | "owned-intent" | "desired-read"
    ) {
        return None;
    }
    Some((|| {
        let request_id: u64 = request.parse().ok()?;
        if request_id == 0
            || request_id > i64::MAX as u64
            || context.endpoint_epoch == 0
            || context.pid <= 1
            || context.target_starttime.is_none()
        {
            return None;
        }
        let settings = source == "settings" && context.settings_allowed();
        let recovery =
            kind == "radio" && source != "settings" && context.startup_escalation_allowed(source);
        if !settings
            && !recovery
            && !(context.owns_agent(source) && matches!(kind, "option" | "owned-intent"))
        {
            return None;
        }
        let payload = parts.next()?;
        let (key, raw) = payload.split_once(':')?;
        let read = kind == "desired-read";
        let mut captured = None;
        let (field, value) = match kind {
            "desired-read" if settings && key == "field" => {
                (serde_json::from_str::<Field>(raw).ok()?, Value::Null)
            }
            "checkbox" if settings => (
                Field::Enabled { agent: key.into() },
                match raw {
                    "true" => true.into(),
                    "false" => false.into(),
                    _ => return None,
                },
            ),
            "radio" if settings && key == "voboost-startup" => (Field::Startup, raw.into()),
            "radio" if recovery && key == "voboost-startup" && raw == "interface" => {
                (Field::Startup, raw.into())
            }
            "option" | "owned-intent" => {
                let (agent, key) = key.split_once('/')?;
                if !settings && agent != source {
                    return None;
                }
                let value = if kind == "owned-intent" {
                    if !crate::owned_intent::supports(source) || key != "intent" {
                        return None;
                    }
                    let (value, capture) = raw.split_once('@')?;
                    let capture = capture.parse::<u64>().ok()?;
                    if capture == 0 {
                        return None;
                    }
                    if !matches!(value, "on" | "off") {
                        return None;
                    }
                    captured = Some((capture, value));
                    value
                } else {
                    raw
                };
                (
                    Field::Option {
                        agent: agent.into(),
                        key: key.into(),
                    },
                    value.into(),
                )
            }
            _ => return None,
        };
        if !field.valid() || (!read && !field.accepts(&value)) {
            return None;
        }
        let input = Input {
            boot_id: boot.into(),
            endpoint_epoch: context.endpoint_epoch,
            request_id,
            injector_pid: 0,
            injector_starttime: 0,
        };
        let command = if recovery {
            Command::SaveStartupRecovery { input }
        } else if read {
            Command::ReadDesired {
                field: field.clone(),
            }
        } else {
            Command::SaveDesired {
                field: field.clone(),
                value,
                input,
            }
        };
        let Outcome::DesiredSaved {
            revision,
            config,
            disposition,
        } = exchange(command).ok()?
        else {
            return None;
        };
        let config: Value = serde_json::from_str(&config).ok()?;
        let value = match &field {
            Field::Startup => config.get("startup")?,
            Field::Enabled { agent } => config.get("agents")?.get(agent)?.get("enabled")?,
            Field::Option { agent, key } => {
                config.get("agents")?.get(agent)?.get("options")?.get(key)?
            }
            Field::LauncherItemVisibility { identity } => config
                .get("agents")?
                .get("launcher")?
                .get("options")?
                .get("itemVisibility")?
                .get(identity)?,
            Field::LauncherAppPreference { identity, key } => config
                .get("agents")?
                .get("launcher")?
                .get("options")?
                .get("appPreferences")?
                .get(identity)?
                .get(key)?,
        };
        let receipt = serde_json::json!({"requestId":request_id,"userRevision":revision,
            "disposition":disposition,"field":field,"value":value});
        let frame = format!("U|{request_id}|{}\n", serde_json::to_string(&receipt).ok()?);
        let fd = reply_fd?;
        if !send(fd, frame.as_bytes()) {
            return None;
        }
        if let Some((capture, choice)) = captured {
            let status = if disposition == voboost_contract::desired::Disposition::Superseded {
                "superseded"
            } else {
                "committed"
            };
            let frame =
                crate::owned_intent::receipt_frame(source, request_id, capture, choice, status)?;
            if !send(fd, frame.as_bytes()) {
                return None;
            }
        }
        if !read {
            super::mark_confirmed_pending(context, fd, request_id);
        }
        Some(1)
    })())
}
