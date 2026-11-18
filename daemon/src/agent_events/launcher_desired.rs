//! Launcher inventory authorizes semantic owner patches; no product lock or document RMW.
use crate::agent_log::EndpointContext;
use voboost_contract::desired::Input;
use voboost_contract::runtime_owner::{Command, Outcome};

fn recognized(kind: &str) -> bool {
    matches!(
        kind,
        "launcher-item-visibility"
            | "launcher-section-visibility"
            | "launcher-app-preference"
            | "launcher-density"
    )
}

/// Outer None delegates other event kinds; recognized invalid launcher actions fail closed.
pub(super) fn route(
    rest: &str,
    context: &EndpointContext,
    reply_fd: Option<i32>,
) -> Option<Option<usize>> {
    let kind = rest.split('|').nth(2)?;
    if !recognized(kind) {
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
        crate::owner_client::call,
        crate::downlink::enqueue_frame,
    )
}

pub(super) fn route_with(
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
    if !recognized(kind) {
        return None;
    }
    Some((|| {
        let request_id: u64 = request.parse().ok()?;
        if request_id == 0
            || request_id > i64::MAX as u64
            || source != "launcher"
            || context.process != "com.qinggan.app.setting"
            || !context.owns_agent("launcher")
            || context.endpoint_epoch == 0
            || context.pid <= 1
            || context.target_starttime.is_none()
        {
            return None;
        }
        let (key, raw) = parts.next()?.split_once(':')?;
        let changes = crate::launcher_config::desired_changes(kind, key, raw, context)?;
        let input = Input {
            boot_id: boot.into(),
            endpoint_epoch: context.endpoint_epoch,
            request_id,
            injector_pid: 0,
            injector_starttime: 0,
        };
        let field = changes.first()?.0.clone();
        let Outcome::DesiredSaved {
            revision,
            config,
            disposition,
        } = exchange(Command::SaveLauncherDesired { changes, input }).ok()?
        else {
            return None;
        };
        let config = voboost_contract::desired::Config::decode(config.as_bytes()).ok()?;
        let value = config.value_at(&field.path())?;
        let frame = format!("U|{request_id}|{}\n", serde_json::to_string(&serde_json::json!({
            "requestId":request_id,"userRevision":revision,"disposition":disposition,"field":field,"value":value
        })).ok()?);
        let fd = reply_fd?;
        if !send(fd, frame.as_bytes()) {
            return None;
        }
        super::mark_confirmed_pending(context, fd, request_id);
        Some(1)
    })())
}

#[cfg(test)]
#[path = "launcher_desired.test.rs"]
mod tests;
