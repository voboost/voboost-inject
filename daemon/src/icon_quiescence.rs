//! Closed launcher-cache-only quiescence. Queue admission is never an ACK.
use crate::agent_log::EndpointContext;
use std::sync::{Mutex, OnceLock};

pub(crate) const PROCESS: &str = "com.qinggan.app.launcher";
use voboost_contract::icon_cache_quiescence::Command;
#[derive(Clone)]
struct Pending {
    command: Command,
    pid: i32,
    starttime: u64,
    epoch: u64,
    acknowledged: bool,
}
fn pending() -> &'static Mutex<Option<Pending>> {
    static PENDING: OnceLock<Mutex<Option<Pending>>> = OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(None))
}
pub(crate) fn begin(context: &EndpointContext, request_id: String) -> Result<Vec<u8>, String> {
    let command = Command {
        schema_version: 1,
        operation: "launcher-cache-quiesce".to_string(),
        request_id,
        generation_id: context.resident_generation_id.clone(),
        catalog_sha256: context.resident_catalog_sha256.clone(),
        document_generation: context
            .document_generation
            .ok_or("launcher desired revision absent")?,
    };
    if !command.validate() || context.process != PROCESS {
        return Err("launcher cache endpoint authority absent".to_string());
    }
    let starttime = context
        .target_starttime
        .ok_or("launcher starttime absent")?;
    let json = serde_json::to_string(&command).map_err(|e| e.to_string())?;
    if json.len() > 1024 {
        return Err("launcher cache command exceeds bound".to_string());
    }
    *pending()
        .lock()
        .map_err(|_| "launcher cache pending lock poisoned")? = Some(Pending {
        command,
        pid: context.pid,
        starttime,
        epoch: context.endpoint_epoch,
        acknowledged: false,
    });
    Ok(format!("C|{json}\n").into_bytes())
}
pub(crate) fn observe(json: &str, context: &EndpointContext) -> Option<usize> {
    if json.len() > 1024 {
        return None;
    }
    let command: Command = serde_json::from_str(json).ok()?;
    let mut all = pending().lock().ok()?;
    let waiting = all.as_mut()?;
    if !command.validate()
        || command != waiting.command
        || context.pid != waiting.pid
        || context.target_starttime != Some(waiting.starttime)
        || context.endpoint_epoch != waiting.epoch
        || context.process != PROCESS
        || context.resident_generation_id != command.generation_id
        || context.resident_catalog_sha256 != command.catalog_sha256
        || context.document_generation != Some(command.document_generation)
    {
        return None;
    }
    waiting.acknowledged = true;
    Some(1)
}
pub(crate) fn acknowledged(context: &EndpointContext) -> bool {
    pending()
        .lock()
        .ok()
        .and_then(|all| {
            all.as_ref().map(|p| {
                p.acknowledged
                    && p.pid == context.pid
                    && p.starttime == context.target_starttime.unwrap_or(0)
                    && p.epoch == context.endpoint_epoch
            })
        })
        .unwrap_or(false)
}
pub(crate) fn reset() {
    if let Ok(mut all) = pending().lock() {
        *all = None;
    }
}

pub(crate) fn receipt(
    context: &EndpointContext,
    transaction_id: &str,
    boot_id: &str,
) -> Result<Vec<u8>, String> {
    let all = pending()
        .lock()
        .map_err(|_| "launcher cache pending lock poisoned")?;
    let p = all.as_ref().ok_or("launcher cache ACK absent")?;
    if !p.acknowledged
        || p.pid != context.pid
        || context.target_starttime != Some(p.starttime)
        || p.epoch != context.endpoint_epoch
    {
        return Err("launcher cache ACK identity changed".to_string());
    }
    serde_json::to_vec(&voboost_contract::icon_cache_quiescence::Receipt {
        schema_version: 1,
        transaction_id: transaction_id.to_owned(),
        boot_id: boot_id.to_owned(),
        process: PROCESS.to_owned(),
        proof: voboost_contract::icon_cache_quiescence::Proof::Acknowledged {
            pid: p.pid,
            starttime: p.starttime,
            endpoint_epoch: p.epoch,
            command: p.command.clone(),
        },
    })
    .map_err(|e| e.to_string())
}

pub(crate) fn no_endpoint_receipt(transaction_id: &str, boot_id: &str) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&voboost_contract::icon_cache_quiescence::Receipt {
        schema_version: 1,
        transaction_id: transaction_id.to_owned(),
        boot_id: boot_id.to_owned(),
        process: PROCESS.to_owned(),
        proof: voboost_contract::icon_cache_quiescence::Proof::NoEndpoint {},
    })
    .map_err(|e| e.to_string())
}
pub(crate) fn persist_receipt(bytes: &[u8]) -> Result<(), String> {
    let root = crate::secure_fs::Directory::open(std::path::Path::new(crate::config::ROOT_ZONE))
        .map_err(|e| e.to_string())?;
    let run = root.open_child("run").map_err(|e| e.to_string())?;
    run.validate_owner_mode(0, 0, crate::config::RUN_DIR_MODE)
        .map_err(|e| e.to_string())?;
    run.write_atomic("icon-cache-quiescence.json", bytes, 0o600)
        .map_err(|e| e.to_string())?;
    run.sync_all().map_err(|e| e.to_string())?;
    if run
        .read_trusted("icon-cache-quiescence.json", 8192, 0o600)
        .map_err(|e| e.to_string())?
        != bytes
    {
        return Err("cache quiescence receipt changed during publication".to_owned());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn context() -> EndpointContext {
        EndpointContext {
            pid: 123,
            process: PROCESS.to_owned(),
            endpoint_epoch: 42,
            target_starttime: Some(1000),
            document_generation: Some(7),
            resident_generation_id: "c".repeat(64),
            resident_catalog_sha256: "a".repeat(64),
            resident_agents: ["launcher-apps".to_owned()].into_iter().collect(),
            selected_agents: ["launcher-apps".to_owned()].into_iter().collect(),
            ..Default::default()
        }
    }
    #[test]
    fn exact_correlated_ack_and_foreign_endpoint_fences() {
        let ctx = context();
        let frame = begin(&ctx, "b".repeat(64)).unwrap();
        let json = std::str::from_utf8(&frame[2..frame.len() - 1]).unwrap();
        assert!(!acknowledged(&ctx));
        for wrong in [
            EndpointContext {
                pid: 124,
                ..ctx.clone()
            },
            EndpointContext {
                endpoint_epoch: 43,
                ..ctx.clone()
            },
            EndpointContext {
                target_starttime: Some(1001),
                ..ctx.clone()
            },
            EndpointContext {
                document_generation: Some(8),
                ..ctx.clone()
            },
            EndpointContext {
                process: "other.process".to_owned(),
                ..ctx.clone()
            },
            EndpointContext {
                resident_generation_id: "other-generation".to_owned(),
                ..ctx.clone()
            },
            EndpointContext {
                resident_catalog_sha256: "c".repeat(64),
                ..ctx.clone()
            },
        ] {
            assert_eq!(observe(json, &wrong), None);
        }
        assert_eq!(
            observe(&json.replace(&"b".repeat(64), &"c".repeat(64)), &ctx),
            None
        );
        assert_eq!(observe(json, &ctx), Some(1));
        assert!(acknowledged(&ctx));
        assert_eq!(observe(json, &ctx), Some(1));
        reset();
        // A disabled launcher agent can retain a live endpoint for the font agent.
        // Cache quiescence must fence inactive/retained Java owners too.
        let font_only = EndpointContext {
            selected_agents: ["font".to_owned()].into_iter().collect(),
            resident_agents: ["font".to_owned()].into_iter().collect(),
            ..ctx.clone()
        };
        let frame = begin(&font_only, "d".repeat(64)).unwrap();
        let font_json = std::str::from_utf8(&frame[2..frame.len() - 1]).unwrap();
        assert_eq!(observe(font_json, &font_only), Some(1));
        let proof: voboost_contract::icon_cache_quiescence::Receipt = serde_json::from_slice(
            &receipt(
                &font_only,
                &"e".repeat(64),
                "11111111-1111-1111-1111-111111111111",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(proof.matches(&"e".repeat(64), "11111111-1111-1111-1111-111111111111"));
        reset();
        assert!(!acknowledged(&ctx));
        assert_eq!(observe(json, &ctx), None);
    }
    #[test]
    fn strict_command_parser_rejects_unknown_duplicate_and_wrong_operation() {
        let good = Command {
            schema_version: 1,
            operation: "launcher-cache-quiesce".to_owned(),
            request_id: "a".repeat(64),
            generation_id: "c".repeat(64),
            catalog_sha256: "b".repeat(64),
            document_generation: 1,
        };
        let json = serde_json::to_string(&good).unwrap();
        assert!(
            serde_json::from_str::<Command>(&json.replacen('{', "{\"unknown\":true,", 1)).is_err()
        );
        assert!(
            serde_json::from_str::<Command>(&json.replacen('{', "{\"schemaVersion\":1,", 1))
                .is_err()
        );
        let mut wrong = good.clone();
        wrong.operation = "execute".to_owned();
        assert!(!wrong.validate());
    }
}
