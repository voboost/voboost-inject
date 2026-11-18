//! One-use expected-death authority for a confirmed agent removal.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::agent_log::EndpointContext;

const PERMIT_TTL: Duration = Duration::from_secs(10);
const MAX_PERMITS: usize = crate::catalog::MAX_AGENTS * crate::catalog::MAX_AGENT_TARGETS;

struct Permit {
    epoch: u64,
    revision: i64,
    request: u64,
    starttime: u64,
    expires: Instant,
    consumed: bool,
}

#[derive(Default)]
struct Permits(HashMap<(i32, String), Permit>);

impl Permits {
    fn authorize(
        &mut self,
        ctx: &EndpointContext,
        request: u64,
        revision: i64,
        now: Instant,
    ) -> bool {
        if ctx.process == "system_server"
            || ctx.pid <= 0
            || ctx.endpoint_epoch == 0
            || ctx.target_starttime.is_none()
            || request == 0
            || request > i64::MAX as u64
            || revision < 0
            || ctx.document_generation != Some(revision)
            || !ctx.settings_generation_is_active()
            || !ctx.restart_allowed
        {
            return false;
        }
        let key = (ctx.pid, ctx.process.clone());
        if let Some(permit) = self.0.get(&key) {
            if permit.epoch == ctx.endpoint_epoch {
                if permit.consumed || Some(permit.starttime) != ctx.target_starttime {
                    return false;
                }
                if revision <= permit.revision {
                    return now < permit.expires
                        && permit.revision == revision
                        && permit.request == request;
                }
            } else if !permit.consumed || Some(permit.starttime) == ctx.target_starttime {
                return false;
            }
        }
        self.0.retain(|_, permit| now < permit.expires);
        if self.0.len() >= MAX_PERMITS && !self.0.contains_key(&key) {
            return false;
        }
        self.0.insert(
            key,
            Permit {
                epoch: ctx.endpoint_epoch,
                revision,
                request,
                starttime: ctx.target_starttime.unwrap(),
                expires: now + PERMIT_TTL,
                consumed: false,
            },
        );
        true
    }

    fn consume(&mut self, pid: i32, process: &str, now: Instant) -> bool {
        if process == "system_server" {
            return false;
        }
        let Some(permit) = self.0.get_mut(&(pid, process.to_owned())) else {
            return false;
        };
        if permit.consumed || now >= permit.expires {
            return false;
        }
        permit.consumed = true;
        true
    }
}

fn permits() -> &'static Mutex<Permits> {
    static PERMITS: OnceLock<Mutex<Permits>> = OnceLock::new();
    PERMITS.get_or_init(|| Mutex::new(Permits::default()))
}

pub fn authorize(ctx: &EndpointContext, request: u64, revision: i64) -> bool {
    permits()
        .lock()
        .is_ok_and(|mut permits| permits.authorize(ctx, request, revision, Instant::now()))
}

pub fn consume_death(pid: i32, process: &str) -> bool {
    permits()
        .lock()
        .is_ok_and(|mut permits| permits.consume(pid, process, Instant::now()))
}

pub fn pending(ctx: &EndpointContext, request: u64, revision: i64) -> bool {
    if ctx.process == "system_server"
        || !ctx.restart_allowed
        || !ctx.settings_generation_is_active()
    {
        return false;
    }
    permits().lock().is_ok_and(|permits| {
        permits
            .0
            .get(&(ctx.pid, ctx.process.clone()))
            .is_some_and(|permit| {
                !permit.consumed
                    && Instant::now() < permit.expires
                    && permit.epoch == ctx.endpoint_epoch
                    && permit.request == request
                    && permit.revision == revision
                    && ctx.document_generation == Some(revision)
                    && Some(permit.starttime) == ctx.target_starttime
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> EndpointContext {
        EndpointContext {
            pid: 123,
            process: "com.qinggan.app.launcher".into(),
            endpoint_epoch: 7,
            target_starttime: Some(99),
            document_generation: Some(12),
            restart_allowed: true,
            resident_agents: ["launcher-apps".into()].into_iter().collect(),
            resident_generation_id: "generation".into(),
            active_generation_id: "generation".into(),
            resident_catalog_sha256: "catalog".into(),
            active_catalog_sha256: "catalog".into(),
            ..EndpointContext::default()
        }
    }

    #[test]
    fn current_signed_removal_authorizes_only_its_own_death_once() {
        let ctx = context();
        let now = Instant::now();
        let mut permits = Permits::default();
        assert!(permits.authorize(&ctx, 1, 12, now));
        assert!(!permits.consume(124, &ctx.process, now));
        assert!(!permits.consume(ctx.pid, "other.process", now));
        assert!(permits.consume(ctx.pid, &ctx.process, now));
        assert!(!permits.consume(ctx.pid, &ctx.process, now));
        assert!(!permits.authorize(&ctx, 1, 12, now));
    }

    #[test]
    fn stale_identity_or_no_removal_never_creates_a_permit() {
        let now = Instant::now();
        let mut permits = Permits::default();
        let mut ctx = context();
        assert!(!permits.authorize(&ctx, 1, 11, now));
        assert!(!permits.authorize(&ctx, 0, 12, now));
        ctx.active_generation_id = "other".into();
        assert!(!permits.authorize(&ctx, 1, 12, now));
        ctx = context();
        ctx.restart_allowed = false;
        assert!(!permits.authorize(&ctx, 1, 12, now));
        ctx = context();
        ctx.target_starttime = None;
        assert!(!permits.authorize(&ctx, 1, 12, now));
        assert!(permits.0.is_empty());
    }

    #[test]
    fn duplicates_do_not_extend_the_exact_expiry_or_rearm_the_request() {
        let ctx = context();
        let now = Instant::now();
        let mut permits = Permits::default();
        assert!(permits.authorize(&ctx, 1, 12, now));
        assert!(permits.authorize(&ctx, 1, 12, now + Duration::from_secs(9)));
        assert!(!permits.authorize(&ctx, 2, 12, now + Duration::from_secs(9)));
        assert!(!permits.consume(ctx.pid, &ctx.process, now + PERMIT_TTL));
        assert!(!permits.authorize(&ctx, 1, 12, now + PERMIT_TTL));
    }

    #[test]
    fn reused_pid_needs_new_attested_birth_and_its_own_removal() {
        let mut ctx = context();
        let now = Instant::now();
        let mut permits = Permits::default();
        assert!(permits.authorize(&ctx, 1, 12, now));
        assert!(permits.consume(ctx.pid, &ctx.process, now));
        ctx.endpoint_epoch += 1;
        assert!(!permits.authorize(&ctx, 1, 12, now));
        ctx.target_starttime = Some(100);
        ctx.restart_allowed = false;
        assert!(!permits.authorize(&ctx, 1, 12, now));
        ctx.restart_allowed = true;
        assert!(permits.authorize(&ctx, 1, 12, now));
        assert!(permits.consume(ctx.pid, &ctx.process, now));
    }

    #[test]
    fn newer_confirmed_revision_can_replace_an_expired_unfinished_permission() {
        let mut ctx = context();
        let now = Instant::now();
        let mut permits = Permits::default();
        assert!(permits.authorize(&ctx, 1, 12, now));
        ctx.document_generation = Some(13);
        assert!(permits.authorize(&ctx, 2, 13, now + PERMIT_TTL));
        assert!(permits.consume(ctx.pid, &ctx.process, now + PERMIT_TTL));
        assert!(!permits.authorize(&ctx, 2, 13, now + PERMIT_TTL));
    }
    #[test]
    fn system_server_never_receives_a_death_permit() {
        let mut ctx = context();
        ctx.process = "system_server".into();
        let mut permits = Permits::default();
        let now = Instant::now();
        assert!(!permits.authorize(&ctx, 1, 12, now));
        assert!(!permits.consume(ctx.pid, &ctx.process, now));
        assert!(!pending(&ctx, 1, 12));
    }
}
