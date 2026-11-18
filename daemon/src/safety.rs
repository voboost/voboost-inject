// safety.rs — device-safety: rate-limit, quarantine, panic, circuit breaker, kill-switch.
//
// Ported from Vala safety.vala + added per-target circuit breaker (device-safety
// spec). Three failure-scope mechanisms:
//   - per-(agent, process) rate-limit: throttle reinjection of one flapping agent
//   - per-target circuit breaker: M crashes / N seconds → stop injecting target
//   - global panic-quarantine: stop everything when deaths spike device-wide

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config;
use crate::log;

const MAX_BACKOFF_SECS: u64 = 1800; // 30 minutes

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn key(agent: &str, process: &str) -> String {
    format!("{agent}@{process}")
}

/// Per-(agent, process) attempt log with sliding-window rate-limit + backoff.
struct AttemptLog {
    times: Vec<u64>, // ring buffer of attempt timestamps
    backoff_step: u32,
    next_allowed: u64,
}

impl AttemptLog {
    fn new(capacity: usize) -> Self {
        Self {
            times: Vec::with_capacity(capacity),
            backoff_step: 0,
            next_allowed: 0,
        }
    }
}

/// Per-target crash counter for the circuit breaker.
struct CrashLog {
    times: Vec<u64>, // crash timestamps within the window
}

impl CrashLog {
    fn new() -> Self {
        Self { times: Vec::new() }
    }
}

pub struct Safety {
    max_attempts: u32,
    window_secs: u64,
    panic_threshold: u32,
    panic_window_secs: u64,

    attempts: HashMap<String, AttemptLog>,
    quarantine: HashMap<String, bool>,
    death_times: Vec<u64>,
    panic: bool,
    plan_disable_all: bool,

    // Per-target circuit breaker state.
    crash_logs: HashMap<String, CrashLog>, // process → crash log
    breaker_threshold: u32,
    breaker_window_secs: u64,
    breaker_threshold_ss: u32, // system_server conservative
    degraded_targets: HashMap<String, bool>,
}

impl Safety {
    pub fn new() -> Self {
        Self::with_params(
            config::SAFETY_MAX_ATTEMPTS,
            (config::SAFETY_WINDOW_MIN as u64) * 60,
            config::SAFETY_PANIC_THRESHOLD,
            config::SAFETY_PANIC_WINDOW_SEC as u64,
            config::BREAKER_THRESHOLD,
            config::BREAKER_WINDOW_SEC as u64,
            config::BREAKER_THRESHOLD_SYSTEM_SERVER,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_params(
        max_attempts: u32,
        window_secs: u64,
        panic_threshold: u32,
        panic_window_secs: u64,
        breaker_threshold: u32,
        breaker_window_secs: u64,
        breaker_threshold_ss: u32,
    ) -> Self {
        Self {
            max_attempts,
            window_secs,
            panic_threshold,
            panic_window_secs,
            attempts: HashMap::new(),
            quarantine: HashMap::new(),
            death_times: Vec::with_capacity(panic_threshold.max(8) as usize),
            panic: false,
            plan_disable_all: false,
            crash_logs: HashMap::new(),
            breaker_threshold,
            breaker_window_secs,
            breaker_threshold_ss,
            degraded_targets: HashMap::new(),
        }
    }

    /// Record an attempt and decide whether it's allowed.
    /// Over budget within the window → quarantine (fail-open).
    pub fn allow_attempt(&mut self, agent: &str, process: &str) -> bool {
        if self.panic {
            return false;
        }
        // Circuit breaker: if this target is degraded, deny.
        if self.degraded_targets.contains_key(process) {
            return false;
        }
        let k = key(agent, process);
        if self.quarantine.contains_key(&k) {
            return false;
        }

        let now = now_secs();
        let log = self
            .attempts
            .entry(k.clone())
            .or_insert_with(|| AttemptLog::new(self.max_attempts as usize));

        if now < log.next_allowed {
            return false;
        }

        // Sliding-window count.
        let cutoff = now.saturating_sub(self.window_secs);
        let count = log.times.iter().filter(|&&t| t >= cutoff).count() as u32;

        if count >= self.max_attempts {
            self.quarantine.insert(k, true);
            return false;
        }

        // Append to ring (cap at max_attempts).
        if log.times.len() >= self.max_attempts as usize {
            log.times.remove(0); // shift oldest
        }
        log.times.push(now);
        true
    }

    /// Call after a failed inject to arm exponential backoff.
    pub fn note_failure(&mut self, agent: &str, process: &str) {
        let k = key(agent, process);
        let Some(log) = self.attempts.get_mut(&k) else {
            return;
        };
        let now = now_secs();
        if log.backoff_step < 31 {
            log.backoff_step += 1;
        }
        let shift = (log.backoff_step.saturating_sub(1)).min(30);
        let mut delay = 1u64 << shift;
        if delay > MAX_BACKOFF_SECS {
            delay = MAX_BACKOFF_SECS;
        }
        log.next_allowed = now + delay;
    }

    /// Call after a successful injection to reset backoff (NOT the attempt ring).
    pub fn note_success(&mut self, agent: &str, process: &str) {
        let k = key(agent, process);
        if let Some(log) = self.attempts.get_mut(&k) {
            log.backoff_step = 0;
            log.next_allowed = 0;
        }
    }

    pub fn is_quarantined(&self, agent: &str, process: &str) -> bool {
        self.panic || self.quarantine.contains_key(&key(agent, process))
    }

    pub fn is_target_degraded(&self, process: &str) -> bool {
        self.degraded_targets.contains_key(process)
    }

    /// Drop daemon-lifetime safety state that is no longer reachable from a
    /// current or retained resident catalog. Signed catalogs bound each
    /// individual release, but without this cutover pruning an unlimited
    /// sequence of releases could retain obsolete identities forever.
    pub fn retain_authorities<'a>(
        &mut self,
        authorities: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) {
        let mut agent_processes = std::collections::HashSet::new();
        let mut processes = std::collections::HashSet::new();
        for (agent, process) in authorities {
            processes.insert(process.to_string());
            agent_processes.insert(key(agent, process));
        }
        self.attempts
            .retain(|identity, _| agent_processes.contains(identity));
        self.quarantine
            .retain(|identity, _| agent_processes.contains(identity));
        self.crash_logs
            .retain(|process, _| processes.contains(process));
        self.degraded_targets
            .retain(|process, _| processes.contains(process));
    }

    // ---- Circuit breaker ----

    /// Record a target crash for the circuit breaker.
    /// If M crashes within N seconds, the target goes degraded.
    pub fn note_target_crash(&mut self, process: &str) {
        let now = now_secs();
        let threshold = if process == "system_server" {
            self.breaker_threshold_ss
        } else {
            self.breaker_threshold
        };

        let crash_log = self
            .crash_logs
            .entry(process.to_string())
            .or_insert_with(CrashLog::new);

        // Prune old entries outside the window.
        let cutoff = now.saturating_sub(self.breaker_window_secs);
        crash_log.times.retain(|&t| t >= cutoff);
        crash_log.times.push(now);

        if crash_log.times.len() as u32 >= threshold {
            self.degraded_targets.insert(process.to_string(), true);
            log::err(
                "safety",
                &format!(
                    "circuit breaker tripped for {process} (crashes={})",
                    crash_log.times.len()
                ),
            );
        }
    }

    // ---- Global panic ----

    /// Count a target death for the global panic-quarantine.
    pub fn note_target_death(&mut self) {
        let now = now_secs();
        self.death_times.push(now);

        // Prune old deaths outside the panic window.
        let cutoff = now.saturating_sub(self.panic_window_secs);
        self.death_times.retain(|&t| t >= cutoff);

        if self.death_times.len() as u32 >= self.panic_threshold {
            self.panic = true;
            log::err(
                "safety",
                &format!(
                    "panic-quarantine tripped (deaths={})",
                    self.death_times.len()
                ),
            );
        }
    }

    pub fn clear_panic(&mut self) {
        self.panic = false;
        self.death_times.clear();
    }

    pub fn panic_quarantined(&self) -> bool {
        self.panic
    }

    // ---- Kill-switch ----

    pub fn set_plan_disable_all(&mut self, value: bool) {
        self.plan_disable_all = value;
    }

    pub fn kill_switch_active(&self) -> bool {
        if self.plan_disable_all {
            return true;
        }
        std::path::Path::new(&config::kill_switch_file()).exists()
    }
}

impl Default for Safety {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn safety() -> Safety {
        Safety::with_params(3, 30, 8, 300, 3, 30, 2)
    }

    #[test]
    fn allow_attempt_permits_below_threshold() {
        let mut s = safety();
        assert!(s.allow_attempt("a", "p"));
    }

    #[test]
    fn note_failure_sets_backoff() {
        let mut s = safety();
        assert!(s.allow_attempt("a", "p"));
        s.note_failure("a", "p");
        // Immediately after a failure, backoff is active (1 second)
        assert!(!s.allow_attempt("a", "p"));
    }

    #[test]
    fn note_success_clears_backoff_for_agent() {
        let mut s = safety();
        s.note_failure("a", "p");
        s.note_failure("a", "p");
        s.note_success("a", "p");
        assert!(s.allow_attempt("a", "p"));
    }

    #[test]
    fn is_target_degraded_after_crash_threshold() {
        let mut s = safety();
        // breaker_threshold=3 for normal targets
        s.note_target_crash("p");
        s.note_target_crash("p");
        s.note_target_crash("p");
        assert!(s.is_target_degraded("p"));
    }

    #[test]
    fn is_quarantined_false_for_unknown_agent() {
        let s = safety();
        assert!(!s.is_quarantined("unknown", "p"));
    }

    #[test]
    fn kill_switch_active_when_plan_disable_all() {
        let mut s = safety();
        assert!(!s.kill_switch_active());
        s.set_plan_disable_all(true);
        assert!(s.kill_switch_active());
    }

    #[test]
    fn catalog_pruning_bounds_rotated_identities_and_preserves_active_state() {
        let mut safety = Safety::with_params(1, 30, 8, 300, 1, 30, 1);
        for index in 0..128 {
            let id = format!("agent-{index}");
            let process = format!("process.{index}");
            assert!(safety.allow_attempt(&id, &process));
            assert!(!safety.allow_attempt(&id, &process));
            safety.note_target_crash(&process);
        }
        assert!(safety.allow_attempt("active-agent", "active.process"));
        safety.note_target_crash("active.process");
        assert!(safety.allow_attempt("resident-agent", "resident.process"));
        safety.note_target_crash("resident.process");

        safety.retain_authorities([
            ("active-agent", "active.process"),
            ("resident-agent", "resident.process"),
        ]);
        assert_eq!(safety.attempts.len(), 2);
        assert_eq!(safety.crash_logs.len(), 2);
        assert!(safety.is_target_degraded("active.process"));
        assert!(safety.is_target_degraded("resident.process"));
        assert!(!safety.is_target_degraded("process.127"));
    }
}
