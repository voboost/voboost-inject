//! Bounded preparation diagnostics only. No admission, status-wire or clock
//! conversion semantics live here; all timing is the existing owner's Instant.
use crate::startup::Identity;
use std::collections::{HashMap, HashSet};
use std::time::Instant;
const MAX_ATTEMPTS: u32 = 8;
const MAX_SAFE_MS: u64 = 9_007_199_254_740_991;
#[derive(Clone, Debug)]
struct Observation {
    pid: i32,
    starttime: u64,
    begin: u64,
    end: u64,
    attempts: u32,
    available: bool,
}
#[derive(Default)]
pub(crate) struct Preparation {
    observed: HashMap<String, Observation>,
}
#[derive(Clone, Copy, Debug)]
pub(crate) enum Stage {
    Maps,
    Authority,
    Desired,
    Bootstrap,
    Payload,
    FinalAttestation,
    Dispatch,
    Rebind,
}
impl Stage {
    fn label(self) -> &'static str {
        match self {
            Self::Maps => "maps",
            Self::Authority => "authority",
            Self::Desired => "desired",
            Self::Bootstrap => "bootstrap",
            Self::Payload => "payload",
            Self::FinalAttestation => "final-attestation",
            Self::Dispatch => "dispatch",
            Self::Rebind => "rebind",
        }
    }
}
pub(crate) struct Attempt {
    identity: Identity,
    process: String,
    observation: Observation,
    attempt: u32,
    begin: u64,
    end: Option<u64>,
    stage: Stage,
    owner_started: Instant,
    completed: bool,
    matched: bool,
}
impl Preparation {
    pub(crate) fn observe(
        &mut self,
        targets: &[(String, i32, u64)],
        allowed: &[String],
        begin: u64,
        end: u64,
    ) {
        let present: HashSet<_> = allowed.iter().map(String::as_str).collect();
        self.observed
            .retain(|process, _| present.contains(process.as_str()));
        for old in self.observed.values_mut() {
            old.available = false;
        }
        if begin > end || end > MAX_SAFE_MS {
            return;
        }
        for (process, pid, starttime) in targets {
            if !present.contains(process.as_str()) || *pid <= 1 || *starttime == 0 {
                continue;
            }
            if let Some(old) = self.observed.get_mut(process) {
                if old.pid == *pid && old.starttime == *starttime {
                    old.available = true;
                    continue;
                }
            }
            self.observed.insert(
                process.clone(),
                Observation {
                    pid: *pid,
                    starttime: *starttime,
                    begin,
                    end,
                    attempts: 0,
                    available: true,
                },
            );
        }
    }
    pub(crate) fn begin(
        &mut self,
        identity: Identity,
        process: &str,
        pid: i32,
        begin: u64,
        owner_started: Instant,
    ) -> Option<Attempt> {
        let observed = self.observed.get_mut(process)?;
        if !observed.available
            || observed.pid != pid
            || observed.end > begin
            || begin > MAX_SAFE_MS
            || observed.attempts >= MAX_ATTEMPTS
        {
            return None;
        }
        observed.attempts += 1;
        Some(Attempt {
            identity,
            process: process.into(),
            observation: observed.clone(),
            attempt: observed.attempts,
            begin,
            end: None,
            stage: Stage::Maps,
            owner_started,
            completed: false,
            matched: true,
        })
    }
}
impl Attempt {
    pub(crate) fn stage(attempt: &mut Option<Self>, stage: Stage) {
        if let Some(attempt) = attempt {
            attempt.stage = stage;
        }
    }
    pub(crate) fn bind(attempt: &mut Option<Self>, starttime: u64) {
        if let Some(attempt) = attempt {
            attempt.matched &= attempt.observation.starttime == starttime;
        }
    }
    pub(crate) fn ready(attempt: &mut Option<Self>, end: u64) {
        if let Some(attempt) = attempt {
            attempt.end = Some(end);
            if !matches!(attempt.stage, Stage::Rebind) {
                attempt.stage = Stage::Dispatch;
            }
        }
    }
    pub(crate) fn cancel(attempt: &mut Option<Self>) {
        if let Some(attempt) = attempt {
            attempt.completed = true;
        }
    }
    pub(crate) fn accepted(
        attempt: &mut Option<Self>,
        rebind: bool,
        dispatch: Option<u64>,
        accepted: u64,
    ) {
        if let Some(attempt) = attempt {
            attempt.completed = true;
            let Some(dispatch) = dispatch else {
                return;
            };
            let end = attempt.end.unwrap_or(dispatch);
            let stage = if rebind {
                Stage::Rebind
            } else {
                Stage::Dispatch
            };
            if let Some(fields) = attempt.fields(
                if rebind { "rebind" } else { "dispatched" },
                stage,
                end,
                Some((dispatch, accepted)),
            ) {
                crate::log::info_fields("startup", "startup.preparation", fields);
            }
        }
    }
    fn fields(
        &self,
        outcome: &str,
        stage: Stage,
        end: u64,
        dispatch: Option<(u64, u64)>,
    ) -> Option<HashMap<String, String>> {
        if !self.matched
            || self.observation.begin > self.observation.end
            || self.observation.end > self.begin
            || self.begin > end
            || end > MAX_SAFE_MS
        {
            return None;
        }
        if let Some((dispatch, accepted)) = dispatch {
            if end > dispatch || dispatch > accepted || accepted > MAX_SAFE_MS {
                return None;
            }
        }
        let mut fields = HashMap::from([
            ("schemaVersion".into(), "1".into()),
            (
                "clockDomain".into(),
                "daemon.monotonicSinceOwnerStart".into(),
            ),
            ("bootId".into(), self.identity.boot_id.clone()),
            ("daemonPid".into(), self.identity.daemon_pid.to_string()),
            (
                "daemonStarttime".into(),
                self.identity.daemon_starttime.to_string(),
            ),
            (
                "manifestSha256".into(),
                self.identity.manifest_sha256.clone(),
            ),
            ("generationId".into(), self.identity.generation_id.clone()),
            ("catalogSha256".into(), self.identity.catalog_sha256.clone()),
            ("process".into(), self.process.clone()),
            ("targetPid".into(), self.observation.pid.to_string()),
            (
                "targetStarttime".into(),
                self.observation.starttime.to_string(),
            ),
            ("attempt".into(), self.attempt.to_string()),
            (
                "observedScanBeginMs".into(),
                self.observation.begin.to_string(),
            ),
            ("observedScanEndMs".into(), self.observation.end.to_string()),
            ("preflightBeginMs".into(), self.begin.to_string()),
            ("preflightEndMs".into(), end.to_string()),
            ("outcome".into(), outcome.into()),
            ("stage".into(), stage.label().into()),
        ]);
        if let Some((dispatch, accepted)) = dispatch {
            fields.insert("dispatchMs".into(), dispatch.to_string());
            fields.insert("dispatchAcceptedMs".into(), accepted.to_string());
        }
        Some(fields)
    }
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let end = self.owner_started.elapsed().as_millis().try_into().ok();
        if let Some(fields) = end.and_then(|end| self.fields("failed", self.stage, end, None)) {
            crate::log::info_fields("startup", "startup.preparation", fields);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn identity() -> Identity {
        Identity {
            boot_id: "11111111-1111-4111-8111-111111111111".into(),
            daemon_pid: 42,
            daemon_starttime: 100,
            manifest_sha256: "a".repeat(64),
            generation_id: "b".repeat(64),
            catalog_sha256: "c".repeat(64),
        }
    }
    fn observed() -> Preparation {
        let mut p = Preparation::default();
        p.observe(&[("target".into(), 50, 200)], &["target".into()], 10, 12);
        p
    }
    #[test]
    fn full_preflight_is_not_zero_legacy_ready_to_dispatch() {
        let directory = tempfile::tempdir().unwrap();
        let logs = directory.path().join("logs");
        crate::canonical_log::with_test_log(&logs, || {
            let mut p = observed();
            let mut attempt = p.begin(identity(), "target", 50, 15, Instant::now());
            // Controlled owner samples model 100ms of preparation without sleeping.
            Attempt::bind(&mut attempt, 200);
            Attempt::ready(&mut attempt, 115);
            Attempt::accepted(&mut attempt, false, Some(115), 116);
        });
        let bytes = std::fs::read(logs.join("segment-active.jsonl")).unwrap();
        let record: crate::canonical_log::CanonicalRecord = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(record.source.kind, "daemon");
        assert_eq!(record.component, "startup");
        assert_eq!(record.message, "startup.preparation");
        let f = &record.fields;
        let millis = |name: &str| f[name].parse::<u64>().unwrap();
        assert_eq!(f.len(), 20);
        assert_eq!(millis("preflightEndMs") - millis("preflightBeginMs"), 100);
        assert_eq!(millis("dispatchMs") - millis("observedScanEndMs"), 103);
        assert_eq!(millis("dispatchMs") - millis("preflightEndMs"), 0);
        assert_eq!(millis("dispatchAcceptedMs"), 116);
        if let Ok(path) = std::env::var("VOBOOST_STARTUP_PREPARATION_FIXTURE") {
            std::fs::write(path, &bytes).unwrap();
        }
    }
    #[test]
    fn failed_preflight_emits_closed_failure_through_real_log_sink() {
        let directory = tempfile::tempdir().unwrap();
        let logs = directory.path().join("logs");
        crate::canonical_log::with_test_log(&logs, || {
            let started = Instant::now() - std::time::Duration::from_millis(20);
            let mut p = observed();
            let mut attempt = p.begin(identity(), "target", 50, 15, started);
            Attempt::stage(&mut attempt, Stage::Payload);
            drop(attempt);
        });
        let bytes = std::fs::read(logs.join("segment-active.jsonl")).unwrap();
        let record: crate::canonical_log::CanonicalRecord = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(record.fields["outcome"], "failed");
        assert_eq!(record.fields["stage"], "payload");
        assert_eq!(record.fields.len(), 18);
        assert!(!record.fields.contains_key("dispatchMs"));
        assert!(!record.fields.contains_key("dispatchAcceptedMs"));
    }
    #[test]
    fn observation_is_first_and_identity_reuse_does_not_inherit_it() {
        let mut p = observed();
        p.observe(&[("target".into(), 50, 200)], &["target".into()], 100, 110);
        let mut a = p
            .begin(identity(), "target", 50, 115, Instant::now())
            .unwrap();
        a.completed = true;
        assert_eq!((a.observation.begin, a.observation.end), (10, 12));
        p.observe(&[("target".into(), 50, 201)], &["target".into()], 120, 125);
        let mut b = p
            .begin(identity(), "target", 50, 130, Instant::now())
            .unwrap();
        b.completed = true;
        assert_eq!(
            (b.observation.begin, b.observation.end, b.attempt),
            (120, 125, 1)
        );
        p.observe(&[], &["target".into()], 140, 145);
        assert!(p
            .begin(identity(), "target", 50, 150, Instant::now())
            .is_none());
    }
    #[test]
    fn failures_and_mismatched_unsafe_clocks_never_claim_dispatch() {
        let mut p = observed();
        let mut a = p
            .begin(identity(), "target", 50, 15, Instant::now())
            .unwrap();
        a.completed = true;
        let failed = a.fields("failed", Stage::Payload, 20, None).unwrap();
        assert!(!failed.contains_key("dispatchMs"));
        assert!(!failed.contains_key("dispatchAcceptedMs"));
        assert!(a
            .fields("dispatched", Stage::Dispatch, 14, Some((15, 16)))
            .is_none());
        assert!(a
            .fields("dispatched", Stage::Dispatch, 20, Some((19, 21)))
            .is_none());
        assert!(a
            .fields(
                "dispatched",
                Stage::Dispatch,
                20,
                Some((21, MAX_SAFE_MS + 1))
            )
            .is_none());
        a.matched = false;
        assert!(a
            .fields("dispatched", Stage::Dispatch, 20, Some((21, 22)))
            .is_none());
    }
    #[test]
    fn inventory_is_signed_and_missing_observation_is_unavailable() {
        let mut p = Preparation::default();
        let allowed = vec!["target".into()];
        p.observe(&[("untrusted".into(), 50, 200)], &allowed, 10, 12);
        assert!(p.observed.is_empty());
        assert!(p
            .begin(identity(), "target", 50, 15, Instant::now())
            .is_none());
        p.observe(&[("target".into(), 50, 200)], &allowed, 10, 12);
        p.observe(&[], &allowed, 20, 22);
        assert!(p
            .begin(identity(), "target", 50, 25, Instant::now())
            .is_none());
        // A temporary unreadable scan cannot reset first observation or retry budget.
        p.observe(&[("target".into(), 50, 200)], &allowed, 30, 32);
        let mut a = p
            .begin(identity(), "target", 50, 35, Instant::now())
            .unwrap();
        assert_eq!((a.observation.begin, a.observation.end), (10, 12));
        a.completed = true;
        p.observe(&[], &[], 40, 42);
        assert!(p.observed.is_empty());
    }
    #[test]
    fn final_identity_replacement_suppresses_attempt_and_rebind_keeps_stage() {
        let mut p = observed();
        let mut a = p.begin(identity(), "target", 50, 15, Instant::now());
        Attempt::bind(&mut a, 201);
        Attempt::ready(&mut a, 115);
        let a = a.as_mut().unwrap();
        assert!(a
            .fields("dispatched", Stage::Dispatch, 115, Some((115, 116)))
            .is_none());
        assert!(a
            .fields("failed", Stage::FinalAttestation, 115, None)
            .is_none());
        a.completed = true;
        let mut b = p.begin(identity(), "target", 50, 16, Instant::now());
        Attempt::stage(&mut b, Stage::Rebind);
        Attempt::ready(&mut b, 116);
        let b = b.as_mut().unwrap();
        let failure = b.fields("failed", b.stage, 117, None).unwrap();
        assert_eq!(failure["stage"], "rebind");
        assert_eq!(failure.len(), 18);
        b.completed = true;
    }
    #[test]
    fn retry_attempts_are_bounded_but_first_observation_is_stable() {
        let mut p = observed();
        for attempt in 1..=MAX_ATTEMPTS {
            let mut a = p
                .begin(identity(), "target", 50, 15, Instant::now())
                .unwrap();
            assert_eq!(a.attempt, attempt);
            assert_eq!(a.observation.end, 12);
            a.completed = true;
        }
        assert!(p
            .begin(identity(), "target", 50, 15, Instant::now())
            .is_none());
    }
}
