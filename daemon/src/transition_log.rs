//! Bounded owner-local log episodes. Observations never delay or skip work.
use std::collections::HashMap;
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Observation {
    Pending,
    Complete,
}

impl From<bool> for Observation {
    fn from(complete: bool) -> Self {
        if complete {
            Self::Complete
        } else {
            Self::Pending
        }
    }
}

#[derive(Clone, Debug)]
struct Episode {
    identity: String,
    reason: String,
    failed: bool,
    started: Instant,
    repeats: u64,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Transitions {
    episodes: HashMap<String, Episode>,
}

impl Transitions {
    pub(crate) fn contains(&self, scope: &str) -> bool {
        self.episodes.contains_key(scope)
    }

    pub(crate) fn clear(&mut self) {
        self.episodes.clear();
    }

    pub(crate) fn waiting(&mut self, scope: &str, identity: &str, reason: &str) {
        self.observe(scope, identity, reason, false);
    }

    pub(crate) fn failed(&mut self, scope: &str, identity: &str, reason: &str) {
        self.failed_changed(scope, identity, reason);
    }

    pub(crate) fn failed_changed(&mut self, scope: &str, identity: &str, reason: &str) -> bool {
        self.observe(scope, identity, reason, true)
    }

    pub(crate) fn result(&mut self, scope: &str, identity: &str, result: Result<(), &str>) {
        match result {
            Ok(()) => self.resolved(scope),
            Err("operation busy") => self.waiting(scope, identity, "operation busy"),
            Err(error) => {
                self.failed(scope, identity, error);
            }
        }
    }

    pub(crate) fn completion(
        &mut self,
        scope: &str,
        identity: &str,
        result: Result<Observation, &str>,
    ) {
        match result {
            Ok(Observation::Pending) => {}
            Ok(Observation::Complete) => self.resolved(scope),
            Err(error) => self.result(scope, identity, Err(error)),
        }
    }

    pub(crate) fn resolved(&mut self, scope: &str) {
        if let Some(previous) = self.episodes.remove(scope) {
            crate::log::debug(
                scope,
                &format!(
                    "observation recovered; previous={} suppressed={} elapsedMs={}",
                    previous.reason,
                    previous.repeats,
                    previous.started.elapsed().as_millis()
                ),
            );
        }
    }

    fn observe(&mut self, scope: &str, identity: &str, reason: &str, failed: bool) -> bool {
        if let Some(previous) = self.episodes.get_mut(scope) {
            if previous.identity == identity
                && previous.reason == reason
                && previous.failed == failed
            {
                previous.repeats = previous.repeats.saturating_add(1);
                return false;
            }
        }
        // Arbitrarily large/new contexts are still emitted, but never retained.
        // This keeps logging memory bounded without suppressing distinct errors.
        if scope.len() <= 128
            && identity.len() <= 1024
            && reason.len() <= 4096
            && (self.episodes.contains_key(scope) || self.episodes.len() < 32)
        {
            self.episodes.insert(
                scope.into(),
                Episode {
                    identity: identity.into(),
                    reason: reason.into(),
                    failed,
                    started: Instant::now(),
                    repeats: 0,
                },
            );
        } else {
            self.episodes.remove(scope);
        }
        if failed {
            crate::log::err(scope, reason);
        } else {
            crate::log::debug(scope, reason);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waits_are_bounded_change_only_and_independent_errors_are_preserved() {
        let root = tempfile::tempdir().unwrap();
        crate::canonical_log::with_test_log(&root.path().join("logs"), || {
            let mut gates = Transitions::default();
            for _ in 0..1000 {
                gates.waiting("owner-a", "generation-a", "operation busy");
            }
            assert_eq!(gates.episodes["owner-a"].repeats, 999);
            gates.failed("owner-a", "generation-a", "operation busy: cleanup failed");
            assert!(gates.episodes["owner-a"].failed);
            gates.failed("owner-b", "generation-a", "permission denied");
            assert_eq!(gates.episodes.len(), 2);
            gates.failed("owner-a", "generation-b", "permission denied");
            assert_eq!(gates.episodes["owner-a"].identity, "generation-b");
            gates.resolved("owner-a");
            assert!(!gates.contains("owner-a"));
            gates.waiting("owner-a", "generation-b", "operation busy");
            assert_eq!(gates.episodes["owner-a"].repeats, 0);
        });
    }

    #[test]
    fn repeated_uninstall_failures_record_only_changes_and_rearm_after_recovery() {
        let root = tempfile::tempdir().unwrap();
        let logs = root.path().join("logs");
        let mut writes = 0;
        crate::canonical_log::with_test_log(&logs, || {
            let mut observations = Transitions::default();
            for reason in [
                "rollback failed",
                "rollback failed",
                "other failure",
                "other failure",
            ] {
                if observations.failed_changed("uninstall-prepare", "generation", reason) {
                    writes += 1;
                }
            }
            for _ in 0..100 {
                observations.failed("uninstall-result", "generation", "publication denied");
            }
            observations.resolved("uninstall-result");
            observations.resolved("uninstall-prepare");
            if observations.failed_changed("uninstall-prepare", "generation", "other failure") {
                writes += 1;
            }
        });
        assert_eq!(writes, 3);
        let bytes = std::fs::read_to_string(logs.join("segment-active.jsonl")).unwrap();
        let rows: Vec<serde_json::Value> = bytes
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(rows.iter().filter(|row| row["level"] == "error").count(), 4);
        assert_eq!(
            rows.iter()
                .filter(|row| row["message"].as_str().unwrap().contains("recovered"))
                .count(),
            2
        );
    }

    #[test]
    fn completion_requires_terminal_success_and_rearms_after_recovery() {
        let root = tempfile::tempdir().unwrap();
        let logs = root.path().join("logs");
        crate::canonical_log::with_test_log(&logs, || {
            let mut observations = Transitions::default();
            observations.completion("apk", "generation:interface", Err("permission denied"));
            for _ in 0..100 {
                observations.completion("apk", "generation:interface", Ok(Observation::Pending));
            }
            observations.completion("apk", "generation:interface", Err("permission denied"));
            assert!(observations.contains("apk"));
            observations.completion("apk", "generation:interface", Ok(Observation::Complete));
            assert!(!observations.contains("apk"));
            observations.completion("apk", "generation:interface", Err("permission denied"));
            observations.completion("apk", "generation:hidden", Err("permission denied"));
        });
        let bytes = std::fs::read_to_string(logs.join("segment-active.jsonl")).unwrap();
        let rows = bytes
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 4);
        assert_eq!(rows.iter().filter(|row| row["level"] == "error").count(), 3);
        assert_eq!(
            rows.iter()
                .filter(|row| row["message"].as_str().unwrap().contains("recovered"))
                .count(),
            1
        );
    }
}
