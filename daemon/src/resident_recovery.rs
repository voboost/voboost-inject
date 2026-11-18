//! Bounded transport-only recovery for an already mapped implant.
//! A failed rebind never authorizes replay of Java bootstrap side effects.
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Identity {
    pub pid: i32,
    pub starttime: u64,
    pub generation: String,
    pub catalog: String,
    pub semantics: String,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Admission {
    Ready,
    Backoff,
    Exhausted,
}
pub(crate) struct Recovery {
    identity: Identity,
    attempts: u8,
    next: Duration,
}
impl Recovery {
    pub fn new(identity: Identity) -> Self {
        Self {
            identity,
            attempts: 0,
            next: Duration::ZERO,
        }
    }
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    pub fn bind(&mut self, identity: Identity) {
        if self.identity != identity {
            *self = Self::new(identity);
        }
    }
    pub fn admit(&self, now: Duration) -> Admission {
        if now < self.next && self.attempts >= 3 {
            Admission::Exhausted
        } else if now < self.next {
            Admission::Backoff
        } else {
            Admission::Ready
        }
    }
    pub fn attempted(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
        self.next = Duration::MAX;
    }
    pub fn failed(&mut self, now: Duration) {
        self.next = now.saturating_add(Duration::from_secs(match self.attempts {
            0 | 1 => 1,
            2 => 5,
            _ => 60,
        }));
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn identity() -> Identity {
        Identity {
            pid: 2866,
            starttime: 931,
            generation: "739dccc4".into(),
            catalog: "4a8e9e50".into(),
            semantics: "font-cyrillic".into(),
        }
    }
    #[test]
    fn captured_1600_failure_storm_is_bounded_without_bootstrap_replay() {
        let mut recovery = Recovery::new(identity());
        let mut calls = 0;
        for poll in 0..1600 {
            let now = Duration::from_millis(poll * 215);
            if recovery.admit(now) == Admission::Ready {
                recovery.attempted();
                recovery.failed(now + Duration::from_millis(200));
                calls += 1;
            }
        }
        assert!((3..=9).contains(&calls));
        assert_eq!(recovery.admit(Duration::from_secs(600)), Admission::Ready);
    }
    #[test]
    fn transient_rebind_rearms_slowly_for_same_identity() {
        let mut r = Recovery::new(identity());
        for now in [0, 1, 6] {
            assert_eq!(r.admit(Duration::from_secs(now)), Admission::Ready);
            r.attempted();
            r.failed(Duration::from_secs(now));
        }
        assert_ne!(r.admit(Duration::from_secs(65)), Admission::Ready);
        assert_eq!(r.admit(Duration::from_secs(66)), Admission::Ready);
        r.attempted();
        r.failed(Duration::from_secs(67));
        assert_ne!(r.admit(Duration::from_secs(126)), Admission::Ready);
        assert_eq!(r.admit(Duration::from_secs(127)), Admission::Ready);
    }

    #[test]
    fn retry_waits_from_completion_then_enters_slow_cooldown() {
        let mut r = Recovery::new(identity());
        r.attempted();
        r.failed(Duration::from_secs(17));
        assert_eq!(r.admit(Duration::from_millis(17999)), Admission::Backoff);
        assert_eq!(r.admit(Duration::from_secs(18)), Admission::Ready);
        r.attempted();
        r.failed(Duration::from_secs(19));
        assert_eq!(r.admit(Duration::from_millis(23999)), Admission::Backoff);
        assert_eq!(r.admit(Duration::from_secs(24)), Admission::Ready);
        r.attempted();
        r.failed(Duration::from_secs(25));
        assert_eq!(r.admit(Duration::from_secs(84)), Admission::Exhausted);
        assert_eq!(r.admit(Duration::from_secs(85)), Admission::Ready);
    }
    #[test]
    fn every_identity_field_fences_budget_and_identical_identity_cannot_reset_it() {
        let original = identity();
        let changes = [
            Identity {
                pid: 2867,
                ..original.clone()
            },
            Identity {
                starttime: 932,
                ..original.clone()
            },
            Identity {
                generation: "next".into(),
                ..original.clone()
            },
            Identity {
                catalog: "next".into(),
                ..original.clone()
            },
            Identity {
                semantics: "disabled".into(),
                ..original.clone()
            },
        ];
        for changed in changes {
            let mut r = Recovery::new(original.clone());
            for _ in 0..3 {
                r.attempted();
                r.failed(Duration::ZERO);
            }
            r.bind(original.clone());
            assert_eq!(r.admit(Duration::from_secs(59)), Admission::Exhausted);
            assert_eq!(r.admit(Duration::from_secs(60)), Admission::Ready);
            r.bind(changed);
            assert_eq!(r.admit(Duration::ZERO), Admission::Ready);
        }
    }
    #[test]
    fn targets_have_independent_budgets() {
        let mut navi = Recovery::new(identity());
        for _ in 0..3 {
            navi.attempted();
        }
        let vehicle = Recovery::new(Identity {
            pid: 2000,
            ..identity()
        });
        assert_eq!(navi.admit(Duration::ZERO), Admission::Exhausted);
        assert_eq!(vehicle.admit(Duration::ZERO), Admission::Ready);
    }
}
