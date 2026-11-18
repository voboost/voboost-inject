//! Suspend-aware observation age on Linux/Android; host-only tests retain monotonic time.
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Stamp {
    pub(super) at: Instant,
    pub(super) boot_ms: Option<u64>,
}

impl Stamp {
    pub(super) fn now() -> Self {
        Self {
            at: Instant::now(),
            boot_ms: crate::startup::boot_ms().ok(),
        }
    }
    fn age(self, now: Self) -> Option<Duration> {
        match (self.boot_ms, now.boot_ms) {
            (Some(before), Some(after)) => after.checked_sub(before).map(Duration::from_millis),
            (None, None) => now.at.checked_duration_since(self.at),
            _ => None,
        }
    }
    pub(super) fn fresh(self, limit: Duration) -> bool {
        self.fresh_at(Self::now(), limit)
    }
    pub(super) fn fresh_at(self, now: Self, limit: Duration) -> bool {
        self.age(now).is_some_and(|age| age <= limit)
    }
    pub(super) fn interrupted(self, now: Self) -> bool {
        let Some(age) = self.age(now) else {
            return true;
        };
        let Some(monotonic) = now.at.checked_duration_since(self.at) else {
            return true;
        };
        age > monotonic.saturating_add(Duration::from_millis(100))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn suspend_age_and_clock_regression_never_preserve_old_observation_freshness() {
        let now = Instant::now();
        let before = Stamp {
            at: now,
            boot_ms: Some(1000),
        };
        let after = Stamp {
            at: now + Duration::from_millis(1),
            boot_ms: Some(61001),
        };
        assert_eq!(before.age(after), Some(Duration::from_millis(60001)));
        assert!(before.interrupted(after));
        assert!(after.interrupted(before));
        assert!(!before.interrupted(Stamp {
            at: now + Duration::from_secs(1),
            boot_ms: Some(2000)
        }));
    }
}
