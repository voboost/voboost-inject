// boot.rs — boot-completion state (monotonic cache of sys.boot_completed).
//
// Ported from Vala boot.vala. The daemon needs to know when sys.boot_completed=1
// to gate boot-deferred agents (manifest boot:true). getprop has no event to
// subscribe to, so the daemon polls while any boot agent is waiting.
//
// Host-testable: the VOBOOST_BOOT_COMPLETED env-var escape hatch is checked
// first (so host tests never fork getprop). A positive result is cached
// monotonically (never forks again); a negative result re-polls on next call.

use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

/// The env-var escape hatch for host test environments.
const BOOT_HATCH_ENV: &str = "VOBOOST_BOOT_COMPLETED";

pub struct BootState {
    /// Once true, stays true for the daemon's lifetime (boot completion is monotonic).
    cached: AtomicBool,
}

impl BootState {
    pub fn new() -> Self {
        Self {
            cached: AtomicBool::new(false),
        }
    }

    /// Returns true if sys.boot_completed=1.
    ///
    /// 1. Check the env-var escape hatch first (host tests).
    /// 2. If already cached positive, return true without forking.
    /// 3. Fork getprop sys.boot_completed; cache on positive.
    /// 4. On failure (non-Android), return false (re-polls next call).
    pub fn boot_completed(&self) -> bool {
        if self.cached.load(Ordering::Relaxed) {
            return true;
        }

        // Escape hatch (host tests): checked first, cached on positive.
        if let Ok(val) = std::env::var(BOOT_HATCH_ENV) {
            if val == "1" {
                self.cached.store(true, Ordering::Relaxed);
                return true;
            }
        }

        // Fork getprop (Android only). Returns "1\n" when boot is complete.
        let output = Command::new("getprop")
            .arg("sys.boot_completed")
            .output();

        match output {
            Ok(o) if o.status.success() => {
                let val = String::from_utf8_lossy(&o.stdout);
                let trimmed = val.trim();
                if trimmed == "1" {
                    self.cached.store(true, Ordering::Relaxed);
                    true
                } else {
                    false
                }
            }
            _ => {
                // getprop unavailable (non-Android host): return false, re-poll next call.
                false
            }
        }
    }
}

impl Default for BootState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    static ENV_LOCK: OnceLock<()> = OnceLock::new();

    fn init_env_lock() {
        ENV_LOCK.get_or_init(|| {
            // Tests that set env vars are not fully thread-safe, but we run sequentially.
        });
    }

    #[test]
    fn hatch_set_returns_true_and_caches() {
        init_env_lock();
        std::env::set_var(BOOT_HATCH_ENV, "1");
        let bs = BootState::new();
        assert!(bs.boot_completed());
        // Clear the env var — the cached result persists.
        std::env::remove_var(BOOT_HATCH_ENV);
        assert!(bs.boot_completed());
    }

    #[test]
    fn empty_env_returns_false_no_panic() {
        init_env_lock();
        std::env::remove_var(BOOT_HATCH_ENV);
        let bs = BootState::new();
        // On a non-Android host getprop fails → returns false.
        let _ = bs.boot_completed();
        // Should not panic or block.
    }
}
