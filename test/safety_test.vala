using Voboost;

void test_rate_limit_then_quarantine() {
    // panic_window_seconds large so we don't trip panic during this test.
    var s = new Safety(3, 5, 100, 3600);
    assert(s.is_quarantined("a", "p") == false);
    int allowed = 0;
    for (int i = 0; i < 6; i++) {
        if (s.allow_attempt("a", "p")) {
            allowed += 1;
        }
    }
    assert(s.is_quarantined("a", "p") == true);
    assert(allowed <= 3);
}

void test_panic_quarantine_sliding_window() {
    // panic_threshold=2, panic_window_seconds=60: two deaths within the window
    // trip panic; clear_panic resets it.
    var s = new Safety(3, 5, 2, 60);
    assert(s.panic_quarantined() == false);
    s.note_target_death();
    s.note_target_death();
    assert(s.panic_quarantined() == true);
    assert(s.allow_attempt("a", "p") == false);
    s.clear_panic();
    assert(s.panic_quarantined() == false);
    assert(s.allow_attempt("a", "p") == true);
}

void test_backoff_reset_on_success() {
    var s = new Safety(10, 5, 100, 3600);
    assert(s.allow_attempt("a", "p") == true);
    // Arm backoff as if the injection failed, then verify it blocks.
    s.note_failure("a", "p");
    assert(s.allow_attempt("a", "p") == false);
    // note_success must clear the backoff so the next attempt is free.
    s.note_success("a", "p");
    assert(s.allow_attempt("a", "p") == true);
}

void test_kill_switch_absent_dir() {
    var s = new Safety(3, 5, 100, 3600);
    assert(s.kill_switch_active("/nonexistent/run") == false);
    s.set_plan_disable_all(true);
    assert(s.kill_switch_active("/nonexistent/run") == true);
}

// note_success resets the exponential-backoff DELAY but not the attempt
// ring: an attempt blocked by backoff is unblocked by note_success, yet the
// earlier attempt still counts toward the budget, so a load-succeeds-then-
// crashes loop still quarantines (see test_crash_loop_quarantines_despite_
// success). Stability against false quarantine is provided at the Supervisor
// level (budgeted skips allow_attempt for already-loaded agents), not here.
void test_attempts_after_backoff_reset() {
    var s = new Safety(2, 1, 100, 3600);
    // First attempt allowed (ring was empty).
    assert(s.allow_attempt("w", "p") == true);
    // Arm backoff.
    s.note_failure("w", "p");
    // Immediate retry blocked by backoff (not quarantine).
    assert(s.allow_attempt("w", "p") == false);
    assert(s.is_quarantined("w", "p") == false);
    // note_success clears the backoff delay only; the ring still holds the
    // first attempt, so only ONE more attempt fits before quarantine.
    s.note_success("w", "p");
    assert(s.allow_attempt("w", "p") == true);
    // Budget now exhausted (2 attempts in the window) -> quarantine.
    assert(s.allow_attempt("w", "p") == false);
    assert(s.is_quarantined("w", "p") == true);
}

// Regression for the crash-loop quarantine hole: an agent that LOADS
// successfully every time (so note_success runs) but whose target keeps
// dying right after MUST still quarantine. Previously note_success cleared
// the attempt ring, so every clean load reset the budget and such an agent
// never hit the per-(agent,process) quarantine — only the global panic
// would, which quarantines every agent instead of the culprit
// (device-safety "Target keeps dying right after an agent injects").
void test_crash_loop_quarantines_despite_success() {
    var s = new Safety(3, 5, 100, 3600);
    // Three load-then-crash cycles. Each allow_attempt is a fresh load
    // (the prior load died, so it is not "already loaded"); note_success
    // runs because the load itself succeeded.
    assert(s.allow_attempt("c", "p") == true);
    s.note_success("c", "p");
    assert(s.allow_attempt("c", "p") == true);
    s.note_success("c", "p");
    assert(s.allow_attempt("c", "p") == true);
    s.note_success("c", "p");
    // Three rapid attempts within the window -> quarantine, despite every
    // load having succeeded.
    assert(s.allow_attempt("c", "p") == false);
    assert(s.is_quarantined("c", "p") == true);
}

// Verify that note_success does NOT clear quarantine: quarantine is a
// one-way latch (only a daemon restart clears it). note_success resets
// only the exponential-backoff DELAY (not the attempt ring — see
// test_crash_loop_quarantines_despite_success), so a quarantined pair stays
// quarantined and is still denied.
void test_quarantine_persists_after_success() {
    var s = new Safety(2, 5, 100, 3600);
    // Exhaust the budget: 2 allowed, 3rd triggers quarantine.
    assert(s.allow_attempt("r", "p") == true);
    assert(s.allow_attempt("r", "p") == true);
    assert(s.allow_attempt("r", "p") == false);
    assert(s.is_quarantined("r", "p") == true);
    // note_success resets only backoff; quarantine is a one-way latch
    // (only daemon restart clears it) and is unaffected.
    s.note_success("r", "p");
    assert(s.is_quarantined("r", "p") == true);
    // Even after reset, quarantined pairs are denied.
    assert(s.allow_attempt("r", "p") == false);
}

// Verify that exponential backoff caps at MAX_BACKOFF_SECONDS (30 min).
// note_failure doubles the delay each call; after enough calls the delay
// must saturate rather than overflow.
void test_backoff_caps_at_max() {
    var s = new Safety(100, 5, 100, 3600);
    assert(s.allow_attempt("b", "p") == true);
    // Drive backoff past the cap: 20 failures → 1,2,4,...524288 capped at
    // 1800. After each failure, next_allowed is now + delay.
    for (int i = 0; i < 20; i++) {
        s.note_failure("b", "p");
    }
    // The agent is blocked by backoff (not quarantine).
    assert(s.is_quarantined("b", "p") == false);
    assert(s.allow_attempt("b", "p") == false);
    // note_success resets the backoff completely.
    s.note_success("b", "p");
    assert(s.allow_attempt("b", "p") == true);
}

// Thin device-oriented helpers (device-safety "Capability detection"):
// the version hint parses the release prefix; capability_present is a
// file-existence probe; coexistence_present reads /proc/PID/maps. The
// coexistence TRUE path needs a live injected target and is covered by
// the on-device coexistence integration test; here we cover the host-
// portable false path (a nonexistent pid has no maps).
void test_capability_helpers() {
    var s = new Safety(3, 5, 100, 3600);
    // version_hint_is_a9: only a leading "9" counts as A9.
    assert(s.version_hint_is_a9("9") == true);
    assert(s.version_hint_is_a9("9.0") == true);
    assert(s.version_hint_is_a9("11") == false);
    assert(s.version_hint_is_a9("") == false);
    // capability_present is a pure file-existence probe.
    string probe = Path.build_filename(
        Environment.get_tmp_dir(),
        "vob-cap-probe-%d".printf(Posix.getpid()));
    assert(s.capability_present(probe) == false);
    try {
        FileUtils.set_contents(probe, "x");
    } catch (FileError e) {
        assert_not_reached();
    }
    assert(s.capability_present(probe) == true);
    FileUtils.unlink(probe);
    // coexistence_present: a nonexistent pid has no maps on any host.
    assert(s.coexistence_present(999999) == false);
}

public static int main(string[] args) {
    Test.init(ref args);
    Test.add_func("/safety/rate-limit", test_rate_limit_then_quarantine);
    Test.add_func("/safety/panic-window", test_panic_quarantine_sliding_window);
    Test.add_func("/safety/backoff-reset", test_backoff_reset_on_success);
    Test.add_func("/safety/kill-switch", test_kill_switch_absent_dir);
    Test.add_func("/safety/backoff-budget",
                  test_attempts_after_backoff_reset);
    Test.add_func("/safety/crash-loop-success",
                  test_crash_loop_quarantines_despite_success);
    Test.add_func("/safety/quarantine-persists",
                  test_quarantine_persists_after_success);
    Test.add_func("/safety/backoff-cap", test_backoff_caps_at_max);
    Test.add_func("/safety/capability-helpers", test_capability_helpers);
    return Test.run();
}
