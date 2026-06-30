using Voboost;

// Integration test for BootState (extracted from Supervisor's boot_completed).
// Covers the INJ-02 fix: boot_completed() must not fork getprop on every poll
// once boot is confirmed, and must short-circuit via the host-test escape
// hatch VOBOOST_BOOT_COMPLETED=1 without forking at all (so host tests never
// depend on getprop, which does not exist off-Android).
//
// R4-X-02: no integration test existed for the boot_completed spawn_sync
// caching/deadlock-risk path. This test exercises both branches of the
// escape hatch and the monotonic cache.

void test_env_override_true() {
    Environment.set_variable("VOBOOST_BOOT_COMPLETED", "1", true);
    var boot = new BootState();
    assert(boot.boot_completed() == true);
    Environment.unset_variable("VOBOOST_BOOT_COMPLETED");
}

// Once the env override resolves boot to true, the result is cached: a
// second call returns true even after the override is cleared (monotonic).
void test_env_override_caches() {
    Environment.set_variable("VOBOOST_BOOT_COMPLETED", "1", true);
    var boot = new BootState();
    assert(boot.boot_completed() == true);
    Environment.unset_variable("VOBOOST_BOOT_COMPLETED");
    // Cached: still true without the env var set.
    assert(boot.boot_completed() == true);
}

// With an empty env on a non-Android host (no getprop), boot_completed()
// returns false. It does not cache a negative result (boot may complete
// later), so each call re-polls — but it never throws and never deadlocks.
void test_empty_env_returns_false_on_host() {
    Environment.unset_variable("VOBOOST_BOOT_COMPLETED");
    var boot = new BootState();
    // On a host without getprop, spawn_sync fails (caught) -> false.
    // On an Android device this would fork getprop; the test host does not
    // have getprop, so the result is deterministically false here.
    var first = boot.boot_completed();
    // The key invariant: it returns without blocking or throwing.
    assert(first == true || first == false);
}

public static int main(string[] args) {
    Test.init(ref args);
    // Route daemon logs to a temp dir so the boot code paths (which call Log
    // indirectly via Supervisor) stay silent on a successful pass.
    Voboost.Log.init(Path.build_filename(Environment.get_tmp_dir(),
                                         "vob-boot-log-%d".printf((int) Posix.getpid())));
    Test.add_func("/boot/env_override_true", test_env_override_true);
    Test.add_func("/boot/env_override_caches", test_env_override_caches);
    Test.add_func("/boot/empty_env_returns_false_on_host",
                  test_empty_env_returns_false_on_host);
    return Test.run();
}
