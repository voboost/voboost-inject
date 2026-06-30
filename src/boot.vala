namespace Voboost {

// Monotonic boot-state cache for sys.boot_completed. Extracted from
// Supervisor so it can be unit-tested without linking frida-core (the rest of
// Supervisor depends on FridaController). The daemon polls boot_completed() on
// the GMainLoop thread; once boot is confirmed (sys.boot_completed=1) the
// value is monotonic for the rest of the boot, so it is cached and the
// spawn_sync is skipped on subsequent polls (INJ-02: avoid repeated forks).
//
// Host-test escape hatch: VOBOOST_BOOT_COMPLETED=1 short-circuits to true
// without forking getprop, so host tests can drive the boot-gated path on a
// non-Android machine where getprop does not exist.
public class BootState : Object {
private bool cached = false;
private bool resolved = false;

// True once sys.boot_completed=1 (or the host-test override is set).
// Monotonic: after the first true result, never forks again. Returns false
// (and re-polls on the next call) while boot is not yet complete.
public bool boot_completed() {
    // Monotonic cache: once boot is confirmed, never fork again.
    if (this.resolved) {
        return this.cached;
    }
    // Host-test escape hatch: allow tests to override boot state without
    // spawning getprop. Checked first so host tests never fork.
    if (Environment.get_variable("VOBOOST_BOOT_COMPLETED") == "1") {
        this.resolved = true;
        this.cached = true;
        return true;
    }
    try {
        string[] argv = { "getprop", "sys.boot_completed" };
        string stdout_buf;
        int exit_status;
        Process.spawn_sync(null, argv, null,
                          SpawnFlags.SEARCH_PATH, null,
                          out stdout_buf, null, out exit_status);
        if (exit_status == 0 && stdout_buf.strip() == "1") {
            // Boot is monotonic: cache the positive result so the polling
            // loop never forks getprop again.
            this.resolved = true;
            this.cached = true;
            return true;
        }
    } catch (Error e) {
        // getprop not available (non-Android host or test env); fall
        // through to the env-var escape hatch checked above.
    }
    return false;
}
}
}
