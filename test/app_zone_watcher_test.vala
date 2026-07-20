using Voboost;

// Host-side integration test for AppZoneWatcher. Exercises the real
// GFileMonitor + debounce path: writing inject.json fires plan_changed,
// creating staging/voboost-inject-update-ready fires inject_update_ready, and
// creating run/disable fires kill_switch_changed. Uses a real GMainLoop so
// the debounce Timeout sources dispatch.
//
// The watcher watches the app-zone DIRECTORY (not the file) so an atomic
// temp+rename write of inject.json is observed — the test mirrors that
// pattern (set_contents to a temp, rename) to match the daemon's own
// status-write pattern and the app's safe write pattern.

private string fresh_dir(string role) {
    string d = Path.build_filename(
        Environment.get_tmp_dir(),
        "vob-azw-%s-%d-%d".printf(role, (int) Posix.getpid(), dirseq++));
    DirUtils.create_with_parents(d, 0700);
    return d;
}

static int dirseq = 0;

// Atomically write `content` to `path` via temp+rename (the safe write
// pattern the daemon uses for inject-status.json and the app should use for
// inject.json). A directory monitor survives the inode swap.
void atomic_write(string path, string content) {
    string tmp = path + ".tmp";
    try {
        FileUtils.set_contents(tmp, content);
    } catch (FileError e) {
        error("write %s: %s", tmp, e.message);
    }
    if (FileUtils.rename(tmp, path) != 0) {
        error("rename %s -> %s", tmp, path);
    }
}

// Drive the GMainLoop until `cond` returns true or the deadline expires.
// FileMonitor + debounce dispatch asynchronously, so the test must pump the
// loop. Returns true if `cond` held, false on timeout (test failure).
bool wait_for(owned SourceFunc cond, int timeout_ms = 5000) {
    MainContext ctx = MainContext.default();
    var now = new DateTime.now_local();
    int64 deadline = now.to_unix() * 1000 + now.get_microsecond() / 1000 +
                     timeout_ms;
    while (!cond()) {
        now = new DateTime.now_local();
        int64 cur = now.to_unix() * 1000 + now.get_microsecond() / 1000;
        if (cur >= deadline) {
            return false;
        }
        ctx.iteration(true);
    }
    return true;
}

// plan_changed fires when inject.json is written (atomic temp+rename).
void test_plan_changed_on_write() {
    string app_zone = fresh_dir("app");
    string run_zone = fresh_dir("run");
    var w = new AppZoneWatcher(app_zone, run_zone, 100);
    try {
        w.start();
    } catch (Error e) {
        assert_not_reached();
    }
    bool fired = false;
    w.plan_changed.connect(() => { fired = true; });
    atomic_write(Path.build_filename(app_zone, "inject.json"),
                 "{\"agents\":[]}");
    assert(wait_for(() => fired));
    w.stop();
    DirUtils.remove(app_zone);
    DirUtils.remove(run_zone);
}

// inject_update_ready fires when staging/voboost-inject-update-ready is
// created and staging/ already exists at start() (ensure_staging_monitor
// establishes the monitor during start).
void test_inject_update_ready_existing_staging() {
    string app_zone = fresh_dir("app");
    string run_zone = fresh_dir("run");
    // staging/ exists BEFORE start() so ensure_staging_monitor finds it.
    string staging = Path.build_filename(app_zone, "staging");
    DirUtils.create(staging, 0700);
    var w = new AppZoneWatcher(app_zone, run_zone, 100);
    try {
        w.start();
    } catch (Error e) {
        assert_not_reached();
    }
    bool fired = false;
    w.inject_update_ready.connect(() => { fired = true; });
    atomic_write(Path.build_filename(staging, "voboost-inject-update-ready"),
                 "ready");
    assert(wait_for(() => fired));
    w.stop();
    FileUtils.unlink(Path.build_filename(staging, "voboost-inject-update-ready"));
    DirUtils.remove(staging);
    DirUtils.remove(app_zone);
    DirUtils.remove(run_zone);
}

// kill_switch_changed fires when run/disable is created.
void test_kill_switch_on_disable_file() {
    string app_zone = fresh_dir("app");
    string run_zone = fresh_dir("run");
    var w = new AppZoneWatcher(app_zone, run_zone, 100);
    try {
        w.start();
    } catch (Error e) {
        assert_not_reached();
    }
    bool fired = false;
    w.kill_switch_changed.connect(() => { fired = true; });
    atomic_write(Path.build_filename(run_zone, "disable"), "1");
    assert(wait_for(() => fired));
    w.stop();
    FileUtils.unlink(Path.build_filename(run_zone, "disable"));
    DirUtils.remove(app_zone);
    DirUtils.remove(run_zone);
}

// A pre-existing voboost-inject-update-ready marker (created before the
// staging monitor is established) is caught by the one-shot check in
// ensure_staging_monitor.
void test_preexisting_inject_update_ready_marker() {
    string app_zone = fresh_dir("app");
    string run_zone = fresh_dir("run");
    // staging/ + marker exist BEFORE start().
    string staging = Path.build_filename(app_zone, "staging");
    DirUtils.create(staging, 0700);
    atomic_write(Path.build_filename(staging, "voboost-inject-update-ready"),
                 "ready");
    var w = new AppZoneWatcher(app_zone, run_zone, 100);
    try {
        w.start();
    } catch (Error e) {
        assert_not_reached();
    }
    bool fired = false;
    w.inject_update_ready.connect(() => { fired = true; });
    // The one-shot check in ensure_staging_monitor should fire the signal
    // (debounced) even though no creation event arrives.
    assert(wait_for(() => fired));
    w.stop();
    FileUtils.unlink(Path.build_filename(staging, "voboost-inject-update-ready"));
    DirUtils.remove(staging);
    DirUtils.remove(app_zone);
    DirUtils.remove(run_zone);
}

public static int main(string[] args) {
    Test.init(ref args);
    Voboost.Log.init(Path.build_filename(
                         Environment.get_tmp_dir(),
                         "vob-azw-log-%d".printf((int) Posix.getpid())));
    Test.add_func("/app-zone-watcher/plan-changed",
                  test_plan_changed_on_write);
    Test.add_func("/app-zone-watcher/inject-update-ready-existing-staging",
                  test_inject_update_ready_existing_staging);
    Test.add_func("/app-zone-watcher/kill-switch",
                  test_kill_switch_on_disable_file);
    Test.add_func("/app-zone-watcher/preexisting-marker",
                  test_preexisting_inject_update_ready_marker);
    return Test.run();
}
