namespace Voboost {
// GFileMonitor on inject.json and staging/voboost-inject-update-ready, with debounce.
// Emits plan_changed / inject_update_ready. The watched zone is untrusted input;
// verification happens downstream. See app-interface#Untrusted plan input
// and #Staging read boundary.
public class AppZoneWatcher : Object {
public string app_zone { get; construct; }
// Root run-zone (/data/voboost/run) watched for the kill-switch
// `disable` file (Bug 1). The device-safety spec requires the daemon
// react when run/disable "appears while the daemon is running" — a
// SHALL requirement, not best-effort. Without this monitor the
// kill-switch is only re-checked on spawn/death/plan-change events, so
// on a quiet device creating run/disable has no effect.
public string run_zone { get; construct; }
public uint debounce_ms { get; construct; }

public signal void plan_changed();
public signal void inject_update_ready();
// Fired when the run/disable kill-switch file is created or deleted.
// The supervisor re-evaluates kill_switched() and runs apply_plan_diff
// (which handles both activation and deactivation).
public signal void kill_switch_changed();

private FileMonitor? plan_mon;
private FileMonitor? staging_mon;
private FileMonitor? kill_mon;
private uint plan_timer = 0;
private uint staging_timer = 0;
private uint kill_timer = 0;

public AppZoneWatcher(string app_zone, string run_zone,
                      uint debounce_ms = 500) {
    Object(app_zone: app_zone, run_zone: run_zone,
           debounce_ms: debounce_ms);
}

public void start() throws Error {
    // Watch the app-zone DIRECTORY for inject.json, not the file. The
    // inotify backend (Android/Linux) tracks inodes, so a file monitor on
    // a not-yet-existing inject.json can miss its creation — the init hook
    // launches the daemon at boot before the app first writes inject.json —
    // and an atomic temp+rename overwrite (the safe write pattern, which
    // the daemon itself uses for inject-status.json) swaps the inode, which
    // a file monitor can also miss on subsequent changes. A directory watch
    // survives both and matches the staging watcher below. (inject-status
    // .json, also in this directory, is filtered out by the basename check.)
    var zone = File.new_for_path(this.app_zone);
    this.plan_mon = zone.monitor_directory(
        FileMonitorFlags.NONE, null);
    // CREATED/CHANGED carry inject.json as `file` (`other` is null);
    // `other` is set only for rename/move events. Check both so a plainly
    // written and an atomically-renamed inject.json are both observed.
    this.plan_mon.changed.connect((file, other, ev) => {
                string? name = file != null ? file.get_basename() : null;
                string? oname = other != null ? other.get_basename() : null;
                if (name == "inject.json" || oname == "inject.json") {
                    schedule_plan();
                }
                // The app creates `staging/` on demand for an OTA, which is
                // usually AFTER the boot-started daemon began watching. Re-
                // establish the staging monitor when staging/ appears so a
                // runtime OTA is observed immediately, not only on the next
                // daemon restart (update-planes "applies immediately").
                if (name == "staging" || oname == "staging") {
                    ensure_staging_monitor();
                }
            });

    // Establish the staging monitor now if staging/ already exists at start.
    ensure_staging_monitor();
    // Bug 1: watch the root run-zone for the kill-switch `disable` file.
    // The run dir is created by the daemon's single-instance lock before
    // start(), so it exists; a missing dir is not fatal (best-effort,
    // retried never — but run/ is guaranteed present). Watch the
    // DIRECTORY (not the file) for the same inode-swap reason as
    // inject.json: an atomic temp+rename create/delete of `disable`
    // swaps the inode, which a file monitor can miss.
    ensure_kill_switch_monitor();
    Log.info("watcher", "watching " + this.app_zone);
}

// Create the run-zone directory monitor for the kill-switch `disable`
// file. Idempotent. Best-effort: a missing run/ is not an error (the
// daemon creates it at startup, so this is defensive only).
private void ensure_kill_switch_monitor() {
    if (this.kill_mon != null) {
        return;
    }
    try {
        this.kill_mon = File.new_for_path(this.run_zone).monitor_directory(
            FileMonitorFlags.NONE, null);
    } catch (Error e) {
        return;  // run/ absent; defensive only (daemon creates it)
    }
    // CREATED/DELETED carry `disable` as `file` (`other` is null for a
    // plain create/delete). Both args are nullable in the GFileMonitor
    // contract; guard `file` so a rename-only event does not null-deref.
    this.kill_mon.changed.connect((file, other, ev) => {
                string? name = file != null ? file.get_basename() : null;
                string? oname = other != null ? other.get_basename() : null;
                if (name == "disable" || oname == "disable") {
                    schedule_kill();
                }
            });
}

// Create the staging/ directory monitor if staging/ exists and is not yet
// watched, and catch a marker that already exists (created before the monitor
// was set, so no creation event will fire). Idempotent. Best-effort: a missing
// staging/ is not an error (the app creates it on demand); it is retried from
// the plan watch when staging/ appears, and start() only throws for an absent
// app zone (the app is not installed), which the supervisor fails safe on.
private void ensure_staging_monitor() {
    if (this.staging_mon != null) {
        return;
    }
    string staging_path = Path.build_filename(this.app_zone, "staging");
    try {
        this.staging_mon = File.new_for_path(staging_path).monitor_directory(
            FileMonitorFlags.NONE, null);
    } catch (Error e) {
        return;  // staging/ still absent; retried when plan_mon sees it appear
    }
    // Same shape as the plan filter above (rename vs create). Both args are
    // nullable in the GFileMonitor contract; guard `file` so a rename-only
    // event (file == null, other == the marker) does not null-deref.
    this.staging_mon.changed.connect((file, other, ev) => {
                string? name = file != null ? file.get_basename() : null;
                string? oname = other != null ? other.get_basename() : null;
                if (name == "voboost-inject-update-ready"
                    || oname == "voboost-inject-update-ready") {
                    schedule_staging();
                }
            });
    // If the marker predates the monitor (staging/ written + marked before the
    // monitor existed), no creation event fires — check once. schedule_staging
    // debounces, so a racing event is harmless.
    if (FileUtils.test(
            Path.build_filename(staging_path, "voboost-inject-update-ready"),
            FileTest.EXISTS)) {
        schedule_staging();
    }
}

private void schedule_plan() {
    if (this.plan_timer != 0) {
        Source.remove(this.plan_timer);
    }
    this.plan_timer = Timeout.add(this.debounce_ms, () => {
                this.plan_timer = 0;
                plan_changed();
                return Source.REMOVE;
            });
}

private void schedule_staging() {
    if (this.staging_timer != 0) {
        Source.remove(this.staging_timer);
    }
    this.staging_timer = Timeout.add(this.debounce_ms, () => {
                this.staging_timer = 0;
                inject_update_ready();
                return Source.REMOVE;
            });
}

private void schedule_kill() {
    if (this.kill_timer != 0) {
        Source.remove(this.kill_timer);
    }
    this.kill_timer = Timeout.add(this.debounce_ms, () => {
                this.kill_timer = 0;
                kill_switch_changed();
                return Source.REMOVE;
            });
}

public void stop() {
    if (this.plan_mon != null) {
        this.plan_mon.cancel();
        this.plan_mon = null;
    }
    if (this.staging_mon != null) {
        this.staging_mon.cancel();
        this.staging_mon = null;
    }
    if (this.kill_mon != null) {
        this.kill_mon.cancel();
        this.kill_mon = null;
    }
    if (this.plan_timer != 0) {
        Source.remove(this.plan_timer);
        this.plan_timer = 0;
    }
    if (this.staging_timer != 0) {
        Source.remove(this.staging_timer);
        this.staging_timer = 0;
    }
    if (this.kill_timer != 0) {
        Source.remove(this.kill_timer);
        this.kill_timer = 0;
    }
}
}
}
