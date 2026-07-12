namespace Voboost {
// Shared log format with the app: "yyyy-MM-dd HH:mm:ss.SSS [tag] src: msg".
// Root-only file /data/voboost/logs/inject-YYYY-MM-DD.log (600), 7-day
// retention. Retention runs at most once per 24 hours (not per log line)
// to avoid directory-scan overhead on every write. See app-interface (D8).
public enum LogTag {
    MINUS,
    PLUS,
    STAR,
    DEBUG;

    public string symbol() {
        switch (this) {
        case LogTag.PLUS:
            return "+";
        case LogTag.STAR:
            return "*";
        case LogTag.DEBUG:
            return "#";
        default:
            return "-";
        }
    }
}

public class Log : Object {
public string dir { get; construct; }

private static Log? instance;
// Debug verbosity, toggled at runtime by the plan's `log_level` field
// ("debug" => on). Lets an operator see frida/inject internals by editing
// inject.json — no rebuild, no reinstall. Default off.
private static bool debug_enabled = false;
// Unix timestamp of the last retention pass; 0 = never run.
private int64 last_prune_ts = 0;

public Log(string dir) {
    Object(dir: dir);
}

public static void init(string dir) {
    instance = new Log(dir);
}

public static Log get_default() {
    if (instance == null) {
        instance = new Log("/data/voboost/logs");
    }
    return instance;
}

// Toggle debug verbosity at runtime (called from Supervisor.load_plan when
// the plan's log_level changes). Idempotent.
public static void set_debug(bool enabled) {
    debug_enabled = enabled;
}

public static bool get_debug() {
    return debug_enabled;
}

public static void info(string source, string message) {
    get_default().write(LogTag.STAR, source, message);
}

public static void ok(string source, string message) {
    get_default().write(LogTag.PLUS, source, message);
}

public static void err(string source, string message) {
    get_default().write(LogTag.MINUS, source, message);
}

// Verbose diagnostics: frida enumerate counts, /proc scans, attach/load
// steps. Suppressed unless the plan set log_level "debug". Use freely in
// hot paths — the flag check is a static bool read, not a syscall.
public static void debug(string source, string message) {
    if (!debug_enabled) {
        return;
    }
    get_default().write(LogTag.DEBUG, source, message);
}

public void write(LogTag tag, string source, string message) {
    var now = new DateTime.now_local();
    string stamp = now.format("%Y-%m-%d %H:%M:%S");
    string line = "%s.%03d [%s] %s: %s\n".printf(
        stamp, now.get_microsecond() / 1000, tag.symbol(), source,
        message);

    try {
        ensure_dir();
        string path = today_path(now);
        var stream = File.new_for_path(path).append_to(
            FileCreateFlags.PRIVATE, null);
        try {
            stream.write(line.data, null);
        } finally {
            // close () throws; a bare throw out of a finally is a compile
            // error in Vala, so swallow the close error (best-effort: the
            // write either succeeded or its error is logged by the catch).
            try {
                stream.close(null);
            } catch (Error close_err) {
            }
        }
        // Enforce 0600 on every write: a prior daemon run or a misbehaving
        // process may have left the daily log file group/world-readable,
        // and the spec (app-interface "Root-only logging") requires 600.
        // chmod is idempotent and cheap (one syscall), so always apply it
        // rather than only on first creation — this also tightens a pre-
        // existing over-permissive same-named file on the next write.
        FileUtils.chmod(path, 0600);
    } catch (Error e) {
        stderr.printf("log write: %s\n", e.message);
    }

    // Prune old logs at most once per 24 hours.
    int64 now_ts = now.to_unix();
    if (now_ts - this.last_prune_ts >= 24 * 3600) {
        prune();
        this.last_prune_ts = now_ts;
    }
}

private string today_path(DateTime now) {
    return Path.build_filename(
        this.dir, "inject-" + now.format("%Y-%m-%d") + ".log");
}

private void ensure_dir() throws Error {
    var d = File.new_for_path(this.dir);
    if (!d.query_exists(null)) {
        d.make_directory_with_parents(null);
        FileUtils.chmod(this.dir, 0700);
    }
}

private void prune() {
    int64 cutoff = new DateTime.now_local().to_unix() - 7 * 24 * 3600;
    try {
        var d = File.new_for_path(this.dir);
        var en = d.enumerate_children(
            "standard::name", FileQueryInfoFlags.NONE, null);
        // Close the enumerator explicitly (the GIO contract) rather than
        // relying on finalization to release its directory handle.
        try {
            FileInfo? info = null;
            while ((info = en.next_file(null)) != null) {
                string name = info.get_name();
                if (!name.has_prefix("inject-") ||
                    !name.has_suffix(".log")) {
                    continue;
                }
                string p = Path.build_filename(this.dir, name);
                var st = File.new_for_path(p).query_info(
                    "time::modified", FileQueryInfoFlags.NONE, null);
                if (st.get_attribute_uint64("time::modified") < cutoff) {
                    FileUtils.unlink(p);
                }
            }
        } finally {
            try {
                en.close(null);
            } catch (Error close_err) {
            }
        }
    } catch (Error e) {
        // Retention is best-effort; never abort logging on a prune error.
        stderr.printf("log prune: %s\n", e.message);
    }
}
}
}
