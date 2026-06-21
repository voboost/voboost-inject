namespace Voboost {
// flock () and its constants are not in the posix VAPI shipped with
// the frida-patched valac. Bind them directly.
[CCode(cname = "flock", cheader_filename = "sys/file.h")]
private extern static int sys_flock(int fd, int operation);
private const int LOCK_SH = 1;
private const int LOCK_EX = 2;
private const int LOCK_NB = 4;
private const int LOCK_UN = 8;

// Entry: single-instance via pidfile + flock, startup-gate (`startup: none`
// in the app-written inject.json -> immediate exit), init Log/
// TrustStore/Manifest/Frida/Safety/watchers/Supervisor, run a GMainLoop,
// clean SIGTERM shutdown. See daemon-lifecycle spec.
public class Daemon : Object {
public const string ROOT_ZONE = "/data/voboost";
public const string APP_ZONE = "/data/user/0/ru.voboost";
// Device-safety defaults (D6): per-(agent,process) reinjection
// rate-limit and global panic-quarantine thresholds.
// See device-safety spec "Reinjection rate-limit and quarantine"
// and "Global panic-quarantine".
private const uint SAFETY_MAX_ATTEMPTS = 3;
private const uint SAFETY_WINDOW_MIN = 5;
private const uint SAFETY_PANIC_THRESHOLD = 8;
private const uint SAFETY_PANIC_WINDOW_SEC = 300;

private MainLoop loop;
private int lock_fd = -1;
private Supervisor? supervisor;
// Latch set on the first SIGTERM so a repeated SIGTERM during the async
// shutdown does not start a second teardown (see the SIGTERM source below,
// which stays installed via Source.CONTINUE).
private bool shutting_down = false;

public Daemon(MainLoop loop) {
    this.loop = loop;
}

// Single-instance: hold an exclusive flock on the pidfile for the whole
// process lifetime. A second instance fails the lock and exits.
public bool acquire_single_instance() {
    string run_dir = Path.build_filename(ROOT_ZONE, "run");
    DirUtils.create_with_parents(run_dir, 0700);
    string pidfile = Path.build_filename(run_dir, "inject.pid");
    this.lock_fd = Posix.open(
        pidfile, Posix.O_RDWR | Posix.O_CREAT, 0600);
    if (this.lock_fd < 0) {
        return false;
    }
    if (sys_flock(this.lock_fd, LOCK_EX | LOCK_NB) != 0) {
        Log.err("main", "another instance holds the pidfile lock");
        // We opened the pidfile but lost the lock: close it so the fd is
        // not held against the process (the process exits right after, but
        // releasing explicitly is correct and lint-clean).
        Posix.close(this.lock_fd);
        this.lock_fd = -1;
        return false;
    }
    string pid = "%d\n".printf(Posix.getpid());
    Posix.ftruncate(this.lock_fd, 0);
    // Write the whole pid (Posix.write may write fewer bytes than requested
    // per POSIX). The pid is informational — single-instance is enforced by
    // the flock above, not the file contents — but a complete write keeps
    // the pid honest for diagnostics.
    size_t off = 0;
    while (off < pid.length) {
        ssize_t n = Posix.write(
            this.lock_fd, pid.data[off: pid.length], pid.length - off);
        if (n < 0) {
            break;
        }
        off += n;
    }
    return true;
}

// Startup-gate: read the `startup` field of the app-written inject.json.
// "none" (case-insensitive) means do nothing. The app mirrors its own
// startup intent here; the daemon runs as root and can read the app zone
// (the reverse is denied). The daemon reads NO config.yaml and parses no
// YAML. Reading untrusted app input here is safe: the gate only moves
// behaviour in the fail-safe direction (skip injection); everything
// injected is still signature-verified. See daemon-lifecycle spec
// "Startup gate via the `inject.json` `startup` field".
public bool startup_permitted() {
    string p = Path.build_filename(APP_ZONE, "inject.json");
    if (!FileUtils.test(p, FileTest.EXISTS)) {
        return true;
    }
    // DoS guard (injection-control size bound): stat is a fast-path
    // hint to skip reading an obviously oversized file; the post-read
    // check below is the authoritative guard (stat is TOCTOU-prone).
    Posix.Stat st;
    if (Posix.stat(p, out st) == 0 &&
        st.st_size > PlanReader.MAX_PLAN_BYTES) {
        return true;
    }
    string content;
    try {
        FileUtils.get_contents(p, out content);
    } catch (Error e) {
        return true;
    }
    // Authoritative size guard: catches TOCTOU growth that stat missed.
    if (content.length > PlanReader.MAX_PLAN_BYTES) {
        return true;
    }
    var parser = new Json.Parser();
    try {
        parser.load_from_data(content, -1);
    } catch (Error e) {
        return true;
    }
    var root = parser.get_root();
    if (root == null || root.get_node_type() != Json.NodeType.OBJECT) {
        return true;
    }
    var obj = root.get_object();
    string startup = "";
    if (obj.has_member("startup")) {
        var node = obj.get_member("startup");
        if (node.get_node_type() == Json.NodeType.VALUE &&
            node.get_value_type() == typeof(string)) {
            startup = node.get_string();
        }
    }
    return startup.down() != "none";
}

public void start() {
    var trust = new TrustStore();
    var manifest = new Manifest();
    var safety = new Safety(
        SAFETY_MAX_ATTEMPTS, SAFETY_WINDOW_MIN, SAFETY_PANIC_THRESHOLD,
        SAFETY_PANIC_WINDOW_SEC);
    var frida = new FridaController(ROOT_ZONE, safety);
    var watcher = new ProcessWatcher(frida, safety);
    var app_watcher = new AppZoneWatcher(APP_ZONE);
    var status = new Status(
        Path.build_filename(APP_ZONE, "inject-status.json"));
    var ota = new Ota(ROOT_ZONE, trust);
    // Single source of truth for the version: the generated
    // DAEMON_VERSION (meson project () version). Only the daemon entry
    // point references it, so host tests need no generated version src.
    status.daemon_version = DAEMON_VERSION;
    this.supervisor = new Supervisor(
        ROOT_ZONE, APP_ZONE, trust, manifest, frida, safety, watcher,
        app_watcher, status, ota);
    this.supervisor.run.begin((obj, res) => {
                this.supervisor.run.end(res);
            });
}

public void shutdown() {
    // Idempotent: the SIGTERM source stays installed (Source.CONTINUE), so a
    // second SIGTERM during the async teardown reaches here again. Latch on
    // the first call and let the in-flight shutdown complete.
    if (this.shutting_down) {
        return;
    }
    this.shutting_down = true;
    Log.info("main", "SIGTERM: clean shutdown");
    if (this.supervisor != null) {
        this.supervisor.shutdown.begin((obj, res) => {
                    this.supervisor.shutdown.end(res);
                    release_lock();
                    this.loop.quit();
                });
    } else {
        release_lock();
        this.loop.quit();
    }
}

private void release_lock() {
    if (this.lock_fd >= 0) {
        sys_flock(this.lock_fd, LOCK_UN);
        Posix.close(this.lock_fd);
        this.lock_fd = -1;
    }
}
}

public static int main(string[] args) {
    Log.init(Path.build_filename(Daemon.ROOT_ZONE, "logs"));
    var loop = new MainLoop();
    var daemon = new Daemon(loop);

    if (!daemon.acquire_single_instance()) {
        return 1;
    }
    if (!daemon.startup_permitted()) {
        Log.info("main", "startup intent is none: gated exit");
        return 0;
    }

    // Keep the SIGTERM source installed (Source.CONTINUE) rather than
    // removing it after the first fire: removing it can let the default
    // SIGTERM disposition return, so a second SIGTERM during the async
    // shutdown would terminate the process without releasing the pidfile
    // lock or detaching sessions. Staying installed keeps every SIGTERM
    // clean (daemon.shutdown () is idempotent); a hard kill uses SIGKILL.
    Unix.signal_add(Posix.Signal.TERM, () => {
            daemon.shutdown();
            return Source.CONTINUE;
        });

    daemon.start();
    loop.run();
    return 0;
}
}
