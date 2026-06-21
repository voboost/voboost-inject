namespace Voboost {
public enum InjectionState {
    ACTIVE,
    FAILED,
    SKIPPED_COEXIST,
    WAITING,
    QUARANTINED;

    public string label() {
        switch (this) {
        case InjectionState.ACTIVE:
            return "active";
        case InjectionState.FAILED:
            return "failed";
        case InjectionState.SKIPPED_COEXIST:
            return "skipped-coexist";
        case InjectionState.QUARANTINED:
            return "quarantined";
        default:
            return "waiting";
        }
    }
}

public class InjectionStatus : Object {
public string id { get; construct; }
public string process { get; construct; }
public InjectionState state { get; construct; }

public InjectionStatus(string id, string process,
                       InjectionState state) {
    Object(id: id, process: process, state: state);
}
}

// Atomic (temp file + rename) write of inject-status.json, app-readable.
// Reports daemon/manifest versions, kill-switch and panic-quarantine state,
// and every per-injection state. See app-interface#Daemon-written status.
public class Status : Object {
public string path { get; construct; }
// The daemon sets this at startup from the generated DAEMON_VERSION
// (single source of truth: the project () version in meson.build).
// ci-versioning forbids defining the version anywhere else, so it is
// never hardcoded here; host tests that construct Status directly leave
// it empty (they do not link the daemon entry point).
public string daemon_version { get; set; default = ""; }
// Daemon state visible to the app: "ready" normally, "degraded" when
// self-verification failed or the frida-core local device could not be
// opened (observe-only; injects nothing until restarted). Without this
// field DEGRADED would be indistinguishable from "no injections yet".
// See app-interface "Daemon-written status".
public string daemon_state { get; set; default = "ready"; }
public int manifest_version { get; set; default = 0; }
public bool kill_switch { get; set; default = false; }
public bool panic_quarantine { get; set; default = false; }

private GenericArray<InjectionStatus> injections;

public Status(string path) {
    Object(path: path);
    this.injections = new GenericArray<InjectionStatus> ();
}

public void set_injection(string id, string process,
                          InjectionState state) {
    for (uint i = 0; i < this.injections.length; i++) {
        if (this.injections[i].id == id &&
            this.injections[i].process == process) {
            this.injections[i] = new InjectionStatus(
                id, process, state);
            return;
        }
    }
    this.injections.add(new InjectionStatus(id, process, state));
}

public string serialize() {
    var b = new Json.Builder();
    b.begin_object();
    b.set_member_name("daemon");
    b.add_string_value(this.daemon_version);
    b.set_member_name("manifest");
    b.add_int_value(this.manifest_version);
    b.set_member_name("state");
    b.add_string_value(this.daemon_state);
    b.set_member_name("killed");
    b.add_boolean_value(this.kill_switch);
    b.set_member_name("panic");
    b.add_boolean_value(this.panic_quarantine);
    b.set_member_name("injections");
    b.begin_array();
    for (uint i = 0; i < this.injections.length; i++) {
        var inj = this.injections[i];
        b.begin_object();
        b.set_member_name("id");
        b.add_string_value(inj.id);
        b.set_member_name("process");
        b.add_string_value(inj.process);
        b.set_member_name("state");
        b.add_string_value(inj.state.label());
        b.end_object();
    }
    b.end_array();
    b.end_object();

    var gen = new Json.Generator();
    gen.set_root(b.get_root());
    gen.pretty = true;
    return gen.to_data(null);
}

// write_atomic: write a temp file, fsync it, then rename over the target
// so the data is on stable storage before the directory entry switches
// (atomic within one filesystem). The temp lives in the same dir as the
// target. The dir is the app zone (app-writable, untrusted), so the chmod
// and fsync operate on an fd opened with O_NOFOLLOW: set_contents already
// replaces a pre-placed symlink at the temp path with a regular file, and
// O_NOFOLLOW then refuses the temp if a racing app swaps it back to a
// symlink — fchmod/fsync act on the opened inode, never following a path
// at a root-owned file. See app-interface "Daemon-written status".
public void write_atomic() throws Error {
    string data = serialize();
    string dir = Path.get_dirname(this.path);
    string tmp = Path.build_filename(dir, ".inject-status.tmp");
    FileUtils.set_contents(tmp, data);
    int fd = Posix.open(tmp, Posix.O_WRONLY | Posix.O_NOFOLLOW);
    if (fd < 0) {
        // Temp is a symlink (race) or open failed: do not touch it by
        // path (could follow a symlink at a root file); remove and abort.
        FileUtils.unlink(tmp);
        throw new IOError.FAILED("status temp open refused");
    }
    Posix.fchmod(fd, 0644);
    Posix.fsync(fd);
    Posix.close(fd);
    if (FileUtils.rename(tmp, this.path) != 0) {
        FileUtils.unlink(tmp);
        throw new IOError.FAILED("status rename failed");
    }
}
}
}
