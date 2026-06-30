namespace Voboost {
public enum InjectResult {
    OK,
    FAILED,
    SKIPPED_COEXIST;
}

// Drives embedded frida-core in-process over the local device: no socket,
// no per-injection exec. Spawn-gating for earliest reach + attach for
// running targets; per-process sessions; every agent runs JavaScript on
// frida-core's QuickJS runtime (GumJS) via a per-process session script.
// Guaranteed resume () of every gated process on success, failure, or
// timeout. See injection-control + device-safety specs (D1, D3, D6).
public class FridaController : Object {
public string root_zone { get; construct; }
public Safety safety { get; construct; }
public uint op_timeout_ms { get; construct; }

private Frida.DeviceManager? manager;
private Frida.Device? device;
private HashTable<uint, Frida.Session> sessions;
// pid -> the `detached` signal handler id of its session, so the handler
// can be disconnected when the session is dropped (see forget_session).
private HashTable<uint, ulong> detached_handlers;
// pid -> ids of agents already loaded into that session, so a
// plan-change re-injection is idempotent (no second session, no
// double-load of an already-active agent).
private HashTable<uint, GenericArray<string> > loaded_agents;
// True after shutdown () has been called — the kill-switch calls shutdown
// to detach sessions and disable gating, and the spec requires a daemon
// restart (not a deactivation) to resume injections. Without this flag,
// a deactivated kill-switch would attempt injection on a shut-down
// controller (device is non-null but gating/sessions are torn down).
public bool is_shut_down { get; private set; default = false; }

public signal void spawn_observed(string process, uint pid);
public signal void process_lost(uint pid);

public FridaController(string root_zone, Safety safety,
                       uint op_timeout_ms = 15000) {
    Object(root_zone: root_zone, safety: safety,
           op_timeout_ms: op_timeout_ms);
}

construct {
    this.sessions = new HashTable<uint, Frida.Session> (
        direct_hash, direct_equal);
    this.detached_handlers = new HashTable<uint, ulong> (
        direct_hash, direct_equal);
    this.loaded_agents = new HashTable<uint, GenericArray<string> > (
        direct_hash, direct_equal);
}

// Disconnect a session's `detached` handler and drop the session entry,
// breaking the ref cycle the handler closure otherwise pins: the closure
// captures `self` and `session`, so session -> (its signal handler) ->
// closure -> session (and -> self) is a cycle that GLib never collects.
// Without this disconnect the Session, its Cancellable, and every Script
// loaded into it leak on each target crash-restart for the daemon's whole
// lifetime. Safe to call whether or not the handler has already fired (the
// lookups simply miss). Called from the handler itself, clear_pid_state,
// and shutdown.
private void forget_session(uint pid) {
    ulong hid = this.detached_handlers.lookup(pid);
    this.detached_handlers.remove(pid);
    var s = this.sessions.lookup(pid);
    if (s != null && hid != 0) {
        SignalHandler.disconnect(s, hid);
    }
    this.sessions.remove(pid);
}

// Clear stale state for a PID (defence against PID reuse on Android
// where pids wrap and a new process can recycle a dead target's PID
// before frida's async detached signal arrives). Called before injecting
// a freshly-spawned process whose PID might have been used before — by
// the supervisor BEFORE it reads loaded_agents in budgeted (), so a stale
// is_agent_loaded cannot let a fresh injection skip the rate-limit budget;
// and again (idempotently) inside inject_gated before attach.
public void clear_pid_state(uint pid) {
    forget_session(pid);
    this.loaded_agents.remove(pid);
}

public async bool open() {
    try {
        this.manager = new Frida.DeviceManager();
        this.device = yield this.manager.get_device_by_type(
            Frida.DeviceType.LOCAL);
        this.device.process_crashed.connect((crash) => {
                    // A target that has a session surfaces death via the
                    // session.detached signal (above), whose handler owns the
                    // session lifecycle and is object-identity guarded
                    // against PID reuse. process_crashed is the fallthrough
                    // for a crash with no surviving session: clear the
                    // loaded-agents entry and fire process_lost so the
                    // supervisor re-injects on respawn. When a session still
                    // exists for this pid, leave it to detached.
                    if (this.sessions.contains(crash.pid)) {
                        return;
                    }
                    this.loaded_agents.remove(crash.pid);
                    process_lost(crash.pid);
                });
        Log.ok("frida", "local device opened");
        // NOTE: do NOT reset is_shut_down here. It defaults to false and
        // open () runs once at startup on a fresh controller; a restart
        // (new controller) is required to resume after a kill-switch
        // (device-safety). Resetting here would race a SIGTERM that calls
        // frida.shutdown () during this method's yield — shutdown sets
        // is_shut_down = true, and a resume-into-open would erase it,
        // letting run () proceed to inject on a torn-down controller.
        return true;
    } catch (Error e) {
        Log.err("frida", "open failed: " + e.message);
        return false;
    }
}

// Enable spawn-gating so targets are reached before they run their own
// code. spawn_added is surfaced as spawn_observed for the watcher.
public async bool enable_gating() {
    if (this.device == null) {
        return false;
    }
    try {
        // A gated spawn is matched to a target by its `identifier`; an
        // already-running target is matched by `Process.name` (find_pid).
        // Both are compared against the manifest `process` field, so on
        // the target spawn.identifier MUST carry the process name (the
        // same value enumerate_processes reports as Process.name). This
        // holds for the zygote-forked framework processes in scope and is
        // verified by integration test #1 (spawn-gating earliest reach).
        this.device.spawn_added.connect((spawn) => {
                    spawn_observed(
                        spawn.identifier ?? "", (uint) spawn.pid);
                });
        yield this.device.enable_spawn_gating();
        Log.ok("frida", "spawn-gating enabled");
        return true;
    } catch (Error e) {
        Log.err("frida", "gating failed: " + e.message);
        return false;
    }
}

public async uint? find_pid(string process) {
    if (this.device == null) {
        return null;
    }
    try {
        // frida-core 17.x: enumerate_processes (ProcessQueryOptions?
        // = null, ...); pass explicit defaults for clarity.
        var opts = new Frida.ProcessQueryOptions();
        var procs = yield this.device.enumerate_processes(opts);
        for (int i = 0; i < procs.size(); i++) {
            var p = procs.get(i);
            if (p.name == process) {
                return (uint) p.pid;
            }
        }
    } catch (Error e) {
        Log.err("frida", "enumerate failed: " + e.message);
    }
    return null;
}

// Inject all enabled agents for a gated (just-spawned) pid, then ALWAYS
// resume the process. resume () runs on every path: success, per-agent
// failure, or timeout. Coexistence skip is checked first — but only for
// a pid we have not injected ourselves: after our own injection the
// maps contain our frida agent, and mistaking it for a foreign tool on
// a plan-change re-injection would wrongly skip (device-safety spec).
public async InjectResult inject_gated(
    uint pid, GenericArray<AgentDef> agents,
    HashTable<string, string> config_by_id) {
    // Fresh spawn: clear any stale state from a previous process that
    // held this PID (PID reuse on Android — the old process died but
    // frida's async detached signal may not have arrived yet).
    clear_pid_state(pid);
    if (foreign_coexistence(pid)) {
        yield resume_safe(pid);
        return InjectResult.SKIPPED_COEXIST;
    }

    InjectResult result = yield attach_and_load(
        pid, agents, config_by_id, "early");
    yield resume_safe(pid);
    return result;
}

// Attach to an already-running target and load agents. No resume here:
// a running process was never gated.
public async InjectResult inject_running(
    uint pid, GenericArray<AgentDef> agents,
    HashTable<string, string> config_by_id) {
    if (foreign_coexistence(pid)) {
        return InjectResult.SKIPPED_COEXIST;
    }
    return yield attach_and_load(pid, agents, config_by_id, "late");
}

// A frida footprint counts as foreign coexistence only when WE have not
// injected this pid: our own injections are tracked in loaded_agents.
private bool foreign_coexistence(uint pid) {
    if (this.loaded_agents.contains(pid)) {
        return false;
    }
    return this.safety.coexistence_present(pid);
}

private async InjectResult attach_and_load(
    uint pid, GenericArray<AgentDef> agents,
    HashTable<string, string> config_by_id, string stage) {
    // Look up the loaded-agents set for this pid; create it LAZILY on the
    // first successful load below (not eagerly here). An eager empty entry
    // would make foreign_coexistence () think the daemon already injected
    // this pid even when every load failed, so a re-injection (e.g. a plan
    // change) would skip the /proc/PID/maps check on a pid the daemon has
    // NOT actually injected — contradicting device-safety "Coexistence
    // skip applies only to processes the daemon has not yet injected
    // itself".
    var done = this.loaded_agents.lookup(pid);

    // The frida Session (and thus QuickJS) is opened LAZILY: only the first
    // agent triggers attach, and the session is reused for the rest. See
    // injection-control "Per-agent runtime routing and per-process lazy
    // runtime" (D3).
    Frida.Session? session = this.sessions.lookup(pid);
    bool any_ok = false;
    // attach () is bounded by op_timeout_ms, so attempt it at most once per
    // attach_and_load: if it fails (process gone / refused / timed out),
    // remember the failure and skip the remaining agents rather than
    // re-attaching (and re-timing-out) once per agent — which would block
    // the GMainLoop for N x op_timeout_ms on a multi-agent target whose
    // process is unreachable.
    bool attach_failed = false;
    for (uint i = 0; i < agents.length; i++) {
        var agent = agents[i];
        if (already_loaded(done, agent.id)) {
            any_ok = true;
            continue;
        }
        string config = config_by_id.lookup(agent.id) ?? "{}";
        if (session == null && !attach_failed) {
            session = yield attach(pid);
            if (session == null) {
                attach_failed = true;
            }
        }
        // No session (attach failed or never attempted): skip this agent.
        if (session == null) {
            Log.err("frida",
                    "skip agent %s(no session)".printf(agent.id));
            continue;
        }
        bool ok = yield load_js(session, agent, config, stage);
        if (ok) {
            if (done == null) {
                done = new GenericArray<string> ();
                this.loaded_agents.insert(pid, done);
            }
            done.add(agent.id);
            any_ok = true;
        }
    }
    return any_ok ? InjectResult.OK : InjectResult.FAILED;
}

private static bool already_loaded(
    GenericArray<string> ? done, string id) {
    if (done == null) {
        return false;
    }
    for (uint i = 0; i < done.length; i++) {
        if (done[i] == id) {
            return true;
        }
    }
    return false;
}

// Per-agent load state query: true when the agent was loaded into
// this pid (either in this cycle or a prior one). Used by
// Supervisor.record () for per-agent status/backoff tracking.
public bool is_agent_loaded(uint pid, string agent_id) {
    var done = this.loaded_agents.lookup(pid);
    if (done == null) {
        return false;
    }
    return already_loaded(done, agent_id);
}

// Bounded-op helper: a Cancellable armed by a one-shot timer. disarm ()
// is cancel-aware and idempotent: a fired timer removed itself
// (Source.REMOVE) and a removed source must not be removed again (GLib
// critical), so it removes only a still-pending timer and zeroes the id
// so a second call is a no-op. The caller logs "timed out" based on
// is_cancelled () in its catch block.
private static void disarm(ref uint tid, Cancellable cancel) {
    if (tid != 0 && !cancel.is_cancelled()) {
        Source.remove(tid);
    }
    tid = 0;
}

// Attach a session, used only when a js agent must run (QuickJS is
// instantiated by create_script, not by attach itself). Returns null on
// failure/timeout so the caller continues with whatever else it can
// (per-agent isolation). Reused across plan-change re-injections.
private async Frida.Session? attach(uint pid) {
    var cancel = new Cancellable();
    uint tid = Timeout.add(this.op_timeout_ms, () => {
                cancel.cancel();
                return Source.REMOVE;
            });
    try {
        // frida-core 17.x: attach (uint pid, SessionOptions? = null,
        // Cancellable? = null). null options so `cancel` binds to the
        // cancellable. (Verified vs frida-core 17.11.0 src/frida.vala.)
        var session = yield this.device.attach(pid, null, cancel);
        disarm(ref tid, cancel);
        this.sessions.insert(pid, session);
        ulong hid = session.detached.connect((reason, crash) => {
                    // Only act if THIS session is still the active one for
                    // pid. frida delivers detached asynchronously, so on PID
                    // reuse a stale signal from the dead session can arrive
                    // AFTER clear_pid_state + a fresh attach inserted a NEW
                    // session for the recycled pid — without this guard it
                    // would remove the new session and miscount a death for a
                    // live process (compared by object identity).
                    if (this.sessions.lookup(pid) != session) {
                        return;
                    }
                    forget_session(pid);
                    this.loaded_agents.remove(pid);
                    // Only count as a target death for unexpected
                    // detachments (process crash, transport error),
                    // not for self-requested detach during shutdown.
                    if (reason !=
                        Frida.SessionDetachReason
                        .APPLICATION_REQUESTED) {
                        process_lost(pid);
                    }
                });
        this.detached_handlers.insert(pid, hid);
        return session;
    } catch (Error e) {
        disarm(ref tid, cancel);
        string why = cancel.is_cancelled() ? "timed out" : e.message;
        Log.err("frida", "attach %u failed: %s".printf(pid, why));
        return null;
    }
}

// Load an agent: create a QuickJS session script from source and load it.
// Per-agent isolation; sha256 re-verified immediately before load. Each
// async step is bounded by op_timeout_ms so a hung frida call cannot
// block the GMainLoop (D6, task 6.5).
private async bool load_js(
    Frida.Session session, AgentDef agent, string config,
    string stage) {
    string path = Path.build_filename(this.root_zone, agent.file);
    // Read as raw bytes (no trailing NUL). FileUtils.get_contents returns a
    // string whose .data includes the terminating NUL, so hashing source.data
    // would include the NUL and diverge from the manifest sha256 (computed by
    // gen-fixtures.sh via openssl and by trust_store.sha256_file via
    // FileUtils.get_data, neither of which includes a NUL). get_data matches
    // sha256_file exactly.
    uint8[] data;
    try {
        FileUtils.get_data(path, out data);
    } catch (Error e) {
        Log.err("frida", "agent read %s: %s".printf(
                    agent.id, e.message));
        return false;
    }
    if (Checksum.compute_for_data(ChecksumType.SHA256, data)
        != agent.sha256.down()) {
        Log.err("frida", "sha256 mismatch at load: " + agent.id);
        return false;
    }
    // create_script_bounded takes the source as a string; the NUL-terminated
    // copy it builds from these bytes is identical to the on-disk file.
    string source = (string) data;

    var script = yield create_script_bounded(session, source, agent.id);
    if (script == null) {
        return false;
    }
    script.message.connect((msg, data) => {
                Log.info("agent/" + agent.id, msg);
            });

    if (!(yield load_script_bounded(script, agent.id))) {
        // Load failed (target timeout/error): the script was created but
        // never loaded. Unload it best-effort so the session does not
        // retain an orphaned created-but-not-loaded Script — the rate
        // limit already caps this at max_attempts per (agent, process)
        // before quarantine, but unloading here keeps even that set from
        // pinning the session until the pid is forgotten. unload() on a
        // never-loaded script is a client-side state flip in frida (no
        // agent handle to talk down), so it returns at once — never a
        // hang; a throw (e.g. already destroyed) is swallowed.
        try {
            yield script.unload();
        } catch (Error unload_err) {
        }
        return false;
    }
    // Deliver config via the agent's rpc.exports.init (stage,
    // {config}) over the frida:rpc protocol. Fire-and-forget: the
    // agent's own init path applies it, well within its init-timeout;
    // Script.post is synchronous and non-throwing in frida-core 17.x.
    script.post(rpc_init_message(stage, config), null);
    Log.ok("frida", "loaded " + agent.id);
    return true;
}

// Bounded create_script: timeout-gated session script creation.
// Consolidates the disarm/cancel pattern into one place.
// Returns null on failure/timeout.
private async Frida.Script? create_script_bounded(
    Frida.Session session, string source, string agent_id) {
    var cancel = new Cancellable();
    uint tid = Timeout.add(this.op_timeout_ms, () => {
                cancel.cancel();
                return Source.REMOVE;
            });
    try {
        var opts = new Frida.ScriptOptions();
        opts.runtime = Frida.ScriptRuntime.QJS;
        var script = yield session.create_script(source, opts, cancel);
        disarm(ref tid, cancel);
        return script;
    } catch (Error e) {
        disarm(ref tid, cancel);
        string why = cancel.is_cancelled() ? "timed out" : e.message;
        Log.err("frida", "create_script %s: %s".printf(agent_id, why));
        return null;
    }
}

// Bounded script.load: timeout-gated script loading.
// Returns false on failure/timeout.
private async bool load_script_bounded(
    Frida.Script script, string agent_id) {
    var cancel = new Cancellable();
    uint tid = Timeout.add(this.op_timeout_ms, () => {
                cancel.cancel();
                return Source.REMOVE;
            });
    try {
        yield script.load(cancel);
        disarm(ref tid, cancel);
        return true;
    } catch (Error e) {
        disarm(ref tid, cancel);
        string why = cancel.is_cancelled() ? "timed out" : e.message;
        Log.err("frida", "load %s: %s".printf(agent_id, why));
        return false;
    }
}

// Build the frida:rpc call to the agent's rpc.exports.init (stage,
// parameters) with parameters.config = <opaque config>:
//   ["frida:rpc", 1, "call", "init", [stage, {"config": <config>}]]
// This is the standard Frida RPC wire format (the same call frida-inject
// makes). Raw frida-core exposes only Script.post/message, so the daemon
// speaks the protocol directly. The opaque config is spliced in as a
// parsed node so the agent receives a real object, not a string.
private string rpc_init_message(string stage, string config) {
    var b = new Json.Builder();
    b.begin_array();
    b.add_string_value("frida:rpc");
    b.add_int_value(1);
    b.add_string_value("call");
    b.add_string_value("init");
    b.begin_array();
    b.add_string_value(stage);
    b.begin_object();
    b.set_member_name("config");
    b.add_value(config_node(config));
    b.end_object();
    b.end_array();
    b.end_array();
    var gen = new Json.Generator();
    gen.set_root(b.get_root());
    return gen.to_data(null);
}

// Parse the opaque config JSON into a node to splice into the RPC call;
// an empty object on parse failure (the daemon never interprets config).
private Json.Node config_node(string config) {
    try {
        var p = new Json.Parser();
        p.load_from_data(config, -1);
        var root = p.get_root();
        if (root != null) {
            return root.copy();
        }
    } catch (Error e) {
        Log.err("frida", "config parse: " + e.message);
    }
    var node = new Json.Node(Json.NodeType.OBJECT);
    node.set_object(new Json.Object());
    return node;
}

// Resume a gated process we are NOT injecting (a non-target spawn).
// enable_spawn_gating is GLOBAL in frida-core (every spawn on the device
// is suspended and surfaced), so the overwhelming majority of gated
// spawns are non-targets. They MUST be resumed immediately and cheaply,
// without attaching a session — attaching frida to every process the
// device spawns would be a performance and stability disaster.
public async void resume_only(uint pid) {
    yield resume_safe(pid);
}

// Guaranteed resume: never let a gated process or boot stay suspended.
// Deliberately NOT bounded by op_timeout_ms, unlike attach/create_script/
// load/inject (which wait on the target and can hang, so they carry a
// Cancellable): resume is a synchronous local-device continuation that does
// not wait on the target, and a timed-out resume could leave the process
// suspended and hang boot — exactly the failure device-safety forbids. So
// resume must be allowed to complete. See daemon-lifecycle
// "Resume is not bounded by a timeout".
private async void resume_safe(uint pid) {
    if (this.device == null) {
        return;
    }
    try {
        yield this.device.resume(pid);
    } catch (Error e) {
        Log.err("frida", "resume %u failed: %s".printf(
                    pid, e.message));
    }
}

// Resume every spawn still suspended by the global gate. Required on
// kill-switch and shutdown: disable_spawn_gating stops gating NEW
// spawns but does not resume already-pending ones, and an embedded
// controller never "disconnects" to trigger frida's cleanup. Without
// this, a gated process (worst case: part of boot) would stay
// suspended — the exact failure device-safety forbids.
public async void resume_pending_spawns() {
    if (this.device == null) {
        return;
    }
    try {
        var pending = yield this.device.enumerate_pending_spawn();
        for (int i = 0; i < pending.size(); i++) {
            yield resume_safe((uint) pending.get(i).pid);
        }
    } catch (Error e) {
        Log.err("frida", "enumerate pending spawn: " + e.message);
    }
}

public async void shutdown() {
    // Idempotent: a kill-switch that activates mid injection-cycle can have
    // BOTH apply_plan_diff and the cycle tail (inject_running_targets) call
    // shutdown() before either observes the other's is_shut_down. The second
    // call would re-detach (no-op), re-disable gating (a spurious error log if
    // frida already disabled it), and re-resume pending spawns. Guarding on
    // is_shut_down — set true on the first call before any yield — makes the
    // second call a clean no-op. SIGTERM after a kill-switch also lands here as
    // a no-op (frida already torn down), which is correct.
    if (this.is_shut_down) {
        return;
    }
    this.is_shut_down = true;
    // Copy pids first to avoid iterator invalidation when the
    // detached signal handler removes entries mid-loop.
    uint[] pids = {};
    foreach (uint pid in this.sessions.get_keys()) {
        pids += pid;
    }
    foreach (uint pid in pids) {
        var s = this.sessions.lookup(pid);
        if (s != null) {
            try {
                yield s.detach();
            } catch (Error e) {
                // Best-effort detach on shutdown; log omission.
                Log.err("frida",
                        "detach %u on shutdown: %s".printf(
                            pid, e.message));
            }
        }
        // Disconnect the `detached` handler and drop the session, breaking
        // the closure ref cycle (see forget_session). detach() may already
        // have fired the handler (APPLICATION_REQUESTED, which the handler
        // excludes from process_lost); forget_session is idempotent either
        // way, so this also covers sessions whose detach never delivered.
        forget_session(pid);
    }
    this.sessions.remove_all();
    this.detached_handlers.remove_all();
    this.loaded_agents.remove_all();
    if (this.device != null) {
        try {
            yield this.device.disable_spawn_gating();
        } catch (Error e) {
            // Best-effort disable on shutdown; log the error.
            Log.err("frida",
                    "disable spawn-gating on shutdown: " + e.message);
        }
        // Resume anything the gate still holds (see above): guaranteed
        // resume applies to shutdown too.
        yield resume_pending_spawns();
    }
}
}
}
