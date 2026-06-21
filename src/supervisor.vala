namespace Voboost {
public enum DaemonState {
    INIT,
    VERIFY_SELF,
    READY,
    DEGRADED;

    public string label() {
        switch (this) {
        case DaemonState.VERIFY_SELF:
            return "verify_self";
        case DaemonState.READY:
            return "ready";
        case DaemonState.DEGRADED:
            return "degraded";
        default:
            return "init";
        }
    }
}

// Daemon state machine: INIT -> VERIFY_SELF -> READY/DEGRADED, then per
// target GATE/ATTACH -> INJECT -> MONITOR. Async error model: every async
// op is wrapped and time-bounded; no error breaks the GMainLoop. Agents are
// injected as soon as their target is reachable; an agent with `boot` in the
// manifest is deferred until sys.boot_completed=1. See daemon-lifecycle spec.
public class Supervisor : Object {
public DaemonState state { get; private set; default = DaemonState.INIT; }
public string root_zone { get; construct; }
public string app_zone { get; construct; }
public TrustStore trust { get; construct; }
public Manifest manifest { get; construct; }
public FridaController frida { get; construct; }
public Safety safety { get; construct; }
public ProcessWatcher watcher { get; construct; }
public AppZoneWatcher app_watcher { get; construct; }
public Status status { get; construct; }
public Ota ota { get; construct; }

// plan is accessed via an immutable snapshot reference. Reload swaps the
// reference atomically so that in-flight injections reading the old
// snapshot are never racing against a partial update. GLib's GMainLoop
// is single-threaded, so a simple reference swap is safe.
private Plan? plan = null;
// True while an injection cycle is in progress; deferred reload waits.
private bool inject_in_progress = false;
private bool reload_pending = false;
// Set when a core apply requested the self-shutdown (init restart). run() checks
// it after the boot early-apply so it does not start an injection cycle that the
// pending SIGTERM teardown would immediately discard.
private bool core_self_shutdown_requested = false;
// GLib source id of the boot poll (0 = not running); see maybe_watch_boot.
private uint boot_timer = 0;
// Cached process→agents map rebuilt on each plan reload so that
// agents_for_process () is O (1) per spawn event instead of rebuilding the
// full map on every call (spawn-gating fires for EVERY process on the
// device, so the map must not be O (agents × entries) per event).
private HashTable<string, GenericArray<AgentDef> >? proc_map = null;

public Supervisor(string root_zone, string app_zone, TrustStore trust,
                  Manifest manifest, FridaController frida,
                  Safety safety, ProcessWatcher watcher,
                  AppZoneWatcher app_watcher, Status status, Ota ota) {
    Object(root_zone: root_zone, app_zone: app_zone, trust: trust,
           manifest: manifest, frida: frida, safety: safety,
           watcher: watcher, app_watcher: app_watcher,
           status: status, ota: ota);
}

public async void run() {
    this.state = DaemonState.VERIFY_SELF;
    // OTA boot recovery: restore manifest.json.prev if the active manifest is
    // absent or fails signature verification (atomic-apply-rollback).
    this.ota.recover_manifest();
    if (!yield verify_self()) {
        // OTA: a DEGRADED restart with a pending core switch rolls back to the
        // previous binary instead of staying degraded (atomic-apply-rollback).
        if (this.ota.core_switch_pending()) {
            this.ota.rollback_core_switch();
            Log.err("supervisor",
                    "DEGRADED after core switch; rolling back and exiting");
            Posix.kill(Posix.getpid(), Posix.Signal.TERM);
            return;
        }
        this.state = DaemonState.DEGRADED;
        this.status.daemon_state = "degraded";
        this.status.kill_switch = false;
        write_status_safe();
        Log.err("supervisor", "DEGRADED: self-verification failed");
        return;
    }

    this.state = DaemonState.READY;
    this.status.daemon_state = "ready";
    this.status.manifest_version = this.manifest.manifest_version;
    // OTA: a READY restart confirms a pending core switch (clear marker, GC the
    // previous binary) — atomic-apply-rollback "Ready restart confirms".
    if (this.ota.core_switch_pending()) {
        this.ota.confirm_core_switch();
    }
    Log.ok("supervisor", "READY");

    load_plan();
    wire_events();

    // frida open failure -> DEGRADED (observe-only, injects nothing):
    // daemon-lifecycle spec "frida-core local device cannot be opened".
    if (!yield this.frida.open()) {
        this.state = DaemonState.DEGRADED;
        this.status.daemon_state = "degraded";
        write_status_safe();
        Log.err("supervisor", "DEGRADED: frida device open failed");
        return;
    }
    // Start the process watcher BEFORE enabling spawn-gating so the full
    // signal chain (spawn_added -> spawn_observed -> target_spawned ->
    // inject_target) is connected when the first gated spawn arrives.
    // Without this, spawns arriving during the enable_spawn_gating yield
    // fire spawn_observed with no handler connected and stay suspended
    // indefinitely (inject_running_targets finds them but inject_running
    // does not call resume_safe).
    this.watcher.start();
    // Spawn-gating failure is not fatal: the daemon degrades to attach-only
    // mode (running targets are still injected, but new spawns are missed
    // until the daemon is restarted).
    if (!yield this.frida.enable_gating()) {
        Log.err("supervisor",
                "spawn-gating failed; attach-only mode");
    }
    try {
        this.app_watcher.start();
    } catch (Error e) {
        Log.err("supervisor", "watcher start: " + e.message);
    }

    // OTA: apply a staged agent update before the first injection so the first
    // set is current (atomic-apply-rollback "before the first injection").
    yield apply_staged_update(false);
    // A staged core apply requested a self-shutdown (init restart): do not
    // begin an injection cycle that the pending SIGTERM teardown discards.
    if (this.core_self_shutdown_requested) {
        return;
    }

    yield inject_running_targets();
    // If any agent is deferred on boot, poll until boot completes and
    // inject the deferred agents then.
    maybe_watch_boot();
    write_status_safe();
}

// Verify the manifest signature and every agent sha256.
// Frida-lib integrity: frida-core is statically linked into this binary;
// the daemon binary itself is signed and verified by the OS init hook
// (root zone is root-owned, cannot be replaced by the app). There is no
// separate frida lib on disk to verify at runtime — waiver recorded here
// per design D10. See daemon-lifecycle spec VERIFY_SELF scenario.
private async bool verify_self() {
    // Defense-in-depth: SELinux is permissive, so the trust boundary
    // rests on Unix ownership. Refuse to trust a misprovisioned root zone
    // (not root-owned, or group/world-writable) and stay DEGRADED.
    if (!root_zone_secure()) {
        Log.err("supervisor", "root zone ownership/mode check failed");
        return false;
    }
    string mpath = Path.build_filename(this.root_zone, "manifest.json");
    string spath = Path.build_filename(this.root_zone, "manifest.sig");
    uint8[] json_bytes;
    uint8[] sig;
    try {
        // g_file_get_data always appends a trailing NUL beyond the length,
        // so the (string) cast in load_verified is safe to read as C string.
        FileUtils.get_data(mpath, out json_bytes);
        FileUtils.get_data(spath, out sig);
    } catch (Error e) {
        Log.err("supervisor", "manifest read: " + e.message);
        return false;
    }
    if (!this.manifest.load_verified(json_bytes, sig, this.trust)) {
        Log.err("supervisor", "manifest signature rejected");
        return false;
    }
    for (uint i = 0; i < this.manifest.agents.length; i++) {
        var a = this.manifest.agents[i];
        string ap = Path.build_filename(this.root_zone, a.file);
        if (!this.trust.verify_agent(ap, a.sha256)) {
            Log.err("supervisor", "sha256 mismatch: " + a.id);
            return false;
        }
    }
    return true;
}

// Root zone must be root-owned and not group/world-writable. Parent-dir
// ownership is the primary guarantee (the app cannot rename/replace it);
// this runtime check additionally catches a misprovisioned zone under
// permissive SELinux. See app-interface "On-disk trust boundary".
private bool root_zone_secure() {
    Posix.Stat st;
    if (Posix.stat(this.root_zone, out st) != 0) {
        Log.err("supervisor", "root zone stat failed");
        return false;
    }
    if (st.st_uid != 0) {
        Log.err("supervisor", "root zone not owned by root");
        return false;
    }
    if ((st.st_mode & (Posix.S_IWGRP | Posix.S_IWOTH)) != 0) {
        Log.err("supervisor", "root zone is group/world-writable");
        return false;
    }
    return true;
}

private void wire_events() {
    this.watcher.target_spawned.connect((process, pid) => {
                inject_target.begin(process, pid);
            });
    this.watcher.target_died.connect((process, pid) => {
                handle_death.begin(process, pid);
            });
    this.app_watcher.plan_changed.connect(() => {
                load_plan();
                apply_plan_diff.begin();
            });
    // OTA: a complete staged update (agents and/or core) is re-verified with the
    // embedded key and applied here. Staged content stays untrusted until the
    // Ota module re-verifies it (app-interface "Staging read boundary").
    this.app_watcher.update_ready.connect(() => {
                apply_staged_update.begin(true);
            });
}

private void load_plan() {
    string p = Path.build_filename(this.app_zone, "inject.json");
    string json = "{}";
    // DoS guard per injection-control: stat is a fast-path hint to
    // skip reading an obviously oversized file (avoids allocating a
    // huge buffer); the post-read check below is the authoritative
    // guard (stat is TOCTOU-prone between the stat and the read).
    if (!plan_file_too_big(p)) {
        try {
            FileUtils.get_contents(p, out json);
        } catch (Error e) {
            json = "{}";
        }
    } else {
        Log.err("plan", "inject.json exceeds MAX_PLAN_BYTES(stat)");
    }
    // Authoritative size guard: catches TOCTOU growth that stat missed.
    if (json.length > PlanReader.MAX_PLAN_BYTES) {
        Log.err("plan", "inject.json exceeds MAX_PLAN_BYTES(read)");
        json = "{}";
    }
    var reader = new PlanReader(this.manifest);
    Plan new_plan = reader.validate(json);

    // The kill-switch flag and the kill/panic status are independent of the
    // injection snapshot, so apply them immediately: a plan `disabled`
    // change must block NEW spawns at once (inject_target re-checks
    // kill_switched () on every gated spawn), even while an in-flight cycle
    // finishes its remaining targets against the old snapshot. Only the
    // snapshot swap + proc_map rebuild must wait for the cycle tail
    // (snapshot isolation).
    this.safety.set_plan_disable_all(new_plan.disable_all);
    this.status.kill_switch = this.safety.kill_switch_active(
        Path.build_filename(this.root_zone, "run"));
    this.status.panic_quarantine = this.safety.panic_quarantined();

    if (this.inject_in_progress) {
        // Defer the snapshot swap + reinjection until the current cycle
        // completes; the tail (inject_running_targets) reapplies it.
        this.reload_pending = true;
        return;
    }
    // Swap the snapshot reference; in-flight reads of the old snapshot
    // complete safely because the GMainLoop is single-threaded.
    this.plan = new_plan;
    this.reload_pending = false;
    this.proc_map = group_enabled_agents_from(new_plan);
}

// stat-based size check (no read): true when inject.json exceeds the
// plan cap. Errors (absent file etc.) report false; the read path then
// handles them. See injection-control "Injection plan validation".
private bool plan_file_too_big(string path) {
    Posix.Stat st;
    if (Posix.stat(path, out st) != 0) {
        return false;
    }
    return st.st_size > PlanReader.MAX_PLAN_BYTES;
}

private async void inject_running_targets() {
    if (kill_switched() || this.frida.is_shut_down) {
        return;
    }
    // Re-entrancy guard. Three callers reach here (run(), apply_plan_diff,
    // and the boot-completion timer) and, because the GMainLoop is
    // single-threaded but this method yields, two entries can overlap
    // (e.g. boot completing while a plan-change cycle is mid-yield). A
    // second concurrent cycle would call allow_attempt again for the same
    // (agent, process) and inflate the rate-limit budget toward a false
    // quarantine. Defer to reload_pending instead: the in-flight cycle
    // reinjects at its tail, so no injection is lost and the budget is
    // consumed once per logical cycle.
    if (this.inject_in_progress) {
        this.reload_pending = true;
        return;
    }
    this.inject_in_progress = true;
    try {
        // Take an immutable snapshot of the plan for this cycle.
        Plan? snapshot = this.plan;
        if (snapshot != null) {
            var per_process = group_enabled_agents_from(snapshot);
            foreach (string process in per_process.get_keys()) {
                // Re-check the teardown latch each iteration: a SIGTERM (or a
                // kill-switch via a path that shuts frida down immediately)
                // runs frida.shutdown () during this loop's find_pid yield,
                // detaching sessions and disabling gating. Without this
                // guard the loop would resume and attach NEW sessions on the
                // half-torn-down device, orphaning them (the finally + tail
                // still run cleanly). This does NOT affect the plan
                // kill-switch mid-cycle, which is deferred to the tail (so
                // is_shut_down stays false through the loop).
                if (this.frida.is_shut_down) {
                    break;
                }
                var agents = per_process.lookup(process);
                uint? pid = yield this.frida.find_pid(process);
                if (pid == null) {
                    mark_waiting(agents);
                    continue;
                }
                // Per-agent boot readiness (marks deferred agents `waiting`).
                var ready = ready_agents(agents);
                if (ready.length == 0) {
                    continue;
                }
                yield do_inject_running(process, pid, ready);
            }
        }
    } finally {
        this.inject_in_progress = false;
    }
    // Apply any deferred plan reload that arrived during this cycle. A
    // kill-switch that arrived mid-cycle is the one case where the shutdown
    // was deliberately deferred to here: load_plan () applied plan_disable_all
    // at once (so new spawns are already blocked via inject_target), but
    // apply_plan_diff does NOT call frida.shutdown () mid-cycle (detaching
    // sessions while this loop keeps attaching new ones on the still-open
    // device would leak them). The tail performs the one guaranteed shutdown
    // once the loop has finished. Without it a mid-cycle kill-switch would
    // leave gating enabled and is_shut_down false, so a later deactivation
    // would resume injection without the required restart (device-safety
    // "Kill-switch is deactivated"). Otherwise re-inject running targets
    // with the new plan.
    if (this.reload_pending) {
        load_plan();
        if (kill_switched()) {
            this.status.kill_switch = true;
            yield this.frida.shutdown();
            // Persist so the app observes the kill-switch without waiting
            // for another event (mirrors apply_plan_diff's post-shutdown
            // write). Without this a mid-cycle kill-switch would leave
            // inject-status.json at killed:false until the next spawn/
            // death/plan change.
            write_status_safe();
        } else if (!this.frida.is_shut_down) {
            yield inject_running_targets();
        }
    }
}

// Handle a spawn-gated target: inject its ready agents, then ALWAYS resume
// the process (guaranteed resume, device-safety). Reached only from the
// target_spawned signal, so the spawn is always gated — every path resumes.
private async void inject_target(string process, uint pid) {
    // Fresh spawn: drop any stale tracking for a recycled pid before
    // injecting, so a delayed death signal for the dead prior process
    // cannot be misattributed to this one (PID-reuse defence).
    this.watcher.clear(pid);
    if (this.frida.is_shut_down) {
        // Frida already torn down (a kill-switch activated earlier, or
        // SIGTERM is mid-teardown and this spawn was gated just before):
        // do NOT inject — a restart is required to resume (device-safety
        // "Kill-switch is deactivated"). The one duty left is to never
        // leave the just-gated process suspended (guaranteed resume).
        yield this.frida.resume_only(pid);
        return;
    }
    if (kill_switched()) {
        // Kill-switch active: injections are already stopped by
        // apply_plan_diff; the one duty left is to never leave the
        // just-gated process suspended (guaranteed resume).
        yield this.frida.resume_only(pid);
        return;
    }
    var agents = agents_for_process(process);
    if (agents.length == 0) {
        // Not a target. Global spawn-gating suspended it, so resume it
        // immediately WITHOUT attaching a session (see resume_only).
        yield this.frida.resume_only(pid);
        return;
    }
    // Drop any stale frida state for a recycled pid BEFORE budgeted ()
    // reads loaded_agents: a not-yet-delivered detached for the dead
    // prior process would otherwise leave loaded_agents[pid] populated,
    // making is_agent_loaded true and letting budgeted skip allow_attempt
    // — so a crash-loop on a reused pid would never consume the rate-limit
    // budget and never per-agent quarantine. Symmetric with watcher.clear
    // above; inject_gated clears again (idempotent) before attach.
    this.frida.clear_pid_state(pid);
    // Per-agent boot readiness: agents with requires_boot wait for
    // sys.boot_completed=1; the rest inject as soon as the process
    // appears (earliest). ready_agents marks the waiters as `waiting`.
    var ready = ready_agents(agents);
    if (ready.length == 0) {
        // Everything here is deferred on boot: resume and wait.
        yield this.frida.resume_only(pid);
        // Boot-deferred agents are marked `waiting` by ready_agents;
        // persist so the app sees them without waiting for another event.
        write_status_safe();
        return;
    }
    var allowed = budgeted(process, pid, ready);
    var res = yield this.frida.inject_gated(
        pid, allowed, config_map(allowed));
    record(process, pid, allowed, res);
    // Track only after a successful inject: process_lost must stay
    // scoped to pids the daemon actually injected so that
    // note_target_death and handle_death only fire for real targets.
    if (res == InjectResult.OK) {
        this.watcher.track(process, pid);
    }
    // Spec (app-interface): status is atomically updated after each
    // injection outcome. Non-targets (agents.length == 0) never reach
    // this point, so no unnecessary I/O on the hot path.
    write_status_safe();
}

private async void do_inject_running(
    string process, uint pid, GenericArray<AgentDef> agents) {
    var allowed = budgeted(process, pid, agents);
    var res = yield this.frida.inject_running(
        pid, allowed, config_map(allowed));
    record(process, pid, allowed, res);
    // Track after successful inject so process_lost fires for this pid
    // and reinjection/safety accounting works (same as gated path).
    if (res == InjectResult.OK) {
        this.watcher.track(process, pid);
    }
    write_status_safe();
}

private async void handle_death(string process, uint pid) {
    // A death delivered while frida is being torn down (SIGTERM) needs no
    // status bookkeeping: the daemon is exiting and the next status is
    // moot. Mirrors the is_shut_down gate at the top of
    // inject_running_targets. (A kill-switch is handled below.)
    if (this.frida.is_shut_down) {
        return;
    }
    this.status.panic_quarantine = this.safety.panic_quarantined();
    if (kill_switched() || this.safety.panic_quarantined()) {
        write_status_safe();
        return;
    }
    // On a target death only the now-quarantined agents change state. The
    // enum has no "dead" state, so a previously-active agent for a dead
    // process keeps its last-known state (ACTIVE) until the process respawns
    // and is re-injected (-> ACTIVE/FAILED): the last-known-outcome /
    // eventually-consistent model the status field is defined to carry.
    var agents = agents_for_process(process);
    for (uint i = 0; i < agents.length; i++) {
        if (this.safety.is_quarantined(agents[i].id, process)) {
            this.status.set_injection(
                agents[i].id, process, InjectionState.QUARANTINED);
        }
    }
    write_status_safe();
}

// On plan change: disable_all/kill-switch stops everything immediately;
// otherwise re-inject running targets. Re-injection is idempotent
// (FridaController reuses the session and skips already-loaded agents),
// so a newly-enabled agent is loaded once and an already-active one is
// not duplicated. A disabled agent simply stops being reinjected and
// clears on the target's next restart (no mid-process live unload).
// Once frida has been shut down (kill-switch activated then deactivated),
// the daemon does NOT resume injections — a restart is required (spec:
// device-safety "Kill-switch is deactivated" scenario).
private async void apply_plan_diff() {
    // load_plan () (always called just before this) already reflected the
    // current kill-switch in status and, via plan_disable_all, blocks new
    // spawns immediately. When a cycle is in flight, do NOT shut frida down
    // here: the in-flight loop would keep attaching sessions on the
    // still-open device after its existing sessions were detached, leaking
    // them. Defer to the cycle tail (inject_running_targets), which performs
    // the one guaranteed shutdown once the loop has finished.
    if (this.inject_in_progress) {
        this.reload_pending = true;
        return;
    }
    this.status.kill_switch = kill_switched();
    if (kill_switched()) {
        yield this.frida.shutdown();
        write_status_safe();
        return;
    }
    if (this.frida.is_shut_down) {
        Log.info("supervisor",
                 "kill-switch deactivated but frida was shut down; "
                 + "restart required to resume injections");
        write_status_safe();
        return;
    }
    yield inject_running_targets();
    write_status_safe();
}

// Decide which agents to inject and reflect the rest in status. An agent
// already loaded into this still-running process is an idempotent
// re-injection (a plan change into a live target): it is forwarded to the
// controller (which skips the actual re-load) WITHOUT consuming the
// rate-limit budget, so a stable agent never accumulates toward a false
// quarantine. A fresh (re-)injection goes through allow_attempt (), whose
// attempts persist across note_success () (see Safety.note_success), so a
// crash-looping agent that loads cleanly still quarantines once the budget
// is spent.
private GenericArray<AgentDef> budgeted(
    string process, uint pid, GenericArray<AgentDef> agents) {
    var allowed = new GenericArray<AgentDef> ();
    for (uint i = 0; i < agents.length; i++) {
        var a = agents[i];
        if (this.frida.is_agent_loaded(pid, a.id)) {
            allowed.add(a);
        } else if (this.safety.allow_attempt(a.id, process)) {
            allowed.add(a);
        } else if (this.safety.is_quarantined(a.id, process)) {
            this.status.set_injection(
                a.id, process, InjectionState.QUARANTINED);
        } else {
            // Denied by the rate-limit backoff window, not (yet)
            // quarantined: report failed, not quarantined.
            this.status.set_injection(
                a.id, process, InjectionState.FAILED);
        }
    }
    return allowed;
}

private void record(string process, uint pid,
                    GenericArray<AgentDef> agents,
                    InjectResult res) {
    for (uint i = 0; i < agents.length; i++) {
        var a = agents[i];
        if (res == InjectResult.SKIPPED_COEXIST) {
            this.status.set_injection(
                a.id, process, InjectionState.SKIPPED_COEXIST);
        } else if (this.frida.is_agent_loaded(pid, a.id)) {
            this.status.set_injection(
                a.id, process, InjectionState.ACTIVE);
            this.safety.note_success(a.id, process);
        } else {
            this.status.set_injection(
                a.id, process, InjectionState.FAILED);
            // Arm exponential backoff so rapid retries of a
            // failing agent are spaced out. note_success resets
            // it on recovery.
            this.safety.note_failure(a.id, process);
        }
    }
}

private void mark_waiting(GenericArray<AgentDef> ? agents) {
    if (agents == null) {
        return;
    }
    for (uint i = 0; i < agents.length; i++) {
        this.status.set_injection(
            agents[i].id, agents[i].process, InjectionState.WAITING);
    }
}

// Per-agent boot-readiness split: an agent with requires_boot waits
// until sys.boot_completed=1; the rest are ready immediately. Deferred
// agents are marked `waiting`; the ready subset is returned. Agents that
// hook late-loading classes should instead defer their own hooks
// (Java.perform / capability detection) rather than set requires_boot.
private GenericArray<AgentDef> ready_agents(
    GenericArray<AgentDef> agents) {
    bool booted = boot_completed();
    var ready = new GenericArray<AgentDef> ();
    for (uint i = 0; i < agents.length; i++) {
        var a = agents[i];
        if (a.requires_boot && !booted) {
            this.status.set_injection(
                a.id, a.process, InjectionState.WAITING);
        } else {
            ready.add(a);
        }
    }
    return ready;
}

// boot has no event to subscribe to, so if any agent is deferred on boot
// and boot is not yet complete, poll until it is, then inject the
// deferred agents. Stops once boot completes (bounded). All other
// readiness is event-driven (D7).
private void maybe_watch_boot() {
    if (this.boot_timer != 0 || boot_completed()
        || !any_requires_boot()) {
        return;
    }
    this.boot_timer = Timeout.add_seconds(2, () => {
                if (!boot_completed()) {
                    return Source.CONTINUE;
                }
                this.boot_timer = 0;
                inject_running_targets.begin((o, r) => {
                    inject_running_targets.end(r);
                    write_status_safe();
                });
                return Source.REMOVE;
            });
}

private bool any_requires_boot() {
    for (uint i = 0; i < this.manifest.agents.length; i++) {
        if (this.manifest.agents[i].requires_boot) {
            return true;
        }
    }
    return false;
}

// Build a process->agents map from a Plan snapshot. Using a snapshot
// parameter prevents a concurrent reload from mutating the map mid-loop.
private HashTable<string, GenericArray<AgentDef> >
group_enabled_agents_from(Plan plan) {
    var map = new HashTable<string, GenericArray<AgentDef> > (
        str_hash, str_equal);
    for (uint i = 0; i < plan.entries.length; i++) {
        var e = plan.entries[i];
        if (!e.enabled) {
            continue;
        }
        var def = this.manifest.find(e.id);
        if (def == null) {
            continue;
        }
        var list = map.lookup(def.process);
        if (list == null) {
            list = new GenericArray<AgentDef> ();
            map.insert(def.process, list);
        }
        list.add(def);
    }
    return map;
}

// O (1) lookup from the cached process→agents map (rebuilt on plan reload).
private GenericArray<AgentDef> agents_for_process(string process) {
    if (this.proc_map == null) {
        return new GenericArray<AgentDef> ();
    }
    var list = this.proc_map.lookup(process);
    return list != null ? list : new GenericArray<AgentDef> ();
}

// id -> opaque config JSON for the agents being injected, taken from the
// current plan snapshot and forwarded verbatim by FridaController (never
// interpreted here). Scoped to the injected agents so disabled entries are
// not serialized into the map; "{}" if the plan is gone (cannot happen for
// an agent that reached injection).
private HashTable<string, string> config_map(
    GenericArray<AgentDef> agents) {
    var map = new HashTable<string, string> (str_hash, str_equal);
    Plan? snapshot = this.plan;
    for (uint i = 0; i < agents.length; i++) {
        string id = agents[i].id;
        string config = "{}";
        if (snapshot != null) {
            for (uint j = 0; j < snapshot.entries.length; j++) {
                if (snapshot.entries[j].id == id) {
                    config = snapshot.entries[j].config;
                    break;
                }
            }
        }
        map.insert(id, config);
    }
    return map;
}

// Kill-switch state is re-checked on every spawn, target death, and plan
// change, so on a normally-busy Android device a run/disable file (or plan
// `disabled`) takes effect within the next event (near-immediate). The
// plan-based switch is the immediate path — it fires plan_changed the moment
// inject.json changes. device-safety scopes the requirement to the behaviour
// once the switch is observed, not to a file-monitor deadline, so no separate
// monitor on run/disable is wired here.
private bool kill_switched() {
    return this.safety.kill_switch_active(
        Path.build_filename(this.root_zone, "run"));
}

// Boot-completion check for boot-deferred agents (manifest `boot:true`).
// Reads sys.boot_completed via `getprop` (the standard Android mechanism).
// NOTE: getprop runs via spawn_sync WHILE global spawn-gating is enabled, so
// it relies on frida-core excluding the controller's own process (and thus
// its getprop child) from gating — otherwise spawn_sync would block the
// GMainLoop and the child's spawn_added could not be delivered/resumed
// (deadlock). Verify on device via integration test #9; if a future frida
// build gates the child, switch boot detection to a non-spawning read.
// The spec's second precondition — frida device open (frida readiness) —
// is guaranteed structurally, not rechecked here: run () calls
// frida.open () and goes DEGRADED on failure BEFORE any injection path is
// reachable, so the device is always open by the time this gate is hit.
// Falls back to the host-test env-var escape hatch on non-Android.
private bool boot_completed() {
    try {
        string[] argv = { "getprop", "sys.boot_completed" };
        string stdout_buf;
        int exit_status;
        Process.spawn_sync(null, argv, null,
                           SpawnFlags.SEARCH_PATH, null,
                           out stdout_buf, null, out exit_status);
        if (exit_status == 0 && stdout_buf.strip() == "1") {
            return true;
        }
    } catch (Error e) {
        // getprop not available (non-Android host or test env); fall
        // through to the env-var escape hatch used in host tests.
    }
    // Host-test escape hatch: allow tests to override boot state.
    return Environment.get_variable("VOBOOST_BOOT_COMPLETED") == "1";
}

private void write_status_safe() {
    try {
        this.status.write_atomic();
    } catch (Error e) {
        Log.err("supervisor", "status write: " + e.message);
    }
}

// OTA: consume a complete staged update from the app-zone staging/ dir. Agent
// plane: re-verify the staged daemon manifest + agent sha256s, swap the manifest
// (immediate), reload, and (when reinject) re-inject. Core plane: re-verify the
// staged release manifest, install the binary content-addressed, repoint the
// launch path, and self-shut down so init restarts the new binary. reinject is
// false on the boot early-apply path (inject_running_targets follows) and true
// on the runtime update_ready path. See ota specs.
private async void apply_staged_update(bool reinject) {
    string staging = Path.build_filename(this.app_zone, "staging");
    // Gate on the update-ready marker (the producer's "complete set ready"
    // signal) and consume it after any attempt, so a successful update is not
    // re-applied on every boot (core plane: that would crash-loop via
    // self-shutdown + init restart). update-planes staging contract.
    if (!this.ota.staged_update_ready(staging)) {
        return;
    }
    // Core plane: a staged binary + signed release manifest. Handled separately
    // because a successful apply ends in a self-shutdown (init restart) and
    // consumes the marker itself before exiting.
    string staged_core = Path.build_filename(staging, "voboost-inject");
    string staged_rm = Path.build_filename(staging, "release-manifest.json");
    string staged_rm_sig = Path.build_filename(
        staging, "release-manifest.json.sig");
    if (FileUtils.test(staged_core, FileTest.EXISTS)
        && FileUtils.test(staged_rm, FileTest.EXISTS)
        && FileUtils.test(staged_rm_sig, FileTest.EXISTS)) {
        yield apply_staged_core(staging, staged_core, staged_rm, staged_rm_sig);
        return;
    }
    // Agent plane: a staged signed daemon manifest.
    string staged_manifest = Path.build_filename(staging, "manifest.json");
    bool applied = FileUtils.test(staged_manifest, FileTest.EXISTS)
                   && do_agent_apply(staging);
    // Consume the marker whether or not the apply succeeded: a present marker
    // implies a complete set (producer contract), so a verified failure is a
    // genuinely bad set the app must re-stage to retry — not something to loop
    // on. On success this prevents the boot-time re-apply.
    this.ota.consume_update_ready(staging);
    if (applied && reinject) {
        yield apply_plan_diff();
    }
}

private async void apply_staged_core(
    string staging, string staged_core, string staged_rm,
    string staged_rm_sig) {
    // DoS guard: reject an oversized staged release manifest before reading it
    // into memory (mirrors apply_core_update's size pre-check).
    Posix.Stat st;
    if (Posix.stat(staged_rm, out st) != 0
        || st.st_size > Ota.MAX_RELEASE_MANIFEST_BYTES) {
        Log.err("supervisor", "staged release-manifest oversize/absent");
        this.ota.consume_update_ready(staging);
        return;
    }
    uint8[] rm_bytes;
    uint8[] rm_sig;
    try {
        FileUtils.get_data(staged_rm, out rm_bytes);
        FileUtils.get_data(staged_rm_sig, out rm_sig);
    } catch (Error e) {
        Log.err("supervisor", "staged release-manifest read: " + e.message);
        this.ota.consume_update_ready(staging);
        return;
    }
    var rm = this.ota.verify_release_manifest(rm_bytes, rm_sig);
    if (rm == null) {
        Log.err("supervisor", "staged release-manifest rejected");
        this.ota.consume_update_ready(staging);
        return;
    }
    var res = this.ota.apply_core_update(staged_core, rm);
    // Consume the marker before the self-shutdown so the post-restart boot does
    // not re-apply the same core (crash-loop). On rejection the bad set is dropped.
    this.ota.consume_update_ready(staging);
    if (res == CoreApplyOutcome.APPLIED) {
        Log.ok("supervisor", "core applied; self-shutdown for init restart");
        this.core_self_shutdown_requested = true;
        write_status_safe();
        // Raise SIGTERM: the installed handler performs the clean teardown
        // (detach sessions, resume pending spawns, release the pidfile lock) and
        // quits the loop, so the process exits and init restarts the new binary
        // (system-ota-survival "Init hook restarts the daemon on exit").
        Posix.kill(Posix.getpid(), Posix.Signal.TERM);
    }
}

// Re-verify and swap the staged daemon manifest, then reload the in-memory
// manifest + plan. Returns false (active set unchanged) if the staged update is
// absent or fails re-verification.
private bool do_agent_apply(string staging) {
    if (!this.ota.apply_agent_update(staging)) {
        return false;
    }
    reload_verified_manifest();
    load_plan();
    return true;
}

private bool reload_verified_manifest() {
    string mpath = Path.build_filename(this.root_zone, "manifest.json");
    string spath = Path.build_filename(this.root_zone, "manifest.sig");
    uint8[] j;
    uint8[] s;
    try {
        FileUtils.get_data(mpath, out j);
        FileUtils.get_data(spath, out s);
    } catch (Error e) {
        return false;
    }
    return this.manifest.load_verified(j, s, this.trust);
}

public async void shutdown() {
    if (this.boot_timer != 0) {
        Source.remove(this.boot_timer);
        this.boot_timer = 0;
    }
    // Stop the app-zone watcher BEFORE tearing frida down: shutdown () yields
    // (frida detach/disable/resume), and while it is suspended the GMainLoop
    // keeps dispatching, so a plan_changed arriving in that window would
    // otherwise queue another apply_plan_diff / injection cycle onto a
    // controller mid-teardown. Stopping the watcher first closes that path.
    this.app_watcher.stop();
    yield this.frida.shutdown();
    write_status_safe();
}
}
}
