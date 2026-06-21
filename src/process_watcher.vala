namespace Voboost {
// Event-driven target tracking over frida-core device signals: inject on
// spawn, reinject on death within the safety budget. Not polling. The
// watcher only surfaces events; reinjection decisions are gated by Safety
// and executed by the Supervisor. See injection-control#Process watching.
public class ProcessWatcher : Object {
public FridaController frida { get; construct; }
public Safety safety { get; construct; }

// pid -> process name we have decided to act on.
private HashTable<uint, string> tracked;

public signal void target_spawned(string process, uint pid);
public signal void target_died(string process, uint pid);

public ProcessWatcher(FridaController frida, Safety safety) {
    Object(frida: frida, safety: safety);
}

construct {
    this.tracked = new HashTable<uint, string> (
        direct_hash, direct_equal);
}

public void start() {
    // Do NOT track every spawn here: enable_spawn_gating is global in
    // frida-core, so this fires for EVERY process the device spawns.
    // The supervisor decides which spawns are targets and calls track ()
    // only for those it actually injects, so `tracked` (and process_lost)
    // stay scoped to real targets and do not grow without bound.
    this.frida.spawn_observed.connect((process, pid) => {
                target_spawned(process, pid);
            });
    this.frida.process_lost.connect((pid) => {
                string? process = this.tracked.lookup(pid);
                if (process == null) {
                    return;
                }
                this.tracked.remove(pid);
                this.safety.note_target_death();
                target_died(process, pid);
            });
    Log.info("watcher", "process events subscribed");
}

public void track(string process, uint pid) {
    this.tracked.insert(pid, process);
}

// Drop any stale tracking for a pid before it is reused. On Android a
// recycled pid can still carry a not-yet-delivered death signal for the
// dead prior process; forgetting it here keeps death accounting scoped to
// the live process the daemon is about to inject (the per-pid analog of
// FridaController.clear_pid_state, which clears frida's per-pid maps).
public void clear(uint pid) {
    this.tracked.remove(pid);
}
}
}
