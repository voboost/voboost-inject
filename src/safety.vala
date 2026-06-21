namespace Voboost {
// Device-safety invariants (D6): per-(agent,process) reinjection rate-limit
// (N per M minutes) with exponential backoff (capped at 30 min) ->
// quarantine -> fail-open; global panic-quarantine on a burst of target
// deaths within a sliding window; coexistence skip via /proc/PID/maps;
// runtime kill-switch (run/disable file or plan disabled flag);
// capability-detection helpers for A9<->A11. See device-safety spec.
public class Safety : Object {
public uint max_attempts { get; construct; }
public uint window_minutes { get; construct; }
public uint panic_threshold { get; construct; }
// Sliding window (seconds) for counting deaths that trigger panic.
public uint panic_window_seconds { get; construct; }

private HashTable<string, AttemptLog> attempts;
private HashTable<string, bool> quarantine;
// Ring buffer of death timestamps for sliding-window panic detection.
private int64[] death_times;
private uint death_head = 0;
private uint death_fill = 0;
private bool panic = false;
private bool plan_disable_all = false;

// MAX_BACKOFF_SECONDS caps the exponential backoff to avoid int overflow.
private const int MAX_BACKOFF_SECONDS = 1800;         // 30 minutes

private class AttemptLog : Object {
// Ring buffer of attempt timestamps; fixed-size, no O (N²) copies
// (consistent with the death_times ring buffer above).
public int64[] times;
public uint head = 0;
public uint fill = 0;
public uint backoff_step = 0;
public int64 next_allowed = 0;

public AttemptLog(uint capacity) {
    this.times = new int64[capacity];
}
}

public Safety(uint max_attempts, uint window_minutes,
              uint panic_threshold,
              uint panic_window_seconds = 300) {
    Object(max_attempts: max_attempts,
           window_minutes: window_minutes,
           panic_threshold: panic_threshold,
           panic_window_seconds: panic_window_seconds);
}

construct {
    this.attempts = new HashTable<string, AttemptLog> (
        str_hash, str_equal);
    this.quarantine = new HashTable<string, bool> (
        str_hash, str_equal);
    // Allocate the death-time ring buffer once. Sized to panic_threshold
    // (or 8 for the panic_threshold==0 misconfig guard) so the ring can
    // always hold enough timestamps for note_target_death's count to reach
    // the threshold — i.e. sz >= panic_threshold holds by construction
    // (panic_threshold==0 trips on count >= 0 regardless of the ring).
    uint sz = this.panic_threshold > 0 ? this.panic_threshold : 8;
    assert(sz >= this.panic_threshold);
    this.death_times = new int64[sz];
}

private static string key(string agent, string process) {
    return agent + "@" + process;
}

// Record an attempt and decide whether it is allowed. Over budget
// within the window -> quarantine the pair and deny (fail-open).
// Honors exponential backoff between attempts. Resets backoff on
// success so a stable injection doesn't accumulate delay.
public bool allow_attempt(string agent, string process) {
    if (this.panic) {
        return false;
    }
    string k = key(agent, process);
    if (this.quarantine.lookup(k)) {
        return false;
    }

    var log = this.attempts.lookup(k);
    if (log == null) {
        log = new AttemptLog(this.max_attempts);
        this.attempts.insert(k, log);
    }

    int64 now = new DateTime.now_local().to_unix();
    if (now < log.next_allowed) {
        return false;
    }

    // Sliding-window rate limit: count how many of the last max_attempts
    // attempts are still inside the window. The ring stores the most recent
    // max_attempts timestamps (writes append an increasing `now`, so the
    // ring holds the last N in increasing order). count reaches
    // max_attempts exactly when max_attempts attempts have all landed
    // within window_minutes — i.e. this IS the "at most N per M minutes"
    // check the spec names, implemented with a fixed-N ring (no unbounded
    // history): once N in-window attempts are recorded the next is
    // quarantined, and attempts older than the window stop counting and are
    // evicted as the ring advances.
    int64 cutoff = now - (int64) this.window_minutes * 60;
    uint count = 0;
    for (uint i = 0; i < log.fill; i++) {
        if (log.times[i] >= cutoff) {
            count++;
        }
    }

    if (count >= this.max_attempts) {
        this.quarantine.insert(k, true);
        return false;
    }

    // Append to the ring buffer.
    uint sz = (uint) log.times.length;
    log.times[log.head % sz] = now;
    log.head++;
    if (log.fill < sz) {
        log.fill++;
    }
    // Backoff is set by note_failure after a failed inject, not here.
    // Separating the two lets allow_attempt enforce the rate window
    // without the backoff timer interfering in tight loops (e.g. tests).
    return true;
}

// Call after a failed inject to arm exponential backoff for the next
// attempt. note_success (below) resets it. Clamps at MAX_BACKOFF_SECONDS.
// The shift is capped at 30 to avoid int32 overflow (1 << 31 is UB in C).
// backoff_step itself is also capped to prevent uint wrap-around producing
// a negative cast (theoretical — requires 2^32 failures — but the guard is
// free).
public void note_failure(string agent, string process) {
    string k = key(agent, process);
    var log = this.attempts.lookup(k);
    if (log == null) {
        return;
    }
    int64 now = new DateTime.now_local().to_unix();
    if (log.backoff_step < 31) {
        log.backoff_step += 1;
    }
    int shift = (int) (log.backoff_step - 1);
    if (shift > 30) {
        shift = 30;
    }
    int64 delay = (int64) (1 << shift);
    if (delay > MAX_BACKOFF_SECONDS) {
        delay = MAX_BACKOFF_SECONDS;
    }
    log.next_allowed = now + delay;
}

// Call after a successful, non-quarantined injection to reset the
// exponential-backoff DELAY only. The attempt ring is intentionally NOT
// cleared: a target that dies shortly after a *successful* load must still
// accumulate attempts toward quarantine (device-safety "Target keeps dying
// right after an agent injects"). Clearing the ring here would let a
// crash-looping agent that loads cleanly re-arm a fresh budget on every
// respawn and so never quarantine (only the global panic would catch it,
// which quarantines every agent, not the culprit).
//
// Stable injections do not accumulate toward a FALSE quarantine all the
// same, because a stable agent never reaches note_success with a fresh
// attempt in the ring: Supervisor.budgeted () skips allow_attempt () for an
// agent already loaded in the still-running process, so a no-op
// re-attestation (e.g. a plan change into a live target) consumes no
// budget. This matches the spec wording verbatim — "reset the backoff
// counter ... so that stable injections do not accumulate delay toward a
// false quarantine" (device-safety) — backoff, not the attempt count.
public void note_success(string agent, string process) {
    string k = key(agent, process);
    var log = this.attempts.lookup(k);
    if (log != null) {
        log.backoff_step = 0;
        log.next_allowed = 0;
    }
}

public bool is_quarantined(string agent, string process) {
    return this.panic || this.quarantine.lookup(key(agent, process));
}

// Count a target death using a sliding window ring buffer. Panic trips
// only when panic_threshold deaths occur within panic_window_seconds.
// This prevents a lifetime-total counter from latching panic forever.
public void note_target_death() {
    int64 now = new DateTime.now_local().to_unix();
    uint sz = (uint) this.death_times.length;
    this.death_times[this.death_head % sz] = now;
    this.death_head++;
    if (this.death_fill < sz) {
        this.death_fill++;
    }

    // Count deaths inside the window.
    int64 cutoff = now - (int64) this.panic_window_seconds;
    uint count = 0;
    for (uint i = 0; i < this.death_fill; i++) {
        if (this.death_times[i] >= cutoff) {
            count++;
        }
    }
    if (count >= this.panic_threshold) {
        this.panic = true;
    }
}

// Clear the panic state and death ring buffer (manual recovery path).
public void clear_panic() {
    this.panic = false;
    this.death_head = 0;
    this.death_fill = 0;
}

public bool panic_quarantined() {
    return this.panic;
}

public void set_plan_disable_all(bool value) {
    this.plan_disable_all = value;
}

// Kill-switch active when run/disable exists or the plan set disabled.
public bool kill_switch_active(string run_dir) {
    if (this.plan_disable_all) {
        return true;
    }
    string p = Path.build_filename(run_dir, "disable");
    return FileUtils.test(p, FileTest.EXISTS);
}

// Coexistence skip: another Frida tool already mapped into the process.
public bool coexistence_present(uint pid) {
    string p = "/proc/%u/maps".printf(pid);
    string contents;
    try {
        if (!FileUtils.get_contents(p, out contents)) {
            return false;
        }
    } catch (Error e) {
        return false;
    }
    return contents.contains("frida-agent") ||
           contents.contains("gum-js-loop") ||
           contents.contains("frida-gadget");
}

// Capability detection (A9 vs A11), device-safety spec: the version string is
// a hint only; the authoritative decision is whether the named symbol/file is
// present. These are the daemon-side detection primitives (file/symbol probe +
// version-string hint); agents additionally detect capabilities at runtime
// (Java.perform / class probes), so no daemon-side routing decision consumes
// them in the inject change — they are exercised by the unit tests and are the
// canonical primitives for any future daemon-side A9/A11 routing.
public bool capability_present(string probe_path) {
    return FileUtils.test(probe_path, FileTest.EXISTS);
}

public bool version_hint_is_a9(string release) {
    return release.has_prefix("9");
}
}
}
