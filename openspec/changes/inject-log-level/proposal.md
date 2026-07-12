## Why

The daemon runs on-device as root and its log is the only diagnostic channel
when something misbehaves in the field. Today it logs only `info`/`ok`/`err`
lines — not enough to diagnose frida attach/inject failures (e.g. why a target
is `waiting`, what `find_pid` returned, whether a spawn was gated). Adding
verbose diagnostics permanently would flood the daily log; rebuilding and
reinstalling the daemon to toggle them is unacceptable for an operator on a
device. A runtime log verbosity, flipped by editing the already-watched
`inject.json`, lets an operator capture a debug trace without rebuild or
reinstall.

`inject.json` is already the single app→daemon hand-off file (the app-interface
spec states "There is no separate `config.yaml`"), already watched by the
app-zone watcher, and already reloaded on change — so a `log_level` field there
is the natural, design-consistent place for a runtime knob (no new file, no new
watcher, no new trust boundary).

## What Changes

- **`inject.json` gains an optional `log_level` field** (`"info"` | `"debug"`,
  default `"info"`; unknown values fall back to `"info"`). Parsed by
  `PlanReader` into `Plan.log_level`.
- **`Log` gains a debug level**: `Log.set_debug (bool)` toggles a static flag,
  `Log.debug (source, msg)` writes (tag `#`) only when the flag is on. The flag
  is applied in `Supervisor.load_plan` right after the plan validates, so a
  `log_level` change takes effect on the next `inject.json` reload (no restart).
- **Verbose diagnostics** added where they were missing: `FridaController.
  find_pid` logs the frida `enumerate_processes` count, name/`/proc`-cmdline
  matches, and the `/proc` scan size — enough to see why a target is `waiting`.

## Impact

- **Operators:** edit `inject.json` (`"log_level": "debug"`), the daemon picks
  it up on the next reload and starts emitting `[#]` debug lines to the same
  daily log file; flip back to `"info"` to stop. No rebuild, no reinstall, no
  daemon restart.
- **Default behaviour:** unchanged — `log_level` absent or `"info"` keeps the
  log exactly as today.
- **Trust/security:** `log_level` is non-sensitive operational metadata read
  from the already-untrusted `inject.json`; it affects only verbosity, not
  injection behaviour. Debug lines must not log secrets (they log process
  names, pids, counts — same data the daemon already handles).
