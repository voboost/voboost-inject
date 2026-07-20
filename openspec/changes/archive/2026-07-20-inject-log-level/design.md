# Design: inject.json log_level

## D1. Why inject.json, not a new file

FACT (app-interface spec): "There is no separate `config.yaml` read by the
daemon." `inject.json` is the single app→daemon hand-off, already watched and
reloaded on change by the app-zone watcher. A `log_level` field there needs no
new file, no new watcher, no new trust-boundary decision — it rides the existing
reload path. A separate config file would contradict the spec and add a second
untrusted-input surface to audit.

## D2. Why a plan field, applied in load_plan

`Supervisor.load_plan` already runs on every reload (initial boot read + every
app-zone change) and is the single point that turns raw `inject.json` into a
validated `Plan`. Applying `Log.set_debug (plan.log_level == "debug")` there —
before any rejection/deferral logic — guarantees a verbosity change takes effect
even when the snapshot swap is deferred (`inject_in_progress`): the operator
sees the change immediately, not after the in-flight cycle.

`Log.debug_enabled` is a static bool (process-global), so `set_debug` is
idempotent and the per-call cost in `Log.debug` is one bool read before the
early return — cheap enough to sprinkle across hot paths (e.g. `find_pid`).

## D3. Tag and file

`LogTag.DEBUG` uses symbol `#` (distinct from `+`/`*`/`-`). Debug lines go to
the same daily log file (`/data/voboost/logs/inject-YYYY-MM-DD.log`, 0600,
7-day retention) — no new file, no new retention rule. An operator greps `#` (or
reads the whole file) to see the verbose trace.

## D4. Where the diagnostics matter (find_pid)

`FridaController.find_pid` was the blind spot: on Android frida's
`enumerate_processes` reports the app *label* as `Process.name` (e.g. "Launcher
Stub"), not the package id a plan targets, so a plan keyed by package never
matched and the agent stayed `waiting` with no log explaining why. The debug
lines now log: the enumerate count, a name match, a `/proc/<pid>/cmdline`
match, and the `/proc` scan size on no-match — enough to see exactly which path
resolved the pid (or why none did).

## D5. What debug lines must NOT log

`log_level` is read from untrusted `inject.json` and debug lines land in a file
the app cannot read (root-only log zone), but a future field operator may raise
verbosity during normal operation. Debug lines therefore log only operational
data already in the daemon's scope — process ids/names, frida enumerate counts,
`/proc` scan sizes, attach/load outcomes — never agent config payloads, keys, or
manifest contents.
