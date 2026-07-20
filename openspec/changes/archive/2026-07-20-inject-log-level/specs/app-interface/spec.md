## MODIFIED Requirements

### Requirement: Untrusted injection plan input
The app SHALL write `inject.json` into its app zone and the daemon SHALL treat it as untrusted
input, validating it against the verified manifest before acting (per the injection-control
capability). `inject.json` is the single app→daemon hand-off file: it carries the `startup` gate
(see daemon-lifecycle), the `disabled` kill-switch, per-agent `enabled` + opaque `config`, and an
optional `log_level` (`"info"` | `"debug"`, default `"info"`; unknown values fall back to
`"info"`). The daemon SHALL forward each agent's `config` verbatim to the agent and SHALL NOT
interpret it beyond a size bound (see injection-control). There is no separate `config.yaml` read
by the daemon. The daemon SHALL apply `log_level` to its logger on every reload (including the
initial boot read) before further plan processing, so flipping it to `"debug"` enables verbose
`[#]` diagnostics (frida enumerate/attach internals, `/proc` scans) in the root-only daily log
without a rebuild, reinstall, or daemon restart.

#### Scenario: Plan changes
- **WHEN** the app writes a new `inject.json`
- **THEN** the daemon detects the change, re-validates it against the manifest, injects any
  newly-enabled agents into their running targets idempotently (an already-loaded agent is not
  loaded twice), and stops (re)injecting agents the plan disabled
- **NOTE** the daemon does NOT live-unload an agent already loaded into a still-running target; a
  disabled agent's effect clears when its target process next restarts (fail-open resume). The
  plan-level `disabled` kill-switch is the immediate stop: it stops all injections and resumes
  gated processes at once (see device-safety).

#### Scenario: log_level toggles debug verbosity at runtime
- **WHEN** `inject.json` sets `"log_level": "debug"` (and the app-zone watcher reloads it)
- **THEN** the daemon starts writing `[#]` debug lines (e.g. `find_pid` enumerate counts and
  `/proc` matches) to the daily log file, without a restart; setting it back to `"info"` (or
  omitting it) stops them

#### Scenario: Unknown or absent log_level is info
- **WHEN** `inject.json` omits `log_level`, or sets it to anything other than `"debug"`
- **THEN** the daemon logs at the default `info` verbosity (no `[#]` debug lines), unchanged
  from before this field existed
