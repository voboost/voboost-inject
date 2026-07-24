## Purpose
Specify the file-based IPC boundary between the unprivileged app and the root daemon, including
trust zones, hand-off files, status reporting, and logging.
## Requirements
### Requirement: Files-only IPC with no socket
The daemon SHALL communicate with the app exclusively through files; it SHALL NOT open any
listening socket.

#### Scenario: Daemon exposes no socket
- **WHEN** the daemon is running
- **THEN** it listens on no socket and all app communication is via files

### Requirement: On-disk trust boundary

The daemon SHALL keep its trusted state in the root-only zone
`/data/voboost-inject` (root:root, 700) whose entire parent chain is
root-owned, so the unprivileged app cannot read, rename, or replace it. The
app zone `/data/user/0/ru.voboost/` is the only place the app writes.

Additionally, at startup (during VERIFY_SELF) the daemon SHALL check that the
root zone is root-owned and not group/world-writable, and SHALL enter
DEGRADED (inject nothing) if it is not. This is defense-in-depth — the
primary guarantee is parent-directory ownership — because SELinux is
permissive on this device.

#### Scenario: App cannot reach the trusted zone

- **WHEN** the unprivileged app attempts to read or modify
  `/data/voboost-inject`
- **THEN** the operation is denied by Unix permissions and parent-directory
  ownership

#### Scenario: Root zone is misprovisioned

- **WHEN** at startup the root zone is not root-owned or is group/world-writable
- **THEN** the daemon enters DEGRADED and injects nothing

### Requirement: Untrusted injection plan input

The app SHALL write `inject.json` into its app zone and the daemon SHALL treat
it as untrusted input, validating it against the verified manifest before
acting (per the injection-control capability). `inject.json` is the single
app→daemon hand-off file: it carries the `startup` gate (see
daemon-lifecycle), the `disabled` kill-switch, per-agent `enabled` + opaque
`config`, and an optional `log_level` (`"info"` | `"debug"`, default `"info"`;
unknown values fall back to `"info"`). The daemon SHALL forward each agent's
`config` verbatim to the agent and SHALL NOT interpret it beyond a size bound
(see injection-control). There is no separate `config.yaml` read by the
daemon. The daemon SHALL apply `log_level` to its logger on every reload
(including the initial boot read) before further plan processing, so flipping
it to `"debug"` enables verbose `[#]` diagnostics (`/proc` scan details,
ptrace/injector return codes, reconciliation marker matches) in the
root-only daily log without a rebuild, reinstall, or daemon restart.

#### Scenario: Plan changes

- **WHEN** the app writes a new `inject.json`
- **THEN** the daemon detects the change, re-validates it against the
  manifest, injects any newly-enabled agents into their running targets
  idempotently (an already-loaded agent is not loaded twice), and stops
  (re)injecting agents the plan disabled
- **NOTE** the daemon does NOT live-unload an agent already loaded into a
  still-running target; a disabled agent's effect clears when its target
  process next restarts. The plan-level `disabled` kill-switch is the
  immediate stop: it stops all new injections at once (see device-safety).

#### Scenario: log_level toggles debug verbosity at runtime

- **WHEN** `inject.json` sets `"log_level": "debug"` (and the app-zone watcher
  reloads it)
- **THEN** the daemon starts writing `[#]` debug lines (e.g. `/proc` scan
  match counts and ptrace/injector diagnostics) to the daily log file,
  without a restart; setting it back to `"info"` (or omitting it) stops them

#### Scenario: Unknown or absent log_level is info

- **WHEN** `inject.json` omits `log_level`, or sets it to anything other than
  `"debug"`
- **THEN** the daemon logs at the default `info` verbosity (no `[#]` debug
  lines), unchanged from before this field existed

### Requirement: Daemon-written status readable by the app

The daemon SHALL write `inject-status.json` into the app zone
(`/data/user/0/ru.voboost/inject-status.json`) so the unprivileged app can
read it, using an atomic write (temp file + rename). Because the app zone is
app-writable while the daemon runs as root, the write SHALL NOT follow an
attacker-placed symlink at the temp path — a status write SHALL NOT modify
any file outside the status path. This is the one daemon-written file in the
app zone — it is the daemon's outbound channel and carries no trusted state;
the daemon's log, which does carry trusted state, stays in the root-only zone
(see Root-only logging). Status SHALL report the daemon state (`ready` or
`degraded` — without it DEGRADED would be invisible to the app), daemon and
manifest versions, kill-switch state, global panic-quarantine state, and
per-injection state (`active`, `failed`, `skipped-coexist`, `waiting`,
`quarantined`). The per-injection state SHALL aggregate the per-process agent
statuses reported over channel B (see `update-planes`), so the app sees one
coherent status per (agent, process) pair even though the injected code runs
independently of the daemon. The full schema (daemon-written, app-readable):

```json
{
  "daemon": "1.0.0-beta1",
  "manifest": 1,
  "state": "ready",
  "killed": false,
  "panic": false,
  "injections": [
    { "id": "wm-viewport", "process": "system_server", "state": "active" }
  ]
}
```

- `daemon` (string): the build version (`Cargo.toml` `[package].version`, via
  the generated version constant).
- `state` (string): `ready` when the daemon is operating normally;
  `degraded` when self-verification failed or the native payload could not be
  verified (observe-only, injects nothing until restarted).
- `manifest` (int): version field from the verified manifest.
- `killed` (bool): true when the runtime kill-switch is active (either
  `/data/voboost-inject/run/disable` exists or the plan set `disabled`).
- `panic` (bool): true when the global panic-quarantine has tripped (mass
  target deaths exceeded the threshold). When true, no injection happens until
  the daemon is restarted.
- `injections` (array): one entry per known (agent, process) pair, with state
  ∈ `active | failed | skipped-coexist | waiting | quarantined`, aggregated
  from channel-B per-process agent statuses. `waiting` covers any agent that
  is not yet injecting because its target is not currently running OR because
  it is deferred on boot completion (see daemon-lifecycle "Per-agent
  boot-readiness gate"); the field is last-known-outcome /
  eventually-consistent, not a precise reason code.

#### Scenario: Status reflects an injection outcome

- **WHEN** an injection succeeds, fails, is skipped for coexistence, waits, or
  is quarantined
- **THEN** the daemon atomically updates `inject-status.json` with that
  per-injection state (aggregated from the channel-B agent status)

#### Scenario: Panic-quarantine is reported

- **WHEN** global panic-quarantine trips (mass target deaths exceed the
  threshold)
- **THEN** the daemon sets `panic: true` in the next status write

#### Scenario: DEGRADED is visible to the app

- **WHEN** the daemon enters DEGRADED (self-verification or payload
  verification failure)
- **THEN** the next status write carries `"state": "degraded"`

#### Scenario: A symlink in the app zone cannot redirect the status write

- **WHEN** the app pre-places a symlink at the status temp-file path pointing
  at a root-owned file
- **THEN** the daemon's status write does not modify the root-owned file; the
  temp is written and renamed without following the symlink

### Requirement: Staging read boundary
The daemon SHALL read the app-zone `staging/` directory and its `update-ready` marker only as
untrusted input to be verified (the swap mechanics belong to the ota capability). The app SHALL NOT
be able to write into the trusted agent set directly.

#### Scenario: App stages an update
- **WHEN** the app populates `staging/` and creates the `update-ready` marker
- **THEN** the daemon treats the staged content as untrusted pending
  verification, never as already-trusted

### Requirement: Root-only logging

The daemon SHALL log to `/data/voboost-inject/logs/inject-YYYY-MM-DD.log`
(600, root-only) using the shared format
`yyyy-MM-dd HH:mm:ss.SSS [tag] source: message` with tags
`[-]`/`[+]`/`[*]`, and SHALL retain logs for 7 days. It SHALL NOT write its
log into the app zone.

#### Scenario: Daemon emits a log line

- **WHEN** the daemon logs an event
- **THEN** the line is appended to the dated file under
  `/data/voboost-inject/logs/` in the shared format, readable only by root

#### Scenario: Log retention

- **WHEN** a daily log file is older than 7 days
- **THEN** it is removed by retention

### Requirement: Parent-directory fsync after status rename

The daemon's `Status.write_atomic` SHALL fsync the parent directory of the
status file after the atomic rename, so that the directory-entry update
pointing at the new inode is durable on stable storage. The parent directory
SHALL be opened with `O_RDONLY | O_DIRECTORY` (refusing non-directories, so a
racing symlink at the parent path cannot redirect the fsync). The dir fsync
SHALL be best-effort: a failure only delays durability (the temp file's data
is already fsynced) and SHALL NOT abort the write or corrupt the status file.

Context: the temp file's data was already fsynced before the rename, but the
parent directory was not fsynced after the rename, so a crash after rename
could leave the old directory entry pointing at the pre-rename inode (the new
bytes survive on disk but are unreachable). The status file is transient and
the reader tolerates a missing/partial file, so the old code was acceptable;
the dir fsync makes the rename durable as defense-in-depth (R4 carried
finding: `Status.write_atomic()` no dir fsync).

#### Scenario: Status write completes and the dir is fsynced
- **WHEN** the daemon writes `inject-status.json` via `write_atomic`
- **THEN** after the rename succeeds, the parent directory is opened with
  `O_RDONLY | O_DIRECTORY` and fsynced
- **AND** a fsync failure is ignored (the write still succeeds)

#### Scenario: Parent path is a symlink
- **WHEN** a racing app swaps the parent directory path to a symlink
- **THEN** `O_DIRECTORY` refuses to open it (the fd is negative)
- **AND** the fsync is skipped without aborting the write

