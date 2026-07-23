## ADDED Requirements

### Requirement: Channel B is files, not a socket

Control between the root daemon and an injected process SHALL be world-readable
files in a dedicated shared directory `/data/voboost-inject/shared/`, not a
socket. A `0644` file in that directory is readable from any SELinux domain
without an extra allow rule, whereas an abstract socket from an
`untrusted_app`-domain process would require allow rules on both ends. The shared
directory's `media_rw_data_file` label is owned by `selinux-domain`; this
capability owns the file protocol over it. There SHALL be no frida-RPC and no
socket for root ↔ injected-process control.

#### Scenario: Root and injected process communicate via files

- **WHEN** the daemon needs to send config to, or read status from, an injected
  process
- **THEN** it reads/writes files under `/data/voboost-inject/shared/` and opens
  no socket and uses no frida-RPC

### Requirement: Config delivery and atomic live-update over channel B

The daemon SHALL deliver a target's config over channel B by writing its
per-process config file and passing that file's path to `implant_init` at
injection; the agent runtime reads it on init. For a live update the daemon SHALL
rewrite the file **atomically** (write to a temp file, then `rename` over the
target path), so a reader never observes a partial file. The agent runtime
watches the file with `inotify` and applies the new config without re-injection;
the watch SHALL be filtered by filename so the handful of `inotify` events a
single atomic rewrite produces collapse to one config-changed action.

#### Scenario: Config seeded at injection

- **WHEN** the daemon injects a target
- **THEN** it writes the per-process config file and passes its path to
  `implant_init`, which the agent runtime reads on init

#### Scenario: Live update is atomic

- **WHEN** the daemon updates an already-injected target's config
- **THEN** it writes a temp file and renames it over the config path, and the
  agent runtime observes the complete new file (never a partial read) and applies
  it without re-injection

#### Scenario: inotify is filtered by filename

- **WHEN** an atomic rewrite fires several `inotify` events
- **THEN** the watch filters by the config filename and coalesces them into a
  single config-changed action

### Requirement: Teardown via a no-agents plan over channel B

Teardown of an injected process's agents SHALL be driven by a channel-B plan that
lists no agents for that process, upon which the agent runtime performs its own
teardown (unhook + release). The daemon SHALL NOT tear down injected code by
exiting or by any out-of-band mechanism; because injected code outlives the
daemon (see `injection-control`), teardown is an explicit in-band instruction, not
a side effect of daemon shutdown.

#### Scenario: No-agents plan tears an injection down

- **WHEN** the daemon writes a channel-B plan that lists no agents for a target
- **THEN** the agent runtime in that target performs its own teardown, and the
  daemon does not attempt to unload code out-of-band

#### Scenario: Daemon exit does not tear down

- **WHEN** the daemon exits (SIGTERM or restart)
- **THEN** injected agents keep running; teardown happens only via a no-agents
  plan, never as a consequence of the exit

### Requirement: Per-process agent status aggregated into inject-status.json

Each injected process SHALL publish its own status file in the channel-B shared
directory (e.g. `<pkg>-agent-status.json`), and the daemon SHALL aggregate those
per-process files into the channel-A `inject-status.json` that the app reads.
Target liveness SHALL be determined from `/proc/<pid>` (a process whose
`/proc/<pid>` is gone is not active), not from the status file alone.

#### Scenario: Daemon aggregates per-process status

- **WHEN** injected processes have written their `<pkg>-agent-status.json` files
- **THEN** the daemon aggregates them into `inject-status.json` for the app to
  read

#### Scenario: Liveness comes from /proc

- **WHEN** a status file exists but the process's `/proc/<pid>` is gone
- **THEN** the daemon does not report that target as active, using `/proc`
  liveness over the stale status file
