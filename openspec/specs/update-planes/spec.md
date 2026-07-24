# update-planes Specification

## Purpose
TBD - created by archiving change ota. Update Purpose after archive.
## Requirements
### Requirement: App-plus-agents update plane
Agents and their signed daemon manifest SHALL be delivered inside the voboost
APK; updating agents SHALL be a new voboost release. This plane SHALL be covered
by the APK's own signature in addition to the daemon-manifest signature. A staged
app+agents update SHALL be applied immediately (atomic manifest swap + re-inject),
not deferred to a restart.

#### Scenario: Agent change ships as a release
- **WHEN** an agent is changed
- **THEN** it is delivered as a new voboost release carrying the updated agent
  and a re-signed daemon manifest inside the APK

#### Scenario: Agent update applies immediately
- **WHEN** the daemon consumes a verified staged agent update
- **THEN** it swaps the manifest and re-injects without restarting the daemon

### Requirement: Core update plane (on-device, no car reboot)
The `voboost-inject` binary (the `inject` channel) SHALL be updatable
on-device without a car reboot: the app downloads the binary and stages it;
the daemon verifies it against the daemon-re-verified release manifest,
installs it under a content-addressed name (`voboost-inject-<sha>`), writes a
switch-pending marker naming the previous active file, repoints the stable
launch path (`/data/voboost/voboost-inject`) to the new file, and performs a
clean self-shutdown; Android init then restarts the service, launching the new
binary. This repo's CI emits only the `inject` release-manifest channel; the
`agents`/`app` channels are produced by the voboost app repo.

#### Scenario: Inject binary update applied without a reboot
- **WHEN** the daemon verifies and installs a staged inject binary, repoints
  the launch path, and self-shuts down
- **THEN** Android init restarts the service and the new binary launches
  without a car reboot

#### Scenario: Inject binary update rolled back on a degraded restart
- **WHEN** the new binary restarts DEGRADED with a switch-pending marker
  present
- **THEN** the daemon repoints the launch path back to the previous binary,
  clears the marker, and self-shuts down, and init restarts the previous
  binary

### Requirement: Producer side of the staging contract
For app+agents updates the app SHALL write the new daemon manifest and agents
into the app-zone `staging/` directory and SHALL create the
`voboost-inject-update-ready` marker only after all staged files are fully
written, so the daemon never reads a partial set. The
`voboost-inject-update-ready` marker is a single-use signal: the daemon SHALL
apply only while it is present and SHALL consume (remove) it after the
attempt, whether the apply succeeded or the set failed verification (see
atomic-apply-rollback "Consume the voboost-inject-update-ready marker after
apply"). This keeps a successful update from being re-applied on every boot.

#### Scenario: Staging completes before the marker
- **WHEN** the app stages a new daemon manifest and agents
- **THEN** it writes all files first and creates
  `voboost-inject-update-ready` last as a single atomic step

#### Scenario: Daemon reads staged content
- **WHEN** the `voboost-inject-update-ready` marker exists
- **THEN** the staged set is complete and consistent for the daemon to
  re-verify with its embedded key

#### Scenario: Daemon consumes the marker after apply
- **WHEN** the daemon finishes applying a staged set (success or verified
  failure)
- **THEN** it removes the `voboost-inject-update-ready` marker, so the next
  boot or a re-fire of the staging watch does not re-apply the same set

#### Scenario: One plane per marker
- **WHEN** a single `voboost-inject-update-ready` marker is staged with
  material for more than one plane (an inject binary AND an agent daemon
  manifest)
- **THEN** the producer has violated the contract; the daemon applies exactly
  one plane per marker — the inject plane when a staged inject binary is
  present (precedence), then consumes the marker — and the agent half is not
  applied until the producer re-stages it under a fresh marker

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

