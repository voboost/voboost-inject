## ADDED Requirements

### Requirement: Ptrace injection via libinjector

The daemon SHALL inject by calling `libinjector`'s flat C-ABI entry
`vbi_inject(pid, so_path, init_sym)` (see `native-payload`), opening no socket
and driving no frida device. It SHALL pass the matching-ABI `libimplant.so`
path as `so_path` and `"implant_init"` as `init_sym`. The daemon SHALL NOT link
`libimplant.so` or any LSPlant/Dobby symbol; its only native seam is the
`extern "C"` call to `libinjector`. The `vbi_inject` return value
(ok / denied / target-gone / dlopen-failed / init-failed) SHALL be surfaced to
device-safety for rate-limit and quarantine accounting.

#### Scenario: Daemon injects through the injector

- **WHEN** the daemon needs to inject an agent set into a target
- **THEN** it calls `vbi_inject(pid, libimplant_<abi>.so, "implant_init")`,
  opening no socket and using no frida

#### Scenario: Injection failure is accounted by safety

- **WHEN** `vbi_inject` returns a non-ok code (denied / target-gone /
  dlopen-failed / init-failed)
- **THEN** the daemon records the outcome for the target and feeds it to the
  device-safety rate-limit and quarantine logic, and does not treat it as a
  successful injection

### Requirement: Reconciliation by the libimplant.so maps marker

The daemon SHALL treat injected code as outliving it: `libimplant.so` and its
agents live in the target independently of the daemon process. On startup and on
every plan change, for each target the daemon SHALL read `/proc/<pid>/maps` and
check for
the real `libimplant.so` path (the `native-payload` idempotency marker). If the
marker is present the target is already injected: the daemon SHALL NOT
re-inject, and SHALL only update that target's config over channel B. A daemon
restart — including an OTA self-update — SHALL reconcile against the marker
rather than re-inject, and SHALL NOT tear down existing hooks. The daemon SHALL
NOT drive teardown by exiting; agent teardown is driven by a "no agents" plan
over channel B (see `update-planes`).

#### Scenario: Startup reconcile skips an already-injected target

- **WHEN** the daemon starts and finds the real `libimplant.so` path in a
  target's `/proc/<pid>/maps`
- **THEN** it treats the target as already injected, does not re-inject, and
  reconciles config over channel B

#### Scenario: Daemon restart does not tear down hooks

- **WHEN** the daemon restarts (crash-restart or OTA self-update) while targets
  hold live injections
- **THEN** the injected code keeps running, the daemon reconciles by the maps
  marker, and there is no teardown storm

#### Scenario: Plan change into an injected target only updates config

- **WHEN** a plan change targets a process whose maps already show the
  `libimplant.so` marker
- **THEN** the daemon writes the updated config over channel B and does not open
  a second injection

## MODIFIED Requirements

### Requirement: Process watching and bounded reinjection

The daemon SHALL watch for target processes by polling `/proc` (there are no
frida process events), injecting when a target appears and reinjecting after a
target dies and reappears, subject to the device-safety rate-limit and
quarantine rules. Target death SHALL be detected by the disappearance of
`/proc/<pid>` (frida's `Session.detached` / `process_crashed` signals are gone).
Reinjection SHALL be idempotent against the maps marker: a target already
carrying the `libimplant.so` marker is not re-injected.

#### Scenario: Target appears after READY

- **WHEN** a watched target process appears in `/proc`
- **THEN** the daemon injects its agents once, provided the maps marker is not
  already present

#### Scenario: Target dies and is restarted

- **WHEN** a watched target's `/proc/<pid>` disappears and the process
  reappears within the allowed reinjection budget
- **THEN** the daemon reinjects its agents

#### Scenario: Re-injection into a still-injected target is idempotent

- **WHEN** a plan change or process event would re-inject a target whose
  `/proc/<pid>/maps` already shows the `libimplant.so` marker
- **THEN** the daemon does not inject again; it only updates config over
  channel B

#### Scenario: /proc scan tolerates races

- **WHEN** a `/proc/<pid>` entry disappears mid-scan (process exited)
- **THEN** the watcher skips that entry and continues, rather than failing the
  whole pass

### Requirement: Opaque config delivery to agents

The daemon SHALL deliver each agent's validated `config` verbatim by writing it
to the target's channel-B config file, whose path it passes to `implant_init`
at injection and rewrites atomically for live updates thereafter (channel-B
transport mechanics are owned by `update-planes`; the Java consumption seam is
owned by `agent-entry-seam`). The daemon SHALL treat `config` as **opaque** — it
SHALL NOT inspect or interpret its contents (no parameter schema); config
semantics belong to the app and the agent. There is no frida `rpc.exports.init`.

#### Scenario: Agent receives config via the channel-B file

- **WHEN** an agent set is injected into a target
- **THEN** the daemon writes the validated per-process config to the target's
  channel-B config file and passes its path to `implant_init`, which the agent
  runtime reads on init

#### Scenario: Config is live-updated atomically

- **WHEN** a plan change alters the config for an already-injected target
- **THEN** the daemon rewrites the channel-B config file atomically
  (write-tmp+rename), and does not re-inject

#### Scenario: Daemon does not interpret config

- **WHEN** the daemon delivers an agent's config
- **THEN** it passes the bytes verbatim and never parses or validates their
  semantics (only the size bound of the plan-validation requirement applies)

### Requirement: Running targets resolved by package id via /proc

The daemon SHALL resolve a target's pid by scanning `/proc` and matching the
manifest `process` field against `/proc/<pid>/cmdline` `argv[0]`. `argv[0]` is
the bytes of `/proc/<pid>/cmdline` up to the first NUL byte (which separates
`argv[0]` from `argv[1]`); the daemon SHALL take that leading token and compare
it directly against `process`, and SHALL NOT split the file on the NUL byte.
This resolves both app targets (`argv[0]` is the package id, e.g.
`com.qinggan.app.launcher`) and native/system targets (`argv[0]` is the binary
name, e.g. `system_server`). There is no frida `enumerate_processes` name match.
The scan SHALL tolerate `/proc/<pid>` entries disappearing mid-scan.

#### Scenario: A running app target is resolved and injected

- **WHEN** the plan targets an already-running Android app by package id
  (e.g. `com.qinggan.app.launcher`)
- **THEN** `find_pid` resolves its pid via `/proc/<pid>/cmdline` `argv[0]`, the
  daemon injects, and `inject-status.json` reports `state: active`

#### Scenario: A native/system target is resolved via cmdline

- **WHEN** the plan targets a process whose `argv[0]` is a binary name
  (e.g. `system_server`)
- **THEN** `find_pid` resolves it from `/proc/<pid>/cmdline` `argv[0]` the same
  way, with no frida name lookup

#### Scenario: argv[0] is taken up to the first NUL, not split

- **WHEN** `find_pid` reads `/proc/<pid>/cmdline`
- **THEN** it takes the bytes up to the first NUL as `argv[0]` and compares that
  directly against `process`, and does not split the contents on the NUL byte

#### Scenario: /proc scan tolerates races

- **WHEN** a `/proc/<pid>` entry disappears mid-scan (process exited)
- **THEN** `find_pid` skips that entry and continues, rather than failing the
  whole lookup

### Requirement: 32-bit target process support

The daemon SHALL be able to inject into both **32-bit (armv7)** and **64-bit
(arm64)** target processes on a mixed-ABI device. This capability is delivered by
`native-payload` runtime bitness detection (the injector detects target bitness
per injection) plus both-ABI payload carriage: the daemon SHALL carry both ABIs
of `libimplant.so` (and the per-ABI hooker prebuilts) and pass the
matching-ABI `libimplant.so` path to `vbi_inject` for each target's detected
bitness. On the target head-unit most system services run as 32-bit processes,
so a daemon that can only reach 64-bit targets is not viable; an ABI mismatch
crashes the target. There is no frida `compat=auto` build option.

#### Scenario: 32-bit target is injected

- **WHEN** the injector detects a 32-bit (armv7) target
- **THEN** the daemon passes the `armeabi-v7a` `libimplant.so` path to
  `vbi_inject` and the agents reach `state: active`

#### Scenario: 64-bit target is injected

- **WHEN** the injector detects a 64-bit (arm64) target
- **THEN** the daemon passes the `arm64-v8a` `libimplant.so` path and injection
  proceeds

#### Scenario: Build missing an ABI cannot inject that ABI's targets

- **WHEN** the daemon is built without one ABI's `libimplant.so` and a target of
  that ABI appears
- **THEN** injection fails for that target (no matching-ABI payload to load),
  and the failure is reported rather than injecting a mismatched-ABI payload

## REMOVED Requirements

### Requirement: In-process frida-core driving

Removed: the daemon no longer embeds or drives frida-core. Injection is a ptrace
entry through `libinjector` (see the added "Ptrace injection via libinjector"
requirement and the `native-payload` capability).

### Requirement: Spawn-gating for earliest injection

Removed: no spawn rail. All agents work in attach mode, and `system_server` is
a long-lived attach target whose event hook covers future `onDisplayChanged`.
Global spawn-gating,
the non-target immediate resume, and the frida-specific gating mechanism no
longer exist.

### Requirement: Per-agent runtime routing and per-process lazy runtime

Removed: there is no QuickJS runtime and no per-process session script. The
injector loads one `libimplant.so` per target, which loads the DEX agents via
`InMemoryDexClassLoader` (see `native-payload`) and calls them through the fixed
Java seam (see `agent-entry-seam`). Multiple agents per process are served by a
single implant/dex load, not by per-agent runtime routing.

### Requirement: Emulator spawn-gating escape hatch

Removed: the `VOBOOST_SKIP_SPAWN_GATING` hatch existed only to survive the
frida-gum `g_assert` abort in `enable_spawn_gating` on the emulator. With no
frida and no spawn-gating, the abort and the hatch are both gone.
