## Purpose
Specify how the daemon drives frida-core for injection: in-process local device, spawn-gating,
per-agent runtime routing, process watching, plan validation, and opaque config delivery.
## Requirements
### Requirement: In-process frida-core driving
The daemon SHALL embed frida-core and drive it in-process over a local device, with no socket
and no per-injection process exec. It SHALL support multiple sessions, one per target process.

#### Scenario: Local device control
- **WHEN** the daemon needs to inject
- **THEN** it uses the embedded frida-core local device API directly,
  opening no socket and exec'ing no helper binary

### Requirement: Spawn-gating for earliest injection
The daemon SHALL spawn-gate not-yet-started targets so that injection happens before the target
runs its own code, and SHALL attach to targets that are already running. Because frida-core's
spawn-gating is **global** (it suspends every process the device spawns, with no per-program
filter), the daemon SHALL resume a non-target gated process immediately WITHOUT attaching a
session, so enabling spawn-gating adds no per-process attach cost to the rest of the device.

#### Scenario: Target not yet started
- **WHEN** a spawn-gated target process is created
- **THEN** the daemon injects its agents before the process executes its own code, then resumes it

#### Scenario: Target already running
- **WHEN** a target process is already running at READY time
- **THEN** the daemon attaches to it and injects its agents

#### Scenario: Non-target process is spawn-gated
- **WHEN** global spawn-gating suspends a process that is not a target of any enabled agent
- **THEN** the daemon resumes it immediately without attaching a session, and never tracks it as a
  target

### Requirement: Per-agent runtime routing and per-process lazy runtime
The daemon SHALL run every agent as JavaScript on frida-core's QuickJS runtime
(GumJS) via a per-process session script (`create_script`). Every target
process that receives at least one agent SHALL be attached (a session opened)
and the QuickJS runtime SHALL be loaded in it. A process that receives no agent
SHALL never be attached (it is resumed immediately — see Spawn-gating).

#### Scenario: Process receives no agent
- **WHEN** a spawned process is not a target of any enabled agent
- **THEN** frida is never attached to it and no runtime is loaded in it

#### Scenario: Process receives an agent
- **WHEN** a target process receives an agent
- **THEN** the QuickJS runtime is loaded in that process and the agent runs on it

### Requirement: Process watching and bounded reinjection
The daemon SHALL watch for target processes via process events (not polling): injecting on spawn,
and reinjecting on target death subject to the device-safety rate-limit and quarantine rules.

#### Scenario: Target appears after READY
- **WHEN** a watched target process spawns
- **THEN** the daemon injects its agents as soon as it appears

#### Scenario: Target dies and is restarted
- **WHEN** a watched target dies and reappears within the allowed reinjection budget
- **THEN** the daemon reinjects its agents

NOTE: `js` targets surface death via the frida `Session.detached` signal; `native`-only targets
(no session) surface a crash via the device `process_crashed` signal. Robust restart-detection for
clean exits of `native`-only targets is refined in the JS→native migration change.

#### Scenario: Re-injection into a still-running target is idempotent
- **WHEN** a plan change triggers re-injection into a target whose session already holds some of
  those agents
- **THEN** the daemon reuses the existing session and loads only the agents not already loaded,
  never opening a second session or loading an already-active agent twice

### Requirement: Injection plan validation
The daemon SHALL validate every entry of the app-written injection plan (`inject.json`) against the
verified manifest before acting: the agent `id` MUST be whitelisted in the manifest, and its
`config` MUST be within the size bound (`MAX_CONFIG_BYTES`); the whole file MUST be within
`MAX_PLAN_BYTES`. Entries failing these checks SHALL be rejected, not injected. The daemon SHALL
treat `config` as **opaque** — it SHALL NOT inspect or interpret its contents (no parameter
schema); config semantics belong to the app and the agent.

#### Scenario: Plan entry references unknown agent
- **WHEN** a plan entry names an agent absent from the manifest
- **THEN** the daemon rejects that entry and does not inject it. An unknown id
  has no manifest `process`, so it forms no known (agent, process) pair and
  carries no `inject-status.json` entry (status reports injection outcomes for
  known pairs only — see app-interface); the rejection is logged (root-only).

#### Scenario: Plan entry config exceeds the size bound
- **WHEN** a plan entry's `config` exceeds `MAX_CONFIG_BYTES` (or the file exceeds `MAX_PLAN_BYTES`)
- **THEN** the daemon rejects that entry and does not inject it
  (a memory/DoS guard, not a schema check)

### Requirement: Opaque config delivery to agents
The daemon SHALL deliver each agent's validated `config` verbatim, without interpreting it. It
SHALL call the agent's `rpc.exports.init(stage, parameters)` with `parameters.config` set to the
config, implementing the `frida:rpc` protocol over `Script.post`/`message`.

#### Scenario: Agent receives config via RPC init
- **WHEN** an agent is loaded
- **THEN** the daemon calls its `rpc.exports.init` with `parameters.config`
  set to the agent's config

### Requirement: Emulator spawn-gating escape hatch

The daemon SHALL provide a `VOBOOST_SKIP_SPAWN_GATING` environment-variable
escape hatch that, when set to `1`, skips the `enable_spawn_gating` call
entirely so the daemon survives in attach-only mode for emulator integration
testing. The escape hatch SHALL NOT be set on production devices. Skipping
spawn-gating SHALL NOT affect attach injection, which uses Linjector
(`inject_running` -> `linjector.inject_library_resource`), not Zymbiote.

Context: frida-core 17.11.0's embedded local-device `enable_spawn_gating`
SIGABRTs the daemon on Android API 28 arm64 emulators. The in-process
Zymbiote prep for zygote loads the `linker64` ELF module, which calls
`gum_metal_array_append` -> `gum_alloc_n_pages(GUM_PAGE_RW)` ->
`g_assert(result != NULL)` -> `abort()`. The abort is in C (frida-gum) and
cannot be caught by Vala `try/catch`, so the documented attach-only graceful
degradation (`enable_gating()` returning `false`) never runs — the process is
gone before the `yield` returns. The escape hatch mirrors the existing
`VOBOOST_BOOT_COMPLETED` test hatch: an emulator-only test affordance.
Production runs on real hardware where the frida-gum `g_assert` does not fire.
The root cause is a frida-gum design choice (OOM-is-fatal in the
metal-allocator); a real fix belongs upstream (a `gum_metal_array` try-variant
with `GError` propagation through `gum_elf_module_load`) and is tracked as
future work.

#### Scenario: Emulator with escape hatch set
- **WHEN** the daemon starts on an Android API 28 arm64 emulator with
  `VOBOOST_SKIP_SPAWN_GATING=1` in its environment
- **THEN** the supervisor skips `enable_spawn_gating`, logs "spawn-gating
  skipped (VOBOOST_SKIP_SPAWN_GATING=1); attach-only mode", reaches READY, and
  stays alive
- **AND** attach injection of running targets continues to work via Linjector

#### Scenario: Emulator without escape hatch
- **WHEN** the daemon starts on an Android API 28 arm64 emulator without
  `VOBOOST_SKIP_SPAWN_GATING` set
- **THEN** the daemon SIGABRTs at `enable_spawn_gating` (frida-gum
  `g_assert(result != NULL)` in `gum_alloc_n_pages`) before reaching READY

#### Scenario: Production device
- **WHEN** the daemon starts on a production device (real hardware)
- **THEN** `VOBOOST_SKIP_SPAWN_GATING` is not set, `enable_spawn_gating`
  succeeds, and spawn-gating operates normally (the frida-gum `g_assert` does
  not fire on real hardware)

### Requirement: Running targets resolved by package id via /proc

The daemon SHALL resolve an already-running target's pid by matching the
manifest `process` field against frida's `enumerate_processes` `Process.name`
first, and, on no match, against `/proc/<pid>/cmdline` `argv[0]`. On Android
frida reports the application label (e.g. "Launcher Stub") as `Process.name`,
not the package id a plan targets ("com.qinggan.app.launcher"), and exposes no
package in `Process.parameters`; `/proc/<pid>/cmdline` `argv[0]` IS the package
id for app processes, so the fallback is what actually resolves app targets.
The frida-name match SHALL remain first so non-Android / native processes
(e.g. `system_server`) frida names by id still resolve. The first match wins.

The `/proc/<pid>/cmdline` read SHALL NOT split the file contents on the NUL
byte. GLib's `g_strsplit` rejects a NUL delimiter (CRITICAL + SIGSEGV), and the
read is unnecessary anyway: `FileUtils.get_contents` returns a NUL-terminated C
string, so the first NUL in `/proc/<pid>/cmdline` (which separates argv[0] from
argv[1]) is already the string terminator — the returned string IS argv[0]. The
daemon SHALL compare the returned string directly against the manifest
`process` field.

#### Scenario: A running app target is resolved and injected
- **WHEN** the plan targets an already-running Android app by package id
  (e.g. `com.qinggan.app.launcher`)
- **THEN** `find_pid` resolves its pid via `/proc/<pid>/cmdline` `argv[0]`
  (frida's label-name match misses), the daemon attaches and injects the agent,
  and `inject-status.json` reports `state: active`

#### Scenario: A native/system target is resolved via frida name
- **WHEN** the plan targets a process frida names by id (e.g. `system_server`)
- **THEN** `find_pid` resolves it from `enumerate_processes` `Process.name`
  without needing the `/proc` fallback

#### Scenario: /proc scan tolerates races
- **WHEN** a `/proc/<pid>` entry disappears mid-scan (process exited)
- **THEN** `find_pid` skips that entry and continues, rather than failing the
  whole lookup

#### Scenario: cmdline is compared without a NUL split
- **WHEN** `find_pid` reads `/proc/<pid>/cmdline` to extract argv[0]
- **THEN** it compares the returned NUL-terminated string directly against the
  manifest `process` field, and SHALL NOT call `g_strsplit` (or equivalent) with
  a NUL delimiter, which would crash the daemon

### Requirement: 32-bit target process support
The daemon SHALL be able to inject its agents into **32-bit (armv7)** target processes on a
mixed-ABI device, not only into 64-bit (arm64) ones. On the target head-unit most system services
run as 32-bit processes (vehicle settings, system service, IME, bluetooth phone, media,
keymanager), so the majority of agents are routed at 32-bit targets; a daemon that can only reach
64-bit processes is not viable on-device. This capability is delivered at build time by the
`frida-core:compat=auto` option (see `build-and-signing`), which embeds frida's 32-bit helper
(`frida-helper-32`) and the armv7 `frida-agent.so` in the daemon ELF. At runtime the existing
`device.attach(pid)` / spawn-gating / `create_script` path is used unchanged — frida selects the
matching-ABI helper per target process automatically once the helper is present in the binary.

#### Scenario: 32-bit target is injected
- **WHEN** the daemon injects an agent into a 32-bit (armv7) target process on the device
- **THEN** the agent reaches `state: active` (not `state: failed` with
  `Unable to handle 32-bit processes`), because the daemon binary carries frida's 32-bit helper

#### Scenario: 64-bit target is unaffected
- **WHEN** the daemon injects an agent into a 64-bit (arm64) target process
- **THEN** injection behaves exactly as before this capability — the 32-bit helper is present in
  the binary but is not used for a 64-bit target

#### Scenario: Build without the 32-bit helper cannot inject into 32-bit targets
- **WHEN** the daemon is built with `frida-core:compat=disabled` (the 32-bit helper omitted) and
  attempts to inject into a 32-bit target process on the device
- **THEN** the injection fails with `Unable to handle 32-bit processes due to build configuration`,
  because the binary carries no 32-bit helper (this is the failure mode this capability removes)

