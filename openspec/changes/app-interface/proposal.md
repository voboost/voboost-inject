## Why

The `app-interface` spec defines the file-based IPC boundary between the app
and the daemon. It carries several references to the old world that the
ptrace migration invalidates: the root zone path `/data/voboost` (now
`/data/voboost-inject` — see `provisioning`, `daemon-lifecycle`), the daemon
version sourced from `meson.build` (now `Cargo.toml` — see `build-and-signing`),
the DEGRADED cause "frida-core local device could not be opened" (no frida —
see `native-payload`), and debug logging referencing frida `find_pid`/
`enumerate` internals. The status schema also needs to reflect that per-process
status now aggregates channel-B agent statuses (see `update-planes`).

## What Changes

- **MODIFIED**:
  - "On-disk trust boundary" — the root zone path is `/data/voboost-inject`
    (not `/data/voboost`).
  - "Untrusted injection plan input" — the debug-log examples no longer
    reference frida `find_pid`/`enumerate` internals (they reference `/proc`
    scans and ptrace/injector diagnostics); the `log_level` mechanism is
    unchanged.
  - "Daemon-written status readable by the app" — the `daemon` version is
    sourced from `Cargo.toml` (not `meson.build`); the DEGRADED cause is
    restated without frida; the `injections` status is noted as aggregating
    per-process agent statuses from channel B (see `update-planes`).
  - "Root-only logging" — the log path is `/data/voboost-inject/logs/` (not
    `/data/voboost/logs/`).
- **Unchanged**: "Files-only IPC with no socket", "Staging read boundary",
  "Parent-directory fsync after status rename" (mechanism-agnostic).

## Capabilities

### Modified Capabilities

- `app-interface`: the IPC boundary is updated for the zone rename
  (`/data/voboost-inject`), the version source (`Cargo.tomv`), the
  frida-free DEGRADED cause and debug diagnostics, and channel-B status
  aggregation. The files-only IPC, staging boundary, and fsync are unchanged.
