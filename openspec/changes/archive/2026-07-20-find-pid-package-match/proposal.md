## Why

The daemon attaches to already-running targets by resolving the manifest
`process` field to a pid via `FridaController.find_pid`, which called frida's
`device.enumerate_processes()` and compared `Process.name == process`. On
Android frida reports the application **label** as `Process.name` (e.g.
"Launcher Stub", "Vehicle Setting Stub"), not the package id the plan targets
("com.qinggan.app.launcher"); `Process.parameters` is empty, so the package is
not reachable through frida at all. As a result every plan keyed by package id
(apps) left its running target `waiting` forever — `find_pid` returned null —
and `attach`/`inject_running` never ran. (Spawn-gated injection worked only
because the spawn path carries the pid directly, bypassing `find_pid`.) This is
a latent bug on real devices too, masked where frida happened to name the
process by id.

## What Changes

- **`FridaController.find_pid`** keeps the frida `enumerate_processes` name
  match first (it is correct for native/system processes frida names by id,
  e.g. `system_server`), then falls back to scanning `/proc/<pid>/cmdline`
  `argv[0]`, which is the package id for Android app processes. The first match
  wins.
- Diagnostics for this path are logged at debug verbosity via the
  `inject-log-level` change (enumerate count, name match, `/proc` match,
  scan size).

## Impact

- **Running-target injection:** app processes targeted by package id now resolve
  to a pid and get attached/injected (`state: active`), where before they sat at
  `waiting`. The `attach-launcher` emulator scenario passes.
- **Spawn-gating path:** unchanged (it never used `find_pid`).
- **Non-Android / native processes:** unchanged — the frida name match still
  handles `system_server` and the like; `/proc` is a fallback only.
- **Security:** `/proc` is read by the root daemon only; `cmdline` is public
  process metadata. No new trust surface.
