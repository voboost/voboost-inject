## MODIFIED Requirements

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
