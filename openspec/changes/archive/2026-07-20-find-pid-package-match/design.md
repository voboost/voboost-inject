# Design: find_pid matches Android app package via /proc

## D1. The label-vs-package mismatch (FACT)

On the Android emulator, with `log_level: debug`, `find_pid` logged:
`enumerate returned 96 procs`, and the qinggan stub processes appeared as
`name='Launcher Stub' pid=4103` and `name='Vehicle Setting Stub' pid=5956`,
with `parameters=[]`. The plan targets `com.qinggan.app.launcher` /
`com.qinggan.app.vehiclesetting` (package ids). `Process.name == process`
therefore never matched, and `parameters` carried no `package` key to fall back
on. `find_pid` returned null and the agent stayed `waiting`.

This is a deduction from the recorded debug log, not a premise.

## D2. Why /proc/<pid>/cmdline is the right source

On Android, an app process's `/proc/<pid>/cmdline` `argv[0]` IS the package id
(verified: `/proc/4103/cmdline` = `com.qinggan.app.launcher`). It is the same
value `ps` reports and the same key the manifest/plan use. Reading it is a
single `get_contents` per numeric `/proc` entry — cheap, root-only, no frida
dependency. Native/system processes (e.g. `system_server`) have `cmdline`
`argv[0]` equal to their comm name, so they match too.

## D3. Why keep the frida match first

frida's `Process.name` is still the right key for processes frida names by id
(native daemons, `system_server`), and on non-Android hosts it may be the only
source. Keeping it first preserves that path; `/proc` is strictly a fallback
for the Android-app case frida misnames. First match wins.

## D4. Robustness of the /proc scan

- Skip non-numeric entry names (`!n[0].isdigit()`) — `/proc` has `self`,
  `cpuinfo`, etc.
- `FileUtils.get_contents` per pid; a missing/unreadable entry (process exited
  mid-scan) is caught and skipped, not fatal.
- `cmdline` is NUL-separated; `split("\0", 2)[0]` takes `argv[0]` only.
- The scan is bounded by the process count (a few hundred on Android) and runs
  only when the frida match misses — not per-event on the hot spawn path.

## D5. Rejected alternatives

- **Match `Process.parameters["package"]`:** empty on Android (`parameters=[]`
  in the debug log); there is no key to read.
- **Drop frida enumerate entirely, use only /proc:** loses the non-Android /
  native-name path and frida's view of processes it cloaks.
- **`spawn.identifier`-style matching for running targets:** spawn gating
  already does this for spawns; running targets have no spawn event, so a
  pid-resolve step is unavoidable, and `/proc` is the authoritative source.
