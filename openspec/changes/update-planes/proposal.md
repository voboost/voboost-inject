## Why

`update-planes` covers the two OTA planes (app+agents inside the APK, the
inject binary on-device) and the staging contract between the app and the root
daemon — call it **channel A** (user ↔ root: `inject.json`,
`inject-status.json`, staging markers). With frida, the daemon talked to the
code inside a target over frida-RPC (`Script.post`/`message`), so there was no
file-based control plane between root and the injected process.

The new daemon has no frida-RPC. Control between the root daemon and the injected
process is now **channel B**: world-readable files in a dedicated shared
directory, watched with `inotify`. Channel B carries the per-process config to
the implant at injection, delivers live config updates without re-injection,
drives teardown via a "no agents" plan, and lets each injected process publish a
status file the daemon aggregates. None of this exists in the current spec.

This change adds the channel-B requirements. It does not modify the existing
channel-A / OTA-plane requirements (the agents `.js`→`.dex` shift and the
native-payload self-update are owned by the `ota`, `trust-verification`, and
`release-manifest` changes; the zone path rename by `provisioning`). The SELinux
label that makes channel B cross-domain is owned by `selinux-domain`; this change
owns the file protocol.

## What Changes

- **ADDED**:
  - "Channel B is files, not a socket" — root ↔ injected-process control is
    world-readable files in `/data/voboost-inject/shared/`, not a socket.
  - "Config delivery and atomic live-update over channel B" — config seeded at
    injection (path handed to `implant_init`) and rewritten atomically
    (write-tmp+rename, zero partial reads) for live updates, observed by the
    agent runtime via `inotify` filtered by filename.
  - "Teardown via a no-agents plan over channel B" — a plan that lists no agents
    for a process drives the agent runtime's own teardown; the daemon does not
    tear down by exiting.
  - "Per-process agent status aggregated into inject-status.json" — each
    injected process writes its own status file; the daemon aggregates them into
    the channel-A `inject-status.json`; target liveness is read from `/proc`.
- **No existing requirement is modified.**

## Capabilities

### Added Capabilities

- `update-planes`: channel B — the file-based control plane between the root
  daemon and each injected process. It replaces frida-RPC with world-readable
  watched files: atomic config delivery and live-update, teardown by a
  "no agents" plan, and per-process status files aggregated into
  `inject-status.json`.
