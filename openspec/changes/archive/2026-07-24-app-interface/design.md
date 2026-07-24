# Design — app-interface (zone rename + frida-free status)

<!-- Date: 2026-07-23. Path rename, version source, and frida references;
     the IPC mechanism is unchanged. -->

## D1 — Why the path, version source, and frida references change

**Choice:** the root zone is `/data/voboost-inject`; the daemon version comes
from `Cargo.toml`; DEGRADED and debug-log references no longer mention
frida-core.

**Reasoning:** these are consistency fixes that follow directly from other
Wave 2 changes. The zone rename (see `provisioning`) moves every path; the
version source (see `build-and-signing`) moves with the build system; the
frida removal (see `native-payload`) means the daemon can no longer fail to
"open the frida-core local device" — its DEGRADED causes are self-verification
failure or (new) the inability to verify the payload. The debug-log examples
that referenced frida `find_pid`/`enumerate` internals now reference the
actual new diagnostics (`/proc` scans, ptrace/injector return codes). None of
this changes the IPC *mechanism* (files-only, atomic writes, staging
boundary); it updates the descriptive content to match the new architecture.

## D2 — Why status aggregates channel-B agent statuses

**Choice:** the `injections` status is noted as aggregating per-process agent
statuses reported over channel B (see `update-planes`).

**Reasoning:** in the frida world, the daemon drove each agent session and
knew its status directly. In the ptrace world, the injected code outlives the
daemon and runs independently (see `native-payload`, `injection-control`);
agent status is reported back over channel B as per-process
`<pkg>-agent-status.json`, which the daemon aggregates into
`inject-status.json` (see `update-planes`). The status schema's `injections`
array is the same shape; only its data source changes (direct knowledge →
channel-B aggregation). Noting this keeps the spec honest about where the
status comes from without changing the app-visible contract.
