# Design — update-planes (add channel B)

<!-- Date: 2026-07-23. Records why root↔process control is files not a socket,
     why the rewrite must be atomic, and why teardown is in-band. -->

## D1 — Why files, not a socket

**Choice:** channel B is world-readable files in a shared dir, not a socket.

**Reasoning:** the injected process may run in an `untrusted_app` SELinux domain.
A `media_rw_data_file`-labeled `0644` file is readable/writable from any domain
with no extra allow rule (machine-verified), so root and the injected process
exchange config/status with zero per-app policy. An abstract socket would need
`allow` rules on both the root domain and every app domain — exactly the policy
churn the file approach avoids. Files also compose with the atomic-rename
guarantee below, which a stream socket does not give for free.

## D2 — Why the rewrite must be atomic (write-tmp + rename)

**Choice:** live config updates write a temp file and `rename` it over the path.

**Reasoning:** the reader (agent runtime) and the writer (daemon) are different
processes with no lock between them. A plain in-place rewrite lets the reader
observe a half-written file on an `inotify` wake. `rename` is atomic on the same
filesystem, so the reader sees either the old or the new complete file, never a
partial one (machine-verified: zero partial reads). The filename filter on the
watch matters because one atomic rewrite emits several `inotify` events
(`CREATE`/`MOVED_TO`/etc.); without the filter the runtime would re-parse config
multiple times per update.

## D3 — Why teardown is an in-band no-agents plan

**Choice:** teardown is driven by a channel-B plan listing no agents, not by
daemon exit.

**Reasoning:** injected code outlives the daemon (see `injection-control`), so
"daemon exits → hooks vanish" is not available and would be wrong even if it were
(it would drop instrumentation on every restart/OTA). The only actor that can
cleanly unhook is the agent runtime inside the target, and the only way to reach
it is channel B. Making teardown an explicit in-band instruction also makes it
idempotent and observable, versus an out-of-band kill that races with live hooks.

## D4 — What this change does NOT touch

- **Channel A / OTA planes** (app+agents APK plane, inject-binary plane, staging
  markers): unchanged here. The agents `.js`→`.dex` shift and native-payload
  self-update are owned by `ota` / `trust-verification` / `release-manifest`.
- **The shared-dir SELinux label**: owned by `selinux-domain`. This change
  assumes the label exists and specifies the file protocol on top of it.
- **The zone path rename** (`/data/voboost` → `/data/voboost-inject`): owned by
  `provisioning`. The channel-B path is written in its final form here only
  because channel B is new (no rename needed).
