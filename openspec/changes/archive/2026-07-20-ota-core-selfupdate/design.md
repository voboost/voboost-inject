## Context

Voboost ships as two APKs: `voboost` (the app) and `voboost-inject` (the root
daemon). The voboost app owns the OTA client and, for the `core` channel,
stages the verified daemon APK into the app-zone `staging/` directory and
creates a single-use `core-update-ready` marker as the last atomic step. The
app NEVER installs the daemon. The daemon owns its own self-update: it observes
the marker, re-verifies the staged APK against its embedded trust, extracts its
own binary, atomically self-replaces, and exits so init restarts the new
binary. This change supersedes the unapplied `ota` change (file-level
incremental core-update + runtime agent manifest-swap).

The daemon's per-agent `manifest.json`+`manifest.sig` is now **build-time
inside the daemon APK** (not runtime-produced by the client). The daemon still
verifies it at VERIFY_SELF against `EMBEDDED_PUBKEY`. There is no runtime
agent plane: agents ride inside the APK and are applied at VERIFY_SELF from
the APK's embedded manifest.

Measured platform facts (unchanged from the superseded design): a system OTA
keeps root and the whole `/data` tree but reverts `/system` (so the init hook
is lost while the daemon binary and agents survive); a car cannot be rebooted
on demand (no fastboot), so an OTA that only took effect "at next boot" would
effectively never apply — this drives the no-reboot self-replace + init-restart
design (D2). On Linux/Android a running process holds its binary by inode, not
by pathname, so `rename(2)` of the running binary is atomic and safe: the
running process keeps executing the old inode until it exits, and the freed
pathname is then repopulated with the new binary for the next exec.

## Goals / Non-Goals

**Goals:**
- The daemon binary updates on-device **without a car reboot**, with automatic
  rollback to the previous binary if the new one comes up DEGRADED.
- The daemon re-verifies every byte it installs into the trusted zone with its
  embedded key (`EMBEDDED_PUBKEY`), never trusting the app's verification.
- The `core-update-ready` marker is single-use: consumed before the apply so a
  successful self-replace + init-restart does not crash-loop on every boot.
- Atomic self-replace with `.prev` rollback; never end up with no binary.
- Survive a system OTA without re-downloading anything; restore the init hook.

**Non-Goals:**
- The OTA client fetch/diff/download/staging-writer (owned by the voboost app
  repo). This change defines the contract the client satisfies (staged APK +
  `core-update-ready` marker) and the daemon side only.
- The daemon APK build/embedding of `manifest.json`+`manifest.sig` (build-time,
  owned by the build-and-signing pipeline). This change consumes the embedded
  manifest at VERIFY_SELF and at APK-apply re-verify.
- APK v2/v3 signature verification by the daemon. The APK is Android-signed,
  but the daemon trusts the **embedded manifest** signature (ed25519 against
  `EMBEDDED_PUBKEY`), not the APK signature (D1).
- Binary-delta patching; the daemon APK is downloaded whole.

## Decisions

### D1. APK verify = re-verify the staged APK's embedded manifest against EMBEDDED_PUBKEY
The staged daemon APK is Android-signed (v2/v3), but the daemon does NOT
verify the APK signature: Android's APK signature is the app/installer's
concern, and the daemon runs as root independent of the package manager. The
daemon's trust anchor is `EMBEDDED_PUBKEY` (ed25519, Monocypher). The APK
carries, as uncompressed ZIP entries, the daemon's `manifest.json`+
`manifest.sig` (build-time, signed with the same key family). The daemon
extracts those two entries, re-verifies the signature against `EMBEDDED_PUBKEY`,
and parses the manifest. Only an APK whose embedded manifest verifies is
accepted for self-replace. *Rejected:* trusting the APK v2/v3 signature — it
crosses a trust boundary the daemon does not own, and a re-signed APK with a
valid embedded manifest is exactly what the daemon intends to trust.

### D2. Self-replace = extract binary from APK -> atomic rename -> init restart
The daemon cannot `exec()` a new binary in place without losing its GMainLoop
state and frida sessions, and a second root process is forbidden (inject's
"only root-holding component" invariant). Instead: extract the daemon ELF
binary from the APK (a raw ELF stored as an uncompressed or deflated ZIP
entry), write it to a root-zone temp, fsync it, fchmod 0755, then atomically
`rename(2)` the **running** binary aside to `voboost-inject.prev` and the
verified temp into `voboost-inject`. `rename(2)` of a running binary is safe on
Linux/Android: the running process keeps its inode until exit; the pathname is
freed for the new binary. The daemon then writes the `core-switch-pending`
marker and performs a clean self-shutdown (SIGTERM to self -> teardown ->
exit). Android init (configured to restart the service on exit, not `oneshot`)
then execs `/data/voboost/voboost-inject`, which now resolves to the new binary
— no car reboot. The marker MUST land before the self-shutdown: it is the
rollback trigger on a DEGRADED restart.

### D3. Rollback-on-DEGRADED = restore from .prev
On a (re)start where the `core-switch-pending` marker is present and the daemon
would enter DEGRADED (VERIFY_SELF fails), the daemon restores the previous
binary: `rename(2)` `voboost-inject.prev` back to `voboost-inject` (overwriting
the bad new binary), clear the marker, and self-shut down so init restarts the
previous binary. On a READY (re)start with the marker present, the switch is
confirmed: clear the marker and remove `voboost-inject.prev` (the previous
binary is no longer needed). If `voboost-inject.prev` is absent at rollback
(first-update edge, or power-loss between the rename and the marker write),
the daemon cannot restore and stays DEGRADED rather than exec a known-bad
binary with no rollback target. *Rejected:* a content-addressed symlink scheme
(the superseded design) — a direct file rename is simpler, keeps a single
`.prev` rollback target, and matches the APK-level "one binary per APK" unit.

### D4. The core-update-ready marker is single-use
The `core-update-ready` marker is the producer's (the voboost app's) "a verified
daemon APK is staged" signal, created last. The daemon treats it as
single-use: it consumes (removes) the marker **before** the apply, so a
successful self-replace + self-shutdown + init-restart does not re-apply the
same APK on every boot — which would crash-loop via self-shutdown + init
restart until init's restart budget exhausts. Consuming it first (rather than
after) is safe because the marker is the trigger, not part of the verified set:
once consumed, the apply proceeds from the re-verified APK alone, and a
verified failure (bad embedded manifest) simply leaves the current binary
active with the marker already gone (the producer re-stages to retry).

### D5. ZIP extraction is minimal, pure-GLib, and bounded
The daemon APK is a ZIP archive. The daemon needs only two specific entries:
the embedded `manifest.json`+`manifest.sig` (for re-verify) and the daemon ELF
binary (for self-replace). A minimal ZIP central-directory reader (parse the
End-of-Central-Directory record, walk the central directory, locate entries by
name, read their local header for the offset and method, inflate deflated
entries via `ZlibDecompressor`) is implemented in `src/ota.vala` with no
external unzip dependency. It is bounded: a maximum APK size and a maximum
entry count guard against pathological archives (mirroring the release-manifest
bounds), and only the two named entries are ever extracted (no arbitrary
extraction). *Rejected:* shelling out to `unzip` — it is not guaranteed on the
device and crosses the trust boundary with an untrusted tool.

### D6. System-OTA survival via re-arm (unchanged)
Because a system OTA reverts only `/system`, the only lost artifact is the init
hook. `make device-rearm HOOK=<path>` restores the guarded hook block via adb;
`/data/voboost`, the daemon, and agents persist, so nothing is re-downloaded.
The init hook MUST configure the daemon service to be restarted on exit (not
`oneshot`), which the no-reboot self-replace depends on.

### D7. Signing reuse (unchanged)
The embedded `manifest.json`+`manifest.sig` and the release manifest are signed
with the same ed25519 key family as the daemon's trust anchor: the private key
lives only in CI secrets; the public key is committed
(`config/release-public.pem`) and (same family) embedded as `EMBEDDED_PUBKEY`.
For beta1 the dev keypair doubles as the release keypair; rotate before a real
release.

## Risks / Trade-offs

- [Power-loss mid-apply] → the self-replace is two renames (running -> `.prev`,
  temp -> running) plus a marker write. Power loss between the two renames
  leaves either the old binary active (no `.prev`, no marker -> normal boot) or
  the new binary active with no `.prev` (marker absent -> normal boot of the new
  binary; if it is bad, DEGRADED with no rollback target -> stay DEGRADED, the
  never-broken invariant holds: no binary is lost, the bad one is just not
  rolled back). Power loss after the marker write but before exit leaves the
  marker present on a clean new binary -> the next READY restart confirms
  (clears the marker, removes `.prev`).
- [A bad new binary] → automatic rollback on a DEGRADED restart via the marker
  + `.prev`. A signed binary that crash-loops *before* VERIFY_SELF (unreachable
  in normal operation — CI host-tests gate the signed release) is recovered by
  a one-line adb rename of `.prev` over the launch path.
- [Injection gap during a core restart] → identical to any daemon restart the
  system already handles (crash + init restart, kill-switch cycle): clean
  shutdown unloads agents, the relaunched daemon re-attaches and re-injects;
  spawns in the window are injected late via attach. No new failure mode.
- [APK ZIP parsing complexity] → bounded by D5 (size/entry caps, named-entry
  only); a malformed APK fails re-verify or extraction and the current binary
  stays active (marker already consumed, producer re-stages).

## Migration Plan

Implementation lands in this change's `tasks.md`. Sequencing: add the
`ota` spec capability (APK-level), rewrite `src/ota.vala` (remove file-level
core-update + agent manifest-swap; add `apply_core_apk_update` + APK
embedded-manifest re-verify + ZIP extraction + `.prev` self-replace/rollback),
update `src/supervisor.vala` and `src/app_zone_watcher.vala` to the
`core-update-ready` marker and the new apply API, update `make release-manifest`
to list the daemon APK as the single `core` entry, rewrite `test/ota_test.vala`
and fixtures, and validate. Rollback is inherent: any failure keeps the
current binary; `voboost-inject.prev` + the marker enable explicit reversion.

## Open Questions

- The exact asset path of the daemon ELF inside the APK (e.g. `assets/voboost-inject`
  vs the APK root) — pinned by the daemon APK build (build-and-signing); the
  daemon's ZIP reader locates it by a fixed name, and the build MUST place it
  there. Tracked in tasks.
- Whether the post-system-OTA re-arm can be made less manual than the host `adb`
  step (unchanged open question from the superseded design).
