## Why

<!-- Round 7 code review (2026-06-28) carried 3 voboost-inject findings as
     acceptable technical debt. This change closes them with defense-in-depth
     fixes that strengthen already-specified invariants (no new capabilities):
     streaming inflate, parent-dir fsync after status rename, and a
     host-testable BootState extraction. -->

Round 7 of the deep code review confirmed 3 carried-over voboost-inject
findings as acceptable technical debt, each with a clear deferral rationale.
This change closes all three with defense-in-depth fixes that strengthen
invariants already specified in `release-manifest`, `app-interface`, and
`daemon-lifecycle` — no new capabilities are introduced.

1. **R4-INJ-01 — `inflate_raw` allocates up to 64 MiB per retry.** The APK
   ZIP reader's deflate path fed the whole compressed buffer to
   `ZlibDecompressor.convert` in a loop that allocated a fresh output buffer
   up to `MAX_APK_BYTES` (64 MiB) per iteration. The APK is signature-
   verified before apply and the bound is 64 MiB, so this was acceptable;
   streaming removes the per-iteration peak entirely.
2. **R4-X-02 — no integration test for `boot_completed` spawn_sync caching.**
   The INJ-02 fix (monotonic cache) had no host test because `boot_completed`
   lived inside `Supervisor`, which depends on `FridaController` (frida-core)
   and so cannot link into the host test harness.
3. **`Status.write_atomic()` no parent-dir fsync.** The temp file's data was
   fsynced but the parent directory was not fsynced after the rename, so a
   crash after rename could leave the old directory entry pointing at the
   pre-rename inode. The status file is transient and the reader tolerates a
   missing/partial file, so this was acceptable; the dir fsync makes the
   rename durable.

## What Changes

- **`src/ota.vala`** — replace the `ZlibDecompressor.convert` retry loop in
  `inflate_raw` with a streaming `GZlibDecompressor` wrapped in a
  `GConverterInputStream` over a `MemoryInputStream`, reading in 64 KiB
  chunks. Peak memory is bounded by the entry's uncompressed size plus one
  chunk; the growable fallback (zero/lying `uncomp_size`) is still capped at
  `MAX_APK_BYTES`.
- **`src/boot.vala`** (new) — extract the boot cache + `getprop` fork +
  `VOBOOST_BOOT_COMPLETED` escape hatch from `Supervisor` into a frida-free
  `BootState` class so it can be unit-tested without linking frida-core.
- **`src/supervisor.vala`** — delegate `boot_completed()` to a `BootState`
  instance (the frida spawn-gating deadlock note is preserved).
- **`src/status.vala`** — after `FileUtils.rename`, open the parent dir with
  `O_RDONLY|O_DIRECTORY` and best-effort `fsync` it so the directory-entry
  update is durable.
- **`test/boot_test.vala`** (new) — host integration test covering the env
  override, the monotonic cache, and the empty-env host path.
- **`src/meson.build`, `test/meson.build`** — wire `boot.vala` into the
  daemon build and the host test harness; add the `boot` test target.

## Capabilities

### Modified Capabilities
- `release-manifest`: the APK ZIP reader's deflate path is now streaming;
  the `MAX_APK_BYTES` bound is unchanged (still the hard cap on total APK
  size and on the growable inflate fallback).
- `app-interface`: `Status.write_atomic` now fsyncs the parent directory
  after rename, strengthening the atomic-write guarantee for
  `inject-status.json`.
- `daemon-lifecycle`: the boot-completion check is extracted to a
  testable `BootState`; the monotonic-cache invariant and the
  `VOBOOST_BOOT_COMPLETED` escape hatch are unchanged.
