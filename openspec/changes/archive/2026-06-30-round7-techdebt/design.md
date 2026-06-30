# Design — round7-techdebt

<!-- Date: 2026-06-30. Records the design decisions for the 3 voboost-inject
     defense-in-depth fixes so the next investigator understands why each
     approach was chosen over the alternatives. -->

## D1 — Streaming inflate via GConverterInputStream

**Choice:** wrap a `GZlibDecompressor` (RAW format) in a
`GConverterInputStream` over a `MemoryInputStream` built from the compressed
slice; read in 64 KiB chunks into a buffer sized at `uncomp_size`.

**Rejected — keep `ZlibDecompressor.convert` with a smaller initial buffer:**
the converter is single-use; an under-sized hint still requires a fresh
converter + bigger buffer per retry, so the per-iteration allocation remains.
Streaming removes the retry loop entirely.

**Rejected — write the compressed slice to a temp file and use
`GZlibDecompressor` on a `FileInputStream`:** the APK is already in memory
(signature-verified before apply); a temp file adds IO and a cleanup path for
no benefit. `MemoryInputStream.from_data` keeps the whole flow in-memory.

**Growable fallback:** when `uncomp_size` is zero or lying (a corrupt/ hostile
APK that passed signature verify — impossible by design but defense-in-depth),
the buffer grows doubling, still capped at `MAX_APK_BYTES` (64 MiB). Only this
path can reach the cap; a well-formed APK never allocates more than
`uncomp_size + 64 KiB`.

## D2 — Extract BootState to a frida-free module

**Choice:** move the `boot_cached`/`boot_resolved` static fields and the
`boot_completed()` body from `Supervisor` into a new `BootState` class in
`src/boot.vala`. `Supervisor` holds a `BootState` instance and delegates.

**Rejected — make `boot_completed` internal and call it from a test that
links `supervisor.vala`:** `supervisor.vala` depends on `FridaController`,
which depends on frida-core. The host test harness cannot link frida-core (no
device), so any test pulling in `supervisor.vala` cannot build on host.
Extracting the frida-free logic is the only way to test it on host.

**Rejected — `#if HOST_TEST` guard around the frida dependency:** Vala has no
preprocessor; conditional compilation would require a build-system split that
is more invasive than a small extraction.

**Invariant preserved:** the monotonic cache (once true, never fork again)
and the `VOBOOST_BOOT_COMPLETED` escape hatch (checked first, so host tests
never fork `getprop`) are unchanged in behavior. The frida spawn-gating
deadlock note in `Supervisor` is preserved verbatim.

## D3 — Parent-dir fsync after status rename

**Choice:** after `FileUtils.rename(tmp, this.path)`, open the parent dir
with `Posix.O_RDONLY | Posix.O_DIRECTORY` and best-effort `Posix.fsync` it.

**Rejected — `Posix.sync()` (global sync):** a global sync flushes every
dirty buffer in the kernel, which is far more expensive than a single dir
fsync and adds latency to every status write. A targeted dir fsync is the
standard pattern for atomic-rename durability.

**Best-effort:** a dir fsync failure only delays durability (the data is
already on stable storage via the temp-file fsync; only the directory-entry
switch is at risk). It never corrupts, so a failure is logged implicitly by
the fd check (`dfd < 0` → skip) and does not abort the write. This matches
the existing pattern where the temp-file fsync is mandatory (aborts on
failure) but the dir fsync is defense-in-depth.

**O_DIRECTORY:** refuses non-directories, so a racing symlink at the parent
path cannot redirect the fsync to a file. Combined with the existing
`O_NOFOLLOW` on the temp file, both the data and the directory entry are
protected from app-zone symlink races.
