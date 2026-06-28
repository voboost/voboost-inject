# Design: emulator spawn-gating crash

<!-- Research date: 2026-06-28. This is a research/design record, not an
     implementation design. It captures the root cause and the decision so the
     next investigator does not re-derive it. -->

## D1. Root cause: `g_assert` in `gum_alloc_n_pages`

`subprojects/frida-gum/gum/gummemory.c:1974`:

```c
gpointer
gum_alloc_n_pages (guint n_pages, GumPageProtection prot)
{
  gpointer result;
  result = gum_try_alloc_n_pages (n_pages, prot);
  g_assert (result != NULL);   /* <-- SIGABRT on mmap failure */
  return result;
}
```

The same pattern is in `gum_alloc_n_pages_near` (line 1986). `gum_try_alloc_n_pages`
returns NULL when `mmap` fails; `g_assert` then calls `abort()`. This is a
**deliberate** frida-gum design choice: OOM in the metal-allocator is treated
as a fatal invariant violation (consistent with glib's own OOM-is-fatal model).

On the Android API 28 arm64 emulator, the mmap failure happens inside the
Zymbiote-prep path that loads the `linker64` ELF module:

```
enable_spawn_gating
  -> RoboLauncher.ensure_loaded -> inject_zymbiote (zygote)
  -> do_prepare_zymbiote_injection -> gum_linker_api_try_init
  -> _gum_native_module_get_elf_module (linker64)
  -> gum_elf_module_load
  -> gum_metal_array_append          (gummetalarray.c:83)
  -> gum_metal_array_ensure_capacity (gummetalarray.c:108)
  -> gum_alloc_n_pages (GUM_PAGE_RW) /* NOT RWX */
  -> g_assert (result != NULL)       -> abort()
```

The allocation is `GUM_PAGE_RW` (read-write, not executable), so this is **not**
a W^X / RWX-proximity issue. It is a plain mmap failure during ELF module
loading.

## D2. Why a narrow `gum_alloc_n_pages` patch is insufficient

The naive fix — replace `g_assert(result != NULL)` with `return NULL` + a
warning — does **not** produce graceful degradation, because the immediate
caller does not check for NULL:

`subprojects/frida-gum/gum/gummetalarray.c:107`:

```c
void
gum_metal_array_ensure_capacity (GumMetalArray * self, guint capacity)
{
  ...
  new_data = gum_alloc_n_pages (size_in_pages, GUM_PAGE_RW);
  gum_memcpy (new_data, self->data, self->length * self->element_size);
  /* ^^^ if new_data is NULL, this is a NULL-deref segfault, not a graceful
   *     failure. The daemon still crashes, just with SIGSEGV instead of
   *     SIGABRT. */
  gum_free_pages (self->data);
  self->data = new_data;
  self->capacity = (size_in_pages * page_size) / self->element_size;
}
```

So patching only `gum_alloc_n_pages` converts SIGABRT into SIGSEGV. The daemon
is still dead.

## D3. Why a full frida-gum patch is too invasive

To actually propagate the failure gracefully, the NULL must travel up:

1. `gum_alloc_n_pages` -> return NULL (instead of abort).
2. `gum_metal_array_ensure_capacity` -> check NULL, return a gboolean / set
   a GError, do NOT memcpy.
3. `gum_metal_array_append` / `gum_metal_array_insert_at` -> currently return
   `gpointer` with **no error channel**. Must change signature to
   `gpointer gum_metal_array_append (... , GError **error)` or similar.
4. **All 6 callers** of `gum_metal_array_append`/`insert_at` must be updated
   to check the error:
   - `gumcloak.c:122, 128, 319, 621, 627` (cloak threads/ranges/fds —
     critical paths, not designed to fail)
   - `gummemory.c:806` (suspend-threads bookkeeping)
   - `gumelfmodule.c` (the ELF-load path that triggers the crash)

This changes the API contract of `GumMetalArray`, touches critical frida-gum
paths (cloak, thread suspension) that have no failure semantics today, and
risks breaking the already-fragile NDK r29 / macOS 26.2 cross-build (see the
existing `frida-core-libc-shim-opaque-file-bionic.patch` for how brittle the
cross-build is). A partial patch (only the ELF path) leaves the other 5
callers still abort-prone.

**Conclusion:** a correct frida-gum patch is a multi-day upstream-quality
refactor (introduce `gum_try_alloc_n_pages` usage in
`gum_metal_array_ensure_capacity` + GError propagation through
`gum_elf_module_load`), not a 5-line wrap patch. It belongs upstream, not as
a vendored diff.

## D4. Why a Vala SIGABRT handler + siglongjmp was rejected

The approach: install a `sigaction(SIGABRT, ...)` handler around
`enable_spawn_gating` that does `siglongjmp` back to the caller, so
`enable_gating()` returns `false` and the supervisor degrades to attach-only.

Rejected for two reasons:

1. **async / state-machine UB.** `enable_spawn_gating` is a Vala `async` method
   (yields on a GMainLoop). Vala compiles `async` into a state-machine `_co`
   function. `sigsetjmp` would be in one stack frame (the `_co` dispatcher)
   while the actual C call into frida-core (where the abort fires) is in a
   **deeper** frame. `siglongjmp` across the async state machine is formally
   undefined behavior: it unwinds through GIO async cleanup, frida mutexes
   (GRecMutex held during Zymbiote prep), and possibly a GMainLoop dispatch
   in progress. On bionic it "usually works" but leaves frida-core's internal
   state (mmap'd agent blobs, held mutexes, half-initialized linker module)
   inconsistent — the next frida call (`enumerate_processes`, `inject`) may
   deadlock or corrupt the GMainLoop. This is a **hidden** defect worse than
   the explicit crash it replaces.

2. **posix.vapi gap.** The Vala `posix` vapi (0.58-frida) exposes `sigaction`,
   `sighandler_t`, `SIGABRT`, `sigemptyset`, `sigprocmask`, `SA_RESTART` — but
   **not** `sigsetjmp`/`siglongjmp`/`sigjmp_buf`. Using them requires manual
   `[CCode (cname = "siglongjmp", cheader_filename = "setjmp.h")]` extern
   declarations with `returns_twice = true` on `sigsetjmp`. Bionic NDK r29
   does provide `sigsetjmp`/`siglongjmp`/`sigjmp_buf` in `<setjmp.h>`, so it
   is buildable, but the async-UB concern (1) dominates.

## D5. Why fork+exec was rejected

Fork a child that calls `enable_spawn_gating` and `_exit`s; the parent
`waitpid`s and treats a SIGABRT child as "spawn-gating unavailable".

Rejected: frida-core local-backend, at the point `enable_spawn_gating` is
called, has already opened `/proc/*/mem` fds, mmap'd the agent blob, and
spawned helper threads (frida-helper). `fork()` does not copy threads but
**does** copy fds (CLOEXEC is not set on every internal fd). The child would
call `enable_spawn_gating` on a `device` object whose helper threads no longer
exist — undefined behavior in frida-core. The child may hang or crash in
unrelated ways, making the waitpid result unreliable.

## D6. Why `_exit` + init-restart was rejected

Install a SIGABRT handler that `_exit(77)` instead of aborting; init restarts
the daemon; the supervisor reads a pidfile marker and marks spawn-gating
failed.

Rejected: this is not graceful degradation — the daemon **dies** and loses all
in-flight state (sessions, OTA progress, kill-switch state). It is strictly
worse than the env-var escape hatch, which keeps the daemon alive in
attach-only mode without a restart.

## D7. Chosen fix: `VOBOOST_SKIP_SPAWN_GATING` env-var (already in place)

`src/supervisor.vala:149`:

```vala
if (Environment.get_variable("VOBOOST_SKIP_SPAWN_GATING") == "1") {
    Log.err("supervisor",
            "spawn-gating skipped (VOBOOST_SKIP_SPAWN_GATING=1); "
            + "attach-only mode");
} else if (!yield this.frida.enable_gating()) {
    Log.err("supervisor", "spawn-gating failed; attach-only mode");
}
```

- On the emulator with the env-var set: the daemon reaches READY and stays
  alive. Attach injection (`inject_running` ->
  `linjector.inject_library_resource`) works, because it uses Linjector, not
  Zymbiote, and is unaffected by skipping `enable_spawn_gating`.
- On production devices: the env-var is never set, so the code path is
  unchanged. Production runs on real hardware where the frida-gum `g_assert`
  does not fire.
- It mirrors the existing `VOBOOST_BOOT_COMPLETED` test hatch: an
  emulator-only escape hatch, not a production code path.

Verified on emulator-5554 (arm64-v8a API 28, `-selinux permissive`):
- with the env-var set: daemon reaches READY and stays alive;
- without it: daemon SIGABRTs at `enable_spawn_gating` (tombstone_31).

## D8. Key finding: standalone frida-server works on the emulator

Standalone `frida-server 17.11.0` (the droidy backend, which does **not** do
in-process Zymbiote prep) works fully on this emulator: spawn + inject
verified. This proves the crash is **specific to the embedded local backend's
in-process Zymbiote injection into zygote**, not a fundamental emulator
limitation (not a W^X / SELinux / kernel-version issue).

Implication: if full spawn-gating on the emulator is ever required, the path
forward is either (a) the upstream frida-gum fix (D3), or (b) switching
voboost-inject from the embedded local-device backend to the remote
frida-server backend (droidy) for emulator test runs. Both are separate
changes.

## D9. Upstream path forward (future work, not this change)

The correct long-term fix is an upstream PR to frida-gum:

1. Add a `gum_metal_array_ensure_capacity_full(self, capacity, GError **)`
   (or a `try` variant) that uses `gum_try_alloc_n_pages` and returns FALSE
   on NULL instead of aborting.
2. Propagate the GError through `gum_elf_module_load` (which already returns
   `gboolean` + `GError **` — so the ELF path is the natural first caller).
3. Leave the cloak/memory critical paths on the aborting variant (their
   OOM-is-fatal contract is intentional).

This is a focused, upstream-acceptable change (it does not change the
`GumMetalArray` API for existing callers, only adds a `_full` variant). It is
tracked as future work; this change only documents the analysis.
