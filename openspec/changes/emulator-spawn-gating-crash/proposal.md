## Why

<!-- Research date: 2026-06-28. Documents the frida-gum 17.11.0 spawn-gating
     SIGABRT on Android API 28 arm64 emulators and records why the chosen fix
     is the existing VOBOOST_SKIP_SPAWN_GATING env-var escape hatch rather than
     a frida-gum C-patch or a Vala-level SIGABRT handler. Captures the full
     root-cause analysis so the next investigator does not redo it. -->

frida-core 17.11.0, embedded in-process over the local-device backend,
SIGABRTs the whole `voboost-inject` daemon the first time
`device.enable_spawn_gating()` is called on an Android API 28 arm64 emulator
(emulator-5554, `-selinux permissive`). The abort is in C (frida-gum
`g_assert`), so Vala `try/catch` cannot catch it and the documented
attach-only graceful degradation (`enable_gating()` returning `false`) never
runs — the process is gone before the `yield` returns.

The crash chain (from tombstone_31):

```
enable_spawn_gating
  -> RoboLauncher.ensure_loaded
  -> inject_zymbiote (zygote)
  -> do_prepare_zymbiote_injection
  -> gum_linker_api_try_init
  -> _gum_native_module_get_elf_module (linker64)
  -> gum_elf_module_load
  -> gum_metal_array_append
  -> gum_metal_array_ensure_capacity
  -> gum_alloc_n_pages (GUM_PAGE_RW)
  -> g_assert (result != NULL)            <-- SIGABRT
```

`gum_alloc_n_pages` calls `gum_try_alloc_n_pages` and, on NULL (mmap failure),
fires `g_assert(result != NULL)` which calls `abort()` directly.

A prior commit (`46ad097`, corrected in `d857b10`) added the
`VOBOOST_SKIP_SPAWN_GATING=1` env-var escape hatch: when set, the supervisor
skips `enable_spawn_gating` entirely, the daemon reaches READY and stays alive
in attach-only mode, and attach injection (Linjector, not Zymbiote) works.
This change documents **why** that env-var is the chosen fix and **why** the
two obvious alternatives (patching frida-gum, or a Vala SIGABRT handler) were
rejected, so the next investigator does not re-derive the analysis.

## What Changes

- **No code change.** The `VOBOOST_SKIP_SPAWN_GATING` env-var escape hatch
  (already in `src/supervisor.vala`) remains the fix. `make build` is
  unaffected.
- **Add** this openspec change recording the root cause, the caller-chain
  analysis (why a narrow `gum_alloc_n_pages` patch is insufficient), the
  rejected alternatives (frida-gum C-patch; Vala SIGABRT handler + siglongjmp;
  fork+exec; `_exit`+restart), and the upstream path forward.
- **Add** a `## ADDED Requirement: Emulator spawn-gating escape hatch` delta
  to `injection-control/spec.md` so the env-var, its scope (emulator test
  only, never production), and its non-effect on attach injection become a
  spec invariant rather than an undocumented code comment.

## Impact

- **Production devices:** unaffected. The env-var is never set in production;
  it mirrors the existing `VOBOOST_BOOT_COMPLETED` test hatch. Production
  devices either run on real hardware (where the frida-gum `g_assert` does
  not fire) or do not set the env-var.
- **Emulator integration testing:** the daemon survives in attach-only mode.
  Spawn-gating-specific tests (earliest-reach injection) are marked
  device-only and are not expected to pass on the emulator.
- **Upstream:** the root cause is a frida-gum design choice (`g_assert` on
  OOM in the metal-allocator). A real fix belongs upstream as a
  `gum_metal_array_ensure_capacity` try-variant with `GError` propagation
  through `gum_elf_module_load`; that is tracked as future work, not in this
  change.
