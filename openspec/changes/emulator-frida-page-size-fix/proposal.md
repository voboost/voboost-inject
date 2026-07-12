## Why

The `emulator-spawn-gating-crash` change concluded "No code change" and kept
`voboost-inject` in DEGRADED (observe-only) mode on Android emulators, because
frida-core 17.11.0's embedded local backend SIGABRTs at `gum_alloc_n_pages ->
g_assert(result != NULL)`. That analysis (design.md D1-D3) treated the mmap
failure as a legitimate OOM in the metal-allocator and proposed a multi-day
`GError`-propagation refactor as the only real fix.

The real root cause is narrower and fixable in one function. The crashing
syscall is `mmap(NULL, 0, ...) = -1 EINVAL`. The mmap length comes from
`size = (1 + n_pages) * gum_query_page_size()`; for that to be 0,
`gum_query_page_size()` must return 0. It returns the static
`gum_cached_page_size`, initialized once in `gum_internal_heap_ref`. The
embedded backend's early Zymbiote / `gum_linker_api_try_init ->
gum_elf_module_load` path reaches `gum_query_page_size()` while the cache is
still 0. So `page_size == 0`, `size == 0`, and QEMU (unlike a real kernel,
which tolerates `mmap(NULL, 0)`) returns EINVAL, aborting the daemon. The
earlier `if (size == 0) size = gum_query_page_size()` guards did not help
because they substitute the same `page_size`, which is itself 0. Standalone
`frida-server 17.11.0` works on the emulator (design.md D8) because it runs a
full `gum_init` first, so its cache is already set.

## What Changes

- **frida-gum patch (persisted via wrap `diff_files`):** make
  `gum_query_page_size()` lazily call `gum_internal_heap_ref ()` on first reach
  (the full, idempotent gum heap init — page-size cache, cloak's
  `GumMetalArray`s, dlmalloc mspaces), so it never returns 0 *and* cloak is
  initialised. This removes the `mmap(NULL,0)` abort for BOTH `attach` and
  `enable_spawn_gating`, without changing the `GumMetalArray` API (unlike the
  rejected D3 refactor). It is defence-in-depth: the root cause is fixed
  separately by the `daemon-frida-init` change (calling `Frida.init ()`), so
  this lazy path is a no-op in practice.
- **Persistence:** collect the `gum_query_page_size` fix and the two
  `size==0` guards into `subprojects/packagefiles/frida-gum-qemu-page-size.patch`
  and wire `diff_files` in `subprojects/frida-gum.wrap`, so clean clones / CI
  apply it.
- **Remove the emulator DEGRADED gate:** delete the `is_emulator()` escape
  hatch (the `run()` block, the `is_emulator()` method, and its cache fields)
  from `src/supervisor.vala`. The gate never fired in production
  (`ro.kernel.qemu=1` never holds on a real device), so the daemon now opens
  frida on an emulator exactly as on a device. `DaemonState.DEGRADED` remains
  for the other paths (verify_self / frida-open / rejections).
- **Docs:** `docs/EMULATOR_DEGRADED_MODE.md` gains a Resolution section with
  the real root cause and the fix.
- **Supersedes** the "No code change" stance of `emulator-spawn-gating-crash`
  and refines its design D1-D3/D7: the fix is `page_size`, not a GError
  refactor, and it also fixes spawn-gating (not only attach-only survival).
  This does NOT remove the `VOBOOST_SKIP_SPAWN_GATING` env-var escape hatch
  defined by `emulator-spawn-gating-crash`: that hatch remains in
  `src/supervisor.vala` as an emulator-only test affordance for the case
  where a future frida-gum build reintroduces an abort that cannot be caught
  in Vala. The page-size fix makes the hatch unnecessary on this frida-gum
  version, but the hatch is retained (defence-in-depth) and is still
  documented by `emulator-spawn-gating-crash`'s spec delta.

## Impact

- **Production devices:** unaffected. `gum_query_page_size` is a no-op once the
  cache is set (real hardware never observes 0 as a crash; the fix only
  self-heals a 0 read). The removed emulator gate never fired in production
  (`ro.kernel.qemu=1` is false on real devices).
- **Emulator testing:** the daemon opens frida, performs attach and spawn-gated
  injection, and contract tests can run in the emulator without real hardware.
- **Upstream:** the fix is a candidate upstream one-liner (initialize
  `gum_cached_page_size` defensively), far smaller than the D9 refactor.
