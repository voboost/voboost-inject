# Design: emulator frida page-size fix

## D1. Deduction: page_size == 0 at the crash site

FACT (strace, EMULATOR_DEGRADED_MODE.md step 5): the crashing syscall is
`mmap(NULL, 0, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = -1
EINVAL`. Length is 0.

FACT (code): `gum_try_alloc_n_pages_near` computes `size = (1 + n_pages) *
gum_query_page_size()`; `gum_metal_array_init` calls `gum_alloc_n_pages(1, ...)`
=> `size = 2 * gum_query_page_size()`. `(1 + n_pages) * page_size == 0` with
`n_pages >= 0` implies `page_size == 0`. Therefore `gum_query_page_size()`
returns 0 at the crash.

`gum_query_page_size()` is the sole accessor of `gum_cached_page_size` (grep:
one read, at its own body). The cache is set once in `gum_internal_heap_ref`.
The embedded backend's early ELF-load path reads it as 0.

This is a DEDUCTION from recorded facts, not a premise.

## D2. Why the earlier guards were no-ops

The prior guards `if (allocation_size == 0) allocation_size = page_size;` and
`if (size == 0) size = gum_query_page_size();` substitute the same `page_size`,
which is 0, so they replace 0 with 0. They correctly identified `size == 0` but
did not check that `page_size` itself is 0. This is the gap the fix closes.

`gum_metal_array_ensure_capacity` divides `size_in_bytes / page_size`, which
would SIGFPE (not SIGABRT) if `page_size == 0` were hit there. The abort is a
SIGABRT in `gum_alloc_n_pages`, so the crash is `gum_metal_array_init`
(`gum_alloc_n_pages(1)`, no division), consistent with the trace.

## D3. Reconciliation with D8 (frida-server works)

frida-server 17.11.0 (droidy) works on the same emulator, so `page_size == 0`
is not universal on this QEMU. It is specific to the embedded local backend's
early init ordering: it reaches `gum_query_page_size()` before the cache is
set. frida-server runs a full `gum_init` first. On a real device the kernel
tolerates `mmap(NULL, 0)`, so the latent bug never aborts there; QEMU rejects
it, so it fires. The prior "QEMU rejects length=0" symptom is correct; the
"OOM in metal-allocator" root cause is not.

## D4. The fix

`gum/gummemory.c` `gum_query_page_size()`:

```c
if (gum_cached_page_size == 0)
  gum_internal_heap_ref ();
return gum_cached_page_size;
```

On first reach this performs the FULL `gum_internal_heap_ref ()` (ref-counted,
idempotent): it sets `gum_cached_page_size`, runs `_gum_cloak_init ()` (so
cloak's `GumMetalArray`s get a non-NULL `data`), and creates the dlmalloc
mspaces. There is no recursion: `gum_internal_heap_ref ()` sets the cache
*before* `_gum_cloak_init ()`, so the recursive `gum_query_page_size ()` call
inside `gum_metal_array_init ()` returns at once. This cures both the
`page_size == 0` abort *and* the follow-on `gum_metal_array_append` SIGSEGV
(NULL `data` after a page_size-only patch).

With `Daemon` now calling `Frida.init ()` (see the `daemon-frida-init` change),
`gum_init ()` runs before any embedded-backend reach, so this lazy path is a
no-op defence-in-depth rather than the primary fix — but it is kept because it
is harmless and protects any caller that queries the page size before
`Frida.init ()`.

## D5. Persistence via wrap diff_files

`subprojects/frida-gum/` is fetched (wrap-git, depth=1) and not under git, so
working-tree edits are ephemeral. The patch is stored at
`subprojects/packagefiles/frida-gum-qemu-page-size.patch` and applied via
`diff_files` in `frida-gum.wrap`, mirroring
`frida-core-libc-shim-opaque-file-bionic.patch`.

## D6. Remove the emulator DEGRADED gate

The `is_emulator()` escape hatch (the `run()` block, the method, and its cache
fields) is deleted. The gate never fired in production (`ro.kernel.qemu=1`
never holds on a real device), so removing it is production-safe; on an
emulator the daemon now opens frida exactly as on a device. `DaemonState.
DEGRADED` remains for verify_self / frida-open / rejections.
`VOBOOST_SKIP_SPAWN_GATING` (a separate hatch) is left as-is; the page_size fix
makes it redundant, but revising it belongs to its own change
(`emulator-spawn-gating-crash`).

## D7. Rejected alternatives

- Newer emulator image (API 30+, google_apis): does not address `page_size==0`
  (init ordering, not an image/kernel property).
- GError propagation through `gum_metal_array_*` (prior D3): unnecessary; the
  mmap is not failing on real OOM.
- frida-server/droidy as the primary backend (prior D8): two-process
  architecture; kept as a fallback only.
