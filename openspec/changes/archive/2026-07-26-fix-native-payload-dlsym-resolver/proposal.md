## Why

The `native-payload` spec requires the injector to resolve `__loader_dlopen`
and `__loader_dlsym` at runtime from the target's `PT_DYNAMIC`
(`DT_SYMTAB`/`DT_STRTAB`), explicitly NOT from a hardcoded offset. The archived
`native-payload` change (2026-07-24) scaffolded the injector but left a
hardcoded-offset `resolve_loader_symbol` with a Phase 1 TODO for the runtime
walk, so the shipped code already violated its own spec.

On the test device this surfaced as a crash: the hardcoded `__loader_dlsym`
offset is `0x14294`, but the real symbol on the device's `linker64` is `0x14430`
(verified via `llvm-nm --dynamic`). The injector resolved `implant_init` at
the wrong address, the remote-call jumped there, and `system_server` crashed
(pid 944 → 8515, with no `IMPLANT_LOGI` reaching logcat — the call never reached
the implant). `__loader_dlopen` (`0x14244`) and `__loader_dlerror` (`0x1412c`)
happened to match, which is why dlopen succeeded but the subsequent dlsym step
killed the target.

A single offset fix (0x14294 → 0x14430) would unblock this device but leave the
spec violation and the device-specific fragility — any linker rebuild or
different Android 9 build breaks injection again. This change implements the
runtime `PT_DYNAMIC` resolver the spec already mandates, eliminating hardcoded
offsets entirely.

## What Changes

- **`injector/elf_resolve.c`** — `resolve_loader_symbol` walks the target
  `linker64`/`linker` `PT_DYNAMIC` at runtime (remote `target_read_mem`) to find
  `DT_SYMTAB`/`DT_STRTAB`/`DT_SYMENT`/`DT_STRSZ`, derives the symbol count, scans
  `.dynsym` linearly, and returns `load_bias + st_value`. Hardcoded offsets
  (`0x14244`/`0x14294`/`0x1412c`) and the Phase 1 TODO are removed. Works for
  both 64- and 32-bit targets (Elf64/Elf32 paths) from the already-detected
  target bitness.
- **`injector/injector.c`** — passes the detected target bitness into the
  resolver so it selects `linker64` vs `linker` and the Elf64 vs Elf32 parse.
- **Symbol count when `DT_HASH` is absent** — the Android 9 `linker64`/`linker`
  carry only `DT_GNU_HASH` (no `DT_HASH`). The resolver derives `nsym` from the
  adjacency of `DT_SYMTAB` and `DT_STRTAB` (`(strtab - symtab) / syment`), which
  holds for these linkers. (The spec's `DT_HASH` requirement is scoped to the
  implant's file-based `safe_resolve_symbol` for ART symbols, not to the
  injector's linker resolver — no spec conflict.)
- **Host unit-test** — `injector/elf_resolve_test.c` exercises the pure ELF
  parser against real `linker64`/`linker` binaries checked into
  `test/fixtures/linker/`, asserting the resolved offsets match `llvm-nm` for
  both ABIs and that unknown symbols return 0. New `make test-injector` target.
- **Committed diagnostics** — the dlerror logging in `injector.c` (via
  `__android_log_print`, `LOCAL_LDLIBS := -llog`) and the `daemon/build.rs`
  Android-only `libinjector.a` link are kept; the `implant/Android.mk`
  `-DLOG_DISABLED` stays in place for production (it was only dropped locally
  during debugging).

## Capabilities

### Modified Capabilities

- `native-payload`: the injector's `__loader_dlopen`/`__loader_dlsym`
  resolution is now runtime `PT_DYNAMIC`-based (as the spec already required),
  not hardcoded-offset. Adds the host unit-test for the resolver. No spec
  requirement text changes — the spec already mandated runtime resolution; this
  change makes the code conform.
