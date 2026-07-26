## Context

The injector resolves `__loader_dlopen`, `__loader_dlsym`, and
`__loader_dlerror` in the target by reading the target's `linker64` (64-bit
targets) or `linker` (32-bit targets) over `process_vm_readv`/ptrace and walking
its `PT_DYNAMIC` segment. There are no hardcoded offsets.

### Verified facts (test device `1234567`, Android 9, API 28, arm64-v8a)

- `linker64` (`/system/bin/linker64`): static-pie DYN, 8 program headers, not
  stripped. `PT_DYNAMIC` vaddr `0x14f6d8` (lies in the `r--p` mapping, reachable
  as `load_bias + vaddr`). `DT_SYMTAB=0x220`, `DT_STRTAB=0x448`, `DT_SYMENT=24`,
  `DT_STRSZ=0x29a`, `DT_GNU_HASH=0x6e8`; `DT_HASH` absent. Symbols:
  `__loader_dlopen=0x14244`, `__loader_dlsym=0x14430`, `__loader_dlerror=0x1412c`.
- `linker` (`/system/bin/linker`): ELF32, `DT_SYMTAB=0x174`, `DT_STRTAB=0x2f4`,
  `DT_SYMENT=16`; `DT_HASH` absent. Symbols: `__loader_dlopen=0x75b9`,
  `__loader_dlsym=0x76fd`, `__loader_dlerror=0x7505`.
- `load_bias` = the `r-xp` mapping base of the linker (LOAD #1 has `p_vaddr=0`
  for both linkers, so the `r-xp` base equals `load_bias`). `load_bias + p_vaddr`
  is valid for every address the resolver touches (`PT_DYNAMIC`, `DT_SYMTAB`,
  `DT_STRTAB`, `DT_GNU_HASH`) — all lie outside the alignment gap between the
  `r-xp` and `r--p` mappings. No mapping-cover lookup is needed.

## Design

### Testable split: pure parser vs target I/O

The ELF parse is separated from ptrace I/O so the parser is host-testable with
no device and no ptrace:

- `resolve_elf64_symbol(const uint8_t *image, uint64_t load_bias, const char *name)`
  and `resolve_elf32_symbol(...)` — pure functions over an in-memory image of
  the linker. Take the full image buffer (the file contents, or a contiguous
  slice covering Ehdr + the program headers + PT_DYNAMIC + SYMTAB + STRTAB).
  Return `load_bias + st_value`, or 0 if not found.
- `resolve_loader_symbol(int pid, int bitness, const char *name)` — target I/O.
  Finds the linker's `r-xp` base (= `load_bias`) in `/proc/<pid>/maps`, reads
  the image regions the parser needs via `target_read_mem`, calls the pure
  parser. The full linker image is small (≤ ~2 MB), but only a few regions are
  needed; the resolver reads Ehdr + all Phdrs first, then PT_DYNAMIC, then
  SYMTAB + STRTAB (each ≤ ~1 KB).

### Counting symbols without `DT_HASH`

Android 9 `linker64`/`linker` expose only `DT_GNU_HASH`, no `DT_HASH`. The
symbol count for a linear `.dynsym` scan is derived from the adjacency of
`DT_SYMTAB` and `DT_STRTAB`: `nsym = (DT_STRTAB - DT_SYMTAB) / DT_SYMENT`. This
holds for both linkers (verified: 64-bit → 23, 32-bit → 24, matching
`llvm-readelf --dyn-syms` counts). Symbols with `st_shndx == SHN_UNDEF` are
skipped (imports, not the `__loader_*` definitions).

### Why not `DT_GNU_HASH` chain walk

A `DT_GNU_HASH` bucket/chain walk yields only the dynamic-symbol range and is
more complex and more brittle than a linear scan over a table that is 23–24
entries. The `.dynsym` of the linker is tiny; linear scan is cheaper and
simpler. The adjacency count is exact for these linkers. If a future linker
layout breaks adjacency, the resolver falls back to a bounded scan (the table
is small and contiguous; a missing terminator is the only failure mode).

### Caller_addr

Unchanged: `find_target_caller_addr` prefers `libart.so` (registered soinfo,
large `r-xp`) then `libc.so`, falling back to `app_process64`. This is a
correctness improvement over the spec's literal "inside `app_process`" —
`app_process64` is an executable, not a registered soinfo, and
`find_containing_library` may return nullptr, dropping the linker into the
restrictive anonymous namespace. The spec's intent (a caller that resolves the
caller's primary namespace) is satisfied by `libart.so`. No spec text change is
required; this is an implementation choice within the spec's caller-namespace
intent. (dlopen already succeeded with this caller on the device.)

## Risks

- **`DT_HASH`-absence on other builds**: if a future Android build regains
  `DT_HASH`, the adjacency heuristic still works (it ignores `DT_HASH`); no
  regression. If a build places `STRTAB` before `SYMTAB`, adjacency breaks —
  the resolver bounds the scan by `DT_STRSZ`/`DT_SYMENT` and tolerates a
  short read by treating a missing symbol as "not found" (returns 0), so it
  fails closed rather than crashing the target.
- **Remote-read over a gap**: not a risk for the addresses the resolver reads
  (verified outside the LOAD#1/LOAD#2 gap). If a device maps with a gap
  covering a needed vaddr, `target_read_mem` returns -1 and the resolver
  returns 0 (no crash). A mapping-cover fallback can be added later if a real
  device needs it; not needed now.
- **After this fix, injection may hang later** (e.g., `AttachCurrentThread`
  under ptrace — hypothesis from the prior handoff). That is a separate change;
  this change's scope is the resolver + its test. The success signal for this
  change is reaching the first `IMPLANT_LOGI("start")` in logcat.
