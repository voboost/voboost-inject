## Context

The injector writes small strings into the target process's own stack memory
(via `PTRACE_POKETEXT`/`process_vm_writev`-style writes) at addresses derived
from the target's stack pointer (SP) at attach time, because there is no
other scratch memory conveniently reachable across the ptrace boundary. The
file already documents the governing constraint: "`.so` path written ~8KB
below SP (closer is clobbered by call frame)" — anything placed too close to
SP gets overwritten once the target executes function calls on its own stack
(here, the two remote calls to `__loader_dlopen` and `__loader_dlsym` that
must run before the final `implant_init` call).

Two bugs shipped in sequence while adding the missing `config_path` plumbing:
1. `vbi_inject` had no `config_path` parameter at all — `cfg` was always the
   `.so` path's address.
2. The fix's first attempt placed the new string 4KB *toward* SP from the
   `.so` path (`str_addr + 4096`, i.e. `SP - 4096`), inside the danger zone
   the file's own comment warns about — the string arrived as an empty
   string (first byte zeroed) by the time `implant_init` read it.

## Goals / Non-Goals

**Goals:**
- Give the injector a real, distinct memory slot for `config_path` that
  survives until `implant_init` reads it.
- Keep the C ABI change minimal and contained to the one existing caller.

**Non-Goals:**
- Not redesigning the stack-scratch-memory scheme itself (e.g. switching to
  `mmap`'d scratch pages in the target) — out of scope for this fix; the
  existing "N KB below SP" convention is kept and extended.
- Not touching the injector's DBG/verbose-trace logging design (tracked
  separately, not part of this change).

## Decisions

- **Add `config_path` as a fourth `vbi_inject` parameter** rather than a
  side-channel (e.g. writing it to a fixed well-known file the target reads
  on its own). The channel-B file *is* that side-channel for config
  contents; what was missing was simply telling the target WHERE that file
  is, which is exactly what an extra argument to `implant_init` is for.
- **Place the new string at `str_addr - 4096`** (further below the `.so`
  path, away from SP) rather than `str_addr + 4096` (toward SP). This keeps
  a single "far from SP" zone for all injector-written strings (`.so` path,
  init-symbol name, config path), consistent with the existing documented
  rationale, instead of introducing a second, riskier zone.
- **Fix the unused-variable build break with a targeted `(void)` discard**,
  not by changing the `VBI_DBG` macro design — that redesign is tracked as a
  separate follow-up (bringing `injector.c` to the same leveled-logging
  convention as `daemon/src/log.rs` / the Kotlin `Logger.kt`), explicitly
  deferred at the requester's direction.

## Risks / Trade-offs

- [Risk] Stack-relative scratch offsets are inherently fragile — a future
  change to how `__loader_dlopen`/`__loader_dlsym` are invoked (e.g. a larger
  call frame) could again clobber a slot that today is "far enough". →
  Mitigation: this change keeps all scratch strings on the same well-tested
  side of `str_addr` (not introducing a new offset scheme), and the emulator
  E2E run is the gate that would catch a regression (`configPath is empty`
  is a distinctive, easy-to-spot symptom).
- [Risk] `vbi_inject`'s C ABI change is breaking, but it has exactly one
  caller in this codebase (`daemon/src/injector.rs`), updated in the same
  change — no external consumers exist (per `injector.h`'s own framing: "The
  daemon's sole extern "C" seam to the native layer").
