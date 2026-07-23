# Design — native-payload

<!-- Date: 2026-07-23. Records why the native payload contract is specified as a
     standalone capability and why each machine-verified mechanism choice is the
     one that lands, versus the alternatives already tried and rejected on the
     device. -->

## D1 — Why a standalone `native-payload` capability

**Choice:** specify the injector/implant/hooker contract as its own capability,
separate from `injection-control` (which will only *drive* it).

**Reasoning:** with frida, the entire mechanism was one opaque C dependency, so
"how code enters a process" had no spec — `injection-control` described frida API
calls. The new mechanism is our code across three artifacts with hard, verified
constraints. Putting the contract in one capability gives every later change a
stable thing to depend on: `injection-control` (drives the injector, reconciles
by the marker), `build-and-signing` (produces the per-ABI artifacts),
`trust-verification`/`release-manifest` (sign/list the `.so` set),
`agent-entry-seam` (the Java entry the implant calls). Splitting mechanism from
orchestration keeps the daemon spec thin and keeps the verified invariants in one
place so they are not re-derived.

**Rejected — fold it into `injection-control`:** that spec would then mix daemon
orchestration (plan, reconcile, safety hand-off) with low-level ptrace/ELF/Dobby
facts, and four other capabilities would have no clean dependency target.

## D2 — Why the hybrid `PTRACE_CONT` + `LR=0` remote call

**Choice:** remote calls use `PTRACE_CONT` with the link register set to `0` and
the fault at `0` treated as the return.

**Reasoning:** `PTRACE_SINGLESTEP` and hardware breakpoints do not fire on the
target kernel `4.14.156-perf+` (machine-verified). AndKittyInjector (MIT) builds
and detects bitness correctly but relies on single-step, so it cannot detect the
remote-call return on this kernel — which is exactly why the hybrid was written.

**Rejected — AndKittyInjector as-is:** dead on this kernel's single-step.
**Rejected — `reveny/Android-Ptrace-Injector` linked in:** GPL-3.0; usable only
as a separate process (mere aggregation), not linked into the daemon.

## D3 — Why runtime ELF symbol resolution, not offsets

**Choice:** resolve `__loader_dlopen`/`__loader_dlsym` from the target's
`PT_DYNAMIC` at runtime; use the `r-xp` segment base for function addresses.

**Reasoning:** a hardcoded offset (`0x14244` observed on this device's `linker64`)
is device/build-specific and breaks across vendor builds. `linker64` is mapped as
split `r--p`+`r-xp` segments both at file-offset 0 on Android 9, so an address
computed against the header segment is wrong — function addresses must use the
code segment base. The observed offset stays in the design doc as an
implementation anchor, not as spec.

## D4 — Why explicit `implant_init`, not constructors

**Choice:** the injector explicitly remote-calls `implant_init`; the implant runs
startup only from there.

**Reasoning:** under ptrace-dlopen the target runs in a hijacked-thread context in
which `__attribute__((constructor))` and `JNI_OnLoad` do not run (verified via
`System.load`). A single explicit entry also removes the PoC's double-run
(`UnsatisfiedLinkError` when the chain fired twice via ctor *and* explicit call).
Hence the single-entry + guard requirement.

## D5 — Why `safe_resolve_symbol`, not `DobbySymbolResolver`

**Choice:** LSPlant's `art_symbol_resolver` is `safe_resolve_symbol`
(`dlsym(RTLD_DEFAULT)` → file-based `.symtab` fallback), never
`DobbySymbolResolver`.

**Reasoning:** the PoC's real root cause was `DobbySymbolResolver` faulting in
`elf_ctx_init` (not a Dobby-trampoline nor logger bug, as earlier believed). The
file-based fallback works because `libart.so` on the device is not stripped
(29 sections, `.symtab` at `0x6026d8`); the symbol count must come from `DT_HASH`
(`DT_GNU_HASH` mis-counted on the first attempt).

## D6 — Why the marker is the real `.so` path

**Choice:** the idempotency marker is the real `libimplant.so` path in
`/proc/<pid>/maps`.

**Reasoning:** ptrace-dlopen loads a real file, so the path in maps is stable and
unambiguous — a better marker than frida's `memfd:frida-agent (deleted)`. This is
also why injected code outlives the daemon (a restart, including OTA self-update,
reconciles by scanning for this path and does not re-inject). The reconciliation
behavior itself belongs to `injection-control`; this spec only fixes the marker.

## D7 — Build constraints referenced, not owned

The toolchain facts (NDK r29 / Clang 21 for LSPlant's C++23 modules, `c++_static`
to avoid the Android 9 `libc++_shared.so` ABI clash, `LOG_DISABLED` at dir scope
so it reaches the C++23 BMIs, `lsplant.hpp` from source, `-flto` removed) are
*constraints on producing a correct payload*. This spec states the ones that are
observable in the artifact's behavior (`safe_resolve_symbol`, silenced logger,
source `lsplant.hpp`, `-flto` off). The mechanics of the toolchain live in
`build-and-signing`; duplicating them here would create two owners.

## D8 — Bitness is per-injection, always

**Choice:** detect target bitness from the live process before every injection;
carry both ABIs.

**Reasoning:** bitness is a property of the device/build, not the agent. On
Android 9 (f0506h) most vendor targets are 32-bit; on Android 11 the same apps
may be 64-bit. A static agent→bitness table would be wrong on a different build,
and an ABI mismatch crashes the target (the PoC injector once crashed a 32-bit
target by treating it as 64-bit). The agent `.dex` is ABI-independent; detection
only chooses the native `.so`.
