## Why

The daemon is moving off `frida-core` to a ptrace-based mechanism. frida
embedded the entire
inject/hook mechanism as one opaque C dependency, so there was no spec for
*how* code enters a target process — the `injection-control` spec only described
how the daemon drove frida's API.

The new mechanism is our own code across three native artifacts —
`libinjector` (C, ptrace entry), `libimplant.so` (C++, in-process loader), and
the hooker (LSPlant + Dobby) — glued by one C-ABI seam. Each artifact carries
hard, machine-verified constraints (the working ptrace remote-call shape, the
runtime symbol resolution, the reason `DobbySymbolResolver` cannot be used, the
idempotency marker, per-injection bitness detection). None of this is captured
by any current spec. Without a spec for the payload contract, `injection-control`
(which will drive it) has nothing to depend on, and the verified invariants —
proven end-to-end on vendor-Android 9 — risk being re-derived or lost.

This change adds the `native-payload` capability: the contract for the three
native artifacts and the mechanism between them, below the Java agent seam
(`agent-entry-seam`) and beneath the daemon orchestration (`injection-control`).
It is purely additive — it introduces no delta against the live frida specs, so
the frida daemon in prod is unaffected until later waves apply.

## What Changes

- **New capability `native-payload`** — specifies:
  - the three native artifacts, their languages, bitness, and boundaries
    (only C-ABI crosses Rust↔native; `std::function` never crosses the language
    boundary);
  - runtime per-injection bitness detection (never a static agent→bitness
    table); the daemon carries both ABIs of every native payload;
  - the hybrid ptrace remote-call mechanism (`PTRACE_CONT` + `LR=0` trap;
    cross-bitness regsets) and why SINGLESTEP/hw-bp are rejected;
  - runtime ELF symbol resolution via `PT_DYNAMIC` (linker64 split r--p/r-xp;
    caller inside `app_process`; path string ~8KB below SP);
  - load via `__loader_dlopen` + explicit remote-call `implant_init` (ctors do
    not run under ptrace-dlopen);
  - the single `implant_init(const char* cfg)` entry point;
  - implant loading agents via `InMemoryDexClassLoader` (JNI) and
    `JNI_GetCreatedJavaVMs`;
  - `lsplant::Init` with Dobby `inline_hooker`/`inline_unhooker` slots;
  - `safe_resolve_symbol` (not `DobbySymbolResolver`) and DT_HASH counting;
  - the silenced Dobby logger;
  - the idempotency marker = real `libimplant.so` path in `/proc/<pid>/maps`;
  - hook stacking (multiple agents / multiple hooks per method).
- **No existing spec is modified.** `injection-control`, `build-and-signing`,
  `trust-verification`, and `agent-entry-seam` will reference this contract in
  their own later changes.

## Capabilities

### Added Capabilities

- `native-payload`: the native injection/hook payload contract — the three
  native artifacts (`libinjector` C, `libimplant.so` C++, LSPlant+Dobby hooker),
  the ptrace entry mechanism, runtime bitness detection, runtime symbol
  resolution, the `implant_init` remote-call seam, and the `/proc/<pid>/maps`
  idempotency marker. This is the mechanism voboost-inject owns below the Java
  agent seam.
