## Context

`implant.cpp` already resolves `lsplant::Init` via `dlsym` on a mangled
symbol name (no exported C header from the LSPlant build) and calls it
before loading the agent dex. The Java `Hooker` facade (`voboost-script`,
specified by `hooker-facade`) needs the same treatment for `lsplant::Hook`/
`UnHook`, reached from Java via two native methods on
`ru.voboost.runtime.HookerNative`.

## Goals / Non-Goals

**Goals:**
- Get `lsplant::Hook`/`UnHook` callable from the Java facade without
  crashing the target on a JNI exception.

**Non-Goals:**
- Not changing the `lsplant::Init` resolution path (already correct, unchanged).
- Not adding new Hooker-facade Java API — this is only the native half of
  the already-specified `hooker-facade` contract.

## Decisions

- **Resolve by mangled symbol name via `dlsym`**, matching the existing
  `lsplant::Init` pattern in this file — consistent with how this repo
  already handles LSPlant's lack of a stable C ABI/exported header.
- **Register natives via `loader.loadClass(...)` + `RegisterNatives`, not
  `FindClass`.** `HookerNative` lives inside the just-loaded in-memory dex,
  which the system classloader (what `FindClass` searches) cannot see.
  `loadClass` on the dex's own `InMemoryDexClassLoader` instance resolves it.
- **Register after the dex loads, before `AgentEntry.init`.** Registration
  needs the dex's class to exist first (loaded moments earlier in
  `load_and_call_agent`); it must complete before any agent's `start()`
  could call `hooker.hook(...)`.
- **Clear JNI exceptions from the underlying LSPlant call defensively.** A
  hook failure (bad target method, LSPlant internal error) SHALL NOT crash
  the target process — matching this repo's general defensive-seam
  philosophy (see `agent-entry-seam`'s "Defensive invocation of the seam").

## Risks / Trade-offs

- [Risk] Mangled symbol names (`_ZN7lsplant2v24HookE...`) break if the
  LSPlant build's compiler/ABI changes. → Mitigation: same risk already
  accepted for `lsplant::Init`; the symbol was taken from `nm -D` against
  the actual built `liblsplant.so`, not guessed (documented in the MVP
  handoff plan).
