## Why

`voboost-script`'s Java `Hooker` facade calls `HookerNative.nativeHook`/
`nativeUnhook` (native methods) to reach `lsplant::Hook`/`UnHook` — but
nothing on the C++ side resolved those LSPlant symbols or registered the
native methods until this (already-implemented, uncommitted) change to
`implant.cpp`. Without it, every `hooker.hook(...)` call in every agent
would fail with `UnsatisfiedLinkError` the first time it ran. This has been
exercised continuously throughout hardware verification this session (every
successful hook — `CarSettingActivity.onCreate`, `CanBusManager` lookups —
depends on this bridge) but had no spec of its own.

## What Changes

- Specify `implant.cpp`'s resolution of `lsplant::Hook`/`UnHook` via `dlsym`
  on mangled symbol names (matching the existing `lsplant::Init` resolution
  pattern already in this file).
- Specify `register_hooker_natives`: `RegisterNatives` for
  `ru/voboost/runtime/HookerNative` on the dex's own classloader (not
  `FindClass`, which only searches the system loader and cannot see a class
  that lives inside the just-loaded in-memory dex), called after the dex is
  loaded and before `AgentEntry.init`.
- Specify defensive JNI-exception handling: both `nativeHook`/`nativeUnhook`
  implementations clear any pending JNI exception from the underlying LSPlant
  call rather than letting it propagate.

## Capabilities

### New Capabilities
(none)

### Modified Capabilities
- `native-payload`: add a requirement for the `HookerNative` JNI bridge
  (resolution, registration ordering, defensive exception handling) —
  this is additional coverage of the implant's native surface, not a change
  to any existing native-payload requirement's behavior.

## Impact

- `implant/implant.cpp`: `lsplant_hook_t`/`lsplant_unhook_t` typedefs +
  `dlsym` resolution, `native_hook_impl`/`native_unhook_impl`,
  `register_hooker_natives`, and its call site in `load_and_call_agent`
  (after dex load, before `AgentEntry.init`).
- No change to `injector`, the daemon, or the Java runtime's public API —
  this is purely the native half of an already-specified Java-facing
  contract (`hooker-facade`, in `voboost-script`).
- Verified throughout this session's hardware testing: every successful
  `hooker.hook(...)` call (both agents) depends on this bridge; no
  `UnsatisfiedLinkError` observed once the dex-classloader `loadClass`
  (not `FindClass`) fix was in place for `HookerNative` resolution.
