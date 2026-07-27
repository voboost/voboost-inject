## ADDED Requirements

### Requirement: HookerNative JNI bridge to lsplant::Hook/UnHook
The implant SHALL resolve `lsplant::Hook` and `lsplant::UnHook` via `dlsym`
on their mangled symbol names (matching the existing `lsplant::Init`
resolution pattern), and SHALL register them as the native implementations
of `ru.voboost.runtime.HookerNative.nativeHook`/`nativeUnhook` via
`RegisterNatives`. Because `HookerNative` lives inside the in-memory agent
dex (not on the system classloader), the implant SHALL resolve the class via
the dex's own `InMemoryDexClassLoader.loadClass(...)`, NOT `FindClass`
(which only searches the system loader and cannot see it). Registration
SHALL happen after the agent dex is loaded and before `AgentEntry.init` is
called, since agents may hook methods as soon as `start()` runs. Both native
implementations SHALL clear any pending JNI exception from the underlying
LSPlant call rather than let it propagate into the target process.

#### Scenario: HookerNative resolves via the dex classloader
- **WHEN** the implant registers `HookerNative`'s native methods
- **THEN** it resolves the class via `loader.loadClass("ru/voboost/runtime/
  HookerNative")` on the just-created `InMemoryDexClassLoader`, not
  `FindClass`

#### Scenario: Registration happens before agents can hook
- **WHEN** the implant loads the agent dex and is about to call
  `AgentEntry.init`
- **THEN** `HookerNative`'s natives are already registered, so any agent's
  `start()` can call `hooker.hook(...)` immediately without
  `UnsatisfiedLinkError`

#### Scenario: A failing hook does not crash the target
- **WHEN** `lsplant::Hook` or `lsplant::UnHook` throws a JNI exception (e.g.
  a malformed target method)
- **THEN** the native implementation clears the exception and returns a
  failure value (`null` / `false`) instead of letting the exception
  propagate into the target process
