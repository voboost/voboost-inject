## 1. Implementation (already done)

- [x] 1.1 Resolve `lsplant::Hook`/`UnHook` via `dlsym` on mangled symbol
  names (`nm -D` against the built `liblsplant.so`, not guessed).
- [x] 1.2 Implement `native_hook_impl`/`native_unhook_impl` delegating to
  the resolved function pointers, clearing JNI exceptions defensively.
- [x] 1.3 Implement `register_hooker_natives` using `loader.loadClass(...)`
  (not `FindClass`) + `RegisterNatives`.
- [x] 1.4 Call `register_hooker_natives` in `load_and_call_agent`, after the
  dex loads and before `AgentEntry.init`.

## 2. Gate

- [x] 2.1 `make build-implant` — both ABIs (arm64-v8a, armeabi-v7a) build
  without errors.
- [x] 2.2 Verified continuously throughout this session's emulator and
  real-hardware testing: every agent hook (`settings-menu`'s
  `CarSettingActivity.onCreate`, `pedestrian-warning`'s reflection-based
  `CanBusManager` lookups) depends on this bridge; no
  `UnsatisfiedLinkError` observed.

## 3. Spec sync

- [x] 3.1 Add the `HookerNative` JNI bridge requirement to `native-payload`.
