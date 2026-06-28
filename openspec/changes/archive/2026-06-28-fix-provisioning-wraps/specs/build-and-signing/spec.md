## ADDED Requirements

### Requirement: Android cross-build uses frida's meson and a complete cross-file
`make build-android` SHALL configure the arm64-v8a device build with frida's own
meson (the `frida/meson` commit pinned by the fetched `frida-core`'s `releng/meson`
submodule), not the system meson, because frida-gum's `quickcompile` (`native:
true`) requires its QuickJS subproject to be built for the build machine — only
frida's meson re-invokes a `[provide]` subproject for the build machine. The
cross-file `config/android-cross.ini` SHALL set `subsystem = 'android'` in
`[host_machine]` (frida-core derives `host_os` from `host_machine.subsystem()` and
gates Android on it) and SHALL name a `readelf` binary in `[binaries]` (frida-core
does `find_program('readelf')` for the non-darwin `host_os_family`; the NDK's
`llvm-readelf` is already on PATH for the cross-compiler). The NDK SHALL be r29 —
frida-core 17.11.0's releng requires exactly major version 29
(`releng/env_android.py NDK_REQUIRED=29`, checked when building the embedded
agent); r27/r27d are rejected with `NdkVersionError`.

#### Scenario: Cross-file declares the Android subsystem
- **WHEN** `config/android-cross.ini` is examined
- **THEN** its `[host_machine]` sets `subsystem = 'android'`, and its `[binaries]`
  names a `readelf` (e.g. `llvm-readelf`)

#### Scenario: NDK version satisfies frida-core
- **WHEN** `make build-android` runs
- **THEN** `ANDROID_NDK_HOME` points at an NDK whose major version is 29 (the
  release workflow pins `ndk-version: r29`; r27/r27d fail the releng check)

#### Scenario: Cross-build configures with frida's meson
- **WHEN** `make build-android` runs `meson setup`
- **THEN** it invokes frida's meson (provisioned by `make init`), and `meson setup`
  exits 0 with no `Subsystem not defined`, `quickjs … did not override`, or
  `Program 'readelf' not found` error

#### Scenario: Device binary builds
- **WHEN** `make build-android` completes
- **THEN** it produces the fully-static arm64-v8a `voboost-inject` device binary
