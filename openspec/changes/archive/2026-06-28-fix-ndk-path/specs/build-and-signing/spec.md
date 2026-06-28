## MODIFIED Requirements

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
agent); r27/r27d are rejected with `NdkVersionError`. `make build-android` SHALL
derive the NDK toolchain PATH automatically from `ANDROID_NDK_HOME` (the glob
`$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/*/bin`), so the cross-compiler and
LLVM tools resolve without the developer manually configuring PATH. It SHALL fail
early with a clear message if `ANDROID_NDK_HOME` is not set or the toolchain bin
is not found.

#### Scenario: Cross-file declares the Android subsystem
- **WHEN** `config/android-cross.ini` is examined
- **THEN** its `[host_machine]` sets `subsystem = 'android'`, and its `[binaries]`
  names a `readelf` (e.g. `llvm-readelf`)

#### Scenario: NDK version satisfies frida-core
- **WHEN** `make build-android` runs
- **THEN** `ANDROID_NDK_HOME` points at an NDK whose major version is 29 (the
  release workflow pins `ndk-version: r29`; r27/r27d fail the releng check)

#### Scenario: NDK toolchain PATH is derived automatically
- **WHEN** `make build-android` runs with `ANDROID_NDK_HOME` set to a valid NDK root
- **THEN** it derives the toolchain bin directory from
  `$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/*/bin`, adds it to PATH for the
  build, and the cross-compiler and LLVM tools resolve without requiring the
  developer to configure PATH manually

#### Scenario: Missing ANDROID_NDK_HOME fails early
- **WHEN** `make build-android` runs without `ANDROID_NDK_HOME`
- **THEN** it fails immediately with the message
  `build-android: ANDROID_NDK_HOME not set` (exit 1), before invoking meson

#### Scenario: Invalid NDK path fails early
- **WHEN** `make build-android` runs with `ANDROID_NDK_HOME` set to a path that
  has no `toolchains/llvm/prebuilt/*/bin`
- **THEN** it fails with `build-android: NDK toolchain not found` (exit 1), before
  invoking meson
