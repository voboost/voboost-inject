## Why

The committed `prebuilt/{arm64-v8a,armeabi-v7a}/liblsplant.so` was built
externally with `c++_shared` (its `DT_NEEDED` includes `libc++_shared.so`).
When the implant `dlopen`s it inside `system_server`, the system loader cannot
reconcile the NDK r29 `std::__ndk1` namespace symbols against the system
libc++ (`std::__1`): `cannot locate symbol
"_ZNSt6__ndk122__libcpp_verbose_abortEPKcz"`. The `build-and-signing` spec
requires `c++_static` + built-from-source, but the committed prebuilt violates
both, and no gate catches it — the spec's "SHALL be built c++_static" was an
ungated premise.

Separately, `libdobby.a` (static-linked into `libimplant.so` at build time) and
`liblsplt.so` (unused — not in `DT_NEEDED` of `liblsplant.so`, not dlopened by
the implant) were carried in the runtime payload and listed in
`release-manifest`/`incremental-delta`/`native-payload` as payload files.
That is pure OTA bloat: neither file is needed at runtime, so shipping them
inflates every payload-only delta for nothing.

## What Changes

- **Wired from-source build (`Makefile`)** — `make build-third-party` builds
  LSPlant and Dobby from the `third_party/{lsplant,dobby}` git submodules via
  CMake (NDK r29 toolchain, `ANDROID_STL=c++_static`), and copies the outputs
  into `prebuilt/<abi>/`. `make build-native` now runs `build-third-party`
  before `build-injector`/`build-implant`, then runs the new
  `make check-prebuilt` gate. Patches to the submodules (Dobby asm/`weak`/
  `module.base`/drop-missing-`Cpu.h`; LSPlant `LOG_DISABLED`/-flto/
  `DEBUG_SYMBOLS_PATH`) live in the submodule working trees and are documented
  in `design.md`.
- **c++_static gate (`Makefile`)** — `make check-prebuilt` rejects any
  `liblsplant.so` or `libimplant.so` whose `DT_NEEDED` includes
  `libc++_shared.so`. This is the gate for the previously-ungated "SHALL be
  c++_static" requirement (codestyle rule: every SHALL needs a gate).
- **Payload slimming** — `libdobby.a` and `liblsplt.so` are removed from the
  runtime payload (`daemon/src/release_manifest.rs` `PAYLOAD_FILES`,
  release-manifest/incremental-delta/native-payload specs). The runtime payload
  is now `libimplant.so` + `liblsplant.so` per ABI; `libdobby.a` is build-time
  only (linked into `libimplant.so`), `liblsplt.so` is dropped entirely.
- **Generated prebuilts untracked** — the from-source outputs
  (`prebuilt/<abi>/liblsplant.so`, `prebuilt/arm64-v8a/libdobby.a`) are
  gitignored. The committed `armeabi-v7a/libdobby.a` is kept as a fallback
  (master Dobby is broken for armv7 — see `## Unverified` in `build-and-signing`).

## Capabilities

### Modified Capabilities

- `build-and-signing`: native artifacts SHALL be produced by a wired from-source
  build of the LSPlant + Dobby submodules (`make build-third-party`), the
  c++_static invariant SHALL be gated by `make check-prebuilt`, liblsplt.so is
  removed (unused), armeabi-v7a Dobby-from-source is marked `## Unverified`
  (upstream Dobby master does not build for armv7).
- `native-payload`: the daemon carries both ABIs of the runtime payload only
  (`libimplant.so`, `liblsplant.so`); `libdobby.a`/`liblsplt.so` are not
  runtime payload.
- `release-manifest`: the release manifest lists only the runtime payload
  files (`libimplant.so`, `liblsplant.so`) per ABI, not libdobby.a/liblsplt.so.
- `incremental-delta`: the per-file sha256 diff covers only the runtime payload
  files (`libimplant.so`, `liblsplant.so`), not libdobby.a/liblsplt.so.
