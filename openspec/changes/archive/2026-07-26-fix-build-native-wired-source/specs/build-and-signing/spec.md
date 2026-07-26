## ADDED Requirements

### Requirement: Third-party hooker libs built from source

The native third-party hooker libraries (LSPlant `liblsplant.so`, Dobby
`libdobby.a`) SHALL be built from source by a wired `make build-third-party`
target that invokes CMake on the `third_party/{lsplant,dobby}` git submodules
with NDK r29 and `ANDROID_STL=c++_static`. The submodules track clean upstream
commits; the NDK r29 / c++_static adaptations the upstream trees need SHALL live
as patch files in `patches/{dobby,lsplant}/` in the repo and SHALL be applied
to the submodule working trees by `make build-third-party` before CMake
(idempotently: skip if already applied). This keeps a fresh
`git submodule update --init` + `make build-third-party` reproducible without
carrying a fork. The daemon SHALL NOT consume a `liblsplant.so` produced
outside this build (a committed prebuilt built by another toolchain). The
c++_static runtime invariant SHALL be gated by `make check-prebuilt`, which
SHALL reject any produced `liblsplant.so` or `libimplant.so` whose `DT_NEEDED`
includes `libc++_shared.so`. `liblsplt.so` SHALL NOT be built or shipped (it
is not in `DT_NEEDED` of `liblsplant.so` and is not dlopened by the implant).
`libdobby.a` is build-time only (statically linked into `libimplant.so`); it is
NOT part of the runtime payload. `make build-native` SHALL chain
`build-third-party` → `build-injector` → `build-implant` → `check-prebuilt`.

#### Scenario: Third-party hooker libs are built from source

- **WHEN** `make build-native` (or `make build-third-party`) runs from a clean
  checkout
- **THEN** it initializes the `third_party/{lsplant,dobby}` git submodules,
  applies the `patches/{dobby,lsplant}/` NDK-r29 patches to their working trees,
  invokes CMake for each ABI to build LSPlant + Dobby from those sources, and
  copies the outputs into `prebuilt/<abi>/`

#### Scenario: c++_static invariant is gated

- **WHEN** `make build-native` finishes producing the native artifacts
- **THEN** `make check-prebuilt` runs `llvm-readelf -d` on every produced
  `prebuilt/<abi>/liblsplant.so` and `implant/libs/<abi>/libimplant.so` and
  fails the build if any of them has `libc++_shared.so` in its `DT_NEEDED`

#### Scenario: liblsplt is not produced

- **WHEN** `make build-native` runs
- **THEN** no `liblsplt.so` is built or placed in `prebuilt/`, and the runtime
  payload does not contain it

#### Scenario: libdobby.a is build-time only

- **WHEN** the implant links against Dobby
- **THEN** `libdobby.a` is statically linked into `libimplant.so` at build
  time, and `libdobby.a` is NOT shipped in the runtime payload

## Unverified

### Requirement: armeabi-v7a Dobby built from source

LSPlant is built from source for both ABIs; Dobby is built from source for
`arm64-v8a`. **armeabi-v7a Dobby is NOT built from source.** Master Dobby
(`jmpews/Dobby` @ 5dfc854) does not build for armeabi-v7a: the "Refactor? Yes"
commits (2023-04) removed `source/MemoryAllocator/CodeBuffer/code_buffer_arm.h`
(which defined `arm_inst_t` / `thumb{1,2}_inst_t`) but left dangling references
(`source/core/assembler/assembler-arm.h:9` still includes the deleted file,
and `source/MemoryAllocator/CodeMemBuffer.h` uses the now-undefined typedefs).
arm64 builds cleanly; armv7 does not.

`prebuilt/armeabi-v7a/libdobby.a` is a committed fallback built from an older
Dobby commit with a working arm port. There is no gate verifying that the
armv7 Dobby is c++_static or reproducible from source — so this requirement is
marked `## Unverified` (codestyle rule: every SHALL needs a gate; no gate →
Unverified + reason). Restoring armv7-from-source requires an upstream fix or
a local arm-port reimplementation; tracked as a follow-up.
