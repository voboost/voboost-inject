# Design — fix-build-native-wired-source

## Context

After the payload-path fix, the implant reaches `dlopen("liblsplant.so")` by
full path but the load fails with `cannot locate symbol
"_ZNSt6__ndk122__libcpp_verbose_abortEPKcz"`. Root cause: the committed
`prebuilt/<abi>/liblsplant.so` was built externally with `c++_shared`
(`DT_NEEDED libc++_shared.so`, NDK r29 `std::__ndk1`), and `system_server` has
no matching libc++ loaded — the system libc++ provides `std::__1`, not
`std::__ndk1`. The `build-and-signing` spec required `c++_static` + built from
source, but the committed prebuilt violated both and no gate caught it.

## Approach

Wired CMake build of the LSPlant + Dobby git submodules into `prebuilt/<abi>/`,
always from source. The NDK toolchain already passes `-static-libstdc++` for
`ANDROID_STL=c++_static`, which inlines libc++ into each `.so` and removes the
`libc++_shared.so` `DT_NEEDED` (verified: both ABIs' new `liblsplant.so` list
only `liblog/libz/libm/libdl/libc`). `libdobby.a` is a static archive linked
into `libimplant.so` at build time; libc++ there is also static.

### OTA win

OTA is already per-file by sha256 (`incremental-delta`). c++_static inlines
libc++ into each `.so` as part of that file, so the files stay independent — a
change to `liblsplant.so` deltas only `liblsplant.so`. c++_shared would have
introduced a *shared* cross-file dependency that couples updates (plus the ABI
bug we just fixed). That is why the spec mandates c++_static.

## Submodules

- `third_party/lsplant` = LSPosed/LSPlant @ a96c797 (master, namespace v2; our
  `lsplant.hpp` matches upstream — cosmetic-only diff).
- `third_party/dobby` = jmpews/Dobby @ 5dfc854 (master; the only tag `latest`
  points at the same commit).
- Recursive subdeps inited: lsplant → dex_builder → parallel_hashmap.

## Patches applied to submodules

The submodules track clean upstream commits (jmpews/Dobby `5dfc854`,
LSPosed/LSPlant `a96c797`); they carry NO local commits. The NDK r29 / c++_static
adaptations the upstream trees need are stored as patch files in the repo at
`patches/{dobby,lsplant}/` and applied to the submodule working trees by
`make build-third-party` before CMake. The apply step is idempotent:
`git -C <sub> apply --reverse --check` detects an already-patched tree and
skips. This keeps a fresh `git submodule update --init` + `make build-third-party`
reproducible without carrying a fork and without depending on /tmp artifacts.
The patches were extracted from the PoC `voboost-inject-new/poc/` working
trees (rule: working artifact → find its source first).

### Dobby (5 patches)

- `closure_bridge_arm64.asm`: `adrp@PAGE + add@PAGEOFF` →
  `ldr TMP_REG_0, =common_closure_bridge_handler` (clang 21 rejects @PAGEOFF
  under -fPIC; literal-pool load is position-independent).
- `common_bridge_handler.h`: `inline` → `__attribute__((weak))` (ADRP needs
  external linkage; weak lets every TU emit it without duplicate-symbol link
  errors).
- `code-patch-tool-posix.cc`: drop `#include "core/arch/Cpu.h"` (file absent).
- `platform.h`: move `#include "dobby/common.h"` to bottom (circular include;
  OSMemory must be declared first for `os_arch_features.h`).
- `ProcessRuntime.cc` + `dobby_symbol_resolver.cc`: `module.load_address` →
  `module.base` (master renamed the field).
- `core/arch/arm/registers-arm.h` + `clear-cache-tool-arm-dummy.cc`:
  `#include "core/arch/Cpu.h"` → `core/arch/CpuRegister.h` (registers-arm.h
  needs `RegisterBase`, which lives in `CpuRegister.h` post-refactor; the
  dummy file just needs to parse). These two are arm-only; arm64 builds
  regardless.

### LSPlant (2 patches)

- `CMakeLists.txt`: `add_compile_definitions(LOG_DISABLED)` (dir scope, reaches
  C++23 module BMIs); drop `-flto`; `target_compile_definitions LOG_DISABLED`;
  guard `DEBUG_SYMBOLS_PATH` against an empty `-DDEBUG_SYMBOLS_PATH=` (the
  post-build step would otherwise create `/${ANDROID_ABI}` at the read-only
  filesystem root).
- `jni_helper.hpp`: wrap `__android_log_print` in `#ifndef LOG_DISABLED`
  (LSPlant's `__android_log_print` crashes inside an ART inline-hook trampoline
  via format-string pointer corruption; `LOG_DISABLED` makes every `LOG*` a
  no-op).

## CMake options

- LSPlant: `-G Ninja` (C++23 modules reject Unix Makefiles); `ANDROID_STL=c++_static`
  via toolchain directly — **NOT** `-DLSPLANT_STANDALONE=ON` (it calls
  `find_package(cxx)`, NDK r29 has no `cxx.cps`); `-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF`
  (-flto off per spec); `-DLSPLANT_BUILD_SHARED=ON`.
- Dobby: Unix Makefiles OK (no C++23 modules); `--target dobby_static`;
  `ANDROID_STL=c++_static`.

## libdobby.a vs liblsplant.so

- `liblsplant.so` — runtime payload. dlopen'd by the implant; shipped in the
  release manifest and the runtime payload dir.
- `libdobby.a` — build-time only. Statically linked into `libimplant.so` by
  the implant `Android.mk` (`LOCAL_STATIC_LIBRARIES := dobby_static`). Never
  dlopen'd at runtime. Removed from the payload.
- `liblsplt.so` — unused. Not in `DT_NEEDED` of `liblsplant.so`; not dlopen'd
  by the implant. Dropped entirely.

## Gate (check-prebuilt)

`make check-prebuilt` runs `llvm-readelf -d` on every `prebuilt/<abi>/liblsplant.so`
and `implant/libs/<abi>/libimplant.so`, fails if `libc++_shared.so` appears in
`DT_NEEDED`. This is the gate for the "SHALL be built c++_static" requirement
(codestyle rule: every SHALL needs a gate; this one was previously missing,
which let the bad prebuilt land).

## armeabi-v7a Dobby — known upstream break

Master Dobby (`jmpews/Dobby` @ 5dfc854) does NOT build for armeabi-v7a. The
"Refactor? Yes" commits (2023-04) removed
`source/MemoryAllocator/CodeBuffer/code_buffer_arm.h` (which defined
`arm_inst_t` / `thumb{1,2}_inst_t`) but left dangling references:
`source/core/assembler/assembler-arm.h:9` still `#include`s the deleted file,
and `source/MemoryAllocator/CodeMemBuffer.h` uses the now-undefined typedefs.
arm64 builds cleanly from source; armv7 does not.

Decision: build arm64 Dobby from source; keep the committed
`prebuilt/armeabi-v7a/libdobby.a` (built from an older Dobby commit with a
working arm port) as a fallback. This is marked `## Unverified` in the
build-and-signing spec (rule: no gate → Unverified + reason). Restoring
armv7-from-source needs an upstream fix or a local arm-port reimplementation —
out of scope for this change.

## Verification (offline)

- `git submodule update --init --recursive && make build-native` produces
  `prebuilt/{arm64-v8a,armeabi-v7a}/liblsplant.so` and
  `prebuilt/arm64-v8a/libdobby.a` (armv7 libdobby.a stays committed).
- `make check-prebuilt` — `DT_NEEDED` of every checked `.so` has no
  `libc++_shared.so`.
- `make build-android` consumes the fresh prebuilts and produces the daemon +
  implant per ABI.
- `cd daemon && cargo fmt --check && cargo clippy --all-targets && cargo test`.
- `make test` (cargo + injector elf_parse + implant dirname).
- `make lint` (uncrustify).
- `npx @fission-ai/openspec validate fix-build-native-wired-source --strict`.

## Device integration (separate step, on real hardware)

Rebuild the implant with the fresh `c++_static` `liblsplant.so`, redeploy the
payload, restart `system_server`, and observe the injection in logcat. Expected:
past `cannot locate symbol` → `lsplant::Init` ok → next step (agent load).
