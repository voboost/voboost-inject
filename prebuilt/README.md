# prebuilt/ — third-party native libraries (per-ABI), built from source

Output directory for the wired from-source build of the LSPlant + Dobby git
submodules (`make build-third-party`). The implant consumes these: libdobby.a
is linked statically into libimplant.so at build time, liblsplant.so is
dlopen'd at runtime (the daemon selects the matching ABI via bitness
detection — see `native-payload` spec).

## Contents per ABI (`arm64-v8a/`, `armeabi-v7a/`)

| File | arm64-v8a | armeabi-v7a | Used by |
|---|---|---|---|
| `libdobby.a` | built from source ([Dobby] @ 5dfc854) | **committed fallback** (see below) | `libimplant.so` (static link) |
| `liblsplant.so` | built from source ([LSPlant] @ a96c797) | built from source ([LSPlant] @ a96c797) | `libimplant.so` (dlopen) |

[Dobby]: https://github.com/jmpews/Dobby
[LSPlant]: https://github.com/LSPosed/LSPlant

## Generated, not committed (mostly)

All artifacts here are gitignored except the armeabi-v7a Dobby fallback. They
are produced by `make build-third-party` from the `third_party/{dobby,lsplant}`
git submodules, and consumed by `make build-implant` (which links
`libdobby.a`) and by the release-manifest/payload step (which ships
`liblsplant.so`). Run `make build-native` to regenerate everything.

### armeabi-v7a/libdobby.a — committed fallback

Master Dobby (`jmpews/Dobby` @ 5dfc854) does NOT build for armeabi-v7a: the
"Refactor? Yes" commits (2023-04) removed
`source/MemoryAllocator/CodeBuffer/code_buffer_arm.h` but left dangling
`#include`s plus `arm_inst_t` / `thumb{1,2}_inst_t` typedefs that no longer
resolve. arm64 builds cleanly from source; armv7 does not. The committed
`armeabi-v7a/libdobby.a` was built from an older Dobby commit that still had a
working arm port, and is kept as a fallback until the upstream armv7 port is
restored or reimplemented. Tracked as `## Unverified` in the build-and-signing
spec (rule: every SHALL needs a gate; armv7 Dobby-from-source has no gate).

## Rebuild

```sh
make build-native   # build-third-party + build-injector + build-implant + check-prebuilt
```

The c++_static gate (`make check-prebuilt`) verifies that liblsplant.so /
libimplant.so do NOT link libc++_shared.so (build-and-signing invariant).
