# prebuilt/ — native payload hooker libraries (per-ABI)

Prebuilt binary dependencies loaded by `libimplant.so` at runtime. The daemon
carries both ABIs and selects the matching one based on runtime bitness
detection (see `native-payload` spec).

## Contents per ABI (`arm64-v8a/`, `armeabi-v7a/`)

| File | Source | License |
|---|---|---|
| `libdobby.a` | [Dobby](https://github.com/jmpews/Dobby) (Apache-2.0) | Static-linked into `libimplant.so` |
| `liblsplant.so` | [LSPlant](https://github.com/LSPosed/LSPlant) (LGPL-2.1) | `dlopen`'d by implant at runtime |
| `liblsplt.so` | [lsplt](https://github.com/LSPosed/LSPlant) (LGPL-2.1) | Dependency of liblsplant |

## Provenance

Built from source with NDK r29 (see `build-and-signing` spec). The committed
binaries were extracted from the PoC `voboost-inject-new/poc/` Maven prefab
extracts (built with NDK r29, `c++_static`). Rebuilding from source is the
canonical path (`make build-native` will invoke the Dobby/LSPlant CMake builds).

## Rebuild

```sh
# From the repo root (once build-and-signing targets are wired):
make build-native
```

The build fetches Dobby + LSPlant source, compiles with NDK r29, and
places the artifacts here.
