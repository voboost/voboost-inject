## Why

The `ci-pipeline` spec provisions the runner with `make init` (which built the
frida-patched `valac`, fetched the frida wrap, and ran meson `setup`), then
lints and builds the daemon via meson. The build moved to Cargo +
`ndk-build`/CMake (see `build-and-signing`): there is no frida wrap, no
patched `valac`, no meson. The CI pipeline must provision and build the new
stack instead, or it will lint/build the wrong toolchain.

The change is narrow: what `make init` provisions and what `make build`
invokes have changed (owned by `build-and-signing`/`provisioning`); this spec
only updates the CI *pipeline* to match — cache keys, the build matrix, and
the provision step's description.

## What Changes

- **MODIFIED**:
  - "Provision via make init, lint, test, build on push and PR" — the provision
    step now builds the Rust toolchain and fetches NDK r29 (not the frida wrap
    / patched valac); the validation build runs `make build` over the Cargo +
    ndk-build/CMake stack.
  - "Cache the make init result" — the cache key tracks the Rust toolchain pin
    (`rust-toolchain.toml`) and the NDK version, not the frida/vala-lint
    revisions; the cached artifact is the Cargo registry/`target/` prefix and
    the fetched NDK.
- **Unchanged**: "No debug build job" (release-only is toolchain-agnostic).

## Capabilities

### Modified Capabilities

- `ci-pipeline`: the push/PR pipeline provisions and builds the Rust +
  NDK r29 stack (no frida wrap, no patched valac, no meson). The `make init`
  cache is keyed on the Rust toolchain pin and NDK version.
