# Design — ci-pipeline (Rust + NDK r29 matrix)

<!-- Date: 2026-07-23. The pipeline follows the build system; only the
     provision and cache details change. -->

## D1 — Why the provision and cache follow the new toolchain

**Choice:** `make init` now provisions the Rust toolchain (from
`rust-toolchain.toml`) and verifies NDK r29; the cache keys on those pins, not
on the frida/vala-lint revisions.

**Reasoning:** the pipeline exists to validate the project's build. When the
build system changes (meson/Vala/frida → Cargo/ndk-build), the provision step
must change with it or it provisions tools that no longer exist and omits
tools that now do. The cache key must track what `make init` actually produces
(the Rust toolchain + NDK), or a cache hit restores stale frida artifacts and
a cache miss rebuilds the wrong thing. The lint/test/build invocation itself
(`make lint`, `make test`, `make build`) is unchanged at the Makefile level —
the Makefile internals swapped, but the CI entry points did not.
