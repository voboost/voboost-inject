# Design — build-and-signing (Rust + NDK replaces meson/Vala/frida)

<!-- Date: 2026-07-23. Records why the build moves to Cargo + ndk-build/CMake,
     why each frida/meson requirement is removed rather than modified, and why
     the native-payload toolchain constraints live here. -->

## D1 — Why a Makefile orchestrates a mixed Cargo + ndk-build/CMake build

**Choice:** a top-level `Makefile` drives the daemon via `cargo-ndk` and the
native artifacts (injector, implant, Dobby, LSPlant prebuilts) via NDK r29
`ndk-build`/CMake, producing per-ABI outputs consumed by the daemon build.

**Reasoning:** the build is fundamentally polyglot — Rust for the daemon, C
for the injector, C++ for the implant and hooker. No single build system is
native to all three. `cargo-ndk` is the idiomatic Rust cross-compiler to
`aarch64-linux-android`; `ndk-build`/CMake is the NDK-native path for C/C++.
A `Makefile` orchestrating both mirrors the existing `make build-android`
entry point (which already wraps meson) so the developer-facing surface
(`make build`, `make build-android`, `make check`, `make lint`) is preserved
while the internals swap. The daemon crate links `libinjector.a` (C, static)
via a `build.rs` FFI declaration; `libimplant.so` and the hooker `.so`/`.a`
are not linked into the daemon (the daemon hands them as files — see
`native-payload` D1), so the daemon build does not depend on the implant build
completing, only on the injector archive.

## D2 — Why each frida/meson requirement is removed, not modified

**Choice:** all five frida/meson-specific requirements are REMOVED, not
MODIFIED.

**Reasoning:** each is entirely about the frida/meson toolchain — the meson
release configuration, the frida-core subproject, the frida-agent hash-style
patch, frida's meson fork, and frida-meson pickle loading. None of these has
a "modified" form under the new stack: there is no frida-core to configure, no
frida-agent to patch, no frida-meson to invoke. Restating them with different
words would be artificial — the new build (Cargo + ndk-build/CMake) is a
different mechanism captured by the ADDED requirements. The toolchain facts
that *do* carry over (NDK r29, the Android target) are restated in the new
requirements because they now belong to a different build system, not because
the old requirement was "modified."

## D3 — Why the toolchain constraints live here, not in native-payload

**Choice:** the native-payload toolchain constraints (NDK r29, c++_static,
LOG_DISABLED, lsplant.hpp from source, `-flto` removed) are owned by this
change (build-and-signing), not by `native-payload`.

**Reasoning:** `native-payload` specifies the *contract* — what the three
artifacts are and the mechanism between them. The toolchain facts (which NDK
version, which C++ runtime, which compile flags) are *build* properties: they
belong to "how the artifacts are built," which is this spec's domain. Putting
them in `native-payload` would make that contract spec also a build spec,
mixing two concerns. The constraints are referenced by `native-payload` (the
PoC proved them) but normatively owned here so there is one place to update
when the toolchain changes. This mirrors how the existing spec owned the
"NDK r29" fact for the frida build — same fact, new build system.

## D4 — Why the version source moves to Cargo.toml

**Choice:** the project version's single source of truth moves from
`meson.build` `project().version` to `Cargo.toml` `[package].version`.

**Reasoning:** `meson.build` is removed; the daemon is a Cargo crate, so
`Cargo.toml` is the natural and only place a Rust project keeps its version.
The CI versioning gate (`ci-versioning`) consumes this value; it is updated in
its own change to read from `Cargo.toml` instead of `meson.build`. The
baseline value `1.0.0-beta1` carries over unchanged.

## D5 — Why the embedded-key generation moves to build.rs

**Choice:** the public key is embedded via a Rust `build.rs` that reads the PEM
and emits a generated Rust source carrying the raw ed25519 bytes (was a meson
`custom_target`).

**Reasoning:** the principle (compiled-in key, never read at runtime, changed
by rebuilding with a different PEM) is toolchain-agnostic and unchanged. Only
the *mechanism* of code generation moves: meson's `custom_target` → Rust's
`build.rs`, because meson is gone. A `build.rs` is the standard Cargo pattern
for build-time code generation and produces the same result: a source file
with the raw key bytes compiled into the binary.
