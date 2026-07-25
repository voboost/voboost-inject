## Why

The `build-and-signing` spec is built entirely around the frida/meson/Vala
toolchain: meson release builds, frida-core as a meson subproject, the
frida-patched `valac`, frida's own meson fork, frida-gum QuickJS, the
`--hash-style=sysv` frida-agent patch, and meson cross-file wiring. The
ptrace migration removes frida-core entirely (see `native-payload`): the
daemon is Rust, the injector is C, the implant is C++, and the hooker is
LSPlant + Dobby. None of the frida build machinery applies. The spec must be
re-rooted on the new toolchain so the build is reproducible and the
machine-verified toolchain constraints are captured in one place.

This change owns the toolchain facts (NDK r29, c++_static, LOG_DISABLED,
lsplant.hpp from source, `-flto` removed) that `native-payload` references but
does not duplicate — the contract says *what* the payload is; this change says
*how it is built*.

## What Changes

- **REMOVED** (frida/meson/Vala-specific, no successor):
  - "Release-only meson build" — meson/Vala/frida-core are gone; replaced by a
    Cargo + ndk-build/CMake build.
  - "frida-core QuickJS subproject from the provisioned wrap" — frida-core is
    removed; no subproject.
  - "Android frida-agent .so keeps a Bionic-loadable hash table" — there is no
    frida-agent; the payload `.so` files are built directly and retain their
    hash tables by default.
  - "Android cross-build uses frida's meson and a complete cross-file" —
    frida's meson fork is gone; the cross-build is cargo-ndk + NDK.
  - "All meson build-dir commands in the Makefile use frida's meson" — no
    meson, no frida-meson.
- **MODIFIED**:
  - "Public key embedded via build-time generation" — the key is now embedded
    via a Rust `build.rs` (not a meson `custom_target`); the principle
    (compiled-in, never read at runtime) is unchanged.
  - "Project version baseline in meson.build" — the version moves from
    `meson.build` `project()` to `Cargo.toml` `[package].version` as the single
    source of truth.
- **ADDED**:
  - "Cargo + ndk-build/CMake mixed build" — the daemon is built with
    `cargo-ndk` (aarch64); the native artifacts (injector, implant, Dobby)
    with NDK r29 `ndk-build`/CMake; a `Makefile` orchestrates both.
  - "Native payload toolchain constraints" — NDK r29 (not r27), c++_static
    (not shared), `LOG_DISABLED`, `lsplant.hpp` from source, `-flto` removed.
  - "Rust and C/C++ lint" — `cargo clippy` (deny warnings) for Rust;
    uncrustify for C/C++.
- **Unchanged**: "Private signing key never in the repository", "Local
  developer dev keypair" (key hygiene and always-on verification are
  toolchain-agnostic).

## Capabilities

### Modified Capabilities

- `build-and-signing`: the build is re-rooted from meson/Vala/frida-core to
  Rust (`cargo-ndk`) + NDK r29 (`ndk-build`/CMake) for the native artifacts.
  The frida-core subproject, the frida-patched valac, frida's meson fork, the
  QuickJS/hash-style machinery, and all meson cross-file wiring are removed.
  The version source of truth moves to `Cargo.toml`; the embedded key is
  generated via `build.rs`. The native-payload toolchain constraints (NDK r29,
  c++_static, LOG_DISABLED, lsplant.hpp from source, no LTO) are owned here.
