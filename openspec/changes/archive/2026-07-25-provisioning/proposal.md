## Why

The `provisioning` spec is built around the frida/meson/Vala toolchain: pinned
frida git wraps, the frida-patched `valac` built from source, frida's own meson
fork provisioned for cross-builds, meson subproject bootstrap rules, and a
meson cross-file. The build moved to Rust (`cargo-ndk`) + NDK r29
`ndk-build`/CMake (see `build-and-signing`); all the frida/meson provisioning
is obsolete. At the same time, the ptrace migration introduces a new zone path
(`/data/voboost` → `/data/voboost-inject` — see `daemon-lifecycle`,
`update-planes`), a shared directory for channel B (see `selinux-domain`,
`update-planes`), and a boot trigger `on nonencrypted` (see `daemon-lifecycle`)
that must be provisioned on the device.

This change re-roots provisioning on the new toolchain and adds the device-side
provisioning the new architecture requires.

## What Changes

- **REMOVED** (frida/meson-specific):
  - "Pinned frida git wrap" — no frida; no wraps.
  - "Subproject wraps are clean-clone bootstrappable" — no meson, no wraps, no
    `meson subprojects download`.
  - "make init provisions frida's meson for cross-builds" — no frida-meson.
- **MODIFIED**:
  - "Documented build toolchain including both linters" — the tool list is
    Rust (`cargo`, `rustup`), NDK r29, `uncrustify` (C/C++ lint), and the OS
    packages; `io.elementary.vala-lint` is removed (no Vala).
  - "Deterministic tool installation via make init" — `make init` provisions
    the Rust toolchain (`rust-toolchain.toml`), verifies NDK r29, and generates
    the dev keypair (no frida wrap, no patched valac, no meson setup).
  - "Per-OS installation instructions" — updated for the Rust + NDK toolchain.
  - "Toolchain check reports any missing tool" — checks for `cargo`,
    `uncrustify`, and NDK r29 (not vala-lint/meson).
  - "Local dev keypair with verification always on" — unchanged mechanism,
    restated under the new zone path.
  - "Android cross-compilation via meson cross-file" — replaced by
    `cargo-ndk` + NDK r29 (the cross-file is gone; `ANDROID_NDK_HOME` is the
    prerequisite).
- **ADDED**:
  - "Device zone provisioning" — the root zone `/data/voboost-inject/` with
    `logs/`, `run/`, `shared/` (channel-B shared dir, `media_rw_data_file`),
    and `payload/` (native payload files) is provisioned on the device.
  - "Init hook for boot trigger" — the daemon service is installed as an init
    hook triggered `on nonencrypted` (before `system_server`), `oneshot` +
    `disabled` as a reboot-loop guard (the self-update restart behavior is
    owned by `ota`).
- **Unchanged**: the dev-keypair principle and always-on verification.

## Capabilities

### Modified Capabilities

- `provisioning`: provisioning is re-rooted from frida/meson/Vala to Rust
  (`cargo-ndk`) + NDK r29. The frida wraps, patched valac, frida-meson, and
  meson cross-file are removed. The device zone (`/data/voboost-inject/` with
  `shared/` for channel B) and the init hook (`on nonencrypted`) are provisioned.
