## Why

The `developer-docs` spec tells developers to provision via `make init` (which
fetched frida sources and built `io.elementary.vala-lint` from source) and to
build a Vala/meson binary. The toolchain moved to Rust (`cargo-ndk`) + NDK r29
(see `build-and-signing`, `provisioning`): there is no frida wrap, no Vala, no
vala-lint. The README and AGENTS.md must describe the new toolchain or a new
developer follows stale instructions.

## What Changes

- **MODIFIED**:
  - "Developer README from clone to built binary" — the README describes the
    Rust + NDK r29 toolchain; the vala-lint gap is replaced by the
    `rustup`/`cargo-ndk`/NDK setup; per-OS notes updated.
  - "Token-economical AGENTS.md" — AGENTS.md references the Rust + NDK
    toolchain and the ptrace/LSPlant architecture (not frida via the pinned
    wrap).
- **Unchanged**: the principle of a concise AGENTS.md and a from-clone-to-binary
  README.

## Capabilities

### Modified Capabilities

- `developer-docs`: the README and AGENTS.md are re-rooted from
  frida/Vala/meson to Rust (`cargo-ndk`) + NDK r29 + ptrace/LSPlant. The
  conciseness and from-clone-to-binary principles are unchanged.
