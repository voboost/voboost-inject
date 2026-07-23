# Design — developer-docs (Rust + NDK toolchain docs)

<!-- Date: 2026-07-23. The docs follow the toolchain. -->

## D1 — Why the docs follow the toolchain

**Choice:** the README and AGENTS.md describe the Rust + NDK r29 toolchain and
the ptrace/LSPlant architecture.

**Reasoning:** developer docs exist to onboard a new contributor from clone to
built binary. When the toolchain changes (frida/Vala/meson → Rust/cargo-ndk +
NDK r29 — see `build-and-signing`, `provisioning`), the docs must describe the
new path or they actively mislead. The vala-lint gap (no Homebrew/apt package,
built from source) is replaced by the Rust toolchain setup (`rustup`,
`rust-toolchain.toml`) and the NDK r29 prerequisite — each with its own
onboarding note. AGENTS.md, which captures durable rules for AI agents, must
reference the current architecture (ptrace injection, LSPlant/Dobby, Cargo
build) not the removed one (frida via pinned wrap). The conciseness invariant
is preserved: the docs point to specs for depth, as before.
