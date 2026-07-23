# Design — ci-versioning (Cargo.toml as version source)

<!-- Date: 2026-07-23. The version source follows the build system. -->

## D1 — Why the version source moves to Cargo.toml

**Choice:** `Cargo.toml` `[package].version` is the single source of truth;
the CI gate reads it.

**Reasoning:** `meson.build` is removed (the daemon is a Cargo crate — see
`build-and-signing`). A Rust project's canonical version lives in
`Cargo.toml`; `cargo` itself reads it for builds, and `cargo metadata` exposes
it for tooling. The CI gate previously read `meson.build`'s `project().version`;
it now reads `Cargo.toml`'s `[package].version`. The baseline `1.0.0-beta1`
and the manual pre-release bump workflow are unchanged — only the file holding
the value changes. Keeping one source of truth (now `Cargo.toml`, was
`meson.build`) preserves the invariant that the tag must match exactly one
defined version.
