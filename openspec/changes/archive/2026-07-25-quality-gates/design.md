# Design — quality-gates (Rust + C/C++ lint/test)

<!-- Date: 2026-07-23. Lint and test follow the language stack. -->

## D1 — Why lint/test follow the language stack

**Choice:** `make lint` runs `cargo clippy` (Rust) + `uncrustify` (C/C++);
`make test` runs `cargo test`.

**Reasoning:** quality gates exist to enforce style and catch regressions in the
project's source. When the source language changes (Vala → Rust + C/C++ — see
`build-and-signing`), the gates must lint and test the new languages or they
are no-ops. `io.elementary.vala-lint` lints Vala, of which there is now none;
`cargo clippy` is the idiomatic Rust linter. `uncrustify` is retained for the
C/C++ sources (injector, implant) — it was already a project tool, just
redirected from Vala to C/C++. `meson test` is gone with meson; `cargo test`
is the Rust-native test runner. The line-length cap (100), the inherited style
rules (English, trailing newline, no commented-out code), and the
Makefile-as-entrypoint invariant are language-agnostic and unchanged. The
fixture-manifest requirement is also unchanged — it generates test fixtures for
the agent manifest, which is language-agnostic.
