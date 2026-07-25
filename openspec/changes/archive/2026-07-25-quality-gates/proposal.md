## Why

The `quality-gates` spec is built around the Vala/meson toolchain: `make lint`
runs `io.elementary.vala-lint` + `uncrustify` over Vala sources, `make test`
runs `meson test`, and the linter config references Vala-specific files. The
project moved to Rust (`cargo`) + C/C++ (NDK) — see `build-and-signing`. There
is no Vala source and no meson. The quality gates must run over the new
languages or they lint/test nothing.

## What Changes

- **MODIFIED**:
  - "Hard line-length cap of 100 characters" — the cap still applies, but the
    Vala-lint config reference is removed; it is enforced via
    `.editorconfig` + `cargo clippy`/`rustfmt` (Rust) and `uncrustify` (C/C++).
  - "make lint guards linter presence" — `make lint` checks for `cargo` (with
    `clippy`) and `uncrustify` (not `io.elementary.vala-lint`).
  - "Uncrustify enforces formatting in make lint and make lint-fix" —
    `uncrustify` runs over C/C++ sources (not Vala); Rust formatting is
    enforced by `rustfmt` / `cargo fmt`.
  - "Host-side test harness, silent on success" — `make test` runs `cargo test`
    (not `meson test`); the "frida-free" qualifier is dropped (there is no
    frida).
- **Unchanged**: "Makefile is the only developer entrypoint" (the target set
  is stable), "Inherited style rules enforced" (English, trailing newline, no
  commented-out code), "Fixture manifest covers integration-scenario target
  processes" (the fixture mechanism is language-agnostic).

## Capabilities

### Modified Capabilities

- `quality-gates`: lint and test are re-rooted from Vala/meson to Rust
  (`cargo clippy`/`rustfmt`/`cargo test`) + C/C++ (`uncrustify`). The
  Makefile entry points, the line-length cap, and the inherited style rules
  are unchanged.
