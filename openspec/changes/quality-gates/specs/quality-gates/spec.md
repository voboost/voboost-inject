## MODIFIED Requirements

### Requirement: Hard line-length cap of 100 characters

The linter SHALL enforce a maximum line length of 100 characters across source and project files,
encoded in `.editorconfig` (`max_line_length = 100`, space indent, size 4, LF) consistently with
`../voboost-codestyle/.editorconfig`. For Rust sources the cap SHALL be enforced via `rustfmt`/
`cargo clippy`; for C/C++ sources via `uncrustify` (using `config/config-uncrustify.cfg`). There is
no Vala-lint config (no Vala source).

#### Scenario: A line exceeds the cap

- **WHEN** a file contains a line longer than 100 characters
- **THEN** `make lint` reports it and exits non-zero

#### Scenario: All lines within the cap

- **WHEN** every line is at most 100 characters
- **THEN** the linter raises no line-length violation

### Requirement: make lint guards linter presence

`make lint` SHALL first verify that `cargo` (with `clippy`) and `uncrustify` are
on PATH; if either is missing it SHALL print a message pointing the developer
to `make init` and exit non-zero, rather than failing with a bare
`command not found`. When both are present it SHALL run `cargo clippy` (deny
warnings) over the Rust sources and `uncrustify --check` (using
`config/config-uncrustify.cfg`) over the C/C++ sources, and exit non-zero on
any violation.

#### Scenario: A linter is not installed

- **WHEN** `make lint` runs and `cargo`/`clippy` (or `uncrustify`) is not on PATH
- **THEN** it prints guidance to run `make init` and exits non-zero, with no raw
  `command not found`

#### Scenario: Lint runs with violations

- **WHEN** `make lint` runs with both linters present and finds any violation
- **THEN** it exits non-zero so the build/CI fails

#### Scenario: Lint runs clean

- **WHEN** `make lint` runs with both linters present and finds no violations
- **THEN** it exits zero

### Requirement: Uncrustify enforces formatting in make lint and make lint-fix

`make lint` SHALL run `uncrustify --check` against all C/C++ sources (injector,
implant, hooker) using `config/config-uncrustify.cfg`, which SHALL enforce `{}`
around all control-flow bodies even when single-line, 4-space indent, and spaces
not tabs. `make lint-fix` SHALL run `uncrustify --replace` on all C/C++
sources, rewriting them to canonical style. Rust source formatting SHALL be
enforced by `cargo fmt` (run by `make lint-fix`); a formatting drift SHALL fail
`make lint`.

#### Scenario: A C/C++ file has a bare if without braces

- **WHEN** a C/C++ source contains `if (cond) statement;` without `{}`
- **THEN** `uncrustify --check` exits non-zero and `make lint` fails

#### Scenario: make lint-fix rewrites sources

- **WHEN** `make lint-fix` runs
- **THEN** C/C++ sources are rewritten by `uncrustify --replace` and Rust
  sources by `cargo fmt`, and a subsequent `make lint` exits zero

### Requirement: Host-side test harness, silent on success

A host-side `cargo test` target SHALL run device-free logic tests. It SHALL be
silent on success and fail loudly.

#### Scenario: Tests pass

- **WHEN** `make test` runs after `make init` on a fresh clone and all tests
  pass
- **THEN** it produces no output on success and exits zero

#### Scenario: A test fails

- **WHEN** any host-side test fails
- **THEN** `make test` reports the failure and exits non-zero
