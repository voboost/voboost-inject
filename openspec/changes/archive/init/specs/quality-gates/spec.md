## ADDED Requirements

### Requirement: Makefile is the only developer entrypoint
All project commands SHALL be invoked via `make <target>`. The Makefile SHALL provide `init`,
`setup`, `build`, `lint`, `lint-fix`, `test`, `check`, and `key-dev`. There
SHALL be no `scripts/` directory.

#### Scenario: Developer lists available commands
- **WHEN** a developer inspects the Makefile
- **THEN** it exposes init, setup, build, lint, lint-fix, test, check, and
  key-dev, and no `scripts/` directory exists

### Requirement: Hard line-length cap of 100 characters
The linter SHALL enforce a maximum line length of 100 characters across source and project files,
encoded in `.editorconfig` (`max_line_length = 100`, space indent, size 4, LF) consistently with
`../voboost-codestyle/.editorconfig`. Vala-lint config in `config/config-vala-lint.conf`.

#### Scenario: A line exceeds the cap
- **WHEN** a file contains a line longer than 100 characters
- **THEN** `make lint` reports it and exits non-zero

#### Scenario: All lines within the cap
- **WHEN** every line is at most 100 characters
- **THEN** the linter raises no line-length violation

### Requirement: Inherited style rules enforced
The linter SHALL enforce the inherited repo conventions: source/comments/docs in English, each file
ends with a single empty line, and no commented-out code blocks.

#### Scenario: File missing a trailing newline
- **WHEN** a file does not end with exactly one empty line
- **THEN** `make lint` reports it and exits non-zero

#### Scenario: Commented-out code present
- **WHEN** a source file contains a commented-out code block
- **THEN** `make lint` reports it and exits non-zero

### Requirement: make lint guards linter presence
`make lint` SHALL first verify that both `uncrustify` and `io.elementary.vala-lint` are on PATH; if
either is missing it SHALL print a message pointing the developer to `make init` and exit non-zero,
rather than failing with a bare `command not found`. When both are present it SHALL run
`io.elementary.vala-lint` (using `config/config-vala-lint.conf`) and `uncrustify --check` (using
`config/config-uncrustify.cfg`) and exit non-zero on any violation.

#### Scenario: A linter is not installed
- **WHEN** `make lint` runs and `io.elementary.vala-lint` (or `uncrustify`) is not on PATH
- **THEN** it prints guidance to run `make init` and exits non-zero, with no raw `command not found`

#### Scenario: Lint runs with violations
- **WHEN** `make lint` runs with both linters present and finds any violation
- **THEN** it exits non-zero so the build/CI fails

#### Scenario: Lint runs clean
- **WHEN** `make lint` runs with both linters present and finds no violations
- **THEN** it exits zero

### Requirement: Uncrustify enforces formatting in make lint and make lint-fix
`make lint` SHALL run `uncrustify --check` against all Vala sources using
`config/config-uncrustify.cfg`, which SHALL enforce `{}` around all control-flow bodies even when
single-line, 4-space indent, and spaces not tabs (mirroring `config-prettier.mjs`). `make lint-fix`
SHALL run `uncrustify --replace` on all Vala sources, rewriting them to canonical style.

#### Scenario: File has a bare if without braces
- **WHEN** a Vala source contains `if (cond) statement;` without `{}`
- **THEN** `uncrustify --check` exits non-zero and `make lint` fails

#### Scenario: make lint-fix rewrites sources
- **WHEN** `make lint-fix` runs
- **THEN** sources are rewritten to canonical style and a subsequent `make lint` exits zero

### Requirement: Host-side test harness, silent on success
A host-side `meson test` target in `test/` SHALL run device-free, frida-free logic tests, wired via
`subdir('test')` in the root `meson.build`. It SHALL be silent on success and fail loudly.

#### Scenario: Tests pass
- **WHEN** `make test` runs after `make init` on a fresh clone and all tests pass
- **THEN** it produces no output on success and exits zero

#### Scenario: A test fails
- **WHEN** any host-side test fails
- **THEN** `make test` reports the failure and exits non-zero
