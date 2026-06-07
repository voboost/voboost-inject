## Purpose
Specify requirements for developer documentation including README and AGENTS.md.

## Requirements

### Requirement: Developer README from clone to built binary
The project SHALL provide a `README.md` covering what to install, how to provision via `make init`,
and how to build, sufficient for a new developer to go from a fresh clone to a built binary. It
SHALL state explicitly that `io.elementary.vala-lint` is built from source by `make init` (no
Homebrew/apt package) and SHALL include per-OS notes (macOS, Linux, Windows/WSL2).

#### Scenario: New developer follows the README
- **WHEN** a new developer follows the README on a fresh clone
- **THEN** they run `make init` to provision the toolchain (including the source-built vala-lint),
  frida sources, and a dev keypair, and can then run `make build` to produce a binary

#### Scenario: README addresses the vala-lint gap
- **WHEN** a developer reaches the linting prerequisites in the README
- **THEN** it states that `io.elementary.vala-lint` has no Homebrew/apt package and is built from a
  pinned source revision by `make init`

### Requirement: Token-economical AGENTS.md
The project SHALL provide a concise root `AGENTS.md` capturing durable repo rules for AI agents:
language policy (chat in Russian, source/docs in English), release-only builds, verification always
on, no private key in the repo, the OpenSpec propose→apply→archive flow, frida via the pinned wrap,
and that `make init` provisions the environment. It SHALL be kept terse, deferring deep detail to
the specs.

#### Scenario: Agent reads AGENTS.md
- **WHEN** an AI agent starts work in the repo
- **THEN** AGENTS.md states the language policy, build/verification/signing rules, the OpenSpec flow,
  and that `make init` provisions the environment, concisely without duplicating spec detail
