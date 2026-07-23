## MODIFIED Requirements

### Requirement: Developer README from clone to built binary

The project SHALL provide a `README.md` covering what to install, how to provision via `make init`,
and how to build, sufficient for a new developer to go from a fresh clone to a built binary. It
SHALL state explicitly that the Rust toolchain is installed via `rustup` (pinned by
`rust-toolchain.toml`) and that Android NDK r29 is an external prerequisite, and SHALL include
per-OS notes (macOS, Linux, Windows/WSL2).

#### Scenario: New developer follows the README

- **WHEN** a new developer follows the README on a fresh clone
- **THEN** they run `make init` to provision the Rust toolchain and verify NDK
  r29, and can then run `make build` to produce a binary

#### Scenario: README addresses the NDK prerequisite

- **WHEN** a developer reaches the build prerequisites in the README
- **THEN** it states that NDK r29 must be installed and `ANDROID_NDK_HOME` set,
  and that `make init` verifies it

### Requirement: Token-economical AGENTS.md

The project SHALL provide a concise root `AGENTS.md` capturing durable repo rules for AI agents:
language policy (chat in Russian, source/docs in English), release-only builds, verification always
on, no private key in the repo, the OpenSpec propose→apply→archive flow, the Rust + NDK r29
toolchain and the ptrace/LSPlant injection architecture, and that `make init` provisions the
environment. It SHALL be kept terse, deferring deep detail to the specs.

#### Scenario: Agent reads AGENTS.md

- **WHEN** an AI agent starts work in the repo
- **THEN** AGENTS.md states the language policy, build/verification/signing rules, the OpenSpec flow,
  the Rust + NDK r29 toolchain and ptrace/LSPlant architecture, and that `make init` provisions the
  environment, concisely without duplicating spec detail
