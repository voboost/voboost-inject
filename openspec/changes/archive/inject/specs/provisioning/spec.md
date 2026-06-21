## MODIFIED Requirements

### Requirement: Deterministic tool installation via make init
`make init` SHALL provision the environment deterministically: install the OS-package tools
(including `uncrustify` and the libraries `vala-lint` needs), build `io.elementary.vala-lint` from a
pinned git revision into the install prefix, fetch the pinned wraps up front
(`meson subprojects download`), build the frida-patched Vala compiler
(`valac` version suffix `-frida`) into the same install prefix from its
transitively-pinned revision — the `[vala]` entry of
frida's `releng` `deps.toml` at the releng commit recorded by the pinned frida-core checkout
(`git ls-tree HEAD releng`), so bumping the frida pin updates the valac pin with no second
hand-maintained number — then run `meson setup`, and generate the local dev keypair. The Makefile
SHALL prepend the install prefix's `bin` to `PATH` so the provisioned tools (vala-lint, forked
valac) are found by every `make` target without shell-profile edits. It SHALL work identically on a
developer machine and in CI.

#### Scenario: Fresh clone is provisioned
- **WHEN** a developer runs `make init` on a clean clone
- **THEN** the OS-package tools and `uncrustify` are installed, `io.elementary.vala-lint` and the
  frida-patched `valac` are built from their pinned revisions into the prefix, the pinned wraps are
  fetched, and a dev keypair exists

#### Scenario: vala-lint has no OS package
- **WHEN** provisioning runs on a system where `io.elementary.vala-lint` is not available via
  Homebrew or apt
- **THEN** `make init` builds it from the pinned git revision rather than assuming a package exists

#### Scenario: Provisioned tools resolve without profile edits
- **WHEN** any `make` target that needs a provisioned tool runs after `make init`
- **THEN** the tool resolves via the Makefile-prepended prefix `bin` on `PATH`, with no manual
  shell-profile setup
