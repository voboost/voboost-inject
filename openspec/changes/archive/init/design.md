## Context

`voboost-inject` is open source; a fresh clone must become buildable, lintable, and testable on any
developer machine and in CI, without the original author's environment. This is the first stage in
the sequence `init → inject → ci → ota`. It merges the previously separate `setup` (provisioning)
and `quality` (gates) stages into one, because they share a single entrypoint (`make init`) and
because a half-provisioned environment (tools present but linters missing) is exactly the failure
mode this project must eliminate.

frida-core is built from source (QuickJS-only, no V8) and is itself Vala + C/GLib, so the toolchain
must compile Vala and cross-compile for the Android target. The Vala linter `vala-lint`
(`io.elementary.vala-lint`) is not packaged for Homebrew or apt and must be built from source.

## Goals / Non-Goals

**Goals:**
- One command (`make init`) takes a clean clone to a ready environment — tools, linters, frida
  wraps, dev keypair — identically locally and in CI.
- Provisioning is deterministic: pinned frida revision, pinned vala-lint revision; nothing relies on
  a tool "happening to be installed".
- `make lint` and `make test` work after `make init`, and fail with actionable guidance (not
  `command not found`) if the environment is incomplete.
- A meson cross-file for Android NDK (arm64-v8a) is provided so the daemon can be cross-compiled.
- Onboarding captured in README (fresh clone → built binary) and a concise AGENTS.md.

**Non-Goals:**
- The daemon build flags (QuickJS-only/static/LTO/strip) and the project version — owned by
  `inject/build-and-signing`; `init` provisions the wrap and toolchain the build consumes.
- The CI pipeline and caching of `make init` — owned by `ci`.
- Production signing — owned by `ci` (private key in CI secrets); `init` covers only the local dev
  keypair.
- The real test cases for daemon logic — authored with `inject`/`ota`; `init` defines the harness.

## Decisions

### D1. `make init` is the single provisioning orchestrator
`make init` runs, in order: toolchain install (OS-package tools + build vala-lint from the pinned
revision) → `setup` (`meson setup`, fetching frida wraps) → `key-dev` (generate the local ed25519
keypair if absent). `make init` is the only documented "from nothing to ready" command; the install
step is inlined into its recipe and is not a separately invokable target. A single entrypoint
removes the "I forgot to install the linter" failure this stage exists to eliminate.
*Alternative rejected:* a separate public `install-tools` target the developer must remember to run
before `setup`.

### D2. vala-lint built from a pinned git revision, not a meson subproject
`io.elementary.vala-lint` has no Homebrew/apt package. `make init` clones it at a **pinned
revision** and `meson build && ninja install`s it into the prefix. It is deliberately **not** a
meson subproject of this project: vala-lint is a developer *tool*, not a product dependency it links
against (unlike frida-core, which must be a subproject). Making it a subproject would couple
`make lint` to configuring/compiling the whole meson tree (including frida) and mix tool install
targets with product build targets. A pinned clone gives the same reproducibility without those
costs. The matching `libvala` for the host `valac` is installed via the OS package (`brew`/`apt`),
which `vala-lint`'s own meson build requires regardless of how it is fetched.

### D3. Pinned frida git wrap, no offline override
`subprojects/{frida,frida-core,frida-gum}.wrap` use `wrap-git` pinned to a fixed tag. Meson fetches
and caches them into `subprojects/` on `meson setup`. *Alternatives rejected:* wrap-file
tarball+sha256 (needs a stable release URL; git pin is simpler to bump/audit); prebuilt
frida-core-devkit (ships V8, conflicts with QuickJS-only).

### D4. Toolchain documented and fully checkable — including both linters
`make check` verifies every required tool by name and reports missing ones with a
non-zero exit. The list explicitly includes **both** `uncrustify` and `io.elementary.vala-lint`, so
a developer never discovers a missing linter only when `make lint` crashes. README documents per-OS
install (macOS Homebrew, Linux apt, Windows WSL2), and `make init` automates it.

### D5. `make lint` guards linter presence before running
`make lint` first checks that `uncrustify` and `io.elementary.vala-lint` are on PATH; if either is
missing it prints "run `make init`" and exits non-zero — never a raw `command not found`. Then it
runs `io.elementary.vala-lint` (100-char cap, English source, single trailing newline, no
commented-out code) and `uncrustify --check`. Linting is a gate, not advisory.

### D6. Formatter target is `lint-fix` (uncrustify), single canonical name
`uncrustify` is the Vala equivalent of prettier: `{}` around all control-flow bodies, 4-space
indent, spaces-not-tabs, trailing newline, mirroring `config-prettier.mjs`. The in-place target is
named **`lint-fix`** (one canonical name; hyphen because `:` is undesirable in a Make target) to
match the Makefile and avoid proposal/implementation drift. `make lint` includes
`uncrustify --check`.

### D7. Tests in test/, via meson test, silent on success
Pure logic tests run via `meson test` (wrapped by `make test`), in `test/` (consistent with other
voboost projects). Silent on success, loud on failure. Device/frida integration tests are
documented but run on a device, not in this harness.

### D8. Local dev keypair, private key out of git, verify always on
`make key-dev` generates an ed25519 dev keypair; the public half is baked into a local build by
`inject`. Private keys are gitignored. No skip-verify mode — dev builds verify too.

### D9. Concise, token-economical AGENTS.md
A short root `AGENTS.md` carries durable repo rules (language policy: chat in Russian, source/docs
in English; release-only; verify always on; no private key in repo; OpenSpec
propose→apply→archive; frida via the pinned wrap; `make init` provisions the env). Deep detail
lives in the specs, not AGENTS.md.

### D10. Android NDK cross-file (arm64-v8a)
The daemon runs on an Android device (arm64-v8a). `config/android-cross.ini` is a meson cross-file
targeting `aarch64-linux-android` via the Android NDK. `make build` performs a host build (for
tests); `make build-android` invokes meson with the cross-file to produce the device binary.
The cross-file is committed; the NDK itself is an external prerequisite documented in the README.

## Risks / Trade-offs

- [Pinned frida/vala-lint revisions drift from upstream] → bumping is a one-line edit + re-fetch;
  the pin is intentional for reproducibility.
- [Building vala-lint from source adds setup time] → accepted; `make init` automates it once and
  `ci` caches the result so it is not rebuilt every run.
- [First fetch needs network] → accepted; frida sources and the vala-lint clone are cached after
  the first `make init`; `ci` restores them from cache.
- [vala-lint's libvala must match the host valac] → its meson build resolves `libvala-<api>` from
  `valac --api-version`; the OS-package `vala` provides the matching dev files.
- [A 100-char cap can fight long frida-core type names] → accepted; wrap or alias; the cap is a hard
  project rule.

## Migration Plan

Design + provisioning + gates land in this change's `tasks.md`. Implementation order: wrap files +
`.gitignore` → toolchain install step inside `make init` (OS tools + build vala-lint) + `make check`
(both linters) + `make key-dev` + `make init` orchestrator → `.editorconfig` + lint/uncrustify
configs + `make lint` (with guard) + `make lint-fix` → `test/` + `meson test` harness + `make test`
→ README + AGENTS.md. Once done, `inject` consumes `subprojects/` and the dev public key with no
local-path assumption, and writes code that passes the gates from the first commit.

## Open Questions

- Exact frida tag/commit and vala-lint revision to pin (and the cadence for bumping them).
- Whether to also provide a containerized `make init` for Windows users who cannot use WSL2.
