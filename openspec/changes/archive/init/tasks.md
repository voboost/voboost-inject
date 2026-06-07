## 1. Provisioning (provisioning)

- [ ] 1.1 Add `subprojects/{frida,frida-core,frida-gum}.wrap` (wrap-git) pinned to a fixed frida tag
- [ ] 1.2 Confirm `meson setup` fetches the pinned frida sources into `subprojects/` and caches them
- [ ] 1.3 Add `.gitignore` entries for private keys, `build/`, and fetched `subprojects/*/`
- [ ] 1.4 Document the required toolchain (Vala, meson, ninja, git, openssl, bsdiff, uncrustify,
      io.elementary.vala-lint, Android cross toolchain/NDK) with minimum versions, per-OS (macOS
      Homebrew, Linux apt, Windows WSL2)
- [ ] 1.5 Inside the `make init` recipe: install OS-package tools (incl. uncrustify and vala-lint's
      libs) and build `io.elementary.vala-lint` from a pinned git revision into the install prefix
- [ ] 1.6 Implement `make check`: verify every required tool by name — including both
      `uncrustify` and `io.elementary.vala-lint` — reporting any missing one with non-zero exit
- [ ] 1.7 Implement `make key-dev`: generate a personal ed25519 dev keypair (idempotent); private
      key gitignored, public key for `inject` to bake into a local build
- [ ] 1.8 Implement `make init`: toolchain install → `setup` (meson setup) → `key-dev`
- [ ] 1.9 Confirm there is no skip-verify path (verification always on)
- [ ] 1.10 Create `config/android-cross.ini` meson cross-file for Android NDK (arm64-v8a,
      `aarch64-linux-android`); commit the cross-file, document NDK as external prerequisite
- [ ] 1.11 Add `make build-android` target: `meson setup` with `--cross-file
      config/android-cross.ini` + `ninja -C` to produce the device binary

## 2. Quality gates (quality-gates)

- [ ] 2.1 Create `Makefile` as the sole entrypoint with targets: `init`, `setup`,
      `build`, `lint`, `lint-fix`, `test`, `check`, `key-dev`; no `scripts/` directory
- [ ] 2.2 Add `.editorconfig` consistent with `../voboost-codestyle/.editorconfig`
      (`max_line_length=100`, space indent 4, LF)
- [ ] 2.3 Add `config/config-vala-lint.conf` enforcing the 100-char cap and inherited style rules
- [ ] 2.4 Add `config/config-uncrustify.cfg`: `{}` around all control-flow bodies, 4-space indent,
      spaces-not-tabs, trailing newline (mirroring `config-prettier.mjs`)
- [ ] 2.5 Implement `make lint`: first guard that `uncrustify` and `io.elementary.vala-lint` are on
      PATH (else print "run `make init`" and exit non-zero), then run vala-lint + `uncrustify
      --check`; exit non-zero on any violation
- [ ] 2.6 Implement `make lint-fix`: `uncrustify --replace` on all Vala sources
- [ ] 2.7 Create `test/meson.build` with a meson test target and a `test/smoke.sh` silent on success
- [ ] 2.8 Connect `test/` in root `meson.build` via `subdir('test')`
- [ ] 2.9 Confirm `make test` runs the smoke test silently on a fresh clone after `make init`

## 3. Developer docs (developer-docs)

- [ ] 3.1 Write `README.md`: fresh clone → `make init` → `make build` (a built binary), with per-OS
      notes and the explicit vala-lint build-from-source step
- [ ] 3.2 Write a concise, token-economical `AGENTS.md` (language policy, release-only, verify
      always on, no private key, OpenSpec flow, frida via wrap, `make init` provisions the env)
