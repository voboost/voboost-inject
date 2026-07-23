## 1. Remove frida/meson provisioning

- [ ] 1.1 Remove frida wraps (`subprojects/{frida,frida-core,frida-gum}.wrap`)
- [ ] 1.2 Remove frida-patched `valac` build from `make init`
- [ ] 1.3 Remove frida-meson provisioning and the libc++ hardening patch
- [ ] 1.4 Remove `meson subprojects download` bootstrap and the meson cross-file

## 2. Rust + NDK toolchain provisioning

- [ ] 2.1 `make init` provisions the Rust toolchain from `rust-toolchain.toml`
- [ ] 2.2 `make init` verifies NDK r29 is present (`ANDROID_NDK_HOME`); clear
      error if missing/wrong version
- [ ] 2.3 `make init` generates the dev keypair (unchanged mechanism)
- [ ] 2.4 `make check` verifies `cargo`, `uncrustify`, NDK r29 present

## 3. Device zone provisioning

- [ ] 3.1 Create `/data/voboost-inject/` with `logs/`, `run/`, `shared/`,
      `payload/`
- [ ] 3.2 `shared/` labeled `media_rw_data_file` via `file_contexts`
      (channel B — see `selinux-domain`, `update-planes`)
- [ ] 3.3 Correct ownership (root) and permissions

## 4. Init hook

- [ ] 4.1 Install daemon service as init hook, trigger `on nonencrypted`
      (fallback `on boot`)
- [ ] 4.2 `oneshot` + `disabled` as reboot-loop guard (self-update restart
      semantics owned by `ota`)

## 5. Docs + cross-build

- [ ] 5.1 Per-OS docs updated for Rust + NDK r29 (no Vala, no meson)
- [ ] 5.2 Android cross-build via `cargo-ndk` + NDK r29 (no meson cross-file;
      `ANDROID_NDK_HOME` is the prerequisite)

## 6. Validate

- [ ] 6.1 `npx @fission-ai/openspec validate provisioning --strict`
- [ ] 6.2 Device test: `make init` provisions Rust + NDK; zone dirs created
      with correct labels; daemon starts `on nonencrypted`
