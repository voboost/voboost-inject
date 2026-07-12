# Voboost Inject Code Style

## Global
- Follows ALL common rules from ../voboost-codestyle/AGENTS.md
- Root Vala binary embedding frida-core, runs as root, injects signed agents

## OpenSpec
- Spec-driven; truth is openspec, no code without an applied change, invariants live in specs
- propose -> apply -> archive
- npx @fission-ai/openspec validate <change> --strict

## Development
- Lines <= 100 chars
- Vala: idiomatic GObject + async/yield on a GMainLoop
- `make init`
- `make lint-fix`

## Emulator & build env (verified — no need to re-check each session)
- SDK: `$HOME/Library/Android/sdk`; NDK r29: `$HOME/Library/Android/sdk/ndk/29.0.14206865`
  (frida-core 17.11.0 releng requires NDK major 29)
- `make build-android` cross-compiles to `build-android/src/voboost-inject` (arm64-v8a,
  bionic-linked, 15M). Cross-file: `config/android-cross.ini`.
- Emulator: `emulator-5554`, AVD `free` (also `free-old`), API 28, `arm64-v8a`,
  `ro.kernel.qemu=1`, `sys.boot_completed=1`. Apple Silicon host.
- **Emulator launch command** (headless, WITHOUT `-writable-system`):
  ```
  nohup $HOME/Library/Android/sdk/emulator/emulator \
    -avd free -no-snapshot-save \
    -no-window -no-audio -no-boot-anim \
    >/tmp/emulator-free.log 2>&1 &
  ```
  NEVER pass `-writable-system`: on this host (Apple Silicon, API 28 arm64) it forces a
  cold boot that never completes, and `adb remount` cannot make `/system` writable either
  (`remount of the / superblock failed: Permission denied`; `/system/etc/init/` stays
  read-only). `/system` init hook is NOT used on the emulator.
- `make emulator-run` provisions `/data/voboost` from `test/fixtures` (root:root 700, no
  init hook) and starts the daemon under `su 0` after `sys.boot_completed=1`.
- SELinux is `Enforcing` by default (NOT Permissive). `setenforce 0` during provision does
  NOT persist across reboots. Init hook uses `seclabel u:r:shell:s0` with a shell-wrapper
  service (`/system/bin/sh /data/voboost/start.sh`) so init can transition to the `shell`
  domain. The `u:r:su:s0` domain does NOT exist in the policy on this emulator.
- Provisioned root zone: `/data/voboost` (root:root, 0700) with `manifest.json`/`manifest.sig`,
  `agents/`, `logs/`, `run/`. Status: `/data/user/0/ru.voboost/inject-status.json`.
- Daemon logs: `/data/voboost/logs/inject-YYYY-MM-DD.log` (Log.err) and
  `/data/voboost/logs/manual-start.log` (stderr, incl. `libbpf: -EINVAL` on API 28, non-fatal).
