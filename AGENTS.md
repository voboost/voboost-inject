# Voboost Inject Code Style

## Global
- Follows ALL common rules from ../voboost-codestyle/AGENTS.md
- Root Vala binary embedding frida-core, runs as root, injects signed agents

## Language
- Chat in Russian; source, comments, and docs in English (ASCII)

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
  (frida-core 17.11.0 releng requires NDK major 29). Set both for Android builds:
  `ANDROID_NDK_HOME=$HOME/Library/Android/sdk/ndk/29.0.14206865 ANDROID_HOME=$HOME/Library/Android/sdk`
- `make build-android` cross-compiles to `build-android/src/voboost-inject` (arm64-v8a,
  bionic-linked, 15M). Cross-file: `config/android-cross.ini`.
- Emulator: `emulator-5554`, AVD `free` (also `free-old`), API 28, `arm64-v8a`,
  `ro.kernel.qemu=1`, `sys.boot_completed=1`. Apple Silicon host.
  `strace` and `timeout` are present at `/system/bin/`.
- **Emulator launch command** (headless, WITHOUT `-writable-system`):
  ```
  nohup $HOME/Library/Android/sdk/emulator/emulator \
    -avd free -no-snapshot-save \
    -no-window -no-audio -no-boot-anim \
    >/tmp/emulator-free.log 2>&1 &
  ```
  Do NOT pass `-writable-system`: on this host (Apple Silicon, API 28 arm64) it
  forces a cold boot that never completes, and `adb remount` cannot make
  `/system` writable either (`remount of the / superblock failed: Permission
  denied`; `/system/etc/init/` stays read-only). A plain boot completes in ~16s.
  So the `/system` init hook is NOT used on the emulator. `-no-snapshot-save`
  prevents corrupting the snapshot with test artifacts; `-no-window -no-audio
  -no-boot-anim` run headless for CI/automation.
- **Run the daemon on the emulator**: `make emulator-run` provisions
  `/data/voboost` from `test/fixtures` (root:root 700, no init hook) and starts
  the daemon under `su 0` after `sys.boot_completed=1`. This matches the
  production start timing exactly: the production init hook (voboost-install
  `INIT_HOOK_BODY`) starts the service `on property:sys.boot_completed=1`
  (service `disabled`+`oneshot`), so a host-driven start is not later than
  production. Auto-start-at-init and reboot-survival are production-only (they
  require a writable `/system`) and are out of scope on the emulator.
- SELinux is `Enforcing` by default (NOT Permissive as previously documented).
  The installer runs `setenforce 0` during provision, but this does NOT persist
  across reboots. The init hook uses `seclabel u:r:shell:s0` with a shell-wrapper
  service (`/system/bin/sh /data/voboost/start.sh`) so init can transition to the
  `shell` domain (which exists in the compiled SELinux policy) and execute the
  daemon. The `u:r:su:s0` domain does NOT exist in the policy on this emulator.
- Provisioned root zone on the emulator: `/data/voboost` (root:root, 0700) with
  `manifest.json`/`manifest.sig`, `agents/`, `logs/`, `run/`. Status written to
  `/data/user/0/ru.voboost/inject-status.json`.
- Daemon logs: `/data/voboost/logs/inject-YYYY-MM-DD.log` (Log.err output) and
  `/data/voboost/logs/manual-start.log` (stderr, incl. `libbpf: -EINVAL` on API 28,
  which is non-fatal). Status: `/data/user/0/ru.voboost/inject-status.json`.
