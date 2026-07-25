BUILD_DIR ?= build

# Local tools directory inside the project for project-specific build tools.
# This keeps all project dependencies self-contained and reproducible.
TOOLS_DIR ?= $(PWD)/.tools
export PATH := $(TOOLS_DIR)/bin:$(PATH)

# Android NDK. The native artifacts (injector, implant) and the cross-built
# daemon all require NDK r29 (Clang 21) — older NDKs fail LSPlant C++23
# modules. ANDROID_NDK_HOME is the single prerequisite (see rust-toolchain.toml
# for the Rust side). Override NDK_HOME only if your env uses a different var.
NDK_HOME ?= $(ANDROID_NDK_HOME)

.PHONY: init build lint lint-fix test check key-dev
.PHONY: build-native build-injector build-implant build-daemon build-new build-android

# From a clean clone to a ready environment, identically locally and in CI.
# The new stack is Rust (cargo + cargo-ndk) and NDK r29 (ndk-build) — no Vala,
# no meson, no frida. Steps: install OS-package tools, ensure the Rust toolchain
# (rust-toolchain.toml) and cargo-ndk, verify NDK r29, then key-dev.
init:
	@os=$$(uname -s); \
	if [ "$$os" = "Darwin" ]; then \
		echo "init: macOS (Homebrew)"; \
		brew install uncrustify openssl@3 curl git || true; \
	elif [ "$$os" = "Linux" ]; then \
		echo "init: Linux (apt)"; \
		sudo apt-get update; \
		sudo apt-get install -y build-essential uncrustify openssl curl git \
			pkg-config; \
	else \
		echo "init: unsupported OS '$$os'. Use WSL2 + Ubuntu." >&2; \
		exit 1; \
	fi
	@command -v cargo >/dev/null 2>&1 || { \
		echo "init: installing rustup (Rust toolchain)"; \
		curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable; \
		source "$$HOME/.cargo/env"; \
	}
	@echo "init: Rust toolchain (rust-toolchain.toml resolves on first cargo run)"
	@cd daemon && cargo --version
	@command -v cargo-ndk >/dev/null 2>&1 || { \
		echo "init: installing cargo-ndk"; \
		cargo install cargo-ndk; \
	}
	@$(MAKE) check-ndk
	@echo "init: done"
	$(MAKE) key-dev

# Verify NDK r29 is present at ANDROID_NDK_HOME (the single cross-build
# prerequisite). Older NDKs fail LSPlant C++23 modules (see build-and-signing).
check-ndk:
	@test -n "$(NDK_HOME)" || { echo "check-ndk: ANDROID_NDK_HOME not set" >&2; exit 1; }
	@test -d "$(NDK_HOME)/toolchains/llvm/prebuilt" || \
		{ echo "check-ndk: NDK toolchain not found at $(NDK_HOME)" >&2; exit 1; }
	@ndk_ver=$$(grep -oE 'Pkg\.Revision = [0-9]+\.[0-9]+' "$(NDK_HOME)/source.properties" 2>/dev/null | grep -oE '^[0-9]+' || echo "0"); \
	if [ "$$ndk_ver" != "29" ]; then \
		echo "check-ndk: NDK r$$ndk_ver found, require r29 (LSPlant C++23 modules)" >&2; \
		exit 1; \
	fi
	@echo "check-ndk: NDK r29 OK ($(NDK_HOME))"

# Host build of the daemon (for host-run tests and check). The cross-build
# (aarch64-linux-android) is `make build-daemon` / `make build-android`.
build:
	cd daemon && cargo build

# Lint: Rust (cargo fmt + clippy) and C/C++ (uncrustify). No Vala linter — the
# Vala stack is gone. quality-gates owns the full gate contract.
lint:
	cd daemon && cargo fmt --check
	cd daemon && cargo clippy --all-targets -- -D warnings
	@if command -v uncrustify >/dev/null 2>&1; then \
		uncrustify --check -c config/config-uncrustify.cfg \
			$$(find injector implant -name '*.c' -o -name '*.cpp' -o -name '*.h' -o -name '*.hpp' 2>/dev/null) \
			|| exit 1; \
	else \
		echo "lint: uncrustify not found; skipping C/C++ check (run \`make init\`)"; \
	fi

lint-fix:
	cd daemon && cargo fmt
	@command -v uncrustify >/dev/null 2>&1 && \
		uncrustify --replace --no-backup -c config/config-uncrustify.cfg \
			$$(find injector implant -name '*.c' -o -name '*.cpp' -o -name '*.h' -o -name '*.hpp' 2>/dev/null) \
		|| echo "lint-fix: uncrustify not found; C/C++ not reformatted"

# Run the Rust test suite (host, pure-Rust; FFI extern blocks are not linked
# under check/test). quality-gates owns the full test contract.
test:
	cd daemon && cargo test

# Verify the toolchain is present (Rust + cargo-ndk + NDK r29 + uncrustify).
check:
	@missing=0; \
	for tool in cargo cargo-ndk git openssl uncrustify; do \
		if command -v "$$tool" >/dev/null 2>&1; then \
			echo "  ok      $$tool"; \
		else \
			echo "  MISSING $$tool" >&2; \
			missing=$$((missing + 1)); \
		fi; \
	done; \
	if [ -n "$(NDK_HOME)" ] && [ -d "$(NDK_HOME)/toolchains/llvm/prebuilt" ]; then \
		echo "  ok      ndk ($(NDK_HOME))"; \
	else \
		echo "  MISSING ndk (ANDROID_NDK_HOME unset or invalid)" >&2; \
		missing=$$((missing + 1)); \
	fi; \
	done; \
	if [ "$$missing" -ne 0 ]; then \
		echo "Missing $$missing tool(s). Run \`make init\` and re-run." >&2; \
		exit 1; \
	fi; \
	echo "All required tools present."

key-dev:
	@keydir=config; priv=$$keydir/key-dev-private.pem; pub=$$keydir/key-dev-public.pem; \
	mkdir -p "$$keydir"; \
	if [ -f "$$priv" ]; then \
		echo "Dev private key already exists at $$priv; leaving it untouched." >&2; \
		exit 0; \
	fi; \
	openssl genpkey -algorithm ed25519 -out "$$priv"; \
	openssl pkey -in "$$priv" -pubout -out "$$pub"; \
	echo "Generated dev keypair:"; \
	echo "  private: $$priv (gitignored)"; \
	echo "  public:  $$pub (baked into local build by the inject change)"

# Cross-compile the full new stack for Android: the native artifacts (injector
# libinjector.a + implant libimplant.so per ABI) via ndk-build, and the daemon
# ELF via cargo-ndk (aarch64-linux-android). Requires ANDROID_NDK_HOME (NDK r29)
# and cargo-ndk. Delegates to build-new (native + daemon). Fails early if the
# NDK is unset or the toolchain is not found (build-and-signing task 5.2).
build-android: build-new
	@echo "build-android: full new-stack cross-build complete"

.PHONY: sign verify-sig

# Release-time ed25519 detached signing/verification (called by release.yml).
# KEY=<pem> and FILE=<path-to-manifest> are passed by the caller.
sign:
	@test -n "$(KEY)"  || { echo "sign: KEY=<private.pem> required"  >&2; exit 2; }
	@test -n "$(FILE)" || { echo "sign: FILE=<manifest> required"    >&2; exit 2; }
	openssl pkeyutl -sign -inkey "$(KEY)" -rawin -in "$(FILE)" -out "$(FILE).sig"
	@echo "Signed $(FILE) -> $(FILE).sig"

.PHONY: sign-elf

# Build the signed inject payload: a single ELF file carrying an appended
# ed25519 signature in trailing bytes (VOBSIG1 magic + LE uint64 SIG_OFFSET
# + 64-byte raw ed25519 sig over the ELF). The kernel loads the ELF by its
# header and ignores the trailing 80 bytes at exec; the daemon's self-update
# reads the trailing block and re-verifies the signature against
# EMBEDDED_PUBKEY. One file, no ZIP wrapper, no embedded manifest.
#
# Inputs (passed by the caller, typically release.yml):
#   BINARY=<path to the stripped daemon ELF>   (required)
#   KEY=<path to the ed25519 private key PEM>   (required)
#   OUT=<output path>                           (default: build/voboost-inject)
#
# Signing goes through a temp file (not an openssl stdin pipe): the pipe mixes
# an error trail into the 64-byte signature. Mirrors test/fixtures/gen-fixtures.sh.
sign-elf:
	@test -n "$(BINARY)" || { echo "sign-elf: BINARY=<daemon-elf> required" >&2; exit 2; }
	@test -n "$(KEY)"     || { echo "sign-elf: KEY=<private.pem> required" >&2; exit 2; }
	@test -f "$(BINARY)"  || { echo "sign-elf: BINARY $(BINARY) not found" >&2; exit 2; }
	@test -f "$(KEY)"     || { echo "sign-elf: KEY $(KEY) not found" >&2; exit 2; }
	@out="$(OUT)"; [ -n "$$out" ] || out=build/voboost-inject; \
	mkdir -p "$$(dirname "$$out")"; \
	sigfile=$$(mktemp); \
	openssl pkeyutl -sign -inkey "$(KEY)" -rawin -in "$(BINARY)" -out "$$sigfile"; \
	python3 -c 'import sys, struct; out,binary,sig=sys.argv[1],sys.argv[2],sys.argv[3]; \
elf=open(binary,"rb").read(); s=open(sig,"rb").read(); \
assert len(s)==64, "ed25519 sig is %d bytes, want 64" % len(s); \
trailing=b"VOBSIG1\\0" + struct.pack("<Q", len(elf)) + s; \
open(out,"wb").write(elf); open(out,"ab").write(trailing); \
print("Wrote "+out)' "$$out" "$(BINARY)" "$$sigfile"; \
	rm -f "$$sigfile"
	@echo "Signed inject payload built"

verify-sig:
	@test -n "$(KEY)"  || { echo "verify-sig: KEY=<public.pem> required" >&2; exit 2; }
	@test -n "$(FILE)" || { echo "verify-sig: FILE=<manifest> required"  >&2; exit 2; }
	openssl pkeyutl -verify -pubin -inkey "$(KEY)" -rawin -in "$(FILE)" -sigfile "$(FILE).sig"
	@echo "Verified $(FILE).sig against $(KEY)"

.PHONY: release-manifest

# OTA release-manifest generator (owned by the ota-core-selfupdate change).
# APK-level: scans DIR for APKs, labels every entry with CHANNEL, stamps
# VERSION, and emits unsigned build/release-manifest.json with per-APK
# path/channel/sha256/size/version. This repo's CI emits only the `inject`
# channel (the daemon APK, a single entry); the `agents`/`app` channels are
# produced by the voboost app repo. Signing is the existing `make sign` (the
# ci release workflow calls both); the OTA client verifies the signed manifest,
# and the daemon re-verifies the staged APK's embedded manifest (not the
# release manifest) at apply time. stat is probed both ways (Linux -c%s,
# macOS -f%z) so it runs locally and in CI.
release-manifest:
	@test -n "$(DIR)"     || { echo "release-manifest: DIR=<release-dir> required"         >&2; exit 2; }
	@test -n "$(CHANNEL)" || { echo "release-manifest: CHANNEL=<agents|inject|app> required"  >&2; exit 2; }
	@test -n "$(VERSION)" || { echo "release-manifest: VERSION=<semver> required"           >&2; exit 2; }
	@test -d "$(DIR)"     || { echo "release-manifest: DIR $(DIR) is not a directory"       >&2; exit 2; }
	@mkdir -p build; out=build/release-manifest.json; \
	{ \
	  echo '{'; \
	  echo '  "version": "$(VERSION)",'; \
	  echo '  "channel": "$(CHANNEL)",'; \
	  printf '  "files": [\n'; \
	  first=1; \
	  ( cd "$(DIR)" && find . -type f | sed 's|^\./||' | sort ) | while read -r rel; do \
	    f="$(DIR)/$$rel"; \
	    sha=$$(openssl dgst -sha256 -hex "$$f" | awk '{ print $$NF }'); \
	    sz=$$(stat -c%s "$$f" 2>/dev/null || stat -f%z "$$f" 2>/dev/null); \
	    jsonesc=$$(printf '%s' "$$rel" | sed 's/\\/\\\\/g; s/"/\\"/g'); \
	    abi=; case "/$$rel/" in \
	      */arm64-v8a/*)   abi=arm64-v8a;; \
	      */armeabi-v7a/*) abi=armeabi-v7a;; \
	    esac; \
	    [ "$$first" = 1 ] || printf ',\n'; first=0; \
	    if [ -n "$$abi" ]; then \
	      printf '    {"path":"%s","channel":"$(CHANNEL)","sha256":"%s","size":%s,"version":"$(VERSION)","abi":"%s"}' \
	        "$$jsonesc" "$$sha" "$$sz" "$$abi"; \
	    else \
	      printf '    {"path":"%s","channel":"$(CHANNEL)","sha256":"%s","size":%s,"version":"$(VERSION)"}' \
	        "$$jsonesc" "$$sha" "$$sz"; \
	    fi; \
	  done; \
	  printf '\n  ]\n'; \
	  echo '}'; \
	} > "$$out"; \
	echo "Wrote $$out"

.PHONY: device-provision device-init-hook device-rearm

# Device zone provisioning (provisioning spec). Run ON-DEVICE via
# `adb shell su 0 make device-provision` (requires root). Creates the root
# zone /data/voboost-inject/ with logs/, run/, shared/ (channel-B shared dir,
# labeled media_rw_data_file via file_contexts — see selinux-domain), and
# payload/ (native payload files). Correct ownership (root) and permissions.
# Idempotent. SELinux labels are applied by restorecon after file_contexts is
# installed (device-init-hook); labels are not set here.
ZONE ?= /data/voboost-inject
device-provision:
	@mkdir -p $(ZONE)/logs $(ZONE)/run $(ZONE)/shared $(ZONE)/payload
	@chown root:root $(ZONE)
	@chmod 700 $(ZONE)
	@chmod 700 $(ZONE)/logs $(ZONE)/run $(ZONE)/payload
	@chmod 771 $(ZONE)/shared
	@echo "device-provision: zone $(ZONE) ready (logs/run/shared/payload)"

# Install the daemon init hook + SELinux policy on-device (provisioning spec).
# Run ON-DEVICE via `adb shell su 0 make device-init-hook` (requires root,
# /system remounted RW to install the .rc + policy). Installs:
#   - config/voboost-inject.rc  → the init service (on nonencrypted, oneshot+
#    disabled reboot-loop guard; self-update restart owned by ota)
#   - selinux/voboost-inject.te + file_contexts → the SELinux domain + labels
# Then runs restorecon to apply the labels (shared/ → media_rw_data_file).
# Requires the files already pushed to the device (e.g. via adb push).
RC_DIR ?= /system/etc/init
SEPOLICY_DIR ?= /system/etc/selinux
device-init-hook:
	@test -w "$(RC_DIR)" || { echo "device-init-hook: $(RC_DIR) not writable (remount /system RW as root)" >&2; exit 2; }
	@cp config/voboost-inject.rc $(RC_DIR)/voboost-inject.rc
	@cp selinux/voboost-inject.te $(SEPOLICY_DIR)/voboost-inject.te 2>/dev/null || \
		echo "device-init-hook: $(SEPOLICY_DIR) not present; skipping .te (pre-compiled policy devices differ)"
	@cp selinux/file_contexts $(SEPOLICY_DIR)/file_contexts 2>/dev/null || true
	@restorecon -RF $(ZONE) 2>/dev/null || echo "device-init-hook: restorecon skipped"
	@echo "device-init-hook: init service + SELinux policy installed"

.PHONY: device-rearm

# OTA system-OTA survival (owned by the ota change). After a system OTA reverts
# /system, the operator runs this on-device via adb to restore the guarded
# init-hook block that launches /data/voboost-inject/voboost-inject. Idempotent:
# a hook that already contains the block is left untouched. HOOK=<on-device path>.
# Requires root (/system remounted RW). The restart-on-exit behavior the inject
# update depends on is set up by initial device provisioning (out of scope); this
# step only restores the launch of the stable path.
device-rearm:
	@test -n "$(HOOK)" || { echo "device-rearm: HOOK=<on-device init-hook path> required" >&2; exit 2; }
	@test -w "$(HOOK)" || { echo "device-rearm: $(HOOK) not writable (remount /system RW as root)" >&2; exit 2; }
	@begin='# >>> voboost-inject (do not edit)'; \
	end='# <<< voboost-inject'; \
	if grep -qF "$$begin" "$(HOOK)" 2>/dev/null; then \
	  echo "device-rearm: hook already armed; nothing to do"; \
	else \
	  printf '\n%s\n' "$$begin" >> "$(HOOK)"; \
	  printf '%s\n' "# Launches /data/voboost-inject/voboost-inject once; init/watchdog restarts on exit." >> "$(HOOK)"; \
	  printf '%s\n' "# No fork-loop: single-instance is enforced by the daemon (pidfile + flock)." >> "$(HOOK)"; \
	  printf '%s\n' "exec /data/voboost-inject/voboost-inject" >> "$(HOOK)"; \
	  printf '%s\n' "$$end" >> "$(HOOK)"; \
	  echo "device-rearm: armed $(HOOK)"; \
	fi

.PHONY: emulator-run

# Android emulator dev deploy (no -writable-system, no /system init hook).
# On this host -writable-system does not cold-boot, and adb remount cannot make
# /system writable (remount of the / superblock failed: Permission denied), so
# the daemon is started from the host instead of by a /system init hook. This
# reproduces the production start timing exactly: the production hook
# (voboost-install INIT_HOOK_BODY) runs the service on property:sys.boot_completed=1
# (service disabled+oneshot), so a host-driven start is not later than production.
# Provisions /data/voboost-inject from test/fixtures (root:root 700), pushes the
# cross-built daemon + signed manifest + agents, then starts the daemon under
# `su 0` (single-instance enforced by the daemon's pidfile + flock).
#   ADB=<adb>            adb binary (default: adb on PATH)
#   EMU_SERIAL=<serial>  emulator serial (default: emulator-5554)
ADB ?= adb
EMU_SERIAL ?= emulator-5554
EMU_ZONE ?= /data/voboost-inject
EMU_APP_ZONE ?= /data/user/0/ru.voboost
EMU_BIN ?= daemon/target/aarch64-linux-android/release/voboost-inject

# voboost app + stubs APKs (sibling repos). Used by emulator-run to install
# the app (which creates /data/data/ru.voboost with the correct UID) and the
# stub target packages the agents inject into.
VOBOOST_APK ?= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))../voboost/build/outputs/apk/release/voboost.apk
STUBS_DIR ?= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))../voboost-stubs

# voboost-install binary + OTA release public key (sibling repo). emulator-run
# drives the real provision scenario (config-provision.json) through
# `voboost-install --install` instead of raw adb commands, so the emulator
# exercises the same provision path as production. The installer handles
# daemon/agents/manifest push, app install, init hook (skipped on emulator via
# fatal=false on remount + write-init-hook), and daemon start. Build it with:
#   cd ../voboost-install/src-tauri && cargo build --release
VOBOOST_INSTALL_BIN ?= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))../voboost-install/src-tauri/target/release/voboost-install
VOBOOST_RELEASE_KEY ?= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))../voboost-install/config/release-public.pem
VOBOOST_MANIFEST ?= test/fixtures/manifest.json
VOBOOST_MANIFEST_SIG ?= test/fixtures/manifest.sig
VOBOOST_AGENTS_DIR ?= test/fixtures/agents

emulator-run:
	@test -f "$(EMU_BIN)" || { echo "emulator-run: $(EMU_BIN) missing (run: make build-android)" >&2; exit 2; }
	@a="$(ADB) -s $(EMU_SERIAL)"; \
	echo "emulator-run: waiting for device $(EMU_SERIAL)"; \
	$$a wait-for-device || exit 1; \
	$$a root >/dev/null 2>&1 || true; \
	$$a wait-for-device || exit 1; \
	echo "emulator-run: waiting for sys.boot_completed=1"; \
	i=0; while [ "$$($$a shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" != "1" ]; do \
	  i=$$((i+1)); [ $$i -ge 120 ] && { echo "emulator-run: boot_completed timeout" >&2; exit 1; }; \
	  sleep 1; \
	done; \
	echo "emulator-run: provisioning via voboost-install --install"; \
	test -x "$(VOBOOST_INSTALL_BIN)" \
	  || { echo "emulator-run: $(VOBOOST_INSTALL_BIN) missing (build: cd ../voboost-install/src-tauri && cargo build --release)" >&2; exit 2; }; \
	test -f "$(VOBOOST_APK)" || { echo "emulator-run: $(VOBOOST_APK) missing" >&2; exit 2; }; \
	ANDROID_SERIAL="$(EMU_SERIAL)" "$(VOBOOST_INSTALL_BIN)" --install "$(VOBOOST_APK)" \
	  --daemon-bin "$(EMU_BIN)" \
	  --agents-dir "$(VOBOOST_AGENTS_DIR)" \
	  --manifest "$(VOBOOST_MANIFEST)" \
	  --manifest-sig "$(VOBOOST_MANIFEST_SIG)" \
	  --release-key "$(VOBOOST_RELEASE_KEY)" \
	  --lang en \
	  || { echo "emulator-run: voboost-install --install failed (see $(EMU_ZONE)/logs/manual-start.log)" >&2; exit 1; }; \
	pid=$$($$a shell "su 0 pgrep -f $(EMU_ZONE)/voboost-inject" 2>/dev/null | tr -d '\r'); \
	test -n "$$pid" || { echo "emulator-run: daemon not running (see $(EMU_ZONE)/logs/manual-start.log)" >&2; exit 1; }; \
	echo "emulator-run: daemon PID=$$pid"; \
	echo "emulator-run: installing stubs"; \
	for stub in $(STUBS_DIR)/*/build/outputs/apk/release/*.apk; do \
	  [ -f "$$stub" ] || continue; \
	  pkg=$$(basename "$$stub" .apk); \
	  case "$$pkg" in \
	    launcher) apkid=com.qinggan.app.launcher ;; \
	    bluetoothphone) apkid=com.qinggan.bluetoothphone ;; \
	    qgime) apkid=com.qinggan.app.qgime ;; \
	    systemservice) apkid=com.qinggan.systemservice ;; \
	    vehiclesetting) apkid=com.qinggan.app.vehiclesetting ;; \
	    *) continue ;; \
	  esac; \
	  if $$a shell pm list packages "$$apkid" 2>/dev/null | grep -q "^package:$$apkid$$"; then \
	    echo "emulator-run: $$apkid already installed"; \
	  else \
	    $$a install -r "$$stub" >/dev/null 2>&1 \
	      || { echo "emulator-run: $$stub install failed" >&2; exit 1; }; \
	    echo "emulator-run: installed $$apkid"; \
	  fi; \
	done; \
	echo "emulator-run: app zone created by provision (app-zone step)"; \
	echo "emulator-run: writing test inject.json (4 agents)"; \
	appuid=$$($$a shell "su 0 stat -c %u /data/data/ru.voboost" 2>/dev/null | tr -d '\r'); \
	appgid=$$($$a shell "su 0 stat -c %g /data/data/ru.voboost" 2>/dev/null | tr -d '\r'); \
	tmpjson=$$(mktemp -t voboost-inject.XXXXXX) || exit 1; \
	printf '%s\n' \
	  '{' \
	  '  "version": 1,' \
	  '  "startup": "boot",' \
	  '  "log_level": "info",' \
	  '  "agents": [' \
	  '    {"id":"wm-viewport","enabled":true},' \
	  '    {"id":"settings-menu","enabled":true},' \
	  '    {"id":"low-speed-sound","enabled":true},' \
	  '    {"id":"launcher-echo","enabled":true}' \
	  '  ]' \
	  '}' > "$$tmpjson"; \
	$$a push "$$tmpjson" /data/local/tmp/voboost-inject.json >/dev/null \
	  || { rm -f "$$tmpjson"; exit 1; }; \
	rm -f "$$tmpjson"; \
	$$a shell "su 0 cp /data/local/tmp/voboost-inject.json $(EMU_APP_ZONE)/inject.json" \
	  || exit 1; \
	$$a shell "su 0 chown $$appuid:$$appgid $(EMU_APP_ZONE)/inject.json" 2>/dev/null || true; \
	$$a shell "su 0 chmod 600 $(EMU_APP_ZONE)/inject.json" 2>/dev/null || true; \
	$$a shell "su 0 rm -f /data/local/tmp/voboost-inject.json" 2>/dev/null || true; \
	echo "emulator-run: app zone ready"; \
	$$a shell "su 0 cat $(EMU_APP_ZONE)/inject-status.json" 2>/dev/null || true

# ===========================================================================
# New stack: Rust daemon + C injector + C++ implant (ptrace, no frida)
# These targets build the new code: the native artifacts (ndk-build) and the
# Rust daemon (cargo-ndk). The old frida/meson/Vala stack has been removed
# (build-and-signing); `make build-android` now delegates to build-new.
# ===========================================================================

# NDK path — required for native builds (C/C++). (Also defined at the top of
# this Makefile; kept here for proximity to the native targets.)
NDK_BUILD ?= $(NDK_HOME)/ndk-build
PREBUILT_DIR ?= $(PWD)/prebuilt

# ---- build the C injector (libinjector.a) ----
# A static archive linked into the Rust daemon via build.rs FFI.
build-injector:
	@test -n "$(NDK_HOME)" || { echo "build-injector: ANDROID_NDK_HOME not set" >&2; exit 1; }
	@echo "build-injector: building libinjector.a (C, arm64-v8a)"
	cd injector && $(NDK_BUILD) NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=Android.mk APP_APPLICATION_MK=Application.mk
	@echo "build-injector: done -> injector/libs/arm64-v8a/libinjector.a"

# ---- build the C++ implant (libimplant.so, per-ABI) ----
# The in-process loader. Both ABIs produced (the daemon selects at runtime).
build-implant:
	@test -n "$(NDK_HOME)" || { echo "build-implant: ANDROID_NDK_HOME not set" >&2; exit 1; }
	@echo "build-implant: building libimplant.so (C++, arm64-v8a + armeabi-v7a)"
	cd implant && $(NDK_BUILD) NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=Android.mk APP_APPLICATION_MK=Application.mk
	@echo "build-implant: done -> implant/libs/{arm64-v8a,armeabi-v7a}/libimplant.so"

# ---- build all native artifacts (injector + implant) ----
build-native: build-injector build-implant
	@echo "build-native: all native artifacts built"

# ---- build the Rust daemon (cargo-ndk, aarch64) ----
# Requires cargo-ndk: cargo install cargo-ndk
build-daemon:
	@command -v cargo-ndk >/dev/null 2>&1 || { echo "build-daemon: cargo-ndk not found (cargo install cargo-ndk)" >&2; exit 1; }
	@test -n "$(NDK_HOME)" || { echo "build-daemon: ANDROID_NDK_HOME not set" >&2; exit 1; }
	@echo "build-daemon: building voboost-inject (Rust, aarch64-linux-android)"
	cd daemon && cargo ndk -t arm64-v8a build --release
	@echo "build-daemon: done -> daemon/target/aarch64-linux-android/release/voboost-inject"

# ---- build everything (daemon + native) ----
build-new: build-native build-daemon
	@echo "build-new: all new-stack artifacts built"
