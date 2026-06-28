BUILD_DIR ?= build

# Local tools directory inside the project for project-specific build tools.
# This keeps all project dependencies self-contained and reproducible.
TOOLS_DIR ?= $(PWD)/.tools
export PATH := $(TOOLS_DIR)/bin:$(PATH)

# Ad-hoc code signing for frida-core's helper on macOS development builds.
# Override with a real Apple Developer identity for distribution.
export MACOS_CERTID ?= -

# Pinned io.elementary.vala-lint revision (no Homebrew/apt package exists).
VALA_LINT_REPO ?= https://github.com/vala-lang/vala-lint.git
VALA_LINT_REV ?= 0.1.0

# frida's meson fork (github.com/frida/meson), pinned by frida-core's
# releng/meson submodule. Standard meson cannot build frida's native
# (build-machine) subprojects — e.g. quickjs for quickcompile — in a cross
# build, so `make build-android` configures via this instead of system meson.
FRIDA_MESON ?= $(PWD)/subprojects/frida-core/releng/meson/meson.py

# Python interpreter used to launch frida's meson. MUST still ship the stdlib
# `distutils` module (removed in Python 3.12, PEP 0632): glib's gdbus-codegen
# (run as a build-machine tool during ninja) imports `distutils.version`.
# macOS system python3 (/usr/bin/python3, 3.9) has distutils; Homebrew's
# python3 (3.12+/3.14) does not. On Linux, /usr/bin/python3 is 3.x with
# distutils on older distros; CI installs python3.11 (see release.yml).
PYTHON_FOR_MESON ?= /usr/bin/python3

.PHONY: init setup build lint lint-fix test check key-dev

# From a clean clone to a ready environment, identically locally and in CI.
# Steps: install OS-package tools + build vala-lint from source, then setup,
# then key-dev. All three steps run in order inside this single recipe.
init:
	@os=$$(uname -s); \
	if [ "$$os" = "Darwin" ]; then \
		echo "init: macOS (Homebrew)"; \
		brew install vala meson ninja bsdiff uncrustify json-glib glib pkg-config; \
	elif [ "$$os" = "Linux" ]; then \
		echo "init: Linux (apt)"; \
		sudo apt-get update; \
		sudo apt-get install -y valac meson ninja-build bsdiff uncrustify \
			libjson-glib-dev libglib2.0-dev pkg-config git openssl curl \
			libvala-dev libgee-0.8-dev; \
	else \
		echo "init: unsupported OS '$$os'. Use WSL2 + Ubuntu." >&2; \
		exit 1; \
	fi; \
	if command -v io.elementary.vala-lint >/dev/null 2>&1; then \
		echo "init: io.elementary.vala-lint already present; skipping its build"; \
	else \
	echo "init: building io.elementary.vala-lint @ $(VALA_LINT_REV)"; \
	src=$$(mktemp -d); \
	git clone --depth 1 --branch "$(VALA_LINT_REV)" "$(VALA_LINT_REPO)" "$$src"; \
	extra_args=""; \
	if [ "$$os" = "Darwin" ]; then extra_args="-Dc_args=-DFNM_EXTMATCH=0"; fi; \
	lint_valac=$$(which -a valac 2>/dev/null | while read -r p; do \
		"$$p" --version 2>/dev/null | grep -q frida || { echo "$$p"; break; }; \
	done); \
	if [ -z "$$lint_valac" ]; then \
		echo "init: no system (non-frida) valac found for vala-lint build" >&2; \
		exit 1; \
	fi; \
	echo "init: using $$lint_valac for vala-lint (needs matching libvala)"; \
	VALAC="$$lint_valac" meson setup "$$src/build" "$$src" --prefix "$(TOOLS_DIR)" $$extra_args; \
	VALAC="$$lint_valac" ninja -C "$$src/build"; \
	ninja -C "$$src/build" install; \
	rm -rf "$$src"; \
	if [ "$$os" = "Darwin" ]; then \
		vlintlib=$$(basename "$(TOOLS_DIR)/lib"/libvala-linter-*.dylib 2>/dev/null || true); \
		if [ -n "$$vlintlib" ]; then \
			install_name_tool -id @rpath/$$vlintlib "$(TOOLS_DIR)/lib/$$vlintlib"; \
			install_name_tool -change "$(TOOLS_DIR)/lib/$$vlintlib" @rpath/$$vlintlib "$(TOOLS_DIR)/bin/io.elementary.vala-lint"; \
			install_name_tool -add_rpath @loader_path/../lib "$(TOOLS_DIR)/bin/io.elementary.vala-lint" 2>/dev/null || true; \
			echo "init: vala-lint install names relativized (relocatable)"; \
		fi; \
	fi; \
	echo "init: vala-lint installed (PATH gets $(TOOLS_DIR)/bin from this Makefile)."; \
	fi
	meson subprojects download
	@if valac --version 2>/dev/null | grep -q -- '-frida'; then \
		echo "init: frida-patched valac already present; skipping its build"; \
	else \
		echo "init: building the frida-patched valac (frida-core hard-requires it)"; \
		releng_rev=$$(git -C subprojects/frida-core ls-tree HEAD releng | awk '{ print $$3 }'); \
		vala_rev=$$(curl -fsSL "https://raw.githubusercontent.com/frida/releng/$$releng_rev/deps.toml" \
			| sed -n '/^\[vala\]/,/^\[/ s/^version *= *"\(.*\)"/\1/p' | head -n 1); \
		test -n "$$vala_rev" || { echo "init: cannot resolve the vala fork pin" >&2; exit 1; }; \
		echo "init: frida/vala revision $$vala_rev (from releng $$releng_rev deps.toml)"; \
		src=$$(mktemp -d); \
		git -C "$$src" init -q; \
		git -C "$$src" remote add origin https://github.com/frida/vala.git; \
		git -C "$$src" fetch -q --depth 1 origin "$$vala_rev"; \
		git -C "$$src" checkout -q --detach FETCH_HEAD; \
		meson setup "$$src/build" "$$src" --prefix "$(TOOLS_DIR)"; \
		ninja -C "$$src/build" install; \
		rm -rf "$$src"; \
	fi
	@if [ -f "$(FRIDA_MESON)" ]; then \
		echo "init: frida-meson already present; skipping its init"; \
	else \
		echo "init: initializing frida-core releng + meson submodules (frida-meson, required for cross-builds)"; \
		git -C subprojects/frida-core submodule update --init --recursive releng; \
	fi
	@echo "init: patching frida-meson for libc++ hardening mode (macOS 26.2 SDK compat)"
	@cd subprojects/frida-core/releng/meson && \
		git apply --check ../../../../subprojects/packagefiles/frida-meson-libcpp-hardening-mode.patch 2>/dev/null && \
		git apply ../../../../subprojects/packagefiles/frida-meson-libcpp-hardening-mode.patch || \
		echo "init: frida-meson libc++ patch already applied or not needed; skipping"
	rm -rf $(BUILD_DIR)
	$(MAKE) key-dev
	$(MAKE) setup

# Configure via frida's meson (PYTHON_FOR_MESON + FRIDA_MESON), not the system
# meson: frida-core's compat/build.py (run during ninja) imports frida-meson's
# `mesonbuild` and pickle-loads the coredata.dat written here — if system meson
# wrote it, the pickle is incompatible (ModuleNotFoundError: mesonbuild.options).
# Using frida-meson for both setup and build-android keeps them consistent.
setup:
	$(PYTHON_FOR_MESON) $(FRIDA_MESON) setup $(BUILD_DIR)

build:
	ninja -C $(BUILD_DIR)

lint:
	@for tool in uncrustify io.elementary.vala-lint; do \
		if ! command -v "$$tool" >/dev/null 2>&1; then \
			echo "lint: '$$tool' not found on PATH; run \`make init\`" >&2; \
			exit 1; \
		fi; \
	done
	io.elementary.vala-lint --config config/config-vala-lint.conf src/ test/ || exit 1
	uncrustify --check -c config/config-uncrustify.cfg -l VALA $$(find src test -name '*.vala' 2>/dev/null) || exit 1

lint-fix:
	uncrustify --replace --no-backup -c config/config-uncrustify.cfg -l VALA \
		$$(find src test -name '*.vala' 2>/dev/null)

test:
	meson test -C $(BUILD_DIR)

check:
	@missing=0; \
	for tool in valac meson ninja git openssl bsdiff uncrustify \
			io.elementary.vala-lint; do \
		if command -v "$$tool" >/dev/null 2>&1; then \
			echo "  ok      $$tool"; \
		else \
			echo "  MISSING $$tool" >&2; \
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

ANDROID_BUILD_DIR ?= build-android

.PHONY: build-android

# Cross-compile for Android arm64-v8a via NDK.
# Requires ANDROID_NDK_HOME; the NDK toolchain PATH is derived
# automatically (mirrors CI's "Put NDK toolchain on PATH" step).
# Configures with frida's meson (FRIDA_MESON, provisioned by
# init) — standard meson cannot build frida's native subprojects
# (quickjs for quickcompile) here.
# Launched via PYTHON_FOR_MESON (must ship `distutils` for glib's gdbus-codegen).
# -Dfrida-core:connectivity=disabled: the daemon is local-backend-only (no TLS/
# ICE); connectivity pulls in gioopenssl/glib-networking, which fails to provide
# the gioopenssl dependency unless glib-networking is built static (it is, via
# the global default_library=static), but TLS/ICE is unused anyway.
build-android:
	@test -n "$(ANDROID_NDK_HOME)" || \
		{ echo "build-android: ANDROID_NDK_HOME not set" >&2; exit 1; }
	@ndk_bin=$$(echo "$(ANDROID_NDK_HOME)"/toolchains/llvm/prebuilt/*/bin); \
	test -d "$$ndk_bin" || \
		{ echo "build-android: NDK toolchain not found" >&2; exit 1; }; \
	echo "build-android: PATH += $$ndk_bin"; \
	export PATH="$$ndk_bin:$$PATH"; \
	export ANDROID_NDK_ROOT="$(ANDROID_NDK_HOME)"; \
	$(PYTHON_FOR_MESON) $(FRIDA_MESON) setup $(ANDROID_BUILD_DIR) \
		--cross-file config/android-cross.ini \
		-Dfrida-core:connectivity=disabled && \
	ninja -C $(ANDROID_BUILD_DIR)

.PHONY: sign verify-sig

# Release-time ed25519 detached signing/verification (called by release.yml).
# KEY=<pem> and FILE=<path-to-manifest> are passed by the caller.
sign:
	@test -n "$(KEY)"  || { echo "sign: KEY=<private.pem> required"  >&2; exit 2; }
	@test -n "$(FILE)" || { echo "sign: FILE=<manifest> required"    >&2; exit 2; }
	openssl pkeyutl -sign -inkey "$(KEY)" -rawin -in "$(FILE)" -out "$(FILE).sig"
	@echo "Signed $(FILE) -> $(FILE).sig"

verify-sig:
	@test -n "$(KEY)"  || { echo "verify-sig: KEY=<public.pem> required" >&2; exit 2; }
	@test -n "$(FILE)" || { echo "verify-sig: FILE=<manifest> required"  >&2; exit 2; }
	openssl pkeyutl -verify -pubin -inkey "$(KEY)" -rawin -in "$(FILE)" -sigfile "$(FILE).sig"
	@echo "Verified $(FILE).sig against $(KEY)"

.PHONY: release-manifest

# OTA release-manifest generator (owned by the ota change). Scans DIR for files,
# labels every entry with CHANNEL, stamps VERSION, and emits unsigned
# build/release-manifest.json with per-file path/channel/sha256/size/version.
# Signing is the existing `make sign` (the ci release workflow calls both); the
# daemon re-verifies the signed manifest with the embedded key on apply.
# stat is probed both ways (Linux -c%s, macOS -f%z) so it runs locally and in CI.
release-manifest:
	@test -n "$(DIR)"     || { echo "release-manifest: DIR=<release-dir> required"         >&2; exit 2; }
	@test -n "$(CHANNEL)" || { echo "release-manifest: CHANNEL=<agents|core|app> required"  >&2; exit 2; }
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
	    [ "$$first" = 1 ] || printf ',\n'; first=0; \
	    printf '    {"path":"%s","channel":"$(CHANNEL)","sha256":"%s","size":%s,"version":"$(VERSION)"}' \
	      "$$jsonesc" "$$sha" "$$sz"; \
	  done; \
	  printf '\n  ]\n'; \
	  echo '}'; \
	} > "$$out"; \
	echo "Wrote $$out"

.PHONY: device-rearm

# OTA system-OTA survival (owned by the ota change). After a system OTA reverts
# /system, the operator runs this on-device via adb to restore the guarded
# init-hook block that launches /data/voboost/voboost-inject. Idempotent: a hook
# that already contains the block is left untouched. HOOK=<on-device path>.
# Requires root (/system remounted RW). The restart-on-exit behavior the core
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
	  printf '%s\n' "# Launches /data/voboost/voboost-inject once; init/watchdog restarts on exit." >> "$(HOOK)"; \
	  printf '%s\n' "# No fork-loop: single-instance is enforced by the daemon (pidfile + flock)." >> "$(HOOK)"; \
	  printf '%s\n' "exec /data/voboost/voboost-inject" >> "$(HOOK)"; \
	  printf '%s\n' "$$end" >> "$(HOOK)"; \
	  echo "device-rearm: armed $(HOOK)"; \
	fi
