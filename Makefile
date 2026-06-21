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
	echo "init: vala-lint installed (PATH gets $(TOOLS_DIR)/bin from this Makefile)."
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
	rm -rf $(BUILD_DIR)
	$(MAKE) key-dev
	$(MAKE) setup

setup:
	meson setup $(BUILD_DIR)

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
# Requires ANDROID_NDK_HOME; the NDK toolchain binaries must be on PATH.
build-android:
	meson setup $(ANDROID_BUILD_DIR) --cross-file config/android-cross.ini
	ninja -C $(ANDROID_BUILD_DIR)
