BUILD_DIR ?= build

# Prefix where make init puts the source-built io.elementary.vala-lint.
# Add $(TOOLS_PREFIX)/bin to PATH so `make lint` and check find it.
TOOLS_PREFIX ?= $(HOME)/.local

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
			libjson-glib-dev libglib2.0-dev pkg-config git openssl \
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
	meson setup "$$src/build" "$$src" --prefix "$(TOOLS_PREFIX)" $$extra_args; \
	ninja -C "$$src/build"; \
	ninja -C "$$src/build" install; \
	rm -rf "$$src"; \
	echo "init: vala-lint installed. Ensure $(TOOLS_PREFIX)/bin is on PATH."
	$(MAKE) setup
	$(MAKE) key-dev

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
	@keydir=keys; priv=$$keydir/dev-private.pem; pub=$$keydir/dev-public.pem; \
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
