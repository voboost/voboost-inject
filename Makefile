BUILD_DIR ?= build

# Local tools directory inside the project for project-specific build tools.
# This keeps all project dependencies self-contained and reproducible.
TOOLS_DIR ?= $(CURDIR)/.tools
export PATH := $(TOOLS_DIR)/bin:$(PATH)

# Android NDK. The native artifacts (injector, implant) and the cross-built
# daemon all require NDK r29 (Clang 21) — older NDKs fail LSPlant C++23
# modules. NDK_HOME selects the shared toolchain; cargo-ndk receives the same
# path through its ANDROID_NDK_HOME input.
NDK_HOME ?= $(ANDROID_NDK_HOME)
export NDK_HOME
export ANDROID_NDK_HOME := $(NDK_HOME)
export PYTHONDONTWRITEBYTECODE := 1
CARGO_NDK_VERSION := 4.1.2
CARGO_AUDIT_VERSION := 0.22.2
CARGO_LLVM_COV_VERSION := 0.6.21
RUST_COVERAGE_TOOLCHAIN := nightly-2026-09-01

.PHONY: init build lint lint-fix test test-tooling check check-ndk openspec-strict openspec-evidence openspec-language test-no-network-client test-doc-consistency test-release-workflow test-make-recipes test-ephemeral-native-role-keys test-daemon-versionless test-daemon-versionless-reproducible
.PHONY: lint-analyzer lint-tidy test-host-asan check-elf-hardening test-release-elf audit-rust
.PHONY: coverage coverage-rust coverage-native
.PHONY: attest-inject-build-identity verify-inject-build-attestation test-native-reproducible-paths test-prepare-beta1-unsigned
.PHONY: verify-product-agent-catalog-authority verify-producer-agent-catalog
.PHONY: test-inject-build-attestation
.PHONY: check-role-public-keys
.PHONY: build-native build-third-party build-injector build-implant \
        build-daemon build-inject build-new build-android check-prebuilt test-armv7-dobby-prebuilt \
        test-clean-checkout-contract test-third-party-source-contract \
        test-injector-init-result test-implant-pipe-bootstrap \
        test-implant-pipe-manifest test-implant-bounded-elf-string \
        test-implant-runtime-safety

# From a clean clone to a ready environment, identically locally and in CI.
# The new stack is Rust (cargo + cargo-ndk) and NDK r29 (ndk-build) — no Vala,
# Steps: install OS-package tools, ensure the Rust toolchain
# (rust-toolchain.toml) and cargo-ndk, then verify NDK r29. Development signing
# identities are generated only for the lifetime of an explicit wrapper command.
init:
	git submodule update --init --recursive
	$(MAKE) --no-print-directory test-third-party-source-contract
	@os=$$(uname -s); \
	if [ "$$os" = "Darwin" ]; then \
		echo "init: macOS (Homebrew)"; \
		brew install uncrustify openssl@3 curl git || true; \
	elif [ "$$os" = "Linux" ]; then \
		echo "init: Linux (apt)"; \
		sudo apt-get update; \
		sudo apt-get install -y build-essential clang llvm default-jdk-headless \
			uncrustify openssl curl git pkg-config; \
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
	@if [ "$$(cargo ndk --version 2>/dev/null)" != "cargo-ndk $(CARGO_NDK_VERSION)" ]; then \
		echo "init: installing cargo-ndk $(CARGO_NDK_VERSION)"; \
		cargo install cargo-ndk --version $(CARGO_NDK_VERSION) --locked --force; \
	fi
	@if ! command -v cargo-audit >/dev/null 2>&1; then \
		echo "init: installing cargo-audit $(CARGO_AUDIT_VERSION)"; \
		cargo install cargo-audit --version $(CARGO_AUDIT_VERSION) --locked --force; \
	fi
	@if [ "$$(cargo llvm-cov --version 2>/dev/null)" != "cargo-llvm-cov $(CARGO_LLVM_COV_VERSION)" ]; then \
		cargo install cargo-llvm-cov --version $(CARGO_LLVM_COV_VERSION) --locked --force; \
	fi
	rustup toolchain install $(RUST_COVERAGE_TOOLCHAIN) --profile minimal \
		--component llvm-tools-preview
	@$(MAKE) check-ndk
	@echo "init: done"

# Verify NDK r29 is present at ANDROID_NDK_HOME (the single cross-build
# prerequisite). Older NDKs fail LSPlant C++23 modules (see release-verification).
check-ndk:
	@test -n "$(NDK_HOME)" || { echo "check-ndk: ANDROID_NDK_HOME not set" >&2; exit 1; }
	@test -d "$(NDK_HOME)/toolchains/llvm/prebuilt" || \
		{ echo "check-ndk: NDK toolchain not found at $(NDK_HOME)" >&2; exit 1; }
	@ndk_ver=$$(sed -nE \
		's/^Pkg\.Revision[[:space:]]*=[[:space:]]*([0-9]+).*/\1/p' \
		"$(NDK_HOME)/source.properties" 2>/dev/null | head -n 1); \
	[ -n "$$ndk_ver" ] || ndk_ver=unknown; \
	if [ "$$ndk_ver" != "29" ]; then \
		echo "check-ndk: NDK r$$ndk_ver found, require r29 (LSPlant C++23 modules)" >&2; \
		exit 1; \
	fi
	@echo "check-ndk: NDK r29 OK ($(NDK_HOME))"

# Release-mode host validation build. The Android cross-build is
# `make build-daemon` / `make build-android`.
build:
	cd daemon && cargo build --release

# Lint: Rust (cargo fmt + clippy) and C/C++ (uncrustify). The repository
# verification targets define the complete host gate contract.
lint: openspec-language openspec-strict openspec-evidence test-daemon-source-topology test-daemon-versionless test-doc-consistency test-release-workflow test-make-recipes test-ephemeral-native-role-keys lint-analyzer lint-tidy
	@missing=0; \
	for tool in cargo node npm uncrustify; do \
		if ! command -v "$$tool" >/dev/null 2>&1; then \
			echo "lint: $$tool not found; run \`make init\`" >&2; \
			missing=$$((missing + 1)); \
		fi; \
	done; \
	test "$$missing" -eq 0
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings
	uncrustify --check -c config/config-uncrustify.cfg \
		$$(find injector implant -name '*.c' -o -name '*.cpp' -o \
		-name '*.h' -o -name '*.hpp' 2>/dev/null)

# Static analyzer gate: zero clang static analyzer findings in first-party
# C/C++ code (NDK toolchain, Android target). Vendored third_party/ findings
# are excluded by path; the remaining adjudicated non-defects are pinned in
# tools/lint-analyzer.ts and fail the gate when the code under them changes.
# Requires NDK_HOME/ANDROID_NDK_HOME (NDK r29).
lint-analyzer: test-inline-hook-publication test-lsplant-stage-callback test-lsplant-backup-publication test-implant-symtab test-native-faults
	@test -n "$(NDK_HOME)" || { echo "lint-analyzer: ANDROID_NDK_HOME not set" >&2; exit 1; }
	NDK_HOME="$(NDK_HOME)" node tools/lint-analyzer.ts

# clang-tidy gate: zero first-party findings under the shared Voboost .clang-tidy
# selection (NDK clang-tidy, Android target). Vendored code is excluded by path.
# Requires NDK_HOME/ANDROID_NDK_HOME (NDK r29).
lint-tidy: test-inline-hook-publication test-lsplant-stage-callback test-lsplant-backup-publication test-implant-symtab test-native-faults
	@test -n "$(NDK_HOME)" || { echo "lint-tidy: ANDROID_NDK_HOME not set" >&2; exit 1; }
	NDK_HOME="$(NDK_HOME)" node tools/lint-tidy.ts

# RustSec gate: fail on any known vulnerability in Cargo.lock. Unmaintained
# and informational transitive warnings do not fail this gate; they are
# reviewed separately (see docs/developer). Requires cargo-audit (make init).
audit-rust:
	@command -v cargo-audit >/dev/null 2>&1 || { echo "audit-rust: cargo-audit not found (run make init)" >&2; exit 1; }
	cargo audit

# Current specs, active changes and all new archive entries are English-only.
# This repository has no grandfathered archive-language exceptions.
openspec-language:
	@if rg -n '[А-Яа-яЁё]' openspec; then \
		echo "openspec-language: Cyrillic text is not allowed" >&2; \
		exit 1; \
	fi

openspec-evidence:
	@node tools/validate-openspec-evidence.ts

openspec-strict:
	@npm run check:openspec:strict

test-no-network-client:
	@node tools/test-no-network-client.ts

test-daemon-source-topology:
	@node tools/test-daemon-source-topology.ts

test-daemon-versionless:
	@node tools/test-daemon-versionless.ts

test-daemon-versionless-reproducible:
	@test -n "$(NDK_HOME)" || { echo "test-daemon-versionless-reproducible: ANDROID_NDK_HOME not set" >&2; exit 1; }
	VOBOOST_NATIVE_REGISTRY="$(if $(NATIVE_REGISTRY),$(abspath $(NATIVE_REGISTRY)))" \
	VOBOOST_AGENT_CATALOG_PUBLIC_KEY_PEM="$(abspath $(AGENT_CATALOG_PUBLIC_KEY_PEM))" \
	VOBOOST_RELEASE_CATALOG_PUBLIC_KEY_PEM="$(abspath $(RELEASE_CATALOG_PUBLIC_KEY_PEM))" \
	VOBOOST_NATIVE_EXECUTABLE_PUBLIC_KEY_PEM="$(abspath $(NATIVE_EXECUTABLE_PUBLIC_KEY_PEM))" \
	VOBOOST_RESTORE_PUBLIC_KEY_PEM="$(abspath $(RESTORE_PUBLIC_KEY_PEM))" \
	RUSTFLAGS="$(RUST_ANDROID_FLAGS)" \
	ANDROID_NDK_HOME="$(NDK_HOME)" tools/test-daemon-versionless-reproducible.sh

test-native-reproducible-paths:
	@node tools/test-native-reproducible-paths.ts

test-clean-checkout-contract:
	@node tools/test-clean-checkout-contract.ts

test-doc-consistency:
	@node tools/test-doc-consistency.ts

test-release-workflow:
	@node tools/test-release-workflow.ts

test-make-recipes:
	@node tools/test-make-recipes.ts

test-ephemeral-native-role-keys:
	@node tools/test-ephemeral-native-role-keys.ts

# Complete executable development-tool contract. CI runs this target directly;
# keeping it separate from lint makes every adapter test visible in the job log
# and prevents package.json-only tests from becoming optional.
test-tooling:
	@npm run check:tooling

lint-fix:
	@for tool in cargo node uncrustify; do \
		command -v "$$tool" >/dev/null 2>&1 || { \
			echo "lint-fix: $$tool not found; run \`make init\`" >&2; \
			exit 1; \
		}; \
	done
	cd daemon && cargo fmt
	uncrustify --replace --no-backup -c config/config-uncrustify.cfg \
		$$(find injector implant -name '*.c' -o -name '*.cpp' -o \
		-name '*.h' -o -name '*.hpp' 2>/dev/null)

# Run every host test gate. Capture output so success is silent; on failure,
# replay the complete log before returning non-zero.
test:
	@test_log=$$(mktemp) || exit 1; \
	trap 'rm -f "$$test_log"' EXIT HUP INT TERM; \
	if ! { \
		cargo test --workspace && \
		$(MAKE) --no-print-directory test-injector && \
		$(MAKE) --no-print-directory test-implant && \
		$(MAKE) --no-print-directory test-cluster-locale-observer && \
		$(MAKE) --no-print-directory test-cluster-ui-root && \
		$(MAKE) --no-print-directory test-cluster-ui-frame && \
		$(MAKE) --no-print-directory test-inject-build-attestation && \
		$(MAKE) --no-print-directory test-sign-elf && \
		$(MAKE) --no-print-directory test-armv7-dobby-prebuilt && \
		$(MAKE) --no-print-directory test-selinux && \
		$(MAKE) --no-print-directory test-selinux-real-policy && \
		$(MAKE) --no-print-directory test-host-asan && \
			$(MAKE) --no-print-directory audit-rust; \
	} >"$$test_log" 2>&1; then \
		cat "$$test_log" >&2; \
		exit 1; \
	fi

# Permanent ASan+UBSan gate for the host C/C++ suite: injector, implant and
# pure SELinux tests are rebuilt with sanitizers and must run without any
# sanitizer report. The sanitized builds replace the regular host test
# binaries in build/; the next unsanitized make test rebuilds them.
SANITIZE_FLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer
test-host-asan:
	@command -v clang >/dev/null 2>&1 || { echo "test-host-asan: clang not found" >&2; exit 1; }
	@$(MAKE) --no-print-directory \
		HOST_CC="clang $(SANITIZE_FLAGS)" \
		HOST_CXX="clang++ $(SANITIZE_FLAGS)" \
		test-injector test-implant test-cluster-locale-observer
	@$(MAKE) --no-print-directory \
		CC="clang $(SANITIZE_FLAGS)" \
		test-selinux-policy-backup test-selinux-policy-inject \
		test-selinux-relabel-walk test-selinux-watchdog
	@echo "test-host-asan: ASan+UBSan host suite passed"

# Linux coverage executes the actual first-party injector and implant
# translation units. The policy checks named production entrypoints plus real
# line/branch execution; it intentionally has no gameable percentage target.
coverage: coverage-rust coverage-native

coverage-rust:
	@command -v cargo-llvm-cov >/dev/null 2>&1 || { echo "coverage-rust: cargo-llvm-cov missing" >&2; exit 1; }
	@CARGO_UNSTABLE_BUILD_DIR_NEW_LAYOUT=false cargo +$(RUST_COVERAGE_TOOLCHAIN) llvm-cov clean --workspace
	@CARGO_UNSTABLE_BUILD_DIR_NEW_LAYOUT=false cargo +$(RUST_COVERAGE_TOOLCHAIN) llvm-cov \
		-p voboost-contract --lib --branch --json --output-path build/rust-coverage-contract.json
	@CARGO_UNSTABLE_BUILD_DIR_NEW_LAYOUT=false cargo +$(RUST_COVERAGE_TOOLCHAIN) llvm-cov \
		--no-clean -p voboost-daemon --bin voboost-daemon --branch --json \
		--output-path build/rust-coverage-daemon.json
	@CARGO_UNSTABLE_BUILD_DIR_NEW_LAYOUT=false cargo +$(RUST_COVERAGE_TOOLCHAIN) llvm-cov \
		--no-clean -p voboost-install --bin voboost-install --branch --json \
		--output-path build/rust-coverage-install.json
	@CARGO_UNSTABLE_BUILD_DIR_NEW_LAYOUT=false cargo +$(RUST_COVERAGE_TOOLCHAIN) llvm-cov \
		--no-clean -p voboost-restore --bin voboost-restore --branch --json \
		--output-path build/rust-coverage-restore.json
	@CARGO_UNSTABLE_BUILD_DIR_NEW_LAYOUT=false cargo +$(RUST_COVERAGE_TOOLCHAIN) llvm-cov \
		--no-clean -p voboost-uninstall --bin voboost-uninstall --branch --json \
		--output-path build/rust-coverage-uninstall.json
	@node tools/check-rust-coverage.ts \
		build/rust-coverage-contract.json \
		build/rust-coverage-daemon.json build/rust-coverage-install.json \
		build/rust-coverage-restore.json build/rust-coverage-uninstall.json

coverage-native:
	@test "$$(uname -s)" = Linux || { echo "coverage-native: Linux is required" >&2; exit 77; }
	@command -v clang >/dev/null 2>&1
	@command -v clang++ >/dev/null 2>&1
	@command -v llvm-profdata >/dev/null 2>&1
	@command -v llvm-cov >/dev/null 2>&1
	@rm -f build/native-coverage-*.profraw build/native-coverage.profdata build/native-coverage.json
	@LLVM_PROFILE_FILE="$(CURDIR)/build/native-coverage-%p.profraw" \
		$(MAKE) --no-print-directory \
		HOST_CC="clang -fprofile-instr-generate -fcoverage-mapping" \
		HOST_CXX="clang++ -fprofile-instr-generate -fcoverage-mapping" \
		test-injector test-implant
	@llvm-profdata merge -sparse build/native-coverage-*.profraw \
		-o build/native-coverage.profdata
	@llvm-cov export build/injector_production_host_test \
		-object build/implant_production_host_test \
		-instr-profile=build/native-coverage.profdata \
		> build/native-coverage.json
	@node tools/check-native-coverage.ts build/native-coverage.json
	@llvm-cov report build/injector_production_host_test \
		-object build/implant_production_host_test \
		-instr-profile=build/native-coverage.profdata \
		-ignore-filename-regex='(_test\\.(c|cpp)|/third_party/|/usr/|/opt/)'

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
	if [ "$$missing" -ne 0 ]; then \
		echo "Missing $$missing tool(s). Run \`make init\` and re-run." >&2; \
		exit 1; \
	fi; \
	test "$$(cargo ndk --version)" = "cargo-ndk $(CARGO_NDK_VERSION)" || { \
		echo "cargo-ndk version differs; require $(CARGO_NDK_VERSION)" >&2; \
		exit 1; \
	}; \
	$(MAKE) --no-print-directory check-ndk; \
	echo "All required tools present."

# ELF release gate: every artifact must be free of debug sections, be PIE
# (ET_DYN), carry GNU_RELRO and a non-executable GNU_STACK, and dynamic
# artifacts must bind immediately (BIND_NOW). voboost-selinux is checked as a
# non-PIE static executable (see build-selinux) with no shared-library
# dependencies. Requires NDK r29.
check-elf-hardening:
	@test -n "$(NDK_HOME)" || { echo "check-elf-hardening: ANDROID_NDK_HOME not set" >&2; exit 1; }
	NDK_HOME="$(NDK_HOME)" node tools/check-elf-hardening.ts
	@! strings target/aarch64-linux-android/release/voboost-install | grep -Fqx 'VOBOOST_EMULATOR_SELINUX_SKIP_V1' || \
		{ echo "check-elf-hardening: production installer contains emulator skip profile" >&2; exit 1; }
	@! strings target/aarch64-linux-android/release/voboost-daemon | grep -Fqx 'VOBOOST_EMULATOR_DAEMON_SELINUX_SKIP_V1' || \
		{ echo "check-elf-hardening: production daemon contains emulator skip profile" >&2; exit 1; }
	@! strings target/aarch64-linux-android/release/voboost-uninstall | grep -Fqx 'VOBOOST_EMULATOR_UNINSTALL_SELINUX_SKIP_V1' || \
		{ echo "check-elf-hardening: production uninstaller contains emulator skip profile" >&2; exit 1; }
	@! strings target/aarch64-linux-android/release/voboost-uninstall | grep -Fqx 'VOBOOST_EMULATOR_UNINSTALL_MOUNT_ADAPTER_V1' || \
		{ echo "check-elf-hardening: production uninstaller contains emulator mount adapter" >&2; exit 1; }
	@! strings target/aarch64-linux-android/release/voboost-restore | grep -Fqx 'VOBOOST_EMULATOR_RESTORE_SELINUX_SKIP_V1' || \
		{ echo "check-elf-hardening: production restore contains emulator skip profile" >&2; exit 1; }

test-release-elf: check-elf-hardening

# Cross-compile the full new stack for Android: the native artifacts (injector
# libinjector.a + implant libimplant.so per ABI) via ndk-build, and both runtime
# ELFs via cargo-ndk (aarch64-linux-android). Requires ANDROID_NDK_HOME (NDK r29)
# and cargo-ndk. Delegates to build-new. Fails early if the
# NDK is unset or the toolchain is not found (release-verification contract).
build-android:
	$(MAKE) --no-print-directory check-role-public-keys
	$(MAKE) --no-print-directory build-new build-selinux
	$(MAKE) --no-print-directory test-daemon-versionless-reproducible
	$(MAKE) --no-print-directory test-release-elf
	$(MAKE) --no-print-directory test-prepare-beta1-unsigned
	@echo "build-android: full new-stack cross-build complete"

test-prepare-beta1-unsigned:
	@test -n "$(NDK_HOME)" || { echo "test-prepare-beta1-unsigned: ANDROID_NDK_HOME not set" >&2; exit 1; }
	ANDROID_NDK_HOME="$(NDK_HOME)" node tools/test-prepare-beta1-unsigned.ts

check-role-public-keys:
	@for pair in \
		"agent-catalog|$(AGENT_CATALOG_PUBLIC_KEY_PEM)" \
		"release-catalog|$(RELEASE_CATALOG_PUBLIC_KEY_PEM)" \
		"restore|$(RESTORE_PUBLIC_KEY_PEM)" \
		"native-executable|$(NATIVE_EXECUTABLE_PUBLIC_KEY_PEM)"; do \
		role=$${pair%%|*}; key=$${pair#*|}; \
		[ -n "$$key" ] && [ -f "$$key" ] || { \
			echo "check-role-public-keys: $$role public key is missing" >&2; exit 2; \
		}; \
		openssl pkey -pubin -in "$$key" -text -noout 2>/dev/null | \
			grep -q '^ED25519 Public-Key:' || { \
			echo "check-role-public-keys: $$role public key is invalid" >&2; exit 2; \
		}; \
	done
	@tmp=$$(mktemp); trap 'rm -f "$$tmp"' EXIT; \
	for key in \
		"$(AGENT_CATALOG_PUBLIC_KEY_PEM)" \
		"$(RELEASE_CATALOG_PUBLIC_KEY_PEM)" \
		"$(RESTORE_PUBLIC_KEY_PEM)" \
		"$(NATIVE_EXECUTABLE_PUBLIC_KEY_PEM)"; do \
		openssl pkey -pubin -in "$$key" -outform DER 2>/dev/null | tail -c 32 | \
			openssl dgst -sha256 -r | awk '{print $$1}' >> "$$tmp"; \
	done; \
	[ "$$(sort -u "$$tmp" | wc -l | tr -d ' ')" = 4 ] || { \
		echo "check-role-public-keys: all four native-consumed product roots must differ" >&2; exit 2; \
	}

.PHONY: sign verify-sig

# Ed25519 detached signing/verification primitives used by product release tooling and tests.
# KEY=<pem> and FILE=<path-to-manifest> are passed by the caller.
sign:
	@test -n "$(KEY)"  || { echo "sign: KEY=<private.pem> required"  >&2; exit 2; }
	@test -n "$(FILE)" || { echo "sign: FILE=<manifest> required"    >&2; exit 2; }
	openssl pkeyutl -sign -inkey "$(KEY)" -rawin -in "$(FILE)" -out "$(FILE).sig"
	@echo "Signed $(FILE) -> $(FILE).sig"

.PHONY: sign-elf verify-elf-signature test-sign-elf

# Build a signed native payload: a single ELF file carrying an appended
# ed25519 signature in trailing bytes (VOBOOST magic + LE uint64 SIG_OFFSET
# + 64-byte raw ed25519 sig over the ELF). The kernel loads the ELF by its
# header and ignores the trailing 80 bytes at exec. Verification binds the
# payload to its native-executable role.
#
# Inputs are passed by the external product release caller or a disposable host test.
#   BINARY=<path to the stripped native ELF>   (required)
#   KEY=<path to the ed25519 private key PEM>   (required)
#   OUT=<output path>                           (default: build/voboost-ROLE)
#
# Signing goes through a temp file (not an openssl stdin pipe): the pipe mixes
# an error trail into the 64-byte signature. Mirrors test/fixtures/gen-fixtures.sh.
sign-elf:
	@test -n "$(BINARY)" || { echo "sign-elf: BINARY=<native-elf> required" >&2; exit 2; }
	@test -n "$(KEY)"     || { echo "sign-elf: KEY=<private.pem> required" >&2; exit 2; }
	@printf '%s\n' "$(ROLE)" | grep -Eq '^(daemon|inject|install|restore|uninstall|selinux)$$' || { echo "sign-elf: invalid ROLE" >&2; exit 2; }
	@test -f "$(BINARY)"  || { echo "sign-elf: BINARY $(BINARY) not found" >&2; exit 2; }
	@test -f "$(KEY)"     || { echo "sign-elf: KEY $(KEY) not found" >&2; exit 2; }
	@set -eu; out="$(OUT)"; [ -n "$$out" ] || out="$(BUILD_DIR)/voboost-$(ROLE)"; \
	mkdir -p "$$(dirname "$$out")"; \
	mkdir -p "$(BUILD_DIR)"; temporary=$$(mktemp -d "$(abspath $(BUILD_DIR))/signature.XXXXXX"); \
	trap 'rm -rf "$$temporary"' EXIT HUP INT TERM; \
	sigfile=$$temporary/signature; transcript=$$temporary/transcript; \
	node tools/release-tool.ts native-executable-transcript "$(ROLE)" "$(BINARY)" "$$transcript"; \
	openssl pkeyutl -sign -inkey "$(KEY)" -rawin -in "$$transcript" -out "$$sigfile"; \
	node tools/release-tool.ts append-signature "$$out" "$(BINARY)" "$$sigfile"
	@echo "Signed native payload built"

verify-elf-signature:
	@test -n "$(SIGNED)" || { echo "verify-elf-signature: SIGNED=<signed-elf> required" >&2; exit 2; }
	@test -n "$(KEY)" || { echo "verify-elf-signature: KEY=<public.pem> required" >&2; exit 2; }
	@printf '%s\n' "$(ROLE)" | grep -Eq '^(daemon|inject|install|restore|uninstall|selinux)$$' || { echo "verify-elf-signature: invalid ROLE" >&2; exit 2; }
	@test -f "$(SIGNED)" && test -f "$(KEY)" || { echo "verify-elf-signature: input missing" >&2; exit 2; }
	@set -eu; mkdir -p "$(BUILD_DIR)"; \
	tmpdir=$$(mktemp -d "$(abspath $(BUILD_DIR))/signature-verify.XXXXXX"); trap 'rm -rf "$$tmpdir"' EXIT HUP INT TERM; \
	node tools/release-tool.ts extract-signature \
		"$(SIGNED)" "$$tmpdir/prefix" "$$tmpdir/signature"; \
	node tools/release-tool.ts native-executable-transcript "$(ROLE)" "$$tmpdir/prefix" "$$tmpdir/transcript"; \
	openssl pkeyutl -verify -pubin -inkey "$(KEY)" -rawin \
		-in "$$tmpdir/transcript" -sigfile "$$tmpdir/signature" >/dev/null

# Exercise the production signing target and verify the daemon-facing layout
# plus the Ed25519 signature using a disposable test identity.
test-sign-elf:
	@set -eu; mkdir -p "$(BUILD_DIR)"; \
	tmpdir=$$(mktemp -d "$(abspath $(BUILD_DIR))/signature-test.XXXXXX"); trap 'rm -rf "$$tmpdir"' EXIT HUP INT TERM; \
	openssl genpkey -algorithm ed25519 -out "$$tmpdir/private.pem"; \
	openssl pkey -in "$$tmpdir/private.pem" -pubout -out "$$tmpdir/public.pem"; \
	printf '\177ELFsign-elf-regression\n' > "$$tmpdir/input"; \
	for signed_role in daemon inject install restore uninstall selinux; do \
	  $(MAKE) --no-print-directory sign-elf ROLE="$$signed_role" BINARY="$$tmpdir/input" \
	    KEY="$$tmpdir/private.pem" OUT="$$tmpdir/signed-$$signed_role" >/dev/null; \
	  for verified_role in daemon inject install restore uninstall selinux; do \
	    if [ "$$signed_role" = "$$verified_role" ]; then \
	      $(MAKE) --no-print-directory verify-elf-signature ROLE="$$verified_role" \
	        SIGNED="$$tmpdir/signed-$$signed_role" KEY="$$tmpdir/public.pem"; \
	    else \
	      ! $(MAKE) --no-print-directory verify-elf-signature ROLE="$$verified_role" \
	        SIGNED="$$tmpdir/signed-$$signed_role" KEY="$$tmpdir/public.pem" >/dev/null 2>&1; \
	    fi; \
	  done; \
	done; \
	node tools/release-tool.ts verify-sign-layout daemon "$$tmpdir/input" "$$tmpdir/signed-daemon" \
		"$$tmpdir/public.pem" "$$tmpdir"
	@echo "test-sign-elf: appended signature layout and verification ok"

verify-sig:
	@test -n "$(KEY)"  || { echo "verify-sig: KEY=<public.pem> required" >&2; exit 2; }
	@test -n "$(FILE)" || { echo "verify-sig: FILE=<manifest> required"  >&2; exit 2; }
	openssl pkeyutl -verify -pubin -inkey "$(KEY)" -rawin -in "$(FILE)" -sigfile "$(FILE).sig"
	@echo "Verified $(FILE).sig against $(KEY)"

AGENT_CATALOG_PUBLIC_KEY_PEM ?= config/release-public.pem
RELEASE_CATALOG_PUBLIC_KEY_PEM ?= config/key-dev-public.pem
RESTORE_PUBLIC_KEY_PEM ?= config/key-dev-public.pem
NATIVE_EXECUTABLE_PUBLIC_KEY_PEM ?= config/key-dev-public.pem
INJECT_BUILD_ATTESTATION ?= build/voboost-inject.build-identity.json
INJECT_BUILD_ATTESTATION_OUT ?= build/voboost-inject.build-identity.json

# Produce a build-time correlation sidecar from the exact signed inject bytes.
# The raw32 identity marker is emitted by daemon/build.rs and consumed by the
# runtime fingerprint path, so this never infers the embedded key from a PEM.
attest-inject-build-identity:
	@test -n "$(INJECT)" || { echo "attest-inject-build-identity: INJECT=<signed-inject> required" >&2; exit 2; }
	@test -f "$(INJECT)" || { echo "attest-inject-build-identity: $(INJECT) missing" >&2; exit 2; }
	@test -f "$(AGENT_CATALOG_PUBLIC_KEY_PEM)" || { echo "attest-inject-build-identity: AGENT_CATALOG_PUBLIC_KEY_PEM=<public.pem> required" >&2; exit 2; }
	@mkdir -p "$$(dirname "$(INJECT_BUILD_ATTESTATION_OUT)")"
	@node tools/release-tool.ts attest-inject \
		"$(INJECT)" "$(AGENT_CATALOG_PUBLIC_KEY_PEM)" "$(INJECT_BUILD_ATTESTATION_OUT)"
	@$(MAKE) --no-print-directory verify-inject-build-attestation \
		INJECT="$(INJECT)" \
		AGENT_CATALOG_PUBLIC_KEY_PEM="$(AGENT_CATALOG_PUBLIC_KEY_PEM)" \
		INJECT_BUILD_ATTESTATION="$(INJECT_BUILD_ATTESTATION_OUT)"
	@echo "Wrote $(INJECT_BUILD_ATTESTATION_OUT)"

# Re-read all inputs instead of trusting the sidecar producer: one exact marker
# occurrence, canonical key bytes, signed-file trailer, size and SHA must agree.
verify-inject-build-attestation:
	@test -n "$(INJECT)" || { echo "verify-inject-build-attestation: INJECT=<signed-inject> required" >&2; exit 2; }
	@test -f "$(INJECT)" || { echo "verify-inject-build-attestation: $(INJECT) missing" >&2; exit 2; }
	@test -f "$(AGENT_CATALOG_PUBLIC_KEY_PEM)" || { echo "verify-inject-build-attestation: AGENT_CATALOG_PUBLIC_KEY_PEM=<public.pem> required" >&2; exit 2; }
	@test -f "$(INJECT_BUILD_ATTESTATION)" || { echo "verify-inject-build-attestation: INJECT_BUILD_ATTESTATION=<json> required" >&2; exit 2; }
	@node tools/release-tool.ts verify-inject-attestation \
		"$(INJECT)" "$(AGENT_CATALOG_PUBLIC_KEY_PEM)" "$(INJECT_BUILD_ATTESTATION)"

# Cross-product authoring gate. The app workflow must already have produced a
# final APK; this independently correlates its exact fingerprint asset and
# signed catalog with the verified signed-inject build identity.
verify-product-agent-catalog-authority:
	@test -n "$(APP_APK)" && [ -f "$(APP_APK)" ] || { echo "verify-product-agent-catalog-authority: APP_APK=<final.apk> required" >&2; exit 2; }
	@$(MAKE) --no-print-directory verify-inject-build-attestation \
		INJECT="$(INJECT)" \
		AGENT_CATALOG_PUBLIC_KEY_PEM="$(AGENT_CATALOG_PUBLIC_KEY_PEM)" \
		INJECT_BUILD_ATTESTATION="$(INJECT_BUILD_ATTESTATION)"
	@node tools/release-tool.ts verify-apk-authority \
		"$(APP_APK)" "$(AGENT_CATALOG_PUBLIC_KEY_PEM)" "$(INJECT_BUILD_ATTESTATION)"

# Mandatory cross-repository producer gate. Callers must supply the exact
# signed outputs and public key from the producer build; missing inputs fail.
verify-producer-agent-catalog:
	@test -n "$(PRODUCER_AGENT_CATALOG)" && [ -f "$(PRODUCER_AGENT_CATALOG)" ] || { echo "verify-producer-agent-catalog: PRODUCER_AGENT_CATALOG=<agents.json> required" >&2; exit 2; }
	@test -n "$(PRODUCER_AGENT_CATALOG_SIG)" && [ -f "$(PRODUCER_AGENT_CATALOG_SIG)" ] || { echo "verify-producer-agent-catalog: PRODUCER_AGENT_CATALOG_SIG=<agents.sig> required" >&2; exit 2; }
	@test -n "$(PRODUCER_AGENT_CATALOG_PUBLIC_KEY_PEM)" && [ -f "$(PRODUCER_AGENT_CATALOG_PUBLIC_KEY_PEM)" ] || { echo "verify-producer-agent-catalog: PRODUCER_AGENT_CATALOG_PUBLIC_KEY_PEM=<public.pem> required" >&2; exit 2; }
	@cargo run --quiet --manifest-path daemon/Cargo.toml \
		--bin voboost-producer-catalog-verifier -- \
		"$(abspath $(PRODUCER_AGENT_CATALOG))" \
		"$(abspath $(PRODUCER_AGENT_CATALOG_SIG))" \
		"$(abspath $(PRODUCER_AGENT_CATALOG_PUBLIC_KEY_PEM))"

test-inject-build-attestation:
	@tmpdir=$$(mktemp -d); trap 'rm -rf "$$tmpdir"' EXIT; \
	openssl genpkey -algorithm ed25519 -out "$$tmpdir/a-private.pem" >/dev/null 2>&1; \
	openssl pkey -in "$$tmpdir/a-private.pem" -pubout -out "$$tmpdir/a-public.pem"; \
	openssl genpkey -algorithm ed25519 -out "$$tmpdir/b-private.pem" >/dev/null 2>&1; \
	openssl pkey -in "$$tmpdir/b-private.pem" -pubout -out "$$tmpdir/b-public.pem"; \
	node tools/release-tool.ts make-fixture-inject "$$tmpdir/inject" "$$tmpdir/a-public.pem"; \
	$(MAKE) --no-print-directory attest-inject-build-identity \
		INJECT="$$tmpdir/inject" AGENT_CATALOG_PUBLIC_KEY_PEM="$$tmpdir/a-public.pem" \
		INJECT_BUILD_ATTESTATION_OUT="$$tmpdir/attestation.json" >/dev/null; \
	$(MAKE) --no-print-directory verify-inject-build-attestation \
		INJECT="$$tmpdir/inject" AGENT_CATALOG_PUBLIC_KEY_PEM="$$tmpdir/a-public.pem" \
		INJECT_BUILD_ATTESTATION="$$tmpdir/attestation.json"; \
	printf '{"schemaVersion":1}\n' > "$$tmpdir/catalog.json"; \
	openssl pkeyutl -sign -inkey "$$tmpdir/a-private.pem" -rawin -in "$$tmpdir/catalog.json" -out "$$tmpdir/a.sig"; \
	openssl pkeyutl -sign -inkey "$$tmpdir/b-private.pem" -rawin -in "$$tmpdir/catalog.json" -out "$$tmpdir/b.sig"; \
	node tools/release-tool.ts make-authority-apks "$$tmpdir"; \
	$(MAKE) --no-print-directory verify-product-agent-catalog-authority \
		APP_APK="$$tmpdir/a.apk" INJECT="$$tmpdir/inject" \
		AGENT_CATALOG_PUBLIC_KEY_PEM="$$tmpdir/a-public.pem" \
		INJECT_BUILD_ATTESTATION="$$tmpdir/attestation.json"; \
	! $(MAKE) --no-print-directory verify-product-agent-catalog-authority \
		APP_APK="$$tmpdir/asset-b.apk" INJECT="$$tmpdir/inject" \
		AGENT_CATALOG_PUBLIC_KEY_PEM="$$tmpdir/a-public.pem" \
		INJECT_BUILD_ATTESTATION="$$tmpdir/attestation.json" >/dev/null 2>&1; \
	! $(MAKE) --no-print-directory verify-product-agent-catalog-authority \
		APP_APK="$$tmpdir/signature-b.apk" INJECT="$$tmpdir/inject" \
		AGENT_CATALOG_PUBLIC_KEY_PEM="$$tmpdir/a-public.pem" \
		INJECT_BUILD_ATTESTATION="$$tmpdir/attestation.json" >/dev/null 2>&1; \
	! $(MAKE) --no-print-directory verify-inject-build-attestation \
		INJECT="$$tmpdir/inject" AGENT_CATALOG_PUBLIC_KEY_PEM="$$tmpdir/b-public.pem" \
		INJECT_BUILD_ATTESTATION="$$tmpdir/attestation.json" >/dev/null 2>&1; \
	cp "$$tmpdir/inject" "$$tmpdir/stale-sha-inject"; \
	node tools/release-tool.ts mutate-byte "$$tmpdir/stale-sha-inject"; \
	! $(MAKE) --no-print-directory verify-inject-build-attestation \
		INJECT="$$tmpdir/stale-sha-inject" AGENT_CATALOG_PUBLIC_KEY_PEM="$$tmpdir/a-public.pem" \
		INJECT_BUILD_ATTESTATION="$$tmpdir/attestation.json" >/dev/null 2>&1; \
	cp "$$tmpdir/inject" "$$tmpdir/stale-size-inject"; \
	node tools/release-tool.ts mutate-size "$$tmpdir/stale-size-inject"; \
	! $(MAKE) --no-print-directory verify-inject-build-attestation \
		INJECT="$$tmpdir/stale-size-inject" AGENT_CATALOG_PUBLIC_KEY_PEM="$$tmpdir/a-public.pem" \
		INJECT_BUILD_ATTESTATION="$$tmpdir/attestation.json" >/dev/null 2>&1; \
	cp "$$tmpdir/inject" "$$tmpdir/duplicate-inject"; \
	node tools/release-tool.ts duplicate-marker "$$tmpdir/duplicate-inject"; \
	! $(MAKE) --no-print-directory verify-inject-build-attestation \
		INJECT="$$tmpdir/duplicate-inject" AGENT_CATALOG_PUBLIC_KEY_PEM="$$tmpdir/a-public.pem" \
		INJECT_BUILD_ATTESTATION="$$tmpdir/attestation.json" >/dev/null 2>&1

# Device zone installation (installation spec). Run ON-DEVICE via
# `adb shell su 0 make device-provision` (requires root). Creates the root
# zone /data/voboost/ with root-owned logs/, run/, state/, payload/ and
# generations/. The only app-owned child is generations/next; runtime IPC uses
# anonymous pipes and no shared directory.
# Idempotent. SELinux labels are applied by restorecon after file_contexts is
# installed (device-init-hook); labels are not set here.
ZONE ?= /data/voboost
APP_DATA_DIR ?= /data/user/0/ru.voboost
device-provision:
	@mkdir -p $(ZONE)/logs $(ZONE)/run $(ZONE)/state $(ZONE)/payload \
	  $(ZONE)/generations $(ZONE)/generations/quarantine
	@chown root:root $(ZONE) $(ZONE)/logs $(ZONE)/run $(ZONE)/state \
	  $(ZONE)/payload $(ZONE)/generations $(ZONE)/generations/quarantine
	@chmod 711 $(ZONE) $(ZONE)/generations
	@chmod 700 $(ZONE)/logs $(ZONE)/run $(ZONE)/state $(ZONE)/payload \
	  $(ZONE)/generations/quarantine
	@if [ -d "$(APP_DATA_DIR)" ]; then \
	  app_uid=$$(stat -c %u "$(APP_DATA_DIR)"); \
	  app_gid=$$(stat -c %g "$(APP_DATA_DIR)"); \
	  mkdir -p "$(ZONE)/generations/next"; \
	  chown "$$app_uid:$$app_gid" "$(ZONE)/generations/next"; \
	  chmod 700 "$(ZONE)/generations/next"; \
	else \
	  echo "device-provision: generations/next skipped; install ru.voboost first"; \
	fi
	@echo "device-provision: zone $(ZONE) ready (logs/run/state/payload/generations)"

# Install the daemon init service on-device (installation spec).
# Run ON-DEVICE via `adb shell su 0 make device-init-hook` (requires root,
# /system remounted RW). SELinux source fragments under selinux/ MUST already
# be compiled into the firmware policy; copying a .te file cannot load policy.
# The target fails closed if restorecon cannot produce the dedicated exec label.
RC_DIR ?= /system/etc/init
device-init-hook:
	@test -w "$(RC_DIR)" || { echo "device-init-hook: $(RC_DIR) not writable (remount /system RW as root)" >&2; exit 2; }
	@cp config/voboost.rc $(RC_DIR)/voboost.rc
	@restorecon -RF $(ZONE)
	@if [ -d "$(APP_DATA_DIR)" ]; then \
	  restorecon -RF "$(APP_DATA_DIR)"; \
	fi
	@ls -Z $(ZONE)/voboost-daemon | grep -q 'voboost_exec' || { \
	  echo "device-init-hook: firmware SELinux policy is not integrated" >&2; exit 2; \
	}
	@echo "device-init-hook: init service installed; activation waits for natural boot"

# ===========================================================================
# Rust daemon + C injector + C++ implant (ptrace)
# These targets build the new code: the native artifacts (ndk-build) and the
# Rust daemon (cargo-ndk).
# (release-verification); `make build-android` now delegates to build-new.
# ===========================================================================

# NDK path — required for native builds (C/C++). (Also defined at the top of
# this Makefile; kept here for proximity to the native targets.)
NDK_BUILD ?= $(NDK_HOME)/ndk-build
NDK_HOST_TAG ?= $(if $(filter Darwin,$(shell uname -s)),darwin-x86_64,linux-x86_64)
NDK_TOOLCHAIN ?= $(NDK_HOME)/toolchains/llvm/prebuilt/$(NDK_HOST_TAG)
NDK_CLANG ?= $(NDK_TOOLCHAIN)/bin/clang
NDK_SYSROOT ?= $(NDK_TOOLCHAIN)/sysroot
PREBUILT_DIR ?= $(CURDIR)/prebuilt
REPRO_SOURCE_PREFIX ?= /src/voboost-inject
REPRO_CFLAGS := -ffile-prefix-map=$(abspath .)=$(REPRO_SOURCE_PREFIX) -ffile-prefix-map=$(CURDIR)/build/third-party-source=$(REPRO_SOURCE_PREFIX)/third_party -fdebug-prefix-map=$(abspath .)=$(REPRO_SOURCE_PREFIX) -fmacro-prefix-map=$(abspath .)=$(REPRO_SOURCE_PREFIX)
CARGO_SOURCE_HOME := $(if $(CARGO_HOME),$(CARGO_HOME),$(HOME)/.cargo)
# Standard-library panic locations can retain the local rust-src installation path.
RUST_SYSROOT := $(shell rustc --print sysroot)
RUST_REMAP_FLAGS := --remap-path-prefix=$(abspath .)=$(REPRO_SOURCE_PREFIX) --remap-path-prefix=$(CARGO_SOURCE_HOME)=/rust/cargo --remap-path-prefix=$(RUST_SYSROOT)=/rust/toolchain
RUST_ANDROID_FLAGS := $(RUST_REMAP_FLAGS) -D warnings

# Native ABIs the daemon carries; both are product-manifest inputs.
NATIVE_ABIS ?= arm64-v8a armeabi-v7a

# Third-party (Dobby + LSPlant) build inputs/outputs.
THIRD_PARTY_DIR ?= $(CURDIR)/third_party
NATIVE_BUILD_SOURCE := $(CURDIR)/build/third-party-source
THIRD_PARTY_BUILD ?= $(BUILD_DIR)/third_party
CMAKE_TOOLCHAIN ?= $(NDK_HOME)/build/cmake/android.toolchain.cmake
CMAKE ?= cmake
# The gitlinks pin reachable upstream Dobby 5dfc854 and LSPlant a96c797.
# Repository-owned, SHA-pinned patches add the NDK r29/c++_static compatibility
# changes before compilation. Source preparation accepts only the clean pinned
# checkout or the byte-exact patched state.
PATCHES_DIR ?= $(CURDIR)/patches

# ---- build third-party natives from source (Dobby + LSPlant) ----
# Wired CMake build of the LSPlant/Dobby git submodules into prebuilt/<abi>/.
# This replaces the externally-built prebuilts (release-verification requires
# c++_static + built-from-source; the prior prebuilts linked libc++_shared.so,
# which conflicts with the in-process system libc++ on Android 9).
#
# LSPlant: built from source for BOTH ABIs (C++23 modules need Ninja; -flto off;
# LOG_DISABLED at dir scope; c++_static via the NDK toolchain, NOT
# -DLSPLANT_STANDALONE=ON which calls find_package(cxx) missing in NDK r29).
#
# Dobby: built from source for arm64-v8a. armeabi-v7a is NOT built here. The
# pinned 5dfc854 gitlink retains the upstream ARM breakage (the "Refactor? Yes"
# commits removed source/MemoryAllocator/CodeBuffer/code_buffer_arm.h but left
# dangling includes; arm_inst_t/thumb{1,2}_inst_t typedefs no longer resolve).
# The armeabi-v7a/libdobby.a is kept as a committed prebuilt fallback until the
# upstream armv7 port is restored or reimplemented. The committed fallback and
# its provenance are checked by release-verification. arm64-v8a
# is fully built from source.
build-third-party: test-third-party-source-contract
	@test -n "$(NDK_HOME)" || { echo "build-third-party: ANDROID_NDK_HOME not set" >&2; exit 1; }
	@test -f "$(CMAKE_TOOLCHAIN)" || { echo "build-third-party: toolchain not found at $(CMAKE_TOOLCHAIN)" >&2; exit 1; }
	@command -v ninja >/dev/null 2>&1 || { echo "build-third-party: ninja not found (LSPlant C++23 modules need it)" >&2; exit 1; }
	@mkdir -p $(PREBUILT_DIR)
	@node tools/prepare-native-third-party-source.ts --apply
	@fresh() { \
	  test "$$(cat "$$1/toolchain.path" 2>/dev/null)" = "$(CMAKE_TOOLCHAIN)" \
	    || printf '%s' --fresh; \
	}; \
	for abi in $(NATIVE_ABIS); do \
	  echo "build-third-party: [$${abi}] Dobby (from source)"; \
	  $(CMAKE) $$(fresh "$(THIRD_PARTY_BUILD)/$${abi}/dobby") -S $(NATIVE_BUILD_SOURCE)/dobby -B $(THIRD_PARTY_BUILD)/$${abi}/dobby \
	    -DCMAKE_TOOLCHAIN_FILE=$(CMAKE_TOOLCHAIN) \
	    -DANDROID_ABI=$${abi} -DANDROID_PLATFORM=android-28 \
	    -DANDROID_STL=c++_static -DCMAKE_BUILD_TYPE=Release \
	    -DCMAKE_C_FLAGS="$(REPRO_CFLAGS)" -DCMAKE_CXX_FLAGS="$(REPRO_CFLAGS)" \
	    -DPlugin.SymbolResolver=ON >/dev/null \
	    || { echo "build-third-party: Dobby configure failed for $${abi}" >&2; exit 1; }; \
	  printf '%s\n' "$(CMAKE_TOOLCHAIN)" > "$(THIRD_PARTY_BUILD)/$${abi}/dobby/toolchain.path"; \
	  if [ "$${abi}" = "armeabi-v7a" ]; then \
	    echo "build-third-party: [$${abi}] Dobby from source not supported (upstream armv7 port broken); using committed prebuilt fallback"; \
	  else \
	    $(CMAKE) --build $(THIRD_PARTY_BUILD)/$${abi}/dobby --target dobby_static -j >/dev/null \
	      || { echo "build-third-party: Dobby build failed for $${abi}" >&2; exit 1; }; \
	    mkdir -p $(PREBUILT_DIR)/$${abi}; \
	    cp $(THIRD_PARTY_BUILD)/$${abi}/dobby/libdobby.a $(PREBUILT_DIR)/$${abi}/libdobby.a; \
	    echo "build-third-party: [$${abi}] libdobby.a <- source"; \
	  fi; \
	  echo "build-third-party: [$${abi}] LSPlant (from source, Ninja)"; \
	  $(CMAKE) $$(fresh "$(THIRD_PARTY_BUILD)/$${abi}/lsplant") -G Ninja -S $(NATIVE_BUILD_SOURCE)/lsplant/lsplant/src/main/jni \
	    -B $(THIRD_PARTY_BUILD)/$${abi}/lsplant \
	    -DCMAKE_TOOLCHAIN_FILE=$(CMAKE_TOOLCHAIN) \
	    -DANDROID_ABI=$${abi} -DANDROID_PLATFORM=android-28 \
	    -DANDROID_STL=c++_static -DLSPLANT_BUILD_SHARED=OFF \
	    -DCMAKE_C_FLAGS="$(REPRO_CFLAGS)" -DCMAKE_CXX_FLAGS="$(REPRO_CFLAGS)" \
	    -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF -DCMAKE_BUILD_TYPE=Release >/dev/null \
	    || { echo "build-third-party: LSPlant configure failed for $${abi}" >&2; exit 1; }; \
	  printf '%s\n' "$(CMAKE_TOOLCHAIN)" > "$(THIRD_PARTY_BUILD)/$${abi}/lsplant/toolchain.path"; \
	  $(CMAKE) --build $(THIRD_PARTY_BUILD)/$${abi}/lsplant --target lsplant_static -j >/dev/null \
	    || { echo "build-third-party: LSPlant build failed for $${abi}" >&2; exit 1; }; \
	  mkdir -p $(PREBUILT_DIR)/$${abi}; \
	  cp $(THIRD_PARTY_BUILD)/$${abi}/lsplant/liblsplant_static.a $(PREBUILT_DIR)/$${abi}/liblsplant_static.a; \
	  cp $(THIRD_PARTY_BUILD)/$${abi}/lsplant/external/dex_builder/libdex_builder_static.a $(PREBUILT_DIR)/$${abi}/libdex_builder_static.a; \
	  echo "build-third-party: [$${abi}] static LSPlant and dex_builder <- source"; \
	done
	@echo "build-third-party: done"

test-armv7-dobby-prebuilt:
	@node tools/test-armv7-dobby-prebuilt.ts

test-third-party-source-contract: test-native-exports
	@node tools/test-third-party-source-contract.ts

.PHONY: test-dobby-code-patch
test-dobby-code-patch:
	@node tools/test-dobby-code-patch.ts

# ---- c++_static gate (release-verification invariant) ----
# The implant contains LSPlant and one static C++ runtime. Reject a dependency
# on libc++_shared.so and require the exact release entrypoints for each ABI.
READELF ?= $(NDK_TOOLCHAIN)/bin/llvm-readelf
check-prebuilt:
	@test -n "$(NDK_HOME)" || { echo "check-prebuilt: ANDROID_NDK_HOME not set" >&2; exit 1; }
	@node tools/check-prebuilt.ts --readelf "$(READELF)"

.PHONY: test-built-native-payload test-native-exports
test-built-native-payload: check-prebuilt

test-native-exports:
	@node --test tools/native-exports.test.ts

# ---- build the C injector (libinjector.a) ----
# A static archive linked into the Rust daemon via build.rs FFI.
# APP_PLATFORM/APP_ABI/APP_STL are passed on the command line: NDK r29 does not
# reliably pick up Application.mk via APP_APPLICATION_MK (it defaults to
# android-21, which hides process_vm_readv/writev — API 23+), so the command
# line is authoritative. Application.mk stays for IDEs/docs.
build-injector:
	@test -n "$(NDK_HOME)" || { echo "build-injector: ANDROID_NDK_HOME not set" >&2; exit 1; }
	@echo "build-injector: compiling production injector for both supported ABIs"
	cd injector && $(NDK_BUILD) NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=Android.mk \
		APP_PLATFORM=android-28 APP_ABI="arm64-v8a armeabi-v7a" APP_STL=none \
		APP_CFLAGS="$(REPRO_CFLAGS)" APP_CPPFLAGS="$(REPRO_CFLAGS)"
	@echo "build-injector: done -> injector/obj/local/{arm64-v8a,armeabi-v7a}/libinjector.a"

# ---- host unit-tests for pure ELF and proc-maps parsers ----
# Runs the ELF parser against real linker64/linker fixtures and separately
# checks exact canonical linker pathname recognition plus allocation/range
# bounds without ptrace or a device. Silent on success (codestyle).
HOST_CC ?= cc
.PHONY: test-injector-elf-parse test-injector-maps-parse test-injector-namespace-abi test-injector-ptrace-state \
	test-injector-thread-group test-injector-thread-group-stable-non-leader-input \
	test-injector-thread-group-unstable-inventory-cleanup \
	test-injector-thread-group-clone-cleanup \
		test-injector-thread-group-malformed-inventory test-injector-target-process-profile \
		test-injector-production-host

test-injector-elf-parse:
	@mkdir -p build
	@$(HOST_CC) -I injector -O2 -Wall -Wextra -Werror -std=c99 \
		injector/elf_parse.c injector/elf_parse_test.c -o build/elf_parse_test \
		|| { echo "test-injector-elf-parse: build failed" >&2; exit 1; }
	@./build/elf_parse_test

test-injector-maps-parse:
	@mkdir -p build
	@$(HOST_CC) -I injector -O2 -Wall -Wextra -Werror -std=c11 \
		injector/maps_parse.c injector/maps_parse_test.c -o build/maps_parse_test \
		|| { echo "test-injector-maps-parse: build failed" >&2; exit 1; }
	@./build/maps_parse_test

test-injector-namespace-abi:
	@mkdir -p build
	@$(HOST_CC) -I injector -O2 -Wall -Wextra -Werror -std=c11 \
		injector/namespace_abi.c injector/namespace_abi_test.c \
		-o build/namespace_abi_test \
		|| { echo "test-injector-namespace-abi: build failed" >&2; exit 1; }
	@./build/namespace_abi_test

test-injector-ptrace-state:
	@mkdir -p build
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -Iinjector \
		injector/ptrace_state.c injector/ptrace_state_test.c -o build/ptrace_state_test \
		|| { echo "test-injector-ptrace-state: build failed" >&2; exit 1; }
	@./build/ptrace_state_test

test-injector-target-process-profile:
	@mkdir -p build
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -Iinjector \
		injector/target_process_profile_test.c -o build/target_process_profile_test \
		|| { echo "test-injector-target-process-profile: build failed" >&2; exit 1; }
	@./build/target_process_profile_test

test-injector-thread-group:
	@mkdir -p build
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -Iinjector \
		injector/ptrace_recovery.c injector/thread_group.c injector/thread_group_test.c -o build/thread_group_test \
		|| { echo "test-injector-thread-group: build failed" >&2; exit 1; }
	@./build/thread_group_test

test-injector-thread-group-stable-non-leader-input: test-injector-thread-group-build
	@./build/thread_group_test stable_non_leader_input

test-injector-thread-group-unstable-inventory-cleanup: test-injector-thread-group-build
	@./build/thread_group_test unstable_inventory_fails_closed_and_cleans_attached_tasks

test-injector-thread-group-clone-cleanup: test-injector-thread-group-build
	@./build/thread_group_test clone_during_operation_is_captured_for_cleanup

test-injector-thread-group-malformed-inventory: test-injector-thread-group-build
	@./build/thread_group_test malformed_inventories_fail_before_attach

.PHONY: test-injector-thread-group-build
test-injector-thread-group-build:
	@mkdir -p build
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -Iinjector \
		injector/ptrace_recovery.c injector/thread_group.c injector/thread_group_test.c -o build/thread_group_test \
		|| { echo "test-injector-thread-group: build failed" >&2; exit 1; }

test-injector-production-host:
	@mkdir -p build
	@if [ "$$(uname -s)" = Linux ]; then \
		$(HOST_CC) -std=c11 -Wall -Wextra -Werror -pthread -Iinjector \
			injector/injector.c injector/remote_call.c injector/elf_resolve.c injector/elf_parse.c \
			injector/maps_parse.c injector/namespace_abi.c \
			injector/ptrace_recovery.c injector/ptrace_state.c \
			injector/thread_group.c injector/production_host_test.c \
			-o build/injector_production_host_test; \
		./build/injector_production_host_test; \
	else \
		$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
			injector/production_host_test.c -o build/injector_production_host_test; \
		./build/injector_production_host_test; status=$$?; test "$$status" -eq 77; \
	fi

test-injector: test-injector-diagnostic-time test-injector-pstate-admission test-injector-remote-call test-injector-managed-call test-injector-restore-stages test-injector-callee-frames
	@mkdir -p build
	@$(MAKE) --no-print-directory test-injector-elf-parse
	@$(MAKE) --no-print-directory test-injector-maps-parse
	@$(MAKE) --no-print-directory test-injector-namespace-abi
	@$(MAKE) --no-print-directory test-injector-ptrace-state
	@$(MAKE) --no-print-directory test-injector-target-process-profile
	@$(MAKE) --no-print-directory test-injector-thread-group
	@$(MAKE) --no-print-directory test-injector-ptrace-recovery
	@$(MAKE) --no-print-directory test-injector-production-host
	@$(CC) -std=c11 -Wall -Wextra -Werror -Iinjector \
		injector/init_result_test.c -o build/init_result_test
	@./build/init_result_test || { echo "test-injector: init result checks failed" >&2; exit 1; }
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		injector/ptrace_cleanup_integration_test.c \
		-o build/ptrace_cleanup_integration_test \
		|| { echo "test-injector: ptrace integration build failed" >&2; exit 1; }
	@if [ "$$(uname -s)" = Linux ]; then \
		./build/ptrace_cleanup_integration_test \
			|| { echo "test-injector: ptrace integration checks failed" >&2; exit 1; }; \
	else \
		./build/ptrace_cleanup_integration_test; status=$$?; \
		test "$$status" -eq 77 \
			|| { echo "test-injector: ptrace non-Linux skip contract failed" >&2; exit 1; }; \
	fi
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -pthread -Iinjector \
		injector/ptrace_state.c injector/ptrace_clone_integration_test.c \
		-o build/ptrace_clone_integration_test \
		|| { echo "test-injector: clone integration build failed" >&2; exit 1; }
	@if [ "$$(uname -s)" = Linux ]; then \
		./build/ptrace_clone_integration_test \
			|| { echo "test-injector: clone integration checks failed" >&2; exit 1; }; \
	else \
		./build/ptrace_clone_integration_test; status=$$?; \
		test "$$status" -eq 77 \
			|| { echo "test-injector: clone non-Linux skip contract failed" >&2; exit 1; }; \
	fi
	@echo "test-injector: elf_parse resolver checks ok"

.PHONY: test-injector-parent-death
test-injector-parent-death:
	@mkdir -p build
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		injector/ptrace_cleanup_integration_test.c \
		-o build/ptrace_cleanup_integration_test
	@if [ "$$(uname -s)" = Linux ]; then \
		./build/ptrace_cleanup_integration_test; \
	else \
		./build/ptrace_cleanup_integration_test; status=$$?; test "$$status" -eq 77; \
	fi

.PHONY: test-injector-ptrace-recovery
test-injector-ptrace-recovery:
	@mkdir -p build
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -Iinjector \
		injector/ptrace_recovery.c injector/ptrace_recovery_test.c \
		-o build/ptrace_recovery_test
	@./build/ptrace_recovery_test

# ---- host tests for implant bootstrap and transport ----
HOST_CXX ?= c++
HOST_CC ?= cc
test-implant: test-system-server-loader test-log-transport test-main-thread-snapshot-scope test-inline-hook-publication test-lsplant-stage-callback test-lsplant-backup-publication test-implant-downlink test-bootstrap-worker test-implant-symtab test-native-faults
	@mkdir -p build
	@$(HOST_CC) -std=c11 -I third_party/yyjson/src -Wall -Wextra -Werror \
		-c third_party/yyjson/src/yyjson.c -o build/yyjson.o
	@$(HOST_CXX) -std=c++20 -pthread -I implant -I third_party/yyjson/src \
		-Wall -Wextra -Werror implant/pipe_bootstrap_test.cpp build/yyjson.o \
		-o build/pipe_bootstrap_test
	@./build/pipe_bootstrap_test \
		|| { echo "test-implant: pipe bootstrap checks failed" >&2; exit 1; }
	@$(HOST_CXX) -std=c++20 -I implant -I third_party/yyjson/src -Wall -Wextra -Werror \
		implant/pipe_bootstrap_manifest_test.cpp build/yyjson.o \
		-o build/pipe_bootstrap_manifest_test \
		|| { echo "test-implant: pipe manifest test build failed" >&2; exit 1; }
	@./build/pipe_bootstrap_manifest_test \
		|| { echo "test-implant: pipe manifest checks failed" >&2; exit 1; }
	@$(HOST_CXX) -std=c++20 -I implant -Wall -Wextra -Werror \
		implant/bounded_elf_string_test.cpp -o build/bounded_elf_string_test \
		|| { echo "test-implant: bounded ELF string test build failed" >&2; exit 1; }
	@./build/bounded_elf_string_test \
		|| { echo "test-implant: bounded ELF string checks failed" >&2; exit 1; }
	@$(HOST_CXX) -std=c++20 -pthread -I implant -Wall -Wextra -Werror \
		implant/runtime_safety_test.cpp -o build/runtime_safety_test \
		|| { echo "test-implant: runtime safety test build failed" >&2; exit 1; }
	@./build/runtime_safety_test \
		|| { echo "test-implant: runtime safety checks failed" >&2; exit 1; }
	@$(HOST_CXX) -std=c++20 -I implant -Wall -Wextra -Werror \
		implant/downlink_watch_apply_test.cpp -o build/downlink_watch_apply_test \
		|| { echo "test-implant: downlink watch apply test build failed" >&2; exit 1; }
	@./build/downlink_watch_apply_test \
		|| { echo "test-implant: downlink watch apply checks failed" >&2; exit 1; }
	@$(HOST_CXX) -std=c++20 -pthread -I implant -Wall -Wextra -Werror \
		implant/state_reply_decode_test.cpp -o build/state_reply_decode_test \
		|| { echo "test-implant: state reply decode test build failed" >&2; exit 1; }
	@./build/state_reply_decode_test \
		|| { echo "test-implant: state reply decode checks failed" >&2; exit 1; }
	@$(MAKE) --no-print-directory test-implant-loader-probe
	@$(MAKE) --no-print-directory test-implant-production-host
	@! rg -n 'signal[[:space:]]*\([[:space:]]*SIGPIPE|(^|[^[:alnum:]_])write[[:space:]]*\([[:space:]]*(g_agent_log_fd|records\[1\])' \
		implant/implant.cpp \
		|| { echo "test-implant: global SIGPIPE or unsafe daemon-pipe write" >&2; exit 1; }
	@echo "test-implant: hostile bootstrap and production attachment seam checks ok"

test-implant-pipe-bootstrap:
	@mkdir -p build
	@$(HOST_CC) -std=c11 -I third_party/yyjson/src -Wall -Wextra -Werror \
		-c third_party/yyjson/src/yyjson.c -o build/yyjson.o
	@$(HOST_CXX) -std=c++20 -pthread -I implant -I third_party/yyjson/src \
		-Wall -Wextra -Werror implant/pipe_bootstrap_test.cpp build/yyjson.o \
		-o build/pipe_bootstrap_test
	@./build/pipe_bootstrap_test

.PHONY: test-implant-downlink
test-implant-downlink:
	@mkdir -p build
	@$(HOST_CC) -std=c11 -I third_party/yyjson/src -Wall -Wextra -Werror \
		-c third_party/yyjson/src/yyjson.c -o build/yyjson.o
	@$(HOST_CXX) -std=c++20 -I implant -I third_party/yyjson/src -Wall -Wextra -Werror \
		implant/downlink_watch_read_test.cpp build/yyjson.o -o build/downlink_watch_read_test
	@./build/downlink_watch_read_test
	@$(HOST_CXX) -std=c++20 -I implant -I third_party/yyjson/src -Wall -Wextra -Werror \
		implant/owned_intent_lane_test.cpp build/yyjson.o -o build/owned_intent_lane_test
	@./build/owned_intent_lane_test
	@$(HOST_CXX) -std=c++20 -I implant -I third_party/yyjson/src -Wall -Wextra -Werror \
		implant/vehicle_commands_test.cpp build/yyjson.o -o build/vehicle_commands_test
	@./build/vehicle_commands_test
	@$(HOST_CXX) -std=c++20 -I implant -Wall -Wextra -Werror \
		implant/cache_quiescence_ack_test.cpp -o build/cache_quiescence_ack_test
	@./build/cache_quiescence_ack_test
	@$(HOST_CXX) -std=c++20 -I implant -I third_party/yyjson/src -Wall -Wextra -Werror \
		implant/cache_maintenance_revision_test.cpp build/yyjson.o -o build/cache_maintenance_revision_test
	@./build/cache_maintenance_revision_test

test-implant-pipe-manifest:
	@mkdir -p build
	@$(HOST_CC) -std=c11 -I third_party/yyjson/src -Wall -Wextra -Werror \
		-c third_party/yyjson/src/yyjson.c -o build/yyjson.o
	@$(HOST_CXX) -std=c++20 -I implant -I third_party/yyjson/src -Wall -Wextra -Werror \
		implant/pipe_bootstrap_manifest_test.cpp build/yyjson.o \
		-o build/pipe_bootstrap_manifest_test
	@./build/pipe_bootstrap_manifest_test

test-implant-bounded-elf-string:
	@mkdir -p build
	@$(HOST_CXX) -std=c++20 -I implant -Wall -Wextra -Werror \
		implant/bounded_elf_string_test.cpp -o build/bounded_elf_string_test
	@./build/bounded_elf_string_test

test-implant-runtime-safety:
	@mkdir -p build
	@$(HOST_CXX) -std=c++20 -pthread -I implant -Wall -Wextra -Werror \
		implant/runtime_safety_test.cpp -o build/runtime_safety_test
	@./build/runtime_safety_test

# Loader-probe host fixtures run against a hand-built JNIEnv function table,
# so they need a JDK include tree but no JVM (regression for the 2026-09-14
# PathClassLoader.getName SIGABRT; see implant/loader_probe.h).
.PHONY: test-implant-loader-probe
test-implant-loader-probe:
	@mkdir -p build
	@if [ -n "$${JAVA_HOME:-}" ]; then java_home="$$JAVA_HOME"; \
	elif [ "$$(uname -s)" = Darwin ] && [ -x /usr/libexec/java_home ]; then \
		java_home=$$(/usr/libexec/java_home); \
	else \
		java_home="$$(dirname $$(dirname $$(command -v javac)))"; \
	fi; \
	test -n "$$java_home" && test -f "$$java_home/include/jni.h" \
		|| { echo "test-implant-loader-probe: JDK with jni.h required" >&2; exit 1; }; \
	includes="-I$$java_home/include"; \
	if [ "$$(uname -s)" = Darwin ]; then \
		includes="$$includes -I$$java_home/include/darwin"; \
	else \
		includes="$$includes -I$$java_home/include/linux"; \
	fi; \
	$(HOST_CXX) -std=c++20 -I implant $$includes -Wall -Wextra -Werror \
		implant/loader_probe_test.cpp -o build/loader_probe_test \
		|| { echo "test-implant: loader probe test build failed" >&2; exit 1; }; \
	./build/loader_probe_test \
		|| { echo "test-implant: loader probe checks failed" >&2; exit 1; }

.PHONY: test-implant-production-host
test-implant-production-host:
	@mkdir -p build
	@if [ "$$(uname -s)" = Linux ]; then \
		java_home="$${JAVA_HOME:-$$(dirname $$(dirname $$(readlink -f $$(command -v javac))))}"; \
		test -n "$$java_home" && test -f "$$java_home/include/jni.h" \
			|| { echo "test-implant-production-host: JAVA_HOME with jni.h required" >&2; exit 1; }; \
		$(HOST_CXX) -std=c++20 -pthread -DVOBOOST_IMPLANT_HOST_TEST \
			-Iimplant -Ithird_party/yyjson/src -I"$$java_home/include" -I"$$java_home/include/linux" \
			-Wall -Wextra -Werror implant/implant.cpp implant/production_host_test.cpp \
			build/yyjson.o -ldl -o build/implant_production_host_test; \
		./build/implant_production_host_test; \
	else \
		$(HOST_CXX) -std=c++20 -Wall -Wextra -Werror \
			implant/production_host_test.cpp -o build/implant_production_host_test; \
		./build/implant_production_host_test; status=$$?; test "$$status" -eq 77; \
	fi

test-injector-init-result:
	@mkdir -p build
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -Iinjector \
		injector/init_result_test.c -o build/init_result_test
	@./build/init_result_test

# ---- build the C++ implant (libimplant.so, per-ABI) ----
# The in-process loader. Both ABIs produced (the daemon selects at runtime).
# APP_PLATFORM/APP_ABI/APP_STL on the command line (see build-injector note).
build-implant:
	@test -n "$(NDK_HOME)" || { echo "build-implant: ANDROID_NDK_HOME not set" >&2; exit 1; }
	@echo "build-implant: building libimplant.so (C++, arm64-v8a + armeabi-v7a)"
	cd implant && $(NDK_BUILD) NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=Android.mk \
		APP_PLATFORM=android-28 APP_ABI="arm64-v8a armeabi-v7a" APP_STL=c++_static \
		APP_CFLAGS="$(REPRO_CFLAGS)" APP_CPPFLAGS="$(REPRO_CFLAGS)"
	@echo "build-implant: done -> implant/libs/{arm64-v8a,armeabi-v7a}/libimplant.so"

# ---- build all native artifacts (third-party + injector + implant) ----
# Third-party sources (LSPlant/Dobby) feed prebuilt/<abi>/ which the implant
# Android.mk consumes as a static Dobby archive. c++_static gate runs after the
# build to enforce the release-verification invariant (libc++_shared banned).
build-native: build-third-party build-injector build-implant check-prebuilt
	@echo "build-native: all native artifacts built"

# ---- build each Rust runtime independently (cargo-ndk, aarch64) ----
# Requires cargo-ndk $(CARGO_NDK_VERSION) from make init. -P 28 = API level 28
# (process_vm_readv/writev need API 23+; the daemon targets Android 9/API 28).
# Output lands in the workspace target/ (Cargo workspace), not daemon/target/.
build-inject: build-injector

build-daemon build-inject:
	@command -v cargo-ndk >/dev/null 2>&1 || { echo "$@: cargo-ndk not found (run make init)" >&2; exit 1; }
	@test -n "$(NDK_HOME)" || { echo "$@: ANDROID_NDK_HOME not set" >&2; exit 1; }
	@test -f "$(AGENT_CATALOG_PUBLIC_KEY_PEM)" || { echo "$@: AGENT_CATALOG_PUBLIC_KEY_PEM missing" >&2; exit 2; }
	@test -f "$(RELEASE_CATALOG_PUBLIC_KEY_PEM)" || { echo "$@: RELEASE_CATALOG_PUBLIC_KEY_PEM missing" >&2; exit 2; }
	@test -f "$(NATIVE_EXECUTABLE_PUBLIC_KEY_PEM)" || { echo "$@: NATIVE_EXECUTABLE_PUBLIC_KEY_PEM missing" >&2; exit 2; }
	@test -f "$(RESTORE_PUBLIC_KEY_PEM)" || { echo "$@: RESTORE_PUBLIC_KEY_PEM missing" >&2; exit 2; }
	@echo "$@: building $(patsubst build-%,voboost-%,$@) (Rust, aarch64-linux-android)"
	cd daemon && \
		VOBOOST_BUILD_TARGET="$(patsubst build-%,%,$@)" \
		VOBOOST_NATIVE_REGISTRY="$(if $(NATIVE_REGISTRY),$(abspath $(NATIVE_REGISTRY)))" \
		VOBOOST_AGENT_CATALOG_PUBLIC_KEY_PEM="$(abspath $(AGENT_CATALOG_PUBLIC_KEY_PEM))" \
		VOBOOST_RELEASE_CATALOG_PUBLIC_KEY_PEM="$(abspath $(RELEASE_CATALOG_PUBLIC_KEY_PEM))" \
		VOBOOST_NATIVE_EXECUTABLE_PUBLIC_KEY_PEM="$(abspath $(NATIVE_EXECUTABLE_PUBLIC_KEY_PEM))" \
		VOBOOST_RESTORE_PUBLIC_KEY_PEM="$(abspath $(RESTORE_PUBLIC_KEY_PEM))" \
		RUSTFLAGS="$(RUST_ANDROID_FLAGS)" \
		cargo ndk -t arm64-v8a -P 28 build --release --bin $(patsubst build-%,voboost-%,$@)
	@echo "$@: ready -> target/aarch64-linux-android/release/$(patsubst build-%,voboost-%,$@)"

build-uninstall:
	@command -v cargo-ndk >/dev/null 2>&1 || { echo "build-uninstall: cargo-ndk not found (run make init)" >&2; exit 1; }
	@test -n "$(NDK_HOME)" || { echo "build-uninstall: ANDROID_NDK_HOME not set" >&2; exit 1; }
	@test -f "$(NATIVE_EXECUTABLE_PUBLIC_KEY_PEM)" || { echo "build-uninstall: NATIVE_EXECUTABLE_PUBLIC_KEY_PEM missing" >&2; exit 2; }
	@test -f "$(RELEASE_CATALOG_PUBLIC_KEY_PEM)" || { echo "build-uninstall: RELEASE_CATALOG_PUBLIC_KEY_PEM missing" >&2; exit 2; }
	@test -f "$(RESTORE_PUBLIC_KEY_PEM)" || { echo "build-uninstall: RESTORE_PUBLIC_KEY_PEM missing" >&2; exit 2; }
	@printf '%s' "$(ANDROID_CERT_SHA256)" | grep -Eq '^[0-9a-f]{64}$$' || { echo "build-uninstall: ANDROID_CERT_SHA256 must be canonical lowercase SHA-256" >&2; exit 2; }
	@echo "build-uninstall: building voboost-uninstall (Rust, aarch64-linux-android)"
	# Discard only this target/package cache so prior release role keys can never
	# survive into the new executable.
	cargo clean -p voboost-uninstall --target aarch64-linux-android
	cd uninstall && \
		VOBOOST_NATIVE_EXECUTABLE_PUBLIC_KEY_PEM="$(abspath $(NATIVE_EXECUTABLE_PUBLIC_KEY_PEM))" \
		VOBOOST_RELEASE_CATALOG_PUBLIC_KEY_PEM="$(abspath $(RELEASE_CATALOG_PUBLIC_KEY_PEM))" \
		VOBOOST_RESTORE_PUBLIC_KEY_PEM="$(abspath $(RESTORE_PUBLIC_KEY_PEM))" \
		VOBOOST_ANDROID_CERT_SHA256="$(ANDROID_CERT_SHA256)" \
		RUSTFLAGS="$(RUST_ANDROID_FLAGS)" \
		cargo ndk -t arm64-v8a -P 28 build --release
	@echo "build-uninstall: done -> target/aarch64-linux-android/release/voboost-uninstall"

build-install:
	@command -v cargo-ndk >/dev/null 2>&1 || { echo "build-install: cargo-ndk not found (run make init)" >&2; exit 1; }
	@test -n "$(NDK_HOME)" || { echo "build-install: ANDROID_NDK_HOME not set" >&2; exit 1; }
	@test -f "$(NATIVE_EXECUTABLE_PUBLIC_KEY_PEM)" || { echo "build-install: NATIVE_EXECUTABLE_PUBLIC_KEY_PEM missing" >&2; exit 2; }
	@test -f "$(RESTORE_PUBLIC_KEY_PEM)" || { echo "build-install: RESTORE_PUBLIC_KEY_PEM missing" >&2; exit 2; }
	@test -f "$(AGENT_CATALOG_PUBLIC_KEY_PEM)" || exit 2
	@test -f "$(RELEASE_CATALOG_PUBLIC_KEY_PEM)" || exit 2
	cargo clean -p voboost-install --target aarch64-linux-android
	cd install && \
		VOBOOST_NATIVE_EXECUTABLE_PUBLIC_KEY_PEM="$(abspath $(NATIVE_EXECUTABLE_PUBLIC_KEY_PEM))" \
		VOBOOST_RESTORE_PUBLIC_KEY_PEM="$(abspath $(RESTORE_PUBLIC_KEY_PEM))" \
		VOBOOST_AGENT_CATALOG_PUBLIC_KEY_PEM="$(abspath $(AGENT_CATALOG_PUBLIC_KEY_PEM))" \
		VOBOOST_RELEASE_CATALOG_PUBLIC_KEY_PEM="$(abspath $(RELEASE_CATALOG_PUBLIC_KEY_PEM))" \
		RUSTFLAGS="$(RUST_ANDROID_FLAGS)" \
		cargo ndk -t arm64-v8a -P 28 build --release
	@echo "build-install: done -> target/aarch64-linux-android/release/voboost-install"

# ---- build everything (daemon + uninstall + native) ----
build-new: build-native build-daemon build-inject build-install build-uninstall build-restore
	@echo "build-new: all new-stack artifacts built"

# ---- SELinux program (/data/voboost/voboost-selinux) ----
# Early boot uses a signed policy transformation. The program is a static
# C binary (vendored libsepol + tweetnacl) executed by init before the daemon.
# Rules are GENERATED from selinux/voboost.te (single source of truth).
SEPOL_DIR      := $(NATIVE_BUILD_SOURCE)/libsepol
SEPOL_SRC      := $(addprefix $(SEPOL_DIR)/src/,$(notdir $(wildcard third_party/libsepol/src/*.c)))
SEPOL_CFLAGS   := -I$(SEPOL_DIR)/include -I$(SEPOL_DIR)/cil/include -I$(SEPOL_DIR)/src -DDARWIN -fcommon -fno-strict-aliasing
SEPOL_CFLAGS_TARGET := -I$(SEPOL_DIR)/include -I$(SEPOL_DIR)/cil/include -I$(SEPOL_DIR)/src -fcommon -fno-strict-aliasing
SELINUX_RELEASE_CFLAGS := -Oz -g0 -ffunction-sections -fdata-sections
SEPOL_HOST_LIB := build/host/libsepol.a
YYJSON_SRC      := third_party/yyjson/src/yyjson.c
YYJSON_CFLAGS   := -Ithird_party/yyjson/src
PUBKEY_HEX     = $(shell openssl pkey -pubin -in "$(NATIVE_EXECUTABLE_PUBLIC_KEY_PEM)" -outform DER 2>/dev/null | tail -c 32 | od -An -tx1 | tr -s ' ' '\n' | grep -v '^$$' | sed 's/^/0x/' | paste -sd, -)

.PHONY: gen-policy-rules prepare-libsepol-source build-selinux-host test-selinux test-selinux-rule-generation test-selinux-policy-inject test-selinux-policy-backup test-selinux-relabel-walk test-selinux-watchdog test-selinux-real-policy test-selinux-mls build-selinux sign-selinux build-restore test-restore test-built-restore sign-restore

prepare-libsepol-source:
	@node tools/prepare-libsepol-source.ts --apply

gen-policy-rules:
	node tools/gen-policy-rules.ts

$(SEPOL_HOST_LIB): prepare-libsepol-source
	@mkdir -p build/host
	@rm -f build/host/sepol_*.o
	@for src in $(SEPOL_SRC); do \
	  obj=build/host/sepol_$$(basename $${src%.c}).o; \
	  $(CC) -O2 $(SEPOL_CFLAGS) -c $$src -o $$obj || exit 1; \
	done
	$(AR) rcs $@ build/host/sepol_*.o

# Host build: signature/idiom checks and unit tests only (no policy files here).
build-selinux-host: NATIVE_EXECUTABLE_PUBLIC_KEY_PEM := config/release-public.pem
build-selinux-host: $(SEPOL_HOST_LIB) gen-policy-rules
	$(CC) -O2 -Iselinux $(SEPOL_CFLAGS) $(YYJSON_CFLAGS) \
	  -DEMBEDDED_PUBKEY_HEX="$(PUBKEY_HEX)" \
	  selinux/voboost-selinux.c selinux/policy_inject.c selinux/tweetnacl.c \
	  $(YYJSON_SRC) \
	  $(SEPOL_HOST_LIB) -o build/host/voboost-selinux

test-selinux: build-selinux-host
	test/selinux/run.sh

.PHONY: test-selinux-boot-source
test-selinux-boot-source: build-selinux-host
	$(CC) -O1 -w -Iselinux $(SEPOL_CFLAGS) $(YYJSON_CFLAGS) -DDARWIN -fcommon \
	  test/selinux/test_boot_policy.c selinux/policy_inject.c \
	  selinux/tweetnacl.c $(YYJSON_SRC) $(SEPOL_HOST_LIB) -o build/host/test_boot_policy
	@temporary=$$(mktemp -d); trap 'rm -rf "$$temporary"' EXIT HUP INT TERM; \
	  ./build/host/test_boot_policy "$$temporary/stock"

test-selinux-rule-generation:
	test/selinux/test_rule_generation.sh

test-selinux-label-contract:
	node tools/test-selinux-label-contract.ts

test-selinux-policy-inject: build-selinux-host
	$(CC) -O1 -Iselinux $(SEPOL_CFLAGS) -DDARWIN -fcommon \
		test/selinux/test_inject.c selinux/policy_inject.c \
		$(SEPOL_HOST_LIB) -o build/host/test_inject
	./build/host/test_inject

test-selinux-policy-backup: build-selinux-host
	$(CC) -O1 -w -Iselinux $(SEPOL_CFLAGS) $(YYJSON_CFLAGS) -DDARWIN -fcommon \
		test/selinux/test_policy_backup.c selinux/policy_inject.c \
		selinux/tweetnacl.c $(YYJSON_SRC) $(SEPOL_HOST_LIB) -o build/host/test_policy_backup
	./build/host/test_policy_backup

test-selinux-relabel-walk: build-selinux-host
	$(CC) -O1 -w -Iselinux $(SEPOL_CFLAGS) $(YYJSON_CFLAGS) -DDARWIN -fcommon \
		test/selinux/test_relabel_walk.c selinux/policy_inject.c \
		selinux/tweetnacl.c $(YYJSON_SRC) $(SEPOL_HOST_LIB) -o build/host/test_relabel_walk
	./build/host/test_relabel_walk

test-selinux-watchdog: build-selinux-host
	$(CC) -O1 -w -Iselinux $(SEPOL_CFLAGS) $(YYJSON_CFLAGS) \
		test/selinux/test_watchdog.c selinux/policy_inject.c \
		selinux/tweetnacl.c $(YYJSON_SRC) $(SEPOL_HOST_LIB) -o build/host/test_watchdog
	./build/host/test_watchdog

test-selinux-real-policy: $(SEPOL_HOST_LIB) gen-policy-rules
	@test -f test/selinux/fixtures/f0506h-free-09-chinese-6.0.3-policy-v30.bin
	@printf '%s  %s\n' \
	  5f08d74b7c2a3aad92f6f5b211e5e6a15d7fe006dd3af086517aea092a8dac25 \
	  test/selinux/fixtures/f0506h-free-09-chinese-6.0.3-policy-v30.bin | shasum -a 256 -c -
	$(CC) -O1 -w -Iselinux -I$(SEPOL_DIR)/include -I$(SEPOL_DIR)/src \
	  -DDARWIN -fcommon test/selinux/test_real_policy.c selinux/policy_inject.c \
	  build/host/libsepol.a -o build/host/test_real_policy
	./build/host/test_real_policy test/selinux/fixtures/f0506h-free-09-chinese-6.0.3-policy-v30.bin
	test/selinux/test_metadata_baseline.sh

test-selinux-mls: $(SEPOL_HOST_LIB) gen-policy-rules
	@test -f test/selinux/fixtures/f0506h-free-09-chinese-6.0.3-policy-v30.bin
	@printf '%s  %s\n' \
	  5f08d74b7c2a3aad92f6f5b211e5e6a15d7fe006dd3af086517aea092a8dac25 \
	  test/selinux/fixtures/f0506h-free-09-chinese-6.0.3-policy-v30.bin | shasum -a 256 -c -
	$(CC) -O1 -w -Iselinux -I$(SEPOL_DIR)/include -I$(SEPOL_DIR)/src \
	  -DDARWIN -fcommon test/selinux/test_mls_eval.c selinux/policy_inject.c \
	  build/host/libsepol.a -o build/host/test_mls_eval
	./build/host/test_mls_eval test/selinux/fixtures/f0506h-free-09-chinese-6.0.3-policy-v30.bin

# Android build: static ARM64 system program signed with role selinux.
# Linked as non-PIE -static (ET_EXEC, load-time relocation free): NDK r29
# bionic contains no static-PIE self-relocator, so a -static-pie image only
# runs on kernels that either load it at its link base or apply the ELF
# relocations themselves. The API 30 emulator kernel (android11-5.4 ranchu)
# does neither and SIGSEGVs during bionic __libc_init, before main. A non-PIE
# static image needs no relocations and runs on every supported kernel
# (verified on the API 30 emulator and on the f0506h Android 9 firmware).
build-selinux: prepare-libsepol-source gen-policy-rules
	@test -n "$(NDK_HOME)" || { echo "build-selinux: NDK_HOME not set" >&2; exit 1; }
	@test -f "$(NATIVE_EXECUTABLE_PUBLIC_KEY_PEM)" || { echo "build-selinux: NATIVE_EXECUTABLE_PUBLIC_KEY_PEM missing" >&2; exit 2; }
	@mkdir -p build/selinux/arm64-v8a
	@objs=""; \
	for src in $(SEPOL_SRC) selinux/policy_inject.c selinux/tweetnacl.c $(YYJSON_SRC); do \
	  obj=build/selinux/arm64-v8a/$$(basename $${src%.c}).o; \
	  $(NDK_CLANG) --target=aarch64-linux-android28 $(SELINUX_RELEASE_CFLAGS) $(REPRO_CFLAGS) $(SEPOL_CFLAGS_TARGET) $(YYJSON_CFLAGS) -Iselinux \
	    -DEMBEDDED_PUBKEY_HEX="$(PUBKEY_HEX)" -c $$src -o $$obj || exit 1; \
	  objs="$$objs $$obj"; \
	done; \
	$(NDK_CLANG) --target=aarch64-linux-android28 $(SELINUX_RELEASE_CFLAGS) -static -Wl,--strip-all -Wl,--gc-sections $(REPRO_CFLAGS) $(SEPOL_CFLAGS_TARGET) $(YYJSON_CFLAGS) -Iselinux \
	  -DEMBEDDED_PUBKEY_HEX="$(PUBKEY_HEX)" \
	  -o build/selinux/arm64-v8a/voboost-selinux.tmp.$$$$ \
	  selinux/voboost-selinux.c $$objs || { rm -f build/selinux/arm64-v8a/voboost-selinux.tmp.$$$$; exit 1; }; \
	mv -f build/selinux/arm64-v8a/voboost-selinux.tmp.$$$$ build/selinux/arm64-v8a/voboost-selinux || exit 1; \
	echo "build-selinux: arm64-v8a done"

sign-selinux:
	@test -f build/selinux/arm64-v8a/voboost-selinux || { echo "sign-selinux: run build-selinux first" >&2; exit 2; }
	@test -f "$(SIGNING_KEY)" || { echo "sign-selinux: SIGNING_KEY=<selinux-private.pem> required" >&2; exit 2; }
	@$(MAKE) --no-print-directory sign-elf \
	  ROLE=selinux \
	  BINARY=build/selinux/arm64-v8a/voboost-selinux \
	  KEY="$(SIGNING_KEY)" \
	  OUT=dist/selinux/arm64-v8a/voboost-selinux

# ---- Stock-policy restore bootstrap (/data/voboost/voboost-restore) ----
test-restore:
	cargo test --manifest-path restore/Cargo.toml
	cargo clippy --manifest-path restore/Cargo.toml --all-targets -- -D warnings

build-restore:
	@command -v cargo-ndk >/dev/null 2>&1 || { echo "build-restore: cargo-ndk not found" >&2; exit 1; }
	@test -n "$(NDK_HOME)" || { echo "build-restore: NDK_HOME not set" >&2; exit 1; }
	@test -f "$(NATIVE_EXECUTABLE_PUBLIC_KEY_PEM)" || { echo "build-restore: NATIVE_EXECUTABLE_PUBLIC_KEY_PEM missing" >&2; exit 2; }
	@test -f "$(RESTORE_PUBLIC_KEY_PEM)" || { echo "build-restore: RESTORE_PUBLIC_KEY_PEM missing" >&2; exit 2; }
	@test -f "$(RELEASE_CATALOG_PUBLIC_KEY_PEM)" || { echo "build-restore: RELEASE_CATALOG_PUBLIC_KEY_PEM missing" >&2; exit 2; }
	@test -f "$(AGENT_CATALOG_PUBLIC_KEY_PEM)" || { echo "build-restore: AGENT_CATALOG_PUBLIC_KEY_PEM missing" >&2; exit 2; }
	@mkdir -p build/restore/arm64-v8a
	cd restore && \
	  VOBOOST_NATIVE_EXECUTABLE_PUBLIC_KEY_PEM="$(abspath $(NATIVE_EXECUTABLE_PUBLIC_KEY_PEM))" \
	  VOBOOST_RESTORE_PUBLIC_KEY_PEM="$(abspath $(RESTORE_PUBLIC_KEY_PEM))" \
	  VOBOOST_RELEASE_CATALOG_PUBLIC_KEY_PEM="$(abspath $(RELEASE_CATALOG_PUBLIC_KEY_PEM))" \
	  VOBOOST_AGENT_CATALOG_PUBLIC_KEY_PEM="$(abspath $(AGENT_CATALOG_PUBLIC_KEY_PEM))" \
	  RUSTFLAGS="$(RUST_ANDROID_FLAGS)" cargo ndk -t arm64-v8a -P 28 build --release
	cp target/aarch64-linux-android/release/voboost-restore build/restore/arm64-v8a/voboost-restore

test-built-restore:
	@test -n "$(NDK_HOME)" || { echo "test-built-restore: ANDROID_NDK_HOME not set" >&2; exit 1; }
	@node tools/check-restore.ts --readelf "$(READELF)"

sign-restore:
	@test -f build/restore/arm64-v8a/voboost-restore || { echo "sign-restore: run build-restore first" >&2; exit 2; }
	@test -f "$(SIGNING_KEY)" || { echo "sign-restore: SIGNING_KEY=<restore-private.pem> required" >&2; exit 2; }
	@$(MAKE) --no-print-directory sign-elf \
	  ROLE=restore \
	  BINARY=build/restore/arm64-v8a/voboost-restore \
	  KEY="$(SIGNING_KEY)" \
	  OUT=dist/restore/arm64-v8a/voboost-restore

.PHONY: test-injector-remote-call
test-injector-remote-call:
	@mkdir -p build
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -Iinjector \
		injector/remote_call.c injector/ptrace_state.c injector/remote_call_test.c -o build/remote_call_test
	@./build/remote_call_test

.PHONY: test-lsplant-stage-callback
test-lsplant-stage-callback:
	@node tools/prepare-native-third-party-source.ts --apply
	@node tools/test-lsplant-stage-callback.ts
	@$(HOST_CXX) -std=c++20 -pthread -Wall -Wextra -Werror -Iimplant -Ibuild \
		implant/hook_stage_record_test.cpp -o build/hook_stage_record_test
	@./build/hook_stage_record_test

.PHONY: test-injector-managed-call
test-injector-managed-call:
	@mkdir -p build
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -pthread -Iinjector \
		injector/ptrace_recovery.c injector/thread_group.c injector/managed_call_test.c \
		-o build/managed_call_test
	@./build/managed_call_test

.PHONY: test-injector-restore-stages
test-injector-restore-stages:
	@mkdir -p build
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -Iinjector \
		injector/regset_restore_test.c -o build/regset_restore_test
	@./build/regset_restore_test

.PHONY: test-injector-callee-frames
test-injector-callee-frames: test-injector-remote-call test-injector-fault-record
	@mkdir -p build
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -Iinjector \
		injector/callee_frames_test.c -o build/callee_frames_test
	@./build/callee_frames_test

.PHONY: test-lsplant-backup-publication
test-lsplant-backup-publication:
	@node tools/prepare-native-third-party-source.ts --apply
	@node tools/test-lsplant-backup-publication.ts
	@$(HOST_CXX) -std=c++20 -Wall -Wextra -Werror -Ibuild \
		implant/hook_publication_test.cpp -o build/hook_publication_test
	@./build/hook_publication_test

.PHONY: test-bootstrap-worker
# Original firmware and generated Gauge samples are external test inputs.
.PHONY: test-cluster-oem
test-cluster-oem:
	@mkdir -p target/cluster-host-tmp
	TMPDIR="$(CURDIR)/target/cluster-host-tmp" cargo test -p voboost-cluster-native --lib -- --ignored

.PHONY: test-cluster-locale-observer
test-cluster-locale-observer:
	@set -eu; mkdir -p build; output=$$(mktemp -d build/cluster-locale-host.XXXXXX); \
	  trap 'rm -f "$$output/locale-observer-test"; rmdir "$$output"' EXIT HUP INT TERM; \
	  $(HOST_CXX) -std=c++20 -Wall -Wextra -Werror -Icluster/sdk/include \
	    cluster/service/locale_observer.cpp cluster/tests/locale_observer.cpp \
	    -o "$$output/locale-observer-test"; \
	  "$$output/locale-observer-test"; \
	  "$$output/locale-observer-test" --missing-symbol; \
	  echo "locale observer host: identity/UI fences, fresh readback, owner lifetime, cleared receipts and missing symbol passed"

test-bootstrap-worker:
	@mkdir -p build
	@$(HOST_CXX) -std=c++20 -pthread -Wall -Wextra -Werror -Iimplant \
		implant/bootstrap_worker_test.cpp -o build/bootstrap_worker_test
	@VOBOOST_WORKER_GOLDEN="$(CURDIR)/build/bootstrap_worker_frame.bin" cargo test --manifest-path daemon/Cargo.toml bootstrap_worker::tests::receipt_is_once_and_frame_matches_native_golden -- --exact --nocapture
	@./build/bootstrap_worker_test build/bootstrap_worker_frame.bin

.PHONY: test-implant-symtab
test-implant-symtab:
	@node tools/prepare-symtab-test.ts
	@$(HOST_CXX) -std=c++20 -Wall -Wextra -Werror -Iimplant -Ibuild \
		implant/symtab_resolver_test.cpp -o build/symtab_resolver_test
	@./build/symtab_resolver_test

.PHONY: test-native-faults
test-native-faults:
	@node tools/prepare-native-fault-tests.ts
	@$(HOST_CXX) -std=c++20 -Wall -Wextra -Werror -Iimplant -Ibuild \
		implant/native_fault_test.cpp -o build/native_fault_test
	@./build/native_fault_test

.PHONY: test-injector-fault-record
test-injector-fault-record:
	@mkdir -p build
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -Iinjector \
		injector/fault_record_test.c -o build/fault_record_test
	@./build/fault_record_test


.PHONY: test-inline-hook-publication
test-inline-hook-publication:
	@node tools/prepare-native-third-party-source.ts --apply
	@node tools/prepare-inline-hook-test.ts
	@java_home="$${JAVA_HOME:-}"; \
	if [ -z "$$java_home" ] && [ "$$(uname -s)" = Darwin ]; then \
		java_home="$$(/usr/libexec/java_home 2>/dev/null)"; \
	elif [ -z "$$java_home" ]; then \
		java_home="$$(dirname $$(dirname $$(readlink -f $$(command -v javac))))"; \
	fi; \
	test -f "$$java_home/include/jni.h" || { echo "test-inline-hook-publication: JDK required" >&2; exit 1; }; \
	platform=linux; [ "$$(uname -s)" != Darwin ] || platform=darwin; \
	$(HOST_CXX) -std=c++23 -pthread -Wall -Wextra -Werror \
		-Wno-gnu-string-literal-operator-template -Ibuild \
		-Ibuild/third-party-source/lsplant/lsplant/src/main/jni/include \
		-I"$$java_home/include" -I"$$java_home/include/$$platform" \
		implant/inline_hook_transaction_test.cpp -o build/inline_hook_transaction_test
	@./build/inline_hook_transaction_test

.PHONY: test-main-thread-snapshot-scope
test-main-thread-snapshot-scope:
	@mkdir -p build
	@$(HOST_CXX) -std=c++20 -I implant -Wall -Wextra -Werror \
		implant/main_thread_snapshot_scope_test.cpp -o build/main_thread_snapshot_scope_test
	@./build/main_thread_snapshot_scope_test

.PHONY: test-injector-pstate-admission
test-injector-pstate-admission: test-injector-pstate-production
	@mkdir -p build
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -Iinjector \
		injector/pstate_admission_test.c -o build/pstate_admission_test
	@./build/pstate_admission_test


.PHONY: test-injector-pstate-production
test-injector-pstate-production:
	@mkdir -p build
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -pthread -Iinjector \
		injector/pstate_production_test.c injector/remote_call.c injector/maps_parse.c \
		injector/namespace_abi.c injector/ptrace_recovery.c injector/ptrace_state.c \
		-o build/pstate_production_test
	@./build/pstate_production_test


.PHONY: test-log-transport
test-log-transport:
	@mkdir -p build
	@$(HOST_CXX) -std=c++20 -pthread -I implant -Wall -Wextra -Werror \
		implant/log_transport_test.cpp -o build/log_transport_test
	@./build/log_transport_test
	@$(HOST_CXX) -std=c++20 -pthread -I implant -Wall -Wextra -Werror \
		implant/event_uplink_test.cpp -o build/event_uplink_test
	@./build/event_uplink_test

.PHONY: test-system-server-loader
test-system-server-loader:
	@mkdir -p build
	@$(HOST_CXX) -std=c++20 -Wall -Wextra -Werror -Iimplant implant/system_server_loader_test.cpp -o build/system_server_loader_test
	@./build/system_server_loader_test

.PHONY: test-injector-diagnostic-time
test-injector-diagnostic-time:
	@mkdir -p build
	@$(HOST_CC) -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror \
		injector/diagnostic_time_test.c -o build/diagnostic_time_test
	@./build/diagnostic_time_test

.PHONY: test-cluster-ui-root
test-cluster-ui-root:
	@mkdir -p build/host
	@$(HOST_CXX) -std=c++20 -O2 -Wall -Wextra -Werror -Icluster/service cluster/tests/ui_root.cpp -o build/host/test_ui_root
	@./build/host/test_ui_root

.PHONY: test-cluster-ui-frame
test-cluster-ui-frame:
	@mkdir -p build/host
	@$(HOST_CXX) -std=c++20 -O2 -Wall -Wextra -Werror -Icluster/service cluster/tests/ui_frame_state.cpp -o build/host/test_ui_frame
	@./build/host/test_ui_frame
	@$(HOST_CXX) -std=c++20 -O2 -Wall -Wextra -Werror -Icluster/service cluster/tests/ui_dispatch.cpp -o build/host/test_ui_dispatch
	@./build/host/test_ui_dispatch
