---
name: skill-commands
description: "Runs voboost-inject build, test, and check commands. Use when executing make or npm targets in voboost-inject; not for writing code or docs."
---

# Commands

- `make check`: verify Rust, cargo-ndk, NDK r29, OpenSSL, and uncrustify prerequisites.
- `make lint`: Rust format/Clippy with `-D warnings` plus C/C++ uncrustify checks.
- `make test`: Rust, injector, implant, and signed-ELF host tests.
- `make build`: release-mode host validation build.
- `make build-android`: canonical daemon and two-ABI native cross-build.
- `npm run dev:android`: local Android cross-build with five disposable role identities removed when the command exits.
- `tools/prepare-beta1-unsigned.sh <output-dir>`: export the exact nine flat unsigned native inputs for product-owned composition.
- `cd daemon && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`: focused Rust gate.
- `npm ci && npm run check:openspec`: install the lockfile-pinned OpenSpec CLI and run strict validation plus repository evidence checks without downloading tooling at execution time.
