# Inheritance

@../voboost-codestyle/AGENTS.md

# Skills

- Commands: [.ai/skill-commands/SKILL.md](.ai/skill-commands/SKILL.md)
- Trust and signing: [.ai/skill-signing/SKILL.md](.ai/skill-signing/SKILL.md)

# Architecture

- `daemon/` builds two Rust executables: `voboost-daemon` owns state, configuration and file logs; `voboost-inject` owns injection and agent orchestration.
- `injector/` is the C ptrace injector linked only into `voboost-inject`. `implant/` is the C++ in-process ART/LSPlant loader built for both supported ABIs.
- The stack is Rust + C + C++ with a ptrace injector.
- The daemon main loop stays synchronous: keep one blocking poll loop plus signal handlers, and do not introduce async execution into that orchestration path.
- Keep `vbi_inject` as the injection host's sole Rust/native C ABI; map failures through stable integer codes and out-parameters, and never link either executable directly to implant, LSPlant, or Dobby symbols.

# Toolchain and Style

- Rust uses edition 2021. `NDK_HOME` selects a complete shared NDK r29 outside project checkouts; Make forwards it as `ANDROID_NDK_HOME` to Cargo. Android native code targets API 28, and the implant uses C++20 with `c++_static`.
- Rust: `cargo fmt` and Clippy with warnings denied. C/C++: `config/config-uncrustify.cfg`; keep lines within 100 characters.
- Do not replace the pinned submodules or patches with a fresh reimplementation of an existing working artifact.

# Source and Generated Artifacts

- `third_party/` plus `patches/` are source inputs; `make build-third-party` produces `prebuilt/<abi>/`. The committed armv7 Dobby archive is the documented fallback exception.
- `make build-daemon` and `make build-inject` produce their respective executable under `target/aarch64-linux-android/release/`. `make build-android` builds the complete native set, including implants under `implant/libs/{arm64-v8a,armeabi-v7a}/`.
- `make release-manifest` and signing targets own outputs under `build/`; edit sources and inputs, never generated manifests, signatures, or binaries.
- Private keys are local or CI inputs and must never enter source, logs, plans, or artifacts other than their intended signatures.

# Platform Gates

- For OEM behavior research, use the retained `/Users/vitaly/Yandex.Disk.localized/voyah-source` corpus instead of pulling and decompiling device APKs again. Start with `docs/00-index.md` and `tools/rag/README.md`; bind findings to the exact firmware and retained artifact identity, and do not treat decompiled evidence as runtime proof.
- `check-prebuilt` rejects native payloads linked to `libc++_shared.so`; both `arm64-v8a` and `armeabi-v7a` outputs are release inputs.
- The root zone is `/data/voboost`; daemon logs are files under `logs/`, not a logcat contract.
- Host builds and permissive emulators do not prove ptrace, injection, SELinux Enforcing, init-hook, OTA, or vehicle readiness. Record those gates separately.
