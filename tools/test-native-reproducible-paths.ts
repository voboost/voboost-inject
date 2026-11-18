#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { main, requireValue, ROOT } from "./lib.ts";

main(() => {
    const makefile = readFileSync(resolve(ROOT, "Makefile"), "utf8");
    for (const fragment of [
        "-ffile-prefix-map=$(abspath .)=$(REPRO_SOURCE_PREFIX)",
        "-fdebug-prefix-map=$(abspath .)=$(REPRO_SOURCE_PREFIX)",
        "-fmacro-prefix-map=$(abspath .)=$(REPRO_SOURCE_PREFIX)",
        "--remap-path-prefix=$(abspath .)=$(REPRO_SOURCE_PREFIX)",
        "--remap-path-prefix=$(CARGO_SOURCE_HOME)=/rust/cargo",
        "RUST_SYSROOT := $(shell rustc --print sysroot)",
        "--remap-path-prefix=$(RUST_SYSROOT)=/rust/toolchain",
        "RUST_ANDROID_FLAGS := $(RUST_REMAP_FLAGS) -D warnings",
        'RUSTFLAGS="$(RUST_ANDROID_FLAGS)"',
        'APP_CFLAGS="$(REPRO_CFLAGS)"',
        'APP_CPPFLAGS="$(REPRO_CFLAGS)"',
    ]) requireValue(makefile.includes(fragment), `native path remap is missing ${fragment}`);

    const forbidden = [Buffer.from(ROOT), Buffer.from("/Users/"), Buffer.from("/private/var/folders/"), Buffer.from("/tmp/voboost-native-role-keys-")];
    const artifacts = [
        "target/aarch64-linux-android/release/voboost-daemon",
        "target/aarch64-linux-android/release/voboost-inject",
        "target/aarch64-linux-android/release/voboost-uninstall",
        "build/restore/arm64-v8a/voboost-restore",
        "build/selinux/arm64-v8a/voboost-selinux",
    ];
    let inspected = 0;
    for (const relative of artifacts) {
        const path = resolve(ROOT, relative);
        if (!existsSync(path)) continue;
        const bytes = readFileSync(path);
        for (const prefix of forbidden) requireValue(!bytes.includes(prefix), `${relative} embeds host path ${prefix}`);
        inspected += 1;
    }
    requireValue(inspected >= 2, "native remap gate requires built Android artifacts");
    console.log(`native-reproducible-paths: remap flags and ${inspected} built artifacts contain no host prefix`);
}, "native-reproducible-paths");
