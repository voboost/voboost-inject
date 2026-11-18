#!/usr/bin/env node

import {
    appendFileSync,
    chmodSync,
    copyFileSync,
    existsSync,
    mkdirSync,
    mkdtempSync,
    readFileSync,
    readdirSync,
    rmSync,
    statSync,
    symlinkSync,
    writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { main, requireValue, ROOT } from "./lib.ts";

const INPUTS: Array<[string, string]> = [
    ["target/aarch64-linux-android/release/voboost-daemon", "voboost-daemon"],
    ["target/aarch64-linux-android/release/voboost-inject", "voboost-inject"],
    ["target/aarch64-linux-android/release/voboost-install", "voboost-install"],
    ["build/restore/arm64-v8a/voboost-restore", "voboost-restore"],
    ["target/aarch64-linux-android/release/voboost-uninstall", "voboost-uninstall"],
    ["build/selinux/arm64-v8a/voboost-selinux", "voboost-selinux"],
    ["config/voboost.rc", "voboost.rc"],
    ["implant/libs/arm64-v8a/libimplant.so", "libimplant-arm64-v8a.so"],
    ["implant/libs/armeabi-v7a/libimplant.so", "libimplant-armeabi-v7a.so"],
];
const RETIRED_PROFILE_MARKER = "VOBOOST_EMULATOR_DAEMON_SELINUX_SKIP_V1";

function tool(name: string): string {
    const ndk = process.env.ANDROID_NDK_HOME ?? "";
    requireValue(ndk.length > 0, "ANDROID_NDK_HOME is required");
    const prebuilt = join(ndk, "toolchains", "llvm", "prebuilt");
    for (const host of readdirSync(prebuilt)) {
        const candidate = join(prebuilt, host, "bin", name);
        if (existsSync(candidate)) return candidate;
    }
    throw new Error(`${name} is unavailable`);
}

function fixture(parent: string, label: string): string {
    const root = join(parent, label);
    mkdirSync(join(root, "tools"), { recursive: true });
    copyFileSync(join(ROOT, "tools", "prepare-beta1-unsigned.sh"), join(root, "tools", "prepare-beta1-unsigned.sh"));
    for (const [relative] of INPUTS) {
        const source = join(ROOT, relative);
        requireValue(existsSync(source), `missing real Android build output ${relative}`);
        const target = join(root, relative);
        mkdirSync(dirname(target), { recursive: true });
        copyFileSync(source, target);
    }
    return root;
}

function run(root: string, output = join(root, "out")): ReturnType<typeof spawnSync> {
    const args = [join(root, "tools", "prepare-beta1-unsigned.sh")];
    args.push(output);
    return spawnSync("bash", args, {
        cwd: root,
        env: process.env,
        encoding: "utf8",
    });
}

main(() => {
    const script = readFileSync(join(ROOT, "tools", "prepare-beta1-unsigned.sh"), "utf8");
    requireValue(!script.includes("../voboost/") && !script.includes("openssl") && !script.includes("SIGNING_KEY"), "adapter is not product-neutral or secretless");
    const parent = mkdtempSync(join(tmpdir(), "voboost-beta1-unsigned-test-"));
    try {
        const first = fixture(parent, "first");
        const firstRun = run(first);
        requireValue(firstRun.status === 0, `valid export failed: ${firstRun.stderr}`);
        const second = fixture(parent, "second");
        const secondRun = run(second);
        requireValue(secondRun.status === 0, `repeat export failed: ${secondRun.stderr}`);
        const expected = INPUTS.map(([, name]) => name).sort();
        requireValue(readdirSync(join(first, "out")).sort().join("\n") === expected.join("\n"), "flat output inventory differs");
        for (const [, name] of INPUTS) {
            const firstFile = join(first, "out", name);
            const secondFile = join(second, "out", name);
            requireValue(readFileSync(firstFile).equals(readFileSync(secondFile)), `${name} export is nondeterministic`);
            const expectedMode = name === "voboost.rc" || name.endsWith(".so") ? 0o644 : 0o755;
            requireValue((statSync(firstFile).mode & 0o777) === expectedMode, `${name} mode differs`);
        }

        const missing = fixture(parent, "missing");
        rmSync(join(missing, INPUTS[0][0]));
        requireValue(run(missing).status !== 0, "missing artifact was accepted");

        const extra = fixture(parent, "extra");
        mkdirSync(join(extra, "out"));
        writeFileSync(join(extra, "out", "foreign"), "foreign");
        requireValue(run(extra).status !== 0, "nonempty output was accepted");

        const wrongAbi = fixture(parent, "wrong-abi");
        copyFileSync(
            join(wrongAbi, "implant/libs/arm64-v8a/libimplant.so"),
            join(wrongAbi, "implant/libs/armeabi-v7a/libimplant.so"),
        );
        requireValue(run(wrongAbi).status !== 0, "wrong ABI artifact was accepted");

        const debug = fixture(parent, "debug");
        const debugPayload = join(debug, "debug-section");
        writeFileSync(debugPayload, "debug");
        const objcopy = spawnSync(
            tool("llvm-objcopy"),
            ["--add-section", `.debug_fixture=${debugPayload}`, join(debug, INPUTS[0][0])],
            { encoding: "utf8" },
        );
        requireValue(objcopy.status === 0, `failed to create debug fixture: ${objcopy.stderr}`);
        requireValue(run(debug).status !== 0, "debug section was accepted");

        const leaked = fixture(parent, "leaked-path");
        appendFileSync(join(leaked, INPUTS[0][0]), "/Users/build/private/source");
        requireValue(run(leaked).status !== 0, "host path leakage was accepted");

        const signed = fixture(parent, "already-signed");
        appendFileSync(
            join(signed, INPUTS[0][0]),
            Buffer.concat([Buffer.from("VOBOOST\0"), Buffer.alloc(72)]),
        );
        requireValue(run(signed).status !== 0, "already signed ELF was accepted");

        const linked = fixture(parent, "linked");
        const linkedPath = join(linked, INPUTS[0][0]);
        rmSync(linkedPath);
        symlinkSync(resolve(ROOT, INPUTS[0][0]), linkedPath);
        requireValue(run(linked).status !== 0, "symlinked input was accepted");

        const wrongMode = fixture(parent, "wrong-mode-source");
        chmodSync(join(wrongMode, INPUTS[0][0]), 0o600);
        const wrongModeRun = run(wrongMode);
        requireValue(wrongModeRun.status === 0, `source mode affected byte export: ${wrongModeRun.stderr}`);
        requireValue(
            (statSync(join(wrongMode, "out", basename(INPUTS[0][0]))).mode & 0o777) === 0o755,
            "canonical output mode was not restored",
        );

        const mixedProduction = fixture(parent, "mixed-production");
        appendFileSync(
            join(mixedProduction, INPUTS[0][0]),
            Buffer.from(`${RETIRED_PROFILE_MARKER}\0`),
        );
        requireValue(run(mixedProduction).status !== 0, "production export accepted an emulator program");

        console.log("prepare-beta1-unsigned: deterministic flat export and hostile gates OK");
    } finally {
        rmSync(parent, { recursive: true, force: true });
    }
}, "prepare-beta1-unsigned");
