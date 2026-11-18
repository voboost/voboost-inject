import { spawnSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import { main, requireValue, ROOT } from "./lib.ts";

// clang-tidy gate: every first-party C/C++ source must be warning-free under
// the shared Voboost .clang-tidy selection (WarningsAsErrors '*'), analyzed
// with the NDK toolchain against the Android target.
//
// Vendored code is out of scope by path: third_party/ and selinux/tweetnacl.c
// (an unmodified copy of the public-domain TweetNaCl reference sources; the
// upstream layout must stay diffable against the original).
const TARGET_TRIPLE = "aarch64-linux-android29";

const GROUPS: { sources: string[]; exclude?: string[]; flags: string[]; compiler: "clang" | "clang++" }[] = [
    {
        compiler: "clang",
        sources: ["injector/*.c"],
        flags: ["-Iinjector", "-D_GNU_SOURCE"],
    },
    {
        compiler: "clang",
        sources: ["selinux/*.c"],
        exclude: ["selinux/tweetnacl.c"],
        flags: [
            "-Iselinux",
            "-Ithird_party/yyjson/src",
            "-Ithird_party/libsepol/include",
            "-Ithird_party/libsepol/cil/include",
            "-Ithird_party/libsepol/src",
            "-DEMBEDDED_PUBKEY_HEX=00",
        ],
    },
    {
        compiler: "clang++",
        sources: ["implant/*.cpp"],
        flags: [
            "-std=c++20",
            "-Iimplant",
            "-Iimplant/include",
            "-Ibuild",
            "-Ithird_party/yyjson/src",
            "-Ithird_party/dobby/include",
            "-Ithird_party/lsplant/lsplant/src/main/jni/include",
            "-D_GNU_SOURCE",
        ],
    },
];

function findNdkTool(name: string): string {
    const ndkHome = process.env.NDK_HOME ?? process.env.ANDROID_NDK_HOME ?? "";
    requireValue(ndkHome !== "", "lint-tidy: NDK_HOME or ANDROID_NDK_HOME must point at NDK r29");
    const prebuilt = join(ndkHome, "toolchains", "llvm", "prebuilt");
    requireValue(existsSync(prebuilt), `lint-tidy: NDK prebuilt toolchains not found under ${ndkHome}`);
    for (const host of readdirSync(prebuilt)) {
        const candidate = join(prebuilt, host, "bin", name);
        if (existsSync(candidate)) return candidate;
    }
    throw new Error(`lint-tidy: ${name} not found in the NDK`);
}

function lintGroup(tidy: string, sysroot: string, group: (typeof GROUPS)[number]): number {
    let findings = 0;
    for (const pattern of group.sources) {
        const directory = pattern.slice(0, pattern.lastIndexOf("/"));
        const extension = pattern.slice(pattern.lastIndexOf("."));
        for (const entry of readdirSync(join(ROOT, directory)).sort()) {
            if (!entry.endsWith(extension)) continue;
            const path = `${directory}/${entry}`;
            if (group.exclude?.includes(path)) continue;
            const result = spawnSync(tidy, [
                `-config-file=${join(ROOT, ".clang-tidy")}`,
                `--header-filter=^(injector|implant|selinux)/`,
                join(ROOT, path),
                "--",
                `--target=${TARGET_TRIPLE}`,
                `--sysroot=${sysroot}`,
                ...(path.endsWith("/inline_hook_transaction_test.cpp")
                    ? ["-Ibuild/third-party-source/lsplant/lsplant/src/main/jni/include", ...group.flags, "-std=c++23"]
                    : group.flags),
            ], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
            if (result.error) throw result.error;
            for (const line of `${result.stdout}${result.stderr}`.split("\n")) {
                const match = /^(\S+?):(\d+):(\d+): (warning|error): /.exec(line);
                if (!match) continue;
                const file = relative(ROOT, match[1]);
                if (file.split("/").includes("third_party")) continue;
                console.error(`lint-tidy: ${file}:${match[2]}:${match[3]} ${line.slice(line.indexOf(": ") + 2)}`);
                findings += 1;
            }
        }
    }
    return findings;
}

main(() => {
    const ndkHome = process.env.NDK_HOME ?? process.env.ANDROID_NDK_HOME ?? "";
    const tidy = findNdkTool("clang-tidy");
    const sysroot = join(ndkHome, "toolchains", "llvm", "prebuilt",
        readdirSync(join(ndkHome, "toolchains", "llvm", "prebuilt"))[0], "sysroot");
    const findings = GROUPS.reduce((total, group) => total + lintGroup(tidy, sysroot, group), 0);
    requireValue(findings === 0, `lint-tidy: ${findings} first-party finding(s)`);
    console.log("lint-tidy: zero first-party findings");
}, "lint-tidy");
