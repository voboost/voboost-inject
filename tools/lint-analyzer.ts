import { spawnSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import { main, requireValue, ROOT } from "./lib.ts";

// Static analyzer gate: every first-party C/C++ source must produce zero
// clang static analyzer findings when analyzed against the Android target.
//
// Findings inside third_party/ are vendored code and are ignored by path.
// First-party findings can only exist as exact entries of EXPECTED_FINDINGS:
// each entry is an individually adjudicated non-defect. The gate fails on any
// finding outside the list and on any list entry that no longer matches, so a
// changed line forces re-adjudication instead of silently keeping a stale
// exemption.
interface Finding {
    file: string;
    line: number;
    column: number;
    check: string;
}

const EXPECTED_FINDINGS: Finding[] = [
    // Individually re-adjudicated 2026-10-08: initial bootstrap, every flag
    // restoration and rebind fail before publication unless this reply FD is
    // O_NONBLOCK. test-native-faults executes the exact production flag block
    // with failing F_GETFL/F_SETFL; test-implant-downlink executes empty live
    // pipe/EAGAIN and final D/A+HUP. The shared framer requires the mutex.
    // Watcher: at most 64 reads, poll outside the mutex, JNI outside it.
    { file: "implant/downlink_watch_read.h", line: 17, column: 29, check: "unix.BlockInCriticalSection" },
    // Legacy State.get: monotonic 500 ms deadline and EAGAIN/EINTR retry.
    { file: "implant/implant.cpp", line: 1461, column: 25, check: "unix.BlockInCriticalSection" },
    // Detailed State.get: same nonblocking FD and monotonic 500 ms deadline.
    { file: "implant/implant.cpp", line: 1570, column: 25, check: "unix.BlockInCriticalSection" },
    // Mutation ACK: zero-time poll and at most 64 reads.
    { file: "implant/implant.cpp", line: 1657, column: 25, check: "unix.BlockInCriticalSection" },
    // Logs exchange: monotonic 1000 ms deadline and EAGAIN/EINTR retry.
    { file: "implant/implant.cpp", line: 1783, column: 25, check: "unix.BlockInCriticalSection" },
    // NDK checker enters a critical section even when trylock returns nonzero
    // in the preceding rejected diagnostic. This test read FD is O_NONBLOCK,
    // bounded poll proves bytes present, and mutex trylock/destroy prove release.
    { file: "implant/hook_stage_record_test.cpp", line: 73, column: 22, check: "unix.BlockInCriticalSection" },
];

const TARGET_TRIPLE = "aarch64-linux-android29";

const GROUPS: { sources: string[]; flags: string[]; compiler: "clang" | "clang++" }[] = [
    {
        compiler: "clang",
        sources: ["injector/*.c"],
        flags: ["-Iinjector", "-D_GNU_SOURCE"],
    },
    {
        compiler: "clang",
        sources: ["selinux/*.c"],
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
    requireValue(ndkHome !== "", "lint-analyzer: NDK_HOME or ANDROID_NDK_HOME must point at NDK r29");
    const prebuilt = join(ndkHome, "toolchains", "llvm", "prebuilt");
    requireValue(existsSync(prebuilt), `lint-analyzer: NDK prebuilt toolchains not found under ${ndkHome}`);
    for (const host of readdirSync(prebuilt)) {
        const candidate = join(prebuilt, host, "bin", name);
        if (existsSync(candidate)) return candidate;
    }
    throw new Error(`lint-analyzer: ${name} not found in the NDK`);
}

function analyzeGroup(toolchainBin: string, group: (typeof GROUPS)[number]): Finding[] {
    const findings: Finding[] = [];
    for (const pattern of group.sources) {
        const directory = pattern.slice(0, pattern.lastIndexOf("/"));
        const extension = pattern.slice(pattern.lastIndexOf("."));
        for (const entry of readdirSync(join(ROOT, directory)).sort()) {
            if (!entry.endsWith(extension)) continue;
            const file = join(ROOT, directory, entry);
            const result = spawnSync(join(toolchainBin, group.compiler), [
                "--analyze",
                `--target=${TARGET_TRIPLE}`,
                `--sysroot=${join(toolchainBin, "..", "sysroot")}`,
                ...(file.endsWith("/inline_hook_transaction_test.cpp")
                    ? ["-Ibuild/third-party-source/lsplant/lsplant/src/main/jni/include", ...group.flags, "-std=c++23"]
                    : group.flags),
                file,
            ], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
            if (result.error) throw result.error;
            const output = `${result.stdout}${result.stderr}`;
            for (const line of output.split("\n")) {
                const match = /^(\S+?):(\d+):(\d+): (warning|error): (?:.*?) \[([^\]]+)\]$/.exec(line);
                if (match) {
                    if (match[4] === "error") {
                        throw new Error(`lint-analyzer: ${relative(ROOT, file)} failed to analyze: ${line}`);
                    }
                    findings.push({
                        file: relative(ROOT, match[1]),
                        line: Number(match[2]),
                        column: Number(match[3]),
                        check: match[5],
                    });
                } else if (/^[^:\s].*: fatal error:/.test(line)) {
                    throw new Error(`lint-analyzer: ${relative(ROOT, file)}: ${line}`);
                }
            }
        }
    }
    return findings;
}

main(() => {
    const ndkHome = process.env.NDK_HOME ?? process.env.ANDROID_NDK_HOME ?? "";
    const toolchainBin = join(ndkHome, "toolchains", "llvm", "prebuilt",
        readdirSync(join(ndkHome, "toolchains", "llvm", "prebuilt"))[0], "bin");

    const firstParty = (finding: Finding) => !finding.file.split("/").includes("third_party");
    const actual = GROUPS.flatMap((group) => analyzeGroup(toolchainBin, group)).filter(firstParty);

    const key = (finding: Finding) => `${finding.file}:${finding.line}:${finding.column}:${finding.check}`;
    const expectedKeys = new Set(EXPECTED_FINDINGS.map(key));
    const actualKeys = new Set(actual.map(key));

    const unexpected = actual.filter((finding) => !expectedKeys.has(key(finding)));
    for (const finding of unexpected) {
        console.error(`lint-analyzer: unexpected finding ${key(finding)}`);
    }
    const stale = EXPECTED_FINDINGS.filter((finding) => !actualKeys.has(key(finding)));
    for (const finding of stale) {
        console.error(`lint-analyzer: stale exemption ${key(finding)} no longer matches the code; re-adjudicate and update EXPECTED_FINDINGS`);
    }
    requireValue(unexpected.length === 0 && stale.length === 0,
        `lint-analyzer: ${unexpected.length} unexpected finding(s), ${stale.length} stale exemption(s)`);
    console.log(`lint-analyzer: ${actual.length} adjudicated finding(s), zero unexpected`);
}, "lint-analyzer");
