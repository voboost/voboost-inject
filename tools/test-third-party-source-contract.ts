#!/usr/bin/env node

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { main, requireValue, ROOT, run, runText } from "./lib.ts";

const EXPECTED = new Map([
    ["third_party/dobby", ["5dfc8546954ce3b3198132ab13fddb89ee92cdd7", "https://github.com/jmpews/Dobby.git"]],
    ["third_party/libsepol", ["c4882b81f186bc131f79ad0b28808bbeef6fc678", "https://android.googlesource.com/platform/external/libsepol"]],
    ["third_party/lsplant", ["a96c7978a9fe578e0e265cc8e45cb117fa8250a3", "https://github.com/LSPosed/LSPlant.git"]],
]);

export function parseGitmodules(source: string): Map<string, string> {
    const result = new Map<string, string>();
    const blocks = source.split(/^\s*\[submodule\s+"/m).slice(1);
    requireValue(blocks.length === EXPECTED.size, ".gitmodules section count differs");
    for (const block of blocks) {
        const closing = block.indexOf('"]');
        requireValue(closing > 0, "malformed .gitmodules section");
        const name = block.slice(0, closing);
        requireValue(!result.has(name), `duplicate .gitmodules section: ${name}`);
        const rows = block.slice(closing + 2).split("\n").map((line) => line.trim()).filter(Boolean);
        const values = new Map<string, string>();
        for (const row of rows) {
            const match = /^(path|url)\s*=\s*(.+)$/.exec(row);
            requireValue(match, `unsupported .gitmodules row: ${row}`);
            requireValue(!values.has(match[1]), `duplicate .gitmodules key: ${match[1]}`);
            values.set(match[1], match[2]);
        }
        requireValue(values.size === 2, `keys differ in .gitmodules section ${name}`);
        const expected = EXPECTED.get(name);
        requireValue(expected && values.get("path") === name && values.get("url") === expected[1], `.gitmodules mapping differs for ${name}`);
        result.set(name, expected[0]);
    }
    return result;
}

function validateCleanSource(repository: string, expected: string): void {
    requireValue(runText("git", ["-C", repository, "rev-parse", "HEAD"]) === expected, `checkout differs at ${repository}`);
    requireValue(runText("git", ["-C", repository, "status", "--porcelain=v1", "--untracked-files=all"]) === "", `third-party source drift at ${repository}`);
}

function driftSelfTest(relative: string, expected: string): void {
    const repository = resolve(ROOT, relative);
    const temporary = mkdtempSync(join(tmpdir(), `voboost-${relative.split("/").at(-1)}-contract-`));
    const checkout = join(temporary, "checkout");
    run("git", ["-C", repository, "worktree", "add", "--detach", checkout, expected]);
    try {
        validateCleanSource(checkout, expected);
        const tracked = resolve(checkout, runText("git", ["-C", checkout, "ls-files"]).split("\n")[0]);
        const original = readFileSync(tracked);
        writeFileSync(tracked, Buffer.concat([original, Buffer.from("\n")]));
        reject(() => validateCleanSource(checkout, expected), `tracked ${relative} mutation was accepted`);
        writeFileSync(tracked, original);
        writeFileSync(resolve(checkout, "rogue-source.c"), "/* drift */\n");
        reject(() => validateCleanSource(checkout, expected), `untracked ${relative} mutation was accepted`);
    } finally {
        run("git", ["-C", repository, "worktree", "remove", "--force", checkout], { allowFailure: true });
        rmSync(temporary, { recursive: true, force: true });
    }
}

function reject(action: () => void, message: string): void {
    try { action(); } catch { return; }
    throw new Error(message);
}

main(() => {
    const gitmodules = readFileSync(resolve(ROOT, ".gitmodules"), "utf8");
    parseGitmodules(gitmodules);
    for (const mutation of [
        `${gitmodules}\n[submodule "foreign"]\n\tpath = third_party/foreign\n\turl = https://example.invalid/foreign\n`,
        gitmodules.replace("\tpath = third_party/dobby\n", "\tpath = third_party/dobby\n\tpath = third_party/dobby-copy\n"),
        gitmodules.replace("https://github.com/LSPosed/LSPlant.git", "https://example.invalid/LSPlant.git"),
    ]) reject(() => parseGitmodules(mutation), ".gitmodules mutation was accepted");

    for (const [path, [expected]] of EXPECTED) {
        const resolvedParent = runText("git", ["rev-parse", `HEAD:${path}`], { allowFailure: true });
        const parent = resolvedParent === `HEAD:${path}` ? "" : resolvedParent;
        const pending = parent ? runText("git", ["submodule", "status", "--", path], { allowFailure: true }) : "";
        const newGitlink = !parent && runText("git", ["status", "--short", "--", path]).startsWith(`?? ${path}/`);
        const indexed = runText("git", ["ls-files", "-s", "--", path], { allowFailure: true });
        const indexedGitlink = indexed.startsWith(`160000 ${expected} `);
        requireValue(parent === expected || pending.startsWith(`+${expected} `) || indexedGitlink || newGitlink, `parent gitlink differs for ${path}`);
        requireValue(runText("git", ["-C", path, "rev-parse", "HEAD"]) === expected, `checked-out source differs for ${path}`);
        if (path !== "third_party/libsepol") driftSelfTest(path, expected);
    }
    const makefile = readFileSync(resolve(ROOT, "Makefile"), "utf8");
    for (const [label, fragment] of [
        ["Dobby arm64 source build", "--target dobby_static"],
        ["Dobby armv7 exception", 'if [ "$${abi}" = "armeabi-v7a" ]'],
        ["LSPlant source build", "--build $(THIRD_PARTY_BUILD)/$${abi}/lsplant"],
        ["both ABI loop", "for abi in $(NATIVE_ABIS)"],
    ]) requireValue(makefile.includes(fragment), `source contract missing ${label}`);
    run("node", ["tools/prepare-native-third-party-source.ts", "--self-test"]);
    run("node", ["tools/prepare-libsepol-source.ts", "--self-test"]);
    console.log("third-party-source-contract: pinned sources and ABI build topology OK");
}, "third-party-source-contract");
