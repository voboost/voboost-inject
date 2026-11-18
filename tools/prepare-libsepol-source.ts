#!/usr/bin/env node

import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, extname, join, resolve } from "node:path";
import { main, requireValue, ROOT, run, runText } from "./lib.ts";
import { prepareBuildSource } from "./native-build-source.ts";

const REPOSITORY = resolve(ROOT, "third_party/libsepol");
const PATCH = resolve(ROOT, "patches/libsepol/0001-android-xperms-layout.patch");
const BASE = "c4882b81f186bc131f79ad0b28808bbeef6fc678";
const PATCH_SHA256 = "d12b749a57b7eee47eae4b7b52aaac986ae516145bf161101dca0ae1370d04d9";

function validate(repository: string, apply: boolean): void {
    requireValue(runText("git", ["-C", repository, "rev-parse", "HEAD"]) === BASE, "libsepol checkout differs from the pinned gitlink");
    requireValue(createHash("sha256").update(readFileSync(PATCH)).digest("hex") === PATCH_SHA256, "parent-owned libsepol patch identity differs");
    const status = runText("git", ["-C", repository, "status", "--porcelain=v1", "--untracked-files=all"]);
    for (const row of status.split("\n").filter((line) => line.startsWith("?? "))) {
        requireValue([".o", ".a", ".d"].includes(extname(row.slice(3))), `untracked libsepol source drift: ${row.slice(3)}`);
    }
    let diff = run("git", ["-C", repository, "diff", "HEAD", "--no-ext-diff", "--binary"]);
    const expected = readFileSync(PATCH);
    if (diff.length === 0) {
        run("git", ["-C", repository, "apply", "--check", PATCH]);
        if (apply) {
            run("git", ["-C", repository, "apply", PATCH]);
            diff = run("git", ["-C", repository, "diff", "HEAD", "--no-ext-diff", "--binary"]);
        }
    }
    if (diff.length) {
        requireValue(diff.equals(expected), "libsepol tracked source differs from the exact pinned patch");
        run("git", ["-C", repository, "apply", "--reverse", "--check", PATCH]);
    }
}

function selfTest(): void {
    const temporary = mkdtempSync(join(tmpdir(), "voboost-libsepol-contract-"));
    const checkout = join(temporary, "checkout");
    run("git", ["-C", REPOSITORY, "worktree", "add", "--detach", checkout, BASE]);
    try {
        validate(checkout, false);
        validate(checkout, true);
        const tracked = join(checkout, "src/avtab.c");
        const original = readFileSync(tracked);
        writeFileSync(tracked, Buffer.concat([original, Buffer.from("\n")]));
        assertRejected(() => validate(checkout, false), "tracked libsepol mutation was accepted");
        writeFileSync(tracked, original);
        writeFileSync(join(checkout, "tests/rogue-source.c"), "/* drift */\n");
        assertRejected(() => validate(checkout, false), "untracked libsepol source mutation was accepted");
    } finally {
        run("git", ["-C", REPOSITORY, "worktree", "remove", "--force", checkout], { allowFailure: true });
        rmSync(temporary, { recursive: true, force: true });
    }
}

function assertRejected(action: () => void, message: string): void {
    try { action(); } catch { return; }
    throw new Error(message);
}

main(() => {
    requireValue(existsSync(PATCH), `patch is absent: ${basename(PATCH)}`);
    validate(REPOSITORY, false);
    if (process.argv.includes("--apply")) prepareBuildSource(REPOSITORY, BASE, PATCH);
    if (process.argv.includes("--self-test")) selfTest();
    console.log("libsepol-source-contract: exact gitlink, patch and source state OK");
}, "libsepol-source-contract");
