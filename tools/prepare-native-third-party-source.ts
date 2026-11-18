#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { main, requireValue, ROOT, run, runText } from "./lib.ts";
import { prepareBuildSource } from "./native-build-source.ts";

type SourceContract = Readonly<{
    name: string;
    repository: string;
    patch: string;
    base: string;
    patchSha256: string;
}>;

const CONTRACTS: readonly SourceContract[] = [
    {
        name: "Dobby",
        repository: "third_party/dobby",
        patch: "patches/dobby/dobby-r29.patch",
        base: "5dfc8546954ce3b3198132ab13fddb89ee92cdd7",
        patchSha256: "5cd539fc5a5540718481371edea2f0c61972fe39a00976ff9dce64f5c5805f9f",
    },
    {
        name: "LSPlant",
        repository: "third_party/lsplant",
        patch: "patches/lsplant/lsplant-r29.patch",
        base: "a96c7978a9fe578e0e265cc8e45cb117fa8250a3",
        patchSha256: "c27874225980d5f55ef1390764869f6f6c2b3af9c9e30912358c49b411fe5ecb",
    },
] as const;

function validate(contract: SourceContract, repository: string, apply: boolean): void {
    const patch = resolve(ROOT, contract.patch);
    requireValue(
        runText("git", ["-C", repository, "rev-parse", "HEAD"]) === contract.base,
        `${contract.name} checkout differs from the reachable upstream gitlink`,
    );
    requireValue(
        createHash("sha256").update(readFileSync(patch)).digest("hex") === contract.patchSha256,
        `${contract.name} parent-owned patch identity differs`,
    );
    const status = runText("git", ["-C", repository, "status", "--porcelain=v1", "--untracked-files=all"]);
    requireValue(
        status.split("\n").every((row) => !row.startsWith("?? ")),
        `${contract.name} checkout contains untracked source`,
    );

    let diff = run("git", ["-C", repository, "diff", "HEAD", "--no-ext-diff", "--binary"]);
    const expected = readFileSync(patch);
    if (diff.length === 0) {
        run("git", ["-C", repository, "apply", "--check", patch]);
        if (apply) {
            run("git", ["-C", repository, "apply", patch]);
            diff = run("git", ["-C", repository, "diff", "HEAD", "--no-ext-diff", "--binary"]);
        }
    }
    if (diff.length > 0) {
        requireValue(diff.equals(expected), `${contract.name} source differs from its exact parent-owned patch`);
        run("git", ["-C", repository, "apply", "--reverse", "--check", patch]);
    }
}

function assertRejected(action: () => void, message: string): void {
    try {
        action();
    } catch {
        return;
    }
    throw new Error(message);
}

function selfTest(contract: SourceContract): void {
    const source = resolve(ROOT, contract.repository);
    const temporary = mkdtempSync(join(tmpdir(), `voboost-${contract.name.toLowerCase()}-contract-`));
    const checkout = join(temporary, "checkout");
    run("git", ["-C", source, "worktree", "add", "--detach", checkout, contract.base]);
    try {
        validate(contract, checkout, false);
        validate(contract, checkout, true);
        const tracked = resolve(checkout, runText("git", ["-C", checkout, "ls-files"]).split("\n")[0]);
        const original = readFileSync(tracked);
        writeFileSync(tracked, Buffer.concat([original, Buffer.from("\n")]));
        assertRejected(() => validate(contract, checkout, false), `${contract.name} tracked drift was accepted`);
        writeFileSync(tracked, original);
        writeFileSync(resolve(checkout, "voboost-rogue-source.c"), "/* drift */\n");
        assertRejected(() => validate(contract, checkout, false), `${contract.name} untracked drift was accepted`);
    } finally {
        run("git", ["-C", source, "worktree", "remove", "--force", checkout], { allowFailure: true });
        rmSync(temporary, { recursive: true, force: true });
    }
}

main(() => {
    for (const contract of CONTRACTS) {
        const repository = resolve(ROOT, contract.repository);
        validate(contract, repository, false);
        if (process.argv.includes("--apply")) prepareBuildSource(repository, contract.base, resolve(ROOT, contract.patch));
        if (process.argv.includes("--self-test")) selfTest(contract);
    }
    console.log("native-third-party-source-contract: reachable gitlinks and exact parent patches OK");
}, "native-third-party-source-contract");
