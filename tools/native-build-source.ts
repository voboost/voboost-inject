import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync, renameSync, mkdtempSync, rmSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { createHash } from "node:crypto";
import { ROOT, requireValue, run, runText } from "./lib.ts";

function gitlinks(repository: string, commit: string): Array<{ path: string; commit: string }> {
    return run("git", ["-C", repository, "ls-tree", "-rz", commit]).toString("utf8").split("\0")
        .flatMap((row) => {
            const match = /^160000 commit ([0-9a-f]{40})\t(.+)$/u.exec(row);
            return match ? [{ path: match[2], commit: match[1] }] : [];
        });
}

function clonePinned(source: string, commit: string, destination: string): void {
    requireValue(runText("git", ["-C", source, "rev-parse", "HEAD"]) === commit, "nested native source gitlink differs");
    run("git", ["clone", "--quiet", "--shared", "--no-checkout", source, destination]);
    run("git", ["-C", destination, "checkout", "--quiet", "--detach", commit]);
    for (const link of gitlinks(source, commit)) {
        const child = resolve(source, link.path);
        const top = runText("git", ["-C", child, "rev-parse", "--show-toplevel"], { allowFailure: true });
        if (!existsSync(child) || top !== realpathSync(child)) continue;
        requireValue(runText("git", ["-C", child, "status", "--porcelain=v1", "--untracked-files=all"]) === "", "nested native source is dirty");
        clonePinned(child, link.commit, join(destination, link.path));
    }
}

function validateNestedCopies(source: string, destination: string, commit: string): void {
    for (const link of gitlinks(source, commit)) {
        const child = resolve(source, link.path);
        if (!existsSync(child)) continue;
        const top = runText("git", ["-C", child, "rev-parse", "--show-toplevel"], { allowFailure: true });
        if (top !== realpathSync(child)) continue;
        const copy = resolve(destination, link.path);
        requireValue(existsSync(copy) && runText("git", ["-C", copy, "rev-parse", "--show-toplevel"], { allowFailure: true }) === realpathSync(copy), "native build nested source missing");
        requireValue(runText("git", ["-C", copy, "rev-parse", "HEAD"]) === link.commit, "native build nested source HEAD drift");
        requireValue(runText("git", ["-C", copy, "status", "--porcelain=v1", "--untracked-files=all"]) === "", "native build nested source is dirty");
        validateNestedCopies(child, copy, link.commit);
    }
}

/** Build copies retain pinned Git identity and receive only the parent-owned patch. */
export function prepareBuildSource(repository: string, base: string, patch: string): string {
    const name = basename(repository);
    requireValue(["dobby", "lsplant", "libsepol"].includes(name), "unknown native source owner");
    const expectedPatch = readFileSync(patch);
    const identity = { schema: 1, base, patchSha256: createHash("sha256").update(expectedPatch).digest("hex") };
    const parent = resolve(ROOT, "build/third-party-source");
    mkdirSync(parent, { recursive: true });
    const destination = join(parent, name);
    const stamp = join(destination, ".git/voboost-source.json");
    if (existsSync(destination)) {
        requireValue(realpathSync(destination) === destination, "native build source directory is a symlink");
        requireValue(existsSync(stamp), "refusing an unowned native build source directory");
        requireValue(readFileSync(stamp, "utf8") === JSON.stringify(identity) + "\n", "native build source identity changed; use a fresh build directory");
        requireValue(runText("git", ["-C", destination, "rev-parse", "HEAD"]) === base, "native build source HEAD drift");
        requireValue(run("git", ["-C", destination, "diff", "HEAD", "--no-ext-diff", "--binary"]).equals(expectedPatch), "native build source patch drift");
        requireValue(!runText("git", ["-C", destination, "status", "--porcelain=v1", "--untracked-files=all"]).split("\n").some((row) => row.startsWith("?? ")), "native build source contains untracked inputs");
        validateNestedCopies(repository, destination, base);
        return destination;
    }
    const temporary = mkdtempSync(join(parent, `.${name}-`));
    try {
        clonePinned(repository, base, temporary);
        run("git", ["-C", temporary, "apply", "--check", patch]);
        run("git", ["-C", temporary, "apply", patch]);
        requireValue(run("git", ["-C", temporary, "diff", "--no-ext-diff", "--binary"]).equals(expectedPatch), "prepared native source differs from parent patch");
        validateNestedCopies(repository, temporary, base);
        writeFileSync(join(temporary, ".git/voboost-source.json"), JSON.stringify(identity) + "\n", { flag: "wx" });
        renameSync(temporary, destination);
    } finally {
        if (existsSync(temporary)) rmSync(temporary, { recursive: true });
    }
    return destination;
}
