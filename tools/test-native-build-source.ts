import { readFileSync, writeFileSync, unlinkSync } from "node:fs";
import { resolve } from "node:path";
import { ROOT, main, requireValue, run, runText } from "./lib.ts";
import { prepareBuildSource } from "./native-build-source.ts";

main(() => {
    const paths = ["third_party/dobby", "third_party/lsplant", "third_party/libsepol"];
    const before = paths.map((path) => runText("git", ["-C", path, "status", "--porcelain=v1", "--untracked-files=all"]));
    run("node", ["tools/prepare-native-third-party-source.ts", "--apply"]);
    run("node", ["tools/prepare-libsepol-source.ts", "--apply"]);
    requireValue(JSON.stringify(before) === JSON.stringify(paths.map((path) => runText("git", ["-C", path, "status", "--porcelain=v1", "--untracked-files=all"]))), "source preparation changed live submodules");
    for (const [name, patch] of [["dobby", "patches/dobby/dobby-r29.patch"], ["lsplant", "patches/lsplant/lsplant-r29.patch"], ["libsepol", "patches/libsepol/0001-android-xperms-layout.patch"]]) {
        const source = resolve(ROOT, "third_party", name);
        const base = runText("git", ["-C", source, "rev-parse", "HEAD"]);
        const copy = prepareBuildSource(source, base, resolve(ROOT, patch));
        requireValue(copy !== source, "native build uses live source");
        const tracked = resolve(copy, runText("git", ["-C", copy, "ls-files"]).split("\n")[0]);
        const bytes = readFileSync(tracked);
        try {
            writeFileSync(tracked, Buffer.concat([bytes, Buffer.from("\n/* build source drift */\n")]));
            let rejected = false;
            try { prepareBuildSource(source, base, resolve(ROOT, patch)); } catch { rejected = true; }
            requireValue(rejected, "mutated native build source was accepted");
        } finally { writeFileSync(tracked, bytes); }
        if (name === "lsplant") {
            const stray = resolve(copy, "lsplant/src/main/jni/external/dex_builder/voboost-drift-test.tmp");
            writeFileSync(stray, "unexpected nested build input\n", { flag: "wx" });
            try {
                let rejected = false;
                try { prepareBuildSource(source, base, resolve(ROOT, patch)); } catch { rejected = true; }
                requireValue(rejected, "untracked nested native build input was accepted");
            } finally { unlinkSync(stray); }
        }
    }
    console.log("native-build-source: pinned patched copies, live source immutability and drift rejection passed");
}, "native-build-source");
