import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { ROOT, requireValue, main } from "./lib.ts";

main(() => {
    const source = readFileSync(resolve(ROOT,
        "build/third-party-source/lsplant/lsplant/src/main/jni/lsplant.cc"), "utf8");
    const begin = "// Voboost diagnostic callback begin\n";
    const end = "// Voboost diagnostic callback end";
    requireValue(source.split(begin).length === 2 && source.split(end).length === 2,
        "diagnostic callback markers differ");
    const callback = source.split(begin)[1].split(end)[0];
    writeFileSync(resolve(ROOT, "build/lsplant_stage_callback_test.inc"),
        "#include <atomic>\n#include <chrono>\n#include <cstdint>\n" + callback);
    const doHook = source.slice(source.indexOf("bool DoHook("), source.indexOf("bool DoUnHook("));
    for (const [before, operation, after] of [
        ['diagnostics.Emit("gc-critical-begin")', "ScopedGCCriticalSection section(",
            'diagnostics.Emit("gc-critical-end")'],
        ['diagnostics.Emit("suspend-all-begin")', 'ScopedSuspendAll suspend("LSPlant Hook", false)',
            'diagnostics.Emit("suspend-all-end")'],
    ]) {
        requireValue(doHook.indexOf(before) >= 0 && doHook.indexOf(operation) > doHook.indexOf(before)
            && doHook.indexOf(after) > doHook.indexOf(operation), "constructor stage ordering differs");
    }
    requireValue(doHook.includes('diagnostics.Emit("mutation-end")'), "mutation stage missing");
    const buildDex = source.slice(source.indexOf("std::tuple<jclass"), source.indexOf("static_assert(std::endian"));
    requireValue(buildDex.includes('Stage jni_stage(diagnostics, "jni-begin", "jni-end")'),
        "JNI interval missing");
    console.log("lsplant-stage-callback: exact prepared callback and constructor boundaries OK");
}, "lsplant-stage-callback");
