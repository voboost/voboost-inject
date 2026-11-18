import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { ROOT, main, requireValue } from "./lib.ts";

main(() => {
    const source = readFileSync(resolve(ROOT,
        "build/third-party-source/lsplant/lsplant/src/main/jni/lsplant.cc"), "utf8");
    const begin = "// Voboost inline publication transaction begin\n";
    const end = "// Voboost inline publication transaction end";
    requireValue(source.split(begin).length === 2 && source.split(end).length === 2,
        "inline publication source boundary differs");
    mkdirSync(resolve(ROOT, "build"), { recursive: true });
    writeFileSync(resolve(ROOT, "build/inline_hook_transaction_test.inc"),
        source.split(begin)[1].split(end)[0]);
    const init = source.slice(source.indexOf("bool InitNative("), source.indexOf("BuildDex("));
    requireValue(init.indexOf("ScopedSuspendAll::Init(resolver)") < init.indexOf("ArtMethod::Init"),
        "suspension prerequisite follows an inline hook initializer");
    requireValue(init.includes("const HookHandler handler(info,") && init.includes(
        "voboost_inline_publication::Install<ScopedGCCriticalSection, ScopedSuspendAll>"),
        "production hook handler has no suspension transaction");
    const dobby = readFileSync(resolve(ROOT,
        "build/third-party-source/dobby/source/InterceptRouting/InlineHookRouting.h"), "utf8");
    const hook = dobby.slice(dobby.indexOf("PUBLIC inline int DobbyHook("));
    writeFileSync(resolve(ROOT, "build/dobby_inline_hook_test.inc"), hook);
    console.log("inline-hook-test: exact prepared LSPlant transaction and Dobby body extracted");
}, "prepare-inline-hook-test");
