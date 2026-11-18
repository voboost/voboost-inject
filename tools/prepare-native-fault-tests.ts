import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { main, requireValue, ROOT } from "./lib.ts";

main(() => {
    const injector = readFileSync(resolve(ROOT, "injector/thread_group.c"), "utf8");
    const implant = readFileSync(resolve(ROOT, "implant/implant.cpp"), "utf8");
    const extract = (source: string, start: string, end: string): string => {
        requireValue(source.split(start).length === 2 && source.split(end).length === 2,
            "native fault-test source boundary differs");
        const begin = source.indexOf(start);
        const finish = source.indexOf(end, begin);
        requireValue(finish > begin, "native fault-test source ordering differs");
        return source.slice(begin, finish);
    };
    mkdirSync(resolve(ROOT, "build"), { recursive: true });
    const syscallSource = extract(injector, "static int system_attach(",
        "static int system_wait_stopped(");
    const classifier = extract(injector, "int vbi_tg_classify_wait_error(",
        "static int parse_u32_token(");
    writeFileSync(resolve(ROOT, "build/thread_group_errno_test.inc"), classifier + syscallSource);
    const bootstrap = extract(implant, "    if (g_pipe_bootstrap.manifest.empty()) {",
        "    return stage_bootstrap_worker();");
    writeFileSync(resolve(ROOT, "build/bootstrap_flags_test.inc"), bootstrap);
}, "prepare-native-fault-tests");
