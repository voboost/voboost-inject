import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { ROOT, requireValue, main } from "./lib.ts";

main(() => {
    const source = readFileSync(resolve(ROOT,
        "build/third-party-source/lsplant/lsplant/src/main/jni/lsplant.cc"), "utf8");
    const begin = "// Voboost backup publication transaction begin\n";
    const end = "// Voboost backup publication transaction end";
    requireValue(source.split(begin).length === 2 && source.split(end).length === 2,
        "publication transaction markers differ");
    writeFileSync(resolve(ROOT, "build/lsplant_backup_publication_test.inc"),
        source.split(begin)[1].split(end)[0]);
    const hook = source.slice(source.indexOf("static jobject HookWithPublisher("),
        source.indexOf("[[maybe_unused]] bool UnHook("));
    requireValue(hook.includes("publisher(env, hooker_object, reflected_backup.get()) == JNI_TRUE")
        && hook.includes("&& !env->ExceptionCheck()"), "publisher does not receive genuine reflected backup");
    requireValue(hook.indexOf("voboost_hook_publication::PublishThenActivate")
        < hook.indexOf("return DoHook(target, hook, backup, diagnostics)"), "transaction does not wrap activation");
    requireValue(hook.includes("if (!publisher) return nullptr;"), "extension accepts missing publisher");
    const native = readFileSync(resolve(ROOT, "implant/implant.cpp"), "utf8");
    requireValue(native.includes("jobject backup = voboost_lsplant_hook_with_backup(")
        && !native.includes("p_lsplant_hook") && !native.includes("load_native_libs"),
        "production must use the statically linked publication entrypoint");
    requireValue(native.includes('"setBackup", "(Ljava/lang/reflect/Method;)V"'), "Java setter ABI changed");
    console.log("lsplant-backup-publication: exact prepared transaction and required native extension OK");
}, "lsplant-backup-publication");
