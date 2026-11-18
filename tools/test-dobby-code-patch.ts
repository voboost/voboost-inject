import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ROOT, main, requireValue, run } from "./lib.ts";

main(() => {
    const parent = join(ROOT, ".work162");
    mkdirSync(parent, { recursive: true });
    const temporary = mkdtempSync(join(parent, "dobby-code-patch-"));
    const path = "source/Backend/UserMode/ExecMemory/code-patch-tool-posix.cc";
    try {
        // Retain only the actual patched translation unit, never a source-tree copy.
        mkdirSync(join(temporary, "source/Backend/UserMode/ExecMemory"), { recursive: true });
        writeFileSync(join(temporary, path), run("git", ["-C", "third_party/dobby", "show", `HEAD:${path}`]));
        const patch = readFileSync(join(ROOT, "patches/dobby/dobby-r29.patch"), "utf8");
        const section = patch.split(/(?=^diff --git )/m).find((part) => part.startsWith(`diff --git a/${path} `));
        requireValue(section, "actual DobbyCodePatch patch missing");
        run("patch", ["-p1", "--batch"], { cwd: temporary, input: Buffer.from(section) });
        mkdirSync(join(temporary, "dobby"));
        writeFileSync(join(temporary, "dobby/dobby_internal.h"), `#include <stdint.h>
#define PUBLIC
using addr_t = uintptr_t;
#define ALIGN_FLOOR(value, alignment) ((uintptr_t)(value) & ~((uintptr_t)(alignment) - 1))
static void ClearCache(void *, void *) {}
`);
        const binary = join(temporary, "regression");
        run(process.env.CXX ?? "clang++", ["-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", temporary,
            "-DDOBBY_PATCH_SOURCE=\"" + join(temporary, path) + "\"",
            "test/dobby_code_patch_test.cpp", "-o", binary]);
        run(binary, []);
        console.log("dobby-code-patch: denied transition, successful writes and page boundaries passed");
    } finally {
        rmSync(temporary, { recursive: true, force: true });
    }
}, "dobby-code-patch");
