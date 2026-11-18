import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { main, requireValue, ROOT } from "./lib.ts";

main(() => {
    const source = readFileSync(resolve(ROOT, "implant/safe_resolve.cpp"), "utf8");
    const signature = "void *safe_resolve_symbol_symtab(";
    requireValue(source.split(signature).length === 2, "symtab resolver source boundary differs");
    // Execute the complete production function with only /proc/self/maps redirected
    // to a fixture. ELF parsing, allocation, reads and cleanup remain unchanged.
    const functionSource = source.slice(source.indexOf(signature));
    requireValue(functionSource.trimEnd().endsWith("}"), "symtab resolver is incomplete");
    mkdirSync(resolve(ROOT, "build"), { recursive: true });
    writeFileSync(resolve(ROOT, "build/symtab_resolver_test.inc"), functionSource);
}, "prepare-symtab-test");
