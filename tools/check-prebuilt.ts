#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { main, requireValue, ROOT, runText } from "./lib.ts";
import { validateNativeExports } from "./native-exports.ts";

type Contract = { path: string; machine: string; soname: string; needed: string[] };
const CONTRACTS: Contract[] = [
    { path: "implant/libs/arm64-v8a/libimplant.so", machine: "AArch64", soname: "libimplant.so", needed: ["libc.so", "libdl.so", "liblog.so", "libm.so", "libz.so"] },
    { path: "implant/libs/armeabi-v7a/libimplant.so", machine: "ARM", soname: "libimplant.so", needed: ["libc.so", "libdl.so", "liblog.so", "libm.so", "libz.so"] },
];

export function validateReadelf(header: string, dynamic: string, contract: Omit<Contract, "path">): void {
    requireValue(/^\s*Type:\s+DYN\b/m.test(header), "payload is not an ET_DYN shared object");
    const machine = /^\s*Machine:\s+(.+?)\s*$/m.exec(header)?.[1];
    requireValue(machine === contract.machine, "payload machine does not match its ABI");
    requireValue(dynamic.includes("Dynamic section at offset"), "payload has no readable dynamic section");
    const sonames = [...dynamic.matchAll(/\(SONAME\).*\[([^\]]+)\]/g)].map((match) => match[1]);
    const needed = [...dynamic.matchAll(/\(NEEDED\).*\[([^\]]+)\]/g)].map((match) => match[1]).sort();
    requireValue(JSON.stringify(sonames) === JSON.stringify([contract.soname]), "payload SONAME differs from its release identity");
    requireValue(JSON.stringify(needed) === JSON.stringify([...contract.needed].sort()), `payload dependencies differ: expected=${contract.needed.sort()}, actual=${needed}`);
}

main(() => {
    const index = process.argv.indexOf("--readelf");
    const readelf = index >= 0 ? process.argv[index + 1] : undefined;
    requireValue(readelf && existsSync(readelf), `llvm-readelf is absent: ${readelf ?? "<missing>"}`);
    for (const contract of CONTRACTS) {
        const path = resolve(ROOT, contract.path);
        requireValue(existsSync(path), `missing ${contract.path}`);
        validateReadelf(runText(readelf, ["-h", path]), runText(readelf, ["-d", path]), contract);
        validateNativeExports(
            runText(readelf, ["--dyn-syms", "--wide", path]),
            readFileSync(resolve(ROOT, "implant/implant.map"), "utf8"),
        );
        console.log(`check-prebuilt: ok ${contract.path} (ET_DYN, closed dynamic contract)`);
    }
    console.log("check-prebuilt: release payload ELF and dynamic-link contract OK");
}, "check-prebuilt");
