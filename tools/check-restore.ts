#!/usr/bin/env node
import { existsSync, lstatSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { main, requireValue, ROOT, runText } from "./lib.ts";

const CONTRACTS = [
    { abi: "arm64-v8a", machine: "AArch64", interpreter: "/system/bin/linker64" },
] as const;
main(() => {
    const index = process.argv.indexOf("--readelf");
    const readelf = index >= 0 ? process.argv[index + 1] : undefined;
    requireValue(readelf && existsSync(readelf), `llvm-readelf is absent: ${readelf ?? "<missing>"}`);
    const uninstallPath = resolve(ROOT, "target/aarch64-linux-android/release/voboost-uninstall");
    requireValue(existsSync(uninstallPath), "missing built voboost-uninstall comparison artifact");
    const uninstallBytes = readFileSync(uninstallPath);
    for (const contract of CONTRACTS) {
        const relative = `build/restore/${contract.abi}/voboost-restore`;
        const path = resolve(ROOT, relative);
        requireValue(existsSync(path), `missing ${relative}`);
        const metadata = lstatSync(path);
        requireValue(metadata.isFile() && !metadata.isSymbolicLink(), `${relative} is not a regular non-symlink file`);
        requireValue(metadata.size > 0 && metadata.size <= 8 * 1024 * 1024, `${relative} exceeds the signed bootstrap bound`);
        const header = runText(readelf, ["-h", path]);
        const program = runText(readelf, ["-l", path]);
        const dynamic = runText(readelf, ["-d", path]);
        requireValue(/^\s*Type:\s+DYN\b/m.test(header), `${relative} is not PIE ET_DYN`);
        requireValue(/^\s*Machine:\s+(.+?)\s*$/m.exec(header)?.[1] === contract.machine, `${relative} machine does not match its ABI`);
        requireValue(
            program.includes(`[Requesting program interpreter: ${contract.interpreter}]`),
            `${relative} Android interpreter differs`,
        );
        requireValue(/^\s*GNU_RELRO\s/m.test(program), `${relative} lacks GNU_RELRO`);
        const stack = /^\s*GNU_STACK\s+.+$/m.exec(program)?.[0] ?? "";
        requireValue(stack.includes(" RW ") && !stack.includes(" RWE "), `${relative} stack is executable`);
        const needed = [...dynamic.matchAll(/\(NEEDED\)\s+Shared library: \[([^\]]+)\]/gu)]
            .map((match) => match[1])
            .sort();
        requireValue(
            JSON.stringify(needed) === JSON.stringify(["libc.so", "libdl.so"]),
            `${relative} dynamic dependency closure differs`,
        );
        requireValue(dynamic.includes("(BIND_NOW)") || dynamic.includes("BIND_NOW"), `${relative} lacks BIND_NOW`);
        requireValue(dynamic.includes("NOW PIE"), `${relative} lacks PIE dynamic flags`);
        requireValue(!readFileSync(path).equals(uninstallBytes), `${relative} is a renamed voboost-uninstall artifact`);
    }
    console.log("restore: ARM64 bootstrap is a bounded hardened Android PIE artifact");
}, "restore");
