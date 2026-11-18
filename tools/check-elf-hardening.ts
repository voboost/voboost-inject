import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { main, requireValue, ROOT, runText } from "./lib.ts";

// Every release artifact must be PIE (ET_DYN), have GNU_RELRO and a
// non-executable GNU_STACK. Dynamically linked artifacts must additionally
// bind all symbols at load time (DT_BIND_NOW / DF_BIND_NOW / DF_1_NOW).
// voboost-selinux is the one exception: it is a non-PIE static executable
// (ET_EXEC). NDK r29 bionic has no static-PIE self-relocator, and kernels
// such as the API 30 emulator's android11-5.4 do not apply the relocations
// of an interpreter-less ET_DYN image, so -static-pie SIGSEGVs during
// __libc_init before main. A relocation-free ET_EXEC runs on every
// supported kernel; it still must not depend on shared libraries.
interface ArtifactExpectation {
    path: string;
    binding: "immediate" | "static";
    elfType?: "DYN" | "EXEC";
}

const ARTIFACTS: ArtifactExpectation[] = [
    { path: "target/aarch64-linux-android/release/voboost-daemon", binding: "immediate" },
    { path: "target/aarch64-linux-android/release/voboost-inject", binding: "immediate" },
    { path: "target/aarch64-linux-android/release/voboost-install", binding: "immediate" },
    { path: "target/aarch64-linux-android/release/voboost-uninstall", binding: "immediate" },
    { path: "build/restore/arm64-v8a/voboost-restore", binding: "immediate" },
    { path: "build/selinux/arm64-v8a/voboost-selinux", binding: "static", elfType: "EXEC" },
    { path: "implant/libs/arm64-v8a/libimplant.so", binding: "immediate" },
    { path: "implant/libs/armeabi-v7a/libimplant.so", binding: "immediate" },
];

function findReadelf(): string {
    const ndkHome = process.env.NDK_HOME ?? process.env.ANDROID_NDK_HOME ?? "";
    if (ndkHome) {
        const prebuilt = join(ndkHome, "toolchains", "llvm", "prebuilt");
        if (existsSync(prebuilt)) {
            for (const host of readdirSync(prebuilt)) {
                const candidate = join(prebuilt, host, "bin", "llvm-readelf");
                if (existsSync(candidate)) return candidate;
            }
        }
    }
    return "llvm-readelf";
}

function checkArtifact(readelf: string, artifact: ArtifactExpectation): void {
    const file = join(ROOT, artifact.path);
    requireValue(existsSync(file), `missing artifact (run the Android build first): ${artifact.path}`);

    const header = runText(readelf, ["--file-header", file]);
    const expectedType = artifact.elfType ?? "DYN";
    requireValue(new RegExp(`Type:\\s+${expectedType}\\s`).test(header), `${artifact.path}: ELF type must be ${expectedType}, got ${/Type:\s+(\S+)/.exec(header)?.[1]}`);

    const program = runText(readelf, ["--program-headers", file]);
    requireValue(/GNU_RELRO/.test(program), `${artifact.path}: GNU_RELRO segment missing`);
    const stack = /GNU_STACK\s+(.*)/.exec(program)?.[1] ?? "";
    requireValue(!/\bRWE\b/.test(stack), `${artifact.path}: GNU_STACK must be non-executable, got "${stack.trim().split(/\s+/).slice(0, 7).join(" ")}"`);

    const sections = runText(readelf, ["--sections", file]);
    requireValue(!/\.debug_[A-Za-z0-9_.-]+/.test(sections), `${artifact.path}: release ELF contains a .debug_* section`);

    if (artifact.binding === "immediate") {
        const dynamic = runText(readelf, ["--dynamic", file]);
        requireValue(
            /(BIND_NOW|FLAGS[^\n]*\bNOW\b|FLAGS_1[^\n]*\bNOW\b)/.test(dynamic),
            `${artifact.path}: immediate binding (BIND_NOW) required for a dynamic artifact`,
        );
    } else {
        const dynamic = runText(readelf, ["--dynamic", file], { allowFailure: true });
        requireValue(!/\bNEEDED\b/.test(dynamic), `${artifact.path}: static executable must not depend on shared libraries`);
    }
    console.log(`elf-hardening ok: ${artifact.path}`);
}

main(() => {
    const readelf = findReadelf();
    for (const artifact of ARTIFACTS) checkArtifact(readelf, artifact);
}, "check-elf-hardening");
