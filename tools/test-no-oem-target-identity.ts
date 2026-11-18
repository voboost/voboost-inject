import { readFileSync } from "node:fs";
import { join } from "node:path";

const root = process.cwd();
const files = [
    "daemon/src/catalog.rs",
    "daemon/src/target_identity.rs",
    "daemon/src/injector.rs",
    "daemon/src/process_watcher.rs",
    "daemon/src/reconcile.rs",
    "daemon/src/runtime.rs",
    "injector/injector.c",
    "injector/injector.h",
    "injector/Android.mk",
    "injector/target_process_profile.h",
    "injector/thread_group.c",
    "injector/thread_group.h",
];
const forbidden = [
    "base_apk",
    "baseApkPaths",
    "signer_certificate",
    "signerCertificateSha256",
    "expect_apk",
    "apk_stamp",
    "target_apk",
    "target_identity_guard",
    "package == target.process",
];
const forbiddenPatterns = [
    /\bpackage\s*:/,
];
const forbiddenRuntimeOnlyPatterns = [
    /\.apk\b/i,
    /androidmanifest/i,
];

for (const file of files) {
    const completeSource = readFileSync(join(root, file), "utf8");
    let source = completeSource;
    if (file === "daemon/src/catalog.rs") {
        const marker = "\n#[cfg(test)]\nmod tests {";
        const markerIndex = completeSource.indexOf(marker);
        if (markerIndex < 0) {
            throw new Error("daemon catalog production/test boundary is missing");
        }
        source = completeSource.slice(0, markerIndex);
    }
    for (const token of forbidden) {
        if (source.includes(token)) {
            throw new Error(`${file} transports forbidden OEM target identity token ${token}`);
        }
    }
    for (const pattern of forbiddenPatterns) {
        if (pattern.test(source)) {
            throw new Error(`${file} transports forbidden OEM target identity pattern ${pattern}`);
        }
    }
    if (file !== "daemon/src/catalog.rs") {
        for (const pattern of forbiddenRuntimeOnlyPatterns) {
            if (pattern.test(source)) {
                throw new Error(`${file} reads forbidden OEM target APK pattern ${pattern}`);
            }
        }
    }
}

const ownedApkConsumers = [
    "install/src/main.rs",
    "uninstall/src/transaction/package.rs",
    "contract/apk.rs",
];
for (const file of ownedApkConsumers) {
    const source = readFileSync(join(root, file), "utf8");
    if (!source.includes("signer_sha256_v2_v3")) {
        throw new Error(`${file} lost Voboost-owned APK signer verification`);
    }
}

console.log("runtime target topology excludes OEM identity and preserves Voboost APK verification");
