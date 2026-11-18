#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { main, requireValue, ROOT } from "./lib.ts";

const FORBIDDEN_CURRENT_PATHS = ["/data/voboost-recovery", "/data/.voboost", "/data/.voboost-install-root", "/system/bin/voboost-selinux", "/data/voboost-uninstall-resume"];

function requireFragment(document: string, fragment: string, label: string): void {
    requireValue(document.includes(fragment), `${label} is missing ${JSON.stringify(fragment)}`);
}

main(() => {
    const english = readFileSync(resolve(ROOT, "README.md"), "utf8");
    const russian = readFileSync(resolve(ROOT, "README.ru.md"), "utf8");
    const prebuilt = readFileSync(resolve(ROOT, "prebuilt/README.md"), "utf8");
    const libsepol = readFileSync(resolve(ROOT, "patches/libsepol/README.md"), "utf8");
    const updateStaging = readFileSync(resolve(ROOT, "openspec/specs/update-staging/spec.md"), "utf8");
    const updateSource = readFileSync(resolve(ROOT, "daemon/src/product_candidate.rs"), "utf8");
    for (const [label, document] of [["README.md", english], ["README.ru.md", russian]] as const) {
        for (const fragment of ["voboost-inject", "docs-dev/native", "LICENSE", "THIRD_PARTY.md"]) {
            requireFragment(document, fragment, label);
        }
        for (const path of FORBIDDEN_CURRENT_PATHS) requireValue(!document.includes(path), `${label} still names forbidden path ${path}`);
        for (const obsolete of ["/data/voboost/trust", "SELinux patcher", "single-reboot completion", "operation-status.json", "install-app-apply"]) {
            requireValue(!document.includes(obsolete), `${label} still names obsolete contract ${obsolete}`);
        }
    }
    for (const [label, document] of [["README.md", english], ["README.ru.md", russian], ["prebuilt/README.md", prebuilt], ["patches/libsepol/README.md", libsepol]] as const) {
        requireValue(document.trim().split("\n").length <= 12, `${label} must remain a concise local entrypoint`);
    }
    requireFragment(prebuilt, "native-dependencies.md", "prebuilt/README.md");
    requireFragment(prebuilt, "armeabi-v7a/libdobby.provenance.json", "prebuilt/README.md");
    requireFragment(libsepol, "native-dependencies.md", "patches/libsepol/README.md");
    requireFragment(libsepol, "0001-android-xperms-layout.patch", "patches/libsepol/README.md");
    const provenance = JSON.parse(readFileSync(resolve(ROOT, "prebuilt/armeabi-v7a/libdobby.provenance.json"), "utf8"));
    requireValue(provenance.sourceCommit === null, "the committed armv7 prebuilt source remains explicitly unknown");
    for (const [label, document] of [["update-staging spec", updateStaging], ["product candidate source", updateSource]] as const) {
        requireFragment(document, "product-proposal.json", label);
        requireFragment(document, "voboost.json", label);
        requireValue(!document.includes("staging-inject"), `${label} still names forbidden staging-inject path`);
    }
    requireValue(
        !updateSource.includes("voboost-inject.json") &&
            !updateSource.includes("update-ready.json") &&
            !updateSource.includes("update-ack.json"),
        "product candidate source still names retired native update authority",
    );
    console.log("doc-consistency: concise entrypoints, source provenance and product candidate authority OK");
}, "doc-consistency");
