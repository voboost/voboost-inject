#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { main, requireValue, ROOT } from "./lib.ts";

main(() => {
    const read = (path: string) => readFileSync(resolve(ROOT, path), "utf8");
    const build = read("daemon/build.rs");
    const mainSource = read("daemon/src/main.rs");
    const runtime = read("daemon/src/runtime.rs");
    const lifecycle = read("daemon/src/lifecycle.rs");
    const candidate = read("daemon/src/product_candidate.rs");
    const makefile = read("Makefile");
    const keyWrapper = read("tools/with-ephemeral-native-role-keys.ts");
    const releaseTool = read("tools/release-tool.ts");

    const productBuildInputs = [
        "VOBOOST_RELEASE_CHANNEL",
        "VOBOOST_RELEASE_BASE_VERSION",
        "VOBOOST_RELEASE_BETA",
        "DAEMON_RELEASE_CHANNEL",
        "DAEMON_BASE_VERSION",
        "DAEMON_RELEASE_BETA",
    ];
    for (const input of productBuildInputs) {
        requireValue(!build.includes(input), `daemon build consumes product identity ${input}`);
        requireValue(
            !keyWrapper.includes(input),
            `native build wrapper injects product identity ${input}`,
        );
    }
    requireValue(!mainSource.includes("/version.rs"), "daemon includes generated product version");
    requireValue(!mainSource.includes("mod update;"), "legacy native update module is reachable");
    requireValue(
        !mainSource.includes("mod release_manifest;"),
        "legacy native manifest parser is reachable",
    );
    requireValue(
        mainSource.includes("mod product_candidate;") &&
            lifecycle.includes("recover_product_activation()"),
        "product candidate is not the runtime product-update owner",
    );
    requireValue(
        !runtime.includes("update-ready.json") && !runtime.includes("update::apply"),
        "runtime still polls legacy native staging",
    );
    for (const authority of [
        "verify-release-manifest",
        "write-release-sbom",
        "install-authorization-transcript",
    ]) {
        requireValue(
            !releaseTool.includes(authority),
            `component release tool still exposes retired authority ${authority}`,
        );
    }

    const buildDaemon = makefile
        .split("build-daemon build-inject:")[1]
        ?.split("\nbuild-uninstall:")[0];
    requireValue(Boolean(buildDaemon), "build-daemon recipe is absent");
    for (const input of [...productBuildInputs, "VOBOOST_NATIVE_MANIFEST_PUBLIC_KEY_PEM"]) {
        requireValue(
            !buildDaemon!.includes(input),
            `build-daemon recipe carries retired input ${input}`,
        );
    }
    requireValue(
        !makefile.includes("\nrelease-manifest:") && !makefile.includes("voboost-inject.json"),
        "Make graph still authors the retired native component manifest",
    );
    requireValue(
        makefile.includes("test-daemon-versionless-reproducible:") &&
            makefile.includes("tools/test-daemon-versionless-reproducible.sh") &&
            makefile
                .split("build-android:")[1]
                ?.split("test-prepare-beta1-unsigned:")[0]
                ?.includes("test-daemon-versionless-reproducible"),
        "Android byte reproducibility gate is not wired",
    );
    const reproducible = read("tools/test-daemon-versionless-reproducible.sh");
    requireValue(
        reproducible.includes('VOBOOST_RELEASE_CHANNEL="$channel"') &&
            reproducible.includes('VOBOOST_RELEASE_BASE_VERSION="$base"') &&
            reproducible.includes('VOBOOST_RELEASE_BETA="$beta"') &&
            reproducible.includes('cmp "$first" "$second"'),
        "Android byte reproducibility gate does not vary retired product identity and compare exact ELF bytes",
    );

    const publish = candidate
        .split("fn publish_product_manifest(")[1]
        ?.split("fn maybe_crash(")[0];
    requireValue(Boolean(publish), "product manifest publication function is absent");
    requireValue(
        publish!.includes("for name in [SIGNATURE, MANIFEST]") &&
            !publish!.includes("voboost-inject.json"),
        "product activation does not publish voboost.json manifest-last",
    );
    requireValue(
        candidate.includes("verify_appended_signature(role, &candidate_bytes)") &&
            candidate.includes("verify_running(path, size, &daemon.sha256)"),
        "product candidate lost native role or running-inode verification",
    );

    console.log(
        "daemon-versionless: no product-version build inputs; product_candidate is the only reachable update owner",
    );
}, "daemon-versionless");
