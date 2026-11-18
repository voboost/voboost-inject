#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { main, requireValue, ROOT } from "./lib.ts";

function target(source: string, name: string): { dependencies: string; body: string } {
    const match = new RegExp(`^${name}:([^\\n]*)\\n((?:\\t.*\\n|\\n)*)`, "m").exec(source);
    requireValue(match, `Make target ${name} is absent`);
    return { dependencies: match[1].trim(), body: match[2] };
}

export function validate(makefile: string, workflow: string): void {
    requireValue(workflow.includes("submodules: recursive"), "CI checkout omits recursive submodules");
    requireValue(workflow.includes("persist-credentials: false"), "CI checkout retains credentials");
    const order = [
        "run: make init",
        "run: npm ci",
        "run: make test-tooling",
        "run: make lint",
        "run: make test",
        "run: make coverage",
        "run: make build",
    ].map((fragment) => workflow.indexOf(`${fragment}\n`));
    requireValue(
        order.every((position) => position >= 0) &&
            order.every((position, index) => index === 0 || order[index - 1] < position),
        "CI does not provision and verify a clean checkout in canonical order",
    );

    const tooling = target(makefile, "test-tooling");
    requireValue(
        tooling.dependencies === "" && tooling.body.trim() === "@npm run check:tooling",
        "make test-tooling must execute the complete package test graph exactly once",
    );
    const init = target(makefile, "init").body
        .split("\n")
        .filter((line) => line.startsWith("\t"))
        .map((line) => line.trim());
    requireValue(
        init[0] === "git submodule update --init --recursive" &&
            init[1] === "$(MAKE) --no-print-directory test-third-party-source-contract",
        "make init source-contract prefix differs",
    );
    const thirdPartyBuild = target(makefile, "build-third-party");
    requireValue(
        thirdPartyBuild.dependencies === "test-third-party-source-contract",
        "build-third-party does not fail closed on source contract",
    );
    requireValue(
        thirdPartyBuild.body.includes("node tools/prepare-native-third-party-source.ts --apply"),
        "build-third-party does not materialize the exact parent patches",
    );
    const testBody = target(makefile, "test").body;
    const gates = ["test-armv7-dobby-prebuilt", "test-selinux", "test-selinux-real-policy"].map(
        (name) => testBody.indexOf(`$(MAKE) --no-print-directory ${name}`),
    );
    requireValue(
        gates.every((position) => position >= 0) && gates[0] < gates[1] && gates[1] < gates[2],
        "make test omits or reorders native provenance and SELinux gates",
    );
    requireValue(
        !/installer-release-event|release-reconciler|repository-dispatch/iu.test(testBody),
        "host test graph still depends on cross-repository release coordination",
    );
}

main(() => {
    const makefile = readFileSync(resolve(ROOT, "Makefile"), "utf8");
    const workflow = readFileSync(resolve(ROOT, ".github/workflows/ci.yml"), "utf8");
    const hostTests = [
        "daemon/src/generation/test_support.rs",
        "daemon/src/generation/tests.rs",
        "test/selinux/run.sh",
    ].map((path) => readFileSync(resolve(ROOT, path), "utf8")).join("\n");
    const hostBuildScripts = [
        "daemon/build.rs",
        "install/build.rs",
        "restore/build.rs",
        "uninstall/build.rs",
    ].map((path) => readFileSync(resolve(ROOT, path), "utf8")).join("\n");
    requireValue(!hostTests.includes("release-private.pem"), "host tests require a persistent private key");
    requireValue(
        !hostBuildScripts.includes("release-public.pem") &&
            !hostBuildScripts.includes("key-dev-public.pem") &&
            !hostBuildScripts.includes("Ok([0; 32])"),
        "host Rust builds bypass distinct secretless role fixtures",
    );
    validate(makefile, workflow);

    const mutations: Array<[string, string, string]> = [
        ["shallow submodules", makefile, workflow.replace("submodules: recursive", "submodules: false")],
        ["retained checkout credentials", makefile, workflow.replace("persist-credentials: false", "persist-credentials: true")],
        ["unpinned Node tooling", makefile, workflow.replace("run: npm ci", "run: npm install")],
        ["init omits recursive update", makefile.replace("\tgit submodule update --init --recursive\n", ""), workflow],
        ["build bypasses source contract", makefile.replace("build-third-party: test-third-party-source-contract", "build-third-party:"), workflow],
        ["test bypasses armv7 provenance", makefile.replace(/\t+\$\(MAKE\) --no-print-directory test-armv7-dobby-prebuilt.*\n/u, ""), workflow],
        ["CI omits tooling tests", makefile, workflow.replace("run: make test-tooling", "run: make build")],
    ];
    for (const [label, changedMakefile, changedWorkflow] of mutations) {
        try {
            validate(changedMakefile, changedWorkflow);
        } catch {
            continue;
        }
        throw new Error(`clean-checkout mutation was accepted: ${label}`);
    }
    console.log("clean-checkout-contract: source and verification gates are reachable from CI");
}, "clean-checkout-contract");
