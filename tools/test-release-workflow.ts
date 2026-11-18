#!/usr/bin/env node

import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { main, requireValue, ROOT } from "./lib.ts";

function ordered(source: string, fragments: string[]): boolean {
    const positions = fragments.map((fragment) => source.indexOf(`${fragment}\n`));
    return positions.every((position) => position >= 0) &&
        positions.every((position, index) => index === 0 || positions[index - 1] < position);
}

export function validate(ci: string, adapter: string, workflows: string[]): void {
    requireValue(
        workflows.length === 1 && workflows[0] === "ci.yml",
        `voboost-inject must own only ci.yml, found: ${workflows.join(", ")}`,
    );
    requireValue(/push:\n\s+branches: \[main\]/u.test(ci), "CI must verify main");
    requireValue(ci.includes("pull_request:") && ci.includes("workflow_dispatch:"), "CI triggers differ");
    requireValue(ci.includes("permissions:\n  contents: read"), "CI permissions are not read-only");
    requireValue(
        !/\bsecrets\.|\benvironment:|contents:\s*write|packages:\s*write|id-token:\s*write/u.test(ci),
        "component CI can receive a private role or write externally",
    );
    requireValue(
        !/dev-vithar|release-request|release-event|repository-dispatch|gh release|upload-artifact/iu.test(ci),
        "component CI still owns release coordination or publication",
    );
    requireValue(
        !/^\s*uses:\s+\S+@v[0-9]+(?:\s+#.*)?$/mu.test(ci),
        "CI action is not pinned to an immutable commit",
    );
    requireValue(ci.includes("submodules: recursive"), "CI does not fetch pinned submodules");
    requireValue(ci.includes("persist-credentials: false"), "CI checkout retains credentials");
    requireValue(
        ordered(ci, [
            "run: make init",
            "run: npm ci",
            "run: make test-tooling",
            "run: make lint",
            "run: make test",
            "run: make coverage",
            "run: make build",
        ]),
        "CI verification order differs",
    );

    const expected = [
        "voboost-daemon",
        "voboost-inject",
        "voboost-install",
        "voboost-restore",
        "voboost-uninstall",
        "voboost-selinux",
        "voboost.rc",
        "libimplant-arm64-v8a.so",
        "libimplant-armeabi-v7a.so",
    ];
    requireValue(
        expected.every((name) => adapter.includes(name)),
        "unsigned product adapter omits a native closure member",
    );
    requireValue(
        !/SIGNING_KEY|PRIVATE_KEY|openssl|gh |git push|upload|release-event|channel/iu.test(adapter),
        "unsigned product adapter performs signing, publication, or channel work",
    );
    requireValue(
        adapter.includes('exported ${#names[@]} flat unsigned native artifacts') &&
            adapter.includes('${#names[@]} -eq ' + expected.length) &&
            !adapter.includes("--emulator"),
        "adapter result or production-only input selection differs",
    );
}

main(() => {
    const workflowDirectory = resolve(ROOT, ".github/workflows");
    const workflows = readdirSync(workflowDirectory).sort();
    const ci = readFileSync(resolve(workflowDirectory, "ci.yml"), "utf8");
    const adapter = readFileSync(resolve(ROOT, "tools/prepare-beta1-unsigned.sh"), "utf8");
    validate(ci, adapter, workflows);

    const mutations: Array<[string, string, string, string[]]> = [
        ["write permission", ci.replace("contents: read", "contents: write"), adapter, workflows],
        ["publication step", `${ci}\n# gh release create\n`, adapter, workflows],
        ["untrusted action tag", ci.replace("@11d5960a326750d5838078e36cf38b85af677262", "@v4"), adapter, workflows],
        ["signing adapter", ci, `${adapter}\n# SIGNING_KEY\n`, workflows],
        ["release workflow", ci, adapter, [...workflows, "release.yml"].sort()],
    ];
    for (const [label, changedCi, changedAdapter, changedWorkflows] of mutations) {
        try {
            validate(changedCi, changedAdapter, changedWorkflows);
        } catch {
            continue;
        }
        throw new Error(`release ownership mutation was accepted: ${label}`);
    }
    console.log("release-workflow: component CI is read-only and release ownership is external");
}, "release-workflow");
