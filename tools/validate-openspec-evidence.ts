#!/usr/bin/env node

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { main, requireValue, ROOT, runText } from "./lib.ts";

const PREFIXES = ["daemon-", "agent-generation-", "runtime-", "emulator-", "injector-", "implant-", "update-", "install-", "restore-", "uninstall-", "release-", "selinux-", "filesystem-", "global-", "native-"];
const CAPABILITIES = new Set([
    "agent-generation-publication", "agent-generation-staging", "daemon-config", "daemon-lifecycle",
    "filesystem-remount-safety", "implant-bootstrap", "implant-native-boundaries", "implant-rebind",
    "global-operation-coordination",
    "emulator-diagnostics",
    "injector-linker-reconstruction", "injector-process-discovery", "injector-remote-execution", "injector-target-evidence",
    "install-recovery", "update-activation", "update-rollback", "update-staging",
    "release-agent-trust", "release-native-trust", "release-signing", "release-verification",
    "native-recovery", "runtime-owner",
    "runtime-observability", "runtime-state", "runtime-transport", "runtime-resource-owner-delivery", "runtime-locale-host", "selinux-domain-policy", "selinux-program",
    "selinux-root-zone", "selinux-target-evidence", "uninstall-completion", "uninstall-control", "uninstall-recovery",
]);
const DEDICATED_MAKE_GATES = new Set([
    "test-cluster-locale-observer",
    "coverage", "test-bootstrap-worker", "test-inline-hook-publication", "test-main-thread-snapshot-scope",
    "test-armv7-dobby-prebuilt", "test-built-restore", "test-built-native-payload", "test-clean-checkout-contract", "test-inject-build-attestation", "test-daemon-versionless-reproducible",
    "test-implant-bounded-elf-string", "test-implant-downlink", "test-implant-pipe-bootstrap", "test-implant-pipe-manifest", "test-implant-production-host", "test-implant-runtime-safety",
    "test-injector-elf-parse", "test-injector-init-result", "test-injector-namespace-abi", "test-injector-parent-death", "test-injector-ptrace-recovery", "test-injector-ptrace-state",
    "test-injector-thread-group-clone-cleanup", "test-injector-thread-group-malformed-inventory",
    "test-injector-thread-group-stable-non-leader-input", "test-injector-thread-group-unstable-inventory-cleanup",
    "test-injector-target-process-profile",
    "test-injector-production-host", "test-injector-remote-call", "test-injector-callee-frames", "test-injector-managed-call", "test-lsplant-stage-callback", "test-lsplant-backup-publication",
    "test-restore", "test-native-reproducible-paths", "test-release-elf", "test-prepare-beta1-unsigned", "test-selinux-policy-backup", "test-selinux-policy-inject",
    "test-selinux-label-contract", "test-selinux-mls", "test-selinux-real-policy", "test-selinux-relabel-walk",
    "test-selinux-rule-generation", "test-selinux-watchdog", "test-selinux-boot-source",
    "test-third-party-source-contract",
    "verify-producer-agent-catalog",
]);
const DEDICATED_NODE_GATES = new Set([
    "tools/test-build-key-minimality.ts",
    "tools/test-daemon-versionless.ts",
    "tools/test-ephemeral-native-role-keys.ts", "tools/test-release-workflow.ts",
    "tools/test-no-oem-target-identity.ts",
    "tools/test-prepare-beta1-unsigned.ts",
]);

export function splitCommand(command: string): string[] {
    const result: string[] = [];
    let value = "";
    let quote = "";
    let escaped = false;
    for (const character of command) {
        if (escaped) { value += character; escaped = false; }
        else if (character === "\\" && quote !== "'") escaped = true;
        else if (quote) { if (character === quote) quote = ""; else value += character; }
        else if (character === "'" || character === '"') quote = character;
        else if (/\s/.test(character)) { if (value) { result.push(value); value = ""; } }
        else value += character;
    }
    requireValue(!quote && !escaped, "unterminated quote or escape");
    if (value) result.push(value);
    return result;
}

export function makeGate(argv: string[]): string {
    requireValue(argv[0] === "make", "Make Gate must use make");
    const targets = argv.slice(1).filter((token) => !token.startsWith("-") && !token.includes("="));
    requireValue(targets.length === 1, `Make Gate must select one named target: ${argv.join(" ")}`);
    return targets[0];
}

function makeTargets(source: string): Set<string> {
    return new Set([...source.matchAll(/^([A-Za-z0-9_.%/-]+)\s*:/gm)].map((match) => match[1]));
}

export function missingLabels(text: string, labels: string[]): string[] {
    return labels.filter((label) => !new RegExp(`^${label}:\\s*\\S`, "m").test(text));
}

function cargoTests(selector: string[]): string[] {
    const args = ["test", ...selector];
    if (!args.includes("--release")) args.push("--release");
    args.push("--", "--list");
    return runText("cargo", args).split("\n").filter((line) => line.endsWith(": test")).map((line) => line.slice(0, -6));
}

export function cargoGate(argv: string[]): { inventory: string; filter: string; selector: string[] } {
    requireValue(argv[0] === "cargo" && argv[1] === "test", "Cargo Gate must use cargo test");
    const separator = argv.indexOf("--");
    const options = separator >= 0 ? argv.slice(2, separator) : argv.slice(2);
    const after = separator >= 0 ? argv.slice(separator + 1) : [];
    let inventory = "workspace";
    const manifestIndex = options.indexOf("--manifest-path");
    if (manifestIndex >= 0) {
        const manifest = options[manifestIndex + 1];
        requireValue([
            "daemon/Cargo.toml",
            "install/Cargo.toml",
            "restore/Cargo.toml",
            "uninstall/Cargo.toml",
            "contract/Cargo.toml",
            "shared/Cargo.toml",
            "cluster/native/Cargo.toml",
        ].includes(manifest), `unsupported Cargo manifest ${manifest}`);
        inventory = manifest.slice(0, manifest.indexOf("/"));
    }
    const optionValues = new Set<number>();
    for (const option of ["--manifest-path", "--package", "-p", "--test", "--bin", "--example", "--features"]) {
        let index = options.indexOf(option);
        while (index >= 0) {
            requireValue(index + 1 < options.length, `Cargo Gate option ${option} requires a value`);
            optionValues.add(index + 1);
            index = options.indexOf(option, index + 1);
        }
    }
    requireValue(separator >= 0 && after.includes("--exact"), `Cargo Gate must pass -- --exact: ${argv.join(" ")}`);
    requireValue(after.every((value) => value === "--exact" || value.startsWith("-")), `Cargo Gate test filter must precede -- --exact: ${argv.join(" ")}`);
    const candidateIndexes = options
        .map((value, index) => ({ value, index }))
        .filter(({ value, index }) => !value.startsWith("-") && !optionValues.has(index));
    requireValue(candidateIndexes.length === 1, `Cargo Gate must select one named test: ${argv.join(" ")}`);
    const candidate = candidateIndexes[0];
    return {
        inventory,
        filter: candidate.value,
        selector: options.filter((_, index) => index !== candidate.index),
    };
}

export function capabilityErrors(actual: ReadonlySet<string>): string[] {
    const errors: string[] = [];
    const fail = (message: string): void => { errors.push(message); };
    const missing = [...CAPABILITIES].filter((name) => !actual.has(name));
    const extra = [...actual].filter((name) => !CAPABILITIES.has(name));
    if (missing.length || extra.length) fail(`capabilities differ: missing=${JSON.stringify(missing.sort())}, extra=${JSON.stringify(extra.sort())}`);
    for (const name of actual) if (!PREFIXES.some((prefix) => name.startsWith(prefix))) fail(`capability has no approved prefix: ${name}`);
    return errors;
}

export function validateOpenSpec(): string[] {
    const errors: string[] = [];
    const fail = (message: string): void => { errors.push(message); };
    const specsRoot = resolve(ROOT, "openspec/specs");
    const actual = new Set(readdirSync(specsRoot, { withFileTypes: true }).filter((entry) => entry.isDirectory() && existsSync(resolve(specsRoot, entry.name, "spec.md"))).map((entry) => entry.name));
    errors.push(...capabilityErrors(actual));

    const requirements = new Map<string, string>();
    const scenarios = new Map<string, string>();
    const markers = new Set<string>();
    const sections = new Set<string>();
    const mappingReferences: Array<{ relative: string; value: string }> = [];
    const gates = {
        daemon: new Set<string>(),
        install: new Set<string>(),
        restore: new Set<string>(),
        uninstall: new Set<string>(),
        contract: new Set<string>(),
        shared: new Set<string>(),
        workspace: new Set<string>(),
        cluster: new Set<string>(),
    };
    const targets = makeTargets(readFileSync(resolve(ROOT, "Makefile"), "utf8"));
    for (const capability of [...actual].sort()) {
        const relative = `openspec/specs/${capability}/spec.md`;
        const text = readFileSync(resolve(ROOT, relative), "utf8");
        for (const mapping of text.matchAll(/^Maps: ([\s\S]*?)(?=\n(?:Preconditions|Unavailable observation):)/gm)) {
            for (const reference of mapping[1].matchAll(/`([^`]+)`/g)) mappingReferences.push({ relative, value: reference[1].replace(/\s+/g, " ") });
        }
        if (/[А-Яа-яЁё]/.test(text)) fail(`${relative}: current OpenSpec contains Cyrillic`);
        if (/<!--[\s\S]*?#\s*(?:Gate|Unverified):[\s\S]*?-->/.test(text)) fail(`${relative}: evidence marker is hidden in a comment`);
        const requirementsEnd = text.indexOf("\n## Unverified\n");
        const normative = requirementsEnd < 0 ? text : text.slice(0, requirementsEnd);
        const requirementMatches = [...normative.matchAll(/^### Requirement: (.+)$/gm)];
        if (!requirementMatches.length) fail(`${relative}: capability contains no requirements`);
        requirementMatches.forEach((requirement, index) => {
            const title = requirement[1];
            if (requirements.has(title)) fail(`${relative}: duplicate requirement title also in ${requirements.get(title)}`);
            else requirements.set(title, relative);
            const start = requirement.index!;
            const end = index + 1 < requirementMatches.length ? requirementMatches[index + 1].index! : normative.length;
            const block = normative.slice(start, end);
            const localScenarios = [...block.matchAll(/^#### Scenario: (.+)$/gm)];
            if (!localScenarios.length) fail(`${relative}: requirement has no scenario: ${title}`);
            for (const scenario of localScenarios) {
                if (scenarios.has(scenario[1])) fail(`${relative}: duplicate scenario title also in ${scenarios.get(scenario[1])}`);
                else scenarios.set(scenario[1], relative);
                if (!text.replace(/\s+/g, " ").includes(`\`${scenario[1]}\``)) fail(`${relative}: scenario has no exact evidence mapping: ${scenario[1]}`);
            }
            const evidence = [...block.matchAll(/^# (Gate|Unverified): (.+)$/gm)];
            if (!evidence.length) fail(`${relative}: requirement has no visible evidence: ${title}`);
            if (localScenarios.length && evidence.length && evidence[0].index! < localScenarios.at(-1)!.index!) fail(`${relative}: evidence precedes final scenario: ${title}`);
            const seen = new Set<string>();
            for (const evidenceMarker of evidence) {
                const kind = evidenceMarker[1];
                const value = evidenceMarker[2];
                if (kind === "Unverified") { markers.add(value); continue; }
                const following = block.slice(evidenceMarker.index! + evidenceMarker[0].length).split(/^#/m, 1)[0];
                for (const label of missingLabels(following, ["Gate contract", "Maps", "Preconditions", "Observable result", "Evidence boundary"])) fail(`${relative}: Gate ${value} lacks ${label} label`);
                if (seen.has(value)) fail(`${relative}: duplicate Gate in requirement ${title}: ${value}`);
                seen.add(value);
                let argv: string[];
                try { argv = splitCommand(value); } catch (error) { fail(`${relative}: invalid Gate ${value}: ${String(error)}`); continue; }
                if (!argv.length || argv.some((token) => ["and", ";", "&&", "||"].includes(token))) { fail(`${relative}: composite or empty Gate: ${value}`); continue; }
                if (argv[0] === "cargo") {
                    try {
                        const gate = cargoGate(argv);
                        gates[gate.inventory as keyof typeof gates].add(JSON.stringify({
                            filter: gate.filter,
                            selector: gate.selector,
                        }));
                    } catch (error) { fail(`${relative}: ${error instanceof Error ? error.message : String(error)}`); }
                } else if (argv[0] === "make") {
                    try {
                        const target = makeGate(argv);
                        if (!targets.has(target)) fail(`${relative}: Gate names missing Make target ${target}`);
                        if (!DEDICATED_MAKE_GATES.has(target)) fail(`${relative}: Make Gate is not an approved dedicated behavioral target: ${target}`);
                    } catch (error) { fail(`${relative}: ${error instanceof Error ? error.message : String(error)}`); }
                } else if (argv[0] === "node") {
                    if (argv.length !== 2 || !DEDICATED_NODE_GATES.has(argv[1])) fail(`${relative}: Node Gate must select one approved dedicated contract test: ${value}`);
                    else if (!existsSync(resolve(ROOT, argv[1]))) fail(`${relative}: Node Gate names missing test ${argv[1]}`);
                } else fail(`${relative}: unsupported Gate executable ${argv[0]}`);
            }
        });
        const unverifiedText = requirementsEnd < 0 ? "" : text.slice(requirementsEnd);
        for (const section of unverifiedText.matchAll(/^### Unverified: (.+)$/gm)) {
            if (sections.has(section[1])) fail(`${relative}: duplicate Unverified section ${section[1]}`);
            sections.add(section[1]);
            const following = unverifiedText.slice(section.index! + section[0].length).split(/^###? /m, 1)[0];
            for (const label of missingLabels(following, ["Maps", "Unavailable observation", "Reason", "Required environment or artifact"])) fail(`${relative}: Unverified section ${section[1]} lacks ${label} label`);
        }
    }
    for (const reference of mappingReferences) {
        if (!requirements.has(reference.value) && !scenarios.has(reference.value)) fail(`${reference.relative}: Maps names unknown Requirement or Scenario: ${reference.value}`);
    }
    if (JSON.stringify([...markers].sort()) !== JSON.stringify([...sections].sort())) fail(`Unverified mapping differs: markers=${JSON.stringify([...markers].sort())}, sections=${JSON.stringify([...sections].sort())}`);

    const listed = new Map<string, string[]>();
    for (const inventory of [
        "daemon",
        "install",
        "restore",
        "uninstall",
        "contract",
        "shared",
        "workspace",
        "cluster",
    ] as const) {
        if (!gates[inventory].size) continue;
        for (const encoded of gates[inventory]) {
            const gate = JSON.parse(encoded) as { filter: string; selector: string[] };
            const key = JSON.stringify(gate.selector);
            let names = listed.get(key);
            if (!names) {
                try {
                    names = cargoTests(gate.selector);
                    listed.set(key, names);
                } catch (error) {
                    fail(`cannot list ${inventory} cargo tests for ${gate.selector.join(" ")}: ${String(error)}`);
                    continue;
                }
            }
            const filter = gate.filter;
            const matches = names.filter((name) => name === filter);
            if (matches.length !== 1) fail(`cargo Gate filter ${filter} selects ${matches.length} ${inventory} tests: ${JSON.stringify(matches)}`);
        }
    }
    return errors;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    main(() => {
        const errors = validateOpenSpec();
        requireValue(errors.length === 0, errors.join("\n"));
        console.log("openspec-evidence: capability, requirement, scenario and evidence structure OK");
    }, "openspec-evidence");
}
