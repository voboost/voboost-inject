#!/usr/bin/env node

import assert from "node:assert/strict";
import { existsSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { ROOT } from "./lib.ts";
import { capabilityErrors, cargoGate, makeGate, missingLabels, splitCommand } from "./validate-openspec-evidence.ts";

assert.deepEqual(
    cargoGate(splitCommand("cargo test --manifest-path daemon/Cargo.toml named_test -- --exact")),
    {
        inventory: "daemon",
        filter: "named_test",
        selector: ["--manifest-path", "daemon/Cargo.toml"],
    },
);
assert.deepEqual(
    cargoGate(splitCommand("cargo test --manifest-path restore/Cargo.toml tests::schema_one_restore_phases_match_architecture_exactly -- --exact")),
    {
        inventory: "restore",
        filter: "tests::schema_one_restore_phases_match_architecture_exactly",
        selector: ["--manifest-path", "restore/Cargo.toml"],
    },
);
assert.deepEqual(
    cargoGate(splitCommand("cargo test --manifest-path daemon/Cargo.toml --test integration named_test -- --exact")),
    {
        inventory: "daemon",
        filter: "named_test",
        selector: ["--manifest-path", "daemon/Cargo.toml", "--test", "integration"],
    },
);
assert.deepEqual(
    cargoGate(splitCommand("cargo test --manifest-path shared/Cargo.toml installed_apk::tests::package_manager_startup_retry_accepts_only_success_without_stderr -- --exact")),
    {
        inventory: "shared",
        filter: "installed_apk::tests::package_manager_startup_retry_accepts_only_success_without_stderr",
        selector: ["--manifest-path", "shared/Cargo.toml"],
    },
);
assert.throws(
    () => cargoGate(splitCommand("cargo test --manifest-path daemon/Cargo.toml named_test")),
    /must pass -- --exact/,
);
assert.equal(makeGate(splitCommand("make test-implant-runtime-safety")), "test-implant-runtime-safety");
assert.throws(() => makeGate(splitCommand("make test-injector test-implant")), /one named target/);
assert.deepEqual(
    missingLabels("Gate contract: x\nMaps: y\nPreconditions: z\nObservable result: q\nEvidence boundary: host", [
        "Gate contract", "Maps", "Preconditions", "Observable result", "Evidence boundary",
    ]),
    [],
);
assert.deepEqual(missingLabels("Maps: x", ["Maps", "Reason"]), ["Reason"]);
assert.throws(
    () => cargoGate(splitCommand("cargo test --manifest-path daemon/Cargo.toml --test integration -- --exact")),
    /select one named test/,
);
assert.throws(
    () => cargoGate(splitCommand("cargo test --manifest-path daemon/Cargo.toml --test named_test -- --exact")),
    /select one named test/,
);


const specsRoot = resolve(ROOT, "openspec/specs");
const currentCapabilities = new Set(readdirSync(specsRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && existsSync(resolve(specsRoot, entry.name, "spec.md")))
    .map((entry) => entry.name));
assert.deepEqual(capabilityErrors(currentCapabilities), []);
assert.ok(capabilityErrors(new Set([...currentCapabilities, "native-undeclared"]))
    .some((error) => error.includes("extra=[\"native-undeclared\"]")));
for (const binary of ["voboost-daemon", "voboost-inject"]) {
    assert.deepEqual(cargoGate(splitCommand(
        `cargo test --manifest-path daemon/Cargo.toml --bin ${binary} exact_test -- --exact`,
    )), {
        inventory: "daemon",
        filter: "exact_test",
        selector: ["--manifest-path", "daemon/Cargo.toml", "--bin", binary],
    });
}

console.log("openspec-evidence-validator: exact Cargo selectors and dedicated Make/Node targets OK");
