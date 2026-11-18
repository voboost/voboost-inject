#!/usr/bin/env node

import {readFileSync} from "node:fs";
import {basename, resolve} from "node:path";
import {main, requireValue, ROOT} from "./lib.ts";

type FunctionCoverage = {name: string; count: number; filenames: string[]};
type FileCoverage = {filename: string; summary: {lines: {covered: number}; branches: {covered: number}}};
type Export = {data: Array<{functions: FunctionCoverage[]; files: FileCoverage[]}>};

const REQUIRED_FUNCTIONS = new Map<string, string[]>([
    ["/contract/agent_catalog.rs", ["AgentCatalog5parse", "AgentCatalog15canonical_bytes"]],
    ["/contract/apk.rs", ["certificate", "signing_digest", "signer_sha256_v2_v3"]],
    ["/contract/operation.rs", ["OperationLease10acquire_in", "OperationLease7publish"]],
    ["/daemon/src/product_candidate.rs", ["recover_product_activation", "continue_generation_only_with_cut"]],
    ["/install/src/main.rs", ["drive_transaction_with", "create_private_recovery_transaction"]],
    ["/install/src/fresh.rs", ["classify_package_probe"]],
    ["/install/src/policy.rs", ["open_verified_live_program", "VerifiedProgram16verify_unchanged"]],
    ["/restore/src/main.rs", ["drive_restore_phases", "validate_archived_init_authority"]],
    ["/uninstall/src/transaction.rs", ["run_terminal_transition", "terminal_cleanup_boot_allowed"]],
]);

const TARGET_ONLY_EXCLUSIONS = [
    ["install/src/main.rs:run_device_transaction", "Android PackageManager, init, SELinux and reboot adapter", "Installer early partial-recovery publication"],
    ["restore/src/main.rs:run", "Android fixed paths, init parent, SELinux and reboot adapter", "Restore lease target ordering"],
    ["uninstall/src/transaction.rs:run_phase_machine", "Android PackageManager, init successor and SELinux teardown domain", "End-to-end teardown-domain reachability"],
    ["daemon/src/lifecycle.rs:run_daemon", "resident Android process, abstract socket, injection and init reboot loop", "Target init supervision"],
] as const;

const REQUIRED_REPORTS = new Set([
    "rust-coverage-contract.json",
    "rust-coverage-daemon.json",
    "rust-coverage-install.json",
    "rust-coverage-restore.json",
    "rust-coverage-uninstall.json",
]);

main(() => {
    requireValue(process.argv.length >= 3, "usage: check-rust-coverage.ts <llvm-cov-export.json>...");
    const reportPaths = process.argv.slice(2);
    const reportNames = new Set(reportPaths.map((path) => basename(path)));
    for (const required of REQUIRED_REPORTS) {
        requireValue(reportNames.has(required), `Rust coverage omits required report ${required}`);
    }
    requireValue(reportNames.size === reportPaths.length, "Rust coverage report list contains duplicates");
    const reports = reportPaths.map((path) => JSON.parse(readFileSync(resolve(path), "utf8")) as Export);
    const functions = reports.flatMap((report) => report.data.flatMap((item) => item.functions));
    const files = reports.flatMap((report) => report.data.flatMap((item) => item.files));
    for (const [suffix, names] of REQUIRED_FUNCTIONS) {
        const file = files.find((candidate) => candidate.filename.endsWith(suffix));
        requireValue(file, `Rust coverage omits production file ${suffix}`);
        requireValue(file.summary.lines.covered > 0, `Rust coverage executes no lines in ${suffix}`);
        requireValue(file.summary.branches.covered > 0, `Rust coverage executes no branches in ${suffix}`);
        for (const name of names) {
            const matches = functions.filter((candidate) =>
                candidate.filenames.some((filename) => filename.endsWith(suffix)) && candidate.name.includes(name),
            );
            requireValue(matches.length > 0, `Rust coverage cannot find ${suffix}:${name}`);
            requireValue(matches.some((candidate) => candidate.count > 0), `Rust coverage never executes ${suffix}:${name}`);
        }
    }
    const specs = readFileSync(resolve(ROOT, "openspec/specs/install-recovery/spec.md"), "utf8") +
        readFileSync(resolve(ROOT, "openspec/specs/global-operation-coordination/spec.md"), "utf8") +
        readFileSync(resolve(ROOT, "openspec/specs/uninstall-recovery/spec.md"), "utf8") +
        readFileSync(resolve(ROOT, "openspec/specs/daemon-lifecycle/spec.md"), "utf8");
    for (const [symbol, reason, limitation] of TARGET_ONLY_EXCLUSIONS) {
        requireValue(reason.length >= 20, `Rust coverage exclusion lacks a precise reason: ${symbol}`);
        requireValue(specs.includes(`# Unverified: ${limitation}`), `Rust coverage exclusion lacks OpenSpec limitation: ${symbol}`);
    }
    process.stdout.write("rust-coverage: critical production functions, lines, and branches executed; target-only exclusions are explicit\n");
}, "rust-coverage");
