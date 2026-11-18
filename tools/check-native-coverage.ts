#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { main, requireValue } from "./lib.ts";

type FunctionCoverage = {name: string; count: number; filenames: string[]};
type FileCoverage = {filename: string; summary: {lines: {covered: number}; branches: {covered: number}}};
type Export = {data: Array<{functions: FunctionCoverage[]; files: FileCoverage[]}>};

const REQUIRED_FUNCTIONS = new Map<string, string[]>([
    ["injector/injector.c", ["vbi_inject"]],
    ["injector/elf_resolve.c", ["target_read_mem", "target_write_mem", "target_verify_mem", "resolve_loader_symbol"]],
    ["implant/implant.cpp", ["implant_init", "implant_finish_log_handoff", "implant_log_read_fd", "implant_state_reply_write_fd", "JNI_OnLoad"]],
]);

// The gate deliberately checks named production entrypoints instead of a
// percentage. Remaining code in these files requires ARM registers, Android
// linker namespaces or ART/JNI and stays under the matching OpenSpec
// Unverified target gates; adding a new host-required entrypoint requires
// adding it above rather than diluting an aggregate threshold.
main(() => {
    requireValue(process.argv.length === 3, "usage: check-native-coverage.ts <llvm-cov-export.json>");
    const report = JSON.parse(readFileSync(resolve(process.argv[2]), "utf8")) as Export;
    const functions = report.data.flatMap((item) => item.functions);
    const files = report.data.flatMap((item) => item.files);
    for (const [suffix, names] of REQUIRED_FUNCTIONS) {
        const file = files.find((candidate) => candidate.filename.endsWith(suffix));
        requireValue(file, `native coverage omits production file ${suffix}`);
        requireValue(file.summary.lines.covered > 0, `native coverage executes no lines in ${suffix}`);
        requireValue(file.summary.branches.covered > 0, `native coverage executes no branches in ${suffix}`);
        for (const name of names) {
            const matches = functions.filter((candidate) =>
                candidate.filenames.some((filename) => filename.endsWith(suffix)) &&
                (candidate.name === name || candidate.name.includes(`${name}(`)),
            );
            requireValue(matches.length >= 1, `native coverage cannot find ${suffix}:${name}`);
            requireValue(matches.some((candidate) => candidate.count > 0), `native coverage never executes ${suffix}:${name}`);
        }
    }
    process.stdout.write("native-coverage: production entrypoints, lines, and branches executed\n");
}, "native-coverage");
