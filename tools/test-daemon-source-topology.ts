import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const main = readFileSync(resolve(root, "daemon/src/main.rs"), "utf8");
const runtime = readFileSync(resolve(root, "daemon/src/runtime.rs"), "utf8");
const lifecycle = readFileSync(resolve(root, "daemon/src/lifecycle.rs"), "utf8");
const generation = readFileSync(resolve(root, "daemon/src/generation.rs"), "utf8");
const agentEvents = readFileSync(resolve(root, "daemon/src/agent_events.rs"), "utf8");

function count(source: string, pattern: RegExp): number {
    return [...source.matchAll(pattern)].length;
}

if (count(main, /^fn main\(\)/gm) !== 1) {
    throw new Error("daemon topology: main.rs must own exactly one startup entrypoint");
}
if (count(main, /^mod runtime;$/gm) !== 1) {
    throw new Error("daemon topology: main.rs must declare runtime exactly once");
}
if (/\bstruct DaemonLoop\b|\bimpl DaemonLoop\b/.test(main)) {
    throw new Error("daemon topology: main.rs must not own DaemonLoop");
}
if (/^fn main\(\)/m.test(runtime)) {
    throw new Error("daemon topology: runtime.rs must not own startup");
}
if (count(runtime, /^(?:pub\(crate\) )?struct DaemonLoop\b/gm) !== 1) {
    throw new Error("daemon topology: runtime.rs must own DaemonLoop exactly once");
}
if (count(runtime, /^impl DaemonLoop\b/gm) !== 1) {
    throw new Error("daemon topology: runtime.rs must own one DaemonLoop implementation");
}

const testSupportMarker = "#[cfg(test)]\npub(crate) mod test_support";
const testSupportOffset = runtime.indexOf(testSupportMarker);
if (testSupportOffset < 0) {
    throw new Error("daemon topology: runtime test support must remain cfg(test)-gated");
}

const productionCallers = new Map<string, [string, string]>([
    ["fn generation_prune_is_safe", ["generation_prune_is_safe", main]],
    ["fn retained_process_index", ["retained_process_index", main]],
    ["fn render_mutation_ack_frame", ["runtime::render_mutation_ack_frame", agentEvents]],
    [
        "fn validate_generation_representability",
        ["runtime::validate_generation_representability", generation],
    ],
    ["enum DaemonPollDisposition", ["DaemonPollDisposition", lifecycle]],
    ["struct DaemonLoop", ["DaemonLoop", lifecycle]],
    ["fn new_with_product_identity", ["new_with_product_identity", lifecycle]],
    ["fn set_uninstall_frozen", ["set_uninstall_frozen", lifecycle]],
    ["fn set_product_identity", ["set_product_identity", lifecycle]],
    ["fn uninstall_frozen", ["uninstall_frozen()", lifecycle]],
    ["fn adopt_generation", ["adopt_generation", lifecycle]],
    ["fn generation_id", ["generation_id()", lifecycle]],
    ["fn fence_native_restart_endpoints", ["fence_native_restart_endpoints", lifecycle]],
    ["fn poll_once", ["poll_once", lifecycle]],
    ["fn prepare_uninstall", ["prepare_uninstall", main]],
]);

for (const [declaration, [symbol, caller]] of productionCallers) {
    if (!caller.includes(symbol)) {
        throw new Error(`daemon topology: ${declaration} lacks its classified production caller`);
    }
}

function declarationName(line: string): string {
    const declaration = line.trim().slice("pub(crate) ".length);
    const end = declaration.search(/[\(<:{]/);
    return declaration.slice(0, end < 0 ? declaration.length : end).trim();
}

const productionSurface = new Set(
    runtime
        .slice(0, testSupportOffset)
        .split("\n")
        .filter((line) => line.trim().startsWith("pub(crate) "))
        .map(declarationName),
);
if (
    productionSurface.size !== productionCallers.size ||
    [...productionSurface].some((declaration) => !productionCallers.has(declaration))
) {
    throw new Error(
        `daemon topology: unclassified runtime pub(crate) production surface: ${[
            ...productionSurface,
        ].join(", ")}`,
    );
}

const testOnlyCount = runtime
    .slice(testSupportOffset)
    .split("\n")
    .filter((line) => line.trim().startsWith("pub(crate) ")).length;
if (testOnlyCount <= 1) {
    throw new Error("daemon topology: runtime test support must own the test-only API surface");
}

console.log("daemon-source-topology: startup/runtime ownership and API surface OK");
