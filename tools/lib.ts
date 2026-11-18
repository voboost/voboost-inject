import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export function run(command: string, args: string[], options: { cwd?: string; input?: Uint8Array; allowFailure?: boolean } = {}): Buffer {
    const result = spawnSync(command, args, {
        cwd: options.cwd ?? ROOT,
        input: options.input,
        encoding: null,
        maxBuffer: 128 * 1024 * 1024,
    });
    if (result.error) throw result.error;
    if (result.status !== 0 && !options.allowFailure) {
        throw new Error(`${command} ${args.join(" ")} failed (${result.status}): ${result.stderr?.toString().trim()}`);
    }
    return result.stdout ?? Buffer.alloc(0);
}

export function runText(command: string, args: string[], options: { cwd?: string; allowFailure?: boolean } = {}): string {
    return run(command, args, options).toString("utf8").trim();
}

export function main(action: () => void, label: string): void {
    try {
        action();
    } catch (error) {
        console.error(`${label}: ${error instanceof Error ? error.message : String(error)}`);
        process.exitCode = 1;
    }
}

export function requireValue(condition: unknown, message: string): asserts condition {
    if (!condition) throw new Error(message);
}
