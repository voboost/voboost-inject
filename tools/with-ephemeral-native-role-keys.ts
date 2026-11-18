#!/usr/bin/env node

import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const ROLES = [
    ["agent-catalog", "AGENT_CATALOG"],
    ["release-catalog", "RELEASE_CATALOG"],
    ["native-executable", "NATIVE_EXECUTABLE"],
    ["restore", "RESTORE"],
] as const;

export function runWithEphemeralNativeRoleKeys(
    command: string,
    args: readonly string[],
    environment: NodeJS.ProcessEnv = process.env,
): number {
    const directory = mkdtempSync(join(tmpdir(), "voboost-native-role-keys-"));
    const childEnvironment = { ...environment };
    try {
        childEnvironment.ANDROID_CERT_SHA256 ??= randomBytes(32).toString("hex");
        for (const [fileRole, environmentRole] of ROLES) {
            const { privateKey, publicKey } = generateKeyPairSync("ed25519");
            const privatePath = join(directory, `${fileRole}-private.pem`);
            const publicPath = join(directory, `${fileRole}-public.pem`);
            writeFileSync(privatePath, privateKey.export({ format: "pem", type: "pkcs8" }), {
                flag: "wx",
                mode: 0o600,
            });
            writeFileSync(publicPath, publicKey.export({ format: "pem", type: "spki" }), {
                flag: "wx",
                mode: 0o600,
            });
            childEnvironment[`${environmentRole}_PUBLIC_KEY_PEM`] = publicPath;
            childEnvironment[`${environmentRole}_SIGNING_KEY_FILE`] = privatePath;
        }
        const child = spawnSync(command, [...args], {
            cwd: resolve(import.meta.dirname, ".."),
            env: childEnvironment,
            stdio: "inherit",
        });
        if (child.error) throw child.error;
        return child.status ?? 1;
    } finally {
        rmSync(directory, { recursive: true, force: true });
    }
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(import.meta.filename)) {
    const [, , command, ...args] = process.argv;
    if (!command) {
        console.error(
            "Usage: node tools/with-ephemeral-native-role-keys.ts <command> [arguments...]",
        );
        process.exit(2);
    }
    process.exit(runWithEphemeralNativeRoleKeys(command, args));
}
