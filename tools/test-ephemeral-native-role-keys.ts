#!/usr/bin/env node

import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main, requireValue } from "./lib.ts";
import { runWithEphemeralNativeRoleKeys } from "./with-ephemeral-native-role-keys.ts";

main(() => {
    const root = mkdtempSync(join(tmpdir(), "voboost-native-role-test-"));
    const evidence = join(root, "evidence.json");
    try {
        const roles = [
            "AGENT_CATALOG",
            "RESTORE",
            "RELEASE_CATALOG",
            "NATIVE_EXECUTABLE",
        ];
        const script = [
            "const crypto=require('node:crypto'),fs=require('node:fs');",
            `const roles=${JSON.stringify(roles)};`,
            "const paths=[],ids=[];",
            "for(const role of roles){",
            "const pub=process.env[role+'_PUBLIC_KEY_PEM'];",
            "const priv=process.env[role+'_SIGNING_KEY_FILE'];",
            "if(!fs.existsSync(pub)||!fs.existsSync(priv))process.exit(3);",
            "paths.push(pub,priv);",
            "ids.push(crypto.createPublicKey(fs.readFileSync(pub)).export({format:'der',type:'spki'}).toString('hex'));",
            "}",
            "if(new Set(ids).size!==roles.length)process.exit(4);",
            `fs.writeFileSync(${JSON.stringify(evidence)},JSON.stringify(paths));`,
        ].join("");
        requireValue(
            runWithEphemeralNativeRoleKeys(process.execPath, ["-e", script]) === 0,
            "ephemeral native role child failed",
        );
        const paths = JSON.parse(readFileSync(evidence, "utf8")) as string[];
        requireValue(paths.every((path) => !existsSync(path)), "ephemeral native role files remain");
        console.log("ephemeral-native-role-keys: distinct roles and cleanup OK");
    } finally {
        rmSync(root, { recursive: true, force: true });
    }
}, "ephemeral-native-role-keys");
