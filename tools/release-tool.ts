#!/usr/bin/env node

import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { main, requireValue, run, runText } from "./lib.ts";

const MAGIC = Buffer.from("VOBOOST\0", "ascii");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function sha256(data: Uint8Array): string {
    return createHash("sha256").update(data).digest("hex");
}

function publicKeyRaw(path: string): Buffer {
    const der = run("openssl", ["pkey", "-pubin", "-in", path, "-outform", "DER"]);
    requireValue(der.length === 44 && der.subarray(0, 12).equals(SPKI_PREFIX), "agent catalog key is not canonical Ed25519 SPKI");
    return der.subarray(12);
}

function parseSignedElf(path: string): { data: Buffer; elf: Buffer; signature: Buffer } {
    const data = readFileSync(path);
    requireValue(data.length >= 80, "signed ELF is too short");
    const trailer = data.subarray(data.length - 80);
    requireValue(trailer.subarray(0, 8).equals(MAGIC), "bad appended-signature magic");
    const offset = Number(trailer.readBigUInt64LE(8));
    requireValue(offset === data.length - 80, "bad signed ELF offset");
    return { data, elf: data.subarray(0, offset), signature: trailer.subarray(16) };
}

function embeddedAgentKey(data: Buffer): Buffer {
    const matches = [...data.toString("latin1").matchAll(/\0VOBOOST_AGENT_CATALOG_RAW32=([0-9a-f]{64})\0/g)];
    requireValue(matches.length === 1, `expected exactly one inject agent-catalog raw32 marker, got ${matches.length}`);
    return Buffer.from(matches[0][1], "hex");
}

function attestation(inject: string, key: string): Record<string, string | number> {
    const signed = parseSignedElf(inject);
    requireValue(signed.data.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])), "inject is not an ELF");
    const embedded = embeddedAgentKey(signed.data);
    requireValue(embedded.equals(publicKeyRaw(key)), "agent catalog public key does not match inject embedded raw32");
    return { schemaVersion: 1, injectSize: signed.data.length, injectSha256: sha256(signed.data), agentCatalogKeySha256: sha256(embedded) };
}

function verifyAttestation(inject: string, key: string, path: string): void {
    const expected = attestation(inject, key);
    const actual: unknown = JSON.parse(readFileSync(path, "ascii"));
    requireValue(actual !== null && typeof actual === "object" && !Array.isArray(actual), "invalid inject build attestation schema");
    const record = actual as Record<string, unknown>;
    requireValue(JSON.stringify(Object.keys(record).sort()) === JSON.stringify(Object.keys(expected).sort()), "invalid inject build attestation keys");
    requireValue(Object.entries(expected).every(([name, value]) => record[name] === value), "stale or mismatched inject build attestation");
}

function unzip(path: string, member: string): Buffer {
    return run("unzip", ["-p", path, member]);
}

function verifyApkAuthority(apk: string, key: string, attestationPath: string): void {
    const att = JSON.parse(readFileSync(attestationPath, "ascii")) as Record<string, unknown>;
    const required = ["assets/agents/agent-catalog-key.sha256", "assets/agents/voboost-agents.json", "assets/agents/voboost-agents.sig"];
    const names = runText("unzip", ["-Z1", apk]).split("\n");
    requireValue(required.every((name) => names.filter((candidate) => candidate === name).length === 1), "missing or duplicate final APK agent authority asset");
    const asset = unzip(apk, required[0]);
    const catalog = unzip(apk, required[1]);
    const signature = unzip(apk, required[2]);
    requireValue(asset.equals(Buffer.from(`${att.agentCatalogKeySha256}\n`, "ascii")), "final APK and inject agent-catalog fingerprints differ");
    requireValue(signature.length === 64, "final APK agent catalog signature is not raw Ed25519");
    const temporary = mkdtempSync(join(tmpdir(), "voboost-apk-authority-"));
    try {
        const catalogPath = join(temporary, "catalog");
        const signaturePath = join(temporary, "signature");
        writeFileSync(catalogPath, catalog);
        writeFileSync(signaturePath, signature);
        run("openssl", ["pkeyutl", "-verify", "-pubin", "-inkey", key, "-rawin", "-in", catalogPath, "-sigfile", signaturePath]);
    } finally {
        rmSync(temporary, { recursive: true, force: true });
    }
}

function makeFixtureInject(path: string, key: string): void {
    const raw = publicKeyRaw(key).toString("hex");
    const elf = Buffer.from(`\x7fELFfixture\0VOBOOST_AGENT_CATALOG_RAW32=${raw}\0`, "latin1");
    const offset = Buffer.alloc(8);
    offset.writeBigUInt64LE(BigInt(elf.length));
    writeFileSync(path, Buffer.concat([elf, MAGIC, offset, Buffer.alloc(64)]));
}

function appendSignature(output: string, binary: string, signaturePath: string): void {
    const elf = readFileSync(binary);
    const signature = readFileSync(signaturePath);
    requireValue(signature.length === 64, `Ed25519 signature is ${signature.length} bytes, expected 64`);
    const offset = Buffer.alloc(8);
    offset.writeBigUInt64LE(BigInt(elf.length));
    mkdirSync(dirname(output), { recursive: true });
    writeFileSync(output, Buffer.concat([elf, MAGIC, offset, signature]));
}

function extractSignedElf(signed: string, prefix: string, signature: string): void {
    const parsed = parseSignedElf(signed);
    writeFileSync(prefix, parsed.elf);
    writeFileSync(signature, parsed.signature);
}

function createAuthorityApk(root: string, name: string, key: string, signature: string): void {
    const staging = join(root, `staging-${name}`);
    const assets = join(staging, "assets/agents");
    mkdirSync(assets, { recursive: true });
    writeFileSync(join(assets, "agent-catalog-key.sha256"), `${sha256(publicKeyRaw(key))}\n`, "ascii");
    copyFileSync(join(root, "catalog.json"), join(assets, "voboost-agents.json"));
    copyFileSync(signature, join(assets, "voboost-agents.sig"));
    run("zip", ["-q", "-r", join(root, `${name}.apk`), "assets"], { cwd: staging });
    rmSync(staging, { recursive: true, force: true });
}

main(() => {
    const [command, ...args] = process.argv.slice(2);
    if (command === "native-executable-transcript" && args.length === 3) {
        const [role, binary, output] = args;
        requireValue(["daemon", "inject", "install", "restore", "uninstall", "selinux"].includes(role), "native executable role differs");
        const elf = readFileSync(binary);
        const length = Buffer.alloc(8);
        length.writeBigUInt64LE(BigInt(elf.length));
        writeFileSync(output, Buffer.concat([
            Buffer.from("voboost-native-executable-v1\0", "ascii"),
            Buffer.from(role, "ascii"),
            Buffer.from([0]),
            length,
            elf,
        ]));
    } else if (command === "append-signature" && args.length === 3) appendSignature(args[0], args[1], args[2]);
    else if (command === "extract-signature" && args.length === 3) extractSignedElf(args[0], args[1], args[2]);
    else if (command === "verify-sign-layout" && args.length === 5) {
        const [role, binary, signed, publicKey, temporary] = args;
        const original = readFileSync(binary);
        const parsed = parseSignedElf(signed);
        requireValue(parsed.elf.equals(original), "ELF prefix changed");
        const prefix = join(temporary, "prefix");
        const signature = join(temporary, "sig");
        const length = Buffer.alloc(8);
        length.writeBigUInt64LE(BigInt(parsed.elf.length));
        writeFileSync(prefix, Buffer.concat([
            Buffer.from("voboost-native-executable-v1\0", "ascii"),
            Buffer.from(role, "ascii"), Buffer.from([0]), length, parsed.elf,
        ]));
        writeFileSync(signature, parsed.signature);
        run("openssl", ["pkeyutl", "-verify", "-pubin", "-inkey", publicKey, "-rawin", "-in", prefix, "-sigfile", signature]);
    } else if (command === "attest-inject" && args.length === 3) {
        const value = attestation(args[0], args[1]);
        mkdirSync(dirname(args[2]), { recursive: true });
        writeFileSync(args[2], `${JSON.stringify(value)}\n`, "ascii");
    } else if (command === "verify-inject-attestation" && args.length === 3) verifyAttestation(args[0], args[1], args[2]);
    else if (command === "verify-apk-authority" && args.length === 3) verifyApkAuthority(args[0], args[1], args[2]);
    else if (command === "make-fixture-inject" && args.length === 2) makeFixtureInject(args[0], args[1]);
    else if (command === "make-authority-apks" && args.length === 1) {
        createAuthorityApk(args[0], "a", join(args[0], "a-public.pem"), join(args[0], "a.sig"));
        createAuthorityApk(args[0], "asset-b", join(args[0], "b-public.pem"), join(args[0], "a.sig"));
        createAuthorityApk(args[0], "signature-b", join(args[0], "a-public.pem"), join(args[0], "b.sig"));
    } else if (command === "mutate-byte" && args.length === 1) {
        const data = readFileSync(args[0]); data[4] ^= 1; writeFileSync(args[0], data);
    } else if (command === "mutate-signature-byte" && args.length === 2) {
        const data = readFileSync(args[0]); requireValue(data.length >= 20, "signed file is too short"); data[data.length - 20] ^= 0xff; writeFileSync(args[1], data);
    } else if (command === "mutate-size" && args.length === 1) {
        const parsed = parseSignedElf(args[0]); const elf = Buffer.concat([parsed.elf, Buffer.from("x")]); const offset = Buffer.alloc(8); offset.writeBigUInt64LE(BigInt(elf.length)); writeFileSync(args[0], Buffer.concat([elf, MAGIC, offset, parsed.signature]));
    } else if (command === "duplicate-marker" && args.length === 1) {
        const parsed = parseSignedElf(args[0]); const marker = /\0VOBOOST_AGENT_CATALOG_RAW32=[0-9a-f]{64}\0/.exec(parsed.elf.toString("latin1"))?.[0]; requireValue(marker, "marker absent"); const elf = Buffer.concat([parsed.elf, Buffer.from(marker, "latin1")]); const offset = Buffer.alloc(8); offset.writeBigUInt64LE(BigInt(elf.length)); writeFileSync(args[0], Buffer.concat([elf, MAGIC, offset, parsed.signature]));
    } else if (command === "json-field" && args.length === 2) {
        let value: unknown = JSON.parse(readFileSync(args[0], "utf8"));
        for (const field of args[1].split(".")) { requireValue(value !== null && typeof value === "object" && !Array.isArray(value), `JSON field is absent: ${args[1]}`); value = (value as Record<string, unknown>)[field]; }
        requireValue(value !== undefined, `JSON field is absent: ${args[1]}`); process.stdout.write(String(value));
    } else throw new Error(`unsupported release-tool command or arguments: ${command ?? "<missing>"}`);
}, "release-tool");
