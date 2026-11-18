#!/usr/bin/env node
// Component-owned exporter for the exact unsigned native inventory. Ports
// tools/prepare-beta1-unsigned.sh: filesystem safety checks, NDK readelf ELF
// validation (kept as the NDK tool — the product does not ship a second
// implementation of the ELF rules), host-path leak scans, role-signature
// magic checks, and the flat native export.
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  closeSync,
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  readSync,
  renameSync,
  rmSync,
  statSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const NAMES = [
  "voboost-daemon",
  "voboost-inject",
  "voboost-install",
  "voboost-restore",
  "voboost-uninstall",
  "voboost-selinux",
  "voboost.rc",
  "libimplant-arm64-v8a.so",
  "libimplant-armeabi-v7a.so",
] as const;

const SOURCES = [
  "target/aarch64-linux-android/release/voboost-daemon",
  "target/aarch64-linux-android/release/voboost-inject",
  "target/aarch64-linux-android/release/voboost-install",
  "build/restore/arm64-v8a/voboost-restore",
  "target/aarch64-linux-android/release/voboost-uninstall",
  "build/selinux/arm64-v8a/voboost-selinux",
  "config/voboost.rc",
  "implant/libs/arm64-v8a/libimplant.so",
  "implant/libs/armeabi-v7a/libimplant.so",
] as const;

const HOST_PATH_PREFIXES = [
  "/Users/",
  "/private/var/folders/",
  "/tmp/voboost-",
  "voboost-native-role-keys-",
] as const;

// Runtime executables must not contain the retired
// emulator profile markers (full-string semantics of `strings | grep -Fqx`).
const RETIRED_MARKERS: ReadonlyArray<readonly [string, string]> = [
  ["voboost-daemon", "VOBOOST_EMULATOR_DAEMON_SELINUX_SKIP_V1"],
  ["voboost-inject", "VOBOOST_EMULATOR_DAEMON_SELINUX_SKIP_V1"],
  ["voboost-install", "VOBOOST_EMULATOR_SELINUX_SKIP_V1"],
  ["voboost-uninstall", "VOBOOST_EMULATOR_UNINSTALL_SELINUX_SKIP_V1"],
  ["voboost-uninstall", "VOBOOST_EMULATOR_UNINSTALL_MOUNT_ADAPTER_V1"],
  ["voboost-restore", "VOBOOST_EMULATOR_RESTORE_SELINUX_SKIP_V1"],
] as const;

function fail(message: string): never {
  throw new Error(`prepare-beta1-unsigned: ${message}`);
}

function containsFullString(buffer: Buffer, needle: string): boolean {
  const needleBuffer = Buffer.from(needle, "latin1");
  let offset = buffer.indexOf(needleBuffer);
  while (offset !== -1) {
    const before = offset === 0 ? 0 : buffer[offset - 1];
    const after = offset + needleBuffer.length;
    const afterByte = after === buffer.length ? 0 : buffer[after];
    const printable = (byte: number) => byte >= 0x20 && byte <= 0x7e;
    if (!printable(before) && !printable(afterByte)) return true;
    offset = buffer.indexOf(needleBuffer, offset + 1);
  }
  return false;
}

function fileLinks(path: string): number {
  return statSync(path).nlink;
}

type ElfBinding = "immediate" | "static";

function checkElf(
  readelf: string,
  source: string,
  expectedMachine: "AArch64" | "ARM",
  binding: ElfBinding,
): void {
  const run = (flag: string): string => {
    const result = spawnSync(readelf, [flag, source], { encoding: "utf8" });
    return result.stdout ?? "";
  };
  const name = basename(source);
  const expectedType = binding === "static" ? "EXEC" : "DYN";
  const header = run("--file-header");
  if (!new RegExp(`Type:\\s+${expectedType}\\s`).test(header))
    fail(`${name} is not ELF type ${expectedType}`);
  if (!header.includes(`Machine:                           ${expectedMachine}`))
    fail(`${name} has wrong ABI`);
  const program = run("--program-headers");
  if (!program.includes("GNU_RELRO")) fail(`${name} lacks GNU_RELRO`);
  if (/GNU_STACK.*RWE/.test(program)) fail(`${name} has executable stack`);
  const sections = run("--sections");
  if (/\.debug_[A-Za-z0-9_.-]+/.test(sections)) fail(`${name} contains debug sections`);
  const dynamic = run("--dynamic");
  if (binding === "immediate") {
    if (!/(BIND_NOW|FLAGS[^\n]*\bNOW\b|FLAGS_1[^\n]*\bNOW\b)/.test(dynamic))
      fail(`${name} lacks immediate binding`);
  } else if (/\bNEEDED\b/.test(dynamic)) {
    fail(`${name} is not a static executable`);
  }
  checkHostPaths(source);
  checkUnsignedMagic(source);
}

function checkHostPaths(source: string): void {
  const bytes = readFileSync(source);
  for (const prefix of HOST_PATH_PREFIXES) {
    if (bytes.includes(Buffer.from(prefix, "latin1")))
      fail(`${basename(source)} embeds host path material (${prefix})`);
  }
}

function checkUnsignedMagic(source: string): void {
  const stats = statSync(source);
  if (stats.size < 80) return;
  const fd = openSync(source, "r");
  const tail = Buffer.alloc(80);
  try {
    readSync(fd, tail, 0, 80, stats.size - 80);
  } finally {
    closeSync(fd);
  }
  if (tail.subarray(0, 8).toString("hex") === "564f424f4f535400")
    fail(`${basename(source)} is already role-signed`);
}

function main(): void {
  const output = process.argv[2];
  if (output === undefined) {
    console.error("usage: prepare-beta1-unsigned.ts <output-dir>");
    process.exit(2);
  }
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const ndk = process.env.ANDROID_NDK_HOME ?? "";
  if (ndk === "") fail("ANDROID_NDK_HOME is required");

  const prebuilt = join(ndk, "toolchains/llvm/prebuilt");
  let readelf: string | undefined;
  for (const entry of existsSync(prebuilt) ? readdirSync(prebuilt) : []) {
    const candidate = join(prebuilt, entry, "bin/llvm-readelf");
    // The NDK ships llvm-readelf as a symlink — resolve it (statSync) rather
    // than requiring a regular file at the link itself.
    if (existsSync(candidate) && statSync(candidate).isFile()) {
      readelf = candidate;
      break;
    }
  }
  if (readelf === undefined) fail("NDK llvm-readelf is unavailable");

  if (existsSync(output)) {
    const stats = lstatSync(output);
    if (!stats.isDirectory()) fail("output is not a directory");
    if (readdirSync(output).length > 0) fail("output directory is not empty");
  }
  const temporary = `${output}.tmp.${process.pid}`;
  if (existsSync(temporary)) fail("temporary output already exists");

  for (let index = 0; index < NAMES.length; index += 1) {
    const name = NAMES[index];
    const source = join(root, SOURCES[index]);
    const stats = lstatSync(source);
    if (!stats.isFile() || stats.isSymbolicLink() || fileLinks(source) !== 1)
      fail(`missing or unsafe ${SOURCES[index]}`);
    if (name.endsWith(".so")) {
      checkElf(readelf, source, name.includes("arm64-v8a") ? "AArch64" : "ARM", "immediate");
    } else if (name !== "voboost.rc") {
      checkElf(readelf, source, "AArch64", name === "voboost-selinux" ? "static" : "immediate");
    } else {
      if (stats.size === 0) fail("voboost.rc is empty");
      checkHostPaths(source);
    }
  }

  for (const [name, marker] of RETIRED_MARKERS) {
    const index = NAMES.indexOf(name);
    if (index < 0) fail(`marker target is absent: ${name}`);
    const source = join(root, SOURCES[index]);
    if (containsFullString(readFileSync(source), marker))
      fail(`${NAMES[index]} contains removed emulator profile (${marker})`);
  }

  mkdirSync(temporary);
  for (let index = 0; index < NAMES.length; index += 1) {
    const name = NAMES[index];
    cpSync(join(root, SOURCES[index]), join(temporary, name));
    chmodSync(join(temporary, name), name === "voboost.rc" || name.endsWith(".so") ? 0o644 : 0o755);
  }

  const actual = readdirSync(temporary).sort().join("\n");
  const expected = [...NAMES].sort().join("\n");
  if (actual !== expected) fail("exported inventory differs");
  if (existsSync(output)) rmSync(output, { recursive: true });
  renameSync(temporary, output);
  console.log(`prepare-beta1-unsigned: exported ${NAMES.length} flat unsigned native artifacts`);
}

main();
