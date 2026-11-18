#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { main, requireValue, ROOT, runText } from "./lib.ts";

main(() => {
    const relative = "prebuilt/armeabi-v7a/libdobby.a";
    const path = resolve(ROOT, relative);
    const data = readFileSync(path);
    const sha256 = "fbaeb9cfe18f6953ad4d24cad34ed4fdd04964fcea0f74ce09285e5dbd11e2fd";
    const blob = "e9f6677dcbb3a859f742bbf6a4e681eb536c3e67";
    requireValue(data.subarray(0, 8).toString() === "!<arch>\n", "prebuilt is not an ar archive");
    requireValue(data.length === 318194, "prebuilt size differs");
    requireValue(createHash("sha256").update(data).digest("hex") === sha256, "prebuilt SHA-256 differs");
    requireValue(runText("git", ["hash-object", relative]) === blob, "prebuilt Git blob differs");
    runText("git", ["ls-files", "--error-unmatch", relative]);
    requireValue(runText("ar", ["t", path]).length > 0, "prebuilt archive has no members");
    const actual: unknown = JSON.parse(readFileSync(path.replace(/libdobby\.a$/, "libdobby.provenance.json"), "utf8"));
    const expected = {
        "schemaVersion": 1,
        "abi": "armeabi-v7a",
        "artifact": "prebuilt/armeabi-v7a/libdobby.a",
        "sha256": "fbaeb9cfe18f6953ad4d24cad34ed4fdd04964fcea0f74ce09285e5dbd11e2fd",
        "gitBlobSha1": "e9f6677dcbb3a859f742bbf6a4e681eb536c3e67",
        "sourceProject": "jmpews/Dobby",
        "sourceCommit": null,
        "provenanceStatus": "committed-prebuilt-source-commit-unknown",
        "reason": "Pinned Dobby gitlink 5dfc854 retains the upstream ARM build breakage",
        "size": 318194,
        "publishedOrigin": {
            "coordinates": "io.github.vvb2060.ndk:dobby:1.2",
            "aarUrl": "https://repo.maven.apache.org/maven2/io/github/vvb2060/ndk/dobby/1.2/dobby-1.2.aar",
            "aarSha256": "251f48ae21686d7f69276c50644ca345f450e45110057437f7d76bb14cddf3a1",
            "member": "prefab/modules/dobby/libs/android.armeabi-v7a/libdobby.a",
            "pomUrl": "https://repo.maven.apache.org/maven2/io/github/vvb2060/ndk/dobby/1.2/dobby-1.2.pom",
            "abiMetadata": {
                "api": 16,
                "ndk": 22,
                "stl": "none"
            },
            "license": "Apache-2.0",
            "licenseUrl": "https://github.com/LSPosed/Dobby/blob/master/LICENSE"
        }
    };
    const matches = (value: unknown): boolean => JSON.stringify(value) === JSON.stringify(expected);
    requireValue(matches(actual), "provenance record differs from the accepted exception");
    for (const invalid of [
        { ...expected, sourceCommit: "5dfc8546954ce3b3198132ab13fddb89ee92cdd7" },
        { ...expected, size: 0 },
        { ...expected, publishedOrigin: { ...expected.publishedOrigin, aarSha256: "0".repeat(64) } },
        { ...expected, publishedOrigin: { ...expected.publishedOrigin, member: "other/libdobby.a" } },
        { ...expected, publishedOrigin: { ...expected.publishedOrigin, abiMetadata: { api: 28, ndk: 29, stl: "c++_static" } } },
    ]) requireValue(!matches(invalid), "invalid provenance accepted");
    console.log("armv7-dobby-prebuilt: exact archive identity, published Maven origin, and unknown-source attestation OK");
}, "armv7-dobby-prebuilt");
