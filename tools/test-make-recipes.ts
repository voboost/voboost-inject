import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {readFileSync} from "node:fs";

function dryRun(target: string): string {
    const rendered = spawnSync("make", ["--dry-run", target], {encoding: "utf8"});
    assert.equal(rendered.status, 0, `${target} dry-run failed: ${rendered.stderr}`);
    return rendered.stdout;
}

for (const target of ["sign-selinux", "sign-restore"]) {
    const rendered = spawnSync("make", ["--dry-run", target, "SIGNING_KEY=/dev/null", "DIR=/tmp/voboost-release", "CHANNEL=inject", "VERSION=1.0.0", "AGENT_CATALOG_PUBLIC_KEY_PEM=/dev/null", "RESTORE_PUBLIC_KEY_PEM=/dev/null", "INJECT_BUILD_ATTESTATION=/dev/null"], {
        encoding: "utf8",
    });
    assert.equal(rendered.status, 0, `${target} dry-run failed: ${rendered.stderr}`);
    const syntax = spawnSync("/bin/sh", ["-n"], {
        encoding: "utf8",
        input: rendered.stdout,
    });
    assert.equal(syntax.status, 0, `${target} shell syntax failed: ${syntax.stderr}`);
}

const packages = ["voboost-daemon", "voboost-install", "voboost-restore", "voboost-uninstall"];
const rustCoverage = dryRun("coverage-rust");
for (const packageName of packages) {
    const stem = packageName.replace("voboost-", "");
    assert.match(rustCoverage, new RegExp(`rust-coverage-${stem}\\.json`), `${packageName} default coverage is missing`);
}

const makefile = readFileSync("Makefile", "utf8");
const ndkEnvironment = spawnSync("make", ["--no-print-directory", "-f", "Makefile", "-f", "-", "print-ndk-environment", "NDK_HOME=/shared/android/ndk/29"], {
    encoding: "utf8",
    input: "print-ndk-environment:\n\t@printf '%s\\n' \"$$NDK_HOME\" \"$$ANDROID_NDK_HOME\" \"$$PYTHONDONTWRITEBYTECODE\"\n",
    env: { ...process.env, ANDROID_NDK_HOME: "/other/android/ndk" },
});
assert.equal(ndkEnvironment.status, 0, ndkEnvironment.stderr);
assert.equal(ndkEnvironment.stdout, "/shared/android/ndk/29\n/shared/android/ndk/29\n1\n", "native and Cargo tools must share NDK_HOME without modifying its tree");
for (const [target, binary, other] of [
    ["build-daemon", "voboost-daemon", "voboost-inject"],
    ["build-inject", "voboost-inject", "voboost-daemon"],
]) {
    const recipe = dryRun(target);
    assert.match(recipe, new RegExp(`cargo ndk[^\\n]*--bin ${binary}(?:\\s|$)`));
    assert.doesNotMatch(recipe, new RegExp(`--bin ${other}(?:\\s|$)`));
}
assert.match(makefile, /^build-new:.*\bbuild-daemon\b.*\bbuild-inject\b/m);
assert.equal((makefile.match(/\bcargo test --workspace\b/g) ?? []).length, 1, "canonical test must run default workspace once");
assert.doesNotMatch(
    makefile,
    /\$\(MAKE\) --no-print-directory test-restore/,
    "canonical test duplicates Restore outside the workspace/profile gates",
);
assert.equal(
    (makefile.match(/\bcargo clippy --workspace --all-targets -- -D warnings\b/g) ?? []).length,
    1,
    "canonical lint must run default workspace once",
);
console.log("make-recipes: signing syntax and production Rust gates OK");

const uninstallRecipe = dryRun("build-uninstall");
assert.match(uninstallRecipe, /test -f .*RELEASE_CATALOG_PUBLIC_KEY_PEM missing/, "uninstall must validate its release catalog key before building");
assert.match(uninstallRecipe, /VOBOOST_RELEASE_CATALOG_PUBLIC_KEY_PEM="[^"\n]+"/, "uninstall must forward the release catalog key into Cargo");
