#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

mkdir -p build
temporary=$(mktemp -d "$PWD/build/policy-rules.XXXXXX")
rules_before=$temporary/before
rules_first=$temporary/first
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

cp selinux/rules.gen.h "$rules_before"
node tools/gen-policy-rules.ts
if ! cmp -s "$rules_before" selinux/rules.gen.h; then
  echo "FAIL: rules.gen.h is stale; regenerate and commit" >&2
  exit 1
fi

cp selinux/rules.gen.h "$rules_first"
node tools/gen-policy-rules.ts
if ! cmp -s "$rules_first" selinux/rules.gen.h; then
  echo "FAIL: policy rule generation is not deterministic" >&2
  exit 1
fi

node --input-type=module <<'JS'
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { generate } from "./tools/gen-policy-rules.ts";
const exact = generate("type voboost; allowxperm voboost can_device:chr_file ioctl { 0x0001 };");
assert.match(exact, /vr_ioctl_commands_0\[\] = \{ 0x0001 \}/);
for (const expression of ["*", "0x0001-0x0002", "0x10000", "0x0001 0x0002-0x0003", "1"]) {
  assert.throws(() => generate(`type voboost; allowxperm voboost can_device:chr_file ioctl { ${expression} };`), /unsupported/);
}
assert.throws(() => generate("type voboost; allowxperm voboost can_device:chr_file nlmsg { 0x0001 };"), /unsupported/);

const rules = readFileSync("selinux/rules.gen.h", "utf8");
for (const [domain, label] of [
  ["voboost_install", "exported3_system_prop"],
  ["voboost_install", "exported_default_prop"],
  ["voboost", "exported_default_prop"],
]) {
  const match = rules.match(new RegExp(`\\{ "${domain}", "${label}", "file", (vr_perms_\\d+), 4 \\}`));
  assert.ok(match, `missing exact native property rule ${domain} ${label}`);
  assert.ok(rules.includes(`${match[1]}[] = { "read", "open", "getattr", "map" }`));
}
// Platform CIL identity is a read-only source, not a policy publication target.
const cilRead = rules.match(/\{ "voboost_restore", "sepolicy_file", "file", (vr_perms_\d+), 3 \}/);
assert.ok(cilRead, "missing exact Restore CIL digest read rule");
assert.ok(rules.includes(`${cilRead[1]}[] = { "read", "open", "getattr" }`));
assert.ok(!rules.includes('{ "su", "sepolicy_file",'), "CIL fix must not add stock su authority");
// Root CLI helpers can remain in su on nosuid mounts. The server independently
// verifies root credentials and the signed installed executable role.
// A general application domain must never inherit this management route.
const runtimeSocket = rules.match(/\{ "voboost", "self", "unix_stream_socket", (vr_perms_\d+), (\d+) \}/);
assert.ok(runtimeSocket, "missing runtime self socket rule");
const permissions = rules.match(new RegExp(`${runtimeSocket[1]}\\[\\] = \{ ([^}]+) \}`));
assert.ok(permissions, "missing runtime self socket permissions");
assert.ok(permissions[1].includes('"connectto"'), "runtime observer cannot connect to daemon");
for (const [target, kind, permission] of [
    ["voboost", "unix_stream_socket", "connectto"],
    ["voboost_data_file", "sock_file", "write"],
]) {
    const match = rules.match(new RegExp(`\\{ "su", "${target}", "${kind}", (vr_perms_\\d+), 1 \\}`));
    assert.ok(match, `missing exact root-management socket rule ${target}:${kind}`);
    assert.ok(rules.includes(`${match[1]}[] = { "${permission}" }`));
}
for (const match of rules.matchAll(/\{ "(appdomain)", "voboost", "unix_stream_socket", (vr_perms_\d+), \d+ \}/g)) {
    const perms = rules.match(new RegExp(`${match[2]}\\[\\] = { ([^}]+) }`));
    assert.ok(perms && !perms[1].includes('"connectto"'), `${match[1]} must not connect to runtime`);
}
JS

echo "policy rule generation: deterministic and current"

node tools/test-native-input-policy.ts
