import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { generate } from "./gen-policy-rules.ts";

const rules = generate(readFileSync(new URL("../selinux/voboost.te", import.meta.url), "utf8"));
function permissions(target: string, kind: string): Set<string> {
    const result = new Set<string>();
    for (const match of rules.matchAll(new RegExp(`\\{ "voboost", "${target}", "${kind}", (vr_perms_\\d+), \\d+ \\}`, "g"))) {
        const declaration = rules.match(new RegExp(`${match[1]}\\[\\] = \\{ ([^}]+) \\}`));
        for (const permission of declaration![1].matchAll(/"([^"]+)"/g)) result.add(permission[1]);
    }
    return result;
}
for (const label of ["default_prop", "system_prop"]) {
    assert.ok(permissions(label, "file").has("map"), `${label} property read requires mmap`);
}
const can = permissions("self", "netlink_crypto_socket");
for (const permission of ["create", "bind", "read"]) assert.ok(can.has(permission), `OEM protocol 21 receiver requires ${permission}`);
for (const permission of ["write", "nlmsg_write"]) assert.ok(!can.has(permission), `passive CAN must not gain ${permission}`);
assert.ok(permissions("block_device", "dir").has("search"), "hardware coding probe must traverse /dev/block");
for (const permission of ["write", "ioctl"]) assert.ok(!permissions("block_device", "blk_file").has(permission), `coding probe must not gain block ${permission}`);

assert.deepEqual([...permissions("vdh_device", "blk_file")].sort(), ["getattr", "open", "read"], "exact OEM NV probe is read-only");
for (const target of ["block_device", "system_block_device", "boot_block_device", "modem_block_device", "persist_block_device", "misc_block_device", "gpt_block_device"]) {
    for (const permission of ["open", "read", "write", "ioctl"]) {
        assert.ok(!permissions(target, "blk_file").has(permission), `NV probe must not gain ${target}:${permission}`);
    }
}

const init = readFileSync(new URL("../config/voboost.rc", import.meta.url), "utf8");
for (const service of ["voboost-daemon", "voboost-inject"]) {
    const block = init.match(new RegExp(`^service ${service} [^\\n]+\\n((?:[ \\t]+[^\\n]*\\n)*)`, "m"));
    assert.ok(block, `missing ${service} init service`);
    assert.match(block[1], /^    group root readproc$/m, `${service} must inventory hidepid=2 through readproc`);
}

console.log("PASS native input policy and init inventory contract (host)");
