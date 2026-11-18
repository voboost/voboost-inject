import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { SELINUX_LABEL_CONTRACT } from "./selinux-label-contract.ts";

const root = resolve(import.meta.dirname, "..");
const contexts = readFileSync(resolve(root, "selinux/file_contexts"), "utf8");
const catchAll = contexts.indexOf(SELINUX_LABEL_CONTRACT.catchAllPattern);
assert(catchAll >= 0);
for (const entry of SELINUX_LABEL_CONTRACT.entries) {
  assert(contexts.includes(entry.pattern));
  assert(contexts.indexOf(entry.pattern) < catchAll, `${entry.path} must precede catch-all`);
}
for (const path of ["/data/voboost/voboost-restore"]) {
  const entry = SELINUX_LABEL_CONTRACT.entries.find((candidate) => candidate.path === path);
  assert.equal(entry?.context, "u:object_r:system_file:s0");
}
for (const [path, context] of [
  ["/data/voboost/voboost-daemon", "u:object_r:voboost_exec:s0"],
  ["/data/voboost/voboost-inject", "u:object_r:voboost_exec:s0"],
  ["/data/voboost/voboost-install", "u:object_r:voboost_install_exec:s0"],
  ["/data/voboost/operation.json", "u:object_r:voboost_operation_file:s0"],
  ["/data/voboost/logs/install-progress.jsonl", "u:object_r:voboost_operation_file:s0"],
  ["/data/voboost/install", "u:object_r:voboost_install_root_dir:s0"],
  ["/data/voboost/install/state.json", "u:object_r:voboost_installed_state_file:s0"],
  ["/data/voboost/recovery", "u:object_r:voboost_recovery_file:s0"],
  ["/data/voboost/state", "u:object_r:voboost_agent_state_file:s0"],
] as const) {
  assert.equal(SELINUX_LABEL_CONTRACT.entries.find((entry) => entry.path === path)?.context, context);
}
assert.equal(
  SELINUX_LABEL_CONTRACT.entries.find((entry) => entry.path.endsWith("voboost-selinux"))?.context,
  "u:object_r:voboost_selinux_exec:s0",
);
console.log("SELinux label contract generation/order tests passed");

function contextFor(path: string): string {
  return SELINUX_LABEL_CONTRACT.entries.find((entry) =>
    new RegExp(`^(?:${entry.pattern})$`).test(path))?.context ?? SELINUX_LABEL_CONTRACT.root;
}
for (const [path, context] of [
  ["/data/voboost/run/restore-reply.json", "u:object_r:voboost_recovery_file:s0"],
  ["/data/voboost/run/desktop-uninstall-result.json", "u:object_r:voboost_uninstall_result_file:s0"],
] as const) {
  assert.equal(contextFor(path), context);
  for (const neighbor of [path + ".tmp", path + "/child", path.replace(".json", "Xjson")]) {
    assert.equal(contextFor(neighbor), SELINUX_LABEL_CONTRACT.root);
  }
}
assert.equal(contextFor("/data/voboost/run/unknown.json"), SELINUX_LABEL_CONTRACT.root);
assert.equal(contextFor("/data/voboost/install/.state.json.tmp"), "u:object_r:voboost_installed_state_file:s0");
for (const suffix of ["/stateXjson", "/nested/state.json", "/state.json.extra"]) {
  assert.equal(contextFor("/data/voboost/install" + suffix), "u:object_r:voboost_install_staging_file:s0");
}


for (const path of [
  "/data/voboost/run/restore-prepare",
  "/data/voboost/run/restore-prepare/restore-journal.json",
  "/data/voboost/run/restore-prepare/.restore-journal.json.tmp",
]) assert.equal(contextFor(path), "u:object_r:voboost_recovery_file:s0");
for (const suffix of ["/unknown", "/restore-journalXjson", "/nested/restore-journal.json", "-other"]) {
  assert.equal(contextFor("/data/voboost/run/restore-prepare" + suffix), SELINUX_LABEL_CONTRACT.root);
}

// Enforcing product reapply hashes and backs up every root-flat helper.
// The daemon must read helpers without gaining authority to execute them.
const policy = readFileSync(resolve(root, "selinux/voboost.te"), "utf8")
  .replace(/#[^\n]*/g, "");
for (const target of ["voboost_install_exec", "voboost_uninstall_exec", "voboost_selinux_exec", "vendor_configs_file", "vendor_file", "sepolicy_file"]) {
  const permissions = new Set([...policy.matchAll(
    new RegExp(`allow\\s+voboost\\s+${target}:file\\s+\\{([^}]+)\\}\\s*;`, "g"),
  )].flatMap((match) => match[1].trim().split(/\s+/)));
  for (const permission of ["read", "open", "getattr"])
    assert(permissions.has(permission), `reapply must verify ${target}: ${permission}`);
  for (const permission of ["execute", "execute_no_trans", "entrypoint", "write"])
    assert(!permissions.has(permission), `reapply must not grant ${target}: ${permission}`);
}

// Only the exact owned A9/A11 final and staged basenames receive the public resource label.
const resourceEntries = SELINUX_LABEL_CONTRACT.entries.filter(entry => entry.symbol.startsWith("RESOURCE_OVERLAY"));
assert.equal(resourceEntries.length, 4);
for (const [path, expected] of [
  ["/vendor/overlay/voboost-setting-ru.apk", true],
  ["/vendor/overlay/.voboost-setting-ru.apk.staged", true],
  ["/vendor/overlay/voboost-setting-ru-a11.apk", true],
  ["/vendor/overlay/.voboost-setting-ru-a11.apk.staged", true],
  ["/vendor/overlay/voboost-setting-ru-a11Xapk", false],
  ["/vendor/overlay/voboost-setting-ru-a11.apk.other", false],
  ["/vendor/overlay/.voboost-setting-ru-a11.apk.staged.other", false],
  ["/vendor/overlay/voboost-setting-ru-a12.apk", false],
  ["/vendor/overlay/stock.apk", false],
  ["/vendor/overlay/voboost-setting-ruXapk", false],
  ["/vendor/overlay/voboost-setting-ru.apk.other", false],
  ["/vendor/overlay/.voboost-setting-ru.apk.staged.other", false],
] as const) {
  assert.equal(resourceEntries.some(entry => new RegExp(`^${entry.pattern}$`).test(path)), expected, path);
}
for (const entry of resourceEntries) assert.equal(entry.context, "u:object_r:voboost_resource_overlay_file:s0");
assert(policy.includes('type_transition voboost_install vendor_overlay_file:file voboost_resource_overlay_file ".voboost-setting-ru.apk.staged";'));
assert(policy.includes('type_transition voboost_install vendor_overlay_file:file voboost_resource_overlay_file ".voboost-setting-ru-a11.apk.staged";'));
console.log("Normal RRO exact label/transition contract passed");

// The file creator must acquire the same label for every bounded RU/EN staged basename.
const variants = readFileSync(resolve(root, "shared/src/owned_overlay.rs"), "utf8");
const staged = new Set([...variants.matchAll(/"(\.voboost-[a-z0-9-]+\.apk\.staged)"/g)].map(match => match[1]));
assert.equal(staged.size, 20);
const transitions = new Set([...policy.matchAll(/type_transition voboost_install vendor_overlay_file:file voboost_resource_overlay_file "([^"]+)";/g)].map(match => match[1]));
assert.deepEqual([...transitions].sort(), [...staged].sort());
assert(!/type_transition\s+voboost_install\s+vendor_overlay_file:file\s+voboost_resource_overlay_file\s*;/.test(policy));
const generated = readFileSync(resolve(root, "selinux/rules.gen.h"), "utf8");
const generatedTransitions = new Set([...generated.matchAll(/\{ "voboost_install", "vendor_overlay_file", "file", "voboost_resource_overlay_file", "([^"]+)" \}/g)].map(match => match[1]));
assert.deepEqual([...generatedTransitions].sort(), [...staged].sort());
assert(!generated.includes('{ "voboost_install", "vendor_overlay_file", "file", "voboost_resource_overlay_file", 0 }'));
for (const foreign of [".voboost-setting-en.apk.staged", ".voboost-systemui-en-a11.apk.staged", ".voboost-setting-en-a12.apk.staged", ".voboost-setting-en.apk.staged.other", ".stock.apk.staged", "voboost-setting-en.apk"])
  assert(!transitions.has(foreign) && !generatedTransitions.has(foreign), foreign);
console.log("All 20 RU/EN staged labels require exact named transitions; foreign names excluded");

// Installed-state publication must not grant write access to transaction directories.
const restoreDirectoryPermissions = (type: string) => new Set(
  [...policy.matchAll(new RegExp(`allow\\s+voboost_restore\\s+${type}:dir\\s+\\{([^}]+)\\}\\s*;`, "g"))]
    .flatMap((match) => match[1].trim().split(/\s+/)),
);
const installedStateParent = restoreDirectoryPermissions("voboost_install_root_dir");
const transactionParent = restoreDirectoryPermissions("voboost_install_staging_file");
for (const permission of ["write", "add_name", "remove_name"]) {
  assert(installedStateParent.has(permission));
  assert(!transactionParent.has(permission));
}
