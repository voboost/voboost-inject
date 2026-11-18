import { writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

type LabelEntry = Readonly<{
  readonly symbol: string;
  readonly path: string;
  readonly pattern: string;
  readonly context: string;
}>;

export const SELINUX_LABEL_CONTRACT = Object.freeze({
  root: "u:object_r:voboost_data_file:s0",
  entries: Object.freeze([
    { symbol: "RESOURCE_JOURNAL_TREE", path: "/data/voboost/i18n-resource-transaction", pattern: "/data/voboost/i18n-resource-transaction(/.*)?", context: "u:object_r:voboost_resource_journal_file:s0" },
    { symbol: "RESOURCE_OVERLAY", path: "/vendor/overlay/voboost-setting-ru.apk", pattern: "/vendor/overlay/voboost-setting-ru\\.apk", context: "u:object_r:voboost_resource_overlay_file:s0" },
    { symbol: "RESOURCE_OVERLAY_STAGE", path: "/vendor/overlay/.voboost-setting-ru.apk.staged", pattern: "/vendor/overlay/\\.voboost-setting-ru\\.apk\\.staged", context: "u:object_r:voboost_resource_overlay_file:s0" },
    { symbol: "RESOURCE_OVERLAY_A11", path: "/vendor/overlay/voboost-setting-ru-a11.apk", pattern: "/vendor/overlay/voboost-setting-ru-a11\\.apk", context: "u:object_r:voboost_resource_overlay_file:s0" },
    { symbol: "RESOURCE_OVERLAY_A11_STAGE", path: "/vendor/overlay/.voboost-setting-ru-a11.apk.staged", pattern: "/vendor/overlay/\\.voboost-setting-ru-a11\\.apk\\.staged", context: "u:object_r:voboost_resource_overlay_file:s0" },
    { symbol: "RUNTIME", path: "/data/voboost/voboost-daemon", pattern: "/data/voboost/voboost-daemon", context: "u:object_r:voboost_exec:s0" },
    { symbol: "INJECT", path: "/data/voboost/voboost-inject", pattern: "/data/voboost/voboost-inject", context: "u:object_r:voboost_exec:s0" },
    { symbol: "INSTALL", path: "/data/voboost/voboost-install", pattern: "/data/voboost/voboost-install", context: "u:object_r:voboost_install_exec:s0" },
    { symbol: "RESTORE", path: "/data/voboost/voboost-restore", pattern: "/data/voboost/voboost-restore", context: "u:object_r:system_file:s0" },
    { symbol: "UNINSTALL", path: "/data/voboost/voboost-uninstall", pattern: "/data/voboost/voboost-uninstall", context: "u:object_r:voboost_uninstall_exec:s0" },
    { symbol: "SELINUX", path: "/data/voboost/voboost-selinux", pattern: "/data/voboost/voboost-selinux", context: "u:object_r:voboost_selinux_exec:s0" },
    { symbol: "OPERATION_TREE", path: "/data/voboost/operation.json", pattern: "/data/voboost/(?:operation\\.(?:json|lock)|\\.operation\\.json\\.tmp)", context: "u:object_r:voboost_operation_file:s0" },
    { symbol: "INSTALL_PROGRESS", path: "/data/voboost/logs/install-progress.jsonl", pattern: "/data/voboost/logs/install-progress\\.jsonl", context: "u:object_r:voboost_operation_file:s0" },
    { symbol: "UPDATE_STAGING_TREE", path: "/data/voboost/install/<tx>/candidate", pattern: "/data/voboost/install/[0-9a-f]{64}/(?:candidate(?:/.*)?|\\.?update-journal\\.json(?:\\.tmp)?)", context: "u:object_r:voboost_update_staging_file:s0" },
    { symbol: "INSTALLED_STATE", path: "/data/voboost/install/state.json", pattern: "/data/voboost/install/(?:state\\.json|\\.state\\.json\\.tmp)", context: "u:object_r:voboost_installed_state_file:s0" },
    { symbol: "INSTALL_ROOT", path: "/data/voboost/install", pattern: "/data/voboost/install", context: "u:object_r:voboost_install_root_dir:s0" },
    { symbol: "INSTALL_TREE", path: "/data/voboost/install/<tx>", pattern: "/data/voboost/install/.*", context: "u:object_r:voboost_install_staging_file:s0" },
    { symbol: "RESTORE_PREPARE", path: "/data/voboost/run/restore-prepare", pattern: "/data/voboost/run/restore-prepare", context: "u:object_r:voboost_recovery_file:s0" },
    { symbol: "RESTORE_PREPARE_JOURNAL", path: "/data/voboost/run/restore-prepare/restore-journal.json", pattern: "/data/voboost/run/restore-prepare/restore-journal\\.json", context: "u:object_r:voboost_recovery_file:s0" },
    { symbol: "RESTORE_PREPARE_TEMP", path: "/data/voboost/run/restore-prepare/.restore-journal.json.tmp", pattern: "/data/voboost/run/restore-prepare/\\.restore-journal\\.json\\.tmp", context: "u:object_r:voboost_recovery_file:s0" },
    { symbol: "RESTORE_REPLY", path: "/data/voboost/run/restore-reply.json", pattern: "/data/voboost/run/restore-reply\\.json", context: "u:object_r:voboost_recovery_file:s0" },
    { symbol: "UNINSTALL_REPLY", path: "/data/voboost/run/desktop-uninstall-result.json", pattern: "/data/voboost/run/desktop-uninstall-result\\.json", context: "u:object_r:voboost_uninstall_result_file:s0" },
    { symbol: "RECOVERY_TREE", path: "/data/voboost/recovery", pattern: "/data/voboost/recovery(/.*)?", context: "u:object_r:voboost_recovery_file:s0" },
    { symbol: "AGENT_STATE_TREE", path: "/data/voboost/state", pattern: "/data/voboost/state(/.*)?", context: "u:object_r:voboost_agent_state_file:s0" },
    { symbol: "UNINSTALL_TREE", path: "/data/voboost/uninstall", pattern: "/data/voboost/uninstall(/.*)?", context: "u:object_r:voboost_uninstall_data_file:s0" },
    { symbol: "INCOMING_TREE", path: "/data/voboost/generations/next", pattern: "/data/voboost/generations/next(/.*)?", context: "u:object_r:voboost_incoming_file:s0" },
    { symbol: "GENERATION_TREE", path: "/data/voboost/generations", pattern: "/data/voboost/generations(/.*)?", context: "u:object_r:voboost_generation_file:s0" },
  ] satisfies readonly LabelEntry[]),
  catchAllPattern: "/data/voboost(/.*)?",
} as const);

const here = dirname(fileURLToPath(import.meta.url));
const injectRoot = resolve(here, "..");

function cHeader(): string {
  const definitions = SELINUX_LABEL_CONTRACT.entries.flatMap((entry) => [
    `#define VOBOOST_PATH_${entry.symbol} "${entry.path}"`,
    `#define VOBOOST_CONTEXT_${entry.symbol} "${entry.context}"`,
  ]);
  return `/* Generated by tools/selinux-label-contract.ts. Do not edit. */\n#ifndef VOBOOST_SELINUX_LABEL_CONTRACT_H\n#define VOBOOST_SELINUX_LABEL_CONTRACT_H\n#define VOBOOST_CONTEXT_ROOT "${SELINUX_LABEL_CONTRACT.root}"\n${definitions.join("\n")}\n#endif\n`;
}

function rustModule(symbols: readonly string[], includeRoot: boolean): string {
  const definitions = SELINUX_LABEL_CONTRACT.entries.filter((entry) => symbols.includes(entry.symbol)).map(
    (entry) => `pub const ${entry.symbol}_CONTEXT: &str = "${entry.context}";`,
  );
  const root = includeRoot ? `\npub const ROOT_CONTEXT: &str = "${SELINUX_LABEL_CONTRACT.root}";` : "";
  return `// Generated by voboost-inject/tools/selinux-label-contract.ts. Do not edit.\n${definitions.join("\n")}${root}\n`;
}

function fileContexts(): string {
  const lines = SELINUX_LABEL_CONTRACT.entries.map(
    (entry) => `${entry.pattern.padEnd(48)} ${entry.context}`,
  );
  return `# Generated by tools/selinux-label-contract.ts. Do not edit.\n# Exact stock recovery entries must precede the root-zone catch-all.\n${lines.join("\n")}\n${SELINUX_LABEL_CONTRACT.catchAllPattern.padEnd(48)} ${SELINUX_LABEL_CONTRACT.root}\n`;
}

writeFileSync(resolve(injectRoot, "selinux/label_contract.h"), cHeader());
writeFileSync(resolve(injectRoot, "selinux/file_contexts"), fileContexts());
writeFileSync(resolve(injectRoot, "shared/src/uninstall_label_contract.rs"), rustModule(["INSTALLED_STATE", "UNINSTALL_TREE", "UNINSTALL", "RUNTIME", "SELINUX", "RESTORE", "RECOVERY_TREE", "AGENT_STATE_TREE"], true));
writeFileSync(resolve(injectRoot, "shared/src/daemon_label_contract.rs"), rustModule(["UNINSTALL_TREE", "UNINSTALL_REPLY"], true));
