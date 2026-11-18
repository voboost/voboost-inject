import { requireValue } from "./lib.ts";

export function validateNativeExports(symbols: string, script: string): void {
    const source = script.replace(/#.*$/gmu, "");
    const body = /^\s*\{\s*global:\s*([\s\S]+?)\s*local:\s*\*;\s*\};\s*$/u.exec(source);
    requireValue(body, "native export map must close all other symbols");
    const patterns = body[1].split(";").map((name) => name.trim()).filter(Boolean);
    requireValue(
        patterns.length > 0 && patterns.every((name) => /^[A-Za-z_][A-Za-z_0-9*]*$/u.test(name)),
        "invalid native export pattern",
    );
    const allowed = patterns.map((name) => new RegExp(`^${name.replace(/\*/gu, ".*")}$`, "u"));
    const defined = new Set<string>();
    for (const line of symbols.split("\n")) {
        const fields = line.trim().split(/\s+/u);
        if (!/^\d+:$/u.test(fields[0] ?? "")) continue;
        requireValue(fields.length >= 7, "malformed native dynamic symbol row");
        if (fields[6] === "UND" || !["GLOBAL", "WEAK", "UNIQUE"].includes(fields[4])) continue;
        if (!["DEFAULT", "PROTECTED"].includes(fields[5])) continue;
        requireValue(fields.length >= 8, "native export has no name");
        const name = fields[7];
        requireValue(
            allowed.some((pattern) => pattern.test(name)),
            `unexpected native export: ${name}`,
        );
        defined.add(name);
    }
    for (const name of patterns.filter((pattern) => !pattern.includes("*"))) {
        requireValue(defined.has(name), `missing native entrypoint: ${name}`);
    }
}
