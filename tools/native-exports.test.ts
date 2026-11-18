import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";
import { ROOT } from "./lib.ts";
import { validateNativeExports } from "./native-exports.ts";

const row = (name: string, index = "7", visibility = "DEFAULT", binding = "GLOBAL") =>
    ` 1: 00000100 16 FUNC ${binding} ${visibility} ${index} ${name}`;
const script = "{ global: entry; _ZTI*; __cxa_*; local: *; };";

test("native exports retain exact entrypoints and shared exception ABI", () => {
    validateNativeExports([
        " 0: 00000000 0 NOTYPE LOCAL DEFAULT UND",
        row("entry"), row("_ZTISt9exception"), row("__cxa_throw"), row("malloc", "UND"),
    ].join("\n"), script);
});

test("native exports reject accidental public and protected implementation symbols", () => {
    for (const visibility of ["DEFAULT", "PROTECTED"]) {
        const symbols = [row("entry"), row("internal", "7", visibility)].join("\n");
        assert.throws(() => validateNativeExports(symbols, script), /unexpected native export/u);
    }
});

test("native exports do not accept an imported or hidden entrypoint", () => {
    assert.throws(() => validateNativeExports(row("entry", "UND"), script), /missing native entrypoint/u);
    assert.throws(() => validateNativeExports(row("entry", "7", "HIDDEN"), script), /missing native entrypoint/u);
});

test("native export maps reject open or malformed recipes and symbol rows", () => {
    assert.throws(
        () => validateNativeExports(row("entry"), "{ global: entry; };"), /close all other/u,
    );
    assert.throws(
        () => validateNativeExports(row("entry"), "{ global: entry[0]; local: *; };"),
        /invalid native export/u,
    );
    assert.throws(
        () => validateNativeExports("1: broken", script), /malformed native dynamic symbol/u,
    );
});

test("production map retains its loader API and rejects internal LSPlant helpers", () => {
    const entrypoints = {
        implant: [
            "implant_init", "implant_finish_log_handoff", "implant_log_read_fd",
            "implant_state_reply_write_fd", "JNI_OnLoad", "log_internal_impl",
        ],
    };
    for (const [name, required] of Object.entries(entrypoints)) {
        const map = readFileSync(resolve(ROOT, `implant/${name}.map`), "utf8");
        const symbols = [...required, "__dynamic_cast", "__gxx_personality_v0"]
            .map((value) => row(value)).join("\n");
        validateNativeExports(symbols, map);
        assert.throws(
            () => validateNativeExports(`${symbols}\n${row("_ZN7lsplant8InternalEv")}`, map),
            /unexpected native export/u,
        );
    }
});
