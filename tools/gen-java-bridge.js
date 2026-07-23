#!/usr/bin/env node
// Generate a Vala source embedding the frida-java-bridge JS as a string
// constant. frida-core 17.x does not bundle the Java bridge in the built
// agent for our configuration (see plans/2026-07-23-frida-java-bridge-
// investigation.md), so the daemon inlines it and prepends it to every
// agent script at create_script time, defining globalThis.Java
// synchronously (mirroring how frida-tools' CLI exposes the bridge via
// Script.evaluate with a wrapper).
//
// Usage: node gen-java-bridge.js <java-bridge.js> <embedded_java_bridge.vala>

"use strict";

const fs = require("fs");
const path = require("path");

const [, , jsPath, outPath] = process.argv;
if (!jsPath || !outPath) {
    console.error("Usage: node gen-java-bridge.js <java-bridge.js> <embedded_java_bridge.vala>");
    process.exit(2);
}

const js = fs.readFileSync(jsPath, "utf8");

// Vala string escaping: backslash first, then double-quote.
const escaped = js.replace(/\\/g, "\\\\").replace(/"/g, '\\"');

const out =
    "// Generated. Do not edit. Embedded frida-java-bridge JS\n" +
    "// (config/java-bridge.js), exposed to agents via frida_controller.\n" +
    "namespace Voboost {\n" +
    '    public const string JAVA_BRIDGE_JS = "' + escaped + '";\n' +
    "}\n";

fs.writeFileSync(outPath, out, "utf8");
