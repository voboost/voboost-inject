#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { main, requireValue, ROOT } from "./lib.ts";

main(() => {
    const read = (path: string) => readFileSync(resolve(ROOT, path), "utf8");
    const daemon = read("daemon/build.rs");
    const install = read("install/build.rs");
    const restore = read("restore/build.rs");
    const uninstall = read("uninstall/build.rs");
    const makefile = read("Makefile");
    const adapter = read("tools/prepare-beta1-unsigned.sh");
    const production = [daemon, install, restore, uninstall, makefile, adapter].join("\n");

    requireValue(
        !production.includes("VOBOOST_INSTALL_AUTHORIZATION_PUBLIC_KEY_PEM") &&
            !production.includes("INSTALL_AUTHORIZATION_PUBLIC_KEY"),
        "production build still requires a distinct install-authorization root",
    );
    for (const source of [daemon, install, restore, uninstall]) {
        requireValue(
            !source.includes("VOBOOST_NATIVE_MANIFEST_PUBLIC_KEY_PEM"),
            "privileged product consumer requires the retired native-manifest root",
        );
    }
    requireValue(
        [daemon, install, restore, uninstall].every((source) =>
            source.includes("VOBOOST_RESTORE_PUBLIC_KEY_PEM"),
        ),
        "restore authority is not shared by every privileged recovery consumer",
    );
    requireValue(
        !adapter.includes("PUBLIC_KEY") &&
            !adapter.includes("PRIVATE_KEY") &&
            !adapter.includes("SIGNING_KEY") &&
            !adapter.includes("openssl"),
        "unsigned adapter consumes signing or key material",
    );
    console.log(
        "build-key-minimality: privileged consumers exclude retired native-manifest input and keep exact product roots",
    );
}, "build-key-minimality");
