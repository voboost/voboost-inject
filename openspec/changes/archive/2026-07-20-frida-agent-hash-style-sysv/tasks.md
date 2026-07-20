## 1. OpenSpec change (frida-agent-hash-style-sysv)

- [x] 1.1 `proposal.md`: why (termux-elf-cleaner strips .gnu.hash, NDK default
      is gnu-only -> hashless -> Bionic dlopen fails), what (--hash-style=sysv),
      impact
- [x] 1.2 `design.md`: D1 where the hash disappears; D2 why hashless; D3 the fix;
      D4 sysv vs both; D5 layered after libc-shim patch
- [x] 1.3 `specs/build-and-signing/spec.md`: ADDED requirement (agent keeps
      DT_HASH; dlopen succeeds)
- [x] 1.4 `.openspec.yaml`: `schema: spec-driven`, `created: 2026-07-01`

## 2. Code

- [x] 2.1 `subprojects/frida-core/lib/agent/meson.build`: add
      `-Wl,--hash-style=sysv` to the Android agent link args
- [x] 2.2 `subprojects/packagefiles/frida-core-android-agent-link-args.patch`:
      generated from the meson.build diff (hash-style only; the `-u malloc`
      emutls fix is in the separate libc-shim patch)
- [x] 2.3 `subprojects/frida-core.wrap`: `diff_files` lists the patch

## 3. Validate

- [x] 3.1 `npx @fission-ai/openspec validate frida-agent-hash-style-sysv --strict`
      passes
- [x] 3.2 Clean-clone validation: `git reset --hard HEAD` in
      `subprojects/frida-core` -> apply libc-shim patch -> apply this patch ->
      both apply cleanly, `make build-android` succeeds
- [x] 3.3 Emulator: `llvm-readelf -d` on final `frida-agent-64.so` shows `DT_HASH`;
      daemon injects an agent into a target (`state: active`, `frida: loaded`)
