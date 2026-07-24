## 1. Release manifest covers the native payload

- [ ] 1.1 `make release-manifest` lists every `inject`-channel file: the daemon
      ELF plus `libimplant.so`, `liblsplant.so`, `liblsplt.so`, `libdobby.a`
      for both `arm64-v8a` and `armeabi-v7a`
- [ ] 1.2 Each payload entry carries `path`, `channel=inject`, `sha256`,
      `size`, `version`, and `abi`
- [ ] 1.3 The daemon verifies each payload file's sha256 against the verified
      release manifest before using it (see `trust-verification`)

## 2. abi field on per-ABI entries

- [ ] 2.1 Add `abi` (`arm64-v8a` | `armeabi-v7a`) to per-ABI payload entries;
      single-ABI entries (daemon ELF) omit it
- [ ] 2.2 The parser rejects a manifest that lists one ABI's payload but not
      the other's (deployment gap) before the daemon tries to inject

## 3. Bounds update

- [ ] 3.1 Entry-count bound updated to cover the payload's ≈8 per-ABI files
      plus the daemon ELF (the bound rejects pathological manifests, not
      normal multi-file lists)

## 4. Validate

- [ ] 4.1 `npx @fission-ai/openspec validate release-manifest --strict`
- [ ] 4.2 Device test: a tampered `libimplant.so` (sha256 mismatch) is rejected
      and not injected; a manifest missing one ABI is rejected at parse
