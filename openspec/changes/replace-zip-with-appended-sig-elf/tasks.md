## 1. OpenSpec change (replace-zip-with-appended-sig-elf)

- [x] 1.1 `proposal.md`: why (ZIP wraps one ELF misleadingly + 200-line ZIP
      reader is attack surface; per-agent manifest moved to app APK), what
      (one ELF + appended VOBSIG1 ed25519 sig), impact, non-goals
- [x] 1.2 `design.md`: D1 appended not sidecar; D2 trailing block format;
      D3 SIG_OFFSET authoritative; D4 ed25519 over raw bytes; D5
      REJECTED_BAD_MANIFEST removed; D6 MAX_APK_BYTES stays, MAX_APK_ENTRIES
      goes; D7 Makefile sign-elf; renaming table; verify_appended_sig sketch
- [x] 1.3 `specs/ota/spec.md`: MODIFIED Re-verify + Apply-staged-update
      requirements (appended-sig flow, no embedded manifest); ADDED
      Inject-payload-is-single-appended-sig-ELF; REMOVED Build-time embedded
      daemon manifest inside the APK
- [x] 1.4 `specs/release-manifest/spec.md`: MODIFIED Streaming APK entry
      inflate (repurposed to appended-sig verify, no inflate path)
- [x] 1.5 `.openspec.yaml`: `schema: spec-driven`, `created: 2026-07-20`

## 2. src/ota.vala — verify_appended_sig + simplified apply

- [ ] 2.1 Add `verify_appended_sig(bytes, trust, out elf_bytes) → bool`:
      static, pure. Reads the trailing 80 bytes, checks `VOBSIG1\0` magic,
      reads LE uint64 SIG_OFFSET (bounds-checked: 1 <= offset <=
      len - 80), slices ELF `[0..offset)`, reads 64-byte sig, returns
      `trust.verify_signature(elf_bytes, sig)` (and the sliced elf_bytes on
      success)
- [ ] 2.2 Add `read_le64(bytes, off) → uint64` helper (the only LE reader
      left after the ZIP reader is removed)
- [ ] 2.3 Remove `extract_apk_entry`, `read_local_entry`, `inflate_raw`,
      `read_le16`, `read_le32` (~200 lines); remove constants
      `APK_BINARY_ENTRY`, `APK_MANIFEST_ENTRY`, `APK_MANIFEST_SIG_ENTRY`,
      `MAX_APK_ENTRIES`
- [ ] 2.4 Rename `MAX_APK_BYTES` → `MAX_INJECT_BYTES` (value unchanged:
      64 MiB) and update all references
- [ ] 2.5 Simplify `apply_inject_update`: read staged file → bound-check →
      `verify_appended_sig` → install returned elf_bytes via `write_bytes_exec`
      (drop the manifest re-verify block and the binary-extract block); update
      the doc comment (no APK, no embedded manifest)
- [ ] 2.6 Simplify `InjectApplyOutcome`: remove `REJECTED_BAD_MANIFEST`
      (unreachable now); map sig/magic/truncation failures to
      `REJECTED_BAD_BINARY`
- [ ] 2.7 `find_staged_inject`: look for the bare name `voboost-inject` (no
      `.apk`)

## 3. Tests + fixtures

- [ ] 3.1 `test/fixtures/gen-fixtures.sh`: produce a signed inject fixture
      (ELF bytes `fake-inject-binary-v1\n` + appended VOBSIG1 + LE uint64
      offset + ed25519 sig over the ELF bytes, signed with the dev key) as
      `voboost-inject` (no extension); a bad-sig fixture (flip a byte in the
      sig) as `voboost-inject-bad-sig`; a no-magic fixture (trailing bytes
      without VOBSIG1) as `voboost-inject-no-magic`; a truncated fixture
      (file shorter than 80 bytes) as `voboost-inject-truncated`. Remove the
      four APK fixtures (`voboost-inject.apk`, `-deflated.apk`, `-bad-sig.apk`,
      `-bad-binary.apk`) and the `voboost-inject-bad` seed
- [ ] 3.2 `test/ota_test.vala`: drop the APK-extract tests
      (`test_apk_extract_*`); drop the deflated-apply test; rename/rewrite
      the apply tests to use the signed-ELF fixture
      (`test_inject_apply_success`, `test_inject_apply_bad_sig`,
      `test_inject_apply_no_magic`, `test_inject_apply_truncated`,
      `test_inject_apply_no_inject`); add a `verify_appended_sig` direct test
      (lying SIG_OFFSET rejected); keep the rollback/confirm/no-prev-target
      tests (unchanged flow)

## 4. Makefile + CI

- [ ] 4.1 `Makefile`: replace the `inject-apk` target with `sign-elf`:
      `openssl pkeyutl -sign -rawin -inkey $KEY -in $BINARY -out $SIGFILE`
      (64-byte raw ed25519 sig), then a small Python helper appends
      `VOBSIG1\0` + LE uint64(file_size of BINARY) + SIGFILE to produce
      `build/voboost-inject`
- [ ] 4.2 `.github/workflows/release.yml`: `make inject-apk` → `make sign-elf`;
      published artifact `voboost-inject.apk` → `voboost-inject` (no
      extension)
- [ ] 4.3 `voboost-install/releases/manifest.json`: inject entry
      `downloadUrl` drops the `.apk` extension

## 5. voboost-app (sibling repo)

- [ ] 5.1 `ApkStager.kt`: rename `INJECT_APK_NAME` → `INJECT_FILE_NAME`,
      value `"voboost-inject.apk"` → `"voboost-inject"` (no extension); KDoc
      updated (no longer an APK)
- [ ] 5.2 voboost-app tests: update references to the renamed constant and
      the new staged filename

## 6. Validate + build

- [ ] 6.1 `npx @fission-ai/openspec validate replace-zip-with-appended-sig-elf
      --strict` passes
- [ ] 6.2 `make build`, `make test` pass (voboost-inject host)
- [ ] 6.3 `cd ../voboost && ANDROID_HOME=/Users/vitaly/Library/Android/sdk
      ./gradlew testUnit` passes (voboost-app)
- [ ] 6.4 `npx @fission-ai/openspec validate --all --strict` passes in both
      repos
