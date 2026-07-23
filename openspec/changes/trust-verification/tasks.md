## 1. Native payload verification via the release manifest

- [ ] 1.1 Before using any native payload file (`libimplant.so`,
      `liblsplant.so`, `liblsplt.so`, `libdobby.a`), verify its sha256 against
      the verified release manifest; reject on mismatch (do not inject)
- [ ] 1.2 Verify the per-ABI file for the bitness the injector detected
      (see `native-payload`); reject if the required ABI's file is absent or
      mismatches
- [ ] 1.3 Re-verify after an OTA self-update swaps the payload (the new
      manifest is the authority for the new files)

## 2. Embedded-key coverage widened

- [ ] 2.1 The embedded key (`EMBEDDED_PUBKEY`) is the trust anchor for both
      the agent manifest and the release manifest; no key is read from disk
- [ ] 2.2 Confirm the release manifest is re-verified with `EMBEDDED_PUBKEY`
      at apply time (the OTA client verifies it first; the daemon re-verifies)

## 3. Per-agent hash (restated)

- [ ] 3.1 Per-agent sha256 check covers the agent `.dex` files against the
      agent manifest (one of two hash-verification paths now)
- [ ] 3.2 Keep "no skip-verify mode" (verification always on, any build)

## 4. Validate

- [ ] 4.1 `npx @fission-ai/openspec validate trust-verification --strict`
- [ ] 4.2 Device test: a tampered `libimplant.so` is rejected (not injected);
      a valid payload injects and the marker appears in `/proc/<pid>/maps`
