# Design — ota (native payload self-update + dex agents)

<!-- Date: 2026-07-23. Records why the inject self-update now covers
     multi-file payload, why re-verify extends to payload sha256, and why
     agents are .dex on the same carrier channel. -->

## D1 — Why the self-update covers the payload files, not just the ELF

**Choice:** the inject self-update swaps the daemon ELF *and* the native
payload files (`libimplant.so`, `liblsplant.so`, `liblsplt.so`, `libdobby.a`
per ABI) as one atomic unit.

**Reasoning:** the payload files are root-owned and ship with the daemon
release (they are `inject`-channel files — see `release-manifest`). If a
self-update swapped only the ELF, the new daemon would inject with stale
payload files — a version skew that could crash targets (a new daemon
expecting a new `libimplant.so` ABI, or a new LSPlant API). The self-update
must treat the ELF + payload as one indivisible update: all verified, all
swapped, or none. The existing atomic-swap machinery (staging → verify →
`.prev` → rename → marker → SIGTERM) is artifact-agnostic and extends
naturally — the ELF rename becomes a directory of renames, all gated by the
same single marker so a partial swap is never observable.

## D2 — Why re-verify extends to payload sha256 (and the ELF keeps appended-sig)

**Choice:** the daemon re-verifies the ELF via its appended `VOBSIG1` signature
(unchanged) *and* re-verifies each payload file's sha256 against the release
manifest (new).

**Reasoning:** the ELF must self-verify before the release manifest is parsed
(it is the bootstrap artifact — the binary that *parses* the manifest), so it
keeps its appended signature. The payload files have no appended signature (see
`release-manifest` D1 — an appended signature cannot cover multiple files and
cannot be appended to a `.so` that `dlopen` loads). Their integrity comes from
the release manifest, which the now-verified daemon parses and re-verifies
with `EMBEDDED_PUBKEY` at apply time. This is two complementary checks: the
ELF proves its own integrity independently (appended-sig), then vouches for
the payload's integrity via the signed manifest it just verified.

## D3 — Why agents are .dex on the same carrier channel

**Choice:** agents ship as `.dex` files (not `.js`), as app-APK assets
(`assets/agents/*.dex`), staged by the app and verified against the agent
manifest — the same carrier channel and verification flow as before.

**Reasoning:** the hooking layer moved from frida's QuickJS (JS scripts) to
LSPlant inside the JVM (Java agents compiled to DEX — see `native-payload`,
`agent-entry-seam`). The OTA *transport* is unaffected: agents are still
app-owned, still ride in the app APK, still staged via `agents-update-ready`,
still verified by sha256 against the agent manifest (signed by key-root — see
`trust-verification`). Only the artifact format changes (`.js` → `.dex`); the
`ScriptExtractor` becomes an `AgentExtractor`, and the agent manifest's per-file
hashes cover `.dex` instead of `.js`. Keeping the carrier channel identical
means the OTA pipeline, the staging markers, and the trust model need no
structural change — just a format swap.
