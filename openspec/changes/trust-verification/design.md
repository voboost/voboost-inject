# Design — trust-verification (native payload coverage)

<!-- Date: 2026-07-23. Records why trust extends to the native payload, why
     the release manifest is the payload's trust source, and why the agent
     manifest is left as the sole source of the target process. -->

## D1 — Why verify the native payload, not just agents

**Choice:** before injecting, the daemon verifies each native payload file's
sha256 against the verified release manifest; a file that does not match is
not used.

**Reasoning:** the agent hash check exists because an agent is app-provided
code that the daemon runs inside a target — untrusted input that must be
integrity-checked. The native payload is the same class of risk at higher
stakes: `libimplant.so` and the hooker run with full process privileges
inside every target. If the daemon injected a payload file without checking
it, a replaced or truncated `.so` (disk corruption, a botched OTA, an
adversary with write access to the root zone) would execute arbitrary native
code with no gate. The release manifest already exists and is signed by the
key-root family (see `release-manifest`); verifying each payload file's sha256
against it is the same mechanism as the agent check, against a different
manifest — one trust anchor (`EMBEDDED_PUBKEY`), two manifests, one principle
(sha256-before-use).

## D2 — Why the release manifest is the payload trust source, not a second signed manifest

**Choice:** the payload's hashes live in the release manifest (already signed
by key-root); no separate "payload manifest" is introduced.

**Reasoning:** a second signed document would duplicate the signing,
distribution, and verification machinery of the release manifest for no
benefit — the release manifest already lists files with sha256 under the
`inject` channel, and the payload files are `inject`-channel files (see
`release-manifest`). The daemon ELF keeps its appended signature for
self-verification at apply time (it must verify before the manifest is
parsed); the payload `.so`/`.a` files do not need appended signatures
because they are never exec'd or self-verified in isolation — they are always
consumed by a daemon that already parsed the verified manifest. Keeping the
payload hashes in the one release manifest avoids a second trust document and
keeps "the signed manifest is the hash source" uniform across agents and
payload.

## D3 — Why the agent manifest stays the sole source of the target process

**Choice:** "Manifest is the source of target process" is left unchanged —
the agent manifest (not the release manifest) defines each agent's target
process.

**Reasoning:** the release manifest is an OTA integrity document (file →
sha256); it carries no injection-plan semantics. The agent-to-process binding
is plan-level metadata that belongs in the agent manifest alongside the
agent's id and kind. Conflating the two would make the release manifest both
an integrity document and an injection-plan source, coupling OTA cadence to
plan semantics. Keeping them separate preserves the existing invariant: the
daemon takes the target process exclusively from the agent manifest and
ignores any such field in the plan.
