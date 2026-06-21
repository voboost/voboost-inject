## Context

Voboost is self-distributed (not via Play); one app distributes and updates
itself, and the Frida agents ship inside its APK. Over a car's connection,
re-downloading the whole payload to change one script is wasteful. This change
designs incremental OTA and the producer side of the trust boundary that feeds
the root daemon.

The split between this change and the implemented `inject` daemon: `inject` is
the trusted on-device executor (verification primitives, embedded trust anchor
`EMBEDDED_PUBKEY`, and it already observes the app-zone `staging/` directory +
`update-ready` marker but only logs them — see `src/app_zone_watcher.vala` and
`Supervisor`'s `update_ready` handler). `ota` is how verified material is produced
and delivered (CI release manifest, the daemon-side apply/rollback that consumes
`update-ready`, the app-side delta client, and post-system-OTA re-arm).

Two distinct signed documents are in play (design D1): the **daemon manifest**
(`manifest.json`+`manifest.sig`, per-agent id/channel/file/sha256/process/
kind/entrypoint/boot, app-signed, daemon-verified against `EMBEDDED_PUBKEY`) and
the **OTA release manifest** (`release-manifest.json`+`.sig`, per-file
sha256/size/version/channel, CI-signed, app/client-verified). Both use the same
ed25519 key family.

Measured platform fact: a system OTA keeps root (firmware stays debuggable +
permissive) and the whole `/data` tree, but reverts `/system` — so the init hook
is lost while binaries and agents survive (see the voboost app repo
`docs/ota-session-runbook.md`, cross-repo). A car also cannot be rebooted on
demand (no fastboot), so an OTA that only took effect "at next boot" would
effectively never apply; this drives the no-reboot core-apply design (D6).

## Goals / Non-Goals

**Goals:**
- Editing one agent downloads only that file (kilobytes); nothing else fetched.
- Every fetched byte is verified against a signed manifest before use.
- Atomic apply with rollback on both planes; never end up broken.
- A staged agent update is applied at the earliest daemon-ready point (right
  after VERIFY_SELF, before the first injection), so the first injection uses the
  new set.
- The daemon binary updates on-device **without a car reboot**, with automatic
  rollback if the new binary comes up DEGRADED.
- Survive a system OTA without re-downloading anything; restore the init hook.

**Non-Goals:**
- The daemon's verification primitives and trust anchor (implemented by `inject`).
- The OTA client fetch/diff/download/staging-writer (owned by the voboost app
  repo, which also produces the `agents`/`app` channel manifests). This change
  defines the contract the client satisfies and the daemon/CI sides.
- Binary-delta patching (`bsdiff`/`bspatch`); changed files are downloaded whole
  (agents are small; the core binary is large but rarely updated).
- A general-purpose package manager; scoped to voboost's components/channels.

## Decisions

### D1. Two manifests, one key family
The **daemon manifest** (`manifest.json`+`manifest.sig`, in `/data/voboost`)
lists each agent with `id`/`channel`/`file`/`sha256`/`process`/`kind`/
`entrypoint`/`boot`; it ships inside the APK and is signed by the app build
pipeline (`ru.voboost`); the daemon verifies it with `EMBEDDED_PUBKEY`
(Monocypher) at VERIFY_SELF. The **OTA release manifest**
(`release-manifest.json`+`.sig`) lists each release file with `path`/`channel`/
`sha256`/`size`/`version`; it is produced and signed by this repo's CI and
verified by the OTA client (the app). Both use the same ed25519 key family.
*Rejected:* one combined manifest — it conflates injection metadata (per-agent,
trusted by the daemon) with release transport (per-file, trusted by the client)
across two trust boundaries.

### D2. Diff-by-hash, download changed files whole (no bsdiff)
The app keeps its current release manifest, fetches the new one, and downloads
only files whose `sha256` changed, each **whole**. Agents are small (kilobytes);
the core binary is large but rarely updated, so the simplicity of whole-file
download beats binary-delta tooling. *Rejected:* `bsdiff`/`bspatch` — it would
add a device dependency and memory/complexity for a (large but rare) core blob,
with no benefit for the small agent files that dominate update frequency.

### D3. Verify every fetched artifact; the daemon re-verifies staged material
Each downloaded file is verified against the `sha256` in the signed release
manifest; the manifest is verified against the public key. The daemon never
trusts the app's verification for material it installs into the trusted zone: it
re-verifies the staged daemon manifest (signature + per-agent sha256) with
`EMBEDDED_PUBKEY`, and for core re-verifies `release-manifest.json.sig` with
`EMBEDDED_PUBKEY` to obtain a trusted core sha256. A failed verification aborts
the apply and leaves the current set intact.

### D4. Two update planes
- **app+agents (frequent):** a new voboost release; agents + a signed daemon
  manifest ride inside the APK. Updating agents = a new release. This plane is
  additionally covered by the APK's own signature. Applied immediately.
- **core (rare):** the `voboost-inject` binary, updated on-device without a car
  reboot (D6).

### D5. Producer side of the staging contract
For app+agents, the app writes the new daemon manifest + agents into the app-zone
`staging/` directory and creates the atomic `update-ready` marker as the last
step. The daemon (consuming the `update-ready` it already observes) treats staged
content as untrusted until it re-verifies with `EMBEDDED_PUBKEY` and performs the
TOCTOU-safe copy + atomic swap. The contract: `update-ready` is created only
after all staged files are fully written, so the daemon never reads a partial
set.

### D6. Atomic apply with rollback
- **agents — manifest swap (not directory swap):** agents are individual files
  whose paths come from the daemon manifest; the authoritative "agent set" is the
  signed `manifest.json`+`manifest.sig`. Content-addressing is a **normative
  producer requirement** (atomic-apply-rollback): a changed agent ships at a new,
  sha-derived path, so the daemon installs new payloads at fresh paths and never
  overwrites a file the active manifest still verifies against — without this, a
  mid-loop failure would leave the active manifest referencing overwritten
  (mismatched) bytes. The daemon copies the staged manifest (+ new agent files)
  into the root zone as TOCTOU-safe temp files, re-verifies them on the
  root-owned inode, then atomically renames the active manifest aside to
  `manifest.json.prev` (+`manifest.sig.prev`) and the verified temp into place.
  Applied immediately (re-inject). Any failure leaves the daemon on the old
  manifest. *Rejected:* swapping an `agents/` directory — the code has no such
  directory-as-a-unit.
- **core — content-addressed install + init restart (no car reboot):** the daemon
  cannot replace its own running binary in place, and a second root process is
  forbidden (inject's "only root-holding component" invariant). Instead the daemon
  verifies the staged binary, installs it as `voboost-inject-<sha>` in the root
  zone, writes a `core-switch-pending` marker naming the previous active file,
  atomically repoints the stable launch path `/data/voboost/voboost-inject` to the
  new file, and performs a clean self-shutdown. Android init (which restarts the
  service on exit) then launches the new binary — no car reboot. Rollback: on a
  (re)start where a `core-switch-pending` marker is present and the daemon would
  enter DEGRADED, the daemon repoints the launch path back to the previous file,
  clears the marker, and self-shuts down; init restarts the previous binary. On a
  READY (re)start the marker is cleared (switch confirmed) and the previous file
  is garbage-collected only when the launch path no longer points at it (if a
  power loss left the launch path still on the previous file, that file is still
  the active binary and is kept).

### D7. System-OTA survival via re-arm
Because a system OTA reverts only `/system`, the only lost artifact is the init
hook. A new operator-invoked `make device-rearm HOOK=<path>` restores the guarded
hook block via adb; `/data/voboost`, the daemon, and agents persist, so nothing is
re-downloaded. The incremental app/agents OTA is independent of the system OTA
cadence. The init hook MUST configure the daemon service to be restarted on exit
(not `oneshot`), which the no-reboot core apply depends on.

### D8. Signing reuse
The release manifest is signed with the same key family as the daemon's trust
anchor: the private key lives only in CI secrets; the public key is committed
(`config/release-public.pem`) and (same family) embedded. The signing/publishing
pipeline (`make sign`/`make verify-sig`, the `ci` release workflow) is already
implemented. For beta1 the dev keypair doubles as the release keypair
(`config/release-public.pem` == `config/key-dev-public.pem`); rotate before a real
release.

### D9. Memory and DoS bounds
The release manifest is signed (a forged signer is out of scope), but a bounded
parser still defends against a pathologically large but legitimately signed
manifest and against truncated/giant downloads: the parser caps manifest size and
entry count (mirroring `PlanReader.MAX_PLAN_BYTES`); a downloaded file whose size
differs from the manifest `size` is rejected before hashing. The daemon also
stat-pre-checks the staged core binary against the trusted `size` before reading
it into memory. `size` is an advisory DoS guard; `sha256` is authoritative.

### D10. The update-ready marker is single-use
The `update-ready` marker is the producer's "a complete staged set is ready"
signal (created last), and the daemon treats it as single-use: it applies only
while the marker is present and removes it after any attempt (success or
verified-failure). This is load-bearing for the core plane: a successful core
apply ends in a self-shutdown + init restart, so if the marker (and the staged
files) were left in place, the restarted daemon would re-apply the same core on
every boot — an infinite crash-loop until init's restart budget exhausts.
Consuming the marker on success breaks the loop; consuming it on a
verified-failure drops a bad set instead of retrying it every boot (the producer
re-stages to retry). The contract that a present marker implies a complete set
makes dropping a verified-bad one safe.

## Risks / Trade-offs

- [Interrupted download/apply mid-update] → `update-ready` is the last atomic
  producer step and the daemon swap is atomic with `manifest.json.prev`/the
  core marker, so an interruption leaves the previous working set.
- [A bad `core` binary] → automatic rollback on a DEGRADED restart via the marker;
  a signed binary that crash-loops *before* VERIFY_SELF (unreachable in normal
  operation — CI host-tests gate the signed release) is recovered by a one-line
  adb repoint of the launch path.
- [Injection gap during a core restart] → identical to any daemon restart the
  system already handles (crash + init restart, kill-switch cycle): clean shutdown
  unloads agents, the relaunched daemon re-attaches and re-injects; spawns in the
  window are injected late via attach. No new failure mode.
- [Re-arm is an operator `adb` step] → tracked as an open question; OTA does not
  depend on automating it, only on the hook being restored.
- [Channel misclassification inflates downloads] → channels are advisory for
  cadence; correctness rests on per-file `sha256` diffing regardless of channel.

## Migration Plan

Implementation lands in this change's `tasks.md`. Sequencing: add the CI
`make release-manifest` generator (the `ci` release workflow already calls it),
implement the daemon-side apply/rollback that consumes `update-ready`, document
the app-side client contract, add `make device-rearm`, and the host-side tests.
Rollback is inherent: any failure keeps the current verified set;
`manifest.json.prev`/the core marker enable explicit reversion.

## Open Questions

- Hosting/transport for the release manifest and files (out of scope here;
  assumed an HTTPS origin).
- Whether the post-system-OTA re-arm can be made less manual than the host `adb`
  step.
