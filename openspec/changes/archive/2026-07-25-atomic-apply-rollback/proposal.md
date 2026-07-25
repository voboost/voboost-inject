## Why

The `atomic-apply-rollback` spec describes the atomic manifest swap and the
inject core update via content-addressed install. Two references need updating:
the zone path `/data/voboost` → `/data/voboost-inject` (see `provisioning`,
`daemon-lifecycle`), and the inject core update now swaps the payload files
alongside the ELF (see `ota`). The atomic-swap, rollback, and boot-recovery
mechanisms are unchanged; the references to the release-manifest re-verify are
already payload-aware ("daemon-re-verified release manifest") and just need the
path and the payload-swap noted.

## What Changes

- **MODIFIED**:
  - "Core update via content-addressed install and init restart" — the stable
    launch path is `/data/voboost-inject/voboost-inject`; the update also
    swaps the per-ABI payload files atomically alongside the ELF repoint.
  - "Core rollback on a degraded restart" — the rollback repoints the launch
    path (path updated) and restores the previous payload.
- **Unchanged**: "Content-addressed agent file paths", "Atomic agent-set swap
  with rollback", "Boot recovery after interrupted agent apply", "Apply staged
  agent updates before the first injection", "Consume the update-ready marker
  after apply", "Never end up broken".

## Capabilities

### Modified Capabilities

- `atomic-apply-rollback`: the inject core update path is updated to
  `/data/voboost-inject`, and the atomic install/rollback swaps the payload
  files alongside the ELF. The agent-set swap, boot recovery, and marker
  semantics are unchanged.
