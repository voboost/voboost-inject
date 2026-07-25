## Why

The `system-ota-survival` spec references the old zone path `/data/voboost` and
the stable launch path `/data/voboost/voboost-inject`. The zone moved to
`/data/voboost-inject` (see `daemon-lifecycle`, `provisioning`); the stable
launch path is now `/data/voboost-inject/voboost-inject`. The survival
semantics are unchanged (a system OTA reverts `/system` but leaves `/data`
intact); only the paths must track the rename so the spec is not
self-contradictory with the rest of the Wave 2 changes.

## What Changes

- **MODIFIED**:
  - "Persistence across a system OTA" — the surviving zone path is
    `/data/voboost-inject` (not `/data/voboost`); the daemon, the payload, and
    the agents all live there.
  - "Init hook restarts the daemon on exit" — the stable launch path is
    `/data/voboost-inject/voboost-inject`.
  - "Init-hook re-arm (operator-invoked)" — `make device-rearm` restores the
    launch of `/data/voboost-inject/voboost-inject`.
- **Unchanged**: "Independence from system OTA cadence".

## Capabilities

### Modified Capabilities

- `system-ota-survival`: the surviving zone path and stable launch path are
  updated from `/data/voboost` to `/data/voboost-inject`. Survival semantics,
  restart-on-exit, and re-arm are otherwise unchanged.
