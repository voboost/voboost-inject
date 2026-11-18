# Add bounded Launcher resource owners

## Why

Setting-only delivery cannot prove Launcher resources through a Setting Context. Independent target owners need separate endpoint-bound variant selection and complete removal.

## What Changes

- Admit exactly Setting and Launcher owners, with two declared variants per owner.
- Separate owner probe sessions and process configuration; publish Setting translation admission only when every declared resource owner has actual readback.
- Preserve one all-owned removal barrier, native helper and resource reboot across up to four profiles.

## Impact

Shared owned-overlay lifecycle, daemon probe workers/events/process projections and their host tests. No SELinux, init, signing or QNX transaction change.
