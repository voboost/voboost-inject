## 1. Channel-B shared directory

- [ ] 1.1 `control_plane.rs` — write/read files under
      `/data/voboost-inject/shared/` (label owned by `selinux-domain`); no socket

## 2. Config delivery and live-update

- [ ] 2.1 On injection, write the per-process config file and pass its path to
      `implant_init`
- [ ] 2.2 Live-update: write temp + `rename` over the config path (atomic, zero
      partial reads)
- [ ] 2.3 Agent-runtime side (voboost-script): `inotify` on the config file,
      filtered by filename, coalesced to one config-changed action

## 3. Teardown

- [ ] 3.1 A channel-B plan listing no agents for a process triggers the agent
      runtime's own teardown; the daemon performs no out-of-band unload

## 4. Status aggregation

- [ ] 4.1 Read each `<pkg>-agent-status.json` from the shared dir; aggregate into
      channel-A `inject-status.json`
- [ ] 4.2 Determine target liveness from `/proc/<pid>`, overriding a stale status
      file

## 5. Validate

- [ ] 5.1 `npx @fission-ai/openspec validate update-planes --strict`
- [ ] 5.2 Device test: config live-update applies without re-injection; a
      no-agents plan tears an injection down; status aggregation reflects `/proc`
      liveness
