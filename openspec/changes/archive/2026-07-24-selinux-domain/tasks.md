## 1. Domain and exec type

- [ ] 1.1 `selinux/voboost-inject.te` — declare the `voboost-inject` domain and
      `voboost-inject_exec` type; enter via `init_daemon_domain`
- [ ] 1.2 `file_contexts` — label the daemon binary `voboost-inject_exec`

## 2. Ptrace and /proc access

- [ ] 2.1 `allow voboost-inject <target_domains>:process ptrace;` covering every
      manifest target domain (app + system/native)
- [ ] 2.2 Allow reading target `/proc/<pid>/maps`, `/proc/<pid>/cmdline`,
      `/proc/<pid>/exe`

## 3. Zone and shared-dir labels

- [ ] 3.1 Allow the `voboost-inject` domain read/write to `/data/voboost-inject`
      (root zone)
- [ ] 3.2 `file_contexts` — label `/data/voboost-inject/shared/` as
      `media_rw_data_file` (no runtime `chcon`)

## 4. Validate

- [ ] 4.1 `npx @fission-ai/openspec validate selinux-domain --strict`
- [ ] 4.2 Enforcing-hardware validation: inject a target, confirm no ptrace/proc
      AVC denials; confirm app and injected process exchange channel-B files
      without extra allow (Permissive emulator does NOT count as proof)
