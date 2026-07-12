# Tasks: fix-ci-wrap-redirects

## A. Remove committed redirect wraps

- [x] 1. `git rm` the seven `[wrap-redirect]` wraps: `subprojects/{libgee,
      libnice,libpsl,libsoup,quickjs,tinycc,usrsctp}.wrap`.
- [x] 2. Confirm `git ls-files subprojects/*.wrap` lists only `frida.wrap`,
      `frida-core.wrap`, `frida-gum.wrap`, `monocypher.wrap`, `selinux.wrap`.

## B. Fix .gitignore

- [x] 3. In `subprojects/.gitignore`, remove the `!` re-allow lines for the
      seven redirect wraps (`!libgee.wrap`, `!libnice.wrap`, `!libpsl.wrap`,
      `!libsoup.wrap`, `!quickjs.wrap`, `!tinycc.wrap`, `!usrsctp.wrap`).
      Keep `!frida-core.wrap`, `!frida-gum.wrap`, `!frida.wrap`,
      `!monocypher.wrap`, `!selinux.wrap`.

## C. Verify

- [x] 4. Simulated a clean clone: removed all fetched subprojects and generated
      redirect wraps, ran `meson subprojects download` — exit 0, all 5 wraps
      fetched, frida-core patch applied, no `wrap-redirect … does not exist`.
- [x] 5. `make lint-fix` and `make check` pass.

## D. OpenSpec

- [x] 6. `npx @fission-ai/openspec validate fix-ci-wrap-redirects --strict`.
- [x] 7. Archived (synced the `provisioning` delta into `openspec/specs/`,
      renamed to `openspec/changes/archive/2026-06-30-fix-ci-wrap-redirects/`).
