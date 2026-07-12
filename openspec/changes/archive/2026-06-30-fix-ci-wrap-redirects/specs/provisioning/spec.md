## MODIFIED Requirements

### Requirement: Subproject wraps are clean-clone bootstrappable

The wraps committed under `subprojects/` SHALL let `meson subprojects download`
and `meson setup` succeed on a clean clone with no manual pre-fetching. Only
top-level **direct**-dependency git wraps (for this project: `frida`,
`frida-core`, `frida-gum`, `monocypher`) and top-level **override** wraps that
carry a `patch_directory` or `diff_files` (for this project: `selinux`, and
`frida-core` itself which carries a `diff_files` patch) SHALL be committed; a
wrap SHALL NOT be a `[wrap-redirect]` whose target lives inside another,
not-yet-fetched subproject — transitive dependencies resolve from each
subproject's own bundled wraps during `meson setup`, and `meson subprojects
download` regenerates any needed `[wrap-redirect]` files itself. Any
`patch_directory` referenced by a wrap SHALL be committed under
`subprojects/packagefiles/<name>/` and SHALL be git-tracked (not excluded by
`subprojects/.gitignore`). A top-level `subprojects/<name>.wrap` SHALL take
precedence over the wrap of the same name inside a fetched subproject (e.g.
`frida-core/subprojects/`), so the project can override a transitive
subproject's wrap with one carrying a `patch_directory` or `diff_files` (e.g.
the committed `subprojects/selinux.wrap` overrides frida-core's selinux wrap
with a `patch_directory = selinux` that fixes libselinux's missing libsepol
dependency; `subprojects/frida-core.wrap` carries a `diff_files` patch for
bionic compat).

`subprojects/.gitignore` SHALL NOT re-allow (`!`) any `[wrap-redirect]` wrap
that points into a sibling subproject directory. The `.gitignore` SHALL
re-allow only the wraps the project authors and commits (the direct git wraps
and the override wraps above). This prevents transitive redirect wraps — which
`meson subprojects download` regenerates automatically — from being committed
and breaking the clean-clone bootstrap (meson resolves every redirect eagerly
before any download, so a redirect whose target is inside a not-yet-fetched
subproject aborts `meson subprojects download` on a clean clone).

#### Scenario: No redirect wraps into not-yet-fetched subprojects
- **WHEN** the committed `subprojects/*.wrap` files are enumerated
- **THEN** every committed wrap is a `[wrap-git]` direct dependency or override,
  and none is a `[wrap-redirect]` pointing into a sibling subproject directory

#### Scenario: .gitignore does not re-allow transitive redirect wraps
- **WHEN** `subprojects/.gitignore` is inspected
- **THEN** it re-allows (`!`) only the direct git wraps (`frida.wrap`,
  `frida-core.wrap`, `frida-gum.wrap`, `monocypher.wrap`) and the override wrap
  (`selinux.wrap`), and does NOT re-allow any transitive `[wrap-redirect]` wrap
  (`libgee.wrap`, `libnice.wrap`, `libpsl.wrap`, `libsoup.wrap`,
  `quickjs.wrap`, `tinycc.wrap`, `usrsctp.wrap`)

#### Scenario: Wrap patch sources are committed and tracked
- **WHEN** a wrap declares `patch_directory = <name>` or `diff_files = <patch>`
- **THEN** the patch directory/file exists under `subprojects/packagefiles/` and is returned by `git ls-files` (tracked, not gitignored)

#### Scenario: Top-level wrap overrides a transitive subproject's wrap
- **WHEN** a top-level `subprojects/<name>.wrap` and a `subprojects/frida-core/subprojects/<name>.wrap` both exist
- **THEN** meson resolves the top-level one (it searches the root `subprojects/` first), applying its `patch_directory`/`diff_files`

#### Scenario: Clean clone provisions wraps without error
- **WHEN** `make init` runs `meson subprojects download` on a clean clone
- **THEN** the command exits 0, fetching the top-level wraps and applying their committed patches, with no `wrap-redirect … does not exist` and no `patch directory does not exist` error
