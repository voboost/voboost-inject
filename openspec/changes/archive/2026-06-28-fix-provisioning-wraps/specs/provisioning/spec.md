## ADDED Requirements

### Requirement: Subproject wraps are clean-clone bootstrappable
The wraps committed under `subprojects/` SHALL let `meson subprojects download` and
`meson setup` succeed on a clean clone with no manual pre-fetching. Only top-level
**direct**-dependency git wraps (for this project: `frida`, `frida-core`,
`frida-gum`, `monocypher`) SHALL be committed; a wrap SHALL NOT be a
`[wrap-redirect]` whose target lives inside another, not-yet-fetched subproject —
transitive dependencies resolve from each subproject's own bundled wraps during
`meson setup`. Any `patch_directory` referenced by a wrap SHALL be committed under
`subprojects/packagefiles/<name>/` and SHALL be git-tracked (not excluded by
`subprojects/.gitignore`).

#### Scenario: No redirect wraps into not-yet-fetched subprojects
- **WHEN** the committed `subprojects/*.wrap` files are enumerated
- **THEN** every committed wrap is a `[wrap-git]` direct dependency, and none is a `[wrap-redirect]` pointing into a sibling subproject directory

#### Scenario: Wrap patch sources are committed and tracked
- **WHEN** a wrap declares `patch_directory = <name>`
- **THEN** the patch directory exists under `subprojects/packagefiles/<name>/` and is returned by `git ls-files` (tracked, not gitignored)

#### Scenario: Clean clone provisions wraps without error
- **WHEN** `make init` runs `meson subprojects download` on a clean clone
- **THEN** the command exits 0, fetching the top-level wraps and applying their committed patches, with no `wrap-redirect … does not exist` and no `patch directory does not exist` error

### Requirement: make init provisions frida's meson for cross-builds
`make init` SHALL provision frida's meson (the `frida/meson` commit pinned by the
fetched `frida-core`'s `releng/meson` submodule), alongside the frida-patched
valac, because the Android cross-build (frida-gum's `quickcompile` `native: true`
tool) requires a `[provide]` subproject to be built for the build machine — only
frida's meson does this; standard meson does not. The provisioned frida-meson SHALL
be the meson used by `make build-android`.

#### Scenario: frida-meson is provisioned alongside frida-valac
- **WHEN** `make init` completes on a clean clone
- **THEN** frida's meson is available at the pinned `frida/meson` commit, and
  `make build-android` resolves and uses it instead of the system meson
