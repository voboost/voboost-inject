# Design: fix-provisioning-wraps

## Root cause (verified)

Meson 1.11 loads the whole wrap set eagerly while constructing `Resolver`:
`Resolver.__post_init__` → `load_wraps()` walks `subprojects/*.wrap` and calls
`PackageDefinition.from_wrap_file` on each. For a `[wrap-redirect]`, that reads
the target file immediately and raises `wrap-redirect <target> filename does not
exist` if it is absent (`mesonbuild/wrap/wrap.py`). The same eager load runs for
both `meson subprojects download` (`msubprojects.run` builds the `Resolver` before
filtering by name) and `meson setup` (`interpreter.py` builds `wrap_resolver` for
the root project). So neither command can bootstrap a clean clone while a redirect
points into a not-yet-fetched subproject.

## Why the redirects are redundant

Frida subprojects bundle their own dependency wraps:
`frida-core/subprojects/{usrsctp,libgee,libnice,...}.wrap`,
`frida-gum/subprojects/{libsoup,quickjs,tinycc,...}.wrap`,
`libsoup/subprojects/libpsl.wrap` (confirmed at the pinned revisions). When meson
processes a subproject it merges that subproject's wraps via `load_and_merge`
(`interpreter.py`), so the transitive deps resolve and fetch from the bundled
wraps without any top-level redirect. Twelve other frida-gum deps (`capstone`,
`glib`, `openssl`, …) already work this way and never had top-level redirects.
Removing the seven redirects makes `usrsctp`/`libsoup`/etc. behave identically.

End state is unchanged: nested deps still land in `subprojects/<name>/` at the
same pinned revisions; only the fetch moment moves from `meson subprojects
download` to `meson setup`. `make init` runs both, and the frida-patched `valac`
build between them needs only `frida-core`, which is a top-level git wrap fetched
by `meson subprojects download`.

## monocypher patch

Upstream `LoupVaillant/Monocypher@4.0.2` ships no `meson.build` (404 on the raw
URL; absent from the tree). The wrap's `patch_directory = monocypher` must supply
one that declares `monocypher_dep` (matched by the wrap's
`[provide] monocypher = monocypher_dep`). The patch is a single
`packagefiles/monocypher/meson.build` (static lib from `src/monocypher.c` +
`src/optional/monocypher-ed25519.c`).

## gitignore

`subprojects/.gitignore` uses `*/` + `!packagefiles/`. The negation re-includes
only the `packagefiles/` directory itself, not its contents (the `*/` rule keeps
re-matching nested paths), so files under `packagefiles/monocypher/` stay ignored.
Verified in an isolated repo: adding `!packagefiles/**` makes
`packagefiles/monocypher/meson.build` tracked while `frida/` etc. stay ignored.

## Alternatives considered

- **Keep redirects, pre-fetch the chain in the Makefile.** Would need
  `frida-core` + `frida-gum` + `libsoup` cloned before `meson subprojects
  download` (libsoup is itself a redirect target for `libpsl`), duplicating wrap
  URL/revision metadata and parsing a nested wrap. Rejected: fragile, violates
  single-source-of-truth.
- **Drop `meson subprojects download`, rely only on `meson setup`.** Rejected: the
  frida-patched `valac` build sits between the two and needs `frida-core` present,
  and `meson setup` hits the same eager-load failure while redirects exist.

## Android cross-build (Group B)

The Android cross-build fails past the clean-clone wraps fix. Three causes, each
verified by re-running `meson setup` (frida-core's `releng` + `releng/meson`
submodules initialized for diagnosis):

1. **subsystem.** `frida-core/meson.build:~78` does
   `tokens = host_machine.subsystem().split('-')` and gates Android on
   `host_os == 'android'` (lines ~322, ~467). For a cross machine, meson reads
   `subsystem` only from the cross-file (`envconfig.py` `from_literal`), so the
   absent key raises `Subsystem not defined or could not be autodetected`. frida's
   own `releng/env.py` writes `("subsystem", …)` into its generated machine file —
   confirming `subsystem = 'android'` is the intended value. Verified: an isolated
   3-line meson project with `subsystem = 'android'` prints
   `host_machine.subsystem() == 'android'`.

2. **frida-meson (native subproject deps).** `frida-gum/meson.build:652` does
   `dependency('quickjs', native: true)` for `quickcompile` (a `native: true`
   build tool that precompiles QuickJS bytecode, `bindings/gumjs/meson.build`).
   Standard meson 1.11.1 executes the quickjs subproject once (host) and does not
   re-invoke it for the build machine, so the native override is missing
   (`did not override … no variable name specified`). frida's own meson fork
   (`releng/.gitmodules` → `github.com/frida/meson.git`, v1.4.99, default
   `meson="internal"` in `meson_configure.py:135`) does:
   `Executing subproject quickjs for machine: build` → resolves. Verified by
   running setup with `releng/meson/meson.py` instead of system meson. This is
   independent of the wrap redirects (confirmed by direct comparison) and of
   `--native-file` (adding it did not help). Note: this corrects an earlier
   over-broad dismissal — frida-meson is NOT needed for `subsystem()` (standard
   meson has it) but IS needed for native subproject deps.

3. **readelf.** `frida-core/meson.build:~493` does `find_program('readelf')` for
   non-darwin `host_os_family` (Android → `linux`). macOS has no `readelf`;
   `llvm-readelf` ships in the NDK prebuilt bin already on PATH for the
   cross-compiler. `readelf = 'llvm-readelf'` in `[binaries]` resolves it on both
   macOS (local) and linux (CI — release.yml puts the NDK bin on PATH).

With all three, `meson setup` (via frida-meson) configures 195 targets, exit 0.
The remaining acceptance step is a full `ninja` compile of the device binary.

## Compile-phase findings (Group B, ninja)

Two further blockers surface after setup, both frida-internal to the embedded-agent
build (`frida-core/compat/build.py`, which builds `frida-agent-arm64.so` for
`assets=embedded` — the agent the daemon injects):

- **tomlkit.** `compat/build.py` imports `releng`; `releng/deps.py:31` does
  `sys.path.insert(0, RELENG_DIR / "tomlkit")` before `from tomlkit.toml_file …`
  (line 33). This resolves only if the `releng/tomlkit` submodule is checked out.
  `make init` uses `git -C subprojects/frida-core submodule update --init
  --recursive releng`, which pulls releng's meson AND tomlkit (and nested) —
  verified: with it the tomlkit step passes; without it,
  `ModuleNotFoundError: No module named 'tomlkit'`.
- **NDK r29.** `releng/env_android.py:176 NDK_REQUIRED = 29`; line 40 raises
  `NdkVersionError` unless the NDK major version is exactly 29. frida-core 17.11.0
  requires r29. The local env had r27 and release.yml pinned r27d — both rejected.
  CI pin fixed to `ndk-version: r29`; locally, r29 must be installed for the build
  to complete (a tooling requirement, not a code change).

## Spec scope

Group A restores conformance to the existing `provisioning` "Fresh clone is
provisioned" scenario and adds a wrap-hygiene invariant. Group B adds
`provisioning` (provision frida-meson) and `build-and-signing` (cross-build
toolchain) requirements; it changes the build-tool invocation, not daemon
runtime behavior.
