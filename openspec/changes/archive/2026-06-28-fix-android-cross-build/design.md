# Design: fix-android-cross-build

## Context

`make build-android` cross-compiles the daemon for Android arm64-v8a via the
NDK, configuring with frida's own meson fork (frida-gum's `quickcompile`
requires its QuickJS subproject built for the build machine). The host is
macOS (Apple clang 17, macOS 26.2 SDK libc++); the target is Android
(aarch64, bionic, NDK r29 / clang 21).

## Decisions

### D1. Disable `connectivity`, set global `default_library=static`
The daemon drives frida-core in-process over the local device (no socket, no
TLS, no ICE — see `frida_controller.vala`). `connectivity` (default `enabled`)
pulls `gioopenssl`/`glib-networking`/`nice`/`usrsctp`, all unused. Disabling it
removes the `gioopenssl` resolution failure entirely. Setting the global
`default_library=static` (not just `frida-core:default_library=static`) makes
every transitive subproject build a static archive, so the `-static`-style link
has no dynamic objects to reject AND glib-networking's `gioopenssl` override
runs (it's gated on `build_static = default_library != 'shared'`). Both are
needed: `connectivity=disabled` for correctness (no unused TLS), and global
`default_library=static` for the link.

### D2. `/usr/bin/python3` for frida-meson (distutils)
glib's gdbus-codegen imports `distutils.version.LooseVersion` (removed in
Python 3.12). Pinning `/usr/bin/python3` (macOS system python 3.9, ships
`distutils`) is the simplest fix — no Homebrew dependency, always present.
On Linux CI, `/usr/bin/python3` is 3.x; if it lacks `distutils`, install
`python3.11` and set `PYTHON_FOR_MESON`. Patching glib's codegen would require
a `patch_directory` on the transitive glib wrap (more invasive, and the
upstream fix is to drop distutils — not our concern).

### D3. Patch frida-core + selinux via wraps (not vendored forks)
The defects are in frida's own subprojects (frida-core, frida's selinux fork).
Vendoring full forks would diverge from frida's pinned revisions. meson's
`diff_files` (frida-core.wrap) and `patch_directory` (selinux.wrap) apply
minimal patches at checkout, keeping the pinned git revisions. A top-level
`subprojects/<name>.wrap` takes precedence over the one inside
`frida-core/subprojects/`.

### D4. `-Wl,-Bstatic -Wl,-Bdynamic` instead of `-static`
NDK r29 ships no static bionic (`libc.a`/`liblog.a` removed). `-static` fails
(`unable to find library -llog`). The frida/glib stack is already static via
`default_library=static`; only bionic system libs (`libc`, `liblog`, `libz`,
`libm`, `libdl`) need dynamic linking — they are always present on Android.
`-Wl,-Bstatic` + `-Wl,-Bdynamic` markers let the static archives link
statically while bionic links dynamically. The binary is self-contained for
the frida/glib stack (no glib/gio/json-glib on the device).

### D5. Explicit `--pkg=gio-2.0`/`--pkg=json-glib-1.0`
frida's meson fork does not auto-derive `--pkg` from `dependencies:` (upstream
meson does). frida-core itself passes `--pkg=gio-2.0` explicitly. We do the
same in `src/meson.build` and `test/meson.build`.

### D6. Skip tests in cross build
Tests are host-only (no test runner on the device, not part of the release
artifact). `meson.build` guards `subdir('test')` with `not meson.is_cross_build()`.

## Alternatives considered

- **Patch glib's codegen to drop distutils**: more invasive (transitive wrap
  patch), and the fix is upstream's responsibility. Rejected for D2.
- **Pin Homebrew python@3.11**: fragile (brew cleanup removed it during
  `make init`); `/usr/bin/python3` is always present. Rejected for D2.
- **Keep `-static`, add static bionic stubs**: NDK r29 has no static bionic;
  building stubs is out of scope. Rejected for D4.
- **Enable `connectivity` + fix gioopenssl via global `default_library=static`**:
  would build unused TLS/ICE (glib-networking, nice, usrsctp, openssl).
  Rejected — `connectivity=disabled` is correct for a local-backend daemon.

## Risks

- The frida-core/selinux patches are pinned to frida-core 17.11.0 / the selinux
  wrap revision; a frida-core wrap bump may require re-basing the patches.
- `/usr/bin/python3` on a future macOS could drop distutils (unlikely before
  the OS removes python 3.9); `PYTHON_FOR_MESON` is overridable.
