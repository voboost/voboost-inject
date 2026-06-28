## Why

`make build-android` (after `make init` + `make setup`) fails to produce the
device binary on macOS. Peeling the onion, eight independent defects block the
arm64-v8a cross-build; each was verified by re-running setup/ninja after the fix.

### A. `gioopenssl` dependency not found (meson setup)
frida-core's `connectivity` feature (default `enabled`) requires the
`gioopenssl` TLS provider. frida-core's `dependency('gioopenssl', ...)`
omits `default_library=static` from its `default_options`, so glib-networking
inherits the global `default_library` (default `shared`). glib-networking only
declares/overrides the `gioopenssl` dependency inside its `if build_static:`
branch (`build_static = default_library != 'shared'`), so with `shared` the
override never runs and meson errors `Dependency 'gioopenssl' is required but
not found`. The daemon is local-backend-only (no TLS/ICE), so `connectivity`
is unnecessary.

### B. glib's `gdbus-codegen` needs `distutils` (removed in Python 3.12)
glib's `gdbus-2.0/codegen/utils.py` imports `distutils.version.LooseVersion`.
`distutils` was removed in Python 3.12 (PEP 0632). Homebrew's `python3`
(3.12+/3.14) has no `distutils`, so the build-machine gdbus-codegen step fails
with `ModuleNotFoundError: No module named 'distutils'`. macOS system
`/usr/bin/python3` (3.9) still ships `distutils`.

### C. selinux `libselinux` cannot find `sepol/sepol.h` (ninja)
frida's selinux fork builds `libselinux` before `libsepol` and with no
`libsepol` dependency, but `libselinux/src/load_policy.c` includes
`<sepol/sepol.h>`. On Android (`host_os == 'android'`) libselinux is built
unconditionally (SELinux label handling for the local backend), so the include
is not found.

### D. frida-core `libc-shim.c` `sizeof(FILE)` on bionic (ninja)
`FRIDA_STDIO_OPAQUE_FILE` is gated on `HAVE_MUSL` only, but bionic (Android)
also has an opaque/incomplete `FILE` (`struct __sFILE` is a forward declaration
in the NDK's `stdio.h`). `sizeof(FILE)` in `frida_file_wrap`/`frida_file_set_handle`
fails to compile. Additionally, bionic declares `stdin`/`stdout`/`stderr` as
non-const `extern FILE *`, while the opaque branch declares them `FILE * const`.

### E. frida-core `modulate.py` asserts on static init/fini entries (ninja)
`modulate.py`'s `_read_function_pointer_section`/`_write_function_pointer_vector`
`assert len(pending) == 0` after processing `.rela.dyn` relocations. NDK r29 /
clang 21 emits init/fini array entries that are statically resolved at link time
(no relocation), so `pending` is never emptied and the assertion fails.

### F. frida-meson `_LIBCPP_ENABLE_ASSERTIONS` removed in macOS 26.2 SDK (ninja)
frida-meson's `ClangCPPCompiler.get_assert_args` emits
`-D_LIBCPP_ENABLE_ASSERTIONS=1` for clang 15-17. This macro was removed in
libc++ (LLVM 18+ / the macOS 26.2 SDK), so the build-machine C++ compile of
`termux-elf-cleaner` fails with `_LIBCPP_ENABLE_ASSERTIONS has been removed`.

### G. frida-core agent `emutls` `realloc` hidden (ninja link)
NDK r29's clang-21 compiler-rt `libclang_rt.builtins` (emutls, auto-linked for
TLS) references `realloc`. The agent's version script
(`frida-agent-android.version`) has `local: *;` which, with `-Wl,-Bsymbolic`,
hides the `realloc` reference → `undefined hidden symbol: realloc`.

### H. `-static` link rejects bionic shared libs (ninja link)
`inject_link_args = ['-static']` forces a fully-static link, but NDK r29 ships
no static bionic (`libc.a`/`liblog.a`/etc. were removed) → `unable to find
library -llog`. The frida/glib stack is already statically linked via
`default_library=static`; only bionic system libs need dynamic linking (they
are always present on Android).

### I. frida-meson does not auto-derive `--pkg` from `dependencies:` (ninja)
frida's meson fork does not convert `dependencies:` to `--pkg=` vala flags the
way upstream meson does, so `gio-2.0`/`json-glib-1.0` VAPIs (referenced by
`frida-core-1.0.vapi` and our sources: `GLib.Cancellable`, `Json.Object`) are
not found. frida-core itself works around this by passing `--pkg=gio-2.0`
explicitly.

### J. `make build` (host) fails on frida-core `compat/build.py` (ninja)
`make setup` used the system meson (Homebrew), which writes `coredata.dat`.
frida-core's `compat/build.py` (run during ninja to build the macOS universal
agent `arch-support.bundle`) imports frida-meson's `mesonbuild` and
`pickle.load`s the `coredata.dat` — but it was written by a different meson
version → `ModuleNotFoundError: No module named 'mesonbuild.options'`. The fix:
`make setup` SHALL configure via frida-meson (the same meson `compat/build.py`
imports), so the `coredata.dat` is written and read by the same meson.

## What Changes

- **A.** `meson.build`: set the global `default_library=static` (so every
  transitive subproject builds a static archive and glib-networking's
  `gioopenssl` override runs), and pass `-Dfrida-core:connectivity=disabled`
  in `make build-android` (the daemon is local-backend-only; no TLS/ICE).
- **B.** `Makefile`: launch frida-meson via `PYTHON_FOR_MESON` (default
  `/usr/bin/python3`, which ships `distutils`).
- **C.** `subprojects/selinux.wrap` (new, overrides frida-core's): same
  `frida/selinux` source + a `patch_directory` that reorders `subdir('libsepol')`
  before `subdir('libselinux')` and adds `libsepol_dep` to libselinux.
- **D, E, G.** `subprojects/frida-core.wrap`: add a `diff_files` patch
  (`frida-core-libc-shim-opaque-file-bionic.patch`) covering `libc-shim.c`
  (opaque FILE + non-const stdio for bionic), `modulate.py` (relax the static-
  reloc assertion), `lib/agent/meson.build` (`-Wl,-u` for emutls allocator
  symbols), and `lib/agent/frida-agent-android.version` (export allocators).
- **F.** `Makefile` `init`: after checking out the releng submodule, apply
  `subprojects/packagefiles/frida-meson-libcpp-hardening-mode.patch` to
  frida-meson's `cpp.py` (use `_LIBCPP_HARDENING_MODE` for clang >= 15).
- **H.** `src/meson.build`: replace `-static` with `-Wl,-Bstatic -Wl,-Bdynamic`
  (static archives link statically; bionic system libs link dynamically).
- **I.** `src/meson.build` + `test/meson.build`: explicitly pass
  `--pkg=gio-2.0` and `--pkg=json-glib-1.0` in `vala_args`.
- `meson.build`: skip `subdir('test')` in a cross build (tests are host-only).
- **J.** `Makefile` `setup`: configure via frida-meson (`PYTHON_FOR_MESON` +
  `FRIDA_MESON`), not the system meson, so the `coredata.dat` is written by
  the same meson frida-core's `compat/build.py` imports (host build fix).

## Capabilities

### Modified Capabilities
- `build-and-signing`: `make build-android` produces the arm64-v8a device binary
  on macOS (and Linux CI) from a clean `make init`. The daemon links the frida/
  glib stack statically and bionic dynamically; `connectivity` (TLS/ICE) is
  disabled (local-backend-only). The build uses a Python that ships `distutils`
  and applies compatibility patches to frida-core and frida-meson for NDK r29 /
  macOS 26.2 SDK.
- `provisioning`: `make init` applies the frida-meson libc++ hardening patch
  after checking out the releng submodule; `subprojects/selinux.wrap` and the
  `frida-core.wrap` `diff_files` patch are committed under `packagefiles/`.

### New Capabilities
None.

## Impact

- **This repo**: `make build-android` works end-to-end on macOS with NDK r29
  (verified: 2011/2011 targets, `build-android/src/voboost-inject` ELF 64-bit
  ARM aarch64, 15 MB). No source/runtime behavior change; same pinned revisions.
- **Build/CI**: CI must use a Python with `distutils` (the release workflow's
  `ubuntu-latest` ships python 3.12 without it — install `python3.11` or use
  `/usr/bin/python3` where available). The frida-core/selinux patches are
  applied automatically by meson via the wraps; the frida-meson patch is applied
  by `make init`.
- **Dependencies**: adds committed patch files under `subprojects/packagefiles/`
  (frida-core, frida-meson, selinux); no runtime dependency change.
