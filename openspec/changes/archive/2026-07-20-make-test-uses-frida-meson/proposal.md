## Why

`make setup` and `make build-android` already invoke frida's own meson
(`PYTHON_FOR_MESON` + `FRIDA_MESON`, the `frida/meson` commit pinned by the
fetched `frida-core`'s `releng/meson` submodule) instead of the system meson.
The Makefile documents exactly why (lines 115-119):

> frida-core's compat/build.py (run during ninja) imports frida-meson's
> `mesonbuild` and pickle-loads the coredata.dat written here — if system meson
> wrote it, the pickle is incompatible (ModuleNotFoundError: mesonbuild.options).

But the `test` target was overlooked: it still called the bare `meson`
(homebrew 1.11.1 on this host), while the build dir's `coredata.dat` /
`build.dat` was written by frida-meson 1.4.99. `meson test` therefore aborts:

```
ERROR: Build data file '.../build/meson-private/build.dat' references functions
or classes that don't exist. ... generated with an old version of meson.
```

`make build` works (ninja only needs the build dir, not a pickle load), so this
bug hid in plain sight until the `emulator-frida-page-size-fix` verification
task 3.2 ("`make build` and `make test` pass (host)") actually ran `make test`.

## What Changes

- **`Makefile` `test` target:** change `meson test -C $(BUILD_DIR)` to
  `$(PYTHON_FOR_MESON) $(FRIDA_MESON) test -C $(BUILD_DIR)`, matching the
  `setup` and `build-android` targets. The build dir is read with the same meson
  that wrote it, so `meson test` loads `coredata.dat` successfully.
- **Invariant:** every Makefile target that reads the meson build dir
  (`setup`, `test`, and any future `compile`/`install` wrapper) SHALL use
  frida-meson, not the system meson, for the same pickle-compatibility reason.

## Impact

- **Local dev / CI:** `make test` now passes (9/9 host unit tests) without the
  developer having to know to hand-invoke `$(FRIDA_MESON) test`.
- **No behaviour change** for `make setup`/`make build`/`make build-android`
  (they already used frida-meson).
- The fix is one Makefile recipe line plus a documenting comment; no source,
  spec invariant outside `build-and-signing`, or test changes.
