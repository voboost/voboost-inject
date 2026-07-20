# Design: make test uses frida's meson

## D1. The pickle incompatibility is real and version-bound

FACT: `make setup` writes `build/meson-private/coredata.dat` via frida-meson
1.4.99 (`/usr/bin/python3 subprojects/frida-core/releng/meson/meson.py`).

FACT: the host's system meson is 1.11.1 (`/opt/homebrew/bin/meson`).

FACT: `meson test` pickle-loads `build.dat`/`coredata.dat` via its own bundled
`mesonbuild.*` modules. frida-meson 1.4.99 and system meson 1.11.1 differ enough
that system meson raises `ModuleNotFoundError: mesonbuild.options` and refuses
the file. This is not a corrupt build dir — it is two different meson versions
disagreeing on the pickle schema.

This is a DEDUCTION from the recorded error, not a premise: a clean `rm -rf
build && make setup && make test` reproduces it deterministically.

## D2. Why `make build` was unaffected

`ninja -C build` (the `build` target) does not pickle-load `coredata.dat`; it
runs the already-generated `build.ninja`. Only meson *commands* (`setup`,
`test`, `compile`, `install`, `--reconfigure`) load the pickle. So `make build`
succeeded while `make test` failed — the bug was invisible until a meson
command other than `setup` was run against the build dir.

## D3. The fix: route `test` through the same meson that wrote the dir

`setup` and `build-android` already use `$(PYTHON_FOR_MESON) $(FRIDA_MESON)`.
Applying the same prefix to `test` makes the reader and writer the same meson,
so the pickle schema matches and `meson test` proceeds. Verified: all 9 host
unit tests pass.

## D4. Scope: not a general "pin meson" mandate

This change only fixes the `test` target and states the invariant for the
existing build-dir-reading targets (`setup`, `test`). It does NOT add a
wrapper for `compile`/`install`/`reconfigure` because no Makefile target
invokes them today; if one is added later, the invariant in the spec flags it
for the same treatment.

## D5. Rejected alternatives

- **`meson setup --reconfigure` with system meson:** would *re-write*
  `coredata.dat` with system-meson's schema, breaking the next `ninja` run
  (frida-core's `compat/build.py` then fails to load it). Swaps one failure for
  another.
- **Downgrade system meson to 1.4.99:** fragile, fights the package manager,
  and unnecessary — frida-meson is already provisioned by `make init`.
- **`pip install meson==1.4.99` into a venv:** extra toolchain surface for no
  gain over the already-pinned frida-meson.
