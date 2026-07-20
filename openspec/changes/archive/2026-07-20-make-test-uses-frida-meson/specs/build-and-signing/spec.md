## ADDED Requirements

### Requirement: All meson build-dir commands in the Makefile use frida's meson

Every `make` target that runs a meson command over the build dir SHALL invoke frida's own meson.

This covers `setup`, `test`, and any future `compile`/`install`/`reconfigure`
wrapper — every meson command that pickle-loads the build dir. They SHALL use
`$(PYTHON_FOR_MESON) $(FRIDA_MESON)`, the same fork that `setup` used to write
`build/meson-private/coredata.dat`. The system meson (a different version)
SHALL NOT be used for any such target, because it cannot load the pickle
frida-meson wrote (`ModuleNotFoundError: mesonbuild.options` / "generated with
an old version of meson"). The `build` target (`ninja -C build`) is exempt: it
runs the generated `build.ninja` and does not load the pickle. In particular,
`make test` SHALL run `$(PYTHON_FOR_MESON) $(FRIDA_MESON) test -C $(BUILD_DIR)`
rather than bare `meson test`.

#### Scenario: make test loads the frida-meson build dir
- **WHEN** `make test` runs after `make setup`
- **THEN** it invokes frida's meson (the same `$(FRIDA_MESON)` that wrote
  `coredata.dat`), loads the build dir without a pickle-version error, and
  runs the host unit tests

#### Scenario: make test no longer uses the system meson
- **WHEN** the `test` recipe in `Makefile` is examined
- **THEN** it is `$(PYTHON_FOR_MESON) $(FRIDA_MESON) test -C $(BUILD_DIR)`,
  not a bare `meson test -C $(BUILD_DIR)`

#### Scenario: build target is unaffected
- **WHEN** `make build` runs
- **THEN** it runs `ninja -C $(BUILD_DIR)` (no meson pickle load) and is
  unchanged by this requirement
