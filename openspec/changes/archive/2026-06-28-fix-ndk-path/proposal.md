## Why

`make build-android` fails from a clean `make init` + `make setup` with:

```
Unknown compiler(s): [['aarch64-linux-android28-clang']]
Running `aarch64-linux-android28-clang --version` gave
  "[Errno 2] No such file or directory"
```

The NDK toolchain binaries (`aarch64-linux-android28-clang`,
`llvm-ar`, `llvm-strip`, `llvm-readelf`) live in
`$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/<host-tag>/bin`,
but `make build-android` does not add that directory to PATH.
The developer must know to do it manually — nothing in the
Makefile, `make init`, or `make check` helps.

CI works because `release.yml` has an explicit "Put NDK toolchain
on PATH" step (lines 82-87) that adds the bin directory to
`$GITHUB_PATH` and sets `ANDROID_NDK_HOME`/`ROOT`. The local
Makefile has no equivalent.

## What Changes

`make build-android` SHALL derive the NDK toolchain PATH from
`ANDROID_NDK_HOME` automatically:

1. **Guard:** fail early with a clear message if
   `ANDROID_NDK_HOME` is not set.
2. **Derive PATH:** resolve the prebuilt bin directory via the
   glob `$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/*/bin`
   (there is exactly one `<host-tag>` directory per NDK install:
   `darwin-x86_64` on macOS, `linux-x86_64` on Linux); fail if
   not found.
3. **Export:** prepend the resolved bin to `PATH` for both the
   `meson setup` and `ninja` invocations within the recipe.

The developer only needs to set `ANDROID_NDK_HOME`; the rest
is automatic — matching what CI does.

## Capabilities

### Modified Capabilities
- `build-and-signing`: `make build-android` SHALL auto-derive
  the NDK toolchain PATH from `ANDROID_NDK_HOME`, removing the
  undocumented manual PATH requirement.

### New Capabilities
None.

## Impact

- **This repo**: `make build-android` works with only
  `ANDROID_NDK_HOME` set (no manual PATH). Existing behavior
  where the developer also sets PATH manually still works (the
  glob finds the same bin directory).
- **Build/CI**: no CI change needed — the CI already sets both
  `ANDROID_NDK_HOME` and PATH; the new guard and PATH derivation
  are no-ops when both are already correct.
- **Dependencies**: none.
