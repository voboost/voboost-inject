# Design: fix-ndk-path

## Root cause (verified)

`make build-android` (Makefile line 163-165) runs:

```makefile
python3 $(FRIDA_MESON) setup $(ANDROID_BUILD_DIR) \
  --cross-file config/android-cross.ini
ninja -C $(ANDROID_BUILD_DIR)
```

`config/android-cross.ini` names bare tool binaries
(`aarch64-linux-android28-clang`, `llvm-ar`, `llvm-strip`,
`llvm-readelf`) in `[binaries]`. These live in the NDK at
`$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/<host-tag>/bin`,
but nothing in the Makefile adds that directory to `PATH`.

The CI workflow `release.yml` has an explicit step (lines 82-87):

```yaml
- name: Put NDK toolchain on PATH
  run: |
    ndk="${{ steps.setup-ndk.outputs.ndk-path }}"
    echo "ANDROID_NDK_HOME=$ndk" >> "$GITHUB_ENV"
    echo "ANDROID_NDK_ROOT=$ndk" >> "$GITHUB_ENV"
    echo "$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin" \
      >> "$GITHUB_PATH"
```

The Makefile has no equivalent — the developer must manually
configure both `ANDROID_NDK_HOME` and `PATH`.

Verified on the local machine:
- NDK r29 (`29.0.14206865`) installed at
  `~/Library/Android/sdk/ndk/29.0.14206865`
- `aarch64-linux-android28-clang` exists at
  `.../toolchains/llvm/prebuilt/darwin-x86_64/bin/`
- `ANDROID_NDK_HOME` is not set; the bin is not on PATH
- `make build-android` fails with `No such file or directory`

## Fix

Combine both recipe lines into a single shell block that:

1. Guards `ANDROID_NDK_HOME` (clear error on unset).
2. Resolves the prebuilt bin via glob
   `$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/*/bin` — NDK
   installs contain exactly one host-tag directory per platform.
3. Exports `PATH` with the resolved bin prepended, then runs
   `meson setup` and `ninja` in the same shell (both need the
   compiler on PATH).

The glob approach matches what the README already uses
(line 355: `$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/*/bin/…`).

## Alternatives considered

- **Makefile-level `export PATH`** (like the existing
  `export PATH := $(TOOLS_DIR)/bin:$(PATH)` on line 6). Rejected:
  `ANDROID_NDK_HOME` may not be set at Makefile parse time, and
  the prebuilt host-tag detection requires a shell glob — cannot
  be done cleanly in a Makefile variable.
- **Require the developer to set PATH manually.** This is the
  status quo — rejected because it is undocumented, error-prone,
  and CI already automates it.
- **Add NDK PATH setup to `make init`.** Rejected: `make init`
  does not install the NDK (it is an external prerequisite), and
  `init` runs once while `ANDROID_NDK_HOME` may change between
  builds.

## Spec scope

Modifies the `build-and-signing` spec: the device build scenario
gains an explicit NDK PATH derivation requirement. No runtime
behavior change.
