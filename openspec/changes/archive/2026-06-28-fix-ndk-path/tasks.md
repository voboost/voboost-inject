# Tasks: fix-ndk-path

## A. Makefile fix

- [ ] 1. `Makefile`: update `build-android` target — guard
      `ANDROID_NDK_HOME`, derive toolchain PATH via glob,
      export for both `meson setup` and `ninja`.
- [ ] 2. Verify `make build-android` without `ANDROID_NDK_HOME`
      fails with the expected message.
- [ ] 3. Verify `make build-android` with `ANDROID_NDK_HOME` set
      resolves the compiler and starts `meson setup`.
- [ ] 4. `make lint-fix` passes.

## B. Docs

- [ ] 5. Update README if the "NDK toolchain binaries on PATH"
      requirement text needs adjustment (currently line 465-466).

## C. Wrap-up

- [ ] 6. Validate the change:
      `npx @fission-ai/openspec validate fix-ndk-path --strict`.
- [ ] 7. Archive once approved.
