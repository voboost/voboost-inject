## 1. Streaming inflate (release-manifest)

- [x] 1.1 Replace `ZlibDecompressor.convert` retry loop in `inflate_raw` with a
      streaming `GConverterInputStream` over a `MemoryInputStream`, reading in
      64 KiB chunks
- [x] 1.2 Bound the output buffer at the entry's `uncomp_size`; grow only on a
      zero/lying hint, still capped at `MAX_APK_BYTES`
- [x] 1.3 Verify the existing deflated-APK fixture test still passes
      (`test_apk_extract_binary_deflated`)

## 2. BootState extraction + host test (daemon-lifecycle)

- [x] 2.1 Extract the boot cache + `getprop` fork + `VOBOOST_BOOT_COMPLETED`
      escape hatch from `Supervisor` into a frida-free `BootState` class
      (`src/boot.vala`)
- [x] 2.2 Delegate `Supervisor.boot_completed()` to a `BootState` instance
- [x] 2.3 Wire `boot.vala` into `src/meson.build` (daemon) and
      `test/meson.build` (host test harness)
- [x] 2.4 Add `test/boot_test.vala` covering the env override, the monotonic
      cache, and the empty-env host path

## 3. Parent-dir fsync after status rename (app-interface)

- [x] 3.1 After `FileUtils.rename` in `Status.write_atomic`, open the parent
      dir with `O_RDONLY|O_DIRECTORY` and best-effort `fsync` it
- [x] 3.2 Verify the existing `status_test` still passes
