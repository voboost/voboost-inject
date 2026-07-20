## Why

The daemon runs on a real target device (Voyah Free, arm64, Android 9 / API 28)
where **6 of the 8 target processes are 32-bit** (armv7), and only 2 are 64-bit
(`com.qinggan.app.launcher`, `system_server`). 13 of the 16 shipped agents are
routed at the 32-bit processes. The current build pins
`frida-core:compat=disabled`, which drops frida's 32-bit helper from the
binary, so the daemon could only inject into the 2 64-bit processes (3 agents).
A field install on the car confirmed the gap: the 32-bit targets reported
`state: failed` with the daemon log line
`Unable to handle 32-bit processes due to build configuration`. Enabling
frida's 32-bit compat is what makes the daemon inject into the processes the
device actually runs — it is the difference between "3 of 16 agents active" and
"all 16".

This is a build-time, not runtime, decision: frida-core's `compat` meson option
selects whether the bundled 32-bit helper (`frida-helper-32`) and the armv7
`frida-agent.so` are linked into the daemon ELF. There is no runtime knob for
this — the helper must be present in the binary at build time.

## What Changes

- **`meson.build`**: `frida-core:compat=disabled` → `frida-core:compat=auto`.
  `auto` enables the 32-bit helper when the target ABI requires it (the
  Android cross build is arm64, but the device runs mixed-ABI processes), so
  the daemon ELF embeds `frida-helper-32` and the armv7 `frida-agent.so`.
- **No runtime code change.** The `frida_controller.vala` injection path
  (`device.attach(pid)` / spawn-gating / `create_script`) is unchanged — frida
  picks the right ABI helper per target process automatically once the helper
  is present in the binary.
- **No trust/signing change.** Agent verification, `EMBEDDED_PUBKEY`, and the
  OTA contract are untouched — this change only affects which processes the
  daemon can reach.

## Capabilities

### New Capabilities
- `32bit-target-support`: the daemon SHALL be able to inject its agents into
  32-bit (armv7) target processes on a mixed-ABI device, not only into 64-bit
  (arm64) ones. Delivered by the `frida-core:compat=auto` build option, which
  embeds frida's 32-bit helper in the daemon ELF.

### Modified Capabilities
- `build-and-signing`: the frida-core subproject options pinning is updated —
  `compat` is no longer `disabled` but `auto`, so the 32-bit helper is built
  into the release daemon binary. The other pinned options (QuickJS-only, V8
  disabled, static, local backend only) are unchanged.

## Impact

- **Daemon binary size:** grows from ~16 MB to ~24 MB on the Android cross
  build — the armv7 `frida-helper-32` + armv7 `frida-agent.so` are now linked
  in. This is expected and accepted (the APK-size change is tracked under the
  voboost-app R8/shrink pipeline, which already strips what it can).
- **Daemon behaviour on device:** the 13 agents routed at 32-bit targets
  (e.g. `settings-menu` at `com.qinggan.app.vehiclesetting`,
  `pedestrian-warning` at `com.qinggan.systemservice`, keyboard/phone/media
  agents) now reach `state: active` instead of `state: failed` with
  `Unable to handle 32-bit processes`. Verified end-to-end on the car.
- **Host build / tests:** unaffected — the host build is x86_64 and the
  compat helper targets the Android cross build. Host `make build` / `make
  test` compile and pass as before.
- **CI / release:** the published `voboost-inject` device binary is larger;
  no release-manifest, signing, or OTA contract change.
