## Context

The daemon runs as root on a real head-unit (Voyah Free, Android 9 / API 28,
arm64-v8a kernel) that runs a **mixed** set of process ABIs: the launcher and
`system_server` are 64-bit, but the system services, vehicle settings, IME,
bluetooth phone, media, and keymanager are 32-bit (armv7). Frida injects a
per-ABI agent into the target process; to inject into a 32-bit process from a
64-bit daemon, frida-core needs its 32-bit helper (`frida-helper-32`) and the
armv7 `frida-agent.so` present in (or reachable from) the daemon binary. Today
the build pins `frida-core:compat=disabled`, which drops the 32-bit helper — so
the daemon could only reach the 2 64-bit processes (3 agents) and failed on the
13 agents routed at 32-bit processes with
`Unable to handle 32-bit processes due to build configuration`.

Measured platform fact — process ABI on the target device (from the car
snapshot, `CURRENT.md`):

| Process | ABI | Agents routed here |
|---|---|---|
| `com.qinggan.app.launcher` | 64-bit | app-launcher, launcher-allapps, media-source, navbar-launcher, weather-widget |
| `system_server` | 64-bit | app-viewport |
| `com.qinggan.systemservice` | **32-bit** | app-multi-display, forced-ev, pedestrian-warning |
| `com.qinggan.app.vehiclesetting` | **32-bit** | adas-activation, settings-menu |
| `com.qinggan.app.qgime` | **32-bit** | keyboard-lock-en, keyboard-ru |
| `com.qinggan.bluetoothphone` | **32-bit** | phone-num |
| `com.qinggan.media` | **32-bit** | media-window |
| `com.qinggan.keymanager.service` | **32-bit** | media-key |

13 of the 16 agents are on 32-bit processes. Without this change the daemon can
deliver only 3 agents; with it, all 16.

## Goals / Non-Goals

**Goals:**
- The daemon binary, as built by `make build-android`, can inject into 32-bit
  (armv7) target processes on a mixed-ABI device, not only into 64-bit ones.
- The fix is a single build-option flip with no runtime/trust/OTA contract
  change.

**Non-Goals:**
- Changing which agents target which process (the agent→process routing lives
  in the signed manifest, owned by the build-and-signing / manifest pipeline).
- Reducing the binary-size cost of the 32-bit helper (accepted ~8 MB growth;
  APK-size mitigation lives in the voboost-app R8/shrink pipeline).
- Adding a runtime ABI knob — the helper is build-time only.

## Decisions

### D1. `compat=auto`, not `compat=enabled`
frida-core's `compat` meson option has three states: `disabled` (no 32-bit
helper), `auto` (build the helper if the target setup needs it), and `enabled`
(force it). We pick `auto`: it lets frida decide based on the cross-build
configuration whether the 32-bit helper is required, which is the safest match
for "the device runs mixed-ABI processes" without over-forcing on builds where
it is irrelevant (e.g. a future host-only test build). `enabled` would also
work for the Android cross build but is stricter than necessary.

### D2. What physically enters the binary
With `compat=auto` the Android cross build links in `frida-helper-32` (the ELF
helper frida spawns to inject into a 32-bit target from the 64-bit daemon) and
the armv7 `frida-agent.so` (the agent payload injected into the 32-bit target).
Confirmed on the rebuilt binary: `frida-helper-32` is present in the ELF and
the `frida_resource_store_get_helper32` symbol resolves. The binary grows from
~16 MB to ~24 MB — the cost of carrying both ABIs.

### D3. Build-time only, no runtime path change
`frida_controller.vala` already drives `device.attach(pid)` and spawn-gating
without naming an ABI; frida selects the helper per-target automatically once
the helper is present in the binary. So there is no Vala change in this change
set — only the `meson.build` option flip. The `Unable to handle 32-bit
processes` error was the runtime symptom of the missing helper; it disappears
once the helper is built in (verified on the car: `pedestrian-warning` reached
`state: active` on `com.qinggan.systemservice`, a 32-bit process).

### D4. No trust boundary crossed
Enabling the 32-bit helper does not change agent verification, the embedded
public key, or the OTA/staging contract. The 32-bit agent payload is the same
signed JavaScript agent, delivered over the same frida session; only the
in-process frida helper ABI differs. The `trust-verification` and
`build-and-signing` signing requirements are untouched.
