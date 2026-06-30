# inject change: build the daemon, statically linked against frida-core.
# Toolchain + option pinning per design D10c: the subproject hard-requires the
# frida-patched valac (provisioned by make init), and the pinned options live
# in the root project() default_options (QuickJS-only via frida-gum:v8=disabled
# — gum's v8 defaults to auto, NOT off; static libs; local backend only;
# frida_version supplied since the wrap checkout has no releng). Explicit
# subproject() first: frida-core registers 'frida-core-1.0' via
# meson.override_dependency (src/api/meson.build), which dependency() then
# resolves; [provide] in the wrap covers implicit fallback too.
# Release-only: buildtype=release set in project() default_options.
# Static link + LTO + strip per build-and-signing spec (task 1.2, D10).
frida_core_sub = subproject('frida-core')
frida_core_dep = dependency('frida-core-1.0', static: true)

# The VAPI file from frida-core's API custom_target. Meson does not
# propagate dependency sources (including VAPI stamps) from subproject
# deps, so we pull the VAPI file explicitly and add it to our executable
# sources. When a .vapi file is in sources, valac processes it directly
# (no --pkg needed) AND meson creates a build-order dependency, ensuring
# the VAPI is generated before our code compiles.
frida_core_vapi = frida_core_sub.get_variable('core_public_vapi')

inject_deps = [
  dependency('glib-2.0'),
  dependency('gobject-2.0'),
  dependency('gio-2.0'),
  dependency('json-glib-1.0'),
  dependency('monocypher'),
  frida_core_dep,
]

# ed25519.vapi is listed in inject_sources (vapi-in-sources), so no --pkg /
# --vapidir wiring is needed for it; posix ships with valac.
# --vapidir adds src/ to valac's package search so stub vapis for transitive
# C-only deps (gthread-2.0 removed from Vala 0.56+, capstone has no vapi)
# propagated by frida-core are found. These stubs carry no Vala API; our code
# never calls gthread or capstone directly.
inject_vala_args = [
  '--pkg=posix',
  '--vapidir', meson.current_source_dir(),
  # frida's meson fork does not auto-derive --pkg flags from `dependencies:`
  # the way upstream meson does, so the gio/json-glib VAPIs (which frida-core's
  # own VAPI and our sources reference: GLib.Cancellable, Json.Object, etc.)
  # must be named explicitly. frida-core does the same in its own meson.build.
  '--pkg=gio-2.0',
  '--pkg=json-glib-1.0',
]

# Host build (make build) links dynamically so it builds on the macOS dev host
# (a full -static link is unsupported there). The Android device build
# (make build-android, a cross build) links every bundled subproject (frida-core,
# glib, gio, json-glib, monocypher, ...) statically via `default_library=static`
# (set globally in the root project) and `static: true` on the frida-core dep
# (D10a), so the daemon is self-contained for the frida/glib stack — no glib/gio/
# json-glib on the device. The bionic system libs (libc, liblog, libz, libm,
# libdl) are linked dynamically: NDK r29 ships no static bionic (libc.a etc.
# were removed), and bionic is always present on Android anyway. A `-static`
# link would fail with "unable to find library -llog" (no liblog.a in the NDK).
inject_link_args = meson.is_cross_build() ? ['-Wl,-Bstatic', '-Wl,-Bdynamic'] : []

# Single source of truth for the daemon version is meson.build's project()
# version (ci-versioning: the version SHALL NOT be defined elsewhere). Generate
# version.vala from it so Status reports the real build version, never a literal.
version_vala = configure_file(
  input: 'version.vala.in',
  output: 'version.vala',
  configuration: configuration_data({'VERSION': meson.project_version()}),
)

# D9b: bake the raw 32-byte ed25519 public key into the binary at build time.
# The generator is an inline sh command — no scripts/ file needed.
# DER of an ed25519 SubjectPublicKeyInfo = 44 bytes: 12-byte SPKI prefix +
# 32-byte raw key. We skip the first 12 bytes (24 hex chars).
embedded_pubkey = custom_target(
  'embedded-pubkey',
  input: meson.project_source_root() / 'config/key-dev-public.pem',
  output: 'embedded_pubkey.vala',
  command: [
    'sh', '-c',
    'set -eu; pem=$1; out=$2; hex=$(openssl pkey -pubin -in "$pem" -outform DER | od -An -v -tx1 | tr -d "[:space:]"); raw=$(printf "%s" "$hex" | cut -c25-); [ "${#raw}" -eq 64 ] || { echo "embedded pubkey: want 64 hex, got ${#raw}" >&2; exit 1; }; bytes=""; i=1; while [ "$i" -le 64 ]; do b=$(printf "%s" "$raw" | cut -c"$i"-"$(($i+1))"); bytes="${bytes:+$bytes, }0x$b"; i=$(($i+2)); done; echo "// Generated. Do not edit. Raw 32-byte ed25519 key (design D9b)." > "$out"; echo "namespace Voboost {" >> "$out"; echo "    public const uint8[] EMBEDDED_PUBKEY = { $bytes };" >> "$out"; echo "}" >> "$out"',
    'sh',
    '@INPUT@',
    '@OUTPUT@',
  ],
)

inject_sources = files(
  'ed25519.vapi',
  'frida-stubs.vapi',
  'log.vala',
  'boot.vala',
  'trust_store.vala',
  'manifest.vala',
  'plan_reader.vala',
  'status.vala',
  'safety.vala',
  'app_zone_watcher.vala',
  'process_watcher.vala',
  'frida_controller.vala',
  'supervisor.vala',
  'ota.vala',
  'main.vala',
)

executable(
  'voboost-inject',
  inject_sources,
  embedded_pubkey,
  version_vala,
  frida_core_vapi,
  dependencies: inject_deps,
  vala_args: inject_vala_args,
  link_args: inject_link_args,
  install: true,
)
