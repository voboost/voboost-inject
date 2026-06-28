project(
  'voboost-inject',
  'vala', 'c',
  version: '1.0.0-beta1',
  meson_version: '>= 1.1.0',
  # Release-only build: static link, LTO (build-and-signing spec, D10).
  # Strip is applied at install time via `meson install --strip`.
  # Subproject options pinned per design D10c — frida defaults would give V8
  # (auto), shared libs, and all tools; QuickJS-only + static + minimal MUST
  # be pinned explicitly.
  default_options: [
    'buildtype=release',
    'b_lto=true',
    'b_staticpic=true',
    # Global static: every transitive subproject (pcre2, xz, sqlite, libpsl,
    # nghttp2, elfutils, glib-networking, ...) builds a static archive so the
    # Android `-static` link has no dynamic objects to reject, and
    # glib-networking's gioopenssl is built as a static lib (its
    # meson.override_dependency('gioopenssl', ...) only runs in the
    # `if build_static:` branch — `build_static = default_library != 'shared'`).
    # The per-subproject `frida-core:default_library=static` below is kept for
    # clarity/frida-core's own option pinning.
    'default_library=static',
    'frida-core:default_library=static',
    'frida-core:frida_version=17.11.0',
    'frida-core:local_backend=enabled',
    'frida-core:fruity_backend=disabled',
    'frida-core:droidy_backend=disabled',
    'frida-core:socket_backend=disabled',
    'frida-core:barebone_backend=disabled',
    'frida-core:compiler_backend=disabled',
    'frida-core:server=disabled',
    'frida-core:portal=disabled',
    'frida-core:inject=disabled',
    'frida-core:gadget=disabled',
    'frida-core:compat=disabled',
    'frida-core:tests=disabled',
    'frida-core:assets=embedded',
    'frida-gum:v8=disabled',
  ],
)

# inject change: daemon build (release-only is the project default option).
# Frida sources are auto-resolved from the pinned git wraps in subprojects/
# on `meson setup`; the frida-core dependency is wired in src/meson.build.
subdir('src')

# init change: host-side test harness (extended by inject with vala unit tests).
# Tests are host-only: skip them in a cross build (make build-android) — they
# would otherwise compile for the cross target and fail (no test runner on the
# device), and they are not part of the release artifact.
if not meson.is_cross_build()
  subdir('test')
endif
