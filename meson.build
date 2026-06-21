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
subdir('test')
