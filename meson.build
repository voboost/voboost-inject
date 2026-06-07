project(
  'voboost-inject',
  'vala', 'c',
  version: '0.1.0',
  meson_version: '>= 0.60.0',
  default_options: ['buildtype=release'],
)

# init change: provisioning only. Frida sources are fetched from the pinned
# git wraps in subprojects/ on `meson setup`. Daemon build targets, the
# frida-core dependency wiring, and the project version are added by `inject`.
message('voboost-inject: provisioning build (init change). No daemon targets yet.')

# init change: host-side test harness.
subdir('test')
