# Host-side test harness (init change). Tests are silent on success and
# fail loudly. inject/ota add real device-free logic tests here.
smoke = find_program('smoke.sh')
test('smoke', smoke)

# inject change: device-free vala unit tests on pure logic. These deps and
# sources are reused and extended by the ota change.
inject_test_deps = [
  dependency('glib-2.0'),
  dependency('gobject-2.0'),
  dependency('gio-2.0'),
  dependency('json-glib-1.0'),
  dependency('monocypher'),
]
inject_test_srcs = files(
  meson.project_source_root() / 'src/ed25519.vapi',
  meson.project_source_root() / 'src/log.vala',
  meson.project_source_root() / 'src/boot.vala',
  meson.project_source_root() / 'src/trust_store.vala',
  meson.project_source_root() / 'src/manifest.vala',
  meson.project_source_root() / 'src/plan_reader.vala',
  meson.project_source_root() / 'src/status.vala',
  meson.project_source_root() / 'src/safety.vala',
  meson.project_source_root() / 'src/ota.vala',
)
inject_test_vala_args = [
  '--pkg=posix',
  # frida's meson fork does not auto-derive --pkg flags from `dependencies:`
  # the way upstream meson does (see src/meson.build for the same fix).
  '--pkg=gio-2.0',
  '--pkg=json-glib-1.0',
]
# Inline custom_target — no scripts/ file needed.
inject_pubkey = custom_target(
  'test-embedded-pubkey',
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

# P6: deterministic test fixtures — make test is self-contained after make init.
# gen-fixtures.sh produces manifest.json, manifest.sig, manifest-bad.sig, and
# a dummy agent, all signed with the dev keypair. The stamp file in the build
# directory prevents re-generation unless the script or key changes.
inject_fixtures = custom_target(
  'inject-test-fixtures',
  input: ['fixtures/gen-fixtures.sh', '../config/key-dev-public.pem'],
  output: 'fixtures.stamp',
  command: [
    'sh', '-c',
    '''set -eu
"$1" && touch "$2"''',
    'sh',
    '@INPUT0@',
    '@OUTPUT@',
  ],
)

foreach t : ['manifest', 'plan', 'safety', 'status', 'trust_store', 'log', 'ota', 'boot']
  exe = executable(
    t + '_test',
    [t + '_test.vala'] + inject_test_srcs + [inject_pubkey],
    dependencies: inject_test_deps,
    vala_args: inject_test_vala_args,
    name_prefix: 'test-',
    implicit_include_directories: false,
  )
  test(t, exe, workdir: meson.project_source_root (),
       depends: inject_fixtures)
endforeach
