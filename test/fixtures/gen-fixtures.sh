#!/bin/sh
# Deterministically generate test fixtures from the committed dev keypair:
# a signed manifest, its detached ed25519 signature, a matching agent payload,
# and a deliberately-corrupt signature. Run from the repo root by meson at
# configure time (or manually). Idempotent.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
priv="$root/config/key-dev-private.pem"

mkdir -p "$here/agents"

agent="$here/agents/wm-viewport.js"
printf '%s\n' "send({ ok: true });" > "$agent"
sha=$(openssl dgst -sha256 -hex "$agent" | awk '{ print $NF }')

cat > "$here/manifest.json" <<JSON
{
  "version": 1,
  "daemon": "1.0.0-beta1",
  "agents": [
    {
      "id": "wm-viewport",
      "channel": "agents",
      "file": "agents/wm-viewport.js",
      "sha256": "$sha",
      "process": "system_server",
      "kind": "js",
      "entrypoint": "",
      "boot": false
    }
  ]
}
JSON

openssl pkeyutl -sign -inkey "$priv" -rawin \
  -in "$here/manifest.json" -out "$here/manifest.sig"

# A corrupt signature for the negative test. Flip the first byte to a value
# guaranteed to differ from the original (XOR 0xFF) so the bad-sig fixture
# can never accidentally equal the valid signature if a key/manifest change
# ever makes the original first byte 0x00.
cp "$here/manifest.sig" "$here/manifest-bad.sig"
first=$(od -An -tu1 -N1 "$here/manifest-bad.sig" | tr -d ' \n')
flipped=$(( first ^ 0xFF ))
printf "\\$(printf '%03o' "$flipped")" \
  | dd of="$here/manifest-bad.sig" bs=1 count=1 conv=notrunc status=none

# OTA release-manifest fixture (signed with the dev keypair): a dummy core
# binary listed as a core-channel entry, plus a corrupt signature for the
# negative test. stat is probed both ways (macOS -f%z, Linux -c%s).
core="$here/voboost-inject"
printf 'fake-core-binary-v1\n' > "$core"
core_sha=$(openssl dgst -sha256 -hex "$core" | awk '{ print $NF }')
core_size=$(stat -f%z "$core" 2>/dev/null || stat -c%s "$core" 2>/dev/null)

cat > "$here/release-manifest.json" <<JSON
{
  "version": "1.0.0-beta1",
  "channel": "core",
  "files": [
    {"path":"voboost-inject","channel":"core","sha256":"$core_sha","size":$core_size,"version":"1.0.0-beta1"}
  ]
}
JSON

openssl pkeyutl -sign -inkey "$priv" -rawin \
  -in "$here/release-manifest.json" -out "$here/release-manifest.json.sig"

cp "$here/release-manifest.json.sig" "$here/release-manifest-bad.sig"
first=$(od -An -tu1 -N1 "$here/release-manifest-bad.sig" | tr -d ' \n')
flipped=$(( first ^ 0xFF ))
printf "\\$(printf '%03o' "$flipped")" \
  | dd of="$here/release-manifest-bad.sig" bs=1 count=1 conv=notrunc status=none

# Multi-agent content-addressed daemon manifest for the agent-apply partial-
# failure test (ota change): two fresh agents, one staged tampered so its sha
# mismatches the manifest, asserting the active set is left intact on failure.
ax="$here/agents/agent-x.js"; printf 'agent-x-content\n' > "$ax"
ay="$here/agents/agent-y.js"; printf 'agent-y-content\n' > "$ay"
shax=$(openssl dgst -sha256 -hex "$ax" | awk '{ print $NF }')
shay=$(openssl dgst -sha256 -hex "$ay" | awk '{ print $NF }')
cat > "$here/manifest-multi.json" <<JSON
{
  "version": 1,
  "daemon": "1.0.0-beta1",
  "agents": [
    {"id":"agent-x","channel":"agents","file":"agents/agent-x.js","sha256":"$shax","process":"system_server","kind":"js","entrypoint":"","boot":false},
    {"id":"agent-y","channel":"agents","file":"agents/agent-y.js","sha256":"$shay","process":"system_server","kind":"js","entrypoint":"","boot":false}
  ]
}
JSON
openssl pkeyutl -sign -inkey "$priv" -rawin \
  -in "$here/manifest-multi.json" -out "$here/manifest-multi.sig"
# Tampered agent-y payload (different content => sha mismatches the manifest).
printf 'agent-y-TAMPERED\n' > "$here/agents/agent-y-bad.js"

# Negative release-manifest fixtures (validly signed, bad content): a
# missing-field entry and an invalid-channel entry. The parser rejects the
# whole manifest on one bad entry even though the signature verifies
# (release-manifest spec).
cat > "$here/release-manifest-bad-entry.json" <<JSON
{"version":"1.0.0-beta1","channel":"core","files":[
  {"path":"voboost-inject","channel":"core","sha256":"$core_sha","version":"1.0.0-beta1"}
]}
JSON
openssl pkeyutl -sign -inkey "$priv" -rawin \
  -in "$here/release-manifest-bad-entry.json" \
  -out "$here/release-manifest-bad-entry.json.sig"

cat > "$here/release-manifest-bad-channel.json" <<JSON
{"version":"1.0.0-beta1","channel":"core","files":[
  {"path":"voboost-inject","channel":"widgets","sha256":"$core_sha","size":$core_size,"version":"1.0.0-beta1"}
]}
JSON
openssl pkeyutl -sign -inkey "$priv" -rawin \
  -in "$here/release-manifest-bad-channel.json" \
  -out "$here/release-manifest-bad-channel.json.sig"
