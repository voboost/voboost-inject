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
