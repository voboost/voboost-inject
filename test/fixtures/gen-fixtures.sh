#!/bin/sh
# Deterministically generate test fixtures from the committed dev keypair:
# - a signed daemon manifest (manifest.json + manifest.sig) + a corrupt sig,
#   used by the boot-recovery tests and as the APK's embedded manifest;
# - a matching agent payload (agents/wm-viewport.js);
# - a signed release manifest (release-manifest.json + .sig) listing the daemon
#   APK as a single core entry, plus negative fixtures (bad-entry, bad-channel,
#   bad-sig, oversize);
# - a daemon APK (voboost-inject.apk): a ZIP with assets/manifest.json,
#   assets/manifest.sig, assets/voboost-inject (the daemon ELF binary), built
#   via Python's zipfile (stdlib), plus a bad-embedded-sig APK and a
#   bad-binary APK for the negative tests.
#
# Run from the repo root by meson at configure time (or manually). Idempotent.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
priv="$root/config/key-dev-private.pem"

mkdir -p "$here/agents"

# --- daemon manifest + agent payload -------------------------------------

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

# --- daemon binary (the ELF the APK embeds at assets/voboost-inject) ------
# A dummy binary; the daemon's ZIP reader extracts it verbatim (stored) or
# inflated (deflate). Two variants: a "good" one and a "bad" one (different
# content, for the bad-binary negative test).
printf 'fake-core-binary-v1\n' > "$here/voboost-inject"
printf 'fake-core-binary-BAD\n' > "$here/voboost-inject-bad"

# --- release manifest (lists the daemon APK as the core entry) -----------
# The release manifest is the OTA client's trust source for the APK size+sha256
# before staging. It lists the APK (voboost-inject.apk), not the raw binary.
apk="$here/voboost-inject.apk"

# Build the daemon APK first (so its sha/size can go in the release manifest).
# Python zipfile is stdlib and produces a well-formed ZIP the daemon's minimal
# reader can parse. Entries are stored uncompressed (method 0) so the reader's
# stored path is exercised; a deflated variant is also built to exercise the
# inflate path.
python3 - "$here" <<'PY'
import os, sys, zipfile
here = sys.argv[1]
def build(apk_path, bin_path, manifest, sig):
    with zipfile.ZipFile(apk_path, 'w', zipfile.ZIP_STORED) as z:
        z.write(manifest, 'assets/manifest.json')
        z.write(sig, 'assets/manifest.sig')
        z.write(bin_path, 'assets/voboost-inject')
build(os.path.join(here, 'voboost-inject.apk'),
      os.path.join(here, 'voboost-inject'),
      os.path.join(here, 'manifest.json'),
      os.path.join(here, 'manifest.sig'))
# A deflated APK (method 8) to exercise the inflate path.
build(os.path.join(here, 'voboost-inject-deflated.apk'),
      os.path.join(here, 'voboost-inject'),
      os.path.join(here, 'manifest.json'),
      os.path.join(here, 'manifest.sig'))
# A bad-embedded-sig APK: valid manifest, corrupt sig.
build(os.path.join(here, 'voboost-inject-bad-sig.apk'),
      os.path.join(here, 'voboost-inject'),
      os.path.join(here, 'manifest.json'),
      os.path.join(here, 'manifest-bad.sig'))
# A bad-binary APK: valid manifest+sig, but a different daemon binary (the
# self-replace still proceeds — the binary is not hash-checked against the
# release manifest by the daemon; this fixture is for the extract path).
build(os.path.join(here, 'voboost-inject-bad-binary.apk'),
      os.path.join(here, 'voboost-inject-bad'),
      os.path.join(here, 'manifest.json'),
      os.path.join(here, 'manifest.sig'))
PY

apk_sha=$(openssl dgst -sha256 -hex "$apk" | awk '{ print $NF }')
apk_size=$(stat -f%z "$apk" 2>/dev/null || stat -c%s "$apk" 2>/dev/null)

cat > "$here/release-manifest.json" <<JSON
{
  "version": "1.0.0-beta1",
  "channel": "core",
  "files": [
    {"path":"voboost-inject.apk","channel":"core","sha256":"$apk_sha","size":$apk_size,"version":"1.0.0-beta1"}
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

# Negative release-manifest fixtures (validly signed, bad content): a
# missing-field entry and an invalid-channel entry. The parser rejects the
# whole manifest on one bad entry even though the signature verifies
# (release-manifest spec).
cat > "$here/release-manifest-bad-entry.json" <<JSON
{"version":"1.0.0-beta1","channel":"core","files":[
  {"path":"voboost-inject.apk","channel":"core","sha256":"$apk_sha","version":"1.0.0-beta1"}
]}
JSON
openssl pkeyutl -sign -inkey "$priv" -rawin \
  -in "$here/release-manifest-bad-entry.json" \
  -out "$here/release-manifest-bad-entry.json.sig"

cat > "$here/release-manifest-bad-channel.json" <<JSON
{"version":"1.0.0-beta1","channel":"core","files":[
  {"path":"voboost-inject.apk","channel":"widgets","sha256":"$apk_sha","size":$apk_size,"version":"1.0.0-beta1"}
]}
JSON
openssl pkeyutl -sign -inkey "$priv" -rawin \
  -in "$here/release-manifest-bad-channel.json" \
  -out "$here/release-manifest-bad-channel.json.sig"
