#!/bin/sh
# Deterministically generate test fixtures from the committed dev keypair:
# - a signed daemon manifest (manifest.json + manifest.sig) + a corrupt sig,
#   used by the boot-recovery tests (the per-agent manifest; it no longer
#   rides in the inject payload, but the daemon still loads/verifies it from
#   the root zone at VERIFY_SELF);
# - a matching agent payload (agents/wm-viewport.js, agents/launcher-echo.js);
# - a signed inject payload (voboost-inject): a single file = the daemon ELF
#   bytes (a stub "fake-inject-binary-v1\n") followed by an 80-byte trailing
#   signature block (8 bytes magic "VOBSIG1\0", 8 bytes LE uint64 SIG_OFFSET,
#   64 bytes raw ed25519 signature over the ELF bytes), plus negative
#   fixtures: voboost-inject-bad-sig (valid magic/offset, flipped signature
#   byte), voboost-inject-no-magic (trailing bytes without VOBSIG1),
#   voboost-inject-truncated (shorter than the 80-byte trailing block);
# - a signed release manifest (release-manifest.json + .sig) listing the
#   inject file as a single inject-channel entry, plus negative fixtures
#   (bad-entry, bad-channel, bad-sig).
#
# Run from the repo root by meson at configure time (or manually). Idempotent.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
priv="$root/config/key-dev-private.pem"

mkdir -p "$here/agents"

# --- daemon manifest + agent payload -------------------------------------
#
# The fixture manifest declares every agent id the app may request in a plan
# (inject.json), so the daemon never logs "rejected unknown agent id" during
# emulator E2E. The app's FeatureFrida set requests: wm-viewport
# (system_server), settings-menu (com.qinggan.app.vehiclesetting),
# low-speed-sound (com.qinggan.app.vehiclesetting, used by the config-delivery
# scenario), and launcher-echo (com.qinggan.app.launcher, used by the
# attach-launcher scenario). Each agent payload is a minimal stub (sends an ok
# marker); the daemon verifies sha256 against the manifest, so the file content
# is hashed and committed alongside the manifest.

emit_agent() {  # emit_agent <id> <file-basename> <process> <payload-line>
  local id="$1" base="$2" proc="$3" payload="$4"
  local file="$here/agents/${base}"
  printf '%s\n' "$payload" > "$file"
  local sha; sha=$(openssl dgst -sha256 -hex "$file" | awk '{ print $NF }')
  printf '    {\n      "id": "%s",\n      "channel": "agents",\n' "$id"
  printf '      "file": "agents/%s",\n' "$base"
  printf '      "sha256": "%s",\n' "$sha"
  printf '      "process": "%s",\n      "boot": false\n    }' "$proc"
}

{
  printf '{\n  "version": 1,\n  "daemon": "1.0.0-beta1",\n  "agents": [\n'
  # Each fixture agent must export rpc.exports.init so the daemon's
  # frida:rpc "init" call (frida_controller.rpc_init_message) resolves
  # instead of failing with "unable to find method 'init'". The init
  # handler returns {ok: true} (the RPC reply) and also send()s a marker
  # message so the integration test can observe the agent loaded. The
  # real production agents (voboost-script/agents) get this via the
  # runAgent() helper in lib/utils.js; these minimal stubs inline it.
  emit_agent "wm-viewport"     "wm-viewport.js"     "system_server"                  "rpc.exports = { init: function() { send({ ok: true, agent: 'wm-viewport' }); return { ok: true }; } };"
  printf ',\n'
  emit_agent "settings-menu"    "settings-menu.js"   "com.qinggan.app.vehiclesetting" "rpc.exports = { init: function() { send({ ok: true, agent: 'settings-menu' }); return { ok: true }; } };"
  printf ',\n'
  emit_agent "low-speed-sound"  "low-speed-sound.js" "com.qinggan.app.vehiclesetting" "rpc.exports = { init: function() { send({ ok: true, agent: 'low-speed-sound' }); return { ok: true }; } };"
  printf ',\n'
  emit_agent "launcher-echo"    "launcher-echo.js"   "com.qinggan.app.launcher"        "rpc.exports = { init: function() { send({ ok: true, agent: 'launcher-echo' }); return { ok: true }; } };"
  printf '\n  ]\n}\n'
} > "$here/manifest.json"

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

# --- inject payload (single appended-sig ELF) ---------------------------
# A stub daemon ELF (the real one is built by `make build-android`; the test
# only exercises the trailing-block parser + signature verify, which do not
# care about ELF structure — the kernel never execs this stub).
printf 'fake-inject-binary-v1\n' > "$here/voboost-inject-elf"

# Build the signed inject payload by appending the VOBSIG1 trailing block to
# the stub ELF: 8 bytes magic, 8 bytes LE uint64 SIG_OFFSET (= ELF byte size),
# 64 bytes raw ed25519 signature over the ELF bytes (signed with the dev
# keypair). Sign via a file (the rest of this script uses `openssl pkeyutl
# -sign -rawin -in <file>`, which is the only form that produces a clean 64-byte
# ed25519 signature on this openssl build — piping into -rawin mixes an error
# trail into the output). Python stdlib only for the trailing-block append
# (struct for the LE uint64).
openssl pkeyutl -sign -inkey "$priv" -rawin \
  -in "$here/voboost-inject-elf" -out "$here/voboost-inject-elf.sig"
python3 - "$here" <<'PY'
import os, struct, sys
here = sys.argv[1]
elf_path = os.path.join(here, "voboost-inject-elf")
sig_path = os.path.join(here, "voboost-inject-elf.sig")
with open(elf_path, "rb") as f:
    elf_bytes = f.read()
with open(sig_path, "rb") as f:
    sig = f.read()
assert len(sig) == 64, f"ed25519 sig is {len(sig)} bytes, want 64"
trailing = b"VOBSIG1\0" + struct.pack("<Q", len(elf_bytes)) + sig
assert len(trailing) == 80, f"trailing block is {len(trailing)} bytes, want 80"

def write_payload(out_path, elf, trail):
    with open(out_path, "wb") as f:
        f.write(elf)
        f.write(trail)

# Good payload: ELF + valid trailing block.
write_payload(os.path.join(here, "voboost-inject"), elf_bytes, trailing)

# Bad-sig payload: valid magic/offset, signature with the first byte flipped.
bad_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
write_payload(
    os.path.join(here, "voboost-inject-bad-sig"),
    elf_bytes,
    b"VOBSIG1\0" + struct.pack("<Q", len(elf_bytes)) + bad_sig,
)

# No-magic payload: trailing bytes without the VOBSIG1 magic (so the parser
# rejects at the magic check before touching the signature).
write_payload(
    os.path.join(here, "voboost-inject-no-magic"),
    elf_bytes,
    b"XXXXXXXX" + struct.pack("<Q", len(elf_bytes)) + sig,
)

# Truncated payload: shorter than the 80-byte trailing block (rejected by the
# minimum-size check before any parsing).
with open(os.path.join(here, "voboost-inject-truncated"), "wb") as f:
    f.write(elf_bytes)
    f.write(b"VOBS")  # only 4 trailing bytes (< 80)

# Lying-offset payload: valid magic and signature, but SIG_OFFSET points past
# the file (out of bounds) so the bounds check rejects it.
write_payload(
    os.path.join(here, "voboost-inject-bad-offset"),
    elf_bytes,
    b"VOBSIG1\0" + struct.pack("<Q", len(elf_bytes) + 4096) + sig,
)
PY
rm -f "$here/voboost-inject-elf.sig"

inject_sha=$(openssl dgst -sha256 -hex "$here/voboost-inject" | awk '{ print $NF }')
inject_size=$(stat -f%z "$here/voboost-inject" 2>/dev/null || stat -c%s "$here/voboost-inject" 2>/dev/null)

# --- release manifest (lists the inject file as the inject entry) --------
# The release manifest is the OTA client's trust source for the inject file
# size+sha256 before staging. It lists the inject file (voboost-inject, a
# single appended-sig ELF), not the old APK wrapper.
cat > "$here/release-manifest.json" <<JSON
{
  "version": "1.0.0-beta1",
  "channel": "inject",
  "files": [
    {"path":"voboost-inject","channel":"inject","sha256":"$inject_sha","size":$inject_size,"version":"1.0.0-beta1"}
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
{"version":"1.0.0-beta1","channel":"inject","files":[
  {"path":"voboost-inject","channel":"inject","sha256":"$inject_sha","version":"1.0.0-beta1"}
]}
JSON
openssl pkeyutl -sign -inkey "$priv" -rawin \
  -in "$here/release-manifest-bad-entry.json" \
  -out "$here/release-manifest-bad-entry.json.sig"

cat > "$here/release-manifest-bad-channel.json" <<JSON
{"version":"1.0.0-beta1","channel":"inject","files":[
  {"path":"voboost-inject","channel":"widgets","sha256":"$inject_sha","size":$inject_size,"version":"1.0.0-beta1"}
]}
JSON
openssl pkeyutl -sign -inkey "$priv" -rawin \
  -in "$here/release-manifest-bad-channel.json" \
  -out "$here/release-manifest-bad-channel.json.sig"
