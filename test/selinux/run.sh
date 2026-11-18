#!/usr/bin/env bash
# Unit tests for the SELinux program (host build).
# 1. rules.gen.h is up to date with selinux/voboost.te (golden diff).
# 2. policy_inject produces the expected types/attrs/allows/transitions
#    on a synthetic expanded policydb.
# 3. Signature checks via the non-executing checksig helper: the signed
#    binary passes, a tampered copy fails. (The tampered file is never
#    executed — a corrupted ELF can wedge the macOS loader.)
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "== selinux: golden diff rules.gen.h"
test/selinux/test_rule_generation.sh

echo "== selinux: inject unit tests"
CC=${CC:-cc}
# Match the prepared headers used to build build/host/libsepol.a.
SEPOL_DIR=${NATIVE_BUILD_SOURCE:-build/third-party-source}/libsepol
$CC -O1 -Iselinux -I"$SEPOL_DIR/include" -I"$SEPOL_DIR/src" \
  -DDARWIN -fcommon \
  test/selinux/test_inject.c selinux/policy_inject.c \
  build/host/libsepol.a -o build/host/test_inject
./build/host/test_inject

echo "== selinux: pristine backup contract"
$CC -O1 -w -Iselinux -I"$SEPOL_DIR/include" -I"$SEPOL_DIR/src" \
  -Ithird_party/yyjson/src \
  -DDARWIN -fcommon \
  test/selinux/test_policy_backup.c selinux/policy_inject.c \
  selinux/tweetnacl.c third_party/yyjson/src/yyjson.c \
  build/host/libsepol.a -o build/host/test_policy_backup
./build/host/test_policy_backup

echo "== selinux: stock boot policy source and compiler snapshots"
make --no-print-directory test-selinux-boot-source

echo "== selinux: async-safe bounded watchdog"
$CC -O1 -w -Iselinux -I"$SEPOL_DIR/include" -I"$SEPOL_DIR/src" \
  -Ithird_party/yyjson/src \
  -DDARWIN -fcommon \
  test/selinux/test_watchdog.c selinux/policy_inject.c \
  selinux/tweetnacl.c third_party/yyjson/src/yyjson.c \
  build/host/libsepol.a -o build/host/test_watchdog
./build/host/test_watchdog

echo "== selinux: descriptor-bound relabel walk"
$CC -O1 -w -Iselinux -I"$SEPOL_DIR/include" -I"$SEPOL_DIR/src" \
  -Ithird_party/yyjson/src \
  -DDARWIN -fcommon \
  test/selinux/test_relabel_walk.c selinux/policy_inject.c \
  selinux/tweetnacl.c third_party/yyjson/src/yyjson.c \
  build/host/libsepol.a -o build/host/test_relabel_walk
./build/host/test_relabel_walk

if [ -f test/selinux/fixtures/f0506h-free-09-chinese-6.0.3-policy-v30.bin ]; then
  echo "== selinux: real firmware policy roundtrip+inject"
  $CC -O1 -w -Iselinux -I"$SEPOL_DIR/include" -I"$SEPOL_DIR/src" \
    -DDARWIN -fcommon \
    test/selinux/test_real_policy.c selinux/policy_inject.c \
    build/host/libsepol.a -o build/host/test_real_policy
  ./build/host/test_real_policy test/selinux/fixtures/f0506h-free-09-chinese-6.0.3-policy-v30.bin
  echo "== selinux: metadata baseline comparison"
  test/selinux/test_metadata_baseline.sh
  echo "== selinux: MLS constraint evaluation (kernel-style)"
  $CC -O1 -w -Iselinux -I"$SEPOL_DIR/include" -I"$SEPOL_DIR/src" \
    -DDARWIN -fcommon \
    test/selinux/test_mls_eval.c selinux/policy_inject.c \
    build/host/libsepol.a -o build/host/test_mls_eval
  ./build/host/test_mls_eval test/selinux/fixtures/f0506h-free-09-chinese-6.0.3-policy-v30.bin
else
  echo "== selinux: real firmware policy fixture absent, skipping"
fi

echo "== selinux: signature checks"
BIN=build/host/voboost-selinux
chmod +x "$BIN"
SIGNATURE_ROOT=$(mktemp -d)
trap 'rm -rf "$SIGNATURE_ROOT"' EXIT
openssl genpkey -algorithm ed25519 -out "$SIGNATURE_ROOT/private.pem"
openssl pkey -in "$SIGNATURE_ROOT/private.pem" -pubout -out "$SIGNATURE_ROOT/public.pem"
make --no-print-directory sign-elf ROLE=selinux BINARY="$BIN" \
  KEY="$SIGNATURE_ROOT/private.pem" OUT=build/host/voboost-selinux.signed >/dev/null

PUBKEY_HEX="$(openssl pkey -pubin -in "$SIGNATURE_ROOT/public.pem" -outform DER | tail -c 32 | od -An -tx1 | tr -s ' ' '\n' | grep -v '^$' | sed 's/^/0x/' | paste -sd, -)"
$CC -O1 -Iselinux \
  -DEMBEDDED_PUBKEY_HEX="$PUBKEY_HEX" \
  test/selinux/checksig.c selinux/tweetnacl.c -o build/host/checksig
if ./build/host/checksig "$BIN"; then
  echo "FAIL: unsigned binary passed appended-signature verification" >&2
  exit 1
fi
./build/host/checksig build/host/voboost-selinux.signed
node tools/release-tool.ts mutate-signature-byte \
  build/host/voboost-selinux.signed build/host/voboost-selinux.tampered
if ./build/host/checksig build/host/voboost-selinux.tampered; then
  echo "FAIL: tampered binary passed signature check" >&2
  exit 1
fi

echo "SELinux program tests: OK"
