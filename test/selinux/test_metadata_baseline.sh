#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
work=$(mktemp -d "$PWD/build/host/metadata-baseline.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
cp selinux/policy_inject.c "$work/policy_inject.c"
BASELINE_WORK="$work" node --input-type=module <<'JS'
import { readFileSync, writeFileSync } from "node:fs";
import { generate } from "./tools/gen-policy-rules.ts";
const source = readFileSync("selinux/voboost.te", "utf8");
const rule = "allow voboost domain:dir getattr;";
if (source.split(rule).length !== 2) throw new Error("metadata rule must occur exactly once");
writeFileSync(`${process.env.BASELINE_WORK}/rules.gen.h`, generate(source.replace(rule, "")));
JS
sepol=${SEPOL_DIR:-"$PWD/build/third-party-source/libsepol"}
cc=${CC:-cc}
"$cc" -O1 -w -Iselinux -I"$sepol/include" -I"$sepol/src" -DDARWIN -fcommon \
  -Dvoboost_policy_inject=baseline_policy_inject -Dvoboost_policy_applied=baseline_policy_applied \
  -Dvoboost_policy_preserves_types=baseline_policy_preserves_types \
  -c "$work/policy_inject.c" -o "$work/baseline.o"
"$cc" -O1 -w -Iselinux -I"$sepol/include" -I"$sepol/src" -DDARWIN -fcommon \
  -DVOBOOST_METADATA_BASELINE test/selinux/test_real_policy.c selinux/policy_inject.c \
  "$work/baseline.o" build/host/libsepol.a -o "$work/test"
"$work/test" test/selinux/fixtures/f0506h-free-09-chinese-6.0.3-policy-v30.bin
