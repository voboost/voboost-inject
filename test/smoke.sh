#!/bin/sh
# Smoke test: verifies the build directory and the daemon binary exist after
# `make build`, so a misconfigured build (missing executable, wrong layout)
# is caught before the Vala unit tests run. Silent on success, loud on
# failure. The real logic tests are the Vala unit tests (manifest, plan,
# safety, status, trust_store, log, ota, boot, app_zone_watcher).
set -eu

# The build dir is passed via MESON_BUILD_ROOT when meson runs the test;
# fall back to the project build/ for manual invocation.
build_root="${MESON_BUILD_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/../build" 2>/dev/null && pwd)}"
if [ -z "$build_root" ]; then
    echo "smoke: could not locate build root" >&2
    exit 1
fi

# The daemon binary is the primary build artifact.
bin="$build_root/src/voboost-inject"
if [ ! -x "$bin" ]; then
    echo "smoke: daemon binary missing or not executable: $bin" >&2
    exit 1
fi

exit 0
