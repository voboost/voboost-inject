#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd -P)
ndk=${ANDROID_NDK_HOME:-}
[[ -n "$ndk" && -d "$ndk/toolchains/llvm/prebuilt" ]] || {
    echo "daemon-versionless-reproducible: ANDROID_NDK_HOME must name NDK r29" >&2
    exit 2
}
for variable in \
    VOBOOST_AGENT_CATALOG_PUBLIC_KEY_PEM \
    VOBOOST_RELEASE_CATALOG_PUBLIC_KEY_PEM \
    VOBOOST_NATIVE_EXECUTABLE_PUBLIC_KEY_PEM \
    VOBOOST_RESTORE_PUBLIC_KEY_PEM \
    VOBOOST_NATIVE_REGISTRY; do
    value=${!variable:-}
    [[ "$value" == /* && -f "$value" && ! -L "$value" ]] || {
        echo "daemon-versionless-reproducible: $variable must name an absolute regular input" >&2
        exit 2
    }
done

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}"
[[ "$CARGO_TARGET_DIR" == /* ]] || {
    echo "daemon-versionless-reproducible: CARGO_TARGET_DIR must be absolute" >&2
    exit 2
}

mkdir -p "$root/build"
temporary=$(mktemp -d "$root/build/versionless.XXXXXX")
cleanup() {
    [[ ! -d "$temporary" ]] || rm -r "$temporary"
}
trap cleanup EXIT HUP INT TERM
chmod 700 "$temporary"

build() {
    local channel=$1 base=$2 beta=$3 binary
    (
        cd "$root/daemon"
        # Rebuild the owned Rust graph; retain third-party dependency artifacts.
        cargo clean --release --target aarch64-linux-android \
            -p voboost-daemon -p voboost-contract -p voboost-shared \
            -p voboost-contract-core -p voboost-qconn
        for binary in voboost-daemon voboost-inject; do
            SOURCE_DATE_EPOCH=0 \
            VOBOOST_BUILD_TARGET="${binary#voboost-}" \
            VOBOOST_RELEASE_CHANNEL="$channel" \
            VOBOOST_RELEASE_BASE_VERSION="$base" \
            VOBOOST_RELEASE_BETA="$beta" \
            RUSTFLAGS="${RUSTFLAGS:-}" \
                cargo ndk -t arm64-v8a -P 28 build --release --locked --bin "$binary"
        done
    )
}

target="$CARGO_TARGET_DIR/aarch64-linux-android/release"
build beta 1.0.0 1
for binary in voboost-daemon voboost-inject; do
    cp "$target/$binary" "$temporary/$binary.first"
done
build release 9.8.7 999
for binary in voboost-daemon voboost-inject; do
    first="$temporary/$binary.first"
    second="$target/$binary"
    cmp "$first" "$second"
    echo "daemon-versionless-reproducible: identical Android ELF $binary"
done
