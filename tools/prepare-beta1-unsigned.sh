#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: prepare-beta1-unsigned.sh <output-dir>" >&2
    exit 2
fi

root=$(cd "$(dirname "$0")/.." && pwd -P)
output=$1
ndk=${ANDROID_NDK_HOME:-}
[[ -n "$ndk" ]] || {
    echo "prepare-beta1-unsigned: ANDROID_NDK_HOME is required" >&2
    exit 2
}

readelf=
for candidate in "$ndk"/toolchains/llvm/prebuilt/*/bin/llvm-readelf; do
    if [[ -x "$candidate" ]]; then
        readelf=$candidate
        break
    fi
done
[[ -n "$readelf" ]] || {
    echo "prepare-beta1-unsigned: NDK llvm-readelf is unavailable" >&2
    exit 2
}

names=(
    voboost-daemon
    voboost-inject
    voboost-install
    voboost-restore
    voboost-uninstall
    voboost-selinux
    voboost.rc
    libimplant-arm64-v8a.so
    libimplant-armeabi-v7a.so
)
sources=(
        target/aarch64-linux-android/release/voboost-daemon
        target/aarch64-linux-android/release/voboost-inject
        target/aarch64-linux-android/release/voboost-install
        build/restore/arm64-v8a/voboost-restore
        target/aarch64-linux-android/release/voboost-uninstall
        build/selinux/arm64-v8a/voboost-selinux
        config/voboost.rc
        implant/libs/arm64-v8a/libimplant.so
        implant/libs/armeabi-v7a/libimplant.so
)
[[ ${#names[@]} -eq 9 && ${#sources[@]} -eq ${#names[@]} ]] || exit 2

if [[ -e "$output" || -L "$output" ]]; then
    [[ -d "$output" && ! -L "$output" ]] || {
        echo "prepare-beta1-unsigned: output is not a directory" >&2
        exit 2
    }
    [[ -z "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
        echo "prepare-beta1-unsigned: output directory is not empty" >&2
        exit 2
    }
fi

temporary="${output}.tmp.$$"
[[ ! -e "$temporary" && ! -L "$temporary" ]] || {
    echo "prepare-beta1-unsigned: temporary output already exists" >&2
    exit 2
}
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

file_links() {
    stat -f %l "$1" 2>/dev/null || stat -c %h "$1"
}

check_elf() {
    local source=$1
    local expected_machine=$2
    local binding=$3
    local header program sections dynamic magic size
    header=$($readelf --file-header "$source")
    # voboost-selinux is linked -static (ET_EXEC); every other artifact is PIE.
    local expected_type=DYN
    [[ "$binding" == static ]] && expected_type=EXEC
    [[ "$header" =~ Type:[[:space:]]+${expected_type}[[:space:]] ]] || {
        echo "prepare-beta1-unsigned: $(basename "$source") is not ELF type ${expected_type}" >&2
        exit 1
    }
    [[ "$header" == *"Machine:                           $expected_machine"* ]] || {
        echo "prepare-beta1-unsigned: $(basename "$source") has wrong ABI" >&2
        exit 1
    }
    program=$($readelf --program-headers "$source")
    [[ "$program" == *GNU_RELRO* ]] || {
        echo "prepare-beta1-unsigned: $(basename "$source") lacks GNU_RELRO" >&2
        exit 1
    }
    ! grep -Eq 'GNU_STACK.*RWE' <<<"$program" || {
        echo "prepare-beta1-unsigned: $(basename "$source") has executable stack" >&2
        exit 1
    }
    sections=$($readelf --sections "$source")
    ! grep -Eq '\.debug_[A-Za-z0-9_.-]+' <<<"$sections" || {
        echo "prepare-beta1-unsigned: $(basename "$source") contains debug sections" >&2
        exit 1
    }
    dynamic=$($readelf --dynamic "$source" 2>&1 || true)
    if [[ "$binding" == immediate ]]; then
        grep -Eq '(BIND_NOW|FLAGS[^[:cntrl:]]*\bNOW\b|FLAGS_1[^[:cntrl:]]*\bNOW\b)' <<<"$dynamic" || {
            echo "prepare-beta1-unsigned: $(basename "$source") lacks immediate binding" >&2
            exit 1
        }
    else
        ! grep -Eq '\bNEEDED\b' <<<"$dynamic" || {
            echo "prepare-beta1-unsigned: voboost-selinux is not a static executable" >&2
            exit 1
        }
    fi
    for prefix in '/Users/' '/private/var/folders/' '/tmp/voboost-' 'voboost-native-role-keys-'; do
        ! LC_ALL=C grep -aFq "$prefix" "$source" || {
            echo "prepare-beta1-unsigned: $(basename "$source") embeds host path material" >&2
            exit 1
        }
    done
    size=$(wc -c <"$source" | tr -d ' ')
    if [[ "$size" -ge 80 ]]; then
        magic=$(tail -c 80 "$source" | head -c 8 | od -An -tx1 | tr -d ' \n')
        [[ "$magic" != 564f424f4f535400 ]] || {
            echo "prepare-beta1-unsigned: $(basename "$source") is already role-signed" >&2
            exit 1
        }
    fi
}

for index in "${!names[@]}"; do
    source="$root/${sources[$index]}"
    [[ -f "$source" && ! -L "$source" && "$(file_links "$source")" == 1 ]] || {
        echo "prepare-beta1-unsigned: missing or unsafe ${sources[$index]}" >&2
        exit 1
    }
    if [[ ${names[$index]} == *.so ]]; then
        if [[ ${names[$index]} == *arm64-v8a* ]]; then
            check_elf "$source" AArch64 immediate
        else
            check_elf "$source" ARM immediate
        fi
    elif [[ ${names[$index]} != voboost.rc ]]; then
        if [[ ${names[$index]} == voboost-selinux ]]; then
            check_elf "$source" AArch64 static
        else
            check_elf "$source" AArch64 immediate
        fi
    else
        [[ -s "$source" ]] || {
            echo "prepare-beta1-unsigned: voboost.rc is empty" >&2
            exit 1
        }
        for prefix in '/Users/' '/private/var/folders/' '/tmp/voboost-' 'voboost-native-role-keys-'; do
            ! LC_ALL=C grep -aFq "$prefix" "$source" || {
                echo "prepare-beta1-unsigned: voboost.rc embeds host path material" >&2
                exit 1
            }
        done
    fi
done

for index in "${!names[@]}"; do
    case "${names[$index]}" in
        voboost-daemon|voboost-inject) marker=VOBOOST_EMULATOR_DAEMON_SELINUX_SKIP_V1 ;;
        voboost-install) marker=VOBOOST_EMULATOR_SELINUX_SKIP_V1 ;;
        voboost-restore) marker=VOBOOST_EMULATOR_RESTORE_SELINUX_SKIP_V1 ;;
        voboost-uninstall) marker=VOBOOST_EMULATOR_UNINSTALL_SELINUX_SKIP_V1 ;;
        *) continue ;;
    esac
    source="$root/${sources[$index]}"
    marker_output=$(strings "$source")
    ! grep -Fqx "$marker" <<<"$marker_output" || {
        echo "prepare-beta1-unsigned: ${names[$index]} contains removed emulator profile" >&2
        exit 1
    }
done
uninstall_mount_marker=VOBOOST_EMULATOR_UNINSTALL_MOUNT_ADAPTER_V1
uninstall_marker_output=$(strings "$root/target/aarch64-linux-android/release/voboost-uninstall")
! grep -Fqx "$uninstall_mount_marker" <<<"$uninstall_marker_output" || {
    echo "prepare-beta1-unsigned: voboost-uninstall contains removed emulator mount adapter" >&2
    exit 1
}

mkdir "$temporary"
for index in "${!names[@]}"; do
    cp "$root/${sources[$index]}" "$temporary/${names[$index]}"
    if [[ ${names[$index]} == voboost.rc || ${names[$index]} == *.so ]]; then
        chmod 0644 "$temporary/${names[$index]}"
    else
        chmod 0755 "$temporary/${names[$index]}"
    fi
done

actual=$(find "$temporary" -mindepth 1 -maxdepth 1 -type f -print | sed 's#^.*/##' | LC_ALL=C sort)
expected=$(printf '%s\n' "${names[@]}" | LC_ALL=C sort)
[[ "$actual" == "$expected" ]] || {
    echo "prepare-beta1-unsigned: exported inventory differs" >&2
    exit 1
}
[[ "$(find "$temporary" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')" == "${#names[@]}" ]] || exit 1

if [[ -d "$output" ]]; then
    rmdir "$output"
fi
mv "$temporary" "$output"
trap - EXIT HUP INT TERM
echo "prepare-beta1-unsigned: exported ${#names[@]} flat unsigned native artifacts"
