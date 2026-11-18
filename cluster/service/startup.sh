#!/bin/sh
# Sourced only from an explicitly verified OEM startup integration.
[ "$#" -eq 2 ] || return 1
vbc_root="$1"
vbc_bootfile="$2"
[ -r "$vbc_bootfile" ] || return 1
# Prepare the RAM objects before daemon and OEM descendants can read them.
# Keep the sourced OEM shell umask unchanged.
(umask 077; "$vbc_root/bin/voboost-cluster-daemon" prepare-boot "$vbc_bootfile") || return 1
(umask 077; exec "$vbc_root/bin/voboost-cluster-daemon" daemon "$vbc_bootfile") &
VOBOOST_CLUSTER_BOOTFILE="$vbc_bootfile"
LD_PRELOAD="$vbc_root/bin/libvoboost-cluster-inject.so${LD_PRELOAD:+:$LD_PRELOAD}"
export VOBOOST_CLUSTER_BOOTFILE LD_PRELOAD
unset vbc_root vbc_bootfile
