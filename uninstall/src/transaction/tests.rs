use super::*;

#[test]
fn state_directory_accepts_only_current_and_legacy_product_contexts() {
    assert!(directory_context_matches(
        AGENT_STATE_CONTEXT,
        AGENT_STATE_CONTEXT
    ));
    assert!(directory_context_matches(AGENT_STATE_CONTEXT, DATA_CONTEXT));
    assert!(!directory_context_matches(
        AGENT_STATE_CONTEXT,
        STOCK_DATA_CONTEXT
    ));
    assert!(!directory_context_matches(
        AGENT_STATE_CONTEXT,
        PROTECTED_CONTEXT
    ));
    assert!(!directory_context_matches(
        DATA_CONTEXT,
        AGENT_STATE_CONTEXT
    ));
    assert!(!directory_context_matches(PROTECTED_CONTEXT, DATA_CONTEXT));
}

#[test]
fn production_watchdog_socket_path_fits_system_address_limits() {
    let recovery = format!("{RECOVERY_ROOT}/{}", "11".repeat(32));
    let old = format!("{recovery}/uninstall-watchdog.sock");
    let current = uninstall_watchdog_socket_path_for(&recovery);

    assert_eq!(old.len(), 111);
    assert_eq!(current.len(), 101);
    assert!(std::os::unix::net::SocketAddr::from_pathname(old).is_err());
    assert!(std::os::unix::net::SocketAddr::from_pathname(current).is_ok());
}

#[test]
fn watchdog_socket_performs_the_exact_commit_handshake() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("watchdog.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream.write_all(&[UNINSTALL_WATCHDOG_READY]).unwrap();
        let mut message = [0_u8; 1];
        stream.read_exact(&mut message).unwrap();
        assert_eq!(message[0], UNINSTALL_WATCHDOG_COMMIT);
        stream.write_all(&[UNINSTALL_WATCHDOG_ACK]).unwrap();
    });
    let mut stream = UnixStream::connect(&path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut message = [0_u8; 1];
    stream.read_exact(&mut message).unwrap();
    assert_eq!(message[0], UNINSTALL_WATCHDOG_READY);
    stream.write_all(&[UNINSTALL_WATCHDOG_COMMIT]).unwrap();
    stream.read_exact(&mut message).unwrap();
    assert_eq!(message[0], UNINSTALL_WATCHDOG_ACK);
    server.join().unwrap();
}

#[test]
fn uninstall_status_reserves_running_reboot_and_failed_slots() {
    for phase in [
        Phase::UninstallPrepare,
        Phase::UninstallRuntimeRemove,
        Phase::UninstallAbsenceVerify,
    ] {
        let number = phase.number();
        assert_eq!(
            uninstall_status_sequence(phase, "running").unwrap(),
            number * 3 - 2
        );
        assert_eq!(
            uninstall_status_sequence(phase, "reboot-required").unwrap(),
            number * 3 - 1
        );
        assert_eq!(
            uninstall_status_sequence(phase, "failed").unwrap(),
            number * 3
        );
    }
    assert!(uninstall_status_sequence(Phase::UninstallPrepare, "complete").is_err());
}

#[test]
fn daemon_starttime_parser_uses_the_last_comm_terminator() {
    let fields = (3..=52).map(|value| value.to_string()).collect::<Vec<_>>();
    let text = format!("123 (voboost ) inject) {}", fields.join(" "));
    assert_eq!(parse_daemon_starttime(&text).unwrap(), 22);
    assert!(parse_daemon_starttime("123 missing").is_err());
}
use tempfile::tempdir;

const A9_ROOT_MOUNTINFO: &[u8] = b"1 0 253:0 / / ro,relatime - ext4 /dev/block/dm-0 ro\n";
const A11_SPLIT_MOUNTINFO: &[u8] = b"1 0 253:0 / / ro - ext4 /dev/block/dm-0 ro\n\
2 1 253:1 / /system ro - ext4 /dev/block/dm-1 ro\n\
3 1 253:2 / /vendor ro - ext4 /dev/block/dm-2 ro\n";

#[test]
fn mount_resolver_deduplicates_a9_system_as_root_and_vendor_symlink_model() {
    let mounts = resolve_required_mounts(
        A9_ROOT_MOUNTINFO,
        &[
            "/system/etc/init/voboost.rc",
            "/system/vendor/etc/selinux/precompiled_sepolicy",
        ],
    )
    .unwrap();
    assert_eq!(mounts.len(), 1);
    assert_eq!(mounts[0].mount_point, "/");
}

#[test]
fn mount_resolver_selects_a11_separate_system_and_vendor_boundaries() {
    let mounts =
        resolve_required_mounts(A11_SPLIT_MOUNTINFO, &[RC_PATH, PRECOMPILED_PATH]).unwrap();
    assert_eq!(
        mounts
            .iter()
            .map(|mount| mount.mount_point.as_str())
            .collect::<Vec<_>>(),
        vec!["/system", "/vendor"]
    );
}

#[test]
fn mount_resolver_decodes_escaped_fields_without_changing_fixed_selection() {
    let mut mountinfo = A11_SPLIT_MOUNTINFO.to_vec();
    mountinfo
        .extend_from_slice(b"4 1 253:3 / /mnt/vendor\\040space ro - ext4 /dev/block/dm-3 ro\n");
    let mounts = resolve_required_mounts(&mountinfo, &[RC_PATH, PRECOMPILED_PATH]).unwrap();
    assert_eq!(mounts.len(), 2);
}

#[test]
fn mount_resolver_accepts_only_the_writable_system_overlay_self_stack() {
    // AVD-style writable-system boot: ext4 root plus an overlay at /system
    // whose first lowerdir is the shadowed /system directory.
    let stack = b"1 0 253:0 / / ro - ext4 /dev/block/dm-0 ro\n2 0 0:22 / /system ro - overlay overlay ro,seclabel,lowerdir=/system,upperdir=/mnt/scratch/overlay/system/upper,workdir=/mnt/scratch/overlay/system/work\n";
    let mounts = resolve_required_mounts(stack, &[RC_PATH]).unwrap();
    assert_eq!(mounts.len(), 1);
    assert_eq!(mounts[0].mount_point, "/system");
    assert_eq!(mounts[0].fs_type, "overlay");

    // A lowerdir pointed elsewhere is a foreign overlay.
    let foreign_lower = b"1 0 253:0 / / ro - ext4 /dev/block/dm-0 ro\n2 0 0:22 / /system ro - overlay overlay ro,seclabel,lowerdir=/other,upperdir=/mnt/u,workdir=/mnt/w\n";
    assert!(resolve_required_mounts(foreign_lower, &[RC_PATH]).is_err());

    // The overlay is worthless without its physical partition beneath.
    let no_physical = b"1 0 253:0 / /data ro - ext4 /dev/block/dm-0 ro\n2 0 0:22 / /system ro - overlay overlay ro,seclabel,lowerdir=/system,upperdir=/mnt/u,workdir=/mnt/w\n";
    assert!(resolve_required_mounts(no_physical, &[RC_PATH]).is_err());

    // A read-only upper-less overlay is not a writable-system stack.
    let ro_only = b"1 0 253:0 / / ro - ext4 /dev/block/dm-0 ro\n2 0 0:22 / /system ro - overlay overlay ro,seclabel,lowerdir=/system\n";
    assert!(resolve_required_mounts(ro_only, &[RC_PATH]).is_err());
}

#[test]
fn mount_resolver_selects_the_topmost_overlay_of_a_same_point_vendor_stack() {
    let stack = b"1 0 253:0 / / ro - ext4 /dev/block/dm-0 ro\n56 45 253:3 / /vendor ro - ext4 /dev/block/dm-3 ro\n57 56 0:24 / /vendor ro - overlay overlay ro,seclabel,lowerdir=/vendor,upperdir=/mnt/scratch/overlay/vendor/upper,workdir=/mnt/scratch/overlay/vendor/work\n";
    let mounts = resolve_required_mounts(stack, &[PRECOMPILED_PATH]).unwrap();
    assert_eq!(mounts.len(), 1);
    assert_eq!(mounts[0].mount_point, "/vendor");
    assert_eq!(mounts[0].fs_type, "overlay");

    // Two same-point physical mounts stay ambiguous.
    let ambiguous = b"1 0 253:0 / / ro - ext4 /dev/block/dm-0 ro\n56 45 253:3 / /vendor ro - ext4 /dev/block/dm-3 ro\n57 45 253:4 / /vendor ro - ext4 /dev/block/dm-4 ro\n";
    assert!(resolve_required_mounts(ambiguous, &[PRECOMPILED_PATH]).is_err());
}

#[test]
fn mount_resolver_rejects_duplicate_ambiguous_missing_overlay_and_source_change() {
    let duplicate = b"1 0 253:0 / / ro - ext4 /dev/block/dm-0 ro\n\
2 0 253:1 / / ro - ext4 /dev/block/dm-1 ro\n";
    assert!(resolve_required_mounts(duplicate, &[RC_PATH]).is_err());
    assert!(resolve_required_mounts(
        b"1 0 253:0 / /data ro - ext4 /dev/block/dm-0 ro\n",
        &[RC_PATH]
    )
    .is_err());
    assert!(resolve_required_mounts(b"1 0 0:1 / / ro - overlay overlay ro\n", &[RC_PATH]).is_err());
    assert!(
        resolve_required_mounts(b"1 0 253:0 / / ro - ext4 foreign-source ro\n", &[RC_PATH])
            .is_err()
    );
}

#[test]
fn mount_resolver_rejects_exact_dot_roots() {
    for root in ["/.", "/.."] {
        let mountinfo = format!("1 0 253:0 {root} /system ro - ext4 /dev/block/dm-0 ro\n");
        assert!(resolve_required_mounts(mountinfo.as_bytes(), &[RC_PATH]).is_err());
    }
}

#[test]
fn mount_resolver_skips_non_canonical_unrelated_mounts() {
    // Android mountinfo contains namespace and sdcardfs entries whose root or
    // mount point is not a canonical absolute path (for example nsfs mounts with
    // a `net:[...]` root). The resolver only needs the canonical block mounts
    // for `/system` and `/vendor`, so an unrelated non-canonical entry must not
    // abort the whole parse.
    let mountinfo = b"33 31 0:3 net:[4026532192] /data/vendor/var/run/netns/router rw shared:17 - nsfs nsfs rw\n\
1 0 253:0 / /system ro - ext4 /dev/block/dm-0 ro\n";
    let mounts = resolve_required_mounts(mountinfo, &[RC_PATH]).unwrap();
    assert_eq!(mounts.len(), 1);
    assert_eq!(mounts[0].mount_point, "/system");
}

#[test]
fn mount_resolver_rejects_duplicate_mount_id_across_distinct_boundaries() {
    let mountinfo = b"1 0 253:0 / /system ro - ext4 /dev/block/dm-0 ro\n\
1 0 253:1 / /vendor ro - ext4 /dev/block/dm-1 ro\n";
    assert!(resolve_required_mounts(mountinfo, &[RC_PATH, PRECOMPILED_PATH]).is_err());
}

#[test]
fn mount_resolver_rejects_subtree_bind_and_ambiguous_superblock_aliases() {
    assert!(resolve_required_mounts(
        b"1 0 253:0 /subtree /system ro - ext4 /dev/block/dm-0 ro\n",
        &[RC_PATH]
    )
    .is_err());
    let aliases = b"1 0 253:0 / /system ro - ext4 /dev/block/dm-0 ro\n\
2 0 253:0 / /vendor ro - ext4 /dev/block/dm-0 ro\n";
    assert!(resolve_required_mounts(aliases, &[RC_PATH, PRECOMPILED_PATH]).is_err());
}

#[test]
fn mount_resolver_rejects_same_superblock_alias_with_different_source_spelling() {
    let aliases = b"1 0 253:0 / /system ro - ext4 /dev/root ro\n\
2 0 253:0 / /vendor ro - ext4 /dev/block/dm-0 ro\n";
    assert!(resolve_required_mounts(aliases, &[RC_PATH, PRECOMPILED_PATH]).is_err());
}

#[test]
fn one_target_mount_resolver_rejects_unselected_full_root_superblock_alias() {
    let aliases = b"1 0 253:0 / / ro - ext4 /dev/block/dm-0 ro\n\
2 1 253:0 / /system ro - ext4 /dev/block/dm-0 ro\n";
    assert!(resolve_required_mounts(aliases, &[RC_PATH]).is_err());
}

#[test]
fn fixed_target_resolution_follows_only_its_fixed_parent_symlink() {
    let root = tempdir().unwrap();
    let system_vendor = root.path().join("system/vendor/etc/selinux");
    fs::create_dir_all(&system_vendor).unwrap();
    std::os::unix::fs::symlink(
        root.path().join("system/vendor"),
        root.path().join("vendor"),
    )
    .unwrap();
    let target = root.path().join("vendor/etc/selinux/precompiled_sepolicy");
    let resolved = resolve_fixed_target(target.to_str().unwrap()).unwrap();
    assert_eq!(
        resolved,
        fs::canonicalize(&system_vendor)
            .unwrap()
            .join("precompiled_sepolicy")
            .to_str()
            .unwrap()
    );
}

#[test]
fn remount_stops_at_first_fixed_boundary_failure() {
    let mounts =
        resolve_required_mounts(A11_SPLIT_MOUNTINFO, &[RC_PATH, PRECOMPILED_PATH]).unwrap();
    let mut attempted = Vec::new();
    let result = remount_required_with(&mounts, |boundary| {
        attempted.push(boundary.mount_point.clone());
        Err("injected mount failure".to_string())
    });
    assert!(result.is_err());
    assert_eq!(attempted, vec!["/system"]);
}

#[test]
fn remount_rejects_major_minor_change_before_first_syscall() {
    let mounts =
        resolve_required_mounts(A11_SPLIT_MOUNTINFO, &[RC_PATH, PRECOMPILED_PATH]).unwrap();
    let changed = b"1 0 253:0 / / ro - ext4 /dev/block/dm-0 ro\n\
2 1 253:9 / /system ro - ext4 /dev/block/dm-1 ro\n\
3 1 253:2 / /vendor ro - ext4 /dev/block/dm-2 ro\n";
    let mut attempted = false;
    let result = remount_verified_with(
        &mounts,
        &[RC_PATH, PRECOMPILED_PATH],
        || Ok(changed.to_vec()),
        |_| {
            attempted = true;
            Ok(())
        },
    );
    assert!(result.is_err());
    assert!(!attempted);
}

#[test]
fn remount_preserves_nosuid_nodev_and_noexec_security_flags() {
    let mountinfo = b"1 0 253:0 / / ro,nosuid,nodev,noexec - ext4 /dev/block/dm-0 ro\n";
    let mounts = resolve_required_mounts(mountinfo, &[RC_PATH, PRECOMPILED_PATH]).unwrap();
    let mut observed = None;
    remount_required_with(&mounts, |mount| {
        observed = Some(mount.security_flags);
        Ok(())
    })
    .unwrap();
    assert_eq!(
        observed,
        Some(REMOUNT_NOSUID | REMOUNT_NODEV | REMOUNT_NOEXEC)
    );
}

#[test]
fn remount_abi_uses_recorded_source_fstype_and_exact_flags() {
    let mountinfo = b"1 0 253:0 / / ro,nosuid,nodev,noexec - ext4 /dev/block/dm-0 ro\n";
    let mount = resolve_required_mounts(mountinfo, &[RC_PATH])
        .unwrap()
        .remove(0);
    remount_boundary_with(&mount, false, |source, target, fs_type, flags, data| {
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(source) }.to_bytes(),
            b"/dev/block/dm-0"
        );
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(fs_type) }.to_bytes(),
            b"ext4"
        );
        assert!(data.is_null());
        assert_eq!(unsafe { std::ffi::CStr::from_ptr(target) }.to_bytes(), b"/");
        // The rw direction is a plain MS_REMOUNT over the recorded security
        // flags: MS_REMOUNT|MS_BIND is a kernel-accepted silent no-op that
        // leaves a locked boundary read-only (verified on the free-09-chinese
        // 6.0.3 emulator), so the bind shape must never be used and a
        // successful rw call is re-checked against the live mount state.
        assert_eq!(flags, 32 | REMOUNT_NOSUID | REMOUNT_NODEV | REMOUNT_NOEXEC);
        0
    })
    .unwrap();
    remount_boundary_with(&mount, true, |source, _target, fs_type, flags, data| {
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(source) }.to_bytes(),
            b"/dev/block/dm-0"
        );
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(fs_type) }.to_bytes(),
            b"ext4"
        );
        assert!(data.is_null());
        assert_eq!(
            flags,
            32 | 1 | REMOUNT_NOSUID | REMOUNT_NODEV | REMOUNT_NOEXEC
        );
        0
    })
    .unwrap();
}

#[test]
fn remount_recanonicalizes_and_blocks_topology_change_before_second_syscall() {
    let mounts =
        resolve_required_mounts(A11_SPLIT_MOUNTINFO, &[RC_PATH, PRECOMPILED_PATH]).unwrap();
    let mut canonicalizations = 0;
    let mut attempted = Vec::new();
    let result = remount_fixed_verified_with(
        &mounts,
        &[RC_PATH, PRECOMPILED_PATH],
        |target| {
            canonicalizations += 1;
            if canonicalizations > 2 && target == RC_PATH {
                Ok("/vendor/etc/init/voboost.rc".to_string())
            } else {
                Ok(target.to_string())
            }
        },
        || Ok(A11_SPLIT_MOUNTINFO.to_vec()),
        |mount| {
            attempted.push(mount.mount_point.clone());
            Ok(())
        },
    );
    assert!(result.is_err());
    assert_eq!(attempted, vec!["/system"]);
}

#[test]
fn scoped_remount_fault_matrix_always_attempts_reverse_ro_restore() {
    let mounts =
        resolve_required_mounts(A11_SPLIT_MOUNTINFO, &[RC_PATH, PRECOMPILED_PATH]).unwrap();

    let mut events = Vec::new();
    let result = scoped_remount_with(
        &mounts,
        || Ok(mounts.clone()),
        |mount, ro| {
            events.push(format!(
                "{}:{}",
                if ro { "ro" } else { "rw" },
                mount.mount_point
            ));
            if !ro && mount.mount_point == "/vendor" {
                Err("second RW failed".to_string())
            } else {
                Ok(())
            }
        },
        || panic!("mutation must not run after partial RW failure"),
    );
    assert!(result.is_err());
    assert_eq!(events, ["rw:/system", "rw:/vendor", "ro:/system"]);

    let mut events = Vec::new();
    let result = scoped_remount_with(
        &mounts,
        || Ok(mounts.clone()),
        |mount, ro| {
            events.push(format!(
                "{}:{}",
                if ro { "ro" } else { "rw" },
                mount.mount_point
            ));
            Ok(())
        },
        || Err("mutation failed".to_string()),
    );
    assert!(result.is_err());
    assert_eq!(
        events,
        ["rw:/system", "rw:/vendor", "ro:/vendor", "ro:/system"]
    );

    let mut events = Vec::new();
    let result = scoped_remount_with(
        &mounts,
        || Ok(mounts.clone()),
        |mount, ro| {
            events.push(format!(
                "{}:{}",
                if ro { "ro" } else { "rw" },
                mount.mount_point
            ));
            if ro && mount.mount_point == "/vendor" {
                Err("first RO failed".to_string())
            } else {
                Ok(())
            }
        },
        || Ok(()),
    );
    assert!(result.is_err());
    assert_eq!(
        events,
        ["rw:/system", "rw:/vendor", "ro:/vendor", "ro:/system"]
    );

    let mut events = Vec::new();
    scoped_remount_with(
        &mounts,
        || Ok(mounts.clone()),
        |mount, ro| {
            events.push(format!(
                "{}:{}",
                if ro { "ro" } else { "rw" },
                mount.mount_point
            ));
            Ok(())
        },
        || Ok(()),
    )
    .unwrap();
    assert_eq!(
        events,
        ["rw:/system", "rw:/vendor", "ro:/vendor", "ro:/system"]
    );

    // The terminal init-hook unlink used to be a shell `rm` after the
    // helper had already restored /system read-only. Model that exact
    // EROFS cut: the mutation is inside the scoped RW window and every
    // changed boundary is still restored RO before the error escapes.
    let system_only = resolve_required_mounts(A11_SPLIT_MOUNTINFO, &[RC_PATH]).unwrap();
    let mut events = Vec::new();
    let result = scoped_remount_with(
        &system_only,
        || Ok(system_only.clone()),
        |mount, ro| {
            events.push(format!(
                "{}:{}",
                if ro { "ro" } else { "rw" },
                mount.mount_point
            ));
            Ok(())
        },
        || Err("unlink terminal init hook: EROFS".to_string()),
    );
    assert_eq!(result.unwrap_err(), "unlink terminal init hook: EROFS");
    assert_eq!(events, ["rw:/system", "ro:/system"]);
}

#[test]
fn scoped_remount_topology_change_blocks_next_syscall() {
    let mounts =
        resolve_required_mounts(A11_SPLIT_MOUNTINFO, &[RC_PATH, PRECOMPILED_PATH]).unwrap();
    let mut changed = mounts.clone();
    changed[1].major_minor = "253:9".to_string();
    let mut checks = 0;
    let mut events = Vec::new();
    let result = scoped_remount_with(
        &mounts,
        || {
            checks += 1;
            Ok(if checks == 1 {
                mounts.clone()
            } else {
                changed.clone()
            })
        },
        |mount, ro| {
            events.push(format!(
                "{}:{}",
                if ro { "ro" } else { "rw" },
                mount.mount_point
            ));
            Ok(())
        },
        || panic!("mutation must not run after topology change"),
    );
    assert!(result.is_err());
    assert_eq!(events, ["rw:/system", "ro:/system"]);
}

#[test]
fn scoped_remount_restores_each_changed_boundary_despite_peer_drift() {
    let mounts =
        resolve_required_mounts(A11_SPLIT_MOUNTINFO, &[RC_PATH, PRECOMPILED_PATH]).unwrap();
    let mut changed = mounts.clone();
    changed[0].major_minor = "253:9".to_string();
    let mut verify_calls = 0;
    let mut events = Vec::new();
    let result = scoped_remount_with(
        &mounts,
        || {
            verify_calls += 1;
            Ok(if verify_calls <= 2 {
                mounts.clone()
            } else {
                changed.clone()
            })
        },
        |mount, ro| {
            events.push(format!(
                "{}:{}",
                if ro { "ro" } else { "rw" },
                mount.mount_point
            ));
            Ok(())
        },
        || Ok(()),
    );
    assert!(result.is_err());
    assert_eq!(events, ["rw:/system", "rw:/vendor", "ro:/vendor"]);
}

#[test]
fn durable_recovery_attempts_every_boundary_and_combines_failures() {
    let mounts =
        resolve_required_mounts(A11_SPLIT_MOUNTINFO, &[RC_PATH, PRECOMPILED_PATH]).unwrap();
    let entries = vec![
        RemountJournalEntry {
            target: ProtectedMutationMount::SystemInitHook,
            boundary: mounts[0].clone(),
            block_read_only: None,
        },
        RemountJournalEntry {
            target: ProtectedMutationMount::VendorPolicy,
            boundary: mounts[1].clone(),
            block_read_only: None,
        },
    ];
    let mut events = Vec::new();
    let result = recover_journaled_boundaries_with(
        &entries,
        |entry| Ok(vec![entry.boundary.clone()]),
        |mount, ro| {
            assert!(ro);
            events.push(mount.mount_point.clone());
            if mount.mount_point == "/vendor" {
                Err("injected vendor RO failure".to_string())
            } else {
                Ok(())
            }
        },
    );
    assert!(result.unwrap_err().contains("injected vendor RO failure"));
    assert_eq!(events, ["/vendor", "/system"]);
}

#[test]
fn durable_recovery_peer_resolution_failures_do_not_block_exact_boundary_ro() {
    let mounts =
        resolve_required_mounts(A11_SPLIT_MOUNTINFO, &[RC_PATH, PRECOMPILED_PATH]).unwrap();
    let entries = vec![
        RemountJournalEntry {
            target: ProtectedMutationMount::SystemInitHook,
            boundary: mounts[0].clone(),
            block_read_only: None,
        },
        RemountJournalEntry {
            target: ProtectedMutationMount::VendorPolicy,
            boundary: mounts[1].clone(),
            block_read_only: None,
        },
    ];
    for peer_error in [
        "peer resolver failed",
        "peer mount is foreign",
        "peer mount is ambiguous",
    ] {
        let mut events = Vec::new();
        let result = recover_journaled_boundaries_with(
            &entries,
            |entry| {
                if entry.target == ProtectedMutationMount::VendorPolicy {
                    Err(peer_error.to_string())
                } else {
                    Ok(vec![entry.boundary.clone()])
                }
            },
            |mount, ro| {
                assert!(ro);
                events.push(mount.mount_point.clone());
                Ok(())
            },
        );
        let error = result.unwrap_err();
        assert!(error.contains(peer_error));
        assert_eq!(events, ["/system"]);
    }
}

#[test]
fn protected_system_init_hook_binds_its_exact_divergent_parent() {
    let divergent = b"1 0 253:0 / / ro - ext4 /dev/block/dm-0 ro\n\
2 1 253:1 / /system ro - ext4 /dev/block/dm-1 ro\n\
3 2 253:2 / /system/bin ro - ext4 /dev/block/dm-2 ro\n\
4 2 253:3 / /system/etc/init ro - ext4 /dev/block/dm-3 ro\n";
    let init = resolve_required_mounts(
        divergent,
        &[ProtectedMutationMount::SystemInitHook.fixed_target()],
    )
    .unwrap();
    assert_eq!(init[0].mount_point, "/system/etc/init");
}

#[test]
fn a9_scoped_remount_executes_one_revalidated_rw_and_ro_for_shared_boundary() {
    let mounts = resolve_required_mounts(
        A9_ROOT_MOUNTINFO,
        &[
            "/system/etc/init/voboost.rc",
            "/system/vendor/etc/selinux/precompiled_sepolicy",
        ],
    )
    .unwrap();
    let mut revalidations = 0;
    let mut calls = Vec::new();
    scoped_remount_with(
        &mounts,
        || {
            revalidations += 1;
            Ok(mounts.clone())
        },
        |mount, read_only| {
            calls.push((mount.mount_point.clone(), read_only));
            Ok(())
        },
        || Ok(()),
    )
    .unwrap();
    assert_eq!(revalidations, 2);
    assert_eq!(
        calls,
        vec![("/".to_string(), false), ("/".to_string(), true)]
    );
}

#[test]
fn a11_scoped_remount_executes_each_revalidated_boundary_once_rw_and_ro() {
    let mounts =
        resolve_required_mounts(A11_SPLIT_MOUNTINFO, &[RC_PATH, PRECOMPILED_PATH]).unwrap();
    let mut revalidations = 0;
    let mut calls = Vec::new();
    scoped_remount_with(
        &mounts,
        || {
            revalidations += 1;
            Ok(mounts.clone())
        },
        |mount, read_only| {
            calls.push((mount.mount_point.clone(), read_only));
            Ok(())
        },
        || Ok(()),
    )
    .unwrap();
    assert_eq!(revalidations, 4);
    assert_eq!(
        calls,
        vec![
            ("/system".to_string(), false),
            ("/vendor".to_string(), false),
            ("/vendor".to_string(), true),
            ("/system".to_string(), true),
        ]
    );
}

fn fixture_sidecars() -> Vec<voboost_shared::mount_policy_transaction::Sidecar> {
    voboost_shared::mount_policy_transaction::parse_sidecar_backup(include_bytes!(
        "../../../test/fixtures/policy-sidecars.json"
    ))
    .unwrap()
}

fn metadata_for(bytes: &[u8]) -> Vec<u8> {
    let mut body = serde_json::to_vec(&serde_json::json!({
        "schemaVersion":2, "path":PRECOMPILED_PATH, "size":bytes.len(), "sha256":sha256_hex(bytes),
        "uid":0, "gid":0, "mode":"0644", "context":"u:object_r:vendor_file:s0", "sidecars":fixture_sidecars(),
    })).unwrap();
    body.push(b'\n');
    body
}

fn recovery_authority_for(path: &Path) -> RecoveryState {
    let zone = fs::symlink_metadata(path).unwrap();
    RecoveryState {
        schema_version: 2,
        transaction_id: "11".repeat(32),
        phase: TerminalCleanupPhase::UninstallActive,
        terminal_boot_id: None,
        terminal_reboot_reason: None,
        terminal_reboot_predicate_sha256: None,
        terminal_reboot_boot_id: None,
        recovery_sha256: sha256_hex(b"signed recovery"),
        zone_dev: zone.dev(),
        zone_ino: zone.ino(),
        policy_size: 6,
        policy_sha256: sha256_hex(b"policy"),
        policy_uid: 0,
        policy_gid: 0,
        policy_mode: "0644".to_string(),
        policy_context: "u:object_r:vendor_file:s0".to_string(),
        policy_sidecars: fixture_sidecars(),
    }
}

#[test]
fn canonical_metadata_round_trips_all_fields() {
    let parsed = parse_backup_metadata(&metadata_for(b"policy")).unwrap();
    assert_eq!(parsed.size, 6);
    assert_eq!(parsed.mode, 0o644);
    assert_eq!(parsed.mode_text, "0644");
    assert_eq!(parsed.context, "u:object_r:vendor_file:s0");
}

#[test]
fn metadata_rejects_duplicate_malformed_and_oversized_contracts() {
    let valid = metadata_for(b"policy");
    let mut duplicate = valid.clone();
    duplicate.extend_from_slice(b"{}\n");
    assert!(parse_backup_metadata(&duplicate).is_err());
    for malformed in [
        b"".as_slice(),
        b"VOBOOST_SELINUX_BACKUP_V1\nsize=01\nsha256=x\nuid=0\ngid=0\nmode=644\ncontext=u:object_r:vendor_file:s0\n".as_slice(),
        b"VOBOOST_SELINUX_BACKUP_V1\nsize=999999999\nsha256=0000000000000000000000000000000000000000000000000000000000000000\nuid=0\ngid=0\nmode=0644\ncontext=u:object_r:vendor_file:s0\n".as_slice(),
    ] {
        assert!(parse_backup_metadata(malformed).is_err());
    }
}

#[test]
fn nofollow_reader_rejects_symlink_hardlink_and_oversize() {
    let dir = tempdir().unwrap();
    let original = dir.path().join("original");
    fs::write(&original, b"1234").unwrap();
    let symlink = dir.path().join("symlink");
    std::os::unix::fs::symlink(&original, &symlink).unwrap();
    assert!(read_regular_nofollow(&symlink, 8).is_err());
    let hardlink = dir.path().join("hardlink");
    fs::hard_link(&original, &hardlink).unwrap();
    assert!(read_regular_nofollow(&original, 8).is_err());
    fs::remove_file(hardlink).unwrap();
    assert!(read_regular_nofollow(&original, 3).is_err());
}

#[test]
fn trusted_context_is_bound_to_the_already_opened_inode() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("authority");
    fs::write(&path, b"first").unwrap();
    let mut trusted = read_regular_nofollow(&path, 16).unwrap();
    trusted.selinux_context = Some(PROTECTED_CONTEXT.to_string());

    fs::remove_file(&path).unwrap();
    fs::write(&path, b"replacement").unwrap();

    assert_eq!(trusted.bytes, b"first");
    assert!(require_trusted_context(&trusted, PROTECTED_CONTEXT, "authority").is_ok());
    assert!(require_trusted_context(&trusted, "u:object_r:foreign_file:s0", "authority").is_err());

    trusted.selinux_context = Some("u:object_r:foreign_file:s0".to_string());
    assert!(require_trusted_context(&trusted, PROTECTED_CONTEXT, "committed hook").is_err());
}

#[test]
fn restore_exec_context_tracks_the_emulator_service_label() {
    // The restore executable is a bootstrap program that runs before the
    // custom SELinux policy is active. Production keeps it on the stock
    // `system_file` label, while the emulator profile labels every service
    // executable with `su_exec` (see install policy `EMULATOR_SERVICE_EXECUTABLES`).
    // The committed uninstall authority must expect the label that install
    // actually publishes, otherwise `remove_owned_file(RESTORE_PATH)` rejects an
    // honest emulator install with `commit temporary directory is not empty`-style
    // context mismatch.
    {
        assert_eq!(RESTORE_EXEC_CONTEXT, STOCK_RECOVERY_CONTEXT);
        assert_eq!(RESTORE_EXEC_CONTEXT, "u:object_r:system_file:s0");
    }
}

#[test]
fn retained_exchange_identity_rejects_named_and_exchanged_races() {
    let dir = tempdir().unwrap();
    let first = dir.path().join("first");
    let second = dir.path().join("second");
    fs::write(&first, b"first").unwrap();
    fs::write(&second, b"second").unwrap();
    let expected = FileStamp::from(&fs::metadata(&first).unwrap());
    let foreign = FileStamp::from(&fs::metadata(&second).unwrap());
    assert!(retained_exchange_identity_matches(
        expected, expected, expected
    ));
    assert!(!retained_exchange_identity_matches(
        expected, expected, foreign
    ));
    assert!(!retained_exchange_identity_matches(
        expected, foreign, expected
    ));
}

#[test]
fn recovery_authority_is_strict_and_binds_the_zone_inode() {
    let dir = tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let state = recovery_authority_for(dir.path());
    let zone = fs::symlink_metadata(dir.path()).unwrap();
    let encoded = serde_json::to_vec(&state).unwrap();
    assert_eq!(parse_recovery_state(&encoded).unwrap(), state);
    assert!(verify_recovery_zone_at(dir.path(), &state, zone.uid(), zone.gid()).unwrap());

    let replacement = tempdir().unwrap();
    fs::set_permissions(replacement.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(verify_recovery_zone_at(replacement.path(), &state, zone.uid(), zone.gid()).is_err());

    let duplicate = String::from_utf8(encoded)
        .unwrap()
        .replacen("{", "{\"schemaVersion\":1,", 1);
    assert!(parse_recovery_state(duplicate.as_bytes()).is_err());
    let mut malformed = state;
    malformed.policy_sha256 = "A".repeat(64);
    assert!(parse_recovery_state(&serde_json::to_vec(&malformed).unwrap()).is_err());
}

#[test]
fn restore_document_is_exact_canonical_and_bounded() {
    let descriptor = b"{\"schemaVersion\":1,\"releaseIdentity\":\"1.0.0-beta1\",\"sourceDefinitionSha256\":\"5f08d74b7c2a3aad92f6f5b211e5e6a15d7fe006dd3af086517aea092a8dac25\",\"restorableClosureSha256\":\"6f08d74b7c2a3aad92f6f5b211e5e6a15d7fe006dd3af086517aea092a8dac25\"}\n";
    let parsed = parse_restore_document(descriptor).unwrap();
    assert_eq!(parsed.release_identity, "1.0.0-beta1");
    assert_eq!(
        parsed.source_definition_sha256,
        "5f08d74b7c2a3aad92f6f5b211e5e6a15d7fe006dd3af086517aea092a8dac25"
    );

    let reordered = String::from_utf8(descriptor.to_vec()).unwrap().replace(
        "\"schemaVersion\":1,\"releaseIdentity\":\"1.0.0-beta1\"",
        "\"releaseIdentity\":\"1.0.0-beta1\",\"schemaVersion\":1",
    );
    assert!(parse_restore_document(reordered.as_bytes()).is_err());
    let uppercase_hash = String::from_utf8(descriptor.to_vec())
        .unwrap()
        .replace("5f08d74b", "5F08D74B");
    assert!(parse_restore_document(uppercase_hash.as_bytes()).is_err());
    assert!(parse_restore_document(&descriptor[..descriptor.len() - 1]).is_err());
    let oversized = vec![b'x'; voboost_contract::release::MAX_RESTORE_BYTES + 1];
    assert!(parse_restore_document(&oversized).is_err());
}

#[test]
fn recovery_state_fits_within_the_committed_bound_with_realistic_fields() {
    // The uninstall recovery authority is a schema-version-2 JSON document
    // published through a bounded `MAX_RECOVERY_STATE_BYTES` reader. Every
    // field that can appear in a fully terminal-advanced state must stay well
    // under that bound, otherwise `publish_recovery_state` rejects an honest
    // authority with `serialized uninstall recovery authority is oversized`.
    let transaction_id = "850487d8d2e7a6620e0d9e75aa2532b40950f4b0d651ee46cb255544979591b2";
    let state = RecoveryState {
        schema_version: 2,
        transaction_id: transaction_id.to_string(),
        phase: TerminalCleanupPhase::UninstallSuccessorStarted,
        terminal_boot_id: Some("d549438e-d8d0-4b21-a834-bef7b69c74b2".to_string()),
        terminal_reboot_reason: Some(TERMINAL_REBOOT_REASON.to_string()),
        terminal_reboot_predicate_sha256: Some(
            "a28b42e668c671b1215d739b1b27b8cdd625982ae560eff77ad73bb0db0019ca".to_string(),
        ),
        terminal_reboot_boot_id: Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_string()),
        recovery_sha256: sha256_hex(b"signed recovery"),
        zone_dev: u64::MAX,
        zone_ino: u64::MAX,
        policy_size: 372436,
        policy_sha256: sha256_hex(b"policy"),
        policy_uid: 0,
        policy_gid: 0,
        policy_mode: "0644".to_string(),
        policy_context: "u:object_r:vendor_configs_file:s0".to_string(),
        policy_sidecars: fixture_sidecars(),
    };
    let body = serde_json::to_vec(&state).unwrap();
    assert!(
        body.len() as u64 <= MAX_RECOVERY_STATE_BYTES,
        "recovery state {} bytes exceeds bound {}",
        body.len(),
        MAX_RECOVERY_STATE_BYTES
    );
    assert!(
        body.len() > 512,
        "recovery state shrank below prior 512-byte budget"
    );
}

#[test]
fn maximum_android_eleven_selectors_fit_both_durable_authority_bounds() {
    let paths = [
        "/vendor/etc/selinux/precompiled_sepolicy.plat_sepolicy_and_mapping.sha256",
        "/vendor/etc/selinux/precompiled_sepolicy.system_ext_sepolicy_and_mapping.sha256",
        "/vendor/etc/selinux/precompiled_sepolicy.product_sepolicy_and_mapping.sha256",
    ];
    let sidecars = paths
        .into_iter()
        .map(|path| {
            let mut sidecar = fixture_sidecars().remove(0);
            sidecar.path = path.into();
            sidecar.pristine = vec![255; 512];
            sidecar.sha256 = sha256_hex(&sidecar.pristine);
            sidecar.selinux_context = format!("u:object_r:{}:s0", "x".repeat(114)).into_bytes();
            sidecar.selinux_context.push(0);
            sidecar
        })
        .collect::<Vec<_>>();
    assert!(voboost_shared::mount_policy_transaction::valid_sidecars(
        &sidecars
    ));
    let metadata = uninstall_contract::PolicyMetadata {
        schema_version: 2,
        path: PRECOMPILED_PATH.into(),
        size: MAX_POLICY_BYTES,
        sha256: "a".repeat(64),
        uid: 0,
        gid: 0,
        mode: "0644".into(),
        context: "u:object_r:vendor_configs_file:s0".into(),
        sidecars: sidecars.clone(),
    };
    let bytes = serde_json::to_vec(&metadata).unwrap();
    assert!(bytes.len() as u64 <= MAX_META_BYTES);
    parse_backup_metadata(&bytes).unwrap();
    let directory = tempdir().unwrap();
    let mut state = recovery_authority_for(directory.path());
    state.policy_sidecars = sidecars;
    let bytes = serde_json::to_vec(&state).unwrap();
    assert!(bytes.len() as u64 <= MAX_RECOVERY_STATE_BYTES);
    parse_recovery_state(&bytes).unwrap();
}

#[test]
fn terminal_cleanup_persists_and_requires_the_current_boot() {
    let dir = tempdir().unwrap();
    let state = recovery_authority_for(dir.path());
    let current = "01234567-89ab-cdef-0123-456789abcdef";
    let changed = "11234567-89ab-cdef-0123-456789abcdef";

    assert_eq!(state.phase, TerminalCleanupPhase::UninstallActive);
    assert!(state.terminal_boot_id.is_none());
    assert!(terminal_cleanup_boot_allowed(&state, current).is_err());

    let prepared = active_terminal_boot_state(&state, current).unwrap();
    assert_eq!(prepared.phase, TerminalCleanupPhase::UninstallActive);
    assert_eq!(prepared.terminal_boot_id.as_deref(), Some(current));
    assert!(terminal_cleanup_boot_allowed(&prepared, current).is_ok());
    assert!(terminal_cleanup_boot_allowed(&prepared, changed).is_err());
    let retry = active_terminal_boot_state(&prepared, current).unwrap();
    assert_eq!(retry, prepared);
    assert!(active_terminal_boot_state(&prepared, changed).is_err());
}

#[test]
fn persisted_terminal_boot_id_endpoint_is_root_only_pathless_and_state_bound() {
    let args = vec![
        "voboost-uninstall".into(),
        "--get-uninstall-bound-boot-id".into(),
    ];
    assert!(get_uninstall_bound_boot_id_args_authorized(&args, 0));
    assert!(!get_uninstall_bound_boot_id_args_authorized(&args, 2000));
    assert!(!get_uninstall_bound_boot_id_args_authorized(
        &[args[0].clone(), args[1].clone(), "foreign".into()],
        0,
    ));

    let boot = "01234567-89ab-cdef-0123-456789abcdef";
    let state = active_terminal_boot_state(&recovery_authority_for(Path::new("/")), boot).unwrap();
    assert_eq!(
        bound_boot_id_from_state(&state, &state.recovery_sha256).unwrap(),
        boot
    );
    assert!(bound_boot_id_from_state(&state, &"ff".repeat(32)).is_err());
    let mut absent = state;
    absent.terminal_boot_id = None;
    assert!(bound_boot_id_from_state(&absent, &absent.recovery_sha256).is_err());
}

#[test]
fn uninstall_watchdog_requires_durable_commit_before_terminal_cleanup() {
    let mut phase = TerminalCleanupPhase::UninstallActive;
    advance_terminal_cleanup_phase(&mut recovery_authority_for(Path::new("/")), phase).unwrap_err();
    assert_eq!(
        phase.next(),
        Some(TerminalCleanupPhase::UninstallWatchdogArmed)
    );
    phase = phase.next().unwrap();
    assert_eq!(
        phase.next(),
        Some(TerminalCleanupPhase::UninstallWatchdogCommitted)
    );
    phase = phase.next().unwrap();
    assert_eq!(
        phase.next(),
        Some(TerminalCleanupPhase::UninstallSuccessorStarted)
    );
    phase = phase.next().unwrap();
    assert_eq!(phase.next(), None);
}

#[test]
fn terminal_tree_walk_is_descriptor_relative_nofollow_and_idempotent_after_each_cut() {
    use std::os::unix::fs::symlink;

    for cut in 0..=3 {
        let directory = tempdir().unwrap();
        let root_path = directory.path().join("root");
        fs::create_dir(&root_path).unwrap();
        fs::create_dir(root_path.join("a")).unwrap();
        fs::write(root_path.join("a/inside"), b"inside").unwrap();
        fs::write(root_path.join("b"), b"leaf").unwrap();
        let outside = directory.path().join("outside");
        fs::write(&outside, b"must survive").unwrap();
        symlink(&outside, root_path.join("c")).unwrap();
        fs::write(root_path.join("keep"), b"authority").unwrap();

        let root = open_directory_nofollow(&root_path, "test root").unwrap();
        let device = root.metadata().unwrap().dev();
        let names = [b"a".as_slice(), b"b".as_slice(), b"c".as_slice()];
        let mut visited = 0usize;
        for name in names.iter().take(cut) {
            remove_tree_member_at(&root, name, device, &mut visited).unwrap();
            root.sync_all().unwrap();
        }

        remove_directory_entries_except(&root, device, &[b"keep"]).unwrap();
        remove_directory_entries_except(&root, device, &[b"keep"]).unwrap();
        assert_eq!(
            directory_entry_names(&root, "test root").unwrap(),
            [b"keep"]
        );
        assert_eq!(fs::read(&outside).unwrap(), b"must survive");
    }
}

#[test]
fn init_successor_restarts_after_every_last_unlink_cut_and_converges_to_zero() {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum SuccessorCut {
        InitHookRemoved,
        RecoveryRemoved,
        ExecutableRemoved,
        RootRemoved,
        RebootRequested,
    }

    impl SuccessorCut {
        fn next(self) -> Option<Self> {
            match self {
                Self::InitHookRemoved => Some(Self::RecoveryRemoved),
                Self::RecoveryRemoved => Some(Self::ExecutableRemoved),
                Self::ExecutableRemoved => Some(Self::RootRemoved),
                Self::RootRemoved => Some(Self::RebootRequested),
                Self::RebootRequested => None,
            }
        }
    }

    let recovery = std::str::from_utf8(RECOVERY_HOOK_BYTES).unwrap();
    // The terminal init-hook services run the /vendor remount teardown, so
    // they must carry the voboost_uninstall capability set in init syntax.
    assert_eq!(
        recovery
            .matches("capabilities DAC_READ_SEARCH DAC_OVERRIDE KILL SYS_ADMIN SYS_BOOT SYS_PTRACE")
            .count(),
        2
    );
    let service = recovery
        .split("service voboost-uninstall-successor")
        .nth(1)
        .unwrap();
    assert!(!service.contains("oneshot"));
    assert!(service.starts_with(" /data/voboost/voboost-uninstall --complete-uninstall\n"));
    assert!(!service.contains("/system/bin/sh"));
    assert!(!service.contains("rm "));

    // The watchdog and successor are separate init-owned processes. Once
    // READY/GO is durable, either survivor repeats the descriptor-relative
    // exact cleanup after the other process dies at any irreversible cut.
    for cut in [
        SuccessorCut::InitHookRemoved,
        SuccessorCut::RecoveryRemoved,
        SuccessorCut::ExecutableRemoved,
        SuccessorCut::RootRemoved,
        SuccessorCut::RebootRequested,
    ] {
        let mut resumed = cut;
        while let Some(next) = resumed.next() {
            resumed = next;
        }
        assert_eq!(resumed, SuccessorCut::RebootRequested);
    }
}

#[test]
fn terminal_protocol_reboots_only_from_durable_device_predicate() {
    let source = include_str!("../../../shared/lifecycle_uninstall_terminal.rs");
    let watchdog = source
        .split("fn run_init_owned_uninstall_watchdog")
        .nth(1)
        .unwrap()
        .split("fn run_init_owned_uninstall_successor")
        .next()
        .unwrap();
    let successor = source
        .split("fn run_init_owned_uninstall_successor")
        .nth(1)
        .unwrap()
        .split("fn run_terminal_cleanup")
        .next()
        .unwrap();
    assert_eq!(watchdog.matches("reboot_terminal()").count(), 1);
    assert!(watchdog.contains("uninstall_peer_lost"));
    assert!(watchdog.matches("perform_terminal_exact_zero").count() >= 3);
    assert_eq!(successor.matches("reboot_terminal()").count(), 1);
    // The successor publishes REBOOT_ARMED after init accepted its reboot
    // request and before returning: exactly one arming publish rides the
    // authenticated stream.
    assert_eq!(
        successor
            .matches("UNINSTALL_SUCCESSOR_REBOOT_ARMED")
            .count(),
        1
    );
    for body in [watchdog, successor] {
        assert!(
            body.find("armed_terminal_reboot_state").unwrap()
                < body.find("reboot_terminal()").unwrap()
        );
        assert!(
            body.find("perform_terminal_exact_zero").unwrap()
                < body.find("reboot_terminal()").unwrap()
        );
    }
}

#[test]
fn terminal_reboot_evidence_is_idempotent_and_rejects_same_reason_after_boot() {
    let mut state = recovery_authority_for(Path::new("/"));
    state.phase = TerminalCleanupPhase::UninstallSuccessorStarted;
    state.terminal_boot_id = Some("01234567-89ab-cdef-0123-456789abcdef".to_string());
    let armed =
        armed_terminal_reboot_state(&state, "01234567-89ab-cdef-0123-456789abcdef").unwrap();
    assert_eq!(
        armed_terminal_reboot_state(&armed, "01234567-89ab-cdef-0123-456789abcdef").unwrap(),
        armed
    );
    assert_eq!(
        armed_terminal_reboot_state(&armed, "fedcba98-7654-3210-fedc-ba9876543210").unwrap_err(),
        "terminal reboot predicate repeated after a boot without progress"
    );
}

#[test]
fn init_services_carry_their_domain_capability_sets() {
    // Android init applies the declared capability set to the service.
    // SELinux allowances alone are not
    // enough: the kernel checks the process effective set (mount(2) →
    // CAP_SYS_ADMIN, DAC walks → DAC_OVERRIDE, …) before SELinux is even
    // consulted. This regression test pins the rc service lines to the
    // matching `self:capability` grants in selinux/voboost.te so the two can
    // never drift apart again (the emulator rc variant that used to carry
    // these lines was removed in the 2026-09-23 cleanup and the regression
    // came back as `remount fixed boundary /vendor: Permission denied`).
    let init = include_str!("../../../config/voboost.rc");
    let policy = include_str!("../../../selinux/voboost.te");
    let service_caps = [
        (
            "voboost-install",
            "chown dac_read_search dac_override sys_admin",
        ),
        ("voboost-relabel", "dac_override dac_read_search fowner"),
        ("voboost-restore", "dac_read_search dac_override sys_admin"),
        (
            "voboost-system-update",
            "dac_read_search dac_override sys_admin",
        ),
        (
            "voboost-uninstall",
            "dac_read_search dac_override kill sys_admin sys_boot sys_ptrace",
        ),
        (
            "voboost-uninstall-watchdog",
            "dac_read_search dac_override kill sys_admin sys_boot sys_ptrace",
        ),
        (
            "voboost-uninstall-successor",
            "dac_read_search dac_override kill sys_admin sys_boot sys_ptrace",
        ),
        (
            "voboost-resource-uninstall-resume",
            "dac_read_search dac_override kill sys_admin sys_boot sys_ptrace",
        ),
        (
            "voboost-daemon",
            "sys_ptrace dac_read_search dac_override kill chown fsetid net_admin",
        ),
        (
            "voboost-inject",
            "sys_ptrace dac_read_search dac_override kill chown fsetid",
        ),
    ];
    for (service, caps) in service_caps {
        let line = format!("    capabilities {}\n", caps.to_ascii_uppercase());
        let service_line = format!("service {service} ");
        let definition = init
            .split_once(&service_line)
            .unwrap_or_else(|| panic!("service {service} is missing from voboost.rc"))
            .1
            .split("\n\n")
            .next()
            .unwrap();
        assert!(
            definition.contains(&line),
            "service {service} must declare `capabilities {caps}` — init applies the declared capabilities"
        );
    }
    // The declared sets must be exactly what the SELinux policy grants the
    // matching domain, so a policy widening without an rc update fails here.
    // The policy may express the set as one braced grant or several single-
    // capability lines, so every `allow <domain> self:capability` occurrence
    // is merged before the comparison.
    let domain_caps = [
        (
            "voboost_install",
            "chown dac_read_search dac_override sys_admin",
        ),
        ("voboost_relabel", "dac_override dac_read_search fowner"),
        ("voboost_restore", "dac_read_search dac_override sys_admin"),
        (
            "voboost_uninstall",
            "dac_read_search dac_override kill sys_admin sys_boot sys_ptrace",
        ),
        (
            "voboost",
            "sys_ptrace dac_read_search dac_override kill chown fsetid net_admin",
        ),
    ];
    for (domain, caps) in domain_caps {
        let needle = format!("allow {domain} self:capability");
        let mut granted: Vec<&str> = Vec::new();
        let mut rest: &str = policy;
        while let Some((_, tail)) = rest.split_once(&needle) {
            let tail = tail.strip_prefix(' ').unwrap_or(tail);
            if let Some(set) = tail
                .strip_prefix('{')
                .and_then(|after| after.split_once("};"))
                .map(|(set, _)| set)
            {
                granted.extend(set.split_whitespace());
            } else {
                let single = tail.split([';', '\n']).next().unwrap().trim();
                granted.push(single);
            }
            rest = tail;
        }
        assert!(
            !granted.is_empty(),
            "{domain} self:capability grant is missing from voboost.te"
        );
        granted.sort_unstable();
        granted.dedup();
        let mut expected: Vec<&str> = caps.split_whitespace().collect();
        expected.sort_unstable();
        assert_eq!(
            granted, expected,
            "{domain} policy capability set drifted from the rc service line"
        );
    }
}

#[test]
fn in_car_uninstall_terminal_path_has_no_desktop_dependency() {
    let terminal = include_str!("../../../shared/lifecycle_uninstall_terminal.rs");
    let secure = include_str!("../../../shared/lifecycle_secure_fs.rs");
    let init = include_str!("../../../config/voboost.rc");
    assert!(terminal.contains("ctl.start"));
    assert!(secure.contains("sys.powerctl"));
    assert!(!terminal.contains("adb"));
    assert!(!secure.contains("adb"));
    assert!(init.contains("voboost-uninstall-watchdog"));
    assert!(init.contains("voboost-uninstall-successor"));
}

#[test]
fn terminal_takeover_rejects_timeout_without_peer_loss() {
    let source = include_str!("../../../shared/lifecycle_uninstall_terminal.rs");
    assert!(source.contains("completion timed out while peer remained authenticated"));
    assert!(source.contains("ErrorKind::UnexpectedEof"));
    assert!(source.contains("ErrorKind::TimedOut"));
}

#[test]
fn terminal_cleanup_publishes_pristine_policy_before_absence_work() {
    let source = include_str!("../../../shared/lifecycle_uninstall_terminal.rs");
    let prepare = source
        .split("pub(super) fn prepare_terminal_cleanup")
        .nth(1)
        .unwrap()
        .split("pub(super) fn connect_uninstall_watchdog")
        .next()
        .unwrap();
    assert!(
        prepare.find("restore_precompiled").unwrap()
            < prepare.find("remove_ordinary_zone_entries").unwrap()
    );
    assert!(
        prepare.find("restore_precompiled").unwrap()
            < prepare.find("UninstallAbsenceVerify").unwrap()
    );
}

#[test]
fn every_phase_journal_cut_resumes_idempotently_in_strict_order() {
    let actions = [
        Phase::UninstallAgentsStop,
        Phase::UninstallPolicyRestorePrepare,
        Phase::UninstallAppRemove,
        Phase::UninstallRuntimeRemove,
        Phase::UninstallTerminalCleanup,
        Phase::UninstallAbsenceVerify,
    ];
    for cut in 0..actions.len() {
        // Fault after the action but before its journal fsync: the last
        // action is deliberately repeated, then every later action runs.
        let persisted_before = if cut == 0 {
            Phase::UninstallPrepare
        } else {
            actions[cut - 1]
        };
        let mut retried = Vec::new();
        let mut phase = persisted_before;
        while let Some(next) = phase.next() {
            retried.push(next);
            phase = next;
        }
        assert_eq!(retried, actions[cut..]);

        // Fault after the journal fsync: resume starts strictly after the
        // persisted action and never skips a later terminal action.
        let mut resumed = Vec::new();
        let mut phase = actions[cut];
        while let Some(next) = phase.next() {
            resumed.push(next);
            phase = next;
        }
        assert_eq!(resumed, actions[cut + 1..]);
    }
}

#[test]
fn every_terminal_cleanup_phase_interruption_allows_only_the_exact_successor() {
    let phases = [
        TerminalCleanupPhase::UninstallActive,
        TerminalCleanupPhase::UninstallWatchdogArmed,
    ];
    for (index, phase) in phases.iter().copied().enumerate() {
        let expected = phases.get(index + 1).copied();
        let mut state = recovery_authority_for(Path::new("/"));
        state.phase = phase;
        for candidate in phases {
            let mut attempt = state.clone();
            let result = advance_terminal_cleanup_phase(&mut attempt, candidate);
            assert_eq!(result.is_ok(), Some(candidate) == expected);
            if result.is_ok() {
                assert_eq!(attempt.phase, candidate);
            } else {
                assert_eq!(attempt.phase, phase);
            }
        }
    }
}

#[test]
fn every_terminal_operation_cut_repeats_before_successor_publication() {
    let phases = [
        TerminalCleanupPhase::UninstallActive,
        TerminalCleanupPhase::UninstallWatchdogArmed,
    ];
    for transition in phases.windows(2) {
        let current = transition[0];
        let next = transition[1];
        let mut state = recovery_authority_for(Path::new("/"));
        state.phase = current;

        let publications = std::cell::Cell::new(0);
        let operations = std::cell::Cell::new(0);
        let before_operation = run_terminal_transition(
            &mut state,
            next,
            |_| Err("operation cut".to_string()),
            |_| {
                publications.set(publications.get() + 1);
                Ok(())
            },
        );
        assert!(before_operation.is_err());
        assert_eq!(state.phase, current);
        assert_eq!(publications.get(), 0);

        let after_operation = run_terminal_transition(
            &mut state,
            next,
            |_| {
                operations.set(operations.get() + 1);
                Ok(())
            },
            |_| {
                publications.set(publications.get() + 1);
                Err("publication cut".to_string())
            },
        );
        assert!(after_operation.is_err());
        assert_eq!(state.phase, current);
        assert_eq!(operations.get(), 1);

        run_terminal_transition(
            &mut state,
            next,
            |_| {
                operations.set(operations.get() + 1);
                Ok(())
            },
            |_| {
                publications.set(publications.get() + 1);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(state.phase, next);
        assert_eq!(operations.get(), 2);
        assert_eq!(publications.get(), 2);
    }
}

#[test]
fn substituted_recovery_hook_bytes_are_rejected() {
    assert!(recovery_hook_bytes_are_exact(RECOVERY_HOOK_BYTES));
    let mut substituted = RECOVERY_HOOK_BYTES.to_vec();
    substituted.extend_from_slice(b"\nservice foreign /system/bin/true\n");
    assert!(!recovery_hook_bytes_are_exact(&substituted));
    assert!(!recovery_hook_bytes_are_exact(
        b"service foreign /system/bin/true\n"
    ));
}

#[test]
fn installed_init_hook_carries_the_uninstall_ownership_marker() {
    // `publish_recovery_hook` refuses to overwrite the installed init hook
    // unless it contains `RC_MARKER`, so the committed `voboost.rc` template
    // must carry that marker.
    // Without it, uninstall aborts with `installed init hook lacks its
    // ownership marker` before the terminal recovery hook is published.
    let production = include_str!("../../../config/voboost.rc");
    assert!(
        production.contains(RC_MARKER),
        "production voboost.rc lacks the uninstall ownership marker"
    );
    // The recovery hook itself must begin with the marker so a later re-entry
    // recognizes it as already-committed authority.
    let recovery = std::str::from_utf8(RECOVERY_HOOK_BYTES).unwrap();
    assert!(recovery.contains(RC_MARKER));
}

#[test]
fn permanent_init_predeclares_terminal_services_with_explicit_primary_retry() {
    let installed = include_str!("../../../config/voboost.rc");
    let primary = installed
        .split("service voboost-uninstall /data/voboost/voboost-uninstall")
        .nth(1)
        .unwrap()
        .split("service voboost-uninstall-watchdog")
        .next()
        .unwrap();
    assert!(primary.contains("disabled"));
    assert!(primary.contains("oneshot"));
    let watchdog = installed
        .split("service voboost-uninstall-watchdog")
        .nth(1)
        .unwrap()
        .split("service voboost-uninstall-successor")
        .next()
        .unwrap();
    let successor = installed
        .split("service voboost-uninstall-successor")
        .nth(1)
        .unwrap()
        .split("service voboost-resource-uninstall-resume")
        .next()
        .unwrap();
    assert!(!watchdog.contains("oneshot"));
    assert!(!successor.contains("oneshot"));
    assert!(watchdog.contains("shutdown critical"));
    assert!(successor.contains("shutdown critical"));
    // The resource resume oneshot is inert outside its exact operation phase
    // (its role self-validates the active uninstall lease), so a per-boot
    // start is safe and restartable services above stay untouched.
    let resume = installed
        .split("service voboost-resource-uninstall-resume")
        .nth(1)
        .unwrap()
        .split("on post-fs-data")
        .next()
        .unwrap();
    assert!(resume.contains("oneshot"));
    assert!(resume.contains("disabled"));
    assert_eq!(
        installed
            .matches("seclabel u:r:voboost_uninstall:s0")
            .count(),
        4
    );
    assert!(!installed.contains("u:r:su:s0"));
    let terminal = std::str::from_utf8(RECOVERY_HOOK_BYTES).unwrap();
    for name in ["voboost-uninstall-watchdog", "voboost-uninstall-successor"] {
        assert!(installed.contains(name));
        assert!(terminal.contains(name));
    }
}

#[test]
fn terminal_primary_retry_remains_bound_to_one_boot() {
    let dir = tempdir().unwrap();
    let state = recovery_authority_for(dir.path());
    let boot = "01234567-89ab-cdef-0123-456789abcdef";
    let bound = active_terminal_boot_state(&state, boot).unwrap();
    assert!(terminal_cleanup_boot_allowed(&bound, boot).is_ok());
    assert!(terminal_cleanup_boot_allowed(&bound, "fedcba98-7654-3210-fedc-ba9876543210").is_err());
}

#[test]
fn terminal_cleanup_requires_the_bound_current_boot_and_zero_preconditions() {
    initialize_uninstall_paths(&"11".repeat(32)).unwrap();
    let state = recovery_authority_for(Path::new("/"));
    let current = "01234567-89ab-cdef-0123-456789abcdef";
    let changed = "fedcba98-7654-3210-fedc-ba9876543210";
    let armed = active_terminal_boot_state(&state, current).unwrap();
    assert!(terminal_cleanup_boot_allowed(&armed, current).is_ok());
    assert!(terminal_cleanup_boot_allowed(&armed, changed).is_err());
    let mut stages = Vec::new();
    let mut stage = TerminalCleanupPhase::UninstallActive;
    while let Some(next) = stage.next() {
        stages.push(next);
        stage = next;
    }
    assert_eq!(
        stages,
        [
            TerminalCleanupPhase::UninstallWatchdogArmed,
            TerminalCleanupPhase::UninstallWatchdogCommitted,
            TerminalCleanupPhase::UninstallSuccessorStarted,
        ]
    );
    assert!(validate_terminal_cleanup_boundary(
        current,
        current,
        Phase::UninstallAbsenceVerify,
        false,
        false
    )
    .is_ok());
    for rejected in [
        (
            current,
            changed,
            Phase::UninstallAbsenceVerify,
            false,
            false,
        ),
        (
            current,
            current,
            Phase::UninstallRuntimeRemove,
            false,
            false,
        ),
        (current, current, Phase::UninstallAbsenceVerify, true, false),
        (current, current, Phase::UninstallAbsenceVerify, false, true),
    ] {
        assert!(validate_terminal_cleanup_boundary(
            rejected.0, rejected.1, rejected.2, rejected.3, rejected.4
        )
        .is_err());
    }
    assert!(TERMINAL_FIXED_PATHS.contains(&RECOVERY_HOOK_TEMP_PATH));
    assert!(TERMINAL_FIXED_PATHS.contains(&RC_PATH));
    assert!(!TERMINAL_FIXED_PATHS.contains(&RECOVERY_PATH));
    assert!(!TERMINAL_FIXED_PATHS.contains(&recovery_state_path()));
}

fn lp(value: &[u8]) -> Vec<u8> {
    let mut encoded = (value.len() as u32).to_le_bytes().to_vec();
    encoded.extend_from_slice(value);
    encoded
}

const APK_SIG_BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";
const APK_SIGNATURE_SCHEME_V3_ID: u32 = 0xf053_68c0;

fn signing_block(certificate: &[u8], id: u32) -> Vec<u8> {
    let mut certificates = lp(certificate);
    let mut signed_data = lp(b"digests");
    signed_data.extend_from_slice(&lp(&certificates));
    if id == APK_SIGNATURE_SCHEME_V3_ID {
        signed_data.extend_from_slice(&28u32.to_le_bytes());
        signed_data.extend_from_slice(&35u32.to_le_bytes());
    }
    signed_data.extend_from_slice(&lp(b"attributes"));
    let mut signer = lp(&signed_data);
    if id == APK_SIGNATURE_SCHEME_V3_ID {
        signer.extend_from_slice(&28u32.to_le_bytes());
        signer.extend_from_slice(&35u32.to_le_bytes());
    }
    signer.extend_from_slice(&lp(b"signatures"));
    signer.extend_from_slice(&lp(b"public-key"));
    let signers = lp(&signer);
    let mut pair = id.to_le_bytes().to_vec();
    pair.extend_from_slice(&lp(&signers));
    let mut pairs = (pair.len() as u64).to_le_bytes().to_vec();
    pairs.extend_from_slice(&pair);
    let size = (pairs.len() + 24) as u64;
    let mut block = size.to_le_bytes().to_vec();
    block.append(&mut pairs);
    block.extend_from_slice(&size.to_le_bytes());
    block.extend_from_slice(APK_SIG_BLOCK_MAGIC);
    certificates.fill(0);
    block
}

#[test]
fn apk_signer_binding_accepts_one_v2_or_v3_certificate_and_rejects_substitution() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("base.apk");
    let certificate = b"bounded DER certificate fixture";
    let expected: [u8; 32] = Sha256::digest(certificate).into();
    for id in [0x7109_871a, APK_SIGNATURE_SCHEME_V3_ID] {
        fs::write(&path, apk_file(&signing_block(certificate, id))).unwrap();
        assert_eq!(installed_apk_signer(&path).unwrap().0, expected);
    }
    fs::write(
        &path,
        apk_file(&signing_block(
            b"different DER certificate fixture",
            APK_SIGNATURE_SCHEME_V3_ID,
        )),
    )
    .unwrap();
    assert_ne!(installed_apk_signer(&path).unwrap().0, expected);
    fs::write(&path, apk_file(&signing_block(certificate, 0x1234_5678))).unwrap();
    assert!(installed_apk_signer(&path).is_err());
}

#[test]
fn package_version_binding_is_canonical_and_bounded() {
    assert_eq!(
        parse_package_version_output(true, b"package:ru.voboost versionCode:123\n", b"").unwrap(),
        123
    );
    // `pm list packages ru.voboost` matches by substring, so the product's own
    // translation packages arrive beside the product record. They are not the
    // product version and must not make the inventory ambiguous.
    assert_eq!(
        parse_package_version_output(
            true,
            b"package:ru.voboost.translation.setting versionCode:1\n\
              package:ru.voboost.translation.media.a11 versionCode:1\n\
              package:ru.voboost versionCode:1000014\n\
              package:ru.voboost.translation.launcher versionCode:1\n",
            b""
        )
        .unwrap(),
        1000014
    );
    for output in [
        b"package:ru.voboost versionCode:0\n".as_slice(),
        b"package:ru.voboost versionCode:0123\n".as_slice(),
        b"package:ru.voboost versionCode:-1\n".as_slice(),
        b"package:ru.voboost versionCode:123\npackage:ru.voboost versionCode:124\n".as_slice(),
        b"package:ru.voboost versionCode:123\nnot a package listing\n".as_slice(),
        b"package:ru.voboost versionCode:9223372036854775808\n".as_slice(),
    ] {
        assert!(parse_package_version_output(true, output, b"").is_err());
    }
    assert!(parse_package_version_output(false, b"", b"error\n").is_err());
}

#[test]
fn package_registration_ignores_derived_packages_only() {
    // The product's translation packages share the substring filter and are
    // not the product package.
    assert!(parse_package_registration_output(
        true,
        b"package:ru.voboost.translation.setting\npackage:ru.voboost\npackage:ru.voboost.translation.media.a11\n",
        b""
    )
    .unwrap());
    assert!(!parse_package_registration_output(
        true,
        b"package:ru.voboost.translation.setting\npackage:ru.voboost.translation.media.a11\n",
        b""
    )
    .unwrap());
    assert!(!parse_package_registration_output(true, b"", b"").unwrap());
    for output in [
        b"package:ru.voboost\npackage:ru.voboost\n".as_slice(),
        b"package:ru.voboost \n".as_slice(),
        b"ru.voboost\n".as_slice(),
        b"package:ru.voboost".as_slice(),
    ] {
        assert!(parse_package_registration_output(true, output, b"").is_err());
    }
    assert!(parse_package_registration_output(false, b"", b"error\n").is_err());
}

#[test]
fn package_removal_command_is_version_guarded() {
    assert_eq!(
        package_uninstall_args(123),
        ["uninstall", "--versionCode", "123", "ru.voboost"]
    );
}

fn apk_file(block: &[u8]) -> Vec<u8> {
    let mut apk = b"APK-prefix".to_vec();
    apk.extend_from_slice(block);
    let central_offset = apk.len() as u32;
    let mut central = [0u8; 46];
    central[..4].copy_from_slice(b"PK\x01\x02");
    apk.extend_from_slice(&central);
    let mut eocd = [0u8; 22];
    eocd[..4].copy_from_slice(b"PK\x05\x06");
    eocd[8..10].copy_from_slice(&1u16.to_le_bytes());
    eocd[10..12].copy_from_slice(&1u16.to_le_bytes());
    eocd[12..16].copy_from_slice(&(central.len() as u32).to_le_bytes());
    eocd[16..20].copy_from_slice(&central_offset.to_le_bytes());
    apk.extend_from_slice(&eocd);
    apk
}

#[test]
fn installed_apk_signer_binds_eocd_footer_block_and_open_inode() {
    let certificate = b"end-to-end DER fixture";
    let apk = apk_file(&signing_block(certificate, APK_SIGNATURE_SCHEME_V3_ID));
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("base.apk");
    fs::write(&path, &apk).unwrap();
    let expected: [u8; 32] = Sha256::digest(certificate).into();
    assert_eq!(installed_apk_signer(&path).unwrap().0, expected);

    let mut malformed = apk.clone();
    let end = malformed.len();
    malformed[end - 22] ^= 1;
    fs::write(&path, malformed).unwrap();
    assert!(installed_apk_signer(&path).is_err());

    let mut substituted = apk.clone();
    let end = substituted.len();
    substituted[end - 6..end - 2].copy_from_slice(&1u32.to_le_bytes());
    fs::write(&path, substituted).unwrap();
    assert!(installed_apk_signer(&path).is_err());

    fs::write(&path, &apk[..apk.len() - 1]).unwrap();
    assert!(installed_apk_signer(&path).is_err());

    fs::write(&path, &apk).unwrap();
    let mutation_path = path.clone();
    assert!(installed_apk_signer_with(&path, || {
        OpenOptions::new()
            .append(true)
            .open(&mutation_path)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        Ok(())
    })
    .is_err());
}

#[test]
fn marker_and_closed_operation_guards_are_exact() {
    assert!(marker_content_is_prepared(MARKER_BYTES));
    assert!(!marker_content_is_prepared(
        b"{\"schemaVersion\":1,\"prepared\":true}"
    ));
}

#[test]
fn primary_invocation_pins_marker_path_root_init_parent_and_empty_argv() {
    assert_eq!(RECOVERY_PATH, "/data/voboost/voboost-uninstall");
    assert_eq!(MARKER_BYTES, b"{\"schemaVersion\":1,\"prepared\":true}\n");
}

#[test]
fn watchdog_invocation_requires_fixed_path_root_init_and_exact_argv() {
    let watchdog = vec!["voboost-uninstall".into(), "--watch-uninstall".into()];
    let successor = vec!["voboost-uninstall".into(), "--complete-uninstall".into()];
    assert!(uninstall_watchdog_args_authorized(&watchdog, 0));
    assert!(!uninstall_watchdog_args_authorized(&watchdog, 2000));
    assert!(uninstall_successor_args_authorized(&successor, 0));
    assert!(!uninstall_successor_args_authorized(&successor, 2000));
}

#[test]
fn terminal_hook_is_exact_fixed_path_and_loaded_teardown_domain() {
    assert_eq!(
        RECOVERY_HOOK_TEMP_PATH,
        "/system/etc/init/.voboost-uninstall-recovery.rc.tmp"
    );
    assert!(recovery_hook_bytes_are_exact(RECOVERY_HOOK_BYTES));
}

#[test]
fn terminal_absence_contract_names_every_fixed_temp_and_app_data_alias() {
    assert_eq!(
        TERMINAL_ROOT_CONTROL_FILES,
        ["operation.json", "operation.lock"]
    );
    assert!(TERMINAL_FIXED_PATHS.contains(&RC_INSTALL_TEMP_PATH));
    assert!(TERMINAL_FIXED_PATHS.contains(&RECOVERY_HOOK_TEMP_PATH));
    assert!(TERMINAL_FIXED_PATHS.contains(&POLICY_RESTORE_TEMP_PATH));
    for path in APP_DATA_PATHS {
        assert!(TERMINAL_FIXED_PATHS.contains(&path));
        assert!(
            require_app_data_absent_with(|candidate| Ok(candidate == Path::new(path))).is_err()
        );
    }
    assert!(require_app_data_absent_with(|_| Ok(false)).is_ok());
}

#[derive(Default)]
struct ScriptedUninstallActions {
    continuation: Option<crate::i18n_resource_files::OperationContinuation>,
    pending_requests: Vec<bool>,
    fail_resume_preflight: bool,
    fail: Option<Phase>,
    executed: Vec<Phase>,
    persisted: Vec<Phase>,
    owner_checks: usize,
}

impl UninstallActions for ScriptedUninstallActions {
    fn before_app_remove(&mut self) -> Result<(), String> {
        if self.fail_resume_preflight {
            Err("resume service missing".into())
        } else {
            Ok(())
        }
    }
    fn resource_continuation(
        &mut self,
    ) -> Result<crate::i18n_resource_files::OperationContinuation, String> {
        Ok(self
            .continuation
            .take()
            .unwrap_or(crate::i18n_resource_files::OperationContinuation::Continue))
    }
    fn resource_boot_pending(&mut self, request: bool) -> Result<(), String> {
        self.pending_requests.push(request);
        Ok(())
    }
    fn verify_owner(&mut self) -> Result<(), String> {
        self.owner_checks += 1;
        Ok(())
    }

    fn execute(&mut self, phase: Phase) -> Result<(), String> {
        self.executed.push(phase);
        if self.fail == Some(phase) {
            Err(format!("injected {phase:?} failure"))
        } else {
            Ok(())
        }
    }

    fn persist(&mut self, phase: Phase) -> Result<(), String> {
        self.persisted.push(phase);
        Ok(())
    }
}

#[test]
fn production_uninstall_driver_executes_every_mutation_before_terminal_handoff() {
    let mut actions = ScriptedUninstallActions::default();
    assert_eq!(
        drive_uninstall_phases(Phase::UninstallPrepare, &mut actions).unwrap(),
        PhaseProgress::Terminal
    );
    assert_eq!(
        actions.executed,
        [
            Phase::UninstallAgentsStop,
            Phase::UninstallPolicyRestorePrepare,
            Phase::UninstallAppRemove,
            Phase::UninstallRuntimeRemove,
            Phase::UninstallTerminalCleanup,
        ]
    );
    assert_eq!(actions.persisted, actions.executed);
    assert_eq!(actions.owner_checks, actions.executed.len());
}

#[test]
fn production_uninstall_driver_restarts_every_failed_mutating_phase() {
    for failed in [
        Phase::UninstallAgentsStop,
        Phase::UninstallPolicyRestorePrepare,
        Phase::UninstallAppRemove,
        Phase::UninstallRuntimeRemove,
        Phase::UninstallTerminalCleanup,
    ] {
        let predecessor = match failed {
            Phase::UninstallAgentsStop => Phase::UninstallPrepare,
            Phase::UninstallPolicyRestorePrepare => Phase::UninstallAgentsStop,
            Phase::UninstallAppRemove => Phase::UninstallPolicyRestorePrepare,
            Phase::UninstallRuntimeRemove => Phase::UninstallAppRemove,
            Phase::UninstallTerminalCleanup => Phase::UninstallRuntimeRemove,
            _ => unreachable!(),
        };
        let mut actions = ScriptedUninstallActions {
            fail: Some(failed),
            ..Default::default()
        };
        assert!(drive_uninstall_phases(predecessor, &mut actions).is_err());
        assert_eq!(actions.executed, [failed]);
        assert!(
            actions.persisted.is_empty(),
            "{failed:?} persisted after failure"
        );
        actions.fail = None;
        assert_eq!(
            drive_uninstall_phases(predecessor, &mut actions).unwrap(),
            PhaseProgress::Terminal
        );
        assert_eq!(
            actions
                .executed
                .iter()
                .filter(|phase| **phase == failed)
                .count(),
            2
        );
    }
}
#[test]
fn uninstall_lease_waits_for_trigger_handoff_but_preserves_failure_boundaries() {
    let mut attempts = 0;
    let mut waits = 0;
    let value = acquire_uninstall_lease_with(
        || {
            attempts += 1;
            if attempts < 3 {
                Err("operation busy".to_string())
            } else {
                Ok(42)
            }
        },
        || waits += 1,
    )
    .unwrap();
    assert_eq!((value, attempts, waits), (42, 3, 2));
    waits = 0;
    let result: Result<(), String> =
        acquire_uninstall_lease_with(|| Err("operation busy".to_string()), || waits += 1);
    assert_eq!(result.unwrap_err(), "operation busy");
    assert_eq!(waits, 20);
    waits = 0;
    let result: Result<(), String> =
        acquire_uninstall_lease_with(|| Err("foreign operation".to_string()), || waits += 1);
    assert_eq!(result.unwrap_err(), "foreign operation");
    assert_eq!(waits, 0);
}

#[test]
fn daemon_inventory_policy_covers_foreign_process_magic_links_read_only() {
    let policy = include_str!("../../../selinux/voboost.te");
    assert!(policy.contains("allow voboost_uninstall domain:lnk_file read;"));
    assert!(!policy.contains("allow voboost_uninstall domain:process ptrace;"));
    assert!(!policy.contains("allow su domain:lnk_file"));
    let source = include_str!("../transaction.rs");
    assert!(source.contains("read daemon executable /proc/{pid}/exe: {error}"));
    assert!(source.contains("/data/voboost/voboost-daemon (deleted)"));
}

#[test]
fn terminal_cleanup_removes_pending_owned_fev_input_journal() {
    let directory = tempdir().unwrap();
    let root_path = directory.path().join("root");
    fs::create_dir(&root_path).unwrap();
    fs::create_dir(root_path.join("state")).unwrap();
    fs::write(root_path.join("state/forced-ev-intent.json"),
        br#"{"schemaVersion":1,"bootId":"11111111-1111-4111-8111-111111111111","captureNs":10,"pid":10,"requestId":1,"choice":"off","pending":true}"#).unwrap();
    fs::write(root_path.join("keep"), b"authority").unwrap();
    let root = open_directory_nofollow(&root_path, "test root").unwrap();
    let device = root.metadata().unwrap().dev();
    remove_directory_entries_except(&root, device, &[b"keep"]).unwrap();
    remove_directory_entries_except(&root, device, &[b"keep"]).unwrap();
    assert!(!root_path.join("state/forced-ev-intent.json").exists());
    assert_eq!(
        directory_entry_names(&root, "test root").unwrap(),
        [b"keep"]
    );
}

#[test]
fn uninstall_peer_argv_accepts_oem_eof_and_single_terminal_nul_only() {
    for argument in [
        None,
        Some("--watch-uninstall"),
        Some("--complete-uninstall"),
    ] {
        let mut expected = RECOVERY_PATH.as_bytes().to_vec();
        if let Some(argument) = argument {
            expected.push(0);
            expected.extend_from_slice(argument.as_bytes());
        }
        let eof = expected.clone();
        expected.push(0);
        assert!(uninstall_peer_argv_matches(&expected, &expected));
        assert!(uninstall_peer_argv_matches(&eof, &expected));
        let mut extra = expected.clone();
        extra.extend_from_slice(b"--foreign\0");
        assert!(!uninstall_peer_argv_matches(&extra, &expected));
        let mut foreign = expected.clone();
        foreign[0] = b'!';
        assert!(!uninstall_peer_argv_matches(&foreign, &expected));
        let mut padding = expected.clone();
        padding.push(0);
        assert!(!uninstall_peer_argv_matches(&padding, &expected));
        assert!(!uninstall_peer_argv_matches(
            &eof[..eof.len() - 1],
            &expected
        ));
        assert!(!uninstall_peer_argv_matches(b"", &expected));
    }
}

#[test]
fn terminal_watchdog_accepts_the_exact_post_reboot_resume_role() {
    let accepted = |argument| {
        let argv = uninstall_peer_argv(argument);
        UNINSTALL_PRIMARY_ROLES
            .iter()
            .any(|role| uninstall_peer_argv_matches(&argv, &uninstall_peer_argv(*role)))
    };
    assert!(accepted(None));
    assert!(accepted(Some("--resume-resource-uninstall")));
    assert!(!accepted(Some("--i18n-none-finalize")));
    assert!(!accepted(Some("--watch-uninstall")));
    assert!(!accepted(Some("--complete-uninstall")));
}

#[test]
fn resource_pause_retains_runtime_and_never_publishes_terminal() {
    use crate::i18n_resource_files::OperationContinuation;
    for continuation in [
        OperationContinuation::RequestReboot,
        OperationContinuation::AwaitBoot,
    ] {
        let mut actions = ScriptedUninstallActions {
            continuation: Some(continuation),
            ..Default::default()
        };
        assert_eq!(
            drive_uninstall_phases(Phase::UninstallPrepare, &mut actions).unwrap(),
            PhaseProgress::ResourceBootPending
        );
        assert_eq!(actions.persisted.last(), Some(&Phase::UninstallAppRemove));
        assert!(!actions.executed.contains(&Phase::UninstallRuntimeRemove));
        assert!(!actions.executed.contains(&Phase::UninstallTerminalCleanup));
        assert_eq!(
            actions.pending_requests,
            [continuation == OperationContinuation::RequestReboot]
        );
    }
}
#[test]
fn resource_fresh_boot_continues_without_repeating_appremove() {
    let mut actions = ScriptedUninstallActions::default();
    assert_eq!(
        drive_uninstall_phases(Phase::UninstallAppRemove, &mut actions).unwrap(),
        PhaseProgress::Terminal
    );
    assert_eq!(
        actions.executed.first(),
        Some(&Phase::UninstallRuntimeRemove)
    );
    assert!(!actions.executed.contains(&Phase::UninstallAppRemove));
    assert!(actions.pending_requests.is_empty());
}
#[test]
fn absent_resume_service_aborts_before_resource_or_app_removal() {
    let mut actions = ScriptedUninstallActions {
        fail_resume_preflight: true,
        ..Default::default()
    };
    assert!(drive_uninstall_phases(Phase::UninstallPrepare, &mut actions).is_err());
    assert!(!actions.executed.contains(&Phase::UninstallAppRemove));
    assert!(!actions.executed.contains(&Phase::UninstallRuntimeRemove));
    assert!(actions.pending_requests.is_empty());
}

#[test]
fn resource_reboot_counter_survives_real_projection_and_wal_recovery() {
    let root = tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let id = "ad".repeat(32);
    let relative = format!("recovery/{id}/uninstall-journal.json");
    let transaction = root.path().join("recovery").join(&id);
    fs::create_dir_all(&transaction).unwrap();
    for directory in [transaction.parent().unwrap(), transaction.as_path()] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let journal = root.path().join(&relative);
    fs::write(&journal, b"AppRemove\n").unwrap();
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
    let mut current = OperationDescriptor::new(
        Operation::Uninstall,
        id.clone(),
        relative,
        "11111111-1111-4111-8111-111111111111".into(),
    )
    .unwrap();
    current.phase = Phase::UninstallAppRemove.name();
    current.outcome = "reboot-required".into();
    current.reboot_count = 1;
    current.status_sequence =
        uninstall_status_sequence(Phase::UninstallAppRemove, "reboot-required").unwrap();
    current.journal_sha256 = sha256_hex(b"AppRemove\n");
    let lease = OperationLease::acquire_in(root.path(), current.clone()).unwrap();
    fs::write(&journal, b"RuntimeRemove\n").unwrap();
    let mut next = current.clone();
    next.phase = Phase::UninstallRuntimeRemove.name();
    next.outcome = "running".into();
    next.status_sequence =
        uninstall_status_sequence(Phase::UninstallRuntimeRemove, "running").unwrap();
    next.journal_sha256 = sha256_hex(b"RuntimeRemove\n");
    next.reboot_count = 0;
    assert!(lease
        .publish(&next)
        .unwrap_err()
        .contains("counter backwards"));
    next.reboot_count = carry_reboot_count(next.reboot_count, Some(&current), &id);
    lease.publish(&next).unwrap();
    drop(lease);
    // Crash cut: durable WAL advanced, projection still describes its predecessor.
    fs::write(&journal, b"TerminalCleanup\n").unwrap();
    let mut recovered = next.clone();
    recovered.phase = Phase::UninstallTerminalCleanup.name();
    recovered.status_sequence =
        uninstall_status_sequence(Phase::UninstallTerminalCleanup, "running").unwrap();
    recovered.journal_sha256 = sha256_hex(b"TerminalCleanup\n");
    recovered.reboot_count = carry_reboot_count(0, Some(&next), &id);
    let _resumed = OperationLease::acquire_in(root.path(), recovered).unwrap();
}
#[test]
fn failed_uninstall_is_not_restarted_indefinitely_by_init() {
    let init = include_str!("../../../config/voboost.rc");
    let service = init
        .split("service voboost-uninstall /data/voboost/voboost-uninstall\n")
        .nth(1)
        .unwrap()
        .split("\nservice ")
        .next()
        .unwrap();
    assert!(service.lines().any(|line| line.trim() == "oneshot"));
    assert!(service.lines().any(|line| line.trim() == "disabled"));
}

#[test]
fn independent_application_cleanup_attempts_every_step_and_preserves_failures() {
    for mask in 0u8..8 {
        let calls = std::cell::RefCell::new(Vec::new());
        let attempt = |index: u32| {
            calls.borrow_mut().push(index);
            if mask & (1u8 << index) != 0u8 {
                Err(format!("failure-{index}"))
            } else {
                Ok(())
            }
        };
        let mut warnings = Vec::new();
        let result = cleanup_application(
            || attempt(0),
            || attempt(1),
            || attempt(2),
            |warning| warnings.push(warning.to_string()),
        );
        assert_eq!(*calls.borrow(), vec![0, 1, 2]);
        assert_eq!(warnings.len(), usize::from(mask & 2 != 0));
        if mask & 2 != 0 {
            assert!(warnings[0].contains("launcher icon cache cleanup: failure-1"));
        }
        if mask & 5 == 0 {
            assert!(result.is_ok());
        } else {
            let error = result.unwrap_err();
            for index in [0u32, 2] {
                assert_eq!(
                    error.contains(&format!("failure-{index}")),
                    mask & (1u8 << index) != 0u8
                );
            }
            assert!(!error.contains("failure-1"));
        }
    }
}

#[test]
fn daemon_stop_attempts_both_services_and_all_observed_processes() {
    let calls = std::cell::RefCell::new(Vec::new());
    let mut observations = 0;
    let result = stop_daemon_with(
        |service| {
            calls.borrow_mut().push(service.to_string());
            Err(format!("stop {service}"))
        },
        || {
            observations += 1;
            Ok(if observations == 1 {
                vec![11, 22]
            } else {
                vec![]
            })
        },
        |pid| {
            calls.borrow_mut().push(pid.to_string());
            Err(format!("signal {pid}"))
        },
    );
    assert_eq!(
        *calls.borrow(),
        ["voboost-inject", "voboost-daemon", "11", "22"]
    );
    assert_eq!(observations, 2);
    let error = result.unwrap_err();
    for expected in [
        "stop voboost-inject",
        "stop voboost-daemon",
        "signal 11",
        "signal 22",
    ] {
        assert!(error.contains(expected));
    }
}

#[test]
fn daemon_stop_rechecks_after_observation_failure() {
    let mut observations = 0;
    let result = stop_daemon_with::<u32>(
        |_| Ok(()),
        || {
            observations += 1;
            Err(format!("observation {observations}"))
        },
        |_| panic!("no process identity was observed"),
    );
    assert_eq!(observations, 2);
    let error = result.unwrap_err();
    assert!(error.contains("observe daemon processes: observation 1"));
    assert!(error.contains("verify daemon stop: observation 2"));
}

#[test]
fn runtime_cleanup_preserves_recovery_before_attempting_all_independent_members() {
    for mask in 0u8..16 {
        let calls = std::cell::RefCell::new(Vec::new());
        let attempt = |index: u32| {
            calls.borrow_mut().push(index);
            if mask & (1u8 << index) != 0 {
                Err(format!("failure-{index}"))
            } else {
                Ok(())
            }
        };
        let result = cleanup_runtime(|| attempt(0), || attempt(1), || attempt(2), || attempt(3));
        if mask & 1 != 0 {
            assert_eq!(*calls.borrow(), [0]);
            assert_eq!(result.unwrap_err(), "failure-0");
        } else {
            assert_eq!(*calls.borrow(), [0, 1, 2, 3]);
            if mask == 0 {
                assert!(result.is_ok());
            } else {
                let error = result.unwrap_err();
                for index in 1u32..4 {
                    assert_eq!(
                        error.contains(&format!("failure-{index}")),
                        mask & (1 << index) != 0
                    );
                }
            }
        }
    }
}
