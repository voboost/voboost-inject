use super::*;

pub(super) const TERMINAL_ROOT_CONTROL_FILES: [&str; 2] = ["operation.json", "operation.lock"];

fn acquire_terminal_uninstall_lease(state: &RecoveryState) -> Result<OperationLease, String> {
    let descriptor = OperationDescriptor::new(
        Operation::Uninstall,
        state.transaction_id.clone(),
        format!("recovery/{}/uninstall-journal.json", state.transaction_id),
        operation_contract::current_boot_id()?,
    )?;
    OperationLease::acquire_in(Path::new(ZONE), descriptor)
}

pub(super) fn prepare_terminal_cleanup(
    self_bytes: &[u8],
    expected: &RecoveryState,
    backup_bytes: &[u8],
    backup_metadata: &BackupMetadata,
    directories: &RetainedUninstallDirectories,
    lease: &OperationLease,
) -> Result<(), String> {
    let state = load_recovery_state()?;
    if state.recovery_sha256 != sha256_hex(self_bytes)
        || state.transaction_id != expected.transaction_id
        || state.zone_dev != expected.zone_dev
        || state.zone_ino != expected.zone_ino
    {
        return Err("terminal cleanup recovery binding differs".to_string());
    }
    // Publish the pristine policy before any absence or reboot work. Re-entry
    // repeats this descriptor-bound replace as the first recoverable action.
    restore_precompiled(backup_bytes, backup_metadata)?;
    verify_restored_policy(&state)?;
    if state.terminal_boot_id.is_none() {
        persist_active_terminal_boot(&state, &canonical_boot_id()?)?;
    }
    match load_phase()? {
        Phase::UninstallTerminalCleanup => {
            persist_phase(Phase::UninstallAbsenceVerify)?;
            publish_uninstall_status(lease, Phase::UninstallAbsenceVerify, "running", 0, None)?;
        }
        Phase::UninstallAbsenceVerify => {}
        _ => return Err("terminal cleanup phase is not armed".to_string()),
    }
    remove_ordinary_zone_entries(directories)?;
    verify_recovery_hook()?;
    let resident_file = openat_regular_nofollow(&directories.root, "voboost-uninstall")?;
    let resident = read_retained_bytes(
        &resident_file,
        MAX_SELF_BYTES,
        "terminal uninstall executable",
    )?;
    require_root_file(resident.stamp, 0o700, "terminal uninstall executable")?;
    require_trusted_context(
        &resident,
        UNINSTALL_EXEC_CONTEXT,
        "terminal uninstall executable",
    )?;
    if resident.bytes != self_bytes {
        return Err("terminal uninstall executable bytes differ".to_string());
    }
    Ok(())
}

pub(super) fn start_uninstall_watchdog_service() -> Result<(), String> {
    super::fixed_process::set_property("ctl.start", "voboost-uninstall-watchdog")
        .map_err(|_| "init rejected uninstall watchdog service start".to_string())
}

pub(super) fn start_uninstall_successor_service() -> Result<(), String> {
    super::fixed_process::set_property("ctl.start", "voboost-uninstall-successor")
        .map_err(|_| "init rejected uninstall successor service start".to_string())
}

pub(super) fn remove_terminal_init_hook(
    directories: &mut RetainedUninstallDirectories,
) -> Result<(), String> {
    if !path_entry_exists(Path::new(RC_PATH))? {
        return Ok(());
    }
    let named = openat_regular_nofollow(&directories.init_parent, "voboost.rc")?;
    let trusted = read_retained_bytes(&named, 4096, "named terminal init hook")?;
    if trusted.stamp != directories.init_hook_stamp
        || !recovery_hook_bytes_are_exact(&trusted.bytes)
    {
        return Err("terminal init hook changed before protected unlink".to_string());
    }
    // Drop every file handle into the terminal hook BEFORE the protected
    // window: the hook lives in the writable /system overlay's upperdir, and
    // overlayfs refuses the closing RO remount (EBUSY) while any descriptor
    // still pins an upperdir inode — even read-only, even unlinked (proven
    // on the emulator kernel by fd-lifetime probes case1/case2). The
    // retained stamp recorded at open() time remains the identity rail: the
    // named leaf is re-verified against it inside the mutation before the
    // unlinkat, so an inode swap across the RW window still fails closed.
    drop(named);
    directories.close_init_hook()?;
    with_protected_mounts_rw(ProtectedMutationMount::SystemInitHook, || {
        let current = openat_regular_nofollow(&directories.init_parent, "voboost.rc")?;
        if FileStamp::from(
            &current
                .metadata()
                .map_err(|error| format!("fstat current terminal init hook: {error}"))?,
        ) != directories.init_hook_stamp
        {
            return Err("terminal init hook inode changed after RW remount".to_string());
        }
        unlinkat_retained(
            &directories.init_parent,
            "voboost.rc",
            &current,
            directories.init_hook_stamp,
            "terminal init hook",
        )?;
        drop(current);
        directories
            .init_parent
            .sync_all()
            .map_err(|error| format!("fsync init parent after terminal unlink: {error}"))
    })?;
    if path_entry_exists(Path::new(RC_PATH))? {
        return Err("terminal init hook remains after protected unlink".to_string());
    }
    Ok(())
}

pub(super) fn remove_terminal_socket() -> Result<(), String> {
    let path = Path::new(uninstall_watchdog_socket_path());
    if !path_entry_exists(path)? {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("lstat terminal handoff socket: {error}"))?;
    if !metadata.file_type().is_socket() || metadata.uid() != 0 || metadata.gid() != 0 {
        return Err("terminal handoff socket identity is unsafe".to_string());
    }
    fs::remove_file(path).map_err(|error| format!("unlink terminal handoff socket: {error}"))?;
    fsync_parent(path)
}

pub(super) fn perform_terminal_exact_zero(
    self_bytes: &[u8],
    state: &RecoveryState,
    directories: &mut RetainedUninstallDirectories,
) -> Result<(), String> {
    if path_entry_exists(Path::new(remount_journal_path()))? {
        recover_pending_remounts()?;
    }
    remove_terminal_init_hook(directories)?;
    remove_terminal_socket()?;
    if path_entry_exists(Path::new(RECOVERY_ROOT))? {
        remove_successor_recovery_state(state, directories)?;
    }
    require_app_data_absent_with(path_entry_exists)?;
    for leaf in TERMINAL_ROOT_CONTROL_FILES {
        if path_entry_exists(&Path::new(ZONE).join(leaf))? {
            let member = openat_regular_nofollow(&directories.root, leaf)?;
            let metadata = member
                .metadata()
                .map_err(|error| format!("fstat terminal {leaf}: {error}"))?;
            let member_stamp = FileStamp::from(&metadata);
            require_root_file(member_stamp, 0o600, &format!("terminal {leaf}"))?;
            unlinkat_retained(
                &directories.root,
                leaf,
                &member,
                member_stamp,
                &format!("terminal {leaf}"),
            )?;
            directories
                .root
                .sync_all()
                .map_err(|error| format!("fsync after terminal {leaf} unlink: {error}"))?;
        }
    }
    let names = directory_entry_names(&directories.root, "terminal last-unlink root")?;
    if names == [b"voboost-uninstall".to_vec()] {
        let executable = openat_regular_nofollow(&directories.root, "voboost-uninstall")?;
        let trusted = read_retained_bytes(
            &executable,
            MAX_SELF_BYTES,
            "terminal last-unlink executable",
        )?;
        if trusted.bytes != self_bytes || !appended_signature_valid(&trusted.bytes) {
            return Err("terminal executable changed before last unlink".to_string());
        }
        unlinkat_retained(
            &directories.root,
            "voboost-uninstall",
            &executable,
            trusted.stamp,
            "terminal executable",
        )?;
        directories
            .root
            .sync_all()
            .map_err(|error| format!("fsync terminal empty root: {error}"))?;
    } else if !names.is_empty() {
        return Err("terminal last-unlink root contains unexpected residue".to_string());
    }
    if path_entry_exists(Path::new(ZONE))? {
        unlinkat_leaf(
            &directories.data_parent,
            b"voboost",
            true,
            "terminal root zone",
        )?;
        directories
            .data_parent
            .sync_all()
            .map_err(|error| format!("fsync data parent after terminal rmdir: {error}"))?;
    }
    if path_entry_exists(Path::new(ZONE))? || path_entry_exists(Path::new(RC_PATH))? {
        return Err("terminal exact-zero proof found a remaining Voboost path".to_string());
    }
    Ok(())
}

pub(super) fn require_app_data_absent_with(
    mut exists: impl FnMut(&Path) -> Result<bool, String>,
) -> Result<(), String> {
    for path in APP_DATA_PATHS {
        if exists(Path::new(path))? {
            return Err(format!(
                "terminal exact-zero found remaining app data: {path}"
            ));
        }
    }
    Ok(())
}

pub(super) fn prepare_uninstall_successor_root(
    expected: &RecoveryState,
    directories: &RetainedUninstallDirectories,
) -> Result<(), String> {
    let root = directories
        .root
        .metadata()
        .map_err(|error| format!("fstat successor root zone: {error}"))?;
    if root.dev() != expected.zone_dev || root.ino() != expected.zone_ino {
        return Err("uninstall successor root-zone identity changed".to_string());
    }
    remove_directory_entries_except(
        &directories.root,
        root.dev(),
        &[
            b"voboost-uninstall",
            b"recovery",
            b"operation.json",
            b"operation.lock",
        ],
    )?;
    if directory_entry_names(&directories.root, "successor root zone")?
        != [
            b"operation.json".to_vec(),
            b"operation.lock".to_vec(),
            b"recovery".to_vec(),
            b"voboost-uninstall".to_vec(),
        ]
    {
        return Err("uninstall successor root shape is not exact".to_string());
    }
    Ok(())
}

fn require_no_pending_cluster_recovery(entries: &[Vec<u8>]) -> Result<(), String> {
    if entries
        .iter()
        .any(|name| matches!(name.as_slice(), b"cluster" | b"recovery.json"))
    {
        return Err(
            "Android teardown reached retained QNX recovery; final deletion is pending".into(),
        );
    }
    Ok(())
}

pub(super) fn remove_successor_recovery_state(
    expected: &RecoveryState,
    directories: &RetainedUninstallDirectories,
) -> Result<(), String> {
    if expected.phase != TerminalCleanupPhase::UninstallSuccessorStarted {
        return Err("uninstall successor cleanup is not durably started".to_string());
    }
    let root_device = directories
        .root
        .metadata()
        .map_err(|error| format!("fstat successor root: {error}"))?
        .dev();
    let recovery =
        openat_directory_nofollow(&directories.root, b"recovery", "successor recovery root")?;
    let recovery_stamp = recovery
        .metadata()
        .map_err(|error| format!("fstat successor recovery root: {error}"))?;
    if recovery_stamp.dev() != root_device {
        return Err("successor recovery crosses a mount boundary".to_string());
    }
    let tx_name = expected.transaction_id.as_bytes();
    if directory_entry_names(&recovery, "successor recovery root")? != [tx_name.to_vec()] {
        return Err("successor recovery root does not contain the exact transaction".to_string());
    }
    let transaction =
        openat_directory_nofollow(&recovery, tx_name, "successor recovery transaction")?;
    let transaction_stamp = transaction
        .metadata()
        .map_err(|error| format!("fstat successor recovery transaction: {error}"))?;
    if transaction_stamp.dev() != root_device {
        return Err("successor transaction crosses a mount boundary".to_string());
    }
    require_no_pending_cluster_recovery(&directory_entry_names(
        &transaction,
        "successor recovery transaction",
    )?)?;
    remove_directory_entries_except(&transaction, root_device, &[b"state.json"])?;
    let retained_state = openat_regular_nofollow(&transaction, "state.json")?;
    let trusted = read_retained_bytes(
        &retained_state,
        MAX_RECOVERY_STATE_BYTES,
        "successor recovery state",
    )?;
    if parse_recovery_state(&trusted.bytes)? != *expected {
        return Err("successor recovery state changed before last unlink".to_string());
    }
    unlinkat_retained(
        &transaction,
        "state.json",
        &retained_state,
        trusted.stamp,
        "successor recovery state",
    )?;
    transaction
        .sync_all()
        .map_err(|error| format!("fsync empty successor transaction: {error}"))?;
    unlinkat_leaf(&recovery, tx_name, true, "successor recovery transaction")?;
    recovery
        .sync_all()
        .map_err(|error| format!("fsync empty successor recovery root: {error}"))?;
    unlinkat_leaf(
        &directories.root,
        b"recovery",
        true,
        "successor recovery root",
    )?;
    directories
        .root
        .sync_all()
        .map_err(|error| format!("fsync successor-ready root: {error}"))?;
    if directory_entry_names(&directories.root, "successor-ready root")?
        != [
            b"operation.json".to_vec(),
            b"operation.lock".to_vec(),
            b"voboost-uninstall".to_vec(),
        ]
    {
        return Err("successor-ready root contains unexpected residue".to_string());
    }
    Ok(())
}

#[cfg(any(target_os = "android", target_os = "linux"))]
pub(super) fn unix_peer_credentials(
    stream: &UnixStream,
) -> Result<(libc::pid_t, u32, u32), String> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut libc::ucred as *mut libc::c_void,
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of::<libc::ucred>()
    {
        return Err(format!(
            "read uninstall watchdog peer credentials: {}",
            thread_errno()
        ));
    }
    Ok((credentials.pid, credentials.uid, credentials.gid))
}

#[cfg(target_vendor = "apple")]
pub(super) fn unix_peer_credentials(
    stream: &UnixStream,
) -> Result<(libc::pid_t, u32, u32), String> {
    let mut uid = 0;
    let mut gid = 0;
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(format!(
            "read uninstall watchdog peer credentials: {}",
            thread_errno()
        ));
    }
    Ok((-1, uid, gid))
}

#[cfg(any(target_os = "android", target_os = "linux", test))]
pub(super) fn uninstall_peer_argv_matches(command: &[u8], expected: &[u8]) -> bool {
    // The OEM kernel may expose the last argument ending at EOF instead of
    // including its terminal NUL. Internal separators and every argument remain exact.
    command == expected
        || expected
            .strip_suffix(&[0])
            .is_some_and(|eof| command == eof)
}

#[cfg(any(target_os = "android", target_os = "linux", test))]
pub(super) fn uninstall_peer_argv(argument: Option<&str>) -> Vec<u8> {
    match argument {
        Some(value) => [RECOVERY_PATH.as_bytes(), b"\0", value.as_bytes(), b"\0"].concat(),
        None => [RECOVERY_PATH.as_bytes(), b"\0"].concat(),
    }
}

pub(super) const UNINSTALL_PRIMARY_ROLES: &[Option<&str>] =
    &[None, Some("--resume-resource-uninstall")];

pub(super) fn require_root_uninstall_watchdog_peer(
    stream: &UnixStream,
    expected_arguments: &[Option<&str>],
) -> Result<(), String> {
    let (pid, uid, gid) = unix_peer_credentials(stream)?;
    if uid != 0 || gid != 0 {
        return Err("uninstall watchdog peer is not root".to_string());
    }
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        if pid <= 1 {
            return Err("uninstall watchdog peer pid is invalid".to_string());
        }
        let executable = fs::read_link(format!("/proc/{pid}/exe"))
            .map_err(|error| format!("read uninstall watchdog peer executable: {error}"))?;
        if executable != Path::new(RECOVERY_PATH) {
            return Err("uninstall watchdog peer executable is not the fixed binary".to_string());
        }
        let expected = expected_arguments
            .iter()
            .map(|argument| uninstall_peer_argv(*argument))
            .collect::<Vec<_>>();
        let longest = expected.iter().map(Vec::len).max().unwrap_or(0);
        let mut command = Vec::with_capacity(longest);
        File::open(format!("/proc/{pid}/cmdline"))
            .map_err(|error| format!("open uninstall watchdog peer argv: {error}"))?
            .take((longest + 1) as u64)
            .read_to_end(&mut command)
            .map_err(|error| format!("read uninstall watchdog peer argv: {error}"))?;
        if !expected
            .iter()
            .any(|argv| uninstall_peer_argv_matches(&command, argv))
        {
            return Err(format!(
                "uninstall watchdog peer argv is not exact: roles={:?}, bytes={}, limit={}, terminalNul={}",
                expected_arguments,
                command.len(),
                longest,
                command.last() == Some(&0)
            ));
        }
    }
    #[cfg(target_vendor = "apple")]
    let _ = (pid, expected_arguments);
    Ok(())
}

pub(super) fn connect_uninstall_watchdog() -> Result<UnixStream, String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match UnixStream::connect(uninstall_watchdog_socket_path()) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(30)))
                    .map_err(|error| format!("bound uninstall watchdog read timeout: {error}"))?;
                stream
                    .set_write_timeout(Some(Duration::from_secs(30)))
                    .map_err(|error| format!("bound uninstall watchdog write timeout: {error}"))?;
                return Ok(stream);
            }
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(format!("connect init-owned uninstall watchdog: {error}")),
        }
    }
}

pub(super) fn commit_to_uninstall_watchdog(lease: OperationLease) -> Result<(), String> {
    start_uninstall_watchdog_service()?;
    let mut stream = connect_uninstall_watchdog()?;
    require_root_uninstall_watchdog_peer(&stream, &[Some("--watch-uninstall")])?;
    let mut message = [0u8; 1];
    stream
        .read_exact(&mut message)
        .map_err(|error| format!("read uninstall watchdog readiness: {error}"))?;
    if message[0] != UNINSTALL_WATCHDOG_READY {
        return Err("uninstall watchdog readiness is invalid".to_string());
    }
    lease.verify_owner()?;
    drop(lease);
    stream
        .write_all(&[UNINSTALL_WATCHDOG_COMMIT])
        .map_err(|error| format!("commit terminal cleanup to uninstall watchdog: {error}"))?;
    stream
        .read_exact(&mut message)
        .map_err(|error| format!("read uninstall watchdog commit acknowledgement: {error}"))?;
    if message[0] != UNINSTALL_WATCHDOG_ACK {
        return Err("uninstall watchdog commit acknowledgement is invalid".to_string());
    }
    Ok(())
}

pub(super) fn bind_uninstall_watchdog_listener() -> Result<UnixListener, String> {
    let path = Path::new(uninstall_watchdog_socket_path());
    if path_entry_exists(path)? {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("lstat stale uninstall watchdog socket: {error}"))?;
        if !metadata.file_type().is_socket() || metadata.uid() != 0 || metadata.gid() != 0 {
            return Err("uninstall watchdog socket path is not a root-owned socket".to_string());
        }
        fs::remove_file(path)
            .map_err(|error| format!("remove stale uninstall watchdog socket: {error}"))?;
        fsync_parent(path)?;
    }
    let listener = UnixListener::bind(path)
        .map_err(|error| format!("bind fixed uninstall watchdog socket: {error}"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("chmod uninstall watchdog socket: {error}"))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("lstat uninstall watchdog socket: {error}"))?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err("published uninstall watchdog socket identity is unsafe".to_string());
    }
    fsync_parent(path)?;
    Ok(listener)
}

pub(super) fn run_init_owned_uninstall_watchdog(self_bytes: &[u8]) -> Result<(), String> {
    let mut state = load_recovery_state()?;
    if state.recovery_sha256 != sha256_hex(self_bytes) {
        return Err("uninstall watchdog executable differs from recovery binding".to_string());
    }
    verify_restored_policy(&state)?;
    let mut directories = RetainedUninstallDirectories::open(&state)?;
    let terminal_lease;
    if state.phase == TerminalCleanupPhase::UninstallWatchdogArmed {
        let listener = bind_uninstall_watchdog_listener()?;
        let (mut stream, _) = listener
            .accept()
            .map_err(|error| format!("accept uninstall watchdog commit peer: {error}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(300)))
            .map_err(|error| format!("bound uninstall watchdog commit timeout: {error}"))?;
        require_root_uninstall_watchdog_peer(&stream, UNINSTALL_PRIMARY_ROLES)?;
        stream
            .write_all(&[UNINSTALL_WATCHDOG_READY])
            .map_err(|error| format!("publish uninstall watchdog readiness: {error}"))?;
        let mut message = [0u8; 1];
        stream
            .read_exact(&mut message)
            .map_err(|error| format!("read uninstall watchdog commit: {error}"))?;
        if message[0] != UNINSTALL_WATCHDOG_COMMIT {
            return Err("uninstall watchdog commit message is invalid".to_string());
        }
        terminal_lease = acquire_terminal_uninstall_lease(&state)?;
        terminal_lease.verify_owner()?;
        advance_terminal_cleanup_phase(
            &mut state,
            TerminalCleanupPhase::UninstallWatchdogCommitted,
        )?;
        replace_recovery_state(&state)?;
        stream
            .write_all(&[UNINSTALL_WATCHDOG_ACK])
            .map_err(|error| format!("acknowledge uninstall watchdog commit: {error}"))?;
    } else if !matches!(
        state.phase,
        TerminalCleanupPhase::UninstallWatchdogCommitted
            | TerminalCleanupPhase::UninstallSuccessorStarted
    ) {
        return Err("uninstall watchdog requires armed, committed or successor state".to_string());
    } else {
        terminal_lease = acquire_terminal_uninstall_lease(&state)?;
        terminal_lease.verify_owner()?;
    }
    prepare_uninstall_successor_root(&state, &directories)?;
    remove_terminal_socket()?;
    start_uninstall_successor_service()?;
    let mut successor = connect_uninstall_watchdog()?;
    require_root_uninstall_watchdog_peer(&successor, &[Some("--complete-uninstall")])?;
    let mut message = [0u8; 1];
    successor
        .read_exact(&mut message)
        .map_err(|error| format!("read uninstall successor readiness: {error}"))?;
    if message[0] != UNINSTALL_WATCHDOG_READY {
        return Err("uninstall successor readiness is invalid".to_string());
    }
    if state.phase == TerminalCleanupPhase::UninstallWatchdogCommitted {
        advance_terminal_cleanup_phase(
            &mut state,
            TerminalCleanupPhase::UninstallSuccessorStarted,
        )?;
        replace_recovery_state(&state)?;
    }
    state = armed_terminal_reboot_state(&state, &canonical_boot_id()?)?;
    replace_recovery_state(&state)?;
    publish_uninstall_status(
        &terminal_lease,
        Phase::UninstallAbsenceVerify,
        "reboot-required",
        1,
        None,
    )?;
    successor
        .write_all(&[UNINSTALL_SUCCESSOR_GO])
        .map_err(|error| format!("arm uninstall successor: {error}"))?;
    terminal_lease.verify_owner()?;
    perform_terminal_exact_zero(self_bytes, &state, &mut directories)?;
    let completion = successor.write_all(&[UNINSTALL_SUCCESSOR_DONE]);
    if let Err(error) = completion {
        if !uninstall_peer_lost(&error) {
            return Err(format!("publish uninstall successor completion: {error}"));
        }
    } else {
        // The successor is the sole reboot owner after DONE. It publishes
        // REBOOT_ARMED once init accepted its sys.powerctl request; until
        // then this watchdog keeps the authenticated connection open, so the
        // armed byte distinguishes "reboot in flight" from "successor died
        // before arming" — the fallback sweep below stays the only path that
        // may issue a watchdog reboot request (a competing request while init
        // is already shutting down is rejected, the v84 double-reboot exit).
        let armed = loop {
            match successor.read_exact(&mut message) {
                Ok(()) if message[0] == UNINSTALL_SUCCESSOR_REBOOT_ARMED => break true,
                Ok(()) => return Err("uninstall successor sent data after completion".to_string()),
                Err(error) if uninstall_peer_lost(&error) => break false,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) => {}
                Err(error) => {
                    return Err(format!("monitor uninstall successor reboot owner: {error}"))
                }
            }
        };
        if armed {
            // Init is already executing the successor's reboot. No sweep, no
            // competing request: the device reboots into a provably absent
            // Voboost state and this survivor exits with the successor's
            // completion.
            return Ok(());
        }
    }
    // The peer was authenticated before GO and is now provably absent. Two
    // fresh exact-zero passes close the crash window after the root was
    // deleted. The already-armed device predicate is the only reboot authority.
    perform_terminal_exact_zero(self_bytes, &state, &mut directories)?;
    perform_terminal_exact_zero(self_bytes, &state, &mut directories)?;
    reboot_terminal()
}

fn uninstall_peer_lost(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::NotConnected
    )
}

pub(super) fn run_init_owned_uninstall_successor(self_bytes: &[u8]) -> Result<(), String> {
    let mut state = load_recovery_state()?;
    if state.recovery_sha256 != sha256_hex(self_bytes)
        || !matches!(
            state.phase,
            TerminalCleanupPhase::UninstallWatchdogCommitted
                | TerminalCleanupPhase::UninstallSuccessorStarted
        )
    {
        return Err("uninstall successor lacks committed watchdog authority".to_string());
    }
    verify_restored_policy(&state)?;
    // Open the retained directory set lazily. The handover socket protocol
    // runs concurrently with the watchdog's terminal exact-zero, whose
    // protected /system window must end with a RO remount; any descriptor
    // this process holds on the init hook (an upperdir inode of the writable
    // /system overlay) pins that overlay and turns the closing remount into
    // EBUSY (observed as the v82 watchdog/successor EBUSY pair). The
    // descriptors are needed only for the post-GO fallback cleanup, so they
    // are opened there instead.
    let listener = bind_uninstall_watchdog_listener()?;
    let (mut stream, _) = listener
        .accept()
        .map_err(|error| format!("accept uninstall watchdog peer: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(300)))
        .map_err(|error| format!("bound uninstall successor timeout: {error}"))?;
    require_root_uninstall_watchdog_peer(&stream, &[Some("--watch-uninstall")])?;
    stream
        .write_all(&[UNINSTALL_WATCHDOG_READY])
        .map_err(|error| format!("publish uninstall successor readiness: {error}"))?;
    let mut message = [0u8; 1];
    stream
        .read_exact(&mut message)
        .map_err(|error| format!("read uninstall successor arm: {error}"))?;
    if message[0] != UNINSTALL_SUCCESSOR_GO {
        return Err("uninstall successor arm message is invalid".to_string());
    }
    // GO is sent only after the watchdog has durably published
    // UninstallSuccessorStarted. From this point the successor uses only the
    // already authenticated state and retained directory descriptors: the
    // recovery state, operation pointer, lock and executable are expected to
    // disappear during exact-zero cleanup.
    state.phase = TerminalCleanupPhase::UninstallSuccessorStarted;
    state = armed_terminal_reboot_state(&state, &canonical_boot_id()?)?;
    let watchdog_completed = match stream.read_exact(&mut message) {
        Ok(()) if message[0] == UNINSTALL_SUCCESSOR_DONE => true,
        Ok(()) => return Err("uninstall successor completion message is invalid".to_string()),
        Err(error) if uninstall_peer_lost(&error) => {
            // The watchdog died before its DONE byte. The init-owned
            // successor repeats the exact nofollow cleanup from retained file
            // descriptors before exercising its unique reboot authority.
            false
        }
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) =>
        {
            return Err(
                "uninstall watchdog completion timed out while peer remained authenticated"
                    .to_string(),
            )
        }
        Err(error) => return Err(format!("read uninstall watchdog completion: {error}")),
    };
    // This successor is the only remaining reboot owner from this point on:
    // whatever the fallback path does, a machine that stays up in the
    // terminal state has no absent-state publisher left (the v93 hang).
    if !watchdog_completed {
        // Open the retained set only now: the watchdog died before DONE, the
        // protected /system window is closed, and this fallback sweep needs
        // its own fresh nofollow descriptors. The watchdog's own sweep may
        // already be complete — it dies in the same ENOENT zone this open
        // sees — and in that case the proof below replaces a duplicated
        // sweep instead of failing the last reboot owner.
        match RetainedUninstallDirectories::open(&state).and_then(|mut directories| {
            perform_terminal_exact_zero(self_bytes, &state, &mut directories)
        }) {
            Ok(()) => {}
            Err(sweep_error) => {
                // Bare-path proof that the dead watchdog finished its exact
                // zero before dying: no zone, no init hook, no journal and
                // no app data may remain anywhere on the machine.
                let already_absent = !path_entry_exists(Path::new(ZONE))?
                    && !path_entry_exists(Path::new(RC_PATH))?
                    && !path_entry_exists(Path::new(remount_journal_path()))?
                    && require_app_data_absent_with(path_entry_exists).is_ok();
                if !already_absent {
                    return Err(format!("fallback terminal sweep failed: {sweep_error}"));
                }
            }
        }
    }
    reboot_terminal()?;
    // The watchdog survived its DONE and is still reading this authenticated
    // stream. Publishing REBOOT_ARMED after init accepted the request tells
    // it not to sweep again and not to issue a competing sys.powerctl while
    // init is shutting down (the v84 watchdog double-reboot exit). A failed
    // write here is harmless: the watchdog falls back to its own sweep and
    // reaches the terminal reboot only in the peer-lost branch.
    let _ = stream.write_all(&[UNINSTALL_SUCCESSOR_REBOOT_ARMED]);
    Ok(())
}

fn finish_pending_cluster_removal(
    detach_android: impl FnOnce() -> Result<(), String>,
    reboot: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    detach_android()?;
    reboot()
}

pub(super) fn run_terminal_cleanup(self_bytes: &[u8], lease: OperationLease) -> Result<(), String> {
    if !path_entry_exists(Path::new(recovery_state_path()))? {
        return Err("terminal cleanup authority is absent".to_string());
    }
    let mut state = load_recovery_state()?;
    if state.recovery_sha256 != sha256_hex(self_bytes) {
        return Err("uninstall recovery executable differs from its authority binding".to_string());
    }
    terminal_cleanup_boot_allowed(&state, &canonical_boot_id()?)?;
    verify_restored_policy(&state)?;
    if crate::cluster_recovery::pending(Path::new(ZONE), &state.transaction_id)? {
        let mut directories = RetainedUninstallDirectories::open(&state)?;
        return finish_pending_cluster_removal(
            || {
                remove_terminal_init_hook(&mut directories)?;
                remove_terminal_socket()?;
                publish_uninstall_status(
                    &lease,
                    Phase::UninstallAbsenceVerify,
                    "reboot-required",
                    1,
                    None,
                )
            },
            reboot_terminal,
        );
    }
    if state.phase == TerminalCleanupPhase::UninstallActive {
        run_terminal_transition(
            &mut state,
            TerminalCleanupPhase::UninstallWatchdogArmed,
            |_| Ok(()),
            replace_recovery_state,
        )?;
    }
    if state.phase == TerminalCleanupPhase::UninstallWatchdogArmed {
        return commit_to_uninstall_watchdog(lease);
    }
    if matches!(
        state.phase,
        TerminalCleanupPhase::UninstallWatchdogCommitted
            | TerminalCleanupPhase::UninstallSuccessorStarted
    ) {
        drop(lease);
        start_uninstall_watchdog_service()?;
        return Ok(());
    }
    Err("terminal uninstall watchdog phase is invalid".to_string())
}

pub(super) fn bound_boot_id_from_state(
    state: &RecoveryState,
    self_sha256: &str,
) -> Result<String, String> {
    if state.recovery_sha256 != self_sha256 {
        return Err("bound boot identity belongs to another uninstaller".to_string());
    }
    let boot_id = state
        .terminal_boot_id
        .as_deref()
        .ok_or_else(|| "terminal boot identity is not persisted".to_string())?;
    if !canonical_boot_id_text(boot_id) {
        return Err("persisted terminal boot identity is not canonical".to_string());
    }
    Ok(boot_id.to_string())
}

pub(super) fn get_uninstall_bound_boot_id(self_bytes: &[u8]) -> Result<String, String> {
    bound_boot_id_from_state(&load_recovery_state()?, &sha256_hex(self_bytes))
}

#[cfg(test)]
pub(super) fn validate_terminal_cleanup_boundary(
    terminal_boot_id: &str,
    current_boot_id: &str,
    phase: Phase,
    selinux_present: bool,
    package_present: bool,
) -> Result<(), String> {
    if !canonical_boot_id_text(terminal_boot_id)
        || !canonical_boot_id_text(current_boot_id)
        || terminal_boot_id != current_boot_id
    {
        return Err("terminal cleanup requires its bound current boot id".to_string());
    }
    if phase != Phase::UninstallAbsenceVerify {
        return Err("terminal cleanup phase is not armed".to_string());
    }
    if selinux_present || package_present {
        return Err("terminal cleanup found incomplete teardown".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod cluster_recovery_retention_tests {
    use super::*;
    #[test]
    fn pending_cluster_reboots_only_after_android_detachment() {
        let calls = std::cell::RefCell::new(Vec::new());
        finish_pending_cluster_removal(
            || {
                calls.borrow_mut().push("detach");
                Ok(())
            },
            || {
                calls.borrow_mut().push("reboot");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(*calls.borrow(), ["detach", "reboot"]);
        assert_eq!(
            finish_pending_cluster_removal(
                || Err("init hook remains".into()),
                || panic!("cannot reboot an unverified Android detachment"),
            )
            .unwrap_err(),
            "init hook remains"
        );
    }

    #[test]
    fn terminal_cleanup_preserves_complete_and_interrupted_cluster_snapshots() {
        assert!(require_no_pending_cluster_recovery(&[]).is_ok());
        assert!(require_no_pending_cluster_recovery(&[
            b"state.json".to_vec(),
            b"diag.log".to_vec()
        ])
        .is_ok());
        for entries in [
            vec![b"cluster".to_vec()],
            vec![b"recovery.json".to_vec()],
            vec![
                b"state.json".to_vec(),
                b"cluster".to_vec(),
                b"recovery.json".to_vec(),
            ],
        ] {
            assert!(require_no_pending_cluster_recovery(&entries).is_err());
        }
    }
}
