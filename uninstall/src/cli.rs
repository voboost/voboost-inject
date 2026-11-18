use super::*;

pub(crate) fn run() {
    let running = read_own_executable().unwrap_or_else(|error| fail("self.read", 1, error));
    let self_bytes = running.bytes.as_slice();
    if !appended_signature_valid(self_bytes) {
        fail("self.verify", 1, "bad appended signature".to_string());
    }
    let args = std::env::args().collect::<Vec<_>>();
    let uid = unsafe { libc::geteuid() };
    let cache_cleanup = args.as_slice().get(1).map(String::as_str)
        == Some("--cleanup-launcher-icons")
        && args.len() == 2
        && uid == 0;
    if cache_cleanup && std::fs::read("/sys/fs/selinux/enforce").ok().as_deref() != Some(b"0") {
        fail(
            "uninstall.icons",
            2,
            "emergency icon cleanup requires actual Permissive recovery".to_string(),
        );
    }
    let resource_role = resource_role_args(&args, uid);
    let watchdog = uninstall_watchdog_args_authorized(&args, uid);
    let successor = uninstall_successor_args_authorized(&args, uid);
    let bound_boot_id = get_uninstall_bound_boot_id_args_authorized(&args, uid);
    if !(args.len() == 1
        || watchdog
        || successor
        || bound_boot_id
        || cache_cleanup
        || resource_role.is_some())
    {
        fail(
            "trigger.check",
            2,
            "uninstall accepts only empty primary argv or an init-owned terminal role".to_string(),
        );
    }
    let current =
        std::env::current_exe().unwrap_or_else(|error| fail("self.path", 2, error.to_string()));
    if current != Path::new("/data/voboost/voboost-uninstall")
        || uid != 0
        || (!parent_is_init() && !cache_cleanup)
    {
        fail(
            "trigger.check",
            2,
            "uninstall requires root, init parent, and its fixed path".to_string(),
        );
    }
    let named = read_regular_nofollow(&current, MAX_SELF_BYTES)
        .unwrap_or_else(|error| fail("self.identity", 2, error));
    require_root_file(running.stamp, 0o700, "primary voboost-uninstall")
        .unwrap_or_else(|error| fail("self.identity", 2, error));
    if named.stamp != running.stamp || named.bytes != self_bytes {
        fail(
            "self.identity",
            2,
            "running uninstall differs from its fixed named inode".to_string(),
        );
    }
    if !cache_cleanup && running.selinux_context.as_deref() != Some(UNINSTALL_EXEC_CONTEXT) {
        fail(
            "self.label",
            2,
            "running uninstall has a foreign SELinux context".to_string(),
        );
    }
    if cache_cleanup {
        crate::cache_cleanup::cleanup_launcher(None)
            .unwrap_or_else(|error| fail("uninstall.icons", 10, error.to_string()));
        println!("launcher icon cache absent");
        return;
    }
    if let Some(role) = resource_role {
        let domain = std::fs::read("/proc/self/attr/current")
            .unwrap_or_else(|error| fail("resource.domain", 2, error.to_string()));
        if domain.split(|byte| *byte == 0 || *byte == b'\n').next()
            != Some(b"u:r:voboost_uninstall:s0".as_slice())
        {
            fail(
                "resource.domain",
                2,
                "resource role requires uninstall domain".into(),
            );
        }
        if role == "none" {
            crate::i18n_resource_files::finalize_none_verified(&RELEASE_CATALOG_PUBLIC_KEY)
                .unwrap_or_else(|error| fail("resource.none", 10, error.to_string()));
            return;
        }
        let active = operation_contract::read_active_in(Path::new(ZONE))
            .unwrap_or_else(|error| fail("resource.resume", 2, error));
        if !resource_resume_phase(active.as_ref()) {
            return;
        }
    }
    if watchdog || successor {
        // Init can start shutdown-critical services during the resource reboot.
        // Only the terminal journal authorizes them to touch uninstall state.
        let active = operation_contract::read_active_in(Path::new(ZONE))
            .unwrap_or_else(|error| fail("uninstall.terminal-admission", 2, error));
        if !terminal_service_phase(active.as_ref()) {
            return;
        }
    }
    let transaction_id = discover_uninstall_transaction_id()
        .unwrap_or_else(|error| fail("uninstall.paths", 2, error));
    initialize_uninstall_paths(&transaction_id)
        .unwrap_or_else(|error| fail("uninstall.paths", 2, error));
    if watchdog {
        run_init_owned_uninstall_watchdog(self_bytes)
            .unwrap_or_else(|error| fail("uninstall.watchdog", 10, error));
        return;
    }
    if successor {
        run_init_owned_uninstall_successor(self_bytes)
            .unwrap_or_else(|error| fail("uninstall.successor", 10, error));
        return;
    }
    if bound_boot_id {
        println!(
            "{}",
            get_uninstall_bound_boot_id(self_bytes).unwrap_or_else(|error| fail(
                "uninstall.bound-boot-id",
                10,
                error
            ))
        );
        return;
    }
    if resource_role == Some("resume") {
        // The caller resumes only the already verified AppRemove WAL.
        if load_phase().unwrap_or_else(|error| fail("resource.phase", 2, error))
            != Phase::UninstallAppRemove
        {
            fail(
                "resource.phase",
                2,
                "resource resume WAL phase differs".into(),
            );
        }
    }
    recover_pending_remounts().unwrap_or_else(|error| fail("remount.recover", 12, error));
    run_phase_machine(self_bytes).unwrap_or_else(|error| fail("uninstall.phase", 10, error));
}
