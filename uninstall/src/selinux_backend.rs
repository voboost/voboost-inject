//! Compile-time SELinux/init boundary for Uninstall.

use voboost_shared::uninstall_label_contract as labels;
pub(crate) const PROTECTED_CONTEXT: &str = labels::UNINSTALL_TREE_CONTEXT;
pub(crate) const INSTALLED_STATE_CONTEXT: &str = labels::INSTALLED_STATE_CONTEXT;
pub(crate) const DATA_CONTEXT: &str = labels::ROOT_CONTEXT;
pub(crate) const AGENT_STATE_CONTEXT: &str = labels::AGENT_STATE_TREE_CONTEXT;
pub(crate) const RECOVERY_TREE_CONTEXT: &str = labels::RECOVERY_TREE_CONTEXT;
pub(crate) const UNINSTALL_EXEC_CONTEXT: &str = labels::UNINSTALL_CONTEXT;
pub(crate) const SELINUX_EXEC_CONTEXT: &str = labels::SELINUX_CONTEXT;
pub(crate) const RESTORE_EXEC_CONTEXT: &str = labels::RESTORE_CONTEXT;
pub(crate) const STOCK_RECOVERY_CONTEXT: &str = labels::RESTORE_CONTEXT;
pub(crate) const RUNTIME_EXEC_CONTEXT: &str = labels::RUNTIME_CONTEXT;

pub(crate) fn restore_policy_with<Publish>(_publish: Publish) -> Result<(), String>
where
    Publish: FnOnce() -> Result<(), String>,
{
    _publish()
}

pub(crate) fn recovery_state_context(current: Option<&str>) -> Result<&'static str, String> {
    if current == Some(PROTECTED_CONTEXT) {
        return Ok(PROTECTED_CONTEXT);
    }
    if current == Some("u:object_r:system_data_file:s0") {
        return Ok("u:object_r:system_data_file:s0");
    }
    Err("current uninstall recovery state has a foreign context".to_string())
}

pub(crate) const RECOVERY_HOOK_BYTES: &[u8] = b"# >>> voboost-daemon (do not edit)\n\
# terminal-only autonomous uninstall hook\n\
# The capability line mirrors the voboost_uninstall domain grant in\n\
# selinux/voboost.te: init applies the declared capabilities and the terminal\n\
# /vendor remount needs CAP_SYS_ADMIN in the effective set.\n\
service voboost-uninstall-watchdog /data/voboost/voboost-uninstall --watch-uninstall\n\
    capabilities DAC_READ_SEARCH DAC_OVERRIDE KILL SYS_ADMIN SYS_BOOT SYS_PTRACE\n\
    class late_start\n    user root\n    group root\n    disabled\n    shutdown critical\n    seclabel u:r:voboost_uninstall:s0\n\
\n\
service voboost-uninstall-successor /data/voboost/voboost-uninstall --complete-uninstall\n\
    capabilities DAC_READ_SEARCH DAC_OVERRIDE KILL SYS_ADMIN SYS_BOOT SYS_PTRACE\n\
    class late_start\n    user root\n    group root\n    disabled\n    shutdown critical\n    seclabel u:r:voboost_uninstall:s0\n";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_policy_restore_invokes_publication() {
        let mut publications = 0;
        restore_policy_with(|| {
            publications += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(publications, 1);

        assert_eq!(
            restore_policy_with(|| Err("publication failed".to_string())).unwrap_err(),
            "publication failed"
        );
    }
}
