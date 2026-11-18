//! Compile-time SELinux boundary for the daemon.

use voboost_shared::daemon_label_contract as labels;
pub(crate) const PROTECTED_CONTEXT: &str = labels::UNINSTALL_TREE_CONTEXT;
pub(crate) const RESULT_CONTEXT: &str = labels::UNINSTALL_REPLY_CONTEXT;
pub(crate) const DATA_CONTEXT: &str = labels::ROOT_CONTEXT;

pub(crate) fn verify_runtime_preconditions() -> Result<(), String> {
    {
        let enforcing = crate::fixed_process::output(
            "/system/bin/getenforce",
            &[],
            std::time::Duration::from_secs(5),
            64,
        )?;
        if !enforcing.status.success()
            || !enforcing.stderr.is_empty()
            || enforcing.stdout != b"Enforcing\n"
        {
            return Err("SELinux is not enforcing".into());
        }
    }
    Ok(())
}
