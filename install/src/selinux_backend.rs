//! Compile-time SELinux/init boundary for Install.

#[allow(dead_code)]
use voboost_shared::uninstall_label_contract as inventory_labels;
pub(crate) const INVENTORY_CONTEXT: &str = inventory_labels::UNINSTALL_TREE_CONTEXT;
