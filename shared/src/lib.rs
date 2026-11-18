//! voboost-shared — the one shared library of the device-side binaries.
//!
//! Every module here is compiled once and linked into the daemon, install,
//! restore and uninstall executables; the previous `#[path]`-include model
//! (a separate compilation of the same source per binary) and the restore
//! borrow of `daemon/src/secure_fs.rs` are gone. The invariants defined in
//! these files (canonical APK-path acceptance, fixed-process bounds, the
//! lifecycle transactions and the label contracts) now have a single
//! definition and a single test suite.

pub mod cluster_mailbox;
pub mod daemon_label_contract;
pub mod early_none_gate;
pub mod fixed_process;
pub mod installed_apk;
pub mod installed_state;
pub mod lifecycle_file;
pub mod mount_policy_transaction;
pub mod native_executable_signature;
pub mod native_release_bundle;
pub mod protected_block;
pub mod protected_system_transaction;
pub mod pw_transport_process;
pub mod secure_fs;
pub mod self_executable;
pub mod uninstall_contract;
pub mod uninstall_label_contract;

// `lifecycle_mounts`, `lifecycle_secure_fs` and
// `lifecycle_uninstall_terminal` are intentionally NOT part of this crate:
// they are the uninstall-only lifecycle whose code shares module scope with
// `uninstall/src/transaction.rs` (the terminal WAL state machine, retained
// descriptors and phase vocabulary stay in the one-shot teardown binary).
// The files remain in this directory and stay `#[path]`-included by
// uninstall so that their compilation context is explicit.

pub mod package_execution;

pub mod resource_target;

pub mod owned_overlay;

pub mod observed_locale;

mod child_privileges;

pub mod diagnostic_log;

mod powertrain;
pub mod vehicle_profile;
