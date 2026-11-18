//! On-disk layout of the generation store, shared by both privileged binaries.
//!
//! The inject binary owns the generation store; the owner daemon reads the
//! active catalog to expand a saved checkbox into its signed dependencies.
//! Both binaries include this file, so the two readers cannot drift onto
//! different file names.

pub use voboost_contract::domain_core::install_layout::{
    CURRENT as ACTIVE_POINTER, GENERATIONS as GENERATIONS_DIR,
};
/// Signed agent catalog inside one generation directory.
pub const CATALOG_FILE: &str = "agents.json";
/// Detached signature of [`CATALOG_FILE`].
pub const CATALOG_SIGNATURE_FILE: &str = "agents.json.sig";
/// Mode of every file inside a generation directory.
pub const GENERATION_FILE_MODE: u32 = 0o444;
/// Mode of a generation directory itself.
pub const GENERATION_DIR_MODE: u32 = 0o555;
