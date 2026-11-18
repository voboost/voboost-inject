//! Shared verified contracts for Voboost privileged binaries.

pub mod agent_catalog;
pub mod apk;
pub mod generation;
pub mod install;
pub mod operation;
pub mod product_update;
pub mod release;
pub mod resource;
pub mod status;
pub mod system_update;
pub mod uninstall_request;

pub mod install_acceptance;

pub mod icon_cache_quiescence;

pub use voboost_contract_core::{
    self as domain_core, catalog as domain_catalog, cluster, cluster_log,
    generation as domain_generation, pw_live as cluster_pw_live, wire as cluster_wire,
};

#[cfg(test)]
mod resource_release_tests;

pub mod resource_none_helper;

pub mod desired;
pub mod native_agent;
pub mod runtime_log;
pub mod runtime_owner;

pub mod strict_json;
