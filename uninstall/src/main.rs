use voboost_contract::resource_none_helper;
mod cache_cleanup;
mod cluster_recovery;
#[path = "../../shared/src/i18n_resource_files.rs"]
mod i18n_resource_files;
mod selinux_backend;
mod transaction;

fn main() {
    transaction::run();
}
