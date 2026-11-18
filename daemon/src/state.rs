//! Inject state routing. Runtime storage is available only through the daemon.
#[cfg(test)]
#[path = "owner/state.rs"]
#[allow(dead_code)]
mod fixture;
#[cfg(test)]
pub(crate) use fixture::*;
#[cfg(not(test))]
mod client;
#[cfg(not(test))]
pub(crate) use client::*;

// The inject host fixture has no resident owner or early-capture authority.
#[cfg(test)]
mod initial_seeding {
    use super::fixture::ReadOutcome;
    use std::path::Path;
    pub(super) fn read(
        _: &Path,
        _: &str,
        _: &str,
        _: bool,
        f: impl FnOnce() -> ReadOutcome,
    ) -> ReadOutcome {
        f()
    }
    pub(super) fn write(
        _: &Path,
        _: &str,
        _: &[u8],
        _: bool,
        f: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        f()
    }
}
