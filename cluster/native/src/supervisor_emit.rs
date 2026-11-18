//! Fixed candidate composition on QNX. The proved emitter and splice build
//! the candidate offline, byte-for-byte from the actual retained OEM tables
//! of /usr/bin/clusterboot; no OEM generator command is ever executed.
use crate::Result;
use alloc::vec::Vec;
#[path = "supervisor_defaults.rs"]
mod defaults;
use super::xml;

/// Rotate only the nonce in the retained own delivery (update path).
pub(crate) fn rotate_nonce(
    xml: &[u8],
    implant: &str,
    bootfile: &str,
    old_nonce: &str,
    new_nonce: &str,
) -> Result<Vec<u8>> {
    xml::rotate_nonce(xml, implant, bootfile, old_nonce, new_nonce)
}

const CLUSTERBOOT: &str = "/usr/bin/clusterboot";
/// Staged full candidate for an originally-absent config file, or an
/// exact-byte augment of the live OEM XML when one exists.
pub(crate) fn candidate(
    live: Option<&[u8]>,
    implant: &str,
    bootfile: &str,
    nonce: &str,
) -> Result<Vec<u8>> {
    match live {
        Some(bytes) => xml::augment(bytes, implant, bootfile, nonce),
        None => {
            let tables = crate::elf::read(CLUSTERBOOT, 8 * 1024 * 1024)?;
            let defaults = defaults::emit(&tables)?;
            xml::augment(&defaults, implant, bootfile, nonce)
        }
    }
}
