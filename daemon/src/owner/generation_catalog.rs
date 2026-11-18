//! Shared read-only verification of the resident owner's active agent catalog.
use crate::generation_layout::{
    ACTIVE_POINTER, CATALOG_FILE, CATALOG_SIGNATURE_FILE, GENERATIONS_DIR, GENERATION_FILE_MODE,
};
use ed25519_dalek::{Signature, VerifyingKey};
use std::io;
use std::path::Path;
use voboost_contract::agent_catalog::AgentCatalog;
use voboost_shared::secure_fs::Directory;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

pub(super) fn active(root: &Path) -> io::Result<(Directory, String)> {
    let generations = Directory::open(root)?.open_child(GENERATIONS_DIR)?;
    let active = generations.read_trusted(ACTIVE_POINTER, 65, GENERATION_FILE_MODE)?;
    let active = std::str::from_utf8(&active).map_err(|_| invalid("active generation invalid"))?;
    let id = active
        .strip_suffix('\n')
        .ok_or_else(|| invalid("active generation invalid"))?;
    if id.len() != 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("active generation invalid"));
    }
    Ok((generations, id.into()))
}

pub(super) fn read(generations: &Directory, id: &str) -> io::Result<AgentCatalog> {
    let generation = generations.open_child(id)?;
    let bytes = generation.read_trusted(
        CATALOG_FILE,
        voboost_contract::agent_catalog::MAX_CATALOG_BYTES,
        GENERATION_FILE_MODE,
    )?;
    let signature = generation.read_trusted(CATALOG_SIGNATURE_FILE, 64, GENERATION_FILE_MODE)?;
    let signature = Signature::from_slice(&signature)
        .map_err(|_| invalid("agent catalog signature invalid"))?;
    VerifyingKey::from_bytes(&crate::native_binary::AGENT_CATALOG_PUBKEY)
        .map_err(|_| invalid("agent catalog key invalid"))?
        .verify_strict(&bytes, &signature)
        .map_err(|_| invalid("agent catalog signature rejected"))?;
    AgentCatalog::parse(&bytes).map_err(invalid)
}

pub(super) fn core_path(root: &Path, id: &str, file: &str) -> std::path::PathBuf {
    root.join(GENERATIONS_DIR).join(id).join(file)
}
