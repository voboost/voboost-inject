//! Durable Cluster mailbox state shared by privileged product operations.
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use voboost_contract::{
    cluster::{self, DeliveryState, DesiredAgent, Receipt, Request},
    cluster_wire::{self, Transport, WireFile},
};

pub const INITIAL_MAILBOX: &[u8] = b"{\"schemaVersion\":1,\"initializing\":true}\n";
const MAX_SAFE: u64 = 9_007_199_254_740_991;
type Result<T> = std::result::Result<T, String>;

fn raw32(text: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(text).map_err(|_| "invalid device public key")?;
    bytes
        .try_into()
        .map_err(|_| "device public key must be raw32".into())
}

/// Provisioned only by the root installer/operator. No app request accepts these fields.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Provision {
    pub schema_version: u32,
    pub pair_id: String,
    pub authority_epoch: String,
    pub android_public_key: String,
    pub qnx_public_key: String,
    pub transport: Transport,
}
impl Provision {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || ![
                &self.pair_id,
                &self.authority_epoch,
                &self.android_public_key,
                &self.qnx_public_key,
            ]
            .iter()
            .all(|s| voboost_contract::release::lower_hash(s))
            || self.android_public_key == self.qnx_public_key
        {
            return Err("invalid explicit Cluster pairing".into());
        }
        VerifyingKey::from_bytes(&raw32(&self.android_public_key)?)
            .map_err(|_| "invalid Android desired authority key")?;
        VerifyingKey::from_bytes(&raw32(&self.qnx_public_key)?)
            .map_err(|_| "invalid QNX receipt authority key")?;
        self.transport.validate()
    }
    /// Enforce separation from all four product signing roles supplied by the caller.
    pub fn validate_roles(&self, roles: &[&[u8; 32]; 4]) -> Result<()> {
        self.validate()?;
        let android = raw32(&self.android_public_key)?;
        let qnx = raw32(&self.qnx_public_key)?;
        if roles.iter().any(|role| **role == android || **role == qnx) {
            return Err("device and release authorities must be distinct".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Lease {
    pub id: String,
    pub boot_id: String,
    pub until_ms: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Pending {
    pub request: Request,
    pub files: Vec<WireFile>,
    pub lease: Option<Lease>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct State {
    pub schema_version: u32,
    pub android_boot_id: String,
    pub android_daemon_epoch: String,
    pub catalog_sha256: String,
    pub closure_sha256: String,
    pub desired_revision: u64,
    pub desired_sha256: String,
    pub agents: Vec<DesiredAgent>,
    pub expected_targets: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub global_locale: Option<cluster::GlobalLocale>,
    pub snapshot_revision: u64,
    pub generation: Option<Receipt>,
    pub observed: Option<Receipt>,
    pub observed_owner_epoch: Option<String>,
    pub delivery_state: DeliveryState,
    pub pending: Option<Pending>,
}
impl State {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.android_boot_id.is_empty()
            || !voboost_contract::release::lower_hash(&self.android_daemon_epoch)
            || ![
                &self.catalog_sha256,
                &self.closure_sha256,
                &self.desired_sha256,
            ]
            .iter()
            .all(|s| voboost_contract::release::lower_hash(s))
            || self.desired_revision > MAX_SAFE
            || self.snapshot_revision == 0
            || self.snapshot_revision > MAX_SAFE
            || cluster::desired_digest(&self.agents)? != self.desired_sha256
        {
            return Err("invalid durable Cluster authority".into());
        }
        if self.expected_targets.len() < self.agents.len()
            || self
                .agents
                .iter()
                .any(|a| !self.expected_targets.contains_key(&a.id))
            || self.expected_targets.values().map(Vec::len).sum::<usize>() > 64
        {
            return Err("invalid expected Cluster target inventory".into());
        }
        for targets in self.expected_targets.values() {
            if targets.is_empty()
                || targets.windows(2).any(|v| v[0] >= v[1])
                || targets
                    .iter()
                    .any(|t| !matches!(t.as_str(), "gauge" | "point" | "light"))
            {
                return Err("invalid expected Cluster target process".into());
            }
        }
        if let Some(locale) = &self.global_locale {
            locale.validate()?;
        }
        if let Some(p) = &self.pending {
            p.request.validate()?;
            cluster_wire::validate_files(&p.files, true)?;
            if p.request.catalog_sha256 != self.catalog_sha256
                || p.request.closure_sha256 != self.closure_sha256
            {
                return Err("pending operation is not current closure".into());
            }
            if let Some(l) = &p.lease {
                if !voboost_contract::release::lower_hash(&l.id) || l.boot_id.is_empty() {
                    return Err("invalid durable lease".into());
                }
            }
        }
        if let Some(g) = &self.generation {
            g.validate()?;
            if g.kind != cluster::ReceiptKind::Generation
                || g.catalog_sha256 != self.catalog_sha256
                || g.closure_sha256 != self.closure_sha256
            {
                return Err("admitted QNX generation mismatch".into());
            }
        }
        if let Some(o) = &self.observed {
            o.validate()?;
            self.validate_receipt_targets(o)?;
            if self.generation.as_ref().map(|g| g.generation_id.as_str())
                != Some(o.generation_id.as_str())
            {
                return Err("observation has no accepted QNX generation".into());
            }
        }
        Ok(())
    }
    pub fn validate_receipt_targets(&self, receipt: &Receipt) -> Result<()> {
        if receipt.agents.iter().any(|row| {
            !self
                .expected_targets
                .get(&row.id)
                .is_some_and(|targets| targets.contains(&row.target_process))
        }) {
            return Err("receipt target outside admitted catalog".into());
        }
        Ok(())
    }
}

/// Read the protected signed request without modifying its durable authority.
pub fn read_signed_request(
    dir: &crate::secure_fs::Directory,
    provision: &Provision,
    key: &ed25519_dalek::SigningKey,
) -> Result<Option<(Request, Vec<u8>)>> {
    if !dir.entry_exists("request.vbc").map_err(|e| e.to_string())? {
        return Ok(None);
    }
    let signed = dir
        .read_trusted("request.vbc", 65536, 0o600)
        .map_err(|e| e.to_string())?;
    let request = Request::verify(&signed, &key.verifying_key())?;
    if request.pair_id != provision.pair_id || request.authority_epoch != provision.authority_epoch
    {
        return Err("signed Cluster request pairing differs".into());
    }
    Ok(Some((request, signed)))
}

/// Reject a product mutation when Cluster uninstall owns the durable mailbox.
/// Caller must hold the shared product operation lock for this entire check and
/// through the subsequent mutation; this reader does not migrate mailbox state.
pub fn reject_pending_uninstall(root: &std::path::Path, roles: &[&[u8; 32]; 4]) -> Result<()> {
    use crate::secure_fs::Directory;
    use ed25519_dalek::SigningKey;
    use std::time::Duration;
    let product = Directory::open(root).map_err(|e| e.to_string())?;
    let owner = unsafe { libc::geteuid() };
    let group = unsafe { libc::getegid() };
    product
        .validate_owner_not_writable(owner, group)
        .map_err(|e| e.to_string())?;
    if !product.entry_exists("cluster").map_err(|e| e.to_string())? {
        return Ok(());
    }
    let dir = product.open_child("cluster").map_err(|e| e.to_string())?;
    dir.validate_owner_mode(owner, group, 0o700)
        .map_err(|e| e.to_string())?;
    let _lock = dir
        .lock_transaction(Duration::from_millis(500))
        .map_err(|e| e.to_string())?;
    let exists = |name| dir.entry_exists(name).map_err(|e| e.to_string());
    let paired = exists("provision.json")?;
    let has_mailbox = exists("mailbox.json")?;
    let uninstall_members = [
        "uninstall-report.vbc",
        "uninstall-final-report.vbc",
        "uninstall-provisional-report.vbc",
        "uninstall-delivery-owner.json",
    ];
    for name in uninstall_members {
        if exists(name)? {
            return Err("Cluster uninstall pending or orphaned; product mutation blocked".into());
        }
    }
    if !paired {
        for name in ["device-signing.seed", "transport.p12", "request.vbc"] {
            if exists(name)? {
                return Err("partial Cluster authority retained".into());
            }
        }
    }
    let provision = if paired {
        let bytes = dir
            .read_trusted("provision.json", 16 * 1024, 0o600)
            .map_err(|e| e.to_string())?;
        let provision: Provision =
            voboost_contract::domain_core::parse_canonical(&bytes, 16 * 1024)?;
        provision.validate_roles(roles)?;
        let mut seed = dir
            .read_trusted("device-signing.seed", 32, 0o600)
            .map_err(|e| e.to_string())?;
        let mut raw: [u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| "device seed must be raw32")?;
        let key = SigningKey::from_bytes(&raw);
        raw.fill(0);
        seed.fill(0);
        if key.verifying_key().to_bytes() != raw32(&provision.android_public_key)? {
            return Err("desired authority seed is not the paired Android key".into());
        }
        let credentials = dir
            .read_trusted("transport.p12", 65536, 0o600)
            .map_err(|e| e.to_string())?;
        if credentials.len() as u64 != provision.transport.credentials.size {
            return Err("paired transport credentials size differs".into());
        }
        Some((provision, key))
    } else {
        None
    };
    if !has_mailbox {
        if paired {
            return Err("provisioned Cluster mailbox missing; authority retained".into());
        }
        return Ok(());
    }
    // request.vbc is published before the mailbox commit. A signed uninstall
    // without matching durable authority is ambiguous with lost old authority,
    // so retain it; a signed non-uninstall may be a harmless retry cut.
    let request_file = if exists("request.vbc")? {
        let (provision, key) = provision
            .as_ref()
            .ok_or("request without Cluster pairing")?;
        let (request, _) = read_signed_request(&dir, provision, key)?
            .ok_or("signed Cluster request disappeared")?;
        if request.kind == cluster::RequestKind::Uninstall {
            return Err("Cluster uninstall pending or orphaned; product mutation blocked".into());
        }
        Some(request)
    } else {
        None
    };
    let bytes = dir
        .read_trusted("mailbox.json", 256 * 1024, 0o600)
        .map_err(|e| e.to_string())?;
    if bytes == INITIAL_MAILBOX {
        return if paired {
            Ok(())
        } else {
            Err("partial Cluster initialization retained".into())
        };
    }
    let state: State = voboost_contract::domain_core::parse_canonical(&bytes, 256 * 1024)?;
    state.validate()?;
    if let Some(pending) = &state.pending {
        let (provision, _) = provision
            .as_ref()
            .ok_or("pending Cluster authority without pairing")?;
        if pending.request.pair_id != provision.pair_id
            || pending.request.authority_epoch != provision.authority_epoch
        {
            return Err("pending Cluster pairing differs".into());
        }
        if pending.request.kind == cluster::RequestKind::Uninstall {
            return Err("Cluster uninstall pending; product mutation blocked".into());
        }
        if request_file.is_none() {
            return Err("pending Cluster request file missing".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod admission_lock_tests {
    use super::*;
    use crate::secure_fs::Directory;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    #[test]
    fn temporary_owner_snapshot_does_not_reject_product_admission() {
        let root = tempfile::tempdir().unwrap();
        let cluster = root.path().join("cluster");
        std::fs::create_dir(&cluster).unwrap();
        std::fs::set_permissions(&cluster, std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory = Directory::open(&cluster).unwrap();
        let guard = directory.lock_transaction(Duration::ZERO).unwrap();
        let path = root.path().to_owned();
        let (started, ready) = std::sync::mpsc::sync_channel(1);
        let (completed, result) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            started.send(()).unwrap();
            let key = [0u8; 32];
            completed
                .send(reject_pending_uninstall(&path, &[&key; 4]))
                .unwrap();
        });
        ready.recv().unwrap();
        let early = result.recv_timeout(Duration::from_millis(80));
        drop(guard);
        assert!(
            matches!(early, Err(std::sync::mpsc::RecvTimeoutError::Timeout)),
            "temporary owner snapshot was treated as terminal: {early:?}"
        );
        assert!(result.recv_timeout(Duration::from_secs(2)).unwrap().is_ok());
        worker.join().unwrap();
    }
}
