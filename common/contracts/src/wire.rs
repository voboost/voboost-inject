//! Descriptor-only local mailbox protocol and credential-free network framing.
use crate::{
    ascii_json, basename, digest, parse_canonical, printable, Result, MAX_CLOSURE_BYTES,
    MAX_DOCUMENT_BYTES, MAX_FILE_BYTES,
};
use alloc::{collections::BTreeSet, string::String, vec::Vec};
use serde::{Deserialize, Serialize};
pub const MAX_WIRE_FILES: usize = 252;
pub const MAX_CREDENTIAL_BYTES: u64 = 65_536;
pub const LEASE_MILLIS: u64 = 30_000;
/// A protected Cluster provision attempt may be retried with the same staged files.
pub const PROVISION_BUSY_EXIT: i32 = 75;
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WireRole {
    Request,
    ReleaseManifest,
    ReleaseManifestSignature,
    AgentCatalog,
    AgentCatalogSignature,
    Daemon,
    Install,
    Restore,
    Uninstall,
    Init,
    Implant,
    AgentCommon,
    AgentModule,
    QnxDaemon,
    QnxInit,
    QnxImplant,
    QnxRuntime,
    QnxAgentModule,
    QnxResourcePack,
    QnxResourceLedger,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireFile {
    pub role: WireRole,
    pub file: String,
    pub size: u64,
    pub sha256: String,
}
pub fn validate_files(files: &[WireFile], require_request: bool) -> Result<()> {
    if files.is_empty() || files.len() > MAX_WIRE_FILES {
        return Err("wire file count invalid".into());
    }
    let mut names = BTreeSet::new();
    let mut total = 0u64;
    for (i, f) in files.iter().enumerate() {
        if !basename(&f.file)
            || !names.insert(&f.file)
            || f.size == 0
            || f.size > MAX_FILE_BYTES
            || !digest(&f.sha256)
        {
            return Err("invalid wire descriptor".into());
        }
        if f.role == WireRole::Request
            && (i != 0 || f.file != "request.vbc" || f.size > MAX_DOCUMENT_BYTES as u64)
        {
            return Err("invalid request descriptor position".into());
        }
        if matches!(
            f.role,
            WireRole::QnxResourcePack | WireRole::QnxResourceLedger
        ) || f.file.starts_with("qnx-resource-i18n-ru-")
        {
            use crate::release::{Abi, Activation, ArtifactRole};
            let pack = f.role == WireRole::QnxResourcePack;
            let expected = if pack {
                ArtifactRole::QnxResourcePack
            } else {
                ArtifactRole::QnxResourceLedger
            };
            if !matches!(
                f.role,
                WireRole::QnxResourcePack | WireRole::QnxResourceLedger
            ) || crate::release::classify(&f.file)?
                != (expected, Activation::AgentGeneration, Some(Abi::QnxAarch64))
                || f.size > if pack { 16 * 1024 * 1024 } else { 1024 * 1024 }
            {
                return Err("QNX resource wire role or bound differs".into());
            }
            let (suffix, other_suffix, role) = if pack {
                (".kzb", ".json", WireRole::QnxResourceLedger)
            } else {
                (".json", ".kzb", WireRole::QnxResourcePack)
            };
            let peer = alloc::format!(
                "{}{other_suffix}",
                f.file
                    .strip_suffix(suffix)
                    .ok_or("QNX resource wire suffix")?
            );
            if !files.iter().any(|v| v.file == peer && v.role == role) {
                return Err("QNX resource wire pair absent".into());
            }
        }
        total = total.checked_add(f.size).ok_or("wire total overflow")?;
    }
    if total > MAX_CLOSURE_BYTES
        || require_request && (files[0].role != WireRole::Request || files[0].file != "request.vbc")
    {
        return Err("invalid wire closure envelope".into());
    }
    Ok(())
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlobIdentity {
    pub size: u64,
    pub sha256: String,
}
impl BlobIdentity {
    pub fn validate(&self) -> Result<()> {
        if self.size == 0 || self.size > MAX_CREDENTIAL_BYTES || !digest(&self.sha256) {
            Err("invalid bounded blob identity".into())
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Transport {
    pub host: String,
    pub port: u16,
    pub server_certificate_sha256: String,
    pub client_certificate_sha256: String,
    pub credentials: BlobIdentity,
}
impl Transport {
    pub fn validate(&self) -> Result<()> {
        if self.host.is_empty()
            || self.host.len() > 255
            || !self
                .host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
            || self.port == 0
            || !digest(&self.server_certificate_sha256)
            || !digest(&self.client_certificate_sha256)
        {
            return Err("invalid paired transport endpoint".into());
        }
        self.credentials.validate()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TakeResult {
    Empty {},
    Busy {},
    SetupRequired {},
    Ready {
        #[serde(rename = "leaseId")]
        lease_id: String,
        #[serde(rename = "transactionId")]
        transaction_id: String,
        #[serde(rename = "leaseMillis")]
        lease_millis: u64,
        transport: Transport,
        files: Vec<WireFile>,
    },
}
impl TakeResult {
    pub fn validate(&self) -> Result<()> {
        if let Self::Ready {
            lease_id,
            transaction_id,
            lease_millis,
            transport,
            files,
        } = self
        {
            if !digest(lease_id) || !digest(transaction_id) || *lease_millis != LEASE_MILLIS {
                return Err("invalid mailbox lease".into());
            }
            transport.validate()?;
            validate_files(files, true)?;
        }
        Ok(())
    }
    pub fn descriptor_count(&self) -> usize {
        match self {
            Self::Ready { files, .. } => files.len() + 1,
            _ => 0,
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportOutcome {
    Delivered,
    Unavailable,
    Failed,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "request", deny_unknown_fields)]
pub enum LocalRequest {
    #[serde(rename = "clusterDeliveryTake")]
    Take {
        #[serde(rename = "protocolVersion")]
        protocol_version: u32,
        #[serde(rename = "requestId")]
        request_id: String,
    },
    #[serde(rename = "clusterDeliveryResult")]
    Result {
        #[serde(rename = "protocolVersion")]
        protocol_version: u32,
        #[serde(rename = "requestId")]
        request_id: String,
        #[serde(rename = "leaseId")]
        lease_id: String,
        #[serde(rename = "transactionId")]
        transaction_id: String,
        #[serde(rename = "transportOutcome")]
        transport_outcome: TransportOutcome,
        #[serde(skip_serializing_if = "Option::is_none")]
        receipt: Option<BlobIdentity>,
    },
}
impl LocalRequest {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let v: Self = parse_canonical(bytes, MAX_DOCUMENT_BYTES)?;
        v.validate()?;
        Ok(v)
    }
    pub fn validate(&self) -> Result<()> {
        let (protocol, id) = match self {
            Self::Take {
                protocol_version,
                request_id,
            } => (*protocol_version, request_id),
            Self::Result {
                protocol_version,
                request_id,
                ..
            } => (*protocol_version, request_id),
        };
        if protocol != 1 || !digest(id) {
            return Err("invalid cluster local request identity".into());
        }
        if let Self::Result {
            lease_id,
            transaction_id,
            transport_outcome,
            receipt,
            ..
        } = self
        {
            if !digest(lease_id) || !digest(transaction_id) {
                return Err("invalid result correlation".into());
            }
            match (transport_outcome, receipt) {
                (TransportOutcome::Delivered, Some(r)) => r.validate()?,
                (TransportOutcome::Failed | TransportOutcome::Unavailable, None) => {}
                _ => return Err("receipt/transport outcome mismatch".into()),
            }
        }
        Ok(())
    }
    pub fn descriptor_count(&self) -> usize {
        match self {
            Self::Result {
                transport_outcome: TransportOutcome::Delivered,
                ..
            } => 1,
            _ => 0,
        }
    }
    pub fn request_id(&self) -> &str {
        match self {
            Self::Take { request_id, .. } | Self::Result { request_id, .. } => request_id,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "lowercase", deny_unknown_fields)]
pub enum ResultStatus {
    Recorded {},
    Rejected { reason: String },
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "response", deny_unknown_fields)]
pub enum LocalResponse {
    #[serde(rename = "clusterDeliveryTake")]
    Take {
        #[serde(rename = "protocolVersion")]
        protocol_version: u32,
        #[serde(rename = "requestId")]
        request_id: String,
        result: TakeResult,
    },
    #[serde(rename = "clusterDeliveryResult")]
    Result {
        #[serde(rename = "protocolVersion")]
        protocol_version: u32,
        #[serde(rename = "requestId")]
        request_id: String,
        result: ResultStatus,
    },
}
impl LocalResponse {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::Take {
                protocol_version,
                request_id,
                result,
            } => {
                if *protocol_version != 1 || !digest(request_id) {
                    return Err("invalid local response identity".into());
                }
                result.validate()?;
            }
            Self::Result {
                protocol_version,
                request_id,
                result,
            } => {
                if *protocol_version != 1 || !digest(request_id) {
                    return Err("invalid local result identity".into());
                }
                if let ResultStatus::Rejected { reason } = result {
                    if !printable(reason, 128) {
                        return Err("invalid rejection reason".into());
                    }
                }
            }
        }
        ascii_json(self)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkHeader {
    pub protocol_version: u32,
    pub files: Vec<WireFile>,
}
impl NetworkHeader {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let v: Self = parse_canonical(bytes, MAX_DOCUMENT_BYTES)?;
        if v.protocol_version != 1 {
            return Err("network protocol mismatch".into());
        }
        validate_files(&v.files, true)?;
        Ok(v)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        if self.protocol_version != 1 {
            return Err("network protocol mismatch".into());
        }
        validate_files(&self.files, true)?;
        ascii_json(self)
    }
}
pub fn frame(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.is_empty() || bytes.len() > MAX_DOCUMENT_BYTES {
        return Err("frame bound exceeded".into());
    }
    let mut framed = (bytes.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(bytes);
    Ok(framed)
}
