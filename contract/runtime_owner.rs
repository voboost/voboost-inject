//! Fixed internal messages between the resident owner and injection process.
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SCHEMA: u8 = 1;
pub const ROOT_ZONE: &str = "/data/voboost";
pub const RUN_DIR: &str = "/data/voboost/run";
pub const STATE_DIR: &str = "/data/voboost/state";
pub const LOG_DIR: &str = "/data/voboost/logs";
pub const RUN_DIR_MODE: u32 = 0o755;
pub const OWNER_PID_NAME: &str = "daemon.pid";
pub const INJECT_PID_NAME: &str = "inject.pid";
pub const MAX_NATIVE_EXECUTABLE_BYTES: usize = 67_108_864;
pub const MAX_FRAME_BYTES: usize = 5 * 1024 * 1024;
pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
pub const MAX_STATUS_BYTES: usize = 1024 * 1024;
pub const MAX_STATE_BYTES: usize = 4096;
pub const MAX_CLUSTER_MAILBOX_BYTES: usize = 256 * 1024;
pub const MAX_SOURCE_BYTES: usize = 96;
pub const MAX_KEY_BYTES: usize = 96;
pub const MAX_NATIVE_ID: u64 = i64::MAX as u64;

/// Durable captured choice. A pending record fences restore until canonical commit.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CapturedIntent {
    pub schema_version: u32,
    pub boot_id: String,
    pub capture_ns: u64,
    pub pid: i32,
    pub request_id: u64,
    pub choice: String,
    pub pending: bool,
}

impl CapturedIntent {
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() || bytes.len() > 1024 {
            return Err("captured intent exceeds bound");
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| "invalid captured intent")?;
        if !value.valid() {
            return Err("invalid captured intent identity");
        }
        Ok(value)
    }
    pub fn valid(&self) -> bool {
        self.schema_version == 1
            && crate::operation::canonical_boot_id(&self.boot_id)
            && self.capture_ns != 0
            && self.request_id != 0
            && self.pid > 0
            && matches!(self.choice.as_str(), "on" | "off")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IntentAdmission {
    Pending,
    Committed,
    Superseded,
}

/// Identity of one owner-issued semantic command, independent of transport requests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeCommandIdentity {
    pub owner_session: String,
    pub boot_id: String,
    pub source: String,
    pub command_id: u64,
    pub revision: u64,
    pub state: String,
    pub value: i32,
}

impl NativeCommandIdentity {
    pub fn valid(&self) -> bool {
        valid_session(&self.owner_session)
            && crate::operation::canonical_boot_id(&self.boot_id)
            && valid_source(&self.source)
            && self.command_id != 0
            && self.command_id <= MAX_NATIVE_ID
            && self.revision != 0
            && self.revision <= MAX_NATIVE_ID
            && !self.state.is_empty()
            && self.state.len() <= MAX_KEY_BYTES
            && self.state.as_bytes()[0].is_ascii_uppercase()
            && self
                .state
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    }
}

/// A bounded reading of the current OEM service, not a received CAN frame.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeVehicleObservation {
    pub acc: i32,
    pub state: String,
    pub value: i32,
    pub sampled_boot_ms: u64,
}
impl NativeVehicleObservation {
    pub fn valid(&self) -> bool {
        matches!(self.acc, 0..=2)
            && self.sampled_boot_ms > 0
            && self.sampled_boot_ms <= MAX_NATIVE_ID
            && matches!(
                self.state.as_str(),
                "IVI_SOC_MODESET" | "HUM_VSP_FUNCTION_SW"
            )
            && match self.state.as_str() {
                "IVI_SOC_MODESET" => (1..=7).contains(&self.value),
                _ => (1..=2).contains(&self.value),
            }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeCommandPhase {
    Offered,
    Execute,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeCommandEnvelope {
    pub schema_version: u8,
    pub identity: NativeCommandIdentity,
    pub phase: NativeCommandPhase,
}

impl NativeCommandEnvelope {
    pub fn valid(&self) -> bool {
        self.schema_version == SCHEMA && self.identity.valid()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ElectricClickStatus {
    NotSubmitted,
    Pending,
    /// An existing automatic command is being cancelled and drained, not claimed by this click.
    Draining,
    Accepted,
    /// No command can complete later; the uncertain Electric action must never be replayed.
    Drained,
    Unknown,
    Busy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeCommandStatus {
    Claim,
    Accepted,
    Cancelled,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeTransportReceipt {
    pub owner_session: String,
    pub boot_id: String,
    pub source: String,
    pub pid: i32,
    pub endpoint_epoch: u64,
    pub available: bool,
}

impl NativeTransportReceipt {
    pub fn valid(&self) -> bool {
        valid_session(&self.owner_session)
            && crate::operation::canonical_boot_id(&self.boot_id)
            && valid_source(&self.source)
            && self.pid > 1
            && self.endpoint_epoch != 0
            && self.endpoint_epoch <= MAX_NATIVE_ID
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClusterPairing {
    pub provision: Vec<u8>,
    pub seed: Vec<u8>,
    pub credentials: Vec<u8>,
}

impl std::fmt::Debug for ClusterPairing {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ClusterPairing { protected material }")
    }
}

impl Drop for ClusterPairing {
    fn drop(&mut self) {
        self.seed.fill(0);
        self.credentials.fill(0);
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClusterArtifact {
    Request,
    Receipt,
    UninstallReport,
}

impl ClusterArtifact {
    pub fn file(self) -> &'static str {
        match self {
            Self::Request => "request.vbc",
            Self::Receipt => "receipt.vbc",
            Self::UninstallReport => "uninstall-report.vbc",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub schema_version: u8,
    pub session: String,
    pub request_id: u64,
    pub command: Command,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Command {
    ElectricClick {
        input: crate::desired::Input,
        poll: bool,
        cancel: bool,
    },
    ReadClusterPwProof {
        challenge: crate::cluster_pw_live::Challenge,
    },
    ImportClusterPairing {
        material: ClusterPairing,
    },
    WriteClusterArtifact {
        artifact: ClusterArtifact,
        bytes: Vec<u8>,
    },
    ReadClusterMailbox {},
    ReplaceClusterMailbox {
        expected: Option<String>,
        next: String,
    },
    ReadClusterEpoch {},
    SetStartup {
        startup: String,
    },
    SaveStartupRecovery {
        input: crate::desired::Input,
    },
    ReadLogSession {},
    ReadNativeCan {
        cursor: u64,
    },
    BeginNativeStateOutage {
        token: String,
    },
    SnapshotNativeStateOutage {
        token: String,
    },
    ReleaseNativeStateOutage {
        token: String,
    },
    CloseNativeStateOutage {
        token: String,
    },
    PublishInjectionStatus {
        bytes: String,
    },
    AppendAppBatch {
        bytes: String,
    },
    AppendLog {
        source: crate::runtime_log::Source,
        record: crate::runtime_log::Record,
    },
    ReadState {
        source: String,
        key: String,
    },
    WriteState {
        source: String,
        key: String,
        value: Value,
    },
    ReadControllerState {
        source: String,
        key: String,
    },
    WriteControllerState {
        source: String,
        key: String,
        value: Value,
    },
    ClearControllerState {
        source: String,
        key: String,
        expected: String,
    },
    ReadJournal {
        source: String,
        key: String,
    },
    RegisterNativeTransport {
        source: String,
        pid: i32,
        endpoint_epoch: u64,
        available: bool,
    },
    ObserveNativeVehicle {
        source: String,
        pid: i32,
        endpoint_epoch: u64,
        observation: NativeVehicleObservation,
    },
    PollNativeCommand {
        source: String,
        pid: i32,
        endpoint_epoch: u64,
    },
    ReportNativeCommand {
        identity: NativeCommandIdentity,
        pid: i32,
        endpoint_epoch: u64,
        status: NativeCommandStatus,
    },
    PrepareIntent {
        source: String,
        key: String,
        record: CapturedIntent,
    },
    FinishIntent {
        source: String,
        key: String,
        record: CapturedIntent,
    },
    RecoverIntent {
        source: String,
        key: String,
    },
    ReplaceJournal {
        source: String,
        key: String,
        expected: Option<String>,
        next: String,
    },
    ReadConfig {},
    SaveDesired {
        field: crate::desired::Field,
        value: Value,
        input: crate::desired::Input,
    },
    SaveLauncherDesired {
        changes: Vec<(crate::desired::Field, Value)>,
        input: crate::desired::Input,
    },
    /// Every target process of `source` has applied the desired document that
    /// removes it, so the saved removal may become an authoritative withdrawal.
    ConfirmAgentWithdrawn {
        source: String,
    },
    ReconcileDesired {
        defaults: String,
    },
    ReadDesired {
        field: crate::desired::Field,
    },
    ReadStartupSession {},
    ReplaceStartupSession {
        expected: Option<String>,
        next: Option<String>,
    },
    ReplaceConfig {
        expected: Option<String>,
        next: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Reply<O = Outcome> {
    pub schema_version: u8,
    pub session: String,
    pub request_id: u64,
    pub outcome: O,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Outcome {
    ElectricClick {
        result: ElectricClickStatus,
    },
    DesiredReconciled {
        revision: u64,
        config: String,
    },
    DesiredSaved {
        revision: u64,
        config: String,
        disposition: crate::desired::Disposition,
    },
    ClusterPwProof {
        proof: Option<Vec<u8>>,
    },
    NativeTransportRegistered {
        receipt: NativeTransportReceipt,
    },
    NativeVehicleObserved {
        source: String,
        boot_id: String,
    },
    NativeCommand {
        source: String,
        command: Option<NativeCommandEnvelope>,
    },
    NativeCommandReported {
        identity: NativeCommandIdentity,
        result: NativeCommandStatus,
    },
    IntentPrepared {
        admission: IntentAdmission,
    },
    ClusterMailbox {
        bytes: Option<String>,
    },
    ClusterEpoch {
        value: String,
    },
    StartupSaved {
        startup: String,
        installed_version: String,
    },
    NativeCan {
        value: Value,
    },
    NativeStateOutage {
        receipt: NativeStateOutageReceipt,
    },
    LogSession {
        boot_id: String,
        writer_id: String,
        sequence: u64,
    },
    BatchLogged {
        batch_id: String,
    },
    Ready {},
    State {
        value: Option<Value>,
    },
    StateCleared {
        cleared: bool,
    },
    Config {
        bytes: Option<String>,
    },
    StartupSession {
        bytes: Option<String>,
    },
    Journal {
        bytes: Option<String>,
    },
    Written {},
    /// The named source is no longer admitted: its saved removal is authoritative.
    Withdrawn {},
    Logged {
        writer_id: String,
        sequence: u64,
    },
    Conflict {},
    Unavailable {},
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeStateOutageReceipt {
    pub kind: String,
    pub token: String,
    pub boot_id: String,
    pub generation_id: String,
    pub catalog_sha256: String,
    pub owner_writer_id: String,
    pub owner_pid: i32,
    pub owner_starttime: u64,
    pub target_pid: i32,
    pub target_starttime: u64,
    pub deadline_monotonic_ms: u64,
    pub observed_monotonic_ms: u64,
    pub reads: u64,
    pub dropped_reads: u64,
    pub writes: u64,
    pub failed_writes: u64,
    pub wait_state_steps: u64,
    pub recovered_values: u64,
    pub recovered_value: Option<bool>,
    pub lease_revision: Option<u64>,
    pub stopped: bool,
    pub released: bool,
    pub closed: bool,
}

fn valid_session(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Request {
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
            return Err("runtime frame exceeds bound");
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| "invalid runtime request")?;
        value.validate()?;
        Ok(value)
    }

    /// Validate typed messages without parsing them again. Transport enforces the frame bound.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != SCHEMA || self.request_id == 0 || !valid_session(&self.session) {
            return Err("invalid runtime request identity");
        }
        let valid = match &self.command {
            Command::ImportClusterPairing { material } => {
                !material.provision.is_empty()
                    && material.provision.len() <= 16 * 1024
                    && material.seed.len() == 32
                    && !material.credentials.is_empty()
                    && material.credentials.len() <= 65536
            }
            Command::WriteClusterArtifact { bytes, .. } => {
                !bytes.is_empty() && bytes.len() <= 65536
            }
            Command::ReadClusterMailbox {} => true,
            Command::ReplaceClusterMailbox { expected, next } => {
                !next.is_empty()
                    && next.len() <= MAX_CLUSTER_MAILBOX_BYTES
                    && expected
                        .as_ref()
                        .is_none_or(|s| s.len() <= MAX_CLUSTER_MAILBOX_BYTES)
            }
            Command::ReadClusterEpoch {} => true,
            Command::ReadClusterPwProof { challenge } => challenge.validate().is_ok(),
            Command::SetStartup { startup } => {
                matches!(startup.as_str(), "none" | "hidden" | "interface")
            }
            Command::ReadLogSession {} | Command::ReadNativeCan { .. } => true,
            Command::BeginNativeStateOutage { token }
            | Command::SnapshotNativeStateOutage { token }
            | Command::ReleaseNativeStateOutage { token }
            | Command::CloseNativeStateOutage { token } => token.len() == 64
                && token.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            Command::PublishInjectionStatus { bytes } => {
                !bytes.is_empty() && bytes.len() <= MAX_STATUS_BYTES
            }
            Command::AppendAppBatch { bytes } => {
                crate::runtime_log::AppBatch::decode(bytes.as_bytes()).is_ok()
            }
            Command::AppendLog { source, record } => {
                source.kind != "qnx" && source.valid() && record.valid()
            },
            Command::ReadState { source, key } | Command::ReadControllerState { source, key } => valid_source(source) && valid_key(key),
            Command::WriteState { source, key, value } | Command::WriteControllerState { source, key, value } => {
                valid_source(source) && valid_key(key) && scalar(value)
            }
            Command::ClearControllerState {
                source,
                key,
                expected,
            } => {
                source == "media-apps"
                    && key == "media-selected-package"
                    && !expected.is_empty()
                    && expected.len() <= 255
                    && expected.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.')
                    })
            }
            Command::ObserveNativeVehicle { source, pid, endpoint_epoch, observation } => {
                valid_source(source) && *pid > 1 && *endpoint_epoch > 0
                    && *endpoint_epoch <= MAX_NATIVE_ID && observation.valid()
            }
            Command::RegisterNativeTransport {
                source,
                pid,
                endpoint_epoch,
                ..
            }
            | Command::PollNativeCommand {
                source,
                pid,
                endpoint_epoch,
            } => {
                valid_source(source)
                    && *pid > 1
                    && *endpoint_epoch != 0
                    && *endpoint_epoch <= MAX_NATIVE_ID
            }
            Command::ReportNativeCommand {
                identity,
                pid,
                endpoint_epoch,
                ..
            } => {
                identity.valid()
                    && *pid > 1
                    && *endpoint_epoch != 0
                    && *endpoint_epoch <= MAX_NATIVE_ID
            }
            Command::PrepareIntent {
                source,
                key,
                record,
            } => valid_source(source) && valid_key(key) && record.valid() && record.pending,
            Command::FinishIntent {
                source,
                key,
                record,
            } => valid_source(source) && valid_key(key) && record.valid() && !record.pending,
            Command::ReadJournal { source, key } | Command::RecoverIntent { source, key } => {
                valid_source(source) && valid_key(key)
            }
            Command::ReplaceJournal {
                source,
                key,
                expected,
                next,
            } => {
                valid_source(source)
                    && valid_key(key)
                    && !next.is_empty()
                    && next.len() <= MAX_STATE_BYTES
                    && expected.as_ref().is_none_or(|s| s.len() <= MAX_STATE_BYTES)
            }
            Command::ElectricClick { input, .. } => input.valid(),
            Command::ReadConfig {} => true,
            Command::SaveDesired {
                field,
                value,
                input,
            } => field.accepts(value) && input.valid(),
            Command::ConfirmAgentWithdrawn { source } => valid_source(source),
            Command::SaveLauncherDesired { changes, input } => input.valid() && !changes.is_empty()
                && changes.len() <= 512 && changes.iter().all(|(field, value)| field.accepts(value)
                    && (matches!(field, crate::desired::Field::LauncherItemVisibility { .. } | crate::desired::Field::LauncherAppPreference { .. })
                    || matches!(field, crate::desired::Field::Option { agent, key } if agent == "launcher" && key == "densityDpi"))),
            Command::ReconcileDesired { defaults } => {
                !defaults.is_empty() && defaults.len() <= MAX_CONFIG_BYTES
            }
            Command::ReadDesired { field } => field.valid(),
            Command::SaveStartupRecovery { input } => input.valid(),
            Command::ReadStartupSession {} => true,
            Command::ReplaceStartupSession { expected, next } => {
                expected.as_ref().is_none_or(|s| s.len() <= 512)
                    && next
                        .as_ref()
                        .is_none_or(|s| !s.is_empty() && s.len() <= 512)
            }
            Command::ReplaceConfig { expected, next } => {
                !next.is_empty()
                    && next.len() <= MAX_CONFIG_BYTES
                    && expected
                        .as_ref()
                        .is_none_or(|bytes| bytes.len() <= MAX_CONFIG_BYTES)
            }
        };
        if !valid {
            return Err("invalid runtime command");
        }
        Ok(())
    }
}

impl Reply {
    pub fn decode(bytes: &[u8], request_id: u64) -> Result<Self, &'static str> {
        Self::decode_as(bytes, request_id)
    }
}

impl<O: serde::de::DeserializeOwned + Into<Outcome>> Reply<O> {
    /// Decode a client's closed reply catalog, retaining the shared wire validation.
    pub fn decode_as(bytes: &[u8], request_id: u64) -> Result<Reply, &'static str> {
        if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
            return Err("runtime frame exceeds bound");
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| "invalid runtime reply")?;
        let value = Reply {
            schema_version: value.schema_version,
            session: value.session,
            request_id: value.request_id,
            outcome: value.outcome.into(),
        };
        if value.schema_version != SCHEMA
            || value.request_id != request_id
            || !valid_session(&value.session)
        {
            return Err("invalid runtime reply identity");
        }
        if matches!(value.outcome, Outcome::Ready {}) != (request_id == 0) {
            return Err("invalid runtime handshake");
        }
        match &value.outcome {
            Outcome::NativeVehicleObserved { source, boot_id }
                if !valid_source(source) || !crate::operation::canonical_boot_id(boot_id) =>
            {
                return Err("invalid native vehicle observation receipt")
            }
            Outcome::NativeTransportRegistered { receipt }
                if !receipt.valid() || receipt.owner_session != value.session =>
            {
                return Err("invalid native transport receipt")
            }
            Outcome::NativeCommand { source, command }
                if !valid_source(source)
                    || command.as_ref().is_some_and(|command| {
                        !command.valid()
                            || command.identity.source != *source
                            || command.identity.owner_session != value.session
                    }) =>
            {
                return Err("invalid native command delivery")
            }
            Outcome::NativeCommandReported { identity, result }
                if !identity.valid()
                    || identity.owner_session != value.session
                    || *result == NativeCommandStatus::Claim =>
            {
                return Err("invalid native command report acknowledgement")
            }
            Outcome::ClusterPwProof { proof: Some(bytes) }
                if bytes.is_empty() || bytes.len() > 8192 =>
            {
                return Err("runtime PW proof exceeds bound")
            }
            Outcome::ClusterMailbox { bytes: Some(bytes) }
                if bytes.len() > MAX_CLUSTER_MAILBOX_BYTES =>
            {
                return Err("runtime cluster mailbox exceeds bound")
            }
            Outcome::ClusterEpoch { value }
                if value.len() != 64
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
            {
                return Err("invalid cluster owner epoch")
            }
            Outcome::StartupSaved {
                startup,
                installed_version,
            } if !matches!(startup.as_str(), "none" | "hidden" | "interface")
                || !semver::Version::parse(installed_version)
                    .is_ok_and(|v| v.to_string() == *installed_version) =>
            {
                return Err("invalid startup acknowledgement")
            }
            Outcome::LogSession {
                boot_id, writer_id, ..
            } if !valid_session(writer_id)
                || writer_id != &value.session
                || boot_id.len() != 36
                || !boot_id.bytes().enumerate().all(|(i, b)| {
                    if matches!(i, 8 | 13 | 18 | 23) {
                        b == b'-'
                    } else {
                        b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                    }
                }) =>
            {
                return Err("invalid current log session")
            }
            Outcome::BatchLogged { batch_id } if !valid_session(batch_id) => {
                return Err("invalid runtime batch acknowledgement")
            }
            Outcome::StartupSession { bytes: Some(bytes) } if bytes.len() > 512 => {
                return Err("startup session exceeds bound")
            }
            Outcome::Logged {
                writer_id,
                sequence,
            } if !valid_session(writer_id) || writer_id != &value.session || *sequence == 0 => {
                return Err("invalid runtime log acknowledgement")
            }
            Outcome::State { value: Some(value) } if !scalar(value) => {
                return Err("invalid runtime scalar")
            }
            Outcome::Journal { bytes: Some(bytes) } if bytes.len() > MAX_STATE_BYTES => {
                return Err("runtime journal exceeds bound")
            }
            Outcome::Config { bytes: Some(bytes) } if bytes.len() > MAX_CONFIG_BYTES => {
                return Err("runtime configuration exceeds bound")
            }
            Outcome::DesiredSaved {
                revision, config, ..
            } if *revision > MAX_NATIVE_ID
                || config.is_empty()
                || config.len() > MAX_CONFIG_BYTES =>
            {
                return Err("invalid saved desired acknowledgement")
            }
            Outcome::DesiredReconciled { revision, config }
                if *revision > MAX_NATIVE_ID
                    || config.is_empty()
                    || config.len() > MAX_CONFIG_BYTES =>
            {
                return Err("invalid reconciled desired acknowledgement")
            }
            _ => {}
        }
        Ok(value)
    }
}

fn scalar(value: &Value) -> bool {
    (value.is_boolean() || value.is_string() || value.is_number())
        && serde_json::to_vec(value).is_ok_and(|bytes| bytes.len() <= MAX_STATE_BYTES)
}

pub fn valid_source(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SOURCE_BYTES
        && value.as_bytes()[0].is_ascii_lowercase()
        && !value.starts_with("voboost-")
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub fn valid_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_KEY_BYTES
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
#[path = "runtime_owner_request_tests.rs"]
mod request_tests;

#[cfg(test)]
mod tests {
    #[test]
    fn captured_intent_rejects_incomplete_duplicate_and_invalid_identity() {
        let valid = serde_json::json!({"schemaVersion":1,"bootId":"11111111-1111-4111-8111-111111111111",
            "captureNs":1,"pid":10,"requestId":1,"choice":"off","pending":true});
        assert!(
            super::CapturedIntent::decode(valid.to_string().as_bytes())
                .unwrap()
                .pending
        );
        assert!(super::CapturedIntent::decode(br#"{"pending":false}"#).is_err());
        for (key, bad) in [
            ("schemaVersion", serde_json::json!(2)),
            ("bootId", serde_json::json!("bad")),
            ("captureNs", serde_json::json!(0)),
            ("pid", serde_json::json!(0)),
            ("requestId", serde_json::json!(0)),
            ("choice", serde_json::json!("observe")),
            ("pending", serde_json::json!("false")),
        ] {
            let mut changed = valid.clone();
            changed[key] = bad;
            assert!(
                super::CapturedIntent::decode(changed.to_string().as_bytes()).is_err(),
                "{key}"
            );
        }
        let duplicate = valid.to_string().replacen('{', "{\"pending\":false,", 1);
        assert!(super::CapturedIntent::decode(duplicate.as_bytes()).is_err());
    }

    use super::*;
    #[test]
    fn fixed_operations_reject_paths_unknown_fields_and_unsafe_identifiers() {
        assert!(serde_json::from_str::<Command>(
            r#"{"operation":"read-config","path":"/elsewhere"}"#
        )
        .is_err());
        assert!(
            serde_json::from_str::<Command>(r#"{"operation":"shell","command":"id"}"#).is_err()
        );
        for source in [
            "",
            "../agent",
            "agent_name",
            "voboost-admin",
            "Agent",
            "a/b",
        ] {
            assert!(!valid_source(source));
        }
        for key in ["", "../key", "a/b", "a.b", "key\n"] {
            assert!(!valid_key(key));
        }
        assert!(valid_source("vehicle-drive-forced-ev"));
        assert!(valid_key("forced-ev-armed"));
    }
    #[test]
    fn local_log_command_cannot_claim_qnx_provenance() {
        let mut value = request(serde_json::json!({
            "operation": "append-log",
            "source": {"kind": "daemon"},
            "record": {"level": "info", "component": "test", "message": "event"}
        }));
        assert!(Request::decode(&serde_json::to_vec(&value).unwrap()).is_ok());
        value["command"]["source"] = serde_json::json!({"kind": "qnx", "id": "cluster-session"});
        assert!(crate::runtime_log::Source::qnx("cluster-session".into()).valid());
        assert!(!crate::runtime_log::Source::qnx("../cluster".into()).valid());
        assert!(Request::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    const SESSION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    fn request(command: serde_json::Value) -> serde_json::Value {
        serde_json::json!({"schemaVersion":SCHEMA,"session":SESSION,"requestId":1,"command":command})
    }
    #[test]
    fn intent_recovery_has_only_a_logical_source_and_declared_key_shape() {
        let valid = request(
            serde_json::json!({"operation":"recover-intent","source":"vehicle-drive-forced-ev","key":"intent"}),
        );
        assert!(Request::decode(&serde_json::to_vec(&valid).unwrap()).is_ok());
        for (field, bad) in [("source", "../agent"), ("key", "../file")] {
            let mut changed = valid.clone();
            changed["command"][field] = bad.into();
            assert!(Request::decode(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        let mut extra = valid;
        extra["command"]["path"] = "/data/foreign".into();
        assert!(Request::decode(&serde_json::to_vec(&extra).unwrap()).is_err());
    }

    #[test]
    fn withdrawal_confirmation_carries_only_a_logical_source_and_a_fixed_outcome() {
        let valid = request(serde_json::json!({
            "operation": "confirm-agent-withdrawn",
            "source": "vehicle-drive-pedestrian-warning"
        }));
        let decoded = Request::decode(&serde_json::to_vec(&valid).unwrap()).unwrap();
        assert!(matches!(
            decoded.command,
            Command::ConfirmAgentWithdrawn { source }
                if source == "vehicle-drive-pedestrian-warning"
        ));
        for bad in ["../agent", "/data/foreign", "voboost-daemon"] {
            let mut changed = valid.clone();
            changed["command"]["source"] = bad.into();
            assert!(Request::decode(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        let mut extra = valid;
        extra["command"]["generation"] = serde_json::json!(4);
        assert!(Request::decode(&serde_json::to_vec(&extra).unwrap()).is_err());
        let reply = Reply {
            schema_version: SCHEMA,
            session: SESSION.into(),
            request_id: 1,
            outcome: Outcome::Withdrawn {},
        };
        let bytes = serde_json::to_vec(&reply).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["outcome"],
            serde_json::json!({"status": "withdrawn"})
        );
        assert!(Reply::decode(&bytes, 1).is_ok());
        let mut with_path = serde_json::to_value(&reply).unwrap();
        with_path["outcome"]["path"] = serde_json::json!("/elsewhere");
        assert!(Reply::decode(&serde_json::to_vec(&with_path).unwrap(), 1).is_err());
    }

    #[test]
    fn decoder_rejects_invalid_identity_unknown_fields_duplicate_fields_and_non_scalar_state() {
        let valid = request(
            serde_json::json!({"operation":"read-state","source":"media-apps","key":"media-selected-package"}),
        );
        assert!(Request::decode(&serde_json::to_vec(&valid).unwrap()).is_ok());
        for (field, bad) in [
            ("schemaVersion", serde_json::json!(2)),
            ("session", serde_json::json!("foreign")),
            ("requestId", serde_json::json!(0)),
        ] {
            let mut value = valid.clone();
            value[field] = bad;
            assert!(Request::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        for command in [
            serde_json::json!({"operation":"read-config","path":"/elsewhere"}),
            serde_json::json!({"operation":"write-state","source":"media-apps","key":"key","value":{"nested":true}}),
            serde_json::json!({"operation":"write-state","source":"media-apps","key":"../key","value":false}),
        ] {
            assert!(Request::decode(&serde_json::to_vec(&request(command)).unwrap()).is_err());
        }
        let duplicate = format!(
            r#"{{"schemaVersion":1,"session":"{SESSION}","requestId":1,"command":{{"operation":"read-state","source":"media-apps","source":"other","key":"key"}}}}"#
        );
        assert!(Request::decode(duplicate.as_bytes()).is_err());
    }
    #[test]
    fn request_bounds_and_valid_scalar_and_config_operations_are_enforced() {
        for command in [
            Command::ReadConfig {},
            Command::WriteState {
                source: "media-apps".into(),
                key: "key".into(),
                value: Value::Bool(false),
            },
            Command::ReplaceConfig {
                expected: None,
                next: "{}".into(),
            },
        ] {
            let value = Request {
                schema_version: SCHEMA,
                session: SESSION.into(),
                request_id: 1,
                command,
            };
            assert!(Request::decode(&serde_json::to_vec(&value).unwrap()).is_ok());
        }
        assert!(Request::decode(&vec![b' '; MAX_FRAME_BYTES + 1]).is_err());
        assert!(Request::decode(b"").is_err());
        let excessive = request(
            serde_json::json!({"operation":"write-state","source":"media-apps","key":"key","value":"x".repeat(MAX_STATE_BYTES)}),
        );
        assert!(Request::decode(&serde_json::to_vec(&excessive).unwrap()).is_err());
        let excessive = request(
            serde_json::json!({"operation":"replace-config","expected":null,"next":"x".repeat(MAX_CONFIG_BYTES+1)}),
        );
        assert!(Request::decode(&serde_json::to_vec(&excessive).unwrap()).is_err());
    }
    #[test]
    fn journals_have_only_logical_owners_and_bounded_payloads() {
        let value = |source: &str, key: &str, next: &str| {
            request(serde_json::json!({
                "operation":"replace-journal","source":source,"key":key,"expected":null,"next":next
            }))
        };
        assert!(
            Request::decode(&serde_json::to_vec(&value("agent", "intent", "{}")).unwrap()).is_ok()
        );
        for invalid in [
            value("../agent", "intent", "{}"),
            value("agent", "../intent", "{}"),
            value("agent", "intent", &"x".repeat(MAX_STATE_BYTES + 1)),
        ] {
            assert!(Request::decode(&serde_json::to_vec(&invalid).unwrap()).is_err());
        }
        let mut extra = value("agent", "intent", "{}");
        extra["command"]["path"] = Value::String("/elsewhere".into());
        assert!(Request::decode(&serde_json::to_vec(&extra).unwrap()).is_err());
    }
    #[test]
    fn replies_require_exact_identity_handshake_and_fixed_empty_variants() {
        let ready = Reply {
            schema_version: SCHEMA,
            session: SESSION.into(),
            request_id: 0,
            outcome: Outcome::Ready {},
        };
        let bytes = serde_json::to_vec(&ready).unwrap();
        assert!(Reply::decode(&bytes, 0).is_ok());
        assert!(Reply::decode(&bytes, 1).is_err());
        let reply = Reply {
            request_id: 1,
            outcome: Outcome::Written {},
            ..ready
        };
        let bytes = serde_json::to_vec(&reply).unwrap();
        assert!(Reply::decode(&bytes, 1).is_ok());
        assert!(Reply::decode(&bytes, 2).is_err());
        let logged = |writer: &str, seq: u64| {
            serde_json::to_vec(&Reply {
                schema_version: SCHEMA,
                session: SESSION.into(),
                request_id: 1,
                outcome: Outcome::Logged {
                    writer_id: writer.into(),
                    sequence: seq,
                },
            })
            .unwrap()
        };
        assert!(Reply::decode(&logged(SESSION, 1), 1).is_ok());
        assert!(Reply::decode(&logged(SESSION, 0), 1).is_err());
        assert!(Reply::decode(&logged("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1), 1).is_err());
        let mut value = serde_json::to_value(&reply).unwrap();
        value["outcome"]["path"] = serde_json::json!("/elsewhere");
        assert!(Reply::decode(&serde_json::to_vec(&value).unwrap(), 1).is_err());
    }

    #[test]
    fn current_log_session_requires_same_writer_and_exact_boot_identity() {
        let head = |boot: &str, writer: &str| {
            serde_json::to_vec(&Reply {
                schema_version: SCHEMA,
                session: SESSION.into(),
                request_id: 1,
                outcome: Outcome::LogSession {
                    boot_id: boot.into(),
                    writer_id: writer.into(),
                    sequence: 0,
                },
            })
            .unwrap()
        };
        let boot = "11111111-1111-4111-8111-111111111111";
        assert!(Reply::decode(&head(boot, SESSION), 1).is_ok());
        assert!(Reply::decode(&head(boot, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), 1).is_err());
        for invalid in [
            "",
            "11111111111141118111111111111111",
            "11111111-1111-4111-8111-11111111111G",
        ] {
            assert!(Reply::decode(&head(invalid, SESSION), 1).is_err());
        }
    }
    #[test]
    fn cluster_epoch_is_a_distinct_bounded_owner_token() {
        let reply = |value: &str| {
            serde_json::to_vec(&Reply {
                schema_version: SCHEMA,
                session: SESSION.into(),
                request_id: 1,
                outcome: Outcome::ClusterEpoch {
                    value: value.into(),
                },
            })
            .unwrap()
        };
        assert!(Reply::decode(&reply(&"a".repeat(64)), 1).is_ok());
        for invalid in [SESSION.to_string(), "a".repeat(65), "G".repeat(64)] {
            assert!(Reply::decode(&reply(&invalid), 1).is_err());
        }
    }
    #[test]
    fn pairing_material_is_bounded_and_debug_never_prints_secrets() {
        let mut request = Request {
            schema_version: SCHEMA,
            session: SESSION.into(),
            request_id: 1,
            command: Command::ImportClusterPairing {
                material: ClusterPairing {
                    provision: b"protected-provision".to_vec(),
                    seed: vec![73; 32],
                    credentials: b"protected-credentials".to_vec(),
                },
            },
        };
        let debug = format!("{request:?}");
        assert!(!debug.contains("protected-provision"));
        assert!(!debug.contains("protected-credentials"));
        assert!(Request::decode(&serde_json::to_vec(&request).unwrap()).is_ok());
        let Command::ImportClusterPairing { material } = &mut request.command else {
            unreachable!()
        };
        material.seed.pop();
        assert!(Request::decode(&serde_json::to_vec(&request).unwrap()).is_err());
    }
    #[test]
    fn captured_choice_commands_bind_direction_and_closed_identity() {
        let record = serde_json::json!({"schemaVersion":1,"bootId":"11111111-1111-4111-8111-111111111111",
        "captureNs":1,"pid":10,"requestId":1,"choice":"off","pending":true});
        for (operation, pending) in [("prepare-intent", true), ("finish-intent", false)] {
            let mut row = record.clone();
            row["pending"] = pending.into();
            let valid = request(
                serde_json::json!({"operation":operation,"source":"vehicle-drive-forced-ev","key":"intent","record":row}),
            );
            assert!(Request::decode(valid.to_string().as_bytes()).is_ok());
            let mut wrong = valid.clone();
            wrong["command"]["record"]["pending"] = (!pending).into();
            assert!(Request::decode(wrong.to_string().as_bytes()).is_err());
            let mut wrong = valid.clone();
            wrong["command"]["record"]["captureNs"] = 0.into();
            assert!(Request::decode(wrong.to_string().as_bytes()).is_err());
            let mut wrong = valid.clone();
            wrong["command"]["record"]["path"] = "/other".into();
            assert!(Request::decode(wrong.to_string().as_bytes()).is_err());
            let mut wrong = valid;
            wrong["command"]["key"] = "../intent".into();
            assert!(Request::decode(wrong.to_string().as_bytes()).is_err());
        }
    }

    #[test]
    fn captured_choice_admission_reply_has_only_declared_outcomes() {
        for admission in ["pending", "committed", "superseded"] {
            let reply = serde_json::json!({"schemaVersion":SCHEMA,"session":SESSION,"requestId":1,
            "outcome":{"status":"intent-prepared","admission":admission}});
            assert!(Reply::decode(reply.to_string().as_bytes(), 1).is_ok());
            assert!(Reply::decode(reply.to_string().as_bytes(), 2).is_err());
        }
        let reply = serde_json::json!({"schemaVersion":SCHEMA,"session":SESSION,"requestId":1,
        "outcome":{"status":"intent-prepared","admission":"accepted"}});
        assert!(Reply::decode(reply.to_string().as_bytes(), 1).is_err());
    }
    fn semantic_identity() -> NativeCommandIdentity {
        NativeCommandIdentity {
            owner_session: SESSION.into(),
            boot_id: "11111111-1111-4111-8111-111111111111".into(),
            source: "vehicle-drive-forced-ev".into(),
            command_id: 7,
            revision: 2,
            state: "IVI_SOC_MODESET".into(),
            value: 5,
        }
    }

    #[test]
    fn semantic_commands_have_closed_endpoint_and_command_identity() {
        for command in [
            serde_json::json!({"operation":"register-native-transport","source":"vehicle-drive-forced-ev","pid":20,"endpointEpoch":30,"available":true}),
            serde_json::json!({"operation":"poll-native-command","source":"vehicle-drive-forced-ev","pid":20,"endpointEpoch":30}),
            serde_json::json!({"operation":"report-native-command","identity":semantic_identity(),"pid":20,"endpointEpoch":30,"status":"claim"}),
        ] {
            let valid = request(command);
            assert!(Request::decode(valid.to_string().as_bytes()).is_ok());
            for (key, value) in [
                ("pid", serde_json::json!(1)),
                ("endpointEpoch", serde_json::json!(0)),
                ("path", serde_json::json!("/arbitrary")),
            ] {
                let mut invalid = valid.clone();
                invalid["command"][key] = value;
                assert!(Request::decode(invalid.to_string().as_bytes()).is_err());
            }
        }
        let mut command = request(serde_json::json!({"operation":"report-native-command",
            "identity":semantic_identity(),"pid":20,"endpointEpoch":30,"status":"accepted"}));
        for (key, value) in [
            ("ownerSession", serde_json::json!("bad")),
            ("bootId", serde_json::json!("bad")),
            ("commandId", serde_json::json!(0)),
            ("revision", serde_json::json!(0)),
            ("state", serde_json::json!("../write")),
        ] {
            let mut invalid = command.clone();
            invalid["command"]["identity"][key] = value;
            assert!(Request::decode(invalid.to_string().as_bytes()).is_err());
        }
        command["command"]["status"] = "execute".into();
        assert!(Request::decode(command.to_string().as_bytes()).is_err());
    }

    #[test]
    fn semantic_deliveries_and_terminal_reports_bind_the_current_owner() {
        let command = NativeCommandEnvelope {
            schema_version: SCHEMA,
            identity: semantic_identity(),
            phase: NativeCommandPhase::Offered,
        };
        let reply = Reply {
            schema_version: SCHEMA,
            session: SESSION.into(),
            request_id: 1,
            outcome: Outcome::NativeCommand {
                source: command.identity.source.clone(),
                command: Some(command),
            },
        };
        let valid = serde_json::to_value(reply).unwrap();
        assert!(Reply::decode(valid.to_string().as_bytes(), 1).is_ok());
        for (key, value) in [
            (
                "ownerSession",
                serde_json::json!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            ),
            (
                "source",
                serde_json::json!("vehicle-drive-pedestrian-warning"),
            ),
            ("commandId", serde_json::json!(0)),
        ] {
            let mut invalid = valid.clone();
            invalid["outcome"]["command"]["identity"][key] = value;
            assert!(Reply::decode(invalid.to_string().as_bytes(), 1).is_err());
        }
        for result in [
            NativeCommandStatus::Accepted,
            NativeCommandStatus::Cancelled,
            NativeCommandStatus::Failed,
            NativeCommandStatus::Unknown,
        ] {
            let reply = Reply {
                schema_version: SCHEMA,
                session: SESSION.into(),
                request_id: 1,
                outcome: Outcome::NativeCommandReported {
                    identity: semantic_identity(),
                    result,
                },
            };
            let mut value = serde_json::to_value(reply).unwrap();
            assert!(Reply::decode(value.to_string().as_bytes(), 1).is_ok());
            assert_eq!(value["outcome"]["status"], "native-command-reported");
            value["outcome"]["result"] = "claim".into();
            assert!(Reply::decode(value.to_string().as_bytes(), 1).is_err());
        }
    }

    #[test]
    fn transport_readiness_receipt_is_not_an_execution_grant() {
        let receipt = NativeTransportReceipt {
            owner_session: SESSION.into(),
            boot_id: "11111111-1111-4111-8111-111111111111".into(),
            source: "vehicle-drive-forced-ev".into(),
            pid: 20,
            endpoint_epoch: 30,
            available: true,
        };
        let reply = Reply {
            schema_version: SCHEMA,
            session: SESSION.into(),
            request_id: 1,
            outcome: Outcome::NativeTransportRegistered { receipt },
        };
        let valid = serde_json::to_value(reply).unwrap();
        assert!(Reply::decode(valid.to_string().as_bytes(), 1).is_ok());
        assert!(valid["outcome"].get("command").is_none());
        for (key, value) in [
            (
                "ownerSession",
                serde_json::json!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            ),
            ("pid", serde_json::json!(1)),
            ("endpointEpoch", serde_json::json!(0)),
        ] {
            let mut invalid = valid.clone();
            invalid["outcome"]["receipt"][key] = value;
            assert!(Reply::decode(invalid.to_string().as_bytes(), 1).is_err());
        }
    }
}
