//! Serialized private state and configuration requests from the signed injector.
mod commands;
mod desired;
mod desired_catalog;
#[cfg(test)]
#[path = "server/desired_catalog.test.rs"]
mod desired_catalog_tests;
mod intent;
mod native;
mod pw_live;
#[cfg(test)]
#[path = "server/startup_projection.test.rs"]
mod startup_projection_tests;
#[cfg(test)]
#[path = "server/withdrawal.test.rs"]
mod withdrawal_tests;
use crate::secure_fs::Directory;
use crate::state::{self, ReadOutcome};
use std::io;
use std::path::{Path, PathBuf};
use voboost_contract::runtime_owner::{Command, Outcome, Reply, Request, MAX_CONFIG_BYTES, SCHEMA};

pub(super) struct Store {
    root: PathBuf,
    session: String,
    current_producer: Option<(i32, u64)>,
    outage: std::cell::RefCell<Option<super::state_outage_auth::Session>>,
    outage_tokens: std::collections::BTreeSet<String>,
    cluster_epoch: String,
    pw_live: pw_live::Live,
    logger: Option<std::sync::Arc<std::sync::Mutex<super::log::Log>>>,
    native_boot: Option<String>,
    running_startup: Option<String>,
    native_enabled: std::collections::BTreeSet<String>,
    native_configured: std::collections::BTreeSet<String>,
    native_revision: u64,
    desired_off_fences: std::collections::BTreeSet<String>,
    desired_catalog_fences: std::collections::BTreeSet<String>,
    /// UI teardown acknowledgements with a bounded lifetime; they grant no authority.
    withdrawing: std::collections::BTreeMap<String, std::time::Instant>,
    desired_catalog: Option<(String, voboost_contract::agent_catalog::AgentCatalog)>,
    command_queue: commands::Queue,
    native_slots: std::collections::BTreeMap<String, native::Slot>,
}
impl Store {
    pub(super) fn new(root: &Path, session: &str) -> io::Result<Self> {
        Directory::open(root)?.validate_owner_mode(
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o755,
        )?;
        let mut epoch = [0u8; 32];
        std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom")?, &mut epoch)?;
        Ok(Self {
            root: root.into(),
            session: session.into(),
            current_producer: None,
            outage: std::cell::RefCell::new(None),
            outage_tokens: std::collections::BTreeSet::new(),
            cluster_epoch: hex::encode(epoch),
            pw_live: Default::default(),
            logger: None,
            native_boot: None,
            running_startup: None,
            native_enabled: Default::default(),
            native_configured: Default::default(),
            native_revision: 0,
            desired_off_fences: Default::default(),
            desired_catalog_fences: Default::default(),
            withdrawing: Default::default(),
            desired_catalog: None,
            command_queue: Default::default(),
            native_slots: Default::default(),
        })
    }
    #[cfg(test)]
    pub(super) fn arm_outage_fixture(&mut self) {
        self.outage_tokens.insert("a".repeat(64));
        *self.outage.borrow_mut() = Some(super::state_outage_auth::Session::fixture());
    }
    #[cfg(test)]
    pub(super) fn with_logger(mut self, logger: super::log::Log) -> io::Result<Self> {
        if logger.writer_id() != self.session {
            return Err(invalid("logging owner session differs"));
        }
        self.logger = Some(std::sync::Arc::new(std::sync::Mutex::new(logger)));
        Ok(self)
    }
    pub(super) fn with_shared_logger(
        mut self,
        logger: std::sync::Arc<std::sync::Mutex<super::log::Log>>,
    ) -> io::Result<Self> {
        if logger
            .lock()
            .map_err(|_| invalid("logging lock poisoned"))?
            .writer_id()
            != self.session
        {
            return Err(invalid("logging owner session differs"));
        }
        self.logger = Some(logger);
        Ok(self)
    }
    pub(super) fn write_log(
        &mut self,
        source: voboost_contract::runtime_log::Source,
        record: voboost_contract::runtime_log::Record,
    ) -> io::Result<(String, u64)> {
        let mut logger = self
            .logger
            .as_ref()
            .ok_or_else(|| invalid("logging session unavailable"))?
            .lock()
            .map_err(|_| invalid("logging lock poisoned"))?;
        let sequence = logger.append_record(source, record)?;
        Ok((logger.writer_id().to_owned(), sequence))
    }
    pub(super) fn write_native_can_log(
        &mut self,
        records: Vec<voboost_contract::runtime_log::Record>,
    ) -> io::Result<u64> {
        self.logger
            .as_ref()
            .ok_or_else(|| invalid("logging session unavailable"))?
            .lock()
            .map_err(|_| invalid("logging lock poisoned"))?
            .append_debug_records(records)
    }
    pub(super) fn native_boot(&self) -> &str {
        self.native_boot.as_deref().unwrap_or("")
    }
    pub(super) fn session(&self) -> &str {
        &self.session
    }
    pub(super) fn initialize_native(&mut self, boot: &str) -> io::Result<()> {
        if self.native_boot.as_deref() != Some(boot) {
            self.revoke_native();
            self.native_slots.clear();
            self.command_queue = Default::default();
            self.native_configured.clear();
            self.running_startup = None;
        }
        self.native_boot = Some(boot.into());
        for codec in super::native::CODECS {
            for key in codec.pending_journals {
                if let Err(error) = self.recover_intent(codec.id, key) {
                    let _ = self.write_log(
                        voboost_contract::runtime_log::Source::daemon(),
                        voboost_contract::runtime_log::Record {
                            level: if error.kind() == io::ErrorKind::WouldBlock {
                                voboost_contract::runtime_log::Level::Debug
                            } else {
                                voboost_contract::runtime_log::Level::Error
                            },
                            component: "native".into(),
                            message: "Captured intent recovery deferred".into(),
                            fields: std::collections::HashMap::from([
                                ("source".into(), codec.id.into()),
                                ("reason".into(), error.to_string()),
                            ]),
                        },
                    );
                }
            }
        }
        self.refresh_native()
    }
    pub(super) fn native_configured(&self) -> &std::collections::BTreeSet<String> {
        &self.native_configured
    }
    #[cfg(test)]
    pub(super) fn native_enabled(&self) -> &std::collections::BTreeSet<String> {
        &self.native_enabled
    }
    fn refresh_native(&mut self) -> io::Result<()> {
        let result = self.refresh_native_inner();
        if result.is_err() {
            self.revoke_native();
        } else {
            self.prune_native();
        }
        result
    }
    fn refresh_native_inner(&mut self) -> io::Result<()> {
        self.native_enabled.clear();
        if self.native_boot.is_none() {
            return Ok(());
        }
        let Some(bytes) = self.config()? else {
            self.revoke_native();
            return Ok(());
        };
        let bytes = self.normalize_desired_catalog(bytes)?;
        let Some(boot) = &self.native_boot else {
            return Ok(());
        };
        validate_config(&bytes)?;
        let config: serde_json::Value = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        if self.running_startup.is_none() {
            let existing = self.startup_session()?;
            if let Some(bytes) = &existing {
                validate_startup_session(bytes)?;
            }
            let existing = existing
                .as_deref()
                .map(serde_json::from_str::<serde_json::Value>)
                .transpose()
                .map_err(io::Error::other)?;
            let startup = existing
                .as_ref()
                .filter(|value| value["bootId"] == *boot)
                .and_then(|value| value["startup"].as_str())
                .or_else(|| config["startup"].as_str())
                .ok_or_else(|| invalid("running startup mode unavailable"))?
                .to_string();
            let session = serde_json::json!({"schemaVersion":1,"bootId":boot,"startup":startup});
            let bytes = serde_json::to_vec(&session).map_err(io::Error::other)?;
            if !existing
                .as_ref()
                .is_some_and(|value| value["bootId"] == *boot)
            {
                let run =
                    Directory::open(&self.root)?.open_or_create_child_with_mode("run", 0o755)?;
                run.validate_owner_mode(
                    unsafe { libc::geteuid() },
                    unsafe { libc::getegid() },
                    0o755,
                )?;
                run.write_atomic("startup-session.json", &bytes, 0o600)?;
            }
            self.running_startup = Some(startup);
        }
        if self.running_startup.as_deref() == Some("none") {
            self.native_configured.clear();
            return Ok(());
        }
        let agents = config["agents"]
            .as_object()
            .ok_or_else(|| invalid("agent configuration unavailable"))?;
        self.native_enabled.extend(
            agents
                .iter()
                .filter(|(_, value)| value["enabled"] == true)
                .map(|(id, _)| id.clone()),
        );
        // Only durable enabled state grants native automation. UI cleanup
        // acknowledgements cannot extend authority after the user saved OFF.
        self.native_configured = self.native_enabled.clone();
        self.refresh_desired_catalog_fences(&config);
        self.apply_desired_off_fences();
        for codec in super::native::CODECS {
            if !self.native_enabled.contains(codec.id) {
                continue;
            }
            for key in codec.pending_journals {
                let field = voboost_contract::desired::Field::Option {
                    agent: codec.id.into(),
                    key: (*key).into(),
                };
                if config["fieldRevisions"].get(field.path()).is_some() {
                    continue;
                }
                let clear = self.journal(codec.id, key).and_then(|bytes| {
                    bytes.map_or(Ok(true), |bytes| {
                        voboost_contract::runtime_owner::CapturedIntent::decode(&bytes)
                            .map(|record| !record.pending)
                            .map_err(invalid)
                    })
                });
                if !matches!(clear, Ok(true)) {
                    self.native_enabled.remove(codec.id);
                    break;
                }
            }
        }
        self.grant_native(&config)?;
        Ok(())
    }
    pub(super) fn maintain_logs(&self) -> io::Result<usize> {
        self.logger
            .as_ref()
            .ok_or_else(|| invalid("logging session unavailable"))?
            .lock()
            .map_err(|_| invalid("logging lock poisoned"))?
            .maintain()
    }
    pub(super) fn dispatch(&mut self, request: Request) -> Reply {
        let outcome = if request.session != self.session {
            Outcome::Unavailable {}
        } else {
            self.command(request.command)
                .unwrap_or(Outcome::Unavailable {})
        };
        Reply {
            schema_version: SCHEMA,
            session: self.session.clone(),
            request_id: request.request_id,
            outcome,
        }
    }
    pub(super) fn dispatch_from(&mut self, mut request: Request, producer: (i32, u64)) -> Reply {
        match &mut request.command {
            Command::SaveDesired { input, .. }
            | Command::SaveLauncherDesired { input, .. }
            | Command::SaveStartupRecovery { input } => {
                input.injector_pid = producer.0;
                input.injector_starttime = producer.1;
            }
            _ => (),
        }
        self.current_producer = Some(producer);
        let reply = self.dispatch(request);
        self.current_producer = None;
        reply
    }
    fn config(&self) -> io::Result<Option<Vec<u8>>> {
        match Directory::open(&self.root)?.read_trusted("agents.json", MAX_CONFIG_BYTES, 0o600) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn journal(&self, source: &str, key: &str) -> io::Result<Option<Vec<u8>>> {
        let directory = match state::open_directory(&self.root.join("state"), false) {
            Ok(directory) => directory,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        match directory.read_trusted(
            &journal_name(source, key)?,
            voboost_contract::runtime_owner::MAX_STATE_BYTES,
            0o600,
        ) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn cluster_mailbox(&self) -> io::Result<Option<String>> {
        let directory = match Directory::open(&self.root)?.open_child("cluster") {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        directory.validate_owner_mode(
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o700,
        )?;
        match directory.read_trusted(
            "mailbox.json",
            voboost_contract::runtime_owner::MAX_CLUSTER_MAILBOX_BYTES,
            0o600,
        ) {
            Ok(bytes) => String::from_utf8(bytes)
                .map(Some)
                .map_err(|_| invalid("invalid cluster mailbox encoding")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
    fn command(&mut self, command: Command) -> io::Result<Outcome> {
        Ok(match command {
            Command::ElectricClick { .. } => {
                return Err(invalid("electric action requires native runtime"))
            }
            Command::BeginNativeStateOutage { token } => {
                let producer = self
                    .current_producer
                    .ok_or_else(|| invalid("outage producer missing"))?;
                if producer.0 <= 1
                    || producer.1 == 0
                    || self.outage_tokens.len() >= 64
                    || self.outage_tokens.contains(&token)
                {
                    return Err(invalid("outage producer or replay"));
                }
                {
                    let mut slot = self.outage.borrow_mut();
                    if slot.as_mut().is_some_and(|session| !session.stale()) {
                        return Err(invalid("outage window already present"));
                    }
                    *slot = None;
                }
                let mut session = super::state_outage_auth::Session::begin(
                    &self.root,
                    self.native_boot(),
                    &self.session,
                    &token,
                    producer,
                )?;
                let receipt = session.receipt(&token, producer, "snapshot")?;
                self.outage_tokens.insert(token);
                *self.outage.borrow_mut() = Some(session);
                Outcome::NativeStateOutage { receipt }
            }
            Command::SnapshotNativeStateOutage { token } => {
                let producer = self
                    .current_producer
                    .ok_or_else(|| invalid("outage producer missing"))?;
                let receipt = self
                    .outage
                    .borrow_mut()
                    .as_mut()
                    .ok_or_else(|| invalid("outage missing"))?
                    .receipt(&token, producer, "snapshot")?;
                Outcome::NativeStateOutage { receipt }
            }
            Command::ReleaseNativeStateOutage { token } => {
                let producer = self
                    .current_producer
                    .ok_or_else(|| invalid("outage producer missing"))?;
                let receipt = self
                    .outage
                    .borrow_mut()
                    .as_mut()
                    .ok_or_else(|| invalid("outage missing"))?
                    .receipt(&token, producer, "release")?;
                Outcome::NativeStateOutage { receipt }
            }
            Command::CloseNativeStateOutage { token } => {
                let producer = self
                    .current_producer
                    .ok_or_else(|| invalid("outage producer missing"))?;
                let mut slot = self.outage.borrow_mut();
                let receipt = slot
                    .as_mut()
                    .ok_or_else(|| invalid("outage missing"))?
                    .receipt(&token, producer, "close")?;
                *slot = None;
                Outcome::NativeStateOutage { receipt }
            }
            Command::ReadClusterPwProof { challenge } => Outcome::ClusterPwProof {
                proof: self.pw_proof(challenge)?,
            },
            Command::ImportClusterPairing { material } => {
                let directory =
                    Directory::open(&self.root)?.open_or_create_private_child("cluster")?;
                directory.validate_owner_mode(
                    unsafe { libc::geteuid() },
                    unsafe { libc::getegid() },
                    0o700,
                )?;
                super::cluster::import(&directory, &material)?;
                Outcome::Written {}
            }
            Command::WriteClusterArtifact { artifact, bytes } => {
                let directory = Directory::open(&self.root)?.open_child("cluster")?;
                directory.validate_owner_mode(
                    unsafe { libc::geteuid() },
                    unsafe { libc::getegid() },
                    0o700,
                )?;
                super::cluster::write(&directory, artifact, &bytes)?;
                Outcome::Written {}
            }
            Command::ReadClusterMailbox {} => Outcome::ClusterMailbox {
                bytes: self.cluster_mailbox()?,
            },
            Command::ReplaceClusterMailbox { expected, next } => {
                let state: voboost_shared::cluster_mailbox::State =
                    voboost_contract::domain_core::parse_canonical(
                        next.as_bytes(),
                        voboost_contract::runtime_owner::MAX_CLUSTER_MAILBOX_BYTES,
                    )
                    .map_err(|error| invalid(&error))?;
                state.validate().map_err(|error| invalid(&error))?;
                let directory =
                    Directory::open(&self.root)?.open_or_create_private_child("cluster")?;
                directory.validate_owner_mode(
                    unsafe { libc::geteuid() },
                    unsafe { libc::getegid() },
                    0o700,
                )?;
                let current = self.cluster_mailbox()?;
                if current != expected {
                    Outcome::Conflict {}
                } else {
                    directory.write_atomic("mailbox.json", next.as_bytes(), 0o600)?;
                    Outcome::Written {}
                }
            }
            Command::ReadClusterEpoch {} => Outcome::ClusterEpoch {
                value: self.cluster_epoch.clone(),
            },
            Command::SetStartup { startup } => self.set_startup(
                &startup,
                &self
                    .native_boot
                    .clone()
                    .ok_or_else(|| invalid("startup boot unavailable"))?,
            )?,
            Command::ReadNativeCan { .. } => Outcome::Unavailable {},
            Command::ReadLogSession {} => {
                let logger = self
                    .logger
                    .as_ref()
                    .ok_or_else(|| invalid("current logging session unavailable"))?
                    .lock()
                    .map_err(|_| invalid("logging lock poisoned"))?;
                let (boot_id, writer_id, sequence) = logger
                    .session()
                    .ok_or_else(|| invalid("current logging session unavailable"))?;
                Outcome::LogSession {
                    boot_id: boot_id.into(),
                    writer_id: writer_id.into(),
                    sequence,
                }
            }
            Command::PublishInjectionStatus { bytes } => {
                let value: crate::strict_json::StrictValue = serde_json::from_str(&bytes)
                    .map_err(|_| invalid("invalid injection status"))?;
                value
                    .validate(crate::strict_json::ValueLimits {
                        max_depth: 64,
                        max_total_nodes: 65536,
                        max_object_properties: 8192,
                        max_array_items: 8192,
                        max_string_bytes: voboost_contract::runtime_owner::MAX_STATUS_BYTES,
                    })
                    .map_err(invalid)?;
                if value
                    .0
                    .get("schemaVersion")
                    .and_then(serde_json::Value::as_u64)
                    != Some(1)
                    || !value
                        .0
                        .get("injections")
                        .is_some_and(serde_json::Value::is_array)
                    || !value
                        .0
                        .get("executors")
                        .is_some_and(serde_json::Value::is_array)
                {
                    return Err(invalid("invalid injection status envelope"));
                }
                let root = Directory::open(&self.root)?;
                root.validate_owner_mode(
                    unsafe { libc::geteuid() },
                    unsafe { libc::getegid() },
                    0o755,
                )?;
                match root.read_trusted(
                    "status.json",
                    voboost_contract::runtime_owner::MAX_STATUS_BYTES,
                    0o644,
                ) {
                    Ok(_) => (),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => (),
                    Err(error) => return Err(error),
                }
                root.write_atomic("status.json", bytes.as_bytes(), 0o644)?;
                Outcome::Written {}
            }
            Command::AppendAppBatch { bytes } => Outcome::BatchLogged {
                batch_id: self
                    .logger
                    .as_ref()
                    .ok_or_else(|| invalid("logging session unavailable"))?
                    .lock()
                    .map_err(|_| invalid("logging lock poisoned"))?
                    .append_app_batch(bytes.as_bytes())?,
            },
            Command::SaveStartupRecovery { input } => self.save_startup_recovery(&input)?,
            Command::ReadStartupSession {} => Outcome::StartupSession {
                bytes: self.startup_session()?,
            },
            Command::ReplaceStartupSession { expected, next } => {
                if let Some(bytes) = &next {
                    validate_startup_session(bytes)?;
                }
                if self.startup_session()? != expected {
                    Outcome::Conflict {}
                } else if expected.is_none() && next.is_none() {
                    Outcome::Written {}
                } else {
                    let directory = Directory::open(&self.root)?
                        .open_or_create_child_with_mode("run", 0o755)?;
                    directory.validate_owner_mode(
                        unsafe { libc::geteuid() },
                        unsafe { libc::getegid() },
                        0o755,
                    )?;
                    match next {
                        Some(bytes) => directory.write_atomic(
                            "startup-session.json",
                            bytes.as_bytes(),
                            0o600,
                        )?,
                        None => {
                            if expected.is_some() {
                                directory.unlink("startup-session.json")?;
                            }
                            directory.sync_all()?;
                        }
                    }
                    Outcome::Written {}
                }
            }
            Command::AppendLog { source, record } => {
                let (writer_id, sequence) = self.write_log(source, record)?;
                Outcome::Logged {
                    writer_id,
                    sequence,
                }
            }
            Command::ReadState { source, key } => {
                match state::read(&self.root.join("state"), &source, &key) {
                    ReadOutcome::Value(value) => Outcome::State { value: Some(value) },
                    ReadOutcome::Missing => Outcome::State { value: None },
                    ReadOutcome::Error => Outcome::Unavailable {},
                }
            }
            Command::ReadControllerState { source, key } => {
                match state::read_controller(&self.root.join("state"), &source, &key) {
                    ReadOutcome::Value(value) => Outcome::State { value: Some(value) },
                    ReadOutcome::Missing => Outcome::State { value: None },
                    ReadOutcome::Error => Outcome::Unavailable {},
                }
            }
            Command::WriteState { source, key, value } => {
                let key = state::storage_key(&source, &key)
                    .ok_or_else(|| invalid("invalid state owner"))?;
                state::write(&self.root.join("state"), &key, &state::render_value(&value))
                    .map_err(|_| invalid("state commit failed"))?;
                Outcome::Written {}
            }
            Command::WriteControllerState { source, key, value } => {
                let key = state::storage_key(&source, &key)
                    .ok_or_else(|| invalid("invalid state owner"))?;
                state::write_controller(
                    &self.root.join("state"),
                    &key,
                    &state::render_value(&value),
                )
                .map_err(|_| invalid("state commit failed"))?;
                Outcome::Written {}
            }
            Command::ClearControllerState {
                source,
                key,
                expected,
            } => {
                let cleared =
                    state::clear_controller_if(&self.root.join("state"), &source, &key, &expected)
                        .map_err(|_| invalid("conditional media state commit failed"))?;
                Outcome::StateCleared { cleared }
            }
            Command::RegisterNativeTransport {
                source,
                pid,
                endpoint_epoch,
                available,
            } => self.register_transport(&source, pid, endpoint_epoch, available)?,
            Command::ObserveNativeVehicle {
                source,
                pid,
                endpoint_epoch,
                observation,
            } => self.observe_vehicle(&source, pid, endpoint_epoch, observation)?,
            Command::PollNativeCommand {
                source,
                pid,
                endpoint_epoch,
            } => self.poll_command(&source, pid, endpoint_epoch)?,
            Command::ReportNativeCommand {
                identity,
                pid,
                endpoint_epoch,
                status,
            } => self.report_command(identity, pid, endpoint_epoch, status)?,
            Command::PrepareIntent {
                source,
                key,
                record,
            } => Outcome::IntentPrepared {
                admission: self.prepare_intent(&source, &key, record)?,
            },
            Command::FinishIntent {
                source,
                key,
                record,
            } => {
                self.finish_intent(&source, &key, record)?;
                Outcome::Written {}
            }
            Command::RecoverIntent { source, key } => {
                self.recover_intent(&source, &key)?;
                self.refresh_native()?;
                Outcome::Written {}
            }
            Command::ReadJournal { source, key } => Outcome::Journal {
                bytes: self
                    .journal(&source, &key)?
                    .map(String::from_utf8)
                    .transpose()
                    .map_err(|_| invalid("journal is not UTF-8"))?,
            },
            Command::ReplaceJournal {
                source,
                key,
                expected,
                next,
            } => {
                if super::native::CODECS.iter().any(|codec| {
                    codec.id == source && codec.pending_journals.contains(&key.as_str())
                }) {
                    return Err(invalid("captured intent requires its closed transaction"));
                }
                let _: crate::strict_json::StrictValue =
                    serde_json::from_str(&next).map_err(|_| invalid("invalid journal JSON"))?;
                if self.journal(&source, &key)?.as_deref() != expected.as_deref().map(str::as_bytes)
                {
                    self.refresh_native()?;
                    Outcome::Conflict {}
                } else {
                    let directory = state::open_directory(&self.root.join("state"), true)?;
                    directory.write_atomic(
                        &journal_name(&source, &key)?,
                        next.as_bytes(),
                        0o600,
                    )?;
                    self.refresh_native()?;
                    Outcome::Written {}
                }
            }
            Command::ReadConfig {} => Outcome::Config {
                bytes: self
                    .config()?
                    .map(String::from_utf8)
                    .transpose()
                    .map_err(|_| invalid("configuration is not UTF-8"))?,
            },
            Command::SaveDesired {
                field,
                value,
                input,
            } => self.save_desired(&field, &value, &input)?,
            Command::SaveLauncherDesired { changes, input } => {
                self.save_launcher_desired(changes, &input)?
            }
            Command::ConfirmAgentWithdrawn { source } => {
                self.confirm_withdrawn(&source);
                Outcome::Withdrawn {}
            }
            Command::ReconcileDesired { defaults } => {
                self.reconcile_desired(defaults.as_bytes())?
            }
            Command::ReadDesired { field } => self.read_desired(&field)?,
            Command::ReplaceConfig { expected, next } => {
                validate_config(next.as_bytes())?;
                let current = self.config()?;
                if current.as_deref() != expected.as_deref().map(str::as_bytes) {
                    Outcome::Conflict {}
                } else {
                    let next = match current {
                        Some(current) => {
                            let previous = desired::Config::decode(&current)?;
                            let proposed = desired::Config::decode(next.as_bytes())?;
                            if !proposed.preserves_user_authority(&previous) {
                                return Ok(Outcome::Conflict {});
                            }
                            next.into_bytes()
                        }
                        None => desired::Config::initial(next.as_bytes())?,
                    };
                    self.revoke_native();
                    crate::secure_fs::write_atomic_private(
                        &self.root.join("agents.json"),
                        &next,
                        0o600,
                    )?;
                    if let Err(error) = self.refresh_native() {
                        let _ = self.write_log(
                            voboost_contract::runtime_log::Source::daemon(),
                            voboost_contract::runtime_log::Record {
                                level: voboost_contract::runtime_log::Level::Error,
                                component: "native".into(),
                                message: "Native configuration unavailable".into(),
                                fields: std::collections::HashMap::from([(
                                    "reason".into(),
                                    error.to_string(),
                                )]),
                            },
                        );
                    }
                    Outcome::Written {}
                }
            }
        })
    }
}
impl Store {
    fn startup_session(&self) -> io::Result<Option<String>> {
        let run = match Directory::open(&self.root)?.open_child("run") {
            Ok(dir) => dir,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        run.validate_owner_mode(
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o755,
        )?;
        match run.read_trusted("startup-session.json", 512, 0o600) {
            Ok(bytes) => String::from_utf8(bytes).map(Some).map_err(io::Error::other),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn set_startup(&mut self, startup: &str, boot_id: &str) -> io::Result<Outcome> {
        if !matches!(startup, "none" | "hidden" | "interface") {
            return Err(invalid("startup mode rejected"));
        }
        let root = Directory::open(&self.root)?;
        let manifest = root.read_trusted(
            "voboost.json",
            voboost_contract::release::MAX_MANIFEST_BYTES,
            0o600,
        )?;
        let manifest: crate::strict_json::StrictValue =
            serde_json::from_slice(&manifest).map_err(io::Error::other)?;
        let version = manifest
            .0
            .get("releaseIdentity")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| invalid("installed version unavailable"))?;
        if !semver::Version::parse(version).is_ok_and(|v| v.to_string() == version) {
            return Err(invalid("installed version invalid"));
        }
        let bytes = self
            .config()?
            .ok_or_else(|| invalid("configuration unavailable"))?;
        validate_config(&bytes)?;
        let config: serde_json::Value = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        let previous = config["startup"]
            .as_str()
            .ok_or_else(|| invalid("startup mode missing"))?;
        let session = serde_json::json!({"schemaVersion":1,"bootId":boot_id,"startup":previous});
        let session = serde_json::to_string(&session).map_err(io::Error::other)?;
        validate_startup_session(&session)?;
        let existing = self.startup_session()?;
        if let Some(ref bytes) = existing {
            validate_startup_session(bytes)?;
        }
        let current_boot = existing
            .as_deref()
            .and_then(|bytes| serde_json::from_str::<serde_json::Value>(bytes).ok())
            .is_some_and(|v| v["bootId"] == boot_id);
        if !current_boot {
            let run = root.open_or_create_child_with_mode("run", 0o755)?;
            run.validate_owner_mode(
                unsafe { libc::geteuid() },
                unsafe { libc::getegid() },
                0o755,
            )?;
            // Preserve the running boot before changing next-boot intent.
            run.write_atomic("startup-session.json", session.as_bytes(), 0o600)?;
        }
        let producer = self
            .current_producer
            .ok_or_else(|| invalid("startup peer unavailable"))?;
        let request_id = desired::Config::decode(&bytes)?
            .user_revision
            .checked_add(1)
            .ok_or_else(|| invalid("desired revision exhausted"))?;
        let installed_version = version.to_string();
        self.save_desired(
            &voboost_contract::desired::Field::Startup,
            &startup.into(),
            &voboost_contract::desired::Input {
                boot_id: boot_id.into(),
                endpoint_epoch: 1,
                request_id,
                injector_pid: producer.0,
                injector_starttime: producer.1,
            },
        )?;
        Ok(Outcome::StartupSaved {
            startup: startup.into(),
            installed_version,
        })
    }
}
fn validate_startup_session(bytes: &str) -> io::Result<()> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Session {
        schema_version: u32,
        boot_id: String,
        startup: String,
    }
    let value: Session =
        serde_json::from_str(bytes).map_err(|_| invalid("invalid startup session"))?;
    if value.schema_version != 1
        || !matches!(value.startup.as_str(), "none" | "hidden" | "interface")
        || value.boot_id.len() != 36
        || !value.boot_id.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
    {
        return Err(invalid("invalid startup session"));
    }
    Ok(())
}
fn journal_name(source: &str, key: &str) -> io::Result<String> {
    let key = state::storage_key(source, key).ok_or_else(|| invalid("invalid journal owner"))?;
    Ok(format!(".{key}.journal.json"))
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn validate_config(bytes: &[u8]) -> io::Result<()> {
    desired::Config::decode(bytes).map(|_| ())
}
#[cfg(test)]
#[path = "server.test.rs"]
mod tests;
