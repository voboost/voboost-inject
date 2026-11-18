//! Synchronous native service, authenticated courier input and startup-controller bridge.
use crate::{
    config::Config,
    controller::Challenge,
    engine::{Authority, ProductRoots},
    ipc::{Body, Direction, Message},
    Result,
};
use alloc::{collections::BTreeMap, vec, vec::Vec};
use voboost_contract_core::{
    cluster::{ObservedAgent, ObservedState, ProcessIdentity, RequestKind},
    hash, parse_canonical,
    wire::NetworkHeader,
};
fn call(
    fd: i32,
    secret: &[u8; 32],
    daemon: &str,
    controller: &str,
    sequence: u64,
    body: Body,
) -> Result<Body> {
    let request = Message {
        schema_version: 1,
        daemon_nonce: daemon.into(),
        controller_nonce: controller.into(),
        direction: Direction::Request,
        sequence,
        body,
    };
    crate::net::write_frame(fd, &request.seal(secret)?)?;
    Ok(Message::open(
        &crate::net::read_frame(fd)?,
        secret,
        daemon,
        controller,
        Direction::Response,
        sequence,
    )?
    .body)
}
pub fn controller(a: &Authority, stop: bool) -> Result<Option<Vec<ObservedAgent>>> {
    controller_query(a, stop, false)
}
fn snapshot_matches(
    body: &Body,
    generation: &str,
    revision: u64,
    desired: &str,
    process: &ProcessIdentity,
) -> bool {
    matches!(body, Body::Snapshot {
        generation_id: Some(id), desired_revision, desired_sha256, agents, ..
    } if id == generation && *desired_revision == revision && desired_sha256 == desired
        && agents.iter().all(|row| row.process.as_ref().map(|p|
            p.pid == process.pid && p.birth_identity == process.birth_identity
                && p.executable_sha256 == process.executable_sha256
                && p.endpoint_epoch == process.endpoint_epoch
                && p.lifecycle_generation > 0).unwrap_or(true)))
}
struct ControllerConnection {
    fd: crate::fs::Fd,
    secret: [u8; 32],
    daemon: alloc::string::String,
    controller: alloc::string::String,
    process: ProcessIdentity,
}
fn controller_connection_for(
    a: &Authority,
    executable: &str,
) -> Result<Option<ControllerConnection>> {
    let Some(fd) = crate::net::unix_connect_optional(&crate::config::owner_socket(
        &a.config.root,
        executable,
    )?)?
    else {
        return Ok(None);
    };
    let challenge: Challenge = parse_canonical(&crate::net::read_frame(fd.0)?, 65536)?;
    if challenge.schema_version != 1 || !voboost_contract_core::digest(&challenge.controller_nonce)
    {
        return Err("invalid controller challenge".into());
    }
    // Every connection gets a fresh service nonce. Old authenticated snapshots
    // cannot become observations in a later service/controller session.
    let daemon = crate::nonce()?;
    let secret = crate::key(&a.config.ipc_secret)?;
    let controller = &challenge.controller_nonce;
    let Body::Register { process } = call(fd.0, &secret, &daemon, controller, 0, Body::Hello {})?
    else {
        return Err("startup controller register required".into());
    };
    if process.endpoint_epoch != *controller
        || process.pid == 0
        || process.lifecycle_generation == 0
        || process.supervisor.as_ref().is_some_and(|s| {
            s.parent_pid <= 1
                || s.parent_pid > voboost_contract_core::MAX_SAFE_INTEGER
                || !voboost_contract_core::digest(&s.nonce)
        })
        || !voboost_contract_core::digest(&process.birth_identity)
        || !voboost_contract_core::digest(&process.executable_sha256)
    {
        return Err("startup controller identity rejected".into());
    }
    crate::elf::process(process.pid, executable, &process.executable_sha256)?;
    Ok(Some(ControllerConnection {
        fd,
        secret,
        daemon,
        controller: challenge.controller_nonce,
        process,
    }))
}
/// Authenticated live owner observation; an old active revision is not disabled success.
pub(crate) struct OwnerObservation {
    pub executable: alloc::string::String,
    pub process: ProcessIdentity,
    pub generation: Option<alloc::string::String>,
    pub revision: u64,
    pub desired: alloc::string::String,
    pub agents: Vec<ObservedAgent>,
}
pub(crate) fn observe_owner_for(a: &Authority, executable: &str) -> Result<OwnerObservation> {
    let c = controller_connection_for(a, executable)?.ok_or("startup controller unavailable")?;
    let body = call(
        c.fd.0,
        &c.secret,
        &c.daemon,
        &c.controller,
        1,
        Body::Observe {},
    )?;
    let Body::Snapshot {
        supervisor,
        generation_id,
        desired_revision,
        desired_sha256,
        agents,
        ..
    } = body
    else {
        return Err("owner snapshot required".into());
    };
    if supervisor != c.process.supervisor {
        return Err("owner parent changed during authenticated observation".into());
    }
    if agents
        .iter()
        .any(|row| row.target_process != crate::config::owner_role(executable).unwrap_or(""))
    {
        return Err("owner observation target attribution differs".into());
    }
    if agents
        .iter()
        .filter_map(|row| row.process.as_ref())
        .any(|p| {
            p.pid != c.process.pid
                || p.birth_identity != c.process.birth_identity
                || p.executable_sha256 != c.process.executable_sha256
                || p.endpoint_epoch != c.process.endpoint_epoch
                || p.supervisor != c.process.supervisor
                || p.lifecycle_generation == 0
        })
    {
        return Err("owner observation process attribution differs".into());
    }
    crate::elf::process(c.process.pid, executable, &c.process.executable_sha256)?;
    Ok(OwnerObservation {
        executable: executable.into(),
        process: c.process,
        generation: generation_id,
        revision: desired_revision,
        desired: desired_sha256,
        agents,
    })
}
static OWNER_QUERY_LOGS: crate::controller::Spin<[crate::diagnostic_log::Transition; 3]> =
    crate::controller::Spin::new([const { crate::diagnostic_log::Transition::new() }; 3]);
fn controller_query(
    a: &Authority,
    stop: bool,
    observe: bool,
) -> Result<Option<Vec<ObservedAgent>>> {
    let Some(generation) = &a.generation else {
        return Ok(None);
    };
    let mut owners: BTreeMap<
        alloc::string::String,
        Vec<(alloc::string::String, alloc::string::String)>,
    > = BTreeMap::new();
    for agent in &generation.catalog.agents {
        if agent.domain != voboost_contract_core::catalog::Domain::Cluster {
            continue;
        }
        for target in &agent.targets {
            if let voboost_contract_core::catalog::Target::Native { executable, .. } = target {
                if crate::config::owner_role(executable)? != target.process() {
                    return Err("selected owner role differs".into());
                }
                let rows = owners.entry(executable.clone()).or_default();
                let key = (
                    agent.id.clone(),
                    alloc::string::String::from(target.process()),
                );
                if !rows.contains(&key) {
                    rows.push(key);
                }
            }
        }
    }
    let mut rows = Vec::new();
    for (executable, expected) in owners {
        let result = controller_query_for(a, stop, observe, &executable);
        let index = match executable.as_str() {
            "/usr/bin/gauge" => 0,
            "/usr/bin/point" => 1,
            "/usr/bin/light" => 2,
            _ => return Err("controller owner unsupported".into()),
        };
        let identity = alloc::format!(
            "{}:{}:{}:{}:{}",
            a.daemon_epoch,
            generation.generation_id,
            a.desired.as_ref().map(|d| d.desired_revision).unwrap_or(0),
            stop,
            executable
        );
        OWNER_QUERY_LOGS.with(|logs| match &result {
            Ok(ControllerQuery::Unavailable) => {
                logs[index].pending("controller-owner", &identity, "controller endpoint absent")
            }
            Ok(ControllerQuery::Pending { revision, failure }) => {
                let mut reason = alloc::format!("controller still reports revision {revision}");
                if let Some(row) = failure {
                    reason.push_str(&alloc::format!("; {}: {}", row.id, row.reason));
                }
                logs[index].pending("controller-owner", &identity, &reason);
            }
            _ => logs[index].observe("controller-owner", &identity, &result),
        });
        let (observed, missing_reason) = match result {
            Ok(ControllerQuery::Ready(rows)) => (rows, "startup-controller-target-unavailable"),
            Ok(ControllerQuery::Pending { .. }) => {
                (Vec::new(), "startup-controller-awaiting-revision")
            }
            Ok(ControllerQuery::Unavailable) => (Vec::new(), "startup-controller-unavailable"),
            Err(reason) if stop => return Err(reason),
            Err(_) => (Vec::new(), "startup-controller-query-failed"),
        };
        rows.extend(complete_owner_rows(expected, observed, missing_reason)?);
    }
    rows.sort_by(|a, b| (&a.id, &a.target_process).cmp(&(&b.id, &b.target_process)));
    Ok(Some(rows))
}
fn complete_owner_rows(
    expected: Vec<(alloc::string::String, alloc::string::String)>,
    observed: Vec<ObservedAgent>,
    missing_reason: &str,
) -> Result<Vec<ObservedAgent>> {
    if observed
        .iter()
        .any(|row| !expected.contains(&(row.id.clone(), row.target_process.clone())))
    {
        return Err("owner observation contains foreign target".into());
    }
    let mut rows = Vec::new();
    for (id, target_process) in expected {
        let mut matches = observed
            .iter()
            .filter(|r| r.id == id && r.target_process == target_process);
        let found = matches.next().cloned();
        if matches.next().is_some() {
            return Err("duplicate owner observation".into());
        }
        let row = found.unwrap_or(ObservedAgent {
            id,
            target_process,
            state: ObservedState::WaitingProcess,
            reason: missing_reason.into(),
            process: None,
        });
        rows.push(row);
    }
    Ok(rows)
}
enum ControllerQuery {
    Unavailable,
    Pending {
        revision: u64,
        failure: Option<ObservedAgent>,
    },
    Ready(Vec<ObservedAgent>),
}
fn controller_query_for(
    a: &Authority,
    stop: bool,
    observe: bool,
    executable: &str,
) -> Result<ControllerQuery> {
    let Some(ControllerConnection {
        fd,
        secret,
        daemon,
        controller,
        process,
    }) = controller_connection_for(a, executable)?
    else {
        if stop {
            return Err("startup controller unavailable".into());
        }
        return Ok(ControllerQuery::Unavailable);
    };
    let controller = &controller;
    let body = if stop {
        Body::Stop {}
    } else if observe {
        Body::Observe {}
    } else {
        let g = a
            .generation
            .as_ref()
            .ok_or("native generation unavailable")?;
        let d = a.desired.as_ref().ok_or("native desired unavailable")?;
        Body::Apply {
            global_locale: a.live_global_locale.clone().filter(|_| {
                crate::engine::monotonic_ms()
                    .is_some_and(|now| now <= a.live_global_locale_deadline_ms)
            }),
            global_locale_deadline_ms: a.live_global_locale_deadline_ms,
            generation_id: g.generation_id.clone(),
            desired_revision: d.desired_revision,
            desired_sha256: d.desired_sha256.clone(),
            agents: g.agent_state_for(executable, &d.agents)?,
        }
    };
    let mut body = call(fd.0, &secret, &daemon, controller, 1, body)?;
    if stop {
        let mut sequence = 2;
        for _ in 0..300 {
            if let Body::Snapshot {
                stopped: true,
                agents,
                ..
            } = &body
            {
                return Ok(ControllerQuery::Ready(agents.clone()));
            }
            if let Body::Snapshot { agents, .. } = &body {
                if agents.iter().any(|r| {
                    matches!(
                        r.state,
                        ObservedState::Failed | ObservedState::ReloadRequired
                    )
                }) {
                    return Err("UI restore requires process reload".into());
                }
            }
            unsafe {
                libc::usleep(10_000);
            }
            body = call(
                fd.0,
                &secret,
                &daemon,
                controller,
                sequence,
                Body::Observe {},
            )?;
            sequence = crate::ipc::advance(sequence)?;
        }
        return Err("UI restore was not observed before deadline".into());
    }
    let g = a.generation.as_ref().ok_or("generation unavailable")?;
    let d = a.desired.as_ref().ok_or("desired unavailable")?;
    let mut sequence = 2;
    if observe
        && !snapshot_matches(
            &body,
            &g.generation_id,
            d.desired_revision,
            &d.desired_sha256,
            &process,
        )
    {
        let _ = call(
            fd.0,
            &secret,
            &daemon,
            controller,
            sequence,
            Body::Apply {
                global_locale: a.live_global_locale.clone().filter(|_| {
                    crate::engine::monotonic_ms()
                        .is_some_and(|now| now <= a.live_global_locale_deadline_ms)
                }),
                global_locale_deadline_ms: a.live_global_locale_deadline_ms,
                generation_id: g.generation_id.clone(),
                desired_revision: d.desired_revision,
                desired_sha256: d.desired_sha256.clone(),
                agents: g.agent_state_for(executable, &d.agents)?,
            },
        )?;
        sequence = crate::ipc::advance(sequence)?;
    }
    for _ in 0..30 {
        if let Body::Snapshot {
            generation_id,
            desired_revision,
            desired_sha256,
            agents,
            ..
        } = &body
        {
            if generation_id.as_deref() == Some(&g.generation_id)
                && *desired_revision == d.desired_revision
                && *desired_sha256 == d.desired_sha256
            {
                for row in agents {
                    if let Some(p) = &row.process {
                        if p.pid != process.pid
                            || p.birth_identity != process.birth_identity
                            || p.executable_sha256 != process.executable_sha256
                            || p.endpoint_epoch != process.endpoint_epoch
                            || p.lifecycle_generation == 0
                        {
                            return Err(
                                "observed native process/session attribution changed".into()
                            );
                        }
                    }
                    if row.state == ObservedState::Applied
                        && !d.agents.iter().any(|v| v.id == row.id && v.enabled)
                    {
                        return Err("disabled native agent claimed applied".into());
                    }
                }
                crate::elf::process(process.pid, executable, &process.executable_sha256)?;
                return Ok(ControllerQuery::Ready(agents.clone()));
            }
        } else {
            return Err("controller observation required".into());
        }
        unsafe {
            libc::usleep(10_000);
        }
        body = call(
            fd.0,
            &secret,
            &daemon,
            controller,
            sequence,
            Body::Observe {},
        )?;
        sequence = crate::ipc::advance(sequence)?;
    }
    match body {
        Body::Snapshot {
            desired_revision,
            agents,
            ..
        } => Ok(ControllerQuery::Pending {
            revision: desired_revision,
            failure: agents.into_iter().find(|row| {
                matches!(
                    row.state,
                    ObservedState::Failed | ObservedState::ReloadRequired
                )
            }),
        }),
        _ => Err("controller observation required".into()),
    }
}
pub fn connection(a: &mut Authority, stream: &crate::tls::Stream) -> Result<()> {
    request(a, stream, &stream.frame()?)
}
fn request(a: &mut Authority, stream: &crate::tls::Stream, first_frame: &[u8]) -> Result<()> {
    if first_frame == voboost_contract_core::pw_live::HELLO {
        return crate::pw_live::exchange(a, stream);
    }
    let header = NetworkHeader::parse(first_frame)?;
    let first = &header.files[0];
    let mut envelope = vec![0; first.size as usize];
    stream.read_exact(&mut envelope)?;
    if hash(&envelope) != first.sha256 {
        return Err("request descriptor digest mismatch".into());
    }
    let request = a.request(&envelope)?;
    let mut delivered = BTreeMap::new();
    if request.kind == RequestKind::Generation {
        if request.files.as_deref() != Some(&header.files[1..]) {
            return Err("network file closure lacks paired authority".into());
        }
        for file in header.files.iter().skip(1) {
            let mut bytes = vec![0; file.size as usize];
            stream.read_exact(&mut bytes)?;
            if hash(&bytes) != file.sha256 {
                return Err("native file delivery digest mismatch".into());
            }
            delivered.insert(file.file.clone(), bytes);
        }
    }
    stream.check_deadline()?;
    let _operation = crate::operation::Lock::existing(&a.root)?;
    let request = a.request(&envelope)?;
    stream.check_deadline()?;
    if request.kind == RequestKind::Uninstall {
        if header.files.len() != 1 {
            return Err("uninstall carries extra files".into());
        }
        let receipt = crate::install::prepare_service_uninstall(a, &request)?;
        return stream.write_frame(&receipt);
    }
    if a.root.exists("restore.lock")? {
        return Err("native uninstall is fenced; cluster reboot required".into());
    }
    let request = match request.kind {
        RequestKind::Generation => {
            if request.files.as_deref() != Some(&header.files[1..]) {
                return Err("network file closure lacks paired authority".into());
            }
            let request = a.import(&envelope, &header, &delivered)?;
            // Current effects are restored on a subsequent original UI frame.
            // Native generation admission itself is never an Applied claim.
            let _ = controller(a, true);
            request
        }
        RequestKind::Desired => {
            if header.files.len() != 1 {
                return Err("desired carries unsigned extra files".into());
            }
            a.admit_desired(&envelope)?
        }
        RequestKind::Observe => {
            if header.files.len() != 1 {
                return Err("observe carries extra files".into());
            }
            a.observation_request(&envelope)?
        }
        RequestKind::Uninstall => return Err("uninstall dispatch invariant".into()),
    };
    let observed = if request.kind == RequestKind::Generation {
        None
    } else {
        controller_query(a, false, request.kind == RequestKind::Observe).unwrap_or(None)
    };
    let receipt = a.receipt(&request, observed)?;
    stream.write_frame(&receipt)
}
pub(crate) fn ignore_socket_sigpipe() -> Result<()> {
    // SSL_set_fd uses a socket BIO whose write can raise SIGPIPE. Only the
    // standalone daemon owns its process disposition; preload never calls this.
    if unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) } == libc::SIG_ERR {
        return Err("native daemon SIGPIPE protection unavailable".into());
    }
    Ok(())
}

pub fn run(config: Config) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("native service requires root".into());
    }
    let _ = crate::diagnostic_ram::attach(&config.pair_id, 0);
    ignore_socket_sigpipe()?;
    let tls = crate::tls::Api::original()?.server(&config.tls)?;
    let mut authority = Authority::open(config, 0, ProductRoots::default())?;
    let mut previous_network_error = None;
    let listener = loop {
        match crate::net::tcp_listen(
            &authority.config.listen.address,
            authority.config.listen.port,
        ) {
            Ok(listener) => break listener,
            Err(error) if error.network_unavailable() => {
                let reason = alloc::format!("{error}");
                if previous_network_error.as_ref() != Some(&reason) {
                    crate::diagnostic_log::emit(
                        "info",
                        "cluster-service",
                        "Waiting for the cluster network",
                        &[("reason", &reason)],
                    );
                    previous_network_error = Some(reason);
                }
                // The OEM startup launches this daemon in the background.
                unsafe { libc::usleep(500_000) };
            }
            Err(error) => return Err(alloc::format!("{error}")),
        }
    };
    let ingress = crate::service_ingress::Ingress::new(tls, authority.daemon_epoch.clone());
    let mut controller_log = crate::diagnostic_log::Transition::default();
    let mut reconcile_log = crate::diagnostic_log::Transition::default();
    let mut connection_log = crate::diagnostic_log::Transition::default();
    let mut pw_log = crate::diagnostic_log::Transition::default();
    let mut tls_log = crate::diagnostic_log::Transition::default();
    // Reconstruct durable intent without waiting for a new checkbox event.
    {
        let _operation = crate::operation::Lock::existing(&authority.root)?;
        if authority.desired.is_some() && !authority.root.exists("restore.lock")? {
            let result = controller(&authority, false);
            controller_log.observe_optional("controller-initial", &authority.daemon_epoch, &result);
        }
    }
    let mut record = ServiceRecord::capture(&authority, true);
    let mut restart_log = crate::owner_restart::PreparationLog::default();
    {
        let _operation = crate::operation::Lock::existing(&authority.root)?;
        authority.root.write(
            "service.json",
            &voboost_contract_core::ascii_json(&record)?,
            0o600,
        )?;
    }
    crate::diagnostic_log::emit("info", "cluster-service", "service ready", &[]);
    loop {
        let reconciliation = (|| -> Result<bool> {
            let _operation = crate::operation::Lock::existing(&authority.root)?;
            if authority.root.exists("shutdown.request")? {
                let request: Shutdown = parse_canonical(
                    &authority
                        .root
                        .read("shutdown.request", SHUTDOWN_MAX, 0o600)?,
                    SHUTDOWN_MAX,
                )?;
                if request.daemon_epoch == authority.daemon_epoch {
                    request.verify(&authority.config)?;
                    if controller(&authority, true)?.is_none() {
                        return Ok(false);
                    }
                    record = ServiceRecord::capture(&authority, false);
                    authority.root.write(
                        "service.json",
                        &voboost_contract_core::ascii_json(&record)?,
                        0o600,
                    )?;
                    return Ok(true);
                }
            }
            if authority.desired.is_some() && !authority.root.exists("restore.lock")? {
                // A matching observation, including ReloadRequired, must not enqueue
                // the same Apply every poll. A fresh controller or changed intent
                // still receives Apply through the authenticated reconciliation path.
                let result = controller_query(&authority, false, true);
                reconcile_log.observe_optional(
                    "controller-reconcile",
                    &authority.daemon_epoch,
                    &result,
                );
                let _ = crate::owner_restart::prepare(&authority, &mut restart_log);
            }
            Ok(false)
        })();
        if matches!(&reconciliation, Ok(true)) {
            return Ok(());
        }
        controller_log.observe("native-reconcile", &authority.daemon_epoch, &reconciliation);
        let Some(accepted) = ingress.next(listener.0) else {
            continue;
        };
        tls_log.observe("tls-ingress", &authority.daemon_epoch, &accepted);
        let (stream, first_frame) = match accepted {
            Ok(connection) => connection,
            Err(_) => continue,
        };
        // A fenced service must still accept an authenticated uninstall retry.
        let transient = first_frame == voboost_contract_core::pw_live::HELLO;
        let result = request(&mut authority, &stream, &first_frame);
        if transient {
            pw_log.observe("pw-request", &authority.daemon_epoch, &result);
        } else {
            connection_log.observe("service-request", &authority.daemon_epoch, &result);
        }
        if transient {
            continue;
        } // No durable service.json heartbeat for live PW.
        let _operation = crate::operation::Lock::existing(&authority.root)?;
        if authority.root.exists("restore.lock")? {
            continue;
        }
        record = ServiceRecord::capture(&authority, true);
        authority.root.write(
            "service.json",
            &voboost_contract_core::ascii_json(&record)?,
            0o600,
        )?;
    }
}
pub fn bootfile(path: &str) -> Result<Config> {
    Config::parse(&crate::fs::read_protected(path, 0, 16384, 0o600)?)
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceRecord {
    pub schema_version: u32,
    pub pid: u64,
    pub boot_id: alloc::string::String,
    pub daemon_epoch: alloc::string::String,
    pub generation_id: Option<alloc::string::String>,
    pub desired_revision: u64,
    pub desired_sha256: alloc::string::String,
    pub running: bool,
}
impl ServiceRecord {
    fn capture(a: &Authority, running: bool) -> Self {
        Self {
            schema_version: 1,
            pid: unsafe { libc::getpid() } as u64,
            boot_id: a.boot_id.clone(),
            daemon_epoch: a.daemon_epoch.clone(),
            generation_id: a.generation.as_ref().map(|g| g.generation_id.clone()),
            desired_revision: a.desired.as_ref().map(|d| d.desired_revision).unwrap_or(0),
            desired_sha256: a
                .desired
                .as_ref()
                .map(|d| d.desired_sha256.clone())
                .unwrap_or_else(|| {
                    voboost_contract_core::cluster::desired_digest(&[]).unwrap_or_default()
                }),
            running,
        }
    }
}
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Shutdown {
    pub schema_version: u32,
    pub daemon_epoch: alloc::string::String,
    pub transaction_id: alloc::string::String,
    pub signed_request: alloc::string::String,
}
pub(crate) const SHUTDOWN_MAX: usize = 2 * 65536 + 4096;
impl Shutdown {
    pub(crate) fn verify(
        &self,
        config: &Config,
    ) -> Result<voboost_contract_core::cluster::Request> {
        if self.schema_version != 1
            || !voboost_contract_core::digest(&self.daemon_epoch)
            || self.signed_request.len() > 2 * 65536
        {
            return Err("offline shutdown authority invalid".into());
        }
        let envelope = hex::decode(&self.signed_request)
            .map_err(|_| "offline shutdown signed request encoding")?;
        let request = Authority::verify_paired_request(config, &envelope)?;
        if request.kind != RequestKind::Uninstall || request.transaction_id != self.transaction_id {
            return Err("offline shutdown request differs".into());
        }
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_owner_is_waiting_and_foreign_or_duplicate_target_proof_is_rejected() {
        let expected = vec![("i18n-ru".into(), "point".into())];
        let missing_reason = "startup-controller-unavailable";
        let missing = complete_owner_rows(expected.clone(), vec![], missing_reason).unwrap();
        assert_eq!(missing[0].target_process, "point");
        assert_eq!(missing[0].state, ObservedState::WaitingProcess);
        assert_eq!(missing[0].reason, missing_reason);
        assert!(missing[0].process.is_none());
        let pending_reason = "startup-controller-awaiting-revision";
        let pending = complete_owner_rows(expected.clone(), vec![], pending_reason).unwrap();
        assert_eq!(pending[0].reason, pending_reason);
        assert!(pending[0].process.is_none());
        let gauge = ObservedAgent {
            id: "i18n-ru".into(),
            target_process: "gauge".into(),
            state: ObservedState::Applied,
            reason: "actual gauge".into(),
            process: None,
        };
        assert!(
            complete_owner_rows(expected.clone(), vec![gauge.clone()], missing_reason).is_err()
        );
        let mut point = gauge;
        point.target_process = "point".into();
        assert!(complete_owner_rows(
            expected.clone(),
            vec![point.clone(), point.clone()],
            missing_reason
        )
        .is_err());
        let ready = complete_owner_rows(expected, vec![point], missing_reason).unwrap();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].target_process, "point");
    }

    #[test]
    fn reload_observation_is_stable_but_changed_intent_or_process_reapplies() {
        let process = ProcessIdentity {
            pid: 42,
            birth_identity: "1".repeat(64),
            executable_sha256: "2".repeat(64),
            endpoint_epoch: "3".repeat(64),
            lifecycle_generation: 2,
            supervisor: None,
        };
        let body = Body::Snapshot {
            supervisor: None,
            generation_id: Some("4".repeat(64)),
            desired_revision: 7,
            desired_sha256: "5".repeat(64),
            agents: vec![ObservedAgent {
                id: "font-cyrillic".into(),
                target_process: "gauge".into(),
                state: ObservedState::ReloadRequired,
                reason: "font-face-loaded".into(),
                process: Some(process.clone()),
            }],
            stopped: false,
        };
        let matches = |p: &ProcessIdentity, revision| {
            snapshot_matches(&body, &"4".repeat(64), revision, &"5".repeat(64), p)
        };
        assert!(matches(&process, 7));
        assert!(!matches(&process, 8));
        assert!(!snapshot_matches(
            &body,
            &"6".repeat(64),
            7,
            &"5".repeat(64),
            &process
        ));
        assert!(!snapshot_matches(
            &body,
            &"4".repeat(64),
            7,
            &"6".repeat(64),
            &process
        ));
        for field in 0..4 {
            let mut replacement = process.clone();
            match field {
                0 => replacement.pid += 1,
                1 => replacement.birth_identity = "6".repeat(64),
                2 => replacement.executable_sha256 = "6".repeat(64),
                _ => replacement.endpoint_epoch = "6".repeat(64),
            }
            assert!(!matches(&replacement, 7));
        }
        let fresh = Body::Snapshot {
            supervisor: None,
            generation_id: None,
            desired_revision: 0,
            desired_sha256: "0".repeat(64),
            agents: vec![],
            stopped: false,
        };
        assert!(!snapshot_matches(
            &fresh,
            &"4".repeat(64),
            7,
            &"5".repeat(64),
            &process
        ));
    }
}
