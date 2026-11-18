//! Resource-only restart preparation. A journal is not supervisor permission.
use crate::{engine::Authority, service::OwnerObservation, Result};
use alloc::string::String;
#[cfg(test)]
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use voboost_contract_core::{
    ascii_json,
    cluster::{ObservedState, ProcessIdentity},
    parse_canonical,
    wire::WireRole,
};
#[cfg(test)]
const FILE: &str = "resource-owner-restart-gauge.json";
const MARKER: &str = "private locale resource stop requires owner restart";
/// Change-only diagnostics use the service's bounded RAM queue.
/// They describe preparation failure/recovery, never owner-stop completion.
#[derive(Default)]
pub(crate) struct PreparationLog {
    last: alloc::collections::BTreeMap<String, (String, String)>,
}
impl PreparationLog {
    fn update<'a>(
        &mut self,
        error: Option<&'a str>,
        executable: &str,
        generation: &str,
    ) -> Option<(&'static str, &'a str)> {
        let bounded = generation.len() <= 1024 && error.is_none_or(|reason| reason.len() <= 4096);
        let next = error.map(|reason| (reason.into(), generation.into()));
        if bounded && self.last.get(executable) == next.as_ref() {
            return None;
        }
        self.last.remove(executable);
        if bounded {
            if let Some(next) = next {
                self.last.insert(executable.into(), next);
            }
        }
        Some(match error {
            Some(reason) => ("error", reason),
            None => ("debug", "preparation recovered"),
        })
    }
    pub(crate) fn observe(&mut self, a: &Authority, executable: &str, result: &Result<()>) {
        let generation = alloc::format!(
            "{}:{}",
            a.generation
                .as_ref()
                .map(|g| g.generation_id.as_str())
                .unwrap_or(""),
            a.desired.as_ref().map(|d| d.desired_revision).unwrap_or(0)
        );
        if let Some((level, reason)) = self.update(
            result.as_ref().err().map(String::as_str),
            executable,
            &generation,
        ) {
            crate::diagnostic_log::emit(
                level,
                "resource-owner-restart-prepare",
                reason,
                &[("owner", executable), ("generation", &generation)],
            );
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
enum Phase {
    Prepared,
    StopRequested,
    OldAbsent,
    StartRequested,
    FreshObserved,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Journal {
    schema_version: u32,
    pair: String,
    epoch: String,
    boot: String,
    storage: String,
    generation: String,
    revision: u64,
    desired: String,
    executable: String,
    old: ProcessIdentity,
    phase: Phase,
    stop_attempts: u8,
    start_attempts: u8,
}
fn owner(executable: &str) -> Result<&str> {
    match executable {
        "/usr/bin/gauge" => Ok("gauge"),
        "/usr/bin/point" => Ok("point"),
        "/usr/bin/light" => Ok("light"),
        _ => Err("resource owner role unsupported".into()),
    }
}
fn disabled(a: &Authority) -> bool {
    a.desired.as_ref().is_some_and(|d| {
        d.agents
            .iter()
            .any(|agent| agent.id == "i18n-ru" && !agent.enabled)
    })
}
impl Journal {
    fn admit(a: &Authority, observed: OwnerObservation) -> Result<Self> {
        let g = a
            .generation
            .as_ref()
            .ok_or("resource restart generation missing")?;
        let d = a
            .desired
            .as_ref()
            .ok_or("resource restart disabled intent missing")?;
        let target_role = owner(&observed.executable)?;
        if !disabled(a)
            || !g.files.iter().any(|f| f.role == WireRole::QnxResourcePack)
            || observed.generation.as_deref() != Some(g.generation_id.as_str())
            || observed.revision == 0
            || observed.revision > d.desired_revision
            || (observed.revision == d.desired_revision && observed.desired != d.desired_sha256)
            || !observed.agents.iter().any(|row| {
                row.id == "i18n-ru"
                    && row.target_process == target_role
                    && row.state == ObservedState::ReloadRequired
                    && row.reason == MARKER
                    && row.process.as_ref().is_some_and(|p| {
                        p.pid == observed.process.pid
                            && p.birth_identity == observed.process.birth_identity
                            && p.endpoint_epoch == observed.process.endpoint_epoch
                    })
            })
        {
            return Err(
                "resource restart does not have current disabled intent and private owner evidence"
                    .into(),
            );
        }
        Ok(Self {
            schema_version: 1,
            pair: a.config.pair_id.clone(),
            epoch: a.config.authority_epoch.clone(),
            boot: a.boot_id.clone(),
            storage: g.storage_id.clone(),
            generation: g.generation_id.clone(),
            revision: d.desired_revision,
            desired: d.desired_sha256.clone(),
            executable: observed.executable,
            old: observed.process,
            phase: Phase::Prepared,
            stop_attempts: 0,
            start_attempts: 0,
        })
    }
    fn current(&self, a: &Authority) -> Result<()> {
        let g = a
            .generation
            .as_ref()
            .ok_or("restart current generation missing")?;
        let d = a
            .desired
            .as_ref()
            .ok_or("restart current desired missing")?;
        if self.schema_version != 1
            || self.pair != a.config.pair_id
            || self.epoch != a.config.authority_epoch
            || self.boot != a.boot_id
            || self.storage != g.storage_id
            || self.generation != g.generation_id
            || self.revision != d.desired_revision
            || self.desired != d.desired_sha256
            || !disabled(a)
            || self.old.pid == 0
            || self.old.pid > voboost_contract_core::MAX_SAFE_INTEGER
            || self.old.lifecycle_generation == 0
            || ![
                &self.old.birth_identity,
                &self.old.executable_sha256,
                &self.old.endpoint_epoch,
            ]
            .iter()
            .all(|value| voboost_contract_core::digest(value))
            || self.stop_attempts > 2
            || self.start_attempts > 2
        {
            return Err("resource restart journal authority changed".into());
        }
        owner(&self.executable)?;
        Ok(())
    }
}
/// Prepare only after an authenticated private-resource reload observation.
/// Actual stop/start requires the separately proven OEM environment seam.
pub(crate) fn prepare(a: &Authority, log: &mut PreparationLog) -> Result<()> {
    prepare_owners(
        |executable| prepare_for(a, executable),
        |executable, result| log.observe(a, executable, result),
    )
}
fn prepare_owners(
    mut action: impl FnMut(&str) -> Result<()>,
    mut observe: impl FnMut(&str, &Result<()>),
) -> Result<()> {
    let mut first = None;
    for executable in ["/usr/bin/gauge", "/usr/bin/point", "/usr/bin/light"] {
        let result = action(executable);
        observe(executable, &result);
        if let Err(reason) = result {
            first.get_or_insert_with(|| alloc::format!("{executable}: {reason}"));
        }
    }
    first.map_or(Ok(()), Err)
}
fn prepare_for(a: &Authority, executable: &str) -> Result<()> {
    let file = alloc::format!("resource-owner-restart-{}.json", owner(executable)?);
    if a.root.exists(&file)? {
        let journal: Journal = parse_canonical(&a.root.read(&file, 16384, 0o600)?, 16384)?;
        if journal.executable != executable {
            return Err("resource restart journal owner differs".into());
        }
        if journal.current(a).is_ok() {
            let permit =
                crate::supervisor_delivery::admit_supervised_owner(a, &journal.executable)?;
            return permit.verify_current(a, &journal.executable);
        }
        if !matches!(journal.phase, Phase::Prepared | Phase::FreshObserved) {
            return Err(
                "interrupted restart must recover its stopped owner before rearming".into(),
            );
        }
    }
    if !disabled(a)
        || a.generation
            .as_ref()
            .is_none_or(|g| !g.files.iter().any(|f| f.role == WireRole::QnxResourcePack))
    {
        return Ok(());
    }
    let selected = a.generation.as_ref().is_some_and(|g| {
        g.selection
            .iter()
            .any(|s| s.id == "i18n-ru" && s.process == owner(executable).unwrap_or(""))
    });
    if !selected {
        return Ok(());
    }
    let observed = crate::service::observe_owner_for(a, executable)?;
    let journal = match Journal::admit(a, observed) {
        Ok(value) => value,
        Err(_) => return Ok(()),
    };
    retain(a, &journal)?;
    let permit = crate::supervisor_delivery::admit_supervised_owner(a, &journal.executable)?;
    permit.verify_current(a, &journal.executable)
}
fn retain(a: &Authority, journal: &Journal) -> Result<()> {
    let bytes = ascii_json(&journal)?;
    let file = alloc::format!(
        "resource-owner-restart-{}.json",
        owner(&journal.executable)?
    );
    a.root.write(&file, &bytes, 0o600)?;
    if a.root.read(&file, 16384, 0o600)? != bytes {
        return Err("resource restart preparation readback differs".into());
    }
    Ok(())
}
#[cfg(test)]
pub(crate) fn actual_signed_admission_regression(a: &Authority) {
    // Signed catalog/product/disabled intent are real; OS observations below are
    // explicit test doubles. Live IPC authentication is tested by service/ipc.
    let g = a.generation.as_ref().unwrap();
    let d = a.desired.as_ref().unwrap();
    let process = ProcessIdentity {
        pid: unsafe { libc::getpid() } as u64,
        birth_identity: "1".repeat(64),
        executable_sha256: "2".repeat(64),
        endpoint_epoch: "3".repeat(64),
        lifecycle_generation: 1,
        supervisor: None,
    };
    let observed = || OwnerObservation {
        executable: a.config.expected_executable.clone(),
        process: process.clone(),
        generation: Some(g.generation_id.clone()),
        revision: d.desired_revision - 1,
        desired: "6".repeat(64),
        agents: alloc::vec![voboost_contract_core::cluster::ObservedAgent {
            id: "i18n-ru".into(),
            target_process: "gauge".into(),
            state: ObservedState::ReloadRequired,
            reason: MARKER.into(),
            process: Some(process.clone())
        }],
    };
    let good = Journal::admit(a, observed()).unwrap();
    good.current(a).unwrap();
    for kind in 0..5 {
        let mut bad = observed();
        match kind {
            0 => bad.generation = Some("7".repeat(64)),
            1 => bad.revision = d.desired_revision + 1,
            2 => bad.agents[0].reason = "unrelated font reload".into(),
            3 => bad.agents[0].process.as_mut().unwrap().endpoint_epoch = "8".repeat(64),
            _ => bad.agents.clear(),
        };
        assert!(Journal::admit(a, bad).is_err());
    }
    retain(a, &good).unwrap();
    let bytes = a.root.read(FILE, 16384, 0o600).unwrap();
    let mut stored: Journal = parse_canonical(&bytes, 16384).unwrap();
    stored.current(a).unwrap();
    stored.revision += 1;
    assert!(stored.current(a).is_err());
    stored.revision -= 1;
    stored.boot = "9".repeat(64);
    assert!(stored.current(a).is_err());
    stored.boot = good.boot.clone();
    stored.old.pid = 0;
    assert!(stored.current(a).is_err());
    stored.old = process;
    stored.phase = Phase::StopRequested;
    stored.revision += 1;
    retain(a, &stored).unwrap();
    assert!(prepare(a, &mut PreparationLog::default())
        .unwrap_err()
        .contains("must recover"));
    assert_eq!(
        a.root.read(FILE, 16384, 0o600).unwrap(),
        ascii_json(&stored).unwrap()
    );
    // Unknown journal state may mean the OEM owner has already been stopped.
    // Never erase it or infer a fresh Prepared state from malformed bytes.
    for corrupt in [
        b"{}".as_slice(),
        b"{\"phase\":\"stopRequested\"}",
        b"not-json",
    ] {
        a.root.write(FILE, corrupt, 0o600).unwrap();
        assert!(prepare(a, &mut PreparationLog::default()).is_err());
        assert_eq!(a.root.read(FILE, 16384, 0o600).unwrap(), corrupt);
    }
    retain(a, &good).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn one_unavailable_owner_does_not_skip_the_other_bounded_preparations() {
        let mut visited = Vec::new();
        let error = prepare_owners(
            |owner| {
                visited.push(String::from(owner));
                if owner == "/usr/bin/gauge" {
                    Err("permit unavailable".into())
                } else {
                    Ok(())
                }
            },
            |_, _| {},
        )
        .unwrap_err();
        assert_eq!(
            visited,
            ["/usr/bin/gauge", "/usr/bin/point", "/usr/bin/light"]
        );
        assert_eq!(error, "/usr/bin/gauge: permit unavailable");
    }
    #[test]
    fn preparation_errors_are_change_only_and_recovery_is_observable() {
        let mut log = PreparationLog::default();
        assert!(log.update(None, "/usr/bin/gauge", "g1").is_none());
        let first = log
            .update(Some("corrupt journal"), "/usr/bin/gauge", "g1")
            .unwrap();
        assert_eq!(first, ("error", "corrupt journal"));
        assert!(log
            .update(Some("corrupt journal"), "/usr/bin/gauge", "g1")
            .is_none());
        assert!(log
            .update(Some("corrupt journal"), "/usr/bin/gauge", "g2")
            .is_some());
        assert!(log
            .update(Some("authority changed"), "/usr/bin/gauge", "g2")
            .is_some());
        let recovered = log.update(None, "/usr/bin/gauge", "g2").unwrap();
        assert_eq!(recovered, ("debug", "preparation recovered"));
        assert!(log.update(None, "/usr/bin/gauge", "g2").is_none());
    }
    #[test]
    fn preparation_preserves_each_owner_error_and_new_reason() {
        let mut log = PreparationLog::default();
        let mut messages = Vec::new();
        for reason in ["point first", "point changed", "point changed"] {
            let result = prepare_owners(
                |owner| {
                    Err(if owner == "/usr/bin/gauge" {
                        "gauge stable".into()
                    } else if owner == "/usr/bin/point" {
                        reason.into()
                    } else {
                        "light stable".into()
                    })
                },
                |owner, result| {
                    if let Some((_, reason)) = log.update(
                        result.as_ref().err().map(String::as_str),
                        owner,
                        "generation:7",
                    ) {
                        messages.push(reason.to_owned());
                    }
                },
            );
            assert_eq!(result.unwrap_err(), "/usr/bin/gauge: gauge stable");
        }
        assert_eq!(messages.len(), 4);
        let joined = messages.join("\n");
        for reason in [
            "gauge stable",
            "point first",
            "point changed",
            "light stable",
        ] {
            assert!(joined.contains(reason));
        }
        let first = alloc::format!("{}first", "x".repeat(200));
        let second = alloc::format!("{}second", "x".repeat(200));
        assert!(log
            .update(Some(&first), "/usr/bin/gauge", "generation:7")
            .is_some());
        assert!(log
            .update(Some(&second), "/usr/bin/gauge", "generation:7")
            .is_some());
    }
    #[test]
    fn owner_names_are_fixed_roles_and_never_shell_arguments() {
        assert_eq!(owner("/usr/bin/gauge").unwrap(), "gauge");
        assert_eq!(owner("/usr/bin/point").unwrap(), "point");
        assert_eq!(owner("/usr/bin/light").unwrap(), "light");
        for path in [
            "gauge",
            "/usr/bin/sysmgr",
            "/usr/bin/gauge;reboot",
            "/usr/bin/../bin/gauge",
        ] {
            assert!(owner(path).is_err());
        }
    }
}
