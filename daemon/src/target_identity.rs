//! Process-level fail-closed authority for signed catalog targets.

use std::{fs::File, io::Read};

use anyhow::{ensure, Context, Result};

use crate::reconcile::ProcMapsSnapshot;

const MAX_STAT: usize = 4096;
const MAX_STATUS: usize = 8192;
const MAX_CONTEXT: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedTarget {
    pub pid: i32,
    pub starttime: u64,
    pub uid: u32,
    pub selinux_context: String,
}

pub fn attest_catalog_target_for_agents(
    catalog: &crate::catalog::AgentCatalog,
    pid: i32,
    process: &str,
    snapshot_starttime: u64,
    agent_ids: &[impl AsRef<str>],
) -> Result<AttestedTarget> {
    validate_agent_authority(catalog, process, agent_ids)?;
    attest_declared_process(pid, process, snapshot_starttime)
}

/// Root CLI admission checks only readable process lifetime authority. The
/// resident daemon must perform full SELinux attestation before any effect.
pub(crate) fn attest_catalog_target_lifetime_for_agents(
    catalog: &crate::catalog::AgentCatalog,
    pid: i32,
    process: &str,
    snapshot_starttime: u64,
    agent_ids: &[impl AsRef<str>],
) -> Result<()> {
    validate_agent_authority(catalog, process, agent_ids)?;
    ensure!(pid > 0, "invalid target PID");
    let before = read_starttime(pid)?;
    ensure!(read_argv0(pid)? == process, "target argv0 mismatch");
    let uids = read_uids(pid)?;
    validate_uids(&uids)?;
    validate_observation_window(snapshot_starttime, before, read_starttime(pid)?)
}

fn validate_agent_authority(
    catalog: &crate::catalog::AgentCatalog,
    process: &str,
    agent_ids: &[impl AsRef<str>],
) -> Result<()> {
    ensure!(!agent_ids.is_empty(), "target authority: empty agent set");
    for id in agent_ids {
        let id = id.as_ref();
        let agent = catalog
            .find(id)
            .with_context(|| format!("unknown selected agent {id}"))?;
        agent
            .targets
            .iter()
            .find(|target| target.process == process)
            .context("selected agent does not declare target process")?;
    }
    Ok(())
}

pub fn read_bound_maps(pid: i32) -> Result<(ProcMapsSnapshot, u64)> {
    let before = read_starttime(pid)?;
    let maps = ProcMapsSnapshot::read(pid).context("read target maps snapshot")?;
    let after = read_starttime(pid)?;
    ensure!(before == after, "target PID changed across maps snapshot");
    Ok((maps, before))
}

fn attest_declared_process(pid: i32, process: &str, snapshot: u64) -> Result<AttestedTarget> {
    ensure!(pid > 0, "invalid target PID");
    let before = read_starttime(pid)?;
    ensure!(read_argv0(pid)? == process, "target argv0 mismatch");
    let uids = read_uids(pid)?;
    let selinux_context = read_selinux_context(pid)?;
    validate_observed_security(&uids, &selinux_context)?;
    let after = read_starttime(pid)?;
    validate_observation_window(snapshot, before, after)?;
    Ok(AttestedTarget {
        pid,
        starttime: before,
        uid: uids[0],
        selinux_context,
    })
}

fn validate_uids(uids: &[u32; 4]) -> Result<()> {
    ensure!(
        uids.iter().all(|uid| *uid == uids[0]),
        "target UID fields are not one stable identity"
    );
    Ok(())
}

fn validate_observed_security(uids: &[u32; 4], selinux_context: &str) -> Result<()> {
    validate_uids(uids)?;
    ensure!(
        !selinux_context.is_empty()
            && selinux_context.len() <= MAX_CONTEXT
            && !selinux_context
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte == 0),
        "target SELinux context is not one bounded identity"
    );
    Ok(())
}

fn validate_observation_window(snapshot: u64, before: u64, after: u64) -> Result<()> {
    ensure!(snapshot > 0 && snapshot == before, "stale maps snapshot");
    ensure!(before == after, "target PID changed during observation");
    Ok(())
}

#[cfg(test)]
fn with_final_process_identity<T>(
    expected_process: &str,
    expected_starttime: u64,
    observed_process: &str,
    observed_starttime: u64,
    operation: impl FnOnce() -> T,
) -> Result<T> {
    ensure!(
        observed_process == expected_process,
        "target argv0 changed before native operation"
    );
    ensure!(
        observed_starttime == expected_starttime,
        "target PID changed before native operation"
    );
    Ok(operation())
}

fn read_argv0(pid: i32) -> Result<String> {
    let file = File::open(format!("/proc/{pid}/cmdline")).context("open target cmdline")?;
    crate::process_watcher::read_bounded_argv0(file)
        .context("read target argv0")?
        .context("target argv0 is not exact bounded UTF-8")
}

fn read_uids(pid: i32) -> Result<[u32; 4]> {
    let bytes = read_bounded(format!("/proc/{pid}/status"), MAX_STATUS)?;
    let text = std::str::from_utf8(&bytes).context("target status is not UTF-8")?;
    let mut result = None;
    for line in text.lines() {
        if let Some(values) = line.strip_prefix("Uid:") {
            ensure!(result.is_none(), "duplicate target Uid field");
            let parsed = values
                .split_ascii_whitespace()
                .map(str::parse::<u32>)
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("invalid target Uid field")?;
            ensure!(parsed.len() == 4, "ambiguous target Uid field");
            result = Some([parsed[0], parsed[1], parsed[2], parsed[3]]);
        }
    }
    result.context("missing target Uid field")
}

fn read_selinux_context(pid: i32) -> Result<String> {
    parse_selinux_context(read_bounded(
        format!("/proc/{pid}/attr/current"),
        MAX_CONTEXT,
    )?)
}

fn parse_selinux_context(mut bytes: Vec<u8>) -> Result<String> {
    if matches!(bytes.last(), Some(b'\n' | 0)) {
        bytes.pop();
    }
    ensure!(!bytes.is_empty(), "empty target SELinux context");
    ensure!(
        !bytes
            .iter()
            .any(|byte| byte.is_ascii_whitespace() || *byte == 0),
        "ambiguous SELinux context"
    );
    String::from_utf8(bytes).context("target SELinux context is not UTF-8")
}

pub(crate) fn read_starttime(pid: i32) -> Result<u64> {
    parse_starttime(&read_bounded(format!("/proc/{pid}/stat"), MAX_STAT)?)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProcStat {
    pub starttime: u64,
    pub kernel_thread: bool,
}

pub(crate) fn read_stat(pid: i32) -> Result<ProcStat> {
    parse_stat(&read_bounded(format!("/proc/{pid}/stat"), MAX_STAT)?)
}

fn parse_stat(bytes: &[u8]) -> Result<ProcStat> {
    let starttime = parse_starttime(bytes)?;
    let text = std::str::from_utf8(bytes).context("target stat is not UTF-8")?;
    let close = text.rfind(')').context("target stat terminator missing")?;
    // Linux proc field 9 is task flags; field 22 is starttime. Neither
    // depends on the mutable/truncated comm string or a process UID.
    let flags = text[close + 1..]
        .split_ascii_whitespace()
        .nth(6)
        .context("missing stat flags")?
        .parse::<u64>()
        .context("invalid stat flags")?;
    Ok(ProcStat {
        starttime,
        kernel_thread: flags & 0x0020_0000 != 0, // Linux PF_KTHREAD.
    })
}

fn parse_starttime(bytes: &[u8]) -> Result<u64> {
    let text = std::str::from_utf8(bytes).context("target stat is not UTF-8")?;
    let open = text.find('(').context("target stat opener missing")?;
    let close = text.rfind(')').context("target stat terminator missing")?;
    ensure!(open < close, "target stat comm malformed");
    ensure!(
        text[..open].trim().parse::<i32>().is_ok_and(|pid| pid > 0),
        "invalid stat PID"
    );
    let fields = text[close + 1..]
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    ensure!(fields.len() > 19, "target stat truncated");
    let value = fields[19]
        .parse::<u64>()
        .context("invalid stat starttime")?;
    ensure!(value > 0, "zero stat starttime");
    Ok(value)
}

fn read_bounded(path: String, max: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .context("open proc authority file")?
        .take((max + 1) as u64)
        .read_to_end(&mut bytes)
        .context("read proc authority file")?;
    ensure!(bytes.len() <= max, "proc authority file exceeds bound");
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_kernel_flag_is_independent_of_comm_and_starttime_stays_exact() {
        let mut fields = vec!["0"; 20];
        fields[0] = "S";
        fields[6] = "2097152";
        fields[19] = "123";
        let stat = format!("42 (custom ) name) {}", fields.join(" "));
        let parsed = parse_stat(stat.as_bytes()).unwrap();
        assert!(parsed.kernel_thread);
        assert_eq!(parsed.starttime, 123);
        fields[6] = "4194304";
        assert!(
            !parse_stat(format!("42 (kernel-looking) {}", fields.join(" ")).as_bytes())
                .unwrap()
                .kernel_thread
        );
        fields[6] = "invalid";
        assert!(parse_stat(format!("42 (name) {}", fields.join(" ")).as_bytes()).is_err());
        assert!(parse_stat(b"42 (short) S 0").is_err());
    }

    #[test]
    fn parses_starttime_and_rejects_malformed_input() {
        let mut fields = vec!["S"; 20];
        fields[19] = "987654";
        assert_eq!(
            parse_starttime(format!("42 (a process) {}", fields.join(" ")).as_bytes()).unwrap(),
            987654
        );
        assert!(parse_starttime(b"42 (name) S 1 2").is_err());
        assert!(parse_starttime(b"42 name S 1 2").is_err());
        assert!(parse_starttime(b"not-a-pid (name) S 1 2").is_err());
        assert!(parse_starttime(b"0 (name) S 1 2").is_err());
    }

    #[test]
    fn signed_agents_authorize_only_their_declared_process() {
        let generation = crate::generation::test_support::verified_variant(1);
        let id = generation.catalog.agents[0].id.as_str();
        let process = generation.catalog.agents[0].targets[0].process.as_str();
        assert!(validate_agent_authority(&generation.catalog, process, &[id]).is_ok());
        assert!(validate_agent_authority(&generation.catalog, "com.example.spoof", &[id]).is_err());
        assert!(validate_agent_authority(&generation.catalog, process, &["missing"]).is_err());
        assert!(
            validate_agent_authority(&generation.catalog, process, &Vec::<String>::new()).is_err()
        );
    }

    #[test]
    fn maps_snapshot_and_observation_must_keep_one_pid_starttime() {
        assert!(validate_observation_window(41, 41, 41).is_ok());
        assert!(validate_observation_window(41, 42, 42).is_err());
        assert!(validate_observation_window(41, 41, 42).is_err());
        assert!(validate_observation_window(0, 0, 0).is_err());
    }

    #[test]
    fn uid_and_selinux_are_observed_identity_not_firmware_allowlists() {
        assert_eq!(
            parse_selinux_context(b"u:r:platform_app:s0\n".to_vec()).unwrap(),
            "u:r:platform_app:s0"
        );
        assert_eq!(
            parse_selinux_context(b"u:r:system_app:s0\0".to_vec()).unwrap(),
            "u:r:system_app:s0"
        );
        assert!(parse_selinux_context(b"u:r:system_app:s0\n\0".to_vec()).is_err());
        assert!(parse_selinux_context(Vec::new()).is_err());
        for uid in [1000_u32, 10_123, 99_999] {
            assert!(validate_observed_security(&[uid; 4], "u:r:any_app:s0").is_ok());
        }
        assert!(
            validate_observed_security(&[1000_u32, 1000, 1001, 1000], "u:r:system_app:s0").is_err()
        );
    }

    #[test]
    fn wrong_process_and_reused_pid_fail_before_native_operation() {
        let mut calls = 0;
        assert!(with_final_process_identity(
            "com.qinggan.audiopolicy.service:fft",
            41,
            "com.qinggan.audiopolicy.service:fft",
            41,
            || calls += 1,
        )
        .is_ok());
        assert_eq!(calls, 1);
        for (process, starttime) in [
            ("com.qinggan.audiopolicy.service:fft", 42),
            ("com.qinggan.audiopolicy.service", 41),
        ] {
            assert!(with_final_process_identity(
                "com.qinggan.audiopolicy.service:fft",
                41,
                process,
                starttime,
                || calls += 1,
            )
            .is_err());
        }
        assert_eq!(calls, 1);
    }
}
