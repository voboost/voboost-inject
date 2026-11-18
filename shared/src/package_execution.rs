//! Root-only execution admission for the one product APK and Android user 0.
use std::time::Duration;

const PACKAGE: &str = "ru.voboost";
const RECOVERY: &str = "ru.voboost/.SchedulerRecoveryReceiver";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    Enabled,
    Disabled,
}

trait Commands {
    fn command(&mut self, arguments: &[&str]) -> Result<String, String>;
    fn verify_no_processes(&mut self) -> Result<(), String>;
    fn verify_no_job(&mut self) -> Result<(), String>;
}

/// The `cmd package list packages <name>` filter is a substring match and
/// the product's own i18n overlay packages (`ru.voboost.translation.*`)
/// match the same filter. Only the exact one full admission line is proof.
fn listed(text: &str) -> Result<bool, String> {
    let mut hits = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || (trimmed.starts_with("package:ru.voboost.translation.")
                && crate::owned_overlay::Variant::from_package(&trimmed["package:".len()..])
                    .is_ok())
        {
            continue;
        }
        if trimmed != "package:ru.voboost" {
            return Err("unexpected package admission query response".into());
        }
        hits.push(trimmed);
    }
    match hits.len() {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err("unexpected package admission query response".into()),
    }
}

fn require_single_user(text: &str) -> Result<(), String> {
    let mut lines = text.lines();
    if lines.next() != Some("Users:") {
        return Err("Android user inventory unavailable".into());
    }
    let users: Vec<_> = lines.filter(|line| !line.trim().is_empty()).collect();
    if users.len() != 1
        || !users[0].trim_start().starts_with("UserInfo{0:")
        || !users[0].contains('}')
    {
        return Err("beta1 APK execution requires the supported user-0-only profile".into());
    }
    Ok(())
}

fn observe(commands: &mut impl Commands) -> Result<Admission, String> {
    let disabled =
        listed(&commands.command(&["package", "list", "packages", "-d", "--user", "0", PACKAGE])?)?;
    let enabled =
        listed(&commands.command(&["package", "list", "packages", "-e", "--user", "0", PACKAGE])?)?;
    match (disabled, enabled) {
        (true, false) => Ok(Admission::Disabled),
        (false, true) => Ok(Admission::Enabled),
        _ => Err("APK admission is absent or inconsistent".into()),
    }
}

fn reconcile_with(commands: &mut impl Commands, desired: Admission) -> Result<(), String> {
    require_single_user(&commands.command(&["user", "list"])?)?;
    // The caller commits canonical startup mode before entering this adapter.
    // Repetition is deliberate: an interruption after any mutation converges.
    match desired {
        Admission::Disabled => {
            commands.command(&["package", "disable-user", "--user", "0", PACKAGE])?;
            if observe(commands)? != Admission::Disabled {
                return Err("APK disable unconfirmed".into());
            }
            commands.command(&["jobscheduler", "cancel", "-u", "0", PACKAGE])?;
            commands.command(&["activity", "force-stop", "--user", "0", PACKAGE])?;
            if observe(commands)? != Admission::Disabled {
                return Err("APK disabled state changed".into());
            }
            commands.verify_no_processes()?;
            commands.verify_no_job()?;
        }
        Admission::Enabled => {
            commands.command(&["package", "enable", "--user", "0", PACKAGE])?;
            if observe(commands)? != Admission::Enabled {
                return Err("APK enable unconfirmed".into());
            }
            let acknowledgement = commands.command(&[
                "activity",
                "broadcast",
                "--include-stopped-packages",
                "--user",
                "0",
                "-a",
                "ru.voboost.action.RECONCILE_SCHEDULER",
                "-n",
                RECOVERY,
            ])?;
            if acknowledgement.lines().last()
                != Some("Broadcast completed: result=1, data=\"scheduler-ready\"")
            {
                return Err("APK scheduler recovery unconfirmed".into());
            }
        }
    }
    Ok(())
}

/// Invoke only after installed signed identity and canonical mode validation.
/// No package, user, path or arbitrary argument is accepted from callers.
pub fn reconcile(desired: Admission) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("APK admission requires root authority".into());
    }
    reconcile_cancellable(desired, &std::sync::atomic::AtomicBool::new(false))
}

pub fn reconcile_cancellable(
    desired: Admission,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("APK admission requires root authority".into());
    }
    reconcile_with(&mut Device { cancelled }, desired)
}

struct Device<'a> {
    cancelled: &'a std::sync::atomic::AtomicBool,
}
impl Device<'_> {
    fn check_cancelled(&self) -> Result<(), String> {
        if self.cancelled.load(std::sync::atomic::Ordering::Acquire) {
            Err("APK execution admission cancelled".into())
        } else {
            Ok(())
        }
    }
}
impl Commands for Device<'_> {
    fn command(&mut self, arguments: &[&str]) -> Result<String, String> {
        self.check_cancelled()?;
        let output = crate::fixed_process::output(
            "/system/bin/cmd",
            arguments,
            Duration::from_secs(2),
            16384,
        )?;
        if !output.status.success() || !output.stderr.is_empty() {
            return Err("fixed APK execution command failed".into());
        }
        String::from_utf8(output.stdout).map_err(|_| "APK execution output is not UTF-8".into())
    }
    fn verify_no_processes(&mut self) -> Result<(), String> {
        let uid = installed_uid()?;
        // ActivityManager owns the process inventory, including cached and
        // non-dumpable app processes; /proc inode ownership is insufficient.
        let uid_text = uid.to_string();
        let state = self.command(&["activity", "get-uid-state", &uid_text])?;
        if state.trim() != "19 (NONEXISTENT)" {
            return Err("APK-owned process absence unconfirmed".into());
        }
        Ok(())
    }
    fn verify_no_job(&mut self) -> Result<(), String> {
        self.check_cancelled()?;
        let output = crate::fixed_process::output(
            "/system/bin/cmd",
            &["jobscheduler", "get-job-state", "-u", "0", PACKAGE, "22082"],
            Duration::from_secs(2),
            16384,
        )?;
        // Android 9 CMD_ERR_NO_JOB=-1001 reaches POSIX wait status as 23.
        // Missing package, permission failure and successful live-job lookup
        // are different outcomes and must never prove absence.
        verify_absent_job(
            output.status.code(),
            &output.stdout,
            &output.stderr,
            installed_uid()?,
        )?;
        Ok(())
    }
}

fn installed_uid() -> Result<u32, String> {
    use std::os::unix::fs::MetadataExt;
    let uid = std::fs::metadata("/data/user/0/ru.voboost")
        .map_err(|e| format!("APK uid: {e}"))?
        .uid();
    if !(10000..20000).contains(&uid) {
        return Err("APK user-0 UID invalid".into());
    }
    Ok(uid)
}
fn verify_absent_job(
    code: Option<i32>,
    stdout: &[u8],
    stderr: &[u8],
    uid: u32,
) -> Result<(), String> {
    if !(10000..20000).contains(&uid) {
        return Err("APK job UID invalid".into());
    }
    // JobSchedulerService emits the exact UID/job tuple on stdout as well
    // as ShellCommand's independent no-job diagnostic on stderr.
    let expected = format!("unknown(u0a{}/jid22082)\n", uid - 10000);
    if code != Some(23)
        || stdout != expected.as_bytes()
        || stderr != b"Could not find job 22082 in package ru.voboost / user 0\n"
    {
        return Err("APK periodic job absence unconfirmed".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        calls: Vec<Vec<String>>,
        state: Admission,
        fail: Option<usize>,
        live: bool,
        scheduler_ack: bool,
        job_absent: bool,
    }
    impl Commands for Fake {
        fn command(&mut self, args: &[&str]) -> Result<String, String> {
            self.calls
                .push(args.iter().map(|s| s.to_string()).collect());
            if self.fail == Some(self.calls.len()) {
                return Err("denied or timeout".into());
            }
            if args[0] == "user" {
                return Ok("Users:\n\tUserInfo{0:Owner:13} running\n".into());
            }
            if args[1] == "disable-user" {
                self.state = Admission::Disabled;
            }
            if args[1] == "enable" {
                self.state = Admission::Enabled;
            }
            if args[1] == "list" {
                let wanted = if args[3] == "-d" {
                    Admission::Disabled
                } else {
                    Admission::Enabled
                };
                return Ok(if wanted == self.state {
                    "package:ru.voboost\n".into()
                } else {
                    String::new()
                });
            }
            if args[1] == "broadcast" && self.scheduler_ack {
                return Ok("Broadcast completed: result=1, data=\"scheduler-ready\"".into());
            }
            if args[1] == "force-stop" {
                self.live = false;
            }
            Ok(String::new())
        }
        fn verify_no_job(&mut self) -> Result<(), String> {
            if self.job_absent {
                Ok(())
            } else {
                Err("job remains".into())
            }
        }
        fn verify_no_processes(&mut self) -> Result<(), String> {
            if self.live {
                Err("live".into())
            } else {
                Ok(())
            }
        }
    }
    fn fake() -> Fake {
        Fake {
            calls: vec![],
            state: Admission::Enabled,
            fail: None,
            live: true,
            scheduler_ack: true,
            job_absent: true,
        }
    }
    #[test]
    fn disable_closes_all_entrypoints_before_success() {
        let mut f = fake();
        reconcile_with(&mut f, Admission::Disabled).unwrap();
        assert_eq!(f.calls[1][1], "disable-user");
        assert_eq!(f.calls[4][0], "jobscheduler");
        assert_eq!(f.calls[5][1], "force-stop");
        assert!(!f.live);
    }
    #[test]
    fn every_interrupted_disable_retries_to_closed_state() {
        for step in 1..=8 {
            let mut f = fake();
            f.fail = Some(step);
            assert!(reconcile_with(&mut f, Admission::Disabled).is_err());
            f.fail = None;
            reconcile_with(&mut f, Admission::Disabled).unwrap();
            assert!(!f.live);
        }
    }
    #[test]
    fn every_interrupted_enable_retries_schedule_after_verified_enable() {
        for step in 1..=5 {
            let mut f = fake();
            f.state = Admission::Disabled;
            f.fail = Some(step);
            assert!(reconcile_with(&mut f, Admission::Enabled).is_err());
            f.fail = None;
            reconcile_with(&mut f, Admission::Enabled).unwrap();
            assert_eq!(f.calls.last().unwrap()[1], "broadcast");
        }
    }
    #[test]
    fn already_disabled_is_revalidated_and_quiesced() {
        let mut f = fake();
        f.state = Admission::Disabled;
        reconcile_with(&mut f, Admission::Disabled).unwrap();
        assert_eq!(f.calls.len(), 8);
    }
    #[test]
    fn aosp_absent_job_requires_exact_uid_tuple_code_and_diagnostic() {
        let stdout = b"unknown(u0a56/jid22082)\n";
        let stderr = b"Could not find job 22082 in package ru.voboost / user 0\n";
        assert!(verify_absent_job(Some(23), stdout, stderr, 10056).is_ok());
        assert!(verify_absent_job(Some(23), stdout, stderr, 10057).is_err());
        assert!(verify_absent_job(Some(0), stdout, stderr, 10056).is_err());
        assert!(verify_absent_job(Some(23), b"", stderr, 10056).is_err());
        assert!(verify_absent_job(Some(23), stdout, b"", 10056).is_err());
        assert!(verify_absent_job(
            Some(24),
            b"unknown(ru.voboost)\n",
            b"Package not found: ru.voboost / user 0\n",
            10056
        )
        .is_err());
    }
    #[test]
    fn cancelled_device_command_does_not_spawn_android_program() {
        let flag = std::sync::atomic::AtomicBool::new(true);
        let mut device = Device { cancelled: &flag };
        assert_eq!(
            device.command(&["user", "list"]).unwrap_err(),
            "APK execution admission cancelled"
        );
    }
    #[test]
    fn other_or_unknown_users_cannot_claim_package_closure() {
        for text in [
            "",
            "Users:\nUserInfo{10:Owner:13}",
            "Users:\nUserInfo{0:Owner:13}\nUserInfo{10:Other:13}",
        ] {
            assert!(require_single_user(text).is_err());
        }
        assert!(require_single_user("Users:\nUserInfo{0:车主:13} running\n").is_ok());
    }
    #[test]
    fn scheduler_failure_cannot_confirm_enable() {
        let mut f = fake();
        f.scheduler_ack = false;
        assert!(reconcile_with(&mut f, Admission::Enabled).is_err());
    }
    #[test]
    fn surviving_job_cannot_confirm_none() {
        let mut f = fake();
        f.job_absent = false;
        assert!(reconcile_with(&mut f, Admission::Disabled).is_err());
    }
    #[test]
    fn query_rejects_foreign_or_multiple_packages() {
        for text in [
            "package:foreign",
            "package:ru.voboost\npackage:other",
            "Success",
        ] {
            assert!(listed(text).is_err());
        }
    }
    #[test]
    fn substring_filter_siblings_do_not_break_admission_queries() {
        // free-09-chinese 6.0.3 emulator, beta1 candidate with i18n overlay
        // packages installed: `cmd package list packages --user 0 ru.voboost`
        // answers with all `ru.voboost.translation.*` siblings too.
        let siblings = "package:ru.voboost.translation.setting\n\
                        package:ru.voboost.translation.launcher\n\
                        package:ru.voboost\n";
        // The overlay sibling lines match the substring filter and arrive
        // in arbitrary order; only the exact admission line counts.
        assert!(listed(siblings).is_ok());
        assert!(listed("package:ru.voboost\npackage:ru.voboost").is_err());
        assert!(listed("package:ru.voboost.translation.x\n").is_err());
    }
}
