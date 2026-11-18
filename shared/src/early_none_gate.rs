//! Path-free next-boot gate. This is not ownership or native locale proof.
use serde::Deserialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Skip,
    DeferCurrentBoot,
    Cleanup,
}
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Startup {
    None,
    Hidden,
    Interface,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Session {
    schema_version: u32,
    boot_id: String,
    #[serde(rename = "startup")]
    _startup: Startup,
}
fn valid_boot(value: &str) -> bool {
    value.len() == 36
        && value != "00000000-0000-0000-0000-000000000000"
        && value.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_digit() || matches!(b, b'a'..=b'f')
            }
        })
}
pub fn decide(
    plan: &[u8],
    session: Option<&[u8]>,
    actual_kernel_boot: &str,
) -> Result<Decision, String> {
    if plan.len() > 1024 * 1024 || !valid_boot(actual_kernel_boot) {
        return Err("invalid early-None plan/boot bound".into());
    }
    let plan = voboost_contract::desired::Config::decode(plan).map_err(|e| e.to_string())?;
    if plan.agents.len() > 64 {
        return Err("invalid early-None plan schema".into());
    }
    if plan.startup != "none" {
        return Ok(Decision::Skip);
    }
    if let Some(bytes) = session {
        if bytes.len() > 512 {
            return Err("early-None session exceeds bound".into());
        }
        let session: Session = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if session.schema_version != 1 || !valid_boot(&session.boot_id) {
            return Err("invalid early-None session".into());
        }
        // A radio writes this existing fence before canonical publication. It must
        // never cause a filesystem side effect in the running boot, even if init
        // is manually asked to restart the cleanup service.
        if session.boot_id == actual_kernel_boot {
            return Ok(Decision::DeferCurrentBoot);
        }
    }
    Ok(Decision::Cleanup)
}
/// Late cleanup uses the already effective boot session: a current None
/// session permits work, while a current Hidden/Interface session defers a radio write.
pub fn decide_late(plan: &[u8], session: Option<&[u8]>, boot: &str) -> Result<Decision, String> {
    let decision = decide(plan, session, boot)?;
    if decision != Decision::DeferCurrentBoot {
        return Ok(decision);
    }
    let current: Session = serde_json::from_slice(session.ok_or("current session missing")?)
        .map_err(|error| error.to_string())?;
    Ok(if matches!(current._startup, Startup::None) {
        Decision::Cleanup
    } else {
        Decision::DeferCurrentBoot
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const A: &str = "11111111-1111-4111-8111-111111111111";
    const B: &str = "22222222-2222-4222-8222-222222222222";
    fn plan(startup: &str) -> Vec<u8> {
        format!(r#"{{"schemaVersion":2,"userRevision":0,"fieldRevisions":{{}},"startup":"{startup}","agents":{{}}}}"#).into_bytes()
    }
    fn session(startup: &str, boot: &str) -> Vec<u8> {
        format!(r#"{{"schemaVersion":1,"startup":"{startup}","bootId":"{boot}"}}"#).into_bytes()
    }
    #[test]
    fn radio_none_is_deferred_across_helper_or_daemon_recreation() {
        for startup in ["interface", "hidden", "none"] {
            let old = session(startup, A);
            for _ in 0..3 {
                assert_eq!(
                    decide(&plan("none"), Some(&old), A).unwrap(),
                    Decision::DeferCurrentBoot
                );
            }
        }
    }
    #[test]
    fn stale_session_admits_only_the_actual_next_boot() {
        let old = session("interface", A);
        assert_eq!(
            decide(&plan("none"), Some(&old), B).unwrap(),
            Decision::Cleanup
        );
    }
    #[test]
    fn missing_session_is_first_boot_intent_not_a_same_boot_radio() {
        assert_eq!(decide(&plan("none"), None, B).unwrap(), Decision::Cleanup);
    }
    #[test]
    fn non_none_never_removes_resource() {
        for mode in ["interface", "hidden"] {
            assert_eq!(decide(&plan(mode), None, A).unwrap(), Decision::Skip);
        }
    }
    #[test]
    fn malformed_session_cannot_authorize_deletion() {
        for bytes in [b"{}".as_slice(),b"null",br#"{"schemaVersion":1,"startup":"interface","bootId":"wrong"}"#,br#"{"schemaVersion":1,"startup":"interface","bootId":"11111111-1111-4111-8111-111111111111","extra":true}"#]{assert!(decide(&plan("none"),Some(bytes),B).is_err());}
    }
    #[test]
    fn malformed_plan_and_zero_boot_cannot_authorize_deletion() {
        for bytes in [
            b"{}".as_slice(),
            br#"{"schemaVersion":2,"startup":"none","agents":{}}"#,
            br#"{"schemaVersion":2,"userRevision":0,"fieldRevisions":{},"startup":"none","startup":"hidden","agents":{}}"#,
        ] {
            assert!(decide(bytes, None, A).is_err());
        }
        assert!(decide(&plan("none"), None, "00000000-0000-0000-0000-000000000000").is_err());
    }
    #[test]
    fn oversize_input_rejected_before_parsing() {
        assert!(decide(&vec![b' '; 1024 * 1024 + 1], None, A).is_err());
        assert!(decide(&plan("none"), Some(&vec![b' '; 513]), A).is_err());
    }
    #[test]
    fn late_cleanup_obeys_effective_session_and_next_boot_radio() {
        assert_eq!(
            decide_late(&plan("none"), Some(&session("none", A)), A).unwrap(),
            Decision::Cleanup
        );
        for prior in ["hidden", "interface"] {
            assert_eq!(
                decide_late(&plan("none"), Some(&session(prior, A)), A).unwrap(),
                Decision::DeferCurrentBoot
            );
            assert_eq!(
                decide_late(&plan("none"), Some(&session(prior, A)), B).unwrap(),
                Decision::Cleanup
            );
        }
        assert_eq!(
            decide_late(&plan("hidden"), Some(&session("none", A)), A).unwrap(),
            Decision::Skip
        );
        assert!(decide_late(
            &plan("none"),
            Some(br#"{"schemaVersion":1,"startup":"none"}"#),
            A
        )
        .is_err());
    }
}
