//! Authenticated current-session CLI requests. Mutations are never replayed.
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};
use voboost_contract::runtime_owner::{Command, Outcome};

#[derive(serde::Deserialize)]
#[serde(
    tag = "status",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum ClientOutcome {
    Ready {},
    NativeCan {
        value: serde_json::Value,
    },
    StartupSaved {
        startup: String,
        installed_version: String,
    },
    LogSession {
        boot_id: String,
        writer_id: String,
        sequence: u64,
    },
    Config {
        bytes: Option<String>,
    },
    StartupSession {
        bytes: Option<String>,
    },
    Unavailable {},
    Conflict {},
}

impl From<ClientOutcome> for voboost_contract::runtime_owner::Outcome {
    fn from(value: ClientOutcome) -> Self {
        match value {
            ClientOutcome::Ready {} => Self::Ready {},
            ClientOutcome::NativeCan { value } => Self::NativeCan { value },
            ClientOutcome::StartupSaved {
                startup,
                installed_version,
            } => Self::StartupSaved {
                startup,
                installed_version,
            },
            ClientOutcome::LogSession {
                boot_id,
                writer_id,
                sequence,
            } => Self::LogSession {
                boot_id,
                writer_id,
                sequence,
            },
            ClientOutcome::Config { bytes } => Self::Config { bytes },
            ClientOutcome::StartupSession { bytes } => Self::StartupSession { bytes },
            ClientOutcome::Unavailable {} => Self::Unavailable {},
            ClientOutcome::Conflict {} => Self::Conflict {},
        }
    }
}

pub(super) fn call(root: &Path, command: Command) -> io::Result<Outcome> {
    let deadline = Instant::now() + Duration::from_millis(500);
    let mut stream = crate::io::connect(&root.join("run/owner.sock"), deadline)?;
    crate::peer::verify(
        &stream,
        crate::native_executable_signature::NativeExecutableRole::Daemon,
    )?;
    crate::io::request::<ClientOutcome>(&mut stream, command, deadline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use voboost_contract::runtime_owner::{Reply, SCHEMA};
    #[test]
    fn client_reply_accepts_its_catalog_and_rejects_injection_only_outcomes() {
        for outcome in [
            serde_json::json!({"status":"ready"}),
            serde_json::json!({"status":"native-can","value":{}}),
            serde_json::json!({"status":"startup-saved","startup":"none","installedVersion":"1.0.0-beta1"}),
            serde_json::json!({"status":"log-session","bootId":"11111111-1111-4111-8111-111111111111","writerId":"a".repeat(32),"sequence":0}),
            serde_json::json!({"status":"config","bytes":null}),
            serde_json::json!({"status":"startup-session","bytes":null}),
            serde_json::json!({"status":"unavailable"}),
            serde_json::json!({"status":"conflict"}),
        ] {
            let id = u64::from(outcome["status"] != "ready");
            let frame = serde_json::json!({"schemaVersion":SCHEMA,"session":"a".repeat(32),"requestId":id,"outcome":outcome});
            let bytes = serde_json::to_vec(&frame).unwrap();
            assert_eq!(
                serde_json::to_value(
                    voboost_contract::runtime_owner::Reply::<ClientOutcome>::decode_as(&bytes, id)
                        .unwrap()
                )
                .unwrap(),
                frame
            );
            for (key, bad) in [
                ("schemaVersion", serde_json::json!(99)),
                ("session", serde_json::json!("bad")),
                ("requestId", serde_json::json!(id + 1)),
            ] {
                let mut bad_frame = frame.clone();
                bad_frame[key] = bad;
                let bytes = serde_json::to_vec(&bad_frame).unwrap();
                assert!(
                    voboost_contract::runtime_owner::Reply::<ClientOutcome>::decode_as(&bytes, id)
                        .is_err()
                );
                assert!(Reply::decode(&bytes, id).is_err());
            }
        }
        let injected = serde_json::json!({"schemaVersion":SCHEMA,"session":"a".repeat(32),"requestId":1,"outcome":{"status":"state","value":true}});
        let bytes = serde_json::to_vec(&injected).unwrap();
        assert!(Reply::decode(&bytes, 1).is_ok());
        assert!(
            voboost_contract::runtime_owner::Reply::<ClientOutcome>::decode_as(&bytes, 1).is_err()
        );
        let invalid_log = serde_json::json!({"schemaVersion":SCHEMA,"session":"a".repeat(32),"requestId":1,"outcome":{"status":"log-session","bootId":"invalid","writerId":"a".repeat(32),"sequence":1}});
        assert!(
            voboost_contract::runtime_owner::Reply::<ClientOutcome>::decode_as(
                &serde_json::to_vec(&invalid_log).unwrap(),
                1
            )
            .is_err()
        );
        for bytes in [
            b"{}".as_slice(),
            br#"{"schemaVersion":1,"schemaVersion":1}"#.as_slice(),
        ] {
            assert!(
                voboost_contract::runtime_owner::Reply::<ClientOutcome>::decode_as(bytes, 1)
                    .is_err()
            );
        }
    }
}
