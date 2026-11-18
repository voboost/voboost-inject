use super::*;
use serde_json::json;

const SESSION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOOT: &str = "11111111-1111-4111-8111-111111111111";

fn commands() -> Vec<Value> {
    let input = json!({"bootId": BOOT, "endpointEpoch": 1, "requestId": 1});
    let record = json!({"level": "info", "component": "test", "message": "event"});
    let captured = json!({"schemaVersion": 1, "bootId": BOOT, "captureNs": 1,
        "pid": 20, "requestId": 1, "choice": "off", "pending": true});
    let mut finished = captured.clone();
    finished["pending"] = false.into();
    let identity = json!({"ownerSession": SESSION, "bootId": BOOT, "source": "agent",
        "commandId": 1, "revision": 1, "state": "IVI_SOC_MODESET", "value": 5});
    let field = json!({"kind": "enabled", "agent": "agent"});
    let batch = json!({"schemaVersion": 1, "batchId": SESSION, "records": [record]}).to_string();
    let challenge = json!({"schemaVersion": 1, "nativeBoot": "a".repeat(64),
        "nativeEpoch": "b".repeat(64), "nonce": "c".repeat(64), "pairId": "d".repeat(64),
        "generationId": "e".repeat(64), "desiredRevision": 1,
        "desiredSha256": "f".repeat(64), "desiredDisabled": true});
    json!([
        {"operation": "electric-click", "input": input, "poll": false, "cancel": false},
        {"operation": "read-cluster-pw-proof", "challenge": challenge},
        {"operation": "import-cluster-pairing", "material": {
            "provision": [1], "seed": vec![1; 32], "credentials": [2]}},
        {"operation": "write-cluster-artifact", "artifact": "request", "bytes": [1]},
        {"operation": "read-cluster-mailbox"},
        {"operation": "replace-cluster-mailbox", "expected": null, "next": "{}"},
        {"operation": "read-cluster-epoch"},
        {"operation": "set-startup", "startup": "hidden"},
        {"operation": "save-startup-recovery", "input": input},
        {"operation": "read-log-session"},
        {"operation": "read-native-can", "cursor": 0},
        {"operation": "begin-native-state-outage", "token": "a".repeat(64)},
        {"operation": "snapshot-native-state-outage", "token": "a".repeat(64)},
        {"operation": "release-native-state-outage", "token": "a".repeat(64)},
        {"operation": "close-native-state-outage", "token": "a".repeat(64)},
        {"operation": "publish-injection-status", "bytes": "{}"},
        {"operation": "append-app-batch", "bytes": batch},
        {"operation": "append-log", "source": {"kind": "daemon"}, "record": record},
        {"operation": "read-state", "source": "agent", "key": "state"},
        {"operation": "write-state", "source": "agent", "key": "state", "value": false},
        {"operation": "read-controller-state", "source": "agent", "key": "state"},
        {"operation": "write-controller-state", "source": "agent", "key": "state", "value": 1},
        {"operation": "clear-controller-state", "source": "media-apps",
            "key": "media-selected-package", "expected": "com.example.player"},
        {"operation": "read-journal", "source": "agent", "key": "intent"},
        {"operation": "register-native-transport", "source": "agent", "pid": 20,
            "endpointEpoch": 1, "available": true},
        {"operation": "poll-native-command", "source": "agent", "pid": 20, "endpointEpoch": 1},
        {"operation": "report-native-command", "identity": identity, "pid": 20,
            "endpointEpoch": 1, "status": "accepted"},
        {"operation": "prepare-intent", "source": "agent", "key": "intent", "record": captured},
        {"operation": "finish-intent", "source": "agent", "key": "intent", "record": finished},
        {"operation": "recover-intent", "source": "agent", "key": "intent"},
        {"operation": "replace-journal", "source": "agent", "key": "intent",
            "expected": null, "next": "{}"},
        {"operation": "read-config"},
        {"operation": "save-desired", "field": field, "value": false, "input": input},
        {"operation": "save-launcher-desired", "changes": [[
            {"kind": "launcher-item-visibility", "identity": "app.test"}, false]], "input": input},
        {"operation": "confirm-agent-withdrawn", "source": "agent"},
        {"operation": "reconcile-desired", "defaults": "{}"},
        {"operation": "read-desired", "field": field},
        {"operation": "read-startup-session"},
        {"operation": "replace-startup-session", "expected": null, "next": "session"},
        {"operation": "replace-config", "expected": null, "next": "{}"}
    ])
    .as_array()
    .unwrap()
    .clone()
}

fn request(command: Value) -> Request {
    serde_json::from_value(json!({"schemaVersion": SCHEMA, "session": SESSION,
        "requestId": 1, "command": command}))
    .unwrap()
}

fn equivalent(request: &Request, expected: Result<(), &'static str>) {
    assert_eq!(request.validate(), expected, "{request:?}");
    let bytes = serde_json::to_vec(request).unwrap();
    assert!(bytes.len() <= MAX_FRAME_BYTES);
    let decoded = Request::decode(&bytes);
    assert_eq!(
        decoded.as_ref().map(|_| ()).map_err(|error| *error),
        expected
    );
    if let Ok(decoded) = decoded {
        assert_eq!(
            serde_json::to_value(decoded).unwrap(),
            serde_json::to_value(request).unwrap()
        );
    }
}

#[test]
fn typed_validation_matches_wire_decode_for_every_command_and_request_identity() {
    let commands = commands();
    assert_eq!(commands.len(), 40);
    for command in commands {
        let mut request = request(command);
        equivalent(&request, Ok(()));
        request.schema_version = SCHEMA + 1;
        equivalent(&request, Err("invalid runtime request identity"));
        request.schema_version = SCHEMA;
        request.request_id = 0;
        equivalent(&request, Err("invalid runtime request identity"));
        request.request_id = 1;
        for session in ["", "a", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "../owner"] {
            request.session = session.into();
            equivalent(&request, Err("invalid runtime request identity"));
        }
    }
}

fn reject(command: Value) {
    equivalent(&request(command), Err("invalid runtime command"));
}

#[test]
fn typed_validation_keeps_shared_identity_and_payload_checks() {
    for command in commands() {
        for (field, bad) in [
            ("source", json!("../agent")),
            ("key", json!("../key")),
            ("pid", json!(1)),
            ("endpointEpoch", json!(0)),
            ("token", json!("G".repeat(64))),
        ] {
            if command
                .get(field)
                .is_some_and(|value| value.is_string() || value.is_number())
            {
                let mut changed = command.clone();
                changed[field] = bad;
                reject(changed);
            }
        }
        if command.get("input").is_some() {
            for (field, bad) in [
                ("bootId", json!("bad")),
                ("requestId", json!(0)),
                ("endpointEpoch", json!(MAX_NATIVE_ID + 1)),
            ] {
                let mut changed = command.clone();
                changed["input"][field] = bad;
                reject(changed);
            }
        }
        if command.get("field").is_some() {
            let mut changed = command.clone();
            changed["field"]["agent"] = "../agent".into();
            reject(changed);
        }
        let operation = command["operation"].as_str().unwrap();
        match operation {
            "write-state" | "write-controller-state" => {
                for bad in [
                    Value::Null,
                    json!({"nested": true}),
                    json!([]),
                    json!("x".repeat(MAX_STATE_BYTES)),
                ] {
                    let mut changed = command.clone();
                    changed["value"] = bad;
                    reject(changed);
                }
            }
            "clear-controller-state" => {
                for (field, bad) in [
                    ("source", json!("other-agent")),
                    ("key", json!("other-key")),
                    ("expected", json!("")),
                    ("expected", json!("x".repeat(256))),
                    ("expected", json!("bad|token")),
                    ("expected", json!("com.example player")),
                    ("expected", json!("com.example\nplayer")),
                    ("expected", json!("com.example.плеер")),
                ] {
                    let mut changed = command.clone();
                    changed[field] = bad;
                    reject(changed);
                }
                let mut changed = command.clone();
                changed["expected"] = "x".repeat(255).into();
                equivalent(&request(changed), Ok(()));
            }
            "prepare-intent" | "finish-intent" => {
                for (field, bad) in [
                    ("schemaVersion", json!(2)),
                    ("bootId", json!("bad")),
                    ("captureNs", json!(0)),
                    ("pid", json!(0)),
                    ("requestId", json!(0)),
                    ("choice", json!("unknown")),
                    ("pending", json!(operation != "prepare-intent")),
                ] {
                    let mut changed = command.clone();
                    changed["record"][field] = bad;
                    reject(changed);
                }
            }
            "report-native-command" => {
                for (field, bad) in [
                    ("ownerSession", json!("bad")),
                    ("bootId", json!("bad")),
                    ("source", json!("../agent")),
                    ("commandId", json!(0)),
                    ("revision", json!(MAX_NATIVE_ID + 1)),
                    ("state", json!("../state")),
                ] {
                    let mut changed = command.clone();
                    changed["identity"][field] = bad;
                    reject(changed);
                }
            }
            "read-cluster-pw-proof" => {
                for field in [
                    "nativeBoot",
                    "nativeEpoch",
                    "nonce",
                    "pairId",
                    "generationId",
                    "desiredSha256",
                ] {
                    let mut changed = command.clone();
                    changed["challenge"][field] = "bad".into();
                    reject(changed);
                }
                let mut changed = command.clone();
                changed["challenge"]["desiredRevision"] = 0.into();
                reject(changed);
            }
            "import-cluster-pairing" => {
                for (field, bad) in [
                    ("provision", json!([])),
                    ("provision", json!(vec![1; 16385])),
                    ("seed", json!(vec![1; 31])),
                    ("credentials", json!([])),
                    ("credentials", json!(vec![1; 65537])),
                ] {
                    let mut changed = command.clone();
                    changed["material"][field] = bad;
                    reject(changed);
                }
            }
            "write-cluster-artifact" => {
                for bytes in [vec![], vec![1; 65537]] {
                    let mut changed = command.clone();
                    changed["bytes"] = json!(bytes);
                    reject(changed);
                }
            }
            "append-log" => {
                for (field, bad) in [
                    ("source", json!({"kind": "qnx", "id": "cluster-session"})),
                    ("source", json!({"kind": "unknown"})),
                    (
                        "record",
                        json!({"level": "info", "component": "", "message": "event"}),
                    ),
                ] {
                    let mut changed = command.clone();
                    changed[field] = bad;
                    reject(changed);
                }
            }
            "append-app-batch" => {
                for bytes in [
                    "",
                    "{}",
                    "{",
                    r#"{"schemaVersion":1,"batchId":"a","records":[]}"#,
                ] {
                    let mut changed = command.clone();
                    changed["bytes"] = bytes.into();
                    reject(changed);
                }
            }
            "save-desired" => {
                let mut changed = command.clone();
                changed["value"] = "wrong type".into();
                reject(changed);
            }
            "save-launcher-desired" => {
                for changes in [
                    json!([]),
                    json!(vec![command["changes"][0].clone(); 513]),
                    json!([[{"kind": "enabled", "agent": "agent"}, true]]),
                    json!([[{"kind": "launcher-item-visibility", "identity": "app.test"}, "wrong type"]]),
                ] {
                    let mut changed = command.clone();
                    changed["changes"] = changes;
                    reject(changed);
                }
            }
            _ => {}
        }
    }
}

#[test]
fn typed_validation_matches_wire_at_string_bounds() {
    for (operation, field, bound, optional, empty_valid) in [
        (
            "replace-cluster-mailbox",
            "next",
            MAX_CLUSTER_MAILBOX_BYTES,
            false,
            false,
        ),
        (
            "replace-cluster-mailbox",
            "expected",
            MAX_CLUSTER_MAILBOX_BYTES,
            true,
            true,
        ),
        (
            "publish-injection-status",
            "bytes",
            MAX_STATUS_BYTES,
            false,
            false,
        ),
        ("replace-journal", "next", MAX_STATE_BYTES, false, false),
        ("replace-journal", "expected", MAX_STATE_BYTES, true, true),
        (
            "reconcile-desired",
            "defaults",
            MAX_CONFIG_BYTES,
            false,
            false,
        ),
        ("replace-startup-session", "expected", 512, true, true),
        ("replace-startup-session", "next", 512, true, false),
        ("replace-config", "expected", MAX_CONFIG_BYTES, true, true),
        ("replace-config", "next", MAX_CONFIG_BYTES, false, false),
    ] {
        let command = commands()
            .into_iter()
            .find(|value| value["operation"] == operation)
            .unwrap();
        for (length, valid) in [(0, empty_valid), (bound, true), (bound + 1, false)] {
            let mut changed = command.clone();
            changed[field] = "x".repeat(length).into();
            equivalent(
                &request(changed),
                if valid {
                    Ok(())
                } else {
                    Err("invalid runtime command")
                },
            );
        }
        if optional {
            let mut changed = command;
            changed[field] = Value::Null;
            equivalent(&request(changed), Ok(()));
        }
    }
    reject(json!({"operation": "set-startup", "startup": "unknown"}));
}

#[test]
fn wire_decode_keeps_structural_rejection_for_every_command() {
    for command in commands() {
        let mut value = serde_json::to_value(request(command)).unwrap();
        value["command"]["path"] = "/elsewhere".into();
        assert_eq!(
            Request::decode(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
            "invalid runtime request"
        );
        value["command"].as_object_mut().unwrap().remove("path");
        let bytes = serde_json::to_string(&value).unwrap();
        let duplicate = bytes.replacen(
            "\"operation\":",
            "\"operation\":\"read-config\",\"operation\":",
            1,
        );
        assert!(Request::decode(duplicate.as_bytes()).is_err());
        let command = value["command"].as_object().unwrap();
        for field in command.keys().filter(|field| field.as_str() != "operation") {
            let mut changed = value.clone();
            changed["command"][field] = json!({"wrong": "type"});
            assert!(
                Request::decode(&serde_json::to_vec(&changed).unwrap()).is_err(),
                "{} {field}",
                command["operation"]
            );
        }
    }
    for bytes in [&b""[..], &b"{"[..], &vec![b' '; MAX_FRAME_BYTES + 1][..]] {
        assert!(Request::decode(bytes).is_err());
    }
}
