use super::*;
use serde_json::json;
use voboost_contract::runtime_owner::{Command, Outcome};

fn context() -> EndpointContext {
    EndpointContext {
        process: "com.qinggan.app.setting".into(),
        pid: 42,
        target_starttime: Some(100),
        endpoint_epoch: 7,
        resident_generation_id: "g".into(),
        active_generation_id: "g".into(),
        resident_catalog_sha256: "catalog".into(),
        active_catalog_sha256: "catalog".into(),
        resident_agents: ["launcher".into()].into_iter().collect(),
        ..EndpointContext::default()
    }
}

#[test]
fn density_admission_is_semantic_and_saved_does_not_require_application() {
    let mut frames = Vec::new();
    let result = route_with(
        "12|launcher|launcher-density|density:240",
        &context(),
        Some(9),
        "boot",
        |command| {
            let Command::SaveLauncherDesired { changes, input } = command else {
                panic!()
            };
            assert_eq!(
                changes,
                vec![(
                    voboost_contract::desired::Field::Option {
                        agent: "launcher".into(),
                        key: "densityDpi".into()
                    },
                    json!(240)
                )]
            );
            assert_eq!(input.request_id, 12);
            assert_eq!(input.endpoint_epoch, 7);
            Ok(Outcome::DesiredSaved {
                revision: 33,
                config: json!({"schemaVersion":2,"startup":"none","agents":{"launcher":{"enabled":false,"options":{"densityDpi":240}}},"userRevision":0,"fieldRevisions":{}}).to_string(),
                disposition: voboost_contract::desired::Disposition::Saved,
            })
        },
        |_, frame| {
            frames.push(String::from_utf8(frame.to_vec()).unwrap());
            true
        },
    );
    assert_eq!(result, Some(Some(1)));
    assert_eq!(frames.len(), 1);
    assert!(frames[0].starts_with("U|12|"));
    assert!(frames[0].contains("\"userRevision\":33"));
}

#[test]
fn recognized_spoof_invalid_value_and_missing_inventory_never_fall_back() {
    for event in [
        "1|settings|launcher-density|density:240",
        "1|launcher|launcher-density|density:241",
        "1|launcher|launcher-item-visibility|item:{}",
        "0|launcher|launcher-density|density:240",
    ] {
        assert_eq!(
            route_with(
                event,
                &context(),
                Some(9),
                "boot",
                |_| panic!("invalid action reached owner"),
                |_, _| panic!()
            ),
            Some(None)
        );
    }
    assert_eq!(
        route_with(
            "1|launcher|other|density:240",
            &context(),
            Some(9),
            "boot",
            |_| panic!(),
            |_, _| panic!()
        ),
        None
    );
}

#[test]
fn owner_failure_never_claims_saved() {
    assert_eq!(
        route_with(
            "12|launcher|launcher-density|density:240",
            &context(),
            Some(9),
            "boot",
            |_| Err(std::io::ErrorKind::BrokenPipe.into()),
            |_, _| panic!("false saved")
        ),
        Some(None)
    );
}

#[test]
fn desired_leaf_and_rendered_section_survive_inventory_and_generation_change() {
    let mut ctx = context();
    ctx.active_generation_id = "install-in-progress".into();
    let item = "8|launcher|launcher-item-visibility|item:{\"snapshot\":\"retained\",\"revision\":1,\"identity\":\"i.absent\",\"visible\":false}";
    let section = "9|launcher|launcher-section-visibility|section:{\"snapshot\":\"retained\",\"revision\":1,\"kind\":\"installed\",\"visible\":false,\"identities\":[\"i.absent\",\"i.another\"]}";
    for (event, count) in [(item, 1), (section, 2)] {
        let mut reached = false;
        assert_eq!(
            route_with(
                event,
                &ctx,
                Some(9),
                "boot",
                |command| {
                    let Command::SaveLauncherDesired { changes, .. } = command else {
                        panic!()
                    };
                    assert_eq!(changes.len(), count);
                    reached = true;
                    Err(std::io::ErrorKind::BrokenPipe.into())
                },
                |_, _| panic!()
            ),
            Some(None)
        );
        assert!(reached);
    }
    for identities in ["[]", "[\"i.a\",\"i.a\"]", "[\"../bad\"]"] {
        let event = format!("10|launcher|launcher-section-visibility|section:{{\"snapshot\":\"retained\",\"revision\":1,\"kind\":\"installed\",\"visible\":false,\"identities\":{identities}}}");
        assert_eq!(
            route_with(&event, &ctx, Some(9), "boot", |_| panic!(), |_, _| panic!()),
            Some(None)
        );
    }
}

#[test]
fn maximum_rendered_section_receipt_stays_within_native_saved_boundary() {
    let identities: Vec<_> = (0..256).map(|index| format!("i.{index:0189}")).collect();
    let raw = json!({"snapshot":"retained", "revision":1, "kind":"installed", "visible":false, "identities":identities});
    let event = format!("15|launcher|launcher-section-visibility|section:{raw}");
    assert!(event.len() > 4096);
    let mut frames = Vec::new();
    let result = route_with(
        &event,
        &context(),
        Some(9),
        "boot",
        |command| {
            let Command::SaveLauncherDesired { changes, .. } = command else {
                panic!()
            };
            assert_eq!(changes.len(), 256);
            let visibility: serde_json::Map<String, serde_json::Value> = identities
                .iter()
                .map(|id| (id.clone(), false.into()))
                .collect();
            Ok(Outcome::DesiredSaved { revision:33,
            config:json!({"schemaVersion":2,"startup":"none","agents":{"launcher":{"enabled":false,"options":{"itemVisibility":visibility}}},"userRevision":0,"fieldRevisions":{}}).to_string(),
            disposition:voboost_contract::desired::Disposition::Saved })
        },
        |_, frame| {
            frames.push(frame.to_vec());
            true
        },
    );
    assert_eq!(result, Some(Some(1)));
    assert_eq!(frames.len(), 1);
    let frame = std::str::from_utf8(&frames[0]).unwrap();
    let document: serde_json::Value =
        serde_json::from_str(frame.trim_end().splitn(3, '|').nth(2).unwrap()).unwrap();
    assert_eq!(document.as_object().unwrap().len(), 5);
    assert!(document["field"].is_object());
    assert_eq!(document["value"], false);
    assert!(frame.len() < 4096);
}
