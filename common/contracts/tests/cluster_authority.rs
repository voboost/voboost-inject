use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use voboost_contract_core::{
    ascii_json,
    catalog::{Catalog, Domain},
    cluster::{
        desired_digest, AcceptedDesired, DesiredAdmission, DesiredAgent, ObservedAgent,
        ObservedState, ProcessIdentity, Receipt, ReceiptKind, Request, RequestKind,
    },
    generation::{closure_digest, selection_digest, GenerationIdentity},
    hash,
    wire::{
        BlobIdentity, LocalRequest, LocalResponse, ResultStatus, TakeResult, Transport,
        TransportOutcome, WireFile, WireRole, LEASE_MILLIS,
    },
};
fn h(c: char) -> String {
    c.to_string().repeat(64)
}
fn desired(revision: u64) -> Request {
    let agents = vec![DesiredAgent {
        id: "cluster-vehicle-status-fuel".into(),
        enabled: true,
        options: BTreeMap::new(),
    }];
    Request {
        global_locale: None,
        schema_version: 1,
        kind: RequestKind::Desired,
        pair_id: h('1'),
        domain: Domain::Cluster,
        authority_epoch: h('2'),
        transaction_id: h('3'),
        catalog_sha256: h('4'),
        closure_sha256: h('5'),
        challenge: h('6'),
        release_manifest_sha256: None,
        files: None,
        desired_revision: Some(revision),
        desired_sha256: Some(desired_digest(&agents).unwrap()),
        agents: Some(agents),
    }
}
#[test]
fn device_authority_cannot_be_replaced_by_transport_or_cross_role_signature() {
    let authority = SigningKey::from_bytes(&[7; 32]);
    let courier = SigningKey::from_bytes(&[8; 32]);
    let request = desired(1);
    let envelope = request.sign(&authority).unwrap();
    assert!(Request::verify(&envelope, &authority.verifying_key()).is_ok());
    assert!(Request::verify(&envelope, &courier.verifying_key()).is_err());
    let mut modified = envelope.clone();
    let at = modified.windows(4).position(|w| w == b"true").unwrap();
    modified[at..at + 4].copy_from_slice(b"null");
    assert!(Request::verify(&modified, &authority.verifying_key()).is_err());
    let mut wrong_endian = envelope.clone();
    wrong_endian[..4].reverse();
    assert!(Request::verify(&wrong_endian, &authority.verifying_key()).is_err());
}
#[test]
fn revisions_reject_replay_conflict_and_do_not_advance_on_retry() {
    let request = desired(2);
    let (a, kind) = AcceptedDesired::admit(None, &request, &h('2'), &h('4'), &h('5')).unwrap();
    assert_eq!(kind, DesiredAdmission::Changed);
    let (_, kind) = AcceptedDesired::admit(Some(&a), &request, &h('2'), &h('4'), &h('5')).unwrap();
    assert_eq!(kind, DesiredAdmission::Idempotent);
    assert!(AcceptedDesired::admit(Some(&a), &desired(1), &h('2'), &h('4'), &h('5')).is_err());
    let mut conflict = request.clone();
    conflict.agents.as_mut().unwrap()[0].enabled = false;
    conflict.desired_sha256 = Some(desired_digest(conflict.agents.as_ref().unwrap()).unwrap());
    assert!(AcceptedDesired::admit(Some(&a), &conflict, &h('2'), &h('4'), &h('5')).is_err());
}
#[test]
fn catalog_rebind_preserves_intent_revision_and_rejects_old_authority() {
    let request = desired(2);
    let (old, _) = AcceptedDesired::admit(None, &request, &h('2'), &h('4'), &h('5')).unwrap();
    let mut next = request.clone();
    next.catalog_sha256 = h('a');
    next.closure_sha256 = h('b');
    let (rebound, outcome) =
        AcceptedDesired::admit(Some(&old), &next, &h('2'), &h('a'), &h('b')).unwrap();
    assert_eq!(outcome, DesiredAdmission::Changed);
    assert_eq!(rebound.desired_revision, old.desired_revision);
    assert_eq!(rebound.desired_sha256, old.desired_sha256);
    assert_eq!(rebound.catalog_sha256, h('a'));
    assert_eq!(rebound.closure_sha256, h('b'));
    let (_, outcome) =
        AcceptedDesired::admit(Some(&rebound), &next, &h('2'), &h('a'), &h('b')).unwrap();
    assert_eq!(outcome, DesiredAdmission::Idempotent);
    assert!(AcceptedDesired::admit(Some(&rebound), &request, &h('2'), &h('a'), &h('b')).is_err());
    next.agents.as_mut().unwrap()[0].enabled = false;
    next.desired_sha256 = Some(desired_digest(next.agents.as_ref().unwrap()).unwrap());
    assert!(AcceptedDesired::admit(Some(&rebound), &next, &h('2'), &h('a'), &h('b')).is_err());
}
fn receipt(request: &Request) -> Receipt {
    let identity = GenerationIdentity {
        domain: Domain::Cluster,
        catalog_sha256: request.catalog_sha256.clone(),
        selection_sha256: h('7'),
        closure_sha256: request.closure_sha256.clone(),
    };
    Receipt {
        schema_version: 1,
        kind: ReceiptKind::Desired,
        pair_id: request.pair_id.clone(),
        domain: Domain::Cluster,
        authority_epoch: request.authority_epoch.clone(),
        transaction_id: request.transaction_id.clone(),
        catalog_sha256: request.catalog_sha256.clone(),
        closure_sha256: request.closure_sha256.clone(),
        selection_sha256: h('7'),
        generation_id: identity.generation_id().unwrap(),
        desired_revision: request.desired_revision.unwrap(),
        desired_sha256: request.desired_sha256.clone().unwrap(),
        challenge: request.challenge.clone(),
        daemon_epoch: h('8'),
        boot_id: "qnx-test-boot".into(),
        observation_revision: 1,
        agents: vec![ObservedAgent {
            target_process: "gauge".into(),
            id: "cluster-vehicle-status-fuel".into(),
            state: ObservedState::Applied,
            reason: "layout-readback".into(),
            process: Some(ProcessIdentity {
                pid: 42,
                birth_identity: h('9'),
                executable_sha256: h('a'),
                endpoint_epoch: h('b'),
                lifecycle_generation: 1,
                supervisor: None,
            }),
        }],
    }
}
#[test]
fn optional_supervisor_observation_requires_exact_nonce_and_parent_bounds() {
    use voboost_contract_core::cluster::SupervisorObservation;
    let request = desired(2);
    let mut receipt = receipt(&request);
    assert!(receipt.validate().is_ok());
    for (nonce, parent_pid, valid) in [
        (h('a'), 42, true),
        (h('a'), 1, false),
        (h('a'), u64::MAX, false),
        ("A".repeat(64), 42, false),
    ] {
        receipt.agents[0].process.as_mut().unwrap().supervisor =
            Some(SupervisorObservation { nonce, parent_pid });
        assert_eq!(receipt.validate().is_ok(), valid);
    }
    receipt.agents[0].process.as_mut().unwrap().supervisor = None;
    let raw = voboost_contract_core::ascii_json(&receipt).unwrap();
    assert!(!core::str::from_utf8(&raw).unwrap().contains("supervisor"));
}
#[test]
fn applied_needs_current_challenge_desired_and_admitted_generation() {
    let request = desired(2);
    let mut receipt = receipt(&request);
    assert!(receipt
        .correlate(&request, Some(&receipt.generation_id))
        .is_ok());
    assert!(receipt.correlate(&request, None).is_err());
    receipt.challenge = h('0');
    assert!(receipt
        .correlate(&request, Some(&receipt.generation_id))
        .is_err());
    receipt.challenge = request.challenge.clone();
    receipt.desired_revision = 1;
    assert!(receipt
        .correlate(&request, Some(&receipt.generation_id))
        .is_err());
    receipt.desired_revision = 2;
    receipt.agents[0].process = None;
    assert!(receipt.validate().is_err());
}
#[test]
fn canonical_local_protocol_rejects_extras_duplicates_order_and_credential_payload() {
    let bytes = format!(
        "{{\"request\":\"clusterDeliveryTake\",\"protocolVersion\":1,\"requestId\":\"{}\"}}\n",
        h('1')
    );
    assert!(LocalRequest::parse(bytes.as_bytes()).is_ok());
    for bad in [
        bytes.replace(
            "\"protocolVersion\":1,",
            "\"protocolVersion\":1,\"agentId\":\"x\",",
        ),
        bytes.replace(
            "\"protocolVersion\":1,",
            "\"protocolVersion\":1,\"protocolVersion\":1,",
        ),
        bytes.replace(
            "\"request\":\"clusterDeliveryTake\",\"protocolVersion\":1,",
            "\"protocolVersion\":1,\"request\":\"clusterDeliveryTake\",",
        ),
    ] {
        assert!(LocalRequest::parse(bad.as_bytes()).is_err());
    }
    let ready = TakeResult::Ready {
        lease_id: h('2'),
        transaction_id: h('3'),
        lease_millis: LEASE_MILLIS,
        transport: Transport {
            host: "192.0.2.2".into(),
            port: 24443,
            server_certificate_sha256: h('4'),
            client_certificate_sha256: h('5'),
            credentials: BlobIdentity {
                size: 32,
                sha256: h('6'),
            },
        },
        files: vec![WireFile {
            role: WireRole::Request,
            file: "request.vbc".into(),
            size: 100,
            sha256: h('7'),
        }],
    };
    assert_eq!(ready.descriptor_count(), 2);
    ready.validate().unwrap();
    let response = LocalResponse::Take {
        protocol_version: 1,
        request_id: h('1'),
        result: ready,
    };
    assert!(String::from_utf8(response.canonical_bytes().unwrap())
        .unwrap()
        .contains("\"status\":\"ready\",\"leaseId\":"));
    let result = LocalRequest::Result {
        protocol_version: 1,
        request_id: h('1'),
        lease_id: h('2'),
        transaction_id: h('3'),
        transport_outcome: TransportOutcome::Unavailable,
        receipt: Some(BlobIdentity {
            size: 32,
            sha256: h('6'),
        }),
    };
    assert!(result.validate().is_err());
    let ok = LocalResponse::Result {
        protocol_version: 1,
        request_id: h('1'),
        result: ResultStatus::Recorded {},
    };
    assert!(ok
        .canonical_bytes()
        .unwrap()
        .ends_with(b"\"result\":{\"status\":\"recorded\"}}\n"));
}
fn catalog_fixture() -> voboost_contract_core::agent_catalog::AgentCatalog {
    serde_json::from_value(serde_json::json!({"schemaVersion":2,"supportedAbis":["arm64-v8a"],"agentEntryAbi":{"schemaVersion":1,"sha256":h('3')},"core":{"file":"agent-common.dex","size":10,"sha256":h('4')},"clusterRuntime":{"file":"libvoboost-runtime-cluster.so","size":10,"sha256":h('2')},"agents":[
 {"id":"font-cyrillic","targets":[{"process":"gauge","file":"libagent-font-cyrillic.so","size":10,"sha256":h('5'),"platform":"qnx","domain":"cluster","entryAbi":"voboost-agent3-v1","boot":false}],"status":"stable","order":1,"activation":{"type":"checkbox","default":true},"title":{"en":"Font","ru":"Font"},"description":{"en":"Font","ru":"Font"},"applicability":{"chip":[],"vehicle":[],"android":[],"powertrain":[],"market":[]}},
 {"id":"settings-executor","kind":"executor","surfaces":["settings"],"targets":[{"process":"com.example.settings","file":"agent-settings.dex","size":10,"sha256":h('6'),"platform":"android","domain":"android","entryAbi":"android-java-v1","entryClass":"ru.voboost.agents.AgentEntry","boot":false}]}]})).unwrap()
}
#[test]
fn catalog2_rejects_java_native_smuggling_and_retains_disabled_closure() {
    let catalog = catalog_fixture();
    let bytes = ascii_json(&catalog).unwrap();
    let admitted = Catalog::parse(
        &bytes,
        &h('3'),
        voboost_contract_core::catalog::NATIVE_ENTRY_ABI_SHA256,
    )
    .unwrap();
    let closure = admitted.closure(Domain::Cluster).unwrap();
    assert_eq!(closure.len(), 2);
    let mut cross_domain = admitted.clone();
    cross_domain.agents[0].disables = Some(vec!["settings-executor".into()]);
    assert!(cross_domain
        .validate(
            &h('3'),
            voboost_contract_core::catalog::NATIVE_ENTRY_ABI_SHA256
        )
        .is_err());
    let multimedia = admitted.closure(Domain::Multimedia).unwrap();
    assert_eq!(multimedia.len(), 2);
    assert!(multimedia.iter().any(|f| f.file == "agent-settings.dex"));
    let digest = closure_digest(&closure).unwrap();
    assert_eq!(digest.len(), 64);
    let text = String::from_utf8(bytes).unwrap();
    assert!(Catalog::parse(
        text.replace(
            "\"entryAbi\":\"voboost-agent3-v1\",",
            "\"entryAbi\":\"voboost-agent3-v1\",\"entryClass\":\"ru.Evil\","
        )
        .as_bytes(),
        &h('3'),
        voboost_contract_core::catalog::NATIVE_ENTRY_ABI_SHA256
    )
    .is_err());
    let pretty = serde_json::to_string_pretty(&catalog).unwrap() + "\n";
    assert!(Catalog::parse(
        pretty.as_bytes(),
        &h('3'),
        voboost_contract_core::catalog::NATIVE_ENTRY_ABI_SHA256
    )
    .is_err());
    let profile = voboost_contract_core::generation::LocalProfile {
        domain: Domain::Cluster,
        os_known: true,
        architecture: "aarch64",
        os_version: None,
        chip: None,
        vehicle: None,
        powertrain: None,
        market: None,
        native_control_available: false,
        build_ids: &[],
    };
    let selected = voboost_contract_core::generation::select(&admitted, &profile).unwrap();
    assert!(selected.is_empty());
    assert_eq!(admitted.closure(Domain::Cluster).unwrap(), closure);
    assert_eq!(selection_digest(&selected).unwrap(), hash(b"[]\n"));
}

#[test]
fn target_scoped_catalog_rejects_runtime_tuple_boot_and_duplicate_mismatches() {
    let baseline = catalog_fixture();
    let check = |raw: &voboost_contract_core::agent_catalog::AgentCatalog| {
        Catalog::parse(
            &ascii_json(raw).unwrap(),
            &h('3'),
            voboost_contract_core::catalog::NATIVE_ENTRY_ABI_SHA256,
        )
    };
    assert!(check(&baseline).is_ok());
    let mut missing = baseline.clone();
    missing.cluster_runtime = None;
    assert!(check(&missing).is_err());
    let mut extra = baseline.clone();
    extra.agents.remove(0);
    assert!(check(&extra).is_err());
    for row in 0..baseline.agents.len() {
        let mut boot = baseline.clone();
        boot.agents[row].targets[0].boot = true;
        assert!(check(&boot).is_err());
        let mut duplicate = baseline.clone();
        let target = duplicate.agents[row].targets[0].clone();
        duplicate.agents[row].targets.push(target);
        assert!(check(&duplicate).is_err());
    }
    let mut tuple = baseline.clone();
    tuple.agents[0].targets[0].domain = voboost_contract_core::agent_catalog::TargetDomain::Android;
    assert!(check(&tuple).is_err());
    let mut java = baseline.clone();
    java.agents[0].targets[0].entry_class = Some("ru.Evil".into());
    assert!(check(&java).is_err());
    let mut legacy = serde_json::to_value(&baseline).unwrap();
    legacy["runtimes"] = serde_json::json!([]);
    assert!(
        serde_json::from_value::<voboost_contract_core::agent_catalog::AgentCatalog>(legacy)
            .is_err()
    );
}

#[test]
fn android_system_server_is_scoped_to_launcher_and_qnx_gauge_is_not_android() {
    let baseline = catalog_fixture();
    let check = |raw: &voboost_contract_core::agent_catalog::AgentCatalog| {
        Catalog::parse(
            &ascii_json(raw).unwrap(),
            &h('3'),
            voboost_contract_core::catalog::NATIVE_ENTRY_ABI_SHA256,
        )
    };
    assert!(check(&baseline).is_ok());
    let mut launcher = baseline.clone();
    launcher.agents[1].id = "launcher".into();
    launcher.agents[1].targets[0].process = "system_server".into();
    assert!(check(&launcher).is_ok());
    for id in ["settings-executor", "font-cyrillic", "foreign"] {
        let mut other = launcher.clone();
        other.agents[1].id = id.into();
        assert!(check(&other).is_err());
    }
    for process in [
        "gauge",
        "zygote",
        "audioserver",
        "system_server:private",
        "com.Example.app",
        "com.example-app",
        "com.example.app:bad.suffix",
        "com.example.app:",
        "com..app",
    ] {
        let mut bad = launcher.clone();
        bad.agents[1].targets[0].process = process.into();
        assert!(check(&bad).is_err(), "{process}");
    }
    for process in [
        "com.example.app",
        "com.example.app:private",
        "com.example._app",
    ] {
        let mut good = launcher.clone();
        good.agents[1].targets[0].process = process.into();
        assert!(check(&good).is_ok(), "{process}");
    }
    let mut native = baseline.clone();
    native.agents[0].targets[0].process = "system_server".into();
    assert!(check(&native).is_err());
}

#[test]
fn receipt_target_pairs_preserve_each_owner_and_reject_duplicates_or_pid_aliases() {
    let request = desired(1);
    let mut value = receipt(&request);
    let original = value.agents[0].clone();
    for (i, process) in ["light", "point"].into_iter().enumerate() {
        let mut row = original.clone();
        row.target_process = process.into();
        let identity = row.process.as_mut().unwrap();
        identity.pid += i as u64 + 1;
        identity.birth_identity = format!("{:064x}", identity.pid);
        value.agents.push(row);
    }
    value.validate().unwrap();
    let key = SigningKey::from_bytes(&[17; 32]);
    let signed = value.sign(&key).unwrap();
    assert_eq!(
        Receipt::verify(&signed, &key.verifying_key())
            .unwrap()
            .agents
            .len(),
        3
    );
    let mut duplicate = value.clone();
    duplicate.agents.push(duplicate.agents[2].clone());
    assert!(duplicate.validate().is_err());
    let mut wrong = value.clone();
    wrong.agents[1].process = wrong.agents[0].process.clone();
    assert!(wrong.validate().is_err());
    let mut foreign = value.clone();
    foreign.agents[2].target_process = "sysmgr".into();
    assert!(foreign.validate().is_err());
    let mut other_agent = value.clone();
    let mut row = original;
    row.id = "other-agent".into();
    row.process.as_mut().unwrap().birth_identity = "c".repeat(64);
    other_agent.agents.push(row);
    assert!(
        other_agent.validate().is_err(),
        "same executable cannot carry mixed process epochs across agents"
    );
}

#[test]
fn three_actual_qnx_roles_preserve_exact_executable_and_reject_unknown_process() {
    let mut raw = catalog_fixture();
    let target = raw.agents[0].targets[0].clone();
    for process in ["light", "point"] {
        let mut row = target.clone();
        row.process = process.into();
        raw.agents[0].targets.push(row);
    }
    let parse = |raw: &voboost_contract_core::agent_catalog::AgentCatalog| {
        Catalog::parse(
            &ascii_json(raw).unwrap(),
            &h('3'),
            voboost_contract_core::catalog::NATIVE_ENTRY_ABI_SHA256,
        )
    };
    let catalog = parse(&raw).unwrap();
    let targets = &catalog
        .agents
        .iter()
        .find(|a| a.domain == Domain::Cluster)
        .unwrap()
        .targets;
    assert_eq!(targets.len(), 3);
    for target in targets {
        match target {
            voboost_contract_core::catalog::Target::Native {
                process,
                executable,
                ..
            } => assert_eq!(executable, &format!("/usr/bin/{process}")),
            _ => panic!("unexpected Dex target"),
        }
    }
    for bad in ["sysmgr", "other", "/usr/bin/gauge"] {
        let mut invalid = raw.clone();
        invalid.agents[0].targets[2].process = bad.into();
        assert!(parse(&invalid).is_err());
    }
}
