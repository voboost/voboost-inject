//! Disposable deterministic transport fixtures. Never used as production authority.
use ed25519_dalek::SigningKey;
use std::{collections::BTreeMap, fs, path::PathBuf};
use voboost_contract_core::{
    ascii_json,
    catalog::Domain,
    cluster::{desired_digest, DesiredAgent, Receipt, ReceiptKind, Request, RequestKind},
    generation::GenerationIdentity,
    wire::*,
};
fn h(c: char) -> String {
    c.to_string().repeat(64)
}
fn main() {
    let output = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("explicit isolated fixture output required"),
    );
    fs::create_dir_all(&output).unwrap();
    let agents = vec![DesiredAgent {
        id: "cluster-vehicle-status-fuel".into(),
        enabled: true,
        options: BTreeMap::new(),
    }];
    let digest = desired_digest(&agents).unwrap();
    let request = Request {
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
        desired_revision: Some(1),
        desired_sha256: Some(digest.clone()),
        agents: Some(agents),
    };
    let key = SigningKey::from_bytes(&[7; 32]);
    let request_envelope = request.sign(&key).unwrap();
    let request_file = WireFile {
        role: WireRole::Request,
        file: "request.vbc".into(),
        size: request_envelope.len() as u64,
        sha256: voboost_contract_core::hash(&request_envelope),
    };
    let take = LocalRequest::Take {
        protocol_version: 1,
        request_id: h('a'),
    };
    let transport = Transport {
        host: "192.0.2.2".into(),
        port: 24443,
        server_certificate_sha256: h('b'),
        client_certificate_sha256: h('c'),
        credentials: BlobIdentity {
            size: 32,
            sha256: h('d'),
        },
    };
    let ready = LocalResponse::Take {
        protocol_version: 1,
        request_id: h('a'),
        result: TakeResult::Ready {
            lease_id: h('e'),
            transaction_id: h('3'),
            lease_millis: LEASE_MILLIS,
            transport,
            files: vec![request_file.clone()],
        },
    };
    let identity = GenerationIdentity {
        domain: Domain::Cluster,
        catalog_sha256: h('4'),
        selection_sha256: h('7'),
        closure_sha256: h('5'),
    };
    let receipt = Receipt {
        schema_version: 1,
        kind: ReceiptKind::Desired,
        pair_id: h('1'),
        domain: Domain::Cluster,
        authority_epoch: h('2'),
        transaction_id: h('3'),
        catalog_sha256: h('4'),
        closure_sha256: h('5'),
        selection_sha256: h('7'),
        generation_id: identity.generation_id().unwrap(),
        desired_revision: 1,
        desired_sha256: digest,
        challenge: h('6'),
        daemon_epoch: h('8'),
        boot_id: "qnx-fixture-boot".into(),
        observation_revision: 1,
        agents: vec![],
    };
    let receipt_envelope = receipt.sign(&key).unwrap();
    let result = LocalRequest::Result {
        protocol_version: 1,
        request_id: h('a'),
        lease_id: h('e'),
        transaction_id: h('3'),
        transport_outcome: TransportOutcome::Delivered,
        receipt: Some(BlobIdentity {
            size: receipt_envelope.len() as u64,
            sha256: voboost_contract_core::hash(&receipt_envelope),
        }),
    };
    let mut files = vec![
        ("take.json", ascii_json(&take).unwrap()),
        ("take-ready.json", ready.canonical_bytes().unwrap()),
        (
            "take-empty.json",
            LocalResponse::Take {
                protocol_version: 1,
                request_id: h('a'),
                result: TakeResult::Empty {},
            }
            .canonical_bytes()
            .unwrap(),
        ),
        (
            "take-setup-required.json",
            LocalResponse::Take {
                protocol_version: 1,
                request_id: h('a'),
                result: TakeResult::SetupRequired {},
            }
            .canonical_bytes()
            .unwrap(),
        ),
        ("result-delivered.json", ascii_json(&result).unwrap()),
        (
            "result-recorded.json",
            LocalResponse::Result {
                protocol_version: 1,
                request_id: h('a'),
                result: ResultStatus::Recorded {},
            }
            .canonical_bytes()
            .unwrap(),
        ),
        (
            "network-header.json",
            NetworkHeader {
                protocol_version: 1,
                files: vec![request_file],
            }
            .canonical_bytes()
            .unwrap(),
        ),
        ("desired.json", request.canonical_bytes().unwrap()),
        ("request.vbc", request_envelope),
        ("receipt.vbc", receipt_envelope),
        (
            "device-fixture-public.raw",
            key.verifying_key().to_bytes().to_vec(),
        ),
    ];
    let valid = ascii_json(&take).unwrap();
    let text = String::from_utf8(valid).unwrap();
    files.push((
        "invalid-take-extra.json",
        text.replace(
            "\"protocolVersion\":1,",
            "\"protocolVersion\":1,\"agentId\":\"untrusted\",",
        )
        .into_bytes(),
    ));
    let mut sums = String::new();
    for (name, bytes) in files {
        fs::write(output.join(name), &bytes).unwrap();
        sums += &format!("{}  {}\n", voboost_contract_core::hash(&bytes), name);
    }
    fs::write(output.join("SHA256SUMS"), sums).unwrap();
}
