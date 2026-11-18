use std::fs;
use voboost_contract::release::{Manifest, RestoreDocument};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = &args[1];
    let manifest_bytes = fs::read(format!("{dir}/voboost.json")).unwrap();
    let manifest = Manifest::parse(&manifest_bytes).unwrap();
    let digest = manifest.digest().unwrap();
    println!("manifest canonical digest: {digest}");

    let restore_bytes = fs::read(format!("{dir}/restore.json")).unwrap();
    let restore = RestoreDocument::parse(&restore_bytes).unwrap();
    println!(
        "restore.sourceDefinitionSha256: {}",
        restore.source_definition_sha256
    );
    println!(
        "restore.restorableClosureSha256: {}",
        restore.restorable_closure_sha256
    );
    println!(
        "computed restorableClosureSha256: {}",
        voboost_contract::release::restorable_closure_sha256(&manifest).unwrap()
    );

    let staging: serde_json::Value =
        serde_json::from_slice(&fs::read(format!("{dir}/staging.json")).unwrap()).unwrap();
    println!("staging.manifestSha256: {}", staging["manifestSha256"]);
    println!("staging.transactionId: {}", staging["transactionId"]);
}
