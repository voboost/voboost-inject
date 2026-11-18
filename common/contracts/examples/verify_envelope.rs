//! Test-only host harness: parse+verify a Python-built request envelope
//! against the production Request::verify path and print the exact reason.
//! Usage: verify_envelope <envelope-file> <android-public-key-hex>
use ed25519_dalek::VerifyingKey;
use voboost_contract_core::cluster::Request;

fn main() {
    if let Some(hdr) = std::env::args().nth(3) {
        let bytes = std::fs::read(&hdr).expect("header");
        match voboost_contract_core::wire::NetworkHeader::parse(&bytes) {
            Ok(h) => println!("HEADER OK files={}", h.files.len()),
            Err(e) => println!("HEADER FAILED: {e}"),
        }
        return;
    }
    let path = std::env::args().nth(1).expect("envelope file");
    let key_hex = std::env::args().nth(2).expect("public key hex");
    let envelope = std::fs::read(&path).expect("read envelope");
    let key_bytes = hex::decode(&key_hex).expect("hex key");
    let arr: [u8; 32] = key_bytes.as_slice().try_into().expect("key len");
    let key = VerifyingKey::from_bytes(&arr).expect("public key");
    match Request::verify(&envelope, &key) {
        Ok(r) => println!(
            "VERIFY OK kind={:?} pair={} catalog={} closure={}",
            r.kind, r.pair_id, r.catalog_sha256, r.closure_sha256
        ),
        Err(e) => println!("VERIFY FAILED: {e}"),
    }
}
