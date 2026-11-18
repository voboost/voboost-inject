use voboost_contract_core::release::Manifest;
#[test]
fn product_owned_canonical_corpus_matches_actual_shared_parser() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test/fixtures/product-release/voboost");
    Manifest::parse(&std::fs::read(root.join("valid/minimal.json")).unwrap()).unwrap();
    for entry in std::fs::read_dir(root.join("invalid")).unwrap() {
        let entry = entry.unwrap();
        let bytes = std::fs::read(entry.path()).unwrap();
        assert!(
            Manifest::parse(&bytes).is_err(),
            "accepted {:?}",
            entry.file_name()
        );
    }
}
