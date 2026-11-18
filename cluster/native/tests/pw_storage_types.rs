extern crate alloc;
pub use voboost_cluster_native::{pw_readback_types, Result};
#[path = "../src/pw_storage_types.rs"]
mod storage;
#[test]
#[ignore = "requires retained original A9/A11 light ELF"]
fn actual_light_storage_records() {
    for name in ["PW_A9_LIGHT_ELF", "PW_A11_LIGHT_ELF"] {
        let file = std::fs::read(std::env::var(name).unwrap()).unwrap();
        let proof = storage::StorageProof::inspect(&file).unwrap();
        let field = proof
            .query(
                "kanzi::AbstractPropertyTypeDescriptor::PropertyStorage",
                "valueSourceEntries._M_impl._M_finish",
            )
            .unwrap();
        assert_eq!(
            field,
            storage::Field {
                kind: 2,
                bytes: 8,
                offset: 32
            }
        );
        assert!(proof.query("unknown", "descriptor").is_none());
        let mut stripped = file;
        stripped[..4].fill(0);
        assert!(storage::StorageProof::inspect(&stripped).is_err());
    }
}
