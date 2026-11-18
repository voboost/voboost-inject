extern crate alloc;
pub use voboost_cluster_native::{elf, pw_readback_types, Result};
#[path = "../src/pw_storage_owner.rs"]
mod owner;
#[path = "../src/pw_readback_owner.rs"]
pub mod pw_readback_owner;
#[path = "../src/pw_storage_types.rs"]
pub mod pw_storage_types;
#[test]
#[ignore = "requires original retained light ELF"]
fn actual_light_storage_owner_rejects_wrong_process_anchor_and_bytes() {
    for name in ["PW_A9_LIGHT_ELF", "PW_A11_LIGHT_ELF"] {
        let file = std::fs::read(std::env::var(name).unwrap()).unwrap();
        let name = "_Z20getApplicationScreenv";
        let exported = pw_readback_types::export_code(&file, name).unwrap();
        let function = elf::LocalFunction {
            value: exported.address,
            size: exported.code.len() as u64,
            anchor_value: exported.address,
            anchor_size: exported.code.len() as u64,
        };
        let code = elf::function_bytes(&file, function.value, function.size).unwrap();
        let loaded = pw_readback_owner::LoadedGetter {
            process: 123,
            base: 0x100000,
            symbol: 0x100000 + function.value,
            forbidden: 0,
        };
        let loads = elf::file_loads(&file).unwrap();
        let proof =
            owner::StorageOwnerProof::inspect(&file, loaded, &loads, |_, _| Ok(code.to_vec()))
                .unwrap();
        let ty = "kanzi::AbstractPropertyTypeDescriptor::PropertyStorage";
        assert!(proof.query(123, loaded.symbol, ty, "descriptor").is_some());
        assert!(proof.query(124, loaded.symbol, ty, "descriptor").is_none());
        assert!(proof
            .query(123, loaded.symbol + 4, ty, "descriptor")
            .is_none());
        assert!(
            owner::StorageOwnerProof::inspect(&file, loaded, &loads, |_, _| Ok(vec![
                0;
                code.len()
            ]))
            .is_err()
        );
    }
}
