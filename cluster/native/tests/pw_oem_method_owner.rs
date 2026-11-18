extern crate alloc;
pub use voboost_cluster_native::{elf, pw_readback_types, Result};
#[path = "../src/pw_oem_method_owner.rs"]
mod owner;
#[path = "../src/pw_readback_owner.rs"]
pub mod pw_readback_owner;

#[test]
#[ignore = "requires original retained OEM ELF"]
fn actual_named_update_owner_is_bound_to_process_and_mapped_code() {
    for (variable, family) in [
        ("PW_A9_OEM_ELF", pw_readback_types::Family::Buffer),
        ("PW_A11_OEM_ELF", pw_readback_types::Family::Object),
    ] {
        let file = std::fs::read(std::env::var(variable).unwrap()).unwrap();
        for method in owner::required_methods(family) {
            let p = if matches!(
                method,
                "_ZN12CContextDataC1Ev" | "_ZN12CContextDataD1Ev" | "_ZN12CContextDataD2Ev"
            ) {
                pw_readback_types::inspect_method_alias(&file, method).unwrap()
            } else {
                pw_readback_types::inspect_method(&file, method).unwrap()
            };
            let base = 0x100000;
            let loaded = pw_readback_owner::LoadedGetter {
                process: 123,
                base,
                symbol: base + p.address(),
                forbidden: 0,
            };
            let loads = elf::file_loads(&file).unwrap();
            let proof = owner::MethodOwnerProof::inspect(&file, method, loaded, &loads, |_, _| {
                Ok(p.code().to_vec())
            })
            .unwrap();
            assert_eq!(proof.original(123), Some(loaded.symbol));
            assert_eq!(proof.original(124), None);
            let return_kind = if p.result == pw_readback_types::AbiType::Void {
                9
            } else {
                1
            };
            assert_eq!(proof.bind(123, return_kind), Some(loaded.symbol));
            assert_eq!(proof.bind(124, return_kind), None);
            assert_eq!(proof.bind(123, if return_kind == 9 { 1 } else { 9 }), None);
            if method == "_ZN12CContextData6updateEji" {
                assert!(owner::MethodOwnerProof::inspect(
                    &file,
                    method,
                    loaded,
                    &loads,
                    |_, _| Ok(vec![0; p.code().len()])
                )
                .is_err());
            }
        }
    }
}

#[test]
#[ignore = "requires original retained A11 OEM ELF"]
fn actual_sound_callback_has_typed_function_pointer() {
    use pw_readback_types::AbiType;
    let file = std::fs::read(std::env::var("PW_A11_OEM_ELF").unwrap()).unwrap();
    let proof = pw_readback_types::inspect_method(
        &file,
        "_Z25dataprocesser_soundEnablePvjPFbP19_vehicleconf_StructEj",
    )
    .unwrap();
    assert_eq!(proof.result, AbiType::Signed(4));
    assert_eq!(proof.parameters.len(), 4);
    assert!(matches!(&proof.parameters[0],AbiType::Pointer(x) if x.as_ref()==&AbiType::Void));
    assert_eq!(proof.parameters[1], AbiType::Unsigned(4));
    let AbiType::Pointer(callback) = &proof.parameters[2] else {
        panic!("callback pointer absent")
    };
    let AbiType::Function { result, parameters } = callback.as_ref() else {
        panic!("callback signature absent")
    };
    assert_eq!(result.as_ref(), &AbiType::Bool);
    assert_eq!(parameters.len(), 1);
    assert!(
        matches!(&parameters[0],AbiType::Pointer(x) if matches!(x.as_ref(),AbiType::Named{name,..} if name=="_vehicleconf_Struct"))
    );
    assert_eq!(proof.parameters[3], AbiType::Unsigned(4));
    let base = 0x100000;
    let loaded = pw_readback_owner::LoadedGetter {
        process: 123,
        base,
        symbol: base + proof.address(),
        forbidden: 0,
    };
    let owner = owner::MethodOwnerProof::inspect(
        &file,
        "_Z25dataprocesser_soundEnablePvjPFbP19_vehicleconf_StructEj",
        loaded,
        &elf::file_loads(&file).unwrap(),
        |_, _| Ok(proof.code().to_vec()),
    )
    .unwrap();
    assert_eq!(owner.original(123), Some(loaded.symbol));
}
