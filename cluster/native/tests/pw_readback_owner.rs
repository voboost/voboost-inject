extern crate alloc;
pub use voboost_cluster_native::{elf, pw_readback_types, Result};
#[path = "../src/pw_readback_owner.rs"]
mod owner;
use pw_readback_types::Family;

#[test]
#[ignore = "requires retained original A9/A11 OEM ELF environment inputs"]
fn actual_getter_proof_requires_current_process_owner_and_mapped_bytes() {
    for (variable, family, method) in [
        (
            "PW_A9_OEM_ELF",
            Family::Buffer,
            "_ZN12CContextData7getDataEjPvj",
        ),
        (
            "PW_A11_OEM_ELF",
            Family::Object,
            "_ZN12CContextData7getDataEjP15CTupMemTemplate",
        ),
    ] {
        let file =
            std::fs::read(std::env::var(variable).expect("actual OEM input absent")).unwrap();
        let p = pw_readback_types::inspect(&file, family).unwrap();
        let base = 0x100000u64;
        let actual = base + p.address();
        let code = p.code().to_vec();
        let loads = elf::file_loads(&file).unwrap();
        let loaded = owner::LoadedGetter {
            process: 123,
            base,
            symbol: actual,
            forbidden: 0,
        };
        let proof = owner::OwnerProof::inspect(&file, family, loaded, &loads, |address, len| {
            assert_eq!(address, actual);
            assert_eq!(len, code.len());
            Ok(code.clone())
        })
        .unwrap();
        assert_eq!(proof.original(), actual);
        assert!(proof.query(123, method, "", "$return").is_some());
        assert!(proof.query(124, method, "", "$return").is_none());
        assert!(proof.query(123, "wrongGetter", "", "$return").is_none());
        assert!(owner::OwnerProof::inspect(
            &file,
            family,
            owner::LoadedGetter {
                symbol: actual + 4,
                ..loaded
            },
            &loads,
            |_, _| Ok(code.clone())
        )
        .is_err());
        assert!(owner::OwnerProof::inspect(
            &file,
            family,
            owner::LoadedGetter {
                forbidden: actual,
                ..loaded
            },
            &loads,
            |_, _| Ok(code.clone())
        )
        .is_err());
        let mut other = loads.clone();
        other[0].offset ^= 8;
        assert!(
            owner::OwnerProof::inspect(&file, family, loaded, &other, |_, _| Ok(code.clone()))
                .is_err()
        );
        assert!(
            owner::OwnerProof::inspect(&file, family, loaded, &loads, |_, _| {
                let mut b = code.clone();
                b[0] ^= 1;
                Ok(b)
            })
            .is_err()
        );
        assert!(owner::OwnerProof::inspect(
            &file,
            family,
            owner::LoadedGetter {
                process: 0,
                ..loaded
            },
            &loads,
            |_, _| Ok(code.clone())
        )
        .is_err());
    }
}
