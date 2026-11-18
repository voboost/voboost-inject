//! Storage type evidence bound to the actual mapped light executable.
use crate::{
    elf::{self, MappedLoad},
    pw_readback_owner::LoadedGetter,
    pw_storage_types::{Field, StorageProof},
    Result,
};
use alloc::vec::Vec;
pub struct StorageOwnerProof {
    proof: StorageProof,
    process: u64,
    anchor: u64,
}
impl StorageOwnerProof {
    pub fn inspect(
        file: &[u8],
        loaded: LoadedGetter,
        loads: &[MappedLoad],
        mut mapped: impl FnMut(u64, usize) -> Result<Vec<u8>>,
    ) -> Result<Self> {
        if loaded.process == 0 {
            return Err("PW storage current process absent".into());
        }
        // The anchor is never called here. It binds debug type records to the
        // actual light executable supplying the current Screen implementation.
        let name = "_Z20getApplicationScreenv";
        let exported = crate::pw_readback_types::export_code(file, name)?;
        let function = elf::LocalFunction {
            value: exported.address,
            size: exported.code.len() as u64,
            anchor_value: exported.address,
            anchor_size: exported.code.len() as u64,
        };
        let actual = elf::checked_mapped_function(
            file,
            function,
            loaded.base,
            loaded.symbol,
            loads,
            loaded.forbidden,
        )?;
        let code = elf::function_bytes(file, function.value, function.size)?;
        if mapped(actual, code.len())?.as_slice() != code {
            return Err("PW storage mapped executable mismatch".into());
        }
        Ok(Self {
            proof: StorageProof::inspect(file)?,
            process: loaded.process,
            anchor: actual,
        })
    }
    pub fn query(
        &self,
        current_process: u64,
        current_anchor: u64,
        ty: &str,
        path: &str,
    ) -> Option<Field> {
        (current_process == self.process && current_anchor == self.anchor)
            .then(|| self.proof.query(ty, path))
            .flatten()
    }
}

#[cfg(target_os = "nto")]
pub mod qnx {
    use super::*;
    use crate::pw_readback_owner::qnx::{pin_input, OwnerSymbol, PinnedInput};
    pub struct Pinned {
        proof: StorageOwnerProof,
        input: PinnedInput,
    }
    /// Worker-only: actual loader/file/type work never runs on a UI frame.
    pub fn prepare(forbidden: u64) -> Result<Pinned> {
        let mut input = pin_input(OwnerSymbol::LightScreen, forbidden)?;
        let proof = StorageOwnerProof::inspect(
            &input.bytes,
            input.loaded,
            &input.loads,
            |address, bytes| {
                // The shared mapped-owner validator has bounded this readable RX
                // range to the retained main-executable loader mapping.
                Ok(unsafe { core::slice::from_raw_parts(address as *const u8, bytes) }.to_vec())
            },
        )?;
        input.bytes.clear();
        input.bytes.shrink_to_fit();
        Ok(Pinned { proof, input })
    }
    impl Pinned {
        pub fn query(&self, ty: &str, path: &str) -> Option<Field> {
            self.proof.query(
                unsafe { libc::getpid() } as u64,
                self.input.loaded.symbol,
                ty,
                path,
            )
        }
    }
}
