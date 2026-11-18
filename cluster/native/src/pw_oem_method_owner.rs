//! Offline named PW method signature + actual mapped-owner admission.
use crate::pw_readback_owner::LoadedGetter;
use crate::{
    elf::{self, LocalFunction, MappedLoad},
    pw_readback_types::{self, AbiType},
    Result,
};
use alloc::vec::Vec;

pub struct MethodOwnerProof {
    original: u64,
    process: u64,
    return_kind: u32,
}
fn pointer_named(ty: &AbiType, name: &str) -> bool {
    matches!(ty,AbiType::Pointer(inner) if matches!(inner.as_ref(),AbiType::Named{name:n,..} if n==name))
}
fn signature(method: &str, result: &AbiType, args: &[AbiType]) -> bool {
    let context = match method {
        "_ZN12CContextData4initEv"
        | "_ZN12CContextDataC1Ev"
        | "_ZN12CContextDataD1Ev"
        | "_ZN12CContextDataD2Ev" => Some(("CContextData", 0)),
        "_ZN20CStateAutocheckDelay4openEj" => Some(("CStateAutocheckDelay", 1)),
        "_ZN15CStateOperation4openEj" | "_ZN15CStateOperation5closeEj" => {
            Some(("CStateOperation", 1))
        }
        "_ZN10CStateInit4openEj" => Some(("CStateInit", 1)),
        "_ZN10CStateExit4openEj" => Some(("CStateExit", 1)),
        "_ZN15CStateAutocheck4openEj" => Some(("CStateAutocheck", 1)),
        "_ZN12CContextData6updateEji" => Some(("CContextData", 2)),
        "_ZN12CContextData6updateEjf" => Some(("CContextData", 3)),
        "_ZN12CContextData6updateEjPv" => Some(("CContextData", 4)),
        _ => None,
    };
    if let Some((class, kind)) = context {
        if result != &AbiType::Void || args.is_empty() || !pointer_named(&args[0], class) {
            return false;
        }
        if kind == 0 {
            return args.len() == 1;
        }
        if args.get(1) != Some(&AbiType::Unsigned(4)) {
            return false;
        }
        return match kind {
            1 => args.len() == 2,
            2 => args.len() == 3 && args[2] == AbiType::Signed(4),
            3 => args.len() == 3 && args[2] == AbiType::Float(4),
            4 => {
                args.len() == 3
                    && matches!(&args[2],AbiType::Pointer(x) if x.as_ref()==&AbiType::Void)
            }
            _ => false,
        };
    }
    if method != "_Z25dataprocesser_soundEnablePvjPFbP19_vehicleconf_StructEj"
        || result != &AbiType::Signed(4)
        || args.len() != 4
    {
        return false;
    }
    if !matches!(&args[0],AbiType::Pointer(x) if x.as_ref()==&AbiType::Void)
        || args[1] != AbiType::Unsigned(4)
        || args[3] != AbiType::Unsigned(4)
    {
        return false;
    }
    let AbiType::Pointer(callback) = &args[2] else {
        return false;
    };
    let AbiType::Function { result, parameters } = callback.as_ref() else {
        return false;
    };
    result.as_ref() == &AbiType::Bool
        && parameters.len() == 1
        && pointer_named(&parameters[0], "_vehicleconf_Struct")
}
impl MethodOwnerProof {
    pub fn inspect(
        file: &[u8],
        method: &str,
        loaded: LoadedGetter,
        loads: &[MappedLoad],
        mut mapped: impl FnMut(u64, usize) -> Result<Vec<u8>>,
    ) -> Result<Self> {
        if loaded.process == 0 {
            return Err("PW method process absent".into());
        }
        let proof = if matches!(
            method,
            "_ZN12CContextDataC1Ev" | "_ZN12CContextDataD1Ev" | "_ZN12CContextDataD2Ev"
        ) {
            pw_readback_types::inspect_method_alias(file, method)?
        } else {
            pw_readback_types::inspect_method(file, method)?
        };
        if !signature(method, &proof.result, &proof.parameters) {
            return Err("PW method signature unsupported".into());
        }
        let reference = LocalFunction {
            value: proof.address(),
            size: proof.code().len() as u64,
            anchor_value: proof.address(),
            anchor_size: proof.code().len() as u64,
        };
        let original = elf::checked_mapped_function(
            file,
            reference,
            loaded.base,
            loaded.symbol,
            loads,
            loaded.forbidden,
        )?;
        if mapped(original, proof.code().len())?.as_slice() != proof.code() {
            return Err("PW mapped method differs from structural owner".into());
        }
        Ok(Self {
            original,
            process: loaded.process,
            return_kind: if proof.result == AbiType::Void { 9 } else { 1 },
        })
    }
    pub fn original(&self, current_process: u64) -> Option<u64> {
        (current_process == self.process).then_some(self.original)
    }
    pub fn bind(&self, current_process: u64, return_kind: u32) -> Option<u64> {
        (return_kind == self.return_kind)
            .then(|| self.original(current_process))
            .flatten()
    }
}

pub fn required_methods(family: pw_readback_types::Family) -> Vec<&'static str> {
    const METHODS: [&str; 11] = [
        "_ZN12CContextDataD1Ev",
        "_ZN12CContextDataD2Ev",
        "_ZN20CStateAutocheckDelay4openEj",
        "_ZN15CStateOperation4openEj",
        "_ZN15CStateOperation5closeEj",
        "_ZN10CStateInit4openEj",
        "_ZN10CStateExit4openEj",
        "_ZN15CStateAutocheck4openEj",
        "_ZN12CContextData6updateEji",
        "_ZN12CContextData6updateEjf",
        "_ZN12CContextData6updateEjPv",
    ];
    let mut names = Vec::from(METHODS);
    names.push(match family {
        pw_readback_types::Family::Buffer => "_ZN12CContextDataC1Ev",
        pw_readback_types::Family::Object => "_ZN12CContextData4initEv",
    });
    if family == pw_readback_types::Family::Object {
        names.push("_Z25dataprocesser_soundEnablePvjPFbP19_vehicleconf_StructEj");
    }
    names
}
#[cfg(target_os = "nto")]
pub mod qnx {
    use super::*;
    use crate::{
        pw_readback_owner::{
            qnx::{pin_input, OwnerSymbol, PinnedInput},
            OwnerProof,
        },
        pw_readback_types::{Family, Field},
    };
    pub struct Pinned {
        getter: OwnerProof,
        methods: Vec<(&'static str, MethodOwnerProof)>,
        input: PinnedInput,
        family: Family,
    }
    fn family(family: Family) -> Result<Pinned> {
        let mut input = pin_input(OwnerSymbol::EngineGetter(family), 0)?;
        let getter =
            OwnerProof::inspect(&input.bytes, family, input.loaded, &input.loads, |at, n| {
                Ok(unsafe { core::slice::from_raw_parts(at as *const u8, n) }.to_vec())
            })?;
        let names = required_methods(family);
        let mut methods = Vec::with_capacity(names.len());
        for name in names {
            let loaded = input.resolve(name)?;
            let proof =
                MethodOwnerProof::inspect(&input.bytes, name, loaded, &input.loads, |at, n| {
                    Ok(unsafe { core::slice::from_raw_parts(at as *const u8, n) }.to_vec())
                })
                .map_err(|e| alloc::format!("PW method {name}: {e}"))?;
            methods.push((name, proof));
        }
        input.discard_file();
        Ok(Pinned {
            getter,
            methods,
            input,
            family,
        })
    }
    /// Both choices are actual structural ABI probes, never firmware identity.
    pub fn prepare() -> Result<Pinned> {
        match family(Family::Buffer) {
            Ok(proof) => Ok(proof),
            Err(buffer) => family(Family::Object).map_err(|object| {
                alloc::format!("PW ABI admission buffer={buffer}; object={object}")
            }),
        }
    }
    impl Pinned {
        pub fn family(&self) -> Family {
            self.family
        }
        pub fn method(&self, name: &str, return_kind: u32) -> Option<u64> {
            self.methods
                .iter()
                .find(|(n, _)| *n == name)?
                .1
                .bind(unsafe { libc::getpid() } as u64, return_kind)
        }
        pub fn getter(&self) -> Option<u64> {
            (unsafe { libc::getpid() } as u64 == self.input.loaded.process)
                .then(|| self.getter.original())
        }
        pub fn query(&self, method: &str, ty: &str, member: &str) -> Option<Field> {
            self.getter
                .query(unsafe { libc::getpid() } as u64, method, ty, member)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{boxed::Box, string::ToString};
    fn context() -> AbiType {
        AbiType::Pointer(Box::new(AbiType::Named {
            tag: 2,
            name: "CContextData".to_string(),
            bytes: 1,
        }))
    }
    #[test]
    fn exact_names_and_primitive_widths_required() {
        let good = [context(), AbiType::Unsigned(4), AbiType::Signed(4)];
        assert!(signature(
            "_ZN12CContextData6updateEji",
            &AbiType::Void,
            &good
        ));
        assert!(!signature(
            "_ZN12CContextData6updateEji",
            &AbiType::Signed(4),
            &good
        ));
        assert!(!signature(
            "_ZN12CContextData6updateEjf",
            &AbiType::Void,
            &good
        ));
        assert!(!signature("unknown", &AbiType::Void, &good));
        assert!(!signature(
            "_ZN12CContextData6updateEji",
            &AbiType::Void,
            &good[..2]
        ));
    }
}
