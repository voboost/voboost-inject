//! Small structural ABI witnesses, not live-call authorization.
//!
//! The find witness records the AAPCS64 indirect-result register convention;
//! its return type, virtual target, object layout and mapped owners require
//! independent admission. Constructor/contains signatures are separate evidence.
use crate::pw_readback_types::{
    export_code, inspect_declaration, AbiType, DeclarationProof, ExportCode,
};
use crate::Result;
use alloc::vec::Vec;

pub const FIND: &str = "_ZNK5kanzi18ResourceDictionary4findB5cxx11ERKNS_10ResourceIDE";
pub const DESTROY: &str = "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev";
pub const DATA: &str = "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE4dataEv";
pub const SIZE: &str = "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE4sizeEv";
pub const CONSTRUCTOR: &str = "_ZN5kanzi10ResourceIDC1EPKc";
pub const CONTAINS: &str = "_ZNK5kanzi18ResourceDictionary8containsERKNS_10ResourceIDE";

/// Offline ABI evidence. Mapped-owner pinning, GNU exception-provider admission,
/// constructor unwind cleanup and the bounded behavioral probe are still required.
pub struct TypedCallEvidence {
    witnesses: CallEvidence,
    constructor: u64,
    contains: u64,
}
impl TypedCallEvidence {
    pub fn address(&self, symbol: &str) -> Option<u64> {
        match symbol {
            CONSTRUCTOR => Some(self.constructor),
            CONTAINS => Some(self.contains),
            _ => self.witnesses.address(symbol),
        }
    }
}
fn named(ty: &AbiType, name: &str, bytes: Option<u64>) -> bool {
    matches!(ty, AbiType::Named {tag: 2 | 0x13, name: n, bytes: b} if n == name && bytes.is_none_or(|v| v == *b))
}
fn constructor_signature(proof: &DeclarationProof) -> bool {
    proof.result == AbiType::Void
        && proof.parameters.len() == 2
        && matches!(&proof.parameters[0], AbiType::Pointer(t) if named(t,"kanzi::ResourceID",Some(48)))
        // AArch64 targets may compile plain char unsigned; the C4 PKc linkage
        // identifies char while DWARF contributes the one-byte pointee width.
        && matches!(&proof.parameters[1], AbiType::Pointer(t) if matches!(t.as_ref(),AbiType::Signed(1)|AbiType::Unsigned(1)))
}
/// The executable supplies DWARF; the two actual providers supply exported code.
/// Itanium C4 constructor declaration covers C1 because the independently proved
/// ResourceID class has no bases. This does not infer an implicit destructor.
pub fn inspect_typed(types: &[u8], core: &[u8], gnu: &[u8]) -> Result<TypedCallEvidence> {
    let _layout = crate::resource_content_types::inspect(types)?;
    let ctor = inspect_declaration(types, "kanzi::ResourceID", "_ZN5kanzi10ResourceIDC4EPKc")?;
    if !constructor_signature(&ctor) {
        return Err("ResourceID constructor signature unsupported".into());
    }
    let witnesses = inspect(core, gnu)?;
    let contains = export_code(core, CONTAINS)?;
    contains_bool(&contains)?;
    Ok(TypedCallEvidence {
        witnesses,
        constructor: export_code(core, CONSTRUCTOR)?.address,
        contains: contains.address,
    })
}

pub struct CallEvidence {
    find: u64,
    destroy: u64,
    data: u64,
    size: u64,
}
impl CallEvidence {
    pub fn address(&self, symbol: &str) -> Option<u64> {
        match symbol {
            FIND => Some(self.find),
            DESTROY => Some(self.destroy),
            DATA => Some(self.data),
            SIZE => Some(self.size),
            _ => None,
        }
    }
}
fn words(code: &[u8]) -> Result<Vec<u32>> {
    if code.is_empty() || code.len() > 256 || !code.len().is_multiple_of(4) {
        return Err("resource ABI body bound".into());
    }
    Ok(code
        .as_chunks::<4>()
        .0
        .iter()
        .map(|v| u32::from_le_bytes(*v))
        .collect())
}
fn getter(code: &[u8], offset: u32) -> Result<()> {
    let ops = words(code)?;
    // LDR X0,[X0,#offset] followed by RET: no calls, stores or alternate paths.
    if ops.len() != 2 || ops[0] != 0xf9400000 | ((offset / 8) << 10) || ops[1] != 0xd65f03c0 {
        return Err("GNU string leaf getter unsupported".into());
    }
    Ok(())
}
fn signed_branch(op: u32, bits: u32, scale: u32) -> i64 {
    ((i64::from(op) << (64 - bits)) >> (64 - bits)) << scale
}
fn stack_restore(op: u32) -> bool {
    let base_sp = (op >> 5) & 31 == 31;
    // 64-bit LDR unsigned-immediate, or LDP offset/post-index. Neither may
    // overwrite X0: the previously established bool must survive to RET.
    base_sp
        && ((op & 0xffc00000 == 0xf9400000 && op & 31 != 0)
            || (matches!(op & 0xffc00000, 0xa9400000 | 0xa8c00000)
                && op & 31 != 0
                && (op >> 10) & 31 != 0))
}
fn contains_bool(proof: &ExportCode) -> Result<()> {
    let ops = words(&proof.code)?;
    let mut epilogues = Vec::new();
    let mut values = 0;
    for (at, op) in ops.iter().enumerate() {
        if *op != 0xd65f03c0 {
            continue;
        }
        let mut start = at;
        while start > 0 && (stack_restore(ops[start - 1]) || ops[start - 1] == 0xd503201f) {
            start -= 1;
        }
        if start == 0 {
            return Err("contains bool initializer absent".into());
        }
        start -= 1;
        values |= match ops[start] {
            0x52800000 => 1, // MOV W0,#0
            0x52800020 => 2, // MOV W0,#1
            _ => return Err("contains return is not normalized bool".into()),
        };
        epilogues.push((start, at));
    }
    if epilogues.len() != 2 || values != 3 {
        return Err("contains bool paths unsupported".into());
    }
    for (at, op) in ops.iter().copied().enumerate() {
        let target = if op & 0xfc000000 == 0x14000000 {
            Some(at as i64 * 4 + signed_branch(op & 0x3ffffff, 26, 2))
        } else if op & 0xff000000 == 0x54000000 || op & 0x7e000000 == 0x34000000 {
            Some(at as i64 * 4 + signed_branch((op >> 5) & 0x7ffff, 19, 2))
        } else if op & 0x7e000000 == 0x36000000 {
            Some(at as i64 * 4 + signed_branch((op >> 5) & 0x3fff, 14, 2))
        } else {
            None
        };
        if let Some(target) = target {
            if target < 0
                || target >= proof.code.len() as i64
                || target % 4 != 0
                || epilogues
                    .iter()
                    .any(|(start, end)| target > (*start * 4) as i64 && target <= (*end * 4) as i64)
            {
                return Err("contains branch bypasses bool initializer".into());
            }
        }
        // Register exits, authenticated branches and ERET can bypass the bool
        // initializer. Only an ordinary BLR call or checked RET X30 may remain.
        if op & 0xfe000000 == 0xd6000000 && op & 0xfffffc1f != 0xd63f0000 && op != 0xd65f03c0 {
            return Err("contains indirect exit unsupported".into());
        }
    }
    if proof.calls.len() != 2
        || !proof.calls.iter().all(|(_, name)| {
            name.as_deref().is_some_and(|name| {
                name == CONTAINS
                    || (name.starts_with("_ZNKSt10_HashtableIN5kanzi10ResourceIDE")
                        && name.ends_with("4findERS3_"))
            })
        })
    {
        return Err("contains genuine lookup callees absent".into());
    }
    Ok(())
}
fn destructor(proof: &ExportCode) -> Result<()> {
    let ops = words(&proof.code)?;
    let active: Vec<_> = ops
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, op)| *op != 0xd503201f)
        .collect();
    if active.len() != 6 {
        return Err("GNU string destructor shape".into());
    }
    let [(load_at, load), (_, cmp), (branch_at, branch), (_, mov), (tail_at, tail), (ret_at, ret)] =
        active[..]
    else {
        return Err("GNU string destructor instruction count".into());
    };
    let scratch = load & 31;
    // LDR Xscratch,[X0],#16 advances this to its inline buffer.
    if load_at != 0
        || !(1..=17).contains(&scratch)
        || load & !31 != 0xf8410400
        || cmp != 0xeb00001f | (scratch << 5)
        || branch & 0xff00001f != 0x54000000
        || mov != 0xaa0003e0 | (scratch << 16)
        || tail & 0xfc000000 != 0x14000000
        || ret != 0xd65f03c0
    {
        return Err("GNU string destructor semantics unsupported".into());
    }
    let destination = (branch_at * 4) as i64 + signed_branch((branch >> 5) & 0x7ffff, 19, 2);
    if destination != (ret_at * 4) as i64
        || proof.calls.len() != 1
        || proof.calls[0].0 != tail_at * 4
        || proof.calls[0].1.as_deref() != Some("_ZdlPv")
    {
        return Err("GNU string destructor delete/inline path unproved".into());
    }
    Ok(())
}
fn find_sret(proof: &ExportCode) -> Result<()> {
    let ops = words(&proof.code)?;
    // The observed wrapper preserves X8 across its sole virtual dispatch and
    // returns that same pointer in X0. This is intentionally only a witness:
    // it cannot prove the virtual implementation constructs a GNU string.
    let saves: Vec<_> = ops
        .iter()
        .enumerate()
        .filter(|(_, op)| **op & !31 == 0xaa0803e0)
        .collect();
    if saves.len() != 1 {
        return Err("resource find indirect result save".into());
    }
    let (save_at, save) = saves[0];
    let register = save & 31;
    if !(19..=28).contains(&register) {
        return Err("resource find result register".into());
    }
    let returns: Vec<_> = ops
        .iter()
        .enumerate()
        .filter(|(_, op)| **op == 0xd65f03c0)
        .collect();
    let dispatch: Vec<_> = ops
        .iter()
        .enumerate()
        .filter(|(_, op)| **op & 0xfffffc1f == 0xd63f0000)
        .collect();
    if returns.len() != 1 || dispatch.len() != 1 {
        return Err("resource find dispatch/return shape".into());
    }
    let (dispatch_at, _) = dispatch[0];
    let (ret_at, _) = returns[0];
    let restore = 0xaa0003e0 | (register << 16);
    let restored = ops
        .iter()
        .enumerate()
        .any(|(at, op)| at > dispatch_at && at < ret_at && *op == restore);
    if save_at >= dispatch_at || dispatch_at >= ret_at || !restored {
        return Err("resource find result preservation absent".into());
    }
    Ok(())
}
pub fn inspect(core: &[u8], gnu: &[u8]) -> Result<CallEvidence> {
    let data = export_code(gnu, DATA)?;
    getter(&data.code, 0)?;
    let size = export_code(gnu, SIZE)?;
    getter(&size.code, 8)?;
    let destroy = export_code(gnu, DESTROY)?;
    destructor(&destroy)?;
    let find = export_code(core, FIND)?;
    find_sret(&find)?;
    Ok(CallEvidence {
        find: find.address,
        destroy: destroy.address,
        data: data.address,
        size: size.address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    fn code(ops: &[u32]) -> Vec<u8> {
        ops.iter().flat_map(|v| v.to_le_bytes()).collect()
    }
    #[test]
    fn getters_reject_store_wrong_offset_and_extra_instruction() {
        assert!(getter(&code(&[0xf9400000, 0xd65f03c0]), 0).is_ok());
        assert!(getter(&code(&[0xf9400400, 0xd65f03c0]), 8).is_ok());
        for bad in [
            vec![0xf9000000, 0xd65f03c0],
            vec![0xf9400400, 0xd65f03c0],
            vec![0xf9400000, 0xd503201f, 0xd65f03c0],
        ] {
            assert!(getter(&code(&bad), 0).is_err());
        }
    }
    #[test]
    fn destructor_requires_actual_delete_and_correct_inline_branch() {
        let mut p = ExportCode {
            address: 1,
            code: code(&[
                0xf8410401, 0xeb00003f, 0x54000080, 0xaa0103e0, 0x14000001, 0xd503201f, 0xd65f03c0,
                0xd503201f,
            ]),
            calls: vec![(16, Some("_ZdlPv".into()))],
        };
        assert!(destructor(&p).is_ok());
        p.calls[0].1 = None;
        assert!(destructor(&p).is_err());
        p.calls[0].1 = Some("_ZdlPv".into());
        p.code[8..12].copy_from_slice(&0x54000060u32.to_le_bytes());
        assert!(destructor(&p).is_err());
        for register in [19, 30] {
            p.code = code(&[
                0xf8410400 | register,
                0xeb00001f | (register << 5),
                0x54000080,
                0xaa0003e0 | (register << 16),
                0x14000001,
                0xd503201f,
                0xd65f03c0,
                0xd503201f,
            ]);
            assert!(
                destructor(&p).is_err(),
                "must preserve callee-saved registers and LR"
            );
        }
    }
    #[test]
    fn contains_rejects_branch_into_uninitialized_return_and_nonbool() {
        let mut p = ExportCode {
            address: 1,
            code: code(&[
                0x94000001, 0x94000001, 0xb4000060, 0x52800020, 0xd65f03c0, 0x52800000, 0xd65f03c0,
            ]),
            calls: vec![
                (
                    0,
                    Some("_ZNKSt10_HashtableIN5kanzi10ResourceIDE4findERS3_".into()),
                ),
                (4, Some(CONTAINS.into())),
            ],
        };
        assert!(contains_bool(&p).is_ok());
        p.code[8..12].copy_from_slice(&0xb4000080u32.to_le_bytes());
        assert!(contains_bool(&p).is_err());
        p.code[8..12].copy_from_slice(&0xb4000060u32.to_le_bytes());
        p.code[12..16].copy_from_slice(&0x52800040u32.to_le_bytes());
        assert!(contains_bool(&p).is_err());
    }
    #[test]
    #[ignore = "requires retained actual OEM files"]
    fn actual_resource_calls() {
        let core = std::fs::read(std::env::var("VOBOOST_RESOURCE_CORE_ELF").unwrap()).unwrap();
        let gnu = std::fs::read(std::env::var("VOBOOST_RESOURCE_GNU_ELF").unwrap()).unwrap();
        let p = inspect(&core, &gnu).unwrap();
        for name in [FIND, DESTROY, DATA, SIZE] {
            assert!(p.address(name).is_some());
        }
        let contains = export_code(&core, CONTAINS).unwrap();
        contains_bool(&contains).unwrap();
        if let Ok(path) = std::env::var("VOBOOST_RESOURCE_TYPES_ELF") {
            let types = std::fs::read(path).unwrap();
            std::println!(
                "ctor declaration {:?}",
                inspect_declaration(&types, "kanzi::ResourceID", "_ZN5kanzi10ResourceIDC4EPKc")
                    .unwrap()
            );
            let typed = inspect_typed(&types, &core, &gnu).unwrap();
            for name in [CONSTRUCTOR, CONTAINS, FIND, DESTROY, DATA, SIZE] {
                assert!(typed.address(name).is_some());
            }
        }
    }
}
