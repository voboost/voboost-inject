//! Minimal additive type/method evidence; never grants live-call admission.
use super::{Die, Dwarf, Elf};
use crate::Result;
use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AbiType {
    Void,
    Signed(u64),
    Unsigned(u64),
    Float(u64),
    Bool,
    Pointer(Box<AbiType>),
    Reference(Box<AbiType>),
    Named {
        tag: u64,
        name: String,
        bytes: u64,
    },
    Function {
        result: Box<AbiType>,
        parameters: Vec<AbiType>,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Member {
    pub name: String,
    pub offset: u64,
    pub ty: AbiType,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypeProof {
    pub name: String,
    pub bytes: u64,
    pub members: Vec<Member>,
    pub bases: usize,
    pub implicit_destructor: bool,
}
pub struct MethodProof {
    address: u64,
    code: Vec<u8>,
    pub result: AbiType,
    pub parameters: Vec<AbiType>,
}
impl MethodProof {
    pub fn address(&self) -> u64 {
        self.address
    }
    pub fn code(&self) -> &[u8] {
        &self.code
    }
}
fn attr_type<'a>(d: &'a Dwarf<'a>, mut n: &'a Die<'a>) -> Result<Option<u32>> {
    for _ in 0..24 {
        if n.ty.is_some() {
            return Ok(n.ty);
        }
        if let Some(r) = n.spec {
            n = d.get(r)?;
        } else {
            return Ok(None);
        }
    }
    Err("ABI inherited type cycle".into())
}
pub(super) fn ty(
    d: &Dwarf<'_>,
    offset: Option<u32>,
    depth: usize,
    budget: &mut usize,
) -> Result<AbiType> {
    *budget = budget.checked_sub(1).ok_or("ABI type work budget")?;
    if depth > 24 {
        return Err("ABI type depth".into());
    }
    let Some(offset) = offset else {
        return Ok(AbiType::Void);
    };
    let n = d.resolve(offset)?;
    Ok(match n.tag {
        0x24 => match (n.encoding, n.size) {
            (Some(5 | 6), Some(b)) => AbiType::Signed(b),
            (Some(7 | 8), Some(b)) => AbiType::Unsigned(b),
            (Some(4), Some(b)) => AbiType::Float(b),
            (Some(2), Some(1)) => AbiType::Bool,
            _ => return Err("ABI scalar unsupported".into()),
        },
        0xf => AbiType::Pointer(Box::new(ty(d, n.ty, depth + 1, budget)?)),
        0x10 | 0x42 => AbiType::Reference(Box::new(ty(d, n.ty, depth + 1, budget)?)),
        4 => AbiType::Named {
            tag: 4,
            name: if n.name.is_some() {
                qualified(d, n)?
            } else {
                String::new()
            },
            bytes: n.size.ok_or("ABI enum size")?,
        },
        2 | 0x13 | 0x17 => AbiType::Named {
            tag: n.tag,
            name: qualified(d, n)?,
            bytes: n.size.unwrap_or(0),
        },
        0x15 => {
            let parameters = parameters(d, n, depth + 1, budget)?;
            AbiType::Function {
                result: Box::new(ty(d, n.ty, depth + 1, budget)?),
                parameters,
            }
        }
        _ => return Err("ABI type unsupported".into()),
    })
}
fn parameters(
    d: &Dwarf<'_>,
    n: &Die<'_>,
    depth: usize,
    budget: &mut usize,
) -> Result<Vec<AbiType>> {
    let id = *d.index.get(&n.offset).ok_or("ABI parameter parent")?;
    let mut result = Vec::new();
    for p in &d.nodes {
        *budget = budget.checked_sub(1).ok_or("ABI child scan budget")?;
        if p.parent != Some(id) {
            continue;
        }
        if p.tag == 0x18 {
            return Err("ABI variadic unsupported".into());
        }
        if p.tag != 5 {
            continue;
        }
        if result.len() == 32 {
            return Err("ABI parameter bound".into());
        }
        result.push(ty(
            d,
            Some(attr_type(d, p)?.ok_or("ABI parameter type absent")?),
            depth,
            budget,
        )?);
    }
    Ok(result)
}
pub(super) fn qualified(d: &Dwarf<'_>, n: &Die<'_>) -> Result<String> {
    let mut parts = Vec::new();
    parts.push(n.name.ok_or("ABI name absent")?);
    let mut parent = n.parent;
    for _ in 0..32 {
        let Some(id) = parent else {
            parts.reverse();
            return Ok(parts.join("::"));
        };
        let p = d.nodes.get(id).ok_or("ABI namespace parent")?;
        if matches!(p.tag, 2 | 0x13 | 0x17 | 0x39) {
            parts.push(p.name.ok_or("ABI anonymous namespace")?);
        }
        parent = p.parent;
    }
    Err("ABI namespace depth".into())
}
pub(super) fn class_in_unit(
    d: &Dwarf<'_>,
    name: &str,
    budget: &mut usize,
) -> Result<Option<TypeProof>> {
    let mut result = None;
    for n in &d.nodes {
        *budget = budget.checked_sub(1).ok_or("ABI class scan budget")?;
        if !matches!(n.tag, 2 | 0x13 | 0x17 | 0x16) || n.name != name.rsplit("::").next() {
            continue;
        }
        if name.contains("::") && qualified(d, n)? != name {
            continue;
        }
        // A named typedef may authoritatively identify an anonymous C record.
        // Follow the same bounded qualifier resolver; do not infer any layout.
        let n = if n.tag == 0x16 {
            d.resolve(n.ty.ok_or("ABI typedef target")?)?
        } else {
            n
        };
        if !matches!(n.tag, 2 | 0x13 | 0x17) || n.size.is_none() {
            continue;
        }
        let id = *d.index.get(&n.offset).ok_or("ABI class parent")?;
        let mut members = Vec::new();
        let mut bases = 0;
        let mut implicit = false;

        for child in &d.nodes {
            *budget = budget.checked_sub(1).ok_or("ABI class child scan budget")?;
            if child.parent != Some(id) {
                continue;
            }
            if child.tag == 0x1c {
                bases += 1;
            }
            if child.tag == 0x2e && child.name.is_some_and(|s| s.starts_with('~')) {
                if !child.artificial {
                    return Err("ABI custom destructor unsupported".into());
                }
                implicit = true;
            }
            if child.tag == 0xd {
                if members.len() == 128 {
                    return Err("ABI member bound".into());
                }
                let offset = child
                    .location
                    .or_else(|| (n.tag == 0x17).then_some(0))
                    .ok_or("ABI member location")?;
                let mt = ty(d, child.ty, 0, budget)?;
                members.push(Member {
                    name: child.name.ok_or("ABI unnamed member")?.to_string(),
                    offset,
                    ty: mt,
                });
            }
        }
        let shape = TypeProof {
            name: name.to_string(),
            bytes: n.size.ok_or("ABI class size")?,
            members,
            bases,
            implicit_destructor: implicit,
        };
        if let Some(previous) = &mut result {
            let old: &mut TypeProof = previous;
            let old_implicit = old.implicit_destructor;
            old.implicit_destructor = shape.implicit_destructor;
            if old != &shape {
                return Err("ABI ambiguous class definition".into());
            }
            old.implicit_destructor |= old_implicit;
        } else {
            result = Some(shape);
        }
    }
    Ok(result)
}
pub fn inspect_type(file: &[u8], name: &str) -> Result<TypeProof> {
    if name.is_empty() || name.len() > 256 {
        return Err("ABI class name bound".into());
    }
    let elf = Elf::open(file)?;
    let d = Dwarf::parse(&elf, u64::MAX, name)?;
    class_in_unit(&d, name, &mut 8_000_000)?.ok_or_else(|| "ABI class absent".into())
}
fn signature(d: &Dwarf<'_>, n: &Die<'_>) -> Result<(AbiType, Vec<AbiType>)> {
    signature_limited(d, n, &mut 8_000_000)
}
fn signature_limited(
    d: &Dwarf<'_>,
    n: &Die<'_>,
    budget: &mut usize,
) -> Result<(AbiType, Vec<AbiType>)> {
    let mut selected_result = None;
    let mut selected_args = None;
    let mut current = n;
    let mut complete = false;
    for _ in 0..24 {
        if let Some(t) = current.ty {
            let observed = ty(d, Some(t), 0, budget)?;
            if selected_result.as_ref().is_some_and(|v| v != &observed) {
                return Err("ABI contradictory return type".into());
            }
            selected_result = Some(observed);
        }
        let args = parameters(d, current, 0, budget)?;
        if !args.is_empty() {
            if selected_args.as_ref().is_some_and(|v| v != &args) {
                return Err("ABI contradictory or partial parameters".into());
            }
            selected_args = Some(args);
        }
        if let Some(spec) = current.spec {
            current = d.get(spec)?;
        } else {
            complete = true;
            break;
        }
    }
    if !complete {
        return Err("ABI signature origin cycle".into());
    }
    let result = selected_result.unwrap_or(AbiType::Void);
    let args = selected_args.unwrap_or_default();
    Ok((result, args))
}
pub fn inspect_method(file: &[u8], symbol: &str) -> Result<MethodProof> {
    if symbol.is_empty() || symbol.len() > 1024 {
        return Err("ABI method name bound".into());
    }
    let elf = Elf::open(file)?;
    let (address, code) = elf.function(symbol)?;
    let d = Dwarf::parse(&elf, address, symbol)?;
    let mut found = d
        .nodes
        .iter()
        .filter(|n| n.tag == 0x2e && n.pc == Some(address) && d.linkage(n) == Some(symbol));
    let n = found.next().ok_or("ABI method definition")?;
    if found.next().is_some() {
        return Err("ABI ambiguous method".into());
    }
    let (result, args) = signature(&d, n)?;
    Ok(MethodProof {
        address,
        code: code.to_vec(),
        result,
        parameters: args,
    })
}

fn context_alias_target(symbol: &str) -> Result<&'static str> {
    match symbol {
        "_ZN12CContextDataC1Ev" | "_ZN12CContextDataC2Ev" => Ok("_ZN12CContextDataC2Ev"),
        "_ZN12CContextDataD1Ev" | "_ZN12CContextDataD2Ev" => Ok("_ZN12CContextDataD2Ev"),
        _ => Err("unsupported CContextData ABI alias".into()),
    }
}
fn admit_context_alias(address: u64, code: &[u8], target: MethodProof) -> Result<MethodProof> {
    // Equal symbol addresses alone do not establish a callable signature. The
    // genuine base variant definition must have the complete this-only shape:
    // no VTT, deleting-destructor selector, other class, or additional argument.
    let this_only = target.parameters.len() == 1
        && matches!(&target.parameters[0], AbiType::Pointer(p)
            if matches!(p.as_ref(),AbiType::Named {tag:2|0x13,name,bytes}
                if name == "CContextData" && *bytes > 0));
    if target.result != AbiType::Void || !this_only {
        return Err("CContextData alias definition signature unsupported".into());
    }
    if target.address != address || target.code != code {
        return Err("CContextData ABI variants are not identical exports".into());
    }
    Ok(target)
}
fn context_destructor_signature(d: &Dwarf<'_>, n: &Die<'_>) -> Result<Vec<AbiType>> {
    let mut work = 8_000_000usize;
    let concrete = parameters(d, n, 0, &mut work)?;
    if concrete.len() != 1 {
        return Err("D2 concrete signature is not this-only".into());
    }
    let mut current = n;
    let mut named_in_charge = false;
    for depth in 0..24 {
        if depth > 0
            && (d.linkage(current) != Some("_ZN12CContextDataD4Ev") || current.pc.is_some())
        {
            return Err("D2 abstract destructor origin unsupported".into());
        }
        if let Some(offset) = current.ty {
            if ty(d, Some(offset), 0, &mut work)? != AbiType::Void {
                return Err("D2 nonvoid origin unsupported".into());
            }
        }
        let args = parameters(d, current, 0, &mut work)?;
        if args != concrete {
            if depth == 0
                || args.len() != 2
                || args[0] != concrete[0]
                || args[1] != AbiType::Signed(4)
            {
                return Err("D2 origin parameter mismatch".into());
            }
            let parent = *d.index.get(&current.offset).ok_or("D2 origin parent")?;
            work = work
                .checked_sub(d.nodes.len())
                .ok_or("D2 origin scan budget")?;
            let extra = d
                .nodes
                .iter()
                .filter(|p| p.parent == Some(parent) && p.tag == 5)
                .nth(1)
                .ok_or("D2 in-charge parameter absent")?;
            if !extra.artificial {
                return Err("D2 extra parameter is not artificial".into());
            }
            match extra.name {
                Some("__in_chrg") => named_in_charge = true,
                None if named_in_charge && current.spec.is_none() => {}
                _ => return Err("D2 in-charge origin name unsupported".into()),
            }
        }
        if let Some(next) = current.spec {
            current = d.get(next)?;
        } else {
            return Ok(concrete);
        }
    }
    Err("D2 abstract origin cycle".into())
}
fn inspect_context_destructor_base(file: &[u8]) -> Result<MethodProof> {
    let symbol = "_ZN12CContextDataD2Ev";
    let elf = Elf::open(file)?;
    let (address, code) = elf.function(symbol)?;
    let d = Dwarf::parse(&elf, address, symbol)?;
    let mut found = d
        .nodes
        .iter()
        .filter(|n| n.tag == 0x2e && n.pc == Some(address) && d.linkage(n) == Some(symbol));
    let n = found.next().ok_or("D2 concrete DWARF definition absent")?;
    if found.next().is_some() {
        return Err("D2 ambiguous concrete definition".into());
    }
    let parameters = context_destructor_signature(&d, n)?;
    Ok(MethodProof {
        address,
        code: code.to_vec(),
        result: AbiType::Void,
        parameters,
    })
}
/// Finite Itanium complete/base variant evidence for the actual PW context.
/// Requires a genuine C2/D2 DWARF definition, its fully inherited signature,
/// and the requested C1/C2/D1/D2 export with identical address AND code extent.
/// C4/D4 declarations and deleting destructors never substitute for definitions.
/// Mapped process ownership and the context field schema remain separate proofs.
pub fn inspect_method_alias(file: &[u8], symbol: &str) -> Result<MethodProof> {
    let target_symbol = context_alias_target(symbol)?;
    let target = if target_symbol == "_ZN12CContextDataD2Ev" {
        inspect_context_destructor_base(file)?
    } else {
        inspect_method(file, target_symbol)?
    };
    let elf = Elf::open(file)?;
    let (address, code) = elf.function(symbol)?;
    admit_context_alias(address, code, target)
}

#[cfg(test)]
mod context_alias_tests {
    use super::*;
    fn destructor_dwarf() -> Dwarf<'static> {
        let nodes = alloc::vec![
            Die {
                offset: 1,
                tag: 2,
                name: Some("CContextData"),
                size: Some(32),
                ..Die::default()
            },
            Die {
                offset: 2,
                tag: 0xf,
                ty: Some(1),
                ..Die::default()
            },
            Die {
                offset: 3,
                tag: 0x24,
                encoding: Some(5),
                size: Some(4),
                ..Die::default()
            },
            Die {
                offset: 4,
                tag: 0x2e,
                linkage: Some("_ZN12CContextDataD4Ev"),
                ..Die::default()
            },
            Die {
                offset: 5,
                tag: 5,
                parent: Some(3),
                ty: Some(2),
                artificial: true,
                ..Die::default()
            },
            Die {
                offset: 6,
                tag: 5,
                parent: Some(3),
                ty: Some(3),
                artificial: true,
                ..Die::default()
            },
            Die {
                offset: 7,
                tag: 0x2e,
                spec: Some(4),
                ..Die::default()
            },
            Die {
                offset: 8,
                tag: 5,
                parent: Some(6),
                ty: Some(2),
                name: Some("this"),
                artificial: true,
                ..Die::default()
            },
            Die {
                offset: 9,
                tag: 5,
                parent: Some(6),
                ty: Some(3),
                name: Some("__in_chrg"),
                artificial: true,
                ..Die::default()
            },
            Die {
                offset: 10,
                tag: 0x2e,
                spec: Some(7),
                linkage: Some("_ZN12CContextDataD2Ev"),
                pc: Some(4),
                ..Die::default()
            },
            Die {
                offset: 11,
                tag: 5,
                parent: Some(9),
                spec: Some(8),
                ..Die::default()
            },
        ];
        let index = nodes
            .iter()
            .enumerate()
            .map(|(id, n)| (n.offset, id))
            .collect();
        Dwarf { nodes, index }
    }
    #[test]
    fn only_named_artificial_d4_in_charge_is_normalized_for_concrete_d2() {
        let good = destructor_dwarf();
        assert_eq!(
            context_destructor_signature(&good, &good.nodes[9])
                .unwrap()
                .len(),
            1
        );
        // Ordinary inspection remains strict; this exception belongs only to
        // the finite concrete destructor-variant admission path.
        assert!(signature(&good, &good.nodes[9]).is_err());
        for change in 0..7 {
            let mut d = destructor_dwarf();
            match change {
                0 => d.nodes[8].artificial = false,
                1 => d.nodes[8].name = Some("__vtt_parm"),
                2 => d.nodes[8].ty = Some(2),
                3 => d.nodes[8].name = None,
                4 => d.nodes[5].name = Some("other"),
                5 => d.nodes[6].pc = Some(8),
                _ => d.nodes[10].ty = Some(3),
            }
            assert!(
                context_destructor_signature(&d, &d.nodes[9]).is_err(),
                "origin {change}"
            );
        }
    }
    fn proof() -> MethodProof {
        MethodProof {
            address: 4,
            code: alloc::vec![0xc0, 0x03, 0x5f, 0xd6],
            result: AbiType::Void,
            parameters: alloc::vec![AbiType::Pointer(Box::new(AbiType::Named {
                tag: 2,
                name: "CContextData".into(),
                bytes: 32,
            }))],
        }
    }
    #[test]
    fn same_address_and_code_do_not_admit_wrong_alias_signature() {
        let code = proof().code;
        assert!(admit_context_alias(4, &code, proof()).is_ok());
        for change in 0..6 {
            let mut p = proof();
            match change {
                0 => p.result = AbiType::Signed(4),
                1 => p.parameters.clear(),
                2 => p.parameters.push(AbiType::Pointer(Box::new(AbiType::Void))),
                3 => {
                    p.parameters[0] = AbiType::Pointer(Box::new(AbiType::Named {
                        tag: 2,
                        name: "OtherContext".into(),
                        bytes: 32,
                    }))
                }
                4 => {
                    p.parameters[0] = AbiType::Pointer(Box::new(AbiType::Named {
                        tag: 2,
                        name: "CContextData".into(),
                        bytes: 0,
                    }))
                }
                _ => {
                    p.parameters[0] = AbiType::Reference(Box::new(AbiType::Named {
                        tag: 2,
                        name: "CContextData".into(),
                        bytes: 32,
                    }))
                }
            }
            assert!(admit_context_alias(4, &code, p).is_err(), "shape {change}");
        }
    }
    #[test]
    fn alias_requires_exact_export_extent_and_legal_variant_family() {
        let code = proof().code;
        assert!(admit_context_alias(8, &code, proof()).is_err());
        assert!(admit_context_alias(4, &code[..3], proof()).is_err());
        for invalid in [
            "_ZN12CContextDataC4Ev",
            "_ZN12CContextDataD0Ev",
            "_ZN12CContextDataD4Ev",
            "_ZN12CContextData4initEv",
            "_ZN5OtherC1Ev",
        ] {
            assert!(context_alias_target(invalid).is_err());
        }
        assert_eq!(
            context_alias_target("_ZN12CContextDataC1Ev").unwrap(),
            "_ZN12CContextDataC2Ev"
        );
        assert_eq!(
            context_alias_target("_ZN12CContextDataD1Ev").unwrap(),
            "_ZN12CContextDataD2Ev"
        );
    }
    #[test]
    #[ignore = "requires retained actual OEM engine files"]
    fn actual_context_constructor_and_destructor_aliases() {
        for variable in ["VOBOOST_PW_ALIAS_A9_ELF", "VOBOOST_PW_ALIAS_A11_ELF"] {
            let file = std::fs::read(std::env::var(variable).expect(variable)).unwrap();
            for symbol in [
                "_ZN12CContextDataC1Ev",
                "_ZN12CContextDataC2Ev",
                "_ZN12CContextDataD1Ev",
                "_ZN12CContextDataD2Ev",
            ] {
                let p = inspect_method_alias(&file, symbol).unwrap();
                assert_eq!(p.result, AbiType::Void);
                assert_eq!(p.parameters.len(), 1);
                std::println!(
                    "{variable} {symbol}: this {:?}, body {} bytes",
                    p.parameters,
                    p.code().len()
                );
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclarationProof {
    pub result: AbiType,
    pub parameters: Vec<AbiType>,
}
pub(super) fn declarations_in_unit(
    d: &Dwarf<'_>,
    linkage: &str,
    work: &mut usize,
) -> Result<Option<DeclarationProof>> {
    let mut found = None;
    for n in &d.nodes {
        *work = work.checked_sub(1).ok_or("ABI declaration scan budget")?;
        if n.tag != 0x2e || d.linkage(n) != Some(linkage) {
            continue;
        }
        let (result, parameters) = signature_limited(d, n, work)?;
        let p = DeclarationProof { result, parameters };
        if found.as_ref().is_some_and(|old| old != &p) {
            return Err("ABI conflicting declarations".into());
        }
        found = Some(p);
    }
    Ok(found)
}
pub fn inspect_declaration(file: &[u8], class: &str, linkage: &str) -> Result<DeclarationProof> {
    if class.len() > 256 || linkage.is_empty() || linkage.len() > 1024 {
        return Err("ABI declaration name bound".into());
    }
    inspect_type(file, class)?;
    let elf = Elf::open(file)?;
    let d = Dwarf::parse(&elf, u64::MAX - 3, linkage)?;
    declarations_in_unit(&d, linkage, &mut 8_000_000)?
        .ok_or_else(|| "ABI declaration absent".into())
}
pub struct ExportCode {
    pub address: u64,
    pub code: Vec<u8>,
    pub calls: Vec<(usize, Option<String>)>,
}
pub fn export_code(file: &[u8], name: &str) -> Result<ExportCode> {
    use alloc::collections::BTreeMap;
    let elf = Elf::open(file)?;
    let (address, code) = elf.function_limited(name, 65536)?;
    let mut sites = Vec::new();
    let mut names: BTreeMap<u64, Option<String>> = BTreeMap::new();
    let mut slots = BTreeMap::new();
    for (i, raw) in code.as_chunks::<4>().0.iter().enumerate() {
        let op = u32::from_le_bytes(*raw);
        if !matches!(op & 0xfc000000, 0x94000000 | 0x14000000) {
            continue;
        }
        let off = i * 4;
        let delta = (((op & 0x03ffffff) as i64) << 38) >> 36;
        let target = address
            .checked_add(off as u64)
            .and_then(|pc| pc.checked_add_signed(delta))
            .ok_or("ABI call target")?;
        if op & 0xfc000000 == 0x14000000
            && target >= address
            && target < address + code.len() as u64
        {
            continue;
        }
        if sites.len() == 4096 {
            return Err("ABI callsite bound".into());
        }
        sites.push((off, target));
        names.entry(target).or_insert(None);
        if let Ok(plt) = elf.code(target, 16) {
            if let Some(slot) = super::plt_slot(plt, target) {
                slots.insert(slot, target);
            }
        }
    }
    for section in elf.sections.iter().filter(|s| s.kind == 4) {
        let symbols = elf
            .sections
            .get(section.link)
            .ok_or("ABI relocation symbols")?;
        let strings = elf
            .sections
            .get(symbols.link)
            .ok_or("ABI relocation strings")?
            .data;
        for r in section.data.as_chunks::<24>().0.iter() {
            elf.spend()?;
            let slot = super::num(r, 0, 8)?;
            let Some(target) = slots.get(&slot) else {
                continue;
            };
            let info = super::num(r, 8, 8)?;
            if info as u32 != 1026 {
                continue;
            }
            let index = (info >> 32) as usize;
            let start = index.checked_mul(24).ok_or("ABI symbol index")?;
            let symbol = symbols
                .data
                .get(start..start.checked_add(24).ok_or("ABI symbol index")?)
                .ok_or("ABI symbol index")?;
            let text = super::text(strings, super::num(symbol, 0, 4)? as usize)?;
            if text.len() > 1024 {
                return Err("ABI symbol name bound".into());
            }
            names.insert(*target, Some(text.to_string()));
        }
    }
    for section in elf.sections.iter().filter(|s| s.kind == 11) {
        let strings = elf
            .sections
            .get(section.link)
            .ok_or("ABI symbol strings")?
            .data;
        for symbol in section.data.as_chunks::<24>().0.iter() {
            elf.spend()?;
            let target = super::num(symbol, 8, 8)?;
            if !names.contains_key(&target) || symbol[4] & 15 != 2 || super::num(symbol, 6, 2)? == 0
            {
                continue;
            }
            let text = super::text(strings, super::num(symbol, 0, 4)? as usize)?;
            if text.len() > 1024 {
                return Err("ABI symbol name bound".into());
            }
            let entry = names.get_mut(&target).ok_or("ABI symbol target")?;
            if entry.is_none() {
                *entry = Some(text.to_string());
            }
        }
    }
    let calls = sites
        .into_iter()
        .map(|(off, target)| (off, names.get(&target).cloned().flatten()))
        .collect();
    Ok(ExportCode {
        address,
        code: code.to_vec(),
        calls,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn dwarf(nodes: Vec<Die<'static>>) -> Dwarf<'static> {
        let index = nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (n.offset, i))
            .collect();
        Dwarf { nodes, index }
    }
    #[test]
    fn signature_origin_variadic_and_missing_types() {
        let mut d = dwarf(alloc::vec![
            Die {
                offset: 0,
                tag: 0x2e,
                spec: Some(1),
                ..Die::default()
            },
            Die {
                offset: 1,
                tag: 0x2e,
                spec: Some(2),
                ..Die::default()
            },
            Die {
                offset: 2,
                tag: 0x2e,
                ..Die::default()
            },
            Die {
                offset: 3,
                tag: 0x24,
                size: Some(4),
                encoding: Some(5),
                ..Die::default()
            },
            Die {
                offset: 4,
                tag: 5,
                parent: Some(2),
                ty: Some(3),
                ..Die::default()
            }
        ]);
        assert_eq!(
            signature(&d, &d.nodes[0]).unwrap(),
            (AbiType::Void, alloc::vec![AbiType::Signed(4)])
        );
        d.nodes[4].ty = None;
        assert!(signature(&d, &d.nodes[0]).is_err());
        d.nodes[4].ty = Some(3);
        d.nodes.push(Die {
            offset: 5,
            tag: 0x18,
            parent: Some(2),
            ..Die::default()
        });
        assert!(signature(&d, &d.nodes[0]).is_err());
        d.nodes.pop();
        d.nodes.push(Die {
            offset: 5,
            tag: 5,
            parent: Some(0),
            ty: Some(3),
            ..Die::default()
        });
        d.nodes.push(Die {
            offset: 6,
            tag: 5,
            parent: Some(2),
            ty: Some(3),
            ..Die::default()
        });
        assert!(signature(&d, &d.nodes[0]).is_err());
    }
    #[test]
    fn class_work_budget_covers_all_candidate_child_scans() {
        let nodes = (0..20)
            .map(|i| Die {
                offset: i,
                tag: 2,
                name: Some("Example"),
                size: Some(8),
                ..Die::default()
            })
            .collect();
        let d = dwarf(nodes);
        assert!(class_in_unit(&d, "Example", &mut 10)
            .unwrap_err()
            .contains("budget"));
    }
    #[test]
    #[ignore = "uses retained actual OEM files, never bundled"]
    fn actual_resource_id_classes_and_getter_signatures() {
        for name in ["VOBOOST_ABI_A9_GAUGE", "VOBOOST_ABI_A11_GAUGE"] {
            let path = std::env::var(name).expect(name);
            let file = std::fs::read(path).unwrap();
            let p = inspect_type(&file, "kanzi::ResourceID").unwrap();
            assert_eq!(p.bytes, 48);
            assert_eq!(p.bases, 0);
            assert_eq!(p.members.len(), 3);
            assert_eq!(p.members[0].name, "m_id");
            assert_eq!(p.members[0].offset, 0);
            assert_eq!(p.members[1].offset, 32);
            assert_eq!(p.members[2].offset, 40);
            std::println!("{name} ResourceID {p:?}");
        }
        for (name, symbol) in [
            ("VOBOOST_PW_A9_ELF", super::super::A9),
            ("VOBOOST_PW_A11_ELF", super::super::A11),
        ] {
            let file = std::fs::read(std::env::var(name).unwrap()).unwrap();
            let p = inspect_method(&file, symbol).unwrap();
            assert!(!p.parameters.is_empty());
            std::println!(
                "{name} method result {:?} args {:?}",
                p.result,
                p.parameters
            );
        }
    }
    #[test]
    fn absent_and_overlong_requests_reject() {
        assert!(inspect_type(&[], "kanzi::ResourceID").is_err());
        assert!(inspect_method(&[], "x").is_err());
        assert!(inspect_type(&[], &"x".repeat(257)).is_err());
    }
}
