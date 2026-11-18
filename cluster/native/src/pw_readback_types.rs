//! Bounded DWARF4 proof for the two actual PW getter ABI shapes. No firmware
//! identity gates. A proof describes file bytes, not a live mapped owner.
use crate::Result;
use alloc::{collections::BTreeMap, vec::Vec};
#[path = "bounded_abi.rs"]
mod abi;
#[path = "pw_a9_copy_proof.rs"]
mod copy_proof;
#[path = "bounded_layout.rs"]
mod layout;
pub use abi::{
    export_code, inspect_declaration, inspect_method, inspect_method_alias, inspect_type, AbiType,
    DeclarationProof, ExportCode, Member, MethodProof, TypeProof,
};
pub use layout::{inspect_field_path, LayoutField, LayoutKind};
const A9: &str = "_ZN12CContextData7getDataEjPvj";
const A11: &str = "_ZN12CContextData7getDataEjP15CTupMemTemplate";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    Buffer,
    Object,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Field {
    pub kind: u32,
    pub bytes: u32,
    pub offset: u32,
    pub count: u32,
}
pub struct Proof {
    family: Family,
    address: u64,
    code: Vec<u8>,
    fields: Vec<(&'static str, &'static str, Field)>,
}
impl Proof {
    pub fn address(&self) -> u64 {
        self.address
    }
    pub fn code(&self) -> &[u8] {
        &self.code
    }
    pub fn query(&self, method: &str, ty: &str, member: &str) -> Option<Field> {
        if method
            != match self.family {
                Family::Buffer => A9,
                Family::Object => A11,
            }
        {
            return None;
        }
        self.fields
            .iter()
            .find(|(t, m, _)| *t == ty && *m == member)
            .map(|v| v.2)
    }
}
fn num(b: &[u8], at: usize, n: usize) -> Result<u64> {
    let end = at.checked_add(n).ok_or("offset overflow")?;
    let data = b.get(at..end).ok_or("ELF/DWARF bounds")?;
    if n > 8 {
        return Err("integer width".into());
    }
    Ok(data
        .iter()
        .enumerate()
        .fold(0, |v, (i, x)| v | ((*x as u64) << (8 * i))))
}
fn plt_slot(code: &[u8], address: u64) -> Option<u64> {
    let a = num(code, 0, 4).ok()? as u32;
    let l = num(code, 4, 4).ok()? as u32;
    let add = num(code, 8, 4).ok()? as u32;
    let branch = num(code, 12, 4).ok()? as u32;
    let base = a & 31;
    let loaded = l & 31;
    if a & 0x9f000000 != 0x90000000
        || l & 0xffc00000 != 0xf9400000
        || ((l >> 5) & 31) != base
        || add & 0xffc00000 != 0x91000000
        || add & 31 != base
        || ((add >> 5) & 31) != base
        || ((add >> 10) & 0xfff) != ((l >> 10) & 0xfff) * 8
        || branch & 0xfffffc1f != 0xd61f0000
        || ((branch >> 5) & 31) != loaded
    {
        return None;
    }
    let imm = (((a >> 5) & 0x7ffff) << 2) | ((a >> 29) & 3);
    let delta = (((imm as i64) << 43) >> 43) << 12;
    (address & !4095)
        .checked_add_signed(delta)?
        .checked_add(((l >> 10) & 0xfff) as u64 * 8)
}
fn text(b: &[u8], at: usize) -> Result<&str> {
    let tail = b.get(at..).ok_or("string offset")?;
    let len = tail
        .iter()
        .take(65536)
        .position(|c| *c == 0)
        .ok_or("string bound")?;
    core::str::from_utf8(&tail[..len]).map_err(|_| "string encoding".into())
}
#[derive(Clone)]
struct Section<'a> {
    name: &'a str,
    kind: u32,
    link: usize,
    entry: usize,
    data: &'a [u8],
}
struct Elf<'a> {
    file: &'a [u8],
    sections: Vec<Section<'a>>,
    scan_budget: core::cell::Cell<usize>,
}
fn metadata_work(sections: &[Section<'_>], limit: usize) -> Result<()> {
    let mut work = 0usize;
    for section in sections.iter().filter(|s| matches!(s.kind, 4 | 11)) {
        if section.entry != 24 || section.data.len() % 24 != 0 {
            return Err("ELF metadata entry size".into());
        }
        work = work
            .checked_add(section.data.len() / 24)
            .filter(|v| *v <= limit)
            .ok_or("ELF metadata work budget")?;
    }
    Ok(())
}
impl<'a> Elf<'a> {
    fn open(file: &'a [u8]) -> Result<Self> {
        if file.len() > 64 * 1024 * 1024
            || file.get(..6) != Some(b"\x7fELF\x02\x01")
            || num(file, 18, 2)? != 183
            || num(file, 58, 2)? != 64
        {
            return Err("unsupported ELF layout".into());
        }
        let at = usize::try_from(num(file, 40, 8)?).map_err(|_| "section offset")?;
        let count = num(file, 60, 2)? as usize;
        let strings = num(file, 62, 2)? as usize;
        if count == 0 || count > 4096 || strings >= count {
            return Err("ELF sections unavailable".into());
        }
        let header = |i: usize| -> Result<&[u8]> {
            file.get(
                at.checked_add(i.checked_mul(64).ok_or("section overflow")?)
                    .ok_or("section overflow")?
                    ..at.checked_add((i + 1) * 64).ok_or("section overflow")?,
            )
            .ok_or_else(|| "section bounds".into())
        };
        let data = |h: &[u8]| -> Result<&'a [u8]> {
            if num(h, 8, 8)? & 0x800 != 0 {
                return Err("compressed DWARF unsupported".into());
            }
            if num(h, 4, 4)? == 8 {
                return Ok(&[]);
            }
            let start = usize::try_from(num(h, 24, 8)?).map_err(|_| "section data offset")?;
            let len = usize::try_from(num(h, 32, 8)?).map_err(|_| "section data size")?;
            file.get(start..start.checked_add(len).ok_or("section data overflow")?)
                .ok_or_else(|| "section data bounds".into())
        };
        let names = data(header(strings)?)?;
        let mut sections = Vec::new();
        for i in 0..count {
            let h = header(i)?;
            sections.push(Section {
                name: text(names, num(h, 0, 4)? as usize)?,
                kind: num(h, 4, 4)? as u32,
                link: num(h, 40, 4)? as usize,
                entry: num(h, 56, 8)? as usize,
                data: data(h)?,
            });
        }
        metadata_work(&sections, 250000)?;
        Ok(Self {
            file,
            sections,
            scan_budget: core::cell::Cell::new(1_000_000),
        })
    }
    fn spend(&self) -> Result<()> {
        let next = self
            .scan_budget
            .get()
            .checked_sub(1)
            .ok_or("ELF scan work budget")?;
        self.scan_budget.set(next);
        Ok(())
    }
    fn section(&self, name: &str) -> Result<&'a [u8]> {
        let mut found = self.sections.iter().filter(|s| s.name == name);
        let value = found.next().ok_or("required DWARF section absent")?.data;
        if found.next().is_some() {
            return Err("duplicate section".into());
        }
        Ok(value)
    }
    fn function(&self, name: &str) -> Result<(u64, &'a [u8])> {
        self.function_limited(name, 4096)
    }
    fn function_limited(&self, name: &str, maximum: u64) -> Result<(u64, &'a [u8])> {
        let mut found = None;
        for section in self.sections.iter().filter(|s| s.kind == 11) {
            if section.entry != 24
                || section.data.len() % 24 != 0
                || section.data.len() / 24 > 250000
            {
                return Err("symbol bounds".into());
            }
            let names = self
                .sections
                .get(section.link)
                .ok_or("symbol strings")?
                .data;
            for entry in section.data.as_chunks::<24>().0.iter() {
                self.spend()?;
                let off = num(entry, 0, 4)? as usize;
                if off >= names.len() {
                    return Err("symbol name bounds".into());
                }
                let end = off.checked_add(name.len()).ok_or("symbol name overflow")?;
                if names.get(off..end) != Some(name.as_bytes()) || names.get(end) != Some(&0) {
                    continue;
                }
                if entry[4] & 15 != 2 || num(entry, 6, 2)? == 0 {
                    continue;
                }
                let address = num(entry, 8, 8)?;
                let size = num(entry, 16, 8)?;
                if size == 0 || size > maximum || size % 4 != 0 {
                    return Err("getter body bound".into());
                }
                let value = (address, self.code(address, size as usize)?);
                if found.replace(value).is_some() {
                    return Err("ambiguous getter".into());
                }
            }
        }
        found.ok_or_else(|| "getter export absent".into())
    }
    fn code(&self, address: u64, size: usize) -> Result<&'a [u8]> {
        let base = num(self.file, 32, 8)? as usize;
        let count = num(self.file, 56, 2)? as usize;
        if num(self.file, 54, 2)? != 56 || count > 128 {
            return Err("program headers".into());
        }
        for i in 0..count {
            let at = base.checked_add(i * 56).ok_or("program header overflow")?;
            if num(self.file, at, 4)? != 1 || num(self.file, at + 4, 4)? & 1 == 0 {
                continue;
            }
            let va = num(self.file, at + 16, 8)?;
            let files = num(self.file, at + 32, 8)?;
            if address < va {
                continue;
            }
            let relative = address - va;
            if relative
                .checked_add(size as u64)
                .is_none_or(|end| end > files)
            {
                continue;
            }
            let off = num(self.file, at + 8, 8)?
                .checked_add(relative)
                .ok_or("code offset")?;
            return self
                .file
                .get(off as usize..(off as usize).checked_add(size).ok_or("code overflow")?)
                .ok_or_else(|| "code bounds".into());
        }
        Err("getter outside executable file segment".into())
    }
    fn call_name(&self, address: u64) -> Option<&'a str> {
        let code = self.code(address, 16).ok()?;
        let slot = plt_slot(code, address)?;
        for reloc in self
            .sections
            .iter()
            .filter(|s| s.kind == 4 && s.entry == 24)
        {
            let symbols = self.sections.get(reloc.link)?;
            let strings = self.sections.get(symbols.link)?.data;
            for r in reloc.data.as_chunks::<24>().0.iter() {
                self.spend().ok()?;
                if num(r, 0, 8).ok()? != slot || num(r, 8, 8).ok()? as u32 != 1026 {
                    continue;
                }
                let index = (num(r, 8, 8).ok()? >> 32) as usize;
                let sym = symbols
                    .data
                    .get(index.checked_mul(24)?..index.checked_add(1)?.checked_mul(24)?)?;
                return text(strings, num(sym, 0, 4).ok()? as usize).ok();
            }
        }
        None
    }
}
struct Cursor<'a> {
    b: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn number(&mut self, n: usize) -> Result<u64> {
        let v = num(self.b, self.at, n)?;
        self.at = self.at.checked_add(n).ok_or("cursor overflow")?;
        Ok(v)
    }
    fn uleb(&mut self) -> Result<u64> {
        let mut v = 0u64;
        for i in 0..10 {
            let b = self.number(1)?;
            if i == 9 && b > 1 {
                return Err("ULEB overflow".into());
            }
            v |= (b & 127) << (i * 7);
            if b & 128 == 0 {
                return Ok(v);
            }
        }
        Err("ULEB bound".into())
    }
    fn sleb(&mut self) -> Result<i64> {
        let mut v = 0u64;
        for i in 0..10 {
            let b = self.number(1)?;
            if i == 9 && b != 0 && b != 127 {
                return Err("SLEB overflow".into());
            }
            v |= (b & 127) << (i * 7);
            if b & 128 == 0 {
                if i < 9 && b & 64 != 0 {
                    v |= (!0u64) << ((i + 1) * 7);
                }
                return Ok(v as i64);
            }
        }
        Err("SLEB bound".into())
    }
    fn skip(&mut self, n: usize) -> Result<()> {
        self.at = self
            .at
            .checked_add(n)
            .filter(|v| *v <= self.b.len())
            .ok_or("block bounds")?;
        Ok(())
    }
}
#[derive(Default)]
struct Die<'a> {
    offset: u32,
    tag: u64,
    parent: Option<usize>,
    name: Option<&'a str>,
    linkage: Option<&'a str>,
    ty: Option<u32>,
    spec: Option<u32>,
    size: Option<u64>,
    location: Option<u64>,
    encoding: Option<u64>,
    upper: Option<u64>,
    count: Option<u64>,
    pc: Option<u64>,
    artificial: bool,
}
struct Dwarf<'a> {
    nodes: Vec<Die<'a>>,
    index: BTreeMap<u32, usize>,
}
#[derive(Clone)]
struct Abbrev {
    tag: u64,
    children: bool,
    attrs: Vec<(u64, u64)>,
}
enum Value<'a> {
    Number(u64),
    Text(&'a str),
    Reference(u32),
    Other,
}
fn form<'a>(c: &mut Cursor<'a>, f: u64, base: usize, strings: &'a [u8]) -> Result<Value<'a>> {
    use Value::*;
    Ok(match f {
        1 => Number(c.number(8)?),
        5 => Number(c.number(2)?),
        6 | 0x17 => Number(c.number(4)?),
        7 => Number(c.number(8)?),
        0xb | 0xc => Number(c.number(1)?),
        0xf => Number(c.uleb()?),
        0xd => {
            let v = c.sleb()?;
            if v < 0 {
                Other
            } else {
                Number(v as u64)
            }
        }
        8 => {
            let s = text(c.b, c.at)?;
            c.skip(s.len() + 1)?;
            Text(s)
        }
        0xe => Text(text(strings, c.number(4)? as usize)?),
        0x10 => Reference(c.number(4)? as u32),
        0x11..=0x15 => {
            let n = match f {
                0x11 => c.number(1)?,
                0x12 => c.number(2)?,
                0x13 => c.number(4)?,
                0x14 => c.number(8)?,
                _ => c.uleb()?,
            };
            Reference(
                u32::try_from((base as u64).checked_add(n).ok_or("reference overflow")?)
                    .map_err(|_| "reference range")?,
            )
        }
        0x19 => Number(1),
        3 | 4 | 9 | 0xa | 0x18 => {
            let n = match f {
                3 => c.number(2)?,
                4 => c.number(4)?,
                0xa => c.number(1)?,
                _ => c.uleb()?,
            };
            c.skip(usize::try_from(n).map_err(|_| "block size")?)?;
            Other
        }
        _ => return Err("unsupported DWARF form".into()),
    })
}
impl<'a> Dwarf<'a> {
    fn parse(elf: &Elf<'a>, address: u64, method: &str) -> Result<Self> {
        Self::parse_limited(elf, address, method, 8_000_000)
    }
    fn parse_limited(elf: &Elf<'a>, address: u64, method: &str, mut work: usize) -> Result<Self> {
        let info = elf.section(".debug_info")?;
        let abbrev = elf.section(".debug_abbrev")?;
        let strings = elf.section(".debug_str")?;
        let mut c = Cursor { b: info, at: 0 };
        let mut selected = None;
        let mut selected_shape: Option<abi::TypeProof> = None;
        let mut selected_layout: Option<layout::LayoutField> = None;
        let mut selected_declaration: Option<abi::DeclarationProof> = None;
        let mut string_bytes = 256 * 1024 * 1024usize;
        let charge = |remaining: &mut usize, amount: usize| -> Result<()> {
            *remaining = remaining.checked_sub(amount).ok_or("DWARF work budget")?;
            Ok(())
        };
        while c.at < info.len() {
            charge(&mut work, 1)?;
            let mut nodes = Vec::new();
            let mut index = BTreeMap::new();
            let base = c.at;
            let length = c.number(4)? as usize;
            if length == 0 || length == u32::MAX as usize {
                return Err("DWARF unit size".into());
            }
            let end =
                c.at.checked_add(length)
                    .filter(|v| *v <= info.len())
                    .ok_or("DWARF unit bounds")?;
            if c.number(2)? != 4 {
                c.at = end;
                continue;
            }
            let aoff = c.number(4)? as usize;
            if c.number(1)? != 8 {
                return Err("DWARF address size".into());
            }
            let mut ac = Cursor {
                b: abbrev,
                at: aoff,
            };
            let mut table = BTreeMap::new();
            loop {
                charge(&mut work, 1)?;
                let code = ac.uleb()?;
                if code == 0 {
                    break;
                }
                if table.len() > 4096 {
                    return Err("abbreviation bound".into());
                }
                let tag = ac.uleb()?;
                let children = ac.number(1)?;
                if children > 1 {
                    return Err("abbreviation children".into());
                }
                let mut attrs = Vec::new();
                loop {
                    charge(&mut work, 1)?;
                    let a = ac.uleb()?;
                    let f = ac.uleb()?;
                    if a == 0 && f == 0 {
                        break;
                    }
                    if a == 0 || f == 0 || attrs.len() > 64 {
                        return Err("abbreviation attributes".into());
                    }
                    attrs.push((a, f));
                }
                if table
                    .insert(
                        code,
                        Abbrev {
                            tag,
                            children: children == 1,
                            attrs,
                        },
                    )
                    .is_some()
                {
                    return Err("duplicate abbreviation".into());
                }
            }
            let mut parents = Vec::<Option<usize>>::new();
            while c.at < end {
                charge(&mut work, 1)?;
                let offset = u32::try_from(c.at).map_err(|_| "DIE offset")?;
                let code = c.uleb()?;
                if code == 0 {
                    if parents.pop().is_none() {
                        return Err("DIE nesting".into());
                    }
                    continue;
                }
                let a = table.get(&code).ok_or("unknown abbreviation")?;
                let retain = matches!(
                    a.tag,
                    1 | 2
                        | 4
                        | 5
                        | 0xd
                        | 0xf
                        | 0x10
                        | 0x13
                        | 0x15
                        | 0x16
                        | 0x17
                        | 0x18
                        | 0x1c
                        | 0x21
                        | 0x24
                        | 0x26
                        | 0x2e
                        | 0x35
                        | 0x37
                        | 0x39
                        | 0x42
                );
                let mut node = Die {
                    offset,
                    tag: a.tag,
                    parent: parents.last().copied().flatten(),
                    ..Die::default()
                };
                for &(attribute, f) in &a.attrs {
                    charge(&mut work, 1)?;
                    let value = form(&mut c, f, base, strings)?;
                    if let Value::Text(text) = &value {
                        charge(&mut string_bytes, text.len())?;
                    }
                    if !retain {
                        continue;
                    }
                    match (attribute, value) {
                        (3, Value::Text(v)) => node.name = Some(v),
                        (0x6e | 0x2007, Value::Text(v)) => node.linkage = Some(v),
                        (0x49, Value::Reference(v)) => node.ty = Some(v),
                        (0x47 | 0x31, Value::Reference(v)) => node.spec = Some(v),
                        (0xb, Value::Number(v)) => node.size = Some(v),
                        (0x38, Value::Number(v)) => node.location = Some(v),
                        (0x34, Value::Number(v)) => node.artificial = v == 1,
                        (0x3e, Value::Number(v)) => node.encoding = Some(v),
                        (0x2f, Value::Number(v)) => node.upper = Some(v),
                        (0x37, Value::Number(v)) => node.count = Some(v),
                        (0x11, Value::Number(v)) => node.pc = Some(v),
                        _ => {}
                    }
                }
                if c.at > end {
                    return Err("DIE crosses unit".into());
                }
                let current = if retain {
                    if nodes.len() >= 350000 {
                        return Err("DIE allocation bound".into());
                    }
                    let id = nodes.len();
                    index.insert(offset, id);
                    nodes.push(node);
                    Some(id)
                } else {
                    None
                };
                if a.children {
                    if parents.len() >= 128 {
                        return Err("DIE depth bound".into());
                    }
                    parents.push(current);
                }
            }
            if c.at != end || !parents.is_empty() {
                return Err("unterminated DWARF unit".into());
            }
            let unit = Self { nodes, index };
            if address == u64::MAX - 3 {
                if let Some(declaration) = abi::declarations_in_unit(&unit, method, &mut work)? {
                    if selected_declaration
                        .as_ref()
                        .is_some_and(|old| old != &declaration)
                    {
                        return Err("conflicting declaration compilation units".into());
                    }
                    if selected_declaration.is_none() {
                        selected = Some(unit);
                        selected_declaration = Some(declaration);
                    }
                }
            } else if address == u64::MAX - 2 {
                if let Some(field) = layout::field_in_unit(&unit, method, &mut work)? {
                    if selected_layout.as_ref().is_some_and(|old| old != &field) {
                        return Err("conflicting layout compilation units".into());
                    }
                    if selected_layout.is_none() {
                        selected = Some(unit);
                        selected_layout = Some(field);
                    }
                }
            } else if address == u64::MAX {
                if let Some(shape) = abi::class_in_unit(&unit, method, &mut work)? {
                    if let Some(previous) = &selected_shape {
                        let mut old = previous.clone();
                        let old_implicit = old.implicit_destructor;
                        old.implicit_destructor = shape.implicit_destructor;
                        if old != shape {
                            return Err("conflicting class compilation units".into());
                        }
                        if shape.implicit_destructor && !old_implicit {
                            selected = Some(unit);
                            selected_shape = Some(shape);
                        }
                    } else {
                        selected = Some(unit);
                        selected_shape = Some(shape);
                    }
                }
            } else if unit
                .nodes
                .iter()
                .any(|n| n.tag == 0x2e && n.pc == Some(address) && unit.linkage(n) == Some(method))
                && selected.replace(unit).is_some()
            {
                return Err("ambiguous getter compilation unit".into());
            }
        }
        selected.ok_or_else(|| "getter DWARF compilation unit absent".into())
    }
    fn get(&self, offset: u32) -> Result<&Die<'a>> {
        self.index
            .get(&offset)
            .and_then(|i| self.nodes.get(*i))
            .ok_or_else(|| "type reference absent".into())
    }
    fn resolve(&self, mut offset: u32) -> Result<&Die<'a>> {
        for _ in 0..24 {
            let n = self.get(offset)?;
            if !matches!(n.tag, 0x16 | 0x26 | 0x35 | 0x37) {
                return Ok(n);
            }
            offset = n.ty.ok_or("type qualifier target")?;
        }
        Err("type cycle/depth".into())
    }
    fn inherited(&self, n: &Die<'a>, ty: bool) -> Result<u32> {
        let mut n = n;
        for _ in 0..16 {
            if ty {
                if let Some(v) = n.ty {
                    return Ok(v);
                }
            }
            if let Some(s) = n.spec {
                n = self.get(s)?;
            } else {
                break;
            }
        }
        Err("method return type absent".into())
    }
    fn linkage(&self, n: &Die<'a>) -> Option<&'a str> {
        let mut n = n;
        for _ in 0..16 {
            if n.linkage.is_some() {
                return n.linkage;
            }
            n = self.get(n.spec?).ok()?;
        }
        None
    }
    fn member(&self, parent: &Die<'a>, name: &str) -> Result<&Die<'a>> {
        let id = *self.index.get(&parent.offset).ok_or("parent DIE")?;
        let mut found = self
            .nodes
            .iter()
            .filter(|v| v.tag == 0xd && v.parent == Some(id) && v.name == Some(name));
        let n = found.next().ok_or("member absent")?;
        if found.next().is_some() {
            return Err("ambiguous member".into());
        }
        Ok(n)
    }
    fn field(&self, parent: &Die<'a>, name: &str, kind: u32) -> Result<Field> {
        let member = self.member(parent, name)?;
        let t = self.resolve(member.ty.ok_or("member type")?)?;
        let at = member
            .location
            .or_else(|| (parent.tag == 0x17).then_some(0))
            .ok_or("member location unsupported")?;
        let bytes = t.size.ok_or("member byte size")?;
        let compatible = match kind {
            1 => t.tag == 0x24 && t.encoding == Some(5),
            2 => t.tag == 0x24 && t.encoding == Some(2),
            6 => t.tag == 2 && t.name.is_some_and(|v| v.starts_with("basic_string<")),
            _ => false,
        };
        if !compatible {
            return Err("member structural type mismatch".into());
        }
        if at
            .checked_add(bytes)
            .is_none_or(|v| v > parent.size.unwrap_or(0))
        {
            return Err("member exceeds object".into());
        }
        Ok(Field {
            kind,
            bytes: u32::try_from(bytes).map_err(|_| "member size")?,
            offset: u32::try_from(at).map_err(|_| "member offset")?,
            count: 1,
        })
    }
    fn array(&self, parent: &Die<'a>, name: &str) -> Result<Field> {
        let member = self.member(parent, name)?;
        let t = self.resolve(member.ty.ok_or("array type")?)?;
        if t.tag != 1 {
            return Err("array required".into());
        }
        let element = self.resolve(t.ty.ok_or("array element")?)?;
        if element.tag != 0x24
            || element.size != Some(1)
            || !matches!(element.encoding, Some(6 | 8))
        {
            return Err("char array required".into());
        }
        let id = *self.index.get(&t.offset).ok_or("array DIE")?;
        let mut ranges = self
            .nodes
            .iter()
            .filter(|v| v.tag == 0x21 && v.parent == Some(id));
        let range = ranges.next().ok_or("array extent")?;
        if ranges.next().is_some() {
            return Err("multidimensional array unsupported".into());
        }
        let count = range
            .count
            .or_else(|| range.upper.and_then(|v| v.checked_add(1)))
            .ok_or("array bound")?;
        let offset = member.location.ok_or("array member location")?;
        if offset
            .checked_add(count)
            .is_none_or(|v| v > parent.size.unwrap_or(0))
        {
            return Err("array exceeds object".into());
        }
        Ok(Field {
            kind: 3,
            bytes: count.try_into().map_err(|_| "array byte count")?,
            offset: offset.try_into().map_err(|_| "array offset")?,
            count: count.try_into().map_err(|_| "array count")?,
        })
    }
}
pub fn inspect(file: &[u8], family: Family) -> Result<Proof> {
    let elf = Elf::open(file)?;
    let method = match family {
        Family::Buffer => A9,
        Family::Object => A11,
    };
    let (address, code) = elf.function(method)?;
    let dwarf = Dwarf::parse(&elf, address, method)?;
    let mut definitions = dwarf
        .nodes
        .iter()
        .filter(|n| n.tag == 0x2e && n.pc == Some(address) && dwarf.linkage(n) == Some(method));
    let definition = definitions
        .next()
        .ok_or("actual getter DWARF definition missing")?;
    if definitions.next().is_some() {
        return Err("ambiguous actual getter definition".into());
    }
    let returned = dwarf.resolve(dwarf.inherited(definition, true)?)?;
    let mut fields = Vec::new();
    match family {
        Family::Object => {
            if returned.tag != 2
                || returned.name != Some("CTupMemTemplate")
                || returned.size != Some(56)
            {
                return Err("actual getter return class mismatch".into());
            }
            fields.push((
                "",
                "$return",
                Field {
                    kind: 7,
                    bytes: 56,
                    offset: 0,
                    count: 1,
                },
            ));
            fields.push((
                "CTupMemTemplate",
                "",
                Field {
                    kind: 5,
                    bytes: 56,
                    offset: 0,
                    count: 1,
                },
            ));
            for name in ["buf", "prebuf"] {
                fields.push(("CTupMemTemplate", name, dwarf.array(returned, name)?));
            }
            for (name, kind) in [("m_valid", 2), ("updateFlag", 2), ("m_string", 6)] {
                fields.push(("CTupMemTemplate", name, dwarf.field(returned, name, kind)?));
            }
        }
        Family::Buffer => {
            if returned.tag != 0x24 || returned.encoding != Some(5) || returned.size != Some(4) {
                return Err("actual getter int32 return mismatch".into());
            }
            let mut unions = dwarf
                .nodes
                .iter()
                .filter(|n| n.tag == 0x17 && n.name == Some("_Data_Union") && n.size.is_some());
            let union = unions.next().ok_or("data union definition absent")?;
            let data = dwarf.field(union, "dataIntSign", 1)?;
            if union.size != Some(16) || data.bytes != 4 || data.offset != 0 {
                return Err("data union layout mismatch".into());
            }
            for other in unions {
                if other.size != union.size || dwarf.field(other, "dataIntSign", 1)? != data {
                    return Err("conflicting data union definitions".into());
                }
            }
            copy_proof::prove(code, address, &|target| elf.call_name(target))?;
            if elf.scan_budget.get() == 0 {
                return Err("ELF scan work budget".into());
            }
            fields.push((
                "",
                "$return",
                Field {
                    kind: 1,
                    bytes: 4,
                    offset: 0,
                    count: 1,
                },
            ));
            fields.push((
                "_Data_Union",
                "",
                Field {
                    kind: 4,
                    bytes: 16,
                    offset: 0,
                    count: 1,
                },
            ));
            fields.push(("_Data_Union", "dataIntSign", data));
            fields.push((
                "",
                "$copyToCallerBuffer",
                Field {
                    kind: 8,
                    bytes: 16,
                    offset: 0,
                    count: 1,
                },
            ));
        }
    }
    Ok(Proof {
        family,
        address,
        code: code.to_vec(),
        fields,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overlapping_symbol_tables_have_one_global_work_budget() {
        let bytes = [0u8; 240];
        let section = Section {
            name: "alias",
            kind: 11,
            link: 0,
            entry: 24,
            data: &bytes,
        };
        assert!(metadata_work(core::slice::from_ref(&section), 20).is_ok());
        let aliased = alloc::vec![section.clone(), section.clone(), section];
        let error = metadata_work(&aliased, 20).unwrap_err();
        assert!(error.contains("metadata work budget"));
        let elf = Elf {
            file: &[],
            sections: Vec::new(),
            scan_budget: core::cell::Cell::new(1),
        };
        assert!(elf.spend().is_ok());
        assert!(elf.spend().is_err());
    }
    #[test]
    fn plt_prefix_followed_by_return_is_not_noreturn_proof() {
        let words = [0xb00005f0u32, 0xf944fe11, 0x9127e210, 0xd61f0220];
        let mut bytes = Vec::new();
        for w in words {
            bytes.extend(w.to_le_bytes());
        }
        assert_eq!(plt_slot(&bytes, 0x43e00), Some(0x1009f8));
        bytes[12..16].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
        assert_eq!(plt_slot(&bytes, 0x43e00), None);
        bytes[12..16].copy_from_slice(&0xd61f0200u32.to_le_bytes());
        assert_eq!(plt_slot(&bytes, 0x43e00), None);
        bytes[12..16].copy_from_slice(&0xd61f0220u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&0x9127c210u32.to_le_bytes());
        assert_eq!(plt_slot(&bytes, 0x43e00), None);
    }
    #[test]
    fn repeated_abbreviation_reparse_spends_global_budget() {
        let mut info = Vec::new();
        for _ in 0..20 {
            info.extend([8, 0, 0, 0, 4, 0, 0, 0, 0, 0, 8, 1]);
        }
        let make = |name, data| Section {
            name,
            kind: 0,
            link: 0,
            entry: 0,
            data,
        };
        let elf = Elf {
            file: &[],
            scan_budget: core::cell::Cell::new(1_000_000),
            sections: alloc::vec![
                make(".debug_info", &info),
                make(".debug_abbrev", &[1, 0x11, 0, 0, 0, 0]),
                make(".debug_str", &[0])
            ],
        };
        let error = Dwarf::parse_limited(&elf, 1, "missing", 30).err().unwrap();
        assert!(error.contains("work budget"), "{error}");
    }
    #[test]
    fn member_type_bounds_and_reference_cycles_reject() {
        let mut nodes = alloc::vec![
            Die {
                offset: 1,
                tag: 2,
                size: Some(56),
                ..Die::default()
            },
            Die {
                offset: 2,
                tag: 0xd,
                parent: Some(0),
                name: Some("m_valid"),
                ty: Some(3),
                location: Some(16),
                ..Die::default()
            },
            Die {
                offset: 3,
                tag: 0x24,
                size: Some(1),
                encoding: Some(2),
                ..Die::default()
            },
        ];
        let index = nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (n.offset, i))
            .collect();
        let mut dwarf = Dwarf {
            nodes: core::mem::take(&mut nodes),
            index,
        };
        assert_eq!(
            dwarf.field(&dwarf.nodes[0], "m_valid", 2).unwrap(),
            Field {
                kind: 2,
                bytes: 1,
                offset: 16,
                count: 1
            }
        );
        dwarf.nodes[2].encoding = Some(5);
        assert!(dwarf.field(&dwarf.nodes[0], "m_valid", 2).is_err());
        dwarf.nodes[2].encoding = Some(2);
        dwarf.nodes[1].location = Some(56);
        assert!(dwarf.field(&dwarf.nodes[0], "m_valid", 2).is_err());
        dwarf.nodes[1].location = Some(16);
        dwarf.nodes[2].tag = 0x16;
        dwarf.nodes[2].ty = Some(3);
        assert!(dwarf.field(&dwarf.nodes[0], "m_valid", 2).is_err());
    }
    #[test]
    fn malformed_cursors_and_absent_debug_fail_closed() {
        assert!(inspect(&[], Family::Object).is_err());
        assert!(Cursor {
            b: &[0x80; 10],
            at: 0
        }
        .uleb()
        .is_err());
        assert!(Cursor {
            b: &[0xff; 10],
            at: 0
        }
        .sleb()
        .is_err());
        assert!(Cursor { b: &[0], at: 1 }.number(1).is_err());
        assert!(form(&mut Cursor { b: &[0], at: 0 }, 0xff, 0, &[]).is_err());
        assert!(text(b"unterminated", 0).is_err());
    }
    #[test]
    #[ignore = "requires retained actual ELF paths, never bundled fixtures"]
    fn actual_retained_owners() {
        for (variable, family) in [
            ("VOBOOST_PW_A9_ELF", Family::Buffer),
            ("VOBOOST_PW_A11_ELF", Family::Object),
        ] {
            let path = std::env::var(variable).unwrap();
            let file = std::fs::read(path).unwrap();
            let proof = inspect(&file, family).unwrap();
            assert!(proof.address() > 0 && !proof.code().is_empty());
            let method = if family == Family::Buffer { A9 } else { A11 };
            assert!(proof.query(method, "", "$return").is_some());
            assert!(proof.query("forged", "", "$return").is_none());
            std::println!(
                "actual {:?}: method address={} bytes={} structural fields={}",
                family,
                proof.address(),
                proof.code().len(),
                proof.fields.len()
            );
            let mut changed = file.clone();
            // Erase real debug metadata, retaining the actual executable body.
            let section = Elf::open(&file).unwrap().section(".debug_info").unwrap();
            let offset = section.as_ptr() as usize - file.as_ptr() as usize;
            changed[offset..offset + section.len()].fill(0);
            assert!(inspect(&changed, family).is_err());
        }
    }
}
