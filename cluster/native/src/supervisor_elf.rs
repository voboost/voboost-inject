//! Bounded ELF relocation and AArch64 PLT evidence for the scoped execve seam.
use crate::Result;
use alloc::vec::Vec;
fn num(b: &[u8], p: usize, n: usize) -> Result<u64> {
    let e = p.checked_add(n).ok_or("supervisor ELF overflow")?;
    let v = b.get(p..e).ok_or("supervisor ELF bounds")?;
    Ok(v.iter()
        .enumerate()
        .fold(0, |a, (i, v)| a | ((*v as u64) << (i * 8))))
}
fn data(b: &[u8], off: u64, size: u64) -> Result<&[u8]> {
    let o = usize::try_from(off).map_err(|_| "ELF offset")?;
    let n = usize::try_from(size).map_err(|_| "ELF size")?;
    b.get(o..o.checked_add(n).ok_or("ELF extent")?)
        .ok_or_else(|| "ELF data bounds".into())
}
fn name(b: &[u8], offset: u64) -> Result<&str> {
    let p = usize::try_from(offset).map_err(|_| "ELF name offset")?;
    let tail = b.get(p..).ok_or("ELF name bounds")?;
    let n = tail
        .iter()
        .take(1024)
        .position(|v| *v == 0)
        .ok_or("ELF name length")?;
    core::str::from_utf8(&tail[..n]).map_err(|_| "ELF name encoding".into())
}
struct Section<'a> {
    name: u64,
    kind: u64,
    flags: u64,
    address: u64,
    offset: u64,
    link: usize,
    entry: u64,
    bytes: &'a [u8],
}
struct Load {
    flags: u64,
    address: u64,
    offset: u64,
    file_size: u64,
    memory_size: u64,
}
fn mapped(loads: &[Load], address: u64, size: u64, flags: u64, offset: Option<u64>) -> bool {
    let Some(end) = address.checked_add(size) else {
        return false;
    };
    loads
        .iter()
        .filter(|l| {
            l.flags & flags == flags
                && address >= l.address
                && l.address
                    .checked_add(l.memory_size)
                    .is_some_and(|e| end <= e)
                && l.address.checked_add(l.file_size).is_some_and(|e| end <= e)
                && offset.is_none_or(|o| l.offset.checked_add(address - l.address) == Some(o))
        })
        .count()
        == 1
}
fn thunk(code: &[u8], address: u64) -> Option<u64> {
    let a = num(code, 0, 4).ok()? as u32;
    let l = num(code, 4, 4).ok()? as u32;
    let add = num(code, 8, 4).ok()? as u32;
    let br = num(code, 12, 4).ok()? as u32;
    let base = a & 31;
    let dest = l & 31;
    if base == 31
        || dest == 31
        || base == dest
        || a & 0x9f000000 != 0x90000000
        || l & 0xffc00000 != 0xf9400000
        || (l >> 5) & 31 != base
        || add & 0xffc00000 != 0x91000000
        || add & 31 != base
        || (add >> 5) & 31 != base
        || (add >> 10) & 0xfff != ((l >> 10) & 0xfff) * 8
        || br & 0xfffffc1f != 0xd61f0000
        || (br >> 5) & 31 != dest
    {
        return None;
    }
    let imm = (((a >> 5) & 0x7ffff) << 2) | ((a >> 29) & 3);
    let delta = (((imm as i64) << 43) >> 43) << 12;
    (address & !4095)
        .checked_add_signed(delta)?
        .checked_add(((l >> 10) & 0xfff) as u64 * 8)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExecveSlot {
    pub offset: u64,
    pub load_flags: u32,
    pub relro: Option<(u64, u64)>,
}
pub(crate) fn has_execve_jump_slot(file: &[u8]) -> Result<()> {
    inspect_execve(file).map(|_| ())
}
struct Tables<'a> {
    loads: Vec<Load>,
    sections: Vec<Section<'a>>,
    names: usize,
    relro: Option<(u64, u64)>,
}
fn tables(file: &[u8]) -> Result<Tables<'_>> {
    if file.len() > 64 * 1024 * 1024
        || file.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || num(file, 18, 2)? != 183
        || num(file, 20, 4)? != 1
        || !matches!(num(file, 16, 2)?, 2 | 3)
        || num(file, 52, 2)? != 64
        || num(file, 54, 2)? != 56
        || num(file, 58, 2)? != 64
    {
        return Err("supervisor ELF format".into());
    }
    let ph = num(file, 32, 8)?;
    let pc = num(file, 56, 2)?;
    let sh = num(file, 40, 8)?;
    let sc = num(file, 60, 2)?;
    let strings = num(file, 62, 2)? as usize;
    if pc == 0 || pc > 128 || sc == 0 || sc > 4096 || strings >= sc as usize {
        return Err("supervisor ELF table bound".into());
    }
    let headers = data(file, ph, pc * 56)?;
    let mut loads = Vec::new();
    let mut relro = None;
    for h in headers.as_chunks::<56>().0 {
        if num(h, 0, 4)? == 0x6474e552 {
            let start = num(h, 16, 8)?;
            let end = start
                .checked_add(num(h, 40, 8)?)
                .ok_or("ELF RELRO overflow")?;
            if relro.replace((start, end)).is_some() {
                return Err("ELF RELRO ambiguity".into());
            }
        }
        if num(h, 0, 4)? != 1 {
            continue;
        }
        let l = Load {
            flags: num(h, 4, 4)?,
            offset: num(h, 8, 8)?,
            address: num(h, 16, 8)?,
            file_size: num(h, 32, 8)?,
            memory_size: num(h, 40, 8)?,
        };
        if l.file_size > l.memory_size || l.address.checked_add(l.memory_size).is_none() {
            return Err("supervisor ELF segment extent".into());
        }
        data(file, l.offset, l.file_size)?;
        loads.push(l);
    }
    let headers = data(file, sh, sc * 64)?;
    let mut sections = Vec::new();
    let mut work = 0usize;
    for h in headers.as_chunks::<64>().0 {
        let kind = num(h, 4, 4)?;
        let size = num(h, 32, 8)?;
        let entry = num(h, 56, 8)?;
        if matches!(kind, 2 | 4 | 11) {
            if entry != 24 || size % 24 != 0 {
                return Err("supervisor ELF metadata entries".into());
            }
            work = work
                .checked_add((size / 24) as usize)
                .filter(|n| *n <= 131072)
                .ok_or("supervisor ELF work bound")?;
        }
        let offset = num(h, 24, 8)?;
        sections.push(Section {
            name: num(h, 0, 4)?,
            kind,
            flags: num(h, 8, 8)?,
            address: num(h, 16, 8)?,
            offset,
            link: num(h, 40, 4)? as usize,
            entry,
            bytes: if kind == 8 {
                &[]
            } else {
                data(file, offset, size)?
            },
        });
    }
    let names = &sections[strings];
    if names.kind != 3 {
        return Err("supervisor ELF section names".into());
    }
    Ok(Tables {
        loads,
        sections,
        names: strings,
        relro,
    })
}
pub(crate) fn inspect_execve(file: &[u8]) -> Result<ExecveSlot> {
    let Tables {
        loads,
        sections,
        names: strings,
        relro,
    } = tables(file)?;
    let names = &sections[strings];
    let mut found = None;
    for rel in sections.iter().filter(|s| s.kind == 4) {
        let sym = sections
            .get(rel.link)
            .filter(|s| s.kind == 11 && s.entry == 24)
            .ok_or("supervisor ELF relocation symbols")?;
        let strings = sections
            .get(sym.link)
            .filter(|s| s.kind == 3)
            .ok_or("supervisor ELF symbol strings")?;
        for r in rel.bytes.as_chunks::<24>().0 {
            let info = num(r, 8, 8)?;
            if info as u32 != 1026 {
                continue;
            }
            let index = usize::try_from(info >> 32).map_err(|_| "ELF symbol index")?;
            let s = sym
                .bytes
                .get(
                    index.checked_mul(24).ok_or("ELF symbol overflow")?
                        ..index
                            .checked_add(1)
                            .and_then(|i| i.checked_mul(24))
                            .ok_or("ELF symbol overflow")?,
                )
                .ok_or("ELF symbol bounds")?;
            if name(strings.bytes, num(s, 0, 4)?)? != "execve" {
                continue;
            }
            if num(s, 6, 2)? != 0
                || num(s, 8, 8)? != 0
                || num(s, 4, 1)? & 15 != 2
                || !matches!(num(s, 4, 1)? >> 4, 1 | 2)
                || num(r, 16, 8)? != 0
            {
                return Err("supervisor execve symbol unsupported".into());
            }
            let slot = num(r, 0, 8)?;
            if slot % 8 != 0 || !mapped(&loads, slot, 8, 2, None) || found.replace(slot).is_some() {
                return Err("supervisor execve slot ambiguous or unmapped".into());
            }
        }
    }
    let slot = found.ok_or("supervisor execve JUMP_SLOT absent")?;
    let mut matches = 0;
    for section in &sections {
        if name(names.bytes, section.name)? != ".plt" {
            continue;
        }
        if section.flags & 6 != 6
            || section.bytes.len() > 65536
            || section.address % 4 != 0
            || !mapped(
                &loads,
                section.address,
                section.bytes.len() as u64,
                1,
                Some(section.offset),
            )
        {
            return Err("supervisor PLT mapping unsupported".into());
        }
        for (i, bytes) in section.bytes.windows(16).step_by(4).enumerate() {
            let address = section
                .address
                .checked_add((i * 4) as u64)
                .ok_or("ELF PLT address")?;
            if thunk(bytes, address) == Some(slot) {
                matches += 1;
            }
        }
    }
    if matches != 1 {
        return Err("supervisor execve PLT thunk absent or ambiguous".into());
    }
    let load = loads
        .iter()
        .find(|l| {
            slot >= l.address
                && l.address
                    .checked_add(l.memory_size)
                    .is_some_and(|end| slot.checked_add(8).is_some_and(|s| s <= end))
                && l.flags & 2 != 0
        })
        .ok_or("ELF execve load absent")?;
    Ok(ExecveSlot {
        offset: slot,
        load_flags: load.flags as u32,
        relro,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    fn put(b: &mut [u8], p: usize, n: usize, v: u64) {
        for i in 0..n {
            b[p + i] = (v >> (8 * i)) as u8;
        }
    }
    pub(super) fn sample() -> Vec<u8> {
        let mut b = vec![0u8; 0x580];
        b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (p, n, v) in [
            (16, 2, 3),
            (18, 2, 183),
            (20, 4, 1),
            (32, 8, 64),
            (40, 8, 0x400),
            (52, 2, 64),
            (54, 2, 56),
            (56, 2, 2),
            (58, 2, 64),
            (60, 2, 6),
            (62, 2, 5),
        ] {
            put(&mut b, p, n, v);
        }
        for (i, flags, off, va, size) in [(0, 5, 0x200, 0x1000, 16), (1, 6, 0x300, 0x2000, 8)] {
            let p = 64 + i * 56;
            for (o, n, v) in [
                (0, 4, 1),
                (4, 4, flags),
                (8, 8, off),
                (16, 8, va),
                (32, 8, size),
                (40, 8, size),
            ] {
                put(&mut b, p + o, n, v);
            }
        }
        b[0xf0..0xf8].copy_from_slice(b"\0execve\0");
        put(&mut b, 0xd8, 4, 1);
        put(&mut b, 0xdc, 1, 0x12);
        put(&mut b, 0x110, 8, 0x2000);
        put(&mut b, 0x118, 8, (1u64 << 32) | 1026);
        let names = b"\0.dynsym\0.dynstr\0.rela.plt\0.plt\0.shstrtab\0";
        b[0x140..0x140 + names.len()].copy_from_slice(names);
        for (i, n, k, fl, va, off, size, link, ent) in [
            (1, 1, 11, 0, 0, 0xc0, 48, 2, 24),
            (2, 9, 3, 0, 0, 0xf0, 8, 0, 0),
            (3, 17, 4, 0, 0, 0x110, 24, 1, 24),
            (4, 27, 1, 6, 0x1000, 0x200, 16, 0, 0),
            (5, 32, 3, 0, 0, 0x140, names.len() as u64, 0, 0),
        ] {
            let p = 0x400 + i * 64;
            for (o, n, v) in [
                (0, 4, n),
                (4, 4, k),
                (8, 8, fl),
                (16, 8, va),
                (24, 8, off),
                (32, 8, size),
                (40, 4, link),
                (56, 8, ent),
            ] {
                put(&mut b, p + o, n, v);
            }
        }
        for (i, w) in [0xb0000010u32, 0xf9400211, 0x91000210, 0xd61f0220]
            .iter()
            .enumerate()
        {
            put(&mut b, 0x200 + i * 4, 4, *w as u64);
        }
        b
    }
    #[test]
    fn accepts_scoped_elf() {
        assert_eq!(
            inspect_execve(&sample()).unwrap(),
            ExecveSlot {
                offset: 0x2000,
                load_flags: 6,
                relro: None
            }
        );
    }
    #[test]
    fn rejects_relocation_and_slot_mutations() {
        for (p, n, v) in [
            (0x118, 4, 1025),
            (0x110, 8, 0x2010),
            (0xde, 2, 1),
            (0x120, 8, 1),
        ] {
            let mut b = sample();
            put(&mut b, p, n, v);
            assert!(has_execve_jump_slot(&b).is_err());
        }
    }
    #[test]
    fn rejects_malformed_thunk_and_permissions() {
        for (p, n, v) in [
            (0x20c, 4, 0xd61f0200),
            (0x204, 4, 0xf9400611),
            (0x208, 4, 0x91002210),
            (124, 4, 4),
            (68, 4, 4),
        ] {
            let mut b = sample();
            put(&mut b, p, n, v);
            assert!(has_execve_jump_slot(&b).is_err());
        }
    }
    #[test]
    fn rejects_truncation_and_bounds() {
        for n in [0, 63, 175, 0x57f] {
            assert!(has_execve_jump_slot(&sample()[..n]).is_err());
        }
        let mut b = sample();
        put(&mut b, 60, 2, 4097);
        assert!(has_execve_jump_slot(&b).is_err());
    }
    #[test]
    #[ignore = "requires retained actual supervisor ELFs"]
    fn actual_four_supervisors() {
        for key in [
            "VOBOOST_A9_SYSMGR",
            "VOBOOST_A9_CLUSTERBOOT",
            "VOBOOST_A11_SYSMGR",
            "VOBOOST_A11_CLUSTERBOOT",
        ] {
            let p = std::env::var(key).unwrap();
            let slot = inspect_execve(&std::fs::read(p).unwrap()).unwrap();
            let expected = match key {
                "VOBOOST_A9_SYSMGR" => (163064, 161144, 163840),
                "VOBOOST_A9_CLUSTERBOOT" => (478120, 475736, 479232),
                "VOBOOST_A11_SYSMGR" => (167160, 165192, 167936),
                _ => (478120, 475688, 479232),
            };
            assert_eq!(
                slot,
                ExecveSlot {
                    offset: expected.0,
                    load_flags: 6,
                    relro: Some((expected.1, expected.2))
                }
            );
        }
    }
}

/// Read-only bounded data access through the same ELF tables used for PLT admission.
#[cfg(any(target_os = "nto", test))]
pub(crate) struct DataReader<'a> {
    file: &'a [u8],
    tables: Tables<'a>,
    relocations: alloc::collections::BTreeMap<u64, (u32, u64, u64)>,
    work: core::cell::Cell<usize>,
    pie: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(target_os = "nto", test))]
pub(crate) struct DataObject {
    pub address: u64,
    pub bytes: u64,
}
#[cfg(any(target_os = "nto", test))]
impl<'a> DataReader<'a> {
    pub(crate) fn open(file: &'a [u8]) -> Result<Self> {
        let tables = tables(file)?;
        let mut relocations = alloc::collections::BTreeMap::new();
        for s in tables
            .sections
            .iter()
            .filter(|s| s.kind == 4 && s.flags & 2 != 0)
        {
            for r in s.bytes.as_chunks::<24>().0 {
                let at = num(r, 0, 8)?;
                let info = num(r, 8, 8)?;
                if relocations
                    .insert(at, (info as u32, info >> 32, num(r, 16, 8)?))
                    .is_some()
                {
                    return Err("ELF duplicate data relocation".into());
                }
            }
        }
        Ok(Self {
            file,
            tables,
            relocations,
            work: core::cell::Cell::new(2_000_000),
            pie: num(file, 16, 2)? == 3,
        })
    }
    fn spend(&self, n: usize) -> Result<()> {
        self.work.set(
            self.work
                .get()
                .checked_sub(n)
                .ok_or("ELF data work budget")?,
        );
        Ok(())
    }
    pub(crate) fn object(&self, wanted: &str) -> Result<DataObject> {
        if wanted.is_empty() || wanted.len() > 128 {
            return Err("ELF object name bound".into());
        }
        let mut found = None;
        for s in self
            .tables
            .sections
            .iter()
            .filter(|s| matches!(s.kind, 2 | 11))
        {
            let strings = self
                .tables
                .sections
                .get(s.link)
                .filter(|x| x.kind == 3)
                .ok_or("ELF object strings")?;
            for entry in s.bytes.as_chunks::<24>().0 {
                self.spend(1)?;
                if name(strings.bytes, num(entry, 0, 4)?)? != wanted {
                    continue;
                }
                if num(entry, 4, 1)? & 15 != 1 || num(entry, 6, 2)? == 0 {
                    return Err("ELF object definition required".into());
                }
                let object = DataObject {
                    address: num(entry, 8, 8)?,
                    bytes: num(entry, 16, 8)?,
                };
                if object.bytes > 65536 || found.replace(object).is_some() {
                    return Err("ELF object bound or ambiguity".into());
                }
                if object.bytes != 0 {
                    self.bytes(object.address, object.bytes as usize)?;
                } else if !self.tables.loads.iter().any(|l| {
                    object.address >= l.address
                        && l.address
                            .checked_add(l.memory_size)
                            .is_some_and(|e| object.address <= e)
                }) {
                    return Err("ELF empty object mapping".into());
                }
            }
        }
        found.ok_or_else(|| "ELF object absent".into())
    }
    pub(crate) fn bytes(&self, address: u64, length: usize) -> Result<&'a [u8]> {
        self.spend(length.checked_add(1).ok_or("ELF read length")?)?;
        let end = address
            .checked_add(length as u64)
            .ok_or("ELF data address")?;
        let mut found = None;
        for l in &self.tables.loads {
            if l.flags & 4 == 0
                || address < l.address
                || l.address.checked_add(l.file_size).is_none_or(|e| end > e)
            {
                continue;
            }
            let off = l
                .offset
                .checked_add(address - l.address)
                .ok_or("ELF data offset")?;
            if found
                .replace(data(self.file, off, length as u64)?)
                .is_some()
            {
                return Err("ELF data mapping ambiguity".into());
            }
        }
        found.ok_or_else(|| "ELF data not file backed".into())
    }
    pub(crate) fn pointer(&self, address: u64) -> Result<u64> {
        if !address.is_multiple_of(8) {
            return Err("ELF unaligned pointer".into());
        }
        let raw = num(self.bytes(address, 8)?, 0, 8)?;
        match self.relocations.get(&address) {
            Some((1027, 0, value)) => Ok(*value),
            Some(_) => Err("ELF pointer relocation unsupported".into()),
            None if raw == 0 || !self.pie => Ok(raw),
            None => Err("ELF nonrelocated PIE pointer".into()),
        }
    }
    pub(crate) fn string(&self, address: u64, limit: usize) -> Result<alloc::string::String> {
        if address == 0 || limit > 4096 {
            return Err("ELF string bound".into());
        }
        let mut result = Vec::new();
        for i in 0..=limit {
            let byte = self.bytes(
                address.checked_add(i as u64).ok_or("ELF string overflow")?,
                1,
            )?[0];
            if byte == 0 {
                return alloc::string::String::from_utf8(result)
                    .map_err(|_| "ELF string UTF8".into());
            }
            result.push(byte);
        }
        Err("ELF string length".into())
    }
}

#[cfg(test)]
mod data_tests {
    use super::*;
    fn put(b: &mut [u8], at: usize, width: usize, value: u64) {
        for i in 0..width {
            b[at + i] = (value >> (i * 8)) as u8;
        }
    }
    fn sample() -> Vec<u8> {
        let mut b = super::tests::sample();
        put(&mut b, 0x4c8, 8, 2);
        put(&mut b, 0x118, 8, 1027);
        put(&mut b, 0x120, 8, 0x1000);
        b
    }
    #[test]
    fn relative_pointer_is_data_evidence() {
        let b = sample();
        let r = DataReader::open(&b).unwrap();
        assert_eq!(r.pointer(0x2000).unwrap(), 0x1000);
    }
    #[test]
    fn rejects_wrong_or_missing_pointer_relocation() {
        for info in [1026, ((1u64) << 32) | 1027] {
            let mut b = sample();
            put(&mut b, 0x118, 8, info);
            assert!(DataReader::open(&b).unwrap().pointer(0x2000).is_err());
        }
        let mut b = sample();
        put(&mut b, 0x4c8, 8, 0);
        put(&mut b, 0x300, 8, 0x1000);
        assert!(DataReader::open(&b).unwrap().pointer(0x2000).is_err());
    }
    #[test]
    fn rejects_unbounded_or_unmapped_strings() {
        let mut b = sample();
        put(&mut b, 96, 8, 128);
        put(&mut b, 104, 8, 128);
        b[0x200..0x264].fill(b"A"[0]);
        let reader = DataReader::open(&b).unwrap();
        assert!(reader.string(0x1000, 99).is_err());
        assert!(reader.string(u64::MAX, 99).is_err());
        assert!(reader.string(0x1000, 4097).is_err());
    }
    #[test]
    fn rejects_function_as_data_object() {
        let b = sample();
        assert!(DataReader::open(&b).unwrap().object("execve").is_err());
    }
}
