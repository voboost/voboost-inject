//! Read-only ELF identity; no target-process memory access.
#[path = "elf_local_provider.rs"]
pub mod local_provider;
use crate::Result;
use alloc::{string::String, vec::Vec};
fn u16le(b: &[u8], n: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        b.get(n..n + 2)
            .ok_or("ELF u16 bounds")?
            .try_into()
            .map_err(|_| "ELF u16")?,
    ))
}
fn u32le(b: &[u8], n: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(n..n + 4)
            .ok_or("ELF u32 bounds")?
            .try_into()
            .map_err(|_| "ELF u32")?,
    ))
}
fn u64le(b: &[u8], n: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(n..n + 8)
            .ok_or("ELF u64 bounds")?
            .try_into()
            .map_err(|_| "ELF u64")?,
    ))
}
pub fn build_id(bytes: &[u8]) -> Result<String> {
    if bytes.get(..6) != Some(b"\x7fELF\x02\x01")
        || u16le(bytes, 18)? != 183
        || u16le(bytes, 54)? != 56
    {
        return Err("not supported AArch64 little-endian ELF".into());
    }
    let phoff = usize::try_from(u64le(bytes, 32)?).map_err(|_| "ELF offset")?;
    let count = u16le(bytes, 56)? as usize;
    if count > 128 {
        return Err("ELF program header bound".into());
    }
    let mut found = None;
    for i in 0..count {
        let p = phoff.checked_add(i * 56).ok_or("ELF offset overflow")?;
        if u32le(bytes, p)? != 4 {
            continue;
        }
        let off = usize::try_from(u64le(bytes, p + 8)?).map_err(|_| "ELF note offset")?;
        let len = usize::try_from(u64le(bytes, p + 32)?).map_err(|_| "ELF note length")?;
        let end = off.checked_add(len).ok_or("ELF note overflow")?;
        let note = bytes.get(off..end).ok_or("ELF note bounds")?;
        let mut at = 0usize;
        while at + 12 <= note.len() {
            let names = u32le(note, at)? as usize;
            let size = u32le(note, at + 4)? as usize;
            let kind = u32le(note, at + 8)?;
            let data = at
                .checked_add(12)
                .and_then(|v| v.checked_add((names + 3) & !3))
                .ok_or("ELF note overflow")?;
            let next = data
                .checked_add((size + 3) & !3)
                .ok_or("ELF note overflow")?;
            if next > note.len() {
                return Err("ELF truncated note".into());
            }
            if kind == 3 && names == 4 && note.get(at + 12..at + 16) == Some(b"GNU\0") {
                if size == 0 || size > 64 || found.is_some() {
                    return Err("ELF build identity ambiguous".into());
                }
                found = Some(hex::encode(&note[data..data + size]));
            }
            at = next;
        }
    }
    found.ok_or_else(|| "ELF GNU build identity missing".into())
}
pub fn read(path: &str, max: usize) -> Result<Vec<u8>> {
    if !voboost_contract_core::safe_path(path) {
        return Err("unsafe compatibility path".into());
    }
    let name = alloc::ffi::CString::new(path).map_err(|_| "ELF path NUL")?;
    read_file(&name, max)
}

fn read_file(name: &core::ffi::CStr, max: usize) -> Result<Vec<u8>> {
    // OEM library canonical names can be symlinks. They are read-only identity inputs,
    // never protected-state writes or native code selected from courier paths.
    let fd = crate::fs::Fd(unsafe { libc::open(name.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) });
    if fd.0 < 0 {
        return Err("compatibility file unavailable".into());
    }
    let s = crate::fs::stat(fd.0)?;
    if s.st_mode & libc::S_IFMT != libc::S_IFREG || s.st_size <= 0 || s.st_size as u64 > max as u64
    {
        return Err("compatibility ELF size/type rejected".into());
    }
    let mut bytes = alloc::vec![0;s.st_size as usize];
    crate::fs::read_exact(fd.0, &mut bytes)?;
    let after = crate::fs::stat(fd.0)?;
    if !crate::fs::unchanged(&s, &after) {
        return Err("compatibility ELF changed while reading".into());
    }
    Ok(bytes)
}
pub fn compatible(path: &str, wanted: &str) -> bool {
    read(path, 64 * 1024 * 1024)
        .and_then(|b| build_id(&b))
        .map(|id| id == wanted)
        .unwrap_or(false)
}

/// QNX exefile contains an executable pathname, not executable bytes.
pub fn process(pid: u64, executable: &str, sha256: &str) -> Result<()> {
    let name = process_path(pid)?;
    if name != executable
        || voboost_contract_core::hash(&read(executable, 64 * 1024 * 1024)?) != sha256
    {
        return Err("startup executable identity differs".into());
    }
    Ok(())
}
pub(crate) fn process_path(pid: u64) -> Result<alloc::string::String> {
    if pid == 0 || pid > voboost_contract_core::MAX_SAFE_INTEGER {
        return Err("process PID rejected".into());
    }
    let path = alloc::ffi::CString::new(alloc::format!("/proc/{pid}/exefile"))
        .map_err(|_| "process path")?;
    let fd = crate::fs::Fd(unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    });
    if fd.0 < 0 {
        return Err("startup process identity unavailable".into());
    }
    if crate::fs::stat(fd.0)?.st_uid != 0 {
        return Err("startup process owner rejected".into());
    }
    let mut buffer = [0u8; 514];
    let n = unsafe { libc::read(fd.0, buffer.as_mut_ptr().cast(), buffer.len()) };
    if n <= 0 || n as usize == buffer.len() {
        return Err("startup executable pathname bound".into());
    }
    let name = &buffer[..n as usize];
    let name = name.strip_suffix(&[0]).unwrap_or(name);
    let name = name.strip_suffix(b"\n").unwrap_or(name);
    core::str::from_utf8(name)
        .map(alloc::string::String::from)
        .map_err(|_| "startup executable pathname invalid".into())
}

/// A genuine hidden function plus a public function in the SAME ELF owner.
/// Values are relative ELF virtual addresses, never callable host pointers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalFunction {
    pub value: u64,
    pub size: u64,
    pub anchor_value: u64,
    pub anchor_size: u64,
}

/// Resolve a unique defined LOCAL STT_FUNC from a retained symbol table.
/// Stripped files, conflicting symbols, non-executable ranges and unsupported
/// ELF layouts reject. Runtime must additionally pin/cross-check the mapped
/// owner using its actual public anchor before converting any value to code.
pub fn local_function(bytes: &[u8], name: &str, anchor: &str) -> Result<LocalFunction> {
    fn region(bytes: &[u8], offset: u64, length: u64) -> Result<&[u8]> {
        let start = usize::try_from(offset).map_err(|_| "ELF local offset")?;
        let count = usize::try_from(length).map_err(|_| "ELF local length")?;
        bytes
            .get(start..start.checked_add(count).ok_or("ELF local range overflow")?)
            .ok_or_else(|| "ELF local range bounds".into())
    }
    if name.is_empty()
        || anchor.is_empty()
        || name == anchor
        || name.len() > 128
        || anchor.len() > 128
        || !name.bytes().all(|c| c.is_ascii_graphic())
        || !anchor.bytes().all(|c| c.is_ascii_graphic())
    {
        return Err("ELF local symbol name rejected".into());
    }
    if bytes.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || u16le(bytes, 16)? != 3
        || u16le(bytes, 18)? != 183
        || u32le(bytes, 20)? != 1
        || u16le(bytes, 52)? != 64
        || u16le(bytes, 54)? != 56
        || u16le(bytes, 58)? != 64
    {
        return Err("ELF local requires AArch64 LE shared ELF64".into());
    }
    let ph_count = u16le(bytes, 56)? as usize;
    let sh_count = u16le(bytes, 60)? as usize;
    if !(1..=128).contains(&ph_count) || !(1..=4096).contains(&sh_count) {
        return Err("ELF local table count rejected".into());
    }
    let ph = region(bytes, u64le(bytes, 32)?, (ph_count as u64) * 56)?;
    let sh = region(bytes, u64le(bytes, 40)?, (sh_count as u64) * 64)?;
    let mut loads = Vec::new();
    for p in ph.as_chunks::<56>().0.iter() {
        if u32le(p, 0)? != 1 {
            continue;
        }
        let offset = u64le(p, 8)?;
        let address = u64le(p, 16)?;
        let files = u64le(p, 32)?;
        let memory = u64le(p, 40)?;
        if files > memory || address.checked_add(memory).is_none() {
            return Err("ELF local LOAD bounds".into());
        }
        region(bytes, offset, files)?;
        for (prior, length, _, _) in &loads {
            if address < prior + length && *prior < address + memory {
                return Err("ELF local overlapping LOAD".into());
            }
        }
        loads.push((address, memory, files, u32le(p, 4)?));
    }
    if loads.is_empty() {
        return Err("ELF local LOAD missing".into());
    }
    let executable = |value: u64, size: u64| -> bool {
        size != 0
            && value & 3 == 0
            && value.checked_add(size).is_some_and(|end| {
                loads
                    .iter()
                    .filter(|(start, _, files, flags)| {
                        flags & 1 != 0 && value >= *start && end <= start + files
                    })
                    .count()
                    == 1
            })
    };
    let mut local = None;
    let mut public = None;
    let mut dynamic = None;
    for section in sh.as_chunks::<64>().0.iter() {
        let kind = u32le(section, 4)?;
        if kind != 2 && kind != 11 {
            continue;
        }
        let length = u64le(section, 32)?;
        if u64le(section, 56)? != 24 || length % 24 != 0 || length / 24 > 1_000_000 {
            return Err("ELF local symbol table bounds".into());
        }
        let index = u32le(section, 40)? as usize;
        let strings = sh
            .get(
                index
                    .checked_mul(64)
                    .ok_or("ELF local string link overflow")?
                    ..index
                        .checked_add(1)
                        .and_then(|n| n.checked_mul(64))
                        .ok_or("ELF local string link overflow")?,
            )
            .ok_or("ELF local string link")?;
        if u32le(strings, 4)? != 3 {
            return Err("ELF local strings type".into());
        }
        let strings = region(bytes, u64le(strings, 24)?, u64le(strings, 32)?)?;
        let symbols = region(bytes, u64le(section, 24)?, length)?;
        for symbol in symbols.as_chunks::<24>().0.iter() {
            let at = u32le(symbol, 0)? as usize;
            let tail = strings.get(at..).ok_or("ELF local string bounds")?;
            let is_name = tail
                .get(..name.len() + 1)
                .is_some_and(|s| s[..name.len()] == *name.as_bytes() && s[name.len()] == 0);
            let is_anchor = tail
                .get(..anchor.len() + 1)
                .is_some_and(|s| s[..anchor.len()] == *anchor.as_bytes() && s[anchor.len()] == 0);
            if !is_name && !is_anchor {
                continue;
            }
            let bind = symbol[4] >> 4;
            let symbol_type = symbol[4] & 15;
            let owner = u16le(symbol, 6)? as usize;
            let value = u64le(symbol, 8)?;
            let size = u64le(symbol, 16)?;
            if owner == 0 || owner >= sh_count || symbol_type != 2 || !executable(value, size) {
                return Err("ELF local function definition rejected".into());
            }
            let owner = &sh[owner * 64..(owner + 1) * 64];
            let owner_start = u64le(owner, 16)?;
            if u32le(owner, 4)? != 1
                || u64le(owner, 8)? & 4 == 0
                || value < owner_start
                || value
                    .checked_add(size)
                    .ok_or("ELF local function overflow")?
                    > owner_start
                        .checked_add(u64le(owner, 32)?)
                        .ok_or("ELF local section overflow")?
            {
                return Err("ELF local function section rejected".into());
            }
            if is_name {
                if kind != 2 || bind != 0 || local.replace((value, size)).is_some() {
                    return Err("ELF local function ambiguous/binding".into());
                }
            } else {
                if bind != 1 && bind != 2 {
                    return Err("ELF public anchor binding".into());
                }
                let target = if kind == 11 {
                    &mut dynamic
                } else {
                    &mut public
                };
                if target.replace((value, size)).is_some() {
                    return Err("ELF public anchor ambiguous".into());
                }
            }
        }
    }
    let (value, size) = local.ok_or("ELF local function unavailable")?;
    let (anchor_value, anchor_size) = public.ok_or("ELF local anchor unavailable")?;
    if dynamic != Some((anchor_value, anchor_size)) {
        return Err("ELF local public anchor mismatch".into());
    }
    Ok(LocalFunction {
        value,
        size,
        anchor_value,
        anchor_size,
    })
}

/// The loader's observed program headers, copied while its owner is pinned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappedLoad {
    pub address: u64,
    pub offset: u64,
    pub files: u64,
    pub memory: u64,
    pub flags: u32,
}

pub fn file_loads(bytes: &[u8]) -> Result<Vec<MappedLoad>> {
    if bytes.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || u16le(bytes, 18)? != 183
        || u16le(bytes, 54)? != 56
    {
        return Err("ELF mapped owner header".into());
    }
    let count = u16le(bytes, 56)? as usize;
    if !(1..=128).contains(&count) {
        return Err("ELF mapped owner count".into());
    }
    let at = usize::try_from(u64le(bytes, 32)?).map_err(|_| "ELF mapped owner offset")?;
    let table = bytes
        .get(
            at..at
                .checked_add(count * 56)
                .ok_or("ELF mapped owner overflow")?,
        )
        .ok_or("ELF mapped owner table")?;
    let mut loads = Vec::new();
    for p in table.as_chunks::<56>().0.iter() {
        if u32le(p, 0)? == 1 {
            loads.push(MappedLoad {
                address: u64le(p, 16)?,
                offset: u64le(p, 8)?,
                files: u64le(p, 32)?,
                memory: u64le(p, 40)?,
                flags: u32le(p, 4)?,
            });
        }
    }
    Ok(loads)
}

/// Derive a callable candidate only after actual loader metadata and actual
/// anchor address agree. Caller still MUST hold the loaded owner and compare
/// both functions' mapped bytes against function_bytes before publishing it.
pub fn checked_mapped_function(
    bytes: &[u8],
    symbol: LocalFunction,
    base: u64,
    anchor_address: u64,
    mapped: &[MappedLoad],
    forbidden: u64,
) -> Result<u64> {
    let file = file_loads(bytes)?;
    if file.is_empty() || file != mapped {
        return Err("ELF mapped owner headers differ".into());
    }
    if base.checked_add(symbol.anchor_value) != Some(anchor_address) {
        return Err("ELF mapped owner anchor address".into());
    }
    let target = base
        .checked_add(symbol.value)
        .ok_or("ELF mapped local address overflow")?;
    if target == 0 || target == forbidden {
        return Err("ELF mapped local self/zero address".into());
    }
    for (value, size) in [
        (symbol.value, symbol.size),
        (symbol.anchor_value, symbol.anchor_size),
    ] {
        let end = value
            .checked_add(size)
            .ok_or("ELF mapped function overflow")?;
        if size == 0
            || size > 65536
            || mapped
                .iter()
                .filter(|p| {
                    p.flags & 5 == 5
                        && value >= p.address
                        && p.address
                            .checked_add(p.files)
                            .is_some_and(|stop| end <= stop)
                })
                .count()
                != 1
        {
            return Err("ELF mapped function not readable executable".into());
        }
        base.checked_add(end)
            .ok_or("ELF mapped function absolute overflow")?;
    }
    Ok(target)
}

pub fn function_bytes(bytes: &[u8], value: u64, size: u64) -> Result<&[u8]> {
    let end = value
        .checked_add(size)
        .ok_or("ELF function bytes overflow")?;
    let mut result = None;
    for p in file_loads(bytes)? {
        if p.flags & 5 == 5
            && value >= p.address
            && p.address
                .checked_add(p.files)
                .is_some_and(|stop| end <= stop)
        {
            if result.is_some() {
                return Err("ELF function bytes ambiguous".into());
            }
            let start = usize::try_from(
                p.offset
                    .checked_add(value - p.address)
                    .ok_or("ELF function bytes offset")?,
            )
            .map_err(|_| "ELF function bytes offset")?;
            let count = usize::try_from(size).map_err(|_| "ELF function bytes size")?;
            result = Some(
                bytes
                    .get(start..start.checked_add(count).ok_or("ELF function bytes range")?)
                    .ok_or("ELF function bytes bounds")?,
            );
        }
    }
    result.ok_or_else(|| "ELF function bytes unavailable".into())
}

#[cfg(test)]
mod local_symbol_tests {
    use super::*;

    #[test]
    fn fixed_oem_name_can_be_read_without_accepting_untrusted_paths() {
        let dir = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let path = dir.path().join("libstdc++.so.6");
        std::fs::write(&path, b"oem").unwrap();
        let path = path.to_str().unwrap();
        let exact = alloc::ffi::CString::new(path).unwrap();
        assert_eq!(read(path, 3).unwrap_err(), "unsafe compatibility path");
        assert_eq!(read_file(&exact, 3).unwrap(), b"oem");
        assert!(read_file(&exact, 2).is_err());
    }
    fn put16(b: &mut [u8], at: usize, v: u16) {
        b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put64(b: &mut [u8], at: usize, v: u64) {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn fixture() -> Vec<u8> {
        let mut b = alloc::vec![0;0x600];
        b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        put16(&mut b, 16, 3);
        put16(&mut b, 18, 183);
        put32(&mut b, 20, 1);
        put64(&mut b, 32, 64);
        put64(&mut b, 40, 0x200);
        put16(&mut b, 52, 64);
        put16(&mut b, 54, 56);
        put16(&mut b, 56, 1);
        put16(&mut b, 58, 64);
        put16(&mut b, 60, 5);
        put32(&mut b, 64, 1);
        put32(&mut b, 68, 5);
        put64(&mut b, 96, 0x600);
        put64(&mut b, 104, 0x600);
        let text = 0x240;
        put32(&mut b, text + 4, 1);
        put64(&mut b, text + 8, 4);
        put64(&mut b, text + 16, 0x100);
        put64(&mut b, text + 24, 0x100);
        put64(&mut b, text + 32, 0x40);
        let names = b"\0_Unwind_Resume\0__gxx_personality_v0\0";
        b[0x180..0x180 + names.len()].copy_from_slice(names);
        let strings = 0x280;
        put32(&mut b, strings + 4, 3);
        put64(&mut b, strings + 24, 0x180);
        put64(&mut b, strings + 32, names.len() as u64);
        for (section, offset, length, kind) in [(0x2c0, 0x400, 72, 2), (0x300, 0x480, 48, 11)] {
            put32(&mut b, section + 4, kind);
            put64(&mut b, section + 24, offset);
            put64(&mut b, section + 32, length);
            put32(&mut b, section + 40, 2);
            put64(&mut b, section + 56, 24);
        }
        fn symbol(b: &mut [u8], at: usize, name: u32, info: u8, value: u64) {
            put32(b, at, name);
            b[at + 4] = info;
            put16(b, at + 6, 1);
            put64(b, at + 8, value);
            put64(b, at + 16, 4);
        }
        symbol(&mut b, 0x418, 1, 2, 0x100);
        symbol(&mut b, 0x430, 16, 0x12, 0x110);
        symbol(&mut b, 0x498, 16, 0x12, 0x110);
        b
    }
    #[test]
    fn local_function_is_unique_executable_and_anchor_bound() {
        let bytes = fixture();
        let found = local_function(&bytes, "_Unwind_Resume", "__gxx_personality_v0").unwrap();
        assert_eq!(
            found,
            LocalFunction {
                value: 0x100,
                size: 4,
                anchor_value: 0x110,
                anchor_size: 4
            }
        );
        for mutation in 0..11 {
            let mut bad = bytes.clone();
            match mutation {
                0 => bad[5] = 2,
                1 => put16(&mut bad, 18, 62),
                2 => put16(&mut bad, 60, 0),
                3 => bad[0x41c] = 0x12,
                4 => bad[0x41c] = 1,
                5 => put64(&mut bad, 0x428, 0),
                6 => put64(&mut bad, 0x420, 0x700),
                7 => put32(&mut bad, 68, 4),
                8 => put64(&mut bad, 0x4a0, 0x114),
                9 => put64(&mut bad, 0x2f8, 16),
                _ => put32(&mut bad, 0x2e8, 99),
            }
            assert!(
                local_function(&bad, "_Unwind_Resume", "__gxx_personality_v0").is_err(),
                "case {mutation}"
            );
        }
        assert!(local_function(&bytes, "missing", "__gxx_personality_v0").is_err());
        let mut duplicate = bytes.clone();
        let local = duplicate[0x418..0x430].to_vec();
        duplicate[0x430..0x448].copy_from_slice(&local);
        assert!(local_function(&duplicate, "_Unwind_Resume", "__gxx_personality_v0").is_err());
    }
    #[test]
    fn mapped_function_rejects_wrong_owner_anchor_self_and_ranges() {
        let bytes = fixture();
        let symbol = local_function(&bytes, "_Unwind_Resume", "__gxx_personality_v0").unwrap();
        let loads = file_loads(&bytes).unwrap();
        let base = 0x100000;
        let proof = |tamper: bool| {
            local_provider::prove(&bytes, base, base + 0x110, &loads, 0, |at, len| {
                let mut content = function_bytes(&bytes, at - base, len as u64)?.to_vec();
                if tamper {
                    content[0] ^= 1;
                }
                Ok(content)
            })
        };
        assert_eq!(proof(false).unwrap(), base + 0x100);
        assert!(proof(true).is_err());
        assert_eq!(
            checked_mapped_function(&bytes, symbol, base, base + 0x110, &loads, 0).unwrap(),
            base + 0x100
        );
        assert_eq!(
            function_bytes(&bytes, symbol.value, symbol.size).unwrap(),
            &[0, 0, 0, 0]
        );
        assert!(checked_mapped_function(&bytes, symbol, base, base + 0x114, &loads, 0).is_err());
        assert!(
            checked_mapped_function(&bytes, symbol, base, base + 0x110, &loads, base + 0x100)
                .is_err()
        );
        let mut other = loads.clone();
        other[0].files -= 1;
        assert!(checked_mapped_function(&bytes, symbol, base, base + 0x110, &other, 0).is_err());
        let mut nonread = bytes.clone();
        put32(&mut nonread, 68, 1);
        let nonread_loads = file_loads(&nonread).unwrap();
        assert!(
            checked_mapped_function(&nonread, symbol, base, base + 0x110, &nonread_loads, 0)
                .is_err()
        );
        assert!(checked_mapped_function(&bytes, symbol, u64::MAX, u64::MAX, &loads, 0).is_err());
        assert!(function_bytes(&bytes, 0x5ff, 4).is_err());
    }
    #[test]
    #[ignore = "requires original A9 and A11 OEM ELF paths through environment"]
    fn local_function_original_a9_a11() {
        for variable in ["VOBOOST_TEST_A9_GNU_ELF", "VOBOOST_TEST_A11_GNU_ELF"] {
            let path = std::env::var(variable).expect("original OEM path required");
            let bytes = std::fs::read(path).unwrap();
            let result = local_function(&bytes, "_Unwind_Resume", "__gxx_personality_v0").unwrap();
            assert!(result.size > 0 && result.value != result.anchor_value);
            let mut stripped = bytes.clone();
            put16(&mut stripped, 60, 0);
            assert!(local_function(&stripped, "_Unwind_Resume", "__gxx_personality_v0").is_err());
        }
    }
}
