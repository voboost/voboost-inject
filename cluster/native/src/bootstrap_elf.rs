//! Read-only, bounded ELF loading and dynamic-export contract probe.
use crate::Result;
use alloc::vec::Vec;

fn u16le(b: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        b.get(at..at + 2)
            .ok_or("ELF u16 bounds")?
            .try_into()
            .map_err(|_| "ELF u16")?,
    ))
}
fn u32le(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4)
            .ok_or("ELF u32 bounds")?
            .try_into()
            .map_err(|_| "ELF u32")?,
    ))
}
fn u64le(b: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(at..at + 8)
            .ok_or("ELF u64 bounds")?
            .try_into()
            .map_err(|_| "ELF u64")?,
    ))
}
#[derive(Clone, Copy)]
struct Load {
    address: u64,
    offset: u64,
    files: u64,

    flags: u32,
}
fn mapped<'a>(bytes: &'a [u8], loads: &[Load], address: u64, length: u64) -> Result<&'a [u8]> {
    let end = address.checked_add(length).ok_or("ELF mapping overflow")?;
    let mut answer = None;
    for load in loads {
        if address >= load.address && end <= load.address + load.files {
            if answer.is_some() {
                return Err("ELF ambiguous file mapping".into());
            }
            let at = usize::try_from(
                load.offset
                    .checked_add(
                        address
                            .checked_sub(load.address)
                            .ok_or("ELF mapping relative offset")?,
                    )
                    .ok_or("ELF mapping file offset")?,
            )
            .map_err(|_| "ELF mapping offset")?;
            let count = usize::try_from(length).map_err(|_| "ELF mapping length")?;
            answer = Some(
                bytes
                    .get(at..at.checked_add(count).ok_or("ELF mapping end")?)
                    .ok_or("ELF mapping bounds")?,
            );
        }
    }
    answer.ok_or_else(|| "ELF address is not file-backed".into())
}
fn executable_address(loads: &[Load], address: u64) -> bool {
    loads.iter().any(|load| {
        load.flags & 1 != 0 && address >= load.address && address < load.address + load.files
    })
}

fn sysv_hash(name: &str) -> u32 {
    let mut hash = 0u32;
    for byte in name.bytes() {
        hash = hash.wrapping_shl(4).wrapping_add(byte as u32);
        let high = hash & 0xf0000000;
        if high != 0 {
            hash ^= high >> 24;
        }
        hash &= !high;
    }
    hash
}
fn gnu_hash(name: &str) -> u32 {
    name.bytes().fold(5381u32, |hash, byte| {
        hash.wrapping_mul(33).wrapping_add(byte as u32)
    })
}
fn reachable(
    bytes: &[u8],
    loads: &[Load],
    tags: &alloc::collections::BTreeMap<u64, u64>,
    name: &str,
    target: u64,
    count: u64,
) -> Result<bool> {
    if let Some(address) = tags.get(&4) {
        let head = mapped(bytes, loads, *address, 8)?;
        let buckets = u32le(head, 0)? as u64;
        let chains = u32le(head, 4)? as u64;
        if buckets == 0 || buckets > 1_000_000 || chains != count {
            return Err("ELF SysV lookup bounds".into());
        }
        let table = mapped(bytes, loads, *address, 8 + 4 * (buckets + chains))?;
        let mut symbol =
            u32le(table, (8 + 4 * (sysv_hash(name) as u64 % buckets)) as usize)? as u64;
        let mut found = false;
        for _ in 0..count {
            if symbol == 0 {
                break;
            }
            if symbol >= count {
                return Err("ELF SysV chain symbol bound".into());
            }
            if symbol == target {
                found = true;
                break;
            }
            symbol = u32le(table, (8 + 4 * buckets + 4 * symbol) as usize)? as u64;
        }
        if !found {
            return Ok(false);
        }
    }
    if let Some(address) = tags.get(&0x6ffffef5) {
        let head = mapped(bytes, loads, *address, 16)?;
        let buckets = u32le(head, 0)? as u64;
        let first = u32le(head, 4)? as u64;
        let blooms = u32le(head, 8)? as u64;
        let shift = u32le(head, 12)?;
        if buckets == 0
            || buckets > 1_000_000
            || blooms == 0
            || !blooms.is_power_of_two()
            || blooms > 1_000_000
            || shift >= 32
        {
            return Err("ELF GNU lookup bounds".into());
        }
        let hash = gnu_hash(name);
        let bloom_at = address
            .checked_add(16 + 8 * ((hash as u64 / 64) % blooms))
            .ok_or("ELF GNU bloom overflow")?;
        let word = u64le(mapped(bytes, loads, bloom_at, 8)?, 0)?;
        let mask = (1u64 << (hash % 64)) | (1u64 << ((hash >> shift) % 64));
        if word & mask != mask {
            return Ok(false);
        }
        let buckets_at = address
            .checked_add(16 + 8 * blooms)
            .ok_or("ELF GNU bucket overflow")?;
        let bucket_at = buckets_at
            .checked_add(4 * (hash as u64 % buckets))
            .ok_or("ELF GNU bucket overflow")?;
        let mut symbol = u32le(mapped(bytes, loads, bucket_at, 4)?, 0)? as u64;
        if symbol == 0 || symbol < first || symbol >= count {
            return Ok(false);
        }
        let chains_at = buckets_at
            .checked_add(4 * buckets)
            .ok_or("ELF GNU chain overflow")?;
        let mut found = false;
        while symbol < count {
            let chain_at = chains_at
                .checked_add(4 * (symbol - first))
                .ok_or("ELF GNU chain overflow")?;
            let chain = u32le(mapped(bytes, loads, chain_at, 4)?, 0)?;
            if symbol == target && chain | 1 == hash | 1 {
                found = true;
                break;
            }
            if chain & 1 != 0 {
                break;
            }
            symbol += 1;
        }
        if !found {
            return Ok(false);
        }
    }
    Ok(true)
}

/// ET_EXEC or PIE entry must be file-backed in an executable LOAD; library
/// probes additionally require exact defined dynamic function exports.
pub(super) fn probe(bytes: &[u8], executable: bool, required: &[&str]) -> Result<()> {
    inspect(bytes, executable, required, None).map(|_| ())
}

/// Select a single loader-visible definition using a closed caller ABI classifier.
#[cfg(any(target_os = "nto", test))]
pub(crate) fn select_export(
    bytes: &[u8],
    compatible: fn(&str) -> bool,
) -> Result<Option<alloc::string::String>> {
    inspect(bytes, false, &[], Some(compatible))
}

fn inspect(
    bytes: &[u8],
    executable: bool,
    required: &[&str],
    compatible: Option<fn(&str) -> bool>,
) -> Result<Option<alloc::string::String>> {
    if bytes.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || !matches!(u16le(bytes, 16)?, 2 | 3)
        || u16le(bytes, 18)? != 183
        || u32le(bytes, 20)? != 1
        || u16le(bytes, 52)? != 64
        || u16le(bytes, 54)? != 56
    {
        return Err("unsupported executable ELF header".into());
    }
    let at = usize::try_from(u64le(bytes, 32)?).map_err(|_| "ELF program offset")?;
    let count = u16le(bytes, 56)? as usize;
    if count == 0
        || count > 128
        || at < 64
        || bytes
            .get(at..at.checked_add(count * 56).ok_or("ELF program overflow")?)
            .is_none()
    {
        return Err("ELF program table bound".into());
    }
    let mut loads = Vec::new();
    let mut dynamic = None;
    for index in 0..count {
        let p = at + index * 56;
        let kind = u32le(bytes, p)?;
        let flags = u32le(bytes, p + 4)?;
        let offset = u64le(bytes, p + 8)?;
        let address = u64le(bytes, p + 16)?;
        let files = u64le(bytes, p + 32)?;
        let memory = u64le(bytes, p + 40)?;
        let align = u64le(bytes, p + 48)?;
        if (kind == 1 && files > memory)
            || offset
                .checked_add(files)
                .filter(|end| *end <= bytes.len() as u64)
                .is_none()
            || address.checked_add(memory).is_none()
            || (align > 1 && (!align.is_power_of_two() || address % align != offset % align))
        {
            return Err("ELF segment bounds/alignment rejected".into());
        }
        if kind == 1 {
            loads.push(Load {
                address,
                offset,
                files,
                flags,
            });
        } else if kind == 2 && dynamic.replace((address, files)).is_some() {
            return Err("ELF dynamic segment ambiguous".into());
        }
    }
    if !loads
        .iter()
        .any(|load| load.flags & 1 != 0 && load.files > 0)
        || (executable && !executable_address(&loads, u64le(bytes, 24)?))
    {
        return Err("ELF executable mapping missing".into());
    }
    if required.is_empty() && compatible.is_none() {
        return Ok(None);
    }
    let (address, length) = dynamic.ok_or("ELF dynamic segment missing")?;
    if length == 0 || length > 65536 || length % 16 != 0 {
        return Err("ELF dynamic table bound".into());
    }
    let table = mapped(bytes, &loads, address, length)?;
    let mut tags = alloc::collections::BTreeMap::new();
    let mut terminated = false;
    for at in (0..table.len()).step_by(16) {
        let tag = u64le(table, at)?;
        if tag == 0 {
            terminated = true;
            break;
        }
        if matches!(tag, 4 | 5 | 6 | 10 | 11 | 0x6ffffef5)
            && tags.insert(tag, u64le(table, at + 8)?).is_some()
        {
            return Err("ELF duplicate dynamic metadata".into());
        }
    }
    if !terminated || tags.get(&11) != Some(&24) {
        return Err("ELF dynamic symbol layout rejected".into());
    }
    let strings_at = *tags.get(&5).ok_or("ELF string table missing")?;
    let strings_len = *tags.get(&10).ok_or("ELF string bound missing")?;
    if strings_len == 0 || strings_len > 4 * 1024 * 1024 {
        return Err("ELF string bound rejected".into());
    }
    let strings = mapped(bytes, &loads, strings_at, strings_len)?;
    let symbols_at = *tags.get(&6).ok_or("ELF symbol table missing")?;
    let symbols = if let Some(hash) = tags.get(&4) {
        let head = mapped(bytes, &loads, *hash, 8)?;
        let buckets = u32le(head, 0)? as u64;
        let symbols = u32le(head, 4)? as u64;
        if buckets == 0 || buckets > 1_000_000 || symbols == 0 || symbols > 1_000_000 {
            return Err("ELF hash bound rejected".into());
        }
        mapped(bytes, &loads, *hash, 8 + 4 * (buckets + symbols))?;
        symbols
    } else if let Some(hash) = tags.get(&0x6ffffef5) {
        let head = mapped(bytes, &loads, *hash, 16)?;
        let buckets = u32le(head, 0)? as u64;
        let first = u32le(head, 4)? as u64;
        let blooms = u32le(head, 8)? as u64;
        if buckets == 0
            || buckets > 1_000_000
            || blooms == 0
            || !blooms.is_power_of_two()
            || blooms > 1_000_000
            || first > 1_000_000
        {
            return Err("ELF GNU hash bound rejected".into());
        }
        let bucket_at = hash
            .checked_add(16 + 8 * blooms)
            .ok_or("ELF GNU bucket overflow")?;
        let bucket_bytes = mapped(bytes, &loads, bucket_at, 4 * buckets)?;
        let chains_at = bucket_at
            .checked_add(4 * buckets)
            .ok_or("ELF GNU chains overflow")?;
        let mut last = first;
        let mut work = 0;
        for bucket in 0..buckets as usize {
            let mut symbol = u32le(bucket_bytes, bucket * 4)? as u64;
            if symbol == 0 {
                continue;
            }
            if symbol < first || symbol >= 1_000_000 {
                return Err("ELF GNU symbol bound rejected".into());
            }
            loop {
                work += 1;
                if work > 1_000_000 || symbol >= 1_000_000 {
                    return Err("ELF GNU chain bound rejected".into());
                }
                let at = chains_at
                    .checked_add(4 * (symbol - first))
                    .ok_or("ELF GNU chain overflow")?;
                let chain = u32le(mapped(bytes, &loads, at, 4)?, 0)?;
                last = last.max(symbol + 1);
                if chain & 1 != 0 {
                    break;
                }
                symbol += 1;
            }
        }
        last
    } else {
        return Err("ELF bounded dynamic symbol count missing".into());
    };
    let symbols = mapped(bytes, &loads, symbols_at, symbols * 24)?;
    let mut found = alloc::vec![false; required.len()];
    let mut selected = None;
    for (symbol_index, symbol) in symbols.as_chunks::<24>().0.iter().enumerate() {
        let name = u32le(symbol, 0)? as usize;
        let tail = strings.get(name..).ok_or("ELF symbol name bounds")?;
        if let Some(compatible) = compatible {
            if let Some(end) = tail.iter().take(513).position(|byte| *byte == 0) {
                if let Ok(name) = core::str::from_utf8(&tail[..end]) {
                    if compatible(name) {
                        if selected.is_some()
                            || !matches!(symbol[4] >> 4, 1 | 2)
                            || symbol[4] & 15 != 2
                            || !matches!(symbol[5] & 3, 0 | 3)
                            || u16le(symbol, 6)? == 0
                            || !executable_address(&loads, u64le(symbol, 8)?)
                            || !reachable(
                                bytes,
                                &loads,
                                &tags,
                                name,
                                symbol_index as u64,
                                symbols.len() as u64 / 24,
                            )?
                        {
                            return Err("lookup export invalid or ambiguous".into());
                        }
                        selected = Some(name.into());
                    }
                }
            }
        }
        for (index, wanted) in required.iter().enumerate() {
            if tail.get(..wanted.len()) != Some(wanted.as_bytes())
                || tail.get(wanted.len()) != Some(&0)
            {
                continue;
            }
            if found[index]
                || !matches!(symbol[4] >> 4, 1 | 2)
                || !matches!(symbol[4] & 15, 2 | 10)
                || !matches!(symbol[5] & 3, 0 | 3)
                || u16le(symbol, 6)? == 0
                || !executable_address(&loads, u64le(symbol, 8)?)
            {
                return Err("ELF function export invalid or ambiguous".into());
            }
            if !reachable(
                bytes,
                &loads,
                &tags,
                wanted,
                symbol_index as u64,
                symbols.len() as u64 / 24,
            )? {
                return Err("required export is unreachable by loader lookup".into());
            }
            found[index] = true;
        }
    }
    if found.iter().any(|present| !present) {
        return Err("required OEM function export missing".into());
    }
    Ok(selected)
}

#[cfg(test)]
pub(crate) fn lookup_fixture(name: &str) -> Vec<u8> {
    let mut bytes = tests::fixture();
    bytes.resize(2048, 0);
    bytes[96..104].copy_from_slice(&2048u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&2048u64.to_le_bytes());
    bytes[264..272].copy_from_slice(&0x400400u64.to_le_bytes());
    bytes[280..288].copy_from_slice(&256u64.to_le_bytes());
    bytes[1025..1025 + name.len()].copy_from_slice(name.as_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn fixture() -> Vec<u8> {
        let mut b = alloc::vec![0; 1024];
        b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        b[16..18].copy_from_slice(&3u16.to_le_bytes());
        b[18..20].copy_from_slice(&183u16.to_le_bytes());
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        b[24..32].copy_from_slice(&0x400320u64.to_le_bytes());
        b[32..40].copy_from_slice(&64u64.to_le_bytes());
        b[52..54].copy_from_slice(&64u16.to_le_bytes());
        b[54..56].copy_from_slice(&56u16.to_le_bytes());
        b[56..58].copy_from_slice(&2u16.to_le_bytes());
        b[64..68].copy_from_slice(&1u32.to_le_bytes());
        b[68..72].copy_from_slice(&5u32.to_le_bytes());
        b[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
        b[96..104].copy_from_slice(&1024u64.to_le_bytes());
        b[104..112].copy_from_slice(&1024u64.to_le_bytes());
        b[112..120].copy_from_slice(&4096u64.to_le_bytes());
        b[120..124].copy_from_slice(&2u32.to_le_bytes());
        b[128..136].copy_from_slice(&256u64.to_le_bytes());
        b[136..144].copy_from_slice(&0x400100u64.to_le_bytes());
        b[152..160].copy_from_slice(&96u64.to_le_bytes());
        b[160..168].copy_from_slice(&96u64.to_le_bytes());
        for (i, (tag, value)) in [
            (5u64, 0x400200u64),
            (10, 64),
            (6, 0x400258),
            (11, 24),
            (4, 0x4002bc),
            (0, 0),
        ]
        .iter()
        .enumerate()
        {
            b[256 + i * 16..264 + i * 16].copy_from_slice(&tag.to_le_bytes());
            b[264 + i * 16..272 + i * 16].copy_from_slice(&value.to_le_bytes());
        }
        b[513..518].copy_from_slice(b"hook\0");
        b[624..628].copy_from_slice(&1u32.to_le_bytes());
        b[628] = 0x12;
        b[630..632].copy_from_slice(&1u16.to_le_bytes());
        b[632..640].copy_from_slice(&0x400320u64.to_le_bytes());
        b[700..704].copy_from_slice(&1u32.to_le_bytes());
        b[704..708].copy_from_slice(&2u32.to_le_bytes());
        b[708..712].copy_from_slice(&1u32.to_le_bytes());
        b
    }
    #[test]
    fn lookup_selection_rejects_duplicate_loader_definitions() {
        let mut bytes = lookup_fixture("lookup");
        bytes.copy_within(624..648, 648);
        bytes[704..708].copy_from_slice(&3u32.to_le_bytes());
        bytes[716..720].copy_from_slice(&2u32.to_le_bytes());
        assert!(select_export(&bytes, |name| name == "lookup").is_err());
    }

    #[test]
    fn accepts_loadable_actual_dynamic_export_not_note_only() {
        let bytes = fixture();
        probe(&bytes, true, &["hook"]).unwrap();
        assert!(probe(&bytes, true, &["missing"]).is_err());
        let mut note_only = bytes.clone();
        note_only[64..68].copy_from_slice(&4u32.to_le_bytes());
        assert!(probe(&note_only, true, &[]).is_err());
        let mut non_executable = bytes.clone();
        non_executable[68..72].copy_from_slice(&4u32.to_le_bytes());
        assert!(probe(&non_executable, true, &[]).is_err());
        let mut entry_outside = bytes;
        entry_outside[24..32].copy_from_slice(&0x500000u64.to_le_bytes());
        assert!(probe(&entry_outside, true, &[]).is_err());
    }
    #[test]
    fn accepts_gnu_hash_and_rejects_unterminated_chain() {
        let mut bytes = fixture();
        bytes[320..328].copy_from_slice(&0x6ffffef5u64.to_le_bytes());
        bytes[700..704].copy_from_slice(&1u32.to_le_bytes());
        bytes[704..708].copy_from_slice(&1u32.to_le_bytes());
        bytes[708..712].copy_from_slice(&1u32.to_le_bytes());
        bytes[712..716].copy_from_slice(&0u32.to_le_bytes());
        let hash = gnu_hash("hook");
        let mask = (1u64 << (hash % 64)) | (1u64 << (hash % 64));
        bytes[716..724].copy_from_slice(&mask.to_le_bytes());
        bytes[724..728].copy_from_slice(&1u32.to_le_bytes());
        bytes[728..732].copy_from_slice(&(hash | 1).to_le_bytes());
        probe(&bytes, true, &["hook"]).unwrap();
        let mut bad_bloom_count = bytes.clone();
        bad_bloom_count[708..712].copy_from_slice(&3u32.to_le_bytes());
        assert!(probe(&bad_bloom_count, true, &["hook"]).is_err());
        let mut empty_bloom = bytes.clone();
        empty_bloom[716..724].copy_from_slice(&0u64.to_le_bytes());
        assert!(probe(&empty_bloom, true, &["hook"]).is_err());
        let mut wrong_hash = bytes.clone();
        wrong_hash[728..732].copy_from_slice(&((hash ^ 2) | 1).to_le_bytes());
        assert!(probe(&wrong_hash, true, &["hook"]).is_err());

        bytes[728..732].copy_from_slice(&0u32.to_le_bytes());
        assert!(probe(&bytes, true, &["hook"]).is_err());
    }
    #[test]
    fn rejects_unreachable_sysv_symbol_and_maps_high_virtual_addresses() {
        let mut bytes = fixture();
        bytes[708..712].copy_from_slice(&0u32.to_le_bytes());
        assert!(probe(&bytes, true, &["hook"]).is_err());
        let load = Load {
            address: u64::MAX - 15,
            offset: 9,
            files: 8,
            flags: 5,
        };
        assert_eq!(mapped(&[0u8; 17], &[load], u64::MAX - 8, 1).unwrap(), &[0]);
    }
    #[test]
    fn rejects_import_only_hidden_unmapped_exports_and_bad_tables() {
        for mutate in [
            |b: &mut Vec<u8>| b[630..632].copy_from_slice(&0u16.to_le_bytes()),
            |b: &mut Vec<u8>| b[629] = 2,
            |b: &mut Vec<u8>| b[632..640].copy_from_slice(&0x500000u64.to_le_bytes()),
            |b: &mut Vec<u8>| b[704..708].copy_from_slice(&u32::MAX.to_le_bytes()),
            |b: &mut Vec<u8>| b[18..20].copy_from_slice(&62u16.to_le_bytes()),
        ] {
            let mut bytes = fixture();
            mutate(&mut bytes);
            assert!(probe(&bytes, true, &["hook"]).is_err());
        }
    }
}
