//! Read-only hardware coding probe. The OEM NVRAM reader may repair storage and is not called.
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

const DEVICE: &str = "/dev/block/vdh";
const HEADER: u64 = 0;
const PRIMARY: u64 = 0x200;
const MIRROR: u64 = 0x20200;
const ITEM: u64 = 51 * 32;
const MARKER: u64 = 127 * 32;

#[derive(PartialEq, Eq)]
struct Snapshot {
    header: [u8; 512],
    primary_marker: [u8; 32],
    mirror_marker: [u8; 32],
    primary_item: [u8; 32],
    mirror_item: [u8; 32],
}

/// Installation/explicit diagnostics only; kernel block reads have no userspace timeout.
pub(crate) fn probe() -> io::Result<Option<&'static str>> {
    let path = Path::new(DEVICE);
    let before = std::fs::symlink_metadata(path)?;
    if !before.file_type().is_block_device() {
        return Err(invalid());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let identity = |metadata: &std::fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.rdev(),
            metadata.mode(),
        )
    };
    if identity(&file.metadata()?) != identity(&before) {
        return Err(invalid());
    }
    let result = read_with(|offset, bytes| read_exact_at(&file, offset, bytes))?;
    if identity(&file.metadata()?) != identity(&before)
        || identity(&std::fs::symlink_metadata(path)?) != identity(&before)
    {
        return Err(invalid());
    }
    Ok(result)
}

fn read_exact_at(file: &File, mut offset: u64, mut bytes: &mut [u8]) -> io::Result<()> {
    let mut interrupted = 0;
    while !bytes.is_empty() {
        match file.read_at(bytes, offset) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => {
                offset += count as u64;
                bytes = &mut bytes[count..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted && interrupted < 3 => {
                interrupted += 1;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn snapshot(read: &mut impl FnMut(u64, &mut [u8]) -> io::Result<()>) -> io::Result<Snapshot> {
    let mut value = Snapshot {
        header: [0; 512],
        primary_marker: [0; 32],
        mirror_marker: [0; 32],
        primary_item: [0; 32],
        mirror_item: [0; 32],
    };
    read(HEADER, &mut value.header)?;
    read(PRIMARY + MARKER, &mut value.primary_marker)?;
    read(MIRROR + MARKER, &mut value.mirror_marker)?;
    read(PRIMARY + ITEM, &mut value.primary_item)?;
    read(MIRROR + ITEM, &mut value.mirror_item)?;
    Ok(value)
}

fn read_with(
    mut read: impl FnMut(u64, &mut [u8]) -> io::Result<()>,
) -> io::Result<Option<&'static str>> {
    let before = snapshot(&mut read)?;
    let after = snapshot(&mut read)?;
    if before != after
        || !matches!(before.header[0], 1 | 2)
        || before.primary_marker[0] > 3
        || before.mirror_marker[0] > 3
        || before.primary_item != before.mirror_item
    {
        return Err(invalid());
    }
    let end = before
        .primary_item
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(32);
    let text = &before.primary_item[..end];
    if text.len() < 26
        || !text.len().is_multiple_of(2)
        || !text.iter().all(u8::is_ascii_hexdigit)
        || before.primary_item[end..].iter().any(|byte| *byte != 0)
    {
        return Err(invalid());
    }
    let first = std::str::from_utf8(&text[..2]).map_err(|_| invalid())?;
    let transmission = u8::from_str_radix(first, 16).map_err(|_| invalid())? & 3;
    Ok(match transmission {
        0 => Some("ev"),
        1 => Some("hybrid"),
        _ => None,
    })
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "hardware powertrain coding is unavailable or inconsistent",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn fixture(first: &str) -> BTreeMap<u64, Vec<u8>> {
        let mut header = vec![0; 512];
        header[0] = 1;
        let mut item = vec![0; 32];
        let text = format!("{first}000000000000000000000000");
        item[..text.len()].copy_from_slice(text.as_bytes());
        BTreeMap::from([
            (HEADER, header),
            (PRIMARY + MARKER, vec![0; 32]),
            (MIRROR + MARKER, vec![1; 32]),
            (PRIMARY + ITEM, item.clone()),
            (MIRROR + ITEM, item),
        ])
    }
    fn run(values: &BTreeMap<u64, Vec<u8>>) -> io::Result<Option<&'static str>> {
        read_with(|offset, output| {
            let input = values.get(&offset).ok_or(io::ErrorKind::NotFound)?;
            if input.len() != output.len() {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            output.copy_from_slice(input);
            Ok(())
        })
    }

    #[test]
    fn original_transmission_bit_is_independent_of_other_hardware_options() {
        for first in ["01", "05", "09", "Fd"] {
            assert_eq!(run(&fixture(first)).unwrap(), Some("hybrid"));
        }
        for first in ["00", "04", "FC"] {
            assert_eq!(run(&fixture(first)).unwrap(), Some("ev"));
        }
        for first in ["02", "03", "FF"] {
            assert_eq!(run(&fixture(first)).unwrap(), None);
        }
    }

    #[test]
    fn both_valid_oem_generations_are_allowed_but_repair_is_never_attempted() {
        for header in [1, 2] {
            for primary in 0..=3 {
                for mirror in 0..=3 {
                    let mut values = fixture("01");
                    values.get_mut(&HEADER).unwrap()[0] = header;
                    values.get_mut(&(PRIMARY + MARKER)).unwrap()[0] = primary;
                    values.get_mut(&(MIRROR + MARKER)).unwrap()[0] = mirror;
                    assert_eq!(run(&values).unwrap(), Some("hybrid"));
                }
            }
        }
        for (offset, invalid_values) in [
            (HEADER, vec![0, 3, 255]),
            (PRIMARY + MARKER, vec![4, 255]),
            (MIRROR + MARKER, vec![4, 255]),
        ] {
            for invalid in invalid_values {
                let mut values = fixture("01");
                values.get_mut(&offset).unwrap()[0] = invalid;
                assert!(run(&values).is_err());
            }
        }
    }

    #[test]
    fn disagreement_and_malformed_or_short_coding_never_default_to_hybrid() {
        let mut values = fixture("01");
        values.get_mut(&(MIRROR + ITEM)).unwrap()[1] = b'0';
        assert!(run(&values).is_err());
        for malformed in [
            b"01".as_slice(),
            b"GG00000000000000000000000000",
            b"0100000000000000000000000",
        ] {
            let mut values = fixture("01");
            let mut item = vec![0; 32];
            item[..malformed.len()].copy_from_slice(malformed);
            values.insert(PRIMARY + ITEM, item.clone());
            values.insert(MIRROR + ITEM, item);
            assert!(run(&values).is_err());
        }
        let mut values = fixture("01");
        values.get_mut(&(MIRROR + ITEM)).unwrap().pop();
        assert_eq!(
            run(&values).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn changing_snapshot_and_read_error_never_become_stable_authority() {
        let values = fixture("01");
        let mut reads = 0;
        assert!(read_with(|offset, output| {
            output.copy_from_slice(&values[&offset]);
            reads += 1;
            if reads == 6 {
                output[0] = 2;
            }
            Ok(())
        })
        .is_err());
        assert_eq!(
            read_with(|_, _| Err(io::ErrorKind::PermissionDenied.into()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
