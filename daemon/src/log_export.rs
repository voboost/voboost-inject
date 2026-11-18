//! Canonical daemon log-stream producer, independent of storage and transport.
use sha2::{Digest, Sha256};
use std::io;

pub const MAX_EXPORT_BYTES: usize = 400 * 1024 * 1024;
pub(crate) const MAGIC: &[u8; 10] = b"VBOOSTLOG1";

pub fn encode(records: &[u8], context: &[u8]) -> io::Result<Vec<u8>> {
    let header = serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"recordsLength":records.len(),"contextLength":context.len()})).map_err(|error| invalid(&error.to_string()))?;
    let payload_len = records
        .len()
        .checked_add(context.len())
        .ok_or_else(|| invalid("export length overflow"))?;
    if payload_len > MAX_EXPORT_BYTES {
        return Err(invalid("export exceeds bound"));
    }
    let mut digest = Sha256::new();
    digest.update(records);
    digest.update(context);
    let mut out = Vec::with_capacity(10 + 1 + 4 + 8 + 32 + header.len() + payload_len);
    out.extend_from_slice(MAGIC);
    out.push(1);
    out.extend_from_slice(&(header.len() as u32).to_be_bytes());
    out.extend_from_slice(&(payload_len as u64).to_be_bytes());
    out.extend_from_slice(&digest.finalize());
    out.extend_from_slice(&header);
    out.extend_from_slice(records);
    out.extend_from_slice(context);
    Ok(out)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(crate) fn timestamp_epoch_millis(value: &str) -> Option<u64> {
    let bytes = value.as_bytes();
    if bytes.len() != 24
        || !bytes
            .iter()
            .enumerate()
            .all(|(i, b)| matches!(i, 4 | 7 | 10 | 13 | 16 | 19 | 23) || b.is_ascii_digit())
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'.'
        || bytes[23] != b'Z'
    {
        return None;
    }
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_year = value[0..4].parse::<i32>().ok()? - 1900;
    tm.tm_mon = value[5..7].parse::<i32>().ok()? - 1;
    tm.tm_mday = value[8..10].parse().ok()?;
    tm.tm_hour = value[11..13].parse().ok()?;
    tm.tm_min = value[14..16].parse().ok()?;
    tm.tm_sec = value[17..19].parse().ok()?;
    let original = (
        tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
    );
    let seconds = unsafe { libc::timegm(&mut tm) };
    if seconds < 0
        || original
            != (
                tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
            )
    {
        return None;
    }
    (seconds as u64)
        .checked_mul(1000)?
        .checked_add(value[20..23].parse().ok()?)
}
