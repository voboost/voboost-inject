//! Bounded binary bootstrap envelope streamed over the existing downlink pipe.

use std::io;

pub const MAGIC: &[u8; 8] = b"VOBOOST1";
pub const MAX_MANIFEST: usize = 2 * 1024 * 1024;
pub const MAX_FILES: usize = 64;
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// Payload bytes admitted to one target process. The signed release may be
/// larger because its files can serve different processes.
pub const MAX_PROCESS_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;
const HEADER_BYTES: u64 = 8 + 4 + 4 + 8;
const FILE_HEADER_BYTES: u64 = 2 + 8;
pub const MAX_ENVELOPE_BYTES: u64 = HEADER_BYTES
    + MAX_MANIFEST as u64
    + MAX_FILES as u64 * (FILE_HEADER_BYTES + 255)
    + MAX_PROCESS_PAYLOAD_BYTES;

/// A signed, already-authorized file description. Payload bytes are loaded
/// only after the complete wire layout and one exact allocation are checked.
pub struct File<'a> {
    pub name: &'a str,
    pub size: u64,
}

#[derive(Debug)]
struct Layout {
    payload_bytes: u64,
    envelope_bytes: usize,
}

fn checked_layout(manifest: &[u8], files: &[File<'_>]) -> io::Result<Layout> {
    if manifest.is_empty()
        || manifest.len() > MAX_MANIFEST
        || files.is_empty()
        || files.len() > MAX_FILES
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid bootstrap bounds",
        ));
    }

    let mut payload_bytes = 0u64;
    let mut envelope_bytes = HEADER_BYTES
        .checked_add(manifest.len() as u64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bootstrap size overflow"))?;
    for file in files {
        if file.name.is_empty() || file.name.len() > 255 || file.size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid bootstrap file",
            ));
        }
        payload_bytes = payload_bytes.checked_add(file.size).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "bootstrap size overflow")
        })?;
        envelope_bytes = envelope_bytes
            .checked_add(FILE_HEADER_BYTES)
            .and_then(|size| size.checked_add(file.name.len() as u64))
            .and_then(|size| size.checked_add(file.size))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "bootstrap size overflow")
            })?;
        if file.size > MAX_FILE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid bootstrap file",
            ));
        }
    }
    if payload_bytes > MAX_PROCESS_PAYLOAD_BYTES || envelope_bytes > MAX_ENVELOPE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bootstrap exceeds per-process memory bound",
        ));
    }
    let envelope_bytes = usize::try_from(envelope_bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "bootstrap envelope does not fit address space",
        )
    })?;
    Ok(Layout {
        payload_bytes,
        envelope_bytes,
    })
}

pub(crate) fn validate_layout(manifest: &[u8], files: &[File<'_>]) -> io::Result<()> {
    checked_layout(manifest, files).map(|_| ())
}

/// Build the exact `VBOOST1` wire image without retaining a second complete
/// payload set. The caller's loader is invoked in descriptor order and may
/// re-open/re-verify each generation file. Peak construction storage is the
/// final envelope plus the one file currently returned by `load`.
pub fn build<F>(manifest: &[u8], files: &[File<'_>], load: F) -> io::Result<Vec<u8>>
where
    F: FnMut(usize) -> io::Result<Vec<u8>>,
{
    build_with_reserve(manifest, files, load, |output, exact| {
        output.try_reserve_exact(exact).map_err(|error| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                format!("reserve bootstrap envelope: {error}"),
            )
        })
    })
}

fn build_with_reserve<F, R>(
    manifest: &[u8],
    files: &[File<'_>],
    mut load: F,
    reserve: R,
) -> io::Result<Vec<u8>>
where
    F: FnMut(usize) -> io::Result<Vec<u8>>,
    R: FnOnce(&mut Vec<u8>, usize) -> io::Result<()>,
{
    let layout = checked_layout(manifest, files)?;
    let mut output = Vec::new();
    reserve(&mut output, layout.envelope_bytes)?;

    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
    output.extend_from_slice(&(files.len() as u32).to_le_bytes());
    output.extend_from_slice(&layout.payload_bytes.to_le_bytes());
    output.extend_from_slice(manifest);
    for (index, file) in files.iter().enumerate() {
        let bytes = load(index)?;
        // The wire layout is self-describing: the header's total payload
        // count is computed from the descriptors (checked_layout), so every
        // streamed file MUST match its declared size. A generation whose
        // on-disk files differ from the catalog descriptors (observed live
        // 2026-09-18: a dex replaced in the generation dir without updating
        // the catalog) otherwise builds an envelope the implant rejects with
        // payload-total-mismatch -> phase-2 "pipe bootstrap read failed" ->
        // daemon retry loop -> circuit breaker, while processes whose file
        // set still matches inject fine. Fail closed at build time instead.
        if bytes.len() as u64 != file.size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "bootstrap file {} size {} differs from descriptor {}",
                    file.name,
                    bytes.len(),
                    file.size
                ),
            ));
        }
        output.extend_from_slice(&(file.name.len() as u16).to_le_bytes());
        output.extend_from_slice(file.name.as_bytes());
        output.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        output.extend_from_slice(&bytes);
    }
    debug_assert_eq!(output.len(), layout.envelope_bytes);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn envelope_is_deterministic_and_preserves_descriptor_order() {
        let files = [
            File {
                name: "agents.dex",
                size: 3,
            },
            File {
                name: "module.dex",
                size: 2,
            },
        ];
        let payloads: [&[u8]; 2] = [b"dex", b"m2"];
        let mut order = Vec::new();
        let out = build(br#"{"schemaVersion":1}"#, &files, |index| {
            order.push(index);
            Ok(payloads[index].to_vec())
        })
        .unwrap();
        assert_eq!(order, vec![0, 1]);
        assert_eq!(&out[..8], MAGIC);
        assert_eq!(u32::from_le_bytes(out[8..12].try_into().unwrap()), 19);
        assert_eq!(u32::from_le_bytes(out[12..16].try_into().unwrap()), 2);
        assert_eq!(u64::from_le_bytes(out[16..24].try_into().unwrap()), 5);
        let mut expected = MAGIC.to_vec();
        expected.extend_from_slice(&19u32.to_le_bytes());
        expected.extend_from_slice(&2u32.to_le_bytes());
        expected.extend_from_slice(&5u64.to_le_bytes());
        expected.extend_from_slice(br#"{"schemaVersion":1}"#);
        for (name, payload) in [("agents.dex", b"dex" as &[u8]), ("module.dex", b"m2")] {
            expected.extend_from_slice(&(name.len() as u16).to_le_bytes());
            expected.extend_from_slice(name.as_bytes());
            expected.extend_from_slice(&(payload.len() as u64).to_le_bytes());
            expected.extend_from_slice(payload);
        }
        assert_eq!(out, expected);
        let module_offset = out
            .windows(b"module.dex".len())
            .position(|w| w == b"module.dex")
            .unwrap();
        let core_offset = out
            .windows(b"agents.dex".len())
            .position(|w| w == b"agents.dex")
            .unwrap();
        assert!(core_offset < module_offset);
    }

    #[test]
    fn exact_process_bound_is_accepted_without_allocating_payload() {
        let layout = checked_layout(
            b"{}",
            &[File {
                name: "agents.dex",
                size: MAX_PROCESS_PAYLOAD_BYTES,
            }],
        )
        .unwrap();
        assert_eq!(layout.payload_bytes, MAX_PROCESS_PAYLOAD_BYTES);
        assert!(layout.envelope_bytes as u64 <= MAX_ENVELOPE_BYTES);
    }

    #[test]
    fn over_bound_and_arithmetic_overflow_fail_before_loading() {
        let loaded = Cell::new(false);
        let over = [
            File {
                name: "a",
                size: MAX_FILE_BYTES,
            },
            File { name: "b", size: 1 },
        ];
        assert!(build(b"{}", &over, |_| {
            loaded.set(true);
            Ok(Vec::new())
        })
        .is_err());
        assert!(!loaded.get());

        let overflow_error = checked_layout(
            b"{}",
            &[File {
                name: "x",
                size: u64::MAX,
            }],
        )
        .unwrap_err();
        assert!(overflow_error.to_string().contains("overflow"));
    }

    #[test]
    fn allocation_failure_is_reported_before_loading() {
        let loaded = Cell::new(false);
        let error = build_with_reserve(
            b"{}",
            &[File {
                name: "agents.dex",
                size: 3,
            }],
            |_| {
                loaded.set(true);
                Ok(b"dex".to_vec())
            },
            |_, _| Err(io::Error::from(io::ErrorKind::OutOfMemory)),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
        assert!(!loaded.get());
    }

    #[test]
    fn loader_size_mismatch_and_invalid_descriptor_fail_closed() {
        let files = [File {
            name: "agents.dex",
            size: 3,
        }];
        assert_eq!(
            build(b"{}", &files, |_| Ok(b"xx".to_vec()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert!(build(b"", &files, |_| Ok(b"dex".to_vec())).is_err());
        assert!(checked_layout(b"{}", &[File { name: "", size: 1 }]).is_err());
    }

    #[test]
    fn descriptor_size_mismatch_fails_closed_like_the_live_breaker_case() {
        // Live 2026-09-18: a dex was replaced inside the generation dir
        // (50468 bytes) without updating the catalog descriptor (54224). The
        // build must fail closed here; the alternative was an envelope whose
        // header total never matched its wire file sizes, which the implant
        // rejected with payload-total-mismatch -> "pipe bootstrap read
        // failed" -> retry loop -> circuit breaker for that process only.
        let files = [File {
            name: "agent-ui-qinggan-com-qinggan-app-setting.dex",
            size: 54224,
        }];
        let error = build(b"{}", &files, |_| Ok(vec![0u8; 50468])).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("differs from descriptor"));
    }

    #[test]
    fn manifest_budget_accepts_n_minus_one_and_n_but_rejects_n_plus_one() {
        let files = [File {
            name: "agents.dex",
            size: 1,
        }];
        for length in [MAX_MANIFEST - 1, MAX_MANIFEST] {
            assert!(validate_layout(&vec![b'x'; length], &files).is_ok());
        }
        assert!(validate_layout(&vec![b'x'; MAX_MANIFEST + 1], &files).is_err());
    }
}
