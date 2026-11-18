//! Bounded machine-code evidence of actual ResourceID temporary cleanup.
use crate::pw_readback_types::{export_code, ExportCode};
use crate::Result;
use alloc::vec::Vec;
const OWNER:&str="_Z20kzuBinaryReadVariantP14KzcInputStreamPK17KzuBinaryFileInfoPN5kanzi7VariantEPNS4_20AbstractPropertyTypeE";
const CTOR: &str = "_ZN5kanzi10ResourceIDC1EPKc";
const ASSIGN:&str="_ZN5boost7variantINS_5blankEJbifN5kanzi9ColorRGBAENS2_7Vector2ENS2_7Vector3ENS2_7Vector4ENS2_10SRTValue2DENS2_10SRTValue3DENS2_9Matrix3x3ENS2_9Matrix4x4ENSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEENS2_10ResourceIDESt10shared_ptrINS2_8ResourceEEPv13KzcQuaternionEE6assignISH_EEvRKT_";
const DELETE: &str = "_ZdlPv";
#[derive(Debug)]
pub struct CleanupProof {
    address: u64,
    code: Vec<u8>,
}
impl CleanupProof {
    pub fn address(&self) -> u64 {
        self.address
    }
    pub fn code(&self) -> &[u8] {
        &self.code
    }
}
pub fn inspect(file: &[u8]) -> Result<CleanupProof> {
    prove(export_code(file, OWNER)?)
}
fn mov_reg(word: u32, d: u32, n: u32) -> bool {
    word == 0xaa0003e0 | (n << 16) | d
}
fn callee(export: &ExportCode, offset: usize, name: &str) -> bool {
    let mut entries = export.calls.iter().filter(|(at, _)| *at == offset);
    matches!(entries.next(),Some((_,Some(found))) if found==name) && entries.next().is_none()
}
fn window(export: &ExportCode, at: usize) -> bool {
    let words: Vec<u32> = export.code[at..at + 48]
        .as_chunks::<4>()
        .0
        .iter()
        .map(|x| u32::from_le_bytes(*x))
        .collect();
    let saved = words[0] & 31;
    // ADD Xsaved, X29, #stackoffset; no shift, flags or truncated arithmetic.
    if !(19..=28).contains(&saved) || words[0] & 0xffc003e0 != 0x910003a0 {
        return false;
    }
    let stackoff = (words[0] >> 10) & 0xfff;
    // Input C string is loaded separately from the same frame.
    if words[1] & 0xffc003ff != 0xf94003a1 || !mov_reg(words[2], 0, saved) {
        return false;
    }
    if !mov_reg(words[4], 1, saved) || words[5] & 0xffe0ffff != 0xaa0003e0 {
        return false;
    }
    let assignment_destination = (words[5] >> 16) & 31;
    if !(19..=28).contains(&assignment_destination) || assignment_destination == saved {
        return false;
    }
    // Same object T: data=[T], SSO=T+16; conditional skip spans precisely BL delete.
    let load = 0xf94003a0 | ((stackoff / 8) << 10);
    if !stackoff.is_multiple_of(8)
        || words[7] != load
        || words[8] != (0x91004001 | (saved << 5))
        || words[9] != 0xeb01001f
        || words[10] != 0x54000040
    {
        return false;
    }
    for (index, name) in [(3, CTOR), (6, ASSIGN), (11, DELETE)] {
        if words[index] & 0xfc000000 != 0x94000000 || !callee(export, at + index * 4, name) {
            return false;
        }
    }
    true
}
fn prove(export: ExportCode) -> Result<CleanupProof> {
    if export.code.len() < 48
        || export.code.len() > 65536
        || !export.code.len().is_multiple_of(4)
        || export.calls.len() > 4096
    {
        return Err("ResourceID cleanup function bound".into());
    }
    for at in (0..=export.code.len() - 48).step_by(4) {
        if window(&export, at) {
            let address = export
                .address
                .checked_add(at as u64)
                .ok_or("ResourceID cleanup address overflow")?;
            return Ok(CleanupProof {
                address,
                code: export.code[at..at + 48].to_vec(),
            });
        }
    }
    Err("ResourceID structural cleanup unsupported".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec};
    fn sample() -> ExportCode {
        let words = [
            0x910503b5u32,
            0xf9404ba1,
            0xaa1503e0,
            0x94000000,
            0xaa1503e1,
            0xaa1703e0,
            0x94000000,
            0xf940a3a0,
            0x910042a1,
            0xeb01001f,
            0x54000040,
            0x94000000,
        ];
        ExportCode {
            address: 0x1000,
            code: words.iter().flat_map(|x| x.to_le_bytes()).collect(),
            calls: vec![
                (12, Some(CTOR.to_string())),
                (24, Some(ASSIGN.to_string())),
                (44, Some(DELETE.to_string())),
            ],
        }
    }
    fn change(s: &mut ExportCode, index: usize, word: u32) {
        s.code[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    #[test]
    fn actual_shape_yields_bound_window() {
        let p = prove(sample()).unwrap();
        assert_eq!(p.address(), 0x1000);
        assert_eq!(p.code().len(), 48);
    }
    #[test]
    fn rejects_wrong_pointer_register() {
        for (i, w) in [
            (0, 0x910503a5),
            (2, 0xaa1403e0),
            (4, 0xaa1403e1),
            (8, 0x91004281),
        ] {
            let mut s = sample();
            change(&mut s, i, w);
            assert!(prove(s).is_err());
        }
    }
    #[test]
    fn rejects_wrong_stack_offset_or_sso_offset() {
        for (i, w) in [(7, 0xf940a7a0), (8, 0x910062a1)] {
            let mut s = sample();
            change(&mut s, i, w);
            assert!(prove(s).is_err());
        }
    }
    #[test]
    fn rejects_wrong_delete_branch() {
        for w in [0x54000041, 0x54000060, 0x14000002] {
            let mut s = sample();
            change(&mut s, 10, w);
            assert!(prove(s).is_err());
        }
    }
    #[test]
    fn rejects_missing_wrong_and_ambiguous_callees() {
        for i in 0..3 {
            let mut s = sample();
            s.calls[i].1 = Some("other".to_string());
            assert!(prove(s).is_err());
            let mut s = sample();
            s.calls[i].1 = None;
            assert!(prove(s).is_err());
        }
        let mut s = sample();
        s.calls.push(s.calls[0].clone());
        assert!(prove(s).is_err());
    }
    #[test]
    fn rejects_noncall_and_truncated_extent() {
        let mut s = sample();
        change(&mut s, 11, 0xd503201f);
        assert!(prove(s).is_err());
        let mut s = sample();
        s.code.pop();
        assert!(prove(s).is_err());
    }
    #[test]
    #[ignore = "requires retained actual ELF, never bundled fixtures"]
    fn actual_retained_cleanup() {
        let path = std::env::var("VOBOOST_RESOURCE_CORE_ELF").unwrap();
        let file = std::fs::read(path).unwrap();
        let proof = inspect(&file).unwrap();
        assert!(proof.address() > 0);
        assert_eq!(proof.code().len(), 48);
    }
    #[test]
    fn scans_without_fixed_window_offset() {
        let mut s = sample();
        s.code.splice(0..0, [0u8; 16]);
        for (offset, _) in &mut s.calls {
            *offset += 16;
        }
        assert_eq!(prove(s).unwrap().address(), 0x1010);
    }
}
