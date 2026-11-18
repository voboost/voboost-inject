//! Bounded, fail-closed AArch64 caller-buffer copy proof.
use alloc::{format, vec, vec::Vec};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum V {
    Other,
    Buffer(i64),
    Stack(i64),
    Constant(u32),
    Pair(usize, u8),
}
#[derive(Clone)]
struct State {
    pc: usize,
    r: [V; 32],
    copied: bool,
    seen: Vec<usize>,
}
fn unsupported(message: &str) -> alloc::string::String {
    format!("unsupported A9 getData copy semantics: {message}")
}
fn signed(v: u32, bits: u32) -> i64 {
    ((v as i64) << (64 - bits)) >> (64 - bits)
}
fn shifted(v: V, n: i64) -> V {
    match v {
        V::Buffer(x) => V::Buffer(x + n),
        V::Stack(x) => V::Stack(x + n),
        _ => V::Other,
    }
}
/// Proves the copy on every reachable normal success / short-data return.
/// The caller separately establishes the mapped ELF owner's identity and lifetime.
pub(super) fn prove<'a>(
    code: &[u8],
    address: u64,
    resolve: &impl Fn(u64) -> Option<&'a str>,
) -> crate::Result<()> {
    if code.is_empty() || code.len() > 4096 || !code.len().is_multiple_of(4) {
        return Err(unsupported("invalid function extent"));
    }
    let mut r = [V::Other; 32];
    r[2] = V::Buffer(0);
    r[31] = V::Stack(0);
    let mut pending = vec![State {
        pc: 0,
        r,
        copied: false,
        seen: Vec::new(),
    }];
    let mut budget = 4096usize;
    let mut success = false;
    while let Some(mut s) = pending.pop() {
        loop {
            if budget == 0 || s.pc >= code.len() || s.pc % 4 != 0 || s.seen.contains(&s.pc) {
                return Err(unsupported("CFG cycle, invalid target or proof budget"));
            }
            budget -= 1;
            s.seen.push(s.pc);
            let pc = s.pc;
            let w = u32::from_le_bytes(code[pc..pc + 4].try_into().unwrap());
            let d = (w & 31) as usize;
            let n = ((w >> 5) & 31) as usize;
            let m = ((w >> 16) & 31) as usize;
            s.pc += 4;
            let target = |delta: i64| -> crate::Result<usize> {
                let t = pc as i64 + delta;
                if t < 0 || t as usize >= code.len() || t % 4 != 0 {
                    Err(unsupported("branch outside function"))
                } else {
                    Ok(t as usize)
                }
            };
            if w == 0xd65f03c0 {
                match s.r[0] {
                    V::Constant(0) | V::Constant(0xffff_fffe) => {
                        if !s.copied {
                            return Err(unsupported("successful return without caller copy"));
                        }
                        success = true;
                    }
                    V::Constant(0xffff_ffff) => {}
                    _ => return Err(unsupported("unknown return value")),
                }
                break;
            } else if w & 0xfc000000 == 0x94000000 {
                let dest =
                    (address as i128 + pc as i128 + signed(w & 0x03ffffff, 26) as i128 * 4) as u64;
                if matches!(resolve(dest), Some("__stack_chk_fail" | "_Unwind_Resume")) {
                    break;
                }
                if s.r[..8].iter().any(|v| matches!(v, V::Buffer(_))) {
                    return Err(unsupported("caller buffer escapes to call"));
                }
                for reg in &mut s.r[..19] {
                    *reg = V::Other;
                }
                s.r[30] = V::Other;
            } else if w & 0xfc000000 == 0x14000000 {
                s.pc = target(signed(w & 0x03ffffff, 26) * 4)?;
            } else if w & 0xff000010 == 0x54000000 || w & 0x7e000000 == 0x34000000 {
                let mut branch = s.clone();
                branch.pc = target(signed((w >> 5) & 0x7ffff, 19) * 4)?;
                pending.push(branch);
            } else if w & 0x7fe0ffe0 == 0x2a0003e0 {
                // MOV register (ORR with zero)
                s.r[d] = if m == 31 { V::Constant(0) } else { s.r[m] };
                if w >> 31 == 0 && matches!(s.r[d], V::Buffer(_)) {
                    return Err(unsupported("truncated buffer pointer"));
                }
                if w >> 31 == 0 && matches!(s.r[d], V::Stack(_) | V::Pair(_, _)) {
                    s.r[d] = V::Other;
                }
            } else if w & 0x7f800000 == 0x52800000 || w & 0x7f800000 == 0x12800000 {
                let shift = ((w >> 21) & 3) * 16;
                if shift >= 32 {
                    return Err(unsupported("wide constant"));
                }
                let value = ((w >> 5) & 0xffff) << shift;
                s.r[d] = V::Constant(if w & 0x40000000 == 0 { !value } else { value });
            } else if w & 0x7f000000 == 0x11000000 {
                // ADD immediate, flags clear
                if w >> 31 == 0 && matches!(s.r[n], V::Buffer(_)) {
                    return Err(unsupported("truncated buffer arithmetic"));
                }
                let amount =
                    (((w >> 10) & 0xfff) as i64) << if w & (1 << 22) != 0 { 12 } else { 0 };
                s.r[d] = shifted(s.r[n], amount);
            } else if w & 0x9f000000 == 0x90000000 {
                s.r[d] = V::Other; // ADRP
            } else if w & 0x3a000000 == 0x28000000 {
                // integer LDP/STP
                if w & 0x40000000 != 0 || w >> 30 != 2 {
                    return Err(unsupported("non-64-bit pair"));
                }
                let rt2 = ((w >> 10) & 31) as usize;
                let mode = (w >> 23) & 3;
                let off = signed((w >> 15) & 127, 7) * 8;
                let base = if mode == 1 {
                    s.r[n]
                } else {
                    shifted(s.r[n], off)
                };
                if w & (1 << 22) != 0 {
                    if matches!(base, V::Buffer(_)) {
                        return Err(unsupported("pair load from caller buffer"));
                    }
                    if !matches!(base, V::Stack(_)) {
                        s.r[d] = V::Pair(pc, 0);
                        s.r[rt2] = V::Pair(pc, 1);
                    } else {
                        s.r[d] = V::Other;
                        s.r[rt2] = V::Other;
                    }
                } else {
                    match base {
                        V::Stack(_)
                            if !matches!(s.r[d], V::Buffer(_))
                                && !matches!(s.r[rt2], V::Buffer(_)) => {}
                        V::Buffer(0)
                            if !s.copied
                                && matches!((s.r[d],s.r[rt2]),(V::Pair(a,0),V::Pair(b,1)) if a==b) =>
                        {
                            s.copied = true
                        }
                        _ => return Err(unsupported("unproved or repeated memory write")),
                    }
                }
                if mode == 1 || mode == 3 {
                    s.r[n] = shifted(s.r[n], off);
                }
            } else if w & 0x3b000000 == 0x39000000 {
                // scalar unsigned-offset load/store
                if w & (1 << 22) != 0 {
                    s.r[d] = V::Other;
                } else if !matches!(s.r[n], V::Stack(_)) || matches!(s.r[d], V::Buffer(_)) {
                    return Err(unsupported("non-stack scalar store"));
                }
            } else if w & 0x3b200000 == 0x38000000 {
                // unscaled/pre/post scalar load/store
                if w & (1 << 22) == 0 {
                    return Err(unsupported("unscaled store"));
                }
                s.r[d] = V::Other;
                let mode = (w >> 10) & 3;
                if mode == 1 || mode == 3 {
                    s.r[n] = shifted(s.r[n], signed((w >> 12) & 511, 9));
                }
            } else if w & 0x3b200c00 == 0x38200800 && w & (1 << 22) != 0 {
                s.r[d] = V::Other; // register-offset load
            } else if w & 0x7fe00c00 == 0x1a800000 {
                // CSEL: explore both possible values
                let mut other = s.clone();
                other.r[d] = if m == 31 { V::Constant(0) } else { s.r[m] };
                pending.push(other);
                s.r[d] = if n == 31 { V::Constant(0) } else { s.r[n] };
            } else if w & 0x1f000000 == 0x0b000000
                || w & 0x1f000000 == 0x0a000000
                || w & 0x7f800000 == 0x53000000
            {
                // Reject provenance loss: a derived caller pointer could escape later.
                if d != 31
                    && (matches!(s.r[n], V::Buffer(_))
                        || (w & 0x7f800000 != 0x53000000 && matches!(s.r[m], V::Buffer(_))))
                {
                    return Err(unsupported("unsupported caller pointer arithmetic"));
                }
                if d != 31 {
                    s.r[d] = V::Other;
                }
            } else if w & 0x7f000000 == 0x71000000 || w & 0x7fe00c00 == 0x7a400000 {
                // CMP immediate and conditional compare only affect flags.
                if w & 0x7f000000 == 0x71000000 && d != 31 {
                    return Err(unsupported("flagged arithmetic result"));
                }
            } else {
                return Err(unsupported(&format!(
                    "unknown instruction {w:08x} at +{pc:x}"
                )));
            }
        }
    }
    if !success {
        return Err(unsupported("no proven successful return"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn run(words: &[u32]) -> crate::Result<()> {
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        prove(&bytes, 0, &|_| None)
    }
    const COPY: [u32; 5] = [0xaa0203f7, 0xa9400c22, 0xa9000ee2, 0x52800000, 0xd65f03c0];
    #[test]
    fn proves_actual_pair_flow() {
        assert!(run(&COPY).is_ok());
    }
    #[test]
    fn missing_or_redirected_store() {
        for replacement in [0xaa0303e3, 0xa9000ec2] {
            let mut x = COPY;
            x[2] = replacement;
            assert!(run(&x).is_err());
        }
    }
    #[test]
    fn caller_buffer_self_copy() {
        let mut x = COPY;
        x[1] = 0xa9400ee2;
        assert!(run(&x).is_err());
    }
    #[test]
    fn early_success() {
        assert!(run(&[0x52800000, 0xd65f03c0]).is_err());
    }
    #[test]
    fn overwritten_buffer() {
        let mut x = COPY.to_vec();
        x.insert(3, 0xf90002e0);
        assert!(run(&x).is_err());
    }
    #[test]
    fn clobbered_pointer() {
        let mut x = COPY.to_vec();
        x.insert(2, 0xaa0003f7);
        assert!(run(&x).is_err());
    }
    #[test]
    fn truncation_and_branch() {
        assert!(prove(&[0], 0, &|_| None).is_err());
        assert!(run(&[0x14000000]).is_err());
        assert!(run(&[0xd61f0000]).is_err());
    }
}
