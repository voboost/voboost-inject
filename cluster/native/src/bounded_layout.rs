//! Read-only DWARF field paths; construction/destruction permission is separate.
use super::{abi, Die, Dwarf, Elf};
use crate::Result;
use alloc::string::{String, ToString};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LayoutKind {
    Size,
    Pointer(String),
    Unsigned,
    Signed,
    Bool,
    Float,
    Enum(String),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LayoutField {
    pub owner_bytes: u64,
    pub offset: u64,
    pub bytes: u64,
    pub kind: LayoutKind,
}

fn charge(work: &mut usize) -> Result<()> {
    *work = work.checked_sub(1).ok_or("layout work budget")?;
    Ok(())
}
fn named<'a>(d: &'a Dwarf<'a>, n: &'a Die<'a>) -> Result<String> {
    abi::qualified(d, n)
}
fn within(owner: &Die<'_>, at: u64, bytes: u64) -> Result<()> {
    let size = owner.size.ok_or("layout incomplete containing type")?;
    if at.checked_add(bytes).is_none_or(|end| end > size) {
        return Err("layout subobject exceeds containing type".into());
    }
    Ok(())
}
fn lookup<'a>(
    d: &'a Dwarf<'a>,
    n: &'a Die<'a>,
    name: &str,
    depth: usize,
    work: &mut usize,
) -> Result<Option<(&'a Die<'a>, u64)>> {
    if depth > 24 {
        return Err("layout inheritance depth".into());
    }
    let id = *d.index.get(&n.offset).ok_or("layout parent")?;
    let mut found = None;
    for child in &d.nodes {
        charge(work)?;
        if child.parent != Some(id) {
            continue;
        }
        let candidate = if child.tag == 0xd && child.name == Some(name) {
            let at = child
                .location
                .or_else(|| (n.tag == 0x17).then_some(0))
                .ok_or("layout member offset")?;
            let ty = d.resolve(child.ty.ok_or("layout member type")?)?;
            within(n, at, ty.size.ok_or("layout member size")?)?;
            Some((child, at))
        } else if child.tag == 0x1c {
            let base = d.resolve(child.ty.ok_or("layout base type")?)?;
            let at = child.location.ok_or("layout base offset")?;
            within(n, at, base.size.ok_or("layout base size")?)?;
            lookup(d, base, name, depth + 1, work)?
                .map(|(member, offset)| (member, offset.checked_add(at)))
                .map(|(member, offset)| {
                    offset
                        .map(|offset| (member, offset))
                        .ok_or("layout base overflow")
                })
                .transpose()?
        } else {
            None
        };
        if let Some(candidate) = candidate {
            if found.is_some() {
                return Err("layout ambiguous inherited field".into());
            }
            found = Some(candidate);
        }
    }
    Ok(found)
}
fn kind(d: &Dwarf<'_>, n: &Die<'_>) -> Result<(LayoutKind, u64)> {
    let bytes = n.size.ok_or("layout incomplete field type")?;
    let result = match n.tag {
        0xf => {
            let name = if let Some(t) = n.ty {
                let p = d.resolve(t)?;
                if matches!(p.tag, 2 | 0x13 | 0x17) {
                    named(d, p)?
                } else if p.tag == 0x24 {
                    p.name.ok_or("layout unnamed scalar pointee")?.to_string()
                } else {
                    return Err("layout pointer target unsupported".into());
                }
            } else {
                "void".to_string()
            };
            LayoutKind::Pointer(name)
        }
        0x24 => match n.encoding {
            Some(7 | 8) => LayoutKind::Unsigned,
            Some(5 | 6) => LayoutKind::Signed,
            Some(2) if bytes == 1 => LayoutKind::Bool,
            Some(4) if bytes == 4 => LayoutKind::Float,
            _ => return Err("layout scalar unsupported".into()),
        },
        4 => LayoutKind::Enum(named(d, n)?),
        _ => return Err("layout terminal type unsupported".into()),
    };
    Ok((result, bytes))
}
fn from_class(d: &Dwarf<'_>, root: &Die<'_>, path: &str, work: &mut usize) -> Result<LayoutField> {
    let owner_bytes = root.size.ok_or("layout owner size")?;
    if path == "$size" {
        return Ok(LayoutField {
            owner_bytes,
            offset: 0,
            bytes: owner_bytes,
            kind: LayoutKind::Size,
        });
    }
    let mut current = root;
    let mut offset = 0u64;
    let mut steps = 0;
    for part in path.split('.') {
        steps += 1;
        if steps > 16 || part.is_empty() {
            return Err("layout field path bound".into());
        }
        let (member, at) = lookup(d, current, part, 0, work)?.ok_or("layout field absent")?;
        offset = offset
            .checked_add(at)
            .ok_or("layout field offset overflow")?;
        current = d.resolve(member.ty.ok_or("layout field type")?)?;
    }
    let (kind, bytes) = kind(d, current)?;
    if offset
        .checked_add(bytes)
        .is_none_or(|end| end > owner_bytes)
    {
        return Err("layout field exceeds owner".into());
    }
    Ok(LayoutField {
        owner_bytes,
        offset,
        bytes,
        kind,
    })
}
pub(super) fn field_in_unit(
    d: &Dwarf<'_>,
    selector: &str,
    work: &mut usize,
) -> Result<Option<LayoutField>> {
    let (name, path) = selector.split_once('\n').ok_or("layout selector")?;
    let mut found = None;
    for n in &d.nodes {
        charge(work)?;
        if !matches!(n.tag, 2 | 0x13 | 0x17)
            || n.size.is_none()
            || n.name != name.rsplit("::").next()
        {
            continue;
        }
        if named(d, n)? != name {
            continue;
        }
        let field = from_class(d, n, path, work)?;
        if found.as_ref().is_some_and(|old| old != &field) {
            return Err("layout conflicting definitions".into());
        }
        found = Some(field);
    }
    Ok(found)
}
pub fn inspect_field_path(file: &[u8], name: &str, path: &str) -> Result<LayoutField> {
    if name.is_empty()
        || name.len() > 512
        || path.is_empty()
        || path.len() > 512
        || name.contains('\n')
        || path.contains('\n')
    {
        return Err("layout query bound".into());
    }
    let selector = alloc::format!("{name}\n{path}");
    let elf = Elf::open(file)?;
    let d = Dwarf::parse(&elf, u64::MAX - 2, &selector)?;
    field_in_unit(&d, &selector, &mut 8_000_000)?.ok_or_else(|| "layout owner absent".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{collections::BTreeMap, vec};
    fn fixture() -> Dwarf<'static> {
        let nodes = vec![
            Die {
                offset: 1,
                tag: 0x13,
                name: Some("Example"),
                size: Some(16),
                ..Die::default()
            },
            Die {
                offset: 2,
                tag: 0x13,
                name: Some("Base"),
                size: Some(8),
                ..Die::default()
            },
            Die {
                offset: 3,
                tag: 0x1c,
                parent: Some(0),
                ty: Some(2),
                location: Some(0),
                ..Die::default()
            },
            Die {
                offset: 4,
                tag: 0xd,
                parent: Some(1),
                name: Some("value"),
                ty: Some(5),
                location: Some(4),
                ..Die::default()
            },
            Die {
                offset: 5,
                tag: 0x24,
                name: Some("unsigned int"),
                size: Some(4),
                encoding: Some(7),
                ..Die::default()
            },
        ];
        let index: BTreeMap<_, _> = nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (n.offset, i))
            .collect();
        Dwarf { nodes, index }
    }
    #[test]
    fn inherited_offset_and_every_containing_bound() {
        let mut d = fixture();
        let p = from_class(&d, &d.nodes[0], "value", &mut 100).unwrap();
        assert_eq!(
            p,
            LayoutField {
                owner_bytes: 16,
                offset: 4,
                bytes: 4,
                kind: LayoutKind::Unsigned
            }
        );
        d.nodes[1].size = Some(7);
        assert!(from_class(&d, &d.nodes[0], "value", &mut 100).is_err());
        d.nodes[1].size = Some(8);
        d.nodes[2].location = Some(12);
        assert!(from_class(&d, &d.nodes[0], "value", &mut 100).is_err());
    }
    #[test]
    fn missing_ambiguous_cycles_and_work_exhaustion_reject() {
        let mut d = fixture();
        assert!(from_class(&d, &d.nodes[0], "absent", &mut 100).is_err());
        assert!(from_class(&d, &d.nodes[0], "value", &mut 0).is_err());
        d.nodes[2].ty = Some(1);
        assert!(from_class(&d, &d.nodes[0], "value", &mut 1000).is_err());
        let mut d = fixture();
        let duplicate = Die {
            offset: 6,
            tag: 0xd,
            parent: Some(0),
            name: Some("value"),
            ty: Some(5),
            location: Some(0),
            ..Die::default()
        };
        d.index.insert(6, d.nodes.len());
        d.nodes.push(duplicate);
        assert!(from_class(&d, &d.nodes[0], "value", &mut 1000).is_err());
    }
}
