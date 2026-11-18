//! Type-only ResourceID evidence from bounded DWARF inspection of real ELF bytes.
//! This module neither admits live calls nor invents missing destructor evidence.
use crate::pw_readback_types::{inspect_type, AbiType, Field, TypeProof};
use crate::Result;
const GNU_STRING: &str =
    "std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestructorEvidence {
    Implicit,
    RequiresStructuralCleanup,
}
#[derive(Debug)]
pub struct TypeEvidence {
    destructor: DestructorEvidence,
}
impl TypeEvidence {
    pub fn destructor(&self) -> DestructorEvidence {
        self.destructor
    }
    pub fn query(&self, ty: &str, member: &str) -> Option<Field> {
        let (kind, bytes, offset) = match (ty, member) {
            ("ResourceID", "$class") => (5, 48, 0),
            ("ResourceID", "m_id") => (6, 32, 0),
            ("ResourceID", "m_hash") => (9, 8, 32),
            ("ResourceID", "m_isURL") => (2, 1, 40),
            ("std::__cxx11::string", "$class") => (6, 32, 0),
            _ => return None,
        };
        Some(Field {
            kind,
            bytes,
            offset,
            count: 1,
        })
    }
}
pub fn inspect(file: &[u8]) -> Result<TypeEvidence> {
    validate(inspect_type(file, "kanzi::ResourceID")?)
}
fn validate(shape: TypeProof) -> Result<TypeEvidence> {
    if shape.name != "kanzi::ResourceID"
        || shape.bytes != 48
        || shape.bases != 0
        || shape.members.len() != 3
    {
        return Err("ResourceID class schema unsupported".into());
    }
    let mut seen = 0u8;
    for member in &shape.members {
        let bit = match (member.name.as_str(), member.offset, &member.ty) {
            (
                "m_id",
                0,
                AbiType::Named {
                    tag: 2,
                    name,
                    bytes: 32,
                },
            ) if name == GNU_STRING => 1,
            ("m_hash", 32, AbiType::Unsigned(8)) => 2,
            ("m_isURL", 40, AbiType::Bool) => 4,
            _ => return Err("ResourceID member schema unsupported".into()),
        };
        if seen & bit != 0 {
            return Err("ResourceID duplicate member".into());
        }
        seen |= bit;
    }
    if seen != 7 {
        return Err("ResourceID members incomplete".into());
    }
    Ok(TypeEvidence {
        destructor: if shape.implicit_destructor {
            DestructorEvidence::Implicit
        } else {
            DestructorEvidence::RequiresStructuralCleanup
        },
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::pw_readback_types::Member;
    use alloc::{string::ToString, vec};
    fn shape() -> TypeProof {
        TypeProof {
            name: "kanzi::ResourceID".to_string(),
            bytes: 48,
            bases: 0,
            implicit_destructor: true,
            members: vec![
                Member {
                    name: "m_id".to_string(),
                    offset: 0,
                    ty: AbiType::Named {
                        tag: 2,
                        name: GNU_STRING.to_string(),
                        bytes: 32,
                    },
                },
                Member {
                    name: "m_hash".to_string(),
                    offset: 32,
                    ty: AbiType::Unsigned(8),
                },
                Member {
                    name: "m_isURL".to_string(),
                    offset: 40,
                    ty: AbiType::Bool,
                },
            ],
        }
    }
    #[test]
    fn complete_schema_exposes_only_verified_fields() {
        let p = validate(shape()).unwrap();
        assert_eq!(p.destructor(), DestructorEvidence::Implicit);
        assert_eq!(
            p.query("ResourceID", "m_hash"),
            Some(Field {
                kind: 9,
                bytes: 8,
                offset: 32,
                count: 1
            })
        );
        assert_eq!(p.query("ResourceID", "$implicitDestructor"), None);
        assert_eq!(p.query("ResourceID", "$alignment"), None);
    }
    #[test]
    fn missing_destructor_demands_separate_evidence() {
        let mut s = shape();
        s.implicit_destructor = false;
        assert_eq!(
            validate(s).unwrap().destructor(),
            DestructorEvidence::RequiresStructuralCleanup
        );
    }
    #[test]
    fn rejects_class_size_name_base_and_member_count() {
        for choice in 0..5 {
            let mut s = shape();
            match choice {
                0 => s.bytes = 40,
                1 => s.name = "other::ResourceID".to_string(),
                2 => s.bases = 1,
                3 => {
                    s.members.pop();
                }
                _ => s.members.push(s.members[0].clone()),
            };
            assert!(validate(s).is_err());
        }
    }
    #[test]
    fn rejects_member_offset_signed_hash_and_nonbool() {
        for choice in 0..4 {
            let mut s = shape();
            match choice {
                0 => s.members[0].offset = 8,
                1 => s.members[1].ty = AbiType::Signed(8),
                2 => s.members[2].ty = AbiType::Unsigned(1),
                _ => s.members[2].name = "different".to_string(),
            };
            assert!(validate(s).is_err());
        }
    }
    #[test]
    fn rejects_similar_string_layouts_and_duplicate_members() {
        for choice in 0..4 {
            let mut s = shape();
            match choice {
                0 => {
                    s.members[0].ty = AbiType::Named {
                        tag: 2,
                        name: "std::string".to_string(),
                        bytes: 32,
                    }
                }
                1 => {
                    s.members[0].ty = AbiType::Named {
                        tag: 2,
                        name: GNU_STRING.to_string(),
                        bytes: 24,
                    }
                }
                2 => {
                    s.members[0].ty = AbiType::Named {
                        tag: 0x13,
                        name: GNU_STRING.to_string(),
                        bytes: 32,
                    }
                }
                _ => s.members[2] = s.members[1].clone(),
            };
            assert!(validate(s).is_err());
        }
    }
    #[test]
    fn reordered_members_preserve_schema() {
        let mut s = shape();
        s.members.reverse();
        assert!(validate(s).is_ok());
    }
    #[test]
    fn malformed_executable_cannot_create_evidence() {
        assert!(inspect(&[]).is_err());
        assert!(inspect(b"not an ELF").is_err());
    }
}
