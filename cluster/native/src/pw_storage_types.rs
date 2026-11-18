//! PW-specific read-only storage evidence. It grants no calls or mapped-owner pin.
use crate::{
    pw_readback_types::{inspect_field_path, LayoutField, LayoutKind},
    Result,
};
use alloc::vec::Vec;
const STORAGE: &str = "kanzi::AbstractPropertyTypeDescriptor::PropertyStorage";
const ENTRY: &str = "kanzi::AbstractPropertyTypeDescriptor::ValueSourceEntry";
const SOURCE: &str = "kanzi::AbstractPropertyTypeDescriptor::ValueSource";
pub struct StorageProof {
    fields: Vec<(&'static str, &'static str, LayoutField)>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Field {
    pub kind: u32,
    pub bytes: u32,
    pub offset: u32,
}
struct Spec {
    ty: &'static str,
    path: &'static str,
    owner: u64,
    offset: u64,
    bytes: u64,
    kind: u32,
    target: &'static str,
}
const SPECS: [Spec; 15] = [
    Spec {
        ty: STORAGE,
        path: "$size",
        owner: 64,
        offset: 0,
        bytes: 64,
        kind: 1,
        target: "",
    },
    Spec {
        ty: STORAGE,
        path: "descriptor",
        owner: 64,
        offset: 8,
        bytes: 8,
        kind: 2,
        target: "kanzi::AbstractPropertyTypeDescriptor",
    },
    Spec {
        ty: STORAGE,
        path: "flags",
        owner: 64,
        offset: 16,
        bytes: 4,
        kind: 3,
        target: "",
    },
    Spec {
        ty: STORAGE,
        path: "valueSourceEntries._M_impl._M_start",
        owner: 64,
        offset: 24,
        bytes: 8,
        kind: 2,
        target: ENTRY,
    },
    Spec {
        ty: STORAGE,
        path: "valueSourceEntries._M_impl._M_finish",
        owner: 64,
        offset: 32,
        bytes: 8,
        kind: 2,
        target: ENTRY,
    },
    Spec {
        ty: STORAGE,
        path: "valueSourceEntries._M_impl._M_end_of_storage",
        owner: 64,
        offset: 40,
        bytes: 8,
        kind: 2,
        target: ENTRY,
    },
    Spec {
        ty: ENTRY,
        path: "$size",
        owner: 24,
        offset: 0,
        bytes: 24,
        kind: 1,
        target: "",
    },
    Spec {
        ty: ENTRY,
        path: "valueSource",
        owner: 24,
        offset: 0,
        bytes: 8,
        kind: 2,
        target: SOURCE,
    },
    Spec {
        ty: ENTRY,
        path: "owner",
        owner: 24,
        offset: 8,
        bytes: 8,
        kind: 2,
        target: "void",
    },
    Spec {
        ty: ENTRY,
        path: "precedence",
        owner: 24,
        offset: 16,
        bytes: 4,
        kind: 3,
        target: "kanzi::PropertyValuePrecedence",
    },
    Spec {
        ty: SOURCE,
        path: "$size",
        owner: 1,
        offset: 0,
        bytes: 1,
        kind: 1,
        target: "",
    },
    Spec {
        ty: "kanzi::PropertyTypeDescriptor<bool>::TypedValueSource",
        path: "$size",
        owner: 1,
        offset: 0,
        bytes: 1,
        kind: 1,
        target: "",
    },
    Spec {
        ty: "kanzi::PropertyTypeDescriptor<bool>::TypedValueSource",
        path: "value",
        owner: 1,
        offset: 0,
        bytes: 1,
        kind: 4,
        target: "",
    },
    Spec {
        ty: "kanzi::PropertyTypeDescriptor<float>::TypedValueSource",
        path: "$size",
        owner: 4,
        offset: 0,
        bytes: 4,
        kind: 1,
        target: "",
    },
    Spec {
        ty: "kanzi::PropertyTypeDescriptor<float>::TypedValueSource",
        path: "value",
        owner: 4,
        offset: 0,
        bytes: 4,
        kind: 5,
        target: "",
    },
];
fn accept(spec: &Spec, field: &LayoutField) -> bool {
    field.owner_bytes == spec.owner
        && field.offset == spec.offset
        && field.bytes == spec.bytes
        && match (&field.kind, spec.kind) {
            (LayoutKind::Size, 1) => true,
            (LayoutKind::Pointer(name), 2) => name == spec.target,
            (LayoutKind::Unsigned, 3) => spec.target.is_empty(),
            (LayoutKind::Enum(name), 3) => name == spec.target,
            (LayoutKind::Bool, 4) => true,
            (LayoutKind::Float, 5) => true,
            _ => false,
        }
}
impl StorageProof {
    pub fn inspect(file: &[u8]) -> Result<Self> {
        let mut fields = Vec::new();
        for spec in &SPECS {
            let field = inspect_field_path(file, spec.ty, spec.path)?;
            if !accept(spec, &field) {
                return Err("PW storage field layout unsupported".into());
            }
            fields.push((spec.ty, spec.path, field));
        }
        Ok(Self { fields })
    }
    pub fn query(&self, ty: &str, path: &str) -> Option<Field> {
        self.fields
            .iter()
            .enumerate()
            .find(|(_, f)| f.0 == ty && f.1 == path)
            .map(|(i, (_, _, field))| Field {
                kind: SPECS[i].kind,
                bytes: field.bytes as u32,
                offset: field.offset as u32,
            })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_shape_dimension_is_required() {
        for spec in &SPECS {
            let kind = match spec.kind {
                1 => LayoutKind::Size,
                2 => LayoutKind::Pointer(spec.target.into()),
                4 => LayoutKind::Bool,
                5 => LayoutKind::Float,
                _ if spec.target.is_empty() => LayoutKind::Unsigned,
                _ => LayoutKind::Enum(spec.target.into()),
            };
            let good = LayoutField {
                owner_bytes: spec.owner,
                offset: spec.offset,
                bytes: spec.bytes,
                kind,
            };
            assert!(accept(spec, &good));
            let mut bad = good.clone();
            bad.offset += 1;
            assert!(!accept(spec, &bad));
            let mut bad = good.clone();
            bad.bytes += 1;
            assert!(!accept(spec, &bad));
            let mut bad = good.clone();
            bad.owner_bytes += 1;
            assert!(!accept(spec, &bad));
            if spec.kind == 2 || !spec.target.is_empty() {
                let mut bad = good.clone();
                bad.kind = if spec.kind == 2 {
                    LayoutKind::Pointer("wrong".into())
                } else {
                    LayoutKind::Enum("wrong".into())
                };
                assert!(!accept(spec, &bad));
            }
            let mut bad = good;
            bad.kind = LayoutKind::Signed;
            assert!(!accept(spec, &bad));
        }
    }
}
