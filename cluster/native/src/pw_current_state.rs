//! Read-only shape of the already constructed OEM receiver. This is not a
//! lifecycle/readiness proof: dispatch publishes its index before state::open.
use crate::{
    pw_readback_types::{inspect_field_path, LayoutField, LayoutKind},
    Result,
};

pub struct Shape {
    bytes: u64,
    fields: [LayoutField; 4],
}

impl Shape {
    pub fn inspect(file: &[u8]) -> Result<Self> {
        let size = inspect_field_path(file, "DataReceiver", "$size")?;
        let fields = [
            inspect_field_path(file, "DataReceiver", "m_isRun")?,
            inspect_field_path(file, "DataReceiver", "m_context.m_curStateIndex")?,
            inspect_field_path(file, "DataReceiver", "m_context.m_themChg")?,
            inspect_field_path(file, "DataReceiver", "m_context.m_isKzready")?,
        ];
        Self::checked(size, fields)
    }

    fn checked(size: LayoutField, fields: [LayoutField; 4]) -> Result<Self> {
        if size.kind != LayoutKind::Size
            || size.offset != 0
            || size.bytes == 0
            || size.owner_bytes != size.bytes
            || size.bytes > 4096
        {
            return Err("PW receiver object shape rejected".into());
        }
        for (index, field) in fields.iter().enumerate() {
            let (kind, bytes) = if index == 1 {
                (LayoutKind::Unsigned, 4)
            } else {
                (LayoutKind::Bool, 1)
            };
            if field.kind != kind
                || field.bytes != bytes
                || field.owner_bytes != size.bytes
                || field
                    .offset
                    .checked_add(bytes)
                    .is_none_or(|end| end > size.bytes)
            {
                return Err("PW receiver member shape rejected".into());
            }
            for previous in &fields[..index] {
                if field.offset < previous.offset + previous.bytes
                    && previous.offset < field.offset + field.bytes
                {
                    return Err("PW receiver members overlap".into());
                }
            }
        }
        Ok(Self {
            bytes: size.bytes,
            fields,
        })
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// A bounded byte copy supplied by a separately admitted mapped owner.
    /// Noncanonical boolean bytes are rejected. A canonical copy does not prove
    /// object construction or completion of Operation::open, even if repeated.
    pub fn decode(&self, bytes: &[u8]) -> Option<Snapshot> {
        if bytes.len() as u64 != self.bytes {
            return None;
        }
        let boolean = |index: usize| match bytes[self.fields[index].offset as usize] {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        };
        let offset = self.fields[1].offset as usize;
        Some(Snapshot {
            running: boolean(0)?,
            state: u32::from_le_bytes(bytes[offset..offset + 4].try_into().ok()?),
            theme_changing: boolean(2)?,
            ui_ready: boolean(3)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub running: bool,
    pub state: u32,
    pub theme_changing: bool,
    pub ui_ready: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (LayoutField, [LayoutField; 4]) {
        let field = |offset, bytes, kind| LayoutField {
            owner_bytes: 32,
            offset,
            bytes,
            kind,
        };
        (
            field(0, 32, LayoutKind::Size),
            [
                field(1, 1, LayoutKind::Bool),
                field(8, 4, LayoutKind::Unsigned),
                field(20, 1, LayoutKind::Bool),
                field(25, 1, LayoutKind::Bool),
            ],
        )
    }
    #[test]
    fn rejects_invalid_field_receipts() {
        for index in 0..4 {
            let (size, mut fields) = fixture();
            fields[index].offset = u64::MAX;
            assert!(Shape::checked(size, fields).is_err());
            let (size, mut fields) = fixture();
            fields[index].owner_bytes = 31;
            assert!(Shape::checked(size, fields).is_err());
            let (size, mut fields) = fixture();
            fields[index].kind = LayoutKind::Signed;
            assert!(Shape::checked(size, fields).is_err());
        }
        let (size, mut fields) = fixture();
        fields[3].offset = fields[2].offset;
        assert!(Shape::checked(size, fields).is_err());
    }
    #[test]
    fn decodes_offsets_but_never_infers_readiness_from_state() {
        let (size, fields) = fixture();
        let shape = Shape::checked(size, fields).unwrap();
        let mut bytes = [0u8; 32];
        bytes[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        let snapshot = shape.decode(&bytes).unwrap();
        assert_eq!(snapshot.state, u32::MAX);
        assert!(!snapshot.running && !snapshot.ui_ready);
        bytes[25] = 255;
        assert!(shape.decode(&bytes).is_none());
    }
}
