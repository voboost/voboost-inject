//! Raw receive evidence, independent of CAN decoding and agent applicability.
use std::collections::BTreeMap;
use voboost_contract::runtime_log::{Level, Record};

#[derive(Debug)]
pub struct Datagram {
    pub bytes: Vec<u8>,
    pub reported_bytes: usize,
    pub socket_buffer_bytes: i32,
    pub sender_pid: u32,
    pub sender_groups: u32,
    pub address_bytes: usize,
    pub sender_family: u16,
    pub flags: i32,
    pub received_boot_ms: Option<u64>,
}

impl Datagram {
    pub fn records(self, sequence: u64, epoch: u64) -> Vec<Record> {
        const CHUNK: usize = 512;
        let parts = self.bytes.len().max(1).div_ceil(CHUNK);
        (0..parts)
            .map(|part| {
                let offset = part * CHUNK;
                let end = (offset + CHUNK).min(self.bytes.len());
                let mut fields = BTreeMap::from([
                    ("datagramSequence".into(), sequence.to_string()),
                    ("receiverEpoch".into(), epoch.to_string()),
                    ("reportedBytes".into(), self.reported_bytes.to_string()),
                    (
                        "socketReceiveBufferBytes".into(),
                        self.socket_buffer_bytes.to_string(),
                    ),
                    ("capturedBytes".into(), self.bytes.len().to_string()),
                    ("senderPid".into(), self.sender_pid.to_string()),
                    ("senderGroups".into(), self.sender_groups.to_string()),
                    ("senderFamily".into(), self.sender_family.to_string()),
                    ("addressBytes".into(), self.address_bytes.to_string()),
                    ("receiveFlags".into(), self.flags.to_string()),
                    ("part".into(), part.to_string()),
                    ("parts".into(), parts.to_string()),
                    ("offset".into(), offset.to_string()),
                    ("bytesHex".into(), hex::encode(&self.bytes[offset..end])),
                ]);
                if let Some(time) = self.received_boot_ms {
                    fields.insert("receiveBootMs".into(), time.to_string());
                } else {
                    fields.insert("receiveClockUnavailable".into(), "true".into());
                }
                Record {
                    level: Level::Debug,
                    component: "native-can".into(),
                    message: "CAN datagram received".into(),
                    fields: fields.into_iter().collect(),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_large_datagram_round_trips_without_id_filtering() {
        for size in [0, 10, 257, 7424, 65536] {
            let bytes: Vec<u8> = (0..size).map(|n| (n % 251) as u8).collect();
            let records = Datagram {
                bytes: bytes.clone(),
                reported_bytes: size,
                socket_buffer_bytes: 524288,
                sender_pid: 0,
                sender_groups: 1,
                address_bytes: 12,
                sender_family: 16,
                flags: 0,
                received_boot_ms: Some(123),
            }
            .records(7, 2);
            let mut restored = Vec::new();
            for record in records {
                assert!(record.valid());
                assert_eq!(record.fields["datagramSequence"], "7");
                assert_eq!(record.fields["receiveBootMs"], "123");
                restored.extend(hex::decode(&record.fields["bytesHex"]).unwrap());
            }
            assert_eq!(restored, bytes);
        }
    }
    #[test]
    fn full_datagram_is_persisted_by_the_canonical_logger() {
        for size in [7424, 65536] {
            let root = tempfile::tempdir().unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let writer = "a".repeat(32);
            let mut logger = crate::log::Log::create(
                root.path(),
                "11111111-1111-4111-8111-111111111111",
                &writer,
            )
            .unwrap();
            let bytes: Vec<u8> = (0..size).map(|n| (n % 251) as u8).collect();
            let records = Datagram {
                bytes: bytes.clone(),
                reported_bytes: size,
                socket_buffer_bytes: 524288,
                sender_pid: 0,
                sender_groups: 1,
                address_bytes: 12,
                sender_family: 16,
                flags: 0,
                received_boot_ms: Some(123),
            }
            .records(1, 1);
            logger.append_debug_records(records).unwrap();
            let logged = std::fs::read(
                root.path()
                    .join(writer)
                    .join("debug-00000000000000000000.jsonl"),
            )
            .unwrap();
            let mut restored = Vec::new();
            for line in logged
                .split(|b| *b == b'\n')
                .filter(|line| !line.is_empty())
            {
                let event: voboost_contract::runtime_log::Event =
                    serde_json::from_slice(line).unwrap();
                restored.extend(hex::decode(&event.fields["bytesHex"]).unwrap());
            }
            assert_eq!(restored, bytes);
        }
    }

    #[test]
    fn incomplete_receive_and_unknown_clock_remain_explicit() {
        let record = Datagram {
            bytes: vec![1, 2],
            reported_bytes: 70000,
            socket_buffer_bytes: 524288,
            sender_pid: 99,
            sender_groups: 0,
            address_bytes: 8,
            sender_family: 0,
            flags: libc::MSG_TRUNC,
            received_boot_ms: None,
        }
        .records(1, 1)
        .remove(0);
        assert_eq!(record.fields["reportedBytes"], "70000");
        assert_eq!(record.fields["capturedBytes"], "2");
        assert_eq!(record.fields["receiveClockUnavailable"], "true");
        assert!(!record.fields.contains_key("receiveBootMs"));
    }
}
