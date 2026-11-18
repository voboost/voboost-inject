//! Scoped GOT replacement transaction. A caller must supply an actual live-map
//! witness; ELF segment flags are deliberately insufficient for this operation.
//! All preparation runs before the OEM supervisor may fork.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
    InvalidWitness,
    OriginalChanged,
    PublishOriginal,
    MakeWritable,
    CompareExchange,
    RestoreProtection,
    RollbackConflict,
}

/// Exact mapping information obtained independently from the running process.
/// `protection` uses the native PROT_READ/WRITE/EXEC values, supplied explicitly
/// rather than inferred from PT_LOAD or PT_GNU_RELRO.
#[derive(Clone, Copy)]
pub struct LiveMapping {
    pub start: usize,
    pub length: usize,
    pub page_size: usize,
    pub protection: i32,
    pub read: i32,
    pub write: i32,
    pub execute: i32,
}

/// Platform operations are separated so errors and concurrent changes can be
/// exercised without writing a host process's loader mappings.
pub trait Operations {
    fn load(&mut self, slot: usize) -> usize;
    fn publish_original(&mut self, original: usize) -> bool;
    fn protect(&mut self, page: usize, length: usize, protection: i32) -> bool;
    fn compare_exchange(&mut self, slot: usize, old: usize, new: usize) -> bool;
}

/// Replace exactly one aligned pointer. Unknown/lazy slot targets never change.
/// No executable permission is introduced, and a failed protection restoration
/// rolls the pointer back before retrying the exact original protection.
pub fn install(
    ops: &mut impl Operations,
    mapping: LiveMapping,
    slot: usize,
    original: usize,
    wrapper: usize,
) -> core::result::Result<(), Failure> {
    let width = core::mem::size_of::<usize>();
    let end = slot.checked_add(width).ok_or(Failure::InvalidWitness)?;
    let map_end = mapping
        .start
        .checked_add(mapping.length)
        .ok_or(Failure::InvalidWitness)?;
    if mapping.page_size == 0
        || !mapping.page_size.is_power_of_two()
        || mapping.start % mapping.page_size != 0
        || mapping.length == 0
        || mapping.length % mapping.page_size != 0
        || slot % width != 0
        || slot < mapping.start
        || end > map_end
        || original == 0
        || wrapper == 0
        || original == wrapper
        || mapping.read == 0
        || mapping.write == 0
        || mapping.execute == 0
        || mapping.read & mapping.write != 0
        || mapping.read & mapping.execute != 0
        || mapping.write & mapping.execute != 0
        || mapping.protection & mapping.read == 0
        || mapping.protection & mapping.execute != 0
        || mapping.protection & !(mapping.read | mapping.write) != 0
    {
        return Err(Failure::InvalidWitness);
    }
    let page = slot & !(mapping.page_size - 1);
    if end
        > page
            .checked_add(mapping.page_size)
            .ok_or(Failure::InvalidWitness)?
    {
        return Err(Failure::InvalidWitness);
    }
    if ops.load(slot) != original {
        return Err(Failure::OriginalChanged);
    }
    if !ops.publish_original(original) {
        return Err(Failure::PublishOriginal);
    }
    let change = mapping.protection & mapping.write == 0;
    if change && !ops.protect(page, mapping.page_size, mapping.protection | mapping.write) {
        return Err(Failure::MakeWritable);
    }
    if !ops.compare_exchange(slot, original, wrapper) {
        if change && !ops.protect(page, mapping.page_size, mapping.protection) {
            return Err(Failure::RestoreProtection);
        }
        return Err(Failure::CompareExchange);
    }
    if change && !ops.protect(page, mapping.page_size, mapping.protection) {
        // mprotect failure leaves the previous writable mapping in force.
        // Never overwrite an intervening owner's value during rollback.
        let rolled_back = ops.compare_exchange(slot, wrapper, original);
        let _ = ops.protect(page, mapping.page_size, mapping.protection);
        return Err(if rolled_back {
            Failure::RestoreProtection
        } else {
            Failure::RollbackConflict
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        value: usize,
        calls: alloc::vec::Vec<i32>,
        fail_at: usize,
        race: bool,
    }
    impl Operations for Fake {
        fn load(&mut self, _: usize) -> usize {
            self.value
        }
        fn publish_original(&mut self, _: usize) -> bool {
            true
        }
        fn protect(&mut self, _: usize, _: usize, p: i32) -> bool {
            self.calls.push(p);
            self.calls.len() != self.fail_at
        }
        fn compare_exchange(&mut self, _: usize, old: usize, new: usize) -> bool {
            if self.race {
                self.value = 77;
                self.race = false;
            }
            if self.value != old {
                return false;
            }
            self.value = new;
            true
        }
    }
    fn mapping() -> LiveMapping {
        LiveMapping {
            start: 4096,
            length: 4096,
            page_size: 4096,
            protection: 1,
            read: 1,
            write: 2,
            execute: 4,
        }
    }
    fn fake() -> Fake {
        Fake {
            value: 10,
            calls: alloc::vec::Vec::new(),
            fail_at: 0,
            race: false,
        }
    }
    #[test]
    fn success_restores_exact_flags() {
        let mut f = fake();
        assert_eq!(install(&mut f, mapping(), 4104, 10, 20), Ok(()));
        assert_eq!(f.value, 20);
        assert_eq!(f.calls, [3, 1]);
    }
    #[test]
    fn unknown_target_is_untouched() {
        let mut f = fake();
        f.value = 99;
        assert_eq!(
            install(&mut f, mapping(), 4104, 10, 20),
            Err(Failure::OriginalChanged)
        );
        assert!(f.calls.is_empty());
        assert_eq!(f.value, 99);
    }
    #[test]
    fn make_writable_failure_does_not_patch() {
        let mut f = fake();
        f.fail_at = 1;
        assert_eq!(
            install(&mut f, mapping(), 4104, 10, 20),
            Err(Failure::MakeWritable)
        );
        assert_eq!(f.value, 10);
    }
    #[test]
    fn race_does_not_overwrite_other_hook() {
        let mut f = fake();
        f.race = true;
        assert_eq!(
            install(&mut f, mapping(), 4104, 10, 20),
            Err(Failure::CompareExchange)
        );
        assert_eq!(f.value, 77);
        assert_eq!(f.calls, [3, 1]);
    }
    #[test]
    fn failed_restore_rolls_back() {
        let mut f = fake();
        f.fail_at = 2;
        assert_eq!(
            install(&mut f, mapping(), 4104, 10, 20),
            Err(Failure::RestoreProtection)
        );
        assert_eq!(f.value, 10);
        assert_eq!(f.calls, [3, 1, 1]);
    }
    #[test]
    fn writable_slot_needs_no_protection_change() {
        let mut f = fake();
        let mut m = mapping();
        m.protection = 3;
        assert_eq!(install(&mut f, m, 4104, 10, 20), Ok(()));
        assert!(f.calls.is_empty());
    }
    #[test]
    fn executable_or_unknown_mapping_is_rejected() {
        for p in [0, 5, 7, 9] {
            let mut f = fake();
            let mut m = mapping();
            m.protection = p;
            assert_eq!(
                install(&mut f, m, 4104, 10, 20),
                Err(Failure::InvalidWitness)
            );
            assert!(f.calls.is_empty());
            assert_eq!(f.value, 10);
        }
    }
}
