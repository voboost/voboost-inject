//! Persistent exact-byte transaction for the fixed OEM supervisor config.
//! The config path, WAL and sidecar names are code constants; all persisted
//! state lives in the protected installation root. Every comparison is an
//! exact byte or exact mode/presence comparison; no new digest is introduced
//! and the pure XML emitters are consumed byte-for-byte, never re-serialized.
//!
//! Actual QNX F_SETLK and remount ABI are probed by the QNX backend at
//! runtime; they are NOT closed or proven by the host failure-matrix tests.
#[cfg(any(target_os = "nto", test))]
use crate::{fs::Dir, Result};
#[cfg(any(target_os = "nto", test))]
use alloc::{string::String, vec::Vec};

// The receipt type belongs to the enclosing Installation record on every
// platform; the transaction machinery behind it is QNX-or-test only.
#[cfg(any(target_os = "nto", test))]
pub(crate) const CONFIG_PATH: &str = "/etc/clsboot/boot_cfg.xml";
#[cfg(any(target_os = "nto", test))]
const RECORD_MAX: usize = 16384;

/// Typed Installation subrecord; absent means no config-delivery capability.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SupervisorConfig {
    pub schema_version: u32,
    pub path: String,
    /// Distinctly recorded original absence, never inferred from emptiness.
    pub original_absent: bool,
    pub original_mode: u32,
    pub installed_mode: u32,
    /// Trusted installer entropy, never a digest; same value as the
    /// VOBOOST_CLUSTER_SUPERVISOR env of the retained candidate.
    pub delivery_nonce: String,
}
#[cfg(any(target_os = "nto", test))]
impl SupervisorConfig {
    /// Full contract check on every persisted receipt: schema, fixed path,
    /// trusted-entropy nonce shape, bounded modes.
    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.path != CONFIG_PATH
            || !valid_nonce(&self.delivery_nonce)
            || self.installed_mode & 0o777 != self.installed_mode
            || self.original_mode & 0o777 != self.original_mode
        {
            return Err("SetupRequired: supervisor config receipt invalid".into());
        }
        Ok(())
    }
}
#[cfg(any(target_os = "nto", test))]
fn valid_nonce(candidate: &str) -> bool {
    candidate.len() == 64
        && candidate
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(any(target_os = "nto", test))]
pub(crate) mod machinery {
    use super::*;
    use crate::fs::UninstallBoot;
    use alloc::{collections::BTreeSet, format};
    pub(crate) const MAX_CONFIG: usize = 1024 * 1024;
    pub(crate) const LOCK_NAME: &str = "supervisor.lock";
    pub(crate) const WAL_NAME: &str = "supervisor-config.wal";
    pub(crate) const ORIGINAL_NAME: &str = "supervisor-config.original";
    pub(crate) const INSTALLED_NAME: &str = "supervisor-config.installed";
    pub(crate) const BEFORE_NAME: &str = "supervisor-config.pending-before";
    pub(crate) const AFTER_NAME: &str = "supervisor-config.pending-after";
    pub(crate) const ABSENT_MARKER: &[u8] = b"VBCSUPABSENT\n";
    pub(crate) const LOCK_MARKER: &[u8] = b"VBCSUPLOCK1\n";
    const LATE_RESTORE_FENCE: &str = "supervisor-uninstall-reboot.json";
    const LATE_RESTORE_REBOOT: &str =
        "native uninstall requires independent new kernel boot after legacy supervisor restoration";

    /// Exact presence/mode observation of one file set.
    #[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub(crate) struct Presence {
        pub(crate) present: bool,
        pub(crate) mode: u32,
    }
    impl Presence {
        pub(crate) fn of(present: bool, mode: u32) -> Result<Self> {
            if mode & 0o777 != mode {
                return Err("SetupRequired: configuration mode invalid".into());
            }
            Ok(Self { present, mode })
        }
    }

    /// Exact live configuration observation, capturing absence distinctly.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct LiveConfig {
        pub present: bool,
        pub bytes: Vec<u8>,
        pub mode: u32,
    }
    impl LiveConfig {
        fn presence(&self) -> Result<Presence> {
            Presence::of(self.present, self.mode)
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) enum WalState {
        Preparing,
        Prepared,
        Applied,
    }

    /// Durable write-ahead journal under the operation lock. No digest fields:
    /// recovery compares exact live and sidecar bytes.
    #[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub(crate) struct Wal {
        pub(crate) schema_version: u32,
        pub(crate) transaction_id: String,
        pub(crate) config_path: String,
        pub(crate) delivery_nonce: String,
        pub(crate) state: WalState,
        // Earlier install WALs carry no direction; they retain the original
        // bounded rollback semantics. Only explicit restore WALs roll forward.
        #[serde(default, skip_serializing_if = "is_false")]
        pub(crate) restoring: bool,
        /// FIRST original absence/mode, captured only once, kept forever.
        pub(crate) first_original: Presence,
        pub(crate) before: Presence,
        pub(crate) after: Presence,
    }
    fn is_false(value: &bool) -> bool {
        !value
    }

    impl Wal {
        pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
            let value: Self = voboost_contract_core::parse_canonical(bytes, RECORD_MAX)?;
            value.validate()?;
            Ok(value)
        }
        pub(crate) fn validate(&self) -> Result<()> {
            if self.schema_version != 1
                || !voboost_contract_core::digest(&self.transaction_id)
                || self.config_path != CONFIG_PATH
                || !valid_nonce(&self.delivery_nonce)
            {
                return Err("SetupRequired: supervisor config WAL invalid".into());
            }
            Ok(())
        }
        pub(crate) fn bytes(&self) -> Result<Vec<u8>> {
            voboost_contract_core::ascii_json(self).map_err(|e: alloc::string::String| e)
        }
    }

    /// One stable regular single-link uid-owned lock inode under the protected
    /// installation root. Never unlinked or replaced; nonblocking fcntl F_WRLCK
    /// held through a dedicated writable FD until this guard drops. QNX
    /// documents process-exit release and close-releases-locks; both collapse to
    /// drop. Actual QNX F_SETLK/filesystem support is probed by this very call at
    /// runtime and is NOT established by host tests.
    pub(crate) struct OperationLock {
        fd: crate::fs::Fd,
    }
    impl OperationLock {
        pub(crate) fn acquire(root: &Dir) -> Result<Self> {
            if !root.exists(LOCK_NAME)? {
                root.write(LOCK_NAME, LOCK_MARKER, 0o600)?;
            }
            if root.read(LOCK_NAME, 64, 0o600)? != LOCK_MARKER {
                return Err("SetupRequired: supervisor lock member foreign".into());
            }
            let name = alloc::ffi::CString::new(format!("{}/{}", root.path, LOCK_NAME))
                .map_err(|_| "supervisor lock path NUL")?;
            let fd = crate::fs::Fd(unsafe {
                libc::open(
                    name.as_ptr(),
                    libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            });
            if fd.0 < 0 {
                return Err("SetupRequired: supervisor lock descriptor unavailable".into());
            }
            let before = crate::fs::stat(fd.0)?;
            // QNX flock carries two padding/peer fields the portable layout omits.
            #[cfg(target_os = "nto")]
            let request = libc::flock {
                l_type: libc::F_WRLCK as libc::c_short,
                l_whence: libc::SEEK_SET as libc::c_short,
                l_zero1: 0,
                l_start: 0,
                l_len: 0,
                l_pid: 0,
                l_sysid: 0,
            };
            #[cfg(not(target_os = "nto"))]
            let request = libc::flock {
                l_type: libc::F_WRLCK as libc::c_short,
                l_whence: libc::SEEK_SET as libc::c_short,
                l_start: 0,
                l_len: 0,
                l_pid: 0,
            };
            // Nonblocking: two writers can never both proceed past this point.
            if unsafe { libc::fcntl(fd.0, libc::F_SETLK, &request) } != 0 {
                return Err("SetupRequired: supervisor operation lock held elsewhere".into());
            }
            let after = crate::fs::stat(fd.0)?;
            if before.st_mode & libc::S_IFMT != libc::S_IFREG
                || before.st_nlink != 1
                || before.st_uid as u32 != root.owner
                || before.st_mode as u32 & 0o777 != 0o600
                || !crate::fs::unchanged(&before, &after)
            {
                return Err("SetupRequired: supervisor lock inode identity rejected".into());
            }
            Ok(Self { fd })
        }
    }
    impl Drop for OperationLock {
        fn drop(&mut self) {
            // QNX flock carries two padding/peer fields the portable layout omits.
            #[cfg(target_os = "nto")]
            let release = libc::flock {
                l_type: libc::F_UNLCK as libc::c_short,
                l_whence: libc::SEEK_SET as libc::c_short,
                l_zero1: 0,
                l_start: 0,
                l_len: 0,
                l_pid: 0,
                l_sysid: 0,
            };
            #[cfg(not(target_os = "nto"))]
            let release = libc::flock {
                l_type: libc::F_UNLCK as libc::c_short,
                l_whence: libc::SEEK_SET as libc::c_short,
                l_start: 0,
                l_len: 0,
                l_pid: 0,
            };
            unsafe {
                libc::fcntl(self.fd.0, libc::F_SETLK, &release);
            }
        }
    }

    /// Named interruption points for the host failure matrix; production passes
    /// an empty set. Every durable boundary in the sequence is coverable.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub(crate) enum Failpoint {
        WalPreparingPersisted,
        SidecarsPersisted,
        WalPrepared,
        FenceWritten,
        RemountWritable,
        BeforeRecheck,
        Published,
        ReadonlyRestored,
        InstalledSidecarPersisted,
        ReceiptPersisted,
        FinalReadback,
    }
    pub(crate) type Failpoints = BTreeSet<Failpoint>;

    /// Mount-and-publish authority for the fixed config path. The QNX backend
    /// mirrors the reviewed oem_startup invariants: pinned root and parent
    /// identity, same filesystem, original readonly required, remount removes
    /// ONLY the readonly flag and verifies every retained flag, atomic publish
    /// plus file/parent fsync plus exact readback, exact flag restoration.
    /// Host tests supply a deterministic mock; no mock claims QNX remount ABI.
    pub(crate) trait Writer {
        fn observe(&mut self) -> Result<LiveConfig>;
        fn writable(&mut self) -> Result<()>;
        fn verify_writable(&mut self) -> Result<()>;
        /// Atomic publish with exact intended mode, fsync file/parent, exact
        /// readback of the published bytes.
        fn publish(&mut self, bytes: &[u8], mode: u32) -> Result<()>;
        /// Bounded protected-member unlink limited to this fixed config path,
        /// used only to restore an originally-absent config.
        fn publish_absence(&mut self) -> Result<()>;
        /// Restore the exact original readonly flags and verify them.
        fn readonly(&mut self) -> Result<()>;
        /// Verify readonly flags plus root/parent identity; when expect_installed
        /// is false the live config must equal the exact original/absent state.
        fn verify_readonly(&mut self, expect_installed: bool) -> Result<()>;
    }

    fn check(failpoints: &Failpoints, point: Failpoint) -> Result<()> {
        if failpoints.contains(&point) {
            return Err(format!("SetupRequired: injected {point:?} interruption"));
        }
        Ok(())
    }

    /// Substring containment used only for ownership admission of live XML.
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
    }

    // Fixed-protected-root sidecar helpers. A vanished member is never absence:
    // original absence and (where allowed) absent-before use an explicit marker.

    fn persist_sidecar(root: &Dir, name: &str, bytes: Option<&[u8]>) -> Result<()> {
        match bytes {
            Some(payload) => root.write(name, payload, 0o600)?,
            None => root.write(name, ABSENT_MARKER, 0o600)?,
        }
        let back = root.read(name, MAX_CONFIG + 16, 0o600)?;
        if back != bytes.unwrap_or(ABSENT_MARKER) {
            return Err(format!("SetupRequired: {name} readback differs"));
        }
        Ok(())
    }
    /// Returns Some(bytes) for a retained payload, Some([]) never, and None for
    /// the explicit absence marker. A missing member is a hard error.
    fn read_sidecar(root: &Dir, name: &str) -> Result<Option<Vec<u8>>> {
        let back = root.read(name, MAX_CONFIG + 16, 0o600)?;
        if back == ABSENT_MARKER {
            return Ok(None);
        }
        Ok(Some(back))
    }
    fn require_absent_or_payload(root: &Dir, name: &str) -> Result<Option<Vec<u8>>> {
        if !root.exists(name)? {
            return Err(format!("SetupRequired: {name} sidecar missing"));
        }
        read_sidecar(root, name)
    }
    /// Retained FIRST original: Some(bytes) or None for recorded absence.
    fn first_original(root: &Dir) -> Result<Option<Vec<u8>>> {
        if !root.exists(ORIGINAL_NAME)? {
            return Ok(None);
        }
        read_sidecar(root, ORIGINAL_NAME)
    }

    /// Delivery-permit admission: pending, malformed or incomplete WAL always
    /// denies, independent of boot id; reboot cannot complete an operation. The
    /// typed receipt is the supervisorConfig subrecord of the enclosing signed
    /// Installation record (install/state.json), never a standalone authority.
    pub(crate) fn permit_ready(root: &Dir) -> Result<Option<SupervisorConfig>> {
        if !crate::install_layout::state_exists(root)? || !root.exists(WAL_NAME)? {
            return Ok(None);
        }
        let Ok(wal) = Wal::parse(&root.read(WAL_NAME, RECORD_MAX, 0o600)?) else {
            return Ok(None);
        };
        if wal.state != WalState::Applied {
            return Ok(None);
        }
        // Read through the existing Installation accessor so every enclosing
        // authority check stays active; a printed subrecord alone is nothing.
        crate::install::supervisor_config_receipt(root)
    }

    /// Validate-or-recover any existing WAL under the operation lock, BEFORE any
    /// sidecar is reused. Recognizes only exact-before or exact-after live state;
    /// unknown bytes are preserved and reported, never overwritten.
    pub(crate) fn recover_existing(root: &Dir, writer: &mut impl Writer) -> Result<()> {
        if !root.exists(WAL_NAME)? {
            return Ok(());
        }
        let mut wal = match Wal::parse(&root.read(WAL_NAME, RECORD_MAX, 0o600)?) {
            Ok(wal) => wal,
            Err(_) => {
                return Err(
                    "SetupRequired: supervisor WAL malformed; journal retained for diagnosis"
                        .into(),
                );
            }
        };
        if wal.state == WalState::Applied {
            return Ok(());
        }
        if wal.state == WalState::Preparing {
            // No system mutation had begun; a bounded proven recovery is required.
            // Missing sidecars allow no system mutation and no permit; either way
            // the journal and any partial sidecars are preserved for diagnosis.
            let _ = root.read(BEFORE_NAME, MAX_CONFIG + 16, 0o600);
            let _ = root.read(AFTER_NAME, MAX_CONFIG + 16, 0o600);
            return Err(
                "SetupRequired: Preparing supervisor WAL; journal and sidecars preserved".into(),
            );
        }
        let before = require_absent_or_payload(root, BEFORE_NAME)?;
        let after = require_absent_or_payload(root, AFTER_NAME)?;
        if wal.restoring {
            // Complete restore forward; never reinstate delivery after retiring its receipt.
            let first = require_absent_or_payload(root, ORIGINAL_NAME)?;
            if after != first || wal.after != wal.first_original {
                return Err("SetupRequired: restore WAL target differs from FIRST original".into());
            }
            let live = writer.observe()?;
            let exact = |bytes: &Option<Vec<u8>>, presence: &Presence| match bytes {
                Some(bytes) => {
                    live.present
                        && presence.present
                        && live.bytes == *bytes
                        && live.mode == presence.mode
                }
                None => !live.present && !presence.present,
            };
            let at_before = exact(&before, &wal.before);
            let at_after = exact(&after, &wal.after);
            if !at_before && !at_after {
                return Err("SetupRequired: supervisor restore live state is foreign".into());
            }
            let installed = require_absent_or_payload(root, INSTALLED_NAME)?;
            match crate::install::supervisor_config_receipt(root)? {
                Some(receipt) => {
                    receipt.validate()?;
                    if receipt.delivery_nonce != wal.delivery_nonce
                        || receipt.original_absent != !wal.first_original.present
                        || receipt.original_mode != wal.first_original.mode
                        || receipt.installed_mode != wal.before.mode
                        || (installed != before && !(at_after && installed.is_none()))
                    {
                        return Err("SetupRequired: restore recovery authority differs".into());
                    }
                }
                None if at_after && installed.is_none() => {}
                None => return Err("SetupRequired: restore recovery receipt missing".into()),
            }
            if !at_after {
                writer.writable()?;
                writer.verify_writable()?;
                if !matches!(writer.observe(), Ok(observed) if observed == live) {
                    writer.readonly()?;
                    return Err("SetupRequired: supervisor restore before-state changed".into());
                }
                match &after {
                    Some(bytes) => writer.publish(bytes, wal.after.mode)?,
                    None => writer.publish_absence()?,
                }
            }
            writer.readonly()?;
            let restored = writer.observe()?;
            let exact_after = match &after {
                Some(bytes) => {
                    restored.present && restored.bytes == *bytes && restored.mode == wal.after.mode
                }
                None => !restored.present,
            };
            if !exact_after {
                return Err("SetupRequired: forward restore readback differs".into());
            }
            writer.verify_readonly(false)?;
            persist_sidecar(root, INSTALLED_NAME, None)?;
            crate::install::clear_supervisor_config_receipt(root)?;
            wal.state = WalState::Applied;
            root.write(WAL_NAME, &wal.bytes()?, 0o600)?;
            return Ok(());
        }
        // Prepared: mutation may have begun or completed. Exact-after rolls back
        // to exact-before with flag restoration; exact-before needs no write.
        let live = writer.observe()?;
        if let Some(expected) = &after {
            if live.present && live.bytes == *expected && live.mode == wal.after.mode {
                let mode = wal.before.mode;
                writer.writable()?;
                writer.verify_writable()?;
                match &before {
                    Some(bytes) => writer.publish(bytes, mode)?,
                    None => writer.publish_absence()?,
                }
                writer.readonly()?;
                let restored = writer.observe()?;
                let exact = match (&before, restored.present) {
                    (Some(bytes), true) => restored.bytes == *bytes && restored.mode == mode,
                    (None, false) => true,
                    _ => false,
                };
                if !exact {
                    return Err(
                        "SetupRequired: recovery rollback unverifiable; journal retained".into(),
                    );
                }
                writer.verify_readonly(false)?;
                wal.state = WalState::Applied;
                root.write(WAL_NAME, &wal.bytes()?, 0o600)?;
                return Ok(());
            }
        }
        let before_exact = match (&before, live.present) {
            (Some(bytes), true) => live.bytes == *bytes && live.mode == wal.before.mode,
            (None, false) => true,
            _ => false,
        };
        if before_exact {
            // Known-before: mark terminal without a content write.
            writer.verify_readonly(false)?;
            wal.state = WalState::Applied;
            root.write(WAL_NAME, &wal.bytes()?, 0o600)?;
            return Ok(());
        }
        Err("SetupRequired: supervisor live config is foreign to the WAL; preserved".into())
    }

    /// What the caller supplies for one operation. `default_candidate` is the
    /// staged full candidate for an originally-absent config, produced offline
    /// through the proved emitter; it never comes from an OEM generator run.
    pub(crate) struct Operation {
        pub transaction_id: String,
        pub implant: String,
        pub bootfile: String,
        pub nonce: String,
        pub default_candidate: Option<Vec<u8>>,
        pub failpoints: Failpoints,
        // Restore reuses the retained receipt nonce; it never rotates it.
        pub restore: bool,
    }

    /// One complete durable save/restore sequence for `/etc/clsboot/boot_cfg.xml`
    /// under the exclusive operation lock. Callers have already revoked delivery.
    /// `composed_from` (when supplied) is the exact live observation the candidate was
    /// built from before the lock; a fresh observation differing from it is a
    /// concurrent foreign change and fails before any durable state is written.
    pub(crate) fn execute(
        root: &Dir,
        writer: &mut impl Writer,
        operation: &Operation,
        candidate: &[u8],
        composed_from: Option<&LiveConfig>,
        installed_mode: u32,
        saving: bool,
    ) -> Result<()> {
        if !valid_nonce(&operation.nonce) {
            return Err("SetupRequired: supervisor delivery nonce invalid".into());
        }
        let live = writer.observe()?;
        if let Some(source) = composed_from {
            if &live != source {
                return Err("SetupRequired: live config changed before transaction lock".into());
            }
        }
        let prior_receipt = permit_ready(root)?;
        let prior_installed = if root.exists(INSTALLED_NAME)? {
            require_absent_or_payload(root, INSTALLED_NAME)?
        } else {
            None
        };
        // Update/reinstall: exact live XML must equal the retained prior
        // candidate; never our own installed output can become the original.
        // Restore admits only through its own validated receipt path in
        // restore(), reusing the retained nonce without rotation.
        let first = match prior_receipt.as_ref() {
            Some(receipt) => {
                // A foreign mode-only change is not the retained state either.
                if !matches_candidate(&live, prior_installed.as_deref())
                    || (!operation.restore && live.mode != receipt.installed_mode)
                {
                    return Err(
                        "SetupRequired: live supervisor config differs from retained candidate"
                            .into(),
                    );
                }
                if !operation.restore && receipt.delivery_nonce == operation.nonce {
                    return Err("SetupRequired: replacement nonce must differ".into());
                }
                if operation.restore && receipt.delivery_nonce != operation.nonce {
                    return Err("SetupRequired: restore nonce differs from receipt".into());
                }
                let retained = first_original(root)?;
                let expect_absent = receipt.original_absent;
                if expect_absent != retained.is_none() {
                    return Err("SetupRequired: first-original sidecar contradicts receipt".into());
                }
                let mode = if expect_absent {
                    0
                } else {
                    receipt.original_mode
                };
                Presence::of(!expect_absent, mode)?
            }
            None => {
                // First install: absent XML keeps absence; present captures the
                // FIRST original bytes. A preexisting original sidecar without a
                // matching receipt is an orphan and is rejected. A live config
                // already containing our implant token or controlled variables is
                // someone else's (or a stale unowned) delivery: byte-idempotent
                // augment alone does not establish ownership.
                if root.exists(ORIGINAL_NAME)? {
                    return Err("SetupRequired: orphan original sidecar without a receipt".into());
                }
                if live.present
                    && (contains(&live.bytes, b"VOBOOST_CLUSTER_BOOTFILE=")
                        || contains(&live.bytes, b"VOBOOST_CLUSTER_SUPERVISOR=")
                        || contains(&live.bytes, operation.implant.as_bytes()))
                {
                    return Err(
                        "SetupRequired: unowned delivery spans present in live config".into(),
                    );
                }
                let original_bytes = if live.present {
                    Some(live.bytes.clone())
                } else {
                    None
                };
                persist_sidecar(root, ORIGINAL_NAME, original_bytes.as_deref())?;
                Presence::of(live.present, live.mode)?
            }
        };
        let first_bytes = first_original(root)?;
        if !live.present && first_bytes.is_some() {
            return Err("SetupRequired: retained original contradicts absence".into());
        }
        // The recovery target is the fresh candidate on install/update, or
        // the exact FIRST original bytes/mode (or original absence) on restore:
        // an interrupted restore must auto-recover to the same target.
        let after_target: Option<Vec<u8>> = if saving {
            Some(candidate.to_vec())
        } else {
            first_bytes.clone()
        };
        let after_mode = if saving { installed_mode } else { first.mode };
        let wal = Wal {
            schema_version: 1,
            transaction_id: operation.transaction_id.clone(),
            config_path: CONFIG_PATH.into(),
            delivery_nonce: operation.nonce.clone(),
            state: WalState::Preparing,
            restoring: operation.restore,
            first_original: first.clone(),
            before: live.presence()?,
            after: Presence::of(after_target.is_some(), after_mode)?,
        };
        // Preparing WAL first: from here every delivery permit is denied.
        root.write(WAL_NAME, &wal.bytes()?, 0o600)?;
        if root.read(WAL_NAME, RECORD_MAX, 0o600)? != wal.bytes()? {
            return Err("SetupRequired: Preparing WAL readback differs".into());
        }
        check(&operation.failpoints, Failpoint::WalPreparingPersisted)?;
        persist_sidecar(
            root,
            BEFORE_NAME,
            if live.present {
                Some(&live.bytes)
            } else {
                None
            },
        )?;
        persist_sidecar(root, AFTER_NAME, after_target.as_deref())?;
        check(&operation.failpoints, Failpoint::SidecarsPersisted)?;
        // Prepared: all recovery bytes are durable.
        let mut prepared = wal.clone();
        prepared.state = WalState::Prepared;
        root.write(WAL_NAME, &prepared.bytes()?, 0o600)?;
        if Wal::parse(&root.read(WAL_NAME, RECORD_MAX, 0o600)?)? != prepared {
            return Err("SetupRequired: Prepared WAL readback differs".into());
        }
        check(&operation.failpoints, Failpoint::WalPrepared)?;
        // Current-kernel revocation fence precedes any system mutation.
        crate::supervisor_delivery::revoke(root)?;
        check(&operation.failpoints, Failpoint::FenceWritten)?;
        writer.writable()?;
        writer.verify_writable()?;
        check(&operation.failpoints, Failpoint::RemountWritable)?;
        // Exact-before recheck immediately before publish.
        let recheck = writer.observe()?;
        if recheck.presence()? != live.presence()? || recheck.bytes != live.bytes {
            return Err("SetupRequired: supervisor before-state changed".into());
        }
        check(&operation.failpoints, Failpoint::BeforeRecheck)?;
        if saving {
            writer.publish(candidate, installed_mode)?;
        } else if let Some(original) = first_bytes.as_deref() {
            writer.publish(original, first.mode)?;
        } else {
            // The FIRST original was absent: absence must be restored, not an
            // empty synthetic XML.
            writer.publish_absence()?;
        }
        check(&operation.failpoints, Failpoint::Published)?;
        writer.readonly()?;
        let verified = writer.observe()?;
        let expected: &[u8] = if saving {
            candidate
        } else if let Some(bytes) = first_bytes.as_deref() {
            bytes
        } else {
            // absent restore: no live bytes expected
            &[]
        };
        let exact = if saving || first_bytes.is_some() {
            verified.present && verified.bytes == expected
        } else {
            !verified.present
        };
        if !exact || (verified.present && verified.mode != after_mode) {
            return Err("SetupRequired: supervisor publish readback differs".into());
        }
        writer.verify_readonly(saving)?;
        check(&operation.failpoints, Failpoint::ReadonlyRestored)?;
        persist_sidecar(
            root,
            INSTALLED_NAME,
            if saving { Some(candidate) } else { None },
        )?;
        check(&operation.failpoints, Failpoint::InstalledSidecarPersisted)?;
        // The new Installation record retains the FIRST original; the subrecord
        // is the typed supervisorConfig receipt inside install/state.json.
        let receipt = SupervisorConfig {
            schema_version: 1,
            path: CONFIG_PATH.into(),
            original_absent: first_original(root)?.is_none(),
            original_mode: first.mode,
            installed_mode,
            delivery_nonce: operation.nonce.clone(),
        };
        if operation.restore {
            crate::install::clear_supervisor_config_receipt(root)?;
        } else {
            crate::install::persist_supervisor_config_receipt(root, &receipt)?;
        }
        check(&operation.failpoints, Failpoint::ReceiptPersisted)?;
        // Terminal Applied only after one complete exact final readback.
        let final_live = writer.observe()?;
        if final_live.bytes != verified.bytes || final_live.presence()? != verified.presence()? {
            return Err("SetupRequired: final supervisor readback differs".into());
        }
        check(&operation.failpoints, Failpoint::FinalReadback)?;
        let mut applied = prepared;
        applied.state = WalState::Applied;
        root.write(WAL_NAME, &applied.bytes()?, 0o600)?;
        Ok(())
    }

    fn matches_candidate(live: &LiveConfig, retained: Option<&[u8]>) -> bool {
        match retained {
            Some(bytes) => live.present && live.bytes == bytes,
            None => !live.present,
        }
    }

    /// The production QNX run orchestration, shared with the host matrix.
    pub(crate) fn run_standard(
        root: &Dir,
        writer: &mut impl Writer,
        operation: &Operation,
        candidate: &[u8],
        composed_from: Option<&LiveConfig>,
        installed_mode: u32,
        saving: bool,
    ) -> Result<()> {
        let _lock = OperationLock::acquire(root)?;
        recover_existing(root, writer)?;
        execute(
            root,
            writer,
            operation,
            candidate,
            composed_from,
            installed_mode,
            saving,
        )
    }

    /// Admit only an already-completed restore or F5 install rollback: exact
    /// FIRST bytes/mode/absence, readonly, terminal WAL and no retained receipt.
    /// An explicit restore also requires its exact target and retired installed
    /// sidecar. No delivery identity is created or reconstructed by this check.
    pub(crate) fn restored_without_receipt(root: &Dir, writer: &mut impl Writer) -> Result<bool> {
        if !root.exists(WAL_NAME)? {
            return Ok(false);
        }
        let wal = match Wal::parse(&root.read(WAL_NAME, RECORD_MAX, 0o600)?) {
            Ok(wal) => wal,
            Err(_) => return Ok(false),
        };
        if wal.state != WalState::Applied {
            return Ok(false);
        }
        // The enclosing Installation record must carry no receipt subrecord: a
        // printed receipt means the tail completed durably and owns the config.
        if crate::install::supervisor_config_receipt(root)?.is_some() {
            return Ok(false);
        }
        // The live config must be the exact recovered FIRST original state
        // (bytes/mode, or recorded original absence); anything else — a foreign
        // change, a still-installed candidate — is NOT a completed waiver and
        // keeps the standard fail-closed refusal.
        let first = require_absent_or_payload(root, ORIGINAL_NAME)?;
        if wal.first_original.present != first.is_some() {
            return Ok(false);
        }
        if wal.restoring
            && (wal.after != wal.first_original
                || require_absent_or_payload(root, AFTER_NAME)? != first
                || require_absent_or_payload(root, INSTALLED_NAME)?.is_some())
        {
            return Ok(false);
        }
        let live = writer.observe()?;
        writer.verify_readonly(false)?;
        Ok(match &first {
            Some(bytes) => {
                live.present && live.bytes == *bytes && live.mode == wal.first_original.mode
            }
            None => !live.present,
        })
    }

    /// Older resident services signed uninstall preparation after restoring
    /// startup without restoring the supervisor XML. Only an exact retained
    /// installation can enter this post-boot repair path. Record the current
    /// kernel before changing XML: OEM processes on this boot could have loaded
    /// the implant through the old XML even with resident delivery disabled.
    pub(crate) fn require_uninstall_restored(
        root: &Dir,
        writer: &mut impl Writer,
        transaction_id: &str,
        boot: impl Into<UninstallBoot>,
    ) -> Result<()> {
        const NOT_RESTORED: &str =
            "native uninstall original supervisor configuration not restored";
        let _lock = OperationLock::acquire(root)?;
        let boot = boot.into();
        if !boot.valid() {
            return Err("native uninstall supervisor restoration kernel unknown".into());
        }
        let fenced_boot = if root.exists(LATE_RESTORE_FENCE)? {
            let (transaction, recorded): (String, UninstallBoot) = voboost_contract_core::parse_canonical(
                &root.read(LATE_RESTORE_FENCE, 256, 0o600)?,
                256,
            )?;
            if transaction != transaction_id || !recorded.valid() || !recorded.same_source(&boot) {
                return Err("native uninstall supervisor restoration fence differs".into());
            }
            Some(recorded)
        } else {
            None
        };
        if restored_without_receipt(root, writer)? {
            return if fenced_boot.as_ref() == Some(&boot) {
                Err(LATE_RESTORE_REBOOT.into())
            } else {
                Ok(())
            };
        }
        if !root.exists(WAL_NAME)? {
            return Err(NOT_RESTORED.into());
        }
        let wal = Wal::parse(&root.read(WAL_NAME, RECORD_MAX, 0o600)?)?;
        match (wal.state, wal.restoring) {
            (WalState::Applied, false) => {
                let receipt = permit_ready(root)?.ok_or(NOT_RESTORED)?;
                receipt.validate()?;
                let first = require_absent_or_payload(root, ORIGINAL_NAME)?;
                let installed = require_absent_or_payload(root, INSTALLED_NAME)?;
                let live = writer.observe()?;
                if wal.delivery_nonce != receipt.delivery_nonce
                    || wal.first_original.present != first.is_some()
                    || wal.first_original.present == receipt.original_absent
                    || wal.first_original.mode != receipt.original_mode
                    || !wal.after.present
                    || wal.after.mode != receipt.installed_mode
                    || live.presence()? != wal.after
                    || installed.is_none()
                    || require_absent_or_payload(root, AFTER_NAME)? != installed
                    || !matches_candidate(&live, installed.as_deref())
                {
                    return Err(NOT_RESTORED.into());
                }
                writer.verify_readonly(true)?;
            }
            // Only recover a Prepared restore previously admitted under the
            // same uninstall authority. An unrelated WAL is not repair proof.
            (WalState::Prepared, true)
                if fenced_boot.is_some() && wal.transaction_id == transaction_id => {}
            _ => return Err(NOT_RESTORED.into()),
        }
        let fence = voboost_contract_core::ascii_json(&(transaction_id, boot))?;
        root.write(LATE_RESTORE_FENCE, &fence, 0o600)?;
        if root.read(LATE_RESTORE_FENCE, 256, 0o600)? != fence {
            return Err("native uninstall supervisor restoration fence readback differs".into());
        }
        restore_locked(root, writer, transaction_id)?;
        if !restored_without_receipt(root, writer)? {
            return Err(NOT_RESTORED.into());
        }
        Err(LATE_RESTORE_REBOOT.into())
    }

    /// The standard restore orchestration, shared verbatim by the QNX
    /// restore_config command and the host failure matrix: operation lock,
    /// bounded recovery of any pending WAL, then restore(). Ordering matters —
    /// permit_ready is consulted only AFTER recovery so the F5 receipt-less
    /// crash window (WAL already Applied by a rolled-back install tail) reaches
    /// the waived-termination branch instead of the old pre-lock refusal. The
    /// delivery identity comes only from a retained receipt. Completed
    /// restore/rollback needs no delivery identity; every other receipt-less state
    /// keeps the hard refusal inside restore().
    pub(crate) fn restore_standard(
        root: &Dir,
        writer: &mut impl Writer,
        transaction_id: &str,
    ) -> Result<()> {
        let _lock = OperationLock::acquire(root)?;
        restore_locked(root, writer, transaction_id)
    }

    fn restore_locked(root: &Dir, writer: &mut impl Writer, transaction_id: &str) -> Result<()> {
        recover_existing(root, writer).and_then(|()| {
            let nonce = permit_ready(root)?
                .map(|receipt| receipt.delivery_nonce)
                .unwrap_or_default();
            let operation = Operation {
                transaction_id: transaction_id.into(),
                implant: String::new(),
                bootfile: String::new(),
                nonce,
                default_candidate: None,
                failpoints: alloc::collections::BTreeSet::new(),
                restore: true,
            };
            restore(root, writer, &operation)
        })
    }

    /// Restore accepted only from an exact retained installed state or the exact
    /// FIRST original/absence. A failed restoration removes nothing: payload,
    /// authority, sidecars and WAL all stay intact for a later bounded recovery.
    pub(crate) fn restore(
        root: &Dir,
        writer: &mut impl Writer,
        operation: &Operation,
    ) -> Result<()> {
        let receipt = match permit_ready(root)? {
            Some(receipt) => {
                if !valid_nonce(&operation.nonce) {
                    return Err("SetupRequired: supervisor delivery nonce invalid".into());
                }
                receipt
            }
            // F5 crash window: the install tail failed before the receipt was
            // durable and the completed recovery restored the FIRST original
            // live. The standard restore target is already in place, so the
            // command terminates successfully; every other receipt-less state
            // keeps the fail-closed refusal below. The waived branch never
            // reaches the nonce comparison: there is no delivery identity to
            // echo and none is required for an already-completed rollback.
            None if restored_without_receipt(root, writer)? => return Ok(()),
            None => return Err("SetupRequired: no validated supervisor config receipt".into()),
        };
        if receipt.delivery_nonce != operation.nonce {
            return Err("SetupRequired: restore nonce differs from receipt".into());
        }
        let live = writer.observe()?;
        let installed = require_absent_or_payload(root, INSTALLED_NAME)?;
        if !matches_candidate(&live, installed.as_deref()) {
            return Err(
                "SetupRequired: live config differs from retained installed candidate".into(),
            );
        }
        // Foreign mode or presence refuses restore exactly like foreign bytes.
        if live.mode != receipt.installed_mode {
            return Err("SetupRequired: live config mode differs from receipt".into());
        }
        // Conditional restore: accept only the exact retained installed state;
        // the exact FIRST original/absent is the target, never overwrite-unknown.
        let bounded = Operation {
            transaction_id: operation.transaction_id.clone(),
            implant: operation.implant.clone(),
            bootfile: operation.bootfile.clone(),
            nonce: operation.nonce.clone(),
            default_candidate: operation.default_candidate.clone(),
            failpoints: operation.failpoints.clone(),
            restore: true,
        };
        // Preserve the exact before-state through the second observation.
        execute(root, writer, &bounded, &[], Some(&live), 0o600, false)
    }
}

#[cfg(any(target_os = "nto", test))]
pub(crate) use machinery::*;

#[cfg(test)]
#[path = "../../tests/supervisor_config_transaction.rs"]
mod tests;

#[cfg(any(target_os = "nto", test))]
const CONFIG_NAME: &str = "boot_cfg.xml";

#[cfg(any(target_os = "nto", test))]
fn identity(a: &libc::stat, b: &libc::stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_mode == b.st_mode
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
}

#[cfg(any(target_os = "nto", test))]
fn parent_identity(parent: &Dir, expected: &libc::stat) -> Result<()> {
    let name =
        alloc::ffi::CString::new(parent.path.as_str()).map_err(|_| "supervisor parent path NUL")?;
    let mut observed = unsafe { core::mem::zeroed::<libc::stat>() };
    if unsafe { libc::lstat(name.as_ptr(), &mut observed) } != 0
        || !identity(expected, &observed)
        || !identity(expected, &crate::fs::stat(parent.fd.0)?)
    {
        return Err("SetupRequired: supervisor parent identity changed".into());
    }
    Ok(())
}

#[cfg(any(target_os = "nto", test))]
fn read_config(parent: &Dir, parent_stat: &libc::stat) -> Result<Option<(Vec<u8>, u32)>> {
    parent_identity(parent, parent_stat)?;
    let member = alloc::format!("{}/{}", parent.path, CONFIG_NAME);
    let name = alloc::ffi::CString::new(member).map_err(|_| "supervisor config path NUL")?;
    let mut s = unsafe { core::mem::zeroed::<libc::stat>() };
    if unsafe { libc::lstat(name.as_ptr(), &mut s) } != 0 {
        return if crate::fs::errno() == libc::ENOENT {
            Ok(None)
        } else {
            Err("SetupRequired: supervisor config metadata unavailable".into())
        };
    }
    if s.st_mode & libc::S_IFMT != libc::S_IFREG
        || s.st_nlink != 1
        || s.st_uid != 0
        || s.st_size < 0
        || s.st_size as u64 > MAX_CONFIG as u64
    {
        return Err("SetupRequired: supervisor config identity rejected".into());
    }
    let fd = crate::fs::Fd(unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    });
    if fd.0 < 0 {
        return Err("SetupRequired: supervisor config descriptor unavailable".into());
    }
    let before = crate::fs::stat(fd.0)?;
    if !identity(&before, &s) {
        return Err("SetupRequired: supervisor config changed during open".into());
    }
    let mut bytes = alloc::vec![0; before.st_size as usize];
    crate::fs::read_exact(fd.0, &mut bytes)?;
    if !crate::fs::unchanged(&before, &crate::fs::stat(fd.0)?) {
        return Err("SetupRequired: supervisor config changed during read".into());
    }
    Ok(Some((bytes, before.st_mode as u32 & 0o777)))
}

/// QNX backend for the fixed config path. This mirrors the reviewed
/// oem_startup invariants for mount authority: pin root and /etc/clsboot
/// directory identities, same qnx6 filesystem, original readonly required,
/// remount removes ONLY the readonly flag and verifies every retained flag,
/// atomic publish plus file/parent fsync plus exact readback, then exact
/// original readonly flag restoration. It does not widen startup authority to
/// any other path. The repeated lock/mount runtime probes are the acceptance
/// of the QNX ABI; host tests never executed this backend.
#[cfg(target_os = "nto")]
pub(crate) mod qnx {
    use super::*;
    use crate::fs::{stat, Fd};
    use alloc::format;

    extern "C" {
        fn mount_parse_generic_args(
            options: *mut libc::c_char,
            flags: *mut libc::c_int,
        ) -> *mut libc::c_char;
    }
    fn filesystem(fd: i32) -> Result<libc::statvfs> {
        let mut value = unsafe { core::mem::zeroed::<libc::statvfs>() };
        if unsafe { libc::fstatvfs(fd, &mut value) } != 0 {
            return Err("SetupRequired: OEM filesystem flags unavailable".into());
        }
        let end = value
            .f_basetype
            .iter()
            .position(|v| *v == 0)
            .ok_or("OEM filesystem type is unterminated")?;
        let name: Vec<u8> = value.f_basetype[..end].iter().map(|v| *v as u8).collect();
        if name != b"qnx6" {
            return Err("SetupRequired: OEM filesystem is not qnx6".into());
        }
        Ok(value)
    }

    pub(crate) struct ConfigFile<'a> {
        root_fd: Fd,
        root_stat: libc::stat,
        parent: &'a Dir,
        parent_stat: libc::stat,
        filesystem_id: u64,
        flags: u64,
    }
    impl<'a> ConfigFile<'a> {
        pub(crate) fn open(parent: &'a Dir) -> Result<Self> {
            if crate::fs::uid()? != 0 || parent.path != "/etc/clsboot" {
                return Err("SetupRequired: supervisor config path authority rejected".into());
            }
            let root_fd = Fd(unsafe {
                libc::open(
                    b"/\0".as_ptr().cast(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            });
            if root_fd.0 < 0 {
                return Err("OEM root descriptor unavailable".into());
            }
            let root_stat = stat(root_fd.0)?;
            let parent_stat = stat(parent.fd.0)?;
            let fs = filesystem(root_fd.0)?;
            if root_stat.st_uid != 0
                || parent_stat.st_uid != 0
                || root_stat.st_dev != parent_stat.st_dev
                || root_stat.st_gid != 0
                || parent_stat.st_gid != 0
                || root_stat.st_mode & 0o002 != 0
                || parent_stat.st_mode & 0o002 != 0
            {
                return Err("SetupRequired: OEM root or parent authority differs".into());
            }
            Ok(Self {
                root_fd,
                root_stat,
                parent,
                parent_stat,
                filesystem_id: fs.f_fsid as u64,
                flags: fs.f_flag as u64,
            })
        }
        fn identities(&self) -> Result<()> {
            let mut path = unsafe { core::mem::zeroed::<libc::stat>() };
            if unsafe { libc::lstat(b"/\0".as_ptr().cast(), &mut path) } != 0
                || !identity(&self.root_stat, &path)
                || !identity(&self.root_stat, &stat(self.root_fd.0)?)
            {
                return Err("SetupRequired: OEM root identity changed".into());
            }
            parent_identity(self.parent, &self.parent_stat)?;
            for fd in [self.root_fd.0, self.parent.fd.0] {
                if filesystem(fd)?.f_fsid as u64 != self.filesystem_id {
                    return Err("SetupRequired: OEM filesystem identity changed".into());
                }
            }
            Ok(())
        }
        fn flags(&self, readonly: bool) -> u64 {
            if readonly {
                self.flags
            } else {
                self.flags & !(libc::ST_RDONLY as u64)
            }
        }
        fn verify(&self, readonly: bool) -> Result<()> {
            self.identities()?;
            for fd in [self.root_fd.0, self.parent.fd.0] {
                if filesystem(fd)?.f_flag as u64 != self.flags(readonly) {
                    return Err("SetupRequired: OEM mount flags differ".into());
                }
            }
            Ok(())
        }
        fn remount(&self, readonly: bool) -> Result<()> {
            if self.flags & libc::ST_RDONLY as u64 == 0 {
                return self.verify(readonly);
            }
            self.identities()?;
            let requested = self.flags(readonly);
            let mut flags = i32::try_from(requested).map_err(|_| "OEM mount flags exceed ABI")?;
            let mut option = *b"remount\0";
            if !unsafe { mount_parse_generic_args(option.as_mut_ptr().cast(), &mut flags) }
                .is_null()
                || flags < 0
                || (flags as u64 & requested) != requested
                || ((flags as u64) & !requested).count_ones() != 1
            {
                return Err("SetupRequired: OEM libc remount option unavailable".into());
            }
            // Same update-the-existing-mount protocol as oem_startup, via the
            // QNX-authored mount -u string-options form.
            if unsafe {
                libc::mount(
                    core::ptr::null(),
                    b"/\0".as_ptr().cast(),
                    flags,
                    b"qnx6\0".as_ptr().cast(),
                    core::ptr::null(),
                    -1,
                )
            } != 0
            {
                return Err("SetupRequired: OEM filesystem remount failed".into());
            }
            Ok(())
        }
        fn read(&self) -> Result<Option<(Vec<u8>, u32)>> {
            self.identities()?;
            read_config(self.parent, &self.parent_stat)
        }
        fn write(&self, bytes: &[u8], mode: u32) -> Result<()> {
            self.identities()?;
            // Absolute temp inside the pinned parent: same filesystem as the
            // target, never CWD-dependent, never a stray in a foreign directory.
            let full = format!("{}/.{}", self.parent.path, crate::nonce()?);
            let temp =
                alloc::ffi::CString::new(full).map_err(|_| "supervisor temporary member NUL")?;
            let fd = Fd(unsafe {
                libc::open(
                    temp.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    mode,
                )
            });
            if fd.0 < 0 {
                return Err("SetupRequired: supervisor temp member unavailable".into());
            }
            let result = (|| {
                crate::fs::write_all(fd.0, bytes)?;
                if unsafe { libc::fchmod(fd.0, mode as libc::mode_t) } != 0 {
                    return Err("SetupRequired: supervisor temp chmod failed".into());
                }
                if unsafe { libc::fsync(fd.0) } != 0 {
                    return Err("SetupRequired: supervisor temp sync failed".into());
                }
                Ok(())
            })();
            if result.is_err() {
                unsafe {
                    libc::unlink(temp.as_ptr());
                }
                return result;
            }
            drop(fd);
            let target = {
                let full = format!("{}/{}", self.parent.path, CONFIG_NAME);
                alloc::ffi::CString::new(full).map_err(|_| "target NUL")?
            };
            if unsafe { libc::rename(temp.as_ptr(), target.as_ptr()) } != 0 {
                unsafe {
                    libc::unlink(temp.as_ptr());
                }
                return Err("SetupRequired: supervisor atomic publish failed".into());
            }
            if unsafe { libc::fsync(self.parent.fd.0) } != 0 {
                return Err("SetupRequired: supervisor parent sync failed".into());
            }
            Ok(())
        }
        fn remove(&self) -> Result<()> {
            self.identities()?;
            let full = format!("{}/{}", self.parent.path, CONFIG_NAME);
            let name = alloc::ffi::CString::new(full).map_err(|_| "removal NUL")?;
            if unsafe { libc::unlink(name.as_ptr()) } != 0 {
                return Err("SetupRequired: supervisor config unlink failed".into());
            }
            if unsafe { libc::fsync(self.parent.fd.0) } != 0 {
                return Err("SetupRequired: supervisor parent sync failed".into());
            }
            Ok(())
        }
    }
    impl Writer for ConfigFile<'_> {
        fn observe(&mut self) -> Result<LiveConfig> {
            match self.read()? {
                Some((bytes, mode)) => Ok(LiveConfig {
                    present: true,
                    bytes,
                    mode,
                }),
                None => Ok(LiveConfig {
                    present: false,
                    bytes: Vec::new(),
                    mode: 0,
                }),
            }
        }
        fn writable(&mut self) -> Result<()> {
            self.remount(false)
        }
        fn verify_writable(&mut self) -> Result<()> {
            self.verify(false)
        }
        fn publish(&mut self, bytes: &[u8], mode: u32) -> Result<()> {
            self.verify(false)?;
            self.write(bytes, mode)?;
            let (back, got) = self
                .read()?
                .ok_or("SetupRequired: supervisor publish readback absent")?;
            if back != bytes || got != mode {
                return Err("SetupRequired: supervisor publish readback differs".into());
            }
            Ok(())
        }
        fn publish_absence(&mut self) -> Result<()> {
            self.verify(false)?;
            match self.read()? {
                None => Ok(()),
                Some(_) => self.remove(),
            }
        }
        fn readonly(&mut self) -> Result<()> {
            self.remount(true)
        }
        fn verify_readonly(&mut self, _expect_installed: bool) -> Result<()> {
            self.verify(true)
        }
    }
    /// One full QNX config transaction: lock, recover, persist, publish.
    /// `candidate` bytes arrive from the proved emitter path byte-for-byte;
    /// `composed_from` is the exact presence/mode/bytes the candidate was composed from
    /// outside the lock — execute reobserves and must see the same state,
    /// so a concurrent foreign change can never be silently clobbered.
    pub(crate) fn run(
        root: &Dir,
        parent: &Dir,
        operation: &Operation,
        candidate: &[u8],
        composed_from: Option<&LiveConfig>,
        installed_mode: u32,
        saving: bool,
    ) -> Result<()> {
        let mut writer = ConfigFile::open(parent)?;
        run_standard(
            root,
            &mut writer,
            operation,
            candidate,
            composed_from,
            installed_mode,
            saving,
        )
    }
}

/// Fixed candidate composition on QNX. The proved emitter and splice build
/// the candidate offline, byte-for-byte from the actual retained OEM tables
/// of /usr/bin/clusterboot; no OEM generator command is ever executed.
#[cfg(target_os = "nto")]
#[path = "supervisor_emit.rs"]
pub(crate) mod emit;

#[cfg(any(target_os = "nto", test))]
#[path = "supervisor_xml.rs"]
pub(crate) mod xml;
