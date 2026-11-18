//! Authenticated device IO for the two-boot resource-only None lifecycle.
use sha2::{Digest, Sha256};
use std::io;
use std::path::Path;
use std::time::Duration;
use voboost_contract::operation::{current_boot_id, GenerationGuard};
use voboost_contract::resource::OwnedResourceArtifact;
use voboost_shared::early_none_gate::{self, Decision};
use voboost_shared::fixed_process;
use voboost_shared::observed_locale;
use voboost_shared::owned_overlay::{self, OverlayState, Variant};
use voboost_shared::secure_fs::Directory;

use super::none_finalizer::{helper_identity, NONE_HELPER_NAME};
use super::none_observation::parse_process;
use super::{publish, Receipt, JOURNAL, MAX_APK};

const ROOT: &str = "/data/voboost";
const PLAN: &str = "agents.json";
const SESSION: &str = "startup-session.json";
const TRANSACTION: &str = "i18n-resource-transaction";
const MAX_HELPER: usize = 64 * 1024 * 1024;
const HELPER_TIMEOUT: Duration = Duration::from_secs(20);
const HELPER_OUTPUT_MAX: usize = 8 * 1024;
const PM_TIMEOUT: Duration = Duration::from_secs(5);
const PM_OUTPUT_MAX: usize = 64 * 1024;

fn fail(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

struct DeviceIo<'a> {
    root: &'a Directory,
    journal: &'a Directory,
    overlays: &'a Directory,
    guard: &'a GenerationGuard,
    boot: &'a str,
    resource: &'a OwnedResourceArtifact,
    /// The last journal state this adapter published; persist is the only writer.
    committed: Receipt,
    product_key: &'a [u8; 32],
    variant: Variant,
}

impl DeviceIo<'_> {
    /// Io fence: actual kernel boot unchanged, GenerationGuard still ours,
    /// and the effective late session still decides None cleanup.
    fn fence_checks(&self) -> io::Result<()> {
        self.guard.verify_owner().map_err(io::Error::other)?;
        if current_boot_id().map_err(io::Error::other)? != self.boot {
            return Err(fail("boot changed during None drive"));
        }
        let plan = self.root.read_trusted(PLAN, 1024 * 1024, 0o600)?;
        let session = match self.root.open_child("run") {
            Ok(run) => {
                run.validate_owner_mode(0, 0, 0o755)?;
                match run.read_trusted(SESSION, 512, 0o600) {
                    Ok(bytes) => Some(bytes),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                    Err(error) => return Err(error),
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        match early_none_gate::decide_late(&plan, session.as_deref(), self.boot)
            .map_err(io::Error::other)?
        {
            Decision::Cleanup => Ok(()),
            _ => Err(fail("effective session no longer admits None cleanup")),
        }
    }

    /// The retained signed authority must still match the receipt exactly.
    fn authority_matches(&self, receipt: &Receipt) -> io::Result<()> {
        if receipt.generation != self.resource.manifest_sha256()
            || receipt.overlay_sha256 != self.resource.artifact().sha256
        {
            return Err(fail("late None authority differs"));
        }
        Ok(())
    }
}

impl none_state::Io for DeviceIo<'_> {
    fn fence(&mut self) -> io::Result<()> {
        self.fence_checks()
    }
    fn verify_authority(&mut self) -> io::Result<()> {
        let actual = super::read_owned_authority_for(
            self.journal,
            &self.committed.generation,
            self.product_key,
            self.variant,
        )?;
        if actual.manifest_sha256() != self.resource.manifest_sha256()
            || actual.artifact() != self.resource.artifact()
        {
            return Err(fail("retained signed authority changed"));
        }
        self.authority_matches(&self.committed)
    }
    fn native_consistency(&mut self) -> io::Result<()> {
        restore_native(self.journal, self.resource)
    }
    /// Removal-only not-enabled fence, after signed ownership and global native EN.
    /// An unclassified inert state is never reported as Disabled or Ready.
    fn disable_overlay(&mut self) -> io::Result<()> {
        match owned_overlay::observe_for(self.variant).map_err(io::Error::other)? {
            OverlayState::Disabled => Ok(()),
            OverlayState::Enabled => {
                let output = fixed_process::output(
                    "/system/bin/cmd",
                    &["overlay", "disable", "--user", "0", self.variant.package()],
                    PM_TIMEOUT,
                    PM_OUTPUT_MAX,
                )
                .map_err(io::Error::other)?;
                if !output.status.success() {
                    return Err(fail("OMS disable command failed"));
                }
                match owned_overlay::observe_for(self.variant).map_err(io::Error::other)? {
                    OverlayState::Disabled => Ok(()),
                    OverlayState::Enabled => Err(fail("OMS disable not observed")),
                    OverlayState::NotEnabledUnclassified => Ok(()),
                }
            }
            OverlayState::NotEnabledUnclassified => Ok(()),
        }
    }
    /// WAL recovery precedes any presence observation.
    fn recover_wal(&mut self) -> io::Result<()> {
        voboost_shared::protected_system_transaction::recover_owned_resource_write(
            self.resource.manifest_sha256(),
        )
        .map_err(io::Error::other)
    }
    /// Only the exact delivered APK digest counts as present; a foreign file fails.
    fn present_matching(&mut self) -> io::Result<bool> {
        match self
            .overlays
            .read_trusted(self.variant.file(), MAX_APK, 0o644)
        {
            Ok(bytes) => {
                if digest(&bytes) != self.committed.overlay_sha256 {
                    return Err(fail("owned overlay APK was replaced"));
                }
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }
    /// Scoped remount unlink plus directory sync for our single owned file.
    fn unlink_owned(&mut self) -> io::Result<()> {
        voboost_shared::protected_system_transaction::with_owned_resource_write(
            self.resource.manifest_sha256(),
            || {
                self.overlays
                    .unlink(self.variant.file())
                    .map_err(|error| error.to_string())?;
                self.overlays.sync_all().map_err(|error| error.to_string())
            },
        )
        .map_err(io::Error::other)?;
        self.overlays.sync_all()?;
        Ok(())
    }
    fn packages_absent(&mut self) -> io::Result<bool> {
        let output = fixed_process::output(
            "/system/bin/cmd",
            &["package", "list", "packages", "-u", self.variant.package()],
            PM_TIMEOUT,
            PM_OUTPUT_MAX,
        )
        .map_err(io::Error::other)?;
        // A registered owned package is a hard failed proof, not readiness.
        // A later bounded service invocation may retry; no final receipt is written.
        super::validate_package_absence(output.status.success(), &output.stdout, &output.stderr)?;
        Ok(true)
    }
    /// Publish only after the journal still equals what this adapter committed.
    fn persist(&mut self, receipt: &Receipt) -> io::Result<()> {
        let bytes = self.journal.read_trusted(JOURNAL, 4096, 0o600)?;
        let current: Receipt = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        if current != self.committed {
            return Err(fail("None journal changed underneath the drive"));
        }
        publish(self.journal, receipt)?;
        self.committed = receipt.clone();
        Ok(())
    }
    /// Existing init property handshake only; no new capabilities.
    fn request_reboot(&mut self) -> io::Result<()> {
        fixed_process::request_reboot().map_err(io::Error::other)
    }
}

use super::none_state;

/// Late two-boot None finalizer driving the pure state engine with real IO.
/// Holds the GenerationGuard and the journal transaction lock for the entire
/// drive; journal phases terminate in `late-none-final`. `None` means no
/// armed resource, ordinary boot, or a still-pending (reboot) drive.
pub(super) fn late_none_verified(product_key: &[u8; 32]) -> io::Result<Option<Receipt>> {
    let root = Directory::open(Path::new(ROOT))?;
    root.validate_owner_not_writable(0, 0)?;
    let boot = current_boot_id().map_err(io::Error::other)?;
    let plan = match root.read_trusted(PLAN, 1024 * 1024, 0o600) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let session = match root.open_child("run") {
        Ok(run) => {
            run.validate_owner_mode(0, 0, 0o755)?;
            match run.read_trusted(SESSION, 512, 0o600) {
                Ok(bytes) => Some(bytes),
                Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                Err(error) => return Err(error),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    if early_none_gate::decide_late(&plan, session.as_deref(), &boot).map_err(io::Error::other)?
        != Decision::Cleanup
    {
        return Ok(None);
    }
    let profiles = super::open_existing_variants()?;
    if profiles.is_empty() {
        return Ok(None);
    }
    let guard = GenerationGuard::acquire_in(Path::new(ROOT)).map_err(io::Error::other)?;
    let batch = super::none_batch::Lease::open()?; // outer lock before profile locks
    let mut admitted = Vec::new();
    for (variant, overlays, journal) in &profiles {
        let receipt: Receipt = serde_json::from_slice(&journal.read_trusted(JOURNAL, 4096, 0o600)?)
            .map_err(io::Error::other)?;
        let resource =
            super::read_owned_authority_for(journal, &receipt.generation, product_key, *variant)?;
        if receipt.schema != 1
            || receipt.generation != resource.manifest_sha256()
            || receipt.overlay_sha256 != resource.artifact().sha256
        {
            return Err(fail("plural None authority differs"));
        }
        super::none_finalizer::retained_helper(journal, &resource)?;
        admitted.push((*variant, overlays, journal, receipt, resource));
    }
    let mut locks = Vec::new();
    for (_, _, journal, _, _) in &admitted {
        locks.push(journal.lock_transaction(Duration::from_secs(5))?);
    }
    let mut receipts: Vec<Receipt> = admitted.iter().map(|(_, _, _, r, _)| r.clone()).collect();
    let mut adapters: Vec<DeviceIo<'_>> = admitted
        .iter()
        .map(|(variant, overlays, journal, receipt, resource)| DeviceIo {
            root: &root,
            journal,
            overlays,
            guard: &guard,
            boot: &boot,
            resource,
            committed: receipt.clone(),
            product_key,
            variant: *variant,
        })
        .collect();
    for adapter in &adapters {
        let actual: Receipt =
            serde_json::from_slice(&adapter.journal.read_trusted(JOURNAL, 4096, 0o600)?)
                .map_err(io::Error::other)?;
        if actual != adapter.committed {
            return Err(fail("plural None receipt changed before lock"));
        }
    }
    let variants: Vec<Variant> = admitted.iter().map(|v| v.0).collect();
    let mut ios: Vec<&mut dyn none_state::Io> = adapters
        .iter_mut()
        .map(|v| v as &mut dyn none_state::Io)
        .collect();
    let native_journal = admitted[0].2;
    let native_resource = &admitted[0].4;
    let outcome = none_state::drive_batch(
        &mut ios,
        &mut receipts,
        &boot,
        &mut || restore_native(native_journal, native_resource),
        &mut |receipts, boot| {
            let members: Vec<_> = variants
                .iter()
                .copied()
                .zip(receipts.iter().cloned())
                .collect();
            if batch.claim(&members, boot)? {
                fixed_process::request_reboot().map_err(io::Error::other)?;
            }
            Ok(())
        },
    )?;
    match outcome {
        none_state::Outcome::Final => {
            let members: Vec<_> = variants
                .iter()
                .copied()
                .zip(receipts.iter().cloned())
                .collect();
            batch.finish(&members, &boot)?;
            Ok(receipts.into_iter().next())
        }
        none_state::Outcome::Pending => Ok(None),
        none_state::Outcome::NoResource => Err(fail("nonempty batch reported no resource")),
    }
}

/// Native reuse: pinned retained helper FD/bytes/inode across the restricted
/// app_process launch, cross-checked against framework locale observation.
/// The signed root-owned 0700 authority slot and held lifecycle guard are
/// the execution trust boundary: this is not FD-based execution and does
/// not protect against an independent malicious root replacing the path.
pub(super) fn restore_native(
    journal: &Directory,
    resource: &OwnedResourceArtifact,
) -> io::Result<()> {
    let slot = super::authority_slot(journal, resource.manifest_sha256())?;
    let (retained, code_fd) = slot.read_trusted_retained(NONE_HELPER_NAME, MAX_HELPER, 0o600)?;
    if super::none_finalizer::retained_helper(journal, resource)? != retained {
        return Err(fail("retained helper bytes differ on reopen"));
    }
    let identity = helper_identity(&code_fd)?;
    let classpath = super::none_finalizer::assemble_classpath_for(
        super::variant_for(resource)?,
        resource.manifest_sha256(),
    )?;
    let result = fixed_process::output_private_java_for_owner_without_capabilities(
        &classpath,
        &resource.descriptor().owner,
        HELPER_TIMEOUT,
        HELPER_OUTPUT_MAX,
    )
    .map_err(io::Error::other)?;
    let english = resource.descriptor().owner == "i18n-en";
    let observation = if english {
        super::none_observation::parse_english_process(result.status.success(), &result.stdout)
    } else {
        parse_process(result.status.success(), &result.stdout)
    }
    .map_err(|error| io::Error::other(format!("{error} ({})", result.status)))?;
    let framework = observed_locale::observe().map_err(io::Error::other)?;
    super::none_finalizer::cross_language_for_owner(
        &resource.descriptor().owner,
        observation.primary_language(),
        framework,
    )?;
    let (after, after_fd) = slot.read_trusted_retained(NONE_HELPER_NAME, MAX_HELPER, 0o600)?;
    if helper_identity(&after_fd)? != identity || after != retained {
        return Err(fail("retained none helper changed during launch"));
    }
    Ok(())
}
