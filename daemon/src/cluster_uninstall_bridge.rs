//! Root-only bridge for the retained, signed native uninstall transaction.
use super::*;
use std::io::Read;

const FINAL_REPORT: &str = "uninstall-final-report.vbc";
const PROVISIONAL_REPORT: &str = "uninstall-provisional-report.vbc";
const RECOVERY_AUTHORITY: &str = "uninstall-authority.json";
const DELIVERY_OWNER: &str = "uninstall-delivery-owner.json";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Actor {
    Settings,
    Desktop,
    Device,
    Observer,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeliveryOwner {
    schema_version: u32,
    actor: Actor,
    transaction_id: String,
    challenge: String,
    product: String,
}

impl DeliveryOwner {
    fn for_request(actor: Actor, request: &Request) -> Result<Self> {
        if request.kind != RequestKind::Uninstall {
            return Err("delivery owner lacks uninstall request".into());
        }
        Ok(Self {
            schema_version: 1,
            actor,
            transaction_id: request.transaction_id.clone(),
            challenge: request.challenge.clone(),
            product: request
                .release_manifest_sha256
                .clone()
                .ok_or("delivery owner lacks product")?,
        })
    }
}

fn bind_actor(dir: &Directory, actor: Actor, request: &Request) -> Result<()> {
    let expected = DeliveryOwner::for_request(actor, request)?;
    if dir
        .entry_exists(DELIVERY_OWNER)
        .map_err(|e| e.to_string())?
    {
        let bytes = dir
            .read_trusted(DELIVERY_OWNER, 2048, 0o600)
            .map_err(|e| e.to_string())?;
        let retained: DeliveryOwner = parse(&bytes, 2048)?;
        if retained != expected {
            return Err("Cluster uninstall delivery owned by another actor or transaction".into());
        }
    } else {
        dir.write_atomic(DELIVERY_OWNER, &encode(&expected)?, 0o600)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Export<'a> {
    schema_version: u32,
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    request: Option<&'a Request>,
    #[serde(skip_serializing_if = "Option::is_none")]
    qnx_public_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pair_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authority_epoch: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    release_manifest_sha256: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    catalog_sha256: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    android_public_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signed_request_hex: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NotRequested<'a> {
    schema_version: u32,
    state: &'static str,
    qnx_public_key: &'a str,
    pair_id: &'a str,
    authority_epoch: &'a str,
}

fn export_not_requested(dir: &Directory, provision: &Provision, state: &State) -> Result<Vec<u8>> {
    if let Some(pending) = &state.pending {
        if !matches!(
            pending.request.kind,
            RequestKind::Generation | RequestKind::Desired | RequestKind::Observe
        ) || pending.request.pair_id != provision.pair_id
            || pending.request.authority_epoch != provision.authority_epoch
        {
            return Err("native pending request differs from active pairing".into());
        }
    }
    for name in [
        UNINSTALL_REPORT,
        FINAL_REPORT,
        PROVISIONAL_REPORT,
        DELIVERY_OWNER,
        RECOVERY_AUTHORITY,
    ] {
        if dir.entry_exists(name).map_err(|e| e.to_string())? {
            return Err("native uninstall artifacts retained without uninstall request".into());
        }
    }
    let credentials = dir
        .read_trusted(CREDENTIAL_FILE, 65536, 0o600)
        .map_err(|e| e.to_string())?;
    if credentials.len() as u64 != provision.transport.credentials.size {
        return Err("paired transport credentials size differs".into());
    }
    encode(&NotRequested {
        schema_version: 1,
        state: "not-requested",
        qnx_public_key: &provision.qnx_public_key,
        pair_id: &provision.pair_id,
        authority_epoch: &provision.authority_epoch,
    })
}

fn verify_final(bytes: &[u8], provision: &Provision, request: &Request) -> Result<()> {
    use voboost_contract::domain_core::domain_operation::{
        AuthenticatedReport, InstalledEvidence, Operation, Outcome, Phase,
    };
    if request.kind != RequestKind::Uninstall {
        return Err("native absence has no retained uninstall request".into());
    }
    let report = AuthenticatedReport::verify(
        bytes,
        &VerifyingKey::from_bytes(&raw32(&provision.qnx_public_key)?)
            .map_err(|_| "invalid native absence authority")?,
        &provision.pair_id,
        &provision.authority_epoch,
        &request.challenge,
        &request.transaction_id,
        request
            .release_manifest_sha256
            .as_deref()
            .ok_or("uninstall product absent")?,
    )?;
    if report.report.domain != Domain::Cluster
        || report.report.operation != Operation::Uninstall
        || report.report.phase != Phase::Complete
        || report.report.outcome != Outcome::Completed
        || report.report.catalog_sha256 != request.catalog_sha256
    {
        return Err("native absence report is unrelated".into());
    }
    let Some(InstalledEvidence::QnxAbsence { startup, .. }) = report.report.installed_evidence
    else {
        return Err("signed native absence evidence missing".into());
    };
    if startup.path != "/scripts/startup_cluster.sh"
        || startup.original_sha256
            != "c26b4913707a1e96933f48a07d6957857cc52853a7e405eb29b2adab9b84f47a"
    {
        return Err("native absence startup differs".into());
    }
    Ok(())
}

pub(super) fn completion_verified(
    dir: &Directory,
    provision: &Provision,
    request: &Request,
) -> Result<bool> {
    if !dir.entry_exists(FINAL_REPORT).map_err(|e| e.to_string())? {
        return Ok(false);
    }
    verify_final(
        &dir.read_trusted(FINAL_REPORT, 65536, 0o600)
            .map_err(|e| e.to_string())?,
        provision,
        request,
    )?;
    Ok(true)
}

#[cfg(test)]
fn export(store: &Store) -> Result<Vec<u8>> {
    export_for_actor(store, None)
}

fn export_for_actor(store: &Store, actor: Option<Actor>) -> Result<Vec<u8>> {
    let dir = store.directory()?;
    let _lock = dir
        .lock_transaction(Duration::from_millis(20))
        .map_err(|e| e.to_string())?;
    let Some((provision, key)) = store.provision(&dir)? else {
        for name in [
            SEED_FILE,
            CREDENTIAL_FILE,
            UNINSTALL_REPORT,
            FINAL_REPORT,
            PROVISIONAL_REPORT,
            DELIVERY_OWNER,
            RECOVERY_AUTHORITY,
        ] {
            if dir.entry_exists(name).map_err(|e| e.to_string())? {
                return Err("partial native authority retained".into());
            }
        }
        return encode(&Export {
            schema_version: 1,
            state: "absent",
            request: None,
            qnx_public_key: None,
            pair_id: None,
            authority_epoch: None,
            release_manifest_sha256: None,
            catalog_sha256: None,
            android_public_key: None,
            signed_request_hex: None,
        });
    };
    if matches!(actor, Some(Actor::Desktop | Actor::Observer)) {
        // Admission observes the retained mailbox before load can migrate epochs
        // or discard a pending locale request. It never claims delivery ownership.
        let state: State = parse(
            &dir.read_trusted(STATE_FILE, MAX_STATE_BYTES, 0o600)
                .map_err(|e| e.to_string())?,
            MAX_STATE_BYTES,
        )?;
        state.validate()?;
        if state.pending.as_ref().map(|p| p.request.kind) != Some(RequestKind::Uninstall) {
            return export_not_requested(&dir, &provision, &state);
        }
        if actor == Some(Actor::Observer) {
            return Err("Cluster removal is owned by the installed device".into());
        }
    }
    // Removal authority survives the Android owner. Read its durable request
    // without owner IPC or epoch normalization; export must not rewrite intent.
    let state: State = parse(
        &dir.read_trusted(STATE_FILE, MAX_STATE_BYTES, 0o600)
            .map_err(|error| error.to_string())?,
        MAX_STATE_BYTES,
    )?;
    state.validate()?;
    let request = &state
        .pending
        .as_ref()
        .ok_or("native uninstall not prepared")?
        .request;
    if request.kind != RequestKind::Uninstall {
        return Err("native uninstall not prepared".into());
    }
    let pending = state
        .pending
        .as_ref()
        .ok_or("native uninstall request missing")?;
    if request.pair_id != provision.pair_id || request.authority_epoch != provision.authority_epoch
    {
        return Err("native uninstall request differs from active pairing".into());
    }
    let descriptor = pending
        .files
        .first()
        .ok_or("native request descriptor missing")?;
    if descriptor.role != WireRole::Request || descriptor.file != REQUEST_FILE {
        return Err("native request descriptor differs".into());
    }
    let signed = dir
        .read_trusted(REQUEST_FILE, 65536, 0o600)
        .map_err(|e| e.to_string())?;
    if signed.len() as u64 != descriptor.size || hash(&signed) != descriptor.sha256 {
        return Err("native signed request differs from descriptor".into());
    }
    let verified = Request::verify(&signed, &key.verifying_key())?;
    if encode(&verified)? != encode(request)? {
        return Err("native signed request differs from pending request".into());
    }
    let signed_hex = hex::encode(&signed);
    if let Some(actor) = actor {
        bind_actor(&dir, actor, request)?;
    }
    let status = if completion_verified(&dir, &provision, request)? {
        "completed"
    } else if dir
        .entry_exists(UNINSTALL_REPORT)
        .map_err(|e| e.to_string())?
    {
        verify_uninstall_report(
            &dir.read_trusted(UNINSTALL_REPORT, 65536, 0o600)
                .map_err(|e| e.to_string())?,
            &provision,
            request,
        )?;
        "restored"
    } else {
        "pending"
    };
    let mut exported = Export {
        schema_version: 1,
        state: status,
        request: Some(request),
        qnx_public_key: Some(&provision.qnx_public_key),
        pair_id: Some(&provision.pair_id),
        authority_epoch: Some(&provision.authority_epoch),
        release_manifest_sha256: request.release_manifest_sha256.as_deref(),
        catalog_sha256: Some(&request.catalog_sha256),
        android_public_key: Some(&provision.android_public_key),
        signed_request_hex: Some(&signed_hex),
    };
    let retained = encode(&exported)?;
    retain_recovery_authority(&dir, &retained)?;
    if actor == Some(Actor::Settings) {
        exported.android_public_key = None;
        exported.signed_request_hex = None;
    }
    encode(&exported)
}

fn retain_recovery_authority(dir: &Directory, bytes: &[u8]) -> Result<()> {
    if dir
        .entry_exists(RECOVERY_AUTHORITY)
        .map_err(|error| error.to_string())?
    {
        let previous = dir
            .read_trusted(RECOVERY_AUTHORITY, 65536, 0o600)
            .map_err(|error| format!("read retained uninstall authority: {error}"))?;
        if previous == bytes {
            return Ok(());
        }
        let without_state = |data: &[u8]| -> Result<serde_json::Value> {
            let mut value: serde_json::Value = serde_json::from_slice(data)
                .map_err(|_| "retained uninstall authority is invalid".to_string())?;
            value
                .as_object_mut()
                .ok_or("retained uninstall authority is not an object")?
                .remove("state");
            Ok(value)
        };
        if without_state(&previous)? != without_state(bytes)? {
            return Err("retained uninstall authority belongs to another request".into());
        }
    }
    dir.write_atomic(RECOVERY_AUTHORITY, bytes, 0o600)
        .map_err(|error| format!("retain uninstall recovery authority: {error}"))
}

pub(crate) fn export_production() -> Result<Vec<u8>> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("native uninstall export requires root".into());
    }
    export_for_actor(&Store::production(), Some(Actor::Observer))
}

pub(crate) fn export_device_production() -> Result<Vec<u8>> {
    export_for_actor(&Store::production(), Some(Actor::Device))
}

pub(crate) fn uninstall_provision() -> Result<Option<Provision>> {
    let store = Store::production();
    let dir = store.directory()?;
    let _lock = dir
        .lock_transaction(Duration::from_millis(20))
        .map_err(|error| error.to_string())?;
    Ok(store.provision(&dir)?.map(|(provision, _)| provision))
}

#[cfg(test)]
fn settings_intent_pending(store: &Store) -> Result<bool> {
    let dir = store.directory()?;
    let _lock = dir
        .lock_transaction(Duration::from_millis(20))
        .map_err(|e| e.to_string())?;
    if !dir
        .entry_exists(DELIVERY_OWNER)
        .map_err(|e| e.to_string())?
    {
        return Ok(false);
    }
    let owner: DeliveryOwner = parse(
        &dir.read_trusted(DELIVERY_OWNER, 2048, 0o600)
            .map_err(|e| e.to_string())?,
        2048,
    )?;
    if owner.actor != Actor::Settings {
        return Ok(false);
    }
    let Some((_, _)) = store.provision(&dir)? else {
        return Err("Settings delivery owner lost pairing".into());
    };
    let state = store
        .load(&dir)?
        .ok_or("Settings delivery owner lost mailbox")?;
    let request = &state
        .pending
        .as_ref()
        .ok_or("Settings delivery owner lost request")?
        .request;
    if owner != DeliveryOwner::for_request(Actor::Settings, request)? {
        return Err("Settings delivery owner differs from pending request".into());
    }
    Ok(true)
}

fn retained_uninstall_state(dir: &Directory) -> Result<State> {
    let state: State = parse(
        &dir.read_trusted(STATE_FILE, MAX_STATE_BYTES, 0o600)
            .map_err(|error| error.to_string())?,
        MAX_STATE_BYTES,
    )?;
    state.validate()?;
    if state.pending.as_ref().map(|pending| pending.request.kind) != Some(RequestKind::Uninstall) {
        return Err("retained mailbox has no uninstall request".into());
    }
    Ok(state)
}

// This journal is evidence to resume transport cleanup, never completion. Only
// FINAL_REPORT is consumed by completion_verified and Android removal gates.
fn provisional(store: &Store, bytes: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
    let dir = store.directory()?;
    let _lock = dir
        .lock_transaction(Duration::from_millis(20))
        .map_err(|e| e.to_string())?;
    let (provision, _) = store
        .provision(&dir)?
        .ok_or("provisional receipt lost pairing")?;
    let state = retained_uninstall_state(&dir)?;
    let request = &state
        .pending
        .as_ref()
        .ok_or("provisional receipt lost request")?
        .request;
    let owner: DeliveryOwner = parse(
        &dir.read_trusted(DELIVERY_OWNER, 2048, 0o600)
            .map_err(|e| e.to_string())?,
        2048,
    )?;
    if owner != DeliveryOwner::for_request(owner.actor, request)? {
        return Err("provisional receipt delivery owner differs".into());
    }
    if let Some(bytes) = bytes {
        if bytes.len() > 65536 {
            return Err("provisional receipt exceeds bound".into());
        }
        verify_final(bytes, &provision, request)?;
        dir.write_atomic(PROVISIONAL_REPORT, bytes, 0o600)
            .map_err(|e| e.to_string())?;
    }
    if !dir
        .entry_exists(PROVISIONAL_REPORT)
        .map_err(|e| e.to_string())?
    {
        return Ok(None);
    }
    let bytes = dir
        .read_trusted(PROVISIONAL_REPORT, 65536, 0o600)
        .map_err(|e| e.to_string())?;
    verify_final(&bytes, &provision, request)?;
    Ok(Some(bytes))
}

pub(crate) fn retain_provisional_production(bytes: &[u8]) -> Result<()> {
    provisional(&Store::production(), Some(bytes)).map(|_| ())
}

pub(crate) fn read_provisional_production() -> Result<Option<Vec<u8>>> {
    provisional(&Store::production(), None)
}

fn import(store: &Store, bytes: &[u8]) -> Result<()> {
    if bytes.len() > 65536 {
        return Err("native absence receipt exceeds bound".into());
    }
    let dir = store.directory()?;
    let _lock = dir
        .lock_transaction(Duration::from_millis(20))
        .map_err(|e| e.to_string())?;
    let (provision, _) = store
        .provision(&dir)?
        .ok_or("native authority unavailable")?;
    let state = retained_uninstall_state(&dir)?;
    let request = &state
        .pending
        .as_ref()
        .ok_or("native uninstall request missing")?
        .request;
    verify_final(bytes, &provision, request)?;
    dir.write_atomic(FINAL_REPORT, bytes, 0o600)
        .map_err(|e| e.to_string())?;
    completion_verified(&dir, &provision, request)?;
    Ok(())
}

pub(crate) fn import_production(source: &Path) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("native absence import requires root".into());
    }
    let guard = crate::operation_contract::GenerationGuard::acquire_in(Path::new(
        crate::config::ROOT_ZONE,
    ))?;
    let mut bytes = Vec::new();
    if source == Path::new("-") {
        std::io::stdin()
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
    } else {
        let parent = source.parent().ok_or("receipt parent absent")?;
        let name = source
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or("receipt name invalid")?;
        let dir = Directory::open(parent).map_err(|e| e.to_string())?;
        bytes = dir
            .read_trusted(name, 65536, 0o600)
            .map_err(|e| e.to_string())?;
    }
    import(&Store::production(), &bytes)?;
    guard.verify_owner()
}

pub(crate) fn import_verified_bytes_production(bytes: &[u8]) -> Result<()> {
    let guard = crate::operation_contract::GenerationGuard::acquire_in(Path::new(
        crate::config::ROOT_ZONE,
    ))?;
    import(&Store::production(), bytes)?;
    guard.verify_owner()
}

#[cfg(test)]
#[path = "cluster_uninstall_export_tests.rs"]
mod export_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use voboost_contract::domain_core::domain_operation::{
        AbsenceChecks, AbsenceStartup, AuthenticatedReport, DomainOperationReport,
        InstalledEvidence, Operation, Outcome, Phase,
    };

    #[test]
    fn retained_authority_refuses_replacement_by_another_request() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let dir = Directory::open(tmp.path()).unwrap();
        let pending = br#"{"state":"pending","request":{"transactionId":"first"}}"#;
        retain_recovery_authority(&dir, pending).unwrap();
        retain_recovery_authority(&dir, pending).unwrap();
        let completed = br#"{"state":"completed","request":{"transactionId":"first"}}"#;
        retain_recovery_authority(&dir, completed).unwrap();
        let foreign = br#"{"state":"pending","request":{"transactionId":"second"}}"#;
        assert!(retain_recovery_authority(&dir, foreign).is_err());
        assert_eq!(
            dir.read_trusted(RECOVERY_AUTHORITY, 65536, 0o600).unwrap(),
            completed
        );
        dir.write_atomic(RECOVERY_AUTHORITY, b"broken", 0o600)
            .unwrap();
        assert!(retain_recovery_authority(&dir, pending).is_err());
        assert_eq!(
            dir.read_trusted(RECOVERY_AUTHORITY, 65536, 0o600).unwrap(),
            b"broken"
        );
    }

    #[test]
    fn delivery_actor_conflict_is_durable_and_same_transaction_resumes_after_restart() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let _provision = super::super::tests::provision_input(&tmp.path().join("input"));
        let root = tmp.path().join("cluster");
        let store = Store::at(&root);
        store.import_provision(&tmp.path().join("input")).unwrap();
        let generation = super::super::tests::generation();
        store
            .project(
                &super::super::tests::core(&generation),
                &generation.catalog_sha256,
                vec![],
            )
            .unwrap();
        assert!(!store.prepare_uninstall(&"a".repeat(64)).unwrap());
        export_for_actor(&store, Some(Actor::Settings)).unwrap();
        assert!(export_for_actor(&store, Some(Actor::Desktop)).is_err());
        let reopened = Store::at(&root);
        assert!(settings_intent_pending(&reopened).unwrap());
        export_for_actor(&reopened, Some(Actor::Settings)).unwrap();
        let dir = reopened.directory().unwrap();
        let mut owner: DeliveryOwner = parse(
            &dir.read_trusted(DELIVERY_OWNER, 2048, 0o600).unwrap(),
            2048,
        )
        .unwrap();
        owner.challenge = "9".repeat(64);
        dir.write_atomic(DELIVERY_OWNER, &encode(&owner).unwrap(), 0o600)
            .unwrap();
        assert!(settings_intent_pending(&reopened).is_err());
        assert!(export_for_actor(&reopened, Some(Actor::Settings)).is_err());
    }

    #[test]
    fn desktop_binding_does_not_admit_settings_worker() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let _provision = super::super::tests::provision_input(&tmp.path().join("input"));
        let store = Store::at(&tmp.path().join("cluster"));
        store.import_provision(&tmp.path().join("input")).unwrap();
        let generation = super::super::tests::generation();
        store
            .project(
                &super::super::tests::core(&generation),
                &generation.catalog_sha256,
                vec![],
            )
            .unwrap();
        assert!(!store.prepare_uninstall(&"a".repeat(64)).unwrap());
        export_for_actor(&store, Some(Actor::Desktop)).unwrap();
        assert!(!settings_intent_pending(&store).unwrap());
        assert!(export_for_actor(&store, Some(Actor::Settings)).is_err());
        export_for_actor(&store, Some(Actor::Desktop)).unwrap();
    }

    #[test]
    fn observer_cannot_claim_device_removal_and_restart_keeps_the_signed_request() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let _provision = super::super::tests::provision_input(&tmp.path().join("input"));
        let root = tmp.path().join("cluster");
        let store = Store::at(&root);
        store.import_provision(&tmp.path().join("input")).unwrap();
        let generation = super::super::tests::generation();
        store
            .project(
                &super::super::tests::core(&generation),
                &generation.catalog_sha256,
                vec![],
            )
            .unwrap();
        assert!(!store.prepare_uninstall(&"a".repeat(64)).unwrap());
        assert!(export_for_actor(&store, Some(Actor::Observer)).is_err());
        assert!(!store
            .directory()
            .unwrap()
            .entry_exists(DELIVERY_OWNER)
            .unwrap());
        let original = export_for_actor(&store, Some(Actor::Device)).unwrap();
        assert_eq!(
            store
                .directory()
                .unwrap()
                .read_trusted(RECOVERY_AUTHORITY, 65536, 0o600)
                .unwrap(),
            original
        );
        let body: serde_json::Value = serde_json::from_slice(&original).unwrap();
        assert!(body["androidPublicKey"].is_string());
        assert!(body["signedRequestHex"].is_string());
        let before = store
            .directory()
            .unwrap()
            .read_trusted(STATE_FILE, MAX_STATE_BYTES, 0o600)
            .unwrap();
        let mut reopened = Store::at(&root);
        reopened.epoch = Some("e".repeat(64));
        assert_eq!(
            export_for_actor(&reopened, Some(Actor::Device)).unwrap(),
            original
        );
        assert_eq!(
            reopened
                .directory()
                .unwrap()
                .read_trusted(STATE_FILE, MAX_STATE_BYTES, 0o600)
                .unwrap(),
            before
        );
        assert!(export_for_actor(&reopened, Some(Actor::Observer)).is_err());
        assert_eq!(
            reopened
                .directory()
                .unwrap()
                .read_trusted(RECOVERY_AUTHORITY, 65536, 0o600)
                .unwrap(),
            original
        );
    }

    #[test]
    fn export_absence_rejects_partial_authority() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let store = Store::at(&tmp.path().join("cluster"));
        let value: serde_json::Value = serde_json::from_slice(&export(&store).unwrap()).unwrap();
        assert_eq!(value["state"], "absent");
        store
            .directory()
            .unwrap()
            .write_atomic(FINAL_REPORT, b"forged", 0o600)
            .unwrap();
        assert!(export(&store).is_err());
    }

    #[test]
    fn offline_one_shot_absence_finishes_original_pending_without_imported_preparation() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let input = tmp.path().join("input");
        let provision = super::super::tests::provision_input(&input);
        let root = tmp.path().join("cluster");
        let store = Store::at(&root);
        store.import_provision(&input).unwrap();
        let generation = super::super::tests::generation();
        store
            .project(
                &super::super::tests::core(&generation),
                &generation.catalog_sha256,
                vec![],
            )
            .unwrap();
        assert!(!store.prepare_uninstall(&"a".repeat(64)).unwrap());
        let before: serde_json::Value =
            serde_json::from_slice(&export_for_actor(&store, Some(Actor::Desktop)).unwrap())
                .unwrap();
        assert_eq!(before["state"], "pending");
        let dir = store.directory().unwrap();
        assert!(!dir.entry_exists(UNINSTALL_REPORT).unwrap());
        let state = store.load(&dir).unwrap().unwrap();
        let request = &state.pending.as_ref().unwrap().request;
        let startup_hash = "c26b4913707a1e96933f48a07d6957857cc52853a7e405eb29b2adab9b84f47a";
        let mut report = AuthenticatedReport {
            schema_version: 1,
            pair_id: provision.pair_id.clone(),
            authority_epoch: provision.authority_epoch.clone(),
            challenge: request.challenge.clone(),
            report: DomainOperationReport {
                schema_version: 2,
                domain: Domain::Cluster,
                operation: Operation::Uninstall,
                phase: Phase::Complete,
                outcome: Outcome::Completed,
                transaction_id: request.transaction_id.clone(),
                release_manifest_sha256: "a".repeat(64),
                catalog_sha256: request.catalog_sha256.clone(),
                generation_id: None,
                desired_revision: 0,
                desired_sha256: cluster::desired_digest(&[]).unwrap(),
                boot_id: None,
                daemon_epoch: None,
                installed_evidence: Some(InstalledEvidence::QnxAbsence {
                    startup: AbsenceStartup {
                        path: "/scripts/startup_cluster.sh".into(),
                        original_sha256: startup_hash.into(),
                        restored_sha256: startup_hash.into(),
                    },
                    checks: AbsenceChecks {
                        daemon_process_absent: true,
                        autostart_removed: true,
                        native_payload_absent: true,
                        persistent_state_absent: true,
                    },
                    proof_sha256: "e".repeat(64),
                }),
            },
        };
        let key = SigningKey::from_bytes(&[74; 32]);
        assert!(provisional(
            &store,
            Some(&report.sign(&SigningKey::from_bytes(&[75; 32])).unwrap())
        )
        .is_err());
        report.report.transaction_id = "9".repeat(64);
        assert!(provisional(&store, Some(&report.sign(&key).unwrap())).is_err());
        report.report.transaction_id = request.transaction_id.clone();
        report.challenge = "9".repeat(64);
        assert!(provisional(&store, Some(&report.sign(&key).unwrap())).is_err());
        report.challenge = request.challenge.clone();
        let signed = report.sign(&key).unwrap();
        provisional(&store, Some(&signed)).unwrap();
        let mut reopened = Store::at(&root);
        reopened.epoch = Some("e".repeat(64));
        let retained = dir
            .read_trusted(STATE_FILE, MAX_STATE_BYTES, 0o600)
            .unwrap();
        assert_eq!(provisional(&reopened, None).unwrap(), Some(signed.clone()));
        import(&reopened, &signed).unwrap();
        assert_eq!(
            dir.read_trusted(STATE_FILE, MAX_STATE_BYTES, 0o600)
                .unwrap(),
            retained
        );
        assert!(completion_verified(&dir, &provision, request).unwrap());
        assert!(reopened.prepare_uninstall(&"a".repeat(64)).unwrap());
        import(&reopened, &signed).unwrap();
        import(&reopened, &signed).unwrap();
        let after: serde_json::Value = serde_json::from_slice(&export(&reopened).unwrap()).unwrap();
        assert_eq!(after["state"], "completed");
        assert_eq!(after["request"], before["request"]);
        assert_eq!(after["qnxPublicKey"], before["qnxPublicKey"]);
        assert_eq!(after["pairId"], before["pairId"]);
        assert_eq!(after["authorityEpoch"], before["authorityEpoch"]);
        assert!(!dir.entry_exists(UNINSTALL_REPORT).unwrap());
        assert!(reopened.prepare_uninstall(&"a".repeat(64)).unwrap());
        let completed = reopened.load(&dir).unwrap().unwrap();
        assert_eq!(
            completed.pending.unwrap().request.kind,
            RequestKind::Uninstall
        );
        assert!(dir.entry_exists(REQUEST_FILE).unwrap());
        let roles = [
            &crate::trust::AGENT_CATALOG_PUBKEY,
            &crate::trust::RELEASE_CATALOG_PUBKEY,
            &crate::trust::NATIVE_EXECUTABLE_PUBKEY,
            &crate::trust::RESTORE_PUBLIC_KEY,
        ];
        assert!(
            voboost_shared::cluster_mailbox::reject_pending_uninstall(tmp.path(), &roles).is_err()
        );
    }

    #[test]
    fn only_exact_signed_absence_unlocks_cleanup_and_is_rechecked() {
        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let provision = super::super::tests::provision_input(&tmp.path().join("input"));
        let store = Store::at(&tmp.path().join("cluster"));
        store.import_provision(&tmp.path().join("input")).unwrap();
        let generation = super::super::tests::generation();
        store
            .project(
                &super::super::tests::core(&generation),
                &generation.catalog_sha256,
                vec![],
            )
            .unwrap();
        assert!(!store.prepare_uninstall(&"a".repeat(64)).unwrap());
        let dir = store.directory().unwrap();
        let state = store.load(&dir).unwrap().unwrap();
        let request = &state.pending.as_ref().unwrap().request;
        let startup_hash = "c26b4913707a1e96933f48a07d6957857cc52853a7e405eb29b2adab9b84f47a";
        let mut report = AuthenticatedReport {
            schema_version: 1,
            pair_id: provision.pair_id.clone(),
            authority_epoch: provision.authority_epoch.clone(),
            challenge: request.challenge.clone(),
            report: DomainOperationReport {
                schema_version: 2,
                domain: Domain::Cluster,
                operation: Operation::Uninstall,
                phase: Phase::Complete,
                outcome: Outcome::Completed,
                transaction_id: request.transaction_id.clone(),
                release_manifest_sha256: "a".repeat(64),
                catalog_sha256: request.catalog_sha256.clone(),
                generation_id: None,
                desired_revision: 0,
                desired_sha256: cluster::desired_digest(&[]).unwrap(),
                boot_id: Some("new-qnx-kernel".into()),
                daemon_epoch: Some("b".repeat(64)),
                installed_evidence: Some(InstalledEvidence::QnxAbsence {
                    startup: AbsenceStartup {
                        path: "/scripts/startup_cluster.sh".into(),
                        original_sha256: startup_hash.into(),
                        restored_sha256: startup_hash.into(),
                    },
                    checks: AbsenceChecks {
                        daemon_process_absent: true,
                        autostart_removed: true,
                        native_payload_absent: true,
                        persistent_state_absent: true,
                    },
                    proof_sha256: "e".repeat(64),
                }),
            },
        };
        let key = SigningKey::from_bytes(&[74; 32]);
        assert!(import(
            &store,
            &report.sign(&SigningKey::from_bytes(&[75; 32])).unwrap()
        )
        .is_err());
        report.challenge = "9".repeat(64);
        assert!(import(&store, &report.sign(&key).unwrap()).is_err());
        report.challenge = request.challenge.clone();
        report.report.catalog_sha256 = "9".repeat(64);
        assert!(import(&store, &report.sign(&key).unwrap()).is_err());
        report.report.catalog_sha256 = request.catalog_sha256.clone();
        export_for_actor(&store, Some(Actor::Settings)).unwrap();
        let signed = report.sign(&key).unwrap();
        provisional(&store, Some(&signed)).unwrap();
        assert_eq!(
            provisional(&Store::at(&tmp.path().join("cluster")), None).unwrap(),
            Some(signed)
        );
        assert!(!completion_verified(&dir, &provision, request).unwrap());
        assert!(!store.prepare_uninstall(&"a".repeat(64)).unwrap());
        import(&store, &report.sign(&key).unwrap()).unwrap();
        assert!(store.prepare_uninstall(&"a".repeat(64)).unwrap());
        let value: serde_json::Value = serde_json::from_slice(&export(&store).unwrap()).unwrap();
        assert_eq!(value["state"], "completed");
        assert!(value.get("androidSigningSeed").is_none());
        dir.write_atomic(FINAL_REPORT, b"forged", 0o600).unwrap();
        assert!(store.prepare_uninstall(&"a".repeat(64)).is_err());
        assert!(export(&store).is_err());
    }
}
