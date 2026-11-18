//! In-process agent loader and receiver for state published by the cluster daemon.
use crate::{
    config::Config,
    engine::{Authority, ProductRoots},
    ipc::{Body, Direction, Message},
    sdk, Result,
};
use alloc::{boxed::Box, collections::BTreeMap, ffi::CString, format, string::String, vec::Vec};
use core::{
    cell::UnsafeCell,
    ffi::{c_char, c_void},
    sync::atomic::{AtomicBool, AtomicPtr, Ordering},
};
use serde::{Deserialize, Serialize};
use voboost_contract_core::{
    ascii_json,
    cluster::{AcceptedDesired, DesiredAgent, ObservedAgent, ObservedState, ProcessIdentity},
    MAX_SAFE_INTEGER,
};
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Challenge {
    pub schema_version: u32,
    pub controller_nonce: String,
}
pub struct Spin<T> {
    busy: AtomicBool,
    value: UnsafeCell<T>,
}
unsafe impl<T: Send> Sync for Spin<T> {}
impl<T> Spin<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self {
            busy: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }
    pub(crate) fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        while self
            .busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        let result = f(unsafe { &mut *self.value.get() });
        self.busy.store(false, Ordering::Release);
        result
    }
    pub(crate) fn take<R>(&self, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        if self
            .busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return None;
        }
        let result = f(unsafe { &mut *self.value.get() });
        self.busy.store(false, Ordering::Release);
        Some(result)
    }
}
#[path = "controller_resources.rs"]
mod resources;

struct Module {
    id: CString,
    file: CString,
    entry: CString,
    configuration: Vec<(CString, CString)>,
    options: Vec<(CString, CString)>,
    enabled: bool,
}
struct Plan {
    catalog: CString,
    generation: CString,
    desired: CString,
    revision: u64,
    global_locale: Option<voboost_contract_core::cluster::GlobalLocale>,
    global_locale_deadline_ms: u64,
    runtime: CString,
    packs: Box<resources::Prepared>,
    modules: Vec<Module>,
    rows: Vec<ObservedAgent>,
    process: ProcessIdentity,
}
enum Command {
    Apply(Box<Plan>),
    Stop,
}
#[derive(Clone)]
struct Snapshot {
    generation: Option<String>,
    revision: u64,
    sha256: String,
    rows: Vec<ObservedAgent>,
}
struct Shared {
    pending: Option<Command>,
    stop_pending: bool,
    snapshot: Option<Snapshot>,
}
static SHARED: Spin<Shared> = Spin::new(Shared {
    pending: None,
    stop_pending: false,
    snapshot: None,
});
struct FontAudit {
    context: Option<(ProcessIdentity, String)>,
    seen: u8,
}
static FONT_AUDIT: Spin<FontAudit> = Spin::new(FontAudit {
    context: None,
    seen: 0,
});
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FontReadback {
    input_sha256: String,
    output_sha256: String,
    input_bytes: usize,
    output_bytes: usize,
    pid: u64,
    endpoint_epoch: String,
    birth_identity: String,
    boot_id: String,
    original_result: i32,
    face_non_null: bool,
}
fn font_identity(size: usize, sha256: &str) -> Option<u8> {
    match (size, sha256) {
        (1644272, "305f942097a1b65d1dca1c357c0197acf62346eea83e2fbe95cc55f62821f000") => Some(1),
        (1697868, "b90b145194f1206b3d515e05d2bc2f27f2411aa0b6897f61755d7b812fe083c1") => Some(2),
        _ => None,
    }
}
/// # Safety
/// Buffers are valid for their bounded lengths during this completed original FT call.
#[no_mangle]
pub unsafe extern "C" fn vbc_controller_font_loaded(
    input: *const u8,
    input_len: usize,
    output: *const u8,
    output_len: usize,
    result: i32,
    face_created: u32,
) {
    if result != 0
        || face_created != 1
        || input.is_null()
        || output.is_null()
        || !matches!(input_len, 1644272 | 1697868)
        || !matches!(
            (input_len, output_len),
            (1644272, 1644272) | (1697868, 1697868 | 1712864)
        )
    {
        return;
    }
    let input_sha256 = voboost_contract_core::hash(core::slice::from_raw_parts(input, input_len));
    let Some(bit) = font_identity(input_len, &input_sha256) else {
        return;
    };
    let event = FONT_AUDIT.with(|audit| {
        if audit.seen & bit != 0 {
            return None;
        }
        audit.seen |= bit;
        let (process, boot) = audit.context.as_ref()?;
        let (pid, endpoint_epoch, birth_identity, boot_id) = (
            process.pid,
            process.endpoint_epoch.clone(),
            process.birth_identity.clone(),
            boot.clone(),
        );
        Some(FontReadback {
            input_sha256,
            output_sha256: voboost_contract_core::hash(core::slice::from_raw_parts(
                output, output_len,
            )),
            input_bytes: input_len,
            output_bytes: output_len,
            pid,
            endpoint_epoch,
            birth_identity,
            boot_id,
            original_result: result,
            face_non_null: true,
        })
    });
    if let Some(event) = event {
        if let Ok(bytes) = ascii_json(&event) {
            if let Ok(json) = core::str::from_utf8(&bytes) {
                if let Ok(message) = c(&format!("VBC font-readback {json}")) {
                    vbc_host_log(message.as_ptr());
                }
            }
        }
    }
}
static RUNTIME: AtomicPtr<sdk::Runtime> = AtomicPtr::new(core::ptr::null_mut());
struct Ui {
    generation: Option<String>,
    runtime_sha: Option<String>,
}
struct UiCell(UnsafeCell<Ui>);
unsafe impl Sync for UiCell {}
static UI: UiCell = UiCell(UnsafeCell::new(Ui {
    generation: None,
    runtime_sha: None,
}));
static STOPPED: AtomicBool = AtomicBool::new(true);
static STARTED: AtomicBool = AtomicBool::new(false);
static VEHICLE_DRIVE_PEDESTRIAN_WARNING_HIDE_ICON: AtomicBool = AtomicBool::new(false);

#[no_mangle]
pub extern "C" fn vbc_vehicle_drive_pedestrian_warning_hide_icon() -> i32 {
    i32::from(VEHICLE_DRIVE_PEDESTRIAN_WARNING_HIDE_ICON.load(Ordering::Acquire))
}
#[cfg(target_os = "nto")]
extern "C" {
    fn vbc_host_resolve(library: *const c_char, symbol: *const c_char) -> *mut c_void;
    fn vbc_host_clock() -> u64;
    fn vbc_host_log(message: *const c_char);
    fn vbc_host_ui_ready() -> i32;
    fn vbc_host_schedule_pw_frame() -> i32;
}
#[cfg(not(target_os = "nto"))]
unsafe extern "C" fn vbc_host_resolve(
    library: *const c_char,
    symbol: *const c_char,
) -> *mut c_void {
    let handle = libc::dlopen(library, libc::RTLD_NOW);
    if handle.is_null() {
        core::ptr::null_mut()
    } else {
        libc::dlsym(handle, symbol)
    }
}
#[cfg(not(target_os = "nto"))]
unsafe extern "C" fn vbc_host_clock() -> u64 {
    0
}
#[cfg(not(target_os = "nto"))]
unsafe extern "C" fn vbc_host_log(_message: *const c_char) {}
#[cfg(not(target_os = "nto"))]
unsafe extern "C" fn vbc_host_ui_ready() -> i32 {
    0
}
fn string(value: *const c_char, max: usize) -> Result<String> {
    if value.is_null() {
        return Err("native callback null string".into());
    }
    let mut n = 0;
    while n <= max && unsafe { *value.add(n) } != 0 {
        n += 1;
    }
    if n > max {
        return Err("native callback string bound".into());
    }
    let bytes = unsafe { core::slice::from_raw_parts(value.cast::<u8>(), n) };
    core::str::from_utf8(bytes)
        .map(String::from)
        .map_err(|_| "native callback UTF8".into())
}
unsafe extern "C" fn compatible(path: *const c_char, id: *const c_char) -> i32 {
    match (string(path, 512), string(id, 128)) {
        (Ok(path), Ok(id)) => i32::from(crate::elf::compatible(&path, &id)),
        _ => 0,
    }
}
fn state(value: i32) -> Option<ObservedState> {
    Some(match value {
        1 => ObservedState::WaitingProcess,
        2 => ObservedState::Injecting,
        3 => ObservedState::Loaded,
        4 => ObservedState::WaitingUi,
        5 => ObservedState::Applied,
        6 => ObservedState::Restoring,
        7 => ObservedState::Disabled,
        8 => ObservedState::Failed,
        9 => ObservedState::Quarantined,
        10 => ObservedState::ReloadRequired,
        _ => return None,
    })
}
unsafe extern "C" fn report(_user: *mut c_void, observation: *const sdk::Observation) {
    let Some(o) = observation.as_ref() else {
        return;
    };
    if o.size < core::mem::size_of::<sdk::Observation>() as u32 || o.lifecycle > MAX_SAFE_INTEGER {
        return;
    }
    let (Ok(id), Ok(reason), Some(state)) =
        (string(o.id, 96), string(o.reason, 128), state(o.state))
    else {
        return;
    };
    if !voboost_contract_core::printable(&reason, 128) {
        return;
    }
    SHARED.with(|shared| {
        let Some(snapshot) = &mut shared.snapshot else {
            return;
        };
        if o.revision != snapshot.revision {
            return;
        }
        let Some(row) = snapshot.rows.iter_mut().find(|r| r.id == id) else {
            return;
        };
        if o.lifecycle == 0
            && matches!(
                state,
                ObservedState::Applied
                    | ObservedState::Loaded
                    | ObservedState::WaitingUi
                    | ObservedState::Restoring
                    | ObservedState::ReloadRequired
            )
        {
            return;
        }
        row.state = state;
        row.reason = reason;
    });
}
unsafe extern "C" fn resolve_host(path: *const c_char, symbol: *const c_char) -> *mut c_void {
    resources::resolve(path, symbol).unwrap_or_else(|| vbc_host_resolve(path, symbol))
}
unsafe impl Sync for sdk::Host {}
static HOST: sdk::Host = sdk::Host {
    abi: 2,
    size: core::mem::size_of::<sdk::Host>() as u32,
    resolve: resolve_host,
    monotonic_ms: vbc_host_clock,
    log: vbc_host_log,
    compatible,
    ui_ready: vbc_host_ui_ready,
    report_user: core::ptr::null_mut(),
    report,
};
fn c(value: &str) -> Result<CString> {
    CString::new(value).map_err(|_| "native authority embedded NUL".into())
}
fn values(values: &BTreeMap<String, String>) -> Result<Vec<(CString, CString)>> {
    values.iter().map(|(k, v)| Ok((c(k)?, c(v)?))).collect()
}
fn pairs(values: &[(CString, CString)]) -> Vec<sdk::KeyValue> {
    values
        .iter()
        .map(|(key, value)| sdk::KeyValue {
            key: key.as_ptr(),
            value: value.as_ptr(),
        })
        .collect()
}
fn request_pw_storage(a: &Authority) -> crate::pw_storage_host::Demand {
    let (Some(g), Some(d)) = (&a.generation, &a.desired) else {
        crate::pw_storage_host::revoke();
        return crate::pw_storage_host::Demand::NotRequested;
    };
    let Some(agent) = g.catalog.agents.iter().find(|v| {
        v.id == "vehicle-drive-pedestrian-warning"
            && v.domain == voboost_contract_core::catalog::Domain::Cluster
    }) else {
        crate::pw_storage_host::revoke();
        return crate::pw_storage_host::Demand::NotRequested;
    };
    let enabled = d.agents.iter().any(|v| v.id == agent.id && v.enabled);
    let selected=g.selection.iter().any(|v|v.id==agent.id&&agent.targets.iter().any(|t|matches!(t,voboost_contract_core::catalog::Target::Native{executable,..}if executable==&a.config.expected_executable)&&t.process()==v.process));
    crate::pw_storage_host::request_consumer(&agent.id, enabled, selected, &g.storage_id)
}
fn plan(a: &Authority, process: &ProcessIdentity) -> Result<Plan> {
    let g = a
        .generation
        .as_ref()
        .ok_or("controller generation absent")?;
    let d = a.desired.as_ref().ok_or("controller desired absent")?;
    let directory = format!("{}/generations/{}", a.config.root, g.storage_id);
    let mut modules = Vec::new();
    let pw_storage = request_pw_storage(a);
    let mut rows = Vec::new();
    let mut resource_owner = None;
    for agent in g
        .catalog
        .agents
        .iter()
        .filter(|v| v.domain == voboost_contract_core::catalog::Domain::Cluster)
    {
        let selected=g.selection.iter().find(|v|v.id==agent.id&&agent.targets.iter().any(|t|matches!(t,voboost_contract_core::catalog::Target::Native{executable,..} if executable==&a.config.expected_executable)&&t.process()==v.process));
        if selected.is_none() {
            continue;
        }
        let desired = d
            .agents
            .iter()
            .find(|v| v.id == agent.id)
            .ok_or("native desired row absent")?;
        let mut row = ObservedAgent {
            id: agent.id.clone(),
            target_process: crate::config::owner_role(&a.config.expected_executable)?.into(),
            state: ObservedState::WaitingProcess,
            reason: "target-not-selected".into(),
            process: None,
        };
        if let Some(target) = selected {
            if agent.id == "i18n-ru" && desired.enabled {
                resource_owner = Some(target.process.as_str());
            }
            let configuration = agent.configuration.clone().unwrap_or_default();
            if configuration
                .keys()
                .any(|k| desired.options.contains_key(k))
            {
                return Err("fixed/native options collide".into());
            }
            modules.push(Module {
                id: c(&agent.id)?,
                file: c(&format!("{directory}/{}", target.file))?,
                entry: c(&target.entry)?,
                configuration: values(&configuration)?,
                options: values(&desired.options)?,
                enabled: desired.enabled,
            });
            row.reason = "awaiting-ui-reconciliation".into();
            if agent.id == "vehicle-drive-pedestrian-warning" && desired.enabled {
                match pw_storage {
                    crate::pw_storage_host::Demand::Waiting => {
                        row.reason = "PW storage admission awaiting worker/retry".into()
                    }
                    crate::pw_storage_host::Demand::Unavailable => {
                        row.reason = "PW storage admission worker unavailable".into()
                    }
                    _ => {}
                }
            }
            row.process = Some(process.clone());
        }
        rows.push(row);
    }
    rows.sort_by(|a, b| a.id.cmp(&b.id));
    let packs = match resource_owner {
        Some(owner) => resources::prepare(a.owned_resource_packs()?, owner, process)?,
        None => resources::Prepared::empty(),
    };
    Ok(Plan {
        catalog: c(&g.identity.catalog_sha256)?,
        generation: c(&g.generation_id)?,
        desired: c(&d.desired_sha256)?,
        revision: d.desired_revision,
        global_locale: a.live_global_locale.clone(),
        global_locale_deadline_ms: a.live_global_locale_deadline_ms,
        runtime: c(&format!("{directory}/libvoboost-runtime-cluster.so"))?,
        packs,
        modules,
        rows,
        process: process.clone(),
    })
}
unsafe extern "C" fn noop() {}
#[derive(Clone, Debug, Eq, PartialEq)]
struct DisabledResourceIntent {
    generation: String,
    revision: u64,
    desired: String,
}
fn disabled_resource_intent(plan: &Plan) -> Option<DisabledResourceIntent> {
    plan.modules
        .iter()
        .any(|module| module.id.to_bytes() == b"i18n-ru" && !module.enabled)
        .then(|| DisabledResourceIntent {
            generation: plan.generation.to_string_lossy().into_owned(),
            revision: plan.revision,
            desired: plan.desired.to_string_lossy().into_owned(),
        })
}
fn restart_intent_matches(shared: &Shared, intent: &DisabledResourceIntent) -> bool {
    let latest = match shared.pending.as_ref() {
        None => true,
        Some(Command::Apply(plan)) => disabled_resource_intent(plan).as_ref() == Some(intent),
        Some(Command::Stop) => false,
    };
    latest
        && shared.snapshot.as_ref().is_some_and(|snapshot| {
            snapshot.generation.as_ref() == Some(&intent.generation)
                && snapshot.revision <= intent.revision
                && (snapshot.revision < intent.revision || snapshot.sha256 == intent.desired)
        })
}
fn mark_retained_resource_restart(intent: Option<&DisabledResourceIntent>) {
    let Some(intent) = intent.filter(|_| resources::retained_restart_required()) else {
        return;
    };
    SHARED.with(|shared| {
        if !restart_intent_matches(shared, intent) {
            return;
        }
        if let Some(row) = shared.snapshot.as_mut().and_then(|snapshot| {
            snapshot.rows.iter_mut().find(|row| {
                row.id == "i18n-ru"
                    && row.process.is_some()
                    && row.state == ObservedState::ReloadRequired
            })
        }) {
            row.reason = "private locale resource stop requires owner restart".into();
        }
    });
}
fn mark_failure(state: ObservedState, reason: &str) {
    SHARED.with(|s| {
        if let Some(snapshot) = &mut s.snapshot {
            for row in &mut snapshot.rows {
                if row.process.is_some() {
                    if state == ObservedState::ReloadRequired
                        && row.id == "i18n-ru"
                        && row.state == ObservedState::ReloadRequired
                        && row.reason == "private locale resource stop requires owner restart"
                    {
                        continue;
                    }
                    row.state = state;
                    row.reason = reason.into();
                }
            }
        }
    });
}
#[cfg(target_os = "nto")]
extern "C" {
    fn vbc_system_locale_publish(
        locale: u32,
        revision: u64,
        endpoint: u64,
        lifecycle: u64,
        deadline: u64,
    ) -> i32;
    fn vbc_system_locale_invalidate();
}
unsafe fn publish_locale(
    locale: Option<&voboost_contract_core::cluster::GlobalLocale>,
    deadline: u64,
) -> Result<()> {
    #[cfg(target_os = "nto")]
    match locale {
        Some(v) => {
            if vbc_system_locale_publish(
                v.locale,
                v.revision,
                v.endpoint_identity,
                v.lifecycle_generation,
                deadline,
            ) != 1
            {
                return Err("global locale publication rejected".into());
            }
        }
        None => vbc_system_locale_invalidate(),
    }
    #[cfg(not(target_os = "nto"))]
    let _ = (locale, deadline);
    Ok(())
}
unsafe fn apply(plan: Plan) -> Result<()> {
    let resource_changed = !resources::matches(plan.packs.key());
    let repeated = SHARED.with(|shared| {
        shared
            .snapshot
            .as_ref()
            .map(|snapshot| {
                snapshot.generation.as_deref() == plan.generation.to_str().ok()
                    && snapshot.revision == plan.revision
                    && snapshot.sha256.as_str() == plan.desired.to_str().unwrap_or("")
                    && snapshot.rows.len() == plan.rows.len()
                    && snapshot.rows.iter().zip(&plan.rows).all(|(old, next)| {
                        old.id == next.id
                            && match (&old.process, &next.process) {
                                (Some(a), Some(b)) => {
                                    a.pid == b.pid
                                        && a.birth_identity == b.birth_identity
                                        && a.executable_sha256 == b.executable_sha256
                                        && a.endpoint_epoch == b.endpoint_epoch
                                        && a.lifecycle_generation > 0
                                }
                                (None, None) => true,
                                _ => false,
                            }
                    })
            })
            .unwrap_or(false)
    });
    if repeated
        && !resource_changed
        && !RUNTIME.load(Ordering::Acquire).is_null()
        && (*UI.0.get()).generation.as_deref() == plan.generation.to_str().ok()
    {
        publish_locale(plan.global_locale.as_ref(), plan.global_locale_deadline_ms)?;
        return Ok(());
    }
    let generation = plan.generation.to_str().map_err(|_| "generation string")?;
    let ui = &mut *UI.0.get();
    let mut runtime = RUNTIME.load(Ordering::Acquire);
    if ui.generation.as_deref() != Some(generation) || resource_changed || runtime.is_null() {
        resources::revoke();
        if let Some(old) = runtime.as_ref() {
            if old.stop.ok_or("runtime stop absent")?() != 0 {
                return Err("old-runtime-reload-required".into());
            }
            RUNTIME.store(core::ptr::null_mut(), Ordering::Release);
        }
        resources::publish(plan.packs)?;
        let library = libc::dlopen(plan.runtime.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
        if library.is_null() {
            return Err("admitted runtime dlopen failed".into());
        }
        let symbol = c("vbc_runtime_v2")?;
        let entry = libc::dlsym(library, symbol.as_ptr());
        if entry.is_null() {
            return Err("admitted runtime export missing".into());
        }
        let entry: unsafe extern "C" fn() -> *mut sdk::Runtime = core::mem::transmute(entry);
        runtime = entry();
        let runtime_ref = runtime
            .as_ref()
            .filter(|r| r.valid())
            .ok_or("runtime ABI2 rejected")?;
        let configuration: Vec<_> = plan
            .modules
            .iter()
            .map(|m| pairs(&m.configuration))
            .collect();
        let domain = c("cluster")?;
        let modules: Vec<_> = plan
            .modules
            .iter()
            .zip(&configuration)
            .map(|(m, p)| sdk::Module {
                size: core::mem::size_of::<sdk::Module>() as u32,
                id: m.id.as_ptr(),
                domain: domain.as_ptr(),
                file: m.file.as_ptr(),
                entry: m.entry.as_ptr(),
                configuration: p.as_ptr(),
                configuration_count: p.len() as u32,
            })
            .collect();
        let authorization = sdk::Authorization {
            abi: 2,
            size: core::mem::size_of::<sdk::Authorization>() as u32,
            catalog: plan.catalog.as_ptr(),
            generation: plan.generation.as_ptr(),
            modules: modules.as_ptr(),
            count: modules.len() as u32,
        };
        if runtime_ref.initialize.ok_or("runtime initialize absent")?(&HOST, &authorization) != 0 {
            return Err("runtime native authorization rejected".into());
        }
        RUNTIME.store(runtime, Ordering::Release);
        STOPPED.store(false, Ordering::Release);
        ui.generation = Some(generation.into());
        ui.runtime_sha = Some(voboost_contract_core::hash(&crate::elf::read(
            plan.runtime.to_str().map_err(|_| "runtime path")?,
            64 * 1024 * 1024,
        )?));
    } else {
        resources::publish(plan.packs)?;
    }
    let runtime = runtime.as_ref().ok_or("runtime unavailable")?;
    let options: Vec<_> = plan.modules.iter().map(|m| pairs(&m.options)).collect();
    let modules: Vec<_> = plan
        .modules
        .iter()
        .zip(&options)
        .map(|(m, p)| sdk::ModuleDesired {
            size: core::mem::size_of::<sdk::ModuleDesired>() as u32,
            id: m.id.as_ptr(),
            enabled: u32::from(m.enabled),
            options: p.as_ptr(),
            count: p.len() as u32,
        })
        .collect();
    let desired = sdk::Desired {
        abi: 2,
        size: core::mem::size_of::<sdk::Desired>() as u32,
        generation: plan.generation.as_ptr(),
        sha256: plan.desired.as_ptr(),
        revision: plan.revision,
        modules: modules.as_ptr(),
        count: modules.len() as u32,
    };
    SHARED.with(|s| {
        s.snapshot = Some(Snapshot {
            generation: Some(generation.into()),
            revision: plan.revision,
            sha256: plan.desired.to_string_lossy().into_owned(),
            rows: plan.rows,
        })
    });
    publish_locale(plan.global_locale.as_ref(), plan.global_locale_deadline_ms)?;
    if runtime.apply.ok_or("runtime desired absent")?(&desired) != 0 {
        return Err("runtime desired rejected".into());
    }
    let _ = plan.process;
    Ok(())
}
fn includes_pw(plan: &Plan) -> bool {
    plan.modules
        .iter()
        .any(|module| module.id.to_bytes() == b"vehicle-drive-pedestrian-warning")
}

fn schedule_pw_frame() {
    #[cfg(target_os = "nto")]
    {
        static SCHEDULE: Spin<crate::diagnostic_log::Transition> =
            Spin::new(crate::diagnostic_log::Transition::new());
        static NEXT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
        if vbc_controller_pw_pending() == 0 {
            return;
        }
        let Some(now) = crate::engine::monotonic_ms() else {
            return;
        };
        let next = NEXT.load(Ordering::Acquire);
        if now < next
            || NEXT
                .compare_exchange(
                    next,
                    now.saturating_add(250),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            return;
        }
        let result =
            crate::elf::local_provider::prepare_shared_exception_provider().and_then(|_| {
                match unsafe { vbc_host_schedule_pw_frame() } {
                    1 => Ok(()),
                    0 => Err("Kanzi task dispatcher not ready".into()),
                    -2 => Err("Kanzi UI dispatcher entrypoints unavailable".into()),
                    -3 => Err("Kanzi application domain unavailable".into()),
                    -4 => Err("Kanzi UI task queue unavailable".into()),
                    _ => Err("Kanzi rejected the pedestrian warning task".into()),
                }
            });
        SCHEDULE.with(|log| log.observe("controller-frame", "PW UI scheduling", &result));
    }
}

#[no_mangle]
pub extern "C" fn vbc_controller_pw_pending() -> i32 {
    let pending = SHARED.take(|shared| match &shared.pending {
        Some(Command::Apply(plan)) => includes_pw(plan),
        Some(Command::Stop) => shared.snapshot.as_ref().is_some_and(|snapshot| {
            snapshot
                .rows
                .iter()
                .any(|row| row.id == "vehicle-drive-pedestrian-warning" && row.process.is_some())
        }),
        None => false,
    });
    i32::from(pending.unwrap_or(false))
}

/// # Safety
/// Called only on the original OEM UI update thread after its original callback.
#[no_mangle]
pub unsafe extern "C" fn vbc_controller_frame() {
    if let Some(command) = SHARED.take(|s| s.pending.take()).flatten() {
        let stopping = matches!(&command, Command::Stop);
        let disabled_intent = match &command {
            Command::Apply(plan) => disabled_resource_intent(plan),
            Command::Stop => None,
        };
        let result = match command {
            Command::Apply(plan) => {
                let revision = plan.revision;
                let changed = SHARED.with(|s| {
                    s.snapshot.as_ref().is_none_or(|snapshot| {
                        snapshot.revision != revision
                            || snapshot.generation.as_deref() != plan.generation.to_str().ok()
                            || snapshot.sha256.as_str() != plan.desired.to_str().unwrap_or("")
                    })
                });
                let result = apply(*plan);
                if changed {
                    let revision = format!("{revision}");
                    crate::diagnostic_log::emit(
                        "debug",
                        "controller-frame",
                        "desired revision consumed on OEM frame",
                        &[
                            ("revision", &revision),
                            (
                                "result",
                                result.as_ref().err().map_or("accepted", String::as_str),
                            ),
                        ],
                    );
                }
                result
            }
            Command::Stop => {
                resources::revoke();
                publish_locale(None, 0).ok();
                if let Some(runtime) = RUNTIME.load(Ordering::Acquire).as_ref() {
                    if runtime.stop.map(|stop| stop()) != Some(0) {
                        Err("native-stop-reload-required".into())
                    } else {
                        RUNTIME.store(core::ptr::null_mut(), Ordering::Release);
                        STOPPED.store(true, Ordering::Release);
                        (*UI.0.get()).generation = None;
                        Ok(())
                    }
                } else {
                    Ok(())
                }
            }
        };
        if result.is_ok() && stopping {
            // Completion belongs to the consumed Stop only. A newer queued Stop
            // must still execute on the OEM thread before it can be acknowledged.
            SHARED.with(|s| {
                if s.stop_pending && !matches!(s.pending, Some(Command::Stop)) {
                    s.stop_pending = false;
                    STOPPED.store(true, Ordering::Release);
                }
            });
        }
        if let Err(reason) = result {
            resources::revoke();
            mark_failure(ObservedState::ReloadRequired, &reason);
            mark_retained_resource_restart(disabled_intent.as_ref());
        }
    }
    if let Some(runtime) = RUNTIME.load(Ordering::Acquire).as_ref() {
        if let Some(update) = runtime.update {
            update(noop as *mut c_void);
        }
    }
}
/// # Safety
/// Arguments and original callback retain the OEM gauge-data ABI and lifetime.
#[no_mangle]
pub unsafe extern "C" fn vbc_controller_data(
    original: *mut c_void,
    input: *mut c_void,
    output: *mut c_void,
    size: u32,
) -> i32 {
    if let Some(runtime) = RUNTIME.load(Ordering::Acquire).as_ref() {
        if let Some(data) = runtime.data {
            data(original, input, output, size);
            return 1;
        }
    }
    0
}
fn response(
    body: Body,
    daemon: &str,
    controller: &str,
    sequence: u64,
    secret: &[u8; 32],
) -> Result<Vec<u8>> {
    Message {
        schema_version: 1,
        daemon_nonce: daemon.into(),
        controller_nonce: controller.into(),
        direction: Direction::Response,
        sequence,
        body,
    }
    .seal(secret)
}
pub(crate) fn pw_matches_current(proof: &voboost_contract_core::pw_live::Proof) -> bool {
    !STOPPED.load(Ordering::Acquire)
        && SHARED.with(|s| {
            s.snapshot.as_ref().is_some_and(|v| {
                v.generation.as_deref() == Some(proof.challenge.generation_id.as_str())
                    && v.revision == proof.challenge.desired_revision
                    && v.sha256 == proof.challenge.desired_sha256
                    && v.rows.iter().any(|r| {
                        r.id == "vehicle-drive-pedestrian-warning"
                            && !matches!(
                                r.state,
                                ObservedState::Failed | ObservedState::ReloadRequired
                            )
                    })
            })
        })
}
fn parse_supervisor(
    nonce: Option<&[u8]>,
    parent_pid: u64,
) -> Option<voboost_contract_core::cluster::SupervisorObservation> {
    let nonce = core::str::from_utf8(nonce?).ok()?;
    if parent_pid <= 1
        || parent_pid > voboost_contract_core::MAX_SAFE_INTEGER
        || !voboost_contract_core::digest(nonce)
    {
        return None;
    }
    Some(voboost_contract_core::cluster::SupervisorObservation {
        nonce: nonce.into(),
        parent_pid,
    })
}
fn fresh_supervisor() -> Option<voboost_contract_core::cluster::SupervisorObservation> {
    let parent_pid = unsafe { libc::getppid() } as u64;
    let pointer = unsafe { libc::getenv(c"VOBOOST_CLUSTER_SUPERVISOR".as_ptr()) };
    let nonce = if pointer.is_null() {
        None
    } else {
        let length = unsafe { libc::strnlen(pointer, 65) };
        if length != 64 {
            None
        } else {
            Some(unsafe { core::slice::from_raw_parts(pointer.cast::<u8>(), length) })
        }
    };
    parse_supervisor(nonce, parent_pid)
}
fn fresh_process(process: &ProcessIdentity) -> ProcessIdentity {
    let mut current = process.clone();
    current.supervisor = fresh_supervisor();
    current
}
fn snapshot() -> Body {
    let supervisor = fresh_supervisor();
    let pw_storage_failure = crate::pw_storage_host::failure();
    SHARED.with(|s| match &s.snapshot {
        Some(v) => {
            let mut agents = v.rows.clone();
            for row in &mut agents {
                if let Some(process) = &mut row.process {
                    process.supervisor = supervisor.clone();
                }
                if row.id == "vehicle-drive-pedestrian-warning"
                    && row.reason == "PW storage capability unavailable"
                {
                    if let Some(reason) = &pw_storage_failure {
                        row.reason = reason.clone();
                    }
                }
            }
            Body::Snapshot {
                supervisor,
                generation_id: v.generation.clone(),
                desired_revision: v.revision,
                desired_sha256: v.sha256.clone(),
                agents,
                stopped: STOPPED.load(Ordering::Acquire) && !s.stop_pending,
            }
        }
        None => Body::Snapshot {
            supervisor,
            generation_id: None,
            desired_revision: 0,
            desired_sha256: voboost_contract_core::cluster::desired_digest(&[]).unwrap_or_default(),
            agents: Vec::new(),
            stopped: STOPPED.load(Ordering::Acquire) && !s.stop_pending,
        },
    })
}
fn receive_agent_state(
    authority: &mut Authority,
    revision: u64,
    identity: String,
    agents: Vec<DesiredAgent>,
) -> Result<()> {
    let generation = authority
        .generation
        .as_ref()
        .ok_or("native generation unavailable")?;
    let role = crate::config::owner_role(&authority.config.expected_executable)?;
    let expected: alloc::collections::BTreeSet<_> = generation
        .selection
        .iter()
        .filter(|target| target.process == role)
        .map(|target| target.id.as_str())
        .collect();
    if agents.len() != expected.len()
        || agents.iter().any(|state| {
            !expected.contains(state.id.as_str())
                || !generation.catalog.agents.iter().any(|agent| {
                    agent.id == state.id && crate::engine::declares_projected_state(agent, state)
                })
        })
    {
        return Err("IPC state does not match this owner's declared agents".into());
    }
    if authority.desired.as_ref().is_some_and(|previous| {
        revision < previous.desired_revision
            || (revision == previous.desired_revision
                && (identity != previous.desired_sha256 || agents != previous.agents))
    }) {
        return Err("IPC state revision is stale or conflicting".into());
    }
    authority.desired = Some(AcceptedDesired {
        authority_epoch: authority.config.authority_epoch.clone(),
        catalog_sha256: generation.identity.catalog_sha256.clone(),
        closure_sha256: generation.identity.closure_sha256.clone(),
        desired_revision: revision,
        desired_sha256: identity,
        agents,
        global_locale: None,
    });
    Ok(())
}

fn session(
    fd: i32,
    config: &Config,
    process: &ProcessIdentity,
    controller: &str,
    cached: &mut Option<Authority>,
) -> Result<()> {
    let secret = crate::key(&config.ipc_secret)?;
    crate::net::write_frame(
        fd,
        &ascii_json(&Challenge {
            schema_version: 1,
            controller_nonce: controller.into(),
        })?,
    )?;
    let hello = Message::hello(&crate::net::read_frame(fd)?, &secret, controller)?;
    let daemon = hello.daemon_nonce;
    crate::net::write_frame(
        fd,
        &response(
            Body::Register {
                process: fresh_process(process),
            },
            &daemon,
            controller,
            0,
            &secret,
        )?,
    )?;
    let mut sequence = 1;
    loop {
        schedule_pw_frame();
        let request = Message::open(
            &crate::net::read_frame(fd)?,
            &secret,
            &daemon,
            controller,
            Direction::Request,
            sequence,
        )?;
        match request.body {
            Body::Apply {
                global_locale,
                global_locale_deadline_ms,
                generation_id,
                desired_revision,
                desired_sha256,
                agents,
            } => {
                let current = |authority: &Authority| {
                    authority
                        .generation
                        .as_ref()
                        .is_some_and(|g| g.generation_id == generation_id)
                };
                if !cached.as_ref().is_some_and(current) {
                    let authority = Authority::open_generation(
                        config.clone(),
                        crate::fs::uid()?,
                        ProductRoots::default(),
                    )?;
                    if !current(&authority) {
                        return Err("IPC refers to stale native generation".into());
                    }
                    *cached = Some(authority);
                }
                let authority = cached.as_mut().ok_or("IPC generation unavailable")?;
                receive_agent_state(authority, desired_revision, desired_sha256, agents)?;
                crate::controller_pw::revoke();
                let mut plan = plan(authority, process)?;
                let hide_icon = authority.desired.as_ref().is_some_and(|desired| {
                    desired.agents.iter().any(|agent| {
                        agent.id == crate::engine::PEDESTRIAN_WARNING_AGENT
                            && agent.enabled
                            && agent
                                .options
                                .get(crate::engine::PEDESTRIAN_WARNING_HIDE_ICON)
                                .is_some_and(|hide| hide == "true")
                    })
                });
                VEHICLE_DRIVE_PEDESTRIAN_WARNING_HIDE_ICON.store(hide_icon, Ordering::Release);
                plan.global_locale = global_locale.filter(|_| {
                    crate::engine::monotonic_ms()
                        .is_some_and(|now| now <= global_locale_deadline_ms)
                });
                plan.global_locale_deadline_ms = global_locale_deadline_ms;
                let schedule = SHARED.with(|s| {
                    let changed = s.snapshot.as_ref().is_none_or(|snapshot| {
                        snapshot.revision != plan.revision
                            || snapshot.generation.as_deref() != plan.generation.to_str().ok()
                            || snapshot.sha256.as_str() != plan.desired.to_str().unwrap_or("")
                    });
                    let schedule = changed && includes_pw(&plan);
                    s.pending = Some(Command::Apply(Box::new(plan)));
                    schedule
                });
                if schedule {
                    crate::diagnostic_log::emit(
                        "debug",
                        "agent-dispatch",
                        "desired state queued for OEM UI",
                        &[],
                    );
                    schedule_pw_frame();
                }
            }
            Body::PwLive { proof, deadline_ms } => {
                let result = (|| {
                    let a = cached.as_ref().ok_or("PW controller state unavailable")?;
                    let now = crate::engine::monotonic_ms().ok_or("PW controller clock absent")?;
                    // Fresh authenticated selection drives bounded retry; this
                    // receipt is type evidence only and grants no PW truth.
                    let _ = request_pw_storage(a);
                    crate::controller_pw::admit(a, proof, deadline_ms, now)
                })();
                if let Err(reason) = result {
                    crate::controller_pw::revoke();
                    return Err(reason);
                }
            }
            Body::Stop {} => {
                VEHICLE_DRIVE_PEDESTRIAN_WARNING_HIDE_ICON.store(false, Ordering::Release);
                crate::pw_storage_host::revoke();
                crate::controller_pw::revoke();
                SHARED.with(|s| {
                    s.stop_pending = true;
                    s.pending = Some(Command::Stop);
                });
                if vbc_controller_pw_pending() != 0 {
                    schedule_pw_frame();
                }
            }
            Body::Observe {} => crate::pw_storage_host::retry(),
            _ => return Err("unexpected startup IPC body".into()),
        }
        crate::net::write_frame(
            fd,
            &response(snapshot(), &daemon, controller, sequence, &secret)?,
        )?;
        sequence = crate::ipc::advance(sequence)?;
    }
}
fn process_identity(config: &Config) -> Result<ProcessIdentity> {
    if crate::fs::uid()? != 0 {
        return Err("startup OEM process must be root".into());
    }
    let executable = crate::elf::read(&config.expected_executable, 64 * 1024 * 1024)?;
    for b in &config.expected_build_ids {
        if !crate::elf::compatible(&b.path, &b.build_id) {
            return Err("startup OEM compatibility rejected".into());
        }
    }
    let controller = crate::nonce()?;
    let pid = unsafe { libc::getpid() } as u64;
    let process = ProcessIdentity {
        pid,
        birth_identity: crate::nonce()?,
        executable_sha256: voboost_contract_core::hash(&executable),
        endpoint_epoch: controller.clone(),
        lifecycle_generation: 1,
        supervisor: None,
    };
    crate::elf::process(pid, &config.expected_executable, &process.executable_sha256)?;
    Ok(process)
}
fn admitted_owner_config(
    config: &Config,
    executable: &str,
    roots: ProductRoots,
) -> Result<Option<Config>> {
    let role = crate::config::owner_role(executable)?;
    let authority = Authority::open_generation(config.clone(), crate::fs::uid()?, roots)?;
    let Some(generation) = authority.generation.as_ref() else {
        return Ok(None);
    };
    let selected = generation.selection.iter().any(|selected| {
        selected.process == role
            && generation.catalog.agents.iter().any(|agent| {
                agent.id == selected.id
                    && agent.targets.iter().any(|target| {
                        matches!(target, voboost_contract_core::catalog::Target::Native {
                            executable: path, ..
                        } if path == executable)
                            && target.process() == selected.process
                    })
            })
    });
    if !selected {
        return Err("actual OEM owner is not a signed selected native target".into());
    }
    let mut config = config.clone();
    if config.expected_executable != executable {
        let bytes = crate::elf::read(executable, 64 * 1024 * 1024)?;
        config.expected_build_ids.retain(|b| b.path != executable);
        config
            .expected_build_ids
            .push(voboost_contract_core::catalog::BuildIdentity {
                path: executable.into(),
                build_id: crate::elf::build_id(&bytes)?,
            });
        config
            .expected_build_ids
            .sort_by(|a, b| a.path.cmp(&b.path));
        config.expected_executable = executable.into();
    }
    config.validate()?;
    Ok(Some(config))
}

fn wait_for_owner_config(
    mut admit: impl FnMut() -> Result<Option<Config>>,
    mut sleep: impl FnMut(u32),
) -> Result<Config> {
    let mut delay_ms = 100;
    loop {
        sleep(delay_ms);
        if let Some(config) = admit()? {
            return Ok(config);
        }
        delay_ms = (delay_ms * 2).min(800);
    }
}
#[cfg(test)]
fn retained_plan(
    config: &Config,
    process: &ProcessIdentity,
    roots: ProductRoots,
) -> Result<Option<Plan>> {
    let authority = Authority::open(config.clone(), crate::fs::uid()?, roots)?;
    FONT_AUDIT.with(|audit| {
        if !matches!(&audit.context, Some((old, _)) if old == process) {
            audit.seen = 0;
        }
        audit.context = Some((process.clone(), authority.boot_id.clone()));
    });
    if authority.generation.is_none() || authority.desired.is_none() {
        return Ok(None);
    }
    plan(&authority, process).map(Some)
}
#[cfg(test)]
unsafe fn reconcile_startup(plan: Plan) -> Result<()> {
    apply(plan)?;
    // Applying desired intent only queues it. Reconcile before returning to OEM startup;
    // earlier dependency-constructor faces still require reload. ui_ready is false,
    // so UI-dependent agents must continue waiting for an original frame.
    let runtime = RUNTIME
        .load(Ordering::Acquire)
        .as_ref()
        .ok_or("startup runtime unavailable")?;
    runtime.update.ok_or("startup runtime update absent")?(noop as *mut c_void);
    Ok(())
}
struct Worker {
    config: Config,
    process: ProcessIdentity,
}
enum Startup {
    Ready(Worker),
    Waiting { config: Config, executable: String },
}
impl Startup {
    fn run(self) -> Result<()> {
        let worker = match self {
            Self::Ready(worker) => worker,
            Self::Waiting { config, executable } => {
                let config = wait_for_owner_config(
                    || admitted_owner_config(&config, &executable, ProductRoots::default()),
                    |delay_ms| unsafe {
                        libc::usleep(delay_ms * 1_000);
                    },
                )?;
                let process = process_identity(&config)?;
                // The service delivers the current intent over IPC. At this point
                // only the normal OEM callbacks may reconcile it on the UI thread.
                Worker { config, process }
            }
        };
        worker.run()
    }
}
impl Worker {
    fn run(self) -> Result<()> {
        let Worker { config, process } = self;
        let controller = &process.endpoint_epoch;
        let root = crate::fs::Dir::open(&config.root, 0)?;
        root.child("run")?;
        let listener = crate::net::unix_listen(&crate::config::owner_socket(
            &config.root,
            &config.expected_executable,
        )?)?;
        let boot_id =
            crate::fs::read_boot_identity(&config.boot_identity_file, &config.pair_id, 0)?;
        FONT_AUDIT.with(|audit| {
            audit.context = Some((process.clone(), boot_id));
        });
        let mut cached = None;
        loop {
            if vbc_controller_pw_pending() != 0 {
                schedule_pw_frame();
                if !crate::net::listener_ready(listener.0, 200)? {
                    continue;
                }
            }
            let fd = crate::net::accept(listener.0)?;
            let _ = session(fd.0, &config, &process, controller, &mut cached);
        }
    }
}
extern "C" fn thread(value: *mut c_void) -> *mut c_void {
    let startup = unsafe { Box::from_raw(value.cast::<Startup>()) };
    if let Err(reason) = startup.run() {
        crate::diagnostic_log::emit("error", "controller-worker", &reason, &[]);
    }
    core::ptr::null_mut()
}
/// # Safety
/// Path is a valid NUL-terminated startup environment string, bounded to512 bytes.
#[no_mangle]
pub unsafe extern "C" fn vbc_controller_start(path: *const c_char) -> i32 {
    if STARTED.swap(true, Ordering::AcqRel) {
        return -1;
    }
    let result = (|| {
        let path = string(path, 512)?;
        let config = Config::parse(&crate::fs::read_protected(&path, 0, 16384, 0o600)?)?;
        let _ = crate::diagnostic_ram::attach(&config.pair_id, 0);
        let executable = crate::elf::process_path(libc::getpid() as u64)?;
        let startup = match admitted_owner_config(&config, &executable, ProductRoots::default())? {
            Some(config) => {
                let process = process_identity(&config)?;
                Startup::Ready(Worker { config, process })
            }
            None => {
                crate::diagnostic_log::emit(
                    "info",
                    "controller-startup",
                    "Waiting for the signed native generation",
                    &[("executable", &executable)],
                );
                Startup::Waiting { config, executable }
            }
        };
        let raw = Box::into_raw(Box::new(startup));
        let mut tid = core::mem::zeroed();
        if libc::pthread_create(&mut tid, core::ptr::null(), thread, raw.cast()) != 0 {
            drop(Box::from_raw(raw));
            return Err(String::from("startup IPC worker unavailable"));
        }
        libc::pthread_detach(tid);
        Ok(())
    })();
    match result {
        Ok(()) => 0,
        Err(reason) => {
            crate::diagnostic_log::emit("error", "controller-startup", &reason, &[]);
            -1
        }
    }
}
#[cfg(test)]
pub(crate) fn actual_signed_pack_ffi_regression(
    first: crate::engine::OwnedPackLeaseInputs,
    next: impl FnMut() -> crate::engine::OwnedPackLeaseInputs,
) {
    let _guard = tests::TEST_LOCK.lock().unwrap();
    resources::actual_signed_ffi_regression(first, next);
}

#[cfg(test)]
pub(crate) fn actual_retained_disabled_intent_regression(authority: &Authority) {
    let _guard = tests::TEST_LOCK.lock().unwrap();
    let process = ProcessIdentity {
        pid: unsafe { libc::getpid() } as u64,
        birth_identity: "1".repeat(64),
        executable_sha256: "2".repeat(64),
        endpoint_epoch: "3".repeat(64),
        lifecycle_generation: 1,
        supervisor: None,
    };
    let admitted = plan(authority, &process).unwrap();
    let intent = disabled_resource_intent(&admitted).expect("actual signed disabled i18n intent");
    assert!(resources::retained_restart_required());
    SHARED.with(|shared| {
        shared.pending = Some(Command::Apply(Box::new(admitted)));
        shared.snapshot = Some(Snapshot {
            generation: Some(intent.generation.clone()),
            revision: intent.revision - 1,
            sha256: "6".repeat(64),
            rows: vec![ObservedAgent {
                id: "i18n-ru".into(),
                target_process: "gauge".into(),
                state: ObservedState::ReloadRequired,
                reason: "runtime desired rejected".into(),
                process: Some(process),
            }],
        });
    });
    let mut stale = intent.clone();
    stale.revision -= 1;
    stale.desired = "6".repeat(64);
    mark_retained_resource_restart(Some(&stale));
    SHARED.with(|shared| {
        assert_eq!(
            shared.snapshot.as_ref().unwrap().rows[0].reason,
            "runtime desired rejected"
        )
    });
    mark_retained_resource_restart(Some(&intent));
    SHARED.with(|shared| {
        assert_eq!(
            shared.snapshot.as_ref().unwrap().rows[0].reason,
            "private locale resource stop requires owner restart"
        );
        assert_eq!(
            shared.snapshot.as_ref().unwrap().revision,
            intent.revision - 1
        );
        shared.snapshot = None;
        shared.pending = None;
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn supervisor_stamp_is_optional_bounded_and_fresh_in_register_identity() {
        use super::*;
        let _guard = TEST_LOCK.lock().unwrap();
        let nonce = "a".repeat(64);
        assert_eq!(
            parse_supervisor(Some(nonce.as_bytes()), 42)
                .unwrap()
                .parent_pid,
            42
        );
        for parent in [0, 1, voboost_contract_core::MAX_SAFE_INTEGER + 1] {
            assert!(parse_supervisor(Some(nonce.as_bytes()), parent).is_none());
        }
        for invalid in ["", "A", &"a".repeat(65), &"G".repeat(64)] {
            assert!(parse_supervisor(Some(invalid.as_bytes()), 42).is_none());
        }
        assert!(parse_supervisor(None, 42).is_none());
        let process = ProcessIdentity {
            pid: 1,
            birth_identity: "1".repeat(64),
            executable_sha256: "2".repeat(64),
            endpoint_epoch: "3".repeat(64),
            lifecycle_generation: 1,
            supervisor: Some(voboost_contract_core::cluster::SupervisorObservation {
                nonce,
                parent_pid: u64::MAX,
            }),
        };
        let observed = fresh_process(&process);
        assert_eq!(observed.supervisor, fresh_supervisor());
        assert_ne!(observed.supervisor, process.supervisor);
        assert_eq!(observed.birth_identity, process.birth_identity);
        let original = SHARED.with(|s| {
            s.snapshot.replace(Snapshot {
                generation: None,
                revision: 1,
                sha256: "4".repeat(64),
                rows: vec![ObservedAgent {
                    id: "i18n-ru".into(),
                    target_process: "gauge".into(),
                    state: ObservedState::ReloadRequired,
                    reason: "private".into(),
                    process: Some(process.clone()),
                }],
            })
        });
        for _ in 0..2 {
            let Body::Snapshot { agents, .. } = snapshot() else {
                panic!("snapshot response required")
            };
            let reply = agents[0].process.as_ref().unwrap();
            assert_eq!(reply.supervisor, fresh_supervisor());
            assert_ne!(reply.supervisor, process.supervisor);
        }
        SHARED.with(|s| s.snapshot = original);
    }
    use super::*;
    use core::sync::atomic::AtomicU64;
    static STOPS: AtomicU64 = AtomicU64::new(0);
    pub(super) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    unsafe extern "C" fn stop() -> i32 {
        STOPS.fetch_add(1, Ordering::SeqCst);
        0
    }
    static TEST_RUNTIME: sdk::Runtime = sdk::Runtime {
        abi: 2,
        size: core::mem::size_of::<sdk::Runtime>() as u32,
        initialize: None,
        apply: None,
        init: None,
        update: None,
        data: None,
        stop: Some(stop),
    };
    #[test]
    fn font_readback_accepts_only_exact_oem_input_identities() {
        let semibold = "305f942097a1b65d1dca1c357c0197acf62346eea83e2fbe95cc55f62821f000";
        let regular = "b90b145194f1206b3d515e05d2bc2f27f2411aa0b6897f61755d7b812fe083c1";
        assert_eq!(font_identity(1644272, semibold), Some(1));
        assert_eq!(font_identity(1697868, regular), Some(2));
        assert_eq!(font_identity(1697868, semibold), None);
        assert_eq!(font_identity(1644272, regular), None);
        assert_eq!(font_identity(1644272, &"0".repeat(64)), None);
        assert_eq!(font_identity(0, semibold), None);
        // A failure never dereferences the FT buffers or emits success evidence.
        unsafe {
            vbc_controller_font_loaded(
                core::ptr::null(),
                1644272,
                core::ptr::null(),
                1644272,
                -1,
                1,
            );
        }
    }
    fn fixture_roots() -> ProductRoots {
        use ed25519_dalek::SigningKey;
        ProductRoots {
            catalog: SigningKey::from_bytes(&[11; 32]).verifying_key().to_bytes(),
            release: SigningKey::from_bytes(&[12; 32]).verifying_key().to_bytes(),
            executable: SigningKey::from_bytes(&[13; 32]).verifying_key().to_bytes(),
        }
    }
    #[test]
    fn startup_waits_for_signed_generation_then_reconstructs_desired_and_rejects_tampering() {
        use voboost_contract_core::{
            catalog::Domain,
            cluster::{DesiredAgent, Request, RequestKind},
            wire::{NetworkHeader, WireFile, WireRole},
        };
        let (_temp, config, roots, bytes, request, android) = crate::engine::tests::fixture();
        let process = ProcessIdentity {
            pid: 42,
            birth_identity: "1".repeat(64),
            executable_sha256: "2".repeat(64),
            endpoint_epoch: "3".repeat(64),
            lifecycle_generation: 1,
            supervisor: None,
        };
        assert!(retained_plan(&config, &process, fixture_roots())
            .unwrap()
            .is_none());
        let mut authority =
            Authority::open(config.clone(), crate::fs::uid().unwrap(), roots).unwrap();
        let envelope = request.sign(&android).unwrap();
        let mut files = vec![WireFile {
            role: WireRole::Request,
            file: "request.vbc".into(),
            size: envelope.len() as u64,
            sha256: voboost_contract_core::hash(&envelope),
        }];
        files.extend(request.files.clone().unwrap());
        let executable = &config.expected_executable;
        let admit = || admitted_owner_config(&config, executable, fixture_roots());
        assert!(admit().unwrap().is_none());
        let mut delays = Vec::new();
        let admitted = wait_for_owner_config(admit, |delay| {
            delays.push(delay);
            if delays.len() == 6 {
                authority
                    .import(
                        &envelope,
                        &NetworkHeader {
                            protocol_version: 1,
                            files: files.clone(),
                        },
                        &bytes,
                    )
                    .unwrap();
            }
        })
        .unwrap();
        assert_eq!(delays, [100, 200, 400, 800, 800, 800]);
        assert_eq!(admitted.expected_executable, *executable);
        assert!(admitted_owner_config(&config, "/usr/bin/light", fixture_roots()).is_err());
        for (revision, enabled) in [(2, true), (3, false)] {
            let agents = vec![DesiredAgent {
                id: "font-cyrillic".into(),
                enabled,
                options: BTreeMap::new(),
            }];
            let generation = authority.generation.as_ref().unwrap();
            let desired = Request {
                global_locale: None,
                schema_version: 1,
                kind: RequestKind::Desired,
                pair_id: config.pair_id.clone(),
                domain: Domain::Cluster,
                authority_epoch: config.authority_epoch.clone(),
                transaction_id: "9".repeat(64),
                catalog_sha256: generation.identity.catalog_sha256.clone(),
                closure_sha256: generation.identity.closure_sha256.clone(),
                challenge: "a".repeat(64),
                release_manifest_sha256: None,
                files: None,
                desired_revision: Some(revision),
                desired_sha256: Some(
                    voboost_contract_core::cluster::desired_digest(&agents).unwrap(),
                ),
                agents: Some(agents),
            };
            authority
                .admit_desired(&desired.sign(&android).unwrap())
                .unwrap();
            let desired = authority.desired.as_ref().unwrap();
            let generation = authority.generation.as_ref().unwrap();
            let projected = generation
                .agent_state_for(executable, &desired.agents)
                .unwrap();
            assert_eq!(projected, desired.agents);
            assert!(generation
                .agent_state_for("/usr/bin/light", &desired.agents)
                .unwrap()
                .is_empty());
            let mut receiver = Authority::open_generation(
                config.clone(),
                crate::fs::uid().unwrap(),
                fixture_roots(),
            )
            .unwrap();
            assert!(receiver.desired.is_none());
            let mut invalid = projected.clone();
            invalid[0].options.insert("undeclared".into(), "on".into());
            assert!(receive_agent_state(
                &mut receiver,
                revision,
                desired.desired_sha256.clone(),
                invalid,
            )
            .is_err());
            receive_agent_state(
                &mut receiver,
                revision,
                desired.desired_sha256.clone(),
                projected,
            )
            .unwrap();
            assert_eq!(
                super::plan(&receiver, &process).unwrap().modules[0].enabled,
                enabled
            );
            let plan = retained_plan(&config, &process, fixture_roots())
                .unwrap()
                .unwrap();
            assert_eq!(plan.revision, revision);
            assert_eq!(plan.modules.len(), 1);
            assert_eq!(plan.modules[0].enabled, enabled);
            assert_eq!(plan.rows[0].process, Some(process.clone()));
            assert_ne!(plan.rows[0].state, ObservedState::Applied);
        }
        let storage = authority.generation.as_ref().unwrap().storage_id.clone();
        authority
            .root
            .child("generations")
            .unwrap()
            .child(&storage)
            .unwrap()
            .write("libagent-font-cyrillic.so", b"tampered", 0o600)
            .unwrap();
        assert!(retained_plan(&config, &process, fixture_roots()).is_err());
        let mut attempts = 0;
        assert!(wait_for_owner_config(admit, |_| attempts += 1).is_err());
        assert_eq!(attempts, 1);
    }
    #[test]
    fn authenticated_local_stop_waits_for_original_ui_frame_and_rejects_replay() {
        let _guard = TEST_LOCK.lock().unwrap();
        let (_temp, config, _roots, _bytes, _request, _android) = crate::engine::tests::fixture();
        crate::fs::Dir::open(&config.root, crate::fs::uid().unwrap())
            .unwrap()
            .child("run")
            .unwrap();
        let path = crate::config::owner_socket(&config.root, &config.expected_executable).unwrap();
        let listener = crate::net::unix_listen(&path).unwrap();
        let process = ProcessIdentity {
            pid: 42,
            birth_identity: "1".repeat(64),
            executable_sha256: "2".repeat(64),
            endpoint_epoch: "3".repeat(64),
            lifecycle_generation: 1,
            supervisor: None,
        };
        let secret = crate::key(&config.ipc_secret).unwrap();
        let controller = process.endpoint_epoch.clone();
        let worker = std::thread::spawn(move || {
            let fd = crate::net::accept(listener.0).unwrap();
            session(fd.0, &config, &process, &controller, &mut None)
        });
        let fd = crate::net::unix_connect(&path).unwrap();
        let challenge: Challenge =
            voboost_contract_core::parse_canonical(&crate::net::read_frame(fd.0).unwrap(), 65536)
                .unwrap();
        let daemon = "4".repeat(64);
        let controller = challenge.controller_nonce;
        let hello = Message {
            schema_version: 1,
            daemon_nonce: daemon.clone(),
            controller_nonce: controller.clone(),
            direction: Direction::Request,
            sequence: 0,
            body: Body::Hello {},
        };
        crate::net::write_frame(fd.0, &hello.seal(&secret).unwrap()).unwrap();
        let register = Message::open(
            &crate::net::read_frame(fd.0).unwrap(),
            &secret,
            &daemon,
            &controller,
            Direction::Response,
            0,
        )
        .unwrap();
        assert!(matches!(register.body, Body::Register { .. }));
        RUNTIME.store(
            (&TEST_RUNTIME as *const sdk::Runtime).cast_mut(),
            Ordering::Release,
        );
        STOPS.store(0, Ordering::SeqCst);
        STOPPED.store(true, Ordering::Release);
        let stop = Message {
            schema_version: 1,
            daemon_nonce: daemon.clone(),
            controller_nonce: controller.clone(),
            direction: Direction::Request,
            sequence: 1,
            body: Body::Stop {},
        };
        let bytes = stop.seal(&secret).unwrap();
        crate::net::write_frame(fd.0, &bytes).unwrap();
        let response = Message::open(
            &crate::net::read_frame(fd.0).unwrap(),
            &secret,
            &daemon,
            &controller,
            Direction::Response,
            1,
        )
        .unwrap();
        assert!(
            matches!(response.body, Body::Snapshot { stopped: false, .. }),
            "an earlier stopped state cannot acknowledge a queued Stop"
        );
        assert_eq!(
            STOPS.load(Ordering::SeqCst),
            0,
            "IPC thread must not stop native UI"
        );
        unsafe {
            vbc_controller_frame();
        }
        assert_eq!(STOPS.load(Ordering::SeqCst), 1);
        assert!(matches!(snapshot(), Body::Snapshot { stopped: true, .. }));
        crate::net::write_frame(fd.0, &bytes).unwrap();
        assert!(
            worker.join().unwrap().is_err(),
            "old sequence must end session"
        );
        SHARED.with(|s| {
            s.pending = None;
            s.snapshot = None;
        });
        RUNTIME.store(core::ptr::null_mut(), Ordering::Release);
    }
    #[test]
    fn module_reconfiguration_preserves_shared_process_identity() {
        let _guard = TEST_LOCK.lock().unwrap();
        let owner = ProcessIdentity {
            pid: 42,
            birth_identity: "1".repeat(64),
            executable_sha256: "2".repeat(64),
            endpoint_epoch: "3".repeat(64),
            lifecycle_generation: 1,
            supervisor: None,
        };
        let original = SHARED.with(|shared| {
            shared.snapshot.replace(Snapshot {
                generation: Some("4".repeat(64)),
                revision: 8,
                sha256: "5".repeat(64),
                rows: ["i18n-ru", "vehicle-drive-pedestrian-warning"]
                    .iter()
                    .map(|id| ObservedAgent {
                        id: (*id).into(),
                        target_process: "light".into(),
                        state: ObservedState::WaitingUi,
                        reason: "waiting".into(),
                        process: Some(owner.clone()),
                    })
                    .collect(),
            })
        });
        for (id, lifecycle) in [(c"i18n-ru", 1), (c"vehicle-drive-pedestrian-warning", 3)] {
            let observation = sdk::Observation {
                size: core::mem::size_of::<sdk::Observation>() as u32,
                state: 5,
                id: id.as_ptr(),
                reason: c"applied".as_ptr(),
                revision: 8,
                lifecycle,
            };
            unsafe { report(core::ptr::null_mut(), &observation) };
        }
        let reported =
            SHARED.with(|shared| core::mem::replace(&mut shared.snapshot, original).unwrap());
        assert!(reported.rows.iter().all(|row| {
            row.state == ObservedState::Applied && row.process.as_ref() == Some(&owner)
        }));
    }

    #[test]
    fn duplicate_apply_preserves_observation_and_fences_changed_identity() {
        let _guard = TEST_LOCK.lock().unwrap();
        fn make_plan(revision: u64, pid: u64) -> Plan {
            let process = ProcessIdentity {
                pid,
                birth_identity: "1".repeat(64),
                executable_sha256: "2".repeat(64),
                endpoint_epoch: "3".repeat(64),
                lifecycle_generation: 1,
                supervisor: None,
            };
            Plan {
                packs: resources::Prepared::empty(),
                global_locale: None,
                global_locale_deadline_ms: 0,
                catalog: c(&"4".repeat(64)).unwrap(),
                generation: c(&"5".repeat(64)).unwrap(),
                desired: c(&if revision == 1 {
                    "6".repeat(64)
                } else {
                    "7".repeat(64)
                })
                .unwrap(),
                revision,
                runtime: c("/not-used-for-same-generation.so").unwrap(),
                modules: Vec::new(),
                rows: vec![ObservedAgent {
                    id: "cluster-vehicle-status-fuel".into(),
                    target_process: "gauge".into(),
                    state: ObservedState::WaitingProcess,
                    reason: "awaiting-ui-reconciliation".into(),
                    process: Some(process.clone()),
                }],
                process,
            }
        }
        unsafe extern "C" fn accept(_desired: *const sdk::Desired) -> i32 {
            0
        }
        static UPDATES: AtomicU64 = AtomicU64::new(0);
        unsafe extern "C" fn update(_original: *mut c_void) {
            UPDATES.fetch_add(1, Ordering::SeqCst);
        }
        let runtime = sdk::Runtime {
            abi: 2,
            size: core::mem::size_of::<sdk::Runtime>() as u32,
            initialize: None,
            apply: Some(accept),
            init: None,
            update: Some(update),
            data: None,
            stop: None,
        };
        let initial = make_plan(1, 42);
        let mut rows = initial.rows.clone();
        rows[0].state = ObservedState::Applied;
        rows[0].reason = "native-ui-readback".into();
        SHARED.with(|s| {
            s.snapshot = Some(Snapshot {
                generation: Some("5".repeat(64)),
                revision: 1,
                sha256: "6".repeat(64),
                rows,
            })
        });
        RUNTIME.store(
            (&runtime as *const sdk::Runtime).cast_mut(),
            Ordering::Release,
        );
        unsafe {
            (*UI.0.get()).generation = Some("5".repeat(64));
            apply(initial).unwrap();
        }
        SHARED.with(|s| {
            assert_eq!(
                s.snapshot.as_ref().unwrap().rows[0].state,
                ObservedState::Applied
            )
        });
        unsafe {
            UPDATES.store(0, Ordering::SeqCst);
            reconcile_startup(make_plan(2, 42)).unwrap();
            assert_eq!(
                UPDATES.load(Ordering::SeqCst),
                1,
                "retained desired must reconcile before the first OEM update"
            );
        }
        SHARED.with(|s| {
            let snapshot = s.snapshot.as_mut().unwrap();
            assert_eq!(snapshot.revision, 2);
            assert_eq!(snapshot.rows[0].state, ObservedState::WaitingProcess);
            snapshot.rows[0].state = ObservedState::Applied;
        });
        unsafe {
            apply(make_plan(2, 43)).unwrap();
        }
        SHARED.with(|s| {
            let snapshot = s.snapshot.as_ref().unwrap();
            assert_eq!(snapshot.rows[0].state, ObservedState::WaitingProcess);
            assert_eq!(snapshot.rows[0].process.as_ref().unwrap().pid, 43);
        });
        for field in 0..5 {
            SHARED.with(|s| s.snapshot.as_mut().unwrap().rows[0].state = ObservedState::Applied);
            let mut plan = make_plan(2, 43);
            match field {
                0 => plan.process.birth_identity = "8".repeat(64),
                1 => plan.process.executable_sha256 = "8".repeat(64),
                2 => plan.process.endpoint_epoch = "8".repeat(64),
                3 => plan.desired = c(&"8".repeat(64)).unwrap(),
                _ => plan.process.pid = 44,
            }
            plan.rows[0].process = Some(plan.process.clone());
            unsafe {
                apply(plan).unwrap();
            }
            SHARED.with(|s| {
                assert_eq!(
                    s.snapshot.as_ref().unwrap().rows[0].state,
                    ObservedState::WaitingProcess
                )
            });
        }
        SHARED.with(|s| {
            s.snapshot.as_mut().unwrap().rows[0].state = ObservedState::Applied;
            let mut plan = make_plan(2, 43);
            plan.generation = c(&"9".repeat(64)).unwrap();
            s.pending = Some(Command::Apply(Box::new(plan)));
        });
        unsafe {
            vbc_controller_frame();
        }
        SHARED.with(|s| {
            assert_eq!(
                s.snapshot.as_ref().unwrap().rows[0].state,
                ObservedState::ReloadRequired
            )
        });
        SHARED.with(|s| {
            s.pending = None;
            s.snapshot = None;
        });
        RUNTIME.store(core::ptr::null_mut(), Ordering::Release);
        unsafe {
            (*UI.0.get()).generation = None;
        }
    }

    #[test]
    fn private_resource_restart_reason_survives_only_matching_reload_bookkeeping() {
        let _guard = TEST_LOCK.lock().unwrap();
        let process = ProcessIdentity {
            pid: 1,
            birth_identity: "1".repeat(64),
            executable_sha256: "2".repeat(64),
            endpoint_epoch: "3".repeat(64),
            lifecycle_generation: 1,
            supervisor: None,
        };
        let reason = "private locale resource stop requires owner restart";
        SHARED.with(|shared| {
            shared.snapshot = Some(Snapshot {
                generation: Some("4".repeat(64)),
                revision: 3,
                sha256: "5".repeat(64),
                rows: ["i18n-ru", "pw"]
                    .into_iter()
                    .map(|id| ObservedAgent {
                        id: id.into(),
                        target_process: "gauge".into(),
                        state: ObservedState::ReloadRequired,
                        reason: reason.into(),
                        process: Some(process.clone()),
                    })
                    .collect(),
            })
        });
        mark_failure(ObservedState::ReloadRequired, "runtime desired rejected");
        SHARED.with(|shared| {
            let snapshot = shared.snapshot.as_ref().unwrap();
            assert_eq!(snapshot.rows[0].reason, reason);
            assert_eq!(snapshot.rows[1].reason, "runtime desired rejected");
            assert_eq!(snapshot.revision, 3); // Never relabel old active proof as new disabled intent.
        });
        mark_failure(ObservedState::Failed, "unrelated fatal error");
        SHARED.with(|shared| {
            assert!(shared
                .snapshot
                .as_ref()
                .unwrap()
                .rows
                .iter()
                .all(|r| r.reason == "unrelated fatal error"));
            shared.snapshot = None;
        });
    }

    #[test]
    fn retained_restart_rejects_no_pack_stale_intent_and_unrelated_reload() {
        let _guard = TEST_LOCK.lock().unwrap();
        let process = ProcessIdentity {
            pid: 1,
            birth_identity: "1".repeat(64),
            executable_sha256: "2".repeat(64),
            endpoint_epoch: "3".repeat(64),
            lifecycle_generation: 1,
            supervisor: None,
        };
        let intent = DisabledResourceIntent {
            generation: "4".repeat(64),
            revision: 3,
            desired: "5".repeat(64),
        };
        SHARED.with(|shared| {
            shared.pending = None;
            shared.snapshot = Some(Snapshot {
                generation: Some(intent.generation.clone()),
                revision: 2,
                sha256: "6".repeat(64),
                rows: vec![ObservedAgent {
                    id: "i18n-ru".into(),
                    target_process: "gauge".into(),
                    state: ObservedState::ReloadRequired,
                    reason: "unrelated font reload".into(),
                    process: Some(process),
                }],
            });
            assert!(restart_intent_matches(shared, &intent));
            let mut stale = intent.clone();
            stale.revision = 1;
            assert!(!restart_intent_matches(shared, &stale));
            let mut foreign = intent.clone();
            foreign.generation = "7".repeat(64);
            assert!(!restart_intent_matches(shared, &foreign));
            shared.pending = Some(Command::Stop);
            assert!(!restart_intent_matches(shared, &intent));
            shared.pending = None;
        });
        assert!(!resources::retained_restart_required());
        mark_retained_resource_restart(Some(&intent));
        SHARED.with(|shared| {
            assert_eq!(
                shared.snapshot.as_ref().unwrap().rows[0].reason,
                "unrelated font reload"
            );
            shared.snapshot = None;
        });
        mark_retained_resource_restart(None);
    }
}
