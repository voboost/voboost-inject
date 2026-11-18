//! Read-only OEM settings snapshots. No provider startup, schema migration or file creation.
use super::clock::Stamp;
use crate::native_api::Read;
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Snapshot {
    identity: String,
    fields: BTreeMap<String, u8>,
    service_running: bool,
}

enum Observation {
    ServicePresent(bool),
    Powertrain(Result<Option<&'static str>, String>),
    Snapshot(Stamp, io::Result<Snapshot>),
}

pub(super) struct Inputs {
    result: mpsc::Receiver<Observation>,
    request: mpsc::SyncSender<(bool, bool)>,
    snapshot: Option<Snapshot>,
    observed: Stamp,
    next: Instant,
    pending: bool,
    probe_powertrain: bool,
    bootstrap: bool,
    powertrain_error: Option<String>,
    error: Option<(String, bool)>,
    service_seen: bool,
    powertrain: Option<Option<&'static str>>,
    pub(super) fence: Arc<AtomicU64>,
}

impl Inputs {
    pub(super) fn start() -> io::Result<Self> {
        let (request, requests) = mpsc::sync_channel(1);
        let (results, result) = mpsc::sync_channel(3);
        std::thread::Builder::new()
            .name("voboost-inputs".into())
            .spawn(move || {
                let mut powertrain = None;
                let mut retry = Instant::now();
                while let Ok((probe, bootstrap)) = requests.recv() {
                    if let Ok(ready) = if bootstrap {
                        bootstrap_ready()
                    } else {
                        Ok(false)
                    } {
                        if results.send(Observation::ServicePresent(!ready)).is_err() {
                            break;
                        }
                    }
                    if probe && powertrain.is_none() && Instant::now() >= retry {
                        let profile_result = voboost_shared::vehicle_profile::cached_powertrain(
                            Path::new(crate::config::ROOT_ZONE),
                        )
                        .map_err(|error| format!("{error:#}"));
                        if let Ok(Some(value)) = profile_result.as_ref() {
                            powertrain = Some(*value);
                        }
                        retry = Instant::now() + Duration::from_secs(1);
                        if results
                            .send(Observation::Powertrain(profile_result))
                            .is_err()
                        {
                            break;
                        }
                    }
                    if results
                        .send(Observation::Snapshot(
                            Stamp::now(),
                            if bootstrap {
                                observe()
                            } else {
                                Err(io::Error::new(
                                    io::ErrorKind::Unsupported,
                                    "bootstrap transport completed",
                                ))
                            },
                        ))
                        .is_err()
                    {
                        break;
                    }
                }
            })?;
        Ok(Self {
            result,
            request,
            snapshot: None,
            observed: Stamp::now(),
            next: Instant::now(),
            pending: false,
            probe_powertrain: false,
            bootstrap: true,
            powertrain_error: None,
            error: None,
            service_seen: false,
            powertrain: None,
            fence: Arc::new(AtomicU64::new(0)),
        })
    }

    #[cfg(test)]
    pub(super) fn fixture(fields: BTreeMap<String, u8>) -> Self {
        let (_results, result) = mpsc::sync_channel(1);
        let (request, _requests) = mpsc::sync_channel(1);
        Self {
            result,
            request,
            snapshot: Some(Snapshot {
                identity: "fixture".into(),
                fields,
                service_running: false,
            }),
            observed: Stamp::now(),
            next: Instant::now(),
            pending: false,
            probe_powertrain: false,
            bootstrap: true,
            powertrain_error: None,
            error: None,
            service_seen: false,
            powertrain: None,
            fence: Arc::new(AtomicU64::new(1)),
        }
    }

    pub(super) fn invalidate(&mut self) {
        self.snapshot = None;
        self.fence.fetch_add(1, Ordering::AcqRel);
    }

    pub(super) fn poll(&mut self) {
        for _ in 0..3 {
            let Ok(observation) = self.result.try_recv() else {
                break;
            };
            match observation {
                Observation::ServicePresent(present) => {
                    self.service_seen |= present;
                }
                Observation::Powertrain(result) => self.observe_powertrain(result),
                Observation::Snapshot(captured_at, result) => {
                    self.pending = false;
                    let available = result.is_ok();
                    self.error = result
                        .as_ref()
                        .err()
                        .filter(|error| {
                            self.bootstrap && error.kind() != io::ErrorKind::Unsupported
                        })
                        .map(|error| (error.to_string(), transient(error)));
                    let snapshot = result.ok();
                    self.service_seen |= snapshot
                        .as_ref()
                        .is_some_and(|snapshot| snapshot.service_running);
                    if self.snapshot != snapshot {
                        self.fence.fetch_add(1, Ordering::AcqRel);
                    }
                    self.snapshot = snapshot;
                    self.observed = captured_at;
                    // Readiness is retried outside the owner poll, with a bounded scan rate.
                    self.next = self.observed.at
                        + if available {
                            Duration::from_millis(100)
                        } else if self.error.as_ref().is_some_and(|(_, expected)| *expected) {
                            Duration::from_millis(250)
                        } else {
                            Duration::from_secs(1)
                        };
                }
            }
        }
        if Instant::now() >= self.next && !self.pending && (self.bootstrap || self.probe_powertrain)
        {
            self.pending = self
                .request
                .try_send((self.probe_powertrain, self.bootstrap))
                .is_ok();
        }
        if !self.observed.fresh(Duration::from_secs(1)) && self.snapshot.take().is_some() {
            self.fence.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn observe_powertrain(&mut self, result: Result<Option<&'static str>, String>) {
        match result {
            Ok(value) => {
                self.powertrain_error = None;
                if self.powertrain != Some(value) {
                    self.fence.fetch_add(1, Ordering::AcqRel);
                }
                self.powertrain = Some(value);
            }
            Err(error) => {
                self.powertrain_error = Some(error);
            }
        }
    }

    pub(super) fn finish_bootstrap(&mut self) {
        if self.bootstrap {
            self.bootstrap = false;
            self.error = None;
            self.invalidate();
        }
    }
    pub(super) fn error(&self) -> Option<&(String, bool)> {
        self.error.as_ref()
    }

    pub(super) fn powertrain_error(&self) -> Option<&str> {
        self.powertrain_error.as_deref()
    }

    pub(super) fn service_seen(&self) -> bool {
        self.service_seen
    }

    pub(super) fn require_powertrain(&mut self, required: bool) {
        self.probe_powertrain = required;
    }

    pub(super) fn powertrain(&self) -> Option<Option<&'static str>> {
        self.powertrain
    }

    pub(super) fn observed(&self) -> Stamp {
        self.observed
    }

    pub(super) fn read(&self, fields: &[&str]) -> Read<Vec<u8>> {
        if self.service_seen || !self.observed.fresh(Duration::from_secs(1)) {
            return Read::Unavailable;
        }
        self.snapshot
            .as_ref()
            .and_then(|snapshot| {
                fields
                    .iter()
                    .map(|field| snapshot.fields.get(*field).copied())
                    .collect()
            })
            .map_or(Read::Unavailable, Read::Value)
    }
}

pub(super) fn transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::Interrupted
            | io::ErrorKind::TimedOut
    ) || matches!(error.raw_os_error(), Some(libc::ENODEV | libc::EAGAIN))
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "OEM settings snapshot unavailable",
    )
}

#[cfg(target_os = "android")]
pub(super) fn property(name: &str) -> io::Result<String> {
    unsafe extern "C" {
        fn __system_property_get(
            name: *const libc::c_char,
            value: *mut libc::c_char,
        ) -> libc::c_int;
    }
    let name = CString::new(name).map_err(|_| invalid())?;
    let mut value = [0 as libc::c_char; 92];
    let count = unsafe { __system_property_get(name.as_ptr(), value.as_mut_ptr()) };
    if !(0..92).contains(&count) {
        return Err(invalid());
    }
    unsafe { CStr::from_ptr(value.as_ptr()) }
        .to_str()
        .map(String::from)
        .map_err(|_| invalid())
}

#[cfg(not(target_os = "android"))]
pub(super) fn property(_: &str) -> io::Result<String> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "OEM properties require Android",
    ))
}

fn observe() -> io::Result<Snapshot> {
    let user = property("persist.sys.qg.userid")?;
    let multi = property("persist.sys.qg.multiuser")?;
    let account_path = Path::new("/private/configs/token/accountInfo");
    let account = bounded_account(account_path)?;
    let is_guest = guest(&account)?;
    let mut service_running = !bootstrap_ready()?;
    let path = resolve(&user, &multi)?;
    let before = database_identity(&path)?;
    let rows = read(&path)?;
    ensure_database_identity(&path, before)?;
    service_running |= !bootstrap_ready()?;
    if property("persist.sys.qg.userid")? != user
        || property("persist.sys.qg.multiuser")? != multi
        || bounded_account(account_path)? != account
        || resolve(&user, &multi)? != path
    {
        return Err(invalid());
    }
    let fields = boot_fields(&rows, is_guest)?;
    // Identity never leaves this private cache and is never logged.
    Ok(Snapshot {
        identity: format!("{user}\n{multi}\n{account}\n{}", path.display()),
        fields,
        service_running,
    })
}

fn boot_fields(
    rows: &BTreeMap<String, String>,
    is_guest: bool,
) -> io::Result<BTreeMap<String, u8>> {
    // OEM ACC2 chooses remembered settings by this scalar, not the current account file.
    let restore_guest = match rows.get("VehicleAccountInfo") {
        Some(value) => value.parse::<i32>().map_err(|_| invalid())? == 1,
        None => true,
    };
    let value = |key: &str, default: u8, max: u8| -> io::Result<u8> {
        let value = rows.get(key).map_or(Ok(default), |value| {
            value.parse::<u8>().map_err(|_| invalid())
        })?;
        if value > max {
            Err(invalid())
        } else {
            Ok(value)
        }
    };
    Ok(BTreeMap::from([
        (
            "EPS_MODE_SET".into(),
            if restore_guest {
                2
            } else {
                value("EPS_MODE_SET", 2, 3)?
            },
        ),
        ("DRIVING_MODE_RETAIN".into(), if is_guest { 1 } else { 2 }),
        (
            "PROP_MODE_SET".into(),
            if restore_guest {
                1
            } else {
                value("PROP_MODE_SET", 1, 3)?
            },
        ),
        (
            "HUM_TBOX_DAILY_REPEAT".into(),
            value("HUM_TBOX_DAILY_REPEAT", 0, 1)?,
        ),
    ]))
}

fn bounded_account(path: &Path) -> io::Result<String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                && path.parent().is_some_and(|parent| parent.is_dir()) =>
        {
            return Ok("guest".into())
        }
        Err(error) => return Err(error),
    };
    if !file.metadata()?.is_file() {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    file.by_ref().take(8193).read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        return Err(invalid());
    }
    let text = String::from_utf8(bytes).map_err(|_| invalid())?;
    Ok(text.lines().collect())
}

fn guest(account: &str) -> io::Result<bool> {
    if account == "guest" || account.is_empty() {
        return Ok(true);
    }
    let fields: Vec<_> = account.split('%').collect();
    if fields.len() < 5 || fields[4].parse::<i32>().is_err() {
        return Err(invalid());
    }
    Ok(false)
}

fn database_name(user: &str) -> String {
    if user.is_empty() {
        return "qinggan_settings.db".into();
    }
    let hash = user.encode_utf16().fold(0i32, |hash, value| {
        hash.wrapping_mul(31).wrapping_add(i32::from(value))
    });
    if hash == 0 {
        "qinggan_settings.db".into()
    } else {
        format!("qinggan_settings.db_{hash}")
    }
}

fn resolve(user: &str, multi: &str) -> io::Result<PathBuf> {
    let name = database_name(user);
    let candidates = match multi {
        "1" | "true" | "y" | "yes" | "on" => {
            vec![PathBuf::from("/private/database/com.qinggan.providers.settings").join(name)]
        }
        "" | "0" | "false" | "n" | "no" | "off" => ["/data/user/0", "/data/user_de/0"]
            .iter()
            .map(|root| {
                Path::new(root)
                    .join("com.qinggan.providers.settings/files/databases")
                    .join(&name)
            })
            .collect(),
        _ => return Err(invalid()),
    };
    let mut found = std::collections::BTreeSet::new();
    for candidate in candidates {
        match std::fs::canonicalize(candidate) {
            Ok(path) => {
                if std::fs::symlink_metadata(&path)?.is_file() {
                    found.insert(path);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    if found.len() != 1 {
        return Err(invalid());
    }
    Ok(found.into_iter().next().unwrap())
}

fn database_identity(path: &Path) -> io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > 16 * 1024 * 1024 {
        return Err(invalid());
    }
    Ok((metadata.dev(), metadata.ino()))
}

fn ensure_database_identity(path: &Path, before: (u64, u64)) -> io::Result<()> {
    if database_identity(path)? == before {
        Ok(())
    } else {
        Err(invalid())
    }
}

/// Bootstrap defaults are valid only before the OEM CAN service can mutate its command cache.
pub(super) fn bootstrap_ready() -> io::Result<bool> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    let mut count = 0;
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .is_none_or(|name| name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_digit()))
        {
            continue;
        }
        count += 1;
        if count > 8192 {
            return Err(invalid());
        }
        let path = entry.path();
        let metadata = match std::fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if can_service_process(metadata.uid(), || {
            let file = match std::fs::File::open(path.join("cmdline")) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error),
            };
            let mut bytes = Vec::new();
            file.take(4097).read_to_end(&mut bytes)?;
            Ok(Some(bytes))
        })? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn can_service_process(
    uid: u32,
    read: impl FnOnce() -> io::Result<Option<Vec<u8>>>,
) -> io::Result<bool> {
    // Both retained OEM manifests bind this package to android.uid.system.
    if uid != 1000 {
        return Ok(false);
    }
    let Some(bytes) = read()? else {
        return Ok(false);
    };
    if bytes.len() > 4096 {
        return Err(invalid());
    }
    Ok(bytes.split(|byte| *byte == 0).next() == Some(b"com.qinggan.canbus.service"))
}

type Callback = unsafe extern "C" fn(
    *mut libc::c_void,
    libc::c_int,
    *mut *mut libc::c_char,
    *mut *mut libc::c_char,
) -> libc::c_int;
struct Sqlite {
    library: *mut libc::c_void,
    open: unsafe extern "C" fn(
        *const libc::c_char,
        *mut *mut libc::c_void,
        libc::c_int,
        *const libc::c_char,
    ) -> libc::c_int,
    close: unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
    exec: unsafe extern "C" fn(
        *mut libc::c_void,
        *const libc::c_char,
        Option<Callback>,
        *mut libc::c_void,
        *mut *mut libc::c_char,
    ) -> libc::c_int,
    timeout: unsafe extern "C" fn(*mut libc::c_void, libc::c_int) -> libc::c_int,
    limit: unsafe extern "C" fn(*mut libc::c_void, libc::c_int, libc::c_int) -> libc::c_int,
}
impl Sqlite {
    fn load() -> io::Result<Self> {
        #[cfg(target_os = "android")]
        let path = c"/system/lib64/libsqlite.so";
        #[cfg(target_os = "macos")]
        let path = c"/usr/lib/libsqlite3.dylib";
        #[cfg(all(not(target_os = "android"), not(target_os = "macos")))]
        let path = c"libsqlite3.so.0";
        let library = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if library.is_null() {
            return Err(invalid());
        }
        unsafe fn symbol(library: *mut libc::c_void, name: &CStr) -> io::Result<*mut libc::c_void> {
            let symbol = unsafe { libc::dlsym(library, name.as_ptr()) };
            if symbol.is_null() {
                Err(invalid())
            } else {
                Ok(symbol)
            }
        }
        let result = (|| unsafe {
            Ok(Self {
                library,
                open: std::mem::transmute::<
                    *mut libc::c_void,
                    unsafe extern "C" fn(
                        *const libc::c_char,
                        *mut *mut libc::c_void,
                        libc::c_int,
                        *const libc::c_char,
                    ) -> libc::c_int,
                >(symbol(library, c"sqlite3_open_v2")?),
                close: std::mem::transmute::<
                    *mut libc::c_void,
                    unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
                >(symbol(library, c"sqlite3_close")?),
                exec: std::mem::transmute::<
                    *mut libc::c_void,
                    unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const libc::c_char,
                        Option<Callback>,
                        *mut libc::c_void,
                        *mut *mut libc::c_char,
                    ) -> libc::c_int,
                >(symbol(library, c"sqlite3_exec")?),
                timeout: std::mem::transmute::<
                    *mut libc::c_void,
                    unsafe extern "C" fn(*mut libc::c_void, libc::c_int) -> libc::c_int,
                >(symbol(library, c"sqlite3_busy_timeout")?),
                limit: std::mem::transmute::<
                    *mut libc::c_void,
                    unsafe extern "C" fn(
                        *mut libc::c_void,
                        libc::c_int,
                        libc::c_int,
                    ) -> libc::c_int,
                >(symbol(library, c"sqlite3_limit")?),
            })
        })();
        if result.is_err() {
            unsafe {
                libc::dlclose(library);
            }
        }
        result
    }
    fn query(&self, db: *mut libc::c_void, sql: &CStr) -> io::Result<Vec<Vec<String>>> {
        unsafe extern "C" fn row(
            out: *mut libc::c_void,
            count: libc::c_int,
            values: *mut *mut libc::c_char,
            _: *mut *mut libc::c_char,
        ) -> libc::c_int {
            let rows = unsafe { &mut *out.cast::<Vec<Vec<String>>>() };
            if rows.len() >= 32 || !(0..=6).contains(&count) {
                return 1;
            }
            let mut columns = Vec::new();
            for index in 0..count as usize {
                let value = unsafe { *values.add(index) };
                if value.is_null() {
                    return 1;
                }
                let value = unsafe { CStr::from_ptr(value) };
                if value.to_bytes().len() > 4096 {
                    return 1;
                }
                let Ok(value) = value.to_str() else {
                    return 1;
                };
                columns.push(value.into());
            }
            rows.push(columns);
            0
        }
        let mut rows = Vec::<Vec<String>>::new();
        if unsafe {
            (self.exec)(
                db,
                sql.as_ptr(),
                Some(row),
                (&mut rows as *mut Vec<Vec<String>>).cast(),
                std::ptr::null_mut(),
            )
        } != 0
        {
            return Err(invalid());
        }
        Ok(rows)
    }
}
impl Drop for Sqlite {
    fn drop(&mut self) {
        unsafe {
            libc::dlclose(self.library);
        }
    }
}

fn read(path: &Path) -> io::Result<BTreeMap<String, String>> {
    let api = Sqlite::load()?;
    let path = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| invalid())?;
    let mut db = std::ptr::null_mut();
    if unsafe { (api.open)(path.as_ptr(), &mut db, 1, std::ptr::null()) } != 0 {
        if !db.is_null() {
            unsafe {
                (api.close)(db);
            }
        }
        return Err(invalid());
    }
    let result = (|| {
        unsafe {
            (api.limit)(db, 0, 16384);
            (api.limit)(db, 1, 4096);
        }
        if unsafe { (api.timeout)(db, 10) } != 0 {
            return Err(invalid());
        }
        api.query(db, c"BEGIN")?;
        let schema = api.query(
            db,
            c"SELECT name,type FROM pragma_table_info('system') ORDER BY cid",
        )?;
        if schema
            != vec![
                vec!["_id".to_string(), "INTEGER".to_string()],
                vec!["name".to_string(), "TEXT".to_string()],
                vec!["value".to_string(), "TEXT".to_string()],
            ]
        {
            return Err(invalid());
        }
        let rows = api.query(db, c"SELECT name,hex(value),typeof(value) FROM system WHERE name IN ('EPS_MODE_SET','PROP_MODE_SET','HUM_TBOX_DAILY_REPEAT','VehicleAccountInfo')")?;
        let mut values = BTreeMap::new();
        for row in rows {
            if row.len() != 3 || row[2] != "text" {
                return Err(invalid());
            }
            let value = String::from_utf8(hex::decode(&row[1]).map_err(|_| invalid())?)
                .map_err(|_| invalid())?;
            if value.as_bytes().contains(&0) || values.insert(row[0].clone(), value).is_some() {
                return Err(invalid());
            }
        }
        api.query(db, c"COMMIT")?;
        Ok(values)
    })();
    if result.is_err() {
        let _ = api.query(db, c"ROLLBACK");
    }
    unsafe {
        (api.close)(db);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_scan_skips_unrelated_root_without_opening_its_cmdline() {
        for uid in [0, 1001, 10000] {
            assert!(!can_service_process(uid, || panic!("foreign cmdline opened")).unwrap());
        }
    }

    #[test]
    fn bootstrap_scan_keeps_unreadable_system_candidates_fail_closed() {
        assert_eq!(
            can_service_process(1000, || Err(io::ErrorKind::PermissionDenied.into()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(!can_service_process(1000, || Ok(None)).unwrap());
        assert!(!can_service_process(1000, || Ok(Some(b"other.service\0".to_vec()))).unwrap());
        assert!(can_service_process(1000, || {
            Ok(Some(b"com.qinggan.canbus.service\0argument\0".to_vec()))
        })
        .unwrap());
        assert!(!can_service_process(1000, || {
            Ok(Some(b"com.qinggan.canbus.service:other\0".to_vec()))
        })
        .unwrap());
        assert!(can_service_process(1000, || Ok(Some(vec![0; 4097]))).is_err());
    }

    #[test]
    fn unavailable_snapshot_backs_off_inventory_without_admitting_bootstrap() {
        let (results, result) = mpsc::sync_channel(1);
        let (request, requests) = mpsc::sync_channel(1);
        let captured = Stamp::now();
        results
            .send(Observation::Snapshot(
                captured,
                Err(io::ErrorKind::PermissionDenied.into()),
            ))
            .unwrap();
        let mut inputs = Inputs::fixture(BTreeMap::new());
        inputs.result = result;
        inputs.request = request;
        inputs.pending = true;
        inputs.poll();
        assert_eq!(inputs.next, captured.at + Duration::from_secs(1));
        assert!(inputs.snapshot.is_none());
        assert_eq!(inputs.read(&["EPS_MODE_SET"]), Read::Unavailable);
        assert!(requests.try_recv().is_err());
    }

    #[test]
    fn pending_input_observation_never_blocks_poll_and_recovers_after_retry() {
        let (results, result) = mpsc::sync_channel(3);
        let (request, requests) = mpsc::sync_channel(1);
        let mut inputs = Inputs::fixture(BTreeMap::new());
        inputs.result = result;
        inputs.request = request;
        inputs.poll();
        assert!(requests.try_recv().is_ok());
        let started = Instant::now();
        for _ in 0..100 {
            inputs.poll();
        }
        assert!(started.elapsed() < Duration::from_millis(100));
        assert!(requests.try_recv().is_err());
        results
            .send(Observation::Snapshot(
                Stamp::now(),
                Err(io::ErrorKind::WouldBlock.into()),
            ))
            .unwrap();
        inputs.poll();
        assert_eq!(inputs.read(&["EPS_MODE_SET"]), Read::Unavailable);
        assert!(requests.try_recv().is_err());
        inputs.next = Instant::now();
        inputs.poll();
        assert!(requests.try_recv().is_ok());
        results
            .send(Observation::Snapshot(
                Stamp::now(),
                Ok(Snapshot {
                    identity: "fixture-ready".into(),
                    fields: BTreeMap::from([("EPS_MODE_SET".into(), 2)]),
                    service_running: false,
                }),
            ))
            .unwrap();
        inputs.poll();
        assert_eq!(inputs.read(&["EPS_MODE_SET"]), Read::Value(vec![2]));
    }

    fn fixture(sql: &CStr) -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::Builder::new()
            .prefix("native-inputs-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap();
        let path = root.path().join("settings.db");
        let api = Sqlite::load().unwrap();
        let name = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        let mut db = std::ptr::null_mut();
        assert_eq!(
            unsafe { (api.open)(name.as_ptr(), &mut db, 6, std::ptr::null()) },
            0
        );
        api.query(db, sql).unwrap();
        assert_eq!(unsafe { (api.close)(db) }, 0);
        (root, path)
    }

    #[test]
    fn read_only_snapshot_probes_schema_and_retains_distinct_missing_keys() {
        let (_root, path) = fixture(c"CREATE TABLE system(_id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT UNIQUE ON CONFLICT REPLACE,value TEXT); INSERT INTO system(name,value) VALUES('EPS_MODE_SET','3'),('HUM_TBOX_DAILY_REPEAT','1')");
        let before = std::fs::read(&path).unwrap();
        let rows = read(&path).unwrap();
        assert_eq!(rows.get("EPS_MODE_SET").map(String::as_str), Some("3"));
        assert!(!rows.contains_key("PROP_MODE_SET"));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1
        );
    }

    #[test]
    fn read_only_snapshot_rejects_wrong_schema_duplicate_and_null_values() {
        for sql in [
            c"CREATE TABLE system(name TEXT,value TEXT)",
            c"CREATE TABLE system(_id INTEGER,name TEXT,value TEXT); INSERT INTO system VALUES(1,'EPS_MODE_SET','1'),(2,'EPS_MODE_SET','2')",
            c"CREATE TABLE system(_id INTEGER,name TEXT,value TEXT); INSERT INTO system VALUES(1,'EPS_MODE_SET',NULL)",
            c"CREATE TABLE system(_id INTEGER,name TEXT,value TEXT); INSERT INTO system VALUES(1,'EPS_MODE_SET','1'||char(0)||'junk')",
        ] {
            let (_root, path) = fixture(sql);
            assert!(read(&path).is_err());
        }
    }

    #[test]
    fn powertrain_probe_error_does_not_become_an_unknown_success() {
        let mut inputs = Inputs::fixture(BTreeMap::new());
        inputs.observe_powertrain(Err("probe failed".into()));
        assert_eq!(inputs.powertrain(), None);
        assert_eq!(inputs.powertrain_error(), Some("probe failed"));
        inputs.observe_powertrain(Ok(None));
        assert_eq!(inputs.powertrain(), Some(None));
        assert_eq!(inputs.powertrain_error(), None);
        inputs.observe_powertrain(Ok(Some("hybrid")));
        assert_eq!(inputs.powertrain(), Some(Some("hybrid")));
        assert_eq!(inputs.powertrain_error(), None);
        inputs.observe_powertrain(Err("probe failed again".into()));
        assert_eq!(inputs.powertrain(), Some(Some("hybrid")));
        assert_eq!(inputs.powertrain_error(), Some("probe failed again"));
    }

    #[test]
    fn custom_user_uses_java_utf16_hash_and_malformed_account_is_not_guest() {
        assert_eq!(database_name(""), "qinggan_settings.db");
        assert_eq!(database_name("abc"), "qinggan_settings.db_96354");
        assert_eq!(database_name("😀"), "qinggan_settings.db_1772899");
        assert!(guest("guest").unwrap());
        assert!(!guest("n%p%1%a%12").unwrap());
        assert!(guest("broken").is_err());
        assert!(guest("n%p%1%a%not-a-number").is_err());
    }
    #[test]
    fn queued_old_snapshot_is_not_refreshed_when_owner_receives_it() {
        let (results, result) = mpsc::sync_channel(1);
        let (request, _requests) = mpsc::sync_channel(1);
        let old = Stamp {
            at: Instant::now() - Duration::from_secs(2),
            boot_ms: crate::startup::boot_ms()
                .ok()
                .and_then(|now| now.checked_sub(2000)),
        };
        results
            .send(Observation::Snapshot(
                old,
                Ok(Snapshot {
                    identity: "fixture".into(),
                    fields: BTreeMap::from([("EPS_MODE_SET".into(), 3)]),
                    service_running: false,
                }),
            ))
            .unwrap();
        let mut inputs = Inputs {
            result,
            request,
            snapshot: None,
            observed: Stamp::now(),
            next: Instant::now(),
            pending: true,
            probe_powertrain: false,
            bootstrap: true,
            powertrain_error: None,
            error: None,
            service_seen: false,
            powertrain: None,
            fence: Arc::new(AtomicU64::new(1)),
        };
        inputs.poll();
        assert_eq!(inputs.read(&["EPS_MODE_SET"]), Read::Unavailable);
        assert!(inputs.snapshot.is_none());
    }

    #[test]
    fn wal_read_observes_committed_rows_without_checkpoint_or_database_write() {
        let (_root, path) = fixture(c"CREATE TABLE system(_id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT UNIQUE ON CONFLICT REPLACE,value TEXT)");
        let api = Sqlite::load().unwrap();
        let name = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        let mut db = std::ptr::null_mut();
        assert_eq!(
            unsafe { (api.open)(name.as_ptr(), &mut db, 2, std::ptr::null()) },
            0
        );
        api.query(db, c"PRAGMA journal_mode=WAL").unwrap();
        api.query(
            db,
            c"INSERT INTO system(name,value) VALUES('EPS_MODE_SET','3')",
        )
        .unwrap();
        let before = std::fs::read(&path).unwrap();
        assert_eq!(
            read(&path).unwrap().get("EPS_MODE_SET").map(String::as_str),
            Some("3")
        );
        api.query(
            db,
            c"BEGIN; UPDATE system SET value='1' WHERE name='EPS_MODE_SET'",
        )
        .unwrap();
        assert_eq!(
            read(&path).unwrap().get("EPS_MODE_SET").map(String::as_str),
            Some("3")
        );
        api.query(db, c"ROLLBACK").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(unsafe { (api.close)(db) }, 0);
    }
    #[test]
    fn same_path_database_replacement_cannot_keep_the_old_inode_authority() {
        let (root, path) = fixture(c"CREATE TABLE system(_id INTEGER,name TEXT,value TEXT)");
        let before = database_identity(&path).unwrap();
        let replacement = root.path().join("replacement.db");
        std::fs::write(&replacement, std::fs::read(&path).unwrap()).unwrap();
        std::fs::rename(replacement, &path).unwrap();
        assert!(ensure_database_identity(&path, before).is_err());
    }
    #[test]
    fn guest_boot_defaults_are_not_reused_after_the_oem_service_is_observed() {
        let rows = BTreeMap::from([
            ("EPS_MODE_SET".into(), "3".into()),
            ("PROP_MODE_SET".into(), "2".into()),
        ]);
        let boot = boot_fields(&rows, true).unwrap();
        assert_eq!(boot.get("EPS_MODE_SET"), Some(&2));
        assert_eq!(boot.get("PROP_MODE_SET"), Some(&1));
        let mut inputs = Inputs::fixture(boot);
        assert_eq!(inputs.read(&["EPS_MODE_SET"]), Read::Value(vec![2]));
        inputs.service_seen = true;
        assert_eq!(inputs.read(&["EPS_MODE_SET"]), Read::Unavailable);
        inputs.snapshot.as_mut().unwrap().service_running = false;
        assert_eq!(inputs.read(&["EPS_MODE_SET"]), Read::Unavailable);
        let mut rows = rows;
        rows.insert("VehicleAccountInfo".into(), "2".into());
        let login = boot_fields(&rows, false).unwrap();
        assert_eq!(login.get("EPS_MODE_SET"), Some(&3));
        assert_eq!(login.get("PROP_MODE_SET"), Some(&2));
    }
    #[test]
    fn acc_restore_flag_and_current_account_have_distinct_startup_authority() {
        let mut rows = BTreeMap::from([
            ("VehicleAccountInfo".into(), "1".into()),
            ("EPS_MODE_SET".into(), "3".into()),
            ("PROP_MODE_SET".into(), "2".into()),
        ]);
        let logged_in_now = boot_fields(&rows, false).unwrap();
        assert_eq!(logged_in_now.get("EPS_MODE_SET"), Some(&2));
        assert_eq!(logged_in_now.get("PROP_MODE_SET"), Some(&1));
        assert_eq!(logged_in_now.get("DRIVING_MODE_RETAIN"), Some(&2));
        rows.insert("VehicleAccountInfo".into(), "2".into());
        let guest_now = boot_fields(&rows, true).unwrap();
        assert_eq!(guest_now.get("EPS_MODE_SET"), Some(&3));
        assert_eq!(guest_now.get("PROP_MODE_SET"), Some(&2));
        assert_eq!(guest_now.get("DRIVING_MODE_RETAIN"), Some(&1));
    }
}
