//! Matching original OpenSSL server APIs; transport identity never grants intent.
use crate::{fs::Fd, Result};
use alloc::{ffi::CString, format, sync::Arc, vec, vec::Vec};
use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};
type P = *mut c_void;
#[derive(Clone)]
pub struct Api {
    _ssl: P,
    _crypto: P,
    method: unsafe extern "C" fn() -> *const c_void,
    ctx_new: unsafe extern "C" fn(*const c_void) -> P,
    ctx_free: unsafe extern "C" fn(P),
    ctx_ctrl: unsafe extern "C" fn(P, c_int, c_long, P) -> c_long,
    ctx_param: unsafe extern "C" fn(P) -> P,
    param_flags: unsafe extern "C" fn(P, c_ulong) -> c_int,
    verify: unsafe extern "C" fn(P, c_int, P),
    ca: unsafe extern "C" fn(P, *const c_char, *const c_char) -> c_int,
    cert: unsafe extern "C" fn(P, *const c_char) -> c_int,
    key: unsafe extern "C" fn(P, *const c_char, c_int) -> c_int,
    check_key: unsafe extern "C" fn(P) -> c_int,
    new: unsafe extern "C" fn(P) -> P,
    free: unsafe extern "C" fn(P),
    set_fd: unsafe extern "C" fn(P, c_int) -> c_int,
    accept: unsafe extern "C" fn(P) -> c_int,
    read: unsafe extern "C" fn(P, P, c_int) -> c_int,
    write: unsafe extern "C" fn(P, *const c_void, c_int) -> c_int,
    verify_result: unsafe extern "C" fn(P) -> c_long,
    get_error: unsafe extern "C" fn(P, c_int) -> c_int,
    err_get_error: unsafe extern "C" fn() -> c_ulong,
    peer: unsafe extern "C" fn(P) -> P,
    x509_free: unsafe extern "C" fn(P),
    digest: unsafe extern "C" fn(P, *const c_void, *mut u8, *mut u32) -> c_int,
    sha256: unsafe extern "C" fn() -> *const c_void,
}
fn symbol<T: Copy>(library: P, name: &str) -> Result<T> {
    let c = CString::new(name).map_err(|_| "TLS symbol NUL")?;
    let p = unsafe { libc::dlsym(library, c.as_ptr()) };
    if p.is_null() || core::mem::size_of::<T>() != core::mem::size_of::<P>() {
        return Err("matching original TLS export unavailable".into());
    }
    Ok(unsafe { core::mem::transmute_copy(&p) })
}
impl Api {
    pub fn load(ssl: &str, crypto: &str) -> Result<Self> {
        let s = CString::new(ssl).map_err(|_| "SSL library NUL")?;
        let c = CString::new(crypto).map_err(|_| "crypto library NUL")?;
        let crypto = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL) };
        let ssl = unsafe { libc::dlopen(s.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if ssl.is_null() || crypto.is_null() {
            return Err("matching original TLS libraries unavailable".into());
        }
        let init: unsafe extern "C" fn(u64, P) -> c_int = symbol(ssl, "OPENSSL_init_ssl")?;
        if unsafe { init(0, core::ptr::null_mut()) } != 1 {
            return Err("TLS initialization failed".into());
        }
        let peer = symbol(ssl, "SSL_get_peer_certificate")
            .or_else(|_| symbol(ssl, "SSL_get1_peer_certificate"))?;
        Ok(Self {
            _ssl: ssl,
            _crypto: crypto,
            method: symbol(ssl, "TLS_server_method")?,
            ctx_new: symbol(ssl, "SSL_CTX_new")?,
            ctx_free: symbol(ssl, "SSL_CTX_free")?,
            ctx_ctrl: symbol(ssl, "SSL_CTX_ctrl")?,
            ctx_param: symbol(ssl, "SSL_CTX_get0_param")?,
            param_flags: symbol(crypto, "X509_VERIFY_PARAM_set_flags")?,
            verify: symbol(ssl, "SSL_CTX_set_verify")?,
            ca: symbol(ssl, "SSL_CTX_load_verify_locations")?,
            cert: symbol(ssl, "SSL_CTX_use_certificate_chain_file")?,
            key: symbol(ssl, "SSL_CTX_use_PrivateKey_file")?,
            check_key: symbol(ssl, "SSL_CTX_check_private_key")?,
            new: symbol(ssl, "SSL_new")?,
            free: symbol(ssl, "SSL_free")?,
            set_fd: symbol(ssl, "SSL_set_fd")?,
            accept: symbol(ssl, "SSL_accept")?,
            read: symbol(ssl, "SSL_read")?,
            write: symbol(ssl, "SSL_write")?,
            verify_result: symbol(ssl, "SSL_get_verify_result")?,
            get_error: symbol(ssl, "SSL_get_error")?,
            err_get_error: symbol(crypto, "ERR_get_error")?,
            peer,
            x509_free: symbol(crypto, "X509_free")?,
            digest: symbol(crypto, "X509_digest")?,
            sha256: symbol(crypto, "EVP_sha256")?,
        })
    }
    pub fn original() -> Result<Self> {
        Self::load("libssl1_1.so.2.1", "libcrypto1_1.so.2.1")
    }
    pub fn server(self, config: &crate::config::Tls) -> Result<Arc<Server>> {
        // Keep certificate/key paths immutable under the same protected-root policy
        // used by the bootfile before passing them to OpenSSL's ordinary file APIs.
        for path in [
            &config.server_certificate,
            &config.server_private_key,
            &config.client_ca,
        ] {
            crate::fs::read_protected(path, crate::fs::uid()?, 65536, 0o600)?;
        }
        let ctx = unsafe { (self.ctx_new)((self.method)()) };
        if ctx.is_null() {
            return Err("TLS context allocation failed".into());
        }
        let server = Server {
            api: self,
            ctx,
            pin: config.client_certificate_sha256.clone(),
        };
        let ca = CString::new(config.client_ca.as_str()).map_err(|_| "TLS path")?;
        let cert = CString::new(config.server_certificate.as_str()).map_err(|_| "TLS path")?;
        let key = CString::new(config.server_private_key.as_str()).map_err(|_| "TLS path")?;
        unsafe {
            (server.api.verify)(ctx, 3, core::ptr::null_mut());
        }
        // The trust store contains the paired client leaf, not a CA chain.
        // OpenSSL 1.1 needs PARTIAL_CHAIN to treat that exact leaf as an anchor.
        let param = unsafe { (server.api.ctx_param)(ctx) };
        if param.is_null() || unsafe { (server.api.param_flags)(param, 0x80000) } != 1 {
            return Err("native mTLS trust configuration rejected".into());
        }
        // OpenSSL 1.1 SSL_CTRL_SET_MIN_PROTO_VERSION and TLS1_2_VERSION.
        if unsafe { (server.api.ctx_ctrl)(ctx, 123, 0x0303, core::ptr::null_mut()) } != 1
            || unsafe { (server.api.ca)(ctx, ca.as_ptr(), core::ptr::null()) } != 1
            || unsafe { (server.api.cert)(ctx, cert.as_ptr()) } != 1
            || unsafe { (server.api.key)(ctx, key.as_ptr(), 1) } != 1
            || unsafe { (server.api.check_key)(ctx) } != 1
        {
            return Err("native mTLS configuration rejected".into());
        }
        Ok(Arc::new(server))
    }
}
pub struct Server {
    api: Api,
    ctx: P,
    pin: alloc::string::String,
}
// OpenSSL 1.1 synchronizes access to the configured context. Rust never
// changes its trust/key/verification settings after publishing this server.
unsafe impl Send for Server {}
unsafe impl Sync for Server {}

impl Drop for Server {
    fn drop(&mut self) {
        unsafe {
            (self.api.ctx_free)(self.ctx);
        }
    }
}
impl Server {
    #[cfg(test)]
    pub fn accept(self: &Arc<Self>, fd: Fd) -> Result<Stream> {
        self.accept_inner(fd, None)
    }

    pub(crate) fn accept_first_frame(
        self: &Arc<Self>,
        fd: Fd,
        deadline: u64,
    ) -> Result<(Stream, Vec<u8>)> {
        let stream = self.accept_inner(fd, Some(deadline))?;
        let first = stream.frame_before(deadline, 65536)?;
        Ok((stream, first))
    }

    fn accept_inner(self: &Arc<Self>, fd: Fd, deadline: Option<u64>) -> Result<Stream> {
        let request_deadline = crate::engine::monotonic_ms()
            .and_then(|now| now.checked_add(voboost_contract_core::wire::LEASE_MILLIS))
            .ok_or("TLS request clock unavailable")?;
        let flags = unsafe { libc::fcntl(fd.0, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd.0, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err("TLS nonblocking mode unavailable".into());
        }
        let ssl = unsafe { (self.api.new)(self.ctx) };
        if ssl.is_null() {
            return Err("TLS connection allocation failed".into());
        }
        let stream = Stream {
            server: self.clone(),
            ssl,
            _fd: fd,
            deadline: request_deadline,
        };
        // Each stage is reported separately: a collapsed message cannot tell a
        // rejected chain from an absent client certificate or a socket failure.
        if unsafe { (self.api.set_fd)(ssl, stream._fd.0) } != 1 {
            return Err("mTLS socket binding failed".into());
        }
        let deadline = deadline.unwrap_or(request_deadline).min(request_deadline);
        loop {
            stream.remaining(deadline)?;
            let resumed = unsafe { (self.api.accept)(ssl) };
            if resumed == 1 {
                break;
            }
            let code = unsafe { (self.api.get_error)(ssl, resumed) };
            if code == 2 || code == 3 {
                stream.wait_for_tls(code, deadline)?;
                continue;
            }
            return Err(format!(
                "mTLS handshake failed: ssl_error={} verify_result={} err=0x{:x}",
                code,
                unsafe { (self.api.verify_result)(ssl) },
                unsafe { (self.api.err_get_error)() }
            ));
        }
        let verified = unsafe { (self.api.verify_result)(ssl) };
        if verified != 0 {
            return Err(format!("mTLS peer verification failed: code={verified}"));
        }
        let peer = unsafe { (self.api.peer)(ssl) };
        if peer.is_null() {
            return Err("mTLS peer certificate missing".into());
        }
        let mut bytes = [0; 32];
        let mut n = 0;
        let ok =
            unsafe { (self.api.digest)(peer, (self.api.sha256)(), bytes.as_mut_ptr(), &mut n) };
        unsafe {
            (self.api.x509_free)(peer);
        }
        if ok != 1 || n != 32 || hex::encode(bytes) != self.pin {
            return Err("mTLS paired client pin rejected".into());
        }
        Ok(stream)
    }
}
pub struct Stream {
    server: Arc<Server>,
    ssl: P,
    _fd: Fd,
    // One monotonic budget covers handshake, envelope, every artifact and reply.
    // Receiving another fragment or entering another IO method never renews it.
    deadline: u64,
}
// Each SSL connection and fd transfer to exactly one owner after ingress.
unsafe impl Send for Stream {}

impl Drop for Stream {
    fn drop(&mut self) {
        unsafe {
            (self.server.api.free)(self.ssl);
        }
    }
}
impl Stream {
    fn remaining(&self, deadline: u64) -> Result<u64> {
        let now = crate::engine::monotonic_ms().ok_or("TLS monotonic clock unavailable")?;
        deadline
            .min(self.deadline)
            .checked_sub(now)
            .filter(|ms| *ms > 0)
            .ok_or_else(|| "TLS absolute deadline".into())
    }

    pub(crate) fn check_deadline(&self) -> Result<()> {
        self.remaining(self.deadline).map(|_| ())
    }

    fn wait_for_tls(&self, code: i32, deadline: u64) -> Result<()> {
        loop {
            let remaining = self.remaining(deadline)?;
            let mut ready = libc::pollfd {
                fd: self._fd.0,
                events: if code == 2 {
                    libc::POLLIN
                } else {
                    libc::POLLOUT
                },
                revents: 0,
            };
            let result =
                unsafe { libc::poll(&mut ready, 1, remaining.min(i32::MAX as u64) as i32) };
            if result < 0 && crate::fs::errno() == libc::EINTR {
                continue;
            }
            self.remaining(deadline)?;
            if result <= 0 || ready.revents & ready.events == 0 {
                return Err("TLS readiness failed before absolute deadline".into());
            }
            return Ok(());
        }
    }

    fn read_before(&self, mut bytes: &mut [u8], deadline: u64) -> Result<()> {
        while !bytes.is_empty() {
            self.remaining(deadline)?;
            let n = unsafe {
                (self.server.api.read)(
                    self.ssl,
                    bytes.as_mut_ptr().cast(),
                    bytes.len().min(i32::MAX as usize) as i32,
                )
            };
            if n > 0 {
                self.remaining(deadline)?;
                bytes = &mut bytes[n as usize..];
            } else {
                let code = unsafe { (self.server.api.get_error)(self.ssl, n) };
                if code != 2 && code != 3 {
                    return Err("TLS deadline read failed".into());
                }
                self.wait_for_tls(code, deadline)?;
            }
        }
        Ok(())
    }

    pub fn frame_before(&self, deadline: u64, maximum: usize) -> Result<Vec<u8>> {
        if maximum == 0 || maximum > 65536 {
            return Err("TLS frame maximum invalid".into());
        }
        let mut size = [0u8; 4];
        self.read_before(&mut size, deadline)?;
        let size = u32::from_be_bytes(size) as usize;
        if size == 0 || size > maximum {
            return Err("TLS deadline frame bound".into());
        }
        let mut bytes = vec![0u8; size];
        self.read_before(&mut bytes, deadline)?;
        Ok(bytes)
    }
    pub fn write_frame_before(&self, bytes: &[u8], deadline: u64) -> Result<()> {
        let frame = voboost_contract_core::wire::frame(bytes)?;
        self.write_before(&frame, deadline)
    }
    fn write_before(&self, mut bytes: &[u8], deadline: u64) -> Result<()> {
        while !bytes.is_empty() {
            self.remaining(deadline)?;
            let length = bytes.len().min(i32::MAX as usize);
            let n =
                unsafe { (self.server.api.write)(self.ssl, bytes.as_ptr().cast(), length as i32) };
            // Our context does not enable SSL_MODE_ENABLE_PARTIAL_WRITE. Do
            // not move the buffer/length while retrying WANT_READ/WANT_WRITE.
            if n <= 0 {
                let code = unsafe { (self.server.api.get_error)(self.ssl, n) };
                if code == 2 || code == 3 {
                    self.wait_for_tls(code, deadline)?;
                    continue;
                }
                return Err("TLS deadline write failed".into());
            }
            if n as usize != length {
                return Err("TLS unexpected partial write".into());
            }
            self.remaining(deadline)?;
            bytes = &bytes[n as usize..];
        }
        Ok(())
    }
    pub fn read_exact(&self, bytes: &mut [u8]) -> Result<()> {
        self.read_before(bytes, self.deadline)
    }
    pub fn write_all(&self, bytes: &[u8]) -> Result<()> {
        self.write_before(bytes, self.deadline)
    }
    pub fn frame(&self) -> Result<Vec<u8>> {
        self.frame_before(self.deadline, 65536)
    }
    pub fn write_frame(&self, b: &[u8]) -> Result<()> {
        self.write_all(&voboost_contract_core::wire::frame(b)?)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        os::unix::fs::PermissionsExt,
        process::{Command, Stdio},
    };
    fn openssl(args: &[&str]) {
        let output = Command::new("openssl").args(args).output().unwrap();
        assert!(output.status.success(), "OpenSSL fixture operation failed");
    }
    #[test]
    fn paired_peer_abort_is_a_reply_error() {
        use std::os::unix::process::ExitStatusExt;
        const MODE: &str = "VOBOOST_TEST_TLS_SIGPIPE";
        if let Ok(mode) = std::env::var(MODE) {
            // Rust's host test runtime ignores SIGPIPE by default. Restore
            // the standalone QNX executable's initial disposition.
            assert_ne!(
                unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) },
                libc::SIG_ERR
            );
            let mut pipe = unsafe { core::mem::zeroed() };
            assert_eq!(unsafe { libc::sigemptyset(&mut pipe) }, 0);
            assert_eq!(unsafe { libc::sigaddset(&mut pipe, libc::SIGPIPE) }, 0);
            assert_eq!(
                unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &pipe, core::ptr::null_mut()) },
                0
            );
            let guarded = mode == "guarded";
            if guarded {
                crate::service::ignore_socket_sigpipe().unwrap();
            }
            host_mtls(true);
            return;
        }
        for mode in ["unguarded", "guarded"] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tls::tests::paired_peer_abort_is_a_reply_error",
                    "--nocapture",
                ])
                .env(MODE, mode)
                .output()
                .unwrap();
            if mode == "unguarded" {
                assert_eq!(
                    output.status.signal(),
                    Some(libc::SIGPIPE),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            } else {
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }

    #[test]
    fn real_host_mtls_requires_paired_client_and_carries_opaque_frames() {
        host_mtls(false);
    }

    fn host_mtls(abort_peer: bool) {
        let temporary = {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../build/cluster-test-tmp");
            std::fs::create_dir_all(&path).unwrap();
            tempfile::tempdir_in(path).unwrap()
        };
        let dir = std::fs::canonicalize(temporary.path()).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = |name: &str| dir.join(name).to_str().unwrap().to_string();
        let ca = path("ca.pem");
        let cakey = path("ca.key");
        openssl(&[
            "req",
            "-x509",
            "-newkey",
            "ed25519",
            "-nodes",
            "-keyout",
            &cakey,
            "-out",
            &ca,
            "-subj",
            "/CN=Disposable native test CA",
            "-days",
            "1",
        ]);
        for name in ["server", "client"] {
            openssl(&[
                "req",
                "-newkey",
                "ed25519",
                "-nodes",
                "-keyout",
                &path(&format!("{name}.key")),
                "-out",
                &path(&format!("{name}.csr")),
                "-subj",
                &format!("/CN=Disposable {name}"),
            ]);
            openssl(&[
                "x509",
                "-req",
                "-in",
                &path(&format!("{name}.csr")),
                "-CA",
                &ca,
                "-CAkey",
                &cakey,
                "-CAcreateserial",
                "-out",
                &path(&format!("{name}.pem")),
                "-days",
                "1",
            ]);
        }
        // Production pairing trusts an exact self-signed non-CA client leaf.
        openssl(&[
            "req",
            "-x509",
            "-newkey",
            "ed25519",
            "-nodes",
            "-keyout",
            &path("client.key"),
            "-out",
            &path("client.pem"),
            "-subj",
            "/CN=Disposable paired client",
            "-days",
            "1",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            "extendedKeyUsage=clientAuth",
        ]);
        // A stranger leaf must fail both chain trust and the exact pin.
        openssl(&[
            "req",
            "-x509",
            "-newkey",
            "ed25519",
            "-nodes",
            "-keyout",
            &path("stranger.key"),
            "-out",
            &path("stranger.pem"),
            "-subj",
            "/CN=Disposable stranger client",
            "-days",
            "1",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            "extendedKeyUsage=clientAuth",
        ]);
        for entry in std::fs::read_dir(&dir).unwrap() {
            std::fs::set_permissions(
                entry.unwrap().path(),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let der = Command::new("openssl")
            .args(["x509", "-in", &path("client.pem"), "-outform", "DER"])
            .output()
            .unwrap();
        assert!(der.status.success());
        let config = crate::config::Tls {
            server_certificate: path("server.pem"),
            server_private_key: path("server.key"),
            client_ca: path("client.pem"),
            client_certificate_sha256: voboost_contract_core::hash(&der.stdout),
        };
        let lib = Command::new("pkg-config")
            .args(["--variable=libdir", "openssl"])
            .output()
            .unwrap();
        assert!(lib.status.success());
        let lib = core::str::from_utf8(&lib.stdout).unwrap().trim();
        #[cfg(target_os = "macos")]
        let (ssl, crypto) = (
            format!("{lib}/libssl.dylib"),
            format!("{lib}/libcrypto.dylib"),
        );
        #[cfg(not(target_os = "macos"))]
        let (ssl, crypto) = (format!("{lib}/libssl.so"), format!("{lib}/libcrypto.so"));
        if abort_peer {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            use std::os::fd::AsRawFd;
            let mut client = Command::new("openssl")
                .args([
                    "s_client",
                    "-quiet",
                    "-connect",
                    &listener.local_addr().unwrap().to_string(),
                    "-CAfile",
                    &ca,
                    "-cert",
                    &path("client.pem"),
                    "-key",
                    &path("client.key"),
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            client
                .stdin
                .as_mut()
                .unwrap()
                .write_all(
                    &voboost_contract_core::wire::frame(voboost_contract_core::cluster_log::HELLO)
                        .unwrap(),
                )
                .unwrap();
            let fd = crate::net::accept(listener.as_raw_fd()).unwrap();
            let server = Api::load(&ssl, &crypto).unwrap().server(&config).unwrap();
            let deadline = crate::engine::monotonic_ms().unwrap() + 2_000;
            let (stream, first) = server.accept_first_frame(fd, deadline).unwrap();
            assert_eq!(first, voboost_contract_core::cluster_log::HELLO);
            // macOS sockets may inherit SO_NOSIGPIPE from the host runtime.
            #[cfg(target_os = "macos")]
            assert_eq!(
                unsafe {
                    let enabled = 0i32;
                    libc::setsockopt(
                        stream._fd.0,
                        libc::SOL_SOCKET,
                        libc::SO_NOSIGPIPE,
                        (&enabled as *const i32).cast(),
                        core::mem::size_of::<i32>() as _,
                    )
                },
                0
            );
            // Make the failed write deterministic across TCP stacks. The
            // actual paired client is then killed before any reply is sent.
            assert_eq!(unsafe { libc::shutdown(stream._fd.0, libc::SHUT_WR) }, 0);
            client.kill().unwrap();
            client.wait().unwrap();
            let mut socket_error = 0i32;
            let mut error_size = core::mem::size_of::<i32>() as libc::socklen_t;
            assert_eq!(
                unsafe {
                    libc::getsockopt(
                        stream._fd.0,
                        libc::SOL_SOCKET,
                        libc::SO_ERROR,
                        (&mut socket_error as *mut i32).cast(),
                        &mut error_size,
                    )
                },
                0
            );
            let deadline = crate::engine::monotonic_ms().unwrap() + 100;
            assert!(stream.write_frame_before(b"reply", deadline).is_err());
            // Exercise the exact QNX BIO primitive even if the host OpenSSL
            // returns an error before calling write on this TCP stack.
            assert_eq!(
                unsafe { libc::write(stream._fd.0, b"x".as_ptr().cast(), 1) },
                -1
            );
            assert_eq!(crate::fs::errno(), libc::EPIPE);
            return;
        }
        for (paired, bounded, stalled_reply) in [
            (true, true, false),
            (true, true, true),
            (true, false, false),
            (false, false, false),
        ] {
            // Cases where the client presents a wrong leaf or none at all
            // must never reach the frame exchange: chain trust or pin fails.
            for stranger in [false, true] {
                if !paired && stranger {
                    continue;
                }
                let listener = crate::net::tcp_listen("127.0.0.1", 0).unwrap();
                let mut address: libc::sockaddr_in = unsafe { core::mem::zeroed() };
                let mut size = core::mem::size_of_val(&address) as libc::socklen_t;
                assert_eq!(
                    unsafe {
                        libc::getsockname(
                            listener.0,
                            (&mut address as *mut libc::sockaddr_in).cast(),
                            &mut size,
                        )
                    },
                    0
                );
                let port = u16::from_be(address.sin_port);
                let wrong_config = config.clone();
                let ssl = ssl.clone();
                let crypto = crypto.clone();
                let server = std::thread::spawn(move || {
                    let api = Api::load(&ssl, &crypto).unwrap();
                    let server = api.server(&wrong_config).unwrap();
                    let fd = crate::net::accept(listener.0).unwrap();
                    let error = match server.accept(fd) {
                        Ok(_) => panic!("unpaired client was accepted"),
                        Err(error) => error,
                    };
                    assert!(
                        error.starts_with("mTLS handshake failed: ssl_error="),
                        "{error}"
                    );
                    assert!(
                        error.contains(" verify_result=") && error.contains(" err=0x"),
                        "{error}"
                    );
                    drop(server);
                });
                let connect = format!("127.0.0.1:{port}");
                let cert = path("stranger.pem");
                let key = path("stranger.key");
                let mut cmd = Command::new("openssl");
                cmd.arg("s_client")
                    .arg("-quiet")
                    .arg("-connect")
                    .arg(&connect);
                cmd.arg("-CAfile").arg(&ca);
                if stranger {
                    cmd.arg("-cert").arg(&cert).arg("-key").arg(&key);
                }
                cmd.stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null());
                let mut client = cmd.spawn().unwrap();
                let _ = client.stdin.take();
                server.join().unwrap();
                let _ = client.kill();
                let _ = client.wait();
            }
            let listener = crate::net::tcp_listen("127.0.0.1", 0).unwrap();
            let mut address: libc::sockaddr_in = unsafe { core::mem::zeroed() };
            let mut size = core::mem::size_of_val(&address) as libc::socklen_t;
            assert_eq!(
                unsafe {
                    libc::getsockname(
                        listener.0,
                        (&mut address as *mut libc::sockaddr_in).cast(),
                        &mut size,
                    )
                },
                0
            );
            let port = u16::from_be(address.sin_port);
            let mut config = config.clone();
            if !paired {
                config.client_certificate_sha256 = "0".repeat(64);
            }
            // The first connection sends no handshake. The paired connection
            // must still be classified and reach the ordinary request path.
            let stalled =
                bounded.then(|| std::net::TcpStream::connect(("127.0.0.1", port)).unwrap());
            let ssl = ssl.clone();
            let crypto = crypto.clone();
            let server = std::thread::spawn(move || {
                let server = Api::load(&ssl, &crypto).unwrap().server(&config).unwrap();
                if bounded {
                    let ingress =
                        crate::service_ingress::Ingress::new(server, "test-session".into());
                    let (mut stream, first) = ingress
                        .next(listener.0)
                        .expect("stalled peer delayed the paired request")
                        .unwrap();
                    assert_eq!(first, b"opaque-request");
                    assert_ne!(
                        unsafe { libc::fcntl(stream._fd.0, libc::F_GETFL) } & libc::O_NONBLOCK,
                        0,
                        "request bodies must retain nonblocking TLS"
                    );
                    assert!(stream.frame_before(0, 1024).is_err());
                    assert!(stream.write_frame_before(b"x", 0).is_err());
                    assert!(stream.frame_before(u64::MAX, 65537).is_err());
                    let deadline = crate::engine::monotonic_ms().unwrap() + 2000;
                    stream
                        .write_frame_before(b"opaque-receipt", deadline)
                        .unwrap();
                    let began = std::time::Instant::now();
                    stream.deadline = crate::engine::monotonic_ms().unwrap() + 200;
                    if stalled_reply {
                        let size = 1024i32;
                        assert_eq!(
                            unsafe {
                                libc::setsockopt(
                                    stream._fd.0,
                                    libc::SOL_SOCKET,
                                    libc::SO_SNDBUF,
                                    (&size as *const i32).cast(),
                                    core::mem::size_of::<i32>() as _,
                                )
                            },
                            0
                        );
                        assert!(stream.write_all(&vec![b'x'; 8 * 1024 * 1024]).is_err());
                    } else {
                        let mut artifact = [0; 1];
                        stream.read_exact(&mut artifact).unwrap();
                        assert_eq!(artifact, *b"A");
                        stream.read_exact(&mut artifact).unwrap();
                        assert_eq!(artifact, *b"B");
                        // A paired peer sends many complete TLS records. Neither
                        // a new artifact nor another fragment renews the budget.
                        assert!(stream.read_exact(&mut [0; 16]).is_err());
                    }
                    assert!(began.elapsed() < std::time::Duration::from_millis(700));
                    assert!(stream.frame_before(u64::MAX, 1024).is_err());
                    assert!(stream.write_frame_before(b"late-reply", u64::MAX).is_err());
                    return true;
                }
                let fd = crate::net::accept(listener.0).unwrap();
                match server.accept(fd) {
                    Ok(stream) => {
                        assert!(paired);
                        assert_eq!(stream.frame().unwrap(), b"opaque-request");
                        stream.write_frame(b"opaque-receipt").unwrap();
                        true
                    }
                    Err(error) => {
                        assert!(!paired);
                        assert_eq!(error, "mTLS paired client pin rejected");
                        false
                    }
                }
            });
            let mut client = Command::new("openssl")
                .args([
                    "s_client",
                    "-quiet",
                    "-connect",
                    &format!("127.0.0.1:{port}"),
                    "-CAfile",
                    &ca,
                    "-cert",
                    &path("client.pem"),
                    "-key",
                    &path("client.key"),
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut input = client.stdin.take().unwrap();
            input
                .write_all(&voboost_contract_core::wire::frame(b"opaque-request").unwrap())
                .unwrap();
            input.flush().unwrap();
            let mut output = client.stdout.take().unwrap();
            let mut length = [0; 4];
            if paired {
                output.read_exact(&mut length).unwrap();
                let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
                output.read_exact(&mut bytes).unwrap();
                assert_eq!(bytes, b"opaque-receipt");
                if bounded && !stalled_reply {
                    input.write_all(b"A").unwrap();
                    input.flush().unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(60));
                    input.write_all(b"B").unwrap();
                    input.flush().unwrap();
                    for _ in 0..16 {
                        if input.write_all(b"x").and_then(|_| input.flush()).is_err() {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(30));
                    }
                }
            }
            assert_eq!(server.join().unwrap(), paired);
            drop(stalled);
            drop(input);
            let _ = client.kill();
            let _ = client.wait();
        }
    }
}
