//! Private-pipe JSSE child with separate slots for vehicle control and QNX diagnostics.
use super::VerifiedCode;
use std::{
    io,
    os::fd::AsRawFd,
    process::Child,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

pub struct Config {
    pub host: String,
    pub port: u16,
    pub server_pin: [u8; 32],
    pub client_pin: [u8; 32],
    pub credential: Vec<u8>,
}
impl Config {
    pub fn read_paired(
        directory: &crate::secure_fs::Directory,
        transport: voboost_contract::cluster_wire::Transport,
    ) -> io::Result<Self> {
        use sha2::{Digest, Sha256};
        let pin = |text: &str| -> io::Result<[u8; 32]> {
            hex::decode(text)
                .map_err(io::Error::other)?
                .try_into()
                .map_err(|_| failure("invalid paired certificate pin"))
        };
        let server_pin = pin(&transport.server_certificate_sha256)?;
        let client_pin = pin(&transport.client_certificate_sha256)?;
        let mut credential = directory.read_trusted("transport.p12", 65536, 0o600)?;
        if credential.len() as u64 != transport.credentials.size
            || hex::encode(Sha256::digest(&credential)) != transport.credentials.sha256
        {
            credential.fill(0);
            return Err(failure("paired transport credential identity differs"));
        }
        Ok(Self {
            host: transport.host,
            port: transport.port,
            server_pin,
            client_pin,
            credential,
        })
    }
}

impl Drop for Config {
    fn drop(&mut self) {
        self.credential.fill(0);
    }
}
pub struct Actor {
    child: Option<Child>,
    _code: Arc<VerifiedCode>,
    input: i32,
    output: i32,
    cancel: Arc<AtomicBool>,
    claim: Option<Claim>,
}
pub struct Slot {
    active: AtomicBool,
    unreaped: std::sync::Mutex<Option<(Child, Claim)>>,
}

impl Slot {
    pub const fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            unreaped: std::sync::Mutex::new(None),
        }
    }

    pub fn reap(&self) {
        let mut pending = self
            .unreaped
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if pending
            .as_mut()
            .is_some_and(|(child, _)| child.try_wait().is_ok_and(|status| status.is_some()))
        {
            pending.take();
        }
    }
}

impl Default for Slot {
    fn default() -> Self {
        Self::new()
    }
}

struct Claim(&'static Slot);
impl Drop for Claim {
    fn drop(&mut self) {
        self.0.active.store(false, Ordering::Release);
    }
}
fn failure(message: &'static str) -> io::Error {
    io::Error::other(message)
}
pub fn transfer(
    fd: i32,
    bytes: &mut [u8],
    write: bool,
    deadline: Instant,
    cancel: &AtomicBool,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        if cancel.load(Ordering::Acquire) {
            return Err(failure("TLS transport cancelled"));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "TLS pipe deadline"));
        }
        let mut poll = libc::pollfd {
            fd,
            events: if write { libc::POLLOUT } else { libc::POLLIN },
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll, 1, 20) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if ready == 0 {
            continue;
        }
        let n = unsafe {
            if write {
                libc::write(fd, bytes[offset..].as_ptr().cast(), bytes.len() - offset)
            } else {
                libc::read(
                    fd,
                    bytes[offset..].as_mut_ptr().cast(),
                    bytes.len() - offset,
                )
            }
        };
        if n < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(error);
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "TLS child closed",
            ));
        }
        offset += n as usize;
    }
    Ok(())
}
impl Actor {
    pub fn spawn(
        slot: &'static Slot,
        code: Arc<VerifiedCode>,
        mut config: Config,
        cancel: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        if config.port == 0
            || cancel.load(Ordering::Acquire)
            || config.host.parse::<std::net::IpAddr>().is_err()
            || config.host.is_empty()
            || config.host.len() > 253
            || !config
                .host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".:-".contains(&b))
            || !(1..=65536).contains(&config.credential.len())
        {
            return Err(failure("TLS transport config invalid"));
        }
        slot.reap();
        if slot
            .active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(failure("previous TLS child still active"));
        }
        let claim = Claim(slot);
        let mut child = code.spawn()?;
        let input = child
            .stdin
            .as_ref()
            .ok_or_else(|| failure("TLS child stdin absent"))?
            .as_raw_fd();
        let output = child
            .stdout
            .as_ref()
            .ok_or_else(|| failure("TLS child stdout absent"))?
            .as_raw_fd();
        for fd in [input, output] {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::last_os_error());
            }
        }
        // Drain bounded diagnostic volume without retaining/logging secret or
        // untrusted JVM text; discarded bytes cannot fill and stall the pipe.
        if let Some(mut stderr) = child.stderr.take() {
            std::thread::spawn(move || {
                use std::io::Read;
                let mut bytes = [0u8; 1024];
                while stderr.read(&mut bytes).is_ok_and(|n| n > 0) {}
            });
        }
        let actor = Self {
            child: Some(child),
            _code: code,
            input,
            output,
            cancel,
            claim: Some(claim),
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        actor.integer(1, deadline)?;
        actor.write(config.host.as_bytes(), deadline)?;
        actor.integer(config.port as u32, deadline)?;
        transfer(
            actor.input,
            &mut config.server_pin,
            true,
            deadline,
            &actor.cancel,
        )?;
        transfer(
            actor.input,
            &mut config.client_pin,
            true,
            deadline,
            &actor.cancel,
        )?;
        actor.write(&config.credential, deadline)?;
        config.credential.fill(0);
        Ok(actor)
    }
    pub fn integer(&self, value: u32, deadline: Instant) -> io::Result<()> {
        transfer(
            self.input,
            &mut value.to_be_bytes(),
            true,
            deadline,
            &self.cancel,
        )
    }
    pub fn write(&self, value: &[u8], deadline: Instant) -> io::Result<()> {
        self.integer(
            value
                .len()
                .try_into()
                .map_err(|_| failure("TLS frame size"))?,
            deadline,
        )?;
        // Own this transient private copy so libc writes never need shared mutation.
        let mut copy = value.to_vec();
        let result = transfer(self.input, &mut copy, true, deadline, &self.cancel);
        copy.fill(0);
        result
    }
    pub fn number(&self, deadline: Instant) -> io::Result<u32> {
        let mut bytes = [0u8; 4];
        transfer(self.output, &mut bytes, false, deadline, &self.cancel)?;
        Ok(u32::from_be_bytes(bytes))
    }
    pub fn read(&self, maximum: usize, deadline: Instant) -> io::Result<Vec<u8>> {
        let size = self.number(deadline)? as usize;
        if size == 0 || size > maximum {
            return Err(failure("TLS child frame bound"));
        }
        let mut bytes = vec![0u8; size];
        transfer(self.output, &mut bytes, false, deadline, &self.cancel)?;
        Ok(bytes)
    }
}
impl Drop for Actor {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let pid = child.id() as i32;
            if pid > 1 {
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                }
            }
            let _ = child.kill();
            let deadline = Instant::now() + Duration::from_millis(250);
            while Instant::now() < deadline {
                if child.try_wait().is_ok_and(|v| v.is_some()) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            if let Some(claim) = self.claim.take() {
                let slot = claim.0;
                *slot.unreaped.lock().unwrap_or_else(|e| e.into_inner()) = Some((child, claim));
            }
        }
    }
}
