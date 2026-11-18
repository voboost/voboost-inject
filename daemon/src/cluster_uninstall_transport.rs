//! Fixed-endpoint, deadline-bound transport; qconn never receives arbitrary shell text.
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};
use voboost_qconn::Qconn;

type Result<T> = std::result::Result<T, String>;
const ENDPOINT: &str = "172.16.100.22:8000";
const NOFOLLOW: u32 = 0o010000;
const CREATE: u32 = 0o000001 | 0o000400 | 0o002000 | NOFOLLOW;

struct BoundedStream {
    stream: TcpStream,
    deadline: Instant,
}
impl BoundedStream {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .map(|d| d.min(Duration::from_secs(5)))
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "Cluster uninstall deadline"))
    }
}
impl Read for BoundedStream {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(out)
    }
}
impl Write for BoundedStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

pub(crate) struct Transport {
    deadline: Instant,
}
impl Transport {
    pub(crate) fn new(budget: Duration) -> Self {
        Self {
            deadline: Instant::now() + budget,
        }
    }
    pub(crate) fn remaining(&self) -> Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| "Cluster uninstall deadline exceeded; authority retained".into())
    }
    fn connect(&self) -> Result<Qconn<BoundedStream, BoundedStream>> {
        let address: SocketAddr = ENDPOINT
            .parse()
            .map_err(|_| "fixed Cluster endpoint invalid")?;
        let stream =
            TcpStream::connect_timeout(&address, self.remaining()?.min(Duration::from_secs(2)))
                .map_err(|e| format!("Cluster qconn connect: {e}"))?;
        let writer = stream.try_clone().map_err(|e| e.to_string())?;
        Ok(Qconn::new(
            BoundedStream {
                stream,
                deadline: self.deadline,
            },
            BoundedStream {
                stream: writer,
                deadline: self.deadline,
            },
        ))
    }
    pub(crate) fn receipt(&self, executable: &str, argv: &[&str]) -> Result<Vec<u8>> {
        self.connect()?.launch_receipt(executable, argv)
    }
    pub(crate) fn absent(&self, path: &str) -> Result<bool> {
        let mut wire = self.connect()?;
        wire.begin_file()?;
        wire.probe_absent(path, NOFOLLOW)
    }
    pub(crate) fn reboot(&self) -> Result<()> {
        self.connect()?
            .launch("/bin/shutdown", &["/bin/shutdown", "-S", "reboot"])
            .map(|_| ())
    }
    pub(crate) fn read(&self, path: &str, maximum: usize) -> Result<Vec<u8>> {
        let mut wire = self.connect()?;
        wire.begin_file()?;
        let (fd, mode, size) = wire.open(path, NOFOLLOW, 0)?;
        let result: Result<Vec<u8>> = (|| {
            if mode & 0o170000 != 0o100000 || mode & 0o077 != 0 || size > maximum as u64 {
                return Err("Cluster finalizer protected file metadata differs".into());
            }
            let mut bytes = Vec::with_capacity(size as usize);
            while bytes.len() < size as usize {
                let count = (size as usize - bytes.len()).min(65536);
                let chunk = wire.read(fd, bytes.len() as u64, count)?;
                if chunk.len() != count {
                    return Err("Cluster finalizer short file".into());
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(bytes)
        })();
        let closed = wire.close(fd);
        result.and_then(|bytes| closed.map(|()| bytes))
    }
    pub(crate) fn upload(&self, path: &str, bytes: &[u8], mode: u32) -> Result<()> {
        if bytes.is_empty()
            || bytes.len() > crate::config::MAX_NATIVE_EXECUTABLE_BYTES
            || !matches!(mode, 0o600 | 0o700)
        {
            return Err("Cluster finalizer upload outside bound".into());
        }
        let mut wire = self.connect()?;
        wire.begin_file()?;
        let (fd, actual, size) = wire.open(path, CREATE, mode)?;
        let result: Result<()> = (|| {
            if actual & 0o170000 != 0o100000 || actual & 0o777 != mode as u64 || size != 0 {
                return Err("Cluster finalizer create metadata differs".into());
            }
            wire.chown_root(fd)?;
            wire.chmod(fd, mode)?;
            for (index, chunk) in bytes.chunks(65536).enumerate() {
                wire.write(fd, (index * 65536) as u64, chunk)?;
            }
            Ok(())
        })();
        let closed = wire.close(fd);
        result?;
        closed?;
        if self.read(path, bytes.len())? != bytes {
            return Err("Cluster finalizer upload readback differs".into());
        }
        Ok(())
    }
    pub(crate) fn rename(&self, from: &str, to: &str) -> Result<()> {
        let mut wire = self.connect()?;
        wire.begin_file()?;
        wire.rename(from, to)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expired_budget_never_connects() {
        let transport = Transport {
            deadline: Instant::now() - Duration::from_secs(1),
        };
        assert!(transport.remaining().is_err());
        assert!(transport.connect().is_err());
    }
}
