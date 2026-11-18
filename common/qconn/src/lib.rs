//! Bounded qconn codec for the admitted native cluster bootstrap.
//! The caller owns the transport deadline and artifact/path admission.
use std::io::{Read, Write};

const PROMPT: &[u8] = b"<qconn-file> ";
const LIMIT: usize = 65536;

enum OpenResponse {
    Opened(u64, u64, u64),
    Errno(u64),
}

pub struct Qconn<R, W> {
    input: R,
    output: W,
}

fn invalid(message: &str) -> String {
    format!("Invalid QNX bootstrap protocol: {message}")
}

fn hex(value: &str) -> Result<u64, String> {
    if value.is_empty() || value.len() > 16 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid("hex field"));
    }
    u64::from_str_radix(value, 16).map_err(|_| invalid("hex overflow"))
}

fn path(value: &str) -> Result<(), String> {
    if !value.starts_with('/')
        || value.len() > 256
        || value.split('/').any(|p| p == ".." || p == ".")
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_.-".contains(&b))
    {
        return Err(invalid("path"));
    }
    Ok(())
}

impl<R: Read, W: Write> Qconn<R, W> {
    pub fn new(input: R, output: W) -> Self {
        Self { input, output }
    }

    pub fn into_parts(self) -> (R, W) {
        (self.input, self.output)
    }

    fn send(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.output
            .write_all(bytes)
            .and_then(|()| self.output.flush())
            .map_err(|e| e.to_string())
    }

    fn raw(&mut self) -> Result<u8, String> {
        let mut byte = [0];
        self.input
            .read_exact(&mut byte)
            .map_err(|e| e.to_string())?;
        Ok(byte[0])
    }

    fn text(&mut self) -> Result<u8, String> {
        // Negotiation is permitted only in text framing, never in a binary body.
        for _ in 0..LIMIT {
            let byte = self.raw()?;
            if byte != 255 {
                return Ok(byte);
            }
            match self.raw()? {
                255 => return Ok(255),
                verb @ 251..=254 => {
                    let option = self.raw()?;
                    if verb == 253 && option == 34 {
                        // Exact OEM qconn requires LINEMODE or ECHO support and
                        // reissues DO LINEMODE after each command. We send whole
                        // command lines; acknowledge only this admitted option.
                        self.send(&[255, 251, 34])?;
                    } else if verb == 251 || verb == 253 {
                        self.send(&[255, if verb == 251 { 254 } else { 252 }, option])?;
                    }
                }
                250 => {
                    let mut previous = 0;
                    let mut ended = false;
                    for _ in 0..LIMIT {
                        let current = self.raw()?;
                        if previous == 255 && current == 240 {
                            ended = true;
                            break;
                        }
                        previous = current;
                    }
                    if !ended {
                        return Err(invalid("telnet subnegotiation limit"));
                    }
                }
                _ => return Err(invalid("telnet command")),
            }
        }
        Err(invalid("telnet negotiation limit"))
    }

    fn until(&mut self, suffix: &[u8]) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        for _ in 0..LIMIT {
            bytes.push(self.text()?);
            if bytes.ends_with(suffix) {
                return Ok(bytes);
            }
        }
        Err(invalid("response limit"))
    }

    fn line(&mut self) -> Result<String, String> {
        let bytes = self.until(b"\n")?;
        let text = std::str::from_utf8(&bytes).map_err(|_| invalid("non-ASCII response"))?;
        if !text.is_ascii() {
            return Err(invalid("non-ASCII response"));
        }
        Ok(text.trim_end_matches(['\r', '\n']).to_owned())
    }

    fn prompt(&mut self) -> Result<(), String> {
        for &byte in PROMPT {
            if self.text()? != byte {
                return Err(invalid("file prompt"));
            }
        }
        Ok(())
    }

    pub fn begin_file(&mut self) -> Result<(), String> {
        self.until(b"QCONN\r\n")?;
        self.send(b"service file\n")?;
        if self.line()? != "OK" {
            return Err(invalid("file service"));
        }
        self.prompt()
    }

    pub fn open(&mut self, name: &str, flags: u32, mode: u32) -> Result<(u64, u64, u64), String> {
        match self.open_response(name, flags, mode)? {
            OpenResponse::Opened(fd, mode, size) => Ok((fd, mode, size)),
            OpenResponse::Errno(errno) => Err(format!("QNX bootstrap open failed: errno {errno}")),
        }
    }

    /// Absence evidence requires an exact remote ENOENT and complete framing.
    /// Existing files or directories are closed and reported as present.
    /// The caller must supply its platform's admitted read-only/NOFOLLOW flags.
    pub fn probe_absent(&mut self, name: &str, flags: u32) -> Result<bool, String> {
        match self.open_response(name, flags, 0)? {
            OpenResponse::Errno(2) => Ok(true),
            OpenResponse::Errno(errno) => Err(format!("QNX bootstrap open failed: errno {errno}")),
            OpenResponse::Opened(fd, _, _) => {
                self.close(fd)?;
                Ok(false)
            }
        }
    }

    /// Test the admitted OEM startup file without creating, truncating, or
    /// writing it. A writable descriptor is closed before reporting failure.
    pub fn probe_readonly_startup(&mut self) -> Result<(), String> {
        const FLAGS: u32 = 0o000001 | 0o000200 | 0o010000;
        match self.open_response("/scripts/startup_cluster.sh", FLAGS, 0)? {
            OpenResponse::Errno(30) => return Ok(()),
            OpenResponse::Opened(fd, _, _) => self.close(fd)?,
            OpenResponse::Errno(_) => (),
        }
        Err(invalid("OEM startup filesystem is not proven read-only"))
    }

    fn open_response(&mut self, name: &str, flags: u32, mode: u32) -> Result<OpenResponse, String> {
        path(name)?;
        self.send(format!("o:\"{name}\":{flags:x}:{mode:x}\n").as_bytes())?;
        let line = self.line()?;
        // qconn returns an error frame for a missing/inaccessible file. Do not
        // expose echoed paths or arbitrary response contents in diagnostics.
        if let Some(error) = line.strip_prefix("e:") {
            // OEM qconn file_error formats strerror(ENOENT), not its number.
            // Admit only the observed exact C-locale spelling; never infer
            // absence from arbitrary diagnostic text or a substring.
            let errno = if error == "No such file or directory" {
                Ok(2)
            } else if error == "Read-only file system" {
                Ok(30)
            } else {
                hex(error)
            };
            if let Ok(errno) = errno {
                if errno != 0 {
                    self.prompt()?;
                    return Ok(OpenResponse::Errno(errno));
                }
            }
        }
        let fields: Vec<_> = line.split(':').collect();
        if fields.len() != 5 || fields[0] != "o" || fields[4] != format!("\"{name}\"") {
            return Err(invalid("open response"));
        }
        let result = (hex(fields[1])?, hex(fields[2])?, hex(fields[3])?);
        self.prompt()?;
        Ok(OpenResponse::Opened(result.0, result.1, result.2))
    }

    pub fn read(&mut self, fd: u64, offset: u64, count: usize) -> Result<Vec<u8>, String> {
        if count == 0 || count > LIMIT || offset.checked_add(count as u64).is_none() {
            return Err(invalid("read extent"));
        }
        self.send(format!("r:{fd:x}:{offset:x}:{count:x}\n").as_bytes())?;
        let mut body = Vec::with_capacity(count);
        loop {
            let line = self.line()?;
            let fields: Vec<_> = line.split(':').collect();
            let more = fields.first() == Some(&"o+");
            if !(more && fields.len() == 2 || fields.first() == Some(&"o") && fields.len() == 4) {
                return Err(invalid("read response"));
            }
            let length =
                usize::try_from(hex(fields[1])?).map_err(|_| invalid("fragment overflow"))?;
            if length > count - body.len() || more && length == 0 {
                return Err(invalid("fragment extent"));
            }
            if !more {
                hex(fields[2])?;
                hex(fields[3])?;
            }
            let start = body.len();
            body.resize(start + length, 0);
            self.input
                .read_exact(&mut body[start..])
                .map_err(|e| e.to_string())?;
            if !more {
                break;
            }
        }
        self.prompt()?;
        Ok(body)
    }

    pub fn write(&mut self, fd: u64, offset: u64, bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() || bytes.len() > LIMIT {
            return Err(invalid("write extent"));
        }
        let next = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| invalid("write overflow"))?;
        self.send(format!("w:{fd:x}:{offset:x}:{:x}:0\n", bytes.len()).as_bytes())?;
        self.send(bytes)?;
        if self.line()? != format!("o:{:x}:{next:x}", bytes.len()) {
            return Err(invalid("write acknowledgement"));
        }
        self.prompt()
    }

    fn simple(&mut self, command: String) -> Result<(), String> {
        self.send(command.as_bytes())?;
        if self.line()? != "o" {
            return Err(invalid("operation acknowledgement"));
        }
        self.prompt()
    }

    pub fn close(&mut self, fd: u64) -> Result<(), String> {
        self.simple(format!("c:{fd:x}\n"))
    }
    pub fn chmod(&mut self, fd: u64, mode: u32) -> Result<(), String> {
        self.simple(format!("a:{fd:x}:{mode:x}\n"))
    }
    pub fn chown_root(&mut self, fd: u64) -> Result<(), String> {
        self.simple(format!("u:{fd:x}:0:0\n"))
    }
    pub fn rename(&mut self, from: &str, to: &str) -> Result<(), String> {
        path(from)?;
        path(to)?;
        self.simple(format!("m:\"{from}\":\"{to}\"\n"))
    }

    /// Removes only the explicitly admitted file; recursive deletion is forbidden.
    pub fn remove(&mut self, name: &str) -> Result<(), String> {
        path(name)?;
        self.simple(format!("d:\"{name}\":0\n"))
    }

    /// Use a fresh connection. Tokens are backend-admitted, never frontend input.
    pub fn launch(&mut self, executable: &str, argv: &[&str]) -> Result<u32, String> {
        self.start(executable, argv, false)
    }

    fn launcher_prompt(&mut self) -> Result<(), String> {
        for &byte in b"<qconn-launcher> " {
            if self.text()? != byte {
                return Err(invalid("launcher prompt"));
            }
        }
        Ok(())
    }

    fn start(
        &mut self,
        executable: &str,
        argv: &[&str],
        direct_output: bool,
    ) -> Result<u32, String> {
        path(executable)?;
        if argv.is_empty()
            || argv.len() > 32
            || argv.iter().any(|s| {
                s.is_empty()
                    || s.len() > 256
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"/_.:=-".contains(&b))
            })
        {
            return Err(invalid("launcher arguments"));
        }
        self.until(b"QCONN\r\n")?;
        self.send(b"service launcher\n")?;
        if self.line()? != "OK" {
            return Err(invalid("launcher service"));
        }
        self.launcher_prompt()?;
        if direct_output {
            // OEM qconn's PTY relay can remain open after the child exits.
            // Direct socket output preserves binary replies and closes on exit.
            self.send(b"set nopty\n")?;
            if self.line()? != "OK" {
                return Err(invalid("launcher nopty acknowledgement"));
            }
            self.launcher_prompt()?;
        }
        self.send(format!("start {executable} {}\n", argv.join(" ")).as_bytes())?;
        let line = self.line()?;
        let value = line
            .strip_prefix("OK ")
            .ok_or_else(|| invalid("launcher acknowledgement"))?;
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid("launcher PID"));
        }
        let pid = value.parse::<u32>().map_err(|_| invalid("launcher PID"))?;
        if pid == 0 {
            return Err(invalid("launcher PID"));
        }
        Ok(pid)
    }

    /// Keep the OEM PTY attached to a command that can shut down qconn itself.
    /// The PID acknowledges dispatch. Only independent evidence proves reboot.
    pub fn launch_pty_complete(
        &mut self,
        executable: &str,
        argv: &[&str],
        acknowledge: impl FnOnce(u32),
    ) -> Result<(), String> {
        acknowledge(self.launch(executable, argv)?);
        self.drain_output(|_| {})
    }

    /// Keep the launcher's direct socket alive until EOF. The transport owns the
    /// wall deadline; the caller must still verify its correlated native report.
    pub fn launch_complete(&mut self, executable: &str, argv: &[&str]) -> Result<u32, String> {
        let pid = self.start(executable, argv, true)?;
        self.drain_output(|_| {})?;
        Ok(pid)
    }

    /// Return bounded helper output after observing launcher EOF. The caller
    /// must authenticate the receipt before treating any bytes as evidence.
    pub fn launch_receipt(&mut self, executable: &str, argv: &[&str]) -> Result<Vec<u8>, String> {
        self.start(executable, argv, true)?;
        let mut receipt = Vec::new();
        let result = self.drain_output(|bytes| receipt.extend_from_slice(bytes));
        if let Err(error) = result {
            receipt.fill(0);
            return Err(error);
        }
        Ok(receipt)
    }

    fn drain_output(&mut self, mut observe: impl FnMut(&[u8])) -> Result<(), String> {
        let mut total = 0;
        let mut scratch = [0_u8; 4096];
        loop {
            let maximum = scratch.len().min(LIMIT - total + 1);
            let result = self.input.read(&mut scratch[..maximum]);
            if let Ok(count) = result {
                if count <= LIMIT - total {
                    observe(&scratch[..count]);
                }
            }
            // Helper output can contain private diagnostics. Never retain or log it.
            scratch.fill(0);
            std::hint::black_box(&mut scratch);
            match result {
                Ok(0) => return Ok(()),
                Ok(count) if count <= LIMIT - total => total += count,
                Ok(_) => return Err(invalid("launcher output limit")),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(invalid("launcher output read failed")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // OEM launcher transcript with LINEMODE renegotiation around set nopty.
    const DIRECT_LAUNCH_REPLY: &[u8] =
        b"QCONN\r\n\xff\xfd\x22OK\r\n\xff\xfa\x22\x01\x01\xff\xf0<qconn-launcher> \
\xff\xfe\x22OK\r\n\xff\xfd\x22<qconn-launcher> \
\xff\xfa\x22\x01\x01\xff\xf0\xff\xfe\x22OK 123\r\n";

    #[test]
    fn open_reports_only_numeric_remote_errno() {
        for (reply, expected) in [
            ("e:2\r\n", "QNX bootstrap open failed: errno 2"),
            ("e:d\r\n", "QNX bootstrap open failed: errno 13"),
            (
                "e:2:private-path\r\n",
                "Invalid QNX bootstrap protocol: open response",
            ),
        ] {
            let mut output = Vec::new();
            let framed = format!("{reply}<qconn-file> ");
            let error = Qconn::new(Cursor::new(framed), &mut output)
                .open("/tmp/a", 0, 0)
                .unwrap_err();
            assert_eq!(error, expected);
        }
    }

    #[test]
    fn absence_probe_accepts_only_framed_remote_enoent() {
        let mut output = Vec::new();
        let mut wire = Qconn::new(Cursor::new(b"e:2\r\n<qconn-file> "), &mut output);
        assert!(wire.probe_absent("/var/voboost", 0x80000).unwrap());
        assert_eq!(output, b"o:\"/var/voboost\":80000:0\n");
        for reply in [
            b"e:d\r\n<qconn-file> ".as_slice(),
            b"e:5a\r\n<qconn-file> ".as_slice(),
            b"e:0\r\n<qconn-file> ".as_slice(),
            b"e:2:extra\r\n<qconn-file> ".as_slice(),
            b"e:2\r\n".as_slice(),
            b"e:2\r\nwrong-prompt".as_slice(),
            b"".as_slice(),
            b"truncated".as_slice(),
        ] {
            let mut output = Vec::new();
            assert!(Qconn::new(Cursor::new(reply), &mut output)
                .probe_absent("/var/voboost", 0x80000)
                .is_err());
        }
    }

    #[test]
    fn readonly_startup_probe_never_writes_and_closes_unexpected_writable_file() {
        let mut sent = Vec::new();
        let reply = b"e:Read-only file system\r\n<qconn-file> ";
        assert!(Qconn::new(Cursor::new(reply), &mut sent)
            .probe_readonly_startup()
            .is_ok());
        assert_eq!(sent, b"o:\"/scripts/startup_cluster.sh\":1081:0\n");

        sent.clear();
        let reply =
            b"o:3:816d:200:\"/scripts/startup_cluster.sh\"\r\n<qconn-file> o\r\n<qconn-file> ";
        assert!(Qconn::new(Cursor::new(reply), &mut sent)
            .probe_readonly_startup()
            .is_err());
        assert_eq!(sent, b"o:\"/scripts/startup_cluster.sh\":1081:0\nc:3\n");

        for reply in [
            b"e:Read-only file system\r\n".as_slice(),
            b"e:Read-only file system elsewhere\r\n<qconn-file> ".as_slice(),
            b"e:No such file or directory\r\n<qconn-file> ".as_slice(),
        ] {
            assert!(Qconn::new(Cursor::new(reply), Vec::new())
                .probe_readonly_startup()
                .is_err());
        }
    }

    #[test]
    fn oem_textual_enoent_requires_exact_error_and_complete_prompt() {
        let reply = b"e:No such file or directory\r\n<qconn-file> ";
        assert!(Qconn::new(Cursor::new(reply), Vec::new())
            .probe_absent("/var/voboost", 0x80000)
            .unwrap());
        assert_eq!(
            Qconn::new(Cursor::new(reply), Vec::new())
                .open("/var/voboost", 0, 0)
                .unwrap_err(),
            "QNX bootstrap open failed: errno 2"
        );
        for error in [
            "",
            "Permission denied",
            "Input/output error",
            "no such file or directory",
            "No such file or directory ",
            " No such file or directory",
            "No such file or directory: private-path",
            "prefix No such file or directory",
            "No such file or directory\r\nextra",
            "Datei oder Verzeichnis nicht gefunden",
        ] {
            let framed = format!("e:{error}\r\n<qconn-file> ");
            let result =
                Qconn::new(Cursor::new(framed), Vec::new()).probe_absent("/var/voboost", 0x80000);
            assert!(result.is_err(), "admitted unknown error: {error:?}");
        }
        for suffix in ["", "<qconn-file>", "wrong-prompt", "extra\r\n<qconn-file> "] {
            let framed = format!("e:No such file or directory\r\n{suffix}");
            assert!(Qconn::new(Cursor::new(framed), Vec::new())
                .probe_absent("/var/voboost", 0x80000)
                .is_err());
        }
    }

    #[test]
    fn exact_read_remove_and_oem_absence_complete_one_transaction() {
        let input = b"o:3:81c0:4:\"/tmp/proof\"\r\n<qconn-file> o:4:0:0\r\nproo<qconn-file> o\r\n<qconn-file> o\r\n<qconn-file> e:No such file or directory\r\n<qconn-file> ";
        let mut sent = Vec::new();
        let mut wire = Qconn::new(Cursor::new(input), &mut sent);
        let (fd, mode, size) = wire.open("/tmp/proof", 0, 0).unwrap();
        assert_eq!((mode, size), (0x81c0, 4));
        assert_eq!(wire.read(fd, 0, size as usize).unwrap(), b"proo");
        wire.close(fd).unwrap();
        wire.remove("/tmp/proof").unwrap();
        assert!(wire.probe_absent("/tmp/proof", 0).unwrap());
        assert_eq!(
            sent,
            b"o:\"/tmp/proof\":0:0\nr:3:0:4\nc:3\nd:\"/tmp/proof\":0\no:\"/tmp/proof\":0:0\n"
        );
    }

    #[test]
    fn absence_probe_closes_existing_files_and_directories() {
        for mode in ["81c0", "41c0"] {
            let reply = format!("o:3:{mode}:0:\"/var/voboost\"\r\n<qconn-file> o\r\n<qconn-file> ");
            let mut output = Vec::new();
            assert!(!Qconn::new(Cursor::new(reply), &mut output)
                .probe_absent("/var/voboost", 0x80000)
                .unwrap());
            assert!(output.ends_with(b"c:3\n"));
        }
        let mut output = Vec::new();
        assert!(Qconn::new(
            Cursor::new(b"o:3:41c0:0:\"/var/voboost\"\r\n<qconn-file> "),
            &mut output
        )
        .probe_absent("/var/voboost", 0x80000)
        .is_err());
    }

    #[test]
    fn absence_probe_never_turns_transport_failure_into_absence() {
        struct Failed(std::io::ErrorKind);
        impl Read for Failed {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(self.0.into())
            }
        }
        for kind in [
            std::io::ErrorKind::TimedOut,
            std::io::ErrorKind::ConnectionReset,
        ] {
            let mut output = Vec::new();
            assert!(Qconn::new(Failed(kind), &mut output)
                .probe_absent("/var/voboost", 0x80000)
                .is_err());
        }
    }

    #[test]
    fn accepts_repeated_oem_linemode_requests_and_skips_text_subnegotiation() {
        let input = b"QCONN\r\n\xff\xfd\x22\xff\xfa\x22\x01\x01\xff\xf0OK\r\n<qconn-file> \xff\xfe\x22o:0:81c0:4:\"/tmp/a\"\r\n\xff\xfd\x22\xff\xfa\x22\x01\x01\xff\xf0<qconn-file> ";
        let mut sent = Vec::new();
        let mut wire = Qconn::new(Fragmented(Cursor::new(input)), &mut sent);
        wire.begin_file().unwrap();
        assert_eq!(wire.open("/tmp/a", 0, 0).unwrap(), (0, 0x81c0, 4));
        assert_eq!(
            sent,
            b"service file\n\xff\xfb\x22o:\"/tmp/a\":0:0\n\xff\xfb\x22"
        );
    }

    #[test]
    fn refuses_unsupported_telnet_options() {
        let mut sent = Vec::new();
        let mut wire = Qconn::new(Cursor::new(b"\xff\xfd\x01\xff\xfb\x03X"), &mut sent);
        assert_eq!(wire.text().unwrap(), b'X');
        assert_eq!(sent, b"\xff\xfc\x01\xff\xfe\x03");
    }

    #[test]
    fn binary_body_never_negotiates_linemode_or_subnegotiation() {
        let body = b"\xff\xfd\x22\xff\xfa\x22\x01\x01\xff\xf0";
        let mut input = format!("o:{:x}:0:0\r\n", body.len()).into_bytes();
        input.extend_from_slice(body);
        input.extend_from_slice(PROMPT);
        let mut sent = Vec::new();
        assert_eq!(
            Qconn::new(Cursor::new(input), &mut sent)
                .read(3, 0, 32)
                .unwrap(),
            body
        );
        assert_eq!(sent, b"r:3:0:20\n");
    }

    struct Fragmented<R>(R);
    impl<R: Read> Read for Fragmented<R> {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            let maximum = bytes.len().min(3);
            self.0.read(&mut bytes[..maximum])
        }
    }

    #[test]
    fn launch_completion_drains_fragmented_binary_output_to_eof() {
        let input = Fragmented(
            Cursor::new(DIRECT_LAUNCH_REPLY).chain(Cursor::new(b"\xff\0\r\n<qconn-file> private")),
        );
        let mut wire = Qconn::new(input, Vec::new());
        assert_eq!(wire.launch_complete("/tmp/a", &["a"]).unwrap(), 123);
        let (mut input, _) = wire.into_parts();
        assert_eq!(input.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn launch_completion_accepts_empty_eof_and_exact_limit() {
        for count in [0, LIMIT] {
            let input =
                Cursor::new(DIRECT_LAUNCH_REPLY).chain(std::io::repeat(0).take(count as u64));
            assert_eq!(
                Qconn::new(input, Vec::new())
                    .launch_complete("/tmp/a", &["a"])
                    .unwrap(),
                123
            );
        }
    }

    #[test]
    fn launch_completion_rejects_output_over_limit() {
        let input =
            Cursor::new(DIRECT_LAUNCH_REPLY).chain(std::io::repeat(0).take((LIMIT + 1) as u64));
        assert!(Qconn::new(input, Vec::new())
            .launch_complete("/tmp/a", &["a"])
            .unwrap_err()
            .contains("output limit"));
    }

    #[test]
    fn launch_receipt_preserves_fragmented_binary_until_eof() {
        let receipt = b"\0\0\0\x04\xff\0\r\n";
        let input = Fragmented(Cursor::new(DIRECT_LAUNCH_REPLY).chain(Cursor::new(receipt)));
        let mut wire = Qconn::new(input, Vec::new());
        assert_eq!(wire.launch_receipt("/tmp/a", &["a"]).unwrap(), receipt);
        let (mut input, sent) = wire.into_parts();
        assert_eq!(input.read(&mut [0]).unwrap(), 0);
        assert_eq!(
            sent,
            b"service launcher\n\xff\xfb\x22set nopty\n\xff\xfb\x22start /tmp/a a\n"
        );
    }

    #[test]
    fn direct_launcher_rejects_bad_nopty_acknowledgement_and_prompt_before_start() {
        for (reply, expected) in [
            ("error unsupported\r\n", "launcher nopty acknowledgement"),
            ("OK 123\r\n", "launcher nopty acknowledgement"),
            ("OK\r\n<qconn-file> ", "launcher prompt"),
        ] {
            let input = Cursor::new(format!("QCONN\r\nOK\r\n<qconn-launcher> {reply}"));
            let mut sent = Vec::new();
            assert_eq!(
                Qconn::new(input, &mut sent).launch_complete("/tmp/a", &["a"]),
                Err(invalid(expected))
            );
            assert_eq!(sent, b"service launcher\nset nopty\n");
        }
    }

    #[test]
    fn pty_launch_reports_pid_even_if_reading_until_eof_fails() {
        struct TimedOut;
        impl Read for TimedOut {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::TimedOut.into())
            }
        }

        let reply = b"QCONN\r\nOK\r\n<qconn-launcher> OK 123\r\nshutdown output";
        let mut wire = Qconn::new(Cursor::new(reply).chain(TimedOut), Vec::new());
        let mut pid = None;
        assert_eq!(
            wire.launch_pty_complete("/tmp/a", &["a"], |value| pid = Some(value)),
            Err(invalid("launcher output read failed"))
        );
        assert_eq!(pid, Some(123));
        let (_, sent) = wire.into_parts();
        assert_eq!(sent, b"service launcher\nstart /tmp/a a\n");
    }

    #[test]
    fn launch_receipt_rejects_output_over_limit() {
        let input =
            Cursor::new(DIRECT_LAUNCH_REPLY).chain(std::io::repeat(0).take((LIMIT + 1) as u64));
        assert!(Qconn::new(input, Vec::new())
            .launch_receipt("/tmp/a", &["a"])
            .unwrap_err()
            .contains("output limit"));
    }

    #[test]
    fn finite_launches_reject_read_errors_after_output_without_disclosing_it() {
        use std::io::ErrorKind;

        struct Failed(ErrorKind);
        impl Read for Failed {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(self.0, "private helper diagnostics"))
            }
        }
        for kind in [
            ErrorKind::TimedOut,
            ErrorKind::ConnectionReset,
            ErrorKind::Other,
        ] {
            let input = || {
                Cursor::new(DIRECT_LAUNCH_REPLY)
                    .chain(Cursor::new(b"private partial output"))
                    .chain(Failed(kind))
            };
            let expected = invalid("launcher output read failed");
            assert_eq!(
                Qconn::new(input(), Vec::new()).launch_complete("/tmp/a", &["a"]),
                Err(expected.clone())
            );
            assert_eq!(
                Qconn::new(input(), Vec::new()).launch_receipt("/tmp/a", &["a"]),
                Err(expected)
            );
        }
    }

    #[test]
    fn oem_maximum_read_reassembles_continuation_and_final_binary_fragments() {
        // OEM file_read has a 65536-byte buffer with 40 bytes reserved for
        // framing. This is the continuation boundary, not a TCP packet size.
        let body: Vec<u8> = (0..65536).map(|n| (n % 256) as u8).collect();
        let mut reply = b"o+:ffd8\r\n".to_vec();
        reply.extend_from_slice(&body[..65536 - 40]);
        reply.extend_from_slice(b"o:28:10000:10010\r\n");
        reply.extend_from_slice(&body[65536 - 40..]);
        reply.extend_from_slice(PROMPT);
        reply.extend_from_slice(b"o\r\n<qconn-file> ");
        let mut sent = Vec::new();
        let mut wire = Qconn::new(Fragmented(Cursor::new(reply)), &mut sent);
        assert_eq!(wire.read(3, 16, 65536).unwrap(), body);
        wire.close(3).unwrap();
        assert_eq!(sent, b"r:3:10:10000\nc:3\n");
    }

    #[test]
    fn captured_oem_8576_read_framing_preserves_payload_and_next_prompt() {
        // Actual startup-wire-8576 capture: one final frame, with repeated OEM
        // LINEMODE negotiation immediately before its header.
        let body: Vec<u8> = (0..8576).map(|n| (n % 256) as u8).collect();
        let mut reply = b"\xff\xfa\x22\x01\x01\xff\xf0\xff\xfe\x22o:2180:2180:2180\r\n".to_vec();
        reply.extend_from_slice(&body);
        reply.extend_from_slice(PROMPT);
        reply.extend_from_slice(b"o\r\n<qconn-file> ");
        let mut sent = Vec::new();
        let mut wire = Qconn::new(Fragmented(Cursor::new(reply)), &mut sent);
        assert_eq!(wire.read(0, 0, 8576).unwrap(), body);
        wire.close(0).unwrap();
        assert_eq!(sent, b"r:0:0:2180\nc:0\n");
    }

    #[test]
    fn binary_read_preserves_telnet_and_prompt_bytes() {
        let body = b"\xff\xfb\x01\r\n<qconn-file> \0";
        let mut reply = format!("o:{:x}:0:0\r\n", body.len()).into_bytes();
        reply.extend(body);
        reply.extend(PROMPT);
        let mut sent = Vec::new();
        assert_eq!(
            Qconn::new(Cursor::new(reply), &mut sent)
                .read(3, 16, 32)
                .unwrap(),
            body
        );
        assert_eq!(sent, b"r:3:10:20\n");
    }

    #[test]
    fn exact_write_and_metadata_requests() {
        let reply = b"o:4:14\r\n<qconn-file> o\r\n<qconn-file> o\r\n<qconn-file> o\r\n<qconn-file> o\r\n<qconn-file> ";
        let mut sent = Vec::new();
        let mut wire = Qconn::new(Cursor::new(reply), &mut sent);
        wire.write(3, 16, b"\0\xff\r\n").unwrap();
        wire.chmod(3, 0o700).unwrap();
        wire.chown_root(3).unwrap();
        wire.close(3).unwrap();
        wire.rename("/tmp/a", "/tmp/b").unwrap();
        assert_eq!(
            sent,
            b"w:3:10:4:0\n\0\xff\r\na:3:1c0\nu:3:0:0\nc:3\nm:\"/tmp/a\":\"/tmp/b\"\n"
        );
    }

    #[test]
    fn rejects_partial_write_and_malformed_reads() {
        assert!(
            Qconn::new(Cursor::new(b"o:3:3\r\n<qconn-file> "), Vec::new())
                .write(0, 0, b"abcd")
                .is_err()
        );
        for reply in [
            b"o+:0\r\n".as_slice(),
            b"o:11:0:0\r\n",
            b"o:1:0:0\r\n",
            b"o:0:0:0\r\nwrong",
        ] {
            assert!(Qconn::new(Cursor::new(reply), Vec::new())
                .read(0, 0, 16)
                .is_err());
        }
    }

    #[test]
    fn exact_nonrecursive_remove_request() {
        let mut sent = Vec::new();
        Qconn::new(Cursor::new(b"o\r\n<qconn-file> "), &mut sent)
            .remove("/tmp/voyemu-qconn-123-abc")
            .unwrap();
        assert_eq!(sent, b"d:\"/tmp/voyemu-qconn-123-abc\":0\n");
        assert!(
            Qconn::new(Cursor::new(b"e:Permission denied\r\n"), Vec::new())
                .remove("/tmp/voyemu-qconn-123-abc")
                .is_err()
        );
    }

    #[test]
    fn exact_service_open_and_launch_requests() {
        let mut sent = Vec::new();
        let mut wire = Qconn::new(
            Cursor::new(b"QCONN\r\nOK\r\n<qconn-file> o:0:81c0:4:\"/tmp/a\"\r\n<qconn-file> "),
            &mut sent,
        );
        wire.begin_file().unwrap();
        assert_eq!(wire.open("/tmp/a", 0, 0).unwrap(), (0, 0x81c0, 4));
        assert_eq!(sent, b"service file\no:\"/tmp/a\":0:0\n");
        sent.clear();
        assert_eq!(
            Qconn::new(
                Cursor::new(b"QCONN\r\nOK\r\n<qconn-launcher> OK 123\r\n"),
                &mut sent
            )
            .launch("/tmp/a", &["a", "install"])
            .unwrap(),
            123
        );
        assert_eq!(sent, b"service launcher\nstart /tmp/a a install\n");
    }
}
