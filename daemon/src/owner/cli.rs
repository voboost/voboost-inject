//! Closed administrative CLI; the resident remains the only config writer.
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::Path;
use voboost_contract::runtime_owner::{Command, Outcome};

#[derive(Debug, PartialEq)]
pub(super) enum Mode {
    Resident,
    Logs,
    NativeCan(u64),
    Startup(String),
}

pub(super) fn parse(arguments: &[OsString]) -> io::Result<Mode> {
    match arguments {
        [] => Ok(Mode::Resident),
        [option] if option == "--logs" => Ok(Mode::Logs),
        [option, cursor] if option == "--observe-native-can" => cursor
            .to_str()
            .and_then(|v| v.parse().ok())
            .map(Mode::NativeCan)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid native CAN cursor")
            }),
        [option, startup]
            if option == "--request-startup-mode"
                && matches!(startup.to_str(), Some("none" | "hidden" | "interface")) =>
        {
            Ok(Mode::Startup(startup.to_str().unwrap().into()))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: voboost-daemon [--logs | --observe-native-can <cursor> | --request-startup-mode <none|hidden|interface>]",
        )),
    }
}

pub(super) fn native_can(root: &Path, cursor: u64, output: &mut impl Write) -> io::Result<()> {
    let Outcome::NativeCan { value } =
        super::client::call(root, Command::ReadNativeCan { cursor })?
    else {
        return Err(io::Error::other("native CAN observation unavailable"));
    };
    serde_json::to_writer(&mut *output, &value).map_err(io::Error::other)?;
    output.write_all(b"\n")
}

pub(super) fn save_startup(
    root: &Path,
    startup: String,
    output: &mut impl Write,
) -> io::Result<()> {
    let outcome = super::client::call(
        root,
        Command::SetStartup {
            startup: startup.clone(),
        },
    )?;
    let Outcome::StartupSaved {
        startup: saved,
        installed_version,
    } = outcome
    else {
        return Err(io::Error::other("startup configuration was not confirmed"));
    };
    if saved != startup {
        return Err(io::Error::other(
            "startup configuration acknowledgement differs",
        ));
    }
    output.write_all(&receipt(&startup, &installed_version)?)
}

fn receipt(startup: &str, installed_version: &str) -> io::Result<Vec<u8>> {
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Receipt<'a> {
        schema_version: u8,
        operation: &'static str,
        requested: &'a str,
        confirmed: &'a str,
        installed_version: &'a str,
    }
    let mut bytes = serde_json::to_vec(&Receipt {
        schema_version: 1,
        operation: "startup-mode",
        requested: startup,
        confirmed: startup,
        installed_version,
    })
    .map_err(io::Error::other)?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(Into::into).collect()
    }
    #[test]
    fn modes_are_exact_and_do_not_accept_injection_helpers() {
        assert_eq!(parse(&[]).unwrap(), Mode::Resident);
        assert_eq!(parse(&args(&["--logs"])).unwrap(), Mode::Logs);
        assert_eq!(
            parse(&args(&["--observe-native-can", "42"])).unwrap(),
            Mode::NativeCan(42)
        );
        assert!(parse(&args(&["--observe-native-can", "-1"])).is_err());
        for value in ["none", "hidden", "interface"] {
            assert_eq!(
                parse(&args(&["--request-startup-mode", value])).unwrap(),
                Mode::Startup(value.into())
            );
        }
        for values in [
            &["--logs", "extra"][..],
            &["--request-startup-mode"],
            &["--request-startup-mode", "unknown"],
            &["--reboot"],
            &["--internal-injector-helper"],
        ] {
            assert!(parse(&args(values)).is_err());
        }
    }
    #[test]
    fn configuration_receipt_matches_installer_wire_fixture() {
        assert_eq!(
            receipt("hidden", "1.0.0-beta1").unwrap(),
            include_bytes!("../../../test/fixtures/wire/startup-mode-hidden.json")
        );
    }
}
