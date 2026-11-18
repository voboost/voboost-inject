use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

fn main() {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 1 {
        eprintln!("usage: apk-signer <voboost-app.apk>");
        std::process::exit(2);
    }
    let path = Path::new(&arguments[0]);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .unwrap_or_else(|error| {
            eprintln!("open APK: {error}");
            std::process::exit(1);
        });
    let stamp = voboost_contract::apk::FileStamp::read(&file).unwrap_or_else(|error| {
        eprintln!("APK identity: {error}");
        std::process::exit(1);
    });
    let certificate =
        voboost_contract::apk::signer_sha256_v2_v3(&file, stamp).unwrap_or_else(|error| {
            eprintln!("APK signer: {error}");
            std::process::exit(1);
        });
    let after = voboost_contract::apk::FileStamp::read(&file).unwrap_or_else(|error| {
        eprintln!("APK revalidation: {error}");
        std::process::exit(1);
    });
    if stamp != after {
        eprintln!("APK changed while verifying signer");
        std::process::exit(1);
    }
    println!("{}", hex::encode(certificate));
}
