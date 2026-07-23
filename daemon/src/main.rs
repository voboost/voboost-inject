// Placeholder main — the full Rust daemon lands in later changes
// (daemon-lifecycle, injection-control, etc.). For now this proves the
// workspace builds and the build.rs embeds the key + version.

pub const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");
include!(concat!(env!("OUT_DIR"), "/embedded_pubkey.rs"));
include!(concat!(env!("OUT_DIR"), "/version.rs"));

fn main() {
    eprintln!(
        "voboost-inject {} — new stack scaffold (not yet functional)",
        DAEMON_VERSION
    );
    eprintln!("embedded pubkey: {} bytes", EMBEDDED_PUBKEY.len());
}
