//! Fixed durable uninstall request contract shared by producers and the
//! install/update workers that must stop before new mutations when an
//! explicit uninstall has priority.

/// Empty request file published by the stable desktop management CLI through
/// the root-owned daemon run area. The Settings host delivers its request
/// over the daemon socket instead (in-memory in the resident daemon).
pub const DESKTOP_REQUEST_PATH: &str = "/data/voboost/run/desktop-uninstall-request";
