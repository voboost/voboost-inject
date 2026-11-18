//! Strict SemVer comparison shared by the OTA and generation paths.

use semver::Version;

/// Return true only when `candidate` has strictly greater SemVer precedence.
/// Build metadata is ignored by SemVer ordering and invalid input fails closed.
pub fn strictly_newer(candidate: &str, running: &str) -> bool {
    matches!(
        (Version::parse(candidate), Version::parse(running)),
        (Ok(candidate), Ok(running))
            if candidate.cmp_precedence(&running).is_gt()
    )
}

/// Parse a strict SemVer value for callers that need the normalized identity.
pub fn parse(version: &str) -> Option<Version> {
    Version::parse(version).ok()
}

#[cfg(test)]
mod tests {
    use super::strictly_newer;

    #[test]
    fn ordering() {
        assert!(strictly_newer("1.0.1", "1.0.0"));
        assert!(strictly_newer("1.1.0", "1.0.99"));
        assert!(strictly_newer("2.0.0", "1.9.9"));
        assert!(!strictly_newer("1.0.0", "1.0.0"));
        assert!(!strictly_newer("1.0.0", "1.0.1"));
        assert!(strictly_newer("1.0.0-beta2", "1.0.0-beta1"));
        assert!(strictly_newer("1.0.0-beta.16", "1.0.0-beta.15"));
        assert!(strictly_newer("1.0.0", "1.0.0-beta1"));
        assert!(!strictly_newer("1.0.0-beta2", "1.0.0"));
        assert!(!strictly_newer("1.0.0+build.2", "1.0.0+build.1"));
        assert!(strictly_newer("1.0.1+build.1", "1.0.0+build.99"));
        assert!(!strictly_newer("1.0.0-01", "1.0.0-1"));
        assert!(!strictly_newer("", "1.0.0"));
        assert!(!strictly_newer("x.y.z", "1.0.0"));
        assert!(!strictly_newer("1.0", "1.0.0"));
        assert!(!strictly_newer("1.0.0.1", "1.0.0"));
    }
}
