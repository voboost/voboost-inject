//! Installed vehicle facts shared with the installer.
pub use voboost_shared::vehicle_profile::{
    canonical_bytes, ensure_vehicle_profile, Getprop, PropSource, VEHICLE_PROFILE_MODE,
};

pub fn recompute_vehicle_profile(
    root: &std::path::Path,
) -> anyhow::Result<crate::selection::VehicleProfileDocument> {
    let previous = ensure_vehicle_profile(root)
        .ok()
        .and_then(|document| canonical_bytes(&document.facts).ok());
    let document = voboost_shared::vehicle_profile::recompute_vehicle_profile(root)?;
    crate::log::info(
        "profile",
        &format!(
            "DIAGNOSTIC RECOMPUTE of vehicle.json: {} -> {}",
            previous
                .as_deref()
                .map(String::from_utf8_lossy)
                .unwrap_or_else(|| "<absent>".into()),
            String::from_utf8_lossy(&canonical_bytes(&document.facts)?)
        ),
    );
    Ok(document)
}
