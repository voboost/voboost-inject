pub use voboost_contract::install::{lower_hash, StagingDescriptor, STAGING_DESCRIPTOR_NAME};
pub use voboost_contract::release::Manifest as InstallDescriptor;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn descriptor_for_cross_module_tests() -> InstallDescriptor {
        InstallDescriptor::parse(include_bytes!(
            "../../test/fixtures/product-release/voboost/valid/minimal.json"
        ))
        .unwrap()
    }

    #[test]
    fn canonical_schema_one_binds_closed_install_inventory_and_catalog_identity() {
        let value = descriptor_for_cross_module_tests();
        let bytes = value.canonical_bytes().unwrap();
        assert_eq!(InstallDescriptor::parse(&bytes).unwrap(), value);
        let mut extra = descriptor_for_cross_module_tests();
        extra.artifacts.push(extra.artifacts[0].clone());
        assert!(extra.validate().is_err());
    }

    #[test]
    fn unknown_reordered_and_noncanonical_catalog_identity_are_rejected() {
        let value = descriptor_for_cross_module_tests();
        let bytes = value.canonical_bytes().unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(InstallDescriptor::parse(
            text.replace("{\"schemaVersion\":1,", "{\"extra\":1,\"schemaVersion\":1,")
                .as_bytes()
        )
        .is_err());
        let mut invalid = descriptor_for_cross_module_tests();
        invalid.artifacts[0].sha256.replace_range(..1, "A");
        assert!(invalid.validate().is_err());
    }
}
