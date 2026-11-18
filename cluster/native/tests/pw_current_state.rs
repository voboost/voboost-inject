pub use voboost_cluster_native::{pw_readback_types, Result};
#[path = "../src/pw_current_state.rs"]
mod current;

#[test]
#[ignore = "requires retained original A9/A11 engine ELF"]
fn actual_receiver_readonly_shape() {
    for name in ["PW_A9_OEM_ELF", "PW_A11_OEM_ELF"] {
        let file = std::fs::read(std::env::var(name).unwrap()).unwrap();
        let shape = current::Shape::inspect(&file).unwrap();
        let mut bytes = vec![0; shape.bytes() as usize];
        let first = shape.decode(&bytes).unwrap();
        assert!(!first.running && !first.ui_ready && !first.theme_changing);
        // Every noncanonical boolean byte is rejected. No guessed state value
        // in this test is interpreted as live readiness.
        for field in ["m_isRun", "m_context.m_themChg", "m_context.m_isKzready"] {
            let offset = pw_readback_types::inspect_field_path(&file, "DataReceiver", field)
                .unwrap()
                .offset as usize;
            bytes[offset] = 2;
            assert!(shape.decode(&bytes).is_none());
            bytes[offset] = 0;
        }
        assert!(shape.decode(&bytes[..bytes.len() - 1]).is_none());
        assert_eq!(shape.decode(&bytes), Some(first));
    }
}
