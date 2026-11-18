extern crate alloc;
pub use voboost_cluster_native::{pw_readback_types, Result};
#[path = "../src/supervisor_defaults.rs"]
pub mod supervisor_defaults;
#[path = "../src/supervisor_elf.rs"]
pub mod supervisor_elf;
#[path = "../src/supervisor_xml.rs"]
pub mod supervisor_xml;

fn without_target_env(xml: &[u8]) -> String {
    let mut text = core::str::from_utf8(xml).unwrap();
    let mut out = String::new();
    while let Some(start) = text.find("<action_exec>") {
        out.push_str(&text[..start]);
        let end = start + text[start..].find("</action_exec>").unwrap() + "</action_exec>".len();
        let action = &text[start..end];
        if ["gauge", "point", "light"]
            .iter()
            .any(|name| action.contains(&format!("<arg>/usr/bin/{name}</arg>")))
        {
            let first = action.find("<m_envs ").unwrap();
            let last = first + action[first..].find("</m_envs>").unwrap() + "</m_envs>".len();
            out.push_str(&action[..first]);
            out.push_str("<TARGET_ENV/>");
            out.push_str(&action[last..]);
        } else {
            out.push_str(action);
        }
        text = &text[end..];
    }
    out.push_str(text);
    out
}
#[test]
#[ignore = "requires retained actual four OEM supervisors"]
fn actual_defaults_splice_preserves_every_other_byte_and_rotates_only_owned_nonce() {
    let mut previous = None;
    for (index, key) in [
        "VOBOOST_A9_CLUSTERBOOT",
        "VOBOOST_A9_SYSMGR",
        "VOBOOST_A11_CLUSTERBOOT",
        "VOBOOST_A11_SYSMGR",
    ]
    .iter()
    .enumerate()
    {
        let file = std::fs::read(std::env::var(key).unwrap()).unwrap();
        let xml = supervisor_defaults::emit(&file).unwrap();
        let implant = "/var/voboost/bin/libvoboost-cluster-inject.so";
        let bootfile = "/var/voboost/boot.json";
        let old = "a".repeat(64);
        let new = "b".repeat(64);
        let changed = supervisor_xml::augment(&xml, implant, bootfile, &old).unwrap();
        assert_eq!(without_target_env(&xml), without_target_env(&changed));
        assert_eq!(
            supervisor_xml::augment(&changed, implant, bootfile, &old).unwrap(),
            changed
        );
        let updated =
            supervisor_xml::rotate_nonce(&changed, implant, bootfile, &old, &new).unwrap();
        assert_eq!(without_target_env(&xml), without_target_env(&updated));
        assert_eq!(
            supervisor_xml::augment(&updated, implant, bootfile, &new).unwrap(),
            updated
        );
        if index % 2 == 1 {
            assert_eq!(previous.as_ref().unwrap(), &xml);
        }
        previous = Some(xml);
    }
}
