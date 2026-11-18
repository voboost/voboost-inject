#[cfg(any(target_os = "nto", test))]
use voboost_contract_core::lookups::Descriptor;

#[cfg(any(target_os = "nto", test))]
mod selection {
    use super::*;
    use crate::Result;

    // Bump when the lookup shape, selection rules or ABI adapter change.
    const CONTRACT: u32 = 2;
    pub(super) const LIBRARY: &str = "/lib64/libkzcoreui.so";
    const ADAPTER: &str = "node-shared-boost-v1";
    const PREFIX: &str = "_ZN5kanzi4Node10lookupNodeI";
    const SUFFIX: &str = "EESt10shared_ptrIT_EN5boost17basic_string_viewIcSt11char_traitsIcEEE";

    fn compatible(name: &str) -> bool {
        matches!(
            name.strip_prefix(PREFIX)
                .and_then(|n| n.strip_suffix(SUFFIX)),
            Some("S0_" | "NS_4NodeE" | "N5kanzi4NodeE")
        )
    }

    fn discover(bytes: &[u8]) -> Result<Option<Descriptor>> {
        let Some(export) = crate::bootstrap::select_export(bytes, compatible)? else {
            return Ok(None);
        };
        Ok(Some(Descriptor::Native {
            library: LIBRARY.into(),
            contract_revision: CONTRACT,
            export,
            adapter: ADAPTER.into(),
        }))
    }

    pub(super) fn selected(descriptor: &Descriptor) -> Result<&str> {
        match descriptor {
            Descriptor::Native {
                library,
                contract_revision,
                export,
                adapter,
            } if library == LIBRARY
                && *contract_revision == CONTRACT
                && adapter == ADAPTER
                && compatible(export) =>
            {
                Ok(export)
            }
            _ => Err("PW lookup contract changed; prepare again during installation".into()),
        }
    }

    pub(super) fn probe(receipt: &Descriptor, bytes: &[u8]) -> Result<alloc::string::String> {
        selected(receipt)?;
        // The receipt records the adapter contract, never an OEM file identity.
        // Re-select from the current file before resolving any callable pointer.
        crate::bootstrap::select_export(bytes, compatible)?
            .ok_or_else(|| "PW current OEM lookup capability missing".into())
    }

    #[cfg(target_os = "nto")]
    pub(super) fn prepare() -> Result<Option<Descriptor>> {
        let bytes = crate::bootstrap::protected_input(LIBRARY, 64 * 1024 * 1024, false)?;
        discover(&bytes)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use voboost_contract_core::lookups::Manifest;

        #[test]
        #[ignore = "requires retained actual A9 OEM Kanzi library"]
        fn actual_a9_lookup_selection() {
            let path =
                std::env::var_os("VOBOOST_TEST_A9_KANZI_LIBRARY").expect("actual OEM library");
            let bytes = std::fs::read(path).expect("read actual OEM library");
            let descriptor = discover(&bytes)
                .expect("bounded OEM ELF")
                .expect("compatible OEM export");
            let export = probe(&descriptor, &bytes).unwrap();
            std::eprintln!("actual OEM bytes={}, selected export={export}", bytes.len());
        }
        #[test]
        fn compatible_library_change_is_reprobed() {
            let name = alloc::format!("{PREFIX}S0_{SUFFIX}");
            let file = crate::bootstrap::lookup_fixture(&name);
            let descriptor = discover(&file).unwrap().unwrap();
            let mut changed = file;
            changed[1000] ^= 1;
            assert_eq!(probe(&descriptor, &changed).unwrap(), name);
        }
        #[test]
        fn stale_export_is_reselected_from_current_library() {
            let old = alloc::format!("{PREFIX}S0_{SUFFIX}");
            let current = alloc::format!("{PREFIX}NS_4NodeE{SUFFIX}");
            let descriptor = discover(&crate::bootstrap::lookup_fixture(&old))
                .unwrap()
                .unwrap();
            assert_eq!(selected(&descriptor).unwrap(), old);
            assert_eq!(
                probe(&descriptor, &crate::bootstrap::lookup_fixture(&current)).unwrap(),
                current
            );
        }
        #[test]
        fn current_missing_invalid_or_ambiguous_capability_never_uses_cached_export() {
            let name = alloc::format!("{PREFIX}S0_{SUFFIX}");
            let file = crate::bootstrap::lookup_fixture(&name);
            let descriptor = discover(&file).unwrap().unwrap();
            assert!(probe(
                &descriptor,
                &crate::bootstrap::lookup_fixture("lookupNodeRaw")
            )
            .is_err());
            for mutate in [
                |b: &mut alloc::vec::Vec<u8>| b[630..632].copy_from_slice(&0u16.to_le_bytes()),
                |b: &mut alloc::vec::Vec<u8>| b[629] = 2,
                |b: &mut alloc::vec::Vec<u8>| b[628] = 0x1a,
                |b: &mut alloc::vec::Vec<u8>| {
                    b[632..640].copy_from_slice(&0x500000u64.to_le_bytes())
                },
                |b: &mut alloc::vec::Vec<u8>| b[708..712].copy_from_slice(&0u32.to_le_bytes()),
                |b: &mut alloc::vec::Vec<u8>| {
                    b.copy_within(624..648, 648);
                    b[704..708].copy_from_slice(&3u32.to_le_bytes());
                    b[716..720].copy_from_slice(&2u32.to_le_bytes());
                },
            ] {
                let mut changed = file.clone();
                mutate(&mut changed);
                assert!(probe(&descriptor, &changed).is_err());
            }
        }
        #[test]
        fn prepares_roundtrips_and_rejects_foreign_contract_or_generation() {
            for parameter in ["S0_", "NS_4NodeE", "N5kanzi4NodeE"] {
                let name = alloc::format!("{PREFIX}{parameter}{SUFFIX}");
                let file = crate::bootstrap::lookup_fixture(&name);
                let descriptor = discover(&file).unwrap().unwrap();
                let generation = "a".repeat(64);
                let mut manifest = Manifest::new(&generation);
                manifest.insert(
                    "vehicle-drive-pedestrian-warning",
                    "cluster-light",
                    "kanzi-lookup-node",
                    descriptor,
                );
                let bytes = manifest.bytes().unwrap();
                assert!(!bytes
                    .windows(b"fileSha256".len())
                    .any(|w| w == b"fileSha256"));
                let parsed = Manifest::parse(&bytes, &generation).unwrap();
                let cached = parsed
                    .get(
                        "vehicle-drive-pedestrian-warning",
                        "cluster-light",
                        "kanzi-lookup-node",
                    )
                    .unwrap();
                let export = selected(cached).unwrap();
                assert_eq!(export, name);
                assert_eq!(probe(cached, &file).unwrap(), name);
                let mut stale = cached.clone();
                if let Descriptor::Native {
                    contract_revision, ..
                } = &mut stale
                {
                    *contract_revision += 1;
                }
                assert!(selected(&stale).is_err());
                assert!(probe(&stale, &file).is_err());
                let mut foreign = cached.clone();
                if let Descriptor::Native { library, .. } = &mut foreign {
                    *library = "/lib64/foreign.so".into();
                }
                assert!(probe(&foreign, &file).is_err());
                let mut hashed = serde_json::to_value(cached).unwrap();
                hashed["fileSha256"] = "a".repeat(64).into();
                assert!(serde_json::from_value::<Descriptor>(hashed).is_err());
                assert!(Manifest::parse(&bytes, &"b".repeat(64)).is_err());
            }
            assert!(discover(&crate::bootstrap::lookup_fixture("lookupNodeRaw"))
                .unwrap()
                .is_none());
        }
    }
}

#[cfg(target_os = "nto")]
mod actual {
    use super::*;
    use crate::{fs::Dir, Result};
    use voboost_contract_core::lookups::{Manifest, FILE, MAX_BYTES};
    pub const AGENT: &str = "vehicle-drive-pedestrian-warning";
    const COMPONENT: &str = "cluster-light";
    const LOOKUP: &str = "kanzi-lookup-node";

    pub fn prepare(directory: &Dir, generation: &str) -> Result<()> {
        let mut manifest = Manifest::new(generation);
        match selection::prepare() {
            Ok(Some(descriptor)) => manifest.insert(AGENT, COMPONENT, LOOKUP, descriptor),
            Ok(None) => {}
            Err(reason) => crate::diagnostic_log::emit("error", "pw-lookup-install", &reason, &[]),
        }
        let bytes = manifest.bytes()?;
        if !directory.exists(FILE)? || directory.read(FILE, MAX_BYTES, 0o600)? != bytes {
            directory.write(FILE, &bytes, 0o600)?;
        }
        Ok(())
    }

    pub fn read(generation: &str) -> Result<Descriptor> {
        if !voboost_contract_core::digest(generation) {
            return Err("PW lookup generation invalid".into());
        }
        let root = Dir::open("/var/voboost", 0)?;
        if root.exists("restore.lock")? {
            return Err("PW lookup installation is fenced".into());
        }
        let directory = Dir::open(&alloc::format!("/var/voboost/generations/{generation}"), 0)?;
        let manifest = Manifest::parse(&directory.read(FILE, MAX_BYTES, 0o600)?, generation)?;
        if root.exists("restore.lock")? {
            return Err("PW lookup installation is fenced".into());
        }
        manifest
            .get(AGENT, COMPONENT, LOOKUP)
            .cloned()
            .ok_or_else(|| "PW lookup not prepared for current generation".into())
    }

    pub fn admit(receipt: &Descriptor) -> Result<crate::pw_readback_owner::qnx::PinnedInput> {
        use crate::pw_readback_owner::qnx::pin_cached_lookup;

        let admission_started = crate::engine::monotonic_ms();
        let bytes = crate::bootstrap::protected_input(selection::LIBRARY, 64 * 1024 * 1024, false)?;
        let started = crate::engine::monotonic_ms();
        let selected = selection::probe(receipt, &bytes)?;
        let probe_finished = crate::engine::monotonic_ms();
        let length = alloc::format!("{}", bytes.len());
        let mut input = pin_cached_lookup(selection::LIBRARY, &selected, bytes)?;
        if let (Some(start), Some(probe_start), Some(probe_end), Some(end)) = (
            admission_started,
            started,
            probe_finished,
            crate::engine::monotonic_ms(),
        ) {
            let elapsed = alloc::format!("{}", probe_end.saturating_sub(probe_start));
            let admission = alloc::format!("{}", end.saturating_sub(start));
            crate::diagnostic_log::emit(
                "info",
                "pw-lookup-cache",
                "current lookup probed and pinned",
                &[
                    ("bytes", &length),
                    ("probeMs", &elapsed),
                    ("admissionMs", &admission),
                ],
            );
        }
        input.discard_file();
        Ok(input)
    }
}
#[cfg(target_os = "nto")]
pub(crate) use actual::{admit, prepare, read, AGENT};
