## MODIFIED Requirements

### Requirement: Running daemon verification binds the opened inode

Post-reboot verification SHALL obtain the daemon PID and start time from the authenticated owner socket. It SHALL open that process's executable once, require a regular single-link root-owned mode-0700 file, hash exactly the manifest-declared size from that descriptor and reject metadata change, growth, digest mismatch or change of owner PID or start time. Product SemVer SHALL not participate in executable verification. The injection host SHALL match its own running device and inode to the trusted installed injection executable. The signed installed closure SHALL still verify both artifacts before commit.

#### Scenario: Running executable changes during verification

- **WHEN** the daemon metadata, size or bytes differ from the daemon row or the running injection host differs from its installed executable
- **THEN** product activation rejects the running product identity

# Gate: cargo test --manifest-path daemon/Cargo.toml product_candidate::tests::post_reboot_requires_both_running_executables -- --exact
Gate contract: Maps: Requirement `Running daemon verification binds the opened inode`; Scenario `Running executable changes during verification`. Preconditions: Distinct daemon and injection executables are installed from a signed host fixture. Observable result: A valid pair passes, while a stale daemon and an injection host running the daemon file both fail. Evidence boundary: Host executable descriptors and artifact identity. Android owner-socket and procfs access require the emulator update gate.
