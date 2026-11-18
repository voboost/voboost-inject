# SELinux target evidence specification

## Purpose

Keep Enforcing target evidence separate from host policy tests.

## Requirements

### Requirement: Enforcing operation requires target evidence

Host policy builds SHALL not be reported as proof of target policy integration, init transition or least privilege.

The daemon does not install a seccomp or other syscall filter. Its custom SELinux domain SHALL remove resident remount, system/vendor mutation, package-manager, and `sys.powerctl` authority. It SHALL retain only the fixed `ctl.start voboost-reboot` handoff during the code-gated, WAL-fenced update-reboot phase. The disabled oneshot `voboost_reboot` domain SHALL revalidate the fixed executable, init parent, operation descriptor, and update WALs, then issue bounded `sys.powerctl=reboot` property calls directly through libc. It SHALL execute no external program and SHALL not remain resident. Daemon compromise still carries ptrace plus target-labeled procfs impact on every process that shares either the `system_app` or `system_server` domain and can request the fenced init handoff. Signed process-name, phase and stopped-process checks narrow normal control flow but cannot narrow a kernel type-enforcement decision after daemon compromise. Documentation and verification SHALL not describe the runtime domain as a complete sandbox.

#### Scenario: Host policy tests pass

- **WHEN** the target was not provisioned and observed under Enforcing
- **THEN** production SELinux activation remains unverified

# Unverified: Enforcing target policy
## Unverified

### Unverified: Enforcing target policy

Maps: Requirement `Enforcing operation requires target evidence`; Scenario `Host policy tests pass`.
Unavailable observation: Compiled policy, both init/domain transitions, exact property-service paths, PackageManager execution, labels, recovery resume, reboot, and real denials operate on the target under Enforcing.
Reason: Host policy builds and synthetic policydb tests cannot observe kernel enforcement, target init, service execution, reboot, or vehicle-specific denials.
Required environment or artifact: A separately authorized, revision-correlated target run under Enforcing with exact artifacts and captured observations for every named boundary.
