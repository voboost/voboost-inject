# Injector target evidence specification

## Purpose

Keep rooted target injection evidence separate from host gates.

## Requirements

### Requirement: Live target behavior remains external evidence

Host state-machine and native harnesses SHALL not be reported as proof of target ptrace, linker namespace, LSPlant, ABI loading or OEM compatibility.

#### Scenario: Host native gates pass

- **WHEN** no rooted target run exists
- **THEN** live injection remains unverified

# Unverified: Rooted target injection
## Unverified

### Unverified: Rooted target injection

Maps: Requirement `Live target behavior remains external evidence`; Scenario `Host native gates pass`.
Unavailable observation: The injector crosses ptrace and linker-namespace boundaries, loads LSPlant for both target ABIs and initializes inside the actual OEM processes.
Reason: Host state-machine and native harnesses do not execute inside a rooted Android target or its OEM processes.
Required environment or artifact: Rooted-device traces for both ABIs against the supported OEM process inventory, including ptrace policy, linker namespace, LSPlant initialization and resulting process state.
