## ADDED Requirements

### Requirement: Reversible supervisor configuration
The native installer SHALL change only the fixed OEM supervisor configuration through an exclusive exact-byte transaction, retaining the first original presence, mode and bytes across updates. Pending recovery or foreign state SHALL prevent successful completion and delivery admission. The transaction SHALL preserve all original mount flags, restore read-only state, and publish its Installation receipt only after exact installed readback.

#### Scenario: Installation and interrupted restoration
- **WHEN** installation, update or restoration encounters interruption or foreign state
- **THEN** the retained journal permits only an exact authorized completion or exact restoration, and unknown state remains preserved

# Unverified: Supervisor transaction acceptance

### Requirement: Fresh supervisor delivery observation
Supervised restart admission SHALL require current Installation configuration evidence and fresh authenticated child observations before and after its reads, with matching nonce, child identity and actual parent. The complete proof SHALL be repeated immediately before stopping an owner.

#### Scenario: Changed observation
- **WHEN** the child, parent, nonce, pending journal or configuration changes
- **THEN** restart admission is refused

# Unverified: Supervisor observation acceptance

## Unverified

### Unverified: Supervisor transaction acceptance
The Reversible supervisor configuration requirement and Installation and interrupted restoration scenario await implementation, named host failure-order tests, and actual QNX lock and mount acceptance. No guest mutation has been performed.

### Unverified: Supervisor observation acceptance
The Fresh supervisor delivery observation requirement and Changed observation scenario await the typed transaction receipt integration and authenticated runtime acceptance on the coordinator-owned QNX guest.
