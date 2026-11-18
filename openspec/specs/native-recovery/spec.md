# Native recovery

## Purpose

Serialize resident and offline native mutations while retaining installation authority and explicit legacy limitations.

## Requirements

### Requirement: Native executors share one mutation boundary

The native resident and offline executor SHALL serialize managed mutations using one stable protected operation-lock inode. They SHALL recheck restoration fences under that lock before changing managed state.

#### Scenario: Another process holds the operation lock

- **WHEN** a native executor already holds the operation lock
- **THEN** another executor cannot start a managed mutation until ownership is released

# Unverified: Native recovery runtime serialization

### Requirement: Legacy installations do not gain fictitious lock support

A new helper SHALL NOT create the operation protocol marker over an existing installation that lacks the protocol.

#### Scenario: An installed product lacks the operation marker

- **WHEN** an installed authority or resident record exists without the operation protocol
- **THEN** initialization is rejected and the existing authority is retained

# Unverified: Legacy native protocol admission

### Requirement: Controller stop acknowledges the consumed UI command

A controller SHALL NOT acknowledge a newly queued Stop using an earlier stopped snapshot. It SHALL keep the stop pending until the original OEM UI thread has consumed and successfully executed that command. A newer queued Stop SHALL retain its own pending state.

#### Scenario: A stopped controller receives another Stop

- **WHEN** Stop is queued while an earlier stopped snapshot exists
- **THEN** the response remains unconfirmed until the UI callback consumes the new Stop

# Unverified: Controller stop acknowledgement

## Unverified

### Unverified: Native recovery runtime serialization

Maps: Requirement `Native executors share one mutation boundary`, Scenario `Another process holds the operation lock`.

Unavailable observation: Actual QNX resident and offline mutation exclusion through recovery.

Reason: Native host process-exclusion tests pass; QNX execution of the new protocol is pending.

Required environment or artifact: Execute the current candidate with a prepared QNX guest and retain conflicting-operation and recovery receipts.

### Unverified: Legacy native protocol admission

Maps: Requirement `Legacy installations do not gain fictitious lock support`, Scenario `An installed product lacks the operation marker`.

Unavailable observation: Legacy QNX recovery with missing operation history.

Reason: Host rejection passes; independent legacy authority and quiescence have not been established.

Required environment or artifact: Prove legacy authority and quiescence through the supported maintenance route without fabricating operation history.

### Unverified: Controller stop acknowledgement

Maps: Requirement `Controller stop acknowledges the consumed UI command`, Scenario `A stopped controller receives another Stop`.

Unavailable observation: Stop acknowledgement on the real QNX UI callback.

Reason: The authenticated IPC host regression passes both pre-callback and post-callback observations; QNX execution remains pending.

Required environment or artifact: Execute queued Stop on the current QNX candidate and retain the callback-bound acknowledgement.
