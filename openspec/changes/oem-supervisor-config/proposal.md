# OEM supervisor configuration

## Why
OEM supervisors use explicit child environments. The installation must deliver the existing signed bootstrap through reversible configuration data.

## What Changes
Add a fixed-path exact-byte transaction for `/etc/clsboot/boot_cfg.xml`, preserving the first original state, all unrelated XML, and filesystem flags. Reject foreign changes and pending recovery. No executable interception or new digest authority is introduced.

## Impact
QNX native installation, restoration and authenticated owner restart admission. Device acceptance remains unverified until the coordinator runs the reviewed candidate.
