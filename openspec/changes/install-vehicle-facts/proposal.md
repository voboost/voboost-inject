# Change: Resolve installed hardware facts before runtime

## Why

Static powertrain coding does not need NVRAM access on every boot. The installer can persist the existing hardware document before normal services start.

## What Changes

- Resolve hardware facts at installation and explicit diagnostic refresh.
- Keep ordinary startup read-only and deny native powertrain admission when cached evidence is unavailable or mismatched.
- Preserve one vehicle.json document and the existing applicability model.

## Impact

Shared fact resolver, fixed device installer, native owner inputs and product documentation. No firmware digest gate, migration or second fact store.
