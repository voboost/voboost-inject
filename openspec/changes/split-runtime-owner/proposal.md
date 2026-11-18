# Split runtime ownership from injection

## Why

Vehicle restoration currently waits for artifact recovery, target discovery and Java bootstrap. State and canonical log files need a single resident owner independent of injection.

## What Changes

- Add an early voboost-daemon owning runtime state, configuration, logs and native PW/FEV.
- Keep target discovery, admission, injection and agent lifecycle in voboost-inject.
- Use bounded authenticated IPC without path-based storage APIs or local writer fallback.
- Update init, signing, release composition and lifecycle verification together.

## Impact

Android runtime, installer and product acceptance; no claim of a verified physical startup time.
