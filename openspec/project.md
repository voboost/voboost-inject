# Voboost Inject

## Project overview

`voboost-inject` is the root trust boundary and runtime authority for Voboost. It verifies hostile app staging, freezes vehicle facts, selects applicable modules, publishes immutable generations, owns canonical user intent and all runtime state/status/logs, injects target processes and connects implants through bounded process-scoped anonymous pipes.

The daemon has no network client. Agents and implants do not open Voboost filesystem paths. Generation publication and agent-setting changes never kill or force-restart OEM processes; a new composition applies at the next natural process start. The daemon is a direct Android init service in a firmware-integrated dedicated SELinux domain.

## OpenSpec workflow

Permanent current truth lives under `openspec/specs`. The repository has been rebaselined to that current-state specification set. Future behavior changes require a validated active delta before implementation.

Validation:

```bash
npm ci
npm run check:openspec
```
