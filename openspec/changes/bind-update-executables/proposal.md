## Why

After the process split, product activation opens its own executable while expecting the daemon artifact. The running process roles need to match the signed release before the update can commit.

## What Changes

- Verify the running daemon through the authenticated owner endpoint.
- Bind the injection host to its installed executable descriptor.
- Keep existing signed-closure and rollback acceptance checks.

## Impact

- Affected specs are update rollback and native activation.
- Product recovery and its host fixtures change in the injection host.
