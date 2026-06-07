# Keys

- `dev-public.pem` / `dev-private.pem` — local developer keypair from `make dev-key`.
  The private key is gitignored (`keys/*-private.pem`); never commit it.
- `release-public.pem` — the production public key, committed by a maintainer. The release
  pipeline (the `ci2` change) verifies release signatures against it. The matching private key
  lives only in the CI secret `SIGNING_KEY_ED25519` and is never committed.

No private key material is ever committed to this repository. Signing and verification themselves
are implemented by the `ci2` change (after `inject`) as Makefile targets; this `ci` change only
documents the key/secret model and stands up the push/PR pipeline.
