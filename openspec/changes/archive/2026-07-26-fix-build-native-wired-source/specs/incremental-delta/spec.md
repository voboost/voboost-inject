## MODIFIED Requirements

### Requirement: Diff by hash and download only changed files

The OTA client SHALL keep its current release manifest, fetch the new signed
manifest, diff the two by per-file `sha256`, and download only files whose hash
changed. Unchanged files SHALL NOT be re-downloaded. The diff SHALL cover every
`inject`-channel runtime payload file: the daemon ELF and each per-ABI runtime
native payload file (`libimplant.so`, `liblsplant.so` — see
`release-manifest`), so a payload-only update downloads only the changed
`.so` files, not the whole ELF. `libdobby.a` (build-time only) and
`liblsplt.so` (unused) are not part of the diff because they are not shipped.
The stored "current manifest" used as the diff base SHALL itself be the last
successfully verified manifest; a manifest that failed signature or schema
verification SHALL NOT be persisted as the current manifest.

#### Scenario: One file changed

- **WHEN** exactly one file's sha256 differs between the current and new release
  manifests (e.g. a single `libimplant.so` per ABI)
- **THEN** the client downloads only that file and fetches nothing else

#### Scenario: Nothing changed

- **WHEN** no file's sha256 differs
- **THEN** the client downloads no component files
