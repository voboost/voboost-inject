## ADDED Requirements

### Requirement: Parent-directory fsync after status rename

The daemon's `Status.write_atomic` SHALL fsync the parent directory of the
status file after the atomic rename, so that the directory-entry update
pointing at the new inode is durable on stable storage. The parent directory
SHALL be opened with `O_RDONLY | O_DIRECTORY` (refusing non-directories, so a
racing symlink at the parent path cannot redirect the fsync). The dir fsync
SHALL be best-effort: a failure only delays durability (the temp file's data
is already fsynced) and SHALL NOT abort the write or corrupt the status file.

Context: the temp file's data was already fsynced before the rename, but the
parent directory was not fsynced after the rename, so a crash after rename
could leave the old directory entry pointing at the pre-rename inode (the new
bytes survive on disk but are unreachable). The status file is transient and
the reader tolerates a missing/partial file, so the old code was acceptable;
the dir fsync makes the rename durable as defense-in-depth (R4 carried
finding: `Status.write_atomic()` no dir fsync).

#### Scenario: Status write completes and the dir is fsynced
- **WHEN** the daemon writes `inject-status.json` via `write_atomic`
- **THEN** after the rename succeeds, the parent directory is opened with
  `O_RDONLY | O_DIRECTORY` and fsynced
- **AND** a fsync failure is ignored (the write still succeeds)

#### Scenario: Parent path is a symlink
- **WHEN** a racing app swaps the parent directory path to a symlink
- **THEN** `O_DIRECTORY` refuses to open it (the fd is negative)
- **AND** the fsync is skipped without aborting the write
