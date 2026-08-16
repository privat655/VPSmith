# ADR 0002 — Step 2 canonical management state and secrets

Status: accepted for VPSmith Platform step 2

## Context

Step 2 owns the complete local persistent administrative state of VPSmith Studio. The finished VPSmith specs require one canonical local source of administrative truth while keeping desired state, observed state, source identities, execution history, backup metadata, productive data, and backup payloads distinct. The Ziel-VPS still consists of exactly Cloud-init, Core, and Module; VPSmith Studio remains outside it.

Two implementation choices were intentionally left open by the specs: the local persistence format and encryption of the running secret store.

## Decision: SQLite for administrative persistence

VPSmith uses a single local SQLite database at `/var/lib/vpsmith/state/vpsmith.db` through `database/sql` and the CGO-free `modernc.org/sqlite` driver. The state directory is restricted to mode `0700` and the database to `0600`.

SQLite was chosen because it provides atomic transactions, crash recovery, constraints, explicit schema versioning, and a mature future backup seam without requiring VPSmith to recreate those mechanisms around JSON or YAML files. The existing step-1 build remains `CGO_ENABLED=0`, so the CGO-dependent `mattn/go-sqlite3` driver is not used.

The database uses:

- schema version 1;
- ordered application migrations;
- `PRAGMA user_version` as the persisted schema marker;
- `BEGIN IMMEDIATE` for domain writes and migrations;
- foreign keys enabled;
- `STRICT` tables;
- rollback-journal (`DELETE`) mode rather than WAL;
- `synchronous=FULL`;
- a short busy timeout;
- effectively one local database connection.

Rollback-journal mode is intentional. VPSmith Studio is a small local single-writer application and does not need WAL's concurrent-writer/read advantages. Avoiding persistent `-wal` and `-shm` companions also keeps later portable export and recovery simpler.

### Rejected persistence alternatives

- **JSON/YAML files:** fewer dependencies, but VPSmith would have to implement multi-object transactions, fsync/rename crash semantics, locking, schema migrations, append-only history protection, and recovery itself.
- **bbolt:** robust and CGO-free, but the key/value model would move relational identity constraints and migration structure into VPSmith code without reducing the overall complexity for this domain.
- **CGO SQLite drivers:** conflict with the existing static CGO-free build contract.

## Decision: AES-256-GCM for the running secret store

Secret values are encrypted individually with AES-256-GCM using Go's standard `crypto/aes`, `crypto/cipher`, and `crypto/rand` packages. Each ciphertext receives a fresh random nonce. Authenticated additional data binds the ciphertext to the crypto format and stable `SecretID`, so ciphertext cannot be silently moved between secret identities.

The 256-bit master key is stored at `/var/lib/vpsmith/state/secret-store.key` with mode `0600`. If an existing database loses its key, VPSmith fails closed instead of generating a replacement and making existing secrets unreadable. Secret material is never part of normal snapshots, history records, execution-bundle metadata, debug formatting, or normal JSON serialization.

This protects a copied database file from revealing secret plaintext. It does not claim protection after compromise of the entire live state volume plus its master key, or compromise of the running VPSmith process. Avoiding that would require an external key or interactive passphrase at every startup, which the VPSmith V1 specs do not require.

The later portable Wiederanlaufpaket must protect both database and master key inside its already specified age-encrypted recovery envelope. Step 2 does not implement that export format.

### Rejected secret-store alternatives

- **SQLCipher:** encrypts the whole database and introduces a specialized SQLite/crypto stack although VPSmith only requires encrypted secret values and intentionally keeps ordinary domain metadata separate.
- **Desktop keyrings / Secret Service:** couple the portable Docker/Podman administration container to host desktop sessions, D-Bus, prompts, and OS-specific adapters.
- **age for every running secret record:** age remains the correct later portable-file envelope, but per-record use would add key/identity management without improving the running local threat boundary.
- **Enterprise KMS:** unnecessary additional infrastructure for a portable local V1 administration tool.

## Module shape

`internal/managementstate` is a deep Module. Its Interface is intentionally small: open/load the state, read a consistent Snapshot, apply an atomic domain Change, resolve a secret for controlled internal use, and close the store. Domain callers do not receive table-level CRUD interfaces and cannot write the persistence layer directly.

The Module owns the invariants that observed state cannot mutate desired state, source synchronization cannot mutate target state, a VPSmith Studio update cannot mutate target Core state, execution history is append-only, and referenced secrets cannot be removed.

## Scope boundary

Step 2 intentionally implements no Git synchronization, SSH connection or execution, deployment compiler, execution bundle creation, backup payload generation, restore, Core lifecycle, Module lifecycle, or new VPSmith Studio management UI. Those later Modules consume this state seam instead of bypassing it.
