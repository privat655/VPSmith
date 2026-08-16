package managementstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type migration struct {
	version int
	up      func(context.Context, *sql.Conn) error
}

var migrations = []migration{{version: 1, up: migrateV1}}

func migrate(ctx context.Context, conn *sql.Conn) error { return migrateWith(ctx, conn, migrations) }

func migrateWith(ctx context.Context, conn *sql.Conn, set []migration) error {
	var current int
	if err := conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&current); err != nil {
		return fmt.Errorf("read management-state schema version: %w", err)
	}
	if current > CurrentSchemaVersion {
		return fmt.Errorf("management-state schema %d is newer than supported schema %d", current, CurrentSchemaVersion)
	}
	for _, item := range set {
		if item.version <= current {
			continue
		}
		if item.version != current+1 {
			return fmt.Errorf("management-state migration gap: have %d, next %d", current, item.version)
		}
		if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
			return fmt.Errorf("begin migration %d: %w", item.version, err)
		}
		committed := false
		func() {
			defer func() {
				if !committed {
					_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
				}
			}()
			if err := item.up(ctx, conn); err != nil {
				return
			}
			if _, err := conn.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", item.version)); err != nil {
				return
			}
			var violations string
			row := conn.QueryRowContext(ctx, "PRAGMA foreign_key_check")
			if err := row.Scan(&violations); err != nil && !errors.Is(err, sql.ErrNoRows) {
				return
			}
			if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
				return
			}
			committed = true
		}()
		if !committed {
			var after int
			_ = conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&after)
			if after != current {
				return fmt.Errorf("migration %d failed and changed schema version", item.version)
			}
			return fmt.Errorf("migration %d failed", item.version)
		}
		current = item.version
	}
	return nil
}

func migrateV1(ctx context.Context, conn *sql.Conn) error {
	const schema = `
CREATE TABLE targets (
  id TEXT PRIMARY KEY,
  address TEXT NOT NULL,
  ssh_user TEXT NOT NULL,
  ssh_identity_secret_id TEXT NOT NULL DEFAULT '',
  ssh_host_key TEXT NOT NULL DEFAULT '',
  ssh_host_fingerprint TEXT NOT NULL DEFAULT '',
  ssh_trust TEXT NOT NULL CHECK (ssh_trust IN ('unknown','confirmed','blocked')),
  desired_json TEXT NOT NULL DEFAULT '{}',
  observed_json TEXT NOT NULL DEFAULT '{}'
) STRICT;
CREATE TABLE core_sources (
  id TEXT PRIMARY KEY,
  role TEXT NOT NULL CHECK (role IN ('embedded','local','target')),
  target_id TEXT NOT NULL DEFAULT '',
  version TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  base_source_id TEXT NOT NULL DEFAULT '',
  UNIQUE(role, target_id, id)
) STRICT;
CREATE TABLE module_sources (
  package_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('remote','local','target')),
  target_id TEXT NOT NULL DEFAULT '',
  owner TEXT NOT NULL DEFAULT '',
  repository TEXT NOT NULL DEFAULT '',
  ref TEXT NOT NULL DEFAULT '',
  commit_sha TEXT NOT NULL DEFAULT '',
  base_commit TEXT NOT NULL DEFAULT '',
  version TEXT NOT NULL,
  package_sha256 TEXT NOT NULL,
  PRIMARY KEY(package_id, role, target_id)
) STRICT;
CREATE TABLE secrets (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  origin TEXT NOT NULL CHECK (origin IN ('generated','user','system')),
  created_at TEXT NOT NULL,
  rotated_at TEXT NOT NULL DEFAULT '',
  rotation_count INTEGER NOT NULL DEFAULT 0 CHECK (rotation_count >= 0),
  ciphertext BLOB
) STRICT;
CREATE TABLE execution_bundles (
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  version TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;
CREATE TABLE execution_records (
  id TEXT PRIMARY KEY,
  bundle_id TEXT NOT NULL REFERENCES execution_bundles(id),
  target_id TEXT NOT NULL,
  outcome TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE TABLE backups (
  id TEXT PRIMARY KEY,
  artifact_type TEXT NOT NULL CHECK (artifact_type IN ('recovery-package','core-backup','module-backup','system-restore-point')),
  target_id TEXT NOT NULL,
  module_instance_id TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  location_ref TEXT NOT NULL DEFAULT '',
  sha256 TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE TRIGGER core_sources_no_update BEFORE UPDATE ON core_sources BEGIN SELECT RAISE(ABORT, 'core source identity is immutable'); END;
CREATE TRIGGER core_sources_no_delete BEFORE DELETE ON core_sources BEGIN SELECT RAISE(ABORT, 'core source identity is immutable'); END;
CREATE TRIGGER module_sources_no_update BEFORE UPDATE ON module_sources BEGIN SELECT RAISE(ABORT, 'module package identity is immutable'); END;
CREATE TRIGGER module_sources_no_delete BEFORE DELETE ON module_sources BEGIN SELECT RAISE(ABORT, 'module package identity is immutable'); END;
CREATE TRIGGER execution_bundles_no_update BEFORE UPDATE ON execution_bundles BEGIN SELECT RAISE(ABORT, 'execution bundle history is immutable'); END;
CREATE TRIGGER execution_bundles_no_delete BEFORE DELETE ON execution_bundles BEGIN SELECT RAISE(ABORT, 'execution bundle history is immutable'); END;
CREATE TRIGGER execution_records_no_update BEFORE UPDATE ON execution_records BEGIN SELECT RAISE(ABORT, 'execution record history is immutable'); END;
CREATE TRIGGER execution_records_no_delete BEFORE DELETE ON execution_records BEGIN SELECT RAISE(ABORT, 'execution record history is immutable'); END;
`
	if _, err := conn.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("create schema v1: %w", err)
	}
	return nil
}
