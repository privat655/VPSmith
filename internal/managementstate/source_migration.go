package managementstate

import (
	"context"
	"database/sql"
	"fmt"
)

func init() { migrations = append(migrations, migration{version: 2, up: migrateV2}) }

func migrateV2(ctx context.Context, conn *sql.Conn) error {
	const schema = `
CREATE TABLE source_artifacts (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('cloud-init','core','embedded-n8n','custom-module')),
  package_id TEXT NOT NULL DEFAULT '',
  package_path TEXT NOT NULL DEFAULT '',
  version TEXT NOT NULL,
  commit_sha TEXT NOT NULL DEFAULT '',
  sha256 TEXT NOT NULL,
  storage_ref TEXT NOT NULL,
  UNIQUE(kind, package_id, commit_sha, sha256)
) STRICT;
CREATE TABLE source_workspaces (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('cloud-init','core','embedded-n8n','custom-module')),
  package_id TEXT NOT NULL DEFAULT '',
  package_path TEXT NOT NULL DEFAULT '',
  base_source_id TEXT NOT NULL REFERENCES source_artifacts(id),
  base_commit TEXT NOT NULL DEFAULT '',
  current_sha256 TEXT NOT NULL,
  storage_ref TEXT NOT NULL,
  synchronized_commit TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE TABLE custom_module_github (
  singleton INTEGER PRIMARY KEY CHECK (singleton=1),
  owner TEXT NOT NULL,
  repository TEXT NOT NULL,
  ref TEXT NOT NULL,
  pat_secret_id TEXT NOT NULL REFERENCES secrets(id) ON DELETE RESTRICT
) STRICT;
CREATE TRIGGER source_artifacts_no_update BEFORE UPDATE ON source_artifacts BEGIN SELECT RAISE(ABORT, 'source artifact identity is immutable'); END;
CREATE TRIGGER source_artifacts_no_delete BEFORE DELETE ON source_artifacts BEGIN SELECT RAISE(ABORT, 'source artifact identity is immutable'); END;
CREATE TRIGGER source_workspace_base_immutable BEFORE UPDATE OF kind,package_id,package_path,base_source_id,base_commit,storage_ref ON source_workspaces BEGIN SELECT RAISE(ABORT, 'source workspace base is immutable'); END;
`
	if _, err := conn.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("create schema v2: %w", err)
	}
	return nil
}
