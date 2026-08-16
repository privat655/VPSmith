package managementstate

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestManagementStateMigratesRealV1ToV2SourceSchema(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "migration.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
		t.Fatal(err)
	}
	if err := migrateWith(ctx, conn, []migration{{version: 1, up: migrateV1}}); err != nil {
		t.Fatal(err)
	}
	var version int
	if err := conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Fatalf("expected schema v1 before upgrade, got %d", version)
	}
	if err := migrateWith(ctx, conn, migrations); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != CurrentSchemaVersion {
		t.Fatalf("expected schema v%d after upgrade, got %d", CurrentSchemaVersion, version)
	}
	for _, table := range []string{"source_artifacts", "source_workspaces", "custom_module_github"} {
		var count int
		if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("migration did not create %s", table)
		}
	}
}
