package managementstate

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func TestMigrationV3RetiresLegacySourceTablesWithoutLosingRows(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:canonical-source-migration?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
		t.Fatal(err)
	}
	if err := migrateWith(ctx, conn, []migration{{version: 1, up: migrateV1}, {version: 2, up: migrateV2}}); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO core_sources(id,role,target_id,version,sha256) VALUES('core_old','embedded','','0.1.0','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO module_sources(package_id,role,target_id,owner,repository,ref,commit_sha,version,package_sha256) VALUES('module-pkg_old','remote','','example','modules','main','abc','0.1.0','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')`); err != nil {
		t.Fatal(err)
	}
	if err := migrateWith(ctx, conn, []migration{{version: 1, up: migrateV1}, {version: 2, up: migrateV2}, {version: 3, up: migrateV3}}); err != nil {
		t.Fatal(err)
	}
	for _, active := range []string{"core_sources", "module_sources"} {
		var count int
		if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, active).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("legacy source table %s remains active", active)
		}
	}
	for _, archived := range []string{"legacy_core_sources_v1", "legacy_module_sources_v1"} {
		var count int
		if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+archived).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("archived source table %s rows=%d, want 1", archived, count)
		}
	}
	var version int
	if err := conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != CurrentSchemaVersion {
		t.Fatalf("schema version=%d want=%d", version, CurrentSchemaVersion)
	}
}
