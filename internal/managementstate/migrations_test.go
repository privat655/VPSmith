package managementstate

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestMigrationFailureRollsBackCompletely(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:migration-test?mode=memory&cache=shared")
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
	if err := migrateWith(ctx, conn, []migration{{version: 1, up: migrateV1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO targets(id,address,ssh_user,ssh_trust) VALUES('target_before_failure','203.0.113.99','dev','confirmed')`); err != nil {
		t.Fatal(err)
	}

	failing := migration{version: 2, up: func(ctx context.Context, conn *sql.Conn) error {
		if _, err := conn.ExecContext(ctx, `CREATE TABLE should_rollback(id TEXT PRIMARY KEY) STRICT`); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, `UPDATE targets SET address='198.51.100.77' WHERE id='target_before_failure'`); err != nil {
			return err
		}
		return errors.New("intentional migration failure")
	}}
	if err := migrateWith(ctx, conn, []migration{{version: 1, up: migrateV1}, failing}); err == nil {
		t.Fatal("failing migration unexpectedly succeeded")
	}

	var version int
	if err := conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Fatalf("schema version after rollback = %d, want 1", version)
	}
	var count int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='should_rollback'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("failed migration left its table behind")
	}
	var address string
	if err := conn.QueryRowContext(ctx, `SELECT address FROM targets WHERE id='target_before_failure'`).Scan(&address); err != nil {
		t.Fatal(err)
	}
	if address != "203.0.113.99" {
		t.Fatalf("failed migration changed existing state: address=%q", address)
	}
	var integrity string
	if err := conn.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil {
		t.Fatal(err)
	}
	if strings.ToLower(integrity) != "ok" {
		t.Fatalf("integrity_check = %q", integrity)
	}
}

func TestMigrationRejectsNewerSchema(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:newer-schema?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "PRAGMA user_version = 999"); err != nil {
		t.Fatal(err)
	}
	if err := migrate(ctx, conn); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("migrate() error = %v", err)
	}
}
