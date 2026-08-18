package managementstate

import (
	"context"
	"database/sql"
	"fmt"
)

func init() {
	migrations = append(migrations, migration{version: 3, up: migrateV3})
}

// migrateV3 retires the Step-2 source tables after Step 3 established
// source_artifacts/source_workspaces as the canonical source model. Historical
// rows are retained under explicit legacy names for forensic/manual recovery,
// but no runtime read or write path consults them after this migration.
func migrateV3(ctx context.Context, conn *sql.Conn) error {
	const schema = `
DROP TRIGGER IF EXISTS core_sources_no_update;
DROP TRIGGER IF EXISTS core_sources_no_delete;
DROP TRIGGER IF EXISTS module_sources_no_update;
DROP TRIGGER IF EXISTS module_sources_no_delete;
ALTER TABLE core_sources RENAME TO legacy_core_sources_v1;
ALTER TABLE module_sources RENAME TO legacy_module_sources_v1;
`
	if _, err := conn.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("retire legacy source schema: %w", err)
	}
	return nil
}
