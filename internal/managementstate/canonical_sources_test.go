package managementstate

import (
	"context"
	"strings"
	"testing"
)

// This regression test closes the Step-2/Step-3 split-brain source model.
func TestSnapshotUsesCanonicalSourceStateOnly(t *testing.T) {
	store, err := NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()

	id, err := NewSourceSnapshotID()
	if err != nil {
		t.Fatal(err)
	}
	artifact := SourceArtifact{
		ID: id, Kind: SourceCloudInit, Version: "cloud-v1",
		SHA256: strings.Repeat("a", 64), StorageRef: "snapshots/sha256/test",
	}
	if err := store.Change(ctx, func(change *Change) error { return change.RegisterSourceArtifact(artifact) }); err != nil {
		t.Fatal(err)
	}

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Sources.Artifacts) != 1 || snapshot.Sources.Artifacts[0].ID != id {
		t.Fatalf("snapshot canonical sources = %#v", snapshot.Sources)
	}

	var legacyTables int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('core_sources','module_sources')`).Scan(&legacyTables); err != nil {
		t.Fatal(err)
	}
	if legacyTables != 0 {
		t.Fatalf("legacy source tables remain active: %d", legacyTables)
	}
}
