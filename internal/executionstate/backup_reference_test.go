package executionstate

import (
	"context"
	"testing"

	"github.com/privat655/VPSmith/internal/execution"
	"github.com/privat655/VPSmith/internal/managementstate"
)

func TestRegisterBundlePersistsConcreteBackupReference(t *testing.T) {
	ctx := context.Background()
	store, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	adapter, err := New(store)
	if err != nil {
		t.Fatal(err)
	}

	run := execution.Run{
		ID: "run_update",
		TargetID: "target_1",
		BundleID: "bundle_update",
		BundleSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Kind: "migration",
		Version: "2.0.0",
		BackupRef: "backup_core_immediate",
	}
	if err := adapter.RegisterBundle(ctx, run); err != nil {
		t.Fatal(err)
	}

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.ExecutionBundles) != 1 {
		t.Fatalf("execution bundles=%d", len(snapshot.ExecutionBundles))
	}
	if got := snapshot.ExecutionBundles[0].BackupRef; got != run.BackupRef {
		t.Fatalf("persisted backup ref=%q want=%q", got, run.BackupRef)
	}
}
