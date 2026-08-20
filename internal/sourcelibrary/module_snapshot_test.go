package sourcelibrary

import (
	"context"
	"testing"

	"github.com/privat655/VPSmith/internal/managementstate"
)

func TestFreezeModuleSnapshotAcceptsImmutableModuleAndRejectsCore(t *testing.T) {
	ctx := context.Background()
	store, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	lib, err := New(t.TempDir(), repositoryPath(t, "embedded"), store, &fakeRemote{})
	if err != nil {
		t.Fatal(err)
	}
	snapshots, err := lib.ImportEmbedded(ctx)
	if err != nil {
		t.Fatal(err)
	}

	module := findKind(t, snapshots, managementstate.SourceEmbeddedN8N)
	frozen, err := lib.FreezeModuleSnapshot(ctx, module.ID)
	if err != nil {
		t.Fatal(err)
	}
	if frozen.ID != module.ID || frozen.SHA256 != module.SHA256 || frozen.FS == nil {
		t.Fatalf("unexpected frozen module snapshot: %#v", frozen.Snapshot)
	}

	core := findKind(t, snapshots, managementstate.SourceCore)
	if _, err := lib.FreezeModuleSnapshot(ctx, core.ID); err == nil {
		t.Fatal("Core snapshot accepted as module source")
	}
}
