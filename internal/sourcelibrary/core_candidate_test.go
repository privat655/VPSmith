package sourcelibrary

import (
	"context"
	"io/fs"
	"testing"

	"github.com/privat655/VPSmith/internal/managementstate"
)

func TestFreezeCoreCandidateNeverExposesMutableWorkspace(t *testing.T) {
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
	base := findKind(t, snapshots, managementstate.SourceCore)
	workspace, err := lib.CreateWorkspace(ctx, base.ID)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err = lib.Apply(ctx, workspace.ID, []Edit{{Path: "README.md", Content: []byte("local Core candidate\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}

	frozen, err := lib.FreezeCoreCandidate(ctx, CoreCandidateRef{WorkspaceID: workspace.ID})
	if err != nil {
		t.Fatal(err)
	}
	if frozen.ID == "" || frozen.ID == base.ID {
		t.Fatalf("workspace was not frozen as a distinct immutable source: %#v", frozen.Snapshot)
	}
	if frozen.SHA256 != workspace.SHA256 {
		t.Fatalf("frozen sha=%s workspace sha=%s", frozen.SHA256, workspace.SHA256)
	}
	before, err := fs.ReadFile(frozen.FS, "README.md")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := lib.Apply(ctx, workspace.ID, []Edit{{Path: "README.md", Content: []byte("changed after freeze\n"), Mode: 0o644}}); err != nil {
		t.Fatal(err)
	}
	after, err := fs.ReadFile(frozen.FS, "README.md")
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("frozen Core candidate changed after workspace mutation")
	}
}

func TestFreezeCoreCandidateRejectsAmbiguousReference(t *testing.T) {
	store, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	lib, err := New(t.TempDir(), repositoryPath(t, "embedded"), store, &fakeRemote{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = lib.FreezeCoreCandidate(context.Background(), CoreCandidateRef{
		SnapshotID:  "source_one",
		WorkspaceID: "workspace_one",
	})
	if err == nil {
		t.Fatal("ambiguous Core candidate must fail closed")
	}
}
