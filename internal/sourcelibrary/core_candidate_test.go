package sourcelibrary

import (
	"context"
	"io/fs"
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/managementstate"
)

func TestFreezeCoreCandidateRejectsMutableWorkspaceUntilExplicitAdoption(t *testing.T) {
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

	if _, err := lib.FreezeCoreCandidate(ctx, CoreCandidateRef{WorkspaceID: workspace.ID}); err == nil || !strings.Contains(err.Error(), "explicitly adopted") {
		t.Fatalf("mutable workspace freeze error=%v", err)
	}
}

func TestAdoptCoreWorkspaceCreatesImmutableSnapshotBeforePlanning(t *testing.T) {
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

	adopted, err := lib.AdoptCoreWorkspace(ctx, workspace.ID)
	if err != nil {
		t.Fatal(err)
	}
	if adopted.ID == "" || adopted.ID == base.ID || adopted.SHA256 != workspace.SHA256 {
		t.Fatalf("workspace was not explicitly adopted as exact immutable source: %#v", adopted.Snapshot)
	}
	before, err := fs.ReadFile(adopted.FS, "README.md")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lib.Apply(ctx, workspace.ID, []Edit{{Path: "README.md", Content: []byte("changed after adoption\n"), Mode: 0o644}}); err != nil {
		t.Fatal(err)
	}
	after, err := fs.ReadFile(adopted.FS, "README.md")
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("adopted Core snapshot changed after workspace mutation")
	}
	frozen, err := lib.FreezeCoreCandidate(ctx, CoreCandidateRef{SnapshotID: adopted.ID})
	if err != nil {
		t.Fatal(err)
	}
	if frozen.SHA256 != adopted.SHA256 {
		t.Fatal("adopted snapshot could not be selected for later planning")
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
