package sourcelibrary

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/managementstate"
)

func TestGitAdapterRejectsEveryForcePushShape(t *testing.T) {
	ctx := context.Background()
	for _, args := range [][]string{
		{"push", "origin", "--force"},
		{"push", "origin", "--force-with-lease"},
		{"push", "origin", "+HEAD:refs/heads/main"},
	} {
		if _, err := gitCommand(ctx, t.TempDir(), "", args...); err == nil || !strings.Contains(err.Error(), "unsafe git push option") {
			t.Fatalf("unsafe Git arguments were not rejected: %#v err=%v", args, err)
		}
	}
}

func TestGitErrorsNeverContainPATMaterial(t *testing.T) {
	const token = "github_pat_plaintext_must_never_escape"
	_, err := gitCommand(context.Background(), t.TempDir(), token, "rev-parse", "definitely-missing")
	if err == nil {
		t.Fatal("expected git command failure")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("PAT leaked through error: %v", err)
	}
}

func TestPostPushRemoteMismatchIsNotMarkedSynchronized(t *testing.T) {
	ctx := context.Background()
	store, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	configureRemote(t, ctx, store)
	remote := &postMismatchRemote{}
	lib, err := New(t.TempDir(), repositoryPath(t, "embedded"), store, remote)
	if err != nil {
		t.Fatal(err)
	}
	packageID, err := managementstate.NewModulePackageID()
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := lib.importSnapshot(ctx, managementstate.SourceCustomModule, packageID, "modules/demo", "1.0.0", "base-commit", tree(t, "base\n"), "")
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := lib.CreateWorkspace(ctx, snapshot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lib.Apply(ctx, workspace.ID, []Edit{{Path: "file.txt", Content: []byte("local\n"), Mode: 0o644}}); err != nil {
		t.Fatal(err)
	}
	_, err = lib.PushCustomModule(ctx, workspace.ID, "update")
	var drift *RemoteDriftError
	if !errors.As(err, &drift) {
		t.Fatalf("post-push ref mismatch must be visible as remote drift, got %v", err)
	}
	state, err := store.Sources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, current := range state.Workspaces {
		if current.ID == workspace.ID && current.SynchronizedCommit != "" {
			t.Fatal("post-push mismatch was marked synchronized")
		}
	}
}

func TestImmutableSnapshotTamperingFailsClosed(t *testing.T) {
	ctx := context.Background()
	store, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	root := t.TempDir()
	lib, err := New(root, repositoryPath(t, "embedded"), store, &fakeRemote{})
	if err != nil {
		t.Fatal(err)
	}
	snapshots, err := lib.ImportEmbedded(ctx)
	if err != nil {
		t.Fatal(err)
	}
	core := findKind(t, snapshots, managementstate.SourceCore)
	path := filepath.Join(root, "snapshots", "sha256", core.SHA256, "README.md")
	if err := os.WriteFile(path, []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := lib.CreateWorkspace(ctx, core.ID); err == nil || !strings.Contains(err.Error(), "immutable source snapshot") {
		t.Fatalf("tampered snapshot did not fail closed: %v", err)
	}
}

func TestLocalSourceOperationsDoNotChangeTargetState(t *testing.T) {
	ctx := context.Background()
	store, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	targetID, err := managementstate.NewTargetID()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Change(ctx, func(change *managementstate.Change) error {
		return change.CreateTarget(managementstate.TargetRegistration{
			ID: targetID, Address: "203.0.113.50", SSHUser: "admin", SSHTrust: managementstate.TrustUnknown,
		})
	}); err != nil {
		t.Fatal(err)
	}
	before, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lib, err := New(t.TempDir(), repositoryPath(t, "embedded"), store, &fakeRemote{})
	if err != nil {
		t.Fatal(err)
	}
	snapshots, err := lib.ImportEmbedded(ctx)
	if err != nil {
		t.Fatal(err)
	}
	core := findKind(t, snapshots, managementstate.SourceCore)
	workspace, err := lib.CreateWorkspace(ctx, core.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lib.Apply(ctx, workspace.ID, []Edit{{Path: "README.md", Content: []byte("local only\n"), Mode: 0o644}}); err != nil {
		t.Fatal(err)
	}
	after, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before.Targets, after.Targets) {
		t.Fatalf("local source operation changed target state\nbefore=%#v\nafter=%#v", before.Targets, after.Targets)
	}
}

type postMismatchRemote struct{}

func (*postMismatchRemote) Fetch(context.Context, RemoteConfig, string) (FetchResult, error) {
	return FetchResult{}, errors.New("unused")
}

func (*postMismatchRemote) Push(context.Context, PushRequest) (PushResult, error) {
	return PushResult{Commit: "our-commit", RemoteCommit: "raced-remote-commit"}, nil
}
