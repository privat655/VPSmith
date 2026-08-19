package sourcelibrary

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/sourcehash"
)

type recoveryTestRemote struct{}

func (recoveryTestRemote) Fetch(context.Context, RemoteConfig, string) (FetchResult, error) {
	return FetchResult{}, errors.New("unused")
}

func (recoveryTestRemote) Push(context.Context, PushRequest) (PushResult, error) {
	return PushResult{}, errors.New("unused")
}

func TestPrepareRecoveryImportReusesExactOrphanWorkspace(t *testing.T) {
	ctx := context.Background()
	state, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	root := t.TempDir()
	library, err := New(root, t.TempDir(), state, recoveryTestRemote{})
	if err != nil {
		t.Fatal(err)
	}
	workspaceID := managementstate.SourceWorkspaceID("workspace_recovery_retry")
	storageRef := filepath.ToSlash(filepath.Join("workspaces", string(workspaceID)))
	target := filepath.Join(root, filepath.FromSlash(storageRef))
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "local.conf"), []byte("same recovery workspace\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sha, err := sourcehash.TreeSHA256(target)
	if err != nil {
		t.Fatal(err)
	}
	sourceRoot := t.TempDir()
	source := filepath.Join(sourceRoot, filepath.FromSlash(storageRef))
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "local.conf"), []byte("same recovery workspace\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	expected := managementstate.SourceState{Workspaces: []managementstate.SourceWorkspace{{
		ID: workspaceID, Kind: managementstate.SourceCore, CurrentSHA256: sha, StorageRef: storageRef,
	}}}
	prepared, err := library.PrepareRecoveryImport(ctx, sourceRoot, expected)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	if len(prepared.trees) != 0 {
		t.Fatalf("exact orphan workspace was staged again: %d trees", len(prepared.trees))
	}
}

func TestPrepareRecoveryImportRejectsDifferentOrphanWorkspace(t *testing.T) {
	ctx := context.Background()
	state, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	root := t.TempDir()
	library, err := New(root, t.TempDir(), state, recoveryTestRemote{})
	if err != nil {
		t.Fatal(err)
	}
	workspaceID := managementstate.SourceWorkspaceID("workspace_recovery_conflict")
	storageRef := filepath.ToSlash(filepath.Join("workspaces", string(workspaceID)))
	target := filepath.Join(root, filepath.FromSlash(storageRef))
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "local.conf"), []byte("different\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sourceRoot := t.TempDir()
	source := filepath.Join(sourceRoot, filepath.FromSlash(storageRef))
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "local.conf"), []byte("recovered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sha, err := sourcehash.TreeSHA256(source)
	if err != nil {
		t.Fatal(err)
	}
	expected := managementstate.SourceState{Workspaces: []managementstate.SourceWorkspace{{
		ID: workspaceID, Kind: managementstate.SourceCore, CurrentSHA256: sha, StorageRef: storageRef,
	}}}
	if _, err := library.PrepareRecoveryImport(ctx, sourceRoot, expected); err == nil {
		t.Fatal("different orphan workspace was accepted for recovery reuse")
	}
}
