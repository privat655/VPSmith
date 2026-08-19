package backuprestore

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/managementstate"
)

func TestSystemRestorePointRejectsTamperedManifestAndPayload(t *testing.T) {
	ctx := context.Background()
	newArtifact := func(t *testing.T) (*Manager, Artifact) {
		t.Helper()
		state, err := managementstate.NewMemory()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = state.Close() })
		target, _ := managementstate.NewTargetID()
		module, _ := managementstate.NewModuleInstanceID()
		if err := state.Change(ctx, func(change *managementstate.Change) error {
			return change.CreateTarget(managementstate.TargetRegistration{ID: target, Address: "127.0.0.1", SSHUser: "admin"})
		}); err != nil {
			t.Fatal(err)
		}
		manager, err := New(t.TempDir(), t.TempDir(), state)
		if err != nil {
			t.Fatal(err)
		}
		identity := &ArtifactIdentity{
			SubjectKind:             "module",
			SubjectID:               string(module),
			Version:                 "1.0.0",
			GitCommit:               strings.Repeat("a", 40),
			PackageSHA256:           strings.Repeat("b", 64),
			Images:                  []ImageIdentity{{Name: "app", Digest: "sha256:" + strings.Repeat("c", 64)}},
			StoragePaths:            []string{"/srv/module/data"},
			PreviousDesiredStateRef: "desired:before-update",
		}
		artifact, err := manager.Create(ctx, CreateRequest{
			Type:             managementstate.BackupSystemRestorePoint,
			TargetID:         target,
			ModuleInstanceID: module,
			Producer: producerFunc(func(_ context.Context, root string) (PayloadDescriptor, error) {
				return PayloadDescriptor{Identity: identity}, os.WriteFile(filepath.Join(root, "data"), []byte("payload"), 0o600)
			}),
		})
		if err != nil {
			t.Fatal(err)
		}
		return manager, artifact
	}

	for _, tc := range []struct {
		name string
		file string
	}{
		{name: "manifest", file: "manifest.yaml"},
		{name: "payload", file: "storage.tar.zst"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager, artifact := newArtifact(t)
			filename := filepath.Join(artifact.Path, tc.file)
			file, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.Write([]byte("tamper")); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Inspect(ctx, artifact.Path, managementstate.BackupSystemRestorePoint, nil); err == nil {
				t.Fatalf("tampered %s was accepted", tc.file)
			}
		})
	}
}
