package backuprestore

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/managementstate"
)

type producerFunc func(context.Context, string) (PayloadDescriptor, error)

func (f producerFunc) Produce(ctx context.Context, root string) (PayloadDescriptor, error) {
	return f(ctx, root)
}

func TestLongTermEnvelopeAgeAndManifestContracts(t *testing.T) {
	ctx := context.Background()
	state, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	targetID, _ := managementstate.NewTargetID()
	if err := state.Change(ctx, func(c *managementstate.Change) error {
		return c.CreateTarget(managementstate.TargetRegistration{ID: targetID, Address: "127.0.0.1", SSHUser: "admin"})
	}); err != nil {
		t.Fatal(err)
	}
	manager, err := New(t.TempDir(), t.TempDir(), state)
	if err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("correct horse battery staple")
	producer := producerFunc(func(_ context.Context, root string) (PayloadDescriptor, error) {
		return PayloadDescriptor{SourceRefs: []string{"source:abc"}}, os.WriteFile(filepath.Join(root, "state.json"), []byte("secret-payload"), 0o600)
	})
	artifact, err := manager.Create(ctx, CreateRequest{Type: managementstate.BackupRecoveryPackage, TargetID: targetID, Passphrase: passphrase, Producer: producer})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(artifact.Path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), string(passphrase)) || strings.Contains(string(data), "secret-payload") {
		t.Fatal("encrypted artifact leaks plaintext")
	}
	inspection, err := manager.Inspect(ctx, artifact.Path, managementstate.BackupRecoveryPackage, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if err := inspection.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Inspect(ctx, artifact.Path, managementstate.BackupCore, passphrase); err == nil {
		t.Fatal("wrong artifact type accepted")
	}
	if _, err := manager.Inspect(ctx, artifact.Path, managementstate.BackupRecoveryPackage, []byte("wrong")); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
}

func TestSystemRestorePointCarriesExactModuleIdentity(t *testing.T) {
	ctx := context.Background()
	state, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	target, _ := managementstate.NewTargetID()
	module, _ := managementstate.NewModuleInstanceID()
	if err := state.Change(ctx, func(c *managementstate.Change) error {
		return c.CreateTarget(managementstate.TargetRegistration{ID: target, Address: "127.0.0.1", SSHUser: "admin"})
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
		Version:                 "1.2.3",
		GitCommit:               strings.Repeat("a", 40),
		PackageSHA256:           strings.Repeat("b", 64),
		Images:                  []ImageIdentity{{Name: "app", Digest: "sha256:" + strings.Repeat("c", 64)}},
		StoragePaths:            []string{"/srv/module/data"},
		SecretIDs:               []managementstate.SecretID{"secret_example"},
		PreviousDesiredStateRef: "desired:before-update",
	}
	producer := producerFunc(func(_ context.Context, root string) (PayloadDescriptor, error) {
		return PayloadDescriptor{Identity: identity}, os.WriteFile(filepath.Join(root, "data"), []byte("x"), 0o600)
	})
	artifact, err := manager.Create(ctx, CreateRequest{Type: managementstate.BackupSystemRestorePoint, TargetID: target, ModuleInstanceID: module, Producer: producer})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Ext(artifact.Path) == ".age" {
		t.Fatal("system restore point was encrypted")
	}
	for _, name := range []string{"manifest.yaml", "storage.tar.zst", "SHA256SUMS"} {
		if _, err := os.Stat(filepath.Join(artifact.Path, name)); err != nil {
			t.Fatal(err)
		}
	}
	inspection, err := manager.Inspect(ctx, artifact.Path, managementstate.BackupSystemRestorePoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Manifest.Identity == nil || inspection.Manifest.Identity.PackageSHA256 != identity.PackageSHA256 || inspection.Manifest.Identity.Images[0].Digest != identity.Images[0].Digest {
		t.Fatal("exact module identity was not preserved in manifest")
	}
}

func TestSystemRestorePointRejectsIncompleteIdentity(t *testing.T) {
	ctx := context.Background()
	state, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	target, _ := managementstate.NewTargetID()
	module, _ := managementstate.NewModuleInstanceID()
	if err := state.Change(ctx, func(c *managementstate.Change) error {
		return c.CreateTarget(managementstate.TargetRegistration{ID: target, Address: "127.0.0.1", SSHUser: "admin"})
	}); err != nil {
		t.Fatal(err)
	}
	manager, err := New(t.TempDir(), t.TempDir(), state)
	if err != nil {
		t.Fatal(err)
	}
	producer := producerFunc(func(_ context.Context, root string) (PayloadDescriptor, error) {
		return PayloadDescriptor{}, os.WriteFile(filepath.Join(root, "data"), []byte("x"), 0o600)
	})
	if _, err := manager.Create(ctx, CreateRequest{Type: managementstate.BackupSystemRestorePoint, TargetID: target, ModuleInstanceID: module, Producer: producer}); err == nil {
		t.Fatal("system restore point without exact identity was accepted")
	}
}

func TestDeleteRollsBackArtifactMoveWhenCatalogueDeleteFails(t *testing.T) {
	ctx := context.Background()
	state, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	target, _ := managementstate.NewTargetID()
	if err := state.Change(ctx, func(c *managementstate.Change) error {
		return c.CreateTarget(managementstate.TargetRegistration{ID: target, Address: "127.0.0.1", SSHUser: "admin"})
	}); err != nil {
		t.Fatal(err)
	}
	manager, err := New(t.TempDir(), t.TempDir(), state)
	if err != nil {
		t.Fatal(err)
	}
	producer := producerFunc(func(_ context.Context, root string) (PayloadDescriptor, error) {
		return PayloadDescriptor{}, os.WriteFile(filepath.Join(root, "state"), []byte("x"), 0o600)
	})
	artifact, err := manager.Create(ctx, CreateRequest{Type: managementstate.BackupRecoveryPackage, TargetID: target, Passphrase: []byte("test-passphrase"), Producer: producer})
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := manager.Delete(cancelled, artifact.Metadata.ID); err == nil {
		t.Fatal("delete unexpectedly succeeded with cancelled catalogue transaction")
	}
	if _, err := os.Stat(artifact.Path); err != nil {
		t.Fatalf("artifact bytes were not restored after failed catalogue delete: %v", err)
	}
	snapshot, err := state.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Backups) != 1 || snapshot.Backups[0].ID != artifact.Metadata.ID {
		t.Fatal("catalogue metadata changed after failed delete")
	}
}
