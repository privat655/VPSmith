package backuprestore

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/privat655/VPSmith/internal/managementstate"
)

type restoreArtifactProducer struct{}

func (restoreArtifactProducer) Produce(_ context.Context, root string) (PayloadDescriptor, error) {
	if err := os.WriteFile(filepath.Join(root, "state.txt"), []byte("previous-state\n"), 0o600); err != nil {
		return PayloadDescriptor{}, err
	}
	return PayloadDescriptor{Identity: &ArtifactIdentity{
		SubjectKind:   "core",
		SubjectID:     "core-source",
		Version:       "1.0.0",
		PackageSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}}, nil
}

func TestPrepareRestoreArtifactKeepsVerifiedPayloadAndCandidateInVolatileScratch(t *testing.T) {
	ctx := context.Background()
	state, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	targetID := managementstate.TargetID("target-restore-artifact")
	if err := state.Change(ctx, func(change *managementstate.Change) error {
		return change.CreateTarget(managementstate.TargetRegistration{ID: targetID, Address: "203.0.113.10", SSHUser: "vpsmith"})
	}); err != nil {
		t.Fatal(err)
	}
	manager, err := New(t.TempDir(), t.TempDir(), state)
	if err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("test-only-restore-passphrase")
	artifact, err := manager.Create(ctx, CreateRequest{Type: managementstate.BackupCore, TargetID: targetID, Passphrase: passphrase, Producer: restoreArtifactProducer{}})
	if err != nil {
		t.Fatal(err)
	}

	prepared, err := manager.PrepareRestoreArtifact(ctx, artifact.Metadata.ID, managementstate.BackupCore, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.PayloadPath == "" || prepared.PayloadSHA256 == "" || prepared.PayloadSize <= 0 {
		t.Fatalf("verified payload identity is incomplete: %#v", prepared)
	}
	if _, err := os.Stat(prepared.PayloadPath); err != nil {
		t.Fatalf("verified payload is unavailable: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(prepared.CandidateRoot, "state.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "previous-state\n" {
		t.Fatalf("restore candidate content=%q", data)
	}
	work := prepared.workDir
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(work); !os.IsNotExist(err) {
		t.Fatalf("volatile restore work survived close: %v", err)
	}
}
