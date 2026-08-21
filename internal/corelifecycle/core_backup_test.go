package corelifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/backuprestore"
	"github.com/privat655/VPSmith/internal/managementstate"
)

type coreBackupTestInspector struct{ observed managementstate.ObservedState }

func (i coreBackupTestInspector) Inspect(context.Context, managementstate.TargetID) (managementstate.ObservedState, error) {
	return i.observed, nil
}

type coreBackupTestStorage struct {
	archive    []byte
	sha256     string
	calls      []string
	paths      []string
	resumeErr  error
	cleanupErr error
}

func (s *coreBackupTestStorage) QuiesceCoreRuntime(context.Context, string) error {
	s.calls = append(s.calls, "quiesce")
	return nil
}

func (s *coreBackupTestStorage) ResumeAndValidateCoreRuntime(context.Context, string) error {
	s.calls = append(s.calls, "resume")
	return s.resumeErr
}

func (s *coreBackupTestStorage) PrepareStorageCopy(_ context.Context, _ string, paths []string) (string, string, int64, error) {
	s.calls = append(s.calls, "prepare")
	s.paths = append([]string(nil), paths...)
	return "copy-1", s.sha256, int64(len(s.archive)), nil
}

func (s *coreBackupTestStorage) TransferStorageCopy(_ context.Context, _ string, _ string, destination io.Writer) error {
	s.calls = append(s.calls, "transfer")
	_, err := destination.Write(s.archive)
	return err
}

func (s *coreBackupTestStorage) CleanupStorageCopy(context.Context, string, string) error {
	s.calls = append(s.calls, "cleanup")
	return s.cleanupErr
}

func TestCoreBackupQuiescesCopiesResumesValidatesThenPersists(t *testing.T) {
	ctx := context.Background()
	lifecycle, backups, storage, targetID, passphrase := newCoreBackupTestLifecycle(t)

	artifact, err := lifecycle.Backup(ctx, BackupRequest{TargetID: targetID, Passphrase: passphrase})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Metadata.ID == "" {
		t.Fatal("Core backup was not catalogued")
	}
	if want := []string{"quiesce", "prepare", "transfer", "resume", "cleanup"}; !reflect.DeepEqual(storage.calls, want) {
		t.Fatalf("Core backup operation order=%#v want=%#v", storage.calls, want)
	}
	if !reflect.DeepEqual(storage.paths, coreBackupStoragePaths()) {
		t.Fatalf("Core backup storage scope=%#v want=%#v", storage.paths, coreBackupStoragePaths())
	}

	inspection, err := backups.InspectArtifact(ctx, artifact.Metadata.ID, managementstate.BackupCore, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer inspection.Close()
	root := t.TempDir()
	if err := backuprestore.ExtractTarZst(inspection.PayloadPath, root, backuprestore.ArchiveOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"management/core-desired.json", coreBackupImageLocksRef, "var/lib/vpsmith/core/authelia/data/state.db", "var/lib/vpsmith/secrets/core/session", "var/lib/vpsmith/inventory/core.json"} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(required))); err != nil {
			t.Fatalf("Core backup payload missing %s: %v", required, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/vpsmith/core/desired.json")); !os.IsNotExist(err) {
		t.Fatalf("generated desired.json survived canonical backup payload: %v", err)
	}
}

func TestCoreBackupResumeFailureDoesNotPersistArtifactAndCleansPlaintext(t *testing.T) {
	ctx := context.Background()
	lifecycle, _, storage, targetID, passphrase := newCoreBackupTestLifecycle(t)
	storage.resumeErr = errors.New("runtime validation failed")

	if _, err := lifecycle.Backup(ctx, BackupRequest{TargetID: targetID, Passphrase: passphrase}); err == nil || !strings.Contains(err.Error(), "runtime validation failed") {
		t.Fatalf("Core backup resume failure = %v", err)
	}
	if want := []string{"quiesce", "prepare", "transfer", "resume", "cleanup"}; !reflect.DeepEqual(storage.calls, want) {
		t.Fatalf("failed Core backup operation order=%#v want=%#v", storage.calls, want)
	}
	snapshot, err := lifecycle.state.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Backups) != 0 {
		t.Fatalf("failed Core backup was catalogued: %#v", snapshot.Backups)
	}
}

func newCoreBackupTestLifecycle(t *testing.T) (*Lifecycle, *backuprestore.Manager, *coreBackupTestStorage, managementstate.TargetID, []byte) {
	t.Helper()
	ctx := context.Background()
	store, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	const packageSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	targetID := managementstate.TargetID("target-core-backup")
	preparedState, observed := validCorePostState()
	desired := preparedState.DesiredCore
	if err := store.Change(ctx, func(change *managementstate.Change) error {
		if err := change.CreateTarget(managementstate.TargetRegistration{ID: targetID, Address: "203.0.113.10", SSHUser: "vpsmith"}); err != nil {
			return err
		}
		if err := change.RegisterSourceArtifact(managementstate.SourceArtifact{ID: "core-source", Kind: managementstate.SourceCore, Version: "1.0.0", SHA256: packageSHA, StorageRef: "snapshots/sha256/" + packageSHA}); err != nil {
			return err
		}
		return change.SetDesiredState(targetID, managementstate.DesiredState{Core: desired})
	}); err != nil {
		t.Fatal(err)
	}

	observed.Core.SourceID = desired.SourceID
	observed.Core.Version = desired.Version
	observed.Core.PackageSHA256 = packageSHA
	archive := coreBackupTestArchive(t, observed)
	sum := sha256.Sum256(archive)
	storage := &coreBackupTestStorage{archive: archive, sha256: hex.EncodeToString(sum[:])}
	backups, err := backuprestore.New(t.TempDir(), t.TempDir(), store)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle := &Lifecycle{state: store, inspector: coreBackupTestInspector{observed: observed}, backups: backups, storage: storage}
	return lifecycle, backups, storage, targetID, []byte("test-only-Core-backup-passphrase")
}

func coreBackupTestArchive(t *testing.T, observed managementstate.ObservedState) []byte {
	t.Helper()
	root := t.TempDir()
	lock := coreBackupImageLocks{
		SourceID: observed.Core.SourceID, Version: observed.Core.Version, PackageSHA256: observed.Core.PackageSHA256,
		Images: map[string]coreBackupImage{
			"caddy":    {Ref: testCaddyRef, Digest: testCaddyDigest},
			"authelia": {Ref: testAutheliaRef, Digest: testAutheliaDigest},
		},
	}
	data, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"var/lib/vpsmith/core/desired.json":            data,
		"var/lib/vpsmith/core/authelia/data/state.db": []byte("authelia-state"),
		"var/lib/vpsmith/secrets/core/session":         []byte("test-secret"),
		"var/lib/vpsmith/inventory/core.json":          []byte("{}\n"),
		"var/lib/vpsmith/execution/proof.json":         []byte("{}\n"),
	}
	for path, content := range files {
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	archivePath := filepath.Join(t.TempDir(), "storage.tar.zst")
	if err := backuprestore.CreateTarZst(root, archivePath); err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	return archive
}
