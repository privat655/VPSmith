package backuprestore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/privat655/VPSmith/internal/managementstate"
)

type storageFixture struct {
	data    []byte
	sha     string
	cleaned bool
}

func (s *storageFixture) PrepareStorageCopy(context.Context, string, []string) (string, string, int64, error) {
	return "copy-test-1", s.sha, int64(len(s.data)), nil
}
func (s *storageFixture) TransferStorageCopy(context.Context, string, string) ([]byte, error) {
	return append([]byte(nil), s.data...), nil
}
func (s *storageFixture) CleanupStorageCopy(context.Context, string, string) error {
	s.cleaned = true
	return nil
}

func TestStorageCopyCleansTargetOnlyAfterLocalVerification(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "data"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "storage.tar.zst")
	if err := CreateTarZst(root, archive); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	fixture := &storageFixture{data: data, sha: hex.EncodeToString(sum[:])}
	state, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	manager, err := New(t.TempDir(), t.TempDir(), state)
	if err != nil {
		t.Fatal(err)
	}
	copy, err := manager.CopyOfflineStorage(context.Background(), fixture, "target_test", []string{"/srv/data"})
	if err != nil {
		t.Fatal(err)
	}
	if !fixture.cleaned || copy.Token != "" || copy.ArchivePath == "" {
		t.Fatal("verified target storage copy was not cleaned and retained locally")
	}
	archivePath := copy.ArchivePath
	if err := copy.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(archivePath); !os.IsNotExist(err) {
		t.Fatalf("volatile storage copy survived Close: %v", err)
	}
}

func TestStorageCopyRetainsTargetMaterialWhenVerificationFails(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "data"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "storage.tar.zst")
	if err := CreateTarZst(root, archive); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &storageFixture{data: data, sha: "0000000000000000000000000000000000000000000000000000000000000000"}
	state, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	manager, err := New(t.TempDir(), t.TempDir(), state)
	if err != nil {
		t.Fatal(err)
	}
	copy, err := manager.CopyOfflineStorage(context.Background(), fixture, "target_test", []string{"/srv/data"})
	if err == nil || fixture.cleaned || copy.Token == "" {
		t.Fatal("verification failure must retain explicit target cleanup token")
	}
}
