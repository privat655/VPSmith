package backuprestore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type TargetStorage interface {
	PrepareStorageCopy(context.Context, string, []string) (token, sha256 string, size int64, err error)
	TransferStorageCopy(context.Context, string, string) ([]byte, error)
	CleanupStorageCopy(context.Context, string, string) error
}

type StorageCopy struct {
	TargetID     string
	Token        string
	ArchivePath  string
	SHA256       string
	Size         int64
	DeclaredPath []string
}

// CopyOfflineStorage orchestrates the common target-side storage-copy seam.
// The lifecycle remains responsible for stopping/starting the subject. Target
// plaintext is removed only after transfer, byte count, hash, and archive
// safety validation have all succeeded. Failures retain the token explicitly
// so the caller can request targeted cleanup; there is no hidden daemon.
func (m *Manager) CopyOfflineStorage(ctx context.Context, target TargetStorage, targetID string, declaredPaths []string) (StorageCopy, error) {
	if target == nil || targetID == "" || len(declaredPaths) == 0 {
		return StorageCopy{}, errors.New("target storage source, target id, and declared paths are required")
	}
	token, expectedSHA, expectedSize, err := target.PrepareStorageCopy(ctx, targetID, declaredPaths)
	if err != nil {
		return StorageCopy{}, err
	}
	result := StorageCopy{TargetID: targetID, Token: token, SHA256: expectedSHA, Size: expectedSize, DeclaredPath: append([]string(nil), declaredPaths...)}
	data, err := target.TransferStorageCopy(ctx, targetID, token)
	if err != nil {
		return result, fmt.Errorf("transfer storage copy %s; target temporary material remains: %w", token, err)
	}
	actual := sha256.Sum256(data)
	actualSHA := hex.EncodeToString(actual[:])
	if int64(len(data)) != expectedSize || actualSHA != expectedSHA {
		return result, fmt.Errorf("verify storage copy %s failed; target temporary material remains", token)
	}
	work, err := os.MkdirTemp(m.root, ".storage-copy-*")
	if err != nil {
		return result, fmt.Errorf("prepare local storage copy %s; target temporary material remains: %w", token, err)
	}
	archive := filepath.Join(work, "storage.tar.zst")
	if err := os.WriteFile(archive, data, 0o600); err != nil {
		_ = os.RemoveAll(work)
		return result, fmt.Errorf("write local storage copy %s; target temporary material remains: %w", token, err)
	}
	if _, err := InspectTarZst(archive); err != nil {
		_ = os.RemoveAll(work)
		return result, fmt.Errorf("inspect local storage copy %s; target temporary material remains: %w", token, err)
	}
	if err := target.CleanupStorageCopy(ctx, targetID, token); err != nil {
		_ = os.RemoveAll(work)
		return result, fmt.Errorf("local storage copy verified but target cleanup %s failed: %w", token, err)
	}
	result.ArchivePath = archive
	result.Token = ""
	return result, nil
}

func (m *Manager) CleanupTargetStorageCopy(ctx context.Context, target TargetStorage, targetID, token string) error {
	if target == nil || targetID == "" || token == "" {
		return errors.New("target storage cleanup identity is required")
	}
	return target.CleanupStorageCopy(ctx, targetID, token)
}
