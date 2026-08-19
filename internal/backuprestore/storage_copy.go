package backuprestore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type TargetStorage interface {
	PrepareStorageCopy(context.Context, string, []string) (token, sha256 string, size int64, err error)
	TransferStorageCopy(context.Context, string, string, io.Writer) error
	CleanupStorageCopy(context.Context, string, string) error
}

type StorageCopy struct {
	TargetID     string
	Token        string
	ArchivePath  string
	SHA256       string
	Size         int64
	DeclaredPath []string
	workDir      string
}

// Close removes the verified local plaintext storage copy. It deliberately does
// not delete target-side temporary material: the caller must first persist and
// verify the consuming backup artifact and then call FinalizeStorageCopy.
func (s *StorageCopy) Close() error {
	if s == nil || s.workDir == "" {
		return nil
	}
	err := os.RemoveAll(s.workDir)
	s.workDir = ""
	s.ArchivePath = ""
	return err
}

// CopyOfflineStorage orchestrates the common target-side storage-copy seam.
// The transfer is streamed directly into volatile local storage while size and
// SHA-256 are computed; the archive is never buffered as one in-memory byte
// slice. The target plaintext token remains live even after local verification.
// A long-term consumer can therefore encrypt and verify its local artifact
// before FinalizeStorageCopy removes the only target-side temporary copy.
func (m *Manager) CopyOfflineStorage(ctx context.Context, target TargetStorage, targetID string, declaredPaths []string) (StorageCopy, error) {
	if target == nil || targetID == "" || len(declaredPaths) == 0 {
		return StorageCopy{}, errors.New("target storage source, target id, and declared paths are required")
	}
	token, expectedSHA, expectedSize, err := target.PrepareStorageCopy(ctx, targetID, declaredPaths)
	if err != nil {
		return StorageCopy{}, err
	}
	result := StorageCopy{TargetID: targetID, Token: token, SHA256: expectedSHA, Size: expectedSize, DeclaredPath: append([]string(nil), declaredPaths...)}
	work, err := m.newWorkDir("storage-copy")
	if err != nil {
		return result, fmt.Errorf("prepare local storage copy %s; target temporary material remains: %w", token, err)
	}
	keepWork := false
	defer func() {
		if !keepWork {
			_ = os.RemoveAll(work)
		}
	}()
	archive := filepath.Join(work, "storage.tar.zst")
	file, err := os.OpenFile(archive, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return result, fmt.Errorf("create local storage copy %s; target temporary material remains: %w", token, err)
	}
	digest := sha256.New()
	counter := &countingWriter{writer: io.MultiWriter(file, digest)}
	transferErr := target.TransferStorageCopy(ctx, targetID, token, counter)
	syncErr := file.Sync()
	closeErr := file.Close()
	if transferErr != nil {
		return result, fmt.Errorf("transfer storage copy %s; target temporary material remains: %w", token, transferErr)
	}
	if syncErr != nil {
		return result, fmt.Errorf("sync local storage copy %s; target temporary material remains: %w", token, syncErr)
	}
	if closeErr != nil {
		return result, fmt.Errorf("close local storage copy %s; target temporary material remains: %w", token, closeErr)
	}
	actualSHA := hex.EncodeToString(digest.Sum(nil))
	if counter.count != expectedSize || actualSHA != expectedSHA {
		return result, fmt.Errorf("verify storage copy %s failed; target temporary material remains", token)
	}
	if _, err := InspectTarZst(archive); err != nil {
		return result, fmt.Errorf("inspect local storage copy %s; target temporary material remains: %w", token, err)
	}
	result.ArchivePath = archive
	result.workDir = work
	keepWork = true
	return result, nil
}

// FinalizeStorageCopy is the success-side commit boundary. Call it only after a
// consuming backup/restore artifact has been persisted and verified. A cleanup
// failure leaves the token intact so an operator can retry targeted cleanup.
func (m *Manager) FinalizeStorageCopy(ctx context.Context, target TargetStorage, copy *StorageCopy) error {
	if target == nil || copy == nil || copy.TargetID == "" || copy.Token == "" || copy.ArchivePath == "" {
		return errors.New("verified storage copy identity is required")
	}
	if err := target.CleanupStorageCopy(ctx, copy.TargetID, copy.Token); err != nil {
		return fmt.Errorf("cleanup verified target storage copy %s: %w", copy.Token, err)
	}
	copy.Token = ""
	return nil
}

type countingWriter struct {
	writer io.Writer
	count  int64
}

func (w *countingWriter) Write(data []byte) (int, error) {
	n, err := w.writer.Write(data)
	w.count += int64(n)
	return n, err
}

func (m *Manager) CleanupTargetStorageCopy(ctx context.Context, target TargetStorage, targetID, token string) error {
	if target == nil || targetID == "" || token == "" {
		return errors.New("target storage cleanup identity is required")
	}
	return target.CleanupStorageCopy(ctx, targetID, token)
}
