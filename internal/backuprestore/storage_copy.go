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

// Close removes the verified local plaintext storage copy. Callers own a
// successful StorageCopy only until they have consumed it into the encrypted
// backup/restore primitive.
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
// slice. Target plaintext is removed only after transfer, byte count, hash, and
// archive safety validation have all succeeded. Failures retain the token so
// the caller can request targeted cleanup; there is no hidden daemon.
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
	if err := target.CleanupStorageCopy(ctx, targetID, token); err != nil {
		return result, fmt.Errorf("local storage copy verified but target cleanup %s failed: %w", token, err)
	}
	result.ArchivePath = archive
	result.workDir = work
	result.Token = ""
	keepWork = true
	return result, nil
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
