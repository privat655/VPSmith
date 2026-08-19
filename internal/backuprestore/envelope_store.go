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
	"strings"

	"github.com/privat655/VPSmith/internal/managementstate"
)

func (m *Manager) catalogEntry(ctx context.Context, id managementstate.BackupArtifactID) (managementstate.BackupArtifactMetadata, error) {
	snapshot, err := m.state.Snapshot(ctx)
	if err != nil {
		return managementstate.BackupArtifactMetadata{}, err
	}
	for _, artifact := range snapshot.Backups {
		if artifact.ID == id {
			return artifact, nil
		}
	}
	return managementstate.BackupArtifactMetadata{}, fmt.Errorf("backup artifact %s does not exist", id)
}

func (m *Manager) locationPath(ref string) (string, error) {
	if ref == "" || !filepath.IsLocal(filepath.FromSlash(ref)) || strings.Contains(ref, "\\") {
		return "", errors.New("invalid backup storage reference")
	}
	path := filepath.Join(m.root, filepath.FromSlash(ref))
	if !sameOrWithin(m.root, path) {
		return "", errors.New("backup storage reference escapes backup root")
	}
	return path, nil
}

// AdoptValidatedRecovery copies a previously validated encrypted recovery file
// into the canonical backup catalogue and lets the caller commit the imported
// management state. The published file is removed again if that commit fails.
func (m *Manager) AdoptValidatedRecovery(ctx context.Context, source string, manifest Manifest, commit func(managementstate.BackupArtifactMetadata) error) (Artifact, error) {
	if commit == nil {
		return Artifact{}, errors.New("recovery commit callback is required")
	}
	if err := validateManifest(manifest, managementstate.BackupRecoveryPackage); err != nil {
		return Artifact{}, err
	}
	if source == "" || !filepath.IsAbs(source) {
		return Artifact{}, errors.New("absolute recovery source path is required")
	}
	if err := ctx.Err(); err != nil {
		return Artifact{}, err
	}
	sha, err := fileSHA256(source)
	if err != nil {
		return Artifact{}, err
	}
	name := fmt.Sprintf("%s-%s.tar.zst.age", manifest.ArtifactType, manifest.ArtifactID)
	final := filepath.Join(m.root, name)
	created := false
	if existingSHA, err := fileSHA256(final); err == nil {
		if existingSHA != sha {
			return Artifact{}, errors.New("existing recovery artifact has different bytes")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Artifact{}, err
	} else {
		work, err := m.newWorkDir("adopt")
		if err != nil {
			return Artifact{}, err
		}
		defer os.RemoveAll(work)
		candidate := filepath.Join(work, name)
		if err := copyFileExclusive(source, candidate, 0o600); err != nil {
			return Artifact{}, err
		}
		if err := publishFileExclusive(candidate, final, 0o600); err != nil {
			return Artifact{}, fmt.Errorf("publish imported recovery artifact: %w", err)
		}
		created = true
	}
	metadata := managementstate.BackupArtifactMetadata{
		ID:          manifest.ArtifactID,
		Type:        manifest.ArtifactType,
		TargetID:    manifest.TargetID,
		CreatedAt:   manifest.CreatedAt,
		LocationRef: name,
		SHA256:      sha,
	}
	if err := commit(metadata); err != nil {
		if created {
			_ = os.Remove(final)
		}
		return Artifact{}, err
	}
	return Artifact{Metadata: metadata, Manifest: manifest, Path: final}, nil
}

func publishFileExclusive(source, destination string, mode os.FileMode) error {
	dir := filepath.Dir(destination)
	temp, err := os.CreateTemp(dir, ".publish-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempName)
	}()
	if err := temp.Chmod(mode); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(temp, in)
	closeInErr := in.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeInErr != nil {
		return closeInErr
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Link(tempName, destination); err != nil {
		return err
	}
	if err := os.Remove(tempName); err != nil {
		_ = os.Remove(destination)
		return err
	}
	if err := syncDirectory(dir); err != nil {
		_ = os.Remove(destination)
		return err
	}
	return nil
}

func copyFileExclusive(source, destination string, mode os.FileMode) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(destination)
		}
	}()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func publishDirectoryExclusive(source, destination string) error {
	dir := filepath.Dir(destination)
	if _, err := os.Lstat(destination); err == nil {
		return os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temp, err := os.MkdirTemp(dir, ".publish-dir-*")
	if err != nil {
		return err
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(temp)
		}
	}()
	if err := os.Chmod(temp, 0o700); err != nil {
		return err
	}
	for _, name := range []string{"manifest.yaml", "storage.tar.zst", "SHA256SUMS"} {
		if err := copyFileExclusive(filepath.Join(source, name), filepath.Join(temp, name), 0o600); err != nil {
			return err
		}
	}
	if err := syncDirectory(temp); err != nil {
		return err
	}
	if err := os.Rename(temp, destination); err != nil {
		return err
	}
	published = true
	return syncDirectory(dir)
}

func fileSHA256(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func treeEnvelopeSHA(root string, names []string) (string, error) {
	hash := sha256.New()
	for _, name := range names {
		digest, err := fileSHA256(filepath.Join(root, name))
		if err != nil {
			return "", err
		}
		_, _ = io.WriteString(hash, name)
		_, _ = io.WriteString(hash, "\x00")
		_, _ = io.WriteString(hash, digest)
		_, _ = io.WriteString(hash, "\n")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func sameOrWithin(base, candidate string) bool {
	base = filepath.Clean(base)
	candidate = filepath.Clean(candidate)
	rel, err := filepath.Rel(base, candidate)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}
