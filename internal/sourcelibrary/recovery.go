package sourcelibrary

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/sourcehash"
)

// ExportRecovery copies only source-library objects named by the canonical
// management state. It never walks the whole sources mount, which prevents
// unrelated or productive data from becoming recovery-package content.
func (l *Library) ExportRecovery(ctx context.Context, destination string) error {
	if destination == "" || !filepath.IsAbs(destination) {
		return errors.New("absolute recovery source destination is required")
	}
	state, err := l.state.Sources(ctx)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return err
	}
	for _, artifact := range state.Artifacts {
		source, err := l.portableRefPath(artifact.StorageRef)
		if err != nil {
			return err
		}
		if err := l.verifySnapshot(artifact); err != nil {
			return err
		}
		target := filepath.Join(destination, filepath.FromSlash(artifact.StorageRef))
		if err := copyTree(source, target); err != nil {
			return fmt.Errorf("export source artifact %s: %w", artifact.ID, err)
		}
	}
	for _, workspace := range state.Workspaces {
		source, err := l.portableRefPath(workspace.StorageRef)
		if err != nil {
			return err
		}
		actual, err := sourcehash.TreeSHA256(source)
		if err != nil {
			return fmt.Errorf("verify source workspace %s: %w", workspace.ID, err)
		}
		if actual != workspace.CurrentSHA256 {
			return fmt.Errorf("source workspace %s integrity mismatch", workspace.ID)
		}
		target := filepath.Join(destination, filepath.FromSlash(workspace.StorageRef))
		if err := copyTree(source, target); err != nil {
			return fmt.Errorf("export source workspace %s: %w", workspace.ID, err)
		}
	}
	return nil
}

// ImportRecovery validates every recovered source object against the imported
// canonical catalogue before publishing it into the Source Library. Existing
// immutable SHA-addressed snapshots are accepted only if bytes match.
func (l *Library) ImportRecovery(ctx context.Context, sourceRoot string, expected managementstate.SourceState) error {
	_ = ctx
	if sourceRoot == "" || !filepath.IsAbs(sourceRoot) {
		return errors.New("absolute recovery source root is required")
	}
	for _, artifact := range expected.Artifacts {
		if err := validateArtifactStorageRef(artifact); err != nil {
			return err
		}
		source := filepath.Join(sourceRoot, filepath.FromSlash(artifact.StorageRef))
		actual, err := sourcehash.TreeSHA256(source)
		if err != nil {
			return fmt.Errorf("verify recovered source artifact %s: %w", artifact.ID, err)
		}
		if actual != artifact.SHA256 {
			return fmt.Errorf("recovered source artifact %s sha256 mismatch", artifact.ID)
		}
		target := filepath.Join(l.root, filepath.FromSlash(artifact.StorageRef))
		if _, statErr := os.Stat(target); statErr == nil {
			existing, err := sourcehash.TreeSHA256(target)
			if err != nil {
				return fmt.Errorf("verify existing source artifact %s: %w", artifact.ID, err)
			}
			if existing != artifact.SHA256 {
				return fmt.Errorf("existing immutable source artifact %s differs", artifact.ID)
			}
			continue
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
		if err := publishRecoveryTree(source, target); err != nil {
			return fmt.Errorf("publish recovered source artifact %s: %w", artifact.ID, err)
		}
	}
	for _, workspace := range expected.Workspaces {
		if err := validateWorkspaceStorageRef(workspace); err != nil {
			return err
		}
		source := filepath.Join(sourceRoot, filepath.FromSlash(workspace.StorageRef))
		actual, err := sourcehash.TreeSHA256(source)
		if err != nil {
			return fmt.Errorf("verify recovered source workspace %s: %w", workspace.ID, err)
		}
		if actual != workspace.CurrentSHA256 {
			return fmt.Errorf("recovered source workspace %s sha256 mismatch", workspace.ID)
		}
		target := filepath.Join(l.root, filepath.FromSlash(workspace.StorageRef))
		if _, err := os.Stat(target); err == nil {
			return fmt.Errorf("recovery source workspace %s already exists", workspace.ID)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := publishRecoveryTree(source, target); err != nil {
			return fmt.Errorf("publish recovered source workspace %s: %w", workspace.ID, err)
		}
	}
	return nil
}

func (l *Library) portableRefPath(ref string) (string, error) {
	if ref == "" || !filepath.IsLocal(filepath.FromSlash(ref)) || strings.Contains(ref, "\\") {
		return "", errors.New("invalid source storage reference")
	}
	path := filepath.Join(l.root, filepath.FromSlash(ref))
	rel, err := filepath.Rel(l.root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("source storage reference escapes library root")
	}
	return path, nil
}

func validateArtifactStorageRef(v managementstate.SourceArtifact) error {
	expected := filepath.ToSlash(filepath.Join("snapshots", "sha256", v.SHA256))
	if v.StorageRef != expected {
		return fmt.Errorf("source artifact %s has non-canonical storage reference", v.ID)
	}
	return nil
}

func validateWorkspaceStorageRef(v managementstate.SourceWorkspace) error {
	expected := filepath.ToSlash(filepath.Join("workspaces", string(v.ID)))
	if v.StorageRef != expected {
		return fmt.Errorf("source workspace %s has non-canonical storage reference", v.ID)
	}
	return nil
}

func publishRecoveryTree(source, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(filepath.Dir(target), ".recovery-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	candidate := filepath.Join(tmp, "payload")
	if err := copyTree(source, candidate); err != nil {
		return err
	}
	return os.Rename(candidate, target)
}
