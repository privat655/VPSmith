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

type recoveryTree struct {
	stagePath   string
	targetPath  string
	expectedSHA string
	reusable    bool
}

// RecoveryImport is a staged Source Library import. It publishes no candidate
// tree until the complete package has passed validation. Close rolls back every
// tree created by this import unless Seal is called after the canonical state
// commit succeeds.
type RecoveryImport struct {
	stageRoot string
	trees     []recoveryTree
	published []string
	sealed    bool
}

func (l *Library) PrepareRecoveryImport(ctx context.Context, sourceRoot string, expected managementstate.SourceState) (*RecoveryImport, error) {
	if sourceRoot == "" || !filepath.IsAbs(sourceRoot) {
		return nil, errors.New("absolute recovery source root is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateRecoverySourceShape(sourceRoot, expected); err != nil {
		return nil, err
	}
	stageRoot, err := os.MkdirTemp(l.root, ".recovery-stage-*")
	if err != nil {
		return nil, fmt.Errorf("create recovery source stage: %w", err)
	}
	if err := os.Chmod(stageRoot, 0o700); err != nil {
		_ = os.RemoveAll(stageRoot)
		return nil, err
	}
	prepared := &RecoveryImport{stageRoot: stageRoot}
	fail := func(err error) (*RecoveryImport, error) {
		_ = prepared.Close()
		return nil, err
	}

	index := 0
	for _, artifact := range expected.Artifacts {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		if err := validateArtifactStorageRef(artifact); err != nil {
			return fail(err)
		}
		source := filepath.Join(sourceRoot, filepath.FromSlash(artifact.StorageRef))
		if err := verifyRecoveryTree(source, artifact.SHA256, "source artifact", string(artifact.ID)); err != nil {
			return fail(err)
		}
		target := filepath.Join(l.root, filepath.FromSlash(artifact.StorageRef))
		if reused, err := reusableRecoveryTree(target, artifact.SHA256); err != nil {
			return fail(fmt.Errorf("verify existing source artifact %s: %w", artifact.ID, err))
		} else if reused {
			continue
		}
		stage := filepath.Join(stageRoot, fmt.Sprintf("tree-%06d", index))
		index++
		if err := copyTree(source, stage); err != nil {
			return fail(fmt.Errorf("stage recovered source artifact %s: %w", artifact.ID, err))
		}
		if err := verifyRecoveryTree(stage, artifact.SHA256, "staged source artifact", string(artifact.ID)); err != nil {
			return fail(err)
		}
		prepared.trees = append(prepared.trees, recoveryTree{stagePath: stage, targetPath: target, expectedSHA: artifact.SHA256, reusable: true})
	}
	for _, workspace := range expected.Workspaces {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		if err := validateWorkspaceStorageRef(workspace); err != nil {
			return fail(err)
		}
		source := filepath.Join(sourceRoot, filepath.FromSlash(workspace.StorageRef))
		if err := verifyRecoveryTree(source, workspace.CurrentSHA256, "source workspace", string(workspace.ID)); err != nil {
			return fail(err)
		}
		target := filepath.Join(l.root, filepath.FromSlash(workspace.StorageRef))
		if reused, err := reusableRecoveryTree(target, workspace.CurrentSHA256); err != nil {
			return fail(fmt.Errorf("verify existing source workspace %s: %w", workspace.ID, err))
		} else if reused {
			continue
		}
		stage := filepath.Join(stageRoot, fmt.Sprintf("tree-%06d", index))
		index++
		if err := copyTree(source, stage); err != nil {
			return fail(fmt.Errorf("stage recovered source workspace %s: %w", workspace.ID, err))
		}
		if err := verifyRecoveryTree(stage, workspace.CurrentSHA256, "staged source workspace", string(workspace.ID)); err != nil {
			return fail(err)
		}
		prepared.trees = append(prepared.trees, recoveryTree{stagePath: stage, targetPath: target, expectedSHA: workspace.CurrentSHA256, reusable: true})
	}
	return prepared, nil
}

func (l *Library) ImportRecovery(ctx context.Context, sourceRoot string, expected managementstate.SourceState) error {
	prepared, err := l.PrepareRecoveryImport(ctx, sourceRoot, expected)
	if err != nil {
		return err
	}
	defer prepared.Close()
	if err := prepared.Commit(); err != nil {
		return err
	}
	prepared.Seal()
	return nil
}

func (r *RecoveryImport) Commit() error {
	if r == nil || r.sealed {
		return errors.New("recovery source import is not commit-ready")
	}
	for i := range r.trees {
		tree := &r.trees[i]
		if err := os.MkdirAll(filepath.Dir(tree.targetPath), 0o700); err != nil {
			r.Rollback()
			return err
		}
		if err := os.Rename(tree.stagePath, tree.targetPath); err != nil {
			if tree.reusable {
				if reused, reuseErr := reusableRecoveryTree(tree.targetPath, tree.expectedSHA); reuseErr == nil && reused {
					_ = os.RemoveAll(tree.stagePath)
					continue
				}
			}
			r.Rollback()
			return fmt.Errorf("publish recovered source tree: %w", err)
		}
		r.published = append(r.published, tree.targetPath)
	}
	return nil
}

func (r *RecoveryImport) Rollback() {
	if r == nil || r.sealed {
		return
	}
	for i := len(r.published) - 1; i >= 0; i-- {
		_ = os.RemoveAll(r.published[i])
	}
	r.published = nil
	if r.stageRoot != "" {
		_ = os.RemoveAll(r.stageRoot)
	}
}

func (r *RecoveryImport) Seal() {
	if r == nil || r.sealed {
		return
	}
	r.sealed = true
	if r.stageRoot != "" {
		_ = os.RemoveAll(r.stageRoot)
	}
	r.published = nil
}

func (r *RecoveryImport) Close() error {
	if r == nil {
		return nil
	}
	if !r.sealed {
		r.Rollback()
	} else if r.stageRoot != "" {
		_ = os.RemoveAll(r.stageRoot)
	}
	return nil
}

func verifyRecoveryTree(root, expectedSHA, kind, id string) error {
	actual, err := sourcehash.TreeSHA256(root)
	if err != nil {
		return fmt.Errorf("verify recovered %s %s: %w", kind, id, err)
	}
	if actual != expectedSHA {
		return fmt.Errorf("recovered %s %s sha256 mismatch", kind, id)
	}
	return nil
}

func reusableRecoveryTree(target, expectedSHA string) (bool, error) {
	if _, err := os.Lstat(target); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	actual, err := sourcehash.TreeSHA256(target)
	if err != nil {
		return false, err
	}
	if actual != expectedSHA {
		return false, errors.New("existing recovery source tree differs")
	}
	return true, nil
}

func validateRecoverySourceShape(root string, expected managementstate.SourceState) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("read recovery source root: %w", err)
	}
	allowedTop := map[string]bool{}
	allowedSnapshots := map[string]bool{}
	allowedWorkspaces := map[string]bool{}
	for _, artifact := range expected.Artifacts {
		if err := validateArtifactStorageRef(artifact); err != nil {
			return err
		}
		allowedTop["snapshots"] = true
		allowedSnapshots[artifact.SHA256] = true
	}
	for _, workspace := range expected.Workspaces {
		if err := validateWorkspaceStorageRef(workspace); err != nil {
			return err
		}
		allowedTop["workspaces"] = true
		allowedWorkspaces[string(workspace.ID)] = true
	}
	for _, entry := range entries {
		if !entry.IsDir() || !allowedTop[entry.Name()] {
			return fmt.Errorf("unexpected recovery source entry %q", entry.Name())
		}
	}
	if len(allowedSnapshots) > 0 {
		rootSnapshots := filepath.Join(root, "snapshots")
		entries, err := os.ReadDir(rootSnapshots)
		if err != nil {
			return err
		}
		if len(entries) != 1 || entries[0].Name() != "sha256" || !entries[0].IsDir() {
			return errors.New("recovery snapshots directory has unexpected shape")
		}
	}
	if err := validateNamedDirectories(filepath.Join(root, "snapshots", "sha256"), allowedSnapshots); err != nil {
		return err
	}
	if err := validateNamedDirectories(filepath.Join(root, "workspaces"), allowedWorkspaces); err != nil {
		return err
	}
	return nil
}

func validateNamedDirectories(root string, expected map[string]bool) error {
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		if len(expected) == 0 {
			return nil
		}
		return fmt.Errorf("recovery source directory %s is missing", root)
	}
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		if !entry.IsDir() || !expected[entry.Name()] {
			return fmt.Errorf("unexpected recovery source object %q", entry.Name())
		}
		seen[entry.Name()] = true
	}
	for name := range expected {
		if !seen[name] {
			return fmt.Errorf("recovery source object %q is missing", name)
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
