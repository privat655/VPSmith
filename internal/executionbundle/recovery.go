package executionbundle

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/privat655/VPSmith/internal/managementstate"
)

// ExportRecovery writes exactly the execution bundles named by canonical
// history. Open verifies each immutable bundle before it is copied.
func (a *Assembler) ExportRecovery(items []managementstate.ExecutionBundleMetadata, destination string) error {
	if destination == "" || !filepath.IsAbs(destination) {
		return errors.New("absolute recovery bundle destination is required")
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return err
	}
	for _, item := range items {
		bundle, err := a.Open(string(item.ID))
		if err != nil {
			return fmt.Errorf("open recovery bundle %s: %w", item.ID, err)
		}
		if bundle.SHA256 != item.SHA256 {
			return fmt.Errorf("recovery bundle %s sha256 differs from canonical history", item.ID)
		}
		path := filepath.Join(destination, string(item.ID)+".tar")
		if err := os.WriteFile(path, bundle.Bytes, 0o400); err != nil {
			return err
		}
	}
	return nil
}

type recoveryBundle struct {
	stagePath  string
	targetPath string
	bytes      []byte
}

// RecoveryImport stages every execution bundle before publishing any of them.
// Close removes every file created by the import unless Seal is called after
// the canonical management-state commit succeeds.
type RecoveryImport struct {
	stageRoot string
	bundles   []recoveryBundle
	published []string
	sealed    bool
}

func (a *Assembler) PrepareRecoveryImport(items []managementstate.ExecutionBundleMetadata, source string) (*RecoveryImport, error) {
	if source == "" || !filepath.IsAbs(source) {
		return nil, errors.New("absolute recovery bundle source is required")
	}
	if err := validateRecoveryBundleShape(source, items); err != nil {
		return nil, err
	}
	stageRoot, err := os.MkdirTemp(a.root, ".recovery-stage-*")
	if err != nil {
		return nil, fmt.Errorf("create recovery bundle stage: %w", err)
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
	for i, item := range items {
		data, err := os.ReadFile(filepath.Join(source, string(item.ID)+".tar"))
		if err != nil {
			return fail(fmt.Errorf("read recovered execution bundle %s: %w", item.ID, err))
		}
		bundle := Bundle{ID: string(item.ID), SHA256: item.SHA256, Bytes: data}
		manifest, err := Verify(bundle)
		if err != nil {
			return fail(fmt.Errorf("verify recovered execution bundle %s: %w", item.ID, err))
		}
		if manifest.BundleID != string(item.ID) || manifest.TargetID != string(item.TargetID) || string(manifest.Kind) != item.Kind || manifest.Version != item.Version {
			return fail(fmt.Errorf("recovered execution bundle %s metadata differs from canonical history", item.ID))
		}
		target := filepath.Join(a.root, string(item.ID)+".tar")
		if existing, err := os.ReadFile(target); err == nil {
			if !bytes.Equal(existing, data) {
				return fail(fmt.Errorf("historical bundle %s already exists with different bytes", item.ID))
			}
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return fail(err)
		}
		stage := filepath.Join(stageRoot, fmt.Sprintf("bundle-%06d.tar", i))
		if err := os.WriteFile(stage, data, 0o400); err != nil {
			return fail(err)
		}
		prepared.bundles = append(prepared.bundles, recoveryBundle{stagePath: stage, targetPath: target, bytes: data})
	}
	return prepared, nil
}

func (a *Assembler) ImportRecovery(items []managementstate.ExecutionBundleMetadata, source string) error {
	prepared, err := a.PrepareRecoveryImport(items, source)
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
		return errors.New("recovery bundle import is not commit-ready")
	}
	for i := range r.bundles {
		bundle := &r.bundles[i]
		if err := os.Rename(bundle.stagePath, bundle.targetPath); err != nil {
			if existing, readErr := os.ReadFile(bundle.targetPath); readErr == nil && bytes.Equal(existing, bundle.bytes) {
				_ = os.Remove(bundle.stagePath)
				continue
			}
			r.Rollback()
			return fmt.Errorf("publish recovered execution bundle: %w", err)
		}
		r.published = append(r.published, bundle.targetPath)
	}
	return nil
}

func (r *RecoveryImport) Rollback() {
	if r == nil || r.sealed {
		return
	}
	for i := len(r.published) - 1; i >= 0; i-- {
		_ = os.Remove(r.published[i])
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

func validateRecoveryBundleShape(source string, items []managementstate.ExecutionBundleMetadata) error {
	entries, err := os.ReadDir(source)
	if err != nil {
		return fmt.Errorf("read recovery execution-bundle directory: %w", err)
	}
	expected := make(map[string]bool, len(items))
	for _, item := range items {
		if item.ID == "" || item.TargetID == "" || item.Kind == "" || item.Version == "" || !validSHA256(item.SHA256) {
			return fmt.Errorf("recovery execution bundle %s metadata is incomplete", item.ID)
		}
		expected[string(item.ID)+".tar"] = true
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !expected[entry.Name()] {
			return fmt.Errorf("unexpected recovery execution-bundle entry %q", entry.Name())
		}
		seen[entry.Name()] = true
	}
	for name := range expected {
		if !seen[name] {
			return fmt.Errorf("recovery execution bundle %q is missing", name)
		}
	}
	return nil
}
