package executionbundle

import (
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

// ImportRecovery verifies recovered bundle bytes and publishes them through the
// same immutable bundle store used by production execution.
func (a *Assembler) ImportRecovery(items []managementstate.ExecutionBundleMetadata, source string) error {
	if source == "" || !filepath.IsAbs(source) {
		return errors.New("absolute recovery bundle source is required")
	}
	for _, item := range items {
		data, err := os.ReadFile(filepath.Join(source, string(item.ID)+".tar"))
		if err != nil {
			return fmt.Errorf("read recovered execution bundle %s: %w", item.ID, err)
		}
		bundle := Bundle{ID: string(item.ID), SHA256: item.SHA256, Bytes: data}
		manifest, err := Verify(bundle)
		if err != nil {
			return fmt.Errorf("verify recovered execution bundle %s: %w", item.ID, err)
		}
		if manifest.BundleID != string(item.ID) {
			return fmt.Errorf("recovered execution bundle %s has different identity", item.ID)
		}
		if err := a.store(bundle); err != nil {
			return fmt.Errorf("publish recovered execution bundle %s: %w", item.ID, err)
		}
	}
	return nil
}
