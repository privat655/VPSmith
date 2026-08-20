package corelifecycle

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/privat655/VPSmith/internal/managementstate"
)

const coreBackupImageLocksRef = "management/core-image-locks.json"

// coreBackupStoragePaths contains the target-side inputs needed to construct a
// canonical Core backup. The generated desired.json is evidence only: the
// producer extracts its exact image locks and removes the generated document
// from the long-term payload before the envelope is created.
func coreBackupStoragePaths() []string {
	return []string{
		"/var/lib/vpsmith/core/desired.json",
		"/var/lib/vpsmith/core/authelia/data",
		"/var/lib/vpsmith/secrets/core",
		"/var/lib/vpsmith/inventory/core.json",
		"/var/lib/vpsmith/execution",
	}
}

type coreBackupImage struct {
	Ref    string `json:"ref"`
	Digest string `json:"digest"`
}

type coreBackupImageLocks struct {
	SourceID      managementstate.SourceSnapshotID `json:"source_id"`
	Version       string                           `json:"version"`
	PackageSHA256 string                           `json:"package_sha256"`
	Images        map[string]coreBackupImage       `json:"images"`
}

func captureCoreImageLocks(root string, observed managementstate.ObservedState) (coreBackupImageLocks, error) {
	path := filepath.Join(root, "var", "lib", "vpsmith", "core", "desired.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return coreBackupImageLocks{}, fmt.Errorf("read backed-up Core execution lock: %w", err)
	}
	var lock coreBackupImageLocks
	if err := json.Unmarshal(data, &lock); err != nil {
		return coreBackupImageLocks{}, fmt.Errorf("decode backed-up Core execution lock: %w", err)
	}
	if lock.SourceID != observed.Core.SourceID || lock.Version != observed.Core.Version || lock.PackageSHA256 != observed.Core.PackageSHA256 {
		return coreBackupImageLocks{}, errors.New("backed-up Core execution lock does not match observed exact Core identity")
	}
	if len(lock.Images) != 2 {
		return coreBackupImageLocks{}, errors.New("backed-up Core execution lock must contain exactly Caddy and Authelia images")
	}
	for _, name := range []string{"caddy", "authelia"} {
		image, ok := lock.Images[name]
		if !ok || strings.TrimSpace(image.Ref) == "" || !validCoreImageDigest(image.Digest) {
			return coreBackupImageLocks{}, fmt.Errorf("backed-up Core execution lock has incomplete %s image identity", name)
		}
	}
	if err := os.Remove(path); err != nil {
		return coreBackupImageLocks{}, fmt.Errorf("remove generated Core desired document from canonical backup payload: %w", err)
	}
	return lock, nil
}

func writeCoreImageLocks(root string, locks coreBackupImageLocks) error {
	managementDir := filepath.Join(root, "management")
	if err := os.MkdirAll(managementDir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(locks, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(coreBackupImageLocksRef)), data, 0o600); err != nil {
		return fmt.Errorf("write Core image locks: %w", err)
	}
	return nil
}

func validCoreImageDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	for _, r := range strings.TrimPrefix(value, "sha256:") {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		return false
	}
	return true
}

func requireCoreBackupReady(snapshot managementstate.Snapshot, target managementstate.Target, observed managementstate.ObservedState) error {
	desired := target.Desired.Core
	if desired.SourceID == "" || desired.Version == "" || desired.CoreContract == "" {
		return errors.New("Core backup requires complete canonical desired identity")
	}
	artifact, err := exactCoreArtifact(snapshot.Sources.Artifacts, desired.SourceID)
	if err != nil {
		return err
	}
	if observed.Core.SourceID != desired.SourceID || observed.Core.Version != desired.Version || observed.Core.PackageSHA256 != artifact.SHA256 {
		return errors.New("Core backup requires desired/observed exact identity match")
	}
	if err := requireSecondaryHardening(observed.Host.SecondaryHardening); err != nil {
		return err
	}
	if err := requireCoreListeners(observed.Host.Listeners); err != nil {
		return err
	}
	if err := requireSwapPostState(desired.Swap, observed.Host.SwapDevices, observed.Host); err != nil {
		return err
	}
	if !observed.Core.Podman.Present || !observed.Core.Podman.Rootless || observed.Core.Podman.CgroupVersion != "v2" || observed.Core.Podman.RootlessNetworkCmd != "pasta" ||
		!observed.Core.Running || !observed.Core.Caddy.Present || !observed.Core.Caddy.Running || !observed.Core.Caddy.ConfigChecked || !observed.Core.Caddy.ConfigValid ||
		!observed.Core.Authelia.Present || !observed.Core.Authelia.Running {
		return errors.New("Core backup requires a healthy Core runtime")
	}
	return nil
}
