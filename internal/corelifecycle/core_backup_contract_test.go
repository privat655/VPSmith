package corelifecycle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/managementstate"
)

func TestCoreBackupStorageScopeExcludesDerivedRuntimeConfiguration(t *testing.T) {
	paths := coreBackupStoragePaths()
	for _, required := range []string{
		"/var/lib/vpsmith/core/desired.json",
		"/var/lib/vpsmith/core/authelia/data",
		"/var/lib/vpsmith/secrets/core",
		"/var/lib/vpsmith/inventory/core.json",
		"/var/lib/vpsmith/execution",
	} {
		if !containsStringValue(paths, required) {
			t.Fatalf("Core backup scope missing %s: %#v", required, paths)
		}
	}
	for _, forbidden := range []string{
		"/var/lib/vpsmith/core/caddy",
		"/var/lib/vpsmith/core/authelia/configuration.yml",
		"/home/vpsmith/.config/containers/systemd",
		"/etc/systemd/system/caddy-edge-http.socket",
	} {
		if containsStringValue(paths, forbidden) {
			t.Fatalf("derived Core artifact entered canonical backup scope: %s", forbidden)
		}
	}
}

func TestCaptureCoreImageLocksRemovesGeneratedDesiredDocument(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "var", "lib", "vpsmith", "core", "desired.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	const packageSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	input := coreBackupImageLocks{
		SourceID: "source-core", Version: "1.0.0", PackageSHA256: packageSHA,
		Images: map[string]coreBackupImage{
			"caddy":    {Ref: "docker.io/library/caddy:2.11.4-alpine", Digest: "sha256:" + strings.Repeat("b", 64)},
			"authelia": {Ref: "docker.io/authelia/authelia:4.39.20", Digest: "sha256:" + strings.Repeat("c", 64)},
		},
	}
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	observed := managementstate.ObservedState{Core: managementstate.CoreObservedState{
		Present: true, SourceID: "source-core", Version: "1.0.0", PackageSHA256: packageSHA,
	}}
	locks, err := captureCoreImageLocks(root, observed)
	if err != nil {
		t.Fatal(err)
	}
	if locks.Images["caddy"].Digest != input.Images["caddy"].Digest || locks.Images["authelia"].Digest != input.Images["authelia"].Digest {
		t.Fatalf("captured Core image locks changed: %#v", locks.Images)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("generated desired.json remains in canonical backup payload: %v", err)
	}
	if err := writeCoreImageLocks(root, locks); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(coreBackupImageLocksRef))); err != nil {
		t.Fatalf("canonical Core image lock file missing: %v", err)
	}
}

func TestCaptureCoreImageLocksFailsClosedOnIdentityMismatch(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "var", "lib", "vpsmith", "core", "desired.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	input := coreBackupImageLocks{
		SourceID: "wrong-source", Version: "1.0.0", PackageSHA256: strings.Repeat("a", 64),
		Images: map[string]coreBackupImage{
			"caddy":    {Ref: "caddy:2", Digest: "sha256:" + strings.Repeat("b", 64)},
			"authelia": {Ref: "authelia:4", Digest: "sha256:" + strings.Repeat("c", 64)},
		},
	}
	data, _ := json.Marshal(input)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	observed := managementstate.ObservedState{Core: managementstate.CoreObservedState{
		SourceID: "source-core", Version: "1.0.0", PackageSHA256: strings.Repeat("a", 64),
	}}
	if _, err := captureCoreImageLocks(root, observed); err == nil {
		t.Fatal("mismatched Core execution lock was accepted")
	}
}

func containsStringValue(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
