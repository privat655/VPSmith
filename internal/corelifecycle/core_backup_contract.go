package corelifecycle

import "github.com/privat655/VPSmith/internal/managementstate"

// coreBackupStoragePaths contains only target-side Core state that is
// canonical or not reproducible. Generated Caddy, Authelia policy, Quadlet,
// network, and host-hardening files are deliberately absent: restore rebuilds
// those artifacts from desired state through the Deployment Compiler.
func coreBackupStoragePaths() []string {
	return []string{
		"/var/lib/vpsmith/core/desired.json",
		"/var/lib/vpsmith/core/authelia/data",
		"/var/lib/vpsmith/secrets/core",
		"/var/lib/vpsmith/inventory/core.json",
		"/var/lib/vpsmith/execution",
	}
}

type coreBackupRuntimeIdentity struct {
	SourceID      managementstate.SourceSnapshotID         `json:"source_id"`
	Version       string                                   `json:"version"`
	PackageSHA256 string                                   `json:"package_sha256"`
	Containers    []managementstate.ContainerObservedState `json:"containers,omitempty"`
}

func coreRuntimeIdentity(observed managementstate.ObservedState) coreBackupRuntimeIdentity {
	return coreBackupRuntimeIdentity{
		SourceID:      observed.Core.SourceID,
		Version:       observed.Core.Version,
		PackageSHA256: observed.Core.PackageSHA256,
		Containers:    append([]managementstate.ContainerObservedState(nil), observed.Core.Containers...),
	}
}
