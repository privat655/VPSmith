package deployment

import (
	"context"
	"io/fs"

	"github.com/privat655/VPSmith/internal/executionbundle"
	"github.com/privat655/VPSmith/internal/modulecontract"
)

type OperationKind string

const (
	Install     OperationKind = "install"
	Update      OperationKind = "update"
	Reconfigure OperationKind = "reconfigure"
	Uninstall   OperationKind = "uninstall"
	Restore     OperationKind = "restore"
	Validate    OperationKind = "validate"
)

type Registry interface {
	Resolve(context.Context, string) (string, error)
}

type Compiler struct {
	modules  modulecontract.Compiler
	registry Registry
	bundles  *executionbundle.Assembler
}

type FrozenModuleSource struct {
	InstanceID    string
	SourceID      string
	PackageID     string
	GitCommit     string
	PackageSHA256 string
	PackageFS     fs.FS
}

type DesiredModule struct {
	InstanceID string
	Source     FrozenModuleSource
	SecretIDs  map[string]string
	Resources  ResourceOverride
}

type ResourceOverride struct {
	MemoryBytes int64
	CPUQuota    int
	PIDsLimit   int
	TasksMax    int
}

type ObservedModule struct {
	InstanceID     string            `json:"instance_id"`
	ModuleID       string            `json:"module_id"`
	PackageID      string            `json:"package_id"`
	Version        string            `json:"version"`
	PackageSHA256  string            `json:"package_sha256"`
	ImageDigests   map[string]string `json:"image_digests"`
	ArtifactSHA256 map[string]string `json:"artifact_sha256"`
	RuntimeObjects []string          `json:"runtime_objects"`
}

type ObservedNetwork struct {
	Name         string `json:"name"`
	Subnet       string `json:"subnet,omitempty"`
	Relationship string `json:"relationship,omitempty"`
}

type ObservedClaim struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
	Owner string `json:"owner,omitempty"`
}

type ObservedState struct {
	TargetID string            `json:"target_id"`
	CoreID   string            `json:"core_id,omitempty"`
	Modules  []ObservedModule  `json:"modules"`
	Networks []ObservedNetwork `json:"networks"`
	Claims   []ObservedClaim   `json:"claims,omitempty"`
}

type Request struct {
	Operation       OperationKind
	TargetID        string
	SubjectInstance string
	DesiredModules  []DesiredModule
	Observed        ObservedState
	CoreContract    string
	CoreSource      executionbundle.SourceIdentity
	BackupRequired  bool
	// SubjectSource is required when the target Sollzustand no longer contains
	// the subject, notably for deinstallation. It freezes the exact installed
	// module package used to derive the removal operation.
	SubjectSource    *FrozenModuleSource
	SubjectSecretIDs map[string]string
}

type PlanStep struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Mutating    bool   `json:"mutating"`
}

type DiffFact struct {
	Kind     string `json:"kind"`
	Subject  string `json:"subject"`
	Desired  string `json:"desired,omitempty"`
	Observed string `json:"observed,omitempty"`
}

type GeneratedArtifact struct {
	Path       string `json:"path"`
	TargetPath string `json:"target_path"`
	Mode       int64  `json:"mode"`
	Data       []byte `json:"-"`
	SHA256     string `json:"sha256"`
}

type FrozenIdentity struct {
	InstanceID    string `json:"instance_id"`
	ModuleID      string `json:"module_id"`
	Version       string `json:"version"`
	SourceID      string `json:"source_id"`
	PackageID     string `json:"package_id"`
	GitCommit     string `json:"git_commit,omitempty"`
	PackageSHA256 string `json:"package_sha256"`
}

type LinkNetwork struct {
	Relationship string `json:"relationship"`
	Name         string `json:"name"`
	Subnet       string `json:"subnet"`
	Alias        string `json:"alias"`
	Provider     string `json:"provider"`
	Consumer     string `json:"consumer"`
}

type PreparedOperation struct {
	Operation       OperationKind                    `json:"operation"`
	PlanRequired    bool                             `json:"plan_required"`
	Plan            []PlanStep                       `json:"plan"`
	FrozenSources   []FrozenIdentity                 `json:"frozen_sources"`
	ImageDigests    map[string]string                `json:"image_digests"`
	ExpectedChanges []DiffFact                       `json:"expected_changes"`
	Artifacts       []GeneratedArtifact              `json:"artifacts"`
	Preconditions   []executionbundle.Precondition   `json:"preconditions"`
	ExpectedPost    any                              `json:"expected_post_state"`
	Validations     []executionbundle.ValidationSpec `json:"validations"`
	LinkNetworks    []LinkNetwork                    `json:"link_networks"`
	Bundle          executionbundle.Bundle           `json:"-"`
}

// BootstrapArtifact is the stable deployment-compiler output contract used by
// Step 7. Step 5 deliberately does not generate Primary Host Hardening yet.
type BootstrapArtifact struct {
	Identity string `json:"identity"`
	SHA256   string `json:"sha256"`
	Bytes    []byte `json:"-"`
}

type compiledModule struct {
	Desired   DesiredModule
	Contract  modulecontract.Module
	Images    map[string]string
	Effective modulecontract.Resources
}
