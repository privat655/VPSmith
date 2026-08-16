package managementstate

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const CurrentSchemaVersion = 2

type TargetID string
type CoreSourceID string
type ModulePackageID string
type ModuleInstanceID string
type SecretID string
type ExecutionBundleID string
type ExecutionRecordID string
type BackupArtifactID string

func NewTargetID() (TargetID, error)         { v, e := newID("target"); return TargetID(v), e }
func NewCoreSourceID() (CoreSourceID, error) { v, e := newID("core-src"); return CoreSourceID(v), e }
func NewModulePackageID() (ModulePackageID, error) {
	v, e := newID("module-pkg")
	return ModulePackageID(v), e
}
func NewModuleInstanceID() (ModuleInstanceID, error) {
	v, e := newID("module-inst")
	return ModuleInstanceID(v), e
}
func NewSecretID() (SecretID, error) { v, e := newID("secret"); return SecretID(v), e }
func NewExecutionBundleID() (ExecutionBundleID, error) {
	v, e := newID("bundle")
	return ExecutionBundleID(v), e
}
func NewExecutionRecordID() (ExecutionRecordID, error) {
	v, e := newID("execution")
	return ExecutionRecordID(v), e
}
func NewBackupArtifactID() (BackupArtifactID, error) {
	v, e := newID("backup")
	return BackupArtifactID(v), e
}

func newID(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate %s id: %w", prefix, err)
	}
	return prefix + "_" + hex.EncodeToString(raw[:]), nil
}

type TrustStatus string

const (
	TrustUnknown   TrustStatus = "unknown"
	TrustConfirmed TrustStatus = "confirmed"
	TrustBlocked   TrustStatus = "blocked"
)

type SecretOrigin string

const (
	SecretGenerated SecretOrigin = "generated"
	SecretUser      SecretOrigin = "user"
	SecretSystem    SecretOrigin = "system"
)

type Target struct {
	ID                  TargetID      `json:"id"`
	Address             string        `json:"address"`
	SSHUser             string        `json:"ssh_user"`
	SSHIdentitySecretID SecretID      `json:"ssh_identity_secret_id,omitempty"`
	SSHHostKey          string        `json:"ssh_host_key,omitempty"`
	SSHHostFingerprint  string        `json:"ssh_host_fingerprint,omitempty"`
	SSHTrust            TrustStatus   `json:"ssh_trust"`
	Desired             DesiredState  `json:"desired"`
	Observed            ObservedState `json:"observed"`
}

type CloudInitDesiredState struct {
	DefinitionVersion string `json:"definition_version,omitempty"`
	DefinitionSHA256  string `json:"definition_sha256,omitempty"`
}

type CoreDesiredState struct {
	SourceID CoreSourceID     `json:"source_id,omitempty"`
	Version  string           `json:"version,omitempty"`
	Swap     SwapDesiredState `json:"swap"`
}

type SwapDesiredState struct {
	Mode    string `json:"mode,omitempty"`
	SizeGiB int    `json:"size_gib,omitempty"`
}

type ResourceOverrides struct {
	MemoryBytes int64 `json:"memory_bytes,omitempty"`
	CPUQuota    int   `json:"cpu_quota_percent,omitempty"`
	PIDsLimit   int   `json:"pids_limit,omitempty"`
	TasksMax    int   `json:"tasks_max,omitempty"`
}

type ModuleDependency struct {
	TargetModule ModuleInstanceID `json:"target_module"`
	InterfaceID  string           `json:"interface_id"`
	Consumer     string           `json:"consumer"`
}

type ModuleDesiredState struct {
	InstanceID   ModuleInstanceID   `json:"instance_id"`
	PackageID    ModulePackageID    `json:"package_id"`
	Version      string             `json:"version"`
	SecretIDs    []SecretID         `json:"secret_ids,omitempty"`
	Resources    ResourceOverrides  `json:"resources,omitempty"`
	Dependencies []ModuleDependency `json:"dependencies,omitempty"`
}

type DesiredState struct {
	CloudInit CloudInitDesiredState `json:"cloud_init"`
	Core      CoreDesiredState      `json:"core"`
	Modules   []ModuleDesiredState  `json:"modules,omitempty"`
}

type CloudInitObservedState struct {
	Present    bool   `json:"present"`
	Status     string `json:"status,omitempty"`
	Version    string `json:"version,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`
}

type CoreObservedState struct {
	Present          bool                           `json:"present"`
	SourceID         CoreSourceID                   `json:"source_id,omitempty"`
	Version          string                         `json:"version,omitempty"`
	PackageSHA256    string                         `json:"package_sha256,omitempty"`
	Running          bool                           `json:"running"`
	Podman           PodmanObservedState            `json:"podman"`
	Units            []UnitObservedState            `json:"units,omitempty"`
	Containers       []ContainerObservedState       `json:"containers,omitempty"`
	Networks         []NetworkObservedState         `json:"networks,omitempty"`
	Caddy            ServiceObservedState           `json:"caddy"`
	Authelia         ServiceObservedState           `json:"authelia"`
	ExecutionProofs  []ExecutionProofObservedState  `json:"execution_proofs,omitempty"`
	ManagedArtifacts []ManagedArtifactObservedState `json:"managed_artifacts,omitempty"`
}

type ModuleObservedState struct {
	Present          bool                           `json:"present"`
	InstanceID       ModuleInstanceID               `json:"instance_id"`
	PackageID        ModulePackageID                `json:"package_id,omitempty"`
	Version          string                         `json:"version,omitempty"`
	PackageSHA256    string                         `json:"package_sha256,omitempty"`
	Running          bool                           `json:"running"`
	Health           string                         `json:"health,omitempty"`
	Units            []UnitObservedState            `json:"units,omitempty"`
	Containers       []ContainerObservedState       `json:"containers,omitempty"`
	Networks         []NetworkObservedState         `json:"networks,omitempty"`
	ManagedArtifacts []ManagedArtifactObservedState `json:"managed_artifacts,omitempty"`
}

type ObservedState struct {
	ObservedAt       string                         `json:"observed_at,omitempty"`
	Host             HostObservedState              `json:"host"`
	CloudInit        CloudInitObservedState         `json:"cloud_init"`
	Core             CoreObservedState              `json:"core"`
	Modules          []ModuleObservedState          `json:"modules,omitempty"`
	LinkNetworks     []LinkNetworkObservedState     `json:"link_networks,omitempty"`
	ManagedArtifacts []ManagedArtifactObservedState `json:"managed_artifacts,omitempty"`
}

type CoreSourceRole string

const (
	CoreSourceEmbedded CoreSourceRole = "embedded"
	CoreSourceLocal    CoreSourceRole = "local"
	CoreSourceTarget   CoreSourceRole = "target"
)

type CoreSource struct {
	ID           CoreSourceID   `json:"id"`
	Role         CoreSourceRole `json:"role"`
	TargetID     TargetID       `json:"target_id,omitempty"`
	Version      string         `json:"version"`
	SHA256       string         `json:"sha256"`
	BaseSourceID CoreSourceID   `json:"base_source_id,omitempty"`
}

type ModuleSourceRole string

const (
	ModuleSourceRemote ModuleSourceRole = "remote"
	ModuleSourceLocal  ModuleSourceRole = "local"
	ModuleSourceTarget ModuleSourceRole = "target"
)

type ModuleSource struct {
	PackageID     ModulePackageID  `json:"package_id"`
	Role          ModuleSourceRole `json:"role"`
	TargetID      TargetID         `json:"target_id,omitempty"`
	Owner         string           `json:"owner,omitempty"`
	Repository    string           `json:"repository,omitempty"`
	Ref           string           `json:"ref,omitempty"`
	Commit        string           `json:"commit,omitempty"`
	BaseCommit    string           `json:"base_commit,omitempty"`
	Version       string           `json:"version"`
	PackageSHA256 string           `json:"package_sha256"`
}

type SecretMetadata struct {
	ID            SecretID     `json:"id"`
	Name          string       `json:"name"`
	Origin        SecretOrigin `json:"origin"`
	CreatedAt     string       `json:"created_at"`
	RotatedAt     string       `json:"rotated_at,omitempty"`
	RotationCount int          `json:"rotation_count"`
	IsSet         bool         `json:"is_set"`
}

type ExecutionBundleMetadata struct {
	ID        ExecutionBundleID `json:"id"`
	TargetID  TargetID          `json:"target_id"`
	Kind      string            `json:"kind"`
	Version   string            `json:"version"`
	SHA256    string            `json:"sha256"`
	CreatedAt string            `json:"created_at"`
}

type ExecutionRecordMetadata struct {
	ID         ExecutionRecordID `json:"id"`
	BundleID   ExecutionBundleID `json:"bundle_id"`
	TargetID   TargetID          `json:"target_id"`
	Outcome    string            `json:"outcome"`
	StartedAt  string            `json:"started_at"`
	FinishedAt string            `json:"finished_at,omitempty"`
}

type BackupArtifactType string

const (
	BackupRecoveryPackage    BackupArtifactType = "recovery-package"
	BackupCore               BackupArtifactType = "core-backup"
	BackupModule             BackupArtifactType = "module-backup"
	BackupSystemRestorePoint BackupArtifactType = "system-restore-point"
)

type BackupArtifactMetadata struct {
	ID               BackupArtifactID   `json:"id"`
	Type             BackupArtifactType `json:"type"`
	TargetID         TargetID           `json:"target_id"`
	ModuleInstanceID ModuleInstanceID   `json:"module_instance_id,omitempty"`
	CreatedAt        string             `json:"created_at"`
	LocationRef      string             `json:"location_ref,omitempty"`
	SHA256           string             `json:"sha256,omitempty"`
}

type Snapshot struct {
	SchemaVersion    int                       `json:"schema_version"`
	Targets          []Target                  `json:"targets"`
	CoreSources      []CoreSource              `json:"core_sources"`
	ModuleSources    []ModuleSource            `json:"module_sources"`
	Secrets          []SecretMetadata          `json:"secrets"`
	ExecutionBundles []ExecutionBundleMetadata `json:"execution_bundles"`
	ExecutionRecords []ExecutionRecordMetadata `json:"execution_records"`
	Backups          []BackupArtifactMetadata  `json:"backups"`
}

func (s *Snapshot) normalize() {
	if s.Targets == nil {
		s.Targets = []Target{}
	}
	if s.CoreSources == nil {
		s.CoreSources = []CoreSource{}
	}
	if s.ModuleSources == nil {
		s.ModuleSources = []ModuleSource{}
	}
	if s.Secrets == nil {
		s.Secrets = []SecretMetadata{}
	}
	if s.ExecutionBundles == nil {
		s.ExecutionBundles = []ExecutionBundleMetadata{}
	}
	if s.ExecutionRecords == nil {
		s.ExecutionRecords = []ExecutionRecordMetadata{}
	}
	if s.Backups == nil {
		s.Backups = []BackupArtifactMetadata{}
	}
	for i := range s.Targets {
		sort.Slice(s.Targets[i].Desired.Modules, func(a, b int) bool {
			return s.Targets[i].Desired.Modules[a].InstanceID < s.Targets[i].Desired.Modules[b].InstanceID
		})
		NormalizeObservedState(&s.Targets[i].Observed)
	}
	sort.Slice(s.Targets, func(i, j int) bool { return s.Targets[i].ID < s.Targets[j].ID })
	sort.Slice(s.CoreSources, func(i, j int) bool { return s.CoreSources[i].ID < s.CoreSources[j].ID })
	sort.Slice(s.ModuleSources, func(i, j int) bool {
		if s.ModuleSources[i].PackageID == s.ModuleSources[j].PackageID {
			return s.ModuleSources[i].Role < s.ModuleSources[j].Role
		}
		return s.ModuleSources[i].PackageID < s.ModuleSources[j].PackageID
	})
	sort.Slice(s.Secrets, func(i, j int) bool { return s.Secrets[i].ID < s.Secrets[j].ID })
	sort.Slice(s.ExecutionBundles, func(i, j int) bool { return s.ExecutionBundles[i].ID < s.ExecutionBundles[j].ID })
	sort.Slice(s.ExecutionRecords, func(i, j int) bool { return s.ExecutionRecords[i].ID < s.ExecutionRecords[j].ID })
	sort.Slice(s.Backups, func(i, j int) bool { return s.Backups[i].ID < s.Backups[j].ID })
}

func validateDesired(value DesiredState) error {
	seen := map[ModuleInstanceID]struct{}{}
	for _, module := range value.Modules {
		if module.InstanceID == "" || module.PackageID == "" || strings.TrimSpace(module.Version) == "" {
			return errors.New("module desired state requires instance id, package id, and version")
		}
		if _, ok := seen[module.InstanceID]; ok {
			return fmt.Errorf("duplicate module instance %s", module.InstanceID)
		}
		seen[module.InstanceID] = struct{}{}
		for _, dependency := range module.Dependencies {
			if dependency.TargetModule == "" || strings.TrimSpace(dependency.InterfaceID) == "" || strings.TrimSpace(dependency.Consumer) == "" {
				return fmt.Errorf("module %s has incomplete dependency", module.InstanceID)
			}
		}
	}
	return nil
}

func validBackupType(value BackupArtifactType) bool {
	switch value {
	case BackupRecoveryPackage, BackupCore, BackupModule, BackupSystemRestorePoint:
		return true
	default:
		return false
	}
}

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func marshalDomain(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode management state: %w", err)
	}
	return data, nil
}
