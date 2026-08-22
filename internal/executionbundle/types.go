package executionbundle

import "encoding/json"

type Kind string

const (
	Installation Kind = "installation"
	Migration    Kind = "migration"
	Validation   Kind = "validation"
)

type DirectoryPrincipal string

const (
	PrincipalRoot  DirectoryPrincipal = "root"
	PrincipalAdmin DirectoryPrincipal = "admin"
)

type SourceIdentity struct {
	Kind          string `json:"kind"`
	ID            string `json:"id"`
	Version       string `json:"version"`
	GitCommit     string `json:"git_commit,omitempty"`
	PackageSHA256 string `json:"package_sha256"`
}

type ImageIdentity struct {
	Name   string `json:"name"`
	Ref    string `json:"ref"`
	Digest string `json:"digest"`
}

type RunnerIdentity struct {
	Version string `json:"version"`
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
}

type SecretReference struct {
	SecretID  string `json:"secret_id"`
	Container string `json:"container"`
	Delivery  string `json:"delivery"`
	Target    string `json:"target"`
}

type Precondition struct {
	Kind     string `json:"kind"`
	Subject  string `json:"subject"`
	Expected string `json:"expected"`
}

type ValidationSpec struct {
	ID       string `json:"id"`
	ReadOnly bool   `json:"read_only"`
}

type Step struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"`
	Artifact string   `json:"artifact,omitempty"`
	Action   string   `json:"action,omitempty"`
	Args     []string `json:"args,omitempty"`
	Mutating bool     `json:"mutating"`
}

type Manifest struct {
	FormatVersion       int               `json:"format_version"`
	Runner              RunnerIdentity    `json:"runner"`
	BundleID            string            `json:"bundle_id"`
	Kind                Kind              `json:"kind"`
	TargetID            string            `json:"target_vps_id"`
	SubjectKind         string            `json:"subject_kind"`
	SubjectID           string            `json:"subject_id"`
	SubjectIdentity     string            `json:"subject_identity"`
	PackageID           string            `json:"package_id,omitempty"`
	PackageSHA256       string            `json:"package_sha256,omitempty"`
	Version             string            `json:"version"`
	Sources             []SourceIdentity  `json:"sources"`
	Images              []ImageIdentity   `json:"images"`
	Directories         []Directory       `json:"directories"`
	Artifacts           []Artifact        `json:"artifacts"`
	Actions             []Action          `json:"actions"`
	ActionWritablePaths []string          `json:"action_writable_paths,omitempty"`
	Secrets             []SecretReference `json:"secrets"`
	Preconditions       []Precondition    `json:"preconditions"`
	ExpectedPost        json.RawMessage   `json:"expected_post_state"`
	Validations         []ValidationSpec  `json:"validations"`
	Steps               []Step            `json:"steps"`
	BackupRequired      bool              `json:"backup_required"`
	BackupRef           string            `json:"backup_ref,omitempty"`
}

type Directory struct {
	Path  string             `json:"path"`
	Owner DirectoryPrincipal `json:"owner"`
	Group DirectoryPrincipal `json:"group"`
	Mode  int64              `json:"mode"`
}

type Artifact struct {
	Path       string `json:"path"`
	TargetPath string `json:"target_path"`
	SHA256     string `json:"sha256"`
	Mode       int64  `json:"mode"`
}

type Action struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type File struct {
	Path       string
	TargetPath string
	Mode       int64
	Data       []byte
}

type Input struct {
	Kind                Kind
	TargetID            string
	SubjectKind         string
	SubjectID           string
	SubjectIdentity     string
	PackageID           string
	PackageSHA256       string
	Version             string
	Sources             []SourceIdentity
	Images              []ImageIdentity
	Directories         []Directory
	Files               []File
	Actions             []File
	ActionIDs           []string
	ActionWritablePaths []string
	Secrets             []SecretReference
	Preconditions       []Precondition
	ExpectedPost        any
	Validations         []ValidationSpec
	Steps               []Step
	BackupRequired      bool
	BackupRef           string
}

type Bundle struct {
	ID       string
	Kind     Kind
	SHA256   string
	Bytes    []byte
	Manifest Manifest
}
