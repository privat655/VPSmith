package managementstate

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

type SourceSnapshotID string
type SourceWorkspaceID string

func NewSourceSnapshotID() (SourceSnapshotID, error) {
	v, err := newID("source")
	return SourceSnapshotID(v), err
}
func NewSourceWorkspaceID() (SourceWorkspaceID, error) {
	v, err := newID("workspace")
	return SourceWorkspaceID(v), err
}

type SourceKind string

const (
	SourceCloudInit    SourceKind = "cloud-init"
	SourceCore         SourceKind = "core"
	SourceEmbeddedN8N  SourceKind = "embedded-n8n"
	SourceCustomModule SourceKind = "custom-module"
)

type SourceArtifact struct {
	ID          SourceSnapshotID `json:"id"`
	Kind        SourceKind       `json:"kind"`
	PackageID   ModulePackageID  `json:"package_id,omitempty"`
	PackagePath string           `json:"package_path,omitempty"`
	Version     string           `json:"version"`
	Commit      string           `json:"commit,omitempty"`
	SHA256      string           `json:"sha256"`
	StorageRef  string           `json:"storage_ref"`
}

type SourceWorkspace struct {
	ID                 SourceWorkspaceID `json:"id"`
	Kind               SourceKind        `json:"kind"`
	PackageID          ModulePackageID   `json:"package_id,omitempty"`
	PackagePath        string            `json:"package_path,omitempty"`
	BaseSourceID       SourceSnapshotID  `json:"base_source_id"`
	BaseCommit         string            `json:"base_commit,omitempty"`
	CurrentSHA256      string            `json:"current_sha256"`
	StorageRef         string            `json:"storage_ref"`
	SynchronizedCommit string            `json:"synchronized_commit,omitempty"`
}

type CustomModuleGithubConfig struct {
	Owner       string   `json:"owner"`
	Repository  string   `json:"repository"`
	Ref         string   `json:"ref"`
	PATSecretID SecretID `json:"pat_secret_id"`
}

type SourceState struct {
	Artifacts          []SourceArtifact          `json:"artifacts"`
	Workspaces         []SourceWorkspace         `json:"workspaces"`
	CustomModuleGithub *CustomModuleGithubConfig `json:"custom_module_github,omitempty"`
}

func (s *Store) Sources(ctx context.Context) (SourceState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.readCanonicalSources(ctx)
}

func (c *Change) RegisterSourceArtifact(v SourceArtifact) error {
	if v.ID == "" || !validSourceKind(v.Kind) || strings.TrimSpace(v.Version) == "" || strings.TrimSpace(v.SHA256) == "" || strings.TrimSpace(v.StorageRef) == "" {
		return errors.New("source artifact metadata is incomplete")
	}
	if v.Kind == SourceCustomModule && (v.PackageID == "" || strings.TrimSpace(v.Commit) == "" || strings.TrimSpace(v.PackagePath) == "") {
		return errors.New("custom module source requires package id, package path, and commit")
	}
	if v.Kind != SourceCustomModule && v.PackageID != "" {
		return errors.New("only custom module source may carry package id")
	}
	if err := c.rejectKnownSecretMaterial(v); err != nil {
		return err
	}
	_, err := c.conn.ExecContext(c.ctx, `INSERT INTO source_artifacts(id,kind,package_id,package_path,version,commit_sha,sha256,storage_ref) VALUES(?,?,?,?,?,?,?,?)`, v.ID, v.Kind, v.PackageID, v.PackagePath, v.Version, v.Commit, v.SHA256, v.StorageRef)
	if err != nil {
		return fmt.Errorf("register immutable source artifact: %w", err)
	}
	return nil
}

func (c *Change) CreateSourceWorkspace(v SourceWorkspace) error {
	if v.ID == "" || !validSourceKind(v.Kind) || v.BaseSourceID == "" || strings.TrimSpace(v.CurrentSHA256) == "" || strings.TrimSpace(v.StorageRef) == "" {
		return errors.New("source workspace metadata is incomplete")
	}
	if v.Kind == SourceCustomModule && (v.PackageID == "" || strings.TrimSpace(v.BaseCommit) == "" || strings.TrimSpace(v.PackagePath) == "") {
		return errors.New("custom module workspace requires package id, package path, and base commit")
	}
	var count int
	if err := c.conn.QueryRowContext(c.ctx, `SELECT COUNT(*) FROM source_artifacts WHERE id=? AND kind=?`, v.BaseSourceID, v.Kind).Scan(&count); err != nil {
		return err
	}
	if count != 1 {
		return errors.New("workspace base source does not exist or has different kind")
	}
	if err := c.rejectKnownSecretMaterial(v); err != nil {
		return err
	}
	_, err := c.conn.ExecContext(c.ctx, `INSERT INTO source_workspaces(id,kind,package_id,package_path,base_source_id,base_commit,current_sha256,storage_ref,synchronized_commit) VALUES(?,?,?,?,?,?,?,?,?)`, v.ID, v.Kind, v.PackageID, v.PackagePath, v.BaseSourceID, v.BaseCommit, v.CurrentSHA256, v.StorageRef, v.SynchronizedCommit)
	if err != nil {
		return fmt.Errorf("create source workspace: %w", err)
	}
	return nil
}

func (c *Change) UpdateSourceWorkspaceCurrent(id SourceWorkspaceID, sha string) error {
	if strings.TrimSpace(sha) == "" {
		return errors.New("workspace sha256 is required")
	}
	result, err := c.conn.ExecContext(c.ctx, `UPDATE source_workspaces SET current_sha256=?, synchronized_commit='' WHERE id=?`, sha, id)
	if err != nil {
		return fmt.Errorf("update source workspace: %w", err)
	}
	return requireOne(result, "source workspace")
}

func (c *Change) MarkSourceWorkspaceSynchronized(id SourceWorkspaceID, commit, sha string) error {
	if strings.TrimSpace(commit) == "" || strings.TrimSpace(sha) == "" {
		return errors.New("synchronized commit and sha256 are required")
	}
	result, err := c.conn.ExecContext(c.ctx, `UPDATE source_workspaces SET synchronized_commit=?, current_sha256=? WHERE id=?`, commit, sha, id)
	if err != nil {
		return fmt.Errorf("mark source workspace synchronized: %w", err)
	}
	return requireOne(result, "source workspace")
}

func (c *Change) ConfigureCustomModuleGithub(v CustomModuleGithubConfig) error {
	if strings.TrimSpace(v.Owner) == "" || strings.TrimSpace(v.Repository) == "" || strings.TrimSpace(v.Ref) == "" || v.PATSecretID == "" {
		return errors.New("custom module github configuration is incomplete")
	}
	if err := c.requireSecret(v.PATSecretID); err != nil {
		return err
	}
	if err := c.rejectKnownSecretMaterial(v); err != nil {
		return err
	}
	_, err := c.conn.ExecContext(c.ctx, `INSERT INTO custom_module_github(singleton,owner,repository,ref,pat_secret_id) VALUES(1,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET owner=excluded.owner,repository=excluded.repository,ref=excluded.ref,pat_secret_id=excluded.pat_secret_id`, v.Owner, v.Repository, v.Ref, v.PATSecretID)
	if err != nil {
		return fmt.Errorf("configure custom module github: %w", err)
	}
	return nil
}

func validSourceKind(v SourceKind) bool {
	switch v {
	case SourceCloudInit, SourceCore, SourceEmbeddedN8N, SourceCustomModule:
		return true
	default:
		return false
	}
}
