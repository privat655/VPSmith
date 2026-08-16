package sourcelibrary

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/releaseinfo"
	"github.com/privat655/VPSmith/internal/sourcehash"
)

type Library struct {
	root         string
	embeddedRoot string
	state        *managementstate.Store
	remote       Remote
}

type Snapshot struct {
	ID          managementstate.SourceSnapshotID
	Kind        managementstate.SourceKind
	PackageID   managementstate.ModulePackageID
	PackagePath string
	Version     string
	Commit      string
	SHA256      string
}

type Workspace struct {
	ID                 managementstate.SourceWorkspaceID
	Kind               managementstate.SourceKind
	PackageID          managementstate.ModulePackageID
	PackagePath        string
	BaseSnapshotID     managementstate.SourceSnapshotID
	BaseCommit         string
	SHA256             string
	SynchronizedCommit string
}

type ChangeKind string

const (
	Added    ChangeKind = "added"
	Modified ChangeKind = "modified"
	Deleted  ChangeKind = "deleted"
)

type FileChange struct {
	Path      string     `json:"path"`
	Kind      ChangeKind `json:"kind"`
	BeforeSHA string     `json:"before_sha256,omitempty"`
	AfterSHA  string     `json:"after_sha256,omitempty"`
}

type Diff struct {
	Changes []FileChange `json:"changes"`
}

type Edit struct {
	Path    string
	Content []byte
	Mode    fs.FileMode
	Delete  bool
}

type MergeResult struct {
	Candidate *Workspace `json:"candidate,omitempty"`
	Conflicts []string   `json:"conflicts"`
}

type RemoteDriftError struct {
	Expected string
	Actual   string
}

func (e *RemoteDriftError) Error() string {
	return fmt.Sprintf("custom module remote drift: expected %s, actual %s", e.Expected, e.Actual)
}

func New(root, embeddedRoot string, state *managementstate.Store, remote Remote) (*Library, error) {
	if state == nil {
		return nil, errors.New("management state is required")
	}
	if remote == nil {
		return nil, errors.New("custom module remote adapter is required")
	}
	for _, p := range []string{
		filepath.Join(root, "snapshots", "sha256"),
		filepath.Join(root, "workspaces"),
	} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			return nil, fmt.Errorf("create source library: %w", err)
		}
	}
	return &Library{root: root, embeddedRoot: embeddedRoot, state: state, remote: remote}, nil
}

func (l *Library) ImportEmbedded(ctx context.Context) ([]Snapshot, error) {
	info, err := releaseinfo.Load(l.embeddedRoot)
	if err != nil {
		return nil, err
	}
	items := []struct {
		kind managementstate.SourceKind
		src  releaseinfo.Source
	}{
		{managementstate.SourceCloudInit, info.Embedded.CloudInit},
		{managementstate.SourceCore, info.Embedded.Core},
		{managementstate.SourceEmbeddedN8N, info.Embedded.N8N},
	}
	out := make([]Snapshot, 0, len(items))
	for _, item := range items {
		path := filepath.Join(l.embeddedRoot, filepath.FromSlash(item.src.Path))
		snap, err := l.importSnapshot(ctx, item.kind, "", "", item.src.Version, "", path, item.src.SHA256)
		if err != nil {
			return nil, err
		}
		out = append(out, snap)
	}
	return out, nil
}

func (l *Library) CreateWorkspace(ctx context.Context, snapshotID managementstate.SourceSnapshotID) (Workspace, error) {
	a, err := l.artifact(ctx, snapshotID)
	if err != nil {
		return Workspace{}, err
	}
	id, err := managementstate.NewSourceWorkspaceID()
	if err != nil {
		return Workspace{}, err
	}
	dst := filepath.Join(l.root, "workspaces", string(id))
	if err := copyTree(l.snapshotPath(a.SHA256), dst); err != nil {
		return Workspace{}, fmt.Errorf("create workspace: %w", err)
	}
	sha, err := sourcehash.TreeSHA256(dst)
	if err != nil {
		_ = os.RemoveAll(dst)
		return Workspace{}, err
	}
	value := managementstate.SourceWorkspace{
		ID: id, Kind: a.Kind, PackageID: a.PackageID, PackagePath: a.PackagePath,
		BaseSourceID: a.ID, BaseCommit: a.Commit, CurrentSHA256: sha,
		StorageRef: filepath.ToSlash(filepath.Join("workspaces", string(id))),
	}
	if err := l.state.Change(ctx, func(c *managementstate.Change) error {
		return c.CreateSourceWorkspace(value)
	}); err != nil {
		_ = os.RemoveAll(dst)
		return Workspace{}, err
	}
	return workspaceFromState(value), nil
}

func (l *Library) Apply(ctx context.Context, id managementstate.SourceWorkspaceID, edits []Edit) (Workspace, error) {
	w, err := l.workspace(ctx, id)
	if err != nil {
		return Workspace{}, err
	}
	root := l.workspacePath(w)
	for _, edit := range edits {
		if err := validateRelativeEditPath(edit.Path); err != nil {
			return Workspace{}, err
		}
		path := filepath.Join(root, filepath.FromSlash(edit.Path))
		if edit.Delete {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return Workspace{}, err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return Workspace{}, err
		}
		mode := edit.Mode.Perm()
		if mode == 0 {
			mode = 0o644
		}
		if err := os.WriteFile(path, edit.Content, mode); err != nil {
			return Workspace{}, err
		}
	}
	return l.RefreshWorkspace(ctx, id)
}

func (l *Library) RefreshWorkspace(ctx context.Context, id managementstate.SourceWorkspaceID) (Workspace, error) {
	w, err := l.workspace(ctx, id)
	if err != nil {
		return Workspace{}, err
	}
	sha, err := sourcehash.TreeSHA256(l.workspacePath(w))
	if err != nil {
		return Workspace{}, err
	}
	if err := l.state.Change(ctx, func(c *managementstate.Change) error {
		return c.UpdateSourceWorkspaceCurrent(id, sha)
	}); err != nil {
		return Workspace{}, err
	}
	w.CurrentSHA256 = sha
	w.SynchronizedCommit = ""
	return workspaceFromState(w), nil
}

func (l *Library) Diff(ctx context.Context, id managementstate.SourceWorkspaceID) (Diff, error) {
	w, err := l.workspace(ctx, id)
	if err != nil {
		return Diff{}, err
	}
	base, err := l.artifact(ctx, w.BaseSourceID)
	if err != nil {
		return Diff{}, err
	}
	return diffTrees(l.snapshotPath(base.SHA256), l.workspacePath(w))
}

func (l *Library) LoadCustomModule(ctx context.Context, packagePath, version string) (Snapshot, error) {
	cfg, err := l.config(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	var fetched FetchResult
	err = l.state.ResolveSecret(ctx, cfg.PATSecretID, func(secret managementstate.SecretMaterial) error {
		var inner error
		fetched, inner = l.remote.Fetch(ctx, RemoteConfig{
			Owner: cfg.Owner, Repository: cfg.Repository, Ref: cfg.Ref,
			Token: string(secret.Bytes()),
		}, packagePath)
		return inner
	})
	if err != nil {
		return Snapshot{}, fmt.Errorf("fetch custom module: %w", err)
	}
	defer os.RemoveAll(fetched.Path)
	packageID, err := managementstate.NewModulePackageID()
	if err != nil {
		return Snapshot{}, err
	}
	return l.importSnapshot(ctx, managementstate.SourceCustomModule, packageID, packagePath, version, fetched.Commit, fetched.Path, "")
}

func (l *Library) PushCustomModule(ctx context.Context, id managementstate.SourceWorkspaceID, message string) (Workspace, error) {
	if strings.TrimSpace(message) == "" {
		return Workspace{}, errors.New("commit message is required")
	}
	w, err := l.workspace(ctx, id)
	if err != nil {
		return Workspace{}, err
	}
	if w.Kind != managementstate.SourceCustomModule {
		return Workspace{}, errors.New("only custom module workspaces can be pushed")
	}
	if _, err := l.RefreshWorkspace(ctx, id); err != nil {
		return Workspace{}, err
	}
	w, err = l.workspace(ctx, id)
	if err != nil {
		return Workspace{}, err
	}
	cfg, err := l.config(ctx)
	if err != nil {
		return Workspace{}, err
	}
	var pushed PushResult
	err = l.state.ResolveSecret(ctx, cfg.PATSecretID, func(secret managementstate.SecretMaterial) error {
		var inner error
		pushed, inner = l.remote.Push(ctx, PushRequest{
			Config: RemoteConfig{
				Owner: cfg.Owner, Repository: cfg.Repository, Ref: cfg.Ref,
				Token: string(secret.Bytes()),
			},
			PackagePath: w.PackagePath, WorkspacePath: l.workspacePath(w),
			BaseCommit: w.BaseCommit, Message: message,
		})
		return inner
	})
	if err != nil {
		var drift *RemoteDriftError
		if errors.As(err, &drift) {
			return Workspace{}, drift
		}
		return Workspace{}, fmt.Errorf("push custom module: %w", err)
	}
	sha, err := sourcehash.TreeSHA256(l.workspacePath(w))
	if err != nil {
		return Workspace{}, err
	}
	if pushed.RemoteCommit != pushed.Commit {
		return Workspace{}, &RemoteDriftError{Expected: pushed.Commit, Actual: pushed.RemoteCommit}
	}
	if err := l.state.Change(ctx, func(c *managementstate.Change) error {
		return c.MarkSourceWorkspaceSynchronized(id, pushed.Commit, sha)
	}); err != nil {
		return Workspace{}, err
	}
	w.CurrentSHA256 = sha
	w.SynchronizedCommit = pushed.Commit
	return workspaceFromState(w), nil
}

func (l *Library) MergeCore(ctx context.Context, id managementstate.SourceWorkspaceID, newBase managementstate.SourceSnapshotID) (MergeResult, error) {
	w, err := l.workspace(ctx, id)
	if err != nil {
		return MergeResult{}, err
	}
	if w.Kind != managementstate.SourceCore {
		return MergeResult{}, errors.New("core merge requires a core workspace")
	}
	oldBase, err := l.artifact(ctx, w.BaseSourceID)
	if err != nil {
		return MergeResult{}, err
	}
	newArtifact, err := l.artifact(ctx, newBase)
	if err != nil {
		return MergeResult{}, err
	}
	if newArtifact.Kind != managementstate.SourceCore {
		return MergeResult{}, errors.New("new core base is not a core snapshot")
	}
	merged, conflicts, err := threeWayMerge(ctx, l.snapshotPath(oldBase.SHA256), l.workspacePath(w), l.snapshotPath(newArtifact.SHA256))
	if err != nil {
		return MergeResult{}, err
	}
	defer os.RemoveAll(merged)
	if len(conflicts) > 0 {
		return MergeResult{Conflicts: conflicts}, nil
	}
	candidate, err := l.createWorkspaceFromPath(ctx, newArtifact, merged)
	if err != nil {
		return MergeResult{}, err
	}
	return MergeResult{Candidate: &candidate, Conflicts: []string{}}, nil
}

func (l *Library) importSnapshot(ctx context.Context, kind managementstate.SourceKind, packageID managementstate.ModulePackageID, packagePath, version, commit, src, expected string) (Snapshot, error) {
	sha, err := sourcehash.TreeSHA256(src)
	if err != nil {
		return Snapshot{}, err
	}
	if expected != "" && sha != expected {
		return Snapshot{}, fmt.Errorf("embedded source sha256 mismatch: expected=%s actual=%s", expected, sha)
	}
	state, err := l.state.Sources(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	for _, a := range state.Artifacts {
		if a.Kind == kind && a.PackageID == packageID && a.Commit == commit && a.SHA256 == sha {
			if err := l.verifySnapshot(a); err != nil {
				return Snapshot{}, err
			}
			return snapshotFromState(a), nil
		}
	}

	dst := l.snapshotPath(sha)
	if _, err := os.Stat(dst); errors.Is(err, os.ErrNotExist) {
		tmp, err := os.MkdirTemp(filepath.Join(l.root, "snapshots"), ".import-*")
		if err != nil {
			return Snapshot{}, err
		}
		defer os.RemoveAll(tmp)
		payload := filepath.Join(tmp, "payload")
		if err := copyTree(src, payload); err != nil {
			return Snapshot{}, err
		}
		check, err := sourcehash.TreeSHA256(payload)
		if err != nil {
			return Snapshot{}, err
		}
		if check != sha {
			return Snapshot{}, errors.New("source changed while importing")
		}
		if err := os.Rename(payload, dst); err != nil {
			if _, statErr := os.Stat(dst); statErr != nil {
				return Snapshot{}, fmt.Errorf("publish immutable snapshot: %w", err)
			}
		}
	} else if err != nil {
		return Snapshot{}, err
	}
	check, err := sourcehash.TreeSHA256(dst)
	if err != nil {
		return Snapshot{}, err
	}
	if check != sha {
		return Snapshot{}, errors.New("immutable snapshot integrity failure")
	}

	id, err := managementstate.NewSourceSnapshotID()
	if err != nil {
		return Snapshot{}, err
	}
	artifact := managementstate.SourceArtifact{
		ID: id, Kind: kind, PackageID: packageID, PackagePath: packagePath,
		Version: version, Commit: commit, SHA256: sha,
		StorageRef: filepath.ToSlash(filepath.Join("snapshots", "sha256", sha)),
	}
	if err := l.state.Change(ctx, func(c *managementstate.Change) error {
		return c.RegisterSourceArtifact(artifact)
	}); err != nil {
		return Snapshot{}, err
	}
	return snapshotFromState(artifact), nil
}

func (l *Library) verifySnapshot(a managementstate.SourceArtifact) error {
	actual, err := sourcehash.TreeSHA256(l.snapshotPath(a.SHA256))
	if err != nil {
		return fmt.Errorf("verify immutable source snapshot %s: %w", a.ID, err)
	}
	if actual != a.SHA256 {
		return fmt.Errorf("immutable source snapshot %s changed: expected=%s actual=%s", a.ID, a.SHA256, actual)
	}
	return nil
}

func (l *Library) createWorkspaceFromPath(ctx context.Context, base managementstate.SourceArtifact, src string) (Workspace, error) {
	id, err := managementstate.NewSourceWorkspaceID()
	if err != nil {
		return Workspace{}, err
	}
	dst := filepath.Join(l.root, "workspaces", string(id))
	if err := copyTree(src, dst); err != nil {
		return Workspace{}, err
	}
	sha, err := sourcehash.TreeSHA256(dst)
	if err != nil {
		_ = os.RemoveAll(dst)
		return Workspace{}, err
	}
	value := managementstate.SourceWorkspace{
		ID: id, Kind: base.Kind, PackageID: base.PackageID, PackagePath: base.PackagePath,
		BaseSourceID: base.ID, BaseCommit: base.Commit, CurrentSHA256: sha,
		StorageRef: filepath.ToSlash(filepath.Join("workspaces", string(id))),
	}
	if err := l.state.Change(ctx, func(c *managementstate.Change) error {
		return c.CreateSourceWorkspace(value)
	}); err != nil {
		_ = os.RemoveAll(dst)
		return Workspace{}, err
	}
	return workspaceFromState(value), nil
}

func (l *Library) config(ctx context.Context) (managementstate.CustomModuleGithubConfig, error) {
	s, err := l.state.Sources(ctx)
	if err != nil {
		return managementstate.CustomModuleGithubConfig{}, err
	}
	if s.CustomModuleGithub == nil {
		return managementstate.CustomModuleGithubConfig{}, errors.New("custom module github is not configured")
	}
	return *s.CustomModuleGithub, nil
}

func (l *Library) artifact(ctx context.Context, id managementstate.SourceSnapshotID) (managementstate.SourceArtifact, error) {
	s, err := l.state.Sources(ctx)
	if err != nil {
		return managementstate.SourceArtifact{}, err
	}
	for _, value := range s.Artifacts {
		if value.ID == id {
			if err := l.verifySnapshot(value); err != nil {
				return managementstate.SourceArtifact{}, err
			}
			return value, nil
		}
	}
	return managementstate.SourceArtifact{}, fmt.Errorf("source snapshot %s does not exist", id)
}

func (l *Library) workspace(ctx context.Context, id managementstate.SourceWorkspaceID) (managementstate.SourceWorkspace, error) {
	s, err := l.state.Sources(ctx)
	if err != nil {
		return managementstate.SourceWorkspace{}, err
	}
	for _, value := range s.Workspaces {
		if value.ID == id {
			return value, nil
		}
	}
	return managementstate.SourceWorkspace{}, fmt.Errorf("source workspace %s does not exist", id)
}

func (l *Library) snapshotPath(sha string) string {
	return filepath.Join(l.root, "snapshots", "sha256", sha)
}

func (l *Library) workspacePath(w managementstate.SourceWorkspace) string {
	return filepath.Join(l.root, filepath.FromSlash(w.StorageRef))
}

func snapshotFromState(value managementstate.SourceArtifact) Snapshot {
	return Snapshot{
		ID: value.ID, Kind: value.Kind, PackageID: value.PackageID,
		PackagePath: value.PackagePath, Version: value.Version,
		Commit: value.Commit, SHA256: value.SHA256,
	}
}

func workspaceFromState(value managementstate.SourceWorkspace) Workspace {
	return Workspace{
		ID: value.ID, Kind: value.Kind, PackageID: value.PackageID,
		PackagePath: value.PackagePath, BaseSnapshotID: value.BaseSourceID,
		BaseCommit: value.BaseCommit, SHA256: value.CurrentSHA256,
		SynchronizedCommit: value.SynchronizedCommit,
	}
}

func validateRelativeEditPath(value string) error {
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(value)))
	if value == "" || clean == "." || clean != value || filepath.IsAbs(filepath.FromSlash(value)) || value == ".." || strings.HasPrefix(value, "../") || strings.HasPrefix(value, ".git/") || value == ".git" {
		return fmt.Errorf("workspace path %q must be a clean relative non-git path", value)
	}
	return nil
}

func copyTree(src, dst string) error {
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	return filepath.WalkDir(src, func(path string, de fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == src {
			return nil
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := de.Info()
		if err != nil {
			return err
		}
		if de.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported source entry %s", rel)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
		if err != nil {
			_ = in.Close()
			return err
		}
		_, copyErr := io.Copy(out, in)
		inErr := in.Close()
		outErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if inErr != nil {
			return inErr
		}
		return outErr
	})
}

func diffTrees(before, after string) (Diff, error) {
	beforeDigests, err := fileDigests(before)
	if err != nil {
		return Diff{}, err
	}
	afterDigests, err := fileDigests(after)
	if err != nil {
		return Diff{}, err
	}
	keys := map[string]struct{}{}
	for key := range beforeDigests {
		keys[key] = struct{}{}
	}
	for key := range afterDigests {
		keys[key] = struct{}{}
	}
	paths := make([]string, 0, len(keys))
	for key := range keys {
		paths = append(paths, key)
	}
	sort.Strings(paths)
	out := Diff{Changes: []FileChange{}}
	for _, path := range paths {
		beforeSHA, beforeOK := beforeDigests[path]
		afterSHA, afterOK := afterDigests[path]
		switch {
		case !beforeOK && afterOK:
			out.Changes = append(out.Changes, FileChange{Path: path, Kind: Added, AfterSHA: afterSHA})
		case beforeOK && !afterOK:
			out.Changes = append(out.Changes, FileChange{Path: path, Kind: Deleted, BeforeSHA: beforeSHA})
		case beforeOK && afterOK && beforeSHA != afterSHA:
			out.Changes = append(out.Changes, FileChange{Path: path, Kind: Modified, BeforeSHA: beforeSHA, AfterSHA: afterSHA})
		}
	}
	return out, nil
}

func fileDigests(root string) (map[string]string, error) {
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, de fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !sourcehash.RelevantPath(rel, de.IsDir()) {
			if de.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if de.IsDir() {
			return nil
		}
		if de.Type()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			sum := sha256.Sum256([]byte("symlink\x00" + target))
			out[rel] = hex.EncodeToString(sum[:])
			return nil
		}
		if !de.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		out[rel] = hex.EncodeToString(sum[:])
		return nil
	})
	return out, err
}
