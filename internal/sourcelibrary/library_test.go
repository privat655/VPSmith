package sourcelibrary

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/managementstate"
)

func TestEmbeddedSnapshotsAndWorkspacesStaySeparated(t *testing.T) {
	ctx := context.Background()
	store, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	root := t.TempDir()
	lib, err := New(root, repositoryPath(t, "embedded"), store, &fakeRemote{})
	if err != nil {
		t.Fatal(err)
	}
	snaps, err := lib.ImportEmbedded(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) != 3 {
		t.Fatalf("got %d embedded snapshots", len(snaps))
	}
	for _, snap := range snaps {
		if snap.Version == "" || snap.SHA256 == "" {
			t.Fatalf("incomplete immutable identity: %#v", snap)
		}
	}
	core := findKind(t, snaps, managementstate.SourceCore)
	ws, err := lib.CreateWorkspace(ctx, core.ID)
	if err != nil {
		t.Fatal(err)
	}
	original := core.SHA256
	ws, err = lib.Apply(ctx, ws.ID, []Edit{{Path: "README.md", Content: []byte("local core edit\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	if ws.SHA256 == original {
		t.Fatal("workspace edit did not change local identity")
	}
	state, err := store.Sources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range state.Artifacts {
		if a.ID == core.ID && a.SHA256 != original {
			t.Fatal("workspace mutated immutable base snapshot")
		}
	}
	diff, err := lib.Diff(ctx, ws.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Changes) == 0 {
		t.Fatal("expected structured diff")
	}
}

func TestCustomModuleLoadPushAndRemoteDrift(t *testing.T) {
	ctx := context.Background()
	remotePath, seed := newBareRemote(t)
	store, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	configureRemote(t, ctx, store)
	lib, err := New(t.TempDir(), repositoryPath(t, "embedded"), store, NewLocalGitRemote(remotePath))
	if err != nil {
		t.Fatal(err)
	}
	snap, err := lib.LoadCustomModule(ctx, "modules/demo", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if snap.Commit == "" || snap.SHA256 == "" {
		t.Fatalf("loaded source lacks exact identity: %#v", snap)
	}
	ws, err := lib.CreateWorkspace(ctx, snap.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ws.BaseCommit != snap.Commit {
		t.Fatal("workspace lost base_commit")
	}
	ws, err = lib.Apply(ctx, ws.ID, []Edit{{Path: "module.yaml", Content: []byte("module_version: 1.0.1\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	pushed, err := lib.PushCustomModule(ctx, ws.ID, "Update demo module")
	if err != nil {
		t.Fatal(err)
	}
	if pushed.SynchronizedCommit == "" {
		t.Fatal("successful push was not verified as synchronized")
	}
	remoteHead := git(t, "", "--git-dir", remotePath, "rev-parse", "refs/heads/main")
	if remoteHead != pushed.SynchronizedCommit {
		t.Fatalf("remote=%s synchronized=%s", remoteHead, pushed.SynchronizedCommit)
	}

	second, err := lib.LoadCustomModule(ctx, "modules/demo", "1.0.1")
	if err != nil {
		t.Fatal(err)
	}
	driftWS, err := lib.CreateWorkspace(ctx, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = lib.Apply(ctx, driftWS.ID, []Edit{{Path: "module.yaml", Content: []byte("module_version: local\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	competingCommit(t, seed, remotePath, "remote change")
	_, err = lib.PushCustomModule(ctx, driftWS.ID, "local change")
	var drift *RemoteDriftError
	if !errors.As(err, &drift) {
		t.Fatalf("expected fail-closed remote drift, got %v", err)
	}
}

func TestPushRaceFailsClosedAndNeverMarksSynchronized(t *testing.T) {
	ctx := context.Background()
	remotePath, seed := newBareRemote(t)
	store, _ := managementstate.NewMemory()
	defer store.Close()
	configureRemote(t, ctx, store)
	remote := &gitRemote{fixedURL: remotePath}
	lib, _ := New(t.TempDir(), repositoryPath(t, "embedded"), store, remote)
	snap, err := lib.LoadCustomModule(ctx, "modules/demo", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	ws, err := lib.CreateWorkspace(ctx, snap.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = lib.Apply(ctx, ws.ID, []Edit{{Path: "module.yaml", Content: []byte("module_version: raced\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	remote.beforePush = func() { competingCommit(t, seed, remotePath, "race winner") }
	_, err = lib.PushCustomModule(ctx, ws.ID, "race loser")
	var drift *RemoteDriftError
	if !errors.As(err, &drift) {
		t.Fatalf("expected race drift, got %v", err)
	}
	state, err := store.Sources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range state.Workspaces {
		if w.ID == ws.ID && w.SynchronizedCommit != "" {
			t.Fatal("failed race was marked synchronized")
		}
	}
}

func TestCoreThreeWayMergeProducesCandidateOrExplicitConflict(t *testing.T) {
	ctx := context.Background()
	store, _ := managementstate.NewMemory()
	defer store.Close()
	lib, _ := New(t.TempDir(), repositoryPath(t, "embedded"), store, &fakeRemote{})
	oldDir := tree(t, "line1\nkeep1\nkeep2\nkeep3\nline5\n")
	old, err := lib.importSnapshot(ctx, managementstate.SourceCore, "", "", "1", "", oldDir, "")
	if err != nil {
		t.Fatal(err)
	}
	ws, err := lib.CreateWorkspace(ctx, old.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = lib.Apply(ctx, ws.ID, []Edit{{Path: "file.txt", Content: []byte("local\nkeep1\nkeep2\nkeep3\nline5\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	newDir := tree(t, "line1\nkeep1\nkeep2\nkeep3\nupstream\n")
	newSnap, err := lib.importSnapshot(ctx, managementstate.SourceCore, "", "", "2", "", newDir, "")
	if err != nil {
		t.Fatal(err)
	}
	merged, err := lib.MergeCore(ctx, ws.ID, newSnap.ID)
	if err != nil {
		t.Fatal(err)
	}
	if merged.Candidate == nil || len(merged.Conflicts) != 0 {
		t.Fatalf("expected clean candidate: %#v", merged)
	}
	if merged.Candidate.BaseSnapshotID != newSnap.ID {
		t.Fatal("clean merge candidate must reference new embedded base")
	}
	if ws.BaseSnapshotID != old.ID {
		t.Fatal("original core workspace base changed")
	}

	conflictWS, err := lib.CreateWorkspace(ctx, old.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = lib.Apply(ctx, conflictWS.ID, []Edit{{Path: "file.txt", Content: []byte("local conflict\nline2\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	conflictDir := tree(t, "upstream conflict\nline2\n")
	conflictBase, err := lib.importSnapshot(ctx, managementstate.SourceCore, "", "", "3", "", conflictDir, "")
	if err != nil {
		t.Fatal(err)
	}
	conflicted, err := lib.MergeCore(ctx, conflictWS.ID, conflictBase.ID)
	if err != nil {
		t.Fatal(err)
	}
	if conflicted.Candidate != nil || len(conflicted.Conflicts) == 0 {
		t.Fatalf("expected explicit unresolved conflict: %#v", conflicted)
	}
}

func TestCoreAndCloudInitHaveNoRemotePushPath(t *testing.T) {
	ctx := context.Background()
	store, _ := managementstate.NewMemory()
	defer store.Close()
	lib, _ := New(t.TempDir(), repositoryPath(t, "embedded"), store, &fakeRemote{})
	snaps, err := lib.ImportEmbedded(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []managementstate.SourceKind{managementstate.SourceCore, managementstate.SourceCloudInit} {
		snap := findKind(t, snaps, kind)
		ws, err := lib.CreateWorkspace(ctx, snap.ID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := lib.PushCustomModule(ctx, ws.ID, "forbidden"); err == nil || !strings.Contains(err.Error(), "only custom module") {
			t.Fatalf("%s acquired a push path: %v", kind, err)
		}
	}
}

type fakeRemote struct{}

func (*fakeRemote) Fetch(context.Context, RemoteConfig, string) (FetchResult, error) {
	return FetchResult{}, errors.New("not configured")
}
func (*fakeRemote) Push(context.Context, PushRequest) (PushResult, error) {
	return PushResult{}, errors.New("not configured")
}

func configureRemote(t *testing.T, ctx context.Context, store *managementstate.Store) {
	t.Helper()
	err := store.Change(ctx, func(c *managementstate.Change) error {
		id, err := c.CreateSecret("custom-module-github-pat", managementstate.SecretUser)
		if err != nil {
			return err
		}
		if err := c.SetSecret(id, []byte("test-token-not-used-by-local-remote")); err != nil {
			return err
		}
		return c.ConfigureCustomModuleGithub(managementstate.CustomModuleGithubConfig{Owner: "local", Repository: "modules", Ref: "main", PATSecretID: id})
	})
	if err != nil {
		t.Fatal(err)
	}
}
func newBareRemote(t *testing.T) (string, string) {
	t.Helper()
	bare := filepath.Join(t.TempDir(), "remote.git")
	git(t, "", "init", "--bare", "-q", bare)
	seed := t.TempDir()
	git(t, seed, "init", "-q", "-b", "main")
	if err := os.MkdirAll(filepath.Join(seed, "modules", "demo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(seed, "modules", "demo", "module.yaml"), []byte("module_version: 1.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, seed, "add", ".")
	git(t, seed, "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-q", "-m", "initial")
	git(t, seed, "remote", "add", "origin", bare)
	git(t, seed, "push", "-q", "origin", "main")
	return bare, seed
}
func competingCommit(t *testing.T, seed, bare, msg string) {
	t.Helper()
	git(t, seed, "fetch", "-q", "origin", "main")
	git(t, seed, "reset", "-q", "--hard", "FETCH_HEAD")
	p := filepath.Join(seed, "modules", "demo", "remote.txt")
	if err := os.WriteFile(p, []byte(msg+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, seed, "add", p)
	git(t, seed, "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-q", "-m", msg)
	git(t, seed, "push", "-q", "origin", "HEAD:main")
}
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}
func repositoryPath(t *testing.T, rel string) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(wd, "..", ".."))
	return filepath.Join(root, rel)
}
func findKind(t *testing.T, s []Snapshot, k managementstate.SourceKind) Snapshot {
	t.Helper()
	for _, v := range s {
		if v.Kind == k {
			return v
		}
	}
	t.Fatalf("missing snapshot kind %s", k)
	return Snapshot{}
}
func tree(t *testing.T, content string) string {
	t.Helper()
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, "file.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return d
}
