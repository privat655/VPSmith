package recoverypackage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/backuprestore"
	"github.com/privat655/VPSmith/internal/executionbundle"
	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/sourcehash"
	"github.com/privat655/VPSmith/internal/sourcelibrary"
)

type rejectingRemote struct{}

func (rejectingRemote) Fetch(context.Context, sourcelibrary.RemoteConfig, string) (sourcelibrary.FetchResult, error) {
	return sourcelibrary.FetchResult{}, errors.New("remote access is not part of recovery acceptance")
}

func (rejectingRemote) Push(context.Context, sourcelibrary.PushRequest) (sourcelibrary.PushResult, error) {
	return sourcelibrary.PushResult{}, errors.New("remote access is not part of recovery acceptance")
}

type recoveryFixture struct {
	state       *managementstate.Store
	sources     *sourcelibrary.Library
	bundles     *executionbundle.Assembler
	backups     *backuprestore.Manager
	service     *Service
	sourceRoot  string
	targetID    managementstate.TargetID
	sshSecret   managementstate.SecretID
	appSecret   managementstate.SecretID
	patSecret   managementstate.SecretID
	workspaceID managementstate.SourceWorkspaceID
}

func TestRecoveryPackageCreateImportIntoFreshState(t *testing.T) {
	ctx := context.Background()
	source := newRecoveryFixture(t, ctx, true)
	passphrase := []byte("step-eight-recovery-passphrase")

	withoutPAT, err := source.service.Create(ctx, CreateRequest{TargetID: source.targetID, Passphrase: passphrase})
	if err != nil {
		t.Fatal(err)
	}
	destination := newEmptyRecoveryFixture(t)
	imported, err := destination.service.Import(ctx, withoutPAT.Path, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if imported.Metadata.Type != managementstate.BackupRecoveryPackage || imported.Metadata.TargetID != source.targetID {
		t.Fatalf("imported recovery metadata=%#v", imported.Metadata)
	}
	assertRecoveredState(t, ctx, source, destination)
	assertSecretEquals(t, ctx, destination.state, source.sshSecret, []byte("ssh-private-key-seed"))
	assertSecretEquals(t, ctx, destination.state, source.appSecret, []byte("canonical-module-secret"))
	if err := destination.state.ResolveSecret(ctx, source.patSecret, func(managementstate.SecretMaterial) error { return nil }); err == nil {
		t.Fatal("Custom Module Github PAT was restored without explicit opt-in")
	}

	withPAT, err := source.service.Create(ctx, CreateRequest{TargetID: source.targetID, Passphrase: passphrase, IncludeCustomModulePAT: true})
	if err != nil {
		t.Fatal(err)
	}
	patDestination := newEmptyRecoveryFixture(t)
	if _, err := patDestination.service.Import(ctx, withPAT.Path, passphrase); err != nil {
		t.Fatal(err)
	}
	assertSecretEquals(t, ctx, patDestination.state, source.patSecret, []byte("custom-module-access-token"))
}

func TestRecoveryImportRejectsNonFreshManagementState(t *testing.T) {
	ctx := context.Background()
	source := newRecoveryFixture(t, ctx, false)
	artifact, err := source.service.Create(ctx, CreateRequest{TargetID: source.targetID, Passphrase: []byte("step-eight-recovery-passphrase")})
	if err != nil {
		t.Fatal(err)
	}
	destination := newEmptyRecoveryFixture(t)
	existingTarget, _ := managementstate.NewTargetID()
	if err := destination.state.Change(ctx, func(change *managementstate.Change) error {
		return change.CreateTarget(managementstate.TargetRegistration{ID: existingTarget, Address: "127.0.0.2", SSHUser: "admin"})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := destination.service.Import(ctx, artifact.Path, []byte("step-eight-recovery-passphrase")); err == nil {
		t.Fatal("recovery import merged into non-fresh management state")
	}
	snapshot, err := destination.state.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Targets) != 1 || snapshot.Targets[0].ID != existingTarget {
		t.Fatal("failed recovery import modified pre-existing management state")
	}
}

func newRecoveryFixture(t *testing.T, ctx context.Context, configurePAT bool) *recoveryFixture {
	t.Helper()
	fixture := newEmptyRecoveryFixture(t)
	fixtureFileRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(fixtureFileRoot, "core.conf"), []byte("core-base\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	sha, err := sourcehash.TreeSHA256(fixtureFileRoot)
	if err != nil {
		t.Fatal(err)
	}
	snapshotID, _ := managementstate.NewSourceSnapshotID()
	storageRef := filepath.ToSlash(filepath.Join("snapshots", "sha256", sha))
	snapshotPath := filepath.Join(fixture.sourceRoot, filepath.FromSlash(storageRef))
	if err := os.MkdirAll(snapshotPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapshotPath, "core.conf"), []byte("core-base\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	fixture.targetID, _ = managementstate.NewTargetID()

	if err := fixture.state.Change(ctx, func(change *managementstate.Change) error {
		var err error
		fixture.sshSecret, err = change.CreateSecret("target ssh identity", managementstate.SecretGenerated)
		if err != nil {
			return err
		}
		if err := change.SetSecret(fixture.sshSecret, []byte("ssh-private-key-seed")); err != nil {
			return err
		}
		fixture.appSecret, err = change.CreateSecret("module canonical secret", managementstate.SecretGenerated)
		if err != nil {
			return err
		}
		if err := change.SetSecret(fixture.appSecret, []byte("canonical-module-secret")); err != nil {
			return err
		}
		fixture.patSecret, err = change.CreateSecret("custom module github pat", managementstate.SecretUser)
		if err != nil {
			return err
		}
		if err := change.SetSecret(fixture.patSecret, []byte("custom-module-access-token")); err != nil {
			return err
		}
		if err := change.RegisterSourceArtifact(managementstate.SourceArtifact{ID: snapshotID, Kind: managementstate.SourceCore, Version: "1.0.0", SHA256: sha, StorageRef: storageRef}); err != nil {
			return err
		}
		if configurePAT {
			if err := change.ConfigureCustomModuleGithub(managementstate.CustomModuleGithubConfig{Owner: "example-owner", Repository: "example-modules", Ref: "main", PATSecretID: fixture.patSecret}); err != nil {
				return err
			}
		}
		if err := change.CreateTarget(managementstate.TargetRegistration{ID: fixture.targetID, Address: "192.0.2.10", SSHUser: "admin", SSHIdentitySecretID: fixture.sshSecret}); err != nil {
			return err
		}
		if err := change.SetSSHTrust(fixture.targetID, "ssh-ed25519 AAAATESTHOSTKEY", "SHA256:test-host-fingerprint", managementstate.TrustConfirmed); err != nil {
			return err
		}
		return change.SetDesiredState(fixture.targetID, managementstate.DesiredState{Core: managementstate.CoreDesiredState{SourceID: snapshotID, Version: "1.0.0", Swap: managementstate.SwapDesiredState{Mode: "none"}}})
	}); err != nil {
		t.Fatal(err)
	}
	workspace, err := fixture.sources.CreateWorkspace(ctx, snapshotID)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err = fixture.sources.Apply(ctx, workspace.ID, []sourcelibrary.Edit{{Path: "local.conf", Content: []byte("local-core-change\n"), Mode: 0o600}})
	if err != nil {
		t.Fatal(err)
	}
	fixture.workspaceID = workspace.ID

	bundle, err := fixture.bundles.Assemble(executionbundle.Input{
		Kind:            executionbundle.Installation,
		TargetID:        string(fixture.targetID),
		SubjectKind:     "core",
		SubjectID:       "core",
		SubjectIdentity: "core-1.0.0",
		PackageSHA256:   sha,
		Version:         "1.0.0",
		Sources:         []executionbundle.SourceIdentity{{Kind: "core", ID: string(snapshotID), Version: "1.0.0", PackageSHA256: sha}},
		Files:           []executionbundle.File{{Path: "artifacts/core.conf", TargetPath: "/var/lib/vpsmith/generated/core.conf", Mode: 0o444, Data: []byte("core-base\n")}},
		Preconditions:   []executionbundle.Precondition{{Kind: "target", Subject: string(fixture.targetID), Expected: "present"}},
		ExpectedPost:    map[string]any{"version": "1.0.0"},
		Steps:           []executionbundle.Step{{ID: "apply", Kind: "apply-artifact", Artifact: "artifacts/core.conf", Mutating: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	recordID, _ := managementstate.NewExecutionRecordID()
	if err := fixture.state.Change(ctx, func(change *managementstate.Change) error {
		if err := change.AppendExecutionBundle(managementstate.ExecutionBundleMetadata{ID: managementstate.ExecutionBundleID(bundle.ID), TargetID: fixture.targetID, Kind: string(executionbundle.Installation), Version: "1.0.0", SHA256: bundle.SHA256, CreatedAt: "2026-08-19T00:00:00Z"}); err != nil {
			return err
		}
		return change.AppendExecutionRecord(managementstate.ExecutionRecordMetadata{ID: recordID, BundleID: managementstate.ExecutionBundleID(bundle.ID), TargetID: fixture.targetID, Outcome: "success", StartedAt: "2026-08-19T00:00:00Z", FinishedAt: "2026-08-19T00:00:01Z"})
	}); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func newEmptyRecoveryFixture(t *testing.T) *recoveryFixture {
	t.Helper()
	state, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	sourceRoot := t.TempDir()
	sources, err := sourcelibrary.New(sourceRoot, t.TempDir(), state, rejectingRemote{})
	if err != nil {
		t.Fatal(err)
	}
	bundles, err := executionbundle.NewAssembler(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	backups, err := backuprestore.New(t.TempDir(), t.TempDir(), state)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(state, sources, bundles, backups)
	if err != nil {
		t.Fatal(err)
	}
	return &recoveryFixture{state: state, sources: sources, bundles: bundles, backups: backups, service: service, sourceRoot: sourceRoot}
}

func assertRecoveredState(t *testing.T, ctx context.Context, source, destination *recoveryFixture) {
	t.Helper()
	want, err := source.state.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := destination.state.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(want.Targets) != 1 || len(got.Targets) != 1 {
		t.Fatalf("targets want=%d got=%d", len(want.Targets), len(got.Targets))
	}
	if !reflect.DeepEqual(want.Targets[0], got.Targets[0]) {
		t.Fatalf("target identity/trust/desired state differ after recovery\nwant=%#v\ngot=%#v", want.Targets[0], got.Targets[0])
	}
	if !reflect.DeepEqual(want.ExecutionBundles, got.ExecutionBundles) || !reflect.DeepEqual(want.ExecutionRecords, got.ExecutionRecords) {
		t.Fatal("execution bundle/history metadata differ after recovery")
	}
	if !reflect.DeepEqual(want.Sources, got.Sources) {
		t.Fatal("source identities/workspace metadata differ after recovery")
	}
	var workspace managementstate.SourceWorkspace
	for _, item := range got.Sources.Workspaces {
		if item.ID == source.workspaceID {
			workspace = item
			break
		}
	}
	if workspace.ID == "" {
		t.Fatal("Core workspace was not restored")
	}
	actual, err := sourcehash.TreeSHA256(filepath.Join(destination.sourceRoot, filepath.FromSlash(workspace.StorageRef)))
	if err != nil {
		t.Fatal(err)
	}
	if actual != workspace.CurrentSHA256 {
		t.Fatalf("restored Core workspace sha=%s want=%s", actual, workspace.CurrentSHA256)
	}
	if len(got.Backups) != 1 || got.Backups[0].Type != managementstate.BackupRecoveryPackage {
		t.Fatalf("recovery restored dangling backup catalogue entries: %#v", got.Backups)
	}
}

func assertSecretEquals(t *testing.T, ctx context.Context, state *managementstate.Store, id managementstate.SecretID, want []byte) {
	t.Helper()
	var got []byte
	if err := state.ResolveSecret(ctx, id, func(material managementstate.SecretMaterial) error {
		got = append([]byte(nil), material.Bytes()...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("restored secret value differs")
	}
	for i := range got {
		got[i] = 0
	}
}

func TestRecoveryPayloadDoesNotContainProductStorage(t *testing.T) {
	ctx := context.Background()
	fixture := newRecoveryFixture(t, ctx, false)
	marker := "PRODUCT-STORAGE-MUST-NOT-BE-IN-RECOVERY"
	productStorage := filepath.Join(t.TempDir(), "module-product-data")
	if err := os.WriteFile(productStorage, []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
	artifact, err := fixture.service.Create(ctx, CreateRequest{TargetID: fixture.targetID, Passphrase: []byte("step-eight-recovery-passphrase")})
	if err != nil {
		t.Fatal(err)
	}
	inspection, err := fixture.backups.PrepareRestore(ctx, artifact.Path, managementstate.BackupRecoveryPackage, []byte("step-eight-recovery-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	defer inspection.Close()
	if entries, err := os.ReadDir(inspection.CandidateRoot); err != nil {
		t.Fatal(err)
	} else if len(entries) != 3 {
		t.Fatalf("unexpected recovery payload shape: %d entries", len(entries))
	}
	if err := filepath.WalkDir(inspection.CandidateRoot, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), marker) {
			return errors.New("productive module storage marker leaked into recovery package")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
