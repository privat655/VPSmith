package corelifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/privat655/VPSmith/internal/backuprestore"
	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/execution"
	"github.com/privat655/VPSmith/internal/executionbundle"
	"github.com/privat655/VPSmith/internal/managementstate"
)

type restoreSuccessExecutionTarget struct {
	bundle executionbundle.Bundle
	starts int
}

func (t *restoreSuccessExecutionTarget) Upload(_ context.Context, _ string, bundle executionbundle.Bundle) error {
	t.bundle = bundle
	return nil
}
func (t *restoreSuccessExecutionTarget) Start(context.Context, string, execution.StartRequest) error {
	t.starts++
	return nil
}
func (t *restoreSuccessExecutionTarget) Observe(_ context.Context, targetID, runID string) (execution.Observation, error) {
	return execution.Observation{Proof: &execution.Proof{
		RunID: runID, BundleID: t.bundle.ID, BundleSHA256: t.bundle.SHA256, TargetID: targetID,
		Status: execution.StatusSuccess, Phase: "finished",
	}}, nil
}
func (*restoreSuccessExecutionTarget) SendSecrets(context.Context, string, string, []execution.SecretValue) error {
	return nil
}

type restoreSuccessSecrets struct{}

func (restoreSuccessSecrets) Resolve(context.Context, string, func([]byte) error) error {
	return errors.New("restore success test bundle has no execution secrets")
}

type restoreSuccessHistory struct{ started, finished int }

func (h *restoreSuccessHistory) RegisterBundle(context.Context, execution.Run) error {
	h.started++
	return nil
}
func (h *restoreSuccessHistory) Finished(context.Context, execution.Run, execution.Proof) error {
	h.finished++
	return nil
}

func TestExecuteRestoreStagesRunsValidatesCleansAndReconcilesHistoricalSecrets(t *testing.T) {
	ctx := context.Background()
	lifecycle, _, storage, targetID, passphrase := newCoreBackupTestLifecycle(t)
	refs, backedUpValues := installRestoreTestSecrets(t, lifecycle, targetID)

	observed := lifecycle.inspector.(coreBackupTestInspector).observed
	storage.archive = coreRestoreSuccessArchive(t, observed, refs, backedUpValues)
	sum := sha256.Sum256(storage.archive)
	storage.sha256 = hex.EncodeToString(sum[:])
	artifact, err := lifecycle.Backup(ctx, BackupRequest{TargetID: targetID, Passphrase: passphrase})
	if err != nil {
		t.Fatal(err)
	}
	storage.calls = nil

	if err := lifecycle.state.Change(ctx, func(change *managementstate.Change) error {
		for i, id := range refs.IDs() {
			if err := change.RotateSecret(id, []byte("post-backup-current-"+string(rune('a'+i)))); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	snapshot, err := lifecycle.state.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	desired := snapshot.Targets[0].Desired.Core
	bundle := restoreSuccessBundle(t, targetID, desired)
	target := &restoreSuccessExecutionTarget{}
	history := &restoreSuccessHistory{}
	executor, err := execution.New(target, restoreSuccessSecrets{}, history, execution.Options{
		PollInterval: time.Microsecond,
		NewRunID: func() (string, error) { return "run_restore_success", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	lifecycle.executor = executor
	prepared := Prepared{
		TargetID:      targetID,
		DesiredCore:   desired,
		PrimaryBefore: observed.Host.PrimaryHardening,
		SwapBefore:    append([]managementstate.SwapDeviceObservedState(nil), observed.Host.SwapDevices...),
		Operation: deployment.PreparedCoreOperation{
			PreparedOperation: deployment.PreparedOperation{Operation: deployment.Restore, Bundle: bundle},
			CoreContract:      desired.CoreContract,
		},
	}

	run, err := lifecycle.ExecuteRestore(ctx, prepared, RestoreExecutionRequest{BackupID: artifact.Metadata.ID, Passphrase: passphrase})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != execution.StatusSuccess || target.starts != 1 || history.started != 1 || history.finished != 1 {
		t.Fatalf("restore execution was not completed exactly once: run=%#v starts=%d history=%d/%d", run, target.starts, history.started, history.finished)
	}
	if want := []string{"stage-restore", "cleanup-restore"}; !reflect.DeepEqual(storage.calls, want) {
		t.Fatalf("restore storage calls=%#v want=%#v", storage.calls, want)
	}
	for _, id := range refs.IDs() {
		var got []byte
		if err := lifecycle.state.ResolveSecret(ctx, id, func(material managementstate.SecretMaterial) error {
			got = material.Bytes()
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, backedUpValues[id]) {
			t.Fatalf("restored secret %s=%q want backed-up value %q", id, got, backedUpValues[id])
		}
	}
}

func installRestoreTestSecrets(t *testing.T, lifecycle *Lifecycle, targetID managementstate.TargetID) (managementstate.CoreSecretReferences, map[managementstate.SecretID][]byte) {
	t.Helper()
	ctx := context.Background()
	snapshot, err := lifecycle.state.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	desired := snapshot.Targets[0].Desired
	var refs managementstate.CoreSecretReferences
	values := map[managementstate.SecretID][]byte{}
	if err := lifecycle.state.Change(ctx, func(change *managementstate.Change) error {
		created := make([]managementstate.SecretID, 4)
		for i := range created {
			id, err := change.CreateSecret("Core restore test secret "+string(rune('a'+i)), managementstate.SecretGenerated)
			if err != nil {
				return err
			}
			value := []byte("backed-up-secret-value-" + string(rune('a'+i)))
			if err := change.SetSecret(id, value); err != nil {
				return err
			}
			created[i] = id
			values[id] = append([]byte(nil), value...)
		}
		refs = managementstate.CoreSecretReferences{
			AutheliaSession: created[0], AutheliaStorage: created[1], AutheliaResetPassword: created[2], AutheliaUsersDatabase: created[3],
		}
		desired.Core.Secrets = refs
		return change.SetDesiredState(targetID, desired)
	}); err != nil {
		t.Fatal(err)
	}
	return refs, values
}

func coreRestoreSuccessArchive(t *testing.T, observed managementstate.ObservedState, refs managementstate.CoreSecretReferences, values map[managementstate.SecretID][]byte) []byte {
	t.Helper()
	root := t.TempDir()
	lock := coreBackupImageLocks{
		SourceID: observed.Core.SourceID, Version: observed.Core.Version, PackageSHA256: observed.Core.PackageSHA256,
		Images: map[string]coreBackupImage{
			"caddy":    {Ref: "docker.io/library/caddy:2.11.4-alpine", Digest: "sha256:" + strings.Repeat("b", 64)},
			"authelia": {Ref: "docker.io/authelia/authelia:4.39.20", Digest: "sha256:" + strings.Repeat("c", 64)},
		},
	}
	lockBytes, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"var/lib/vpsmith/core/desired.json":                lockBytes,
		"var/lib/vpsmith/core/authelia/data/state.db":      []byte("historical-authelia-state"),
		"var/lib/vpsmith/inventory/core.json":              []byte("{}\n"),
		"var/lib/vpsmith/execution/core/historical-proof":  []byte("{}\n"),
	}
	for _, id := range refs.IDs() {
		files["var/lib/vpsmith/secrets/core/"+string(id)] = values[id]
	}
	for path, content := range files {
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	archivePath := filepath.Join(t.TempDir(), "core-restore-storage.tar.zst")
	if err := backuprestore.CreateTarZst(root, archivePath); err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	return archive
}

func restoreSuccessBundle(t *testing.T, targetID managementstate.TargetID, desired managementstate.CoreDesiredState) executionbundle.Bundle {
	t.Helper()
	assembler, err := executionbundle.NewAssembler(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := assembler.Assemble(executionbundle.Input{
		Kind:            executionbundle.Migration,
		TargetID:        string(targetID),
		SubjectKind:     "core",
		SubjectID:       "core",
		SubjectIdentity: string(desired.SourceID),
		PackageSHA256:   strings.Repeat("a", 64),
		Version:         desired.Version,
		Images: []executionbundle.ImageIdentity{
			{Name: "caddy", Ref: "docker.io/library/caddy:2.11.4-alpine", Digest: "sha256:" + strings.Repeat("b", 64)},
			{Name: "authelia", Ref: "docker.io/authelia/authelia:4.39.20", Digest: "sha256:" + strings.Repeat("c", 64)},
		},
		Preconditions: []executionbundle.Precondition{{Kind: "target", Subject: string(targetID), Expected: "same-target"}},
		ExpectedPost:  map[string]any{"artifacts": map[string]string{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}
