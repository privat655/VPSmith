package corelifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/privat655/VPSmith/internal/backuprestore"
	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/execution"
	"github.com/privat655/VPSmith/internal/managementstate"
)

func TestExecuteRestoreCommitsNoLocalStateWhenBackedUpSecretReconciliationFails(t *testing.T) {
	ctx := context.Background()
	lifecycle, _, storage, targetID, passphrase := newCoreBackupTestLifecycle(t)
	refs, backedUpValues := installRestoreTestSecrets(t, lifecycle, targetID)
	observed := lifecycle.inspector.(coreBackupTestInspector).observed
	storage.archive = coreRestoreArchiveWithoutSecret(t, observed, refs, backedUpValues, refs.IDs()[0])
	sum := sha256.Sum256(storage.archive)
	storage.sha256 = hex.EncodeToString(sum[:])
	artifact, err := lifecycle.Backup(ctx, BackupRequest{TargetID: targetID, Passphrase: passphrase})
	if err != nil {
		t.Fatal(err)
	}
	storage.calls = nil

	if err := lifecycle.state.Change(ctx, func(change *managementstate.Change) error {
		for i, id := range refs.IDs() {
			if err := change.RotateSecret(id, []byte("current-before-atomic-restore-"+string(rune('a'+i)))); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before, err := lifecycle.state.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}

	desired := before.Targets[0].Desired.Core
	bundle := restoreSuccessBundle(t, targetID, desired)
	target := &restoreSuccessExecutionTarget{}
	executor, err := execution.New(target, restoreSuccessSecrets{}, &restoreSuccessHistory{}, execution.Options{
		PollInterval: time.Microsecond,
		NewRunID:     func() (string, error) { return "run_restore_atomic", nil },
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

	_, err = lifecycle.ExecuteRestore(ctx, prepared, RestoreExecutionRequest{BackupID: artifact.Metadata.ID, Passphrase: passphrase})
	if err == nil || !strings.Contains(err.Error(), "read restored Core secret") {
		t.Fatalf("restore with incomplete backed-up secret set error=%v", err)
	}
	after, err := lifecycle.state.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	beforeTarget, err := targetFromSnapshot(before, targetID)
	if err != nil {
		t.Fatal(err)
	}
	afterTarget, err := targetFromSnapshot(after, targetID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(afterTarget.Desired, beforeTarget.Desired) || !reflect.DeepEqual(afterTarget.Observed, beforeTarget.Observed) {
		t.Fatalf("failed local restore reconciliation partially committed Management State: before=%#v after=%#v", beforeTarget, afterTarget)
	}
}

func coreRestoreArchiveWithoutSecret(t *testing.T, observed managementstate.ObservedState, refs managementstate.CoreSecretReferences, values map[managementstate.SecretID][]byte, missing managementstate.SecretID) []byte {
	t.Helper()
	original := coreRestoreSuccessArchive(t, observed, refs, values)
	input := filepath.Join(t.TempDir(), "input.tar.zst")
	if err := os.WriteFile(input, original, 0o600); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := backuprestore.ExtractTarZst(input, root, backuprestore.ArchiveOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "var", "lib", "vpsmith", "secrets", "core", string(missing))); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "without-secret.tar.zst")
	if err := backuprestore.CreateTarZst(root, output); err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	return archive
}
