package corelifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/execution"
	"github.com/privat655/VPSmith/internal/executionbundle"
	"github.com/privat655/VPSmith/internal/managementstate"
)

type restoreFailureExecutionTarget struct {
	bundle     executionbundle.Bundle
	observeErr error
	failed     bool
}

func (t *restoreFailureExecutionTarget) Upload(_ context.Context, _ string, bundle executionbundle.Bundle) error {
	t.bundle = bundle
	return nil
}
func (*restoreFailureExecutionTarget) Start(context.Context, string, execution.StartRequest) error {
	return nil
}
func (t *restoreFailureExecutionTarget) Observe(_ context.Context, targetID, runID string) (execution.Observation, error) {
	if t.observeErr != nil {
		return execution.Observation{}, t.observeErr
	}
	status := execution.StatusSuccess
	errText := ""
	if t.failed {
		status = execution.StatusFailed
		errText = "restore action failed"
	}
	return execution.Observation{Proof: &execution.Proof{
		RunID: runID, BundleID: t.bundle.ID, BundleSHA256: t.bundle.SHA256, TargetID: targetID,
		Status: status, Phase: "finished", Error: errText,
	}}, nil
}
func (*restoreFailureExecutionTarget) SendSecrets(context.Context, string, string, []execution.SecretValue) error {
	return nil
}

func TestExecuteRestoreDoesNotReconcileSecretsAfterFailedOrUnknownExecution(t *testing.T) {
	for _, tc := range []struct {
		name       string
		failed     bool
		observeErr error
	}{
		{name: "failed proof", failed: true},
		{name: "unknown after start", observeErr: errors.New("ssh disconnected")},
	} {
		t.Run(tc.name, func(t *testing.T) {
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

			current := map[managementstate.SecretID][]byte{}
			if err := lifecycle.state.Change(ctx, func(change *managementstate.Change) error {
				for i, id := range refs.IDs() {
					value := []byte("current-after-backup-" + string(rune('a'+i)))
					if err := change.RotateSecret(id, value); err != nil {
						return err
					}
					current[id] = append([]byte(nil), value...)
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
			target := &restoreFailureExecutionTarget{failed: tc.failed, observeErr: tc.observeErr}
			history := &restoreSuccessHistory{}
			executor, err := execution.New(target, restoreSuccessSecrets{}, history, execution.Options{
				PollInterval: time.Microsecond,
				NewRunID:     func() (string, error) { return "run_restore_failure", nil },
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

			if _, err := lifecycle.ExecuteRestore(ctx, prepared, RestoreExecutionRequest{BackupID: artifact.Metadata.ID, Passphrase: passphrase}); err == nil {
				t.Fatal("failed/unknown restore unexpectedly succeeded")
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
				if !reflect.DeepEqual(got, current[id]) {
					t.Fatalf("secret %s changed after failed/unknown restore: got=%q want=%q", id, got, current[id])
				}
			}
		})
	}
}
