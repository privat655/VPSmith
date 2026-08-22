package corelifecycle

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/execution"
)

func (s *coreBackupTestStorage) StageCoreRestorePayload(_ context.Context, _ string, _ string, input io.Reader, _ string, _ int64) error {
	s.calls = append(s.calls, "stage-restore")
	_, err := io.Copy(io.Discard, input)
	return err
}

func (s *coreBackupTestStorage) CleanupCoreRestorePayload(context.Context, string, string) error {
	s.calls = append(s.calls, "cleanup-restore")
	return nil
}

func TestExecuteRestoreWrongPassphraseBlocksBeforeTargetMutation(t *testing.T) {
	ctx := context.Background()
	lifecycle, _, storage, targetID, passphrase := newCoreBackupTestLifecycle(t)
	artifact, err := lifecycle.Backup(ctx, BackupRequest{TargetID: targetID, Passphrase: passphrase})
	if err != nil {
		t.Fatal(err)
	}
	storage.calls = nil
	lifecycle.executor = &execution.Executor{}
	prepared := Prepared{
		TargetID:  targetID,
		Operation: deployment.PreparedCoreOperation{PreparedOperation: deployment.PreparedOperation{Operation: deployment.Restore}},
	}
	prepared.Operation.Bundle.ID = "bundle_restore_test"

	_, err = lifecycle.ExecuteRestore(ctx, prepared, RestoreExecutionRequest{BackupID: artifact.Metadata.ID, Passphrase: []byte("wrong-passphrase")})
	if err == nil || !strings.Contains(err.Error(), "prepare Core restore payload") {
		t.Fatalf("wrong restore passphrase error=%v", err)
	}
	if len(storage.calls) != 0 {
		t.Fatalf("wrong passphrase mutated target through calls=%#v", storage.calls)
	}
}
