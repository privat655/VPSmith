package managementstate

import (
	"context"
	"testing"
)

func TestRecoveryPreservesExecutionBundleBackupReference(t *testing.T) {
	ctx := context.Background()
	source, err := NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = source.Close() })
	const targetID TargetID = "target_recovery_backup_ref"
	const backupID BackupArtifactID = "backup_core_immediate"
	if err := source.Change(ctx, func(change *Change) error {
		if err := change.CreateTarget(TargetRegistration{ID: targetID, Address: "203.0.113.10", SSHUser: "dev", SSHTrust: TrustConfirmed}); err != nil {
			return err
		}
		if err := change.RegisterBackup(BackupArtifactMetadata{ID: backupID, Type: BackupCore, TargetID: targetID}); err != nil {
			return err
		}
		return change.AppendExecutionBundle(ExecutionBundleMetadata{
			ID: "bundle_update", TargetID: targetID, Kind: "migration", Version: "2.0.0",
			SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", BackupRef: backupID,
		})
	}); err != nil {
		t.Fatal(err)
	}

	recovery, err := source.ExportRecovery(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	defer recovery.Zero()

	destination, err := NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = destination.Close() })
	if err := destination.ReplaceFromRecovery(ctx, recovery, BackupArtifactMetadata{
		ID: "backup_recovery_import", Type: BackupRecoveryPackage, TargetID: targetID,
	}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := destination.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.ExecutionBundles) != 1 || snapshot.ExecutionBundles[0].BackupRef != backupID {
		t.Fatalf("recovered execution bundles=%#v", snapshot.ExecutionBundles)
	}
}
