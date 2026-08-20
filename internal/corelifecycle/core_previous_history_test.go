package corelifecycle

import (
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/managementstate"
)

func TestPreviousCoreBackupFromHistoryUsesLatestTerminalCoreUpdate(t *testing.T) {
	targetID := managementstate.TargetID("target_history")
	snapshot := managementstate.Snapshot{
		Backups: []managementstate.BackupArtifactMetadata{
			{ID: "backup_old", Type: managementstate.BackupCore, TargetID: targetID},
			{ID: "backup_latest", Type: managementstate.BackupCore, TargetID: targetID},
			{ID: "backup_unbound", Type: managementstate.BackupCore, TargetID: targetID},
		},
		ExecutionBundles: []managementstate.ExecutionBundleMetadata{
			{ID: "bundle_old", TargetID: targetID, BackupRef: "backup_old", CreatedAt: "2026-08-20T10:00:00Z"},
			{ID: "bundle_latest", TargetID: targetID, BackupRef: "backup_latest", CreatedAt: "2026-08-20T11:00:00Z"},
		},
		ExecutionRecords: []managementstate.ExecutionRecordMetadata{
			{ID: "run_old", BundleID: "bundle_old", TargetID: targetID, Outcome: "success", StartedAt: "2026-08-20T10:00:01Z", FinishedAt: "2026-08-20T10:00:10Z"},
			{ID: "run_latest", BundleID: "bundle_latest", TargetID: targetID, Outcome: "failed", StartedAt: "2026-08-20T11:00:01Z", FinishedAt: "2026-08-20T11:00:10Z"},
		},
	}

	got, err := previousCoreBackupFromHistory(snapshot, targetID)
	if err != nil {
		t.Fatal(err)
	}
	if got != "backup_latest" {
		t.Fatalf("previous Core backup=%q want backup_latest", got)
	}
}

func TestPreviousCoreBackupFromHistoryBlocksLatestUnknownUpdate(t *testing.T) {
	targetID := managementstate.TargetID("target_history")
	snapshot := managementstate.Snapshot{
		Backups: []managementstate.BackupArtifactMetadata{
			{ID: "backup_complete", Type: managementstate.BackupCore, TargetID: targetID},
			{ID: "backup_unknown", Type: managementstate.BackupCore, TargetID: targetID},
		},
		ExecutionBundles: []managementstate.ExecutionBundleMetadata{
			{ID: "bundle_complete", TargetID: targetID, BackupRef: "backup_complete", CreatedAt: "2026-08-20T10:00:00Z"},
			{ID: "bundle_unknown", TargetID: targetID, BackupRef: "backup_unknown", CreatedAt: "2026-08-20T11:00:00Z"},
		},
		ExecutionRecords: []managementstate.ExecutionRecordMetadata{
			{ID: "run_complete", BundleID: "bundle_complete", TargetID: targetID, Outcome: "success", StartedAt: "2026-08-20T10:00:01Z", FinishedAt: "2026-08-20T10:00:10Z"},
		},
	}

	_, err := previousCoreBackupFromHistory(snapshot, targetID)
	if err == nil || !strings.Contains(err.Error(), "reconcile") {
		t.Fatalf("unknown latest Core update error=%v", err)
	}
}

func TestPreviousCoreBackupFromHistoryIgnoresUnboundAndWrongTargetBackups(t *testing.T) {
	targetID := managementstate.TargetID("target_history")
	snapshot := managementstate.Snapshot{
		Backups: []managementstate.BackupArtifactMetadata{
			{ID: "backup_unbound", Type: managementstate.BackupCore, TargetID: targetID},
			{ID: "backup_other", Type: managementstate.BackupCore, TargetID: "target_other"},
		},
		ExecutionBundles: []managementstate.ExecutionBundleMetadata{
			{ID: "bundle_other", TargetID: targetID, BackupRef: "backup_other", CreatedAt: "2026-08-20T11:00:00Z"},
		},
	}

	_, err := previousCoreBackupFromHistory(snapshot, targetID)
	if err == nil || !strings.Contains(err.Error(), "no terminal Core update") {
		t.Fatalf("unbound/wrong-target backup error=%v", err)
	}
}
