package corelifecycle

import (
	"context"
	"errors"
	"fmt"

	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/managementstate"
)

type PreviousCoreRestoreRequest struct {
	TargetID         managementstate.TargetID
	BackupPassphrase []byte
}

// PreparePreviousCoreRestore is the visible recovery plan for the exact Core
// state captured immediately before the latest terminal Core update attempt.
// The restore point is resolved from immutable local execution history; callers
// cannot substitute an arbitrary historical Core backup.
func (l *Lifecycle) PreparePreviousCoreRestore(ctx context.Context, req PreviousCoreRestoreRequest) (Prepared, error) {
	if req.TargetID == "" || len(req.BackupPassphrase) == 0 {
		return Prepared{}, errors.New("previous Core restore requires target and recovery passphrase")
	}
	if l == nil || l.state == nil || l.backups == nil {
		return Prepared{}, errors.New("complete Core lifecycle is required")
	}
	snapshot, err := l.state.Snapshot(ctx)
	if err != nil {
		return Prepared{}, fmt.Errorf("read previous Core update history: %w", err)
	}
	backupID, err := previousCoreBackupFromHistory(snapshot, req.TargetID)
	if err != nil {
		return Prepared{}, err
	}
	verified, err := l.previousCoreStateFromBackup(ctx, backupID, req.TargetID, req.BackupPassphrase)
	if err != nil {
		return Prepared{}, fmt.Errorf("verify immediately previous Core backup: %w", err)
	}
	prepared, err := l.PrepareRestore(ctx, PrepareRequest{
		TargetID:         req.TargetID,
		BackupID:         backupID,
		BackupPassphrase: req.BackupPassphrase,
	})
	if err != nil {
		return Prepared{}, err
	}
	if prepared.Operation.Operation != deployment.Restore || prepared.DesiredCore.SourceID != verified.SourceID || prepared.DesiredCore.Version != verified.Version || prepared.Operation.Bundle.Manifest.PackageSHA256 != verified.PackageSHA256 {
		return Prepared{}, errors.New("previous Core restore plan lost exact backed-up identity")
	}
	return prepared, nil
}

func previousCoreBackupFromHistory(snapshot managementstate.Snapshot, targetID managementstate.TargetID) (managementstate.BackupArtifactID, error) {
	validBackups := make(map[managementstate.BackupArtifactID]struct{})
	for _, backup := range snapshot.Backups {
		if backup.TargetID == targetID && backup.Type == managementstate.BackupCore {
			validBackups[backup.ID] = struct{}{}
		}
	}

	type candidate struct {
		bundleID  managementstate.ExecutionBundleID
		backupID  managementstate.BackupArtifactID
		eventTime string
		terminal  bool
	}
	var latest *candidate
	for _, bundle := range snapshot.ExecutionBundles {
		if bundle.TargetID != targetID || bundle.BackupRef == "" {
			continue
		}
		if _, ok := validBackups[bundle.BackupRef]; !ok {
			continue
		}
		if bundle.CreatedAt == "" {
			return "", fmt.Errorf("Core update bundle %s has incomplete local history", bundle.ID)
		}
		current := candidate{bundleID: bundle.ID, backupID: bundle.BackupRef, eventTime: bundle.CreatedAt}
		for _, record := range snapshot.ExecutionRecords {
			if record.TargetID != targetID || record.BundleID != bundle.ID {
				continue
			}
			if record.Outcome != "success" && record.Outcome != "failed" {
				return "", fmt.Errorf("Core update bundle %s has non-terminal local history; reconcile before restore", bundle.ID)
			}
			when := record.FinishedAt
			if when == "" {
				when = record.StartedAt
			}
			if when == "" {
				return "", fmt.Errorf("Core update bundle %s has incomplete terminal history", bundle.ID)
			}
			if when >= current.eventTime {
				current.eventTime = when
				current.terminal = true
			}
		}
		if latest == nil || current.eventTime > latest.eventTime {
			copy := current
			latest = &copy
		} else if current.eventTime == latest.eventTime && current.bundleID != latest.bundleID {
			return "", errors.New("ambiguous latest Core update history blocks previous-state restore")
		}
	}
	if latest == nil {
		return "", errors.New("no terminal Core update with an immediate backup is available")
	}
	if !latest.terminal {
		return "", fmt.Errorf("latest Core update %s has no terminal proof; reconcile before restore", latest.bundleID)
	}
	return latest.backupID, nil
}
