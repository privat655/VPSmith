package corelifecycle

import (
	"context"
	"errors"
	"reflect"

	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/managementstate"
)

type PreviousCoreRestoreRequest struct {
	TargetID         managementstate.TargetID
	Previous         PreviousCoreState
	BackupPassphrase []byte
}

// PreparePreviousCoreRestore is the visible recovery plan for the exact Core
// state captured immediately before a Core update. It re-verifies the previous
// state against the immutable backup catalogue and then delegates to the same
// canonical Core restore preparation path used by explicit backup restore.
func (l *Lifecycle) PreparePreviousCoreRestore(ctx context.Context, req PreviousCoreRestoreRequest) (Prepared, error) {
	if req.TargetID == "" || req.Previous.BackupID == "" || len(req.BackupPassphrase) == 0 {
		return Prepared{}, errors.New("previous Core restore requires target, immediate backup, and recovery passphrase")
	}
	verified, err := l.previousCoreStateFromBackup(ctx, req.Previous.BackupID, req.TargetID, req.BackupPassphrase)
	if err != nil {
		return Prepared{}, err
	}
	if !reflect.DeepEqual(verified, req.Previous) {
		return Prepared{}, errors.New("previous Core state no longer matches the immediate update backup")
	}
	prepared, err := l.PrepareRestore(ctx, PrepareRequest{
		TargetID:         req.TargetID,
		BackupID:         req.Previous.BackupID,
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
