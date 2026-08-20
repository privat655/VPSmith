package corelifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"

	"github.com/privat655/VPSmith/internal/backuprestore"
	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/execution"
	"github.com/privat655/VPSmith/internal/managementstate"
)

type CoreRestoreStorage interface {
	StageCoreRestorePayload(context.Context, string, string, io.Reader, string, int64) error
	CleanupCoreRestorePayload(context.Context, string, string) error
}

type RestoreExecutionRequest struct {
	BackupID   managementstate.BackupArtifactID
	Passphrase []byte
}

// ExecuteRestore is the only complete Core restore execution path. It reopens
// the approved catalogued backup after plan approval, verifies that those exact
// bytes still match the prepared Core identity and image locks, streams the
// verified payload through the existing strict-SSH target adapter, and then
// executes the already compiled immutable restore bundle.
func (l *Lifecycle) ExecuteRestore(ctx context.Context, prepared Prepared, req RestoreExecutionRequest) (execution.Run, error) {
	if l == nil || l.backups == nil || l.storage == nil || l.executor == nil {
		return execution.Run{}, errors.New("complete Core restore lifecycle is required")
	}
	if prepared.Operation.Operation != deployment.Restore || prepared.TargetID == "" || prepared.Operation.Bundle.ID == "" {
		return execution.Run{}, errors.New("prepared Core restore operation is required")
	}
	if req.BackupID == "" || len(req.Passphrase) == 0 {
		return execution.Run{}, errors.New("Core restore requires the approved backup and recovery passphrase")
	}
	storage, ok := l.storage.(CoreRestoreStorage)
	if !ok {
		return execution.Run{}, errors.New("target storage does not support Core restore staging")
	}

	restore, err := l.backups.PrepareRestoreArtifact(ctx, req.BackupID, managementstate.BackupCore, req.Passphrase)
	if err != nil {
		return execution.Run{}, fmt.Errorf("prepare Core restore payload: %w", err)
	}
	defer restore.Close()
	if err := validatePreparedRestoreArtifact(prepared, req.BackupID, restore); err != nil {
		return execution.Run{}, err
	}

	payload, err := os.Open(restore.PayloadPath)
	if err != nil {
		return execution.Run{}, fmt.Errorf("open verified Core restore payload: %w", err)
	}
	stageErr := storage.StageCoreRestorePayload(ctx, string(prepared.TargetID), prepared.Operation.Bundle.ID, payload, restore.PayloadSHA256, restore.PayloadSize)
	closeErr := payload.Close()
	if stageErr != nil || closeErr != nil {
		cleanupErr := storage.CleanupCoreRestorePayload(context.WithoutCancel(ctx), string(prepared.TargetID), prepared.Operation.Bundle.ID)
		return execution.Run{}, errors.Join(stageErr, closeErr, cleanupErr)
	}

	run, executeErr := l.Execute(ctx, prepared)
	cleanupErr := storage.CleanupCoreRestorePayload(context.WithoutCancel(ctx), string(prepared.TargetID), prepared.Operation.Bundle.ID)
	if executeErr != nil || cleanupErr != nil {
		return run, errors.Join(executeErr, cleanupErr)
	}
	return run, nil
}

func validatePreparedRestoreArtifact(prepared Prepared, backupID managementstate.BackupArtifactID, restore *backuprestore.CataloguedRestore) error {
	if restore == nil || restore.Manifest.ArtifactID != backupID || restore.Manifest.TargetID != prepared.TargetID || restore.Manifest.Identity == nil {
		return errors.New("Core restore backup no longer matches the approved plan")
	}
	identity := restore.Manifest.Identity
	if identity.SubjectKind != "core" || identity.SubjectID != string(prepared.DesiredCore.SourceID) || identity.Version != prepared.DesiredCore.Version || identity.PackageSHA256 != prepared.Operation.Bundle.Manifest.PackageSHA256 {
		return errors.New("Core restore backup exact identity no longer matches the approved plan")
	}

	desiredBytes, err := os.ReadFile(filepath.Join(restore.CandidateRoot, "management", "core-desired.json"))
	if err != nil {
		return fmt.Errorf("read approved Core restore desired state: %w", err)
	}
	var desired managementstate.CoreDesiredState
	if err := json.Unmarshal(desiredBytes, &desired); err != nil {
		return fmt.Errorf("decode approved Core restore desired state: %w", err)
	}
	if !reflect.DeepEqual(desired, prepared.DesiredCore) {
		return errors.New("Core restore desired state no longer matches the approved plan")
	}

	lockBytes, err := os.ReadFile(filepath.Join(restore.CandidateRoot, filepath.FromSlash(coreBackupImageLocksRef)))
	if err != nil {
		return fmt.Errorf("read approved Core restore image locks: %w", err)
	}
	var locks coreBackupImageLocks
	if err := json.Unmarshal(lockBytes, &locks); err != nil {
		return fmt.Errorf("decode approved Core restore image locks: %w", err)
	}
	bundleImages := make(map[string]coreBackupImage, len(prepared.Operation.Bundle.Manifest.Images))
	for _, image := range prepared.Operation.Bundle.Manifest.Images {
		bundleImages[image.Name] = coreBackupImage{Ref: image.Ref, Digest: image.Digest}
	}
	if len(locks.Images) != 2 || len(bundleImages) != 2 {
		return errors.New("Core restore image lock set no longer matches the approved plan")
	}
	for _, name := range []string{"caddy", "authelia"} {
		if locks.Images[name] != bundleImages[name] {
			return fmt.Errorf("Core restore %s image identity no longer matches the approved plan", name)
		}
	}
	return nil
}
