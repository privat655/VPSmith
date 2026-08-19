package corelifecycle

import (
	"context"
	"errors"
	"fmt"

	"github.com/privat655/VPSmith/internal/backuprestore"
	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/execution"
	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/sourcelibrary"
	"github.com/privat655/VPSmith/internal/targetgateway"
)

type Sources interface {
	CurrentEmbedded(context.Context, managementstate.SourceKind) (sourcelibrary.FrozenSnapshot, error)
}

type Inspector interface {
	Inspect(context.Context, managementstate.TargetID) (managementstate.ObservedState, error)
}

type Compiler interface {
	PrepareCore(context.Context, deployment.CoreRequest) (deployment.PreparedOperation, error)
}

type Lifecycle struct {
	state     *managementstate.Store
	sources   Sources
	inspector Inspector
	compiler  Compiler
	executor  *execution.Executor
	backups   *backuprestore.Manager
	storage   *targetgateway.StorageBackupTarget
}

type PrepareRequest struct {
	TargetID       managementstate.TargetID
	SourceID       managementstate.SourceSnapshotID
	Swap           managementstate.SwapDesiredState
	BackupVerified bool
}

type BackupRequest struct {
	TargetID   managementstate.TargetID
	Passphrase []byte
}

type Prepared struct {
	Operation deployment.PreparedOperation
}

type ReconcileRequest struct {
	TargetID     managementstate.TargetID
	RunID        string
	BundleID     string
	BundleSHA256 string
}

func New(state *managementstate.Store, sources Sources, inspector Inspector, compiler Compiler, executor *execution.Executor, backups *backuprestore.Manager, storage *targetgateway.StorageBackupTarget) (*Lifecycle, error) {
	if state == nil || sources == nil || inspector == nil || compiler == nil || executor == nil || backups == nil || storage == nil {
		return nil, errors.New("complete Core lifecycle dependencies are required")
	}
	return &Lifecycle{state: state, sources: sources, inspector: inspector, compiler: compiler, executor: executor, backups: backups, storage: storage}, nil
}

func (l *Lifecycle) PrepareInstall(ctx context.Context, req PrepareRequest) (Prepared, error) {
	return l.prepare(ctx, deployment.Install, req)
}
func (l *Lifecycle) PrepareUpdate(ctx context.Context, req PrepareRequest) (Prepared, error) {
	return l.prepare(ctx, deployment.Update, req)
}
func (l *Lifecycle) PrepareSwapChange(ctx context.Context, req PrepareRequest) (Prepared, error) {
	return l.prepare(ctx, deployment.Reconfigure, req)
}
func (l *Lifecycle) PrepareRestore(ctx context.Context, req PrepareRequest) (Prepared, error) {
	return l.prepare(ctx, deployment.Restore, req)
}
func (l *Lifecycle) PrepareValidation(ctx context.Context, req PrepareRequest) (Prepared, error) {
	return l.prepare(ctx, deployment.Validate, req)
}

func (l *Lifecycle) Execute(ctx context.Context, prepared Prepared) (execution.Run, error) {
	if prepared.Operation.Bundle.ID == "" {
		return execution.Run{}, errors.New("prepared Core operation is required")
	}
	return l.executor.Execute(ctx, prepared.Operation.Bundle.Manifest.TargetID, prepared.Operation.Bundle)
}

func (l *Lifecycle) Reconcile(ctx context.Context, req ReconcileRequest) (execution.Run, error) {
	return l.executor.Reconcile(ctx, string(req.TargetID), req.RunID, req.BundleID, req.BundleSHA256)
}

func (l *Lifecycle) Diagnose(ctx context.Context, targetID managementstate.TargetID) (managementstate.ObservedState, error) {
	return l.inspector.Inspect(ctx, targetID)
}

func (l *Lifecycle) Backup(ctx context.Context, req BackupRequest) (backuprestore.Artifact, error) {
	observed, err := l.inspector.Inspect(ctx, req.TargetID)
	if err != nil {
		return backuprestore.Artifact{}, err
	}
	if !observed.Core.Present {
		return backuprestore.Artifact{}, errors.New("Core backup requires an installed Core")
	}
	paths := []string{"/var/lib/vpsmith/core", "/var/lib/vpsmith/inventory", "/var/lib/vpsmith/execution"}
	copy, err := l.backups.CopyOfflineStorage(ctx, l.storage, string(req.TargetID), paths)
	if err != nil {
		return backuprestore.Artifact{}, err
	}
	defer copy.Close()
	producer := corePayloadProducer{copy: copy, observed: observed}
	artifact, err := l.backups.Create(ctx, backuprestore.CreateRequest{Type: managementstate.BackupCore, TargetID: req.TargetID, Passphrase: req.Passphrase, Producer: producer})
	if err != nil {
		return backuprestore.Artifact{}, err
	}
	if err := l.backups.FinalizeStorageCopy(ctx, l.storage, &copy); err != nil {
		return backuprestore.Artifact{}, fmt.Errorf("Core backup persisted but target temporary copy cleanup failed: %w", err)
	}
	return artifact, nil
}

func (l *Lifecycle) prepare(ctx context.Context, kind deployment.OperationKind, req PrepareRequest) (Prepared, error) {
	if req.TargetID == "" {
		return Prepared{}, errors.New("target id is required")
	}
	observed, err := l.inspector.Inspect(ctx, req.TargetID)
	if err != nil {
		return Prepared{}, err
	}
	if err := requirePrimary(observed); err != nil {
		return Prepared{}, err
	}
	if kind == deployment.Install && observed.Core.Present {
		return Prepared{}, errors.New("Core is already installed")
	}
	if kind != deployment.Install && !observed.Core.Present {
		return Prepared{}, errors.New("Core is not installed")
	}
	if kind == deployment.Update && !req.BackupVerified {
		return Prepared{}, errors.New("Core update requires a successful verified Core backup")
	}
	source, err := l.sources.CurrentEmbedded(ctx, managementstate.SourceCore)
	if err != nil {
		return Prepared{}, err
	}
	if req.SourceID != "" && source.ID != req.SourceID {
		return Prepared{}, errors.New("requested Core source is not the frozen candidate")
	}
	coreReq := deployment.CoreRequest{
		Operation: kind, TargetID: string(req.TargetID),
		Source: deployment.FrozenCoreSource{SourceID: string(source.ID), Version: source.Version, GitCommit: source.Commit, PackageSHA256: source.SHA256, PackageFS: source.FS},
		SwapMode: req.Swap.Mode, SwapSizeGiB: req.Swap.SizeGiB, BackupRequired: kind == deployment.Update,
	}
	if observed.Core.Present {
		coreReq.ObservedCoreID = string(observed.Core.SourceID)
	}
	op, err := l.compiler.PrepareCore(ctx, coreReq)
	if err != nil {
		return Prepared{}, err
	}
	return Prepared{Operation: op}, nil
}

func requirePrimary(observed managementstate.ObservedState) error {
	f := observed.Host.PrimaryHardening
	if !observed.Host.Reachable || !observed.Host.SSH || !observed.CloudInit.Present || observed.CloudInit.Status != "ok" {
		return errors.New("successful Cloud-init and SSH are required")
	}
	if !f.RootPasswordLocked || !f.SSHConfigValid || !f.UFWActive || f.UFWUnexpectedPublicAllow || !f.Fail2banSSHActive || !f.Fail2banRecidiveActive {
		return errors.New("Primary Host Hardening is not effective")
	}
	return nil
}

type corePayloadProducer struct {
	copy     backuprestore.StorageCopy
	observed managementstate.ObservedState
}

func (p corePayloadProducer) Produce(ctx context.Context, root string) (backuprestore.PayloadDescriptor, error) {
	if err := ctx.Err(); err != nil {
		return backuprestore.PayloadDescriptor{}, err
	}
	if err := backuprestore.ExtractTarZst(p.copy.ArchivePath, root, backuprestore.ArchiveOptions{}); err != nil {
		return backuprestore.PayloadDescriptor{}, err
	}
	identity := &backuprestore.ArtifactIdentity{SubjectKind: "core", SubjectID: string(p.observed.Core.SourceID), Version: p.observed.Core.Version, PackageSHA256: p.observed.Core.PackageSHA256, StoragePaths: append([]string(nil), p.copy.DeclaredPath...)}
	return backuprestore.PayloadDescriptor{Identity: identity}, nil
}
