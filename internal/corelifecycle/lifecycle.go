package corelifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/privat655/VPSmith/internal/backuprestore"
	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/execution"
	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/sourcelibrary"
	"github.com/privat655/VPSmith/internal/targetgateway"
)

const maxAutoSwapBytes int64 = 4 << 30

type Sources interface {
	FreezeCoreCandidate(context.Context, sourcelibrary.CoreCandidateRef) (sourcelibrary.FrozenSnapshot, error)
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
	TargetID         managementstate.TargetID
	Candidate        sourcelibrary.CoreCandidateRef
	Swap             managementstate.SwapDesiredState
	BackupID         managementstate.BackupArtifactID
	BackupPassphrase []byte
}

type BackupRequest struct {
	TargetID   managementstate.TargetID
	Passphrase []byte
}

type Prepared struct {
	Operation     deployment.PreparedOperation
	TargetID      managementstate.TargetID
	DesiredCore   managementstate.CoreDesiredState
	PrimaryBefore managementstate.PrimaryHardeningObservedState
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
	return &Lifecycle{
		state:     state,
		sources:   sources,
		inspector: inspector,
		compiler:  compiler,
		executor:  executor,
		backups:   backups,
		storage:   storage,
	}, nil
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

// Execute is the only Core mutation entry point. A successful target runner is
// not enough: the lifecycle inspects the real target again and commits desired
// and observed state only after the complete Core postconditions hold.
func (l *Lifecycle) Execute(ctx context.Context, prepared Prepared) (execution.Run, error) {
	if prepared.TargetID == "" || prepared.Operation.Bundle.ID == "" {
		return execution.Run{}, errors.New("prepared Core operation is required")
	}
	run, err := l.executor.Execute(ctx, string(prepared.TargetID), prepared.Operation.Bundle)
	if err != nil {
		return run, err
	}
	observed, err := l.inspector.Inspect(ctx, prepared.TargetID)
	if err != nil {
		return run, fmt.Errorf("inspect Core after execution: %w", err)
	}
	if err := validatePostState(prepared, observed); err != nil {
		return run, fmt.Errorf("Core post-validation failed: %w", err)
	}
	snapshot, err := l.state.Snapshot(ctx)
	if err != nil {
		return run, fmt.Errorf("read Management State after Core validation: %w", err)
	}
	target, err := targetFromSnapshot(snapshot, prepared.TargetID)
	if err != nil {
		return run, err
	}
	desired := target.Desired
	if err := l.state.Change(ctx, func(change *managementstate.Change) error {
		if prepared.Operation.Operation != deployment.Validate {
			desired.Core = prepared.DesiredCore
			if err := change.SetDesiredState(prepared.TargetID, desired); err != nil {
				return err
			}
		}
		return change.RecordObservedState(prepared.TargetID, observed)
	}); err != nil {
		return run, fmt.Errorf("commit Core lifecycle state: %w", err)
	}
	return run, nil
}

func (l *Lifecycle) Reconcile(ctx context.Context, req ReconcileRequest) (execution.Run, error) {
	return l.executor.Reconcile(ctx, string(req.TargetID), req.RunID, req.BundleID, req.BundleSHA256)
}

func (l *Lifecycle) Diagnose(ctx context.Context, targetID managementstate.TargetID) (managementstate.ObservedState, error) {
	if targetID == "" {
		return managementstate.ObservedState{}, errors.New("target id is required")
	}
	return l.inspector.Inspect(ctx, targetID)
}

func (l *Lifecycle) Backup(ctx context.Context, req BackupRequest) (backuprestore.Artifact, error) {
	if req.TargetID == "" {
		return backuprestore.Artifact{}, errors.New("target id is required")
	}
	observed, err := l.inspector.Inspect(ctx, req.TargetID)
	if err != nil {
		return backuprestore.Artifact{}, err
	}
	if !observed.Core.Present {
		return backuprestore.Artifact{}, errors.New("Core backup requires an installed Core")
	}
	snapshot, err := l.state.Snapshot(ctx)
	if err != nil {
		return backuprestore.Artifact{}, err
	}
	target, err := targetFromSnapshot(snapshot, req.TargetID)
	if err != nil {
		return backuprestore.Artifact{}, err
	}
	paths := []string{"/var/lib/vpsmith/core", "/var/lib/vpsmith/inventory", "/var/lib/vpsmith/execution"}
	copy, err := l.backups.CopyOfflineStorage(ctx, l.storage, string(req.TargetID), paths)
	if err != nil {
		return backuprestore.Artifact{}, err
	}
	defer copy.Close()
	producer := corePayloadProducer{
		copy:      copy,
		observed:  observed,
		desired:   target.Desired.Core,
		bundleRef: latestSuccessfulBundle(snapshot, req.TargetID),
	}
	artifact, err := l.backups.Create(ctx, backuprestore.CreateRequest{
		Type:       managementstate.BackupCore,
		TargetID:   req.TargetID,
		Passphrase: req.Passphrase,
		Producer:   producer,
	})
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
	if err := requireSupportedHost(observed); err != nil {
		return Prepared{}, err
	}
	snapshot, err := l.state.Snapshot(ctx)
	if err != nil {
		return Prepared{}, err
	}
	target, err := targetFromSnapshot(snapshot, req.TargetID)
	if err != nil {
		return Prepared{}, err
	}
	if kind == deployment.Install && observed.Core.Present {
		return Prepared{}, errors.New("Core is already installed")
	}
	if kind != deployment.Install && !observed.Core.Present {
		return Prepared{}, errors.New("Core is not installed")
	}

	var backupManifest *backuprestore.Manifest
	if kind == deployment.Update || kind == deployment.Restore {
		manifest, err := l.verifiedCoreBackup(ctx, req, observed, kind)
		if err != nil {
			return Prepared{}, err
		}
		backupManifest = &manifest
	}

	candidateRef, err := candidateForOperation(kind, req, observed, backupManifest)
	if err != nil {
		return Prepared{}, err
	}
	source, err := l.sources.FreezeCoreCandidate(ctx, candidateRef)
	if err != nil {
		return Prepared{}, err
	}
	if backupManifest != nil && kind == deployment.Restore {
		if err := backupMatchesSource(*backupManifest, source); err != nil {
			return Prepared{}, err
		}
	}

	swap := req.Swap
	if kind == deployment.Update || kind == deployment.Validate {
		swap = target.Desired.Core.Swap
	}
	if swap.Mode == "" {
		swap.Mode = "none"
	}
	effectiveSwapBytes, err := resolveSwap(observed, swap, kind == deployment.Install)
	if err != nil {
		return Prepared{}, err
	}

	coreReq := deployment.CoreRequest{
		Operation:          kind,
		TargetID:           string(req.TargetID),
		Source:             deployment.FrozenCoreSource{SourceID: string(source.ID), Version: source.Version, GitCommit: source.Commit, PackageSHA256: source.SHA256, PackageFS: source.FS},
		SwapMode:           swap.Mode,
		SwapSizeGiB:        swap.SizeGiB,
		EffectiveSwapBytes: effectiveSwapBytes,
		ObservedArtifacts:  observedArtifactHashes(observed.Core.ManagedArtifacts),
		BackupRequired:     kind == deployment.Update,
	}
	if observed.Core.Present {
		if observed.Core.SourceID == "" || observed.Core.PackageSHA256 == "" {
			return Prepared{}, errors.New("installed Core identity is incomplete")
		}
		coreReq.ObservedCoreID = string(observed.Core.SourceID)
		coreReq.ObservedCoreSHA256 = observed.Core.PackageSHA256
	}
	operation, err := l.compiler.PrepareCore(ctx, coreReq)
	if err != nil {
		return Prepared{}, err
	}
	desiredCore := managementstate.CoreDesiredState{SourceID: source.ID, Version: source.Version, Swap: swap}
	return Prepared{
		Operation:     operation,
		TargetID:      req.TargetID,
		DesiredCore:   desiredCore,
		PrimaryBefore: observed.Host.PrimaryHardening,
	}, nil
}

func (l *Lifecycle) verifiedCoreBackup(ctx context.Context, req PrepareRequest, observed managementstate.ObservedState, kind deployment.OperationKind) (backuprestore.Manifest, error) {
	if req.BackupID == "" {
		return backuprestore.Manifest{}, errors.New("Core update/restore requires a concrete verified Core backup")
	}
	inspection, err := l.backups.InspectArtifact(ctx, req.BackupID, managementstate.BackupCore, req.BackupPassphrase)
	if err != nil {
		return backuprestore.Manifest{}, fmt.Errorf("verify Core backup: %w", err)
	}
	defer inspection.Close()
	manifest := inspection.Manifest
	if manifest.TargetID != req.TargetID || manifest.Identity == nil || manifest.Identity.SubjectKind != "core" {
		return backuprestore.Manifest{}, errors.New("Core backup belongs to another target or subject")
	}
	if kind == deployment.Update {
		identity := manifest.Identity
		if identity.SubjectID != string(observed.Core.SourceID) || identity.Version != observed.Core.Version || identity.PackageSHA256 != observed.Core.PackageSHA256 {
			return backuprestore.Manifest{}, errors.New("Core update backup does not match the installed exact Core identity")
		}
	}
	return manifest, nil
}

func candidateForOperation(kind deployment.OperationKind, req PrepareRequest, observed managementstate.ObservedState, backup *backuprestore.Manifest) (sourcelibrary.CoreCandidateRef, error) {
	switch kind {
	case deployment.Install, deployment.Update:
		return req.Candidate, nil
	case deployment.Reconfigure, deployment.Validate:
		if req.Candidate.SnapshotID != "" || req.Candidate.WorkspaceID != "" {
			return sourcelibrary.CoreCandidateRef{}, errors.New("Core reconfigure/validation must use the installed Core source")
		}
		return sourcelibrary.CoreCandidateRef{SnapshotID: observed.Core.SourceID}, nil
	case deployment.Restore:
		if backup == nil || backup.Identity == nil || backup.Identity.SubjectID == "" {
			return sourcelibrary.CoreCandidateRef{}, errors.New("Core restore backup has no previous source identity")
		}
		if req.Candidate.SnapshotID != "" || req.Candidate.WorkspaceID != "" {
			return sourcelibrary.CoreCandidateRef{}, errors.New("Core restore source is selected by the verified backup")
		}
		return sourcelibrary.CoreCandidateRef{SnapshotID: managementstate.SourceSnapshotID(backup.Identity.SubjectID)}, nil
	default:
		return sourcelibrary.CoreCandidateRef{}, errors.New("unsupported Core operation")
	}
}

func backupMatchesSource(manifest backuprestore.Manifest, source sourcelibrary.FrozenSnapshot) error {
	identity := manifest.Identity
	if identity == nil || identity.SubjectID != string(source.ID) || identity.Version != source.Version || identity.PackageSHA256 != source.SHA256 {
		return errors.New("Core restore source does not match the verified backup identity")
	}
	return nil
}

func resolveSwap(observed managementstate.ObservedState, swap managementstate.SwapDesiredState, installing bool) (int64, error) {
	switch swap.Mode {
	case "none":
		if swap.SizeGiB != 0 {
			return 0, errors.New("Core swap size is only valid for swapfile")
		}
		return 0, nil
	case "preserve-existing":
		if swap.SizeGiB != 0 {
			return 0, errors.New("Core swap size is only valid for swapfile")
		}
		if observed.Host.Swap.TotalBytes <= 0 {
			return 0, errors.New("preserve-existing requires existing foreign swap")
		}
		if !installing {
			return 0, errors.New("preserve-existing requires observed foreign-swap ownership before reconfiguration")
		}
		return 0, nil
	case "swapfile":
		var size int64
		if swap.SizeGiB == 0 {
			size = observed.Host.Memory.TotalBytes
			if size > maxAutoSwapBytes {
				size = maxAutoSwapBytes
			}
		} else if swap.SizeGiB > 0 {
			size = int64(swap.SizeGiB) << 30
		} else {
			return 0, errors.New("Core swap size must be auto or a positive GiB value")
		}
		if size <= 0 {
			return 0, errors.New("cannot determine Core swapfile size")
		}
		if observed.Host.RootFilesystem.AvailableBytes <= size {
			return 0, errors.New("insufficient free disk space for Core swapfile")
		}
		return size, nil
	default:
		return 0, errors.New("Core swap mode must be none, swapfile, or preserve-existing")
	}
}

func observedArtifactHashes(artifacts []managementstate.ManagedArtifactObservedState) map[string]string {
	out := make(map[string]string, len(artifacts))
	for _, artifact := range artifacts {
		if artifact.Present && artifact.Path != "" && artifact.SHA256 != "" {
			out[artifact.Path] = artifact.SHA256
		}
	}
	return out
}

func requirePrimary(observed managementstate.ObservedState) error {
	facts := observed.Host.PrimaryHardening
	if !observed.Host.Reachable || !observed.Host.SSH || !observed.CloudInit.Present || observed.CloudInit.Status != "ok" {
		return errors.New("successful Cloud-init and SSH are required")
	}
	if !facts.RootPasswordLocked || !facts.SSHConfigValid || !facts.UFWActive || facts.UFWUnexpectedPublicAllow || !facts.Fail2banSSHActive || !facts.Fail2banRecidiveActive {
		return errors.New("Primary Host Hardening is not effective")
	}
	return nil
}

func requireSupportedHost(observed managementstate.ObservedState) error {
	if strings.ToLower(observed.Host.OSID) != "ubuntu" || observed.Host.OSVersion != "24.04" {
		return fmt.Errorf("unsupported target OS %s %s; VPSmith Step 9 requires Ubuntu 24.04", observed.Host.OSID, observed.Host.OSVersion)
	}
	if observed.Host.Kernel == "" || observed.Host.Memory.TotalBytes <= 0 || observed.Host.RootFilesystem.AvailableBytes <= 0 {
		return errors.New("target host facts are incomplete")
	}
	return nil
}

func validatePostState(prepared Prepared, observed managementstate.ObservedState) error {
	if err := requirePrimary(observed); err != nil {
		return err
	}
	if !reflect.DeepEqual(prepared.PrimaryBefore, observed.Host.PrimaryHardening) {
		return errors.New("Core operation changed Cloud-init-owned Primary Host Hardening")
	}
	if !observed.Core.Present || observed.Core.SourceID != prepared.DesiredCore.SourceID || observed.Core.Version != prepared.DesiredCore.Version || observed.Core.PackageSHA256 != prepared.Operation.Bundle.Manifest.PackageSHA256 {
		return errors.New("effective Core identity does not match the approved bundle")
	}
	if !observed.Core.Podman.Present || !observed.Core.Podman.Rootless || observed.Core.Podman.CgroupVersion != "v2" || observed.Core.Podman.RootlessNetworkCmd != "pasta" {
		return errors.New("rootless Podman foundation is not effective")
	}
	if !observed.Core.Running {
		return errors.New("expected Core runtime is not running")
	}
	if !observed.Core.Caddy.Present || !observed.Core.Caddy.Running || !observed.Core.Caddy.ConfigChecked || !observed.Core.Caddy.ConfigValid {
		return errors.New("Caddy is not running with a valid checked configuration")
	}
	if !observed.Core.Authelia.Present || !observed.Core.Authelia.Running {
		return errors.New("Authelia is not running")
	}
	return nil
}

func targetFromSnapshot(snapshot managementstate.Snapshot, id managementstate.TargetID) (managementstate.Target, error) {
	for _, target := range snapshot.Targets {
		if target.ID == id {
			return target, nil
		}
	}
	return managementstate.Target{}, fmt.Errorf("target %s does not exist in Management State", id)
}

type corePayloadProducer struct {
	copy      backuprestore.StorageCopy
	observed  managementstate.ObservedState
	desired   managementstate.CoreDesiredState
	bundleRef string
}

func (p corePayloadProducer) Produce(ctx context.Context, root string) (backuprestore.PayloadDescriptor, error) {
	if err := ctx.Err(); err != nil {
		return backuprestore.PayloadDescriptor{}, err
	}
	if err := backuprestore.ExtractTarZst(p.copy.ArchivePath, root, backuprestore.ArchiveOptions{}); err != nil {
		return backuprestore.PayloadDescriptor{}, err
	}
	managementDir := filepath.Join(root, "management")
	if err := os.MkdirAll(managementDir, 0o700); err != nil {
		return backuprestore.PayloadDescriptor{}, err
	}
	desiredBytes, err := json.MarshalIndent(p.desired, "", "  ")
	if err != nil {
		return backuprestore.PayloadDescriptor{}, err
	}
	desiredBytes = append(desiredBytes, '\n')
	if err := os.WriteFile(filepath.Join(managementDir, "core-desired.json"), desiredBytes, 0o600); err != nil {
		return backuprestore.PayloadDescriptor{}, err
	}
	identity := &backuprestore.ArtifactIdentity{
		SubjectKind:             "core",
		SubjectID:               string(p.observed.Core.SourceID),
		Version:                 p.observed.Core.Version,
		PackageSHA256:           p.observed.Core.PackageSHA256,
		StoragePaths:            append([]string(nil), p.copy.DeclaredPath...),
		PreviousDesiredStateRef: "management/core-desired.json",
		ExecutionBundleRef:      p.bundleRef,
	}
	descriptor := backuprestore.PayloadDescriptor{
		Identity:   identity,
		SourceRefs: []string{string(p.observed.Core.SourceID)},
	}
	if p.bundleRef != "" {
		descriptor.BundleRefs = []string{p.bundleRef}
	}
	return descriptor, nil
}

func latestSuccessfulBundle(snapshot managementstate.Snapshot, targetID managementstate.TargetID) string {
	latestFinished := ""
	latestBundle := ""
	for _, record := range snapshot.ExecutionRecords {
		if record.TargetID != targetID || record.Outcome != "success" || record.BundleID == "" {
			continue
		}
		when := record.FinishedAt
		if when == "" {
			when = record.StartedAt
		}
		if when > latestFinished {
			latestFinished = when
			latestBundle = string(record.BundleID)
		}
	}
	return latestBundle
}
