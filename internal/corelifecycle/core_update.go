package corelifecycle

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/sourcelibrary"
)

type coreCandidateInspector interface {
	InspectCoreCandidate(context.Context, deployment.FrozenCoreSource) (deployment.CoreCandidateInspection, error)
}

type PreviousCoreState struct {
	BackupID          managementstate.BackupArtifactID
	SourceID          managementstate.SourceSnapshotID
	Version           string
	PackageSHA256     string
	ExecutionBundleID string
	Images            map[string]deployment.FrozenCoreImage
}

type PreparedUpdate struct {
	Prepared
	Previous PreviousCoreState
}

func (l *Lifecycle) PrepareUpdateWithBackup(ctx context.Context, req PrepareRequest) (PreparedUpdate, error) {
	if req.TargetID == "" {
		return PreparedUpdate{}, errors.New("target id is required")
	}
	if req.BackupID != "" {
		return PreparedUpdate{}, errors.New("Core update must create its own immediate Core backup")
	}
	if len(req.BackupPassphrase) == 0 {
		return PreparedUpdate{}, errors.New("Core update requires the recovery passphrase for its immediate backup")
	}
	if l == nil || l.state == nil || l.sources == nil || l.inspector == nil || l.compiler == nil || l.backups == nil || l.storage == nil {
		return PreparedUpdate{}, errors.New("complete Core update lifecycle is required")
	}

	frozen, err := l.preflightUpdateCandidate(ctx, req)
	if err != nil {
		return PreparedUpdate{}, err
	}

	artifact, err := l.Backup(ctx, BackupRequest{TargetID: req.TargetID, Passphrase: req.BackupPassphrase})
	if err != nil {
		return PreparedUpdate{}, fmt.Errorf("create immediate Core update backup: %w", err)
	}
	previous, err := l.previousCoreStateFromBackup(ctx, artifact.Metadata.ID, req.TargetID, req.BackupPassphrase)
	if err != nil {
		return PreparedUpdate{}, fmt.Errorf("verify immediate Core update backup: %w", err)
	}

	prepared, err := l.prepare(ctx, deployment.Update, PrepareRequest{
		TargetID:         req.TargetID,
		Candidate:        sourcelibrary.CoreCandidateRef{SnapshotID: frozen.ID},
		BackupID:         artifact.Metadata.ID,
		BackupPassphrase: req.BackupPassphrase,
	})
	if err != nil {
		return PreparedUpdate{}, err
	}
	if prepared.Operation.Bundle.Manifest.PackageSHA256 != frozen.SHA256 || prepared.DesiredCore.SourceID != frozen.ID || prepared.DesiredCore.Version != frozen.Version {
		return PreparedUpdate{}, errors.New("Core update candidate changed after immediate backup")
	}
	return PreparedUpdate{Prepared: prepared, Previous: previous}, nil
}

func (l *Lifecycle) preflightUpdateCandidate(ctx context.Context, req PrepareRequest) (sourcelibrary.FrozenSnapshot, error) {
	if req.Candidate.WorkspaceID != "" {
		return sourcelibrary.FrozenSnapshot{}, errors.New("mutable Core workspace must be explicitly adopted before Core update planning")
	}
	observed, err := l.inspector.Inspect(ctx, req.TargetID)
	if err != nil {
		return sourcelibrary.FrozenSnapshot{}, err
	}
	if err := requirePrimary(observed); err != nil {
		return sourcelibrary.FrozenSnapshot{}, err
	}
	if err := requireSupportedHost(observed); err != nil {
		return sourcelibrary.FrozenSnapshot{}, err
	}
	if err := requireCoreUpdateDiskSpace(observed); err != nil {
		return sourcelibrary.FrozenSnapshot{}, fmt.Errorf("Core update disk preflight failed: %w", err)
	}
	snapshot, err := l.state.Snapshot(ctx)
	if err != nil {
		return sourcelibrary.FrozenSnapshot{}, err
	}
	target, err := targetFromSnapshot(snapshot, req.TargetID)
	if err != nil {
		return sourcelibrary.FrozenSnapshot{}, err
	}
	if !observed.Core.Present {
		return sourcelibrary.FrozenSnapshot{}, errors.New("Core is not installed")
	}
	if err := requireSteadyCoreBeforeMutation(snapshot, target, observed, deployment.Update); err != nil {
		return sourcelibrary.FrozenSnapshot{}, err
	}
	if err := completeCoreDesiredRuntime(target.Desired.Core); err != nil {
		return sourcelibrary.FrozenSnapshot{}, fmt.Errorf("Core update requires complete canonical desired state: %w", err)
	}
	if err := requireCoreSecretReferences(snapshot, target.Desired.Core.Secrets); err != nil {
		return sourcelibrary.FrozenSnapshot{}, err
	}

	frozen, err := l.sources.FreezeCoreCandidate(ctx, req.Candidate)
	if err != nil {
		return sourcelibrary.FrozenSnapshot{}, err
	}
	if frozen.ID == "" || frozen.Kind != managementstate.SourceCore || frozen.Version == "" || frozen.SHA256 == "" || frozen.FS == nil {
		return sourcelibrary.FrozenSnapshot{}, errors.New("Core update candidate did not freeze to a complete immutable Core source")
	}
	inspector, ok := l.compiler.(coreCandidateInspector)
	if !ok {
		return sourcelibrary.FrozenSnapshot{}, errors.New("Deployment Compiler does not expose read-only Core candidate inspection")
	}
	candidate, err := inspector.InspectCoreCandidate(ctx, deployment.FrozenCoreSource{
		SourceID:      string(frozen.ID),
		Version:       frozen.Version,
		GitCommit:     frozen.Commit,
		PackageSHA256: frozen.SHA256,
		PackageFS:     frozen.FS,
	})
	if err != nil {
		return sourcelibrary.FrozenSnapshot{}, fmt.Errorf("inspect Core update candidate: %w", err)
	}
	if candidate.Version != frozen.Version || candidate.CoreContract == "" {
		return sourcelibrary.FrozenSnapshot{}, errors.New("Core update candidate inspection changed frozen identity")
	}
	if err := requireLifecycleModuleCompatibility(ctx, snapshot, target, observed, candidate.CoreContract, l.sources, l.compiler); err != nil {
		return sourcelibrary.FrozenSnapshot{}, err
	}
	resolver := l.dns
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if err := requireDNSARecord(ctx, resolver, "auth."+target.Desired.Core.Domain, target.Address); err != nil {
		return sourcelibrary.FrozenSnapshot{}, err
	}
	return frozen, nil
}

func (l *Lifecycle) previousCoreStateFromBackup(ctx context.Context, backupID managementstate.BackupArtifactID, targetID managementstate.TargetID, passphrase []byte) (PreviousCoreState, error) {
	inspection, err := l.backups.InspectArtifact(ctx, backupID, managementstate.BackupCore, passphrase)
	if err != nil {
		return PreviousCoreState{}, err
	}
	defer inspection.Close()
	if inspection.Manifest.TargetID != targetID || inspection.Manifest.Identity == nil || inspection.Manifest.Identity.SubjectKind != "core" {
		return PreviousCoreState{}, errors.New("immediate Core backup belongs to another target or subject")
	}
	desired, locks, err := coreStateFromBackup(inspection)
	if err != nil {
		return PreviousCoreState{}, err
	}
	identity := inspection.Manifest.Identity
	if identity.SubjectID != string(desired.SourceID) || identity.Version != desired.Version || identity.PackageSHA256 != locks.PackageSHA256 || locks.SourceID != desired.SourceID || locks.Version != desired.Version {
		return PreviousCoreState{}, errors.New("immediate Core backup identity is inconsistent")
	}
	if identity.ExecutionBundleRef == "" {
		return PreviousCoreState{}, errors.New("immediate Core backup has no verified historical Core execution bundle")
	}
	images := make(map[string]deployment.FrozenCoreImage, len(locks.Images))
	for name, image := range locks.Images {
		images[name] = deployment.FrozenCoreImage{Ref: image.Ref, Digest: image.Digest}
	}
	return PreviousCoreState{
		BackupID:          backupID,
		SourceID:          desired.SourceID,
		Version:           desired.Version,
		PackageSHA256:     identity.PackageSHA256,
		ExecutionBundleID: identity.ExecutionBundleRef,
		Images:            images,
	}, nil
}
