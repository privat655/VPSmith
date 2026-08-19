package recoverypackage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/privat655/VPSmith/internal/backuprestore"
	"github.com/privat655/VPSmith/internal/executionbundle"
	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/sourcelibrary"
)

const managementStateFile = "management-state.json"

type Service struct {
	state   *managementstate.Store
	sources *sourcelibrary.Library
	bundles *executionbundle.Assembler
	backups *backuprestore.Manager
}

func New(state *managementstate.Store, sources *sourcelibrary.Library, bundles *executionbundle.Assembler, backups *backuprestore.Manager) (*Service, error) {
	if state == nil || sources == nil || bundles == nil || backups == nil {
		return nil, errors.New("recovery package requires canonical state, source library, bundle store, and backup manager")
	}
	return &Service{state: state, sources: sources, bundles: bundles, backups: backups}, nil
}

type CreateRequest struct {
	TargetID               managementstate.TargetID
	Passphrase             []byte
	IncludeCustomModulePAT bool
}

func (s *Service) Create(ctx context.Context, request CreateRequest) (backuprestore.Artifact, error) {
	if request.TargetID == "" {
		return backuprestore.Artifact{}, errors.New("recovery target id is required")
	}
	producer := &producer{state: s.state, sources: s.sources, bundles: s.bundles, targetID: request.TargetID, includePAT: request.IncludeCustomModulePAT}
	return s.backups.Create(ctx, backuprestore.CreateRequest{Type: managementstate.BackupRecoveryPackage, TargetID: request.TargetID, Passphrase: request.Passphrase, Producer: producer})
}

func (s *Service) Import(ctx context.Context, source string, passphrase []byte) (backuprestore.Artifact, error) {
	prepared, err := s.backups.PrepareRestore(ctx, source, managementstate.BackupRecoveryPackage, passphrase)
	if err != nil {
		return backuprestore.Artifact{}, err
	}
	defer prepared.Close()
	data, err := os.ReadFile(filepath.Join(prepared.CandidateRoot, managementStateFile))
	if err != nil {
		return backuprestore.Artifact{}, fmt.Errorf("read recovery management state: %w", err)
	}
	var recovery managementstate.RecoveryState
	if err := json.Unmarshal(data, &recovery); err != nil {
		return backuprestore.Artifact{}, fmt.Errorf("decode recovery management state: %w", err)
	}
	defer recovery.Zero()
	if !containsTarget(recovery.Snapshot.Targets, prepared.Manifest.TargetID) {
		return backuprestore.Artifact{}, errors.New("recovery manifest target is absent from canonical payload state")
	}
	// Verify and publish canonical supporting stores before the single database
	// commit. Failures leave no visible management-state mutation. Published
	// immutable objects without a catalogue reference are inert and may be
	// safely reused by a retry.
	if err := s.sources.ImportRecovery(ctx, filepath.Join(prepared.CandidateRoot, "sources"), recovery.Snapshot.Sources); err != nil {
		return backuprestore.Artifact{}, fmt.Errorf("import recovery sources: %w", err)
	}
	if err := s.bundles.ImportRecovery(recovery.Snapshot.ExecutionBundles, filepath.Join(prepared.CandidateRoot, "execution-bundles")); err != nil {
		return backuprestore.Artifact{}, fmt.Errorf("import recovery execution bundles: %w", err)
	}
	return s.backups.AdoptValidatedRecovery(ctx, source, prepared.Manifest, func(metadata managementstate.BackupArtifactMetadata) error {
		return s.state.ReplaceFromRecovery(ctx, recovery, metadata)
	})
}

type producer struct {
	state      *managementstate.Store
	sources    *sourcelibrary.Library
	bundles    *executionbundle.Assembler
	targetID   managementstate.TargetID
	includePAT bool
}

func (p *producer) Produce(ctx context.Context, root string) (backuprestore.PayloadDescriptor, error) {
	recovery, err := p.state.ExportRecovery(ctx, p.includePAT)
	if err != nil {
		return backuprestore.PayloadDescriptor{}, err
	}
	defer recovery.Zero()
	if !containsTarget(recovery.Snapshot.Targets, p.targetID) {
		return backuprestore.PayloadDescriptor{}, errors.New("recovery target is not present in canonical management state")
	}
	data, err := json.Marshal(recovery)
	if err != nil {
		return backuprestore.PayloadDescriptor{}, fmt.Errorf("encode recovery management state: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, managementStateFile), data, 0o600); err != nil {
		return backuprestore.PayloadDescriptor{}, err
	}
	if err := p.sources.ExportRecovery(ctx, filepath.Join(root, "sources")); err != nil {
		return backuprestore.PayloadDescriptor{}, err
	}
	if err := p.bundles.ExportRecovery(recovery.Snapshot.ExecutionBundles, filepath.Join(root, "execution-bundles")); err != nil {
		return backuprestore.PayloadDescriptor{}, err
	}
	var sourceRefs []string
	for _, item := range recovery.Snapshot.Sources.Artifacts {
		sourceRefs = append(sourceRefs, string(item.ID)+":"+item.SHA256)
	}
	for _, item := range recovery.Snapshot.Sources.Workspaces {
		sourceRefs = append(sourceRefs, string(item.ID)+":"+item.CurrentSHA256)
	}
	var bundleRefs []string
	for _, item := range recovery.Snapshot.ExecutionBundles {
		bundleRefs = append(bundleRefs, string(item.ID)+":"+item.SHA256)
	}
	sort.Strings(sourceRefs)
	sort.Strings(bundleRefs)
	return backuprestore.PayloadDescriptor{SourceRefs: sourceRefs, BundleRefs: bundleRefs, RestoreRefs: []string{"canonical-management-state", "ssh-host-trust", "canonical-secrets", "source-library", "execution-history"}}, nil
}

func containsTarget(targets []managementstate.Target, id managementstate.TargetID) bool {
	for _, target := range targets {
		if target.ID == id {
			return true
		}
	}
	return false
}
