package recoverypackage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	if err := requireRecoveryPayloadLayout(prepared.CandidateRoot); err != nil {
		return backuprestore.Artifact{}, err
	}
	data, err := os.ReadFile(filepath.Join(prepared.CandidateRoot, managementStateFile))
	if err != nil {
		return backuprestore.Artifact{}, fmt.Errorf("read recovery management state: %w", err)
	}
	recovery, err := decodeRecoveryState(data)
	if err != nil {
		return backuprestore.Artifact{}, err
	}
	defer recovery.Zero()
	if len(recovery.Snapshot.Backups) != 0 {
		return backuprestore.Artifact{}, errors.New("recovery package must not contain backup catalogue entries without their artifact bytes")
	}
	if !containsTarget(recovery.Snapshot.Targets, prepared.Manifest.TargetID) {
		return backuprestore.Artifact{}, errors.New("recovery manifest target is absent from canonical payload state")
	}

	sourceImport, err := s.sources.PrepareRecoveryImport(ctx, filepath.Join(prepared.CandidateRoot, "sources"), recovery.Snapshot.Sources)
	if err != nil {
		return backuprestore.Artifact{}, fmt.Errorf("prepare recovery sources: %w", err)
	}
	defer sourceImport.Close()
	bundleImport, err := s.bundles.PrepareRecoveryImport(recovery.Snapshot.ExecutionBundles, filepath.Join(prepared.CandidateRoot, "execution-bundles"))
	if err != nil {
		return backuprestore.Artifact{}, fmt.Errorf("prepare recovery execution bundles: %w", err)
	}
	defer bundleImport.Close()

	if err := sourceImport.Commit(); err != nil {
		return backuprestore.Artifact{}, fmt.Errorf("publish recovery sources: %w", err)
	}
	if err := bundleImport.Commit(); err != nil {
		return backuprestore.Artifact{}, fmt.Errorf("publish recovery execution bundles: %w", err)
	}
	artifact, err := s.backups.AdoptValidatedRecovery(ctx, source, prepared.Manifest, func(metadata managementstate.BackupArtifactMetadata) error {
		return s.state.ReplaceFromRecovery(ctx, recovery, metadata)
	})
	if err != nil {
		return backuprestore.Artifact{}, err
	}
	sourceImport.Seal()
	bundleImport.Seal()
	return artifact, nil
}

type ReconnectionDifference struct {
	Kind        string `json:"kind"`
	ExecutionID string `json:"execution_id,omitempty"`
	BundleID    string `json:"bundle_id,omitempty"`
	LocalValue  string `json:"local_value,omitempty"`
	TargetValue string `json:"target_value,omitempty"`
}

type ReconnectionReport struct {
	TargetID    managementstate.TargetID      `json:"target_id"`
	Observed    managementstate.ObservedState `json:"observed"`
	Matches     bool                          `json:"matches"`
	Differences []ReconnectionDifference      `json:"differences"`
}

// Reconcile compares restored local execution history with immutable target
// execution proofs. It is deliberately read-only and never chooses a winner.
func (s *Service) Reconcile(ctx context.Context, targetID managementstate.TargetID, observed managementstate.ObservedState) (ReconnectionReport, error) {
	if targetID == "" {
		return ReconnectionReport{}, errors.New("reconnection target id is required")
	}
	snapshot, err := s.state.Snapshot(ctx)
	if err != nil {
		return ReconnectionReport{}, err
	}
	if !containsTarget(snapshot.Targets, targetID) {
		return ReconnectionReport{}, fmt.Errorf("target %s does not exist", targetID)
	}
	return compareReconnection(snapshot, targetID, observed), nil
}

func compareReconnection(snapshot managementstate.Snapshot, targetID managementstate.TargetID, observed managementstate.ObservedState) ReconnectionReport {
	report := ReconnectionReport{TargetID: targetID, Observed: observed, Differences: []ReconnectionDifference{}}
	bundles := map[string]managementstate.ExecutionBundleMetadata{}
	for _, bundle := range snapshot.ExecutionBundles {
		if bundle.TargetID == targetID {
			bundles[string(bundle.ID)] = bundle
		}
	}
	records := map[string]managementstate.ExecutionRecordMetadata{}
	for _, record := range snapshot.ExecutionRecords {
		if record.TargetID == targetID {
			records[string(record.ID)] = record
		}
	}
	proofs := map[string]managementstate.ExecutionProofObservedState{}
	for _, proof := range observed.Core.ExecutionProofs {
		proofs[proof.ID] = proof
		bundle, ok := bundles[proof.BundleID]
		if !ok {
			report.Differences = append(report.Differences, ReconnectionDifference{Kind: "target-only-bundle", ExecutionID: proof.ID, BundleID: proof.BundleID, TargetValue: proof.BundleSHA256})
			continue
		}
		if bundle.SHA256 != proof.BundleSHA256 {
			report.Differences = append(report.Differences, ReconnectionDifference{Kind: "bundle-sha256-mismatch", ExecutionID: proof.ID, BundleID: proof.BundleID, LocalValue: bundle.SHA256, TargetValue: proof.BundleSHA256})
		}
		if record, ok := records[proof.ID]; !ok {
			report.Differences = append(report.Differences, ReconnectionDifference{Kind: "target-only-run", ExecutionID: proof.ID, BundleID: proof.BundleID, TargetValue: proof.Outcome})
		} else if string(record.BundleID) != proof.BundleID || record.Outcome != proof.Outcome {
			report.Differences = append(report.Differences, ReconnectionDifference{Kind: "execution-history-mismatch", ExecutionID: proof.ID, BundleID: proof.BundleID, LocalValue: string(record.BundleID) + ":" + record.Outcome, TargetValue: proof.BundleID + ":" + proof.Outcome})
		}
	}
	for id, record := range records {
		if _, ok := proofs[id]; !ok {
			report.Differences = append(report.Differences, ReconnectionDifference{Kind: "local-only-run", ExecutionID: id, BundleID: string(record.BundleID), LocalValue: record.Outcome})
		}
	}
	sort.Slice(report.Differences, func(i, j int) bool {
		a, b := report.Differences[i], report.Differences[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.ExecutionID != b.ExecutionID {
			return a.ExecutionID < b.ExecutionID
		}
		return a.BundleID < b.BundleID
	})
	report.Matches = len(report.Differences) == 0
	return report
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
	// Backup catalogue entries are not portable without the corresponding
	// artifact bytes. Recovery packages therefore restore management identity,
	// desired state, secrets, sources, and execution history, but not stale
	// references to independent backup artifacts.
	recovery.Snapshot.Backups = []managementstate.BackupArtifactMetadata{}
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

func decodeRecoveryState(data []byte) (managementstate.RecoveryState, error) {
	var recovery managementstate.RecoveryState
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&recovery); err != nil {
		return managementstate.RecoveryState{}, fmt.Errorf("decode recovery management state: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return managementstate.RecoveryState{}, errors.New("recovery management state contains multiple JSON values")
		}
		return managementstate.RecoveryState{}, fmt.Errorf("decode recovery management state trailer: %w", err)
	}
	return recovery, nil
}

func requireRecoveryPayloadLayout(root string) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("read recovery payload root: %w", err)
	}
	expected := map[string]bool{managementStateFile: false, "sources": true, "execution-bundles": true}
	if len(entries) != len(expected) {
		return errors.New("recovery payload has unexpected top-level entries")
	}
	for _, entry := range entries {
		wantDir, ok := expected[entry.Name()]
		if !ok || entry.IsDir() != wantDir {
			return fmt.Errorf("unexpected recovery payload entry %q", entry.Name())
		}
	}
	return nil
}

func containsTarget(targets []managementstate.Target, id managementstate.TargetID) bool {
	for _, target := range targets {
		if target.ID == id {
			return true
		}
	}
	return false
}
