package corelifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/executionbundle"
	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/sourcelibrary"
)

type coreVersionedSources struct {
	byID map[managementstate.SourceSnapshotID]sourcelibrary.FrozenSnapshot
	refs []sourcelibrary.CoreCandidateRef
}

func (s *coreVersionedSources) FreezeCoreCandidate(_ context.Context, ref sourcelibrary.CoreCandidateRef) (sourcelibrary.FrozenSnapshot, error) {
	s.refs = append(s.refs, ref)
	frozen, ok := s.byID[ref.SnapshotID]
	if !ok {
		return sourcelibrary.FrozenSnapshot{}, errors.New("unexpected Core source")
	}
	return frozen, nil
}

func TestPreparePreviousCoreRestoreResolvesImmediateUpdateBackupAndExactOldIdentity(t *testing.T) {
	ctx := context.Background()
	lifecycle, _, _, targetID, passphrase := newCoreBackupTestLifecycle(t)
	installUpdateTestSecrets(t, lifecycle, targetID)
	seedSuccessfulCoreBundle(t, lifecycle, targetID)

	oldSource := sourcelibrary.FrozenSnapshot{
		Snapshot: sourcelibrary.Snapshot{ID: "core-source", Kind: managementstate.SourceCore, Version: "1.0.0", SHA256: strings.Repeat("a", 64)},
		FS:       coreLifecycleFS("1.0.0", "1", deployment.Restore),
	}
	newSource := sourcelibrary.FrozenSnapshot{
		Snapshot: sourcelibrary.Snapshot{ID: "core-source-v2", Kind: managementstate.SourceCore, Version: "2.0.0", SHA256: strings.Repeat("f", 64)},
		FS:       coreLifecycleFS("2.0.0", "2", deployment.Update),
	}
	sources := &coreVersionedSources{byID: map[managementstate.SourceSnapshotID]sourcelibrary.FrozenSnapshot{
		oldSource.ID: oldSource,
		newSource.ID: newSource,
	}}
	assembler, err := executionbundle.NewAssembler(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := deployment.New(coreUpdateRegistry{}, assembler)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle.sources = sources
	lifecycle.compiler = compiler
	lifecycle.dns = dnsResolverStub{ips: []net.IP{net.ParseIP("203.0.113.10")}}

	update, err := lifecycle.PrepareUpdateWithBackup(ctx, PrepareRequest{
		TargetID: targetID, Candidate: sourcelibrary.CoreCandidateRef{SnapshotID: newSource.ID}, BackupPassphrase: passphrase,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := recordTerminalUpdateAttempt(ctx, lifecycle, targetID, update, "success"); err != nil {
		t.Fatal(err)
	}

	inspector := lifecycle.inspector.(coreBackupTestInspector)
	inspector.observed.Core.SourceID = newSource.ID
	inspector.observed.Core.Version = newSource.Version
	inspector.observed.Core.PackageSHA256 = newSource.SHA256
	lifecycle.inspector = inspector

	prepared, err := lifecycle.PreparePreviousCoreRestore(ctx, PreviousCoreRestoreRequest{
		TargetID: targetID, BackupPassphrase: passphrase,
	})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Operation.Operation != deployment.Restore || prepared.DesiredCore.SourceID != oldSource.ID || prepared.DesiredCore.Version != oldSource.Version {
		t.Fatalf("previous Core restore did not select old exact identity: %#v", prepared)
	}
	if prepared.Operation.Bundle.Manifest.PackageSHA256 != oldSource.SHA256 {
		t.Fatalf("previous Core restore package sha=%q", prepared.Operation.Bundle.Manifest.PackageSHA256)
	}
	images := map[string]string{}
	for _, image := range prepared.Operation.Bundle.Manifest.Images {
		images[image.Name] = image.Digest
	}
	if images["caddy"] != update.Previous.Images["caddy"].Digest || images["authelia"] != update.Previous.Images["authelia"].Digest {
		t.Fatalf("previous Core restore lost backed-up image locks: %#v", images)
	}
}

func TestPreparePreviousCoreRestoreRejectsArbitraryUnboundBackup(t *testing.T) {
	lifecycle, _, _, targetID, passphrase := newCoreBackupTestLifecycle(t)
	_, err := lifecycle.Backup(context.Background(), BackupRequest{TargetID: targetID, Passphrase: passphrase})
	if err != nil {
		t.Fatal(err)
	}
	_, err = lifecycle.PreparePreviousCoreRestore(context.Background(), PreviousCoreRestoreRequest{
		TargetID: targetID, BackupPassphrase: passphrase,
	})
	if err == nil || !strings.Contains(err.Error(), "no terminal Core update") {
		t.Fatalf("unbound Core backup restore error=%v", err)
	}
}

func recordTerminalUpdateAttempt(ctx context.Context, lifecycle *Lifecycle, targetID managementstate.TargetID, update PreparedUpdate, outcome string) error {
	bundle := update.Operation.Bundle
	return lifecycle.state.Change(ctx, func(change *managementstate.Change) error {
		if err := change.AppendExecutionBundle(managementstate.ExecutionBundleMetadata{
			ID:        managementstate.ExecutionBundleID(bundle.ID),
			TargetID:  targetID,
			Kind:      string(bundle.Kind),
			Version:   bundle.Manifest.Version,
			SHA256:    bundle.SHA256,
			BackupRef: update.Previous.BackupID,
			CreatedAt: "2026-08-20T12:00:00Z",
		}); err != nil {
			return err
		}
		return change.AppendExecutionRecord(managementstate.ExecutionRecordMetadata{
			ID: "execution_update_v2", BundleID: managementstate.ExecutionBundleID(bundle.ID), TargetID: targetID,
			Outcome: outcome, StartedAt: "2026-08-20T12:00:01Z", FinishedAt: "2026-08-20T12:00:10Z",
		})
	})
}

func coreLifecycleFS(version, contract string, operation deployment.OperationKind) fs.FS {
	definition, err := json.Marshal(map[string]any{
		"core_version":  version,
		"core_contract": contract,
		"images": map[string]any{
			"caddy":    map[string]string{"ref": "docker.io/library/caddy:2.11.4-alpine"},
			"authelia": map[string]string{"ref": "docker.io/authelia/authelia:4.39.20"},
		},
	})
	if err != nil {
		panic(err)
	}
	return fstest.MapFS{
		"core.json":                            &fstest.MapFile{Data: definition},
		"actions/runtime.sh":                   &fstest.MapFile{Data: []byte("#!/bin/sh\nset -eu\n")},
		"actions/" + string(operation) + ".sh": &fstest.MapFile{Data: []byte("#!/bin/sh\nset -eu\nexit 0\n"), Mode: 0o755},
	}
}
