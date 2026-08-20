package corelifecycle

import (
	"context"
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

func TestPreparePreviousCoreRestoreUsesImmediateUpdateBackupAndExactOldIdentity(t *testing.T) {
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

	inspector := lifecycle.inspector.(coreBackupTestInspector)
	inspector.observed.Core.SourceID = newSource.ID
	inspector.observed.Core.Version = newSource.Version
	inspector.observed.Core.PackageSHA256 = newSource.SHA256
	lifecycle.inspector = inspector

	prepared, err := lifecycle.PreparePreviousCoreRestore(ctx, PreviousCoreRestoreRequest{
		TargetID: targetID, Previous: update.Previous, BackupPassphrase: passphrase,
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

func TestPreparePreviousCoreRestoreRejectsTamperedPreviousState(t *testing.T) {
	lifecycle, _, _, targetID, passphrase := newCoreBackupTestLifecycle(t)
	previous := PreviousCoreState{
		BackupID: "backup_not_from_update", SourceID: "core-source", Version: "1.0.0", PackageSHA256: strings.Repeat("a", 64), ExecutionBundleID: "bundle_core_v1",
		Images: map[string]deployment.FrozenCoreImage{},
	}
	_, err := lifecycle.PreparePreviousCoreRestore(context.Background(), PreviousCoreRestoreRequest{
		TargetID: targetID, Previous: previous, BackupPassphrase: passphrase,
	})
	if err == nil {
		t.Fatal("tampered previous Core state was accepted")
	}
}

func coreLifecycleFS(version, contract string, operation deployment.OperationKind) fs.FS {
	definition := []byte(`{"core_version":"` + version + `","core_contract":"` + contract + `","images":{"caddy":{"ref":"docker.io/library/caddy:2.11.4-alpine"},"authelia":{"ref":"docker.io/authelia/authelia:4.39.20"}}}`)
	return fstest.MapFS{
		"core.json":                  &fstest.MapFile{Data: definition},
		"actions/runtime.sh":         &fstest.MapFile{Data: []byte("#!/bin/sh\nset -eu\n")},
		"actions/" + string(operation) + ".sh": &fstest.MapFile{Data: []byte("#!/bin/sh\nset -eu\nexit 0\n"), Mode: 0o755},
	}
}
