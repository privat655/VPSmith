package corelifecycle

import (
	"context"
	"encoding/json"
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

type coreUpdateSource struct {
	frozen sourcelibrary.FrozenSnapshot
	refs   []sourcelibrary.CoreCandidateRef
}

func (s *coreUpdateSource) FreezeCoreCandidate(_ context.Context, ref sourcelibrary.CoreCandidateRef) (sourcelibrary.FrozenSnapshot, error) {
	s.refs = append(s.refs, ref)
	return s.frozen, nil
}

type coreUpdateRegistry struct{}

func (coreUpdateRegistry) Resolve(_ context.Context, ref string) (string, error) {
	if strings.Contains(ref, "authelia") {
		return "sha256:" + strings.Repeat("e", 64), nil
	}
	return "sha256:" + strings.Repeat("d", 64), nil
}

func TestPrepareUpdateWithBackupCreatesImmediateVerifiedPreviousCoreState(t *testing.T) {
	ctx := context.Background()
	lifecycle, _, storage, targetID, passphrase := newCoreBackupTestLifecycle(t)
	refs := installUpdateTestSecrets(t, lifecycle, targetID)
	seedSuccessfulCoreBundle(t, lifecycle, targetID)

	candidate := sourcelibrary.FrozenSnapshot{
		Snapshot: sourcelibrary.Snapshot{
			ID: "core-source-v2", Kind: managementstate.SourceCore, Version: "2.0.0", SHA256: strings.Repeat("f", 64),
		},
		FS: coreUpdateFS("2.0.0", "2"),
	}
	sources := &coreUpdateSource{frozen: candidate}
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

	prepared, err := lifecycle.PrepareUpdateWithBackup(ctx, PrepareRequest{
		TargetID:         targetID,
		Candidate:        sourcelibrary.CoreCandidateRef{SnapshotID: candidate.ID},
		BackupPassphrase: passphrase,
	})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Operation.Operation != deployment.Update || prepared.Operation.Bundle.Manifest.PackageSHA256 != candidate.SHA256 {
		t.Fatalf("unexpected prepared update: %#v", prepared.Operation)
	}
	if prepared.Previous.BackupID == "" || prepared.Previous.SourceID != "core-source" || prepared.Previous.Version != "1.0.0" || prepared.Previous.PackageSHA256 != strings.Repeat("a", 64) {
		t.Fatalf("previous Core state was not frozen from the immediate backup: %#v", prepared.Previous)
	}
	if prepared.Previous.ExecutionBundleID != "bundle_core_v1" {
		t.Fatalf("previous Core bundle=%q", prepared.Previous.ExecutionBundleID)
	}
	if len(prepared.Previous.Images) != 2 || prepared.Previous.Images["caddy"].Digest != "sha256:"+strings.Repeat("b", 64) || prepared.Previous.Images["authelia"].Digest != "sha256:"+strings.Repeat("c", 64) {
		t.Fatalf("previous Core image locks=%#v", prepared.Previous.Images)
	}
	if len(sources.refs) != 2 || sources.refs[0].SnapshotID != candidate.ID || sources.refs[1].SnapshotID != candidate.ID || sources.refs[1].WorkspaceID != "" {
		t.Fatalf("update candidate was not pinned to the preflight immutable snapshot: %#v", sources.refs)
	}
	if want := []string{"quiesce", "prepare", "transfer", "resume", "cleanup"}; !equalStrings(storage.calls, want) {
		t.Fatalf("Core update backup calls=%#v want=%#v", storage.calls, want)
	}
	snapshot, err := lifecycle.state.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Backups) != 1 || snapshot.Backups[0].ID != prepared.Previous.BackupID || snapshot.Backups[0].Type != managementstate.BackupCore {
		t.Fatalf("Core update did not persist exactly its immediate backup: %#v", snapshot.Backups)
	}
	if prepared.DesiredCore.Secrets != refs {
		t.Fatalf("Core update changed stable secret references: got=%#v want=%#v", prepared.DesiredCore.Secrets, refs)
	}
}

func TestPrepareUpdateWithBackupRejectsCallerSelectedBackup(t *testing.T) {
	lifecycle, _, _, targetID, passphrase := newCoreBackupTestLifecycle(t)
	_, err := lifecycle.PrepareUpdateWithBackup(context.Background(), PrepareRequest{
		TargetID: targetID, BackupID: "backup_external", BackupPassphrase: passphrase,
	})
	if err == nil || !strings.Contains(err.Error(), "must create its own immediate Core backup") {
		t.Fatalf("caller-selected Core update backup error=%v", err)
	}
}

func installUpdateTestSecrets(t *testing.T, lifecycle *Lifecycle, targetID managementstate.TargetID) managementstate.CoreSecretReferences {
	t.Helper()
	ctx := context.Background()
	inspector := lifecycle.inspector.(coreBackupTestInspector)
	inspector.observed.Host.OSID = "ubuntu"
	inspector.observed.Host.OSVersion = "24.04"
	inspector.observed.Host.Kernel = "6.8.0-test"
	inspector.observed.Host.RootFilesystem = managementstate.FilesystemObservedState{TotalBytes: 40 << 30, AvailableBytes: 30 << 30}
	lifecycle.inspector = inspector

	snapshot, err := lifecycle.state.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	desired := snapshot.Targets[0].Desired
	var refs managementstate.CoreSecretReferences
	if err := lifecycle.state.Change(ctx, func(change *managementstate.Change) error {
		created := make([]managementstate.SecretID, 4)
		for i := range created {
			id, err := change.CreateSecret("Core update test secret "+string(rune('a'+i)), managementstate.SecretGenerated)
			if err != nil {
				return err
			}
			if err := change.SetSecret(id, []byte("Core-update-test-secret-value-"+string(rune('a'+i)))); err != nil {
				return err
			}
			created[i] = id
		}
		refs = managementstate.CoreSecretReferences{
			AutheliaSession: created[0], AutheliaStorage: created[1], AutheliaResetPassword: created[2], AutheliaUsersDatabase: created[3],
		}
		desired.Core.Secrets = refs
		return change.SetDesiredState(targetID, desired)
	}); err != nil {
		t.Fatal(err)
	}
	return refs
}

func seedSuccessfulCoreBundle(t *testing.T, lifecycle *Lifecycle, targetID managementstate.TargetID) {
	t.Helper()
	if err := lifecycle.state.Change(context.Background(), func(change *managementstate.Change) error {
		if err := change.AppendExecutionBundle(managementstate.ExecutionBundleMetadata{
			ID: "bundle_core_v1", TargetID: targetID, Kind: "installation", Version: "1.0.0", SHA256: strings.Repeat("9", 64), CreatedAt: "2026-08-20T17:00:00Z",
		}); err != nil {
			return err
		}
		return change.AppendExecutionRecord(managementstate.ExecutionRecordMetadata{
			ID: "execution_core_v1", BundleID: "bundle_core_v1", TargetID: targetID, Outcome: "success", StartedAt: "2026-08-20T17:00:00Z", FinishedAt: "2026-08-20T17:01:00Z",
		})
	}); err != nil {
		t.Fatal(err)
	}
	inspector := lifecycle.inspector.(coreBackupTestInspector)
	inspector.observed.Core.ExecutionProofs = append(inspector.observed.Core.ExecutionProofs, managementstate.ExecutionProofObservedState{
		ID: "proof_core_v1", BundleID: "bundle_core_v1", Outcome: "success",
	})
	lifecycle.inspector = inspector
}

func coreUpdateFS(version, contract string) fs.FS {
	data, err := json.Marshal(map[string]any{
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
		"core.json":          &fstest.MapFile{Data: data},
		"actions/runtime.sh": &fstest.MapFile{Data: []byte("#!/bin/sh\nset -eu\n")},
		"actions/update.sh":  &fstest.MapFile{Data: []byte("#!/bin/sh\nset -eu\nexit 0\n"), Mode: 0o755},
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
