package corelifecycle

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/executionbundle"
	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/sourcelibrary"
)

func TestPrepareUpdateWithBackupStopsBeforeCompilationWhenImmediateBackupFails(t *testing.T) {
	ctx := context.Background()
	lifecycle, _, storage, targetID, passphrase := newCoreBackupTestLifecycle(t)
	installUpdateTestSecrets(t, lifecycle, targetID)
	storage.resumeErr = errors.New("post-backup Core validation failed")

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
	if err == nil || !strings.Contains(err.Error(), "post-backup Core validation failed") {
		t.Fatalf("Core update backup failure error=%v", err)
	}
	if prepared.Operation.Bundle.ID != "" || prepared.Previous.BackupID != "" {
		t.Fatalf("failed immediate backup leaked a prepared update: %#v", prepared)
	}
	if len(sources.refs) != 1 || sources.refs[0].SnapshotID != candidate.ID {
		t.Fatalf("Core update continued to compilation after backup failure: %#v", sources.refs)
	}
	snapshot, err := lifecycle.state.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Backups) != 0 {
		t.Fatalf("failed immediate Core backup was catalogued: %#v", snapshot.Backups)
	}
	if want := []string{"quiesce", "prepare", "transfer", "resume", "cleanup"}; !equalStrings(storage.calls, want) {
		t.Fatalf("failed immediate Core backup calls=%#v want=%#v", storage.calls, want)
	}
}
