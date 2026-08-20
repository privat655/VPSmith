package corelifecycle

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/executionbundle"
	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/sourcelibrary"
)

func TestPrepareUpdateBindsImmediateBackupIntoImmutableBundle(t *testing.T) {
	ctx := context.Background()
	lifecycle, _, _, targetID, passphrase := newCoreBackupTestLifecycle(t)
	installUpdateTestSecrets(t, lifecycle, targetID)
	seedSuccessfulCoreBundle(t, lifecycle, targetID)
	candidate := sourcelibrary.FrozenSnapshot{
		Snapshot: sourcelibrary.Snapshot{ID: "core-source-v2", Kind: managementstate.SourceCore, Version: "2.0.0", SHA256: strings.Repeat("f", 64)},
		FS:       coreUpdateFS("2.0.0", "2"),
	}
	lifecycle.sources = &coreUpdateSource{frozen: candidate}
	assembler, err := executionbundle.NewAssembler(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := deployment.New(coreUpdateRegistry{}, assembler)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle.compiler = compiler
	lifecycle.dns = dnsResolverStub{ips: []net.IP{net.ParseIP("203.0.113.10")}}

	prepared, err := lifecycle.PrepareUpdateWithBackup(ctx, PrepareRequest{
		TargetID: targetID, Candidate: sourcelibrary.CoreCandidateRef{SnapshotID: candidate.ID}, BackupPassphrase: passphrase,
	})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Previous.BackupID == "" {
		t.Fatal("Core update created no immediate backup")
	}
	if got := prepared.Operation.Bundle.Manifest.BackupRef; got != string(prepared.Previous.BackupID) {
		t.Fatalf("Core update bundle backup ref=%q want=%q", got, prepared.Previous.BackupID)
	}
}
