package corelifecycle

import (
	"context"
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/managementstate"
)

func TestLegacyPrepareUpdateCannotBypassImmediateBackupOperation(t *testing.T) {
	_, err := (&Lifecycle{}).PrepareUpdate(context.Background(), PrepareRequest{TargetID: "target-update"})
	if err == nil || !strings.Contains(err.Error(), "PrepareUpdateWithBackup") {
		t.Fatalf("legacy Core update entry point error=%v", err)
	}
}

func TestLatestSuccessfulCoreBundleUsesObservedCoreProofsNotLatestTargetBundle(t *testing.T) {
	snapshot := managementstate.Snapshot{
		ExecutionRecords: []managementstate.ExecutionRecordMetadata{
			{ID: "run-core", BundleID: "bundle_core", TargetID: "target-1", Outcome: "success", StartedAt: "2026-08-20T18:00:00Z", FinishedAt: "2026-08-20T18:01:00Z"},
			{ID: "run-module", BundleID: "bundle_module", TargetID: "target-1", Outcome: "success", StartedAt: "2026-08-20T18:02:00Z", FinishedAt: "2026-08-20T18:03:00Z"},
		},
	}
	observed := managementstate.ObservedState{Core: managementstate.CoreObservedState{
		ExecutionProofs: []managementstate.ExecutionProofObservedState{
			{ID: "proof-core", BundleID: "bundle_core", Outcome: "success"},
		},
	}}
	if got := latestSuccessfulCoreBundle(snapshot, observed, "target-1"); got != "bundle_core" {
		t.Fatalf("latest successful Core bundle=%q", got)
	}
}
