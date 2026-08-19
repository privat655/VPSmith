package recoverypackage

import (
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/managementstate"
)

func TestDecodeRecoveryStateRejectsUnknownFields(t *testing.T) {
	_, err := decodeRecoveryState([]byte(`{"snapshot":{"schema_version":3},"secret_values":{},"unexpected":true}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown recovery field was accepted: %v", err)
	}
}

func TestCompareReconnectionReportsHistoryDriftWithoutChoosingWinner(t *testing.T) {
	target := managementstate.TargetID("target_test")
	bundleID := managementstate.ExecutionBundleID("bundle_test")
	runID := managementstate.ExecutionRecordID("execution_test")
	snapshot := managementstate.Snapshot{
		Targets: []managementstate.Target{{ID: target}},
		ExecutionBundles: []managementstate.ExecutionBundleMetadata{{
			ID: bundleID, TargetID: target, Kind: "installation", Version: "1.0.0",
			SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}},
		ExecutionRecords: []managementstate.ExecutionRecordMetadata{{
			ID: runID, BundleID: bundleID, TargetID: target, Outcome: "success", StartedAt: "2026-08-19T00:00:00Z",
		}},
	}
	observed := managementstate.ObservedState{Core: managementstate.CoreObservedState{ExecutionProofs: []managementstate.ExecutionProofObservedState{{
		ID: string(runID), BundleID: string(bundleID),
		BundleSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Kind:         "installation", Outcome: "failed",
	}}}}
	report := compareReconnection(snapshot, target, observed)
	if report.Matches {
		t.Fatal("history drift was reported as matching")
	}
	if len(report.Differences) != 2 {
		t.Fatalf("differences=%#v", report.Differences)
	}
	kinds := map[string]bool{}
	for _, difference := range report.Differences {
		kinds[difference.Kind] = true
	}
	if !kinds["bundle-sha256-mismatch"] || !kinds["execution-history-mismatch"] {
		t.Fatalf("missing expected drift facts: %#v", report.Differences)
	}
}

func TestCompareReconnectionAcceptsMatchingHistory(t *testing.T) {
	target := managementstate.TargetID("target_test")
	bundleID := managementstate.ExecutionBundleID("bundle_test")
	runID := managementstate.ExecutionRecordID("execution_test")
	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	snapshot := managementstate.Snapshot{
		Targets:          []managementstate.Target{{ID: target}},
		ExecutionBundles: []managementstate.ExecutionBundleMetadata{{ID: bundleID, TargetID: target, Kind: "installation", Version: "1.0.0", SHA256: sha}},
		ExecutionRecords: []managementstate.ExecutionRecordMetadata{{ID: runID, BundleID: bundleID, TargetID: target, Outcome: "success", StartedAt: "2026-08-19T00:00:00Z"}},
	}
	observed := managementstate.ObservedState{Core: managementstate.CoreObservedState{ExecutionProofs: []managementstate.ExecutionProofObservedState{{ID: string(runID), BundleID: string(bundleID), BundleSHA256: sha, Kind: "installation", Outcome: "success"}}}}
	report := compareReconnection(snapshot, target, observed)
	if !report.Matches || len(report.Differences) != 0 {
		t.Fatalf("matching history reported drift: %#v", report.Differences)
	}
}
