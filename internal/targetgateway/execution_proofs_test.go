package targetgateway

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestProductionInspectionImportsCanonicalTargetExecutionProofs(t *testing.T) {
	const proofJSON = `{"bundle_id":"bundle-canonical","bundle_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","finished_at":"2026-08-18T18:00:01Z","format_version":1,"kind":"migration","phase":"finished","run_id":"run-canonical","started_at":"2026-08-18T18:00:00Z","status":"success","steps":[],"target_vps_id":"target-fixture"}`
	const proofSHA256 = "83fe595238b3929f8f3a418bc41e7f371faeefb7df73bddb9b7e4ba8c7b3e35c"

	base := inspectionFixture(t)
	runner := &captureRunner{}
	runner.hook = func(name string, args []string) ([]byte, []byte, error) {
		if name != "ssh" {
			return nil, nil, errors.New("unexpected process")
		}
		command := args[len(args)-1]
		switch {
		case strings.Contains(command, coreInventoryPath) && strings.Contains(command, "/var/tmp/vpsmith-execution") && strings.Contains(command, "sha256sum"):
			sha := strings.Repeat("a", 64)
			inventory := `{"source_id":"core-source","version":"1","package_sha256":"` + sha + `","execution_proofs":[{"id":"stale-inventory","kind":"installation","outcome":"failed","sha256":"` + strings.Repeat("c", 64) + `"}]}`
			return []byte(inventory + executionProofsMarker + "PROOF\trun-canonical\t" + proofSHA256 + "\t" + proofJSON + "\n"), nil, nil
		default:
			return base(name, args)
		}
	}

	transport := newSSHTransportAt(t.TempDir(), runner)
	key := testHostObservation(4)
	observed, err := transport.Inspect(context.Background(), session{
		endpoint:     endpoint{Address: "203.0.113.11", SSHUser: "dev"},
		HostKey:      key.PublicKey,
		IdentitySeed: bytes.Repeat([]byte{6}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(observed.Core.ExecutionProofs) != 1 {
		t.Fatalf("execution proofs = %#v", observed.Core.ExecutionProofs)
	}
	proof := observed.Core.ExecutionProofs[0]
	if proof.ID != "run-canonical" || proof.Kind != "migration" || proof.Outcome != "success" || proof.SHA256 != proofSHA256 {
		t.Fatalf("execution proof = %#v", proof)
	}
}

func TestExecutionProofObservationRejectsHashMismatch(t *testing.T) {
	const proofJSON = `{"bundle_id":"bundle-canonical","bundle_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","format_version":1,"kind":"migration","run_id":"run-canonical","status":"success"}`
	_, err := parseExecutionProofFacts([]byte("PROOF\trun-canonical\t" + strings.Repeat("b", 64) + "\t" + proofJSON + "\n"))
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("hash mismatch error = %v", err)
	}
}
