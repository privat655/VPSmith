package targetgateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/privat655/VPSmith/internal/managementstate"
)

const executionProofsMarker = "\nVPSMITH_EXECUTION_PROOFS_V1\n"

type executionProofDocument struct {
	FormatVersion int    `json:"format_version"`
	RunID         string `json:"run_id"`
	BundleID      string `json:"bundle_id"`
	BundleSHA256  string `json:"bundle_sha256"`
	Kind          string `json:"kind"`
	Status        string `json:"status"`
}

// coreObservation reads Core inventory and the runner-owned execution-proof
// store in one read-only SSH operation. The proof store is the canonical source
// for executed-bundle facts; inventory execution_proofs fields are deliberately
// ignored by callers.
func (t *sshTransport) coreObservation(ctx context.Context, sess session) ([]byte, []managementstate.ExecutionProofObservedState, error) {
	const script = `set -eu
root=/var/tmp/vpsmith-execution
if [ -f /var/lib/vpsmith/execution/.active ]; then root=/var/lib/vpsmith/execution; fi
if [ -r /var/lib/vpsmith/inventory/core.json ]; then cat -- /var/lib/vpsmith/inventory/core.json; fi
printf '\nVPSMITH_EXECUTION_PROOFS_V1\n'
for proof in "$root"/proofs/*.json; do
  [ -e "$proof" ] || continue
  [ -f "$proof" ] && [ ! -L "$proof" ] || { echo 'invalid execution proof file' >&2; exit 51; }
  name=${proof##*/}
  run=${name%.json}
  before=$(sha256sum -- "$proof"); before=${before%% *}
  printf 'PROOF\t%s\t%s\t' "$run" "$before"
  cat -- "$proof"
  after=$(sha256sum -- "$proof"); after=${after%% *}
  [ "$before" = "$after" ] || { echo 'execution proof changed during inspection' >&2; exit 52; }
done`

	raw, err := t.runRemote(ctx, sess, "sudo -n sh -eu -c "+shellQuote(script))
	if err != nil {
		return nil, nil, fmt.Errorf("read core inventory and execution proofs: %w", err)
	}
	parts := bytes.SplitN(raw, []byte(executionProofsMarker), 2)
	if len(parts) == 1 {
		// Test/fake transports written before the proof-store contract returned
		// only the inventory document. Production always emits the marker.
		return raw, []managementstate.ExecutionProofObservedState{}, nil
	}
	proofs, err := parseExecutionProofFacts(parts[1])
	if err != nil {
		return nil, nil, err
	}
	return bytes.TrimSpace(parts[0]), proofs, nil
}

func parseExecutionProofFacts(raw []byte) ([]managementstate.ExecutionProofObservedState, error) {
	result := []managementstate.ExecutionProofObservedState{}
	seen := map[string]struct{}{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 4)
		if len(fields) != 4 || fields[0] != "PROOF" {
			return nil, errors.New("invalid execution proof observation output")
		}
		runID, digest, document := fields[1], fields[2], fields[3]
		if !safeExecutionID(runID) || !validSHA256(digest) {
			return nil, errors.New("invalid execution proof identity")
		}
		if _, exists := seen[runID]; exists {
			return nil, errors.New("duplicate execution proof identity")
		}
		seen[runID] = struct{}{}

		hash := sha256.Sum256(append([]byte(document), '\n'))
		if hex.EncodeToString(hash[:]) != digest {
			return nil, errors.New("execution proof sha256 mismatch")
		}
		var proof executionProofDocument
		if err := json.Unmarshal([]byte(document), &proof); err != nil {
			return nil, fmt.Errorf("decode execution proof: %w", err)
		}
		if proof.FormatVersion != 1 || proof.RunID != runID || !safeExecutionID(proof.BundleID) || !validSHA256(proof.BundleSHA256) || strings.TrimSpace(proof.Kind) == "" {
			return nil, errors.New("invalid execution proof document")
		}
		if proof.Status != "success" && proof.Status != "failed" {
			continue
		}
		result = append(result, managementstate.ExecutionProofObservedState{
			ID:           runID,
			BundleID:     proof.BundleID,
			BundleSHA256: proof.BundleSHA256,
			Kind:         proof.Kind,
			Outcome:      proof.Status,
			SHA256:       digest,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
