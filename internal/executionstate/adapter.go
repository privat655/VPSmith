package executionstate

import (
	"context"
	"errors"
	"fmt"

	"github.com/privat655/VPSmith/internal/execution"
	"github.com/privat655/VPSmith/internal/managementstate"
)

// Adapter imports target-side execution facts into the local append-only
// management history and resolves secret IDs without exposing secret material
// outside the caller-provided callback.
type Adapter struct {
	store *managementstate.Store
}

func New(store *managementstate.Store) (*Adapter, error) {
	if store == nil {
		return nil, errors.New("management state is required")
	}
	return &Adapter{store: store}, nil
}

func (a *Adapter) Resolve(ctx context.Context, id string, consume func([]byte) error) error {
	if id == "" || consume == nil {
		return errors.New("secret id and consumer are required")
	}
	return a.store.ResolveSecret(ctx, managementstate.SecretID(id), func(material managementstate.SecretMaterial) error {
		value := material.Bytes()
		defer zero(value)
		return consume(value)
	})
}

// Started registers the immutable bundle metadata if it is not already known.
// The canonical in-flight state lives on the target proof; local execution
// record metadata is appended only when that proof reaches a terminal state.
func (a *Adapter) RegisterBundle(ctx context.Context, run execution.Run) error {
	snapshot, err := a.store.Snapshot(ctx)
	if err != nil {
		return err
	}
	for _, existing := range snapshot.ExecutionBundles {
		if existing.ID != managementstate.ExecutionBundleID(run.BundleID) {
			continue
		}
		if existing.TargetID != managementstate.TargetID(run.TargetID) || existing.SHA256 != run.BundleSHA256 || existing.Kind != run.Kind || existing.Version != run.Version {
			return fmt.Errorf("execution bundle %s already exists with different immutable metadata", run.BundleID)
		}
		return nil
	}
	return a.store.Change(ctx, func(change *managementstate.Change) error {
		return change.AppendExecutionBundle(managementstate.ExecutionBundleMetadata{
			ID:       managementstate.ExecutionBundleID(run.BundleID),
			TargetID: managementstate.TargetID(run.TargetID),
			Kind:     run.Kind,
			Version:  run.Version,
			SHA256:   run.BundleSHA256,
		})
	})
}

func (a *Adapter) Finished(ctx context.Context, run execution.Run, proof execution.Proof) error {
	if proof.RunID != run.ID || proof.BundleID != run.BundleID || proof.BundleSHA256 != run.BundleSHA256 || proof.TargetID != run.TargetID {
		return errors.New("target execution proof does not match local run identity")
	}
	if proof.Status != execution.StatusSuccess && proof.Status != execution.StatusFailed {
		return errors.New("only terminal target proofs may enter immutable local history")
	}
	snapshot, err := a.store.Snapshot(ctx)
	if err != nil {
		return err
	}
	for _, existing := range snapshot.ExecutionRecords {
		if existing.ID != managementstate.ExecutionRecordID(run.ID) {
			continue
		}
		if existing.BundleID != managementstate.ExecutionBundleID(run.BundleID) || existing.TargetID != managementstate.TargetID(run.TargetID) || existing.Outcome != string(proof.Status) || existing.StartedAt != proof.StartedAt || existing.FinishedAt != proof.FinishedAt {
			return fmt.Errorf("execution record %s already exists with different immutable metadata", run.ID)
		}
		return nil
	}
	return a.store.Change(ctx, func(change *managementstate.Change) error {
		return change.AppendExecutionRecord(managementstate.ExecutionRecordMetadata{
			ID:         managementstate.ExecutionRecordID(run.ID),
			BundleID:   managementstate.ExecutionBundleID(run.BundleID),
			TargetID:   managementstate.TargetID(run.TargetID),
			Outcome:    string(proof.Status),
			StartedAt:  proof.StartedAt,
			FinishedAt: proof.FinishedAt,
		})
	})
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
