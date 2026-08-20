package execution

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/privat655/VPSmith/internal/executionbundle"
)

var ErrStatusUnknown = errors.New("execution status is unknown; reconcile before retry")

type Executor struct {
	target  Target
	secrets Secrets
	history History
	poll    time.Duration
	newID   func() (string, error)
}

func New(target Target, secrets Secrets, history History, opts Options) (*Executor, error) {
	if target == nil {
		return nil, errors.New("execution target is required")
	}
	if secrets == nil {
		return nil, errors.New("secret resolver is required")
	}
	if history == nil {
		return nil, errors.New("execution history is required")
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 100 * time.Millisecond
	}
	if opts.NewRunID == nil {
		opts.NewRunID = randomRunID
	}
	return &Executor{target: target, secrets: secrets, history: history, poll: opts.PollInterval, newID: opts.NewRunID}, nil
}

func (e *Executor) Execute(ctx context.Context, targetID string, bundle executionbundle.Bundle) (Run, error) {
	return e.execute(ctx, targetID, bundle, false)
}

// ExecuteVerifiedCoreRestore is intentionally narrow. Callers may use it only
// after independently verifying and staging the approved Core restore payload.
// The generic Execute entry point refuses the same bundle before upload/start.
func (e *Executor) ExecuteVerifiedCoreRestore(ctx context.Context, targetID string, bundle executionbundle.Bundle) (Run, error) {
	return e.execute(ctx, targetID, bundle, true)
}

func (e *Executor) execute(ctx context.Context, targetID string, bundle executionbundle.Bundle, verifiedCoreRestore bool) (Run, error) {
	manifest, err := validateBundle(targetID, bundle)
	if err != nil {
		return Run{}, err
	}
	if isCoreRestore(manifest) && !verifiedCoreRestore {
		return Run{}, errors.New("Core restore execution requires ExecuteVerifiedCoreRestore after verified payload staging")
	}
	if verifiedCoreRestore && !isCoreRestore(manifest) {
		return Run{}, errors.New("verified Core restore execution requires a Core restore bundle")
	}
	runID, err := e.newID()
	if err != nil {
		return Run{}, fmt.Errorf("allocate execution run id: %w", err)
	}
	run := Run{ID: runID, TargetID: targetID, BundleID: bundle.ID, BundleSHA256: bundle.SHA256, Kind: string(manifest.Kind), Version: manifest.Version, Status: StatusNotStarted}
	if err := e.target.Upload(ctx, targetID, bundle); err != nil {
		return run, fmt.Errorf("upload execution bundle: %w", err)
	}
	if err := e.history.RegisterBundle(ctx, run); err != nil {
		return run, fmt.Errorf("register execution bundle: %w", err)
	}
	if err := e.target.Start(ctx, targetID, StartRequest{
		RunID: runID, BundleID: bundle.ID, BundleSHA256: bundle.SHA256, TargetID: targetID, Runner: manifest.Runner,
	}); err != nil {
		run.Status = StatusUnknown
		return run, fmt.Errorf("start execution bundle: %w: %w", err, ErrStatusUnknown)
	}
	run.Status = StatusRunning
	secretSent := false
	for {
		obs, err := e.target.Observe(ctx, targetID, runID)
		if err != nil {
			run.Status = StatusUnknown
			return run, fmt.Errorf("observe started execution: %w: %w", err, ErrStatusUnknown)
		}
		if err := validateObservationIdentity(run, obs.Proof); err != nil {
			run.Status = StatusUnknown
			return run, err
		}
		run = classify(run, obs)
		if obs.Proof == nil && !obs.LockHeld && !obs.UnitRunning {
			run.Status = StatusUnknown
			return run, fmt.Errorf("started execution disappeared before producing a proof: %w", ErrStatusUnknown)
		}
		if obs.Proof != nil {
			run.Phase = obs.Proof.Phase
		}
		if !secretSent && obs.Proof != nil && obs.Proof.Status == StatusRunning && obs.Proof.Phase == "awaiting-secrets" {
			values, err := e.resolveSecrets(ctx, manifest.Secrets)
			if err != nil {
				return run, err
			}
			err = e.target.SendSecrets(ctx, targetID, runID, values)
			zeroValues(values)
			if err != nil {
				run.Status = StatusUnknown
				return run, fmt.Errorf("deliver execution secrets: %w: %w", err, ErrStatusUnknown)
			}
			secretSent = true
		}
		if obs.Proof != nil && terminal(obs.Proof.Status) {
			if err := e.history.Finished(ctx, run, *obs.Proof); err != nil {
				return run, fmt.Errorf("record finished execution: %w", err)
			}
			if obs.Proof.Status == StatusFailed {
				return run, fmt.Errorf("execution failed: %s", obs.Proof.Error)
			}
			return run, nil
		}
		if run.Status == StatusInterrupted {
			return run, ErrStatusUnknown
		}
		select {
		case <-ctx.Done():
			run.Status = StatusUnknown
			return run, fmt.Errorf("execution wait cancelled: %w: %w", ctx.Err(), ErrStatusUnknown)
		case <-time.After(e.poll):
		}
	}
}

func isCoreRestore(manifest executionbundle.Manifest) bool {
	if manifest.SubjectKind != "core" || manifest.SubjectID != "core" {
		return false
	}
	for _, action := range manifest.Actions {
		if action.ID == "core-restore" {
			return true
		}
	}
	return false
}

func (e *Executor) Reconcile(ctx context.Context, targetID, runID, bundleID, bundleSHA256 string) (Run, error) {
	if targetID == "" || runID == "" || bundleID == "" || bundleSHA256 == "" {
		return Run{}, errors.New("complete execution identity is required")
	}
	run := Run{ID: runID, TargetID: targetID, BundleID: bundleID, BundleSHA256: bundleSHA256, Status: StatusUnknown}
	obs, err := e.target.Observe(ctx, targetID, runID)
	if err != nil {
		return run, fmt.Errorf("reconcile execution: %w", err)
	}
	if obs.Proof != nil {
		if obs.Proof.RunID != runID || obs.Proof.BundleID != bundleID || obs.Proof.BundleSHA256 != bundleSHA256 || obs.Proof.TargetID != targetID {
			return run, errors.New("execution proof identity mismatch")
		}
		run.Phase = obs.Proof.Phase
	}
	run = classify(run, obs)
	if obs.Proof != nil && terminal(obs.Proof.Status) {
		if err := e.history.Finished(ctx, run, *obs.Proof); err != nil {
			return run, fmt.Errorf("record reconciled execution: %w", err)
		}
	}
	return run, nil
}

func (e *Executor) resolveSecrets(ctx context.Context, refs []executionbundle.SecretReference) ([]SecretValue, error) {
	ids := map[string]struct{}{}
	for _, ref := range refs {
		if ref.SecretID == "" {
			return nil, errors.New("bundle contains empty secret id")
		}
		ids[ref.SecretID] = struct{}{}
	}
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	values := make([]SecretValue, 0, len(ordered))
	for _, id := range ordered {
		var copied []byte
		if err := e.secrets.Resolve(ctx, id, func(value []byte) error {
			copied = append([]byte(nil), value...)
			return nil
		}); err != nil {
			zero(copied)
			zeroValues(values)
			return nil, fmt.Errorf("resolve execution secret %s: %w", id, err)
		}
		if len(copied) == 0 {
			zeroValues(values)
			return nil, fmt.Errorf("execution secret %s is empty", id)
		}
		values = append(values, SecretValue{ID: id, Value: copied})
	}
	return values, nil
}

func classify(run Run, obs Observation) Run {
	if obs.Proof == nil {
		if obs.LockHeld || obs.UnitRunning {
			run.Status = StatusRunning
		} else {
			run.Status = StatusNotStarted
		}
		return run
	}
	switch obs.Proof.Status {
	case StatusSuccess, StatusFailed:
		run.Status = obs.Proof.Status
	case StatusRunning:
		if obs.LockHeld || obs.UnitRunning {
			run.Status = StatusRunning
		} else {
			run.Status = StatusInterrupted
		}
	default:
		run.Status = StatusUnknown
	}
	return run
}

func validateBundle(targetID string, bundle executionbundle.Bundle) (executionbundle.Manifest, error) {
	if targetID == "" {
		return executionbundle.Manifest{}, errors.New("target id is required")
	}
	manifest, err := executionbundle.Verify(bundle)
	if err != nil {
		return executionbundle.Manifest{}, err
	}
	if manifest.TargetID != targetID {
		return executionbundle.Manifest{}, errors.New("execution bundle identity does not match target")
	}
	return manifest, nil
}

func validateObservationIdentity(run Run, proof *Proof) error {
	if proof == nil {
		return nil
	}
	if proof.RunID != run.ID || proof.BundleID != run.BundleID || proof.BundleSHA256 != run.BundleSHA256 || proof.TargetID != run.TargetID {
		return errors.New("execution proof identity mismatch")
	}
	return nil
}

func terminal(status Status) bool { return status == StatusSuccess || status == StatusFailed }

func randomRunID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "run_" + hex.EncodeToString(raw[:]), nil
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func zeroValues(values []SecretValue) {
	for i := range values {
		zero(values[i].Value)
	}
}
