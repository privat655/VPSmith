package targetgateway

import (
	"context"
	"errors"

	"github.com/privat655/VPSmith/internal/execution"
	"github.com/privat655/VPSmith/internal/executionbundle"
	"github.com/privat655/VPSmith/internal/managementstate"
)

const secretStreamMagic = "VPSMITH-SECRETS-1\n"

type executionTransport interface {
	UploadExecution(context.Context, session, executionbundle.Bundle) error
	StartExecution(context.Context, session, execution.StartRequest) error
	ObserveExecution(context.Context, session, string) (execution.Observation, error)
	SendExecutionSecrets(context.Context, session, string, []execution.SecretValue) error
}

type executionTarget struct{ gateway *Gateway }

// NewExecutionTarget exposes only the transport operations required by the
// deep execution module. The general Gateway does not gain an arbitrary
// structural mutation surface.
func NewExecutionTarget(gateway *Gateway) (execution.Target, error) {
	if gateway == nil {
		return nil, errors.New("target gateway is required")
	}
	return &executionTarget{gateway: gateway}, nil
}

// Upload transfers one immutable execution bundle to the target selected by the
// already-confirmed SSH session. Existing bytes are accepted only when their
// SHA-256 is identical; a historical bundle is never overwritten.
func (a *executionTarget) Upload(ctx context.Context, targetID string, bundle executionbundle.Bundle) error {
	if targetID == "" {
		return errors.New("target id is required")
	}
	manifest, err := executionbundle.Verify(bundle)
	if err != nil {
		return err
	}
	if manifest.TargetID != targetID {
		return errors.New("execution bundle belongs to another target")
	}
	sess, err := a.gateway.strictSession(ctx, managementstate.TargetID(targetID))
	if err != nil {
		return err
	}
	defer zero(sess.IdentitySeed)
	transport, ok := a.gateway.transport.(executionTransport)
	if !ok {
		return errors.New("target transport does not support execution bundles")
	}
	return transport.UploadExecution(ctx, sess, bundle)
}

// Start requests exactly one detached target-side run. Any transport error is
// intentionally ambiguous to callers: execution.Executor will reconcile the
// run before a later retry rather than issuing a second blind start.
func (a *executionTarget) Start(ctx context.Context, targetID string, request execution.StartRequest) error {
	if targetID == "" || request.TargetID != targetID || !safeExecutionID(request.RunID) || !safeExecutionID(request.BundleID) {
		return errors.New("invalid execution start identity")
	}
	if !validSHA256(request.BundleSHA256) || !validSHA256(request.Runner.SHA256) || !safeBundlePath(request.Runner.Path) || request.Runner.Version == "" {
		return errors.New("invalid execution start integrity identity")
	}
	sess, err := a.gateway.strictSession(ctx, managementstate.TargetID(targetID))
	if err != nil {
		return err
	}
	defer zero(sess.IdentitySeed)
	transport, ok := a.gateway.transport.(executionTransport)
	if !ok {
		return errors.New("target transport does not support execution bundles")
	}
	return transport.StartExecution(ctx, sess, request)
}

func (a *executionTarget) Observe(ctx context.Context, targetID, runID string) (execution.Observation, error) {
	if targetID == "" || !safeExecutionID(runID) {
		return execution.Observation{}, errors.New("invalid execution observation identity")
	}
	sess, err := a.gateway.strictSession(ctx, managementstate.TargetID(targetID))
	if err != nil {
		return execution.Observation{}, err
	}
	defer zero(sess.IdentitySeed)
	transport, ok := a.gateway.transport.(executionTransport)
	if !ok {
		return execution.Observation{}, errors.New("target transport does not support execution bundles")
	}
	return transport.ObserveExecution(ctx, sess, runID)
}

func (a *executionTarget) SendSecrets(ctx context.Context, targetID, runID string, values []execution.SecretValue) error {
	if targetID == "" || !safeExecutionID(runID) {
		return errors.New("invalid execution secret target")
	}
	sess, err := a.gateway.strictSession(ctx, managementstate.TargetID(targetID))
	if err != nil {
		return err
	}
	defer zero(sess.IdentitySeed)
	transport, ok := a.gateway.transport.(executionTransport)
	if !ok {
		return errors.New("target transport does not support execution bundles")
	}
	return transport.SendExecutionSecrets(ctx, sess, runID, values)
}
