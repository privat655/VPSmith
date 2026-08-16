package targetgateway

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/privat655/VPSmith/internal/execution"
	"github.com/privat655/VPSmith/internal/executionbundle"
	"github.com/privat655/VPSmith/internal/managementstate"
)

type step6Transport struct {
	*fakeTransport
	uploads      int
	starts       int
	observations map[string]execution.Observation
	secretCalls  int
	runtimeCalls int
	healthCalls  int
}

func (f *step6Transport) UploadExecution(_ context.Context, sess session, _ executionbundle.Bundle) error {
	if len(sess.IdentitySeed) == 0 || sess.HostKey == "" {
		return errors.New("strict execution session missing")
	}
	f.uploads++
	return nil
}

func (f *step6Transport) StartExecution(_ context.Context, sess session, _ execution.StartRequest) error {
	if len(sess.IdentitySeed) == 0 || sess.HostKey == "" {
		return errors.New("strict execution session missing")
	}
	f.starts++
	return nil
}

func (f *step6Transport) ObserveExecution(_ context.Context, _ session, runID string) (execution.Observation, error) {
	return f.observations[runID], nil
}

func (f *step6Transport) SendExecutionSecrets(_ context.Context, _ session, _ string, _ []execution.SecretValue) error {
	f.secretCalls++
	return nil
}

func (f *step6Transport) ControlModuleRuntime(_ context.Context, _ session, moduleID managementstate.ModuleInstanceID, action RuntimeAction) (RuntimeResult, error) {
	f.runtimeCalls++
	return RuntimeResult{ModuleInstanceID: moduleID, Action: action, Units: []string{"vpsmith-" + string(moduleID) + "-app.service"}}, nil
}

func (f *step6Transport) HealthcheckModule(_ context.Context, _ session, moduleID managementstate.ModuleInstanceID) (HealthcheckResult, error) {
	f.healthCalls++
	return HealthcheckResult{ModuleInstanceID: moduleID, Type: "tcp", Container: "vpsmith-" + string(moduleID) + "-app", Healthy: true}, nil
}

func confirmedStep6Gateway(t *testing.T) (*Gateway, *step6Transport) {
	t.Helper()
	ctx := context.Background()
	store := newTargetStore(t, "target-a")
	key := testHostObservation(13)
	remote := &step6Transport{fakeTransport: &fakeTransport{offered: key}, observations: map[string]execution.Observation{}}
	gateway := newGateway(store, remote, time.Now)
	if _, err := gateway.EnsureIdentity(ctx, "target-a"); err != nil {
		t.Fatal(err)
	}
	if err := gateway.ConfirmHostKey(ctx, "target-a", key); err != nil {
		t.Fatal(err)
	}
	return gateway, remote
}

func TestExecutionTargetUsesStrictGatewayWithoutExpandingGeneralGatewaySurface(t *testing.T) {
	gateway, remote := confirmedStep6Gateway(t)
	target, err := NewExecutionTarget(gateway)
	if err != nil {
		t.Fatal(err)
	}
	assembler, err := executionbundle.NewAssembler(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := assembler.Assemble(executionbundle.Input{
		Kind: executionbundle.Installation, TargetID: "target-a", SubjectKind: "core", SubjectID: "core", SubjectIdentity: "core", Version: "1.0.0",
		ExpectedPost: map[string]any{"artifacts": map[string]string{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := target.Upload(context.Background(), "target-a", bundle); err != nil {
		t.Fatal(err)
	}
	if remote.uploads != 1 {
		t.Fatalf("uploads=%d", remote.uploads)
	}
	if err := target.Start(context.Background(), "target-a", execution.StartRequest{
		RunID: "run_1", BundleID: bundle.ID, BundleSHA256: bundle.SHA256, TargetID: "target-a", Runner: bundle.Manifest.Runner,
	}); err != nil {
		t.Fatal(err)
	}
	if remote.starts != 1 {
		t.Fatalf("starts=%d", remote.starts)
	}
}

func TestRuntimeControllerAcceptsOnlyTypedInventoryBoundModuleOperations(t *testing.T) {
	gateway, remote := confirmedStep6Gateway(t)
	controller, err := NewRuntimeController(gateway)
	if err != nil {
		t.Fatal(err)
	}
	result, err := controller.Control(context.Background(), "target-a", "n8n-1", RuntimeRestart)
	if err != nil {
		t.Fatal(err)
	}
	if result.ModuleInstanceID != "n8n-1" || result.Action != RuntimeRestart || remote.runtimeCalls != 1 {
		t.Fatalf("runtime result=%#v calls=%d", result, remote.runtimeCalls)
	}
	if _, err := controller.Control(context.Background(), "target-a", "n8n-1", RuntimeAction("shell")); err == nil {
		t.Fatal("arbitrary runtime action accepted")
	}
	if remote.runtimeCalls != 1 {
		t.Fatal("invalid runtime action reached transport")
	}
	health, err := controller.Healthcheck(context.Background(), "target-a", "n8n-1")
	if err != nil {
		t.Fatal(err)
	}
	if !health.Healthy || health.ModuleInstanceID != "n8n-1" || remote.healthCalls != 1 {
		t.Fatalf("health=%#v calls=%d", health, remote.healthCalls)
	}
}
