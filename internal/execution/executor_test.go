package execution

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/privat655/VPSmith/internal/executionbundle"
)

type fakeTarget struct {
	observations []Observation
	observeErr   error
	uploads      int
	starts       int
	secretCalls  int
	secretValues [][]SecretValue
	startRequest StartRequest
}

func (f *fakeTarget) Upload(context.Context, string, executionbundle.Bundle) error {
	f.uploads++
	return nil
}
func (f *fakeTarget) Start(_ context.Context, _ string, request StartRequest) error {
	f.starts++
	f.startRequest = request
	return nil
}
func (f *fakeTarget) Observe(context.Context, string, string) (Observation, error) {
	if f.observeErr != nil {
		return Observation{}, f.observeErr
	}
	if len(f.observations) == 0 {
		return Observation{}, nil
	}
	v := f.observations[0]
	if len(f.observations) > 1 {
		f.observations = f.observations[1:]
	}
	return v, nil
}
func (f *fakeTarget) SendSecrets(_ context.Context, _, _ string, values []SecretValue) error {
	f.secretCalls++
	copyValues := make([]SecretValue, len(values))
	for i := range values {
		copyValues[i] = SecretValue{ID: values[i].ID, Value: append([]byte(nil), values[i].Value...)}
	}
	f.secretValues = append(f.secretValues, copyValues)
	return nil
}

type fakeSecrets map[string][]byte

func (f fakeSecrets) Resolve(_ context.Context, id string, consume func([]byte) error) error {
	v, ok := f[id]
	if !ok {
		return errors.New("missing")
	}
	return consume(append([]byte(nil), v...))
}

type fakeHistory struct{ started, finished int }

func (f *fakeHistory) RegisterBundle(context.Context, Run) error  { f.started++; return nil }
func (f *fakeHistory) Finished(context.Context, Run, Proof) error { f.finished++; return nil }

func testBundle(t *testing.T) executionbundle.Bundle {
	t.Helper()
	assembler, err := executionbundle.NewAssembler(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := assembler.Assemble(executionbundle.Input{
		Kind:            executionbundle.Installation,
		TargetID:        "target_1",
		SubjectKind:     "module",
		SubjectID:       "module_1",
		SubjectIdentity: "test",
		Version:         "1.0.0",
		Secrets: []executionbundle.SecretReference{
			{SecretID: "secret_b", Container: "module_1/app", Delivery: "environment", Target: "B"},
			{SecretID: "secret_a", Container: "module_1/app", Delivery: "environment", Target: "A"},
			{SecretID: "secret_a", Container: "module_1/worker", Delivery: "environment", Target: "A"},
		},
		ExpectedPost: map[string]any{"artifacts": map[string]string{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func proofFor(bundle executionbundle.Bundle, status Status, phase string) *Proof {
	return &Proof{
		RunID: "run_1", BundleID: bundle.ID, BundleSHA256: bundle.SHA256,
		TargetID: "target_1", Status: status, Phase: phase,
	}
}

func newTestExecutor(t *testing.T, target Target, secrets fakeSecrets, history *fakeHistory) *Executor {
	t.Helper()
	e, err := New(target, secrets, history, Options{PollInterval: time.Microsecond, NewRunID: func() (string, error) { return "run_1", nil }})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestExecuteDeliversSecretsOnlyAfterVerifiedRunnerRequestsThem(t *testing.T) {
	bundle := testBundle(t)
	target := &fakeTarget{observations: []Observation{
		{Proof: proofFor(bundle, StatusRunning, "preconditions"), LockHeld: true},
		{Proof: proofFor(bundle, StatusRunning, "awaiting-secrets"), LockHeld: true},
		{Proof: proofFor(bundle, StatusSuccess, "finished")},
	}}
	history := &fakeHistory{}
	e := newTestExecutor(t, target, fakeSecrets{"secret_a": []byte("A"), "secret_b": []byte("B")}, history)
	got, err := e.Execute(context.Background(), "target_1", bundle)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusSuccess {
		t.Fatalf("status=%s", got.Status)
	}
	if target.secretCalls != 1 {
		t.Fatalf("secret calls=%d", target.secretCalls)
	}
	if len(target.secretValues[0]) != 2 || target.secretValues[0][0].ID != "secret_a" || target.secretValues[0][1].ID != "secret_b" {
		t.Fatalf("secret delivery is not unique and deterministic: %#v", target.secretValues[0])
	}
	if history.started != 1 || history.finished != 1 {
		t.Fatalf("history started=%d finished=%d", history.started, history.finished)
	}
}

func TestExecuteUsesRunnerIdentityParsedFromHashedBundleBytes(t *testing.T) {
	bundle := testBundle(t)
	verified, err := executionbundle.Verify(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Manifest.Runner.Path = "actions/attacker.sh"
	bundle.Manifest.Runner.SHA256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	target := &fakeTarget{observations: []Observation{{Proof: proofFor(bundle, StatusSuccess, "finished")}}}
	e := newTestExecutor(t, target, fakeSecrets{}, &fakeHistory{})
	if _, err := e.Execute(context.Background(), "target_1", bundle); err != nil {
		t.Fatal(err)
	}
	if target.startRequest.Runner != verified.Runner {
		t.Fatalf("start used mutable manifest runner %#v; want verified %#v", target.startRequest.Runner, verified.Runner)
	}
}

func TestExecuteTransportLossReturnsUnknownAndNeverRestarts(t *testing.T) {
	bundle := testBundle(t)
	target := &fakeTarget{observeErr: errors.New("ssh disconnected")}
	e := newTestExecutor(t, target, fakeSecrets{}, &fakeHistory{})
	got, err := e.Execute(context.Background(), "target_1", bundle)
	if !errors.Is(err, ErrStatusUnknown) {
		t.Fatalf("err=%v", err)
	}
	if got.Status != StatusUnknown {
		t.Fatalf("status=%s", got.Status)
	}
	if target.starts != 1 {
		t.Fatalf("starts=%d; expected exactly one", target.starts)
	}
}

func TestReconcileClassifiesInterruptedRunWithoutRetry(t *testing.T) {
	target := &fakeTarget{observations: []Observation{{Proof: &Proof{
		RunID: "run_1", BundleID: "bundle_abc", BundleSHA256: "sha", TargetID: "target_1", Status: StatusRunning, Phase: "steps",
	}}}}
	e := newTestExecutor(t, target, fakeSecrets{}, &fakeHistory{})
	got, err := e.Reconcile(context.Background(), "target_1", "run_1", "bundle_abc", "sha")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusInterrupted {
		t.Fatalf("status=%s", got.Status)
	}
	if target.starts != 0 {
		t.Fatalf("reconcile restarted execution")
	}
}

func TestReconcileRejectsProofIdentityMismatch(t *testing.T) {
	target := &fakeTarget{observations: []Observation{{Proof: &Proof{
		RunID: "run_other", BundleID: "bundle_abc", BundleSHA256: "sha", TargetID: "target_1", Status: StatusSuccess,
	}}}}
	e := newTestExecutor(t, target, fakeSecrets{}, &fakeHistory{})
	if _, err := e.Reconcile(context.Background(), "target_1", "run_1", "bundle_abc", "sha"); err == nil {
		t.Fatal("expected proof identity mismatch")
	}
}

func TestExecuteRejectsWrongTargetBeforeUpload(t *testing.T) {
	bundle := testBundle(t)
	target := &fakeTarget{}
	e := newTestExecutor(t, target, fakeSecrets{}, &fakeHistory{})
	if _, err := e.Execute(context.Background(), "target_2", bundle); err == nil {
		t.Fatal("expected target mismatch")
	}
	if target.uploads != 0 || target.starts != 0 {
		t.Fatal("wrong-target bundle reached transport")
	}
}

func TestExecuteRejectsCorruptedBundleBeforeTransport(t *testing.T) {
	bundle := testBundle(t)
	target := &fakeTarget{}
	e := newTestExecutor(t, target, fakeSecrets{}, &fakeHistory{})
	bundle.Bytes = append([]byte(nil), bundle.Bytes...)
	bundle.Bytes[len(bundle.Bytes)/2] ^= 0x01
	if _, err := e.Execute(context.Background(), "target_1", bundle); err == nil {
		t.Fatal("expected local bundle sha256 mismatch")
	}
	if target.uploads != 0 || target.starts != 0 {
		t.Fatal("corrupted bundle reached target transport")
	}
}

func TestExecuteAmbiguousStartRequiresReconcile(t *testing.T) {
	bundle := testBundle(t)
	target := &startErrorTarget{fakeTarget: fakeTarget{}, err: errors.New("ssh lost after request")}
	e := newTestExecutor(t, target, fakeSecrets{}, &fakeHistory{})
	got, err := e.Execute(context.Background(), "target_1", bundle)
	if !errors.Is(err, ErrStatusUnknown) {
		t.Fatalf("err=%v", err)
	}
	if got.Status != StatusUnknown || target.starts != 1 {
		t.Fatalf("run=%#v starts=%d", got, target.starts)
	}
}

type startErrorTarget struct {
	fakeTarget
	err error
}

func (f *startErrorTarget) Start(context.Context, string, StartRequest) error {
	f.starts++
	return f.err
}

func TestExecuteStartedRunWithoutProofRequiresReconcile(t *testing.T) {
	bundle := testBundle(t)
	target := &fakeTarget{observations: []Observation{{}}}
	e := newTestExecutor(t, target, fakeSecrets{}, &fakeHistory{})
	got, err := e.Execute(context.Background(), "target_1", bundle)
	if !errors.Is(err, ErrStatusUnknown) {
		t.Fatalf("err=%v", err)
	}
	if got.Status != StatusUnknown || target.starts != 1 {
		t.Fatalf("run=%#v starts=%d", got, target.starts)
	}
}

func TestReconcileImportsTerminalTargetProofIntoLocalHistory(t *testing.T) {
	history := &fakeHistory{}
	target := &fakeTarget{observations: []Observation{{Proof: &Proof{
		RunID: "run_1", BundleID: "bundle_abc", BundleSHA256: "sha", TargetID: "target_1",
		Status: StatusSuccess, Phase: "finished", StartedAt: "2026-08-16T10:00:00Z", FinishedAt: "2026-08-16T10:00:01Z",
	}}}}
	e := newTestExecutor(t, target, fakeSecrets{}, history)
	got, err := e.Reconcile(context.Background(), "target_1", "run_1", "bundle_abc", "sha")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusSuccess || history.finished != 1 {
		t.Fatalf("reconcile status=%s finished-history=%d", got.Status, history.finished)
	}
}
