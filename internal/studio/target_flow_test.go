package studio

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/bootstrap"
	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/targetgateway"
)

type fakeTargetApplication struct {
	observeCalls int
	confirmCalls int
	enrollCalls int
	addressCalls int
	trusted bool
	observation targetgateway.HostKeyObservation
}

func (f *fakeTargetApplication) PrepareNewTarget(context.Context, bootstrap.NewTargetRequest) (bootstrap.PreparedTarget, error) { return bootstrap.PreparedTarget{}, errors.New("unused") }
func (f *fakeTargetApplication) SetTargetAddress(context.Context, managementstate.TargetID, string) error { f.addressCalls++; return nil }
func (f *fakeTargetApplication) ObserveHostKey(context.Context, managementstate.TargetID) (targetgateway.HostKeyObservation, error) { f.observeCalls++; return f.observation, nil }
func (f *fakeTargetApplication) ConfirmHostKey(_ context.Context, _ managementstate.TargetID, got targetgateway.HostKeyObservation) error {
	f.confirmCalls++
	if got != f.observation { return errors.New("different observation") }
	f.trusted = true
	return nil
}
func (f *fakeTargetApplication) Enroll(context.Context, managementstate.TargetID) (targetgateway.EnrollmentResult, error) {
	f.enrollCalls++
	if !f.trusted { return targetgateway.EnrollmentResult{}, targetgateway.ErrTrustRequired }
	return targetgateway.EnrollmentResult{}, nil
}

func TestTOFUObservationCannotImplicitlyConfirmOrEnroll(t *testing.T) {
	app := &fakeTargetApplication{observation: targetgateway.HostKeyObservation{Algorithm: "ssh-ed25519", PublicKey: "ssh-ed25519 AAAA", Fingerprint: "SHA256:test"}}
	handler := Handler(BuildIdentity{}, app)

	observe := httptest.NewRequest(http.MethodPost, "/api/targets/target_test/host-key/observe", strings.NewReader(`{"address":"203.0.113.10"}`))
	observe.Header.Set("Content-Type", "application/json")
	observeResult := httptest.NewRecorder()
	handler.ServeHTTP(observeResult, observe)
	if observeResult.Code != http.StatusOK { t.Fatalf("observe status=%d body=%s", observeResult.Code, observeResult.Body.String()) }
	if app.observeCalls != 1 || app.addressCalls != 1 || app.confirmCalls != 0 || app.trusted { t.Fatalf("observe mutated trust: %#v", app) }

	enroll := httptest.NewRequest(http.MethodPost, "/api/targets/target_test/enroll", strings.NewReader(`{}`))
	enroll.Header.Set("Content-Type", "application/json")
	enrollResult := httptest.NewRecorder()
	handler.ServeHTTP(enrollResult, enroll)
	if enrollResult.Code != http.StatusPreconditionRequired || app.confirmCalls != 0 { t.Fatalf("enroll before confirm status=%d confirmCalls=%d", enrollResult.Code, app.confirmCalls) }

	confirm := httptest.NewRequest(http.MethodPost, "/api/targets/target_test/host-key/confirm", strings.NewReader(`{"algorithm":"ssh-ed25519","public_key":"ssh-ed25519 AAAA","fingerprint":"SHA256:test"}`))
	confirm.Header.Set("Content-Type", "application/json")
	confirmResult := httptest.NewRecorder()
	handler.ServeHTTP(confirmResult, confirm)
	if confirmResult.Code != http.StatusOK || app.confirmCalls != 1 || !app.trusted { t.Fatalf("explicit confirm failed status=%d calls=%d", confirmResult.Code, app.confirmCalls) }

	enrollAfter := httptest.NewRequest(http.MethodPost, "/api/targets/target_test/enroll", strings.NewReader(`{}`))
	enrollAfter.Header.Set("Content-Type", "application/json")
	enrollAfterResult := httptest.NewRecorder()
	handler.ServeHTTP(enrollAfterResult, enrollAfter)
	if enrollAfterResult.Code != http.StatusOK { t.Fatalf("enroll after confirm status=%d body=%s", enrollAfterResult.Code, enrollAfterResult.Body.String()) }
}
