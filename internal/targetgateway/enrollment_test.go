package targetgateway

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/privat655/VPSmith/internal/managementstate"
)

type enrollmentTransport struct {
	*fakeTransport
	hardening PrimaryHardeningFacts
}

func (f *enrollmentTransport) InspectPrimaryHardening(context.Context, session) (PrimaryHardeningFacts, error) {
	return f.hardening, nil
}

func validPrimaryHardening() PrimaryHardeningFacts {
	return PrimaryHardeningFacts{SSHConfigValid: true, SSHValues: map[string]string{
		"permitrootlogin": "no", "passwordauthentication": "no", "kbdinteractiveauthentication": "no", "pubkeyauthentication": "yes", "permitemptypasswords": "no", "x11forwarding": "no", "allowagentforwarding": "no", "allowtcpforwarding": "no", "allowstreamlocalforwarding": "no", "permittunnel": "no", "gatewayports": "no", "permituserenvironment": "no",
	}, UFWActive: true, UFWDefaultIncoming: "deny", UFWDefaultRouted: "deny", UFWAllowedPublicTCPPorts: []int{443, 22, 80}, Fail2banSSHActive: true, UnattendedUpgradesEnabled: true, AutomaticRebootDisabled: true}
}

func enrolledObserved() managementstate.ObservedState {
	return managementstate.ObservedState{CloudInit: managementstate.CloudInitObservedState{Present: true, Status: "ok", Version: "cloud-init-v1", FinishedAt: "2026-08-17T00:00:00Z"}, Modules: []managementstate.ModuleObservedState{}}
}

func enrollmentGateway(t *testing.T, observed managementstate.ObservedState, facts PrimaryHardeningFacts) (*Gateway, context.Context) {
	t.Helper()
	ctx := context.Background()
	store := newTargetStore(t, "target-a")
	key := testHostObservation(1)
	remote := &enrollmentTransport{fakeTransport: &fakeTransport{offered: key, facts: observed}, hardening: facts}
	gateway := newGateway(store, remote, time.Now)
	if _, err := gateway.EnsureIdentity(ctx, "target-a"); err != nil {
		t.Fatal(err)
	}
	if err := gateway.ConfirmHostKey(ctx, "target-a", key); err != nil {
		t.Fatal(err)
	}
	return gateway, ctx
}

func TestEnrollRequiresStatusAndEffectiveHardeningAndLeavesCoreAbsent(t *testing.T) {
	gateway, ctx := enrollmentGateway(t, enrolledObserved(), validPrimaryHardening())
	result, err := gateway.Enroll(ctx, "target-a")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Observed.CloudInit.Present || result.Observed.Core.Present || len(result.Observed.Modules) != 0 {
		t.Fatalf("unexpected enrolled state: %#v", result.Observed)
	}
}

func TestEnrollRejectsSuccessfulStatusWhenHardeningIsWrong(t *testing.T) {
	facts := validPrimaryHardening()
	facts.SSHValues["passwordauthentication"] = "yes"
	gateway, ctx := enrollmentGateway(t, enrolledObserved(), facts)
	_, err := gateway.Enroll(ctx, "target-a")
	if err == nil || !strings.Contains(err.Error(), "passwordauthentication") {
		t.Fatalf("error=%v", err)
	}
}

func TestEnrollRejectsHardeningWhenAtomicStatusIsMissing(t *testing.T) {
	observed := enrolledObserved()
	observed.CloudInit = managementstate.CloudInitObservedState{}
	gateway, ctx := enrollmentGateway(t, observed, validPrimaryHardening())
	if _, err := gateway.Enroll(ctx, "target-a"); err == nil {
		t.Fatal("missing status accepted")
	}
}

func TestEnrollRejectsCoreOrModules(t *testing.T) {
	observed := enrolledObserved()
	observed.Core.Present = true
	gateway, ctx := enrollmentGateway(t, observed, validPrimaryHardening())
	if _, err := gateway.Enroll(ctx, "target-a"); err == nil {
		t.Fatal("core present accepted")
	}
	observed = enrolledObserved()
	observed.Modules = []managementstate.ModuleObservedState{{Present: true, InstanceID: "module-a"}}
	gateway, ctx = enrollmentGateway(t, observed, validPrimaryHardening())
	if _, err := gateway.Enroll(ctx, "target-a"); err == nil {
		t.Fatal("module present accepted")
	}
}
