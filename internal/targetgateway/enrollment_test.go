package targetgateway

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/privat655/VPSmith/internal/managementstate"
)

type enrollmentProcessRunner struct {
	name string
	args []string
}

func (r *enrollmentProcessRunner) Run(_ context.Context, name string, args ...string) ([]byte, []byte, error) {
	r.name = name
	r.args = append([]string(nil), args...)
	return nil, nil, nil
}

func validPrimaryHardening() PrimaryHardeningFacts {
	return PrimaryHardeningFacts{RootPasswordLocked: true, SSHConfigValid: true, SSHValues: map[string]string{
		"permitrootlogin": "no", "passwordauthentication": "no", "kbdinteractiveauthentication": "no",
		"pubkeyauthentication": "yes", "authenticationmethods": "publickey", "permitemptypasswords": "no",
		"logingracetime": "20", "maxauthtries": "3", "maxsessions": "3", "maxstartups": "10:30:60",
		"x11forwarding": "no", "allowagentforwarding": "no", "allowtcpforwarding": "no",
		"allowstreamlocalforwarding": "no", "permittunnel": "no", "gatewayports": "no",
		"permituserenvironment": "no", "compression": "no", "loglevel": "verbose",
	}, UFWActive: true, UFWDefaultIncoming: "deny", UFWDefaultOutgoing: "allow", UFWDefaultRouted: "deny", UFWLoggingLow: true,
		UFWAllowedPublicTCPPorts: []int{443, 22, 80}, Fail2banSSHActive: true, Fail2banRecidiveActive: true,
		UnattendedUpgradesEnabled: true, AutomaticRebootDisabled: true}
}

func enrolledObserved() managementstate.ObservedState {
	return managementstate.ObservedState{
		Host:      managementstate.HostObservedState{PrimaryHardening: validPrimaryHardening()},
		CloudInit: managementstate.CloudInitObservedState{Present: true, Status: "ok", Version: "cloud-init-v1", FinishedAt: "2026-08-17T00:00:00Z"},
		Modules:   []managementstate.ModuleObservedState{},
	}
}

func enrollmentGateway(t *testing.T, observed managementstate.ObservedState, facts PrimaryHardeningFacts) (*Gateway, context.Context) {
	t.Helper()
	ctx := context.Background()
	store := newTargetStore(t, "target-a")
	if err := store.Change(ctx, func(change *managementstate.Change) error {
		return change.SetDesiredState("target-a", managementstate.DesiredState{CloudInit: managementstate.CloudInitDesiredState{DefinitionVersion: "cloud-init-v1"}})
	}); err != nil {
		t.Fatal(err)
	}
	observed.Host.PrimaryHardening = facts
	key := testHostObservation(1)
	remote := &fakeTransport{offered: key, facts: observed}
	gateway := newGateway(store, remote, time.Now)
	if _, err := gateway.EnsureIdentity(ctx, "target-a"); err != nil {
		t.Fatal(err)
	}
	if err := gateway.ConfirmHostKey(ctx, "target-a", key); err != nil {
		t.Fatal(err)
	}
	return gateway, ctx
}

func TestEnrollRequiresStatusDesiredVersionAndEffectiveHardeningAndLeavesCoreAbsent(t *testing.T) {
	gateway, ctx := enrollmentGateway(t, enrolledObserved(), validPrimaryHardening())
	result, err := gateway.Enroll(ctx, "target-a")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Observed.CloudInit.Present || result.Observed.Core.Present || len(result.Observed.Modules) != 0 {
		t.Fatalf("unexpected enrolled state: %#v", result.Observed)
	}
	if !result.Observed.Host.PrimaryHardening.RootPasswordLocked || !result.Observed.Host.PrimaryHardening.SSHConfigValid || !result.PrimaryHardening.Fail2banRecidiveActive {
		t.Fatalf("canonical Primary Host Hardening facts missing: %#v", result)
	}
}

func TestEnrollRejectsSuccessfulStatusWithWrongVersion(t *testing.T) {
	observed := enrolledObserved()
	observed.CloudInit.Version = "other"
	gateway, ctx := enrollmentGateway(t, observed, validPrimaryHardening())
	_, err := gateway.Enroll(ctx, "target-a")
	if err == nil || !strings.Contains(err.Error(), "does not match desired version") {
		t.Fatalf("error=%v", err)
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

func TestEnrollRejectsUnlockedRootOrUnexpectedFirewallAllow(t *testing.T) {
	facts := validPrimaryHardening()
	facts.RootPasswordLocked = false
	gateway, ctx := enrollmentGateway(t, enrolledObserved(), facts)
	if _, err := gateway.Enroll(ctx, "target-a"); err == nil || !strings.Contains(err.Error(), "root password") {
		t.Fatalf("unlocked root accepted: %v", err)
	}
	facts = validPrimaryHardening()
	facts.UFWUnexpectedPublicAllow = true
	gateway, ctx = enrollmentGateway(t, enrolledObserved(), facts)
	if _, err := gateway.Enroll(ctx, "target-a"); err == nil {
		t.Fatal("unexpected public UFW allow accepted")
	}
}

func TestEnrollRejectsWrongOutgoingUFWDefault(t *testing.T) {
	facts := validPrimaryHardening()
	facts.UFWDefaultOutgoing = "deny"
	gateway, ctx := enrollmentGateway(t, enrolledObserved(), facts)
	if _, err := gateway.Enroll(ctx, "target-a"); err == nil {
		t.Fatal("wrong outgoing UFW default accepted")
	}
}

func TestEnrollRejectsMissingUFWLoggingOrRecidive(t *testing.T) {
	facts := validPrimaryHardening()
	facts.UFWLoggingLow = false
	gateway, ctx := enrollmentGateway(t, enrolledObserved(), facts)
	if _, err := gateway.Enroll(ctx, "target-a"); err == nil {
		t.Fatal("missing UFW logging accepted")
	}
	facts = validPrimaryHardening()
	facts.Fail2banRecidiveActive = false
	gateway, ctx = enrollmentGateway(t, enrolledObserved(), facts)
	if _, err := gateway.Enroll(ctx, "target-a"); err == nil {
		t.Fatal("missing fail2ban recidive accepted")
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

func TestPrimaryHardeningInspectionUsesReadOnlySudoAndCompleteEffectiveProbe(t *testing.T) {
	runner := &enrollmentProcessRunner{}
	transport := newSSHTransportAt(t.TempDir(), runner)
	_, err := transport.InspectPrimaryHardening(context.Background(), session{
		endpoint:     endpoint{Address: "127.0.0.1:2222", SSHUser: "vpsmith"},
		HostKey:      "ssh-ed25519 AAAA",
		IdentitySeed: make([]byte, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	if runner.name != "ssh" || len(runner.args) == 0 {
		t.Fatalf("runner call = %s %#v", runner.name, runner.args)
	}
	remoteCommand := runner.args[len(runner.args)-1]
	for _, want := range []string{"sudo -n sh -eu -c", "getent shadow root", "root_locked", "user='", "authenticationmethods", "logingracetime", "maxauthtries", "maxsessions", "maxstartups", "compression", "loglevel", "ufw_defaults", "ufw_forwarding", "ufw_logging_low", "ufw_unexpected_allow", "fail2ban-client status recidive"} {
		if !strings.Contains(remoteCommand, want) {
			t.Fatalf("primary hardening probe missing %q: %q", want, remoteCommand)
		}
	}
}
