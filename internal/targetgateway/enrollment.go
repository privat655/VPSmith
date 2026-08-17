package targetgateway

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/privat655/VPSmith/internal/managementstate"
)

type PrimaryHardeningFacts = managementstate.PrimaryHardeningObservedState

type EnrollmentResult struct {
	Observed         managementstate.ObservedState
	PrimaryHardening PrimaryHardeningFacts
}

// Enroll verifies an already-confirmed TOFU session. It is read-only and
// succeeds only when the atomic status, desired definition and independently
// observed Primary Host Hardening agree.
func (g *Gateway) Enroll(ctx context.Context, targetID managementstate.TargetID) (EnrollmentResult, error) {
	target, err := g.target(ctx, targetID)
	if err != nil {
		return EnrollmentResult{}, err
	}
	sess, err := g.strictSession(ctx, targetID)
	if err != nil {
		return EnrollmentResult{}, err
	}
	defer zero(sess.IdentitySeed)
	observed, err := g.transport.Inspect(ctx, sess)
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("inspect enrollment target: %w", err)
	}
	if err := validateEnrollment(observed, target.Desired.CloudInit); err != nil {
		return EnrollmentResult{}, err
	}
	observed.ObservedAt = g.now().UTC().Format("2006-01-02T15:04:05.999999999Z07:00")
	managementstate.NormalizeObservedState(&observed)
	if err := g.state.Change(ctx, func(change *managementstate.Change) error { return change.RecordObservedState(targetID, observed) }); err != nil {
		return EnrollmentResult{}, fmt.Errorf("record enrolled target inspection: %w", err)
	}
	return EnrollmentResult{Observed: observed, PrimaryHardening: observed.Host.PrimaryHardening}, nil
}

func validateEnrollment(observed managementstate.ObservedState, desired managementstate.CloudInitDesiredState) error {
	facts := observed.Host.PrimaryHardening
	if !observed.CloudInit.Present || observed.CloudInit.Status != "ok" || strings.TrimSpace(observed.CloudInit.Version) == "" || strings.TrimSpace(observed.CloudInit.FinishedAt) == "" {
		return errors.New("cloud-init successful atomic status is required")
	}
	if strings.TrimSpace(desired.DefinitionVersion) == "" || observed.CloudInit.Version != desired.DefinitionVersion {
		return fmt.Errorf("cloud-init observed version %q does not match desired version %q", observed.CloudInit.Version, desired.DefinitionVersion)
	}
	if observed.Core.Present || len(observed.Modules) != 0 {
		return errors.New("enrollment requires Cloud-init only; Core and Modules must be absent")
	}
	required := map[string]string{
		"permitrootlogin": "no", "passwordauthentication": "no", "kbdinteractiveauthentication": "no",
		"pubkeyauthentication": "yes", "authenticationmethods": "publickey", "permitemptypasswords": "no",
		"logingracetime": "20", "maxauthtries": "3", "maxsessions": "3", "maxstartups": "10:30:60",
		"x11forwarding": "no", "allowagentforwarding": "no", "allowtcpforwarding": "no",
		"allowstreamlocalforwarding": "no", "permittunnel": "no", "gatewayports": "no",
		"permituserenvironment": "no", "compression": "no", "loglevel": "verbose",
	}
	if !facts.SSHConfigValid {
		return errors.New("effective ssh configuration is invalid")
	}
	for key, want := range required {
		if strings.ToLower(facts.SSHValues[key]) != want {
			return fmt.Errorf("effective ssh %s must be %s", key, want)
		}
	}
	ports := append([]int(nil), facts.UFWAllowedPublicTCPPorts...)
	sort.Ints(ports)
	if !facts.UFWActive || facts.UFWDefaultIncoming != "deny" || facts.UFWDefaultRouted != "deny" || !facts.UFWLoggingLow || !reflect.DeepEqual(ports, []int{22, 80, 443}) {
		return errors.New("effective UFW policy does not match Primary Host Hardening")
	}
	if !facts.Fail2banSSHActive || !facts.Fail2banRecidiveActive {
		return errors.New("fail2ban ssh and recidive jails must be active")
	}
	if !facts.UnattendedUpgradesEnabled || !facts.AutomaticRebootDisabled {
		return errors.New("automatic security update policy is not effective")
	}
	return nil
}
