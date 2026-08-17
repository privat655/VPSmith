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

type PrimaryHardeningFacts struct {
	SSHConfigValid                   bool
	SSHValues                        map[string]string
	UFWActive                        bool
	UFWDefaultIncoming               string
	UFWDefaultRouted                 string
	UFWAllowedPublicTCPPorts         []int
	Fail2banSSHActive                bool
	UnattendedUpgradesEnabled        bool
	AutomaticRebootDisabled          bool
}

type EnrollmentResult struct {
	Observed         managementstate.ObservedState
	PrimaryHardening PrimaryHardeningFacts
}

type primaryHardeningInspector interface {
	InspectPrimaryHardening(context.Context, session) (PrimaryHardeningFacts, error)
}

// Enroll verifies an already-confirmed TOFU session. It is read-only and
// succeeds only when the atomic status and independently observed hardening agree.
func (g *Gateway) Enroll(ctx context.Context, targetID managementstate.TargetID) (EnrollmentResult, error) {
	sess, err := g.strictSession(ctx, targetID)
	if err != nil {
		return EnrollmentResult{}, err
	}
	defer zero(sess.IdentitySeed)
	inspector, ok := g.transport.(primaryHardeningInspector)
	if !ok {
		return EnrollmentResult{}, errors.New("target transport cannot inspect primary hardening")
	}
	observed, err := g.transport.Inspect(ctx, sess)
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("inspect enrollment target: %w", err)
	}
	facts, err := inspector.InspectPrimaryHardening(ctx, sess)
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("inspect primary hardening: %w", err)
	}
	if err := validateEnrollment(observed, facts); err != nil {
		return EnrollmentResult{}, err
	}
	observed.ObservedAt = g.now().UTC().Format("2006-01-02T15:04:05.999999999Z07:00")
	managementstate.NormalizeObservedState(&observed)
	if err := g.state.Change(ctx, func(change *managementstate.Change) error { return change.RecordObservedState(targetID, observed) }); err != nil {
		return EnrollmentResult{}, fmt.Errorf("record enrolled target inspection: %w", err)
	}
	return EnrollmentResult{Observed: observed, PrimaryHardening: facts}, nil
}

func validateEnrollment(observed managementstate.ObservedState, facts PrimaryHardeningFacts) error {
	if !observed.CloudInit.Present || observed.CloudInit.Status != "ok" || strings.TrimSpace(observed.CloudInit.Version) == "" || strings.TrimSpace(observed.CloudInit.FinishedAt) == "" {
		return errors.New("cloud-init successful atomic status is required")
	}
	if observed.Core.Present || len(observed.Modules) != 0 {
		return errors.New("enrollment requires Cloud-init only; Core and Modules must be absent")
	}
	required := map[string]string{
		"permitrootlogin": "no", "passwordauthentication": "no", "kbdinteractiveauthentication": "no",
		"pubkeyauthentication": "yes", "permitemptypasswords": "no", "x11forwarding": "no",
		"allowagentforwarding": "no", "allowtcpforwarding": "no", "allowstreamlocalforwarding": "no",
		"permittunnel": "no", "gatewayports": "no", "permituserenvironment": "no",
	}
	if !facts.SSHConfigValid {
		return errors.New("effective ssh configuration is invalid")
	}
	for key, want := range required {
		if facts.SSHValues[key] != want {
			return fmt.Errorf("effective ssh %s must be %s", key, want)
		}
	}
	ports := append([]int(nil), facts.UFWAllowedPublicTCPPorts...)
	sort.Ints(ports)
	if !facts.UFWActive || facts.UFWDefaultIncoming != "deny" || facts.UFWDefaultRouted != "deny" || !reflect.DeepEqual(ports, []int{22, 80, 443}) {
		return errors.New("effective UFW policy does not match Primary Host Hardening")
	}
	if !facts.Fail2banSSHActive {
		return errors.New("fail2ban ssh jail is not active")
	}
	if !facts.UnattendedUpgradesEnabled || !facts.AutomaticRebootDisabled {
		return errors.New("automatic security update policy is not effective")
	}
	return nil
}
