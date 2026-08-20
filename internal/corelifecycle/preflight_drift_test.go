package corelifecycle

import (
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/managementstate"
)

func TestRequireSteadyCoreBeforeMutationRejectsEffectiveDrift(t *testing.T) {
	_, observed := validCorePostState()
	observed.Host.RootFilesystem.AvailableBytes = 20 << 30
	snapshot := managementstate.Snapshot{Sources: managementstate.SourceState{Artifacts: []managementstate.SourceArtifact{{
		ID: "core-source", Kind: managementstate.SourceCore, Version: "1.0.0", SHA256: strings.Repeat("a", 64),
	}}}}
	target := managementstate.Target{Desired: managementstate.DesiredState{Core: managementstate.CoreDesiredState{
		SourceID: "core-source", Version: "1.0.0", CoreContract: "1",
		Swap: managementstate.SwapDesiredState{Mode: "swapfile", SizeGiB: 2},
	}}}

	if err := requireSteadyCoreBeforeMutation(snapshot, target, observed, deployment.Update); err != nil {
		t.Fatalf("steady Core rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*managementstate.ObservedState)
		want   string
	}{
		{"source", func(v *managementstate.ObservedState) { v.Core.SourceID = "other" }, "identity drift"},
		{"secondary", func(v *managementstate.ObservedState) { v.Host.SecondaryHardening.AuditdActive = false }, "Secondary Host Hardening"},
		{"runtime", func(v *managementstate.ObservedState) { v.Core.Caddy.Running = false }, "runtime"},
		{"listener", func(v *managementstate.ObservedState) { v.Host.Listeners[2].Public = true; v.Host.Listeners[2].Loopback = false }, "listener"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, candidate := validCorePostState()
			candidate.Host.RootFilesystem.AvailableBytes = 20 << 30
			tt.mutate(&candidate)
			err := requireSteadyCoreBeforeMutation(snapshot, target, candidate, deployment.Update)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestRequireSteadyCoreBeforeMutationDoesNotBlockRecoveryRestore(t *testing.T) {
	_, observed := validCorePostState()
	observed.Core.Running = false
	observed.Core.Caddy.Running = false
	if err := requireSteadyCoreBeforeMutation(managementstate.Snapshot{}, managementstate.Target{}, observed, deployment.Restore); err != nil {
		t.Fatalf("restore was blocked by steady-state gate: %v", err)
	}
}
