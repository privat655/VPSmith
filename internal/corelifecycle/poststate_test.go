package corelifecycle

import (
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/executionbundle"
	"github.com/privat655/VPSmith/internal/managementstate"
)

func TestCorePostValidationRequiresEffectiveHostRuntimeContract(t *testing.T) {
	prepared, observed := validCorePostState()
	if err := validatePostState(prepared, observed); err != nil {
		t.Fatalf("valid Core post-state rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*managementstate.ObservedState)
		want   string
	}{
		{"apparmor", func(v *managementstate.ObservedState) { v.Host.SecondaryHardening.AppArmorEnabled = false }, "Secondary Host Hardening"},
		{"journald", func(v *managementstate.ObservedState) { v.Host.SecondaryHardening.JournalSystemMaxUseBytes = 300 << 20 }, "Secondary Host Hardening"},
		{"low ports", func(v *managementstate.ObservedState) { v.Host.SecondaryHardening.UnprivilegedPortStart = 0 }, "Secondary Host Hardening"},
		{"docker", func(v *managementstate.ObservedState) { v.Host.SecondaryHardening.DockerAbsent = false }, "Secondary Host Hardening"},
		{"public high port", func(v *managementstate.ObservedState) {
			v.Host.Listeners[2] = managementstate.ListenerObservedState{Address: "0.0.0.0", Port: 8080, Public: true, Protocol: "tcp"}
		}, "listener"},
		{"missing public https", func(v *managementstate.ObservedState) { v.Host.Listeners = v.Host.Listeners[:3] }, "listener"},
		{"swapfile missing", func(v *managementstate.ObservedState) { v.Host.SwapDevices = nil }, "swap"},
		{"swapfile wrong size", func(v *managementstate.ObservedState) { v.Host.SwapDevices[0].SizeBytes = 1 << 30 }, "swap"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, candidate := validCorePostState()
			tt.mutate(&candidate)
			err := validatePostState(prepared, candidate)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validatePostState() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestCorePostValidationEnforcesAllSwapModes(t *testing.T) {
	prepared, observed := validCorePostState()

	prepared.DesiredCore.Swap = managementstate.SwapDesiredState{Mode: "none"}
	observed.Host.SwapDevices = nil
	if err := validatePostState(prepared, observed); err != nil {
		t.Fatalf("swap=none rejected without active swap: %v", err)
	}
	observed.Host.SwapDevices = []managementstate.SwapDeviceObservedState{{Path: "/dev/vdb", Kind: "partition", SizeBytes: 1 << 30}}
	if err := validatePostState(prepared, observed); err == nil {
		t.Fatal("swap=none accepted active foreign swap")
	}

	prepared.DesiredCore.Swap = managementstate.SwapDesiredState{Mode: "preserve-existing"}
	if err := validatePostState(prepared, observed); err != nil {
		t.Fatalf("preserve-existing rejected one foreign swap: %v", err)
	}
	observed.Host.SwapDevices[0].CoreManaged = true
	if err := validatePostState(prepared, observed); err == nil {
		t.Fatal("preserve-existing accepted Core-managed swap")
	}
}

func validCorePostState() (Prepared, managementstate.ObservedState) {
	const packageSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	primary := managementstate.PrimaryHardeningObservedState{
		RootPasswordLocked: true, SSHConfigValid: true, UFWActive: true,
		Fail2banSSHActive: true, Fail2banRecidiveActive: true,
	}
	secondary := managementstate.SecondaryHardeningObservedState{
		AppArmorEnabled: true, AuditdActive: true, ChronyActive: true,
		JournalPersistent: true, JournalSystemMaxUseBytes: 200 << 20, JournalRuntimeMaxUseBytes: 50 << 20,
		CoredumpDisabled: true, ApportDisabled: true,
		TmpTmpfs: true, TmpNoExec: true, TmpNoSuid: true, TmpNoDev: true,
		BlockedModulesEffective: true, IPv6Disabled: true, UnprivilegedPortStart: 1024,
		DockerAbsent: true, ContainerdAbsent: true, SubUIDRangePresent: true, SubGIDRangePresent: true, LingerEnabled: true,
	}
	prepared := Prepared{
		PrimaryBefore: primary,
		DesiredCore: managementstate.CoreDesiredState{
			SourceID: "core-source", Version: "1.0.0", CoreContract: "1",
			Swap: managementstate.SwapDesiredState{Mode: "swapfile", SizeGiB: 2},
		},
		Operation: deployment.PreparedCoreOperation{PreparedOperation: deployment.PreparedOperation{
			Bundle: executionbundle.Bundle{Manifest: executionbundle.Manifest{PackageSHA256: packageSHA}},
		}},
	}
	observed := managementstate.ObservedState{
		Host: managementstate.HostObservedState{
			Reachable: true, SSH: true, PrimaryHardening: primary, SecondaryHardening: secondary,
			SwapDevices: []managementstate.SwapDeviceObservedState{{Path: "/var/lib/vpsmith/swapfile", Kind: "file", SizeBytes: 2 << 30, CoreManaged: true}},
			Listeners: []managementstate.ListenerObservedState{
				{Address: "0.0.0.0", Port: 80, Public: true, Protocol: "tcp"},
				{Address: "0.0.0.0", Port: 443, Public: true, Protocol: "tcp"},
				{Address: "127.0.0.1", Port: 8080, Loopback: true, Protocol: "tcp"},
				{Address: "127.0.0.1", Port: 8443, Loopback: true, Protocol: "tcp"},
			},
		},
		CloudInit: managementstate.CloudInitObservedState{Present: true, Status: "ok"},
		Core: managementstate.CoreObservedState{
			Present: true, SourceID: "core-source", Version: "1.0.0", PackageSHA256: packageSHA, Running: true,
			Podman:   managementstate.PodmanObservedState{Present: true, Rootless: true, CgroupVersion: "v2", RootlessNetworkCmd: "pasta"},
			Caddy:    managementstate.ServiceObservedState{Present: true, Running: true, ConfigChecked: true, ConfigValid: true},
			Authelia: managementstate.ServiceObservedState{Present: true, Running: true},
		},
	}
	return prepared, observed
}
