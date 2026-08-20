package corelifecycle

import (
	"errors"
	"fmt"

	"github.com/privat655/VPSmith/internal/managementstate"
)

const (
	expectedJournalSystemMaxUse  int64 = 200 << 20
	expectedJournalRuntimeMaxUse int64 = 50 << 20
)

func requireCoreOwnedPostState(prepared Prepared, observed managementstate.ObservedState) error {
	if err := requireSecondaryHardening(observed.Host.SecondaryHardening); err != nil {
		return err
	}
	if err := requireCoreListeners(observed.Host.Listeners); err != nil {
		return err
	}
	if err := requireSwapPostState(prepared.DesiredCore.Swap, prepared.SwapBefore, observed.Host); err != nil {
		return err
	}
	return nil
}

func requireSecondaryHardening(facts managementstate.SecondaryHardeningObservedState) error {
	if !facts.AppArmorEnabled || !facts.AuditdActive || !facts.ChronyActive ||
		!facts.JournalPersistent || facts.JournalSystemMaxUseBytes != expectedJournalSystemMaxUse || facts.JournalRuntimeMaxUseBytes != expectedJournalRuntimeMaxUse ||
		!facts.CoredumpDisabled || !facts.ApportDisabled ||
		!facts.TmpTmpfs || !facts.TmpNoExec || !facts.TmpNoSuid || !facts.TmpNoDev ||
		!facts.BlockedModulesEffective || !facts.IPv6Disabled || facts.UnprivilegedPortStart != 1024 ||
		!facts.DockerAbsent || !facts.ContainerdAbsent ||
		!facts.SubUIDRangePresent || !facts.SubGIDRangePresent || !facts.LingerEnabled {
		return errors.New("Secondary Host Hardening is not effective")
	}
	return nil
}

func requireCoreListeners(listeners []managementstate.ListenerObservedState) error {
	publicRequired := map[int]bool{80: false, 443: false}
	loopbackRequired := map[int]bool{8080: false, 8443: false}
	for _, listener := range listeners {
		if listener.Protocol != "" && listener.Protocol != "tcp" {
			continue
		}
		if listener.Public {
			switch listener.Port {
			case 22:
				// SSH remains Cloud-init owned and is the only non-Core public listener allowed.
			case 80, 443:
				publicRequired[listener.Port] = true
			default:
				return fmt.Errorf("unexpected public listener on tcp/%d", listener.Port)
			}
		}
		if listener.Port == 8080 || listener.Port == 8443 {
			if !listener.Loopback || listener.Public {
				return fmt.Errorf("Core high-port listener tcp/%d is not loopback-only", listener.Port)
			}
			loopbackRequired[listener.Port] = true
		}
	}
	for port, present := range publicRequired {
		if !present {
			return fmt.Errorf("required public Core listener tcp/%d is missing", port)
		}
	}
	for port, present := range loopbackRequired {
		if !present {
			return fmt.Errorf("required loopback Core listener tcp/%d is missing", port)
		}
	}
	return nil
}

func requireSwapPostState(desired managementstate.SwapDesiredState, before []managementstate.SwapDeviceObservedState, host managementstate.HostObservedState) error {
	swaps := host.SwapDevices
	switch desired.Mode {
	case "none":
		if len(swaps) != 0 {
			return errors.New("swap post-state does not match mode none")
		}
		return nil
	case "preserve-existing":
		if len(before) != 1 || before[0].CoreManaged {
			return errors.New("preserve-existing requires exactly one foreign swap device before execution")
		}
		if len(swaps) != 1 || swaps[0].CoreManaged || !samePreservedSwap(before[0], swaps[0]) {
			return errors.New("swap post-state did not preserve the existing foreign swap device unchanged")
		}
		return nil
	case "swapfile":
		if len(swaps) != 1 || !swaps[0].CoreManaged || swaps[0].Path != "/var/lib/vpsmith/swapfile" {
			return errors.New("swap post-state does not contain exactly one Core-managed swapfile")
		}
		expected := host.Memory.TotalBytes
		if expected > maxAutoSwapBytes {
			expected = maxAutoSwapBytes
		}
		if desired.SizeGiB > 0 {
			expected = int64(desired.SizeGiB) << 30
		}
		if expected <= 0 || swaps[0].SizeBytes != expected {
			return fmt.Errorf("swap post-state size is %d bytes, expected %d", swaps[0].SizeBytes, expected)
		}
		return nil
	default:
		return errors.New("swap post-state has unsupported desired mode")
	}
}

func samePreservedSwap(before, after managementstate.SwapDeviceObservedState) bool {
	return before.Path == after.Path && before.Kind == after.Kind && before.SizeBytes == after.SizeBytes && before.Priority == after.Priority
}
