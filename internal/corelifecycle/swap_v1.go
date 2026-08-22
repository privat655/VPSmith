package corelifecycle

import (
	"errors"
	"fmt"

	"github.com/privat655/VPSmith/internal/managementstate"
)

func resolveSwapV1(observed managementstate.ObservedState, desired managementstate.SwapDesiredState) (int64, error) {
	devices := observed.Host.SwapDevices
	if len(devices) > 1 {
		return 0, errors.New("Swap V1 supports at most one active swap device")
	}
	if desired.SizeGiB < 0 {
		return 0, errors.New("Core swap size must be auto or a positive GiB value")
	}

	switch desired.Mode {
	case "none":
		if desired.SizeGiB != 0 {
			return 0, errors.New("Core swap size is only valid for swapfile")
		}
		if len(devices) == 1 {
			if err := requireSafeSwapoff(observed.Host.Memory.AvailableBytes, devices[0].UsedBytes); err != nil {
				return 0, err
			}
		}
		return 0, nil
	case "preserve-existing":
		if desired.SizeGiB != 0 {
			return 0, errors.New("Core swap size is only valid for swapfile")
		}
		if len(devices) != 1 || devices[0].CoreManaged {
			return 0, errors.New("preserve-existing requires exactly one active foreign swap device")
		}
		return 0, nil
	case "swapfile":
		size := observed.Host.Memory.TotalBytes
		if desired.SizeGiB > 0 {
			size = int64(desired.SizeGiB) << 30
		} else if size > maxAutoSwapBytes {
			size = maxAutoSwapBytes
		}
		if size <= 0 {
			return 0, errors.New("cannot determine Core swapfile size")
		}
		if observed.Host.RootFilesystem.AvailableBytes <= size {
			return 0, errors.New("insufficient free disk space for Core swapfile")
		}
		if len(devices) == 1 {
			device := devices[0]
			needsSwapoff := !device.CoreManaged || device.Path != "/var/lib/vpsmith/swapfile" || device.SizeBytes != size
			if needsSwapoff {
				if err := requireSafeSwapoff(observed.Host.Memory.AvailableBytes, device.UsedBytes); err != nil {
					return 0, err
				}
			}
		}
		return size, nil
	default:
		return 0, errors.New("Core swap mode must be none, swapfile, or preserve-existing")
	}
}

func requireSafeSwapoff(availableRAM, usedSwap int64) error {
	if usedSwap < 0 || availableRAM < 0 {
		return errors.New("swap memory facts are invalid")
	}
	if availableRAM < usedSwap {
		return fmt.Errorf("available RAM (%d bytes) cannot absorb used swap (%d bytes)", availableRAM, usedSwap)
	}
	return nil
}
