package corelifecycle

import (
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/managementstate"
)

func TestResolveSwapV1UsesConcreteObservedSwapDevice(t *testing.T) {
	observed := managementstate.ObservedState{Host: managementstate.HostObservedState{
		Memory:         managementstate.MemoryObservedState{TotalBytes: 8 << 30, AvailableBytes: 3 << 30},
		RootFilesystem: managementstate.FilesystemObservedState{AvailableBytes: 20 << 30},
		SwapDevices: []managementstate.SwapDeviceObservedState{{
			Path: "/dev/vdb", Kind: "partition", SizeBytes: 1 << 30, UsedBytes: 256 << 20,
		}},
	}}

	if size, err := resolveSwapV1(observed, managementstate.SwapDesiredState{Mode: "preserve-existing"}); err != nil || size != 0 {
		t.Fatalf("preserve-existing = %d, %v", size, err)
	}
	if size, err := resolveSwapV1(observed, managementstate.SwapDesiredState{Mode: "none"}); err != nil || size != 0 {
		t.Fatalf("disable foreign swap = %d, %v", size, err)
	}
	if size, err := resolveSwapV1(observed, managementstate.SwapDesiredState{Mode: "swapfile"}); err != nil || size != 4<<30 {
		t.Fatalf("replace foreign swap with auto Core swap = %d, %v", size, err)
	}
}

func TestResolveSwapV1FailsClosedOnAmbiguousOrUnsafeSwap(t *testing.T) {
	base := managementstate.ObservedState{Host: managementstate.HostObservedState{
		Memory:         managementstate.MemoryObservedState{TotalBytes: 4 << 30, AvailableBytes: 64 << 20},
		RootFilesystem: managementstate.FilesystemObservedState{AvailableBytes: 20 << 30},
	}}

	multi := base
	multi.Host.SwapDevices = []managementstate.SwapDeviceObservedState{
		{Path: "/dev/vdb", SizeBytes: 1 << 30},
		{Path: "/dev/vdc", SizeBytes: 1 << 30},
	}
	if _, err := resolveSwapV1(multi, managementstate.SwapDesiredState{Mode: "none"}); err == nil || !strings.Contains(err.Error(), "one active swap") {
		t.Fatalf("multiple swap devices error = %v", err)
	}

	unsafe := base
	unsafe.Host.SwapDevices = []managementstate.SwapDeviceObservedState{{Path: "/dev/vdb", SizeBytes: 1 << 30, UsedBytes: 128 << 20}}
	if _, err := resolveSwapV1(unsafe, managementstate.SwapDesiredState{Mode: "none"}); err == nil || !strings.Contains(err.Error(), "available RAM") {
		t.Fatalf("unsafe swapoff error = %v", err)
	}

	core := base
	core.Host.Memory.AvailableBytes = 2 << 30
	core.Host.SwapDevices = []managementstate.SwapDeviceObservedState{{Path: "/var/lib/vpsmith/swapfile", SizeBytes: 2 << 30, UsedBytes: 64 << 20, CoreManaged: true}}
	if _, err := resolveSwapV1(core, managementstate.SwapDesiredState{Mode: "preserve-existing"}); err == nil {
		t.Fatal("preserve-existing accepted Core-managed swap")
	}
}
