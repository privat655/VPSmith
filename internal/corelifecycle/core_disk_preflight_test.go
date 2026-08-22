package corelifecycle

import (
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/managementstate"
)

func TestCoreUpdateDiskPreflightReservesBackupAndChangeCapacity(t *testing.T) {
	observed := managementstate.ObservedState{Host: managementstate.HostObservedState{
		CoreBackupSourceBytes: 2 << 30,
		RootFilesystem:        managementstate.FilesystemObservedState{AvailableBytes: (2 << 30) + coreBackupFilesystemOverhead + coreUpdateChangeReserve},
	}}
	if err := requireCoreUpdateDiskSpace(observed); err != nil {
		t.Fatalf("exact required update capacity rejected: %v", err)
	}
	observed.Host.RootFilesystem.AvailableBytes--
	if err := requireCoreUpdateDiskSpace(observed); err == nil || !strings.Contains(err.Error(), "backup and update") {
		t.Fatalf("insufficient update capacity error=%v", err)
	}
}

func TestCoreDiskPreflightFailsClosedWithoutMeasuredBackupSourceSize(t *testing.T) {
	observed := managementstate.ObservedState{Host: managementstate.HostObservedState{
		RootFilesystem: managementstate.FilesystemObservedState{AvailableBytes: 100 << 30},
	}}
	if err := requireCoreBackupDiskSpace(observed); err == nil || !strings.Contains(err.Error(), "facts") {
		t.Fatalf("missing backup source size error=%v", err)
	}
}
