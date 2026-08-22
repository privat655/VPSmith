package corelifecycle

import (
	"errors"
	"fmt"

	"github.com/privat655/VPSmith/internal/managementstate"
)

const coreBackupFilesystemOverhead int64 = 64 << 20
const coreUpdateChangeReserve int64 = 1 << 30

func requireCoreBackupDiskSpace(observed managementstate.ObservedState) error {
	available := observed.Host.RootFilesystem.AvailableBytes
	source := observed.Host.CoreBackupSourceBytes
	if available <= 0 || source <= 0 {
		return errors.New("Core backup disk facts are incomplete")
	}
	required, ok := safeAddBytes(source, coreBackupFilesystemOverhead)
	if !ok || available < required {
		return fmt.Errorf("insufficient target disk space for Core backup: available=%d required=%d", available, required)
	}
	return nil
}

func requireCoreUpdateDiskSpace(observed managementstate.ObservedState) error {
	if err := requireCoreBackupDiskSpace(observed); err != nil {
		return err
	}
	required, ok := safeAddBytes(observed.Host.CoreBackupSourceBytes, coreBackupFilesystemOverhead)
	if !ok {
		return errors.New("Core update disk requirement overflows")
	}
	required, ok = safeAddBytes(required, coreUpdateChangeReserve)
	if !ok || observed.Host.RootFilesystem.AvailableBytes < required {
		return fmt.Errorf("insufficient target disk space for Core backup and update: available=%d required=%d", observed.Host.RootFilesystem.AvailableBytes, required)
	}
	return nil
}

func safeAddBytes(a, b int64) (int64, bool) {
	if a < 0 || b < 0 || a > (1<<63-1)-b {
		return 0, false
	}
	return a + b, true
}
