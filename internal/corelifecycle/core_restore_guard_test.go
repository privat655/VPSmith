package corelifecycle

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/execution"
	"github.com/privat655/VPSmith/internal/managementstate"
)

func TestGenericExecuteRejectsRestoreBeforeRunner(t *testing.T) {
	ctx := context.Background()
	lifecycle, _, _, targetID, _ := newCoreBackupTestLifecycle(t)
	observed := lifecycle.inspector.(coreBackupTestInspector).observed
	snapshot, err := lifecycle.state.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	desired := snapshot.Targets[0].Desired.Core
	bundle := restoreSuccessBundle(t, targetID, desired)
	target := &restoreSuccessExecutionTarget{}
	history := &restoreSuccessHistory{}
	executor, err := execution.New(target, restoreSuccessSecrets{}, history, execution.Options{
		PollInterval: time.Microsecond,
		NewRunID:     func() (string, error) { return "run_generic_restore", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	lifecycle.executor = executor
	prepared := Prepared{
		TargetID:      targetID,
		DesiredCore:   desired,
		PrimaryBefore: observed.Host.PrimaryHardening,
		SwapBefore:    append([]managementstate.SwapDeviceObservedState(nil), observed.Host.SwapDevices...),
		Operation: deployment.PreparedCoreOperation{
			PreparedOperation: deployment.PreparedOperation{Operation: deployment.Restore, Bundle: bundle},
			CoreContract:      desired.CoreContract,
		},
	}

	_, err = lifecycle.Execute(ctx, prepared)
	if err == nil || !strings.Contains(err.Error(), "ExecuteVerifiedCoreRestore") {
		t.Fatalf("generic restore execution error=%v", err)
	}
	if target.starts != 0 || history.started != 0 || history.finished != 0 {
		t.Fatalf("generic restore reached executor: starts=%d history=%d/%d", target.starts, history.started, history.finished)
	}
}
