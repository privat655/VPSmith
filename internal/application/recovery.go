package application

import (
	"context"

	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/recoverypackage"
)

// ReconnectAfterRecovery uses the restored SSH identity and saved strict host
// trust through the existing target gateway, then compares the read-only target
// execution proofs with restored local history. It never re-enters TOFU and it
// never chooses or applies a winner when drift is found.
func (a *Application) ReconnectAfterRecovery(ctx context.Context, id managementstate.TargetID) (recoverypackage.ReconnectionReport, error) {
	observed, err := a.gateway.Inspect(ctx, id)
	if err != nil {
		return recoverypackage.ReconnectionReport{}, err
	}
	return a.recovery.Reconcile(ctx, id, observed)
}
