package targetgateway

import (
	"context"
	"errors"

	"github.com/privat655/VPSmith/internal/managementstate"
)

type RuntimeAction string

const (
	RuntimeStart   RuntimeAction = "start"
	RuntimeStop    RuntimeAction = "stop"
	RuntimeRestart RuntimeAction = "restart"
)

type RuntimeResult struct {
	ModuleInstanceID managementstate.ModuleInstanceID `json:"module_instance_id"`
	Action           RuntimeAction                    `json:"action"`
	Units            []string                         `json:"units"`
}

type HealthcheckResult struct {
	ModuleInstanceID managementstate.ModuleInstanceID `json:"module_instance_id"`
	Type             string                           `json:"type"`
	Container        string                           `json:"container"`
	Healthy          bool                             `json:"healthy"`
	ExitCode         int                              `json:"exit_code"`
	Stdout           string                           `json:"stdout,omitempty"`
	Stderr           string                           `json:"stderr,omitempty"`
}

type RuntimeController interface {
	Control(context.Context, managementstate.TargetID, managementstate.ModuleInstanceID, RuntimeAction) (RuntimeResult, error)
	Healthcheck(context.Context, managementstate.TargetID, managementstate.ModuleInstanceID) (HealthcheckResult, error)
}

type runtimeTransport interface {
	ControlModuleRuntime(context.Context, session, managementstate.ModuleInstanceID, RuntimeAction) (RuntimeResult, error)
	HealthcheckModule(context.Context, session, managementstate.ModuleInstanceID) (HealthcheckResult, error)
}

type runtimeController struct{ gateway *Gateway }

func NewRuntimeController(gateway *Gateway) (RuntimeController, error) {
	if gateway == nil {
		return nil, errors.New("target gateway is required")
	}
	return &runtimeController{gateway: gateway}, nil
}

// Control changes only the current runtime state of an already-inventoried
// module. Callers cannot provide systemd unit names or remote commands.
func (c *runtimeController) Control(ctx context.Context, targetID managementstate.TargetID, moduleID managementstate.ModuleInstanceID, action RuntimeAction) (RuntimeResult, error) {
	if targetID == "" || moduleID == "" {
		return RuntimeResult{}, errors.New("target id and module instance id are required")
	}
	if action != RuntimeStart && action != RuntimeStop && action != RuntimeRestart {
		return RuntimeResult{}, errors.New("unsupported runtime action")
	}
	sess, err := c.gateway.strictSession(ctx, targetID)
	if err != nil {
		return RuntimeResult{}, err
	}
	defer zero(sess.IdentitySeed)
	transport, ok := c.gateway.transport.(runtimeTransport)
	if !ok {
		return RuntimeResult{}, errors.New("target transport does not support direct runtime operations")
	}
	return transport.ControlModuleRuntime(ctx, sess, moduleID, action)
}

// Healthcheck executes exactly the primary read-only healthcheck stored in the
// target's generated module inventory. Callers cannot inject a command, URL,
// port or container name through this interface.
func (c *runtimeController) Healthcheck(ctx context.Context, targetID managementstate.TargetID, moduleID managementstate.ModuleInstanceID) (HealthcheckResult, error) {
	if targetID == "" || moduleID == "" {
		return HealthcheckResult{}, errors.New("target id and module instance id are required")
	}
	sess, err := c.gateway.strictSession(ctx, targetID)
	if err != nil {
		return HealthcheckResult{}, err
	}
	defer zero(sess.IdentitySeed)
	transport, ok := c.gateway.transport.(runtimeTransport)
	if !ok {
		return HealthcheckResult{}, errors.New("target transport does not support module healthchecks")
	}
	return transport.HealthcheckModule(ctx, sess, moduleID)
}
