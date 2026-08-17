package bootstrap

import (
	"context"
	"errors"
	"fmt"

	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/targetgateway"
)

type Coordinator struct {
	state    *managementstate.Store
	gateway  *targetgateway.Gateway
	compiler *deployment.Compiler
}

type NewTargetRequest struct{ Hostname, Timezone, Administrator, DefinitionVersion string }
type PreparedTarget struct {
	TargetID    managementstate.TargetID
	SSHIdentity targetgateway.SSHIdentity
	CloudInit   deployment.BootstrapArtifact
}

func New(state *managementstate.Store, gateway *targetgateway.Gateway, compiler *deployment.Compiler) (*Coordinator, error) {
	if state == nil || gateway == nil || compiler == nil {
		return nil, errors.New("management state, target gateway, and deployment compiler are required")
	}
	return &Coordinator{state: state, gateway: gateway, compiler: compiler}, nil
}

func (c *Coordinator) PrepareNewTarget(ctx context.Context, req NewTargetRequest) (PreparedTarget, error) {
	id, err := managementstate.NewTargetID()
	if err != nil {
		return PreparedTarget{}, err
	}
	desired := managementstate.CloudInitDesiredState{DefinitionVersion: req.DefinitionVersion, Hostname: req.Hostname, Timezone: req.Timezone, Administrator: req.Administrator}
	if err := c.state.Change(ctx, func(ch *managementstate.Change) error { return ch.CreatePendingTarget(id, req.Administrator) }); err != nil {
		return PreparedTarget{}, err
	}
	identity, err := c.gateway.EnsureIdentity(ctx, id)
	if err != nil {
		return PreparedTarget{}, err
	}
	artifact, err := c.compiler.PrepareBootstrap(deployment.BootstrapRequest{TargetID: string(id), Desired: desired, SSHPublicKey: identity.PublicKey})
	if err != nil {
		return PreparedTarget{}, err
	}
	desired.DefinitionSHA256 = artifact.SHA256
	if err := c.state.Change(ctx, func(ch *managementstate.Change) error {
		return ch.SetDesiredState(id, managementstate.DesiredState{CloudInit: desired})
	}); err != nil {
		return PreparedTarget{}, fmt.Errorf("record Cloud-init desired state: %w", err)
	}
	return PreparedTarget{TargetID: id, SSHIdentity: identity, CloudInit: artifact}, nil
}

func (c *Coordinator) SetTargetAddress(ctx context.Context, id managementstate.TargetID, address string) error {
	return c.state.Change(ctx, func(ch *managementstate.Change) error { return ch.SetTargetAddress(id, address) })
}
