package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/sourcelibrary"
	"github.com/privat655/VPSmith/internal/targetgateway"
)

const cloudInitTemplatePath = "cloud-init.yaml.tmpl"

type sourceLibrary interface {
	CurrentEmbedded(context.Context, managementstate.SourceKind) (sourcelibrary.FrozenSnapshot, error)
}

type Coordinator struct {
	state *managementstate.Store
	gateway *targetgateway.Gateway
	compiler *deployment.Compiler
	sources sourceLibrary
}

type NewTargetRequest struct{ Hostname, Timezone, Administrator string }
type PreparedTarget struct {
	TargetID managementstate.TargetID
	SSHIdentity targetgateway.SSHIdentity
	CloudInitSource sourcelibrary.Snapshot
	CloudInit deployment.BootstrapArtifact
}

func New(state *managementstate.Store, gateway *targetgateway.Gateway, compiler *deployment.Compiler, sources sourceLibrary) (*Coordinator, error) {
	if state == nil || gateway == nil || compiler == nil || sources == nil { return nil, errors.New("management state, target gateway, deployment compiler, and source library are required") }
	return &Coordinator{state: state, gateway: gateway, compiler: compiler, sources: sources}, nil
}

func (c *Coordinator) PrepareNewTarget(ctx context.Context, req NewTargetRequest) (PreparedTarget, error) {
	source, err := c.sources.CurrentEmbedded(ctx, managementstate.SourceCloudInit)
	if err != nil { return PreparedTarget{}, fmt.Errorf("resolve released Cloud-init source: %w", err) }
	templateBytes, err := fs.ReadFile(source.FS, cloudInitTemplatePath)
	if err != nil { return PreparedTarget{}, fmt.Errorf("read released Cloud-init template: %w", err) }
	desired := managementstate.CloudInitDesiredState{
		SourceSnapshotID: source.ID,
		DefinitionVersion: source.Version,
		SourceSHA256: source.SHA256,
		Hostname: req.Hostname,
		Timezone: req.Timezone,
		Administrator: req.Administrator,
	}
	if err := deployment.ValidateBootstrapDesired(desired); err != nil { return PreparedTarget{}, fmt.Errorf("validate Cloud-init target values: %w", err) }
	id, err := managementstate.NewTargetID()
	if err != nil { return PreparedTarget{}, err }
	if err := c.state.Change(ctx, func(ch *managementstate.Change) error { return ch.CreatePendingTarget(id, req.Administrator) }); err != nil { return PreparedTarget{}, err }
	identity, err := c.gateway.EnsureIdentity(ctx, id)
	if err != nil { return PreparedTarget{}, err }
	artifact, err := c.compiler.PrepareBootstrap(deployment.BootstrapRequest{
		TargetID: string(id), Desired: desired, SSHPublicKey: identity.PublicKey,
		Source: deployment.BootstrapSource{SnapshotID: source.ID, Version: source.Version, SHA256: source.SHA256, Template: templateBytes},
	})
	if err != nil { return PreparedTarget{}, err }
	desired.RenderedSHA256 = artifact.SHA256
	if err := c.state.Change(ctx, func(ch *managementstate.Change) error { return ch.SetDesiredState(id, managementstate.DesiredState{CloudInit: desired}) }); err != nil {
		return PreparedTarget{}, fmt.Errorf("record Cloud-init desired state: %w", err)
	}
	return PreparedTarget{TargetID: id, SSHIdentity: identity, CloudInitSource: source.Snapshot, CloudInit: artifact}, nil
}

func (c *Coordinator) SetTargetAddress(ctx context.Context, id managementstate.TargetID, address string) error {
	return c.state.Change(ctx, func(ch *managementstate.Change) error { return ch.SetTargetAddress(id, address) })
}
