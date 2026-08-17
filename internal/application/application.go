package application

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/privat655/VPSmith/internal/bootstrap"
	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/execution"
	"github.com/privat655/VPSmith/internal/executionbundle"
	"github.com/privat655/VPSmith/internal/executionstate"
	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/registry"
	"github.com/privat655/VPSmith/internal/sourcelibrary"
	"github.com/privat655/VPSmith/internal/targetgateway"
)

// Paths are the persistent and runtime locations owned by one VPSmith Studio
// process. All paths must be absolute so the composition cannot silently use a
// caller-dependent working directory.
type Paths struct {
	StateDir     string
	SourcesDir   string
	BackupsDir   string
	EmbeddedRoot string
	SSHRuntimeDir string
	BundlesDir   string
}

// Application is the single production composition root for the Step 1-7
// VPSmith domain modules. Adapters such as the local Studio HTTP server and the
// Step-7 live verifier call this module instead of rebuilding their own graph.
type Application struct {
	state     *managementstate.Store
	sources   *sourcelibrary.Library
	gateway   *targetgateway.Gateway
	compiler  *deployment.Compiler
	bootstrap *bootstrap.Coordinator
	executor  *execution.Executor
}

func Open(ctx context.Context, paths Paths) (*Application, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	if err := normalizePaths(&paths); err != nil {
		return nil, err
	}
	for _, path := range []string{paths.StateDir, paths.SourcesDir, paths.BackupsDir, paths.SSHRuntimeDir, paths.BundlesDir} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return nil, fmt.Errorf("create VPSmith application directory %s: %w", path, err)
		}
	}

	state, err := managementstate.Open(paths.StateDir)
	if err != nil {
		return nil, fmt.Errorf("open canonical management state: %w", err)
	}
	fail := func(err error) (*Application, error) {
		_ = state.Close()
		return nil, err
	}

	sources, err := sourcelibrary.New(paths.SourcesDir, paths.EmbeddedRoot, state, sourcelibrary.NewGithubRemote())
	if err != nil {
		return fail(fmt.Errorf("open canonical source library: %w", err))
	}
	if _, err := sources.ImportEmbedded(ctx); err != nil {
		return fail(fmt.Errorf("import embedded source snapshots: %w", err))
	}
	gateway, err := targetgateway.New(state, paths.SSHRuntimeDir)
	if err != nil {
		return fail(fmt.Errorf("open target gateway: %w", err))
	}
	bundles, err := executionbundle.NewAssembler(paths.BundlesDir)
	if err != nil {
		return fail(fmt.Errorf("open execution bundle store: %w", err))
	}
	compiler, err := deployment.New(registry.NewOCI(http.DefaultClient), bundles)
	if err != nil {
		return fail(fmt.Errorf("open deployment compiler: %w", err))
	}
	bootstrapCoordinator, err := bootstrap.New(state, gateway, compiler, sources)
	if err != nil {
		return fail(fmt.Errorf("open bootstrap coordinator: %w", err))
	}
	executionTarget, err := targetgateway.NewExecutionTarget(gateway)
	if err != nil {
		return fail(fmt.Errorf("open execution target: %w", err))
	}
	executionState, err := executionstate.New(state)
	if err != nil {
		return fail(fmt.Errorf("open execution state adapter: %w", err))
	}
	executor, err := execution.New(executionTarget, executionState, executionState, execution.Options{})
	if err != nil {
		return fail(fmt.Errorf("open execution module: %w", err))
	}
	return &Application{state: state, sources: sources, gateway: gateway, compiler: compiler, bootstrap: bootstrapCoordinator, executor: executor}, nil
}

func normalizePaths(paths *Paths) error {
	if paths == nil {
		return errors.New("application paths are required")
	}
	if paths.SSHRuntimeDir == "" && paths.StateDir != "" {
		paths.SSHRuntimeDir = filepath.Join(paths.StateDir, "ssh-runtime")
	}
	if paths.BundlesDir == "" && paths.StateDir != "" {
		paths.BundlesDir = filepath.Join(paths.StateDir, "execution-bundles")
	}
	for name, value := range map[string]string{
		"state": paths.StateDir, "sources": paths.SourcesDir, "backups": paths.BackupsDir,
		"embedded": paths.EmbeddedRoot, "ssh runtime": paths.SSHRuntimeDir, "bundles": paths.BundlesDir,
	} {
		if value == "" || !filepath.IsAbs(value) {
			return fmt.Errorf("absolute %s path is required", name)
		}
	}
	return nil
}

func (a *Application) Close() error {
	if a == nil || a.state == nil {
		return nil
	}
	return a.state.Close()
}

func (a *Application) PrepareNewTarget(ctx context.Context, req bootstrap.NewTargetRequest) (bootstrap.PreparedTarget, error) {
	return a.bootstrap.PrepareNewTarget(ctx, req)
}

func (a *Application) SetTargetAddress(ctx context.Context, id managementstate.TargetID, address string) error {
	return a.bootstrap.SetTargetAddress(ctx, id, address)
}

func (a *Application) ObserveHostKey(ctx context.Context, id managementstate.TargetID) (targetgateway.HostKeyObservation, error) {
	return a.gateway.ObserveHostKey(ctx, id)
}

func (a *Application) ConfirmHostKey(ctx context.Context, id managementstate.TargetID, observation targetgateway.HostKeyObservation) error {
	return a.gateway.ConfirmHostKey(ctx, id, observation)
}

func (a *Application) Enroll(ctx context.Context, id managementstate.TargetID) (targetgateway.EnrollmentResult, error) {
	return a.gateway.Enroll(ctx, id)
}

func (a *Application) Execute(ctx context.Context, targetID string, bundle executionbundle.Bundle) (execution.Run, error) {
	return a.executor.Execute(ctx, targetID, bundle)
}

func (a *Application) State() *managementstate.Store { return a.state }
func (a *Application) Sources() *sourcelibrary.Library { return a.sources }
func (a *Application) Gateway() *targetgateway.Gateway { return a.gateway }
func (a *Application) Compiler() *deployment.Compiler { return a.compiler }
