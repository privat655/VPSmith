package corelifecycle

import (
	"context"
	"errors"
	"fmt"

	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/sourcelibrary"
)

type moduleSnapshotSource interface {
	FreezeModuleSnapshot(context.Context, managementstate.SourceSnapshotID) (sourcelibrary.FrozenSnapshot, error)
}

type moduleCompatibilityChecker interface {
	CheckCoreCompatibility(string, []deployment.FrozenModuleSource) error
}

func requireLifecycleModuleCompatibility(ctx context.Context, snapshot managementstate.Snapshot, target managementstate.Target, observed managementstate.ObservedState, coreContract string, sources Sources, compiler Compiler) error {
	if len(target.Desired.Modules) == 0 {
		return nil
	}
	moduleSources, ok := sources.(moduleSnapshotSource)
	if !ok {
		return errors.New("Source Library does not expose immutable module snapshots for Core compatibility")
	}
	checker, ok := compiler.(moduleCompatibilityChecker)
	if !ok {
		return errors.New("Deployment Compiler does not expose Core compatibility checking")
	}
	return requireInstalledModulesCompatible(ctx, snapshot, target, observed, coreContract, moduleSources, checker)
}

func freezeLifecycleModuleSources(ctx context.Context, snapshot managementstate.Snapshot, target managementstate.Target, observed managementstate.ObservedState, sources Sources) ([]deployment.FrozenModuleSource, error) {
	if len(target.Desired.Modules) == 0 {
		return []deployment.FrozenModuleSource{}, nil
	}
	moduleSources, ok := sources.(moduleSnapshotSource)
	if !ok {
		return nil, errors.New("Source Library does not expose immutable module snapshots for Core platform generation")
	}
	return freezeInstalledModuleSources(ctx, snapshot, target, observed, moduleSources)
}

func requireInstalledModulesCompatible(ctx context.Context, snapshot managementstate.Snapshot, target managementstate.Target, observed managementstate.ObservedState, coreContract string, sources moduleSnapshotSource, checker moduleCompatibilityChecker) error {
	if len(target.Desired.Modules) == 0 {
		return nil
	}
	if sources == nil || checker == nil {
		return errors.New("Core compatibility dependencies are required when modules are installed")
	}
	frozen, err := freezeInstalledModuleSources(ctx, snapshot, target, observed, sources)
	if err != nil {
		return err
	}
	if err := checker.CheckCoreCompatibility(coreContract, frozen); err != nil {
		return fmt.Errorf("Core candidate is incompatible with installed modules: %w", err)
	}
	return nil
}

func freezeInstalledModuleSources(ctx context.Context, snapshot managementstate.Snapshot, target managementstate.Target, observed managementstate.ObservedState, sources moduleSnapshotSource) ([]deployment.FrozenModuleSource, error) {
	if len(target.Desired.Modules) == 0 {
		return []deployment.FrozenModuleSource{}, nil
	}
	if sources == nil {
		return nil, errors.New("immutable module source access is required when modules are installed")
	}
	frozen := make([]deployment.FrozenModuleSource, 0, len(target.Desired.Modules))
	for _, desired := range target.Desired.Modules {
		actual, err := exactObservedModule(desired, observed.Modules)
		if err != nil {
			return nil, err
		}
		artifact, err := exactModuleArtifact(snapshot.Sources.Artifacts, desired, actual)
		if err != nil {
			return nil, err
		}
		source, err := sources.FreezeModuleSnapshot(ctx, artifact.ID)
		if err != nil {
			return nil, fmt.Errorf("freeze installed module %s: %w", desired.InstanceID, err)
		}
		if source.ID != artifact.ID || source.Kind != artifact.Kind || source.PackageID != artifact.PackageID || source.Version != artifact.Version || source.SHA256 != artifact.SHA256 || source.FS == nil {
			return nil, fmt.Errorf("installed module %s frozen source identity changed", desired.InstanceID)
		}
		frozen = append(frozen, deployment.FrozenModuleSource{
			InstanceID:    string(desired.InstanceID),
			SourceID:      string(source.ID),
			PackageID:     string(source.PackageID),
			GitCommit:     source.Commit,
			PackageSHA256: source.SHA256,
			PackageFS:     source.FS,
		})
	}
	return frozen, nil
}

func exactObservedModule(desired managementstate.ModuleDesiredState, modules []managementstate.ModuleObservedState) (managementstate.ModuleObservedState, error) {
	var match *managementstate.ModuleObservedState
	for i := range modules {
		if modules[i].InstanceID != desired.InstanceID {
			continue
		}
		if match != nil {
			return managementstate.ModuleObservedState{}, fmt.Errorf("module %s has ambiguous observed state", desired.InstanceID)
		}
		match = &modules[i]
	}
	if match == nil || !match.Present {
		return managementstate.ModuleObservedState{}, fmt.Errorf("module %s is missing from observed state", desired.InstanceID)
	}
	if match.PackageID != desired.PackageID || match.Version != desired.Version || match.PackageSHA256 == "" {
		return managementstate.ModuleObservedState{}, fmt.Errorf("module %s desired/observed identity drift blocks Core mutation", desired.InstanceID)
	}
	return *match, nil
}

func exactModuleArtifact(artifacts []managementstate.SourceArtifact, desired managementstate.ModuleDesiredState, observed managementstate.ModuleObservedState) (managementstate.SourceArtifact, error) {
	var match *managementstate.SourceArtifact
	for i := range artifacts {
		artifact := &artifacts[i]
		if artifact.PackageID != desired.PackageID || artifact.Version != desired.Version || artifact.SHA256 != observed.PackageSHA256 {
			continue
		}
		if artifact.Kind != managementstate.SourceEmbeddedN8N && artifact.Kind != managementstate.SourceCustomModule {
			continue
		}
		if match != nil {
			return managementstate.SourceArtifact{}, fmt.Errorf("module %s exact immutable source is ambiguous", desired.InstanceID)
		}
		match = artifact
	}
	if match == nil {
		return managementstate.SourceArtifact{}, fmt.Errorf("module %s exact immutable source is unavailable", desired.InstanceID)
	}
	return *match, nil
}
