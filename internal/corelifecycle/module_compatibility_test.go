package corelifecycle

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/sourcelibrary"
)

type moduleSnapshotStub struct {
	values map[managementstate.SourceSnapshotID]sourcelibrary.FrozenSnapshot
}

func (s moduleSnapshotStub) FreezeModuleSnapshot(_ context.Context, id managementstate.SourceSnapshotID) (sourcelibrary.FrozenSnapshot, error) {
	value, ok := s.values[id]
	if !ok {
		return sourcelibrary.FrozenSnapshot{}, errMissingModuleSnapshot
	}
	return value, nil
}

type compatibilityStub struct {
	contract string
	modules  []deployment.FrozenModuleSource
}

func (s *compatibilityStub) CheckCoreCompatibility(contract string, modules []deployment.FrozenModuleSource) error {
	s.contract = contract
	s.modules = append([]deployment.FrozenModuleSource(nil), modules...)
	return nil
}

func TestRequireInstalledModulesCompatibleUsesExactObservedSourceIdentity(t *testing.T) {
	artifact := managementstate.SourceArtifact{
		ID: "source_n8n", Kind: managementstate.SourceCustomModule,
		PackageID: "pkg_n8n", Version: "2.3.0", SHA256: strings.Repeat("a", 64),
	}
	snapshot := managementstate.Snapshot{Sources: managementstate.SourceState{Artifacts: []managementstate.SourceArtifact{artifact}}}
	target := managementstate.Target{Desired: managementstate.DesiredState{Modules: []managementstate.ModuleDesiredState{{InstanceID: "n8n-main", PackageID: "pkg_n8n", Version: "2.3.0"}}}}
	observed := managementstate.ObservedState{Modules: []managementstate.ModuleObservedState{{Present: true, InstanceID: "n8n-main", PackageID: "pkg_n8n", Version: "2.3.0", PackageSHA256: artifact.SHA256}}}
	source := moduleSnapshotStub{values: map[managementstate.SourceSnapshotID]sourcelibrary.FrozenSnapshot{
		artifact.ID: {Snapshot: sourcelibrary.Snapshot{ID: artifact.ID, Kind: artifact.Kind, PackageID: artifact.PackageID, Version: artifact.Version, SHA256: artifact.SHA256}, FS: fstest.MapFS{"module.yaml": &fstest.MapFile{Data: []byte("frozen")}}},
	}}
	checker := &compatibilityStub{}

	if err := requireInstalledModulesCompatible(context.Background(), snapshot, target, observed, "1", source, checker); err != nil {
		t.Fatal(err)
	}
	if checker.contract != "1" || len(checker.modules) != 1 {
		t.Fatalf("compatibility call = contract %q modules %#v", checker.contract, checker.modules)
	}
	got := checker.modules[0]
	if got.InstanceID != "n8n-main" || got.SourceID != string(artifact.ID) || got.PackageID != string(artifact.PackageID) || got.PackageSHA256 != artifact.SHA256 || got.PackageFS == nil {
		t.Fatalf("frozen compatibility identity = %#v", got)
	}
}

func TestRequireInstalledModulesCompatibleBlocksDesiredObservedDrift(t *testing.T) {
	artifact := managementstate.SourceArtifact{ID: "source_n8n", Kind: managementstate.SourceCustomModule, PackageID: "pkg_n8n", Version: "2.3.0", SHA256: strings.Repeat("a", 64)}
	snapshot := managementstate.Snapshot{Sources: managementstate.SourceState{Artifacts: []managementstate.SourceArtifact{artifact}}}
	target := managementstate.Target{Desired: managementstate.DesiredState{Modules: []managementstate.ModuleDesiredState{{InstanceID: "n8n-main", PackageID: "pkg_n8n", Version: "2.3.0"}}}}
	observed := managementstate.ObservedState{Modules: []managementstate.ModuleObservedState{{Present: true, InstanceID: "n8n-main", PackageID: "pkg_n8n", Version: "2.3.0", PackageSHA256: strings.Repeat("b", 64)}}}

	err := requireInstalledModulesCompatible(context.Background(), snapshot, target, observed, "1", moduleSnapshotStub{}, &compatibilityStub{})
	if err == nil || !strings.Contains(err.Error(), "exact immutable source") {
		t.Fatalf("drift error = %v", err)
	}
}

var errMissingModuleSnapshot = &moduleSnapshotError{}

type moduleSnapshotError struct{}

func (*moduleSnapshotError) Error() string { return "module snapshot missing" }
