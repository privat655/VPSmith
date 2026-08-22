package corelifecycle

import (
	"errors"
	"fmt"

	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/managementstate"
)

func requireSteadyCoreBeforeMutation(snapshot managementstate.Snapshot, target managementstate.Target, observed managementstate.ObservedState, kind deployment.OperationKind) error {
	if kind != deployment.Update && kind != deployment.Reconfigure {
		return nil
	}
	desired := target.Desired.Core
	if desired.SourceID == "" || desired.Version == "" || desired.CoreContract == "" {
		return errors.New("Core desired identity is incomplete")
	}
	artifact, err := exactCoreArtifact(snapshot.Sources.Artifacts, desired.SourceID)
	if err != nil {
		return err
	}
	if artifact.Version != desired.Version {
		return errors.New("Core desired source version does not match canonical source artifact")
	}
	if observed.Core.SourceID != desired.SourceID || observed.Core.Version != desired.Version || observed.Core.PackageSHA256 != artifact.SHA256 {
		return errors.New("Core desired/observed identity drift blocks mutation")
	}
	if err := requireSecondaryHardening(observed.Host.SecondaryHardening); err != nil {
		return err
	}
	if err := requireCoreListeners(observed.Host.Listeners); err != nil {
		return err
	}
	if err := requireSwapPostState(desired.Swap, observed.Host.SwapDevices, observed.Host); err != nil {
		return err
	}
	if !observed.Core.Podman.Present || !observed.Core.Podman.Rootless || observed.Core.Podman.CgroupVersion != "v2" || observed.Core.Podman.RootlessNetworkCmd != "pasta" ||
		!observed.Core.Running || !observed.Core.Caddy.Present || !observed.Core.Caddy.Running || !observed.Core.Caddy.ConfigChecked || !observed.Core.Caddy.ConfigValid ||
		!observed.Core.Authelia.Present || !observed.Core.Authelia.Running {
		return errors.New("Core runtime drift blocks mutation")
	}
	for _, module := range target.Desired.Modules {
		actual, err := exactObservedModule(module, observed.Modules)
		if err != nil {
			return err
		}
		if _, err := exactModuleArtifact(snapshot.Sources.Artifacts, module, actual); err != nil {
			return err
		}
	}
	return nil
}

func exactCoreArtifact(artifacts []managementstate.SourceArtifact, id managementstate.SourceSnapshotID) (managementstate.SourceArtifact, error) {
	for _, artifact := range artifacts {
		if artifact.ID != id {
			continue
		}
		if artifact.Kind != managementstate.SourceCore || artifact.Version == "" || artifact.SHA256 == "" {
			return managementstate.SourceArtifact{}, errors.New("Core desired source metadata is invalid")
		}
		return artifact, nil
	}
	return managementstate.SourceArtifact{}, fmt.Errorf("Core desired source %s is unavailable", id)
}
