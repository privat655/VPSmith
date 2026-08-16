package deployment

import (
	"errors"
	"fmt"
)

func validateProviderRemoval(req Request, mods []compiledModule) error {
	var removedModuleID string
	for _, o := range req.Observed.Modules {
		if o.InstanceID == req.SubjectInstance {
			removedModuleID = o.ModuleID
			break
		}
	}
	if removedModuleID == "" {
		return nil
	}
	for _, m := range mods {
		for _, d := range m.Contract.Dependencies {
			if d.TargetModule == removedModuleID {
				return fmt.Errorf("cannot uninstall provider %s: still required by %s", req.SubjectInstance, m.Desired.InstanceID)
			}
		}
	}
	return nil
}

func validateUpdate(req Request, mods []compiledModule) ([]string, error) {
	if req.Operation != Update {
		return nil, nil
	}
	var target *compiledModule
	for i := range mods {
		if mods[i].Desired.InstanceID == req.SubjectInstance {
			target = &mods[i]
			break
		}
	}
	if target == nil {
		return nil, errors.New("update subject not in desired state")
	}
	var old string
	for _, o := range req.Observed.Modules {
		if o.InstanceID == req.SubjectInstance {
			old = o.Version
			break
		}
	}
	if old == "" {
		return nil, errors.New("installed exact module version is unknown")
	}
	transition, ok := target.Contract.UpdateFrom[old]
	if !ok {
		return nil, fmt.Errorf("target version %s has no direct update_from transition from %s", target.Contract.Version, old)
	}
	return append([]string(nil), transition.Actions...), nil
}
