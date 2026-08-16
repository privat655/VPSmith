package deployment

import (
	"errors"
	"fmt"
	"strings"

	"github.com/privat655/VPSmith/internal/modulecontract"
)

func validateRequest(req Request) error {
	switch req.Operation {
	case Install, Update, Reconfigure, Uninstall, Restore, Validate:
	default:
		return errors.New("unsupported operation")
	}
	if strings.TrimSpace(req.TargetID) == "" {
		return errors.New("target id is required")
	}
	if strings.TrimSpace(req.SubjectInstance) == "" {
		return errors.New("subject module instance is required")
	}
	if req.Observed.TargetID != "" && req.Observed.TargetID != req.TargetID {
		return errors.New("observed state belongs to different target")
	}
	seen := map[string]struct{}{}
	for _, m := range req.DesiredModules {
		if m.InstanceID == "" || (m.Source.InstanceID != "" && m.Source.InstanceID != m.InstanceID) {
			return errors.New("desired module identity is inconsistent")
		}
		if _, ok := seen[m.InstanceID]; ok {
			return fmt.Errorf("duplicate desired module instance %s", m.InstanceID)
		}
		seen[m.InstanceID] = struct{}{}
	}
	return nil
}

func validateSubject(req Request, mods []compiledModule) error {
	if req.Operation == Uninstall {
		return nil
	}
	for _, m := range mods {
		if m.Desired.InstanceID == req.SubjectInstance {
			return nil
		}
	}
	return fmt.Errorf("subject module %s is absent from desired state", req.SubjectInstance)
}

func validateSecretBindings(m modulecontract.Module, bindings map[string]string) error {
	if bindings == nil {
		bindings = map[string]string{}
	}
	for _, s := range m.Secrets {
		if strings.TrimSpace(bindings[s.ID]) == "" {
			return fmt.Errorf("secret %s has no stable SecretID binding", s.ID)
		}
	}
	for id := range bindings {
		found := false
		for _, s := range m.Secrets {
			if s.ID == id {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("secret binding %s is not declared by module", id)
		}
	}
	return nil
}

func mergeResources(base modulecontract.Resources, o ResourceOverride) modulecontract.Resources {
	out := base
	if o.MemoryBytes > 0 {
		out.MemoryBytes = o.MemoryBytes
	}
	if o.CPUQuota > 0 {
		out.CPUQuota = o.CPUQuota
	}
	if o.PIDsLimit > 0 {
		out.PIDsLimit = o.PIDsLimit
	}
	if o.TasksMax > 0 {
		out.TasksMax = o.TasksMax
	}
	return out
}
