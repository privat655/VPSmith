package modulecontract

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	identifierRE   = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[-_.][a-z0-9]+)*$`)
	exactVersionRE = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,3}(?:[-+][0-9A-Za-z.-]+)?$`)
	hostnameRE     = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

func validate(m *Module) error {
	if !identifierRE.MatchString(m.ID) {
		return errors.New("module_id must be a stable lowercase identifier")
	}
	if err := exactVersion("module_version", m.Version); err != nil {
		return err
	}
	if err := exactVersion("core_contract", m.CoreContract); err != nil {
		return err
	}
	if len(m.Images) == 0 {
		return errors.New("at least one image is required")
	}
	if len(m.Containers) == 0 {
		return errors.New("at least one container is required")
	}
	if strings.TrimSpace(m.ValidationAction) == "" {
		return errors.New("validation_action is required")
	}
	if !m.Uninstall.DeletePersistentData || !m.Uninstall.DeleteSecrets {
		return errors.New("uninstall must delete persistent data and module secrets")
	}
	if m.Resources.MemoryBytes <= 0 || m.Resources.CPUQuota <= 0 || m.Resources.PIDsLimit <= 0 || m.Resources.TasksMax <= 0 {
		return errors.New("resource defaults must all be positive")
	}

	imageIDs := map[string]struct{}{}
	for id, image := range m.Images {
		if !identifierRE.MatchString(id) {
			return fmt.Errorf("invalid image id %q", id)
		}
		if err := validateImageRef(image.Ref); err != nil {
			return fmt.Errorf("image %s: %w", id, err)
		}
		imageIDs[id] = struct{}{}
	}
	containers, err := validateContainers(m, imageIDs)
	if err != nil {
		return err
	}
	if err := validateStorage(m, containers); err != nil {
		return err
	}
	if err := validateNetworks(m, containers); err != nil {
		return err
	}
	if err := validateSecrets(m, containers); err != nil {
		return err
	}
	if err := validateIntegration(m, containers); err != nil {
		return err
	}
	return validateActions(m)
}

func validateContainers(m *Module, images map[string]struct{}) (map[string]struct{}, error) {
	containers := map[string]struct{}{}
	for i := range m.Containers {
		c := &m.Containers[i]
		if !identifierRE.MatchString(c.ID) {
			return nil, fmt.Errorf("invalid container id %q", c.ID)
		}
		if _, exists := containers[c.ID]; exists {
			return nil, fmt.Errorf("duplicate container %s", c.ID)
		}
		containers[c.ID] = struct{}{}
		if _, ok := images[c.Image]; !ok {
			return nil, fmt.Errorf("container %s references unknown image %s", c.ID, c.Image)
		}
		if c.User < 0 {
			return nil, fmt.Errorf("container %s requires numeric runtime user", c.ID)
		}
		if c.UserNS != "nomap" {
			return nil, fmt.Errorf("container %s must use UserNS=nomap", c.ID)
		}
		if len(c.HostPorts) != 0 {
			return nil, fmt.Errorf("container %s requests direct public hostports", c.ID)
		}
		seenCaps := map[string]struct{}{}
		for _, capability := range c.Capabilities {
			if strings.TrimSpace(capability) == "" {
				return nil, fmt.Errorf("container %s has empty capability", c.ID)
			}
			if _, exists := seenCaps[capability]; exists {
				return nil, fmt.Errorf("container %s has duplicate capability %s", c.ID, capability)
			}
			seenCaps[capability] = struct{}{}
		}
		seenNets := map[string]struct{}{}
		for _, network := range c.Networks {
			if _, exists := seenNets[network]; exists {
				return nil, fmt.Errorf("container %s has duplicate network %s", c.ID, network)
			}
			seenNets[network] = struct{}{}
		}
		seenMountTargets := map[string]struct{}{}
		for _, mount := range c.Mounts {
			if _, exists := seenMountTargets[mount.Target]; exists {
				return nil, fmt.Errorf("container %s has duplicate mount target %s", c.ID, mount.Target)
			}
			seenMountTargets[mount.Target] = struct{}{}
		}
	}
	return containers, nil
}
