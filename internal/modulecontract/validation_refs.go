package modulecontract

import (
	"errors"
	"fmt"
	"strings"
)

func validateStorage(m *Module, containers map[string]struct{}) error {
	storage := map[string]struct{}{}
	paths := map[string]string{}
	for _, s := range m.Persistent {
		if !identifierRE.MatchString(s.ID) {
			return fmt.Errorf("invalid persistent storage id %q", s.ID)
		}
		if _, exists := storage[s.ID]; exists {
			return fmt.Errorf("duplicate persistent storage %s", s.ID)
		}
		if !isAbsoluteCleanPath(s.Path) {
			return fmt.Errorf("persistent storage %s has invalid path", s.ID)
		}
		if owner, exists := paths[s.Path]; exists {
			return fmt.Errorf("persistent path %s claimed by both %s and %s", s.Path, owner, s.ID)
		}
		storage[s.ID] = struct{}{}
		paths[s.Path] = s.ID
	}
	for _, c := range m.Containers {
		for _, mount := range c.Mounts {
			if _, ok := storage[mount.StorageID]; !ok {
				return fmt.Errorf("container %s references undeclared persistent storage %s", c.ID, mount.StorageID)
			}
			if !isAbsoluteCleanPath(mount.Target) {
				return fmt.Errorf("container %s has invalid mount target", c.ID)
			}
		}
	}
	return nil
}

func validateNetworks(m *Module, containers map[string]struct{}) error {
	networks := map[string]struct{}{}
	for _, n := range m.Networks {
		if !identifierRE.MatchString(n.ID) {
			return fmt.Errorf("invalid module network id %q", n.ID)
		}
		if _, exists := networks[n.ID]; exists {
			return fmt.Errorf("duplicate module network %s", n.ID)
		}
		switch n.Role {
		case "edge", "internal", "app", "egress":
		default:
			return fmt.Errorf("module network %s has invalid role %q", n.ID, n.Role)
		}
		networks[n.ID] = struct{}{}
	}
	for _, c := range m.Containers {
		for _, network := range c.Networks {
			if _, ok := networks[network]; !ok {
				return fmt.Errorf("container %s references unknown module network %s", c.ID, network)
			}
		}
	}
	return nil
}

func validateSecrets(m *Module, containers map[string]struct{}) error {
	secretIDs := map[string]struct{}{}
	secretEnvNames := map[string]struct{}{}
	secretTargets := map[string]string{}
	for _, s := range m.Secrets {
		if !identifierRE.MatchString(s.ID) {
			return fmt.Errorf("invalid secret id %q", s.ID)
		}
		if _, exists := secretIDs[s.ID]; exists {
			return fmt.Errorf("duplicate secret %s", s.ID)
		}
		secretIDs[s.ID] = struct{}{}
		if s.Source != "generated" && s.Source != "user" {
			return fmt.Errorf("secret %s has invalid source", s.ID)
		}
		if s.Delivery != "environment" && s.Delivery != "file" {
			return fmt.Errorf("secret %s has invalid delivery", s.ID)
		}
		if strings.TrimSpace(s.Name) == "" {
			return fmt.Errorf("secret %s requires target name", s.ID)
		}
		if s.Delivery == "environment" {
			secretEnvNames[s.Name] = struct{}{}
		}
		if s.Delivery == "file" && !isAbsoluteCleanPath(s.Path) {
			return fmt.Errorf("secret %s file delivery requires absolute clean path", s.ID)
		}
		if len(s.Containers) == 0 {
			return fmt.Errorf("secret %s has no target container", s.ID)
		}
		for _, c := range s.Containers {
			if _, ok := containers[c]; !ok {
				return fmt.Errorf("secret %s references unknown container %s", s.ID, c)
			}
			target := s.Name
			if s.Delivery == "file" {
				target = s.Path
			}
			key := c + ":" + s.Delivery + ":" + target
			if owner, exists := secretTargets[key]; exists {
				return fmt.Errorf("secret target %s is shared by %s and %s", key, owner, s.ID)
			}
			secretTargets[key] = s.ID
		}
	}
	for _, c := range m.Containers {
		for name := range c.Environment {
			if _, secret := secretEnvNames[name]; secret {
				return fmt.Errorf("container %s environment %s duplicates declared secret target", c.ID, name)
			}
		}
	}
	return nil
}

func validateIntegration(m *Module, containers map[string]struct{}) error {
	networkRoles := map[string]string{}
	for _, n := range m.Networks {
		networkRoles[n.ID] = n.Role
	}
	containerNetworks := map[string]map[string]struct{}{}
	for _, c := range m.Containers {
		containerNetworks[c.ID] = map[string]struct{}{}
		for _, n := range c.Networks {
			containerNetworks[c.ID][networkRoles[n]] = struct{}{}
		}
	}
	for _, e := range m.Egress {
		if _, ok := containers[e.Container]; !ok {
			return fmt.Errorf("egress references unknown container %s", e.Container)
		}
		if strings.TrimSpace(e.Reason) == "" {
			return fmt.Errorf("egress for container %s requires reason", e.Container)
		}
		if _, ok := containerNetworks[e.Container]["egress"]; !ok {
			return fmt.Errorf("egress container %s must be attached to an egress network", e.Container)
		}
	}
	routeKeys := map[string]struct{}{}
	for _, r := range m.PublicRoutes {
		if !hostnameRE.MatchString(strings.ToLower(r.Hostname)) {
			return fmt.Errorf("invalid public hostname %q", r.Hostname)
		}
		if _, ok := containers[r.Container]; !ok {
			return fmt.Errorf("public route references unknown container %s", r.Container)
		}
		if r.Port < 1 || r.Port > 65535 {
			return fmt.Errorf("public route %s has invalid port", r.Hostname)
		}
		if r.PathPrefix == "" || !strings.HasPrefix(r.PathPrefix, "/") {
			return fmt.Errorf("public route %s requires absolute path prefix", r.Hostname)
		}
		if r.Authelia.Mode != "protected" && r.Authelia.Mode != "public" {
			return fmt.Errorf("public route %s has invalid Authelia mode", r.Hostname)
		}
		routeKey := strings.ToLower(r.Hostname) + ":" + r.PathPrefix
		if _, exists := routeKeys[routeKey]; exists {
			return fmt.Errorf("duplicate public route %s%s", r.Hostname, r.PathPrefix)
		}
		routeKeys[routeKey] = struct{}{}
		if _, ok := containerNetworks[r.Container]["edge"]; !ok {
			return fmt.Errorf("public route container %s must be attached to an edge network", r.Container)
		}
	}
	if err := validateHealthcheck(m.Healthcheck, containers, true); err != nil {
		return err
	}
	seenChecks := map[string]struct{}{}
	for _, h := range m.ServiceChecks {
		if !identifierRE.MatchString(h.ID) {
			return fmt.Errorf("service check requires stable id")
		}
		if _, exists := seenChecks[h.ID]; exists {
			return fmt.Errorf("duplicate service check %s", h.ID)
		}
		seenChecks[h.ID] = struct{}{}
		if err := validateHealthcheck(h, containers, false); err != nil {
			return err
		}
	}

	interfaces := map[string]struct{}{}
	for _, in := range m.Interfaces {
		if !identifierRE.MatchString(in.ID) {
			return fmt.Errorf("invalid internal interface id %q", in.ID)
		}
		if _, exists := interfaces[in.ID]; exists {
			return fmt.Errorf("duplicate internal interface %s", in.ID)
		}
		interfaces[in.ID] = struct{}{}
		if _, ok := containers[in.Container]; !ok {
			return fmt.Errorf("interface %s references unknown container %s", in.ID, in.Container)
		}
		if in.Port < 1 || in.Port > 65535 {
			return fmt.Errorf("interface %s has invalid port", in.ID)
		}
		if in.Protocol != "tcp" && in.Protocol != "http" {
			return fmt.Errorf("interface %s has invalid protocol", in.ID)
		}
	}
	dependencyKeys := map[string]struct{}{}
	for _, d := range m.Dependencies {
		if !identifierRE.MatchString(d.TargetModule) || !identifierRE.MatchString(d.InterfaceID) {
			return errors.New("dependency requires valid target_module and interface")
		}
		if d.TargetModule == m.ID {
			return fmt.Errorf("module %s cannot depend on itself through a Link-Net", m.ID)
		}
		if _, ok := containers[d.Consumer]; !ok {
			return fmt.Errorf("dependency references unknown consumer container %s", d.Consumer)
		}
		key := d.TargetModule + ":" + d.InterfaceID + ":" + d.Consumer
		if _, exists := dependencyKeys[key]; exists {
			return fmt.Errorf("duplicate dependency %s", key)
		}
		dependencyKeys[key] = struct{}{}
	}
	return nil
}
