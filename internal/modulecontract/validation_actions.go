package modulecontract

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
)

func validateActions(m *Module) error {
	if len(m.Actions) == 0 {
		return errors.New("at least validation action must be registered")
	}
	for id, rel := range m.Actions {
		if !identifierRE.MatchString(id) {
			return fmt.Errorf("invalid action id %q", id)
		}
		if err := validateActionPath(rel); err != nil {
			return fmt.Errorf("action %s: %w", id, err)
		}
	}
	if _, ok := m.Actions[m.ValidationAction]; !ok {
		return fmt.Errorf("unknown validation action %s", m.ValidationAction)
	}
	for oldVersion, transition := range m.UpdateFrom {
		if err := exactVersion("update_from", oldVersion); err != nil {
			return err
		}
		if oldVersion == m.Version {
			return fmt.Errorf("update_from cannot reference target version %s", oldVersion)
		}
		for _, action := range transition.Actions {
			if _, ok := m.Actions[action]; !ok {
				return fmt.Errorf("unknown action id %s in update_from %s", action, oldVersion)
			}
		}
	}
	return nil
}

func validateHealthcheck(h Healthcheck, containers map[string]struct{}, primary bool) error {
	label := "service check"
	if primary {
		label = "healthcheck"
	}
	if h.ID == "" && !primary {
		return errors.New("service check requires id")
	}
	if _, ok := containers[h.Container]; !ok {
		return fmt.Errorf("%s references unknown container %s", label, h.Container)
	}
	switch h.Type {
	case "http":
		u, err := url.Parse(h.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("%s requires valid http(s) url", label)
		}
	case "tcp":
		if h.Port < 1 || h.Port > 65535 {
			return fmt.Errorf("%s requires valid tcp port", label)
		}
	case "command":
		if len(h.Command) == 0 || strings.TrimSpace(h.Command[0]) == "" {
			return fmt.Errorf("%s requires command", label)
		}
	default:
		return fmt.Errorf("%s type must be http, tcp, or command", label)
	}
	return nil
}

func validateActionPath(value string) error {
	if value == "" || path.Clean(value) != value || strings.HasPrefix(value, "/") || strings.Contains(value, "..") {
		return errors.New("action path must be a clean relative path")
	}
	if !strings.HasPrefix(value, "actions/") || !strings.HasSuffix(value, ".sh") {
		return errors.New("action path must match actions/<file>.sh")
	}
	if strings.Count(value, "/") != 1 {
		return errors.New("action scripts must live directly under actions/")
	}
	return nil
}
