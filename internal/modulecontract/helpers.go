package modulecontract

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
)

func validateImageRef(ref string) error {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return errors.New("image ref is required")
	}
	if strings.Contains(ref, "@") {
		return errors.New("module image must declare a readable fixed tag, not a digest")
	}
	slash := strings.LastIndex(ref, "/")
	colon := strings.LastIndex(ref, ":")
	if colon <= slash || colon == len(ref)-1 {
		return errors.New("image ref must include explicit tag")
	}
	tag := ref[colon+1:]
	if strings.EqualFold(tag, "latest") {
		return errors.New("latest image tag is forbidden")
	}
	if strings.ContainsAny(tag, "*<>=^~| ") {
		return errors.New("free image version/range is forbidden")
	}
	return nil
}

func exactVersion(field, value string) error {
	value = strings.TrimSpace(value)
	if !exactVersionRE.MatchString(value) || strings.ContainsAny(value, "*<>=^~| ,") {
		return fmt.Errorf("%s must be an exact version", field)
	}
	return nil
}

func isAbsoluteCleanPath(value string) bool {
	return strings.HasPrefix(value, "/") && path.Clean(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}

func normalize(m *Module) {
	if m.Images == nil {
		m.Images = map[string]Image{}
	}
	if m.Actions == nil {
		m.Actions = map[string]string{}
	}
	if m.UpdateFrom == nil {
		m.UpdateFrom = map[string]UpdateTransition{}
	}
	if m.ActionFiles == nil {
		m.ActionFiles = map[string][]byte{}
	}
	sort.Slice(m.Containers, func(i, j int) bool { return m.Containers[i].ID < m.Containers[j].ID })
	for i := range m.Containers {
		sort.Strings(m.Containers[i].Capabilities)
		sort.Strings(m.Containers[i].Networks)
		sort.Slice(m.Containers[i].Mounts, func(a, b int) bool { return m.Containers[i].Mounts[a].Target < m.Containers[i].Mounts[b].Target })
	}
	sort.Slice(m.Persistent, func(i, j int) bool { return m.Persistent[i].ID < m.Persistent[j].ID })
	sort.Slice(m.Secrets, func(i, j int) bool { return m.Secrets[i].ID < m.Secrets[j].ID })
	for i := range m.Secrets {
		sort.Strings(m.Secrets[i].Containers)
	}
	sort.Slice(m.Networks, func(i, j int) bool { return m.Networks[i].ID < m.Networks[j].ID })
	sort.Slice(m.Egress, func(i, j int) bool {
		if m.Egress[i].Container == m.Egress[j].Container {
			return m.Egress[i].Reason < m.Egress[j].Reason
		}
		return m.Egress[i].Container < m.Egress[j].Container
	})
	sort.Slice(m.PublicRoutes, func(i, j int) bool {
		if m.PublicRoutes[i].Hostname == m.PublicRoutes[j].Hostname {
			return m.PublicRoutes[i].PathPrefix < m.PublicRoutes[j].PathPrefix
		}
		return m.PublicRoutes[i].Hostname < m.PublicRoutes[j].Hostname
	})
	for i := range m.PublicRoutes {
		sort.Strings(m.PublicRoutes[i].Authelia.Users)
		sort.Strings(m.PublicRoutes[i].Authelia.Groups)
	}
	sort.Slice(m.ServiceChecks, func(i, j int) bool { return m.ServiceChecks[i].ID < m.ServiceChecks[j].ID })
	sort.Slice(m.Interfaces, func(i, j int) bool { return m.Interfaces[i].ID < m.Interfaces[j].ID })
	sort.Slice(m.Dependencies, func(i, j int) bool {
		a, b := m.Dependencies[i], m.Dependencies[j]
		if a.TargetModule != b.TargetModule {
			return a.TargetModule < b.TargetModule
		}
		if a.InterfaceID != b.InterfaceID {
			return a.InterfaceID < b.InterfaceID
		}
		return a.Consumer < b.Consumer
	})
}
