package deployment

import (
	"fmt"
	"sort"
	"strings"
)

func generateArtifacts(mods []compiledModule, links []LinkNetwork) ([]GeneratedArtifact, error) {
	var out []GeneratedArtifact
	linkByParticipant := map[string][]LinkNetwork{}
	for _, l := range links {
		linkByParticipant[l.Provider] = append(linkByParticipant[l.Provider], l)
		linkByParticipant[l.Consumer] = append(linkByParticipant[l.Consumer], l)
	}
	for _, m := range mods {
		prefix := "vpsmith-" + m.Desired.InstanceID
		for _, n := range m.Contract.Networks {
			internal := n.Role != "edge" && n.Role != "egress"
			data := []byte(fmt.Sprintf("[Network]\nInternal=%t\nLabel=vpsmith.managed=true\nLabel=vpsmith.role=%s\n", internal, n.Role))
			out = append(out, artifact("artifacts/quadlet/"+prefix+"-"+n.ID+".network", "/var/lib/vpsmith/generated/quadlet/"+prefix+"-"+n.ID+".network", 0o444, data))
		}
		for _, c := range m.Contract.Containers {
			out = append(out, artifact("artifacts/quadlet/"+prefix+"-"+c.ID+".container", "/var/lib/vpsmith/generated/quadlet/"+prefix+"-"+c.ID+".container", 0o444,
				[]byte(generateContainer(m, c.ID, linkByParticipant))))
		}
	}
	for _, l := range links {
		data := []byte(fmt.Sprintf("[Network]\nInternal=true\nSubnet=%s\nLabel=vpsmith.relationship=%s\n", l.Subnet, l.Relationship))
		out = append(out, artifact("artifacts/quadlet/"+l.Name+".network", "/var/lib/vpsmith/generated/quadlet/"+l.Name+".network", 0o444, data))
	}
	out = append(out, artifact("artifacts/core/Caddyfile", "/var/lib/vpsmith/generated/core/Caddyfile", 0o444, []byte(generateCaddy(mods))))
	out = append(out, artifact("artifacts/core/caddy-networks.conf", "/var/lib/vpsmith/generated/core/caddy-networks.conf", 0o444, []byte(generateCaddyNetworks(mods))))
	out = append(out, artifact("artifacts/core/authelia-access-control.yml", "/var/lib/vpsmith/generated/core/authelia-access-control.yml", 0o444, []byte(generateAuthelia(mods))))
	inventory, err := generateInventory(mods, links)
	if err != nil {
		return nil, err
	}
	out = append(out, artifact("artifacts/inventory/modules.json", "/var/lib/vpsmith/inventory/modules.json", 0o444, inventory))
	linkInventory, err := generateLinkInventory(links)
	if err != nil {
		return nil, err
	}
	out = append(out, artifact("artifacts/inventory/link-networks.json", "/var/lib/vpsmith/inventory/link-networks.json", 0o444, linkInventory))
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func generateContainer(m compiledModule, containerID string, links map[string][]LinkNetwork) string {
	var cIndex int
	for i := range m.Contract.Containers {
		if m.Contract.Containers[i].ID == containerID {
			cIndex = i
			break
		}
	}
	c := m.Contract.Containers[cIndex]
	prefix := "vpsmith-" + m.Desired.InstanceID
	var b strings.Builder
	b.WriteString("[Unit]\nDescription=VPSmith " + m.Desired.InstanceID + " " + c.ID + "\n\n[Container]\n")
	fmt.Fprintf(&b, "Image=%s@%s\nContainerName=%s-%s\nUserNS=nomap\nUser=%d\nDropCapability=ALL\n", m.Contract.Images[c.Image].Ref, m.Images[c.Image], prefix, c.ID, c.User)
	for _, cap := range c.Capabilities {
		fmt.Fprintf(&b, "AddCapability=%s\n", cap)
	}
	for _, n := range c.Networks {
		fmt.Fprintf(&b, "Network=%s-%s.network\n", prefix, n)
	}
	for _, l := range links[m.Desired.InstanceID+"/"+c.ID] {
		fmt.Fprintf(&b, "Network=%s.network\n", l.Name)
		if l.Provider == m.Desired.InstanceID+"/"+c.ID {
			fmt.Fprintf(&b, "NetworkAlias=%s\n", l.Alias)
		}
	}
	for _, mount := range c.Mounts {
		src := storagePath(m, mount.StorageID)
		opt := ""
		if mount.ReadOnly {
			opt = ":ro"
		}
		fmt.Fprintf(&b, "Volume=%s:%s%s\n", src, mount.Target, opt)
	}
	for _, key := range sortedStringKeys(c.Environment) {
		fmt.Fprintf(&b, "Environment=%s=%s\n", key, c.Environment[key])
	}
	for _, s := range m.Contract.Secrets {
		for _, target := range s.Containers {
			if target != c.ID {
				continue
			}
			secretID := m.Desired.SecretIDs[s.ID]
			if s.Delivery == "environment" {
				fmt.Fprintf(&b, "EnvironmentFile=/var/lib/vpsmith/secrets/%s/%s.env\n", m.Desired.InstanceID, secretID)
			} else {
				fmt.Fprintf(&b, "Volume=/var/lib/vpsmith/secrets/%s/%s:%s:ro\n", m.Desired.InstanceID, secretID, s.Path)
			}
		}
	}
	fmt.Fprintf(&b, "PidsLimit=%d\n\n[Service]\nMemoryMax=%d\nCPUQuota=%d%%\nTasksMax=%d\n", m.Effective.PIDsLimit, m.Effective.MemoryBytes, m.Effective.CPUQuota, m.Effective.TasksMax)
	return b.String()
}

func storagePath(m compiledModule, id string) string {
	for _, s := range m.Contract.Persistent {
		if s.ID == id {
			return s.Path
		}
	}
	return ""
}
