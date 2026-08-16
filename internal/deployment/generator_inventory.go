package deployment

import (
	"encoding/json"
	"sort"
)

func generateInventory(mods []compiledModule, links []LinkNetwork) ([]byte, error) {
	type unitRef struct {
		Name  string `json:"name"`
		Scope string `json:"scope"`
	}
	type invModule struct {
		InstanceID       string            `json:"instance_id"`
		ModuleID         string            `json:"module_id"`
		PackageID        string            `json:"package_id"`
		Version          string            `json:"version"`
		PackageSHA256    string            `json:"package_sha256"`
		ImageDigests     map[string]string `json:"image_digests"`
		Units            []unitRef         `json:"units"`
		Containers       []string          `json:"containers"`
		Networks         []string          `json:"networks"`
		ManagedArtifacts []string          `json:"managed_artifacts"`
	}
	doc := struct {
		Modules []invModule `json:"modules"`
	}{}
	for _, m := range mods {
		prefix := "vpsmith-" + m.Desired.InstanceID
		im := invModule{
			InstanceID: m.Desired.InstanceID, ModuleID: m.Contract.ID, PackageID: m.Desired.Source.PackageID,
			Version: m.Contract.Version, PackageSHA256: m.Desired.Source.PackageSHA256, ImageDigests: m.Images,
		}
		for _, c := range m.Contract.Containers {
			name := prefix + "-" + c.ID
			im.Units = append(im.Units, unitRef{Name: name + ".service", Scope: "user"})
			im.Containers = append(im.Containers, name)
			im.ManagedArtifacts = append(im.ManagedArtifacts, "/var/lib/vpsmith/generated/quadlet/"+name+".container")
		}
		for _, n := range m.Contract.Networks {
			name := prefix + "-" + n.ID
			im.Networks = append(im.Networks, name)
			im.ManagedArtifacts = append(im.ManagedArtifacts, "/var/lib/vpsmith/generated/quadlet/"+name+".network")
		}
		for _, l := range links {
			if participantInstance(l.Provider) == m.Desired.InstanceID || participantInstance(l.Consumer) == m.Desired.InstanceID {
				im.Networks = append(im.Networks, l.Name)
				im.ManagedArtifacts = append(im.ManagedArtifacts, "/var/lib/vpsmith/generated/quadlet/"+l.Name+".network")
			}
		}
		im.ManagedArtifacts = append(im.ManagedArtifacts,
			"/var/lib/vpsmith/generated/core/Caddyfile",
			"/var/lib/vpsmith/generated/core/authelia-access-control.yml")
		sort.Strings(im.Containers)
		sort.Strings(im.Networks)
		sort.Strings(im.ManagedArtifacts)
		doc.Modules = append(doc.Modules, im)
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func generateLinkInventory(links []LinkNetwork) ([]byte, error) {
	doc := struct {
		Networks []LinkNetwork `json:"networks"`
	}{Networks: links}
	data, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func participantInstance(value string) string {
	for i := 0; i < len(value); i++ {
		if value[i] == '/' {
			return value[:i]
		}
	}
	return value
}
