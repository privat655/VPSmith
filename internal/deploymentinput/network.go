package deploymentinput

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/managementstate"
)

// Networks translates the persisted read-only target facts into the network
// slice consumed by the Step 5 deployment compiler. Only inventory-backed,
// definition-matching Link-Nets carry a managed relationship. Every other
// present Podman network is treated as foreign collision input.
func Networks(observed managementstate.ObservedState) ([]deployment.ObservedNetwork, error) {
	result := make([]deployment.ObservedNetwork, 0, len(observed.PodmanNetworks)+len(observed.LinkNetworks))
	managedNames := map[string]struct{}{}
	for _, link := range observed.LinkNetworks {
		if !link.Present {
			continue
		}
		if !link.DefinitionMatches {
			return nil, fmt.Errorf("observed Link-Net %s differs from its managed definition", link.Name)
		}
		if strings.TrimSpace(link.Name) == "" || strings.TrimSpace(link.Subnet) == "" || strings.TrimSpace(link.Relationship) == "" {
			return nil, errors.New("observed managed Link-Net identity is incomplete")
		}
		if _, exists := managedNames[link.Name]; exists {
			return nil, fmt.Errorf("duplicate observed managed Link-Net %s", link.Name)
		}
		managedNames[link.Name] = struct{}{}
		result = append(result, deployment.ObservedNetwork{Name: link.Name, Subnet: link.Subnet, Relationship: link.Relationship})
	}
	for _, network := range observed.PodmanNetworks {
		if !network.Present {
			continue
		}
		if strings.TrimSpace(network.Name) == "" {
			return nil, errors.New("observed Podman network name is empty")
		}
		if _, managed := managedNames[network.Name]; managed {
			continue
		}
		if len(network.Subnets) == 0 {
			result = append(result, deployment.ObservedNetwork{Name: network.Name})
			continue
		}
		for _, subnet := range network.Subnets {
			result = append(result, deployment.ObservedNetwork{Name: network.Name, Subnet: subnet})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Name != result[j].Name {
			return result[i].Name < result[j].Name
		}
		if result[i].Subnet != result[j].Subnet {
			return result[i].Subnet < result[j].Subnet
		}
		return result[i].Relationship < result[j].Relationship
	})
	return result, nil
}
