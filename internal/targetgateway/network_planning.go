package targetgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/privat655/VPSmith/internal/managementstate"
)

const linkRelationshipLabel = "vpsmith.relationship"

type planningLinkInventoryDocument struct {
	Networks []struct {
		Name         string `json:"name"`
		Subnet       string `json:"subnet"`
		Relationship string `json:"relationship"`
	} `json:"networks"`
}

type podmanNetworkListEntry struct {
	Name       string            `json:"name"`
	Internal   bool              `json:"internal"`
	Labels     map[string]string `json:"labels"`
	Subnets    []struct {
		Subnet string `json:"subnet"`
	} `json:"subnets"`
}

// planningNetworkFacts adds only the network facts needed by the Step 5
// collision/reuse contract. Foreign Podman networks remain foreign even when
// they forge a VPSmith relationship label; only link-networks.json binds a
// network name to a managed relationship.
func (t *sshTransport) planningNetworkFacts(ctx context.Context, sess session, links []managementstate.LinkNetworkObservedState) ([]managementstate.NetworkObservedState, []managementstate.LinkNetworkObservedState, error) {
	networks, err := t.allPodmanNetworkFacts(ctx, sess)
	if err != nil {
		return nil, nil, err
	}
	declared, err := t.planningLinkInventory(ctx, sess)
	if err != nil {
		return nil, nil, err
	}
	actualByName := make(map[string]managementstate.NetworkObservedState, len(networks))
	for _, network := range networks {
		actualByName[network.Name] = network
	}
	declaredByName := make(map[string]struct {
		subnet       string
		relationship string
	}, len(declared.Networks))
	for _, ref := range declared.Networks {
		if !safeObjectName(ref.Name) || strings.TrimSpace(ref.Relationship) == "" {
			return nil, nil, errors.New("link-network inventory contains invalid identity")
		}
		prefix, err := netip.ParsePrefix(ref.Subnet)
		if err != nil || prefix.String() != ref.Subnet {
			return nil, nil, fmt.Errorf("link-network inventory %s contains invalid subnet", ref.Name)
		}
		if _, exists := declaredByName[ref.Name]; exists {
			return nil, nil, fmt.Errorf("link-network inventory contains duplicate network %s", ref.Name)
		}
		declaredByName[ref.Name] = struct {
			subnet       string
			relationship string
		}{subnet: ref.Subnet, relationship: ref.Relationship}
	}
	for i := range links {
		link := &links[i]
		ref, ok := declaredByName[link.Name]
		if !ok {
			return nil, nil, fmt.Errorf("observed Link-Net %s is missing from inventory", link.Name)
		}
		if !link.Present {
			continue
		}
		actual, ok := actualByName[link.Name]
		if !ok || !actual.Present {
			continue
		}
		link.Relationship = actual.Relationship
		if len(actual.Subnets) == 1 {
			link.Subnet = actual.Subnets[0]
		}
		link.DefinitionMatches = len(actual.Subnets) == 1 && actual.Subnets[0] == ref.subnet && actual.Relationship == ref.relationship
	}
	return networks, links, nil
}

func (t *sshTransport) allPodmanNetworkFacts(ctx context.Context, sess session) ([]managementstate.NetworkObservedState, error) {
	stdout, err := t.runRemote(ctx, sess, `if command -v podman >/dev/null 2>&1; then podman network ls --format json; fi`)
	if err != nil {
		return nil, fmt.Errorf("list podman networks: %w", err)
	}
	if len(bytes.TrimSpace(stdout)) == 0 {
		return []managementstate.NetworkObservedState{}, nil
	}
	var entries []podmanNetworkListEntry
	if err := json.Unmarshal(stdout, &entries); err != nil {
		return nil, fmt.Errorf("decode podman network list: %w", err)
	}
	result := make([]managementstate.NetworkObservedState, 0, len(entries))
	seen := map[string]struct{}{}
	for _, entry := range entries {
		if !safeObjectName(entry.Name) {
			return nil, errors.New("podman network list contains invalid network name")
		}
		if _, exists := seen[entry.Name]; exists {
			return nil, fmt.Errorf("podman network list contains duplicate network %s", entry.Name)
		}
		seen[entry.Name] = struct{}{}
		fact := managementstate.NetworkObservedState{
			Name: entry.Name, Present: true, Internal: entry.Internal,
			Relationship: strings.TrimSpace(entry.Labels[linkRelationshipLabel]),
		}
		for _, subnet := range entry.Subnets {
			prefix, err := netip.ParsePrefix(subnet.Subnet)
			if err != nil {
				return nil, fmt.Errorf("podman network %s contains invalid subnet", entry.Name)
			}
			fact.Subnets = append(fact.Subnets, prefix.String())
		}
		sort.Strings(fact.Subnets)
		result = append(result, fact)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func (t *sshTransport) planningLinkInventory(ctx context.Context, sess session) (planningLinkInventoryDocument, error) {
	raw, err := t.readOptional(ctx, sess, linkInventoryPath)
	if err != nil {
		return planningLinkInventoryDocument{}, err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return planningLinkInventoryDocument{Networks: []struct {
			Name         string `json:"name"`
			Subnet       string `json:"subnet"`
			Relationship string `json:"relationship"`
		}{}}, nil
	}
	var document planningLinkInventoryDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return planningLinkInventoryDocument{}, fmt.Errorf("decode planning link-network inventory: %w", err)
	}
	return document, nil
}
