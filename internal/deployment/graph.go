package deployment

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"

	"github.com/privat655/VPSmith/internal/modulecontract"
)

func deriveLinks(mods []compiledModule, observed []ObservedNetwork) ([]LinkNetwork, error) {
	byModule := map[string][]compiledModule{}
	for _, m := range mods {
		byModule[m.Contract.ID] = append(byModule[m.Contract.ID], m)
	}
	byRelationship := map[string]ObservedNetwork{}
	usedSubnets := map[string]string{}
	usedNames := map[string]string{}
	for _, n := range observed {
		ownerKey := n.Relationship
		if ownerKey == "" {
			ownerKey = "observed:" + n.Name
		}
		if n.Name != "" {
			if owner, exists := usedNames[n.Name]; exists && owner != ownerKey {
				return nil, fmt.Errorf("observed network name collision %s", n.Name)
			}
			usedNames[n.Name] = ownerKey
		}
		if n.Subnet != "" {
			if _, err := netip.ParsePrefix(n.Subnet); err != nil {
				return nil, fmt.Errorf("observed network %s has invalid subnet", n.Name)
			}
			if owner, exists := usedSubnets[n.Subnet]; exists && owner != ownerKey {
				return nil, fmt.Errorf("observed subnet collision %s", n.Subnet)
			}
			usedSubnets[n.Subnet] = ownerKey
		}
		if n.Relationship != "" {
			if _, exists := byRelationship[n.Relationship]; exists {
				return nil, fmt.Errorf("duplicate observed Link-Net relationship %s", n.Relationship)
			}
			byRelationship[n.Relationship] = n
		}
	}

	var out []LinkNetwork
	for _, consumer := range mods {
		for _, d := range consumer.Contract.Dependencies {
			provider, iface, err := resolveProvider(byModule, consumer, d)
			if err != nil {
				return nil, err
			}
			rel := provider.Desired.InstanceID + "/" + d.InterfaceID + "->" + consumer.Desired.InstanceID + "/" + d.Consumer
			digest := sha256.Sum256([]byte(rel))
			name := "vpsmith-link-" + hex.EncodeToString(digest[:6])
			alias := "if-" + hex.EncodeToString(digest[:4])
			subnet, err := selectLinkSubnet(rel, name, digest, byRelationship, usedNames, usedSubnets)
			if err != nil {
				return nil, err
			}
			usedNames[name] = rel
			usedSubnets[subnet] = rel
			out = append(out, LinkNetwork{
				Relationship: rel, Name: name, Subnet: subnet, Alias: alias,
				Provider: provider.Desired.InstanceID + "/" + iface.Container,
				Consumer: consumer.Desired.InstanceID + "/" + d.Consumer,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Relationship < out[j].Relationship })
	return out, nil
}

func resolveProvider(byModule map[string][]compiledModule, consumer compiledModule, d modulecontract.Dependency) (compiledModule, *modulecontract.InternalInterface, error) {
	providers := byModule[d.TargetModule]
	if len(providers) == 0 {
		return compiledModule{}, nil, fmt.Errorf("dependency %s/%s has missing provider %s", consumer.Desired.InstanceID, d.InterfaceID, d.TargetModule)
	}
	if len(providers) > 1 {
		return compiledModule{}, nil, fmt.Errorf("dependency %s/%s has ambiguous provider %s", consumer.Desired.InstanceID, d.InterfaceID, d.TargetModule)
	}
	provider := providers[0]
	for i := range provider.Contract.Interfaces {
		if provider.Contract.Interfaces[i].ID == d.InterfaceID {
			return provider, &provider.Contract.Interfaces[i], nil
		}
	}
	return compiledModule{}, nil, fmt.Errorf("provider %s does not offer interface %s", provider.Desired.InstanceID, d.InterfaceID)
}

func selectLinkSubnet(rel, name string, sum [32]byte, byRelationship map[string]ObservedNetwork, usedNames, usedSubnets map[string]string) (string, error) {
	if existing, ok := byRelationship[rel]; ok {
		if existing.Name != name {
			return "", fmt.Errorf("Link-Net relationship %s has unexpected observed name %s", rel, existing.Name)
		}
		if existing.Subnet == "" {
			return "", fmt.Errorf("Link-Net relationship %s has no observed subnet", rel)
		}
		if owner := usedSubnets[existing.Subnet]; owner != "" && owner != rel {
			return "", fmt.Errorf("Link-Net subnet %s collides with %s", existing.Subnet, owner)
		}
		return existing.Subnet, nil
	}
	if owner := usedNames[name]; owner != "" && owner != rel {
		return "", fmt.Errorf("Link-Net name %s collides with observed network", name)
	}
	return chooseSubnet(sum, usedSubnets)
}

func chooseSubnet(sum [32]byte, used map[string]string) (string, error) {
	seed := (int(sum[0]) << 8) | int(sum[1])
	for probe := 0; probe < 4096; probe++ {
		v := (seed + probe) & 0x0fff
		candidate := fmt.Sprintf("10.%d.%d.0/24", 240+(v>>8), v&0xff)
		if used[candidate] == "" {
			return candidate, nil
		}
	}
	return "", errors.New("no collision-free Link-Net subnet available")
}
