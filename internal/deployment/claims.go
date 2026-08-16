package deployment

import (
	"fmt"
	"sort"
	"strings"
)

type claim struct{ Kind, Value, Owner string }

func validateClaims(mods []compiledModule, links []LinkNetwork, observed []ObservedClaim) error {
	claims := deriveClaims(mods, links)
	for _, o := range observed {
		if strings.TrimSpace(o.Kind) == "" || strings.TrimSpace(o.Value) == "" {
			return fmt.Errorf("observed claim is incomplete")
		}
		claims = append(claims, claim{Kind: o.Kind, Value: o.Value, Owner: "observed:" + o.Owner})
	}
	sort.Slice(claims, func(i, j int) bool {
		if claims[i].Kind != claims[j].Kind {
			return claims[i].Kind < claims[j].Kind
		}
		if claims[i].Value != claims[j].Value {
			return claims[i].Value < claims[j].Value
		}
		return claims[i].Owner < claims[j].Owner
	})
	for i := 1; i < len(claims); i++ {
		a, b := claims[i-1], claims[i]
		if a.Kind == b.Kind && a.Value == b.Value && !sameLogicalOwner(a.Owner, b.Owner) {
			return fmt.Errorf("resource collision: %s %s claimed by %s and %s", a.Kind, a.Value, a.Owner, b.Owner)
		}
	}
	return nil
}

func deriveClaims(mods []compiledModule, links []LinkNetwork) []claim {
	var claims []claim
	for _, m := range mods {
		prefix := "vpsmith-" + m.Desired.InstanceID
		for _, c := range m.Contract.Containers {
			claims = append(claims,
				claim{"container", prefix + "-" + c.ID, m.Desired.InstanceID},
				claim{"unit", prefix + "-" + c.ID + ".service", m.Desired.InstanceID})
		}
		for _, s := range m.Contract.Persistent {
			claims = append(claims, claim{"path", s.Path, m.Desired.InstanceID})
		}
		for _, n := range m.Contract.Networks {
			claims = append(claims, claim{"network", prefix + "-" + n.ID, m.Desired.InstanceID})
		}
		for _, r := range m.Contract.PublicRoutes {
			claims = append(claims, claim{"hostname", strings.ToLower(r.Hostname), m.Desired.InstanceID})
		}
		for _, id := range m.Desired.SecretIDs {
			claims = append(claims, claim{"secret", id, m.Desired.InstanceID})
		}
	}
	for _, l := range links {
		claims = append(claims,
			claim{"network", l.Name, l.Relationship},
			claim{"subnet", l.Subnet, l.Relationship},
			claim{"alias", l.Name + ":" + l.Alias, l.Relationship})
	}
	return claims
}

func sameLogicalOwner(a, b string) bool {
	trim := func(v string) string { return strings.TrimPrefix(v, "observed:") }
	return trim(a) != "" && trim(a) == trim(b)
}
