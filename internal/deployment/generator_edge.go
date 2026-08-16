package deployment

import (
	"fmt"
	"sort"
	"strings"
)

func generateCaddy(mods []compiledModule) string {
	var b strings.Builder
	b.WriteString("{\n\tadmin off\n}\n\n")
	for _, m := range mods {
		for _, r := range m.Contract.PublicRoutes {
			fmt.Fprintf(&b, "%s {\n", r.Hostname)
			if r.PathPrefix != "/" {
				fmt.Fprintf(&b, "\thandle_path %s* {\n", r.PathPrefix)
			}
			indent := "\t"
			if r.PathPrefix != "/" {
				indent = "\t\t"
			}
			if r.Authelia.Mode == "protected" {
				fmt.Fprintf(&b, "%sforward_auth authelia:9091 {\n%scopy_headers Remote-User Remote-Groups Remote-Email Remote-Name\n%s}\n", indent, indent+"\t", indent)
			}
			fmt.Fprintf(&b, "%sreverse_proxy vpsmith-%s-%s:%d\n", indent, m.Desired.InstanceID, r.Container, r.Port)
			if r.PathPrefix != "/" {
				b.WriteString("\t}\n")
			}
			b.WriteString("}\n\n")
		}
	}
	return b.String()
}

func generateAuthelia(mods []compiledModule) string {
	var b strings.Builder
	b.WriteString("access_control:\n  default_policy: deny\n  rules:\n")
	for _, m := range mods {
		for _, r := range m.Contract.PublicRoutes {
			policy := "bypass"
			if r.Authelia.Mode == "protected" {
				policy = "two_factor"
			}
			fmt.Fprintf(&b, "    - domain: %s\n      policy: %s\n", r.Hostname, policy)
			if r.PathPrefix != "/" {
				fmt.Fprintf(&b, "      resources:\n        - '^%s.*$'\n", regexpQuote(r.PathPrefix))
			}
			if len(r.Authelia.Users) > 0 || len(r.Authelia.Groups) > 0 {
				b.WriteString("      subject:\n")
				for _, u := range r.Authelia.Users {
					fmt.Fprintf(&b, "        - 'user:%s'\n", u)
				}
				for _, g := range r.Authelia.Groups {
					fmt.Fprintf(&b, "        - 'group:%s'\n", g)
				}
			}
		}
	}
	return b.String()
}

func regexpQuote(v string) string {
	r := strings.NewReplacer(".", "\\.", "+", "\\+", "?", "\\?", "(", "\\(", ")", "\\)", "[", "\\[", "]", "\\]", "{", "\\{", "}", "\\}", "^", "\\^", "$", "\\$", "|", "\\|")
	return r.Replace(v)
}

func generateCaddyNetworks(mods []compiledModule) string {
	seen := map[string]struct{}{}
	var values []string
	for _, m := range mods {
		needed := map[string]struct{}{}
		for _, r := range m.Contract.PublicRoutes {
			needed[r.Container] = struct{}{}
		}
		for _, c := range m.Contract.Containers {
			if _, ok := needed[c.ID]; !ok {
				continue
			}
			for _, nID := range c.Networks {
				for _, n := range m.Contract.Networks {
					if n.ID == nID && n.Role == "edge" {
						value := "vpsmith-" + m.Desired.InstanceID + "-" + n.ID + ".network"
						if _, ok := seen[value]; !ok {
							seen[value] = struct{}{}
							values = append(values, value)
						}
					}
				}
			}
		}
	}
	sort.Strings(values)
	var b strings.Builder
	b.WriteString("[Container]\n")
	for _, value := range values {
		fmt.Fprintf(&b, "Network=%s\n", value)
	}
	return b.String()
}
