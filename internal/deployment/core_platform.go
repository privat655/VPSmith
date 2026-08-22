package deployment

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/privat655/VPSmith/internal/modulecontract"
)

const CoreAutheliaEnrollmentSelfServiceTOTP = "self-service-totp"

type CoreAutheliaConfiguration struct {
	Users      []string `json:"users,omitempty"`
	Groups     []string `json:"groups,omitempty"`
	Enrollment string   `json:"enrollment"`
}

type CorePublicRoute struct {
	Hostname   string `json:"hostname"`
	PathPrefix string `json:"path"`
	AuthMode   string `json:"auth_mode"`
}

type corePlatformRoute struct {
	CorePublicRoute
	Backend  string
	Users    []string
	Groups   []string
	Networks []string
}

type corePlatform struct {
	Routes   []corePlatformRoute
	Networks []string
}

func normalizeCoreAuthelia(value CoreAutheliaConfiguration) (CoreAutheliaConfiguration, error) {
	value.Users = normalizedSubjectNames(value.Users)
	value.Groups = normalizedSubjectNames(value.Groups)
	if value.Enrollment == "" {
		value.Enrollment = CoreAutheliaEnrollmentSelfServiceTOTP
	}
	if value.Enrollment != CoreAutheliaEnrollmentSelfServiceTOTP {
		return CoreAutheliaConfiguration{}, errors.New("Core Authelia enrollment must use self-service-totp")
	}
	for _, item := range append(append([]string(nil), value.Users...), value.Groups...) {
		if item == "" || strings.ContainsAny(item, "\r\n\t:'\"") {
			return CoreAutheliaConfiguration{}, fmt.Errorf("invalid Core Authelia subject %q", item)
		}
	}
	return value, nil
}

func normalizedSubjectNames(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func (c *Compiler) compileCorePlatform(coreContract string, sources []FrozenModuleSource, auth CoreAutheliaConfiguration) (corePlatform, error) {
	auth, err := normalizeCoreAuthelia(auth)
	if err != nil {
		return corePlatform{}, err
	}
	modules, err := c.compileFrozenPlatformModules(coreContract, sources)
	if err != nil {
		return corePlatform{}, err
	}
	return corePlatformFromModules(modules, auth)
}

type frozenPlatformModule struct {
	InstanceID string
	Contract   modulecontract.Module
}

func (c *Compiler) compileFrozenPlatformModules(coreContract string, sources []FrozenModuleSource) ([]frozenPlatformModule, error) {
	if c == nil {
		return nil, errors.New("deployment compiler is required")
	}
	if strings.TrimSpace(coreContract) == "" {
		return nil, errors.New("Core candidate core_contract is required")
	}
	ordered := append([]FrozenModuleSource(nil), sources...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].InstanceID < ordered[j].InstanceID })
	seen := map[string]struct{}{}
	out := make([]frozenPlatformModule, 0, len(ordered))
	for _, source := range ordered {
		if source.InstanceID == "" || source.SourceID == "" || source.PackageID == "" || source.PackageSHA256 == "" || source.PackageFS == nil {
			return nil, fmt.Errorf("module %s frozen source identity is incomplete", source.InstanceID)
		}
		if _, ok := seen[source.InstanceID]; ok {
			return nil, fmt.Errorf("duplicate installed module instance %s", source.InstanceID)
		}
		seen[source.InstanceID] = struct{}{}
		contract, err := c.modules.Compile(modulecontract.Package{FS: source.PackageFS})
		if err != nil {
			return nil, fmt.Errorf("compile module %s for Core platform: %w", source.InstanceID, err)
		}
		if contract.CoreContract != coreContract {
			return nil, fmt.Errorf("module %s requires core_contract %s, Core candidate provides %s", source.InstanceID, contract.CoreContract, coreContract)
		}
		out = append(out, frozenPlatformModule{InstanceID: source.InstanceID, Contract: contract})
	}
	return out, nil
}

func corePlatformFromModules(modules []frozenPlatformModule, auth CoreAutheliaConfiguration) (corePlatform, error) {
	users := stringSet(auth.Users)
	groups := stringSet(auth.Groups)
	seenRoutes := map[string]struct{}{}
	seenNetworks := map[string]struct{}{}
	var platform corePlatform
	for _, module := range modules {
		containers := map[string]modulecontract.Container{}
		for _, container := range module.Contract.Containers {
			containers[container.ID] = container
		}
		networks := map[string]modulecontract.Network{}
		for _, network := range module.Contract.Networks {
			networks[network.ID] = network
		}
		for _, route := range module.Contract.PublicRoutes {
			key := route.Hostname + "\x00" + route.PathPrefix
			if _, ok := seenRoutes[key]; ok {
				return corePlatform{}, fmt.Errorf("duplicate public route %s%s", route.Hostname, route.PathPrefix)
			}
			seenRoutes[key] = struct{}{}
			container, ok := containers[route.Container]
			if !ok {
				return corePlatform{}, fmt.Errorf("public route %s%s references unknown container %s", route.Hostname, route.PathPrefix, route.Container)
			}
			var routeNetworks []string
			for _, networkID := range container.Networks {
				network, ok := networks[networkID]
				if !ok || network.Role != "edge" {
					continue
				}
				name := "vpsmith-" + module.InstanceID + "-" + network.ID + ".network"
				routeNetworks = append(routeNetworks, name)
				seenNetworks[name] = struct{}{}
			}
			if len(routeNetworks) == 0 {
				return corePlatform{}, fmt.Errorf("public route %s%s has no edge network", route.Hostname, route.PathPrefix)
			}
			sort.Strings(routeNetworks)
			for _, user := range route.Authelia.Users {
				if _, ok := users[user]; !ok {
					return corePlatform{}, fmt.Errorf("public route %s%s references unknown Core Authelia user %s", route.Hostname, route.PathPrefix, user)
				}
			}
			for _, group := range route.Authelia.Groups {
				if _, ok := groups[group]; !ok {
					return corePlatform{}, fmt.Errorf("public route %s%s references unknown Core Authelia group %s", route.Hostname, route.PathPrefix, group)
				}
			}
			platform.Routes = append(platform.Routes, corePlatformRoute{
				CorePublicRoute: CorePublicRoute{Hostname: route.Hostname, PathPrefix: route.PathPrefix, AuthMode: route.Authelia.Mode},
				Backend:         fmt.Sprintf("vpsmith-%s-%s:%d", module.InstanceID, route.Container, route.Port),
				Users:           append([]string(nil), route.Authelia.Users...),
				Groups:          append([]string(nil), route.Authelia.Groups...),
				Networks:        routeNetworks,
			})
		}
	}
	sort.Slice(platform.Routes, func(i, j int) bool {
		if platform.Routes[i].Hostname == platform.Routes[j].Hostname {
			if platform.Routes[i].PathPrefix == platform.Routes[j].PathPrefix {
				return platform.Routes[i].Backend < platform.Routes[j].Backend
			}
			return platform.Routes[i].PathPrefix < platform.Routes[j].PathPrefix
		}
		return platform.Routes[i].Hostname < platform.Routes[j].Hostname
	})
	for network := range seenNetworks {
		platform.Networks = append(platform.Networks, network)
	}
	sort.Strings(platform.Networks)
	return platform, nil
}

func platformFromCompiledModules(mods []compiledModule) corePlatform {
	modules := make([]frozenPlatformModule, 0, len(mods))
	for _, mod := range mods {
		modules = append(modules, frozenPlatformModule{InstanceID: mod.Desired.InstanceID, Contract: mod.Contract})
	}
	platform, err := corePlatformFromModules(modules, CoreAutheliaConfiguration{Users: allRouteUsers(modules), Groups: allRouteGroups(modules), Enrollment: CoreAutheliaEnrollmentSelfServiceTOTP})
	if err != nil {
		panic(err)
	}
	return platform
}

func allRouteUsers(modules []frozenPlatformModule) []string {
	var out []string
	for _, module := range modules {
		for _, route := range module.Contract.PublicRoutes {
			out = append(out, route.Authelia.Users...)
		}
	}
	return normalizedSubjectNames(out)
}

func allRouteGroups(modules []frozenPlatformModule) []string {
	var out []string
	for _, module := range modules {
		for _, route := range module.Contract.PublicRoutes {
			out = append(out, route.Authelia.Groups...)
		}
	}
	return normalizedSubjectNames(out)
}

func stringSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}

func publicRouteExpectations(platform corePlatform) []CorePublicRoute {
	out := make([]CorePublicRoute, 0, len(platform.Routes))
	for _, route := range platform.Routes {
		out = append(out, route.CorePublicRoute)
	}
	return out
}

func renderLegacyCaddy(platform corePlatform) string {
	var b strings.Builder
	b.WriteString("{\n\tadmin off\n}\n\n")
	for _, route := range platform.Routes {
		fmt.Fprintf(&b, "%s {\n", route.Hostname)
		if route.PathPrefix != "/" {
			fmt.Fprintf(&b, "\thandle_path %s* {\n", route.PathPrefix)
		}
		indent := "\t"
		if route.PathPrefix != "/" {
			indent = "\t\t"
		}
		if route.AuthMode == "protected" {
			fmt.Fprintf(&b, "%sforward_auth authelia:9091 {\n%scopy_headers Remote-User Remote-Groups Remote-Email Remote-Name\n%s}\n", indent, indent+"\t", indent)
		}
		fmt.Fprintf(&b, "%sreverse_proxy %s\n", indent, route.Backend)
		if route.PathPrefix != "/" {
			b.WriteString("\t}\n")
		}
		b.WriteString("}\n\n")
	}
	return b.String()
}

func renderLegacyAuthelia(platform corePlatform) string {
	var b strings.Builder
	b.WriteString("access_control:\n  default_policy: deny\n  rules:\n")
	for _, route := range platform.Routes {
		policy := "bypass"
		if route.AuthMode == "protected" {
			policy = "two_factor"
		}
		fmt.Fprintf(&b, "    - domain: %s\n      policy: %s\n", route.Hostname, policy)
		if route.PathPrefix != "/" {
			fmt.Fprintf(&b, "      resources:\n        - '^%s.*$'\n", regexpQuote(route.PathPrefix))
		}
		if len(route.Users) > 0 || len(route.Groups) > 0 {
			b.WriteString("      subject:\n")
			for _, user := range route.Users {
				fmt.Fprintf(&b, "        - 'user:%s'\n", user)
			}
			for _, group := range route.Groups {
				fmt.Fprintf(&b, "        - 'group:%s'\n", group)
			}
		}
	}
	return b.String()
}

func renderPlatformNetworks(platform corePlatform) string {
	var b strings.Builder
	b.WriteString("[Container]\n")
	for _, network := range platform.Networks {
		fmt.Fprintf(&b, "Network=%s\n", network)
	}
	return b.String()
}

func renderCoreModuleSites(platform corePlatform) string {
	if len(platform.Routes) == 0 {
		return ""
	}
	byHost := map[string][]corePlatformRoute{}
	var hosts []string
	for _, route := range platform.Routes {
		if _, ok := byHost[route.Hostname]; !ok {
			hosts = append(hosts, route.Hostname)
		}
		byHost[route.Hostname] = append(byHost[route.Hostname], route)
	}
	sort.Strings(hosts)
	var b strings.Builder
	for _, host := range hosts {
		fmt.Fprintf(&b, "http://%s {\n\tredir https://%s{uri} permanent\n}\n\n", host, host)
		fmt.Fprintf(&b, "%s {\n\timport access_log\n\timport security_headers\n\timport strip_identity\n\tencode zstd gzip\n", host)
		routes := byHost[host]
		sort.SliceStable(routes, func(i, j int) bool {
			if routes[i].PathPrefix == "/" {
				return false
			}
			if routes[j].PathPrefix == "/" {
				return true
			}
			return len(routes[i].PathPrefix) > len(routes[j].PathPrefix)
		})
		hasRoot := false
		for _, route := range routes {
			if route.PathPrefix == "/" {
				hasRoot = true
				b.WriteString("\thandle {\n")
			} else {
				fmt.Fprintf(&b, "\thandle_path %s* {\n", route.PathPrefix)
			}
			if route.AuthMode == "protected" {
				b.WriteString("\t\timport authelia\n")
			}
			fmt.Fprintf(&b, "\t\treverse_proxy %s {\n", route.Backend)
			for _, header := range []string{"X-Forwarded-User", "X-Forwarded-Groups", "X-Forwarded-Email", "X-Forwarded-Name"} {
				fmt.Fprintf(&b, "\t\t\theader_up -%s\n", header)
			}
			b.WriteString("\t\t\theader_up Cookie \"authelia_session=[^;]+\" \"authelia_session=_\"\n")
			b.WriteString("\t\t}\n\t}\n")
		}
		if !hasRoot {
			b.WriteString("\thandle {\n\t\trespond \"not found\" 404\n\t}\n")
		}
		b.WriteString("}\n\n")
	}
	return b.String()
}

func renderCoreAutheliaRules(platform corePlatform) string {
	var b strings.Builder
	for _, route := range platform.Routes {
		policy := "bypass"
		if route.AuthMode == "protected" {
			policy = "two_factor"
		}
		fmt.Fprintf(&b, "    - domain: %s\n      policy: %s\n", route.Hostname, policy)
		if route.PathPrefix != "/" {
			fmt.Fprintf(&b, "      resources:\n        - '^%s.*$'\n", regexpQuote(route.PathPrefix))
		}
		if len(route.Users) > 0 || len(route.Groups) > 0 {
			b.WriteString("      subject:\n")
			for _, user := range route.Users {
				fmt.Fprintf(&b, "        - 'user:%s'\n", user)
			}
			for _, group := range route.Groups {
				fmt.Fprintf(&b, "        - 'group:%s'\n", group)
			}
		}
	}
	return b.String()
}
