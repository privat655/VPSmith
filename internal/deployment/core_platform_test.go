package deployment

import (
	"context"
	"strings"
	"testing"
)

func TestPrepareCoreCompilesInstalledModulePlatformContributionsWithoutModuleSpecialCases(t *testing.T) {
	compiler := coreCompiler(t)
	req := coreRequest(Install)
	req.Authelia = CoreAutheliaConfiguration{
		Groups: []string{"admins"}, Enrollment: CoreAutheliaEnrollmentSelfServiceTOTP,
	}
	req.InstalledModules = []FrozenModuleSource{reqSource("n8n-1", "n8n", "2.0.0", "[]")}

	prepared, err := compiler.PrepareCore(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.PublicRoutes) != 1 || prepared.PublicRoutes[0] != (CorePublicRoute{Hostname: "n8n.example.test", PathPrefix: "/", AuthMode: "protected"}) {
		t.Fatalf("compiled public routes=%#v", prepared.PublicRoutes)
	}

	artifacts := map[string]string{}
	for _, artifact := range prepared.Artifacts {
		artifacts[artifact.TargetPath] = string(artifact.Data)
	}
	caddy := artifacts["/var/lib/vpsmith/core/caddy/Caddyfile"]
	for _, want := range []string{
		"n8n.example.test",
		"import authelia",
		"reverse_proxy vpsmith-n8n-1-app:8080",
		"header_up -X-Forwarded-User",
		"header_up Cookie \"authelia_session=[^;]+\" \"authelia_session=_\"",
	} {
		if !strings.Contains(caddy, want) {
			t.Fatalf("generated Core Caddyfile missing %q:\n%s", want, caddy)
		}
	}
	quadlet := artifacts["/home/vpsmith/.config/containers/systemd/caddy.container"]
	if !strings.Contains(quadlet, "Network=vpsmith-n8n-1-edge.network") {
		t.Fatalf("Caddy is not attached to the module edge network:\n%s", quadlet)
	}
	authelia := artifacts["/var/lib/vpsmith/core/authelia/configuration.yml"]
	for _, want := range []string{
		"domain: n8n.example.test",
		"policy: two_factor",
		"- 'group:admins'",
	} {
		if !strings.Contains(authelia, want) {
			t.Fatalf("generated Core Authelia configuration missing %q:\n%s", want, authelia)
		}
	}
	if strings.Contains(authelia, "domain: '*.example.test'") {
		t.Fatalf("Core Authelia configuration retained the old wildcard policy instead of exact module contributions:\n%s", authelia)
	}
}

func TestPrepareCoreRejectsModuleRouteSubjectOutsideCanonicalAutheliaCatalog(t *testing.T) {
	compiler := coreCompiler(t)
	req := coreRequest(Install)
	req.InstalledModules = []FrozenModuleSource{reqSource("n8n-1", "n8n", "2.0.0", "[]")}

	_, err := compiler.PrepareCore(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "admins") {
		t.Fatalf("missing Authelia group error=%v", err)
	}
}

func TestCoreCompatibilityAndPlatformGenerationShareTheSameFrozenModuleContract(t *testing.T) {
	compiler := coreCompiler(t)
	module := reqSource("custom-1", "custom", "2.0.0", "[]")
	if err := compiler.CheckCoreCompatibility("1.0", []FrozenModuleSource{module}); err != nil {
		t.Fatal(err)
	}

	req := coreRequest(Install)
	req.Authelia = CoreAutheliaConfiguration{Groups: []string{"admins"}}
	req.InstalledModules = []FrozenModuleSource{module}
	prepared, err := compiler.PrepareCore(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.PublicRoutes) != 1 || prepared.PublicRoutes[0].Hostname != "custom.example.test" {
		t.Fatalf("generic module route was not compiled: %#v", prepared.PublicRoutes)
	}
}
