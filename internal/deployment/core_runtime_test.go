package deployment

import (
	"context"
	"strings"
	"testing"
)

func TestPrepareCoreGeneratesCompleteRuntimeFromDesiredState(t *testing.T) {
	compiler := coreCompiler(t)
	req := coreRequest(Install)

	prepared, err := compiler.PrepareCore(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	artifacts := make(map[string]GeneratedArtifact, len(prepared.Artifacts))
	for _, item := range prepared.Artifacts {
		artifacts[item.TargetPath] = item
	}
	for _, path := range []string{
		coreDesiredTarget,
		"/etc/systemd/journald.conf.d/90-vpsmith-core.conf",
		"/etc/systemd/coredump.conf.d/90-vpsmith-core.conf",
		"/etc/systemd/system/tmp.mount",
		"/etc/modprobe.d/90-vpsmith-core-blocklist.conf",
		"/etc/sysctl.d/90-vpsmith-core.conf",
		"/etc/audit/rules.d/90-vpsmith-core.rules",
		"/etc/containers/containers.conf.d/90-vpsmith-rootless.conf",
		"/etc/systemd/system/caddy-edge-http.socket",
		"/etc/systemd/system/caddy-edge-http.service",
		"/etc/systemd/system/caddy-edge-https.socket",
		"/etc/systemd/system/caddy-edge-https.service",
		"/var/lib/vpsmith/core/caddy/Caddyfile",
		"/var/lib/vpsmith/core/authelia/configuration.yml",
		"/home/vpsmith/.config/containers/systemd/vpsmith-core.network",
		"/home/vpsmith/.config/containers/systemd/authelia.container",
		"/home/vpsmith/.config/containers/systemd/caddy.container",
		"/var/lib/vpsmith/core/generated/inventory.json",
	} {
		if _, ok := artifacts[path]; !ok {
			t.Fatalf("missing generated Core runtime artifact %s", path)
		}
	}

	caddy := string(artifacts["/var/lib/vpsmith/core/caddy/Caddyfile"].Data)
	for _, required := range []string{
		"admin off",
		"email admin@example.test",
		"auth.example.test",
		"forward_auth authelia:9091",
		"uri /api/authz/forward-auth",
		"request_header -Remote-User",
		"request_header -X-Forwarded-User",
		"respond \"not found\" 404",
	} {
		if !strings.Contains(caddy, required) {
			t.Fatalf("generated Caddyfile missing %q:\n%s", required, caddy)
		}
	}

	authelia := string(artifacts["/var/lib/vpsmith/core/authelia/configuration.yml"].Data)
	for _, required := range []string{
		"default_2fa_method: totp",
		"default_policy: deny",
		"domain: auth.example.test",
		"policy: bypass",
		"domain: '*.example.test'",
		"policy: two_factor",
		"authelia_url: https://auth.example.test",
		"path: /config/users_database.yml",
		"path: /data/db.sqlite3",
	} {
		if !strings.Contains(authelia, required) {
			t.Fatalf("generated Authelia config missing %q:\n%s", required, authelia)
		}
	}

	caddyQuadlet := string(artifacts["/home/vpsmith/.config/containers/systemd/caddy.container"].Data)
	for _, required := range []string{
		"UserNS=nomap",
		"PublishPort=127.0.0.1:8080:80/tcp",
		"PublishPort=127.0.0.1:8443:443/tcp",
		"ReadOnly=true",
		"NoNewPrivileges=true",
	} {
		if !strings.Contains(caddyQuadlet, required) {
			t.Fatalf("generated Caddy Quadlet missing %q:\n%s", required, caddyQuadlet)
		}
	}
	for _, ref := range prepared.Bundle.Manifest.Images {
		if !strings.Contains(caddyQuadlet+string(artifacts["/home/vpsmith/.config/containers/systemd/authelia.container"].Data), ref.Digest) {
			t.Fatalf("runtime Quadlets do not use frozen digest for %s", ref.Name)
		}
	}

	sysctl := string(artifacts["/etc/sysctl.d/90-vpsmith-core.conf"].Data)
	if !strings.Contains(sysctl, "net.ipv4.ip_unprivileged_port_start = 1024") || !strings.Contains(sysctl, "net.ipv6.conf.all.disable_ipv6 = 1") {
		t.Fatalf("generated Core sysctl contract is incomplete:\n%s", sysctl)
	}
}
