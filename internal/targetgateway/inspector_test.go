package targetgateway

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/managementstate"
)

func TestProductionInspectionUsesOnlyKnownReadOnlyShapes(t *testing.T) {
	runner := &captureRunner{}
	runner.hook = inspectionFixture(t)
	transport := newSSHTransportAt(t.TempDir(), runner)
	key := testHostObservation(4)
	observed, err := transport.Inspect(context.Background(), session{endpoint: endpoint{Address: "203.0.113.11", SSHUser: "dev"}, HostKey: key.PublicKey, IdentitySeed: bytes.Repeat([]byte{6}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if !observed.Host.Reachable || !observed.CloudInit.Present || !observed.Core.Present || !observed.Core.Podman.Rootless || len(observed.Modules) != 1 || len(observed.LinkNetworks) != 1 {
		t.Fatalf("inspection = %#v", observed)
	}
	if !observed.Host.PrimaryHardening.SSHConfigValid || !observed.Host.PrimaryHardening.UFWLoggingLow || !observed.Host.PrimaryHardening.Fail2banRecidiveActive {
		t.Fatalf("primary hardening facts = %#v", observed.Host.PrimaryHardening)
	}
	if !observed.Core.Caddy.ConfigChecked || !observed.Core.Caddy.ConfigValid {
		t.Fatalf("caddy facts = %#v", observed.Core.Caddy)
	}
	link := observed.LinkNetworks[0]
	if link.Subnet != "10.240.1.0/24" || link.Relationship != "provider-1/api->module-a/app" || !link.DefinitionMatches {
		t.Fatalf("link facts = %#v", link)
	}
	if len(observed.PodmanNetworks) != 2 || observed.PodmanNetworks[0].Name != "core-net" || observed.PodmanNetworks[1].Name != "foreign-net" {
		t.Fatalf("podman networks = %#v", observed.PodmanNetworks)
	}
	if !reflect.DeepEqual(observed.PodmanNetworks[1].Subnets, []string{"10.240.2.0/24"}) {
		t.Fatalf("foreign network subnets = %#v", observed.PodmanNetworks[1].Subnets)
	}
}

func TestProductionInspectionKeepsManagedLinkDefinitionDriftVisible(t *testing.T) {
	base := inspectionFixture(t)
	runner := &captureRunner{}
	runner.hook = func(name string, args []string) ([]byte, []byte, error) {
		command := args[len(args)-1]
		if command == `if command -v podman >/dev/null 2>&1; then podman network ls --format json; fi` {
			return []byte(`[{"name":"core-net","internal":true,"labels":{"vpsmith.relationship":"provider-1/api->module-a/app"},"subnets":[{"subnet":"10.240.99.0/24"}]}]`), nil, nil
		}
		return base(name, args)
	}
	transport := newSSHTransportAt(t.TempDir(), runner)
	key := testHostObservation(4)
	observed, err := transport.Inspect(context.Background(), session{endpoint: endpoint{Address: "203.0.113.11", SSHUser: "dev"}, HostKey: key.PublicKey, IdentitySeed: bytes.Repeat([]byte{6}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if len(observed.LinkNetworks) != 1 || observed.LinkNetworks[0].DefinitionMatches {
		t.Fatalf("drifted link facts = %#v", observed.LinkNetworks)
	}
	if observed.LinkNetworks[0].Subnet != "10.240.99.0/24" {
		t.Fatalf("actual subnet was not preserved: %#v", observed.LinkNetworks[0])
	}
}

func inspectionFixture(t *testing.T) func(string, []string) ([]byte, []byte, error) {
	t.Helper()
	sha := strings.Repeat("a", 64)
	return func(name string, args []string) ([]byte, []byte, error) {
		if name != "ssh" {
			return nil, nil, errors.New("unexpected process")
		}
		command := args[len(args)-1]
		switch {
		case strings.HasPrefix(command, "set -eu\nhostname="):
			return []byte("hostname\tvps-1\nkernel\tLinux 6.1\nos_id\tdebian\nos_version\t12\nroot_total\t100000\nroot_available\t50000\nmem_total\t200000\nmem_available\t100000\nswap_total\t10000\nswap_free\t8000\nreboot\t0\nufw\t1\nfail2ban\t1\n"), nil, nil
		case strings.Contains(command, cloudInitStatusPath):
			return []byte("status=ok\nversion=1\nfinished_at=2026-08-16T09:00:00Z\n"), nil, nil
		case strings.HasPrefix(command, "sudo -n sh -eu -c ") &&
			strings.Contains(command, "ssh_config_valid") &&
			strings.Contains(command, "sshd -T -C user=") &&
			strings.Contains(command, "ufw status verbose") &&
			strings.Contains(command, "fail2ban-client status recidive") &&
			strings.Contains(command, "apt-config shell"):
			return []byte("ssh_config_valid\t1\nssh_permitrootlogin\tno\nssh_passwordauthentication\tno\nssh_kbdinteractiveauthentication\tno\nssh_pubkeyauthentication\tyes\nssh_authenticationmethods\tpublickey\nssh_permitemptypasswords\tno\nssh_logingracetime\t20\nssh_maxauthtries\t3\nssh_maxsessions\t3\nssh_maxstartups\t10:30:60\nssh_x11forwarding\tno\nssh_allowagentforwarding\tno\nssh_allowtcpforwarding\tno\nssh_allowstreamlocalforwarding\tno\nssh_permittunnel\tno\nssh_gatewayports\tno\nssh_permituserenvironment\tno\nssh_compression\tno\nssh_loglevel\tVERBOSE\nufw_active\t1\nufw_logging_low\t1\nufw_incoming\tdeny\nufw_routed\tdeny\nufw_port\t22\nufw_port\t80\nufw_port\t443\nfail2ban_sshd\t1\nfail2ban_recidive\t1\nunattended\t1\nautomatic_reboot\tfalse\n"), nil, nil
		case strings.Contains(command, coreInventoryPath):
			return []byte(`{"source_id":"core-source","version":"1","package_sha256":"` + sha + `","units":[{"name":"core.service","scope":"user"}],"containers":["caddy"],"networks":["core-net"],"caddy":{"unit":{"name":"core.service","scope":"user"},"container":"caddy","config_path":"/etc/vpsmith/Caddyfile"},"authelia":{"unit":{"name":"core.service","scope":"user"},"container":"caddy"},"managed_artifacts":["/etc/vpsmith/Caddyfile"],"execution_proofs":[{"id":"exec-1","outcome":"success","sha256":"` + sha + `"}]}`), nil, nil
		case strings.Contains(command, moduleInventoryPath):
			return []byte(`{"modules":[{"instance_id":"module-a","package_id":"pkg-a","version":"1","package_sha256":"` + sha + `","units":[{"name":"module-a.service","scope":"user"}],"containers":["module-a"],"networks":["core-net"],"managed_artifacts":["/var/lib/vpsmith/module-a/config.json"]}]}`), nil, nil
		case strings.Contains(command, linkInventoryPath):
			return []byte(`{"networks":[{"relationship":"provider-1/api->module-a/app","name":"core-net","subnet":"10.240.1.0/24","alias":"if-aabbccdd","provider":"provider-1/app","consumer":"module-a/app"}]}`), nil, nil
		case command == `if command -v podman >/dev/null 2>&1; then podman info --format json; fi`:
			return []byte(`{"host":{"cgroupVersion":"v2","security":{"rootless":true},"rootlessNetworkCmd":"pasta"}}`), nil, nil
		case command == `if command -v podman >/dev/null 2>&1; then podman network ls --format json; fi`:
			return []byte(`[{"name":"core-net","internal":true,"labels":{"vpsmith.relationship":"provider-1/api->module-a/app"},"subnets":[{"subnet":"10.240.1.0/24"}]},{"name":"foreign-net","internal":false,"labels":{},"subnets":[{"subnet":"10.240.2.0/24"}]}]`), nil, nil
		case strings.HasPrefix(command, "systemctl --user show --no-pager --property=LoadState"):
			return []byte("LoadState=loaded\nActiveState=active\nSubState=running\n"), nil, nil
		case command == "podman inspect 'caddy' 2>/dev/null || true", command == "podman inspect 'module-a' 2>/dev/null || true":
			return []byte(`[{"State":{"Running":true,"Health":{"Status":"healthy"}},"NetworkSettings":{"Networks":{"core-net":{}}}}]`), nil, nil
		case command == "podman network inspect 'core-net' 2>/dev/null || true":
			return []byte(`[{"name":"core-net","internal":true,"containers":{"1":{"name":"caddy"},"2":{"name":"module-a"}}}]`), nil, nil
		case strings.HasPrefix(command, "if [ -f '") && strings.Contains(command, "sha256sum --"):
			return []byte(sha + "  file\n"), nil, nil
		case command == "podman exec 'caddy' caddy validate --config '/etc/vpsmith/Caddyfile'":
			return nil, nil, nil
		default:
			t.Fatalf("unexpected inspection operation: %q", command)
			return nil, nil, nil
		}
	}
}

func TestNormalizeObservedStateDoesNotChangeFactMeaning(t *testing.T) {
	value := richObservedFacts()
	before := cloneObserved(value)
	managementstate.NormalizeObservedState(&value)
	if len(value.Modules) != len(before.Modules) || !reflect.DeepEqual(value.Host, before.Host) || !reflect.DeepEqual(value.CloudInit, before.CloudInit) {
		t.Fatal("normalization changed non-ordering facts")
	}
}
