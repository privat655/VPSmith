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
	if !observed.Core.Caddy.ConfigChecked || !observed.Core.Caddy.ConfigValid {
		t.Fatalf("caddy facts = %#v", observed.Core.Caddy)
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
		case strings.Contains(command, coreInventoryPath):
			return []byte(`{"source_id":"core-source","version":"1","package_sha256":"` + sha + `","units":[{"name":"core.service","scope":"user"}],"containers":["caddy"],"networks":["core-net"],"caddy":{"unit":{"name":"core.service","scope":"user"},"container":"caddy","config_path":"/etc/vpsmith/Caddyfile"},"authelia":{"unit":{"name":"core.service","scope":"user"},"container":"caddy"},"managed_artifacts":["/etc/vpsmith/Caddyfile"],"execution_proofs":[{"id":"exec-1","outcome":"success","sha256":"` + sha + `"}]}`), nil, nil
		case strings.Contains(command, moduleInventoryPath):
			return []byte(`{"modules":[{"instance_id":"module-a","package_id":"pkg-a","version":"1","package_sha256":"` + sha + `","units":[{"name":"module-a.service","scope":"user"}],"containers":["module-a"],"networks":["core-net"],"managed_artifacts":["/var/lib/vpsmith/module-a/config.json"]}]}`), nil, nil
		case strings.Contains(command, linkInventoryPath):
			return []byte(`{"networks":[{"name":"core-net"}]}`), nil, nil
		case command == `if command -v podman >/dev/null 2>&1; then podman info --format json; fi`:
			return []byte(`{"host":{"cgroupVersion":"v2","security":{"rootless":true},"rootlessNetworkCmd":"pasta"}}`), nil, nil
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
