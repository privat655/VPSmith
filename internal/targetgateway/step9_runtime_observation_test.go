package targetgateway

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/managementstate"
)

func TestStep9RuntimeObservationUsesRealImageTLSRouteAndDiskFacts(t *testing.T) {
	const caddyDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const autheliaDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

	runner := &captureRunner{}
	runner.hook = func(name string, args []string) ([]byte, []byte, error) {
		if name != "ssh" {
			return nil, nil, errors.New("unexpected process")
		}
		command := args[len(args)-1]
		switch {
		case strings.HasPrefix(command, "sudo -n du -s -B1 -- "):
			return []byte("125829120\n"), nil, nil
		case strings.Contains(command, coreInventoryPath):
			return []byte(`{"auth_domain":"auth.example.test","public_routes":[{"hostname":"app.example.test","path_prefix":"/","auth_mode":"protected"},{"hostname":"public.example.test","path_prefix":"/health","auth_mode":"public"}]}`), nil, nil
		case command == "podman inspect --format '{{.ImageName}}\\t{{.ImageDigest}}' 'caddy' 2>/dev/null || true":
			return []byte("docker.io/library/caddy:2.11.4-alpine\t" + caddyDigest + "\n"), nil, nil
		case command == "podman inspect --format '{{.ImageName}}\\t{{.ImageDigest}}' 'authelia' 2>/dev/null || true":
			return []byte("docker.io/authelia/authelia:4.39.20\t" + autheliaDigest + "\n"), nil, nil
		case strings.Contains(command, "--resolve 'auth.example.test:443:127.0.0.1'"):
			assertVerifiedHTTPSProbe(t, command, "https://auth.example.test/")
			return []byte("200\n"), nil, nil
		case strings.Contains(command, "--resolve 'app.example.test:443:127.0.0.1'"):
			assertVerifiedHTTPSProbe(t, command, "https://app.example.test/")
			return []byte("302\n"), nil, nil
		case strings.Contains(command, "--resolve 'public.example.test:443:127.0.0.1'"):
			assertVerifiedHTTPSProbe(t, command, "https://public.example.test/health")
			return []byte("204\n"), nil, nil
		default:
			t.Fatalf("unexpected Step 9 runtime observation command: %q", command)
			return nil, nil, nil
		}
	}

	transport := newSSHTransportAt(t.TempDir(), runner)
	key := testHostObservation(22)
	observed := managementstate.ObservedState{Core: managementstate.CoreObservedState{
		Present: true,
		Containers: []managementstate.ContainerObservedState{
			{Name: "caddy", Present: true, Running: true},
			{Name: "authelia", Present: true, Running: true},
		},
	}}
	if err := transport.enrichStep9Runtime(context.Background(), session{endpoint: endpoint{Address: "203.0.113.20", SSHUser: "dev"}, HostKey: key.PublicKey, IdentitySeed: bytes.Repeat([]byte{8}, 32)}, &observed); err != nil {
		t.Fatal(err)
	}
	if observed.Host.CoreBackupSourceBytes != 125829120 {
		t.Fatalf("Core backup source bytes=%d", observed.Host.CoreBackupSourceBytes)
	}
	if !observed.Core.HTTPS {
		t.Fatal("Core HTTPS was not proven")
	}
	if len(observed.Core.Containers) != 2 || observed.Core.Containers[0].ImageDigest != caddyDigest || observed.Core.Containers[1].ImageDigest != autheliaDigest {
		t.Fatalf("exact running image facts=%#v", observed.Core.Containers)
	}
	if len(observed.Core.PublicRoutes) != 2 {
		t.Fatalf("public route facts=%#v", observed.Core.PublicRoutes)
	}
	protected := observed.Core.PublicRoutes[0]
	if protected.StatusCode != 302 || !protected.HTTPS || !protected.AuthEnforced || protected.AuthMode != "protected" {
		t.Fatalf("protected route facts=%#v", protected)
	}
	public := observed.Core.PublicRoutes[1]
	if public.StatusCode != 204 || !public.HTTPS || !public.AuthEnforced || public.AuthMode != "public" {
		t.Fatalf("public route facts=%#v", public)
	}
}

func TestStep9RuntimeObservationFailsClosedWithoutRunningImageDigest(t *testing.T) {
	runner := &captureRunner{}
	runner.hook = func(name string, args []string) ([]byte, []byte, error) {
		command := args[len(args)-1]
		switch {
		case strings.HasPrefix(command, "sudo -n du -s -B1 -- "):
			return []byte("4096\n"), nil, nil
		case strings.Contains(command, coreInventoryPath):
			return []byte(`{"auth_domain":"auth.example.test","public_routes":[]}`), nil, nil
		case strings.HasPrefix(command, "podman inspect --format"):
			return []byte("docker.io/library/caddy:2.11.4-alpine\t\n"), nil, nil
		default:
			return nil, nil, errors.New("unexpected command")
		}
	}
	transport := newSSHTransportAt(t.TempDir(), runner)
	key := testHostObservation(23)
	observed := managementstate.ObservedState{Core: managementstate.CoreObservedState{Present: true, Containers: []managementstate.ContainerObservedState{{Name: "caddy", Present: true, Running: true}}}}
	err := transport.enrichStep9Runtime(context.Background(), session{endpoint: endpoint{Address: "203.0.113.21", SSHUser: "dev"}, HostKey: key.PublicKey, IdentitySeed: bytes.Repeat([]byte{9}, 32)}, &observed)
	if err == nil || !strings.Contains(err.Error(), "image identity") {
		t.Fatalf("missing running image digest error=%v", err)
	}
}

func assertVerifiedHTTPSProbe(t *testing.T, command, url string) {
	t.Helper()
	if !strings.Contains(command, "'"+url+"'") {
		t.Fatalf("HTTPS probe URL missing: %q", command)
	}
	if strings.Contains(command, " --insecure") || strings.Contains(command, " -k") {
		t.Fatalf("HTTPS probe disabled certificate verification: %q", command)
	}
}
