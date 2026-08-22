package targetgateway

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestStep9HostFactsUsesSSHAdministratorInsteadOfSudoUser(t *testing.T) {
	runner := &captureRunner{}
	runner.hook = func(name string, args []string) ([]byte, []byte, error) {
		if name != "ssh" {
			t.Fatalf("process = %q, want ssh", name)
		}
		command := args[len(args)-1]
		if !strings.Contains(command, "ADMIN_USER=$1") {
			t.Fatalf("Step 9 probe does not bind the explicit administrator: %s", command)
		}
		if strings.Contains(command, "$USER") {
			t.Fatalf("Step 9 probe still depends on sudo USER: %s", command)
		}
		if !strings.Contains(command, "-- 'vpsmith'") {
			t.Fatalf("Step 9 probe did not receive the SSH administrator argument: %s", command)
		}
		return []byte(step9HostFactsFixture), nil, nil
	}

	transport := newSSHTransportAt(t.TempDir(), runner)
	key := testHostObservation(9)
	facts, _, _, err := transport.step9HostFacts(context.Background(), session{
		endpoint: endpoint{Address: "203.0.113.15", SSHUser: "vpsmith"},
		HostKey: key.PublicKey, IdentitySeed: bytes.Repeat([]byte{9}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !facts.SubUIDRangePresent || !facts.SubGIDRangePresent || !facts.LingerEnabled {
		t.Fatalf("runtime foundation facts = %#v", facts)
	}
}
