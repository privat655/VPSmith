package targetgateway

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestCoreBackupRuntimeUsesFixedServicesThroughStrictSSH(t *testing.T) {
	runner := &streamingCaptureRunner{}
	transport := newSSHTransportAt(t.TempDir(), runner)
	sess := session{
		endpoint:     endpoint{Address: "203.0.113.10", SSHUser: "dev"},
		HostKey:      testHostObservation(31).PublicKey,
		IdentitySeed: bytes.Repeat([]byte{7}, 32),
	}

	if err := transport.QuiesceCoreRuntime(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
	if err := transport.ResumeAndValidateCoreRuntime(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("remote calls=%d, want 2", len(runner.calls))
	}
	for i, call := range runner.calls {
		if call.name != "ssh" {
			t.Fatalf("call %d uses %q, want strict ssh", i, call.name)
		}
		for _, required := range []string{"-F", "none", "BatchMode=yes", "StrictHostKeyChecking=yes", "IdentityAgent=none"} {
			if !containsArg(call.args, required) {
				t.Fatalf("call %d missing strict ssh argument %q: %#v", i, required, call.args)
			}
		}
	}

	stop := runner.calls[0].args[len(runner.calls[0].args)-1]
	for _, required := range []string{
		"systemctl --user is-active --quiet caddy.service",
		"systemctl --user is-active --quiet authelia.service",
		"systemctl --user stop caddy.service authelia.service",
	} {
		if !strings.Contains(stop, required) {
			t.Fatalf("quiesce command missing %q: %s", required, stop)
		}
	}

	resume := runner.calls[1].args[len(runner.calls[1].args)-1]
	for _, required := range []string{
		"systemctl --user start authelia.service caddy.service",
		"podman exec caddy caddy validate",
		"podman exec authelia",
		"/var/lib/vpsmith/core/desired.json",
		"https://auth.${domain}",
	} {
		if !strings.Contains(resume, required) {
			t.Fatalf("resume command missing %q: %s", required, resume)
		}
	}
}
