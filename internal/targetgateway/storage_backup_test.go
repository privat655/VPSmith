package targetgateway

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"
)

type streamingCaptureRunner struct {
	calls []processCall
	data  []byte
}

func (r *streamingCaptureRunner) Run(_ context.Context, name string, args ...string) ([]byte, []byte, error) {
	r.calls = append(r.calls, processCall{name: name, args: append([]string(nil), args...)})
	return nil, nil, nil
}

func (r *streamingCaptureRunner) RunOutput(_ context.Context, output io.Writer, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, processCall{name: name, args: append([]string(nil), args...)})
	_, err := output.Write(r.data)
	return nil, err
}

func TestStreamedStorageTransferUsesSharedStrictSSHInvocation(t *testing.T) {
	runtimeDir := t.TempDir()
	key := testHostObservation(9)
	runner := &streamingCaptureRunner{data: []byte("streamed-storage")}
	transport := newSSHTransportAt(runtimeDir, runner)
	var output bytes.Buffer
	stderr, err := transport.runRemoteOutput(context.Background(), session{
		endpoint: endpoint{Address: "203.0.113.10", SSHUser: "dev"},
		HostKey: key.PublicKey, IdentitySeed: bytes.Repeat([]byte{4}, 32),
	}, "cat storage", &output)
	if err != nil {
		t.Fatal(err)
	}
	if len(stderr) != 0 || output.String() != "streamed-storage" {
		t.Fatalf("stderr=%q output=%q", stderr, output.String())
	}
	if len(runner.calls) != 1 || runner.calls[0].name != "ssh" {
		t.Fatalf("calls=%#v", runner.calls)
	}
	args := runner.calls[0].args
	for _, expected := range []string{"-F", "none", "BatchMode=yes", "StrictHostKeyChecking=yes", "GlobalKnownHostsFile=/dev/null", "UpdateHostKeys=no", "IdentitiesOnly=yes", "IdentityAgent=none", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no", "ClearAllForwardings=yes", "PermitLocalCommand=no"} {
		if !containsArg(args, expected) {
			t.Fatalf("streamed ssh args missing %q", expected)
		}
	}
	entries, err := os.ReadDir(runtimeDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("streamed ssh left ephemeral files: %d", len(entries))
	}
}
