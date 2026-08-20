package targetgateway

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

type inputStreamingCaptureRunner struct {
	calls []processCall
	input []byte
}

func (r *inputStreamingCaptureRunner) Run(_ context.Context, name string, args ...string) ([]byte, []byte, error) {
	r.calls = append(r.calls, processCall{name: name, args: append([]string(nil), args...)})
	return nil, nil, nil
}

func (r *inputStreamingCaptureRunner) RunInputStream(_ context.Context, input io.Reader, name string, args ...string) ([]byte, []byte, error) {
	r.calls = append(r.calls, processCall{name: name, args: append([]string(nil), args...)})
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, nil, err
	}
	r.input = data
	return nil, nil, nil
}

func TestStageCoreRestorePayloadStreamsThroughStrictSSHToBundleScopedRootOnlyPath(t *testing.T) {
	runner := &inputStreamingCaptureRunner{}
	transport := newSSHTransportAt(t.TempDir(), runner)
	sess := session{
		endpoint:     endpoint{Address: "203.0.113.10", SSHUser: "dev"},
		HostKey:      testHostObservation(32).PublicKey,
		IdentitySeed: bytes.Repeat([]byte{8}, 32),
	}
	payload := []byte("verified-restore-payload")
	const bundleID = "bundle_0123456789abcdef0123456789abcdef"
	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	if err := transport.StageCoreRestorePayload(context.Background(), sess, bundleID, bytes.NewReader(payload), digest, int64(len(payload))); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(runner.input, payload) {
		t.Fatalf("streamed payload=%q want=%q", runner.input, payload)
	}
	if len(runner.calls) != 1 || runner.calls[0].name != "ssh" {
		t.Fatalf("calls=%#v", runner.calls)
	}
	for _, required := range []string{"-F", "none", "BatchMode=yes", "StrictHostKeyChecking=yes", "IdentityAgent=none"} {
		if !containsArg(runner.calls[0].args, required) {
			t.Fatalf("missing strict ssh argument %q: %#v", required, runner.calls[0].args)
		}
	}
	command := runner.calls[0].args[len(runner.calls[0].args)-1]
	for _, required := range []string{
		"/var/lib/vpsmith/tmp/core-restore/" + bundleID,
		"payload.tar.zst.upload.$$",
		"sha256sum",
		"stat -c %s",
		"chmod 0400",
		"payload.tar.zst",
	} {
		if !strings.Contains(command, required) {
			t.Fatalf("restore staging command missing %q: %s", required, command)
		}
	}
}
