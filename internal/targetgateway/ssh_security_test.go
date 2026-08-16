package targetgateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"os"
	"strings"
	"testing"
)

func TestSelectHostKeyPrefersEd25519AndRejectsAmbiguousKeysets(t *testing.T) {
	ed := testHostObservation(1)
	rsaBlob := appendSSHStrings([]byte("ssh-rsa"), []byte{1, 2, 3}, []byte{1, 0, 1})
	rsa := "ssh-rsa " + base64.StdEncoding.EncodeToString(rsaBlob)
	selected, err := selectHostKey([]byte("203.0.113.1 " + rsa + "\n203.0.113.1 " + ed.PublicKey + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if selected != ed {
		t.Fatalf("selected = %#v want %#v", selected, ed)
	}
	other := testHostObservation(2)
	if _, err := selectHostKey([]byte("203.0.113.1 " + ed.PublicKey + "\n203.0.113.1 " + other.PublicKey + "\n")); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous host keys error = %v", err)
	}
}

func TestOpenSSHPrivateKeyEncodingMatchesProtocolEnvelope(t *testing.T) {
	encoded, err := marshalOpenSSHPrivateKey("vpsmith:test", bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(encoded)
	if block == nil || len(rest) != 0 || block.Type != "OPENSSH PRIVATE KEY" {
		t.Fatalf("pem block = %#v", block)
	}
	payload := block.Bytes
	magic := []byte("openssh-key-v1\x00")
	if !bytes.HasPrefix(payload, magic) {
		t.Fatal("missing openssh key magic")
	}
	payload = payload[len(magic):]
	cipherName, payload, err := readSSHString(payload)
	if err != nil {
		t.Fatal(err)
	}
	kdfName, payload, err := readSSHString(payload)
	if err != nil {
		t.Fatal(err)
	}
	kdfOptions, payload, err := readSSHString(payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(cipherName) != "none" || string(kdfName) != "none" || len(kdfOptions) != 0 {
		t.Fatal("unexpected private key envelope")
	}
	if len(payload) < 4 || binary.BigEndian.Uint32(payload[:4]) != 1 {
		t.Fatal("unexpected key count")
	}
}

type captureRunner struct {
	calls []processCall
	hook  func(string, []string) ([]byte, []byte, error)
}
type processCall struct {
	name string
	args []string
}

func (r *captureRunner) Run(_ context.Context, name string, args ...string) ([]byte, []byte, error) {
	r.calls = append(r.calls, processCall{name: name, args: append([]string(nil), args...)})
	if r.hook != nil {
		return r.hook(name, args)
	}
	return []byte("ok\n"), nil, nil
}

func TestStrictSSHInvocationUsesExactTrustAndCleansEphemeralFiles(t *testing.T) {
	runtimeDir := t.TempDir()
	key := testHostObservation(3)
	runner := &captureRunner{}
	runner.hook = func(name string, args []string) ([]byte, []byte, error) {
		if name != "ssh" {
			t.Fatalf("process = %q", name)
		}
		identity := argumentAfter(t, args, "-i")
		knownHosts := optionValue(t, args, "UserKnownHostsFile")
		assertMode(t, identity, 0o600)
		assertMode(t, knownHosts, 0o600)
		known, err := os.ReadFile(knownHosts)
		if err != nil {
			t.Fatal(err)
		}
		if string(known) != "203.0.113.10 "+key.PublicKey+"\n" {
			t.Fatalf("known hosts = %q", known)
		}
		return []byte("host\n"), nil, nil
	}
	transport := newSSHTransportAt(runtimeDir, runner)
	_, err := transport.runRemote(context.Background(), session{endpoint: endpoint{Address: "203.0.113.10", SSHUser: "dev"}, HostKey: key.PublicKey, IdentitySeed: bytes.Repeat([]byte{4}, 32)}, "hostname")
	if err != nil {
		t.Fatal(err)
	}
	args := runner.calls[0].args
	for _, expected := range []string{"-F", "none", "BatchMode=yes", "StrictHostKeyChecking=yes", "GlobalKnownHostsFile=/dev/null", "UpdateHostKeys=no", "IdentitiesOnly=yes", "IdentityAgent=none", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no", "ClearAllForwardings=yes", "PermitLocalCommand=no"} {
		if !containsArg(args, expected) {
			t.Fatalf("ssh args missing %q", expected)
		}
	}
	entries, err := os.ReadDir(runtimeDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("ephemeral files remain: %d", len(entries))
	}
}

func TestEndpointAndInventoryInputsAreConservative(t *testing.T) {
	if safeObjectName("bad name") || safeObjectName("--option") || safeArtifactPath("/etc/passwd") || safeArtifactPath("relative") {
		t.Fatal("unsafe input accepted")
	}
	if !safeObjectName("core.service") || !safeArtifactPath("/etc/vpsmith/core/Caddyfile") {
		t.Fatal("safe input rejected")
	}
	if _, err := parseEndpoint("example.com"); err == nil {
		t.Fatal("DNS hostname accepted")
	}
	if got, err := parseEndpoint("[2001:db8::1]:2222"); err != nil || got.host != "2001:db8::1" || got.port != "2222" {
		t.Fatalf("IPv6 endpoint = %#v err=%v", got, err)
	}
}

func appendSSHStrings(values ...[]byte) []byte {
	var out bytes.Buffer
	for _, value := range values {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(value)))
		out.Write(n[:])
		out.Write(value)
	}
	return out.Bytes()
}
func argumentAfter(t *testing.T, args []string, name string) string {
	t.Helper()
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	t.Fatalf("argument %q missing", name)
	return ""
}
func optionValue(t *testing.T, args []string, option string) string {
	t.Helper()
	prefix := option + "="
	for _, arg := range args {
		if strings.HasPrefix(arg, prefix) {
			return strings.TrimPrefix(arg, prefix)
		}
	}
	t.Fatalf("option %q missing", option)
	return ""
}
func containsArg(args []string, value string) bool {
	for _, candidate := range args {
		if candidate == value {
			return true
		}
	}
	return false
}
func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("mode=%04o want=%04o", info.Mode().Perm(), want)
	}
}
