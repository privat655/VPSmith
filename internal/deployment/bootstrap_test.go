package deployment

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/managementstate"
)

func testBootstrapRequest(t *testing.T) BootstrapRequest {
	t.Helper()
	templateBytes, err := os.ReadFile(filepath.Join("..", "..", "embedded", "cloud-init", "cloud-init.yaml.tmpl"))
	if err != nil { t.Fatal(err) }
	sourceID := managementstate.SourceSnapshotID("source_cloud_test")
	sourceSHA := strings.Repeat("a", 64)
	return BootstrapRequest{
		TargetID: "target_a",
		Desired: managementstate.CloudInitDesiredState{SourceSnapshotID: sourceID, DefinitionVersion: "0.1.0", SourceSHA256: sourceSHA, Hostname: "vps-a", Timezone: "Europe/Berlin", Administrator: "admin"},
		SSHPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockPublicKeyOnly vpsmith:target_a",
		Source: BootstrapSource{SnapshotID: sourceID, Version: "0.1.0", SHA256: sourceSHA, Template: templateBytes},
	}
}

func TestPrepareBootstrapProducesOnlyPrimaryCloudInit(t *testing.T) {
	c := newCompiler(t, "docker.io/example/unused:1")
	req := testBootstrapRequest(t)
	got, err := c.PrepareBootstrap(req); if err != nil { t.Fatal(err) }
	if len(got.Bytes) >= MaxCloudInitBytes { t.Fatalf("cloud-init size=%d", len(got.Bytes)) }
	if got.Identity != req.Source.Version { t.Fatalf("identity=%q want source version %q", got.Identity, req.Source.Version) }
	text := string(got.Bytes)
	required := []string{"ssh_deletekeys: true", "ssh_genkeytypes: [ed25519, rsa]", "passwd -l root", "getent shadow root", "PermitRootLogin no", "PasswordAuthentication no", "KbdInteractiveAuthentication no", "PubkeyAuthentication yes", "AuthenticationMethods publickey", "PermitEmptyPasswords no", "LoginGraceTime 20", "MaxAuthTries 3", "MaxSessions 3", "MaxStartups 10:30:60", "AllowAgentForwarding no", "AllowTcpForwarding no", "AllowStreamLocalForwarding no", "PermitTunnel no", "GatewayPorts no", "PermitUserEnvironment no", "Compression no", "LogLevel VERBOSE", "ufw default deny incoming", "ufw default deny routed", "ufw allow 22/tcp", "ufw allow 80/tcp", "ufw allow 443/tcp", "ufw logging low", "fail2ban-client status sshd", "fail2ban-client status recidive", "Unattended-Upgrade::Automatic-Reboot \"false\"", "sshd -t", "sshd -T", "status=ok", "version=0.1.0", "mktemp /var/lib/vpsmith/cloud-init/.status", "mv -f \"$vpsmith_tmp\" /var/lib/vpsmith/cloud-init/status"}
	for _, want := range required { if !strings.Contains(text, want) { t.Errorf("missing %q", want) } }
	forbidden := []string{"podman", "quadlet", "caddy", "authelia", "/var/lib/vpsmith/core", "/var/lib/vpsmith/modules", "/swapfile", "mkswap", "swapon", "swapoff", "github.com", "ghcr.io", "curl ", "wget ", "hashed_passwd", "chpasswd:"}
	lower := strings.ToLower(text)
	for _, bad := range forbidden { if strings.Contains(lower, strings.ToLower(bad)) { t.Errorf("forbidden responsibility %q", bad) } }
	keyFields := strings.Fields(req.SSHPublicKey)
	if !strings.Contains(text, keyFields[0]+" "+keyFields[1]) { t.Error("public key material missing") }
	if bytes.Contains(got.Bytes, []byte("OPENSSH PRIVATE KEY")) { t.Error("private key leaked") }
}

func TestPrepareBootstrapRejectsProvenanceMismatch(t *testing.T) {
	c := newCompiler(t, "docker.io/example/unused:1")
	cases := []func(*BootstrapRequest){
		func(req *BootstrapRequest) { req.Desired.SourceSnapshotID = "source_other" },
		func(req *BootstrapRequest) { req.Desired.DefinitionVersion = "other" },
		func(req *BootstrapRequest) { req.Desired.SourceSHA256 = strings.Repeat("b", 64) },
	}
	for i, mutate := range cases { req := testBootstrapRequest(t); mutate(&req); if _, err := c.PrepareBootstrap(req); err == nil { t.Fatalf("provenance mismatch case %d accepted", i) } }
}

func TestPrepareBootstrapWritesSuccessOnlyAfterEffectiveValidation(t *testing.T) {
	c := newCompiler(t, "docker.io/example/unused:1")
	artifact, err := c.PrepareBootstrap(testBootstrapRequest(t)); if err != nil { t.Fatal(err) }
	text := string(artifact.Bytes)
	clear := strings.Index(text, "rm -f /var/lib/vpsmith/cloud-init/status")
	rootValidation := strings.Index(text, "getent shadow root")
	lastValidation := strings.Index(text, "fail2ban-client status recidive")
	success := strings.Index(text, "status=ok")
	publish := strings.Index(text, "mv -f \"$vpsmith_tmp\" /var/lib/vpsmith/cloud-init/status")
	if clear < 0 || rootValidation < 0 || lastValidation < 0 || success < 0 || publish < 0 || !(clear < rootValidation && rootValidation < lastValidation && lastValidation < success && success < publish) { t.Fatalf("atomic status ordering is unsafe: clear=%d root=%d validation=%d success=%d publish=%d", clear, rootValidation, lastValidation, success, publish) }
	if strings.Contains(text, "passwd -l root >/dev/null 2>&1 || true") { t.Fatal("root password lock must fail closed") }
}

func TestPrepareBootstrapIsDeterministic(t *testing.T) {
	c := newCompiler(t, "docker.io/example/unused:1"); req := testBootstrapRequest(t)
	a, err := c.PrepareBootstrap(req); if err != nil { t.Fatal(err) }
	b, err := c.PrepareBootstrap(req); if err != nil { t.Fatal(err) }
	if !bytes.Equal(a.Bytes, b.Bytes) || a.SHA256 != b.SHA256 { t.Fatal("same frozen source and canonical input must produce identical Cloud-init") }
}

func TestPrepareBootstrapRejectsUnsafeTargetScalars(t *testing.T) {
	c := newCompiler(t, "docker.io/example/unused:1")
	cases := []func(*BootstrapRequest){func(req *BootstrapRequest) { req.Desired.Timezone = "Etc/UTC #comment" }, func(req *BootstrapRequest) { req.Desired.Timezone = "../UTC" }, func(req *BootstrapRequest) { req.Desired.Hostname = "Bad_Host" }, func(req *BootstrapRequest) { req.Desired.Hostname = "-host" }, func(req *BootstrapRequest) { req.Desired.Administrator = "root" }, func(req *BootstrapRequest) { req.Desired.Administrator = "Admin" }}
	for i, mutate := range cases { req := testBootstrapRequest(t); mutate(&req); if _, err := c.PrepareBootstrap(req); err == nil { t.Fatalf("unsafe target scalar case %d accepted", i) } }
}

func TestPrepareBootstrapPassesOfficialCloudInitSchema(t *testing.T) {
	if _, err := exec.LookPath("cloud-init"); err != nil { t.Skip("cloud-init validator not installed") }
	c := newCompiler(t, "docker.io/example/unused:1"); req := testBootstrapRequest(t)
	req.TargetID = "target_schema"; req.Desired.Hostname = "schema-vps"; req.Desired.Timezone = "UTC"
	artifact, err := c.PrepareBootstrap(req); if err != nil { t.Fatal(err) }
	path := filepath.Join(t.TempDir(), "cloud-init.yaml")
	if err := os.WriteFile(path, artifact.Bytes, 0o600); err != nil { t.Fatal(err) }
	cmd := exec.Command("cloud-init", "schema", "--config-file", path)
	out, err := cmd.CombinedOutput(); if err != nil { t.Fatalf("cloud-init schema failed: %v\n%s", err, out) }
}
