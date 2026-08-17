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

func TestPrepareBootstrapProducesOnlyPrimaryCloudInit(t *testing.T) {
	c := newCompiler(t, "docker.io/example/unused:1")
	req := BootstrapRequest{TargetID: "target_a", Desired: managementstate.CloudInitDesiredState{DefinitionVersion: "cloud-init-v1", Hostname: "vps-a", Timezone: "Europe/Berlin", Administrator: "admin"}, SSHPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockPublicKeyOnly vpsmith:target_a"}
	got, err := c.PrepareBootstrap(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Bytes) >= MaxCloudInitBytes {
		t.Fatalf("cloud-init size=%d", len(got.Bytes))
	}
	text := string(got.Bytes)
	required := []string{"PermitRootLogin no", "PasswordAuthentication no", "KbdInteractiveAuthentication no", "PubkeyAuthentication yes", "AllowAgentForwarding no", "AllowTcpForwarding no", "AllowStreamLocalForwarding no", "PermitTunnel no", "GatewayPorts no", "PermitUserEnvironment no", "ufw default deny incoming", "ufw default deny routed", "ufw allow 22/tcp", "ufw allow 80/tcp", "ufw allow 443/tcp", "fail2ban-client status sshd", "Unattended-Upgrade::Automatic-Reboot \"false\"", "sshd -t", "sshd -T", "status=ok", "mktemp /var/lib/vpsmith/cloud-init/.status", "mv -f \"$tmp\" /var/lib/vpsmith/cloud-init/status"}
	for _, want := range required {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q", want)
		}
	}
	forbidden := []string{"podman", "quadlet", "caddy", "authelia", "/swapfile", "mkswap", "swapon", "swapoff", "github.com/privat655", "ghcr.io/privat655", "hashed_passwd", "chpasswd:"}
	lower := strings.ToLower(text)
	for _, bad := range forbidden {
		if strings.Contains(lower, strings.ToLower(bad)) {
			t.Errorf("forbidden responsibility %q", bad)
		}
	}
	if !strings.Contains(text, req.SSHPublicKey) {
		t.Error("public key missing")
	}
	if bytes.Contains(got.Bytes, []byte("OPENSSH PRIVATE KEY")) {
		t.Error("private key leaked")
	}
}

func TestPrepareBootstrapIsDeterministic(t *testing.T) {
	c := newCompiler(t, "docker.io/example/unused:1")
	req := BootstrapRequest{TargetID: "target_a", Desired: managementstate.CloudInitDesiredState{DefinitionVersion: "cloud-init-v1", Hostname: "vps-a", Timezone: "UTC", Administrator: "admin"}, SSHPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockPublicKeyOnly"}
	a, err := c.PrepareBootstrap(req)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.PrepareBootstrap(req)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes, b.Bytes) || a.SHA256 != b.SHA256 {
		t.Fatal("same canonical input must produce identical Cloud-init")
	}
}

func TestPrepareBootstrapPassesOfficialCloudInitSchema(t *testing.T) {
	if _, err := exec.LookPath("cloud-init"); err != nil {
		t.Skip("cloud-init validator not installed")
	}
	c := newCompiler(t, "docker.io/example/unused:1")
	req := BootstrapRequest{TargetID: "target_schema", Desired: managementstate.CloudInitDesiredState{DefinitionVersion: "cloud-init-v1", Hostname: "schema-vps", Timezone: "UTC", Administrator: "admin"}, SSHPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockPublicKeyOnly"}
	artifact, err := c.PrepareBootstrap(req)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cloud-init.yaml")
	if err := os.WriteFile(path, artifact.Bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cloud-init", "schema", "--config-file", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cloud-init schema failed: %v\n%s", err, out)
	}
}
