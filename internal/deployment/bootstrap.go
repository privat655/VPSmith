package deployment

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/privat655/VPSmith/internal/managementstate"
)

const MaxCloudInitBytes = 16 * 1024

var safeBootstrapToken = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

type BootstrapRequest struct {
	TargetID     string
	Desired      managementstate.CloudInitDesiredState
	SSHPublicKey string
}

// PrepareBootstrap compiles the complete provider-facing Cloud-init document.
// Cloud-init is deliberately not an execution bundle: it runs before SSH trust
// exists and contains only Part 1 (Primary Host Hardening).
func (c *Compiler) PrepareBootstrap(req BootstrapRequest) (BootstrapArtifact, error) {
	if c == nil {
		return BootstrapArtifact{}, errors.New("deployment compiler is required")
	}
	if err := validateBootstrapRequest(req); err != nil {
		return BootstrapArtifact{}, err
	}
	data := []byte(renderCloudInit(req))
	if len(data) >= MaxCloudInitBytes {
		return BootstrapArtifact{}, fmt.Errorf("cloud-init is %d bytes; must be smaller than %d", len(data), MaxCloudInitBytes)
	}
	sum := sha256.Sum256(data)
	return BootstrapArtifact{Identity: req.Desired.DefinitionVersion, SHA256: hex.EncodeToString(sum[:]), Bytes: data}, nil
}

func validateBootstrapRequest(req BootstrapRequest) error {
	for name, value := range map[string]string{
		"target id": req.TargetID, "definition version": req.Desired.DefinitionVersion,
		"hostname": req.Desired.Hostname, "timezone": req.Desired.Timezone, "administrator": req.Desired.Administrator,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if !safeBootstrapToken.MatchString(req.Desired.Hostname) || !safeBootstrapToken.MatchString(req.Desired.Administrator) {
		return errors.New("hostname and administrator must use safe characters")
	}
	if strings.ContainsAny(req.Desired.Timezone, "\r\n\x00") || strings.Contains(req.Desired.Timezone, "..") || strings.HasPrefix(req.Desired.Timezone, "/") {
		return errors.New("invalid timezone")
	}
	fields := strings.Fields(req.SSHPublicKey)
	if len(fields) < 2 || fields[0] != "ssh-ed25519" || strings.ContainsAny(req.SSHPublicKey, "\r\n\x00") {
		return errors.New("complete ssh-ed25519 public key is required")
	}
	return nil
}

func renderCloudInit(req BootstrapRequest) string {
	return fmt.Sprintf(`#cloud-config
hostname: %s
timezone: %s
package_update: true
package_upgrade: true
packages: [openssh-server, sudo, ufw, fail2ban, unattended-upgrades]
ssh_pwauth: false
disable_root: true
users:
  - name: %s
    shell: /bin/bash
    groups: [adm, sudo]
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: true
    ssh_authorized_keys:
      - %s
write_files:
  - path: /etc/ssh/sshd_config.d/60-vpsmith-primary.conf
    owner: root:root
    permissions: '0644'
    content: |
      PermitRootLogin no
      PasswordAuthentication no
      KbdInteractiveAuthentication no
      PubkeyAuthentication yes
      PermitEmptyPasswords no
      AllowUsers %s
      X11Forwarding no
      AllowAgentForwarding no
      AllowTcpForwarding no
      AllowStreamLocalForwarding no
      PermitTunnel no
      GatewayPorts no
      PermitUserEnvironment no
      DisableForwarding yes
  - path: /etc/fail2ban/jail.d/vpsmith-sshd.local
    owner: root:root
    permissions: '0644'
    content: |
      [DEFAULT]
      backend = systemd
      banaction = ufw
      bantime = 1h
      findtime = 10m
      maxretry = 4
      [sshd]
      enabled = true
      port = ssh
  - path: /etc/apt/apt.conf.d/52-vpsmith-auto-upgrades
    owner: root:root
    permissions: '0644'
    content: |
      APT::Periodic::Update-Package-Lists "1";
      APT::Periodic::Unattended-Upgrade "1";
      Unattended-Upgrade::Automatic-Reboot "false";
runcmd:
  - |
      set -eu
      rm -f /var/lib/vpsmith/cloud-init/status
      passwd -l root >/dev/null 2>&1 || true
      sshd -t
      systemctl reload ssh.service 2>/dev/null || systemctl reload sshd.service
      ufw --force reset >/dev/null
      ufw default deny incoming >/dev/null
      ufw default allow outgoing >/dev/null
      ufw default deny routed >/dev/null
      ufw allow 22/tcp >/dev/null
      ufw allow 80/tcp >/dev/null
      ufw allow 443/tcp >/dev/null
      ufw --force enable >/dev/null
      systemctl enable --now fail2ban.service >/dev/null
      systemctl enable --now unattended-upgrades.service >/dev/null 2>&1 || true
      sshd -t
      ssh_effective=$(sshd -T -C user=%s,host=$(hostname),addr=127.0.0.1)
      require_sshd() { printf '%%s\n' "$ssh_effective" | grep -Fxq "$1 $2"; }
      require_sshd permitrootlogin no
      require_sshd passwordauthentication no
      require_sshd kbdinteractiveauthentication no
      require_sshd pubkeyauthentication yes
      require_sshd permitemptypasswords no
      require_sshd x11forwarding no
      require_sshd allowagentforwarding no
      require_sshd allowtcpforwarding no
      require_sshd allowstreamlocalforwarding no
      require_sshd permittunnel no
      require_sshd gatewayports no
      require_sshd permituserenvironment no
      printf '%%s\n' "$ssh_effective" | grep -Eq '^allowusers([[:space:]]+)%s$'
      ufw status verbose | grep -Fxq 'Status: active'
      ufw status verbose | grep -Fq 'Default: deny (incoming), allow (outgoing), deny (routed)'
      rules=$(ufw status | awk '$2=="ALLOW" {print $1}' | sort -u | paste -sd, -)
      [ "$rules" = '22/tcp,443/tcp,80/tcp' ] || [ "$rules" = '22/tcp,80/tcp,443/tcp' ]
      systemctl is-active --quiet fail2ban.service
      fail2ban-client status sshd >/dev/null
      [ "$(apt-config shell x APT::Periodic::Unattended-Upgrade | sed -n "s/^x='\(.*\)'$/\1/p")" = 1 ]
      [ "$(apt-config shell x Unattended-Upgrade::Automatic-Reboot | sed -n "s/^x='\(.*\)'$/\1/p")" = false ]
      install -d -m 0755 /var/lib/vpsmith/cloud-init
      tmp=$(mktemp /var/lib/vpsmith/cloud-init/.status.XXXXXX)
      trap 'rm -f "$tmp"' EXIT
      { printf 'status=ok\n'; printf 'version=%s\n'; printf 'finished_at=%%s\n' "$(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ)"; } >"$tmp"
      chmod 0644 "$tmp"
      mv -f "$tmp" /var/lib/vpsmith/cloud-init/status
      trap - EXIT
`, req.Desired.Hostname, req.Desired.Timezone, req.Desired.Administrator, req.SSHPublicKey, req.Desired.Administrator,
		req.Desired.Administrator, req.Desired.Administrator, req.Desired.DefinitionVersion)
}
