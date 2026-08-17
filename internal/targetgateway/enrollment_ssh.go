package targetgateway

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
)

func (t *sshTransport) InspectPrimaryHardening(ctx context.Context, sess session) (PrimaryHardeningFacts, error) {
	const probe = `set -eu
if sshd -t; then printf 'ssh_config_valid\t1\n'; else printf 'ssh_config_valid\t0\n'; exit 0; fi
sshd -T -C user="$USER",host="$(hostname)",addr=127.0.0.1 | awk '$1 ~ /^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitemptypasswords|x11forwarding|allowagentforwarding|allowtcpforwarding|allowstreamlocalforwarding|permittunnel|gatewayports|permituserenvironment)$/ {print "ssh_" $1 "\t" $2}'
ufw status verbose | awk '/^Status:/ {print "ufw_active\t" ($2=="active"?1:0)} /^Default:/ {gsub(/[(),]/,""); print "ufw_incoming\t" $2; print "ufw_routed\t" $6}'
ufw status | awk '$2=="ALLOW" {p=$1; sub(/\/tcp$/, "", p); if (p ~ /^[0-9]+$/) print "ufw_port\t" p}'
if systemctl is-active --quiet fail2ban.service && fail2ban-client status sshd >/dev/null 2>&1; then printf 'fail2ban_sshd\t1\n'; else printf 'fail2ban_sshd\t0\n'; fi
u=$(apt-config shell x APT::Periodic::Unattended-Upgrade | sed -n "s/^x='\(.*\)'$/\1/p")
r=$(apt-config shell x Unattended-Upgrade::Automatic-Reboot | sed -n "s/^x='\(.*\)'$/\1/p")
printf 'unattended\t%s\n' "$u"
printf 'automatic_reboot\t%s\n' "$r"`
	stdout, err := t.runRemote(ctx, sess, probe)
	if err != nil {
		return PrimaryHardeningFacts{}, err
	}
	facts := PrimaryHardeningFacts{SSHValues: map[string]string{}}
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "\t")
		if !ok {
			continue
		}
		switch {
		case key == "ssh_config_valid":
			facts.SSHConfigValid = value == "1"
		case strings.HasPrefix(key, "ssh_"):
			facts.SSHValues[strings.TrimPrefix(key, "ssh_")] = value
		case key == "ufw_active":
			facts.UFWActive = value == "1"
		case key == "ufw_incoming":
			facts.UFWDefaultIncoming = value
		case key == "ufw_routed":
			facts.UFWDefaultRouted = value
		case key == "ufw_port":
			port, err := strconv.Atoi(value)
			if err != nil {
				return facts, fmt.Errorf("invalid UFW port fact: %w", err)
			}
			facts.UFWAllowedPublicTCPPorts = append(facts.UFWAllowedPublicTCPPorts, port)
		case key == "fail2ban_sshd":
			facts.Fail2banSSHActive = value == "1"
		case key == "unattended":
			facts.UnattendedUpgradesEnabled = value == "1"
		case key == "automatic_reboot":
			facts.AutomaticRebootDisabled = value == "false"
		}
	}
	return facts, scanner.Err()
}
