package targetgateway

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func (t *sshTransport) InspectPrimaryHardening(ctx context.Context, sess session) (PrimaryHardeningFacts, error) {
	probe := `set -eu
export LC_ALL=C
root_hash=$(getent shadow root | cut -d: -f2)
case "$root_hash" in !*|'*'*) printf 'root_locked\t1\n' ;; *) printf 'root_locked\t0\n' ;; esac
if sshd -t; then printf 'ssh_config_valid\t1\n'; else printf 'ssh_config_valid\t0\n'; exit 0; fi
sshd -T -C user=` + shellQuote(sess.SSHUser) + `,host="$(hostname)",addr=127.0.0.1 | awk '$1 ~ /^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|authenticationmethods|permitemptypasswords|logingracetime|maxauthtries|maxsessions|maxstartups|x11forwarding|allowagentforwarding|allowtcpforwarding|allowstreamlocalforwarding|permittunnel|gatewayports|permituserenvironment|compression|loglevel)$/ {print "ssh_" $1 "\t" $2}'
ufw status verbose | awk '/^Status:/ {print "ufw_active\t" ($2=="active"?1:0)} /^Logging:/ {print "ufw_logging_low\t" ($2=="on" && $3=="(low)"?1:0)} /^Default:/ {sub(/^Default:[[:space:]]*/, ""); print "ufw_defaults\t" $0}'
ipv4_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || printf '?')
ipv6_forward=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || printf '?')
printf 'ufw_forwarding\t%s,%s\n' "$ipv4_forward" "$ipv6_forward"
ufw status | awk '$2=="ALLOW" {rule=$1; if (rule ~ /^[0-9]+\/tcp$/) {p=rule; sub(/\/tcp$/, "", p); if (!seen[p]++) print "ufw_port\t" p} else {print "ufw_unexpected_allow\t1"}}'
if systemctl is-active --quiet fail2ban.service && fail2ban-client status sshd >/dev/null 2>&1; then printf 'fail2ban_sshd\t1\n'; else printf 'fail2ban_sshd\t0\n'; fi
if systemctl is-active --quiet fail2ban.service && fail2ban-client status recidive >/dev/null 2>&1; then printf 'fail2ban_recidive\t1\n'; else printf 'fail2ban_recidive\t0\n'; fi
u=$(apt-config shell x APT::Periodic::Unattended-Upgrade | sed -n "s/^x='\(.*\)'$/\1/p")
r=$(apt-config shell x Unattended-Upgrade::Automatic-Reboot | sed -n "s/^x='\(.*\)'$/\1/p")
printf 'unattended\t%s\n' "$u"
printf 'automatic_reboot\t%s\n' "$r"`
	stdout, err := t.runRemote(ctx, sess, "sudo -n sh -eu -c "+shellQuote(probe))
	if err != nil {
		return PrimaryHardeningFacts{}, err
	}
	facts := PrimaryHardeningFacts{SSHValues: map[string]string{}}
	var reportedRouted string
	forwardingDisabled := false
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "\t")
		if !ok {
			continue
		}
		switch {
		case key == "root_locked":
			facts.RootPasswordLocked = value == "1"
		case key == "ssh_config_valid":
			facts.SSHConfigValid = value == "1"
		case strings.HasPrefix(key, "ssh_"):
			facts.SSHValues[strings.TrimPrefix(key, "ssh_")] = value
		case key == "ufw_active":
			facts.UFWActive = value == "1"
		case key == "ufw_defaults":
			incoming, outgoing, routed, err := parseUFWDefaults(value)
			if err != nil {
				return facts, err
			}
			facts.UFWDefaultIncoming = incoming
			facts.UFWDefaultOutgoing = outgoing
			reportedRouted = routed
		case key == "ufw_forwarding":
			forwardingDisabled = value == "0,0"
		case key == "ufw_logging_low":
			facts.UFWLoggingLow = value == "1"
		case key == "ufw_unexpected_allow":
			facts.UFWUnexpectedPublicAllow = value == "1"
		case key == "ufw_port":
			port, err := strconv.Atoi(value)
			if err != nil {
				return facts, fmt.Errorf("invalid UFW port fact: %w", err)
			}
			facts.UFWAllowedPublicTCPPorts = append(facts.UFWAllowedPublicTCPPorts, port)
		case key == "fail2ban_sshd":
			facts.Fail2banSSHActive = value == "1"
		case key == "fail2ban_recidive":
			facts.Fail2banRecidiveActive = value == "1"
		case key == "unattended":
			facts.UnattendedUpgradesEnabled = value == "1"
		case key == "automatic_reboot":
			facts.AutomaticRebootDisabled = value == "false"
		}
	}
	if err := scanner.Err(); err != nil {
		return facts, err
	}
	facts.UFWDefaultRouted = reportedRouted
	if reportedRouted == "disabled" && forwardingDisabled {
		// UFW reports routed policy as disabled when kernel forwarding is off.
		// That is an effective deny and is stricter than allowing forwarded traffic.
		facts.UFWDefaultRouted = "deny"
	}
	return facts, nil
}

func parseUFWDefaults(value string) (incoming, outgoing, routed string, err error) {
	for _, part := range strings.Split(value, ",") {
		fields := strings.Fields(strings.TrimSpace(part))
		if len(fields) != 2 {
			return "", "", "", fmt.Errorf("invalid UFW default policy %q", part)
		}
		policy := strings.ToLower(fields[0])
		direction := strings.Trim(fields[1], "()")
		switch direction {
		case "incoming":
			incoming = policy
		case "outgoing":
			outgoing = policy
		case "routed":
			routed = policy
		default:
			return "", "", "", fmt.Errorf("unknown UFW default direction %q", direction)
		}
	}
	if incoming == "" || outgoing == "" || routed == "" {
		return "", "", "", errors.New("UFW default policies must include incoming, outgoing, and routed")
	}
	return incoming, outgoing, routed, nil
}
