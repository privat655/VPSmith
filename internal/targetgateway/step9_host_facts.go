package targetgateway

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/privat655/VPSmith/internal/managementstate"
)

const step9HostFactsProbe = `set -eu
# vpsmith_step9_host_facts
ADMIN_USER=$1
[ -n "$ADMIN_USER" ] || { echo "Step 9 administrator is required" >&2; exit 1; }
bool_service() {
  if systemctl is-active --quiet "$1" 2>/dev/null; then printf '1'; else printf '0'; fi
}
config_value() {
  file=$1
  key=$2
  systemd-analyze cat-config "$file" 2>/dev/null | awk -F= -v key="$key" '
    /^[[:space:]]*#/ {next}
    $1 ~ "^[[:space:]]*" key "[[:space:]]*$" {value=$2}
    END {gsub(/^[[:space:]]+|[[:space:]]+$/, "", value); print value}
  '
}
app_armor=0
command -v aa-enabled >/dev/null 2>&1 && aa-enabled >/dev/null 2>&1 && app_armor=1 || true
auditd=$(bool_service auditd.service)
chrony=$(bool_service chrony.service)
journal_storage=$(config_value systemd/journald.conf Storage)
journal_system_max=$(config_value systemd/journald.conf SystemMaxUse)
journal_runtime_max=$(config_value systemd/journald.conf RuntimeMaxUse)
journal_persistent=0
[ "$journal_storage" = persistent ] && [ -d /var/log/journal ] && journal_persistent=1 || true
coredump_storage=$(config_value systemd/coredump.conf Storage)
coredump_process_max=$(config_value systemd/coredump.conf ProcessSizeMax)
coredump_disabled=0
[ "$coredump_storage" = none ] && [ "$coredump_process_max" = 0 ] && coredump_disabled=1 || true
apport_disabled=1
for unit in \
  apport.service \
  apport-autoreport.path \
  apport-autoreport.service \
  apport-autoreport.timer \
  apport-coredump-hook@.service \
  apport-forward.socket \
  apport-forward@.service
do
  [ "$(systemctl is-enabled "$unit" 2>/dev/null || true)" = masked ] || apport_disabled=0
done
for unit in \
  apport.service \
  apport-autoreport.path \
  apport-autoreport.service \
  apport-autoreport.timer \
  apport-forward.socket
do
  systemctl is-active --quiet "$unit" 2>/dev/null && apport_disabled=0 || true
done
tmp_fstype=$(findmnt -n -o FSTYPE /tmp 2>/dev/null || true)
tmp_options=$(findmnt -n -o OPTIONS /tmp 2>/dev/null || true)
blocked_modules=1
for module in cramfs freevxfs jffs2 hfs hfsplus udf dccp sctp rds tipc; do
  if lsmod | awk 'NR > 1 {print $1}' | grep -Fxq "$module"; then
    blocked_modules=0
    break
  fi
  dry_run=$(modprobe -n "$module" 2>/dev/null || true)
  case "$dry_run" in
    *'/bin/false'*) ;;
    *) blocked_modules=0; break ;;
  esac
done
ipv6_disabled=0
if [ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || true)" = 1 ] && \
   [ "$(sysctl -n net.ipv6.conf.default.disable_ipv6 2>/dev/null || true)" = 1 ] && \
   [ "$(sysctl -n net.ipv6.conf.lo.disable_ipv6 2>/dev/null || true)" = 1 ]; then
  ipv6_disabled=1
fi
unprivileged_port_start=$(sysctl -n net.ipv4.ip_unprivileged_port_start 2>/dev/null || printf '0')
docker_absent=1
command -v docker >/dev/null 2>&1 && docker_absent=0 || true
for package in docker.io docker-ce docker-ce-cli; do
  dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q 'install ok installed' && docker_absent=0 || true
done
systemctl is-active --quiet docker.service 2>/dev/null && docker_absent=0 || true
systemctl is-active --quiet docker.socket 2>/dev/null && docker_absent=0 || true
containerd_absent=1
command -v containerd >/dev/null 2>&1 && containerd_absent=0 || true
for package in containerd containerd.io; do
  dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q 'install ok installed' && containerd_absent=0 || true
done
systemctl is-active --quiet containerd.service 2>/dev/null && containerd_absent=0 || true
subuid=0
awk -F: -v u="$ADMIN_USER" '$1 == u && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && $3 >= 65536 {found=1} END {exit !found}' /etc/subuid 2>/dev/null && subuid=1 || true
subgid=0
awk -F: -v u="$ADMIN_USER" '$1 == u && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && $3 >= 65536 {found=1} END {exit !found}' /etc/subgid 2>/dev/null && subgid=1 || true
linger=0
[ "$(loginctl show-user "$ADMIN_USER" -p Linger --value 2>/dev/null || true)" = yes ] && linger=1 || true
printf 'hardening\tapp_armor_enabled\t%s\n' "$app_armor"
printf 'hardening\tauditd_active\t%s\n' "$auditd"
printf 'hardening\tchrony_active\t%s\n' "$chrony"
printf 'hardening\tjournal_persistent\t%s\n' "$journal_persistent"
printf 'hardening\tjournal_system_max_use\t%s\n' "$journal_system_max"
printf 'hardening\tjournal_runtime_max_use\t%s\n' "$journal_runtime_max"
printf 'hardening\tcoredump_disabled\t%s\n' "$coredump_disabled"
printf 'hardening\tapport_disabled\t%s\n' "$apport_disabled"
printf 'hardening\ttmp_fstype\t%s\n' "$tmp_fstype"
printf 'hardening\ttmp_options\t%s\n' "$tmp_options"
printf 'hardening\tblocked_modules_effective\t%s\n' "$blocked_modules"
printf 'hardening\tipv6_disabled\t%s\n' "$ipv6_disabled"
printf 'hardening\tunprivileged_port_start\t%s\n' "$unprivileged_port_start"
printf 'hardening\tdocker_absent\t%s\n' "$docker_absent"
printf 'hardening\tcontainerd_absent\t%s\n' "$containerd_absent"
printf 'hardening\tsubuid_range_present\t%s\n' "$subuid"
printf 'hardening\tsubgid_range_present\t%s\n' "$subgid"
printf 'hardening\tlinger_enabled\t%s\n' "$linger"
swapon --show --bytes --noheadings --output NAME,TYPE,SIZE,USED,PRIO 2>/dev/null | while read -r name kind size used priority; do
  [ -n "$name" ] || continue
  printf 'swap\t%s\t%s\t%s\t%s\t%s\n' "$name" "$kind" "$size" "$used" "$priority"
done
ss -H -ltn 2>/dev/null | awk '{printf "listener\ttcp\t%s\n", $4}'`

func (t *sshTransport) step9HostFacts(ctx context.Context, sess session) (managementstate.SecondaryHardeningObservedState, []managementstate.SwapDeviceObservedState, []managementstate.ListenerObservedState, error) {
	command := "sudo -n sh -eu -c " + shellQuote(step9HostFactsProbe) + " -- " + shellQuote(sess.endpoint.SSHUser)
	stdout, err := t.runRemote(ctx, sess, command)
	if err != nil {
		return managementstate.SecondaryHardeningObservedState{}, nil, nil, fmt.Errorf("read Step 9 host facts: %w", err)
	}
	return parseStep9HostFacts(stdout)
}

func parseStep9HostFacts(raw []byte) (managementstate.SecondaryHardeningObservedState, []managementstate.SwapDeviceObservedState, []managementstate.ListenerObservedState, error) {
	var hardening managementstate.SecondaryHardeningObservedState
	var swaps []managementstate.SwapDeviceObservedState
	var listeners []managementstate.ListenerObservedState
	values := map[string]string{}

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "hardening":
			if len(fields) != 3 || fields[1] == "" {
				return hardening, nil, nil, errors.New("invalid Step 9 hardening fact output")
			}
			values[fields[1]] = fields[2]
		case "swap":
			if len(fields) != 6 || fields[1] == "" {
				return hardening, nil, nil, errors.New("invalid Step 9 swap fact output")
			}
			size, err := parseNonNegativeInt64(fields[3], "swap size")
			if err != nil {
				return hardening, nil, nil, err
			}
			used, err := parseNonNegativeInt64(fields[4], "swap used")
			if err != nil {
				return hardening, nil, nil, err
			}
			priority, err := strconv.Atoi(strings.TrimSpace(fields[5]))
			if err != nil {
				return hardening, nil, nil, errors.New("invalid swap priority")
			}
			swaps = append(swaps, managementstate.SwapDeviceObservedState{Path: fields[1], Kind: fields[2], SizeBytes: size, UsedBytes: used, Priority: priority, CoreManaged: fields[1] == "/var/lib/vpsmith/swapfile"})
		case "listener":
			if len(fields) != 3 || fields[1] != "tcp" {
				return hardening, nil, nil, errors.New("invalid Step 9 listener fact output")
			}
			listener, err := parseTCPListener(fields[2])
			if err != nil {
				return hardening, nil, nil, err
			}
			listeners = append(listeners, listener)
		default:
			return hardening, nil, nil, errors.New("unknown Step 9 host fact output")
		}
	}
	if err := scanner.Err(); err != nil {
		return hardening, nil, nil, err
	}

	var err error
	hardening.AppArmorEnabled = values["app_armor_enabled"] == "1"
	hardening.AuditdActive = values["auditd_active"] == "1"
	hardening.ChronyActive = values["chrony_active"] == "1"
	hardening.JournalPersistent = values["journal_persistent"] == "1"
	hardening.JournalSystemMaxUseBytes, err = parseOptionalSystemdBytes(values["journal_system_max_use"])
	if err != nil {
		return hardening, nil, nil, fmt.Errorf("journald SystemMaxUse: %w", err)
	}
	hardening.JournalRuntimeMaxUseBytes, err = parseOptionalSystemdBytes(values["journal_runtime_max_use"])
	if err != nil {
		return hardening, nil, nil, fmt.Errorf("journald RuntimeMaxUse: %w", err)
	}
	hardening.CoredumpDisabled = values["coredump_disabled"] == "1"
	hardening.ApportDisabled = values["apport_disabled"] == "1"
	hardening.TmpTmpfs = values["tmp_fstype"] == "tmpfs"
	tmpOptions := commaSet(values["tmp_options"])
	hardening.TmpNoExec = tmpOptions["noexec"]
	hardening.TmpNoSuid = tmpOptions["nosuid"]
	hardening.TmpNoDev = tmpOptions["nodev"]
	hardening.BlockedModulesEffective = values["blocked_modules_effective"] == "1"
	hardening.IPv6Disabled = values["ipv6_disabled"] == "1"
	hardening.UnprivilegedPortStart, err = strconv.Atoi(strings.TrimSpace(values["unprivileged_port_start"]))
	if err != nil || hardening.UnprivilegedPortStart < 0 {
		return hardening, nil, nil, errors.New("invalid unprivileged port start")
	}
	hardening.DockerAbsent = values["docker_absent"] == "1"
	hardening.ContainerdAbsent = values["containerd_absent"] == "1"
	hardening.SubUIDRangePresent = values["subuid_range_present"] == "1"
	hardening.SubGIDRangePresent = values["subgid_range_present"] == "1"
	hardening.LingerEnabled = values["linger_enabled"] == "1"
	return hardening, swaps, listeners, nil
}

func parseNonNegativeInt64(value, name string) (int64, error) {
	parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("invalid %s", name)
	}
	return parsed, nil
}

func parseOptionalSystemdBytes(value string) (int64, error) {
	if strings.TrimSpace(value) == "" {
		return 0, nil
	}
	return parseSystemdBytes(value)
}

func parseSystemdBytes(value string) (int64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, errors.New("value is missing")
	}
	multiplier := int64(1)
	suffix := value[len(value)-1]
	switch suffix {
	case 'K', 'k':
		multiplier = 1 << 10
		value = value[:len(value)-1]
	case 'M', 'm':
		multiplier = 1 << 20
		value = value[:len(value)-1]
	case 'G', 'g':
		multiplier = 1 << 30
		value = value[:len(value)-1]
	case 'T', 't':
		multiplier = 1 << 40
		value = value[:len(value)-1]
	}
	base, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || base < 0 || (base != 0 && base > (1<<63-1)/multiplier) {
		return 0, errors.New("invalid byte size")
	}
	return base * multiplier, nil
}

func commaSet(value string) map[string]bool {
	result := map[string]bool{}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			result[item] = true
		}
	}
	return result
}

func parseTCPListener(value string) (managementstate.ListenerObservedState, error) {
	value = strings.TrimSpace(value)
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return managementstate.ListenerObservedState{}, fmt.Errorf("invalid tcp listener %q", value)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return managementstate.ListenerObservedState{}, fmt.Errorf("invalid tcp listener port %q", portText)
	}
	host = strings.Trim(host, "[]")
	loopback := false
	if ip := net.ParseIP(host); ip != nil {
		loopback = ip.IsLoopback()
	}
	return managementstate.ListenerObservedState{Address: host, Port: port, Public: !loopback, Loopback: loopback, Protocol: "tcp"}, nil
}
