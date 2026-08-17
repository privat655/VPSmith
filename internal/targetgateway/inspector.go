package targetgateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/privat655/VPSmith/internal/managementstate"
)

func (t *sshTransport) hostFacts(ctx context.Context, sess session) (managementstate.HostObservedState, error) {
	const probe = `set -eu
hostname=$(hostname)
kernel=$(uname -sr)
os_id=''
os_version=''
if [ -r /etc/os-release ]; then
  . /etc/os-release
  os_id=${ID:-}
  os_version=${VERSION_ID:-}
fi
set -- $(df -B1 -P / | tail -n 1)
root_total=$2
root_available=$4
mem_total=$(awk '/^MemTotal:/ {print $2 * 1024}' /proc/meminfo)
mem_available=$(awk '/^MemAvailable:/ {print $2 * 1024}' /proc/meminfo)
swap_total=$(awk '/^SwapTotal:/ {print $2 * 1024}' /proc/meminfo)
swap_free=$(awk '/^SwapFree:/ {print $2 * 1024}' /proc/meminfo)
reboot=0
[ ! -e /var/run/reboot-required ] || reboot=1
ufw=0
systemctl is-active --quiet ufw.service 2>/dev/null && ufw=1 || true
fail2ban=0
systemctl is-active --quiet fail2ban.service 2>/dev/null && fail2ban=1 || true
printf 'hostname\t%s\n' "$hostname"
printf 'kernel\t%s\n' "$kernel"
printf 'os_id\t%s\n' "$os_id"
printf 'os_version\t%s\n' "$os_version"
printf 'root_total\t%s\n' "$root_total"
printf 'root_available\t%s\n' "$root_available"
printf 'mem_total\t%s\n' "$mem_total"
printf 'mem_available\t%s\n' "$mem_available"
printf 'swap_total\t%s\n' "$swap_total"
printf 'swap_free\t%s\n' "$swap_free"
printf 'reboot\t%s\n' "$reboot"
printf 'ufw\t%s\n' "$ufw"
printf 'fail2ban\t%s\n' "$fail2ban"`
	stdout, err := t.runRemote(ctx, sess, probe)
	if err != nil {
		return managementstate.HostObservedState{}, fmt.Errorf("read host facts: %w", err)
	}
	values, err := parseTabFacts(stdout)
	if err != nil {
		return managementstate.HostObservedState{}, err
	}
	rootTotal, err := int64Fact(values, "root_total")
	if err != nil {
		return managementstate.HostObservedState{}, err
	}
	rootAvailable, err := int64Fact(values, "root_available")
	if err != nil {
		return managementstate.HostObservedState{}, err
	}
	memTotal, err := int64Fact(values, "mem_total")
	if err != nil {
		return managementstate.HostObservedState{}, err
	}
	memAvailable, err := int64Fact(values, "mem_available")
	if err != nil {
		return managementstate.HostObservedState{}, err
	}
	swapTotal, err := int64Fact(values, "swap_total")
	if err != nil {
		return managementstate.HostObservedState{}, err
	}
	swapFree, err := int64Fact(values, "swap_free")
	if err != nil {
		return managementstate.HostObservedState{}, err
	}
	return managementstate.HostObservedState{
		Reachable: true, SSH: true,
		Hostname: values["hostname"], OSID: values["os_id"], OSVersion: values["os_version"], Kernel: values["kernel"],
		RootFilesystem: managementstate.FilesystemObservedState{TotalBytes: rootTotal, AvailableBytes: rootAvailable},
		Memory:         managementstate.MemoryObservedState{TotalBytes: memTotal, AvailableBytes: memAvailable},
		Swap:           managementstate.MemoryObservedState{TotalBytes: swapTotal, AvailableBytes: swapFree},
		RebootRequired: values["reboot"] == "1", UFWActive: values["ufw"] == "1", Fail2banActive: values["fail2ban"] == "1",
	}, nil
}

func (t *sshTransport) cloudInitFacts(ctx context.Context, sess session) (managementstate.CloudInitObservedState, error) {
	stdout, err := t.readOptional(ctx, sess, cloudInitStatusPath)
	if err != nil {
		return managementstate.CloudInitObservedState{}, err
	}
	if len(bytes.TrimSpace(stdout)) == 0 {
		return managementstate.CloudInitObservedState{Present: false}, nil
	}
	facts := managementstate.CloudInitObservedState{Present: true}
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "status":
			facts.Status = value
		case "version":
			facts.Version = value
		case "finished_at":
			facts.FinishedAt = value
		}
	}
	return facts, scanner.Err()
}

type unitRef struct {
	Name  string `json:"name"`
	Scope string `json:"scope"`
}

type caddyRef struct {
	Unit       unitRef `json:"unit"`
	Container  string  `json:"container"`
	ConfigPath string  `json:"config_path"`
}

type serviceRef struct {
	Unit      unitRef `json:"unit"`
	Container string  `json:"container"`
}

type coreInventory struct {
	SourceID         managementstate.SourceSnapshotID              `json:"source_id"`
	Version          string                                        `json:"version"`
	PackageSHA256    string                                        `json:"package_sha256"`
	Units            []unitRef                                     `json:"units"`
	Containers       []string                                      `json:"containers"`
	Networks         []string                                      `json:"networks"`
	Caddy            *caddyRef                                     `json:"caddy,omitempty"`
	Authelia         *serviceRef                                   `json:"authelia,omitempty"`
	ManagedArtifacts []string                                      `json:"managed_artifacts"`
	ExecutionProofs  []managementstate.ExecutionProofObservedState `json:"execution_proofs"`
}

type moduleInventoryDocument struct {
	Modules []moduleInventory `json:"modules"`
}

type moduleInventory struct {
	InstanceID       managementstate.ModuleInstanceID `json:"instance_id"`
	PackageID        managementstate.ModulePackageID  `json:"package_id"`
	Version          string                           `json:"version"`
	PackageSHA256    string                           `json:"package_sha256"`
	Units            []unitRef                        `json:"units"`
	Containers       []string                         `json:"containers"`
	Networks         []string                         `json:"networks"`
	ManagedArtifacts []string                         `json:"managed_artifacts"`
}

type linkInventoryDocument struct {
	Networks []struct {
		Name string `json:"name"`
	} `json:"networks"`
}

func (t *sshTransport) coreFacts(ctx context.Context, sess session) (managementstate.CoreObservedState, error) {
	raw, err := t.readOptional(ctx, sess, coreInventoryPath)
	if err != nil {
		return managementstate.CoreObservedState{}, err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return managementstate.CoreObservedState{Present: false}, nil
	}
	var inventory coreInventory
	if err := json.Unmarshal(raw, &inventory); err != nil {
		return managementstate.CoreObservedState{}, fmt.Errorf("decode core inventory: %w", err)
	}
	facts := managementstate.CoreObservedState{
		Present: true, SourceID: inventory.SourceID, Version: inventory.Version, PackageSHA256: inventory.PackageSHA256,
		ExecutionProofs: append([]managementstate.ExecutionProofObservedState(nil), inventory.ExecutionProofs...),
	}
	facts.Podman, err = t.podmanFacts(ctx, sess)
	if err != nil {
		return facts, err
	}
	for _, ref := range inventory.Units {
		unit, err := t.unitFacts(ctx, sess, ref)
		if err != nil {
			return facts, err
		}
		facts.Units = append(facts.Units, unit)
	}
	for _, name := range inventory.Containers {
		container, err := t.containerFacts(ctx, sess, name)
		if err != nil {
			return facts, err
		}
		facts.Containers = append(facts.Containers, container)
	}
	for _, name := range inventory.Networks {
		network, err := t.networkFacts(ctx, sess, name)
		if err != nil {
			return facts, err
		}
		facts.Networks = append(facts.Networks, network)
	}
	for _, path := range inventory.ManagedArtifacts {
		artifact, err := t.artifactFacts(ctx, sess, path)
		if err != nil {
			return facts, err
		}
		facts.ManagedArtifacts = append(facts.ManagedArtifacts, artifact)
	}
	if inventory.Caddy != nil {
		facts.Caddy, err = t.caddyFacts(ctx, sess, *inventory.Caddy)
		if err != nil {
			return facts, err
		}
	}
	if inventory.Authelia != nil {
		facts.Authelia, err = t.serviceFacts(ctx, sess, *inventory.Authelia)
		if err != nil {
			return facts, err
		}
	}
	facts.Running = allExpectedRunning(facts.Units, facts.Containers)
	return facts, nil
}

func (t *sshTransport) moduleFacts(ctx context.Context, sess session) ([]managementstate.ModuleObservedState, error) {
	raw, err := t.readOptional(ctx, sess, moduleInventoryPath)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return []managementstate.ModuleObservedState{}, nil
	}
	var document moduleInventoryDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("decode module inventory: %w", err)
	}
	result := make([]managementstate.ModuleObservedState, 0, len(document.Modules))
	for _, inventory := range document.Modules {
		if inventory.InstanceID == "" || inventory.PackageID == "" {
			return nil, errors.New("module inventory entry is missing identity")
		}
		facts := managementstate.ModuleObservedState{
			Present: true, InstanceID: inventory.InstanceID, PackageID: inventory.PackageID,
			Version: inventory.Version, PackageSHA256: inventory.PackageSHA256,
		}
		for _, ref := range inventory.Units {
			unit, err := t.unitFacts(ctx, sess, ref)
			if err != nil {
				return nil, err
			}
			facts.Units = append(facts.Units, unit)
		}
		for _, name := range inventory.Containers {
			container, err := t.containerFacts(ctx, sess, name)
			if err != nil {
				return nil, err
			}
			facts.Containers = append(facts.Containers, container)
			if facts.Health == "" && container.Health != "" {
				facts.Health = container.Health
			}
		}
		for _, name := range inventory.Networks {
			network, err := t.networkFacts(ctx, sess, name)
			if err != nil {
				return nil, err
			}
			facts.Networks = append(facts.Networks, network)
		}
		for _, path := range inventory.ManagedArtifacts {
			artifact, err := t.artifactFacts(ctx, sess, path)
			if err != nil {
				return nil, err
			}
			facts.ManagedArtifacts = append(facts.ManagedArtifacts, artifact)
		}
		facts.Running = allExpectedRunning(facts.Units, facts.Containers)
		result = append(result, facts)
	}
	return result, nil
}

func (t *sshTransport) linkFacts(ctx context.Context, sess session) ([]managementstate.LinkNetworkObservedState, error) {
	raw, err := t.readOptional(ctx, sess, linkInventoryPath)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return []managementstate.LinkNetworkObservedState{}, nil
	}
	var document linkInventoryDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("decode link-network inventory: %w", err)
	}
	result := make([]managementstate.LinkNetworkObservedState, 0, len(document.Networks))
	for _, ref := range document.Networks {
		network, err := t.networkFacts(ctx, sess, ref.Name)
		if err != nil {
			return nil, err
		}
		result = append(result, managementstate.LinkNetworkObservedState{Name: ref.Name, Present: network.Present, Members: network.Members})
	}
	return result, nil
}

func (t *sshTransport) podmanFacts(ctx context.Context, sess session) (managementstate.PodmanObservedState, error) {
	stdout, err := t.runRemote(ctx, sess, `if command -v podman >/dev/null 2>&1; then podman info --format json; fi`)
	if err != nil {
		return managementstate.PodmanObservedState{}, err
	}
	if len(bytes.TrimSpace(stdout)) == 0 {
		return managementstate.PodmanObservedState{Present: false}, nil
	}
	var info struct {
		Host struct {
			CgroupVersion string `json:"cgroupVersion"`
			Security      struct {
				Rootless bool `json:"rootless"`
			} `json:"security"`
			RootlessNetworkCmd string `json:"rootlessNetworkCmd"`
		} `json:"host"`
	}
	if err := json.Unmarshal(stdout, &info); err != nil {
		return managementstate.PodmanObservedState{}, fmt.Errorf("decode podman info: %w", err)
	}
	return managementstate.PodmanObservedState{
		Present: true, Rootless: info.Host.Security.Rootless, CgroupVersion: info.Host.CgroupVersion,
		RootlessNetworkCmd: info.Host.RootlessNetworkCmd,
	}, nil
}

func (t *sshTransport) unitFacts(ctx context.Context, sess session, ref unitRef) (managementstate.UnitObservedState, error) {
	if !safeObjectName(ref.Name) {
		return managementstate.UnitObservedState{}, errors.New("inventory contains invalid unit name")
	}
	if ref.Scope == "" {
		ref.Scope = "user"
	}
	if ref.Scope != "user" && ref.Scope != "system" {
		return managementstate.UnitObservedState{}, errors.New("inventory contains invalid unit scope")
	}
	prefix := "systemctl"
	if ref.Scope == "user" {
		prefix += " --user"
	}
	command := prefix + " show --no-pager --property=LoadState --property=ActiveState --property=SubState " + shellQuote(ref.Name) + " 2>/dev/null || true"
	stdout, err := t.runRemote(ctx, sess, command)
	if err != nil {
		return managementstate.UnitObservedState{}, err
	}
	values := parseEqualsFacts(stdout)
	present := values["LoadState"] != "" && values["LoadState"] != "not-found"
	return managementstate.UnitObservedState{
		Name: ref.Name, Scope: ref.Scope, Present: present, Running: values["ActiveState"] == "active",
		ActiveState: values["ActiveState"], SubState: values["SubState"],
	}, nil
}

func (t *sshTransport) containerFacts(ctx context.Context, sess session, name string) (managementstate.ContainerObservedState, error) {
	if !safeObjectName(name) {
		return managementstate.ContainerObservedState{}, errors.New("inventory contains invalid container name")
	}
	command := "podman inspect " + shellQuote(name) + " 2>/dev/null || true"
	stdout, err := t.runRemote(ctx, sess, command)
	if err != nil {
		return managementstate.ContainerObservedState{}, err
	}
	if len(bytes.TrimSpace(stdout)) == 0 {
		return managementstate.ContainerObservedState{Name: name, Present: false}, nil
	}
	var entries []struct {
		State struct {
			Running bool `json:"Running"`
			Health  *struct {
				Status string `json:"Status"`
			} `json:"Health"`
		} `json:"State"`
		NetworkSettings struct {
			Networks map[string]json.RawMessage `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := json.Unmarshal(stdout, &entries); err != nil || len(entries) != 1 {
		return managementstate.ContainerObservedState{}, errors.New("decode podman container inspection")
	}
	result := managementstate.ContainerObservedState{Name: name, Present: true, Running: entries[0].State.Running}
	if entries[0].State.Health != nil {
		result.Health = entries[0].State.Health.Status
	}
	for network := range entries[0].NetworkSettings.Networks {
		result.Networks = append(result.Networks, network)
	}
	sort.Strings(result.Networks)
	return result, nil
}

func (t *sshTransport) networkFacts(ctx context.Context, sess session, name string) (managementstate.NetworkObservedState, error) {
	if !safeObjectName(name) {
		return managementstate.NetworkObservedState{}, errors.New("inventory contains invalid network name")
	}
	command := "podman network inspect " + shellQuote(name) + " 2>/dev/null || true"
	stdout, err := t.runRemote(ctx, sess, command)
	if err != nil {
		return managementstate.NetworkObservedState{}, err
	}
	if len(bytes.TrimSpace(stdout)) == 0 {
		return managementstate.NetworkObservedState{Name: name, Present: false}, nil
	}
	var entries []struct {
		Name       string `json:"name"`
		Internal   bool   `json:"internal"`
		Containers map[string]struct {
			Name string `json:"name"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(stdout, &entries); err != nil || len(entries) != 1 {
		return managementstate.NetworkObservedState{}, errors.New("decode podman network inspection")
	}
	result := managementstate.NetworkObservedState{Name: name, Present: true, Internal: entries[0].Internal}
	for id, container := range entries[0].Containers {
		member := container.Name
		if member == "" {
			member = id
		}
		result.Members = append(result.Members, member)
	}
	sort.Strings(result.Members)
	return result, nil
}

func (t *sshTransport) artifactFacts(ctx context.Context, sess session, path string) (managementstate.ManagedArtifactObservedState, error) {
	if !safeArtifactPath(path) {
		return managementstate.ManagedArtifactObservedState{}, errors.New("inventory contains invalid managed artifact path")
	}
	command := "if [ -f " + shellQuote(path) + " ]; then sha256sum -- " + shellQuote(path) + "; fi"
	stdout, err := t.runRemote(ctx, sess, command)
	if err != nil {
		return managementstate.ManagedArtifactObservedState{}, err
	}
	fields := strings.Fields(string(stdout))
	if len(fields) == 0 {
		return managementstate.ManagedArtifactObservedState{Path: path, Present: false}, nil
	}
	if len(fields[0]) != 64 || !isHex(fields[0]) {
		return managementstate.ManagedArtifactObservedState{}, errors.New("invalid managed artifact sha256")
	}
	return managementstate.ManagedArtifactObservedState{Path: path, Present: true, SHA256: strings.ToLower(fields[0])}, nil
}

func (t *sshTransport) caddyFacts(ctx context.Context, sess session, ref caddyRef) (managementstate.ServiceObservedState, error) {
	service, err := t.serviceFacts(ctx, sess, serviceRef{Unit: ref.Unit, Container: ref.Container})
	if err != nil {
		return service, err
	}
	if !service.Present || ref.Container == "" || ref.ConfigPath == "" {
		return service, nil
	}
	if !safeObjectName(ref.Container) || !safeArtifactPath(ref.ConfigPath) {
		return service, errors.New("inventory contains invalid caddy reference")
	}
	command := "podman exec " + shellQuote(ref.Container) + " caddy validate --config " + shellQuote(ref.ConfigPath)
	_, err = t.runRemote(ctx, sess, command)
	service.ConfigChecked = true
	service.ConfigValid = err == nil
	return service, nil
}

func (t *sshTransport) serviceFacts(ctx context.Context, sess session, ref serviceRef) (managementstate.ServiceObservedState, error) {
	result := managementstate.ServiceObservedState{}
	if ref.Unit.Name != "" {
		unit, err := t.unitFacts(ctx, sess, ref.Unit)
		if err != nil {
			return result, err
		}
		result.Present = unit.Present
		result.Running = unit.Running
	}
	if ref.Container != "" {
		container, err := t.containerFacts(ctx, sess, ref.Container)
		if err != nil {
			return result, err
		}
		result.Present = result.Present || container.Present
		if ref.Unit.Name == "" {
			result.Running = container.Running
		} else {
			result.Running = result.Running && container.Running
		}
	}
	return result, nil
}

func allExpectedRunning(units []managementstate.UnitObservedState, containers []managementstate.ContainerObservedState) bool {
	if len(units) == 0 && len(containers) == 0 {
		return false
	}
	for _, unit := range units {
		if !unit.Present || !unit.Running {
			return false
		}
	}
	for _, container := range containers {
		if !container.Present || !container.Running {
			return false
		}
	}
	return true
}
