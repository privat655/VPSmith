package managementstate

import "sort"

// PrimaryHardeningObservedState contains effective read-only facts owned by
// Cloud-init. It is part of the canonical target observation, not a second
// desired-state source.
type PrimaryHardeningObservedState struct {
	RootPasswordLocked        bool              `json:"root_password_locked"`
	SSHConfigValid            bool              `json:"ssh_config_valid"`
	SSHValues                 map[string]string `json:"ssh_values,omitempty"`
	UFWActive                 bool              `json:"ufw_active"`
	UFWDefaultIncoming        string            `json:"ufw_default_incoming,omitempty"`
	UFWDefaultOutgoing        string            `json:"ufw_default_outgoing,omitempty"`
	UFWDefaultRouted          string            `json:"ufw_default_routed,omitempty"`
	UFWLoggingLow             bool              `json:"ufw_logging_low"`
	UFWUnexpectedPublicAllow  bool              `json:"ufw_unexpected_public_allow"`
	UFWAllowedPublicTCPPorts  []int             `json:"ufw_allowed_public_tcp_ports,omitempty"`
	Fail2banSSHActive         bool              `json:"fail2ban_ssh_active"`
	Fail2banRecidiveActive    bool              `json:"fail2ban_recidive_active"`
	UnattendedUpgradesEnabled bool              `json:"unattended_upgrades_enabled"`
	AutomaticRebootDisabled   bool              `json:"automatic_reboot_disabled"`
}

// SecondaryHardeningObservedState contains effective host facts owned by Core.
// They are observed independently from generated files so a present file is
// never accepted as proof that hardening is effective.
type SecondaryHardeningObservedState struct {
	AppArmorEnabled           bool  `json:"apparmor_enabled"`
	AuditdActive              bool  `json:"auditd_active"`
	ChronyActive              bool  `json:"chrony_active"`
	JournalPersistent         bool  `json:"journal_persistent"`
	JournalSystemMaxUseBytes  int64 `json:"journal_system_max_use_bytes"`
	JournalRuntimeMaxUseBytes int64 `json:"journal_runtime_max_use_bytes"`
	CoredumpDisabled          bool  `json:"coredump_disabled"`
	ApportDisabled            bool  `json:"apport_disabled"`
	TmpTmpfs                  bool  `json:"tmp_tmpfs"`
	TmpNoExec                 bool  `json:"tmp_noexec"`
	TmpNoSuid                 bool  `json:"tmp_nosuid"`
	TmpNoDev                  bool  `json:"tmp_nodev"`
	BlockedModulesEffective   bool  `json:"blocked_modules_effective"`
	IPv6Disabled              bool  `json:"ipv6_disabled"`
	UnprivilegedPortStart     int   `json:"unprivileged_port_start"`
	DockerAbsent              bool  `json:"docker_absent"`
	ContainerdAbsent          bool  `json:"containerd_absent"`
	SubUIDRangePresent        bool  `json:"subuid_range_present"`
	SubGIDRangePresent        bool  `json:"subgid_range_present"`
	LingerEnabled             bool  `json:"linger_enabled"`
}

type SwapDeviceObservedState struct {
	Path        string `json:"path"`
	Kind        string `json:"kind,omitempty"`
	SizeBytes   int64  `json:"size_bytes"`
	UsedBytes   int64  `json:"used_bytes"`
	Priority    int    `json:"priority"`
	CoreManaged bool   `json:"core_managed"`
}

type ListenerObservedState struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Public   bool   `json:"public"`
	Loopback bool   `json:"loopback"`
	Protocol string `json:"protocol,omitempty"`
}

// HostObservedState contains direct host facts collected read-only over SSH.
type HostObservedState struct {
	Reachable             bool                            `json:"reachable"`
	SSH                   bool                            `json:"ssh"`
	Hostname              string                          `json:"hostname,omitempty"`
	OSID                  string                          `json:"os_id,omitempty"`
	OSVersion             string                          `json:"os_version,omitempty"`
	Kernel                string                          `json:"kernel,omitempty"`
	RootFilesystem        FilesystemObservedState         `json:"root_filesystem"`
	CoreBackupSourceBytes int64                           `json:"core_backup_source_bytes,omitempty"`
	Memory                MemoryObservedState             `json:"memory"`
	Swap                  MemoryObservedState             `json:"swap"`
	SwapDevices           []SwapDeviceObservedState       `json:"swap_devices,omitempty"`
	Listeners             []ListenerObservedState         `json:"listeners,omitempty"`
	RebootRequired        bool                            `json:"reboot_required"`
	UFWActive             bool                            `json:"ufw_active"`
	Fail2banActive        bool                            `json:"fail2ban_active"`
	PrimaryHardening      PrimaryHardeningObservedState   `json:"primary_hardening"`
	SecondaryHardening    SecondaryHardeningObservedState `json:"secondary_hardening"`
}

type FilesystemObservedState struct {
	TotalBytes     int64 `json:"total_bytes"`
	AvailableBytes int64 `json:"available_bytes"`
}

type MemoryObservedState struct {
	TotalBytes     int64 `json:"total_bytes"`
	AvailableBytes int64 `json:"available_bytes"`
}

type PodmanObservedState struct {
	Present            bool   `json:"present"`
	Rootless           bool   `json:"rootless"`
	CgroupVersion      string `json:"cgroup_version,omitempty"`
	RootlessNetworkCmd string `json:"rootless_network_cmd,omitempty"`
}

type UnitObservedState struct {
	Name        string `json:"name"`
	Scope       string `json:"scope"`
	Present     bool   `json:"present"`
	Running     bool   `json:"running"`
	ActiveState string `json:"active_state,omitempty"`
	SubState    string `json:"sub_state,omitempty"`
}

type ContainerObservedState struct {
	Name        string   `json:"name"`
	Present     bool     `json:"present"`
	Running     bool     `json:"running"`
	Health      string   `json:"health,omitempty"`
	ImageRef    string   `json:"image_ref,omitempty"`
	ImageDigest string   `json:"image_digest,omitempty"`
	Networks    []string `json:"networks,omitempty"`
}

type PublicRouteObservedState struct {
	Hostname     string `json:"hostname"`
	PathPrefix   string `json:"path"`
	AuthMode     string `json:"auth_mode"`
	StatusCode   int    `json:"status_code"`
	HTTPS        bool   `json:"https"`
	AuthEnforced bool   `json:"auth_enforced,omitempty"`
}

type NetworkObservedState struct {
	Name         string   `json:"name"`
	Internal     bool     `json:"internal"`
	Present      bool     `json:"present"`
	Subnets      []string `json:"subnets,omitempty"`
	Relationship string   `json:"relationship,omitempty"`
	Members      []string `json:"members,omitempty"`
}

type ServiceObservedState struct {
	Present       bool `json:"present"`
	Running       bool `json:"running"`
	ConfigChecked bool `json:"config_checked,omitempty"`
	ConfigValid   bool `json:"config_valid,omitempty"`
}

type ManagedArtifactObservedState struct {
	Path    string `json:"path"`
	Present bool   `json:"present"`
	SHA256  string `json:"sha256,omitempty"`
}

type ExecutionProofObservedState struct {
	ID           string `json:"id"`
	BundleID     string `json:"bundle_id"`
	BundleSHA256 string `json:"bundle_sha256"`
	Kind         string `json:"kind,omitempty"`
	Outcome      string `json:"outcome,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
}

type LinkNetworkObservedState struct {
	Name              string   `json:"name"`
	Present           bool     `json:"present"`
	Subnet            string   `json:"subnet,omitempty"`
	Relationship      string   `json:"relationship,omitempty"`
	DefinitionMatches bool     `json:"definition_matches"`
	Members           []string `json:"members,omitempty"`
}

// NormalizeObservedState makes set-like facts deterministic without changing
// their meaning. The observation timestamp is intentionally left untouched.
func NormalizeObservedState(value *ObservedState) {
	if value == nil {
		return
	}
	sort.Ints(value.Host.PrimaryHardening.UFWAllowedPublicTCPPorts)
	sort.Slice(value.Host.SwapDevices, func(i, j int) bool { return value.Host.SwapDevices[i].Path < value.Host.SwapDevices[j].Path })
	sort.Slice(value.Host.Listeners, func(i, j int) bool {
		if value.Host.Listeners[i].Port == value.Host.Listeners[j].Port {
			return value.Host.Listeners[i].Address < value.Host.Listeners[j].Address
		}
		return value.Host.Listeners[i].Port < value.Host.Listeners[j].Port
	})
	sort.Slice(value.Modules, func(i, j int) bool { return value.Modules[i].InstanceID < value.Modules[j].InstanceID })
	sort.Slice(value.Core.Units, func(i, j int) bool { return value.Core.Units[i].Name < value.Core.Units[j].Name })
	sort.Slice(value.Core.Containers, func(i, j int) bool { return value.Core.Containers[i].Name < value.Core.Containers[j].Name })
	sort.Slice(value.Core.Networks, func(i, j int) bool { return value.Core.Networks[i].Name < value.Core.Networks[j].Name })
	sort.Slice(value.Core.PublicRoutes, func(i, j int) bool {
		if value.Core.PublicRoutes[i].Hostname == value.Core.PublicRoutes[j].Hostname {
			return value.Core.PublicRoutes[i].PathPrefix < value.Core.PublicRoutes[j].PathPrefix
		}
		return value.Core.PublicRoutes[i].Hostname < value.Core.PublicRoutes[j].Hostname
	})
	sort.Slice(value.Core.ManagedArtifacts, func(i, j int) bool { return value.Core.ManagedArtifacts[i].Path < value.Core.ManagedArtifacts[j].Path })
	sort.Slice(value.Core.ExecutionProofs, func(i, j int) bool { return value.Core.ExecutionProofs[i].ID < value.Core.ExecutionProofs[j].ID })
	for i := range value.Core.Containers {
		sort.Strings(value.Core.Containers[i].Networks)
	}
	for i := range value.Core.Networks {
		sort.Strings(value.Core.Networks[i].Members)
		sort.Strings(value.Core.Networks[i].Subnets)
	}
	for i := range value.Modules {
		module := &value.Modules[i]
		sort.Slice(module.Units, func(a, b int) bool { return module.Units[a].Name < module.Units[b].Name })
		sort.Slice(module.Containers, func(a, b int) bool { return module.Containers[a].Name < module.Containers[b].Name })
		sort.Slice(module.Networks, func(a, b int) bool { return module.Networks[a].Name < module.Networks[b].Name })
		sort.Slice(module.ManagedArtifacts, func(a, b int) bool { return module.ManagedArtifacts[a].Path < module.ManagedArtifacts[b].Path })
		for j := range module.Containers {
			sort.Strings(module.Containers[j].Networks)
		}
		for j := range module.Networks {
			sort.Strings(module.Networks[j].Members)
			sort.Strings(module.Networks[j].Subnets)
		}
	}
	sort.Slice(value.PodmanNetworks, func(i, j int) bool { return value.PodmanNetworks[i].Name < value.PodmanNetworks[j].Name })
	for i := range value.PodmanNetworks {
		sort.Strings(value.PodmanNetworks[i].Members)
		sort.Strings(value.PodmanNetworks[i].Subnets)
	}
	sort.Slice(value.LinkNetworks, func(i, j int) bool { return value.LinkNetworks[i].Name < value.LinkNetworks[j].Name })
	for i := range value.LinkNetworks {
		sort.Strings(value.LinkNetworks[i].Members)
	}
	sort.Slice(value.ManagedArtifacts, func(i, j int) bool { return value.ManagedArtifacts[i].Path < value.ManagedArtifacts[j].Path })
}
