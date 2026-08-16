package modulecontract

import "io/fs"

// Compiler is the single module-package seam. Callers provide an immutable
// package view; YAML, package layout and contract validation stay behind it.
type Compiler struct{}

type Package struct {
	FS fs.FS
}

type Module struct {
	ID               string                      `json:"module_id"`
	Version          string                      `json:"module_version"`
	CoreContract     string                      `json:"core_contract"`
	Images           map[string]Image            `json:"images"`
	Containers       []Container                 `json:"containers"`
	Persistent       []PersistentStorage         `json:"persistent_storage"`
	Secrets          []Secret                    `json:"secrets"`
	Resources        Resources                   `json:"resources"`
	Networks         []Network                   `json:"networks"`
	Egress           []EgressRule                `json:"egress"`
	PublicRoutes     []PublicRoute               `json:"public_routes"`
	Healthcheck      Healthcheck                 `json:"healthcheck"`
	ServiceChecks    []Healthcheck               `json:"service_checks,omitempty"`
	ValidationAction string                      `json:"validation_action"`
	Interfaces       []InternalInterface         `json:"interfaces"`
	Dependencies     []Dependency                `json:"dependencies"`
	Actions          map[string]string           `json:"actions"`
	UpdateFrom       map[string]UpdateTransition `json:"update_from"`
	Uninstall        Uninstall                   `json:"uninstall"`
	ActionFiles      map[string][]byte           `json:"-"`
}

type Image struct {
	Ref string `yaml:"ref" json:"ref"`
}

type Container struct {
	ID           string            `yaml:"id" json:"id"`
	Image        string            `yaml:"image" json:"image"`
	User         int               `yaml:"user" json:"user"`
	UserNS       string            `yaml:"userns" json:"userns"`
	Capabilities []string          `yaml:"capabilities" json:"capabilities,omitempty"`
	Mounts       []Mount           `yaml:"mounts" json:"mounts,omitempty"`
	Networks     []string          `yaml:"networks" json:"networks,omitempty"`
	HostPorts    []HostPort        `yaml:"host_ports" json:"host_ports,omitempty"`
	Environment  map[string]string `yaml:"environment" json:"environment,omitempty"`
}

type HostPort struct {
	HostPort      int `yaml:"host_port" json:"host_port"`
	ContainerPort int `yaml:"container_port" json:"container_port"`
}

type Mount struct {
	StorageID string `yaml:"storage" json:"storage"`
	Target    string `yaml:"target" json:"target"`
	ReadOnly  bool   `yaml:"read_only" json:"read_only"`
}

type PersistentStorage struct {
	ID   string `yaml:"id" json:"id"`
	Path string `yaml:"path" json:"path"`
}

type Secret struct {
	ID         string   `yaml:"id" json:"id"`
	Source     string   `yaml:"source" json:"source"`
	Delivery   string   `yaml:"delivery" json:"delivery"`
	Name       string   `yaml:"name" json:"name"`
	Path       string   `yaml:"path" json:"path,omitempty"`
	Containers []string `yaml:"containers" json:"containers"`
}

type Resources struct {
	MemoryBytes int64 `yaml:"memory_bytes" json:"memory_bytes"`
	CPUQuota    int   `yaml:"cpu_quota_percent" json:"cpu_quota_percent"`
	PIDsLimit   int   `yaml:"pids_limit" json:"pids_limit"`
	TasksMax    int   `yaml:"tasks_max" json:"tasks_max"`
}

type Network struct {
	ID   string `yaml:"id" json:"id"`
	Role string `yaml:"role" json:"role"`
}

type EgressRule struct {
	Container string `yaml:"container" json:"container"`
	Reason    string `yaml:"reason" json:"reason"`
}

type PublicRoute struct {
	Hostname   string         `yaml:"hostname" json:"hostname"`
	PathPrefix string         `yaml:"path" json:"path"`
	Container  string         `yaml:"container" json:"container"`
	Port       int            `yaml:"port" json:"port"`
	Authelia   AutheliaPolicy `yaml:"authelia" json:"authelia"`
}

type AutheliaPolicy struct {
	Mode   string   `yaml:"mode" json:"mode"`
	Users  []string `yaml:"users" json:"users,omitempty"`
	Groups []string `yaml:"groups" json:"groups,omitempty"`
}

type Healthcheck struct {
	ID        string   `yaml:"id" json:"id"`
	Type      string   `yaml:"type" json:"type"`
	Container string   `yaml:"container" json:"container"`
	URL       string   `yaml:"url" json:"url,omitempty"`
	Port      int      `yaml:"port" json:"port,omitempty"`
	Command   []string `yaml:"command" json:"command,omitempty"`
}

type InternalInterface struct {
	ID        string `yaml:"id" json:"id"`
	Container string `yaml:"container" json:"container"`
	Port      int    `yaml:"port" json:"port"`
	Protocol  string `yaml:"protocol" json:"protocol"`
}

type Dependency struct {
	TargetModule string `yaml:"target_module" json:"target_module"`
	InterfaceID  string `yaml:"interface" json:"interface"`
	Consumer     string `yaml:"consumer" json:"consumer"`
}

type UpdateTransition struct {
	Actions []string `yaml:"actions" json:"actions"`
}

type Uninstall struct {
	DeletePersistentData bool `yaml:"delete_persistent_data" json:"delete_persistent_data"`
	DeleteSecrets        bool `yaml:"delete_secrets" json:"delete_secrets"`
}

type rawModule struct {
	ModuleID         string                      `yaml:"module_id"`
	ModuleVersion    string                      `yaml:"module_version"`
	CoreContract     string                      `yaml:"core_contract"`
	Images           map[string]Image            `yaml:"images"`
	Containers       []Container                 `yaml:"containers"`
	Persistent       []PersistentStorage         `yaml:"persistent_storage"`
	Secrets          []Secret                    `yaml:"secrets"`
	Resources        Resources                   `yaml:"resources"`
	Networks         []Network                   `yaml:"networks"`
	Egress           []EgressRule                `yaml:"egress"`
	PublicRoutes     []PublicRoute               `yaml:"public_routes"`
	Healthcheck      Healthcheck                 `yaml:"healthcheck"`
	ServiceChecks    []Healthcheck               `yaml:"service_checks"`
	ValidationAction string                      `yaml:"validation_action"`
	Interfaces       []InternalInterface         `yaml:"interfaces"`
	Dependencies     []Dependency                `yaml:"dependencies"`
	Actions          map[string]string           `yaml:"actions"`
	UpdateFrom       map[string]UpdateTransition `yaml:"update_from"`
	Uninstall        Uninstall                   `yaml:"uninstall"`
}
