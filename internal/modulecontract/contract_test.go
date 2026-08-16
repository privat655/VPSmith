package modulecontract

import (
	"testing"
	"testing/fstest"
)

const validModuleYAML = `
module_id: n8n
module_version: "2.3.0"
core_contract: "1.0"
images:
  app:
    ref: docker.io/n8nio/n8n:2.3.0
containers:
  - id: app
    image: app
    user: 1000
    userns: nomap
    capabilities: [CHOWN]
    mounts:
      - storage: data
        target: /home/node/.n8n
    networks: [app, edge, egress]
persistent_storage:
  - id: data
    path: /var/lib/vpsmith/modules/n8n/data
secrets:
  - id: encryption-key
    source: generated
    delivery: environment
    name: N8N_ENCRYPTION_KEY
    containers: [app]
resources:
  memory_bytes: 536870912
  cpu_quota_percent: 100
  pids_limit: 256
  tasks_max: 512
networks:
  - {id: app, role: app}
  - {id: edge, role: edge}
  - {id: egress, role: egress}
egress:
  - container: app
    reason: HTTPS API and webhook delivery
public_routes:
  - hostname: n8n.example.test
    path: /
    container: app
    port: 5678
    authelia:
      mode: protected
      groups: [admins]
healthcheck:
  type: http
  container: app
  url: http://127.0.0.1:5678/healthz
service_checks:
  - id: worker
    type: command
    container: app
    command: [node, --version]
validation_action: validate
interfaces:
  - id: webhook-api
    container: app
    port: 5678
    protocol: http
dependencies: []
actions:
  validate: actions/validate.sh
  migrate: actions/migrate.sh
update_from:
  "2.2.0":
    actions: [migrate]
uninstall:
  delete_persistent_data: true
  delete_secrets: true
`

func packageWithYAML(y string) Package {
	return Package{FS: fstest.MapFS{
		"module.yaml":         &fstest.MapFile{Data: []byte(y)},
		"actions/validate.sh": &fstest.MapFile{Data: []byte("#!/bin/sh\nexit 0\n")},
		"actions/migrate.sh":  &fstest.MapFile{Data: []byte("#!/bin/sh\nexit 0\n")},
	}}
}

func TestCompileValidModule(t *testing.T) {
	m, err := (Compiler{}).Compile(packageWithYAML(validModuleYAML))
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != "n8n" || m.Version != "2.3.0" {
		t.Fatalf("unexpected identity: %#v", m)
	}
	if len(m.ServiceChecks) != 1 || m.ServiceChecks[0].ID != "worker" {
		t.Fatalf("service checks not normalized: %#v", m.ServiceChecks)
	}
	if got := string(m.ActionFiles["migrate"]); got != "#!/bin/sh\nexit 0\n" {
		t.Fatalf("action content not frozen: %q", got)
	}
}

func TestCompileRejectsForbiddenContracts(t *testing.T) {
	tests := []struct{ name, from, to string }{
		{"latest", "docker.io/n8nio/n8n:2.3.0", "docker.io/n8nio/n8n:latest"},
		{"free image version", "docker.io/n8nio/n8n:2.3.0", "docker.io/n8nio/n8n:^2"},
		{"unknown action", "actions: [migrate]", "actions: [missing]"},
		{"undeclared storage", "storage: data", "storage: missing"},
		{"unreasoned egress", "reason: HTTPS API and webhook delivery", "reason: ''"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			y := replaceOnce(t, validModuleYAML, tc.from, tc.to)
			if _, err := (Compiler{}).Compile(packageWithYAML(y)); err == nil {
				t.Fatal("expected compile failure")
			}
		})
	}
}

func TestCompileRejectsDirectHostPort(t *testing.T) {
	y := replaceOnce(t, validModuleYAML, "    networks: [app, edge, egress]\n", "    networks: [app, edge, egress]\n    host_ports:\n      - host_port: 8080\n        container_port: 5678\n")
	if _, err := (Compiler{}).Compile(packageWithYAML(y)); err == nil {
		t.Fatal("expected host-port rejection")
	}
}

func TestCompileRejectsDuplicateInterface(t *testing.T) {
	y := replaceOnce(t, validModuleYAML, "dependencies: []", `  - id: webhook-api
    container: app
    port: 5679
    protocol: http
dependencies: []`)
	if _, err := (Compiler{}).Compile(packageWithYAML(y)); err == nil {
		t.Fatal("expected duplicate interface rejection")
	}
}

func TestCompileRejectsUnknownFieldAndActionPathEscape(t *testing.T) {
	y := validModuleYAML + "unknown_field: true\n"
	if _, err := (Compiler{}).Compile(packageWithYAML(y)); err == nil {
		t.Fatal("expected unknown-field rejection")
	}
	y = replaceOnce(t, validModuleYAML, "actions/validate.sh", "actions/../validate.sh")
	if _, err := (Compiler{}).Compile(packageWithYAML(y)); err == nil {
		t.Fatal("expected action path rejection")
	}
}

func replaceOnce(t *testing.T, in, old, new string) string {
	t.Helper()
	idx := -1
	for i := 0; i+len(old) <= len(in); i++ {
		if in[i:i+len(old)] == old {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatalf("fixture fragment not found: %q", old)
	}
	return in[:idx] + new + in[idx+len(old):]
}
