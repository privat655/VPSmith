package deployment

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestCheckCoreCompatibilityUsesFrozenModuleContracts(t *testing.T) {
	compiler := &Compiler{}
	compatible := FrozenModuleSource{InstanceID: "n8n-main", SourceID: "source-n8n", PackageID: "n8n", PackageSHA256: strings.Repeat("a", 64), PackageFS: compatibilityModuleFS("1")}
	if err := compiler.CheckCoreCompatibility("1", []FrozenModuleSource{compatible}); err != nil {
		t.Fatalf("compatible Core rejected: %v", err)
	}

	incompatible := compatible
	incompatible.InstanceID = "n8n-old"
	incompatible.PackageFS = compatibilityModuleFS("0")
	if err := compiler.CheckCoreCompatibility("1", []FrozenModuleSource{incompatible}); err == nil || !strings.Contains(err.Error(), "n8n-old") {
		t.Fatalf("incompatible module error = %v", err)
	}
}

func TestCheckCoreCompatibilityFailsClosedOnIncompleteFrozenIdentity(t *testing.T) {
	compiler := &Compiler{}
	err := compiler.CheckCoreCompatibility("1", []FrozenModuleSource{{InstanceID: "broken", PackageFS: compatibilityModuleFS("1")}})
	if err == nil {
		t.Fatal("incomplete frozen module identity accepted")
	}
}

func compatibilityModuleFS(coreContract string) fstest.MapFS {
	yaml := `module_id: test
module_version: "1.0.0"
core_contract: "` + coreContract + `"
images:
  app:
    ref: docker.io/library/busybox:1.36.1
containers:
  - id: app
    image: app
    user: 1000
    userns: nomap
    capabilities: []
    networks: [app]
persistent_storage: []
secrets: []
resources:
  memory_bytes: 134217728
  cpu_quota_percent: 100
  pids_limit: 128
  tasks_max: 256
networks:
  - {id: app, role: app}
egress: []
public_routes: []
healthcheck:
  type: command
  container: app
  command: ["true"]
service_checks: []
validation_action: validate
interfaces: []
dependencies: []
actions:
  validate: actions/validate.sh
update_from: {}
uninstall:
  delete_persistent_data: false
  delete_secrets: false
`
	return fstest.MapFS{
		"module.yaml":         &fstest.MapFile{Data: []byte(yaml)},
		"actions/validate.sh": &fstest.MapFile{Data: []byte("#!/bin/sh\nexit 0\n"), Mode: 0o755},
	}
}
