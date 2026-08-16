package deploymentinput

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/executionbundle"
	"github.com/privat655/VPSmith/internal/managementstate"
)

type registryStub map[string]string

func (r registryStub) Resolve(_ context.Context, ref string) (string, error) {
	digest, ok := r[ref]
	if !ok {
		return "", fmt.Errorf("unknown image ref %s", ref)
	}
	return digest, nil
}

func TestObservedNetworkFactsDriveDeploymentLinkReuseAndCollisions(t *testing.T) {
	compiler := integrationCompiler(t)
	provider := integrationModule("provider-1", "provider", "[]")
	consumer := integrationModule("consumer-1", "consumer", "[{target_module: provider, interface: api, consumer: app}]")
	req := deployment.Request{
		Operation:       deployment.Install,
		TargetID:        "target-1",
		SubjectInstance: "consumer-1",
		DesiredModules:  []deployment.DesiredModule{provider, consumer},
		Observed:        deployment.ObservedState{TargetID: "target-1"},
		CoreContract:    "1.0",
	}

	initial, err := compiler.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(initial.LinkNetworks) != 1 {
		t.Fatalf("initial links = %#v", initial.LinkNetworks)
	}
	link := initial.LinkNetworks[0]

	managed := managementstate.ObservedState{
		PodmanNetworks: []managementstate.NetworkObservedState{{
			Name: link.Name, Present: true, Subnets: []string{link.Subnet}, Relationship: link.Relationship,
		}},
		LinkNetworks: []managementstate.LinkNetworkObservedState{{
			Name: link.Name, Present: true, Subnet: link.Subnet, Relationship: link.Relationship, DefinitionMatches: true,
		}},
	}
	req.Observed.Networks, err = Networks(managed)
	if err != nil {
		t.Fatal(err)
	}
	reused, err := compiler.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(reused.LinkNetworks) != 1 || reused.LinkNetworks[0] != link {
		t.Fatalf("managed Link-Net changed: %#v -> %#v", link, reused.LinkNetworks)
	}

	foreignSubnet := managementstate.ObservedState{PodmanNetworks: []managementstate.NetworkObservedState{{
		Name: "foreign-net", Present: true, Subnets: []string{link.Subnet},
	}}}
	req.Observed.Networks, err = Networks(foreignSubnet)
	if err != nil {
		t.Fatal(err)
	}
	moved, err := compiler.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if moved.LinkNetworks[0].Subnet == link.Subnet {
		t.Fatal("foreign observed subnet was reused")
	}

	foreignName := managementstate.ObservedState{PodmanNetworks: []managementstate.NetworkObservedState{{
		Name: link.Name, Present: true, Subnets: []string{"10.250.1.0/24"},
	}}}
	req.Observed.Networks, err = Networks(foreignName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compiler.Prepare(context.Background(), req); err == nil {
		t.Fatal("foreign observed network using the stable Link-Net name must block")
	}
}

func integrationCompiler(t *testing.T) *deployment.Compiler {
	t.Helper()
	assembler, err := executionbundle.NewAssembler(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := deployment.New(registryStub{
		"docker.io/example/provider:2.0.0": "sha256:" + strings.Repeat("a", 64),
		"docker.io/example/consumer:2.0.0": "sha256:" + strings.Repeat("b", 64),
	}, assembler)
	if err != nil {
		t.Fatal(err)
	}
	return compiler
}

func integrationModule(instance, moduleID, dependencies string) deployment.DesiredModule {
	yaml := fmt.Sprintf(`module_id: %s
module_version: "2.0.0"
core_contract: "1.0"
images:
  app: {ref: docker.io/example/%s:2.0.0}
containers:
  - id: app
    image: app
    user: 1000
    userns: nomap
    mounts: [{storage: data, target: /data}]
    networks: [app, egress]
persistent_storage:
  - {id: data, path: /var/lib/vpsmith/%s/data}
secrets:
  - id: key
    source: generated
    delivery: environment
    name: APP_KEY
    containers: [app]
resources: {memory_bytes: 268435456, cpu_quota_percent: 100, pids_limit: 128, tasks_max: 256}
networks:
  - {id: app, role: app}
  - {id: egress, role: egress}
egress:
  - {container: app, reason: "HTTPS integrations"}
healthcheck: {type: tcp, container: app, port: 8080}
validation_action: validate
interfaces:
  - {id: api, container: app, port: 8080, protocol: http}
dependencies: %s
actions:
  validate: actions/validate.sh
update_from: {}
uninstall: {delete_persistent_data: true, delete_secrets: true}
`, moduleID, moduleID, moduleID, dependencies)
	return deployment.DesiredModule{
		InstanceID: instance,
		Source: deployment.FrozenModuleSource{
			InstanceID:    instance,
			SourceID:      "source-" + instance,
			PackageID:     "pkg-" + instance,
			GitCommit:     "commit-" + instance,
			PackageSHA256: strings.Repeat("c", 64),
			PackageFS: fstest.MapFS{
				"module.yaml":         &fstest.MapFile{Data: []byte(yaml)},
				"actions/validate.sh": &fstest.MapFile{Data: []byte("#!/bin/sh\nexit 0\n")},
			},
		},
		SecretIDs: map[string]string{"key": "secret-" + instance},
	}
}
