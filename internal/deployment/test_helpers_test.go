package deployment

import (
	"context"
	"fmt"
	"testing"
	"testing/fstest"

	"github.com/privat655/VPSmith/internal/executionbundle"
)

type fakeRegistry map[string]string

func (r fakeRegistry) Resolve(_ context.Context, ref string) (string, error) {
	v, ok := r[ref]
	if !ok {
		return "", fmt.Errorf("unknown ref %s", ref)
	}
	return v, nil
}

const digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func moduleFS(moduleID, version, deps string) fstest.MapFS {
	yaml := fmt.Sprintf(`module_id: %s
module_version: %q
core_contract: "1.0"
images:
  app: {ref: docker.io/example/%s:%s}
containers:
  - id: app
    image: app
    user: 1000
    userns: nomap
    mounts: [{storage: data, target: /data}]
    networks: [app, edge, egress]
    environment: {TZ: Europe/Berlin}
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
  - {id: edge, role: edge}
  - {id: egress, role: egress}
egress:
  - {container: app, reason: "HTTPS integrations"}
public_routes:
  - hostname: %s.example.test
    path: /
    container: app
    port: 8080
    authelia: {mode: protected, groups: [admins]}
healthcheck: {type: tcp, container: app, port: 8080}
validation_action: validate
interfaces:
  - {id: api, container: app, port: 8080, protocol: http}
dependencies: %s
actions:
  validate: actions/validate.sh
  migrate-one: actions/migrate-one.sh
  migrate-two: actions/migrate-two.sh
update_from:
  "1.0.0": {actions: [migrate-one, migrate-two]}
uninstall: {delete_persistent_data: true, delete_secrets: true}
`, moduleID, version, moduleID, version, moduleID, moduleID, deps)
	return fstest.MapFS{
		"module.yaml":            &fstest.MapFile{Data: []byte(yaml)},
		"actions/validate.sh":    &fstest.MapFile{Data: []byte("#!/bin/sh\nexit 0\n")},
		"actions/migrate-one.sh": &fstest.MapFile{Data: []byte("#!/bin/sh\necho one\n")},
		"actions/migrate-two.sh": &fstest.MapFile{Data: []byte("#!/bin/sh\necho two\n")},
	}
}

func reqSource(instance, moduleID, version, deps string) FrozenModuleSource {
	return FrozenModuleSource{
		InstanceID: instance, SourceID: "source-" + instance, PackageID: "pkg-" + instance,
		GitCommit: "commit-" + instance, PackageSHA256: hashChar(instance), PackageFS: moduleFS(moduleID, version, deps),
	}
}

func desired(instance, moduleID, version, deps string) DesiredModule {
	return DesiredModule{
		InstanceID: instance, Source: reqSource(instance, moduleID, version, deps),
		SecretIDs: map[string]string{"key": "secret-" + instance},
	}
}

func hashChar(seed string) string {
	b := 'c'
	if len(seed) > 0 {
		b = rune('a' + (int(seed[0]) % 6))
	}
	out := make([]byte, 64)
	for i := range out {
		out[i] = byte(b)
	}
	return string(out)
}

func newCompiler(t *testing.T, refs ...string) *Compiler {
	t.Helper()
	r := fakeRegistry{}
	for i, ref := range refs {
		if i%2 == 0 {
			r[ref] = digestA
		} else {
			r[ref] = digestB
		}
	}
	a, err := executionbundle.NewAssembler(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(r, a)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func baseRequest() Request {
	m := desired("n8n-1", "n8n", "2.0.0", "[]")
	return Request{
		Operation: Install, TargetID: "target-1", SubjectInstance: "n8n-1", DesiredModules: []DesiredModule{m},
		Observed: ObservedState{TargetID: "target-1"}, CoreContract: "1.0",
	}
}
