package deployment

import (
	"bytes"
	"context"
	"testing"
	"testing/fstest"
)

func TestPrepareBlocksInvalidModuleContractsThroughCompilerSeam(t *testing.T) {
	tests := []struct {
		name string
		from string
		to   string
		ref  string
	}{
		{"latest", "docker.io/example/n8n:2.0.0", "docker.io/example/n8n:latest", "docker.io/example/n8n:latest"},
		{"free image version", "docker.io/example/n8n:2.0.0", "docker.io/example/n8n:^2", "docker.io/example/n8n:^2"},
		{"unknown action", "migrate-two]}", "missing]}", "docker.io/example/n8n:2.0.0"},
		{"undeclared persistent state", "storage: data", "storage: missing", "docker.io/example/n8n:2.0.0"},
		{"unreasoned egress", `reason: "HTTPS integrations"`, `reason: ""`, "docker.io/example/n8n:2.0.0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := baseRequest()
			raw := moduleFS("n8n", "2.0.0", "[]")
			b := bytes.Replace(raw["module.yaml"].Data, []byte(tc.from), []byte(tc.to), 1)
			if bytes.Equal(b, raw["module.yaml"].Data) {
				t.Fatalf("fixture edit %q not applied", tc.from)
			}
			raw["module.yaml"] = &fstest.MapFile{Data: b}
			req.DesiredModules[0].Source.PackageFS = raw
			c := newCompiler(t, tc.ref)
			if _, err := c.Prepare(context.Background(), req); err == nil {
				t.Fatal("expected compiler rejection")
			}
		})
	}
}

func TestPrepareBlocksDirectModuleHostPort(t *testing.T) {
	req := baseRequest()
	raw := moduleFS("n8n", "2.0.0", "[]")
	needle := []byte("    networks: [app, edge, egress]\n")
	repl := []byte("    networks: [app, edge, egress]\n    host_ports: [{host_port: 8080, container_port: 8080}]\n")
	raw["module.yaml"] = &fstest.MapFile{Data: bytes.Replace(raw["module.yaml"].Data, needle, repl, 1)}
	req.DesiredModules[0].Source.PackageFS = raw
	c := newCompiler(t, "docker.io/example/n8n:2.0.0")
	if _, err := c.Prepare(context.Background(), req); err == nil {
		t.Fatal("expected direct hostport rejection")
	}
}

func TestPrepareBlocksObservedResourceCollision(t *testing.T) {
	req := baseRequest()
	req.Observed.Claims = []ObservedClaim{{Kind: "path", Value: "/var/lib/vpsmith/n8n/data", Owner: "foreign"}}
	c := newCompiler(t, "docker.io/example/n8n:2.0.0")
	if _, err := c.Prepare(context.Background(), req); err == nil {
		t.Fatal("expected desired/observed path collision")
	}
}

func TestPrepareBlocksDesiredResourceCollision(t *testing.T) {
	a := desired("first-1", "shared", "2.0.0", "[]")
	b := desired("second-1", "shared", "2.0.0", "[]")
	c := newCompiler(t, "docker.io/example/shared:2.0.0")
	req := Request{Operation: Install, TargetID: "target-1", SubjectInstance: "first-1", DesiredModules: []DesiredModule{a, b}, Observed: ObservedState{TargetID: "target-1"}, CoreContract: "1.0"}
	if _, err := c.Prepare(context.Background(), req); err == nil {
		t.Fatal("expected collision between two desired persistent path claims")
	}
}
