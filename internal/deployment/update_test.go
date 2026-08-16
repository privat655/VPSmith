package deployment

import (
	"context"
	"fmt"
	"testing"
)

func TestPrepareUpdateRequiresDirectTransitionAndPreservesActionOrder(t *testing.T) {
	req := baseRequest()
	req.Operation = Update
	req.Observed.Modules = []ObservedModule{{InstanceID: "n8n-1", ModuleID: "n8n", Version: "1.0.0", PackageSHA256: "old"}}
	c := newCompiler(t, "docker.io/example/n8n:2.0.0")
	p, err := c.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range p.Bundle.Manifest.Steps {
		if s.Kind == "action" {
			got = append(got, s.Action)
		}
	}
	want := []string{"migrate-one", "migrate-two", "validate"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("action order = %v, want %v", got, want)
	}
	req.Observed.Modules[0].Version = "0.9.0"
	if _, err := c.Prepare(context.Background(), req); err == nil {
		t.Fatal("expected missing direct update_from transition")
	}
}

func TestPrepareDoesNotChainUpdateTransitions(t *testing.T) {
	req := baseRequest()
	req.Operation = Update
	req.Observed.Modules = []ObservedModule{{InstanceID: "n8n-1", ModuleID: "n8n", Version: "0.9.0"}}
	c := newCompiler(t, "docker.io/example/n8n:2.0.0")
	if _, err := c.Prepare(context.Background(), req); err == nil {
		t.Fatal("compiler must not search for an intermediate update path")
	}
}
