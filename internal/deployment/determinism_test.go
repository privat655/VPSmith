package deployment

import (
	"bytes"
	"context"
	"testing"
)

func TestPrepareIsByteDeterministicAndFreezesIdentities(t *testing.T) {
	req := baseRequest()
	c := newCompiler(t, "docker.io/example/n8n:2.0.0")
	one, err := c.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	two, err := c.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(one.Bundle.Bytes, two.Bundle.Bytes) || one.Bundle.SHA256 != two.Bundle.SHA256 {
		t.Fatal("same input must produce byte-identical bundle and SHA-256")
	}
	if len(one.Artifacts) != len(two.Artifacts) {
		t.Fatal("artifact count changed")
	}
	for i := range one.Artifacts {
		if one.Artifacts[i].Path != two.Artifacts[i].Path || !bytes.Equal(one.Artifacts[i].Data, two.Artifacts[i].Data) || one.Artifacts[i].SHA256 != two.Artifacts[i].SHA256 {
			t.Fatalf("artifact %d is not byte-deterministic", i)
		}
	}
	if one.FrozenSources[0].GitCommit != "commit-n8n-1" || one.FrozenSources[0].PackageSHA256 == "" || one.ImageDigests["n8n-1/app"] != digestA {
		t.Fatalf("identities were not frozen: %#v", one)
	}
}

func TestPrepareRelevantDesiredChangeChangesHash(t *testing.T) {
	req := baseRequest()
	c := newCompiler(t, "docker.io/example/n8n:2.0.0")
	one, err := c.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	req.DesiredModules[0].Resources.MemoryBytes = 1073741824
	two, err := c.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if one.Bundle.SHA256 == two.Bundle.SHA256 {
		t.Fatal("resource override must change generated bundle")
	}
}

func TestPrepareSemanticModuleOrderIsCanonical(t *testing.T) {
	a := desired("a-1", "alpha", "2.0.0", "[]")
	b := desired("b-1", "beta", "2.0.0", "[]")
	c := newCompiler(t, "docker.io/example/alpha:2.0.0", "docker.io/example/beta:2.0.0")
	req := Request{Operation: Install, TargetID: "target-1", SubjectInstance: "a-1", DesiredModules: []DesiredModule{a, b}, Observed: ObservedState{TargetID: "target-1"}, CoreContract: "1.0"}
	one, err := c.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	req.DesiredModules = []DesiredModule{b, a}
	two, err := c.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(one.Bundle.Bytes, two.Bundle.Bytes) {
		t.Fatal("semantic input order changed canonical bundle")
	}
}
